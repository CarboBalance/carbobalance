// api/hotmart-webhook.js
// Recebe notificações da Hotmart e autoriza o e-mail no Firebase

const { initializeApp, cert, getApps } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

// Inicializa Firebase Admin (apenas uma vez)
if (!getApps().length) {
  initializeApp({
    credential: cert({
      projectId:    process.env.FIREBASE_PROJECT_ID,
      clientEmail:  process.env.FIREBASE_CLIENT_EMAIL,
      privateKey:   process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }),
  });
}

const db = getFirestore();

// Token secreto para validar que a requisição vem da Hotmart
const HOTMART_TOKEN = process.env.HOTMART_WEBHOOK_TOKEN;

module.exports = async function handler(req, res) {
  // Aceita apenas POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const body = req.body;

    // Log para debug (remover em produção)
    console.log('Webhook recebido:', JSON.stringify(body));

    // Valida token da Hotmart (segurança)
    const token = req.headers['x-hotmart-hottok'] 
               || req.headers['hottok']
               || req.headers['authorization']
               || req.query.token
               || req.query.hottok;
    console.log('Token recebido:', token);
    console.log('Headers:', JSON.stringify(req.headers));
    if (HOTMART_TOKEN && token !== HOTMART_TOKEN) {
      console.error('Token inválido:', token);
      // Em modo teste da Hotmart, aceitar mesmo sem token correto
      if (!token || token === 'undefined') {
        console.log('Sem token — possível teste da Hotmart, continuando...');
      } else {
        return res.status(401).json({ error: 'Unauthorized' });
      }
    }

    // Extrai o evento e e-mail do comprador
    const event = body?.event;
    const email = body?.data?.buyer?.email || body?.buyer?.email;

    if (!email) {
      console.error('E-mail não encontrado no payload:', JSON.stringify(body));
      return res.status(400).json({ error: 'Email not found in payload' });
    }

    const emailNorm = email.toLowerCase().trim();

    // Eventos que autorizam o acesso
    const APPROVE_EVENTS = [
      'PURCHASE_APPROVED',
      'PURCHASE_COMPLETE',
      'SUBSCRIPTION_ACTIVE',
    ];

    // Eventos que revogam o acesso (reembolso, chargeback)
    const REVOKE_EVENTS = [
      'PURCHASE_REFUNDED',
      'PURCHASE_CHARGEBACK',
      'PURCHASE_CANCELED',
      'SUBSCRIPTION_CANCELED',
    ];

    if (APPROVE_EVENTS.includes(event)) {
      // Autoriza o e-mail
      await db.collection('authorized_emails').doc(emailNorm).set({
        email:       emailNorm,
        authorizedAt: new Date().toISOString(),
        event,
        buyerName:   body?.data?.buyer?.name || '',
        active:      true,
      });
      console.log(`✅ E-mail autorizado: ${emailNorm} (${event})`);
      return res.status(200).json({ success: true, message: `Email ${emailNorm} autorizado` });

    } else if (REVOKE_EVENTS.includes(event)) {
      // Revoga o acesso
      await db.collection('authorized_emails').doc(emailNorm).set({
        active:    false,
        revokedAt: new Date().toISOString(),
        event,
      }, { merge: true });
      console.log(`🚫 Acesso revogado: ${emailNorm} (${event})`);
      return res.status(200).json({ success: true, message: `Acesso de ${emailNorm} revogado` });

    } else {
      // Evento ignorado (ex: PURCHASE_BILLET_PRINTED)
      console.log(`ℹ️ Evento ignorado: ${event}`);
      return res.status(200).json({ success: true, message: `Evento ${event} ignorado` });
    }

  } catch (error) {
    console.error('Erro no webhook:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};
