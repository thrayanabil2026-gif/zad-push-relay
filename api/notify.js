const crypto = require('crypto');
const webpush = require('web-push');

function setCorsHeaders(req, res) {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, x-zad-relay-secret'
  );
  res.setHeader('Cache-Control', 'no-store');
}

function getVapidConfig() {
  const publicKey = String(process.env.VAPID_PUBLIC_KEY || '')
    .trim()
    .replace(/^["']|["']$/g, '')
    .replace(/\s+/g, '');
  const privateKey = String(process.env.VAPID_PRIVATE_KEY || '')
    .trim()
    .replace(/^["']|["']$/g, '')
    .replace(/\s+/g, '');
  const subject = String(process.env.VAPID_SUBJECT || 'mailto:support@zadtoo.com').trim();
  const relaySecret = String(process.env.RELAY_SECRET || '').trim();

  let vapidReady = false;
  if (publicKey.length >= 80 && privateKey.length >= 30) {
    try {
      const padding = '='.repeat((4 - (publicKey.length % 4)) % 4);
      const b64 = (publicKey + padding).replace(/-/g, '+').replace(/_/g, '/');
      const raw = Buffer.from(b64, 'base64');
      vapidReady = raw.length === 65 && raw[0] === 0x04;
    } catch {
      vapidReady = false;
    }
  }

  return { publicKey, privateKey, subject, relaySecret, vapidReady };
}

function timingSafeMatch(expected, actual) {
  if (!expected) return true;
  if (!actual) return false;
  const a = Buffer.from(String(expected));
  const b = Buffer.from(String(actual));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function sanitizeSubscription(sub) {
  if (!sub || typeof sub !== 'object') return null;
  const endpoint = typeof sub.endpoint === 'string' ? sub.endpoint.trim() : '';
  const p256dh = typeof sub.keys?.p256dh === 'string' ? sub.keys.p256dh.trim() : '';
  const auth = typeof sub.keys?.auth === 'string' ? sub.keys.auth.trim() : '';
  if (!endpoint.startsWith('https://') || !p256dh || !auth) return null;
  return {
    endpoint,
    ...(sub.expirationTime !== undefined ? { expirationTime: sub.expirationTime } : {}),
    keys: { p256dh, auth }
  };
}

function maskEndpoint(endpoint) {
  try {
    const u = new URL(endpoint);
    return {
      host: u.hostname,
      idSuffix: endpoint.length > 8 ? `...${endpoint.slice(-8)}` : '***'
    };
  } catch {
    return { host: 'unknown', idSuffix: '***' };
  }
}

module.exports = async function handler(req, res) {
  setCorsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  const cfg = getVapidConfig();

  if (req.method === 'GET') {
    res.status(200).json({
      ok: cfg.vapidReady,
      service: 'zad-push-relay',
      stateless: true,
      vapidReady: cfg.vapidReady,
      publicKey: cfg.vapidReady ? cfg.publicKey : '',
      requiresSecret: Boolean(cfg.relaySecret),
      message: cfg.vapidReady
        ? 'حلقة وصل الإشعارات تعمل بنجاح دون تخزين'
        : 'يرجى ضبط VAPID_PUBLIC_KEY و VAPID_PRIVATE_KEY في إعدادات Vercel'
    });
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ ok: false, error: 'Method Not Allowed' });
    return;
  }

  if (!cfg.vapidReady) {
    res.status(503).json({
      ok: false,
      error: 'مفاتيح VAPID غير مضبوطة في متغيرات البيئة على Vercel'
    });
    return;
  }

  const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
  const providedSecret =
    req.headers['x-zad-relay-secret'] ||
    (typeof body.secret === 'string' ? body.secret : '');

  if (cfg.relaySecret && !timingSafeMatch(cfg.relaySecret, providedSecret)) {
    res.status(401).json({ ok: false, error: 'رمز التحقق غير صحيح (Unauthorized)' });
    return;
  }

  const rawSubs = Array.isArray(body.subscriptions) ? body.subscriptions.slice(0, 25) : [];
  const validSubs = rawSubs.map(sanitizeSubscription).filter(Boolean);

  if (validSubs.length === 0) {
    res.status(200).json({
      ok: false,
      sent: 0,
      failed: 0,
      expiredEndpoints: [],
      results: [],
      error: 'لا توجد اشتراكات متصفح صالحة للإرسال'
    });
    return;
  }

  const rawPayload = body.payload && typeof body.payload === 'object' ? body.payload : {};
  const payloadObj = {
    type: String(rawPayload.type || 'new_message').slice(0, 40),
    eventId: String(rawPayload.eventId || `vrl_${Date.now()}`).slice(0, 80),
    title: String(rawPayload.title || 'واتساب زاد').slice(0, 120),
    body: String(rawPayload.body || 'إشعار جديد').slice(0, 240),
    url: String(rawPayload.url || '/chat').slice(0, 300),
    sentAt: String(rawPayload.sentAt || Date.now()),
    ...(rawPayload.messageId ? { messageId: String(rawPayload.messageId).slice(0, 90) } : {}),
    ...(rawPayload.conversationId ? { conversationId: String(rawPayload.conversationId).slice(0, 90) } : {}),
    ...(rawPayload.groupId ? { groupId: String(rawPayload.groupId).slice(0, 90) } : {}),
    ...(rawPayload.senderUid ? { senderUid: String(rawPayload.senderUid).slice(0, 90) } : {}),
    ...(rawPayload.senderName ? { senderName: String(rawPayload.senderName).slice(0, 80) } : {}),
    ...(rawPayload.senderPhoto ? { senderPhoto: String(rawPayload.senderPhoto).slice(0, 300) } : {}),
    ...(rawPayload.receiverUid ? { receiverUid: String(rawPayload.receiverUid).slice(0, 90) } : {}),
    ...(rawPayload.callId ? { callId: String(rawPayload.callId).slice(0, 90) } : {}),
    ...(rawPayload.callerUid ? { callerUid: String(rawPayload.callerUid).slice(0, 90) } : {}),
    ...(rawPayload.callerName ? { callerName: String(rawPayload.callerName).slice(0, 80) } : {}),
    ...(rawPayload.callerPhoto ? { callerPhoto: String(rawPayload.callerPhoto).slice(0, 300) } : {}),
    ...(rawPayload.status ? { status: String(rawPayload.status).slice(0, 40) } : {})
  };

  let payloadStr = JSON.stringify(payloadObj);
  if (Buffer.byteLength(payloadStr, 'utf8') > 3500) {
    delete payloadObj.senderPhoto;
    delete payloadObj.callerPhoto;
    payloadObj.body = payloadObj.body.slice(0, 120);
    payloadStr = JSON.stringify(payloadObj);
  }

  const opts = body.options && typeof body.options === 'object' ? body.options : {};
  const ttl = Math.max(10, Math.min(86400, Number(opts.TTL || 180) || 180));
  const allowedUrgency = ['very-low', 'low', 'normal', 'high'];
  const urgency = allowedUrgency.includes(opts.urgency) ? opts.urgency : 'high';

  try {
    webpush.setVapidDetails(cfg.subject, cfg.publicKey, cfg.privateKey);
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: `خطأ في إعداد مفاتيح VAPID: ${err?.message || 'غير معروف'}`
    });
    return;
  }

  let sent = 0;
  let failed = 0;
  const expiredEndpoints = [];
  const results = [];

  await Promise.all(
    validSubs.map(async (sub) => {
      const { host, idSuffix } = maskEndpoint(sub.endpoint);
      try {
        const pushRes = await webpush.sendNotification(sub, payloadStr, {
          TTL: ttl,
          urgency
        });
        sent++;
        results.push({
          channel: 'webpush',
          hostOrSource: host,
          idSuffix,
          ok: true,
          statusCode: Number(pushRes?.statusCode || 201)
        });
      } catch (err) {
        failed++;
        const statusCode = Number(err?.statusCode || err?.status || 0) || undefined;
        if (statusCode === 404 || statusCode === 410) {
          expiredEndpoints.push(sub.endpoint);
        }
        results.push({
          channel: 'webpush',
          hostOrSource: host,
          idSuffix,
          ok: false,
          statusCode,
          errorCode: statusCode ? `HTTP_${statusCode}` : 'WEBPUSH_ERR',
          errorReason: String(err?.body || err?.message || 'Push send failed').slice(0, 140)
        });
      }
    })
  );

  res.status(200).json({
    ok: sent > 0,
    stateless: true,
    sent,
    failed,
    expiredEndpoints,
    results
  });
};
