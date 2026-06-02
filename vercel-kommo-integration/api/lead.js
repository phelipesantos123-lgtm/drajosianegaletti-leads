/**
 * Vercel Serverless Function — Recebe lead do formulário do site
 * e cria Contato + Lead no Kommo via API v4.
 *
 * Endpoint: POST /api/lead
 * Body esperado: { name, whatsapp, email, utm_source?, utm_campaign?, gclid?, ... }
 */

const KOMMO_SUBDOMAIN = process.env.KOMMO_SUBDOMAIN;
const KOMMO_TOKEN = process.env.KOMMO_TOKEN;
const KOMMO_PIPELINE_ID = parseInt(process.env.KOMMO_PIPELINE_ID, 10);
const KOMMO_STATUS_ID = parseInt(process.env.KOMMO_STATUS_ID, 10);
const KOMMO_RESPONSIBLE_USER_ID = process.env.KOMMO_RESPONSIBLE_USER_ID
  ? parseInt(process.env.KOMMO_RESPONSIBLE_USER_ID, 10)
  : null;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

const KOMMO_BASE = `https://${KOMMO_SUBDOMAIN}.kommo.com/api/v4`;

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 5;

function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + RATE_LIMIT_WINDOW_MS;
  }
  record.count++;
  rateLimitMap.set(ip, record);
  if (rateLimitMap.size > 1000) {
    for (const [k, v] of rateLimitMap.entries()) {
      if (now > v.resetAt) rateLimitMap.delete(k);
    }
  }
  return record.count <= RATE_LIMIT_MAX_REQUESTS;
}

function sanitizeString(value, maxLen) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/[\x00-\x1F\x7F]/g, '')
    .replace(/<[^>]*>/g, '')
    .replace(/[\u202E\u200B-\u200F]/g, '')
    .trim()
    .slice(0, maxLen || 200);
}

function isValidEmail(email) {
  if (typeof email !== 'string' || email.length > 120) return false;
  return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email);
}

function isValidName(name) {
  if (typeof name !== 'string' || name.length < 2 || name.length > 80) return false;
  return /^[\p{L}\s'-]+$/u.test(name);
}

function isLikelySpam(name, whatsapp, email) {
  if (/^[a-z]{1,4}$/i.test(name)) return true;
  if (/(.)\1{4,}/.test(name)) return true;
  if (/@(mailinator|tempmail|10minutemail|guerrillamail|throwaway|yopmail|trashmail|fakeinbox)\./i.test(email)) return true;
  const digits = whatsapp.replace(/\D/g, '');
  if (/^(\d)\1+$/.test(digits)) return true;
  if (/0123456789|1234567890|9876543210/.test(digits)) return true;
  return false;
}

async function kommoFetch(path, options = {}) {
  const res = await fetch(`${KOMMO_BASE}${path}`, {
    ...options,
    headers: {
      'Authorization': `Bearer ${KOMMO_TOKEN}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!res.ok) {
    const err = new Error(`Kommo API ${res.status}`);
    err.status = res.status;
    err.payload = data;
    throw err;
  }
  return data;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const origin = req.headers.origin || req.headers.referer || '';
  if (ALLOWED_ORIGIN !== '*' && !origin.startsWith(ALLOWED_ORIGIN)) {
    if (origin) {
      console.warn('[BLOCK] Origin não autorizada:', origin);
      return res.status(403).json({ error: 'Forbidden' });
    }
  }

  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  if (!checkRateLimit(ip)) {
    console.warn('[BLOCK] Rate limit excedido:', ip);
    return res.status(429).json({ error: 'Too many requests' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;

    if (body._honeypot || body.website) {
      console.log('[BLOCK] Honeypot acionado:', ip);
      return res.status(200).json({ ok: true, lead_id: 0 });
    }

    const name = sanitizeString(body.name, 80);
    const whatsapp = sanitizeString(body.whatsapp, 25);
    const email = sanitizeString(body.email, 120).toLowerCase();

    const errors = [];
    if (!isValidName(name)) errors.push('name');
    if (whatsapp.replace(/\D/g, '').length < 10) errors.push('whatsapp');
    if (!isValidEmail(email)) errors.push('email');

    if (errors.length > 0) {
      return res.status(400).json({ error: 'Invalid payload', fields: errors });
    }

    if (isLikelySpam(name, whatsapp, email)) {
      console.log('[BLOCK] Spam detectado:', { name: name.slice(0, 20), ip });
      return res.status(200).json({ ok: true, lead_id: 0 });
    }

    const utmSource = sanitizeString(body.utm_source || '', 100).toLowerCase();
    const gclid = sanitizeString(body.gclid || '', 200);
    const fbclid = sanitizeString(body.fbclid || '', 200);
    let originTag = 'Site';
    if (utmSource.includes('google') || gclid) originTag = 'Google Ads';
    else if (utmSource.includes('facebook') || utmSource.includes('fb') || fbclid) originTag = 'Facebook Ads';
    else if (utmSource.includes('instagram') || utmSource.includes('ig')) originTag = 'Instagram Ads';

    const complexPayload = [{
      name: `Lead Dra Josiane - ${name}`,
      pipeline_id: KOMMO_PIPELINE_ID,
      status_id: KOMMO_STATUS_ID,
      ...(KOMMO_RESPONSIBLE_USER_ID && { responsible_user_id: KOMMO_RESPONSIBLE_USER_ID }),
      _embedded: {
        contacts: [{
          name: name,
          ...(KOMMO_RESPONSIBLE_USER_ID && { responsible_user_id: KOMMO_RESPONSIBLE_USER_ID }),
          custom_fields_values: [
            { field_code: 'PHONE', values: [{ value: whatsapp, enum_code: 'MOB' }] },
            { field_code: 'EMAIL', values: [{ value: email, enum_code: 'WORK' }] },
          ],
        }],
        tags: [{ name: originTag }],
      },
    }];

    const kommoResponse = await kommoFetch('/leads/complex', {
      method: 'POST',
      body: JSON.stringify(complexPayload),
    });

    const leadId = kommoResponse?.[0]?.id;

    if (leadId && (body.utm_source || body.gclid || body.utm_campaign)) {
      const noteLines = [
        '📊 Origem do lead:',
        body.utm_source   && `• Source: ${sanitizeString(body.utm_source, 100)}`,
        body.utm_medium   && `• Medium: ${sanitizeString(body.utm_medium, 100)}`,
        body.utm_campaign && `• Campanha: ${sanitizeString(body.utm_campaign, 200)}`,
        body.utm_content  && `• Anúncio: ${sanitizeString(body.utm_content, 200)}`,
        body.utm_term     && `• Palavra-chave: ${sanitizeString(body.utm_term, 200)}`,
        gclid             && `• GCLID: ${gclid}`,
        body.page_url     && `• Página: ${sanitizeString(body.page_url, 500)}`,
      ].filter(Boolean);

      try {
        await kommoFetch(`/leads/${leadId}/notes`, {
          method: 'POST',
          body: JSON.stringify([{
            note_type: 'common',
            params: { text: noteLines.join('\n') },
          }]),
        });
      } catch (noteErr) {
        console.warn('[WARN] Falha ao criar nota:', noteErr.message);
      }
    }

    console.log(`[OK] Lead criado: ${leadId} | tag: ${originTag}`);
    return res.status(200).json({ ok: true, lead_id: leadId });

  } catch (err) {
    console.error('[ERROR] Falha ao processar lead:', err.message || 'unknown');
    if (err.payload) console.error('[ERROR] Detalhes:', JSON.stringify(err.payload).slice(0, 500));
    return res.status(200).json({ ok: false });
  }
}
