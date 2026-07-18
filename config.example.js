module.exports = {
    BOT_TOKEN: "YOUR_TELEGRAM_BOT_TOKEN",
    BOT_URL: "YOUR_BOT_WEB_URL", // مثال: https://yourdomain.com
    ADMIN_ID: "YOUR_TELEGRAM_ADMIN_ID", // معرف تيليجرام الخاص بك كمسؤول
    ENCRYPTION_KEY: "YOUR_32_BYTE_ENCRYPTION_KEY", // مفتاح تشفير 32 بايت (استخدم `openssl rand -base64 32` لتوليد واحد)
    HMAC_SECRET: "YOUR_HMAC_SECRET", // مفتاح سري لـ HMAC (استخدم `openssl rand -base64 32` لتوليد واحد)
    NONCE_SECRET: "YOUR_NONCE_SECRET", // مفتاح سري لـ Nonce (استخدم `openssl rand -base64 32` لتوليد واحد)
    FREE_LOCATION_LIMIT: 3, // عدد مرات كشف الموقع المجانية لغير الـ VIP
    FREE_AUDIO_LIMIT: 2,    // عدد مرات تسجيل الصوت المجانية لغير الـ VIP
    REFERRAL_STARS: 2,      // عدد النجوم التي يحصل عليها المستخدم عند كل إحالة ناجحة
    COOLDOWN_SECONDS: 30,   // فترة التهدئة بين إنشاء الروابط (بالثواني)
};
