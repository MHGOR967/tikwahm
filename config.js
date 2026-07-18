module.exports = {
    BOT_TOKEN: process.env.BOT_TOKEN || "YOUR_BOT_TOKEN",
    ADMIN_ID: process.env.ADMIN_ID || "YOUR_ADMIN_ID",
    BOT_URL: process.env.BOT_URL || "https://yourdomain.com",
    PORT: process.env.PORT || 3000,
    ENCRYPTION_KEY: process.env.ENCRYPTION_KEY || "xK9mQ2vL8pR4wZ7nB5jF0hT3yA6cU1sE",
    ENCRYPTION_IV: process.env.ENCRYPTION_IV || "nV4kW8xP2mL6qR9j",
    HMAC_SECRET: process.env.HMAC_SECRET || "hR7kL3mN9pQ2sT5vX8zA1cE4fG6iJ0wY",
    NONCE_SECRET: process.env.NONCE_SECRET || "pL5mK8nJ3qR7sT9vW2xY4zA6bC0dE1fG",
    FREE_LOCATION_LIMIT: parseInt(process.env.FREE_LOCATION_LIMIT) || 7,
    FREE_AUDIO_LIMIT: parseInt(process.env.FREE_AUDIO_LIMIT) || 3,
    REFERRAL_STARS: parseInt(process.env.REFERRAL_STARS) || 2,
    COOLDOWN_SECONDS: parseInt(process.env.COOLDOWN_SECONDS) || 30,
    VIP_PRICE_STARS: parseInt(process.env.VIP_PRICE_STARS) || 250,
    VIP_PRICE_REFERRALS: parseInt(process.env.VIP_PRICE_REFERRALS) || 10,

};
