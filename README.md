# TikTuk Camera Bot (Node.js)

هذا المشروع هو إعادة كتابة لبوت تيليجرام TikTuk Camera Bot من PHP إلى Node.js، مع تحسينات في الأداء والميزات والأمان.

## الميزات

*   **التقاط الصور**: إنشاء روابط لالتقاط الصور من الكاميرا الأمامية أو الخلفية.
*   **كشف الموقع**: إنشاء روابط للحصول على الموقع الجغرافي الدقيق.
*   **تسجيل فيديو وصوت**: ميزات VIP لتسجيل فيديو 5 ثواني وصوت 10 ثواني.
*   **روابط مخصصة**: تحويل أي رابط إلى رابط التقاط.
*   **نظام VIP**: اشتراك VIP بالنجوم أو الإحالات.
*   **نظام الإحالة والمستويات والإنجازات**.
*   **دعم 5 لغات**: العربية، الإنجليزية، الهندية، البنغالية، الروسية.
*   **لوحة تحكم أدمن كاملة**.
*   **تشفير AES-256-CBC + HMAC**.
*   **حماية متقدمة**: Rate Limiting, Nonce, Cooldown, Security Headers.
*   **جاهز لـ Render**: يدعم Webhook و Long Polling.

---

## النشر على Render

### الخطوات:

1. **ارفع المشروع على GitHub**

2. **أنشئ Web Service جديد على Render:**
   - اذهب إلى [render.com](https://render.com) وسجّل دخول
   - اضغط "New" → "Web Service"
   - اربط حساب GitHub واختر الريبو

3. **إعدادات البناء:**
   - **Runtime**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `node index.js`

4. **أضف Environment Variables:**

   | المتغير | الوصف | مثال |
   |---------|-------|------|
   | `BOT_TOKEN` | توكن البوت من BotFather | `123456:ABC-DEF...` |
   | `ADMIN_ID` | آيدي تيليجرام حقك | `123456789` |
   | `BOT_URL` | رابط Render حقك (بدون / في النهاية) | `https://your-app.onrender.com` |
   | `USE_WEBHOOK` | فعّل وضع Webhook | `true` |
   | `ENCRYPTION_KEY` | مفتاح تشفير 32 حرف | `xK9mQ2vL8pR4wZ7nB5jF0hT3yA6cU1sE` |
   | `HMAC_SECRET` | مفتاح HMAC | `hR7kL3mN9pQ2sT5vX8zA1cE4fG6iJ0wY` |
   | `NONCE_SECRET` | مفتاح Nonce | `pL5mK8nJ3qR7sT9vW2xY4zA6bC0dE1fG` |

   **متغيرات اختيارية:**

   | المتغير | الوصف | القيمة الافتراضية |
   |---------|-------|------------------|
   | `FREE_LOCATION_LIMIT` | محاولات الموقع المجانية | `7` |
   | `FREE_AUDIO_LIMIT` | محاولات الصوت المجانية | `3` |
   | `REFERRAL_STARS` | نجوم كل إحالة | `2` |
   | `COOLDOWN_SECONDS` | فترة التهدئة | `30` |
   | `VIP_PRICE_STARS` | سعر VIP بالنجوم | `250` |
   | `VIP_PRICE_REFERRALS` | سعر VIP بالإحالات | `10` |

5. **اضغط "Create Web Service"** وانتظر النشر

### ملاحظات مهمة لـ Render:

- **USE_WEBHOOK=true** ضروري على Render لأن Long Polling ما يشتغل مع Free Tier
- **BOT_URL** لازم يكون الرابط الكامل بدون `/` في النهاية
- Render يعطيك بورت تلقائي عبر `PORT` environment variable، المشروع يقرأه تلقائياً
- البيانات (ملفات JSON) تنحذف عند كل deploy جديد على Render Free Tier. للحفاظ عليها استخدم Render Disk أو قاعدة بيانات خارجية

---

## التشغيل المحلي (للتطوير)

1. **تثبيت التبعيات:**
   ```bash
   npm install
   ```

2. **إعداد config.js:**
   عدّل القيم في `config.js` أو حط Environment Variables

3. **تشغيل البوت:**
   ```bash
   node index.js
   ```
   أو مع nodemon:
   ```bash
   npx nodemon index.js
   ```

   في الوضع المحلي يشتغل بـ Long Polling (بدون webhook).

---

## هيكلة المشروع

```
tiktuk-bot-js/
├── index.js            # الملف الرئيسي (البوت + خادم Express)
├── config.js           # الإعدادات (يقرأ من Environment Variables)
├── config.example.js   # مثال للإعدادات
├── package.json        # تبعيات المشروع
├── README.md           # هذا الملف
└── data/               # (يتم إنشاؤه تلقائياً)
    ├── users.json
    ├── settings.json
    ├── links.json
    ├── bot.log
    ├── security.log
    └── nonces_used.json
```

---

## أوامر الأدمن

| الأمر | الوصف |
|-------|-------|
| `/admin` | عرض لوحة التحكم |
| `/stats` | إحصائيات البوت |
| `/broadcast [رسالة]` | إذاعة لجميع المستخدمين |
| `/ban [آيدي]` | حظر مستخدم |
| `/unban [آيدي]` | فك حظر |
| `/addvip [آيدي]` | إضافة VIP |
| `/removevip [آيدي]` | إلغاء VIP |
| `/maintenance` | تفعيل/تعطيل الصيانة |
| `/setchannel [@channel]` | قناة إجبارية |
| `/removechannel` | إلغاء القناة |
| `/users` | قائمة المستخدمين |
| `/user [آيدي]` | معلومات مستخدم |
| `/addstars [آيدي] [عدد]` | إضافة نجوم |
| `/removestars [آيدي] [عدد]` | حذف نجوم |
| `/topusers` | أفضل المستخدمين |
| `/viplist` | قائمة VIP |
| `/setcooldown [ثواني]` | تغيير الكولداون |
| `/setvip_stars [سعر]` | سعر VIP بالنجوم |
| `/setvip_refs [عدد]` | سعر VIP بالإحالات |
| `/setreferral_stars [عدد]` | نجوم الإحالة |
| `/resetalltrials` | إعادة تعيين المحاولات المجانية |
| `/logs` | آخر السجلات |
| `/security` | سجل الأمان |

---
