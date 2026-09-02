'use strict';
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const cron = require('node-cron');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bwip = require('bwip-js');
const webpush = require('web-push');
const { posDb, dentrustDb, sessionDb, initDb, seedManager, verifyPassword, hashPassword, getSettings, ALL_PERMS, EMPLOYEE_DEFAULT_PERMS } = require('./db');

const BASE = (process.env.BASE_PATH || '').replace(/\/$/, '');
const PORT = parseInt(process.env.PORT || '5000', 10);
const DATABASE_URL = process.env.DATABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';

// ── VAPID / Web Push ─────────────────────────────────────────────────────────
const VAPID_PUBLIC_KEY  = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL       = process.env.VAPID_EMAIL || 'mailto:admin@dentrust.site';
if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
  console.log('[Push] VAPID configured ✓');
} else {
  console.warn('[Push] VAPID keys not set — push notifications disabled');
}
// قاعدة بيانات موحدة — الموقع والـ POS على نفس الـ database
const HAS_WEBSITE_DB = true;
const UPLOAD_FOLDER = path.join(__dirname, 'static', 'uploads');
const ALLOWED_EXT = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp']);

const app = express();
app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
const POS_ORIGINS = (process.env.TRUSTED_ORIGINS || 'https://dentrust-pos.onrender.com,http://localhost:5000,https://dentrust.site,https://www.dentrust.site').split(',').map(s => s.trim());
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || POS_ORIGINS.includes(origin) || /localhost/.test(origin)) return cb(null, true);
    cb(null, false);
  },
  credentials: true,
}));
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(`${BASE}/static`, express.static(path.join(__dirname, 'static')));
app.get('/favicon.ico', (req, res) => res.sendFile(path.join(__dirname, 'static', 'apple-touch-icon.png')));

const sessionStore = new PgSession({
  pool: sessionDb,
  schemaName: 'pos_data',
  tableName: 'session',
  createTableIfMissing: true,
});

app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'pos-dev-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  // secure: 'auto' (بدل ما يكون ثابت على NODE_ENV==='production') يخلي express-session
  // يقرر لكل طلب لوحده بالاعتماد على req.secure (اللي بيتحدد صح لو trust proxy مضبوط،
  // وهو مضبوط تحت). القيمة الثابتة (true دايمًا في production) كانت بتخلي الكوكي "Secure"
  // حتى لو الطلب الحقيقي اتقرا كـ http من جوه التطبيق — والمتصفح ساعتها يرفض يخزّن أو
  // يبعت الكوكي خالص، فالجلسة تضيع فورًا.
  //
  // maxAge (30 يوم): قبل كذا مكنش فيه maxAge، يعني الكوكي كانت "session cookie" —
  // بتتمسح لما "الجلسة" تتقفل. على الموبايل والتطبيق المثبت كـ PWA، كل مرة تفتح
  // التطبيق أو تعمل رفرش، المتصفح/النظام غالبًا بيتعامل معاها كجلسة جديدة ويمسح
  // الكوكي ده — فتحتاج تسجيل دخول من جديد كل مرة. دلوقتي الكوكي بتفضل محفوظة
  // فعليًا لمدة 30 يوم حتى لو قفلت المتصفح أو التطبيق.
  cookie: { httpOnly: true, sameSite: 'lax', secure: 'auto', maxAge: 30 * 24 * 60 * 60 * 1000 },
}));

// ── Rate Limiters ─────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts — try again in 15 minutes.' } });
const apiLimiter = rateLimit({ windowMs: 60*1000, max: 200, standardHeaders: true, legacyHeaders: false, skip: (req) => !!req.session?.user_id, message: { error: 'Too many requests.' } });

// ── Helpers ──────────────────────────────────────────────────────────────────

function isMgr(req) {
  if (!req.session?.user_id) return false;
  const r = req.session?.role;
  return r === 'manager' || r === 'admin' || req.session?.is_manager === true;
}
function hasPerm(req, perm) {
  if (isMgr(req)) return true;
  return !!(req.session?.permissions?.[perm]);
}

const OPEN_PATHS = new Set([`${BASE}/login`, `${BASE}/logout`, `${BASE}/sw.js`]);
const OPEN_API = [
  '/api/sync/order-placed', '/api/stats', '/api/sync/confirm-online-order',
  '/api/sync/upsert-product', '/api/sync/upsert-customer', '/api/settings',
  '/api/ai/fashion-chat', '/api/ai/fashion-chat-stream', '/api/ai/fashion-tryon',
  '/api/ai/stylebot', '/api/products',
  '/api/admin/price-tracker',
  '/api/push/vapid-public-key',
  '/api/website-orders/alerts/count',
  '/api/website-orders/alerts',
  '/api/warehouse/products',
  '/api/warehouse/transfer',
  '/api/push/subscribe',
];

function authGuard(req, res, next) {
  if (req.session?.user_id) return next();
  const p = req.path;
  if (OPEN_PATHS.has(req.originalUrl.split('?')[0])) return next();
  if (OPEN_API.some(a => p.endsWith(a) || p.includes(a))) return next();
  if (p.startsWith(`${BASE}/static/`) || p.includes('/static/')) return next();
  // أي طلب لمسار /api يعتبر طلب بيانات (fetch) مش صفحة — لازم يرجع JSON 401
  // وليس ريدايركت لصفحة الـ HTML بتاعة /login. قبل كذا كان بيعتمد على
  // req.xhr / Accept header اللي fetch() العادي مبيبعتهاش، فكان أي انقطاع
  // بسيط في الجلسة يرجّع صفحة /login (HTML) كرد على fetch، والكود اللي في
  // الواجهة كان بيحاول يعمل res.json() عليها فيكسر الصفحة بالكامل (مثال:
  // صفحة العملاء).
  const isApiPath = p.startsWith(`${BASE}/api`) || p.startsWith('/api');
  if (isApiPath || req.xhr || req.headers.accept?.includes('application/json')) {
    return res.status(401).json({ error: 'غير مصرح' });
  }
  // احفظ الصفحة المطلوبة عشان بعد الـ login نرجع ليها
  const dest = req.originalUrl;
  if (!dest.includes("/login") && !dest.includes("/logout")) { req.session.returnTo = dest; }
  return res.redirect(`${BASE}/login`);
}
app.post(`${BASE}/login`, loginLimiter);
app.use(`${BASE}/api`, apiLimiter);
app.use(authGuard);

function periodFilter(period, col) {
  if (period === 'today') return `${col}::date = CURRENT_DATE`;
  if (period === 'week')  return `${col}::date >= CURRENT_DATE - INTERVAL '7 days'`;
  if (period === 'month') return `TO_CHAR(${col}::date,'YYYY-MM') = TO_CHAR(CURRENT_DATE,'YYYY-MM')`;
  return '1=1';
}

async function renderPage(req, res, view, extra = {}) {
  const settings = await getSettings().catch(() => ({}));
  const perms = req.session?.permissions || {};
  res.render(view, {
    base: BASE,
    reqPath: req.path,
    currentUser: req.session?.user_id ? { id: req.session.user_id, username: req.session.username } : null,
    isMgr: isMgr(req),
    canEditPrices: hasPerm(req, 'edit_prices'),
    canReturn: hasPerm(req, 'process_returns'),
    userPerms: perms,
    settings,
    ...extra,
  });
}

// ── Upload ───────────────────────────────────────────────────────────────────
fs.mkdirSync(UPLOAD_FOLDER, { recursive: true });
// Images are stored as base64 data-URLs directly in the DB (image_url field).
// This avoids the Render ephemeral-filesystem problem: files in static/uploads/
// are wiped on every restart/redeploy, so product images would show 404 errors.
// Base64 in PostgreSQL survives restarts because the DB itself is persistent.
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const ext = file.originalname.split('.').pop().toLowerCase();
    const ALLOWED_MIME = new Set(['image/png','image/jpeg','image/gif','image/webp']);
    cb(null, ALLOWED_EXT.has(ext) && ALLOWED_MIME.has(file.mimetype));
  },
  limits: { fileSize: 3 * 1024 * 1024 }, // 3 MB — keeps base64 strings manageable
});

// ── Page Routes ──────────────────────────────────────────────────────────────

app.get([`${BASE}`, `${BASE}/`], (req, res) => {
  if (!hasPerm(req, 'pos')) {
    const fallbacks = [
      ['inventory',  `${BASE}/inventory`],
      ['customers',  `${BASE}/customers`],
      ['accounting', `${BASE}/accounting`],
      ['invoices',   `${BASE}/invoices`],
      ['expiry',     `${BASE}/expiry`],
    ];
    for (const [perm, url] of fallbacks) {
      if (hasPerm(req, perm)) return res.redirect(url);
    }
    return res.redirect(`${BASE}/logout`);
  }
  return renderPage(req, res, 'pos');
});
app.get(`${BASE}/inventory`, (req, res) => {
  if (!hasPerm(req, 'inventory')) return res.redirect(`${BASE}/`);
  return renderPage(req, res, 'inventory');
});
app.get(`${BASE}/customers`, (req, res) => {
  if (!hasPerm(req, 'customers')) return res.redirect(`${BASE}/`);
  res.set('Cache-Control', 'no-store');
  return renderPage(req, res, 'customers');
});
app.get(`${BASE}/accounting`, (req, res) => {
  if (!hasPerm(req, 'accounting')) return res.redirect(`${BASE}/`);
  return renderPage(req, res, 'accounting');
});
app.get(`${BASE}/invoices`, (req, res) => {
  if (!hasPerm(req, 'invoices') && !hasPerm(req, 'process_returns')) return res.redirect(`${BASE}/`);
  return renderPage(req, res, 'invoices');
});
app.get(`${BASE}/settings`, (req, res) => {
  if (!isMgr(req)) return res.redirect(`${BASE}/`);
  return renderPage(req, res, 'settings');
});
app.get(`${BASE}/barcodes`, (req, res) => {
  if (!hasPerm(req, 'inventory')) return res.redirect(`${BASE}/`);
  return renderPage(req, res, 'barcodes');
});
app.get(`${BASE}/expiry`, (req, res) => {
  if (!hasPerm(req, 'expiry')) return res.redirect(`${BASE}/`);
  return renderPage(req, res, 'expiry');
});
app.get(`${BASE}/notifications`, (req, res) => { if (!req.session?.user_id) return res.redirect(`${BASE}/login`); return renderPage(req, res, 'notifications'); });
app.get(`${BASE}/warehouse`, (req, res) => {
  if (!isMgr(req)) return res.redirect(`${BASE}/`);
  return renderPage(req, res, 'warehouse');
});
app.get(`${BASE}/product-movements`, (req, res) => {
  if (!isMgr(req)) return res.redirect(`${BASE}/`);
  return renderPage(req, res, 'product_movements');
});
app.get(`${BASE}/top-selling`, (req, res) => {
  if (!isMgr(req)) return res.redirect(`${BASE}/`);
  return renderPage(req, res, 'top_selling');
});
app.get(`${BASE}/admin/price-tracker`, (req, res) => {
  if (!isMgr(req)) return res.redirect(`${BASE}/`);
  return renderPage(req, res, 'price_tracker');
});
app.get(`${BASE}/admin/users`, (req, res) => {
  if (!isMgr(req)) return res.redirect(`${BASE}/`);
  return renderPage(req, res, 'admin_users');
});
app.get(`${BASE}/admin/attendance`, (req, res) => {
  if (!isMgr(req)) return res.redirect(`${BASE}/`);
  return renderPage(req, res, 'attendance');
});
app.get(`${BASE}/sync`, async (req, res) => {
  if (!isMgr(req)) return res.redirect(`${BASE}/`);
  const settings = await getSettings().catch(() => ({}));
  const viewData = {
    base: BASE,
    reqPath: req.path,
    currentUser: req.session?.user_id ? { id: req.session.user_id, username: req.session.username } : null,
    isMgr: true,
    canEditPrices: hasPerm(req, 'edit_prices'),
    canReturn: hasPerm(req, 'process_returns'),
    userPerms: req.session?.permissions || {},
    settings,
  };
  res.render('sync', viewData, (err, html) => {
    if (err) return res.status(500).send(String(err));
    const cleanupBtn = `<div id=\"pos-cleanup-bar\" style=\"position:fixed;bottom:24px;left:24px;z-index:9999;direction:rtl;\">
  <button onclick=\"posCleanupCats()\" id=\"pos-cleanup-btn\" style=\"background:#1a56db;color:#fff;border:none;border-radius:12px;padding:12px 22px;font-size:14px;font-family:inherit;cursor:pointer;box-shadow:0 4px 16px rgba(26,86,219,.35);\">
    🧹 تنظيف Categories المكررة
  </button>
  <div id=\"pos-cleanup-res\" style=\"margin-top:8px;padding:10px 14px;border-radius:10px;font-size:13px;font-weight:600;display:none;\"></div>
</div>
<script>
async function posCleanupCats(){
  const btn=document.getElementById('pos-cleanup-btn'),r=document.getElementById('pos-cleanup-res');
  btn.disabled=true; btn.textContent='⏳ جاري التنظيف...'; r.style.display='none';
  try{
    const resp=await fetch('${BASE}/api/sync/cleanup-website-categories',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'}});
    const d=await resp.json();
    r.style.display='block';
    if(resp.ok&&d.ok){
      r.style.background='#ecfdf5'; r.style.color='#065f46'; r.style.border='1px solid #6ee7b7';
      r.textContent=d.removed===0?'✅ مفيش categories مكررة!':'✅ تم حذف '+d.removed+' category مكررة!';
    }else{
      r.style.background='#fef2f2'; r.style.color='#991b1b'; r.style.border='1px solid #fca5a5';
      r.textContent='❌ '+(d.error||'خطأ غير متوقع');
    }
  }catch(e){ r.style.display='block'; r.textContent='❌ تعذّر الاتصال'; }
  finally{ btn.disabled=false; btn.textContent='🧹 تنظيف Categories المكررة'; }
}
</script>`;
    // inject before </body> or </html> or at the end
    if (html.includes('</body>')) {
      html = html.replace('</body>', cleanupBtn + '\n</body>');
    } else if (html.includes('</html>')) {
      html = html.replace('</html>', cleanupBtn + '\n</html>');
    } else {
      html = html + cleanupBtn;
    }
    res.send(html);
  });
});
app.get(`${BASE}/suppliers`, (req, res) => {
  if (!req.session?.user_id) return res.redirect(`${BASE}/login`);
  return renderPage(req, res, 'suppliers');
});
app.get(`${BASE}/cash-register`, (req, res) => { if (!req.session?.user_id) return res.redirect(`${BASE}/login`); return renderPage(req, res, 'cash_register'); });

app.get(`${BASE}/invoice/:sale_id`, async (req, res) => {
  try {
    const sid = parseInt(req.params.sale_id, 10);
    const { rows: [sale] } = await posDb.query(
      `SELECT s.*, c.name AS customer_name, c.phone AS customer_phone, c.address AS customer_address,
              u.username AS cashier_name
       FROM sales s
       LEFT JOIN customers c ON s.customer_id=c.id
       LEFT JOIN users u ON u.id=s.cashier_id
       WHERE s.id=$1`, [sid]
    );
    if (!sale) return res.status(404).send('الفاتورة غير موجودة');
    // Fetch items with returned quantities per item
    const { rows: items } = await posDb.query(`
      SELECT si.*,
        COALESCE(ri_sum.returned_qty, 0) AS returned_qty,
        GREATEST(0, si.quantity - COALESCE(ri_sum.returned_qty, 0)) AS net_qty
      FROM sale_items si
      LEFT JOIN (
        SELECT ri.sale_item_id, SUM(ri.quantity) AS returned_qty
        FROM return_items ri
        JOIN returns r ON r.id = ri.return_id
        WHERE r.sale_id = $1
        GROUP BY ri.sale_item_id
      ) ri_sum ON ri_sum.sale_item_id = si.id
      WHERE si.sale_id = $1
    `, [sid]);
    // Total returned amount for this sale
    const { rows: [retRow] } = await posDb.query(
      `SELECT COALESCE(SUM(total_refund),0) AS total_returned FROM returns WHERE sale_id=$1`, [sid]
    );
    const totalReturned = Math.round(parseFloat(retRow.total_returned || 0) * 100) / 100;
    const netTotal = Math.max(0, Math.round((parseFloat(sale.total_amount || 0) - totalReturned) * 100) / 100);
    const customer = sale.customer_id ? {
      name: sale.customer_name || '',
      phone: sale.customer_phone || '',
      address: sale.customer_address || '',
    } : null;
    let previousBalance = 0;
    if (['credit','split'].includes(sale.payment_method) && sale.customer_id) {
      // previousBalance = current debt minus this sale's NET credit portion (after returns)
      const { rows: [pb] } = await posDb.query('SELECT total_debt FROM customers WHERE id=$1', [sale.customer_id]);
      let saleDebtPortion = netTotal;
      if (sale.payment_method === 'split') {
        try { saleDebtPortion = parseFloat(JSON.parse(sale.payment_split || '{}').credit || 0); } catch (_) {}
      }
      previousBalance = pb ? Math.max(0, parseFloat(pb.total_debt || 0) - saleDebtPortion) : 0;
    }
    const st = await getSettings();
    res.render('invoice', { sale, items, customer, previousBalance, totalReturned, netTotal, st, base: BASE,
      canEditPrices: hasPerm(req, 'edit_prices'), isMgr: isMgr(req), cashierName: sale.cashier_name || req.session?.username || null });
  } catch (err) {
    console.error(err);
    res.status(500).send('خطأ داخلي');
  }
});

// ── Auth ─────────────────────────────────────────────────────────────────────

app.get(`${BASE}/login`, (req, res) => {
  if (req.session?.user_id) return res.redirect(`${BASE}/`);
  res.render('login', { base: BASE, error: null });
});

app.post(`${BASE}/login`, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.render('login', { base: BASE, error: 'يرجى إدخال اسم المستخدم وكلمة المرور' });
  try {
    const { rows } = await posDb.query('SELECT * FROM users WHERE username=$1 AND is_active=1', [username.trim()]);
    const user = rows[0];
    if (!user) return res.render('login', { base: BASE, error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    const ok = await verifyPassword(password, user.password_hash);
    if (!ok) return res.render('login', { base: BASE, error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    let perms = {};
    try { perms = typeof user.permissions === 'string' ? JSON.parse(user.permissions) : (user.permissions || {}); } catch (_) {}
    if (user.role === 'manager') perms = { ...ALL_PERMS };
    const returnTo = req.session.returnTo || null;
    req.session.user_id = user.id;
    req.session.username = user.username;
    req.session.role = user.role;
    req.session.permissions = perms;
    // لازم نستنى الجلسة تتحفظ في قاعدة البيانات الأول، وبعدين نعمل redirect —
    // لو عملنا redirect على طول، الصفحة الجديدة بتفتح قبل ما الجلسة تتسجل،
    // فبتلاقي "مفيش جلسة" وبتحوّل المستخدم لصفحة تسجيل الدخول تاني.
    req.session.save(async (saveErr) => {
      if (saveErr) {
        console.error('[login] session save error:', saveErr);
        return res.render('login', { base: BASE, error: 'خطأ في حفظ الجلسة، حاول مرة أخرى' });
      }
      await posDb.query(
        'INSERT INTO user_sessions (user_id, ip_address) VALUES ($1, $2)',
        [user.id, req.ip]
      ).catch(() => {});
      if (user.role !== 'manager') {
        sendPushToManagers('🔓 دخول موظف', `${user.username} سجّل دخول للتطبيق`, `${BASE}/`, 'employee-login').catch(() => {});
      }
      res.redirect(returnTo || `${BASE}/`);
    });
  } catch (err) {
    console.error(err);
    res.render('login', { base: BASE, error: 'خطأ في الخادم' });
  }
});

app.get(`${BASE}/logout`, async (req, res) => {
  if (req.session?.user_id) {
    const wasManager = req.session.role === 'manager';
    const uname = req.session.username;
    await posDb.query(
      "UPDATE user_sessions SET logout_at=NOW()::text WHERE user_id=$1 AND logout_at IS NULL",
      [req.session.user_id]
    ).catch(() => {});
    if (!wasManager) {
      sendPushToManagers('🔒 خروج موظف', `${uname} سجّل خروج من التطبيق`, `${BASE}/`, 'employee-logout').catch(() => {});
    }
  }
  req.session.destroy(() => res.redirect(`${BASE}/login`));
});

// POST — بيتبعت تلقائيًا من المتصفح لما الموظف يقفل التاب أو التطبيق (حتى لو مضغطش زر خروج)
// بيقفل الجلسة فورًا من السيرفر، وبيبلّغ المدير لو اللي قفل مش مدير
app.post(`${BASE}/api/session/close`, async (req, res) => {
  try {
    if (req.session?.user_id) {
      const wasManager = req.session.role === 'manager';
      const uname = req.session.username;
      await posDb.query(
        "UPDATE user_sessions SET logout_at=NOW()::text WHERE user_id=$1 AND logout_at IS NULL",
        [req.session.user_id]
      ).catch(() => {});
      if (!wasManager) {
        sendPushToManagers('🔒 خروج موظف', `${uname} قفل التطبيق`, `${BASE}/`, 'employee-close').catch(() => {});
      }
      req.session.destroy(() => {});
    }
  } catch (_) {}
  res.status(204).end();
});

// كان هنا سيرفر بيرجّع ملف Service Worker فاضي (بدون أي محتوى حقيقي) من مسار الجذر،
// في حين إن الـ Service Worker الحقيقي (اللي فيه كاش وإشعارات) متسجّل من مسار
// /static/sw.js في footer.ejs بـ scope='/'. الملفات الثابتة (static) متسجّلة
// بحد أقصى نطاق (scope) هو المجلد بتاعها ('/static/')، فمحاولة تسجيله بنطاق '/'
// كانت بترفض من المتصفح (SecurityError). الحل: نخدم نفس ملف sw.js الحقيقي من مسار
// الجذر مع الهيدر الصحيح، ونغيّر مسار التسجيل في footer.ejs يشاور على هنا.
app.get(`${BASE}/sw.js`, (req, res) => {
  res.setHeader('Service-Worker-Allowed', BASE || '/');
  res.sendFile(path.join(__dirname, 'static', 'sw.js'));
});

// ── API: Me / Password ───────────────────────────────────────────────────────

app.post(`${BASE}/api/users/me/password`, async (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) return res.status(400).json({ error: 'الحقول مطلوبة' });
  if (new_password.length < 4) return res.status(400).json({ error: 'كلمة المرور الجديدة قصيرة جداً' });
  try {
    const { rows } = await posDb.query('SELECT * FROM users WHERE id=$1', [req.session.user_id]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
    const ok = await verifyPassword(current_password, user.password_hash);
    if (!ok) return res.status(400).json({ error: 'كلمة المرور الحالية غير صحيحة' });
    const hash = await hashPassword(new_password);
    await posDb.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, user.id]);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── API: Users ───────────────────────────────────────────────────────────────

app.get(`${BASE}/api/users`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'مسموح للمدير فقط' });
  try {
    const { rows } = await posDb.query('SELECT id, username, role, permissions, is_active, created_at FROM users ORDER BY id');
    res.json(rows.map(u => ({ ...u, permissions: typeof u.permissions === 'string' ? JSON.parse(u.permissions || '{}') : u.permissions })));
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/users`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'مسموح للمدير فقط' });
  const d = req.body;
  try {
    const hash = await hashPassword(d.password || '1234');
    const role = d.role || 'employee';
    const perms = role === 'manager' ? { ...ALL_PERMS } : (d.permissions || { ...EMPLOYEE_DEFAULT_PERMS });
    await posDb.query(
      'INSERT INTO users (username, password_hash, role, permissions) VALUES ($1,$2,$3,$4)',
      [d.username, hash, role, JSON.stringify(perms)]
    );
    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'اسم المستخدم مسجل مسبقاً' });
    res.status(500).json({ error: 'خطأ داخلي' });
  }
});

app.put(`${BASE}/api/users/:uid`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'مسموح للمدير فقط' });
  const uid = parseInt(req.params.uid, 10);
  const d = req.body;
  try {
    if (d.password) {
      const hash = await hashPassword(d.password);
      await posDb.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hash, uid]);
    }
    if (d.role !== undefined) await posDb.query('UPDATE users SET role=$1 WHERE id=$2', [d.role, uid]);
    if (d.permissions !== undefined) await posDb.query('UPDATE users SET permissions=$1 WHERE id=$2', [JSON.stringify(d.permissions), uid]);
    if (d.is_active !== undefined) await posDb.query('UPDATE users SET is_active=$1 WHERE id=$2', [d.is_active ? 1 : 0, uid]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── API: Attendance ──────────────────────────────────────────────────────────

app.get(`${BASE}/api/attendance`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'مسموح للمدير فقط' });
  try {
    // Support both param names: date_from/date_to (legacy) and from/to (UI sends these)
    const user_id  = req.query.user_id;
    const date_from = req.query.date_from || req.query.from;
    const date_to   = req.query.date_to   || req.query.to;
    let sql = `SELECT us.*, u.username FROM user_sessions us JOIN users u ON u.id=us.user_id WHERE 1=1`;
    const params = [];
    if (user_id) { params.push(user_id); sql += ` AND us.user_id=$${params.length}`; }
    if (date_from) { params.push(date_from); sql += ` AND us.login_at::date >= $${params.length}::date`; }
    if (date_to) { params.push(date_to); sql += ` AND us.login_at::date <= $${params.length}::date`; }
    sql += ' ORDER BY us.login_at DESC LIMIT 500';
    const { rows } = await posDb.query(sql, params);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── API: Upload Image ─────────────────────────────────────────────────────────

app.post(`${BASE}/api/upload-image`, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'نوع الملف غير مدعوم أو لم يتم إرسال ملف' });
  // Upload directly to Supabase Storage if key is available — only the URL is stored in DB
  if (SUPABASE_SERVICE_KEY) {
    try {
      const ext = req.file.mimetype.split('/')[1]?.replace('jpeg','jpg') || 'jpg';
      const filename = `uploads/${uuidv4()}.${ext}`;
      const uploadUrl = `${SUPABASE_BASE}/storage/v1/object/products/${filename}`;
      const resp = await fetch(uploadUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': req.file.mimetype,
          'x-upsert': 'true',
        },
        body: req.file.buffer,
      });
      if (resp.ok) {
        const publicUrl = `${SUPABASE_BASE}/storage/v1/object/public/products/${filename}`;
        return res.json({ ok: true, url: publicUrl });
      }
    } catch (_) {}
  }
  // No Supabase key → refuse (no base64 fallback)
  res.status(500).json({ ok: false, error: 'رفع الصور غير متاح — تحقق من إعداد Supabase' });
});

// ── API: Products ─────────────────────────────────────────────────────────────

app.get(`${BASE}/api/stock-snapshot`, async (req, res) => {
  try {
    const { rows } = await posDb.query('SELECT id, quantity FROM products');
    res.json(rows);
  } catch(err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/products/generate-barcode`, async (req, res) => {
  try {
    const { randomInt } = require('crypto');
    for (let i = 0; i < 50; i++) {
      const code = String(randomInt(10000, 99999));
      const { rows } = await posDb.query('SELECT id FROM products WHERE barcode=$1', [code]);
      if (!rows.length) return res.json({ barcode: code });
    }
    res.json({ barcode: String(randomInt(100000, 999999)) });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/products/categories`, async (req, res) => {
  try {
    const { rows } = await posDb.query(
      "SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != '' ORDER BY category"
    );
    res.json(rows.map(r => r.category));
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.delete(`${BASE}/api/products/categories/:name`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  try {
    const name = decodeURIComponent(req.params.name).trim();
    await posDb.query(
      "UPDATE products SET category=NULL WHERE LOWER(TRIM(category))=LOWER($1)",
      [name]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/products/low-stock`, async (req, res) => {
  try {
    const { rows } = await posDb.query(
      'SELECT id, product_name, quantity, min_stock, category FROM products WHERE min_stock > 0 AND quantity <= min_stock ORDER BY (quantity - min_stock) ASC'
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/products/financial-summary`, async (req, res) => {
  try {
    const { rows: [r] } = await posDb.query(
      `SELECT COALESCE(SUM(purchase_price * quantity), 0) AS total_cost,
              COALESCE(SUM(sale_price * quantity), 0) AS total_revenue,
              COALESCE(SUM((sale_price - purchase_price) * quantity), 0) AS total_profit
       FROM products`
    );
    res.json(r);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/products/search`, async (req, res) => {
  // Note: uses PRODUCT_LIST_COLS defined above (no base64)
  try {
    const q = (req.query.q || '').trim();
    const cat = req.query.category;
    let sql = `SELECT ${PRODUCT_LIST_COLS} FROM products WHERE 1=1`;
    const params = [];
    if (q) { params.push(q, `%${q}%`); sql += ` AND (barcode=$${params.length-1} OR product_name ILIKE $${params.length})`; }
    if (cat) { params.push(cat); sql += ` AND category=$${params.length}`; }
    sql += ' ORDER BY product_name LIMIT 100';
    const { rows } = await posDb.query(sql, params);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// Columns for list endpoints — excludes heavy base64 image_url, adds has_image flag
const PRODUCT_LIST_COLS = `id, barcode, product_name, quantity, purchase_price, sale_price,
  expiry_date, category, min_stock, description, variants, section, checkbox_values,
  is_offer, original_price, is_best_seller, is_hidden_from_website,
  dentrust_id, (image_url IS NOT NULL AND (image_url LIKE 'http%' OR image_url LIKE 'data:%' OR image_url LIKE '/objects/%' OR image_url LIKE 'objects/%')) AS has_image,
  CASE
    WHEN image_url LIKE 'http%' THEN image_url
    WHEN image_url LIKE '/objects/%' THEN 'https://ywfunodybcqakhweuxwn.supabase.co/storage/v1/object/public' || image_url
    WHEN image_url LIKE 'objects/%'  THEN 'https://ywfunodybcqakhweuxwn.supabase.co/storage/v1/object/public/' || image_url
    ELSE NULL
  END AS image_url`;

app.get(`${BASE}/api/products`, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    let rows;
    try {
      if (q) {
        ({ rows } = await posDb.query(
          `SELECT ${PRODUCT_LIST_COLS} FROM products WHERE barcode=$1 OR product_name ILIKE $2 ORDER BY product_name`,
          [q, `%${q}%`]
        ));
      } else {
        ({ rows } = await posDb.query(`SELECT ${PRODUCT_LIST_COLS} FROM products ORDER BY product_name`));
      }
    } catch (colErr) {
      // Fallback: if column is missing, add it and use SELECT *
      await posDb.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS is_hidden_from_website BOOLEAN DEFAULT FALSE').catch(() => {});
      await posDb.query('ALTER TABLE public.products ADD COLUMN IF NOT EXISTS is_hidden_from_website BOOLEAN DEFAULT FALSE').catch(() => {});
      if (q) {
        ({ rows } = await posDb.query(`SELECT * FROM products WHERE barcode=$1 OR product_name ILIKE $2 ORDER BY product_name`, [q, `%${q}%`]));
      } else {
        ({ rows } = await posDb.query(`SELECT * FROM products ORDER BY product_name`));
      }
    }
    res.json(rows || []);
  } catch (err) {
    console.error('GET /api/products error:', err);
    res.json([]);
  }
});

// Serves just the image for a product (base64 → raw image response, cached)
app.get(`${BASE}/api/products/:pid/image`, async (req, res) => {
  try {
    const { rows: [p] } = await posDb.query('SELECT image_url FROM products WHERE id=$1', [req.params.pid]);
    if (!p?.image_url) return res.status(404).end();
    if (p.image_url.startsWith('http')) return res.redirect(p.image_url);
    // Convert relative Supabase storage paths to full public URLs
    if (p.image_url.startsWith('/objects/')) {
      return res.redirect('https://ywfunodybcqakhweuxwn.supabase.co/storage/v1/object/public' + p.image_url);
    }
    if (p.image_url.startsWith('objects/')) {
      return res.redirect('https://ywfunodybcqakhweuxwn.supabase.co/storage/v1/object/public/' + p.image_url);
    }
    // Parse base64 data URL: data:<mime>;base64,<data>
    const m = p.image_url.match(/^data:([^;]+);base64,(.+)$/);
    if (!m) return res.status(404).end();
    const buf = Buffer.from(m[2], 'base64');
    res.set('Content-Type', m[1]);
    res.set('Cache-Control', 'public, max-age=86400'); // cache 24h
    res.send(buf);
  } catch (err) { res.status(500).end(); }
});

app.post(`${BASE}/api/products`, async (req, res) => {
  const d = req.body;
  try {
    const variantsJson = d.variants ? JSON.stringify(d.variants) : null;
    const cbJson = d.checkbox_values ? JSON.stringify(d.checkbox_values) : null;
    const mainPhoto = (d.photos && d.photos[0]) || d.image_url || null;
    const { rows: [ins] } = await posDb.query(
      `INSERT INTO products (barcode, product_name, quantity, purchase_price, sale_price, expiry_date, image_url, category, min_stock, description, variants, section, checkbox_values)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`,
      [d.barcode || null, d.product_name, d.quantity || 0,
       d.purchase_price || 0, d.sale_price || 0,
       d.expiry_date || null, mainPhoto,
       d.category || null, parseInt(d.min_stock || 0, 10),
       d.description || null, variantsJson, d.section || 'dental', cbJson]
    );
    // حفظ كل الصور (حتى 5) مباشرة في public.products.photos
    if (d.photos && d.photos.length > 0) {
      posDb.query('UPDATE public.products SET photos=$1 WHERE id=$2',
        [d.photos.slice(0, 5), ins.id]).catch(() => {});
    }
    // بيرفع صورة المنتج الجديد (لو موجودة) وبينشئه على الموقع تلقائيًا
    if (HAS_WEBSITE_DB) {
      syncNewProductToDentrust(ins.id, { ...d, image_url: mainPhoto })
        .catch(err => console.error('[sync new product]', err.message));
    }
    res.status(201).json({ ok: true, id: ins.id });
  } catch (err) {
    console.error('[POST /api/products]', err.message, err.stack);
    if (err.code === '23505') return res.status(400).json({ error: 'الباركود مسجل مسبقاً' });
    res.status(500).json({ error: 'خطأ داخلي' });
  }
});

app.get(`${BASE}/api/products/:pid`, async (req, res, next) => {
  const pid = parseInt(req.params.pid, 10);
  if (isNaN(pid)) return next();
  try {
    const { rows: [p] } = await posDb.query('SELECT * FROM products WHERE id=$1', [pid]);
    if (!p) return res.status(404).json({ error: 'المنتج غير موجود' });
    // Convert relative Supabase storage paths to full public URLs
    if (p.image_url && p.image_url.startsWith('/objects/')) {
      p.image_url = 'https://ywfunodybcqakhweuxwn.supabase.co/storage/v1/object/public' + p.image_url;
    } else if (p.image_url && p.image_url.startsWith('objects/')) {
      p.image_url = 'https://ywfunodybcqakhweuxwn.supabase.co/storage/v1/object/public/' + p.image_url;
    }
    res.json(p);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── صور المنتج (حتى 5) ────────────────────────────────────────────────────────
app.get(`${BASE}/api/products/:pid/photos`, async (req, res) => {
  try {
    const { rows: [p] } = await posDb.query(
      'SELECT photos FROM public.products WHERE id=$1', [req.params.pid]
    );
    // Convert relative Supabase storage paths to full public URLs
    const photos = (p?.photos || []).map(url => {
      if (!url) return url;
      if (url.startsWith('/objects/')) return 'https://ywfunodybcqakhweuxwn.supabase.co/storage/v1/object/public' + url;
      if (url.startsWith('objects/'))  return 'https://ywfunodybcqakhweuxwn.supabase.co/storage/v1/object/public/' + url;
      return url;
    });
    res.json({ photos });
  } catch (err) { res.json({ photos: [] }); }
});

app.put(`${BASE}/api/products/:pid/photos`, async (req, res) => {
  const pid = parseInt(req.params.pid, 10);
  const photos = (req.body.photos || []).filter(Boolean).slice(0, 5);
  try {
    await posDb.query('UPDATE public.products SET photos=$1 WHERE id=$2', [photos, pid]);
    // زامن مع الموقع لو مرتبط
    if (HAS_WEBSITE_DB) {
      posDb.query('SELECT dentrust_id FROM products WHERE id=$1', [pid])
        .then(({ rows: [r] }) => {
          if (r?.dentrust_id) {
            dentrustDb.query('UPDATE products SET photos=$1 WHERE id=$2', [photos, r.dentrust_id])
              .catch(() => {});
          }
        }).catch(() => {});
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('[PUT /api/products/:pid/photos]', err.message);
    res.status(500).json({ error: 'خطأ داخلي' });
  }
});

app.put(`${BASE}/api/products/:pid`, async (req, res) => {
  const pid = parseInt(req.params.pid, 10);
  const d = req.body;
  try {
    await posDb.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS is_hidden_from_website BOOLEAN DEFAULT FALSE').catch(() => {});
    await posDb.query('ALTER TABLE public.products ADD COLUMN IF NOT EXISTS is_hidden_from_website BOOLEAN DEFAULT FALSE').catch(() => {});
    await posDb.query('ALTER TABLE public.products ADD COLUMN IF NOT EXISTS is_hidden BOOLEAN DEFAULT FALSE').catch(() => {});
    await posDb.query('ALTER TABLE public.products ADD COLUMN IF NOT EXISTS hidden BOOLEAN DEFAULT FALSE').catch(() => {});

    const variantsJson = d.variants ? (typeof d.variants === 'string' ? d.variants : JSON.stringify(d.variants)) : null;
    const cbJson = d.checkbox_values ? (typeof d.checkbox_values === 'string' ? d.checkbox_values : JSON.stringify(d.checkbox_values)) : null;
    const isHidden = d.is_hidden_from_website === true || d.is_hidden_from_website === 'true';
    const pPrice = (d.purchase_price != null && d.purchase_price !== '') ? (parseFloat(d.purchase_price) || null) : null;
    const sPrice = parseFloat(d.sale_price || 0);
    const qty = parseInt(d.quantity || 0, 10);
    const minStock = parseInt(d.min_stock || 0, 10);

    const params = [
      d.barcode || null,
      d.product_name || 'بدون اسم',
      qty,
      pPrice,
      sPrice,
      d.expiry_date || null,
      d.category || null,
      minStock,
      d.description || null,
      variantsJson,
      d.section || 'dental',
      cbJson,
      isHidden,
      pid,
    ];

    const updateQuery = `UPDATE products SET barcode=$1, product_name=$2, quantity=$3,
      purchase_price=COALESCE($4, purchase_price), sale_price=$5,
      expiry_date=$6, category=$7, min_stock=$8, description=$9, variants=$10,
      section=$11, checkbox_values=$12, is_hidden_from_website=$13 WHERE id=$14`;

    try {
      await posDb.query(updateQuery, params);
    } catch (viewErr) {
      // Fallback: update on public.products directly if view trigger has issue
      await posDb.query(
        `UPDATE public.products SET barcode=$1, product_name=$2, quantity=$3,
         purchase_price=COALESCE($4, purchase_price), sale_price=$5,
         expiry_date=$6, category=$7, min_stock=$8, description=$9, variants=$10,
         section=$11, checkbox_values=$12, is_hidden_from_website=$13 WHERE id=$14`,
        params
      ).catch(async () => {
        await posDb.query(
          `UPDATE products SET barcode=$1, product_name=$2, quantity=$3,
           purchase_price=COALESCE($4, purchase_price), sale_price=$5,
           expiry_date=$6, category=$7, min_stock=$8, description=$9, variants=$10,
           section=$11, checkbox_values=$12 WHERE id=$13`,
          params.slice(0, 12).concat([pid])
        );
      });
    }

    // Auto-sync product_cost_batches with current stock and variant levels
    if (qty <= 0) {
      await posDb.query('UPDATE product_cost_batches SET remaining_quantity = 0 WHERE product_id = $1', [pid]).catch(() => {});
    } else if (d.checkbox_values) {
      try {
        const cbv = typeof d.checkbox_values === 'string' ? JSON.parse(d.checkbox_values) : d.checkbox_values;
        for (const [key, val] of Object.entries(cbv)) {
          const vStock = (typeof val === 'object' && val !== null && val.stock != null) ? parseInt(val.stock, 10) : (typeof val === 'number' ? val : 0);
          if (vStock <= 0) {
            const shortKey = key.includes('::') ? key.split('::').pop() : key;
            await posDb.query(
              `UPDATE product_cost_batches SET remaining_quantity = 0 WHERE product_id = $1 AND (selected_option = $2 OR selected_option = $3)`,
              [pid, key, shortKey]
            ).catch(() => {});
          }
        }
      } catch (_) {}
    }

    try {
      await syncUpdateProductToDentrust(pid, d);
    } catch (syncErr) {
      console.error('[SYNC ERROR] syncUpdateProductToDentrust failed for pid', pid, ':', syncErr.message);
    }

    res.json({ ok: true, is_hidden_from_website: isHidden });
  } catch (err) {
    console.error('[PRODUCT UPDATE ERROR] pid:', pid, 'error:', err.message);
    res.status(500).json({ error: 'خطأ داخلي: ' + err.message });
  }
});

app.delete(`${BASE}/api/products/:pid`, async (req, res) => {
  const pid = parseInt(req.params.pid, 10);
  try {
    const { rows: [row] } = await posDb.query('SELECT dentrust_id FROM products WHERE id=$1', [pid]);
    await posDb.query('DELETE FROM products WHERE id=$1', [pid]);
    let syncError = null;
    if (row?.dentrust_id && DATABASE_URL) {
      try {
        const client = await dentrustDb.connect();
        try { await client.query('DELETE FROM products WHERE id=$1', [row.dentrust_id]); }
        finally { client.release(); }
      } catch (e) { syncError = e.message; }
    }
    const resp = { ok: true };
    if (syncError) resp.sync_warning = `حُذف من POS لكن فشل الحذف من DenTrust: ${syncError}`;
    res.json(resp);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/products/:pid/apply-discount`, async (req, res) => {
  const pid = parseInt(req.params.pid, 10);
  try {
    await posDb.query('UPDATE products SET sale_price=$1 WHERE id=$2', [parseFloat(req.body.new_price || 0), pid]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/products/:pid/toggle-website-visibility`, async (req, res) => {
  const pid = parseInt(req.params.pid, 10);
  try {
    await posDb.query('ALTER TABLE public.products ADD COLUMN IF NOT EXISTS is_hidden_from_website BOOLEAN DEFAULT FALSE').catch(() => {});
    await posDb.query('ALTER TABLE public.products ADD COLUMN IF NOT EXISTS is_hidden BOOLEAN DEFAULT FALSE').catch(() => {});
    await posDb.query('ALTER TABLE public.products ADD COLUMN IF NOT EXISTS hidden BOOLEAN DEFAULT FALSE').catch(() => {});
    await posDb.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS is_hidden_from_website BOOLEAN DEFAULT FALSE').catch(() => {});
    
    // Fetch product details safely with SELECT *
    let p = null;
    try {
      const { rows } = await posDb.query('SELECT * FROM public.products WHERE id=$1', [pid]);
      p = rows[0];
    } catch (_) {
      const { rows } = await posDb.query('SELECT * FROM products WHERE id=$1', [pid]);
      p = rows[0];
    }
    if (!p) return res.status(404).json({ error: 'المنتج غير موجود' });

    const isCurrentHidden = p.is_hidden_from_website === true || p.is_hidden === true || p.hidden === true;
    const newState = !isCurrentHidden;
    
    // Update local database (try both public.products and products)
    await posDb.query('UPDATE public.products SET is_hidden_from_website=$1, is_hidden=$1, hidden=$1 WHERE id=$2', [newState, pid])
      .catch(async () => {
        await posDb.query('UPDATE products SET is_hidden_from_website=$1 WHERE id=$2', [newState, pid]).catch(() => {});
      });

    // Sync with website database
    if (HAS_WEBSITE_DB) {
      try {
        const client = await dentrustDb.connect();
        try {
          await client.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS is_hidden BOOLEAN DEFAULT FALSE').catch(() => {});
          await client.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS hidden BOOLEAN DEFAULT FALSE').catch(() => {});
          await client.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS is_hidden_from_website BOOLEAN DEFAULT FALSE').catch(() => {});

          let targetWebId = p.dentrust_id;
          if (!targetWebId) {
            const { rows: [found] } = await client.query(
              'SELECT id FROM products WHERE LOWER(TRIM(name)) = LOWER(TRIM($1)) OR (barcode IS NOT NULL AND barcode = $2 AND barcode != \'\') LIMIT 1',
              [p.product_name || '', p.barcode || '']
            ).catch(() => ({ rows: [] }));
            if (found) {
              targetWebId = found.id;
              await posDb.query('UPDATE public.products SET dentrust_id=$1 WHERE id=$2', [targetWebId, pid]).catch(() => {});
              await posDb.query('UPDATE products SET dentrust_id=$1 WHERE id=$2', [targetWebId, pid]).catch(() => {});
            }
          }

          if (targetWebId) {
            await client.query(
              'UPDATE products SET is_hidden=$1, hidden=$1, is_hidden_from_website=$1 WHERE id=$2',
              [newState, targetWebId]
            ).catch(() => {});
            await client.query('UPDATE products SET is_active=$1 WHERE id=$2', [!newState, targetWebId]).catch(() => {});
          }
        } finally {
          client.release();
        }
      } catch (syncErr) {
        console.error('[TOGGLE VISIBILITY SYNC ERROR]', syncErr.message);
      }
    }

    res.json({ ok: true, is_hidden_from_website: newState });
  } catch (err) {
    console.error('Toggle visibility error:', err);
    res.status(500).json({ error: 'خطأ داخلي: ' + err.message });
  }
});

app.post(`${BASE}/api/products/:pid/mark-damaged`, async (req, res) => {
  const pid = parseInt(req.params.pid, 10);
  try {
    const { rows: [prod] } = await posDb.query('SELECT * FROM products WHERE id=$1', [pid]);
    if (prod) {
      const loss = parseFloat(prod.quantity || 0) * parseFloat(prod.purchase_price || 0);
      await posDb.query('UPDATE products SET quantity=0 WHERE id=$1', [pid]);
      await posDb.query(
        "INSERT INTO expenses (title, amount, date) VALUES ($1,$2,CURRENT_DATE::text)",
        [`خسارة/تلف: ${prod.product_name}`, loss]
      );
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.put(`${BASE}/api/products/:pid/supplier`, async (req, res) => {
  const pid = parseInt(req.params.pid, 10);
  try {
    await posDb.query('UPDATE products SET supplier_id=$1 WHERE id=$2', [req.body.supplier_id || null, pid]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── API: Barcode image ────────────────────────────────────────────────────────

app.get(`${BASE}/api/barcode/:text`, async (req, res) => {
  try {
    const png = await bwip.toBuffer({
      bcid: 'code128', text: req.params.text,
      scale: 3, height: 12, includetext: true, textxalign: 'center',
    });
    res.set('Content-Type', 'image/png').send(png);
  } catch (err) { res.status(400).send('Invalid barcode'); }
});

// ── API: Cash Sessions ────────────────────────────────────────────────────────

app.get(`${BASE}/api/cash-sessions`, async (req, res) => {
  try {
    const { rows } = await posDb.query(
      'SELECT cs.*, u.username as cashier_name FROM cash_sessions cs LEFT JOIN users u ON u.id=cs.cashier_id ORDER BY cs.id DESC LIMIT 30'
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/cash-sessions`, async (req, res) => {
  const d = req.body;
  if (d.opening_balance == null || d.opening_instapay == null) {
    return res.status(400).json({ error: 'يرجى إدخال رصيد الخزينة النقدي ورصيد انستا باي' });
  }
  try {
    const { rows: [open] } = await posDb.query(
      "SELECT id FROM cash_sessions WHERE status='open' AND cashier_id=$1", [req.session.user_id]
    );
    if (open) return res.status(400).json({ error: 'يوجد جلسة مفتوحة بالفعل', session_id: open.id });
    const now = new Date().toISOString();
    const today = now.substring(0, 10);
    const { rows: [ins] } = await posDb.query(
      "INSERT INTO cash_sessions (cashier_id, date, opening_balance, opening_instapay, status, opened_at) VALUES ($1,$2,$3,$4,'open',$5) RETURNING id",
      [req.session.user_id, today, parseFloat(d.opening_balance), parseFloat(d.opening_instapay), now]
    );
    res.status(201).json({ ok: true, session_id: ins.id });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.put(`${BASE}/api/cash-sessions/:sid`, async (req, res) => {
  const sid = parseInt(req.params.sid, 10);
  const d = req.body;
  try {
    const { rows: [sess] } = await posDb.query('SELECT * FROM cash_sessions WHERE id=$1', [sid]);
    if (!sess) return res.status(404).json({ error: 'جلسة غير موجودة' });
    const closing = parseFloat(d.closing_balance || 0);
    const instapayCl = parseFloat(d.instapay_closing || 0);
    const notes = d.notes || '';
    const sessDate = sess.date || new Date().toISOString().substring(0, 10);

    const { rows: [cashRow] } = await posDb.query(
      "SELECT COALESCE(SUM(total_amount),0) as total FROM sales WHERE (payment_method='cash' OR payment_method='naqdi') AND date::date=$1::date",
      [sessDate]
    );
    let cashSales = parseFloat(cashRow?.total || 0);
    let instapaySales = 0;

    const { rows: [instRow] } = await posDb.query(
      "SELECT COALESCE(SUM(total_amount),0) as total FROM sales WHERE payment_method='instapay' AND date::date=$1::date",
      [sessDate]
    );
    instapaySales = parseFloat(instRow?.total || 0);

    const { rows: splitRows } = await posDb.query(
      "SELECT payment_split FROM sales WHERE payment_method='split' AND date::date=$1::date", [sessDate]
    );
    let splitCash = 0, splitInsta = 0;
    for (const row of splitRows) {
      try { const sp = JSON.parse(row.payment_split || '{}'); splitCash += parseFloat(sp.cash || 0); splitInsta += parseFloat(sp.instapay || 0); } catch (_) {}
    }
    cashSales += splitCash; instapaySales += splitInsta;

    const { rows: creditRows } = await posDb.query(
      "SELECT payment_split FROM sales WHERE payment_method='credit' AND payment_split IS NOT NULL AND date::date=$1::date", [sessDate]
    );
    for (const row of creditRows) {
      try { const ps = JSON.parse(row.payment_split || '{}'); cashSales += parseFloat(ps.cash || 0); instapaySales += parseFloat(ps.instapay || 0); } catch (_) {}
    }

    const { rows: [dcRow] } = await posDb.query("SELECT COALESCE(SUM(cash_amount),0) as t FROM customer_payments WHERE date::date=$1::date", [sessDate]);
    const { rows: [diRow] } = await posDb.query("SELECT COALESCE(SUM(instapay_amount),0) as t FROM customer_payments WHERE date::date=$1::date", [sessDate]);
    cashSales += parseFloat(dcRow?.t || 0); instapaySales += parseFloat(diRow?.t || 0);

    const expectedCash = parseFloat(sess.opening_balance || 0) + cashSales;
    const expectedInsta = parseFloat(sess.opening_instapay || 0) + instapaySales;
    const discCash = closing - expectedCash;
    const discInsta = instapayCl - expectedInsta;

    await posDb.query(
      `UPDATE cash_sessions SET closing_balance=$1, expected_cash=$2, discrepancy=$3,
       instapay_sales=$4, instapay_closing=$5, instapay_discrepancy=$6,
       cash_sales=$7, status='closed', notes=$8, closed_at=$9 WHERE id=$10`,
      [closing, expectedCash, discCash, instapaySales, instapayCl, discInsta, cashSales, notes, new Date().toISOString(), sid]
    );
    res.json({ ok: true, expected_cash: expectedCash, discrepancy_cash: discCash, instapay_sales: instapaySales, expected_instapay: expectedInsta, discrepancy_instapay: discInsta });
  } catch (err) { console.error(err); res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── API: Sales ────────────────────────────────────────────────────────────────

app.post(`${BASE}/api/sales`, async (req, res) => {
  const d = req.body;
  const items = d.items || [];
  const total = parseFloat(d.total_amount || 0);
  const method = d.payment_method || 'cash';
  const customerId = d.customer_id || null;
  const customerNameFree = (d.customer_name || '').trim() || null;
  const splitJson = d.payment_split ? JSON.stringify(d.payment_split) : null;

  if (!customerId && !customerNameFree) {
    return res.status(400).json({ error: 'لازم تدخل اسم العميل قبل إتمام الفاتورة' });
  }

  const client = await posDb.connect();
  try {
    await client.query('BEGIN');
    for (const item of items) {
      const { rows: [prod] } = await client.query('SELECT quantity, product_name, sale_price, variants, checkbox_values FROM products WHERE id=$1', [item.product_id]);
      if (item.product_id) {
        if (!prod) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: `المنتج "${item.product_name || '#' + item.product_id}" غير موجود في قاعدة البيانات` });
        }
        if (prod.quantity <= 0) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: `المنتج "${prod.product_name}" غير متوفر في المخزون (الكمية: 0)` });
        }
        if (prod.quantity < item.quantity) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: `الكمية المطلوبة (${item.quantity}) تتجاوز المخزون المتاح (${prod.quantity}) للمنتج: ${prod.product_name}` });
        }
        // ── Variant-level stock validation ──────────────────────────────────
        const _selSzChk = item._size || item.selected_size;
        if (_selSzChk && prod.variants) {
          try {
            const _vObj2 = typeof prod.variants === 'string' ? JSON.parse(prod.variants) : prod.variants;
            const _vSz   = (_vObj2?.sizes || []).find(s => s.label === _selSzChk);
            if (_vSz !== undefined && _vSz.qty < item.quantity) {
              await client.query('ROLLBACK');
              return res.status(400).json({
                error: `الكمية المطلوبة (${item.quantity}) تتجاوز مخزون المقاس "${_selSzChk}" المتاح (${_vSz.qty}) للمنتج: ${prod.product_name}`
              });
            }
          } catch (_e) {}
        }
        // ── Checkbox-option stock validation ─────────────────────────────────
        const _selCbChk = item.selected_option || item.selectedOption || item._checkbox;
        if (_selCbChk && prod.checkbox_values) {
          try {
            const _cbv2 = typeof prod.checkbox_values === 'string' ? JSON.parse(prod.checkbox_values) : prod.checkbox_values;
            const _cbOpt = _cbv2?.[_selCbChk];
            if (_cbOpt && typeof _cbOpt === 'object' && _cbOpt.stock != null && _cbOpt.stock < item.quantity) {
              await client.query('ROLLBACK');
              return res.status(400).json({
                error: `الكمية المطلوبة (${item.quantity}) تتجاوز المخزون المتاح (${_cbOpt.stock}) للخيار "${_selCbChk.split('::').pop()}" من المنتج: ${prod.product_name}`
              });
            }
          } catch (_e2) {}
        }
      }
      if (prod && !hasPerm(req, 'edit_prices')) {
        const dbPrice = parseFloat(prod.sale_price || 0);
        const reqPrice = parseFloat(item.unit_price || dbPrice);
        if (Math.abs(reqPrice - dbPrice) > 0.005) {
          await client.query('ROLLBACK');
          return res.status(403).json({ error: 'ليس لديك صلاحية تعديل الأسعار' });
        }
      }
    }
    const amtReceived    = d.amount_received != null ? parseFloat(d.amount_received) : null;
    const changeDue      = d.change_due != null ? parseFloat(d.change_due) : null;
    const discountAmount = d.discount_amount != null ? parseFloat(d.discount_amount) : 0;
    const deliveryAmount = d.delivery_amount != null ? parseFloat(d.delivery_amount) : 0;
    const { rows: [sale] } = await client.query(
      `INSERT INTO sales (total_amount, payment_method, customer_id, cashier_id, customer_name, amount_received, change_due, payment_split, discount_amount, delivery_amount)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
      [total, method, customerId, req.session.user_id, customerNameFree, amtReceived, changeDue, splitJson, discountAmount, deliveryAmount]
    );
    const saleId = sale.id;
    const lowStockItemIds = [];
    for (const item of items) {
      const { rows: [snap] } = await client.query('SELECT purchase_price FROM products WHERE id=$1', [item.product_id]);
      const snapPp = snap ? parseFloat(snap.purchase_price || 0) : 0;
      const selOptSaved = item.selected_option || item.selectedOption || item._checkbox || item._size || item.selected_size || null;
      await client.query(
        `INSERT INTO sale_items (sale_id, product_id, product_name, quantity, unit_price, snapshot_purchase_price, snapshot_unit_price, selected_option)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [saleId, item.product_id, item.product_name, item.quantity, item.unit_price, snapPp, parseFloat(item.unit_price), selOptSaved]
      );
      const stockUpdate = await client.query(
        'UPDATE products SET quantity = GREATEST(0, quantity - $1) WHERE id=$2 AND quantity >= $1 RETURNING id, quantity',
        [item.quantity, item.product_id]
      );
      if (!stockUpdate.rows.length) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: `المنتج "${item.product_name}" نفد من المخزن أو الكمية غير كافية` });
      }
      const newQty = parseInt(stockUpdate.rows[0].quantity || 0, 10);
      const prevQty = newQty + parseInt(item.quantity || 0, 10);

      // Deduct per-variant qty from variants JSON if a specific size was sold
      const selSize = item._size || item.selected_size;
      if (selSize) {
        try {
          const { rows: [pv] } = await client.query('SELECT variants FROM products WHERE id=$1', [item.product_id]);
          if (pv?.variants) {
            const vObj = typeof pv.variants === 'string' ? JSON.parse(pv.variants) : { ...pv.variants };
            const sIdx = (vObj.sizes || []).findIndex(s => s.label === selSize);
            if (sIdx >= 0) {
              vObj.sizes[sIdx].qty = Math.max(0, (vObj.sizes[sIdx].qty || 0) - item.quantity);
              await client.query('UPDATE products SET variants=$1 WHERE id=$2', [JSON.stringify(vObj), item.product_id]);
            }
          }
        } catch(_) {}
      }
      // Deduct checkbox_values stock if a checkbox option was sold
      const selCheckbox = item.selected_option || item.selectedOption || item._checkbox;
      if (selCheckbox) {
        try {
          const { rows: [pc] } = await client.query('SELECT checkbox_values FROM products WHERE id=$1', [item.product_id]);
          if (pc?.checkbox_values) {
            const cbv = typeof pc.checkbox_values === 'string' ? JSON.parse(pc.checkbox_values) : { ...pc.checkbox_values };
            if (cbv[selCheckbox] && typeof cbv[selCheckbox] === 'object' && cbv[selCheckbox].stock != null) {
              cbv[selCheckbox].stock = Math.max(0, cbv[selCheckbox].stock - item.quantity);
              // Recalculate main quantity as the sum of all remaining checkbox stocks.
              // Without this, the earlier GREATEST(0, quantity-N) can drive quantity to 0
              // while individual option stocks still have items, causing a false "نفذ".
              const totalCbQty = Object.values(cbv).reduce((sum, v) =>
                sum + (typeof v === 'object' && v.stock != null ? Math.max(0, v.stock) : 0), 0);
              await client.query(
                'UPDATE products SET quantity=$1, checkbox_values=$2 WHERE id=$3',
                [totalCbQty, JSON.stringify(cbv), item.product_id]
              );
            }
          }
        } catch(_) {}
      }

      // Log movement to audit log
      await logProductMovement({
        productId: item.product_id,
        productName: item.product_name,
        movementType: 'sale',
        referenceId: saleId,
        referenceTitle: `فاتورة مبيعات #${saleId}`,
        selectedOption: selOptSaved,
        quantityChange: -Math.abs(parseInt(item.quantity || 0, 10)),
        quantityBefore: prevQty,
        quantityAfter: newQty,
        unitPrice: parseFloat(item.unit_price || 0),
        unitCost: snapPp,
        userName: req.session?.username || 'كاشير',
        notes: `مبيعات للعميل: ${customerNameFree || 'نقدي'}`
      }, client);
      lowStockItemIds.push(item.product_id);
    }
    if (method === 'credit' && customerId) {
      const debtAmount = total - (amtReceived || 0);
      if (debtAmount > 0) await client.query('UPDATE customers SET total_debt = total_debt + $1 WHERE id=$2', [debtAmount, customerId]);
    } else if (method === 'split' && customerId && d.payment_split) {
      const creditPortion = parseFloat(d.payment_split.credit || 0);
      if (creditPortion > 0) await client.query('UPDATE customers SET total_debt = total_debt + $1 WHERE id=$2', [creditPortion, customerId]);
    }
    await client.query('COMMIT');

    let lowStock = [];
    if (lowStockItemIds.length > 0) {
      const placeholders = lowStockItemIds.map((_, i) => `$${i + 1}`).join(',');
      const { rows: lsRows } = await posDb.query(
        `SELECT id, product_name, quantity, min_stock FROM products WHERE min_stock > 0 AND quantity <= min_stock AND id IN (${placeholders})`,
        lowStockItemIds
      );
      lowStock = lsRows.map(r => ({ id: r.id, name: r.product_name, qty: r.quantity, min: r.min_stock }));
    }
    if (lowStock.length > 0) sendLowStockPush(lowStock).catch(() => {});
    syncProductsNow(items.map(i => i.product_id).filter(Boolean)).catch(() => {});
    if (customerId) {
      const splitParsed = splitJson ? JSON.parse(splitJson) : null;
      syncSaleToSupabase(customerId, customerNameFree, saleId, total, method, splitParsed, items).catch(async (err) => {
        // لو Supabase كان offline، نحفظ في sync_queue ونحاول تاني
        await posDb.query(
          `INSERT INTO sync_queue (type, payload, attempts) VALUES ('sale_to_supabase', $1, 0)`,
          [JSON.stringify({ posCustomerId: customerId, posCustomerName: customerNameFree, saleId, totalAmount: total, paymentMethod: method, splitData: splitParsed, items })]
        ).catch(() => {});
      });
    }
    res.status(201).json({ ok: true, sale_id: saleId, low_stock: lowStock });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(err);
    res.status(500).json({ error: 'خطأ داخلي' });
  } finally { client.release(); }
});

app.get(`${BASE}/api/sales`, async (req, res) => {
  try {
    const { rows } = await posDb.query(
      `SELECT s.*, c.name as customer_name FROM sales s LEFT JOIN customers c ON s.customer_id=c.id ORDER BY s.date DESC LIMIT 100`
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sales/:sid/mark-credit-paid`, async (req, res) => {
  const sid = parseInt(req.params.sid, 10);
  const d = req.body;
  const cashAmount = parseFloat(d.cash_amount || 0);
  const instapayAmount = parseFloat(d.instapay_amount || 0);
  try {
    const { rows: [sale] } = await posDb.query('SELECT * FROM sales WHERE id=$1', [sid]);
    if (!sale) return res.status(404).json({ error: 'الفاتورة غير موجودة' });
    if (sale.credit_paid) return res.json({ ok: true, already_paid: true });
    if (!['credit', 'split'].includes(sale.payment_method)) return res.status(400).json({ error: 'الفاتورة ليست آجل' });
    let debtAmount;
    if (sale.payment_method === 'split') {
      const splitData = JSON.parse(sale.payment_split || '{}');
      debtAmount = parseFloat(splitData.credit || 0);
    } else {
      // آجل كامل: الدين = إجمالي الفاتورة ناقص ما دُفع وقت الشراء
      debtAmount = parseFloat(sale.total_amount || 0) - parseFloat(sale.amount_received || 0);
    }
    await posDb.query('UPDATE sales SET credit_paid=true WHERE id=$1', [sid]);
    if (debtAmount > 0 && sale.customer_id) {
      await posDb.query('UPDATE customers SET total_debt = GREATEST(0, total_debt - $1) WHERE id=$2', [debtAmount, sale.customer_id]);
    }
    if ((cashAmount + instapayAmount) > 0 && sale.customer_id) {
      await posDb.query(
        'INSERT INTO customer_payments (customer_id, amount, cash_amount, instapay_amount, note) VALUES ($1,$2,$3,$4,$5)',
        [sale.customer_id, cashAmount + instapayAmount, cashAmount, instapayAmount, `وارد مديونية — فاتورة #${sid}`]
      );
    }
    res.json({ ok: true, debt_reduced: Math.round(debtAmount * 100) / 100 });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.delete(`${BASE}/api/sales/:sid`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'مسموح للمدير فقط' });
  const sid = parseInt(req.params.sid, 10);
  try {
    const { rows: [sale] } = await posDb.query('SELECT * FROM sales WHERE id=$1', [sid]);
    if (!sale) return res.status(404).json({ error: 'الفاتورة غير موجودة' });
    const { rows: items } = await posDb.query(
      `SELECT si.product_id, si.product_name, si.quantity, si.selected_option, COALESCE(ri_sum.returned,0) AS returned
       FROM sale_items si
       LEFT JOIN (SELECT ri.sale_item_id, SUM(ri.quantity) AS returned FROM return_items ri
                  JOIN returns r ON r.id=ri.return_id WHERE r.sale_id=$1 GROUP BY ri.sale_item_id) ri_sum
         ON ri_sum.sale_item_id=si.id WHERE si.sale_id=$1`, [sid]
    );
    for (const item of items) {
      const netRestore = parseInt(item.quantity || 0, 10) - parseInt(item.returned || 0, 10);
      if (netRestore <= 0) continue;

      let pid = item.product_id;
      if (!pid && item.product_name) {
        const { rows: [pn] } = await posDb.query('SELECT id FROM products WHERE LOWER(product_name)=LOWER($1) LIMIT 1', [item.product_name]);
        if (pn) pid = pn.id;
      }
      if (!pid) continue;

      const { rows: [prod] } = await posDb.query('SELECT quantity, checkbox_values, variants FROM products WHERE id=$1', [pid]);
      if (!prod) continue;

      let hasOptionRestored = false;

      // 1. Restore checkbox_values stock if variant option tracked
      if (item.selected_option && prod.checkbox_values) {
        try {
          const cbv = typeof prod.checkbox_values === 'string' ? JSON.parse(prod.checkbox_values) : { ...prod.checkbox_values };
          const optClean = item.selected_option.trim().toLowerCase();
          const cbKey = Object.keys(cbv).find(k => {
            const kClean = k.trim().toLowerCase();
            return kClean === optClean || kClean.endsWith('::' + optClean) || kClean.split('::').pop().trim() === optClean;
          });

          if (cbKey && typeof cbv[cbKey] === 'object' && cbv[cbKey].stock != null) {
            cbv[cbKey].stock = (parseInt(cbv[cbKey].stock, 10) || 0) + netRestore;
            cbv[cbKey].disabled = false;
            const totalCbQty = Object.values(cbv).reduce((sum, v) =>
              sum + (typeof v === 'object' && v.stock != null ? Math.max(0, parseInt(v.stock, 10)) : 0), 0);
            await posDb.query(
              'UPDATE products SET quantity=$1, checkbox_values=$2 WHERE id=$3',
              [totalCbQty, JSON.stringify(cbv), pid]
            );
            hasOptionRestored = true;
          }
        } catch (_e) {}
      }

      // 2. Restore variants JSON sizes if tracked
      if (!hasOptionRestored && item.selected_option && prod.variants) {
        try {
          const vObj = typeof prod.variants === 'string' ? JSON.parse(prod.variants) : { ...prod.variants };
          const optClean = item.selected_option.trim().toLowerCase();
          const sIdx = (vObj.sizes || []).findIndex(s => {
            const lClean = (s.label || '').trim().toLowerCase();
            return lClean === optClean || lClean.endsWith('::' + optClean) || lClean.split('::').pop().trim() === optClean;
          });
          if (sIdx >= 0) {
            vObj.sizes[sIdx].qty = (parseInt(vObj.sizes[sIdx].qty, 10) || 0) + netRestore;
            await posDb.query('UPDATE products SET quantity = quantity + $1, variants=$2 WHERE id=$3', [netRestore, JSON.stringify(vObj), pid]);
            hasOptionRestored = true;
          }
        } catch (_e) {}
      }

      // 3. Simple Product stock restoration
      if (!hasOptionRestored) {
        await posDb.query('UPDATE products SET quantity = quantity + $1 WHERE id=$2', [netRestore, pid]);
      }

      // Log movement to audit log
      await logProductMovement({
        productId: pid,
        productName: item.product_name || 'صنف',
        movementType: 'adjustment',
        referenceId: sid,
        referenceTitle: `إلغاء وحذف فاتورة #${sid}`,
        selectedOption: item.selected_option || null,
        quantityChange: netRestore,
        quantityBefore: parseInt(prod.quantity || 0, 10),
        quantityAfter: parseInt(prod.quantity || 0, 10) + netRestore,
        userName: req.session?.username || 'المدير',
        notes: `استرجاع رصيد تلقائي عند حذف الفاتورة`
      }).catch(() => {});
    }
    if (sale.customer_id && ['credit','split'].includes(sale.payment_method) && !sale.credit_paid) {
      const { rows: [rr] } = await posDb.query("SELECT COALESCE(SUM(total_refund),0) AS t FROM returns WHERE sale_id=$1", [sid]);
      let netDebt;
      if (sale.payment_method === 'split') {
        const sp = JSON.parse(sale.payment_split || '{}');
        netDebt = Math.max(0, parseFloat(sp.credit || 0) - parseFloat(rr?.t || 0));
      } else {
        netDebt = Math.max(0, parseFloat(sale.total_amount) - parseFloat(sale.amount_received || 0) - parseFloat(rr?.t || 0));
      }
      if (netDebt > 0) await posDb.query('UPDATE customers SET total_debt = GREATEST(0, total_debt - $1) WHERE id=$2', [netDebt, sale.customer_id]);
    }
    // Delete expenses associated with returns of this sale
    try {
      const { rows: saleReturns } = await posDb.query('SELECT id, total_refund FROM returns WHERE sale_id=$1', [sid]);
      for (const ret of saleReturns) {
        await posDb.query(
          `DELETE FROM expenses WHERE id = (
             SELECT id FROM expenses WHERE (title LIKE $1 OR title LIKE $2) AND amount=$3 ORDER BY id DESC LIMIT 1
           )`,
          [`مردود #${ret.id} %`, `مردود فاتورة #${sid}%`, ret.total_refund]
        );
      }
    } catch (_) {}
    await posDb.query('DELETE FROM return_items WHERE return_id IN (SELECT id FROM returns WHERE sale_id=$1)', [sid]);
    await posDb.query('DELETE FROM returns WHERE sale_id=$1', [sid]);
    await posDb.query('DELETE FROM sale_items WHERE sale_id=$1', [sid]);
    await posDb.query('DELETE FROM sales WHERE id=$1', [sid]);
    // Also delete linked online order from website DB and POS alerts
    if (sale.dentrust_order_id) {
      try {
        const dtClient = await dentrustDb.connect();
        try { await dtClient.query('DELETE FROM orders WHERE id=$1', [sale.dentrust_order_id]); }
        finally { dtClient.release(); }
      } catch (_) {}
      try { await posDb.query('DELETE FROM website_order_alerts WHERE dentrust_order_id=$1', [String(sale.dentrust_order_id)]); } catch (_) {}
    }
    const restoredPids = items.map(i => i.product_id).filter(Boolean);
    if (restoredPids.length) syncProductsNow(restoredPids).catch(() => {});
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── API: Customers ────────────────────────────────────────────────────────────

app.get(`${BASE}/api/customers`, async (req, res) => {
  try {
    const { rows } = await posDb.query(`
      SELECT c.*,
        COALESCE(SUM(CASE WHEN s.payment_method != 'refund' THEN s.total_amount ELSE 0 END), 0) AS total_purchases
      FROM customers c
      LEFT JOIN sales s ON s.customer_id = c.id
      GROUP BY c.id
      ORDER BY total_purchases DESC, c.name ASC
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/customers`, async (req, res) => {
  const d = req.body;
  if (!d.name) return res.status(400).json({ error: 'الاسم مطلوب' });
  try {
    // Check duplicate phone before inserting
    if (d.phone && d.phone.trim()) {
      const { rows: [existing] } = await posDb.query(
        'SELECT id, name FROM customers WHERE phone=$1', [d.phone.trim()]
      );
      if (existing) {
        return res.status(409).json({
          error: `رقم الهاتف موجود بالفعل باسم "${existing.name}"`,
          existing: { id: existing.id, name: existing.name }
        });
      }
    }
    await posDb.query(
      'INSERT INTO customers (name, phone, address, installment_plan) VALUES ($1,$2,$3,$4)',
      [d.name, d.phone?.trim() || '', d.address || '', d.installment_plan || '']
    );
    // ── Sync new customer to website (Supabase) ──────────────────────────────
    try {
      const { rows: [newCust] } = await posDb.query('SELECT id, name, phone FROM customers WHERE phone=$1', [d.phone?.trim() || '']);
      if (newCust) syncCustomerToSupabase(newCust).catch(() => {});
    } catch (syncErr) {
      console.error('[sync] POS→Supabase customer sync failed:', syncErr.message);
    }
    // ────────────────────────────────────────────────────────────────────────
    res.status(201).json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/customers/:cid/orders`, async (req, res) => {
  const cid = parseInt(req.params.cid, 10);
  try {
    const { rows: sales } = await posDb.query(
      `SELECT s.*, CASE WHEN s.payment_method IN ('credit','split') THEN 0 ELSE 1 END as sort_key
       FROM sales s WHERE s.customer_id=$1 ORDER BY sort_key ASC, s.date DESC`, [cid]
    );
    const result = [];
    for (const s of sales) {
      const { rows: saleItems } = await posDb.query('SELECT * FROM sale_items WHERE sale_id=$1', [s.id]);
      result.push({ ...s, items: saleItems });
    }
    res.json(result);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/customers/:cid/pay`, async (req, res) => {
  const cid = parseInt(req.params.cid, 10);
  const d = req.body;
  let amount = parseFloat(d.amount || 0);
  let cashAmt = parseFloat(d.cash_amount || 0);
  let instaAmt = parseFloat(d.instapay_amount || 0);
  if (cashAmt + instaAmt === 0 && amount > 0) cashAmt = amount;
  try {
    await posDb.query('UPDATE customers SET total_debt = GREATEST(0, total_debt - $1) WHERE id=$2', [amount, cid]);
    await posDb.query(
      'INSERT INTO customer_payments (customer_id, amount, cash_amount, instapay_amount, note) VALUES ($1,$2,$3,$4,$5)',
      [cid, amount, cashAmt, instaAmt, d.note || '']
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/customers/:cid/payments`, async (req, res) => {
  const cid = parseInt(req.params.cid, 10);
  try {
    const { rows } = await posDb.query('SELECT * FROM customer_payments WHERE customer_id=$1 ORDER BY date DESC', [cid]);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/customers/:cid/statement`, async (req, res) => {
  const cid = parseInt(req.params.cid, 10);
  try {
    const { rows: [c] } = await posDb.query('SELECT * FROM customers WHERE id=$1', [cid]);
    if (!c) return res.status(404).json({ error: 'العميل غير موجود' });
    const { rows: creditSales } = await posDb.query(
      "SELECT total_amount, amount_received, payment_method, payment_split FROM sales WHERE customer_id=$1 AND payment_method IN ('credit','split')", [cid]
    );
    let totalInvoiced = 0;
    for (const s of creditSales) {
      if (s.payment_method === 'split') {
        try { totalInvoiced += parseFloat(JSON.parse(s.payment_split || '{}').credit || 0); } catch (_) {}
      } else {
        totalInvoiced += parseFloat(s.total_amount || 0) - parseFloat(s.amount_received || 0);
      }
    }
    const { rows: [tp] } = await posDb.query("SELECT COALESCE(SUM(amount),0) as t FROM customer_payments WHERE customer_id=$1", [cid]);
    const { rows: [tr] } = await posDb.query("SELECT COALESCE(SUM(r.total_refund),0) as t FROM returns r JOIN sales s ON s.id=r.sale_id WHERE s.customer_id=$1 AND s.payment_method IN ('credit','split')", [cid]);
    const totalReturned = Math.round(parseFloat(tr.t) * 100) / 100;
    const netInvoiced   = Math.round(Math.max(0, totalInvoiced - totalReturned) * 100) / 100;
    res.json({
      total_invoiced: Math.round(totalInvoiced * 100) / 100,
      total_returned: totalReturned,
      net_invoiced:   netInvoiced,
      total_paid: Math.round(parseFloat(tp.t) * 100) / 100,
      remaining: Math.round(parseFloat(c.total_debt) * 100) / 100,
    });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── تعديل بيانات عميل ────────────────────────────────────────────────────────
app.patch(`${BASE}/api/customers/:cid`, async (req, res) => {
  if (!isMgr(req) && !hasPerm(req, 'customers')) return res.status(403).json({ error: 'غير مصرح' });
  const cid = parseInt(req.params.cid, 10);
  const { name, phone, address, installment_plan } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'الاسم مطلوب' });
  try {
    const { rowCount } = await posDb.query(
      `UPDATE customers SET
         name             = $1,
         phone            = COALESCE(NULLIF($2,''), phone),
         address          = COALESCE(NULLIF($3,''), address),
         installment_plan = COALESCE(NULLIF($4,''), installment_plan)
       WHERE id = $5`,
      [name.trim(), (phone||'').trim(), (address||'').trim(), (installment_plan||'').trim(), cid]
    );
    if (!rowCount) return res.status(404).json({ error: 'العميل غير موجود' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── دمج عميلين ────────────────────────────────────────────────────────────────
app.post(`${BASE}/api/customers/merge`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'المدير فقط يمكنه دمج العملاء' });
  const keepId = parseInt(req.body.keep_id, 10);
  const dropId = parseInt(req.body.drop_id, 10);
  if (!keepId || !dropId) return res.status(400).json({ error: 'يجب اختيار عميلين' });
  if (keepId === dropId) return res.status(400).json({ error: 'لا يمكن دمج عميل مع نفسه' });
  const client = await posDb.connect();
  try {
    await client.query('BEGIN');
    const { rows: [keep] } = await client.query('SELECT * FROM customers WHERE id=$1', [keepId]);
    const { rows: [drop] } = await client.query('SELECT * FROM customers WHERE id=$1', [dropId]);
    if (!keep || !drop) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'أحد العملاء غير موجود' }); }
    await client.query('UPDATE sales                SET customer_id=$1 WHERE customer_id=$2', [keepId, dropId]);
    await client.query('UPDATE customer_payments    SET customer_id=$1 WHERE customer_id=$2', [keepId, dropId]);
    await client.query('UPDATE customer_manual_debts SET customer_id=$1 WHERE customer_id=$2', [keepId, dropId]).catch(() => {});
    await client.query('UPDATE installment_schedules SET customer_id=$1 WHERE customer_id=$2', [keepId, dropId]);
    const mergedDebt = parseFloat(keep.total_debt || 0) + parseFloat(drop.total_debt || 0);
    await client.query('UPDATE customers SET total_debt=$1 WHERE id=$2', [mergedDebt, keepId]);
    await client.query('DELETE FROM customers WHERE id=$1', [dropId]);
    await client.query('COMMIT');
    res.json({ ok: true, merged_debt: mergedDebt, kept: keep.name, dropped: drop.name });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: 'خطأ داخلي: ' + err.message });
  } finally { client.release(); }
});

app.delete(`${BASE}/api/customers/:cid`, async (req, res) => {
  try {
    await posDb.query('DELETE FROM customers WHERE id=$1', [parseInt(req.params.cid, 10)]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── Manual Debts ────────────────────────────────────────────────────────────

app.post(`${BASE}/api/customers/:cid/manual-debt`, async (req, res) => {
  const cid = parseInt(req.params.cid, 10);
  const { amount, reason } = req.body;
  if (!amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) {
    return res.status(400).json({ error: 'أدخل مبلغاً صحيحاً' });
  }
  const client = await posDb.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'INSERT INTO customer_manual_debts (customer_id, amount, reason) VALUES ($1,$2,$3)',
      [cid, parseFloat(amount), reason || '']
    );
    await client.query(
      'UPDATE customers SET total_debt = total_debt + $1 WHERE id=$2',
      [parseFloat(amount), cid]
    );
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: 'خطأ داخلي' });
  } finally { client.release(); }
});

app.get(`${BASE}/api/customers/:cid/manual-debts`, async (req, res) => {
  const cid = parseInt(req.params.cid, 10);
  try {
    const { rows } = await posDb.query(
      'SELECT * FROM customer_manual_debts WHERE customer_id=$1 ORDER BY date DESC',
      [cid]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.delete(`${BASE}/api/customers/:cid/manual-debt/:did`, async (req, res) => {
  const cid = parseInt(req.params.cid, 10);
  const did = parseInt(req.params.did, 10);
  const client = await posDb.connect();
  try {
    await client.query('BEGIN');
    const { rows: [debt] } = await client.query('SELECT * FROM customer_manual_debts WHERE id=$1 AND customer_id=$2', [did, cid]);
    if (!debt) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'غير موجود' });
    }
    await client.query('DELETE FROM customer_manual_debts WHERE id=$1', [did]);
    await client.query('UPDATE customers SET total_debt = GREATEST(0, total_debt - $1) WHERE id=$2', [parseFloat(debt.amount || 0), cid]);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: 'خطأ داخلي' });
  } finally { client.release(); }
});

// ── API: Expenses ─────────────────────────────────────────────────────────────

app.get(`${BASE}/api/expenses`, async (req, res) => {
  try {
    const period = req.query.period || 'all';
    const pf = periodFilter(period, 'date');
    const { rows } = await posDb.query(`SELECT * FROM expenses WHERE ${pf} ORDER BY date DESC`);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/expenses`, async (req, res) => {
  const d = req.body;
  try {
    await posDb.query(
      'INSERT INTO expenses (title, amount, date) VALUES ($1,$2,$3)',
      [d.title, parseFloat(d.amount), d.date || new Date().toISOString().substring(0, 10)]
    );
    res.status(201).json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.delete(`${BASE}/api/expenses/:eid`, async (req, res) => {
  try {
    await posDb.query('DELETE FROM expenses WHERE id=$1', [parseInt(req.params.eid, 10)]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── API: Extra Profits ────────────────────────────────────────────────────────
app.get(`${BASE}/api/extra-profits`, async (req, res) => {
  try {
    const period = req.query.period || 'all';
    let where = '';
    if (period === 'today') where = `WHERE date::date = CURRENT_DATE`;
    else if (period === 'week')  where = `WHERE date::date >= CURRENT_DATE - INTERVAL '7 days'`;
    else if (period === 'month') where = `WHERE TO_CHAR(date::date,'YYYY-MM') = TO_CHAR(CURRENT_DATE,'YYYY-MM')`;
    const { rows } = await posDb.query(`SELECT * FROM extra_profits ${where} ORDER BY id DESC`);
    res.json(rows);
  } catch (err) { console.error(err); res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/extra-profits`, async (req, res) => {
  try {
    const { title, amount, date } = req.body;
    if (!title || !amount) return res.status(400).json({ error: 'البيان والمبلغ مطلوبان' });
    const d = date || new Date().toISOString().substring(0, 10);
    const { rows: [row] } = await posDb.query(
      'INSERT INTO extra_profits (title, amount, date) VALUES ($1, $2, $3) RETURNING *',
      [title, parseFloat(amount), d]
    );
    res.json(row);
  } catch (err) { console.error(err); res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.delete(`${BASE}/api/extra-profits/:id`, async (req, res) => {
  try {
    await posDb.query('DELETE FROM extra_profits WHERE id=$1', [parseInt(req.params.id, 10)]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── API: Reports ──────────────────────────────────────────────────────────────

app.get(`${BASE}/api/reports/summary`, async (req, res) => {
  const period = req.query.period || 'month';
  try {
    const df = periodFilter(period, 's.date');
    const ef = periodFilter(period, 'e.date');
    const rf = periodFilter(period, 'r.date');
    // Revenue = total_amount minus delivery (delivery goes to courier, not net profit)
    const { rows: [sdR] } = await posDb.query(
      `SELECT COALESCE(SUM(s.total_amount - COALESCE(s.delivery_amount,0)),0) as r
       FROM sales s WHERE ${df}`
    );
    const { rows: [sdC] } = await posDb.query(
      `SELECT
         COALESCE(SUM(si.quantity * COALESCE(si.snapshot_purchase_price,0)),0)
         - COALESCE((
             SELECT SUM(ri.quantity * COALESCE(si2.snapshot_purchase_price,0))
             FROM return_items ri
             JOIN sale_items si2 ON si2.id = ri.sale_item_id
             JOIN returns r2 ON r2.id = ri.return_id
             JOIN sales s2 ON s2.id = r2.sale_id
             WHERE ${df.replace(/s\./g, 's2.')}
           ), 0) as c
       FROM sale_items si JOIN sales s ON s.id=si.sale_id WHERE ${df}`
    );
    const sd = { r: sdR.r, c: sdC.c };
    const { rows: [et] } = await posDb.query(
      `SELECT COALESCE(SUM(e.amount),0) as t FROM expenses e WHERE ${ef} AND e.title NOT LIKE 'مردود #%'`
    );
    const { rows: [rt] } = await posDb.query(
      `SELECT COALESCE(SUM(r.total_refund),0) as t FROM returns r WHERE ${rf}`
    );
    const { rows: [sc] } = await posDb.query(`SELECT COUNT(*) as cnt FROM sales s WHERE ${df}`);
    const pf = period === 'today' ? `WHERE date::date = CURRENT_DATE`
             : period === 'week'  ? `WHERE date::date >= CURRENT_DATE - INTERVAL '7 days'`
             : period === 'month' ? `WHERE TO_CHAR(date::date,'YYYY-MM') = TO_CHAR(CURRENT_DATE,'YYYY-MM')`
             : '';
    const { rows: [epR] } = await posDb.query(
      `SELECT COALESCE(SUM(amount),0) as t FROM extra_profits ${pf}`
    );
    const rev = parseFloat(sd.r || 0), cost = parseFloat(sd.c || 0), exp = parseFloat(et.t || 0), refunds = parseFloat(rt.t || 0);
    const extraProfit = parseFloat(epR.t || 0);
    const netRev = Math.max(0, rev - refunds);
    const gross = netRev - cost;
    const netProfit = gross - exp + extraProfit;
    const { rows: payRows } = await posDb.query(
      `SELECT payment_method, COUNT(*) as cnt, SUM(total_amount) as total FROM sales s WHERE ${df} GROUP BY payment_method`
    );
    let cashRev = 0, instaRev = 0;
    for (const row of payRows) {
      const m = row.payment_method || '';
      const t = parseFloat(row.total || 0);
      if (m === 'cash' || m === 'naqdi') cashRev += t;
      if (m === 'instapay') instaRev += t;
    }
    const { rows: splitRows } = await posDb.query(
      `SELECT payment_split FROM sales s WHERE payment_method='split' AND ${df}`
    );
    for (const row of splitRows) {
      try { const sp = JSON.parse(row.payment_split || '{}'); cashRev += parseFloat(sp.cash || 0); instaRev += parseFloat(sp.instapay || 0); } catch (_) {}
    }
    res.json({
      revenue: r2(rev), refunds: r2(refunds), net_revenue: r2(netRev),
      cost: r2(cost), gross_profit: r2(gross), expenses: r2(exp), extra_profit: r2(extraProfit), net_profit: r2(netProfit),
      sales_count: parseInt(sc.cnt, 10),
      payment_breakdown: payRows.map(r => ({ ...r, cnt: parseInt(r.cnt, 10), total: parseFloat(r.total || 0) })),
      cash_revenue: r2(cashRev), instapay_revenue: r2(instaRev),
    });
  } catch (err) { console.error(err); res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/expiry-alerts`, async (req, res) => {
  const months = Math.max(1, parseInt(req.query.months || '3', 10) || 3);
  const days = months * 30;
  try {
    const { rows } = await posDb.query(
      `SELECT * FROM products WHERE expiry_date IS NOT NULL AND expiry_date::date <= CURRENT_DATE + ($1 || ' days')::interval ORDER BY expiry_date`,
      [days]
    );
    const today = new Date().toISOString().substring(0, 10);
    res.json(rows.map(r => ({ ...r, status: String(r.expiry_date) < today ? 'expired' : 'warning' })));
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/reports/top-products`, async (req, res) => {
  const period = req.query.period || 'month';
  try {
    const df = periodFilter(period, 's.date');
    const { rows } = await posDb.query(
      `SELECT si.product_name, SUM(si.quantity) as total_qty, SUM(si.quantity*si.unit_price) as total_revenue
       FROM sale_items si JOIN sales s ON s.id=si.sale_id WHERE ${df}
       GROUP BY si.product_name ORDER BY total_qty DESC LIMIT 20`
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/reports/top-customers`, async (req, res) => {
  const period = req.query.period || 'month';
  try {
    const df = periodFilter(period, 's.date');
    const { rows } = await posDb.query(
      `SELECT COALESCE(c.name, s.customer_name, 'عميل نقدي') as customer_name,
              COUNT(*) as order_count, SUM(s.total_amount) as total_spent
       FROM sales s LEFT JOIN customers c ON c.id=s.customer_id WHERE ${df}
       GROUP BY COALESCE(c.name, s.customer_name, 'عميل نقدي') ORDER BY total_spent DESC LIMIT 20`
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/reports/hourly`, async (req, res) => {
  const period = req.query.period || 'today';
  try {
    const df = periodFilter(period, 's.date');
    const { rows } = await posDb.query(
      `SELECT TO_CHAR(s.date::timestamp, 'HH24') as hour, COUNT(*) as cnt, SUM(s.total_amount) as total
       FROM sales s WHERE ${df} GROUP BY hour ORDER BY hour`
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/stats`, async (req, res) => {
  try {
    const [inv, fin, exp] = await Promise.all([
      posDb.query(`SELECT COUNT(*) as total_products,
                          COALESCE(SUM(CASE WHEN quantity <= min_stock AND min_stock > 0 THEN 1 ELSE 0 END), 0) as low_stock
                   FROM products`),
      posDb.query(`SELECT
                          COALESCE(SUM(CASE WHEN COALESCE(s.source,'pos')='pos' THEN s.total_amount - COALESCE(s.delivery_amount,0) ELSE 0 END),0) as pos_revenue,
                          COALESCE(SUM(CASE WHEN s.source='online' THEN s.total_amount - COALESCE(s.delivery_amount,0) ELSE 0 END),0) as online_revenue,
                          COALESCE(SUM(s.total_amount - COALESCE(s.delivery_amount,0)),0) as revenue,
                          COALESCE(SUM(si.quantity * COALESCE(si.snapshot_purchase_price, 0)),0) as cost
                   FROM sales s
                   LEFT JOIN sale_items si ON si.sale_id = s.id
                   WHERE s.payment_method != 'refund'`),
      posDb.query(`SELECT COALESCE(SUM(amount),0) as total_expenses FROM expenses`),
    ]);
    const revenue = parseFloat(fin.rows[0].revenue);
    const cost    = parseFloat(fin.rows[0].cost);
    const expenses = parseFloat(exp.rows[0].total_expenses);
    const posRevenue = parseFloat(fin.rows[0].pos_revenue || fin.rows[0].revenue);
    const onlineRevenue = parseFloat(fin.rows[0].online_revenue || 0);
    res.json({
      total_products: parseInt(inv.rows[0].total_products, 10),
      low_stock:      parseInt(inv.rows[0].low_stock, 10),
      posRevenue,
      onlineRevenue,
      totalRevenue: posRevenue + onlineRevenue,
      posCost:     cost,
      posExpenses: expenses,
      posNetProfit: revenue - cost - expenses,
    });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── API: Invoices ─────────────────────────────────────────────────────────────

app.get(`${BASE}/api/invoices`, async (req, res) => {
  try {
    const { rows } = await posDb.query(
      `SELECT s.*, c.name AS customer_name, c.phone AS customer_phone,
              COALESCE(ret.total_refunded,0) AS total_refunded,
              COALESCE(ret.return_count,0) AS return_count,
              COALESCE(prof.profit,0) AS profit
       FROM sales s
       LEFT JOIN customers c ON s.customer_id = c.id
       LEFT JOIN (SELECT sale_id, SUM(total_refund) AS total_refunded, COUNT(*) AS return_count FROM returns GROUP BY sale_id) ret ON ret.sale_id = s.id
       LEFT JOIN (SELECT sale_id, SUM((unit_price - COALESCE(snapshot_purchase_price,0)) * quantity) AS profit FROM sale_items GROUP BY sale_id) prof ON prof.sale_id = s.id
       ORDER BY s.date DESC`
    );
    const result = rows.map(r => {
      const totalRefunded = parseFloat(r.total_refunded || 0);
      const totalAmt = parseFloat(r.total_amount || 0);
      let returnStatus = 0;
      if (totalRefunded >= totalAmt && totalAmt > 0) returnStatus = 2;
      else if (totalRefunded > 0) returnStatus = 1;
      return { ...r, return_status: returnStatus, is_returned: returnStatus === 2 };
    });
    res.json(result);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/invoices/:sid`, async (req, res) => {
  const sid = parseInt(req.params.sid, 10);
  try {
    const { rows: [inv] } = await posDb.query(
      `SELECT s.*, c.name AS customer_name, c.phone AS customer_phone,
              c.address AS customer_address, c.city AS customer_city
       FROM sales s LEFT JOIN customers c ON s.customer_id = c.id WHERE s.id=$1`, [sid]
    );
    if (!inv) return res.status(404).json({ error: 'الفاتورة غير موجودة' });
    const { rows: [refRow] } = await posDb.query(
      `SELECT COALESCE(SUM(total_refund),0) AS total_refunded FROM returns WHERE sale_id=$1`, [sid]
    );
    inv.total_refunded = parseFloat(refRow.total_refunded || 0);
    const { rows: itemsRaw } = await posDb.query('SELECT * FROM sale_items WHERE sale_id=$1', [sid]);
    const items = [];
    for (const item of itemsRaw) {
      const { rows: [ret] } = await posDb.query(
        'SELECT COALESCE(SUM(ri.quantity),0) as qty FROM return_items ri WHERE ri.sale_item_id=$1', [item.id]
      );
      const returnedQty = parseInt(ret?.qty || 0, 10);
      items.push({ ...item, returned_qty: returnedQty, remaining_qty: Math.max(0, item.quantity - returnedQty) });
    }
    const totalRemaining = items.reduce((s, i) => s + i.remaining_qty, 0);
    const totalSold = items.reduce((s, i) => s + i.quantity, 0);
    const returnStatus = (totalRemaining === 0 && totalSold > 0) ? 2 : (totalRemaining < totalSold ? 1 : 0);
    inv.return_status = returnStatus;
    inv.profit = items.reduce((s, i) => s + (parseFloat(i.unit_price||0) - parseFloat(i.snapshot_purchase_price||0)) * parseInt(i.quantity||0, 10), 0);
    const { rows: returns } = await posDb.query(
      `SELECT r.*, u.username AS processed_by_name FROM returns r
       LEFT JOIN users u ON u.id = r.processed_by WHERE r.sale_id=$1 ORDER BY r.date`, [sid]
    );
    res.json({ invoice: inv, items, returns });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── تعديل بيانات العميل على الفاتورة ──────────────────────────────────────────
app.patch(`${BASE}/api/sales/:sid/customer`, async (req, res) => {
  if (!isMgr(req) && !hasPerm(req, 'invoices')) return res.status(403).json({ error: 'غير مصرح' });
  const sid = parseInt(req.params.sid, 10);
  const { customer_name, customer_phone, customer_address } = req.body;
  try {
    const { rows: [sale] } = await posDb.query('SELECT * FROM sales WHERE id=$1', [sid]);
    if (!sale) return res.status(404).json({ error: 'الفاتورة غير موجودة' });
    await posDb.query('UPDATE sales SET customer_name=$1 WHERE id=$2', [customer_name || sale.customer_name, sid]);
    if (sale.customer_id) {
      await posDb.query(
        `UPDATE customers SET
           name    = COALESCE(NULLIF($1,''), name),
           phone   = COALESCE(NULLIF($2,''), phone),
           address = COALESCE(NULLIF($3,''), address)
         WHERE id=$4`,
        [customer_name, customer_phone, customer_address, sale.customer_id]
      );
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── تعديل أسعار الأصناف في الفاتورة ──────────────────────────────────────────
app.patch(`${BASE}/api/sales/:sid/item-prices`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'المدير فقط يمكنه تعديل الأسعار' });
  const sid = parseInt(req.params.sid, 10);
  const { items } = req.body; // [{ id, unit_price }]
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'لا توجد أصناف للتعديل' });
  const client = await posDb.connect();
  try {
    await client.query('BEGIN');
    const { rows: [oldSale] } = await client.query(
      'SELECT total_amount, payment_method, customer_id, amount_received, payment_split FROM sales WHERE id=$1', [sid]
    );
    for (const it of items) {
      const price = parseFloat(it.unit_price);
      if (isNaN(price) || price < 0) continue;
      await client.query(
        'UPDATE sale_items SET unit_price=$1, snapshot_unit_price=$1 WHERE id=$2 AND sale_id=$3',
        [price, parseInt(it.id, 10), sid]
      );
    }
    const { rows: [tot] } = await client.query(
      'SELECT COALESCE(SUM(unit_price * quantity),0) AS t FROM sale_items WHERE sale_id=$1', [sid]
    );
    const { rows: [disc] } = await client.query('SELECT discount_amount, delivery_amount FROM sales WHERE id=$1', [sid]);
    const newTotal = Math.max(0, parseFloat(tot.t) - parseFloat(disc?.discount_amount || 0) + parseFloat(disc?.delivery_amount || 0));
    await client.query('UPDATE sales SET total_amount=$1 WHERE id=$2', [newTotal, sid]);
    if (oldSale?.customer_id && ['credit','split'].includes(oldSale.payment_method)) {
      let oldDebt, newDebt;
      if (oldSale.payment_method === 'split') {
        const sp = JSON.parse(oldSale.payment_split || '{}');
        oldDebt = parseFloat(sp.credit || 0);
        // For split: credit portion changes proportionally with total change
        const ratio = oldSale.total_amount > 0 ? (newTotal / parseFloat(oldSale.total_amount)) : 1;
        newDebt = Math.max(0, oldDebt * ratio);
      } else {
        const amtReceived = parseFloat(oldSale.amount_received || 0);
        oldDebt = Math.max(0, parseFloat(oldSale.total_amount || 0) - amtReceived);
        newDebt = Math.max(0, newTotal - amtReceived);
      }
      const diff = Math.round((newDebt - oldDebt) * 100) / 100;
      if (diff !== 0) {
        await client.query(
          'UPDATE customers SET total_debt = GREATEST(0, total_debt + $1) WHERE id=$2',
          [diff, oldSale.customer_id]
        );
      }
    }
    await client.query('COMMIT');
    res.json({ ok: true, new_total: newTotal });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: 'خطأ داخلي' });
  } finally { client.release(); }
});

app.post(`${BASE}/api/invoices/:sid/return`, async (req, res) => {
  if (!hasPerm(req, 'process_returns')) return res.status(403).json({ error: 'ليس لديك صلاحية معالجة المردودات' });
  const sid = parseInt(req.params.sid, 10);
  const d = req.body;
  const reason = d.reason || '';
  let selected = d.items || [];
  const client = await posDb.connect();
  try {
    await client.query('BEGIN');
    const { rows: [sale] } = await client.query('SELECT * FROM sales WHERE id=$1', [sid]);
    if (!sale) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'الفاتورة غير موجودة' }); }
    const { rows: allItems } = await client.query('SELECT * FROM sale_items WHERE sale_id=$1', [sid]);
    if (!selected.length) {
      for (const item of allItems) {
        const { rows: [al] } = await client.query('SELECT COALESCE(SUM(ri.quantity),0) as qty FROM return_items ri WHERE ri.sale_item_id=$1', [item.id]);
        const rem = item.quantity - parseInt(al.qty, 10);
        if (rem > 0) selected.push({ sale_item_id: item.id, quantity: rem });
      }
    }
    if (!selected.length) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'لا توجد أصناف متبقية للاسترجاع' }); }
    let totalRefund = 0;
    const validated = [];
    for (const sel of selected) {
      const selSid = parseInt(sel.sale_item_id, 10);
      const qty = parseInt(sel.quantity || 0, 10);
      const { rows: [item] } = await client.query('SELECT * FROM sale_items WHERE id=$1 AND sale_id=$2', [selSid, sid]);
      if (!item || qty <= 0) continue;
      const { rows: [al] } = await client.query('SELECT COALESCE(SUM(ri.quantity),0) as qty FROM return_items ri WHERE ri.sale_item_id=$1', [selSid]);
      const allowed = Math.min(qty, item.quantity - parseInt(al.qty, 10));
      if (allowed <= 0) continue;
      validated.push({ item, quantity: allowed });
      totalRefund += allowed * parseFloat(item.unit_price);
    }
    if (!validated.length) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'الكميات غير صحيحة أو مسترجعة مسبقاً' }); }
    const { rows: [ret] } = await client.query(
      'INSERT INTO returns (sale_id, total_refund, reason, processed_by) VALUES ($1,$2,$3,$4) RETURNING id',
      [sid, totalRefund, reason || '', req.session?.user_id || null]
    );
    const returnId = ret.id;
    for (const v of validated) {
      const { item, quantity } = v;
      let validProdId = null;
      if (item.product_id) {
        try {
          const { rows: [pExists] } = await client.query('SELECT id FROM products WHERE id=$1', [item.product_id]);
          if (pExists) validProdId = item.product_id;
        } catch (_) {}
      }
      await client.query(
        'INSERT INTO return_items (return_id, sale_item_id, product_id, product_name, quantity, unit_price) VALUES ($1,$2,$3,$4,$5,$6)',
        [returnId, item.id, validProdId, item.product_name || '', quantity, parseFloat(item.unit_price || 0)]
      );
      if (validProdId) await client.query('UPDATE products SET quantity = quantity + $1 WHERE id=$2', [quantity, validProdId]);
      // Restore checkbox_values stock or variants stock if the returned item had an option/size
      if (validProdId && item.selected_option) {
        try {
          const { rows: [pcb] } = await client.query('SELECT checkbox_values, variants FROM products WHERE id=$1', [validProdId]);
          if (pcb?.checkbox_values) {
            const cbv = typeof pcb.checkbox_values === 'string' ? JSON.parse(pcb.checkbox_values) : { ...pcb.checkbox_values };
            if (cbv[item.selected_option] && typeof cbv[item.selected_option] === 'object' && cbv[item.selected_option].stock != null) {
              cbv[item.selected_option].stock = (cbv[item.selected_option].stock || 0) + quantity;
              cbv[item.selected_option].disabled = false;
              // Recalculate main quantity from sum of all checkbox stocks to stay in sync
              const totalCbQty = Object.values(cbv).reduce((sum, v) =>
                sum + (typeof v === 'object' && v.stock != null ? Math.max(0, v.stock) : 0), 0);
              await client.query(
                'UPDATE products SET quantity=$1, checkbox_values=$2 WHERE id=$3',
                [totalCbQty, JSON.stringify(cbv), validProdId]
              );
            }
          }
          if (pcb?.variants) {
            const vObj = typeof pcb.variants === 'string' ? JSON.parse(pcb.variants) : { ...pcb.variants };
            const sIdx = (vObj.sizes || []).findIndex(s => s.label === item.selected_option);
            if (sIdx >= 0) {
              vObj.sizes[sIdx].qty = (vObj.sizes[sIdx].qty || 0) + quantity;
              await client.query('UPDATE products SET variants=$1 WHERE id=$2', [JSON.stringify(vObj), validProdId]);
            }
          }
        } catch (_cbErr) {}
      }

      // Log movement to audit log
      await logProductMovement({
        productId: validProdId,
        productName: item.product_name || '',
        movementType: 'return',
        referenceId: sid,
        referenceTitle: `مرتجع إذن #${returnId} فاتورة #${sid}`,
        selectedOption: item.selected_option || null,
        quantityChange: Math.abs(parseInt(quantity || 0, 10)),
        quantityBefore: 0,
        quantityAfter: quantity,
        unitPrice: parseFloat(item.unit_price || 0),
        unitCost: 0,
        userName: req.session?.username || 'كاشير',
        notes: `مرتجع فاتورة: ${reason || 'بدون سبب'}`
      }, client);
    }
    if (sale.customer_id && ['credit','split'].includes(sale.payment_method || '')) {
      await client.query('UPDATE customers SET total_debt = GREATEST(0, total_debt - $1) WHERE id=$2', [totalRefund, sale.customer_id]);
    }
    try {
      await client.query('INSERT INTO expenses (title, amount, date) VALUES ($1,$2,CURRENT_DATE::text)',
        [`مردود #${returnId} فاتورة #${sid}${reason ? ` (${reason})` : ''}`, totalRefund]);
    } catch (_) {}
    await client.query('COMMIT');
    syncProductsNow(validated.filter(v => v.item.product_id).map(v => v.item.product_id)).catch(() => {});
    res.status(201).json({ ok: true, refund_amount: totalRefund });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Invoice return error:', err);
    res.status(500).json({ error: 'خطأ أثناء الاسترجاع: ' + err.message });
  } finally { client.release(); }
});

app.delete(`${BASE}/api/returns/:rid`, async (req, res) => {
  if (!hasPerm(req, 'process_returns')) return res.status(403).json({ error: 'ليس لديك صلاحية' });
  const rid = parseInt(req.params.rid, 10);
  const client = await posDb.connect();
  try {
    await client.query('BEGIN');
    const { rows: [ret] } = await client.query('SELECT * FROM returns WHERE id=$1', [rid]);
    if (!ret) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'المردود غير موجود' }); }
    const { rows: [sale] } = await client.query('SELECT * FROM sales WHERE id=$1', [ret.sale_id]);
    const { rows: returnItems } = await client.query('SELECT * FROM return_items WHERE return_id=$1', [rid]);
    const productIds = [];
    for (const ri of returnItems) {
      if (ri.product_id) {
        await client.query('UPDATE products SET quantity = GREATEST(0, quantity - $1) WHERE id=$2', [ri.quantity, ri.product_id]);
        productIds.push(ri.product_id);
      }
      if (ri.product_id && ri.sale_item_id) {
        try {
          const { rows: [si] } = await client.query('SELECT selected_option FROM sale_items WHERE id=$1', [ri.sale_item_id]);
          if (si?.selected_option) {
            const { rows: [pcb] } = await client.query('SELECT checkbox_values, variants FROM products WHERE id=$1', [ri.product_id]);
            if (pcb?.checkbox_values) {
              const cbv = typeof pcb.checkbox_values === 'string' ? JSON.parse(pcb.checkbox_values) : { ...pcb.checkbox_values };
              if (cbv[si.selected_option] && typeof cbv[si.selected_option] === 'object' && cbv[si.selected_option].stock != null) {
                cbv[si.selected_option].stock = Math.max(0, (cbv[si.selected_option].stock || 0) - ri.quantity);
                if (cbv[si.selected_option].stock === 0) cbv[si.selected_option].disabled = true;
                const totalCbQty = Object.values(cbv).reduce((sum, v) =>
                  sum + (typeof v === 'object' && v.stock != null ? Math.max(0, v.stock) : 0), 0);
                await client.query('UPDATE products SET quantity=$1, checkbox_values=$2 WHERE id=$3',
                  [totalCbQty, JSON.stringify(cbv), ri.product_id]);
              }
            }
            if (pcb?.variants) {
              const vObj = typeof pcb.variants === 'string' ? JSON.parse(pcb.variants) : { ...pcb.variants };
              const sIdx = (vObj.sizes || []).findIndex(s => s.label === si.selected_option);
              if (sIdx >= 0) {
                vObj.sizes[sIdx].qty = Math.max(0, (vObj.sizes[sIdx].qty || 0) - ri.quantity);
                await client.query('UPDATE products SET variants=$1 WHERE id=$2', [JSON.stringify(vObj), ri.product_id]);
              }
            }
          }
        } catch (_cbUndoErr) {}
      }
    }
    if (sale?.customer_id && ['credit','split'].includes(sale?.payment_method)) {
      await client.query('UPDATE customers SET total_debt = total_debt + $1 WHERE id=$2', [ret.total_refund, sale.customer_id]);
    }
    // Delete matching expense — try new format (includes return id) then fall back to old format
    await client.query(
      `DELETE FROM expenses WHERE id = (
         SELECT id FROM expenses
         WHERE (title LIKE $1 OR title LIKE $2) AND amount=$3
         ORDER BY id DESC LIMIT 1
       )`,
      [`مردود #${rid} %`, `مردود فاتورة #${ret.sale_id}%`, ret.total_refund]
    );
    await client.query('DELETE FROM return_items WHERE return_id=$1', [rid]);
    await client.query('DELETE FROM returns WHERE id=$1', [rid]);
    await client.query('COMMIT');
    if (productIds.length) syncProductsNow(productIds).catch(() => {});
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: 'خطأ داخلي' });
  } finally { client.release(); }
});

app.post(`${BASE}/api/invoices/:sid/add-items`, async (req, res) => {
  const sid = parseInt(req.params.sid, 10);
  const { items } = req.body;
  if (!items?.length) return res.status(400).json({ error: 'لا توجد أصناف' });
  const client = await posDb.connect();
  try {
    await client.query('BEGIN');
    const { rows: [sale] } = await client.query('SELECT * FROM sales WHERE id=$1', [sid]);
    if (!sale) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'الفاتورة غير موجودة' }); }
    let extraTotal = 0;
    const updatedProductIds = [];
    for (const item of items) {
      const prodId = item.product_id;
      const qty = parseInt(item.quantity || 1, 10);
      const price = parseFloat(item.unit_price || 0);
      const name = item.product_name || '';
      const selOpt = item.selected_option || item.selectedOption || item._checkbox || item._size || item.selected_size || null;
      let prod = null;
      if (prodId) {
        const { rows: [p] } = await client.query('SELECT * FROM products WHERE id=$1', [prodId]);
        if (!p) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'المنتج غير موجود' }); }
        if (p.quantity < qty) { await client.query('ROLLBACK'); return res.status(400).json({ error: `مخزون غير كافٍ لـ ${p.product_name}` }); }

        // Variant stock check
        if (selOpt && p.variants) {
          try {
            const vObj = typeof p.variants === 'string' ? JSON.parse(p.variants) : p.variants;
            const vSz = (vObj?.sizes || []).find(s => s.label === selOpt);
            if (vSz !== undefined && vSz.qty < qty) {
              await client.query('ROLLBACK');
              return res.status(400).json({ error: `الكمية المطلوبة تتجاوز مخزون المقاس "${selOpt}" المتاح (${vSz.qty})` });
            }
          } catch (_) {}
        }
        // Checkbox stock check
        if (selOpt && p.checkbox_values) {
          try {
            const cbv = typeof p.checkbox_values === 'string' ? JSON.parse(p.checkbox_values) : p.checkbox_values;
            const cbOpt = cbv?.[selOpt];
            if (cbOpt && typeof cbOpt === 'object' && cbOpt.stock != null && cbOpt.stock < qty) {
              await client.query('ROLLBACK');
              return res.status(400).json({ error: `الكمية المطلوبة تتجاوز المخزون المتاح للخيار "${selOpt}" (${cbOpt.stock})` });
            }
          } catch (_) {}
        }
        prod = p;
      }
      const snapPp = prod ? parseFloat(prod.purchase_price || 0) : 0;
      await client.query(
        'INSERT INTO sale_items (sale_id, product_id, product_name, quantity, unit_price, snapshot_purchase_price, snapshot_unit_price, selected_option) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [sid, prodId, name || prod?.product_name || '', qty, price, snapPp, price, selOpt]
      );
      if (prodId) {
        const stockRes = await client.query(
          'UPDATE products SET quantity = GREATEST(0, quantity - $1) WHERE id=$2 AND quantity >= $1 RETURNING id',
          [qty, prodId]
        );
        if (!stockRes.rows.length) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: `نفد المخزون للمنتج ${name || prod?.product_name || '#' + prodId}` });
        }
        // Deduct variant stock
        if (selOpt && prod?.variants) {
          try {
            const vObj = typeof prod.variants === 'string' ? JSON.parse(prod.variants) : { ...prod.variants };
            const sIdx = (vObj.sizes || []).findIndex(s => s.label === selOpt);
            if (sIdx >= 0) {
              vObj.sizes[sIdx].qty = Math.max(0, (vObj.sizes[sIdx].qty || 0) - qty);
              await client.query('UPDATE products SET variants=$1 WHERE id=$2', [JSON.stringify(vObj), prodId]);
            }
          } catch (_) {}
        }
        // Deduct checkbox stock
        if (selOpt && prod?.checkbox_values) {
          try {
            const cbv = typeof prod.checkbox_values === 'string' ? JSON.parse(prod.checkbox_values) : { ...prod.checkbox_values };
            if (cbv[selOpt] && typeof cbv[selOpt] === 'object' && cbv[selOpt].stock != null) {
              cbv[selOpt].stock = Math.max(0, (cbv[selOpt].stock || 0) - qty);
              if (cbv[selOpt].stock === 0) cbv[selOpt].disabled = true;
              const totalCbQty = Object.values(cbv).reduce((sum, v) =>
                sum + (typeof v === 'object' && v.stock != null ? Math.max(0, v.stock) : 0), 0);
              await client.query('UPDATE products SET quantity=$1, checkbox_values=$2 WHERE id=$3',
                [totalCbQty, JSON.stringify(cbv), prodId]);
            }
          } catch (_) {}
        }
        updatedProductIds.push(prodId);
      }
      extraTotal += qty * price;
    }
    await client.query('UPDATE sales SET total_amount = total_amount + $1 WHERE id=$2', [extraTotal, sid]);
    if (sale.customer_id) {
      if (sale.payment_method === 'credit') {
        await client.query('UPDATE customers SET total_debt = total_debt + $1 WHERE id=$2', [extraTotal, sale.customer_id]);
        if (sale.credit_paid) {
          await client.query('UPDATE sales SET credit_paid=0 WHERE id=$1', [sid]);
        }
      } else if (sale.payment_method === 'split') {
        let splitData = {};
        try { splitData = JSON.parse(sale.payment_split || '{}'); } catch(_) {}
        splitData.credit = (parseFloat(splitData.credit || 0) + extraTotal);
        await client.query('UPDATE sales SET payment_split=$1 WHERE id=$2', [JSON.stringify(splitData), sid]);
        await client.query('UPDATE customers SET total_debt = total_debt + $1 WHERE id=$2', [extraTotal, sale.customer_id]);
      }
    }
    await client.query('COMMIT');
    if (updatedProductIds.length) syncProductsNow(updatedProductIds).catch(() => {});
    res.status(201).json({ ok: true, added_amount: extraTotal });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: 'خطأ داخلي' });
  } finally { client.release(); }
});

// ── API: Settings ─────────────────────────────────────────────────────────────

app.get(`${BASE}/api/backup`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'مسموح للمدير فقط' });
  try {
    const tables = ['products', 'customers', 'sales', 'sale_items', 'expenses',
                    'suppliers', 'store_settings', 'users', 'cash_register_entries'];
    const backup = { exported_at: new Date().toISOString(), tables: {} };
    for (const t of tables) {
      try {
        const { rows } = await posDb.query(`SELECT * FROM ${t}`);
        backup.tables[t] = rows;
      } catch (_) { backup.tables[t] = []; }
    }
    const json = JSON.stringify(backup, null, 2);
    const date = new Date().toISOString().slice(0, 10);
    res.setHeader('Content-Disposition', `attachment; filename="pos_backup_${date}.json"`);
    res.setHeader('Content-Type', 'application/json');
    res.send(json);
  } catch (err) { res.status(500).json({ error: 'خطأ في التصدير' }); }
});

app.post(`${BASE}/api/restore`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'مسموح للمدير فقط' });
  try {
    const { tables } = req.body;
    if (!tables || typeof tables !== 'object') return res.status(400).json({ error: 'بيانات غير صالحة' });
    const RESTORE_ORDER = ['suppliers', 'customers', 'products', 'users', 'store_settings',
                           'sales', 'sale_items', 'expenses', 'cash_register_entries'];
    let restored = 0;
    for (const table of RESTORE_ORDER) {
      const rows = tables[table];
      if (!Array.isArray(rows) || !rows.length) continue;
      const cols = Object.keys(rows[0]).filter(c => c !== 'id');
      if (!cols.length) continue;
      for (const row of rows) {
        try {
          const vals = cols.map(c => row[c]);
          const placeholders = cols.map((_, i) => `$${i + 1}`).join(', ');
          await posDb.query(
            `INSERT INTO ${table} (${cols.join(', ')}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`,
            vals
          );
          restored++;
        } catch (_) {}
      }
    }
    res.json({ ok: true, restored });
  } catch (err) { res.status(500).json({ error: 'خطأ في الاستعادة' }); }
});

app.get(`${BASE}/api/settings`, async (req, res) => {
  try { res.json(await getSettings()); } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/settings`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'مسموح للمدير فقط' });
  const d = req.body;
  try {
    for (const [k, v] of Object.entries(d)) {
      await posDb.query(
        'INSERT INTO store_settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2',
        [k, String(v)]
      );
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── API: Suppliers ────────────────────────────────────────────────────────────

app.get(`${BASE}/api/suppliers`, async (req, res) => {
  try {
    const { rows } = await posDb.query(
      `SELECT s.*, COUNT(p.id) as product_count
       FROM suppliers s LEFT JOIN products p ON p.supplier_id=s.id
       GROUP BY s.id ORDER BY s.name`
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/suppliers`, async (req, res) => {
  const d = req.body;
  try {
    await posDb.query('INSERT INTO suppliers (name, phone, address, notes) VALUES ($1,$2,$3,$4)', [d.name, d.phone || '', d.address || '', d.notes || '']);
    res.status(201).json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.put(`${BASE}/api/suppliers/:sid`, async (req, res) => {
  const d = req.body;
  try {
    await posDb.query('UPDATE suppliers SET name=$1, phone=$2, address=$3, notes=$4 WHERE id=$5', [d.name, d.phone || '', d.address || '', d.notes || '', req.params.sid]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.delete(`${BASE}/api/suppliers/:sid`, async (req, res) => {
  try {
    await posDb.query('UPDATE products SET supplier_id=NULL WHERE supplier_id=$1', [req.params.sid]);
    await posDb.query('DELETE FROM suppliers WHERE id=$1', [req.params.sid]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/suppliers/:sid/products`, async (req, res) => {
  try {
    const { rows } = await posDb.query('SELECT * FROM products WHERE supplier_id=$1 ORDER BY product_name', [req.params.sid]);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── API: Installments ─────────────────────────────────────────────────────────

app.get(`${BASE}/api/installments`, async (req, res) => {
  try {
    const customerId = req.query.customer_id || req.query.cid;
    let sql = `SELECT i.*, c.name as customer_name FROM installment_schedules i LEFT JOIN customers c ON c.id=i.customer_id WHERE 1=1`;
    const params = [];
    if (customerId) { params.push(customerId); sql += ` AND i.customer_id=$${params.length}`; }
    sql += ' ORDER BY i.due_date ASC';
    const { rows } = await posDb.query(sql, params);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/installments`, async (req, res) => {
  const d = req.body;
  try {
    await posDb.query(
      'INSERT INTO installment_schedules (customer_id, sale_id, installment_number, amount, due_date, notes) VALUES ($1,$2,$3,$4,$5,$6)',
      [d.customer_id, d.sale_id || null, d.installment_number || 1, d.amount, d.due_date, d.notes || '']
    );
    res.status(201).json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.put(`${BASE}/api/installments/:iid`, async (req, res) => {
  const d = req.body;
  const client = await posDb.connect();
  try {
    await client.query('BEGIN');
    const { rows: [prev] } = await client.query('SELECT * FROM installment_schedules WHERE id=$1', [req.params.iid]);
    await client.query('UPDATE installment_schedules SET status=$1, paid_date=$2, notes=$3 WHERE id=$4',
      [d.status, d.paid_date || null, d.notes || '', req.params.iid]);
    if (prev && d.status === 'paid' && prev.status !== 'paid' && prev.customer_id) {
      await client.query(
        'UPDATE customers SET total_debt = GREATEST(0, total_debt - $1) WHERE id=$2',
        [parseFloat(prev.amount || 0), prev.customer_id]
      );
    }
    if (prev && d.status !== 'paid' && prev.status === 'paid' && prev.customer_id) {
      await client.query(
        'UPDATE customers SET total_debt = total_debt + $1 WHERE id=$2',
        [parseFloat(prev.amount || 0), prev.customer_id]
      );
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: 'خطأ داخلي' });
  } finally { client.release(); }
});

app.delete(`${BASE}/api/installments/:iid`, async (req, res) => {
  try {
    await posDb.query('DELETE FROM installment_schedules WHERE id=$1', [req.params.iid]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── API: CSV Export ────────────────────────────────────────────────────────────

app.get(`${BASE}/api/export/csv`, async (req, res) => {
  const type = req.query.type || 'sales';
  const period = req.query.period || 'all';
  function periodFilter(col) {
    if (period === 'today') return `AND DATE(${col}) = CURRENT_DATE`;
    if (period === 'week')  return `AND DATE(${col}) >= CURRENT_DATE - INTERVAL '7 days'`;
    if (period === 'month') return `AND DATE(${col}) >= DATE_TRUNC('month', CURRENT_DATE)`;
    if (period === 'year')  return `AND DATE(${col}) >= DATE_TRUNC('year', CURRENT_DATE)`;
    return '';
  }
  try {
    let rows, headers;
    if (type === 'sales') {
      ({ rows } = await posDb.query(`SELECT s.id, s.date, s.total_amount, s.payment_method, COALESCE(c.name,'') as customer FROM sales s LEFT JOIN customers c ON c.id=s.customer_id WHERE 1=1 ${periodFilter('s.date')} ORDER BY s.date DESC`));
      headers = ['id', 'date', 'total_amount', 'payment_method', 'customer'];
    } else if (type === 'products') {
      ({ rows } = await posDb.query('SELECT id, barcode, product_name, quantity, purchase_price, sale_price, category FROM products ORDER BY product_name'));
      headers = ['id', 'barcode', 'product_name', 'quantity', 'purchase_price', 'sale_price', 'category'];
    } else if (type === 'customers') {
      ({ rows } = await posDb.query('SELECT id, name, phone, total_debt FROM customers ORDER BY name'));
      headers = ['id', 'name', 'phone', 'total_debt'];
    } else if (type === 'expenses') {
      ({ rows } = await posDb.query(`SELECT e.id, e.date, e.title, e.amount FROM expenses e WHERE 1=1 ${periodFilter('e.date')} ORDER BY e.date DESC`));
      headers = ['id', 'date', 'title', 'amount'];
    } else if (type === 'top-products') {
      ({ rows } = await posDb.query(`SELECT si.product_name, SUM(si.quantity) as total_qty, SUM(si.quantity * si.unit_price) as total_revenue FROM sale_items si JOIN sales s ON s.id=si.sale_id WHERE 1=1 ${periodFilter('s.date')} GROUP BY si.product_name ORDER BY total_qty DESC LIMIT 100`));
      headers = ['product_name', 'total_qty', 'total_revenue'];
    } else if (type === 'top-customers') {
      ({ rows } = await posDb.query(`SELECT c.name, c.phone, COUNT(s.id) as orders, SUM(s.total_amount) as total_spent FROM sales s JOIN customers c ON c.id=s.customer_id WHERE 1=1 ${periodFilter('s.date')} GROUP BY c.id, c.name, c.phone ORDER BY total_spent DESC LIMIT 100`));
      headers = ['name', 'phone', 'orders', 'total_spent'];
    } else {
      ({ rows } = await posDb.query('SELECT id, name, phone, total_debt FROM customers ORDER BY name'));
      headers = ['id', 'name', 'phone', 'total_debt'];
    }
    const csv = [headers.join(','), ...rows.map(r => headers.map(h => `"${String(r[h] || '').replace(/"/g, '""')}"`).join(','))].join('\n');
    res.set('Content-Type', 'text/csv; charset=utf-8').set('Content-Disposition', `attachment; filename="${type}.csv"`).send('\uFEFF' + csv);
  } catch (err) { res.status(500).send('خطأ'); }
});

// ── Supabase Storage Image Upload ─────────────────────────────────────────────
// Uploads a base64 data-URL to Supabase Storage and returns the public URL.
// Requires SUPABASE_SERVICE_KEY env var (Supabase → Settings → API → service_role).
async function uploadBase64ToSupabase(dataUrl) {
  if (!SUPABASE_SERVICE_KEY || !dataUrl || !dataUrl.startsWith('data:')) return null;
  try {
    const matches = dataUrl.match(/^data:([^;]+);base64,(.+)$/);
    if (!matches) return null;
    const [, mimeType, base64Data] = matches;
    const buffer = Buffer.from(base64Data, 'base64');
    const ext = mimeType.split('/')[1]?.replace('jpeg', 'jpg') || 'jpg';
    const filename = `uploads/${uuidv4()}.${ext}`;
    const uploadUrl = `${SUPABASE_BASE}/storage/v1/object/products/${filename}`;
    const resp = await fetch(uploadUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': mimeType,
        'x-upsert': 'true',
      },
      body: buffer,
    });
    if (!resp.ok) return null;
    return `${SUPABASE_BASE}/storage/v1/object/public/products/${filename}`;
  } catch (_) { return null; }
}

// ── DenTrust Sync Helpers ─────────────────────────────────────────────────────

async function syncDentrustBatch(updates) {
  if (!updates.length || !HAS_WEBSITE_DB) return;
  const client = await dentrustDb.connect();
  try {
    for (const { pid, delta, selectedOption } of updates) {
      const { rows: [row] } = await posDb.query('SELECT dentrust_id FROM products WHERE id=$1', [pid]);
      if (!row?.dentrust_id) continue;
      // Deduct overall stock
      await client.query(
        'UPDATE products SET stock = GREATEST(0, COALESCE(stock,0) + $1), is_sold_out = (GREATEST(0, COALESCE(stock,0) + $1) <= 0) WHERE id=$2',
        [delta, row.dentrust_id]
      );
      // Deduct checkbox variant stock if selectedOption provided
      if (selectedOption && delta < 0) {
        try {
          const { rows: [prod] } = await client.query('SELECT checkbox_values FROM products WHERE id=$1', [row.dentrust_id]);
          if (prod?.checkbox_values) {
            const cbv = typeof prod.checkbox_values === 'string' ? JSON.parse(prod.checkbox_values) : { ...prod.checkbox_values };
            // Try both full key "category::key" and short key "key"
            const shortKey = selectedOption.includes('::') ? selectedOption.split('::').pop() : null;
            const optKey = cbv[selectedOption] !== undefined ? selectedOption
                         : (shortKey && cbv[shortKey] !== undefined ? shortKey : null);
            if (optKey && typeof cbv[optKey] === 'object' && cbv[optKey].stock != null) {
              cbv[optKey].stock = Math.max(0, cbv[optKey].stock + delta);
              // Recalculate total stock as sum of all variant stocks (same logic as POS)
              const newTotalStock = Object.values(cbv).reduce(
                (s, v) => s + (typeof v === 'object' && v.stock != null ? Math.max(0, v.stock) : 0), 0
              );
              await client.query(
                'UPDATE products SET stock=$1, is_sold_out=$2, checkbox_values=$3 WHERE id=$4',
                [newTotalStock, newTotalStock <= 0, JSON.stringify(cbv), row.dentrust_id]
              );
            }
          }
        } catch(_) {}
      }
    }
  } finally { client.release(); }
}

// Push actual current POS stock values to website for specific products (real-time, state-based not delta-based)
async function syncProductsNow(productIds) {
  if (!productIds.length || !HAS_WEBSITE_DB) return;
  try {
    const ids = [...new Set(productIds.filter(Boolean))];
    if (!ids.length) return;
    const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');
    const { rows: linked } = await posDb.query(
      `SELECT id, dentrust_id, quantity, checkbox_values, variants FROM products WHERE dentrust_id IS NOT NULL AND id IN (${placeholders})`,
      ids
    );
    if (!linked.length) return;
    const client = await dentrustDb.connect();
    try {
      for (const p of linked) {
        try {
          const cbJson = p.checkbox_values
            ? (typeof p.checkbox_values === 'string' ? p.checkbox_values : JSON.stringify(p.checkbox_values))
            : null;
          const varJson = p.variants
            ? (typeof p.variants === 'string' ? p.variants : JSON.stringify(p.variants))
            : null;
          // جيب الصورة من الموقع عشان تتزبط في الـ POS
          const { rows: [webProd] } = await client.query(
            'SELECT photos FROM products WHERE id=$1', [p.dentrust_id]
          ).catch(() => ({ rows: [null] }));
          if (cbJson) {
            await client.query(
              'UPDATE products SET stock=$1, is_sold_out=$2, checkbox_values=$3 WHERE id=$4',
              [p.quantity, p.quantity <= 0, cbJson, p.dentrust_id]
            );
          } else if (varJson) {
            await client.query(
              'UPDATE products SET stock=$1, is_sold_out=$2, variants=$3 WHERE id=$4',
              [p.quantity, p.quantity <= 0, varJson, p.dentrust_id]
            );
          } else {
            await client.query(
              'UPDATE products SET stock=$1, is_sold_out=$2 WHERE id=$3',
              [p.quantity, p.quantity <= 0, p.dentrust_id]
            );
          }
          if (firstPhoto) {
            await posDb.query(
              'UPDATE products SET image_url=COALESCE(NULLIF(image_url,\'\'), $1) WHERE id=$2',
              [firstPhoto, p.id]
            ).catch(() => {});
          }
        } catch (_) {}
      }
      cacheDel('site_products');
    } finally { client.release(); }
  } catch (_) {}
}


async function syncNewProductToDentrust(posId, d) {
  const client = await dentrustDb.connect();
  try {
    const catName = (d.category || '').trim() || 'General';
    let { rows: [catRow] } = await client.query("SELECT id FROM categories WHERE LOWER(TRIM(name))=LOWER($1) LIMIT 1", [catName.toLowerCase()]);
    if (!catRow) {
      try {
        const { rows: [newCat] } = await client.query("INSERT INTO categories (name, section) VALUES ($1, 'dental') RETURNING id", [catName]);
        catRow = newCat;
      } catch (_dupErr) {
        const { rows: [existing] } = await client.query("SELECT id FROM categories WHERE LOWER(TRIM(name))=LOWER($1) LIMIT 1", [catName.toLowerCase()]);
        catRow = existing;
      }
    }
    const details = (d.description || '').trim() || d.product_name;
    const variantsJson = d.variants ? JSON.stringify(d.variants) : null;
    const cbJson = d.checkbox_values ? JSON.stringify(d.checkbox_values) : null;
    // Upload image to Supabase Storage so it appears on the website
    let photosArr = [];
    if (d.image_url) {
      if (d.image_url.startsWith('data:')) {
        const imgUrl = await uploadBase64ToSupabase(d.image_url);
        if (imgUrl) photosArr = [imgUrl];
      } else if (d.image_url.startsWith('http')) {
        photosArr = [d.image_url];
      }
    }
    const { rows: [ins] } = await client.query(
      'INSERT INTO products (name, price, purchase_price, stock, is_offer, photos, category_id, expiry_date, details, section, variants, checkbox_values) VALUES ($1,$2,$3,$4,false,$5,$6,$7,$8,$9,$10,$11) RETURNING id',
      [d.product_name, d.sale_price || 0, d.purchase_price ? String(d.purchase_price) : null,
       d.quantity || 0, photosArr, catRow.id, d.expiry_date || null, details,
       d.section || 'dental', variantsJson, cbJson]
    );
    await posDb.query('UPDATE products SET dentrust_id=$1 WHERE id=$2', [ins.id, posId]);
  } finally { client.release(); }
}

async function syncUpdateProductToDentrust(pid, d) {
  let targetWebId = null;
  const { rows: [row] } = await posDb.query('SELECT dentrust_id, product_name, barcode FROM products WHERE id=$1', [pid]);
  targetWebId = row?.dentrust_id;
  
  const client = await dentrustDb.connect();
  try {
    if (!targetWebId && row?.product_name) {
      const { rows: [found] } = await client.query(
        'SELECT id FROM products WHERE LOWER(TRIM(name)) = LOWER(TRIM($1)) OR (barcode IS NOT NULL AND barcode = $2 AND barcode != \'\') LIMIT 1',
        [row.product_name, row.barcode || '']
      ).catch(() => ({ rows: [] }));
      if (found) {
        targetWebId = found.id;
        await posDb.query('UPDATE products SET dentrust_id=$1 WHERE id=$2', [targetWebId, pid]).catch(() => {});
      }
    }
    if (!targetWebId) return;

    const variantsJson = d.variants ? JSON.stringify(d.variants) : null;
    const cbJson = d.checkbox_values ? JSON.stringify(d.checkbox_values) : null;
    const isHidden = d.is_hidden_from_website === true || d.is_hidden_from_website === 'true';

    await client.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS is_hidden BOOLEAN DEFAULT FALSE').catch(() => {});
    await client.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS hidden BOOLEAN DEFAULT FALSE').catch(() => {});
    await client.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS is_hidden_from_website BOOLEAN DEFAULT FALSE').catch(() => {});

    await client.query(
      'UPDATE products SET name=$1, price=$2, stock=$3, expiry_date=$4, purchase_price=COALESCE($5, purchase_price), variants=$6, section=$7, checkbox_values=$8, is_hidden=$9, hidden=$9, is_hidden_from_website=$9 WHERE id=$10',
      [d.product_name, d.sale_price || 0, d.quantity || 0, d.expiry_date || null,
       d.purchase_price ? String(d.purchase_price) : null, variantsJson,
       d.section || 'dental', cbJson, isHidden, targetWebId]);
    await client.query('UPDATE products SET is_active=$1 WHERE id=$2', [!isHidden, targetWebId]).catch(() => {});
  } finally { client.release(); }
}

// ── Sync POS customer → Supabase (creates account with token for website login) ─
async function syncCustomerToSupabase(posCustomer) {
  if (!HAS_WEBSITE_DB) return null;
  const phone = posCustomer.phone?.trim();
  if (!phone) return null;
  const client = await dentrustDb.connect();
  try {
    const { rows: [existing] } = await client.query(
      'SELECT id FROM customers WHERE phone=$1', [phone]
    );
    if (existing) {
      await client.query(
        `UPDATE customers SET name = CASE WHEN name IS NULL OR name='' THEN $1 ELSE name END WHERE phone=$2`,
        [posCustomer.name || '', phone]
      );
      if (posCustomer.id) {
        await posDb.query(
          'UPDATE customers SET dentrust_id=$1 WHERE id=$2 AND dentrust_id IS NULL',
          [existing.id, posCustomer.id]
        );
      }
      return existing.id;
    } else {
      const token = uuidv4();
      const { rows: [ins] } = await client.query(
        'INSERT INTO customers (name, phone, token) VALUES ($1,$2,$3) RETURNING id',
        [posCustomer.name || '', phone, token]
      );
      if (ins && posCustomer.id) {
        await posDb.query('UPDATE customers SET dentrust_id=$1 WHERE id=$2', [ins.id, posCustomer.id]);
      }
      return ins?.id ?? null;
    }
  } finally {
    client.release();
  }
}

// ── Sync POS sale → Supabase orders (so customer sees it on the website) ────
async function syncSaleToSupabase(posCustomerId, posCustomerName, saleId, totalAmount, paymentMethod, splitData, items) {
  if (!HAS_WEBSITE_DB || !posCustomerId) return;
  const { rows: [cust] } = await posDb.query(
    'SELECT name, phone, city, region, street, building_number, landmark FROM customers WHERE id=$1', [posCustomerId]
  );
  // Fix: لو مفيش تليفون، نستخدم identifier بديل بدل ما نوقف الـ sync
  const phone = cust?.phone?.trim() || `pos_customer_${posCustomerId}`;
  const custName = cust?.name || posCustomerName || 'عميل نقدي';
  // Fix: أوردرات البيع من الكاشير مفيهاش عنوان توصيل، لكن الجدول محتاج القيم دي موجودة
  // (حتى لو فاضية) زي بالظبط ما بيحصل لما العميل يطلب من الموقع نفسه
  const city = cust?.city || '';
  const region = cust?.region || '';
  const street = cust?.street || '';
  const buildingNumber = cust?.building_number || '';
  const landmark = cust?.landmark || '';
  const client = await dentrustDb.connect();
  try {
    const instapayAmt = parseFloat(splitData?.instapay || 0);
    await client.query('BEGIN');
    const { rows: [order] } = await client.query(
      `INSERT INTO orders (customer_name, phone, total_price, payment_method, status, shipping_fee, instapay_amount, city, region, street, building_number, landmark)
       VALUES ($1,$2,$3,$4,'delivered',0,$5,$6,$7,$8,$9,$10) RETURNING id`,
      [custName, phone, totalAmount, paymentMethod, instapayAmt, city, region, street, buildingNumber, landmark]
    );
    if (!order) { await client.query('ROLLBACK'); return; }
    // Fix: كانت أخطاء إدراج المنتجات هنا بتُبلَع بصمت (catch فاضي)، فكان
    // ينشأ الطلب بسعره الصحيح لكن بدون منتجات بشكل نهائي بدون أي تنبيه.
    // دلوقتي: أي خطأ في إدراج أي منتج يفشّل العملية كاملة (rollback) ويترفع
    // الخطأ لفوق، عشان الطلب يتحفظ في sync_queue ويُعاد المحاولة تلقائيًا
    // بدل ما يفضل طلب ناقص المنتجات للأبد.
    for (const item of items) {
      await client.query(
        'INSERT INTO order_items (order_id, product_name, quantity, unit_price, selected_option) VALUES ($1,$2,$3,$4,$5)',
        [
          order.id,
          item.product_name || 'منتج',
          item.quantity || 1,
          item.unit_price || 0,
          item.selected_option || item.selectedOption || item._checkbox || null,
        ]
      );
    }
    await client.query('COMMIT');
    await posDb.query('UPDATE sales SET dentrust_order_id=$1 WHERE id=$2', [String(order.id), saleId]).catch(() => {});
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('[syncSaleToSupabase] failed, will retry via sync_queue:', err.message);
    throw err;
  } finally {
    client.release();
  }
}

async function upsertCustomerInPOS(data) {
  const { name, phone, city, region, street, building, landmark, address, dentrust_id } = data;
  if (!phone) return null;
  const cleanPhone = phone.trim();
  const fullAddr = address || [street, building, region].filter(Boolean).join('، ');
  const { rows: [existing] } = await posDb.query('SELECT id FROM customers WHERE phone=$1', [cleanPhone]);
  if (existing) {
    await posDb.query(
      `UPDATE customers SET
        name = CASE WHEN name IS NULL OR name='' THEN $1 ELSE name END,
        city = COALESCE(NULLIF($2,''), city), region = COALESCE(NULLIF($3,''), region),
        street = COALESCE(NULLIF($4,''), street), building_number = COALESCE(NULLIF($5,''), building_number),
        landmark = COALESCE(NULLIF($6,''), landmark), address = COALESCE(NULLIF($7,''), address),
        dentrust_id = COALESCE(dentrust_id, $8) WHERE phone=$9`,
      [name, city || '', region || '', street || '', building || '', landmark || '', fullAddr, dentrust_id, cleanPhone]
    );
    return existing.id;
  }
  const { rows: [ins] } = await posDb.query(
    'INSERT INTO customers (name, phone, city, region, street, building_number, landmark, address, dentrust_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',
    [name, cleanPhone, city || '', region || '', street || '', building || '', landmark || '', fullAddr, dentrust_id]
  );
  // 🔔 Alert POS staff: new customer registered from website
  try {
    const addrDisplay = fullAddr || city || region || '';
    await posDb.query(
      `INSERT INTO website_order_alerts
         (customer_name, customer_phone, customer_city, customer_address, dentrust_order_id, total_amount, items_count, items_summary, seen)
       VALUES ($1,$2,$3,$4,'new_customer',0,0,'تسجيل جديد من الموقع',false)`,
      [name, cleanPhone, city || '', addrDisplay]
    );
  } catch (_) {}
  return ins.id;
}

// ── API: Sync Routes ──────────────────────────────────────────────────────────

app.get(`${BASE}/api/sync/dentrust-products`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  // connected to website DB (single-DB or Supabase mode)
  try {
    const client = await dentrustDb.connect();
    try {
      const { rows } = await client.query('SELECT id, name, stock FROM products ORDER BY name');
      res.json(rows);
    } finally { client.release(); }
  } catch (err) { res.status(503).json({ error: 'فشل الاتصال بـ DenTrust' }); }
});

app.get(`${BASE}/api/sync/pos-products`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  try {
    const { rows } = await posDb.query('SELECT id, product_name, quantity, dentrust_id FROM products ORDER BY product_name');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/sync/dentrust-customers`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  // connected to website DB (single-DB or Supabase mode)
  try {
    const client = await dentrustDb.connect();
    try {
      const { rows } = await client.query('SELECT id, name, phone FROM customers ORDER BY name LIMIT 1000');
      res.json(rows);
    } finally { client.release(); }
  } catch (err) { res.status(503).json({ error: 'فشل الاتصال بـ DenTrust' }); }
});

app.get(`${BASE}/api/sync/pos-customers`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  try {
    const { rows } = await posDb.query('SELECT id, name, phone, dentrust_id FROM customers ORDER BY name');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/link`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  // Support both payload formats: {pos_id, dentrust_id} and {pos_product_id, dentrust_product_id}
  const posId      = req.body.pos_id       || req.body.pos_product_id;
  const dentrustId = req.body.dentrust_id  || req.body.dentrust_product_id;
  await posDb.query('UPDATE products SET dentrust_id=$1 WHERE id=$2', [dentrustId || null, posId]);
  res.json({ ok: true });
});

app.post(`${BASE}/api/sync/push-unlinked`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  // connected to website DB (single-DB or Supabase mode)
  try {
    const { rows: unlinked } = await posDb.query('SELECT * FROM products WHERE dentrust_id IS NULL');
    let pushed = 0, failed = 0;
    for (const p of unlinked) {
      try {
        await syncNewProductToDentrust(p.id, { product_name: p.product_name, sale_price: p.sale_price, purchase_price: p.purchase_price, quantity: p.quantity, category: p.category, description: p.description, expiry_date: p.expiry_date });
        pushed++;
      } catch (_) { failed++; }
    }
    res.json({ ok: true, pushed, failed });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/push-stock`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  // connected to website DB (single-DB or Supabase mode)
  try {
    const { rows: linked } = await posDb.query('SELECT * FROM products WHERE dentrust_id IS NOT NULL');
    const client = await dentrustDb.connect();
    let updated = 0;
    try {
      for (const p of linked) {
        try { await client.query('UPDATE products SET stock=$1, is_sold_out=$2 WHERE id=$3', [p.quantity, p.quantity <= 0, p.dentrust_id]); updated++; } catch (_) {}
      }
    } finally { client.release(); }
    res.json({ ok: true, updated });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/push-images`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  if (!SUPABASE_SERVICE_KEY) return res.status(400).json({ error: 'SUPABASE_SERVICE_KEY غير مضبوط في الـ Environment Variables' });
  try {
    const { rows: linked } = await posDb.query(
      `SELECT id, dentrust_id, image_url FROM products WHERE dentrust_id IS NOT NULL AND image_url IS NOT NULL AND image_url != ''`
    );
    const client = await dentrustDb.connect();
    let uploaded = 0, skipped = 0, failed = 0;
    try {
      for (const p of linked) {
        try {
          // Skip if already a Supabase Storage URL
          if (p.image_url && p.image_url.startsWith('http')) {
            await client.query('UPDATE products SET photos=$1 WHERE id=$2 AND (photos IS NULL OR photos=\'[]\' OR photos=\'\')',
              [JSON.stringify([p.image_url]), p.dentrust_id]);
            skipped++;
            continue;
          }
          if (!p.image_url.startsWith('data:')) {
            // Old broken filesystem path — clear it in POS DB
            await posDb.query('UPDATE products SET image_url=NULL WHERE id=$1', [p.id]);
            skipped++;
            continue;
          }
          const imgUrl = await uploadBase64ToSupabase(p.image_url);
          if (imgUrl) {
            // Update website photos
            await client.query('UPDATE products SET photos=$1 WHERE id=$2', [JSON.stringify([imgUrl]), p.dentrust_id]);
            // Also update POS image_url with the new Supabase URL so it shows in POS inventory
            await posDb.query('UPDATE products SET image_url=$1 WHERE id=$2', [imgUrl, p.id]);
            uploaded++;
          } else { failed++; }
        } catch (_) { failed++; }
      }
    } finally { client.release(); }
    cacheDel('site_products');
    res.json({ ok: true, uploaded, skipped, failed, total: linked.length });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/pull-images`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  try {
    // Get all POS products linked to website that have no valid image_url
    const { rows: linked } = await posDb.query(
      `SELECT p.id, p.dentrust_id, p.image_url FROM products p
       WHERE p.dentrust_id IS NOT NULL
       AND (p.image_url IS NULL OR p.image_url = '' OR (p.image_url NOT LIKE 'data:%' AND p.image_url NOT LIKE 'http%'))`
    );
    const client = await dentrustDb.connect();
    let updated = 0, skipped = 0;
    try {
      for (const p of linked) {
        try {
          const { rows: [wp] } = await client.query(
            'SELECT photos FROM products WHERE id=$1', [p.dentrust_id]
          );
          if (!wp) { skipped++; continue; }
          let photos = [];
          try { photos = typeof wp.photos === 'string' ? JSON.parse(wp.photos) : (wp.photos || []); } catch(_) {}
          const firstPhoto = photos.find(u => u && u.startsWith('http'));
          if (!firstPhoto) { skipped++; continue; }
          await posDb.query('UPDATE products SET image_url=$1 WHERE id=$2', [firstPhoto, p.id]);
          updated++;
        } catch (_) { skipped++; }
      }
    } finally { client.release(); }
    res.json({ ok: true, updated, skipped, total: linked.length });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/push-purchase-prices`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  // connected to website DB (single-DB or Supabase mode)
  try {
    const { rows: linked } = await posDb.query('SELECT * FROM products WHERE dentrust_id IS NOT NULL AND purchase_price > 0');
    const client = await dentrustDb.connect();
    let updated = 0;
    try {
      for (const p of linked) {
        try { await client.query('UPDATE products SET purchase_price=$1 WHERE id=$2', [String(p.purchase_price), p.dentrust_id]); updated++; } catch (_) {}
      }
    } finally { client.release(); }
    res.json({ ok: true, updated });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/pull-stock`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  // connected to website DB (single-DB or Supabase mode)
  try {
    const { rows: linked } = await posDb.query('SELECT * FROM products WHERE dentrust_id IS NOT NULL');
    const client = await dentrustDb.connect();
    let updated = 0;
    try {
      for (const p of linked) {
        try {
          const { rows: [dt] } = await client.query('SELECT stock FROM products WHERE id=$1', [p.dentrust_id]);
          if (dt) { await posDb.query('UPDATE products SET quantity=$1 WHERE id=$2', [dt.stock || 0, p.id]); updated++; }
        } catch (_) {}
      }
    } finally { client.release(); }
    res.json({ ok: true, updated });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/import-products`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  // connected to website DB (single-DB or Supabase mode)
  try {
    const client = await dentrustDb.connect();
    let created = 0, updated = 0;
    try {
      const { rows: dtProducts } = await client.query('SELECT p.*, c.name as cat_name FROM products p LEFT JOIN categories c ON c.id=p.category_id ORDER BY p.name');
      for (const p of dtProducts) {
        try {
          const photoUrl = Array.isArray(p.photos) && p.photos.length > 0
            ? p.photos[0]
            : (typeof p.photos === 'string' ? p.photos : null);
          const { rows: [existing] } = await posDb.query('SELECT id FROM products WHERE dentrust_id=$1', [p.id]);
          if (!existing) {
            await posDb.query(
              `INSERT INTO products (product_name, sale_price, quantity, category, expiry_date, description, dentrust_id, image_url)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
              [p.name, p.price || 0, p.stock || 0, p.cat_name || '', p.expiry_date || null, p.details || '', p.id, photoUrl]
            );
            created++;
          } else {
            await posDb.query(
              `UPDATE products SET product_name=$1, sale_price=$2, quantity=$3, category=$4, image_url=COALESCE($6, image_url) WHERE id=$5`,
              [p.name, p.price || 0, p.stock || 0, p.cat_name || '', existing.id, photoUrl]
            );
            updated++;
          }
        } catch (_) {}
      }
    } finally { client.release(); }
    res.json({ ok: true, created, updated, total: created + updated });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/import-customers`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  // connected to website DB (single-DB or Supabase mode)
  try {
    const client = await dentrustDb.connect();
    let created = 0, skipped = 0;
    try {
      const { rows: dtCustomers } = await client.query('SELECT * FROM customers ORDER BY name LIMIT 2000');
      for (const c of dtCustomers) {
        try {
          const phone = c.phone || c.phone_number || '';
          const { rows: [existing] } = await posDb.query('SELECT id FROM customers WHERE phone=$1 OR dentrust_id=$2', [phone, c.id]);
          if (existing) { skipped++; }
          else {
            await upsertCustomerInPOS({ name: c.name, phone, city: c.city, region: c.region, street: c.street, building: c.building_number, landmark: c.landmark, dentrust_id: c.id });
            created++;
          }
        } catch (_) { skipped++; }
      }
    } finally { client.release(); }
    res.json({ ok: true, created, skipped, total: created + skipped });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/sync/status`, (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  res.json({
    lastPull: null,
    lastPush: null,
    intervalMinutes: 1,
  });
});

app.get(`${BASE}/tools/cleanup-categories`, (req, res) => {
  if (!isMgr(req)) return res.redirect(`${BASE}/login`);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>تنظيف Categories المكررة — DenTrust</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Cairo','Segoe UI',sans-serif;background:#f0f4ff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:16px;padding:40px;max-width:480px;width:100%;box-shadow:0 4px 24px rgba(0,0,0,.1);text-align:center}
.icon{font-size:52px;margin-bottom:16px}
h1{font-size:20px;color:#1a1a2e;margin-bottom:10px}
p{font-size:14px;color:#666;line-height:1.8;margin-bottom:28px}
button{background:#1a56db;color:#fff;border:none;border-radius:10px;padding:14px 36px;font-size:16px;cursor:pointer;width:100%;transition:background .2s}
button:hover:not(:disabled){background:#1342b0}
button:disabled{background:#93b4f5;cursor:not-allowed}
.result{display:none;margin-top:20px;padding:14px;border-radius:10px;font-size:15px;font-weight:600}
.ok{background:#ecfdf5;color:#065f46;border:1px solid #6ee7b7}
.err{background:#fef2f2;color:#991b1b;border:1px solid #fca5a5}
.spinner{display:none;margin:14px auto 0;width:26px;height:26px;border:3px solid #e0e7ff;border-top-color:#1a56db;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="card">
  <div class="icon">🧹</div>
  <h1>تنظيف الـ Categories المكررة</h1>
  <p>تحذف الـ categories المكررة من قاعدة بيانات الموقع<br>وتربط كل المنتجات بالـ category الصحيحة تلقائياً.</p>
  <button id="btn" onclick="run()">🧹 تنظيف الـ Categories المكررة</button>
  <div class="spinner" id="sp"></div>
  <div class="result" id="res"></div>
</div>
<script>
async function run(){
  const btn=document.getElementById('btn'),sp=document.getElementById('sp'),res=document.getElementById('res');
  btn.disabled=true; sp.style.display='block'; res.style.display='none';
  try{
    const r=await fetch('${BASE}/api/sync/cleanup-website-categories',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'}});
    const d=await r.json();
    res.style.display='block';
    if(r.ok&&d.ok){
      res.className='result ok';
      res.textContent=d.removed===0?'✅ ممتاز! مفيش categories مكررة.':'✅ تم حذف '+d.removed+' category مكررة من '+d.groups+' مجموعة!';
    }else{
      res.className='result err';
      res.textContent='❌ '+(d.error||'خطأ غير متوقع');
    }
  }catch(e){
    res.style.display='block';
    res.className='result err';
    res.textContent='❌ تعذّر الاتصال: '+e.message;
  }finally{sp.style.display='none';btn.disabled=false;}
}
</script>
</body>
</html>`);
});


app.post(`${BASE}/api/sync/cleanup-website-categories`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  if (!HAS_WEBSITE_DB) return res.status(400).json({ error: 'لا توجد قاعدة بيانات موقع' });
  const client = await dentrustDb.connect();
  try {
    // Find canonical id (MIN) for each name group
    const { rows: dupes } = await client.query(`
      SELECT LOWER(TRIM(name)) AS norm, MIN(id) AS keep_id, array_agg(id ORDER BY id) AS all_ids
      FROM categories
      GROUP BY LOWER(TRIM(name))
      HAVING COUNT(*) > 1
    `);
    let fixed = 0;
    for (const row of dupes) {
      const dupIds = row.all_ids.filter(id => id !== row.keep_id);
      // Re-point products that reference duplicate category ids to the canonical one
      await client.query(
        `UPDATE products SET category_id=$1 WHERE category_id = ANY($2::int[])`,
        [row.keep_id, dupIds]
      );
      // Delete the duplicate categories
      await client.query('DELETE FROM categories WHERE id = ANY($1::int[])', [dupIds]);
      fixed += dupIds.length;
    }
    res.json({ ok: true, removed: fixed, groups: dupes.length });
  } catch (err) {
    res.status(500).json({ error: 'خطأ داخلي', detail: err.message });
  } finally { client.release(); }
});

async function doFullSync() {
  let synced_products = 0, synced_customers = 0;
  // website DB available via dentrustDb
  const client = await dentrustDb.connect();
  try {
    // Sync products
    const { rows: dtProducts } = await client.query('SELECT p.*, c.name as cat_name FROM products p LEFT JOIN categories c ON c.id=p.category_id ORDER BY p.name');
    for (const p of dtProducts) {
      try {
        const photoUrl = Array.isArray(p.photos) && p.photos.length > 0 ? p.photos[0] : null;
        const cbJson = p.checkbox_values
          ? (typeof p.checkbox_values === 'string' ? p.checkbox_values : JSON.stringify(p.checkbox_values))
          : null;
        const { rows: [ex] } = await posDb.query('SELECT id FROM products WHERE dentrust_id=$1', [p.id]);
        if (!ex) {
          await posDb.query(
            `INSERT INTO products (product_name, sale_price, quantity, category, expiry_date, description, dentrust_id, image_url, checkbox_values)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
            [p.name, p.price || 0, p.stock || 0, p.cat_name || '', p.expiry_date || null, p.details || '', p.id, photoUrl, cbJson]
          );
        } else {
          // السعر محمي — لا يُعدَّل إلا من POS
          await posDb.query(
            `UPDATE products SET product_name=$1, quantity=$2, category=$3,
             image_url=COALESCE($4, image_url), checkbox_values=COALESCE($5, checkbox_values),
             expiry_date=COALESCE($6, expiry_date) WHERE id=$7`,
            [p.name, p.stock || 0, p.cat_name || '', photoUrl, cbJson, p.expiry_date || null, ex.id]);
        }
        synced_products++;
      } catch (_) {}
    }
    // Sync customers
    const { rows: dtCustomers } = await client.query('SELECT * FROM customers ORDER BY name LIMIT 2000');
    for (const c of dtCustomers) {
      try {
        const phone = c.phone || c.phone_number || '';
        await upsertCustomerInPOS({ name: c.name, phone, city: c.city, region: c.region, street: c.street, building: c.building_number, landmark: c.landmark, dentrust_id: c.id });
        synced_customers++;
      } catch (_) {}
    }
  } finally { client.release(); }
  return { synced_products, synced_customers };
}

app.post(`${BASE}/api/sync/full`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  try {
    const result = await doFullSync();
    res.json({ ok: true, ...result });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/force-full`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  try {
    const result = await doFullSync();
    res.json({ ok: true, ...result });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── Bulk push: POS customers → Supabase ──────────────────────────────────────
app.post(`${BASE}/api/sync/push-customers-to-supabase`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  if (!HAS_WEBSITE_DB) return res.status(503).json({ error: 'الاتصال بـ Supabase غير متاح' });
  try {
    const { rows: posCustomers } = await posDb.query(
      "SELECT id, name, phone FROM customers WHERE phone IS NOT NULL AND phone <> '' ORDER BY id"
    );
    let synced = 0, failed = 0;
    for (const c of posCustomers) {
      try { await syncCustomerToSupabase(c); synced++; } catch (_) { failed++; }
    }
    res.json({ ok: true, total: posCustomers.length, synced, failed });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── Bulk push: POS sales → Supabase orders ────────────────────────────────────
app.post(`${BASE}/api/sync/push-sales-to-supabase`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  if (!HAS_WEBSITE_DB) return res.status(503).json({ error: 'الاتصال بـ Supabase غير متاح' });
  try {
    const { rows: sales } = await posDb.query(
      `SELECT s.id, s.total_amount, s.payment_method, s.payment_split, s.customer_id, s.customer_name
       FROM sales s
       JOIN customers c ON c.id = s.customer_id AND c.phone IS NOT NULL AND c.phone <> ''
       WHERE s.dentrust_order_id IS NULL
       ORDER BY s.id`
    );
    let synced = 0, failed = 0;
    for (const sale of sales) {
      try {
        const { rows: items } = await posDb.query(
          'SELECT product_name, quantity, unit_price FROM sale_items WHERE sale_id=$1', [sale.id]
        );
        const splitData = sale.payment_split ? JSON.parse(sale.payment_split) : null;
        await syncSaleToSupabase(sale.customer_id, sale.customer_name, sale.id, sale.total_amount, sale.payment_method, splitData, items);
        synced++;
      } catch (_) { failed++; }
    }
    res.json({ ok: true, total: sales.length, synced, failed });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/fix-missing-items`, async (req, res) => {
  if (!isMgr(req)) return res.status(200).json({ ok: true, fixed: 0, skipped: 0, failed: 0 });
  if (!HAS_WEBSITE_DB) return res.status(503).json({ error: 'لا يوجد اتصال بـ Supabase' });
  try {
    const { rows: sales } = await posDb.query(
      `SELECT s.id, s.dentrust_order_id FROM sales s
       WHERE s.dentrust_order_id IS NOT NULL
       ORDER BY s.id`
    );
    let fixed = 0, skipped = 0, failed = 0;
    for (const sale of sales) {
      try {
        const dtId = parseInt(sale.dentrust_order_id);
        if (!dtId) { skipped++; continue; }
        const client = await dentrustDb.connect();
        try {
          const { rows: existing } = await client.query(
            'SELECT id FROM order_items WHERE order_id=$1 LIMIT 1', [dtId]
          );
          if (existing.length > 0) { skipped++; continue; }
          const { rows: items } = await posDb.query(
            'SELECT product_name, quantity, unit_price FROM sale_items WHERE sale_id=$1', [sale.id]
          );
          if (!items.length) { skipped++; continue; }
          for (const item of items) {
            await client.query(
              'INSERT INTO order_items (order_id, product_name, quantity, unit_price) VALUES ($1,$2,$3,$4)',
              [dtId, item.product_name || 'منتج', item.quantity || 1, item.unit_price || 0]
            );
          }
          fixed++;
        } finally { client.release(); }
      } catch (_) { failed++; }
    }
    res.json({ ok: true, fixed, skipped, failed });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/upsert-customer`, async (req, res) => {
  const d = req.body;
  try {
    // Accept both canonical and legacy alias field names
    const posId = await upsertCustomerInPOS({
      name:        d.name        || d.customer_name,
      phone:       d.phone       || d.customer_phone || d.phone_number,
      city:        d.city        || d.customer_city,
      region:      d.region      || d.customer_region,
      street:      d.street      || d.customer_street,
      building:    d.building_number || d.customer_building || d.building,
      landmark:    d.landmark    || d.customer_landmark,
      address:     d.address,
      dentrust_id: d.dentrust_id || d.dentrust_customer_id,
    });
    res.json({ ok: true, customer_id: posId });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── Safety net: guarantee order_items are saved on the website DB ───────────
// The website (Hostinger/React) writes the order itself directly to Supabase
// on checkout, then calls this endpoint with the same items as a courtesy
// notification for the POS. If the website's own order_items insert silently
// failed (e.g. blocked by a Supabase RLS policy, a dropped request, etc.) the
// order would otherwise be left with a price but no items — exactly the "my
// orders" bug. This function re-checks and backfills order_items using the
// POS server's direct (RLS-bypassing) Postgres connection, so the order is
// always complete regardless of what happened on the frontend.
async function ensureOrderItemsSaved(dentrustOrderId, items) {
  if (!HAS_WEBSITE_DB || !dentrustOrderId || !items || !items.length) return;
  const orderId = parseInt(dentrustOrderId, 10);
  if (!orderId) return;
  const client = await dentrustDb.connect();
  try {
    const { rows: existing } = await client.query(
      'SELECT id FROM order_items WHERE order_id=$1 LIMIT 1', [orderId]
    );
    if (existing.length > 0) return; // already saved correctly, nothing to do
    for (const item of items) {
      await client.query(
        'INSERT INTO order_items (order_id, product_id, product_name, quantity, unit_price, selected_option) VALUES ($1,$2,$3,$4,$5,$6)',
        [
          orderId,
          item.product_id || item.productId || null,
          item.product_name || item.name || 'منتج',
          item.quantity || 1,
          item.unit_price || 0,
          item.selected_option || item.selectedOption || null,
        ]
      );
    }
  } catch (err) {
    console.error('[ensureOrderItemsSaved] failed to backfill order_items for order', dentrustOrderId, err.message);
  } finally {
    client.release();
  }
}

app.post(`${BASE}/api/sync/order-placed`, async (req, res) => {
  const d = req.body;
  try {
    // 🔔 Insert alert for POS staff
    const alertItems = (d.items || []);
    const alertSummary = alertItems.map(i => `${i.product_name || i.name || '?'} x${i.quantity || 1}`).join('، ');
    const alertTotal = parseFloat(d.total_amount || d.total || 0) ||
      alertItems.reduce((s, i) => s + parseFloat(i.unit_price || 0) * parseInt(i.quantity || 1, 10), 0);
    await posDb.query(
      `INSERT INTO website_order_alerts
         (customer_name, customer_phone, customer_city, customer_address, dentrust_order_id,
          total_amount, items_count, items_summary, promo_code, discount_amount, delivery_amount)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [
        d.customer_name || 'عميل',
        d.customer_phone || '',
        d.customer_city || d.city || '',
        [d.customer_region || d.region, d.customer_street || d.street,
         d.customer_building || d.building_number, d.customer_landmark || d.landmark
        ].filter(Boolean).join(' - ') || '',
        d.dentrust_order_id || null,
        alertTotal, alertItems.length, alertSummary || '—',
        d.promo_code || null,
        d.discount_amount != null && d.discount_amount !== '' ? parseFloat(d.discount_amount) : null,
        (d.delivery_amount != null && d.delivery_amount !== '' ? parseFloat(d.delivery_amount) : (d.delivery_fee != null && d.delivery_fee !== '' ? parseFloat(d.delivery_fee) : null))
      ]
    ).catch(() => {});

    // 🔔 Send push notification to all staff devices
    sendPushToAll(
      '🛒 طلب جديد من الموقع!',
      `العميل: ${d.customer_name || 'عميل'} — الإجمالي: ${alertTotal.toFixed(2)} ج.م`,
      `${BASE}/website-orders`,
      'web-order'
    ).catch(() => {});

    const customerId = await upsertCustomerInPOS({
      name: d.customer_name,
      phone: d.customer_phone,
      city:     d.customer_city     || d.city,
      region:   d.customer_region   || d.region,
      street:   d.customer_street   || d.street,
      building: d.customer_building || d.building_number,
      landmark: d.customer_landmark || d.landmark,
      dentrust_id: d.dentrust_customer_id,
    });
    const items = d.items || [];
    // Safety net — make sure the order actually has its items saved on the
    // website DB, regardless of what happened on the frontend checkout call.
    await ensureOrderItemsSaved(d.dentrust_order_id, items);
    let total = parseFloat(d.total_amount || d.total || 0);
    if (!total && items.length) total = items.reduce((s, i) => s + parseFloat(i.unit_price || 0) * parseInt(i.quantity || 1, 10), 0);
    const onlineDiscount = d.discount_amount != null && d.discount_amount !== '' ? parseFloat(d.discount_amount) : 0;
    const onlineDelivery = d.delivery_amount != null && d.delivery_amount !== '' ? parseFloat(d.delivery_amount) : (d.delivery_fee != null && d.delivery_fee !== '' ? parseFloat(d.delivery_fee) : 0);
    const { rows: [sale] } = await posDb.query(
      `INSERT INTO sales (total_amount, payment_method, customer_id, source, dentrust_order_id, customer_name, discount_amount, delivery_amount)
       VALUES ($1,'online',$2,'online',$3,$4,$5,$6) RETURNING id`,
      [total, customerId, d.dentrust_order_id || null, d.customer_name || '', onlineDiscount, onlineDelivery]
    );
    const saleId = sale.id;
    let deducted = 0;
    // Helper: find POS product by dentrust_id first, then barcode, then name
    async function findPosProduct(item) {
      const dtProdId = item.dentrust_product_id || item.productId || item.product_id;
      // 1. Try by dentrust_id (fastest — requires sync setup)
      if (dtProdId) {
        const { rows: [r] } = await posDb.query(
          'SELECT id, product_name, purchase_price FROM products WHERE dentrust_id=$1', [dtProdId]
        );
        if (r) return r;
      }
      // 2. Try by barcode
      if (item.barcode) {
        const { rows: [r] } = await posDb.query(
          'SELECT id, product_name, purchase_price FROM products WHERE barcode=$1', [item.barcode]
        );
        if (r) {
          // Auto-link dentrust_id so future orders find it instantly
          if (dtProdId) posDb.query('UPDATE products SET dentrust_id=$1 WHERE id=$2 AND dentrust_id IS NULL', [dtProdId, r.id]).catch(() => {});
          return r;
        }
      }
      // 3. Try by product_name (case-insensitive exact match)
      const pname = (item.product_name || item.name || '').trim();
      if (pname) {
        const { rows: [r] } = await posDb.query(
          'SELECT id, product_name, purchase_price FROM products WHERE LOWER(product_name)=LOWER($1)', [pname]
        );
        if (r) {
          // Auto-link dentrust_id for next time
          if (dtProdId) posDb.query('UPDATE products SET dentrust_id=$1 WHERE id=$2 AND dentrust_id IS NULL', [dtProdId, r.id]).catch(() => {});
          return r;
        }
      }
      return null;
    }

    const deductedProdIds = [];
    for (const item of items) {
      const prod = await findPosProduct(item);
      const itemQty = item.quantity || 1;
      const selOpt  = item.selectedOption || item.selected_option || null;
      await posDb.query(
        'INSERT INTO sale_items (sale_id, product_id, product_name, quantity, unit_price, snapshot_unit_price, snapshot_purchase_price, selected_option) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [saleId, prod?.id || null, item.product_name || item.name || prod?.product_name || '', itemQty, item.unit_price || 0, item.unit_price || 0, prod?.purchase_price || 0, selOpt]
      );
      if (prod?.id) {
        // Deduct overall quantity first (covers non-checkbox products)
        await posDb.query('UPDATE products SET quantity = GREATEST(0, quantity - $1) WHERE id=$2', [itemQty, prod.id]);

        // ── Checkbox-option stock deduction ─────────────────────────────────
        // When a specific option is selected (e.g. a size/colour sold on the website),
        // deduct from that option's stock inside checkbox_values JSON and then
        // recalculate the main quantity as the sum of all remaining option stocks.
        // This mirrors the same logic used for in-store POS sales.
        if (selOpt) {
          try {
            const { rows: [pv] } = await posDb.query('SELECT checkbox_values FROM products WHERE id=$1', [prod.id]);
            if (pv?.checkbox_values) {
              const cbv = typeof pv.checkbox_values === 'string' ? JSON.parse(pv.checkbox_values) : { ...pv.checkbox_values };
              // selectedOption from website may be "category::key" — try both forms
              const shortKey = selOpt.includes('::') ? selOpt.split('::').pop() : null;
              const optKey   = cbv[selOpt] !== undefined ? selOpt
                             : (shortKey && cbv[shortKey] !== undefined ? shortKey : null);
              if (optKey && typeof cbv[optKey] === 'object' && cbv[optKey].stock != null) {
                cbv[optKey].stock = Math.max(0, cbv[optKey].stock - itemQty);
                // Recalculate main quantity as sum of all remaining checkbox stocks
                const newQty = Object.values(cbv).reduce(
                  (s, v) => s + (typeof v === 'object' && v.stock != null ? Math.max(0, v.stock) : 0), 0);
                await posDb.query(
                  'UPDATE products SET quantity=$1, checkbox_values=$2 WHERE id=$3',
                  [newQty, JSON.stringify(cbv), prod.id]
                );
              }
            }
          } catch (_) {}
        }

        deducted++;
        deductedProdIds.push({ pid: prod.id, delta: -itemQty, selectedOption: selOpt });
      }
    }
    // Sync actual current POS stock to website (NOT delta — website already deducted its own stock)
    if (deductedProdIds.length > 0) syncProductsNow(deductedProdIds.map(d => d.pid)).catch(() => {});
    // Flask: online orders do NOT increment customer debt on order-placed;
    // debt tracking is handled separately via confirm-online-order / credit payments.
    res.json({ ok: true, sale_id: saleId, deducted, customer_id: customerId });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// Flask-equivalent payment method normalization for online orders
function normalizePaymentMethod(raw) {
  const ALLOWED = new Set(['cash', 'instapay', 'credit', 'online', 'split']);
  if (!raw) return 'cash';
  const m = String(raw).toLowerCase().trim();
  if (m === 'cod') return 'cash';
  if (m === 'split') return 'instapay';
  return ALLOWED.has(m) ? m : 'cash';
}

app.post(`${BASE}/api/sync/confirm-online-order`, async (req, res) => {
  const { dentrust_order_id, payment_method, total_amount, customer_name } = req.body;
  try {
    const method = normalizePaymentMethod(payment_method);
    const orderId = parseInt(dentrust_order_id, 10);
    if (isNaN(orderId)) return res.json({ ok: true, sale_id: null, note: 'invalid order id' });
    let { rows: [sale] } = await posDb.query('SELECT * FROM sales WHERE dentrust_order_id=$1', [orderId]);
    if (!sale) {
      // Flask behavior: create a full sale when not found, resolving customer + items from DenTrust DB
      const total = parseFloat(total_amount || 0);
      const creditPaid = (method === 'credit') ? 0 : 1;
      let custId = null;
      let saleItems = [];
      try {
        const dtClient = await dentrustDb.connect();
        try {
          // Look up DenTrust order for customer + items
          const { rows: [dtOrder] } = await dtClient.query('SELECT * FROM orders WHERE id=$1', [orderId]);
          if (dtOrder) {
            custId = await upsertCustomerInPOS({
              name: dtOrder.customer_name || customer_name || '',
              phone: dtOrder.customer_phone || '',
              city: dtOrder.customer_city || dtOrder.city,
              region: dtOrder.customer_region || dtOrder.region,
              street: dtOrder.customer_street || dtOrder.street,
            });
            const { rows: dtItems } = await dtClient.query('SELECT * FROM order_items WHERE order_id=$1', [orderId]);
            saleItems = dtItems;
          }
        } finally { dtClient.release(); }
      } catch (_) {}
      const { rows: [newSale] } = await posDb.query(
        `INSERT INTO sales (total_amount, payment_method, source, dentrust_order_id, customer_name, customer_id, credit_paid)
         VALUES ($1,$2,'online',$3,$4,$5,$6) RETURNING *`,
        [total, method, orderId, customer_name || '', custId, creditPaid]
      );
      for (const item of saleItems) {
        try {
          const { rows: [prod] } = await posDb.query('SELECT id, product_name FROM products WHERE dentrust_id=$1', [item.product_id || item.dentrust_product_id]);
          await posDb.query(
            'INSERT INTO sale_items (sale_id, product_id, product_name, quantity, unit_price, snapshot_unit_price) VALUES ($1,$2,$3,$4,$5,$6)',
            [newSale.id, prod?.id || null, item.product_name || prod?.product_name || '', item.quantity || 1, item.unit_price || item.price || 0, item.unit_price || item.price || 0]
          );
          if (prod?.id) await posDb.query('UPDATE products SET quantity = GREATEST(0, quantity - $1) WHERE id=$2', [item.quantity || 1, prod.id]);
        } catch (_) {}
      }
      return res.json({ ok: true, sale_id: newSale.id });
    } else {
      // Flask behavior: if sale already exists, return idempotently without mutating financial state
    }
    res.json({ ok: true, sale_id: sale.id });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/upsert-product`, async (req, res) => {
  const d = req.body;
  const action = d.action || 'upsert';
  const name = d.name || d.product_name || '';
  const price = d.price || d.sale_price || 0;
  const stock = d.stock !== undefined ? d.stock : (d.quantity !== undefined ? d.quantity : 0);
  const category = d.category || d.cat_name || null;
  const expiry = d.expiry_date || null;
  try {
    if (d.dentrust_id) {
      let { rows: [existing] } = await posDb.query('SELECT id FROM products WHERE dentrust_id=$1', [d.dentrust_id]);
      if (!existing && name) {
        // Link-by-name: find unlinked product with matching name
        const { rows: [byName] } = await posDb.query(
          'SELECT id FROM products WHERE LOWER(product_name)=LOWER($1) AND (dentrust_id IS NULL OR dentrust_id=0) LIMIT 1', [name]
        );
        if (byName) {
          await posDb.query('UPDATE products SET dentrust_id=$1 WHERE id=$2', [d.dentrust_id, byName.id]);
          existing = byName;
        }
      }
      if (existing) {
        const _cbJsonUp = d.checkbox_values ? JSON.stringify(d.checkbox_values) : null;
        // سعر الشراء محمي — لا يُعدَّل من الموقع، والـ POS هو المصدر الوحيد له
        await posDb.query(
          'UPDATE products SET product_name=$1, quantity=$2, expiry_date=$3, category=COALESCE($4, category), checkbox_values=COALESCE($5, checkbox_values) WHERE dentrust_id=$6',
          [name, stock, expiry, category, _cbJsonUp, d.dentrust_id]
        );
      } else {
        await posDb.query(
          'INSERT INTO products (product_name, sale_price, quantity, expiry_date, dentrust_id, category) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING',
          [name, price, stock, expiry, d.dentrust_id, category]
        );
      }
    }
    res.json({ ok: true, action });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/delete-product`, async (req, res) => {
  const { dentrust_id } = req.body;
  if (dentrust_id) await posDb.query('DELETE FROM products WHERE dentrust_id=$1', [dentrust_id]).catch(() => {});
  res.json({ ok: true });
});


// ── Utility ───────────────────────────────────────────────────────────────────

function r2(n) { return Math.round(parseFloat(n || 0) * 100) / 100; }


// ═══════════════════════════════════════════════════════════════════════════════
// ── WEBSITE API (called from dentrust.site — no POS session required) ─────────
// ═══════════════════════════════════════════════════════════════════════════════

const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY || '';
const SUPABASE_BASE = 'https://ywfunodybcqakhweuxwn.supabase.co';
const WEBSITE_ORIGINS = (process.env.WEBSITE_ORIGIN || 'https://dentrust.site,https://www.dentrust.site')
  .split(',').map(s => s.trim());

const webCors = cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (WEBSITE_ORIGINS.some(o => origin === o) || /localhost/.test(origin)) return cb(null, true);
    cb(null, false);
  },
  credentials: false,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
});
app.options('/api/*', webCors);

// ── Products (public, from Supabase) ─────────────────────────────────────────
const _memCache = {};
function cacheSet(k, v, ttlMs) { _memCache[k] = { v, exp: Date.now() + ttlMs }; }
function cacheGet(k) { const e = _memCache[k]; return e && e.exp > Date.now() ? e.v : null; }
function cacheDel(k) { delete _memCache[k]; }

app.get('/api/products', webCors, async (req, res) => {
  // products served from website DB — 30s in-memory cache
  const cached = cacheGet('site_products');
  if (cached) return res.json(cached);
  try {
    const client = await dentrustDb.connect();
    try {
      const { rows } = await client.query(
        `SELECT p.id, p.name, p.price, p.purchase_price, p.stock,
                p.photos[1] AS image_url, p.expiry_date, p.description,
                c.name AS category_name, p.category_id
         FROM products p
         LEFT JOIN categories c ON c.id = p.category_id
         ORDER BY p.name`
      );
      // Convert relative Supabase storage paths to full public URLs
      for (const row of rows) {
        if (row.image_url && row.image_url.startsWith('/objects/')) {
          row.image_url = 'https://ywfunodybcqakhweuxwn.supabase.co/storage/v1/object/public' + row.image_url;
        } else if (row.image_url && row.image_url.startsWith('objects/')) {
          row.image_url = 'https://ywfunodybcqakhweuxwn.supabase.co/storage/v1/object/public/' + row.image_url;
        }
      }
      cacheSet('site_products', rows, 30000);
      res.json(rows);
    } finally { client.release(); }
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── Storage proxy (Supabase storage images) ───────────────────────────────────
app.get('/api/storage/*', webCors, async (req, res) => {
  const storagePath = req.path.replace('/api/storage', '');
  const target = `${SUPABASE_BASE}/storage/v1${storagePath}`;
  try {
    const r = await fetch(target, { signal: AbortSignal.timeout(10000) });
    if (!r.ok) return res.status(r.status).send('Not found');
    const ct = r.headers.get('content-type');
    if (ct) res.setHeader('Content-Type', ct);
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.send(Buffer.from(await r.arrayBuffer()));
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── Bot Knowledge – cache + loader ────────────────────────────────────────────
let _knowledgeCache = null;
let _knowledgeCacheAt = 0;
const KNOWLEDGE_TTL = 300_000; // 5 min cache — reduces DB hits on every chat message

async function getBotKnowledgeText() {
  const now = Date.now();
  if (_knowledgeCache !== null && now - _knowledgeCacheAt < KNOWLEDGE_TTL) {
    return _knowledgeCache;
  }
  try {
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('knowledge timeout')), 4000)
    );

    const [knowledgeResult, productsResult] = await Promise.race([
      Promise.all([
        posDb.query("SELECT category, title, content FROM bot_knowledge WHERE active=true ORDER BY category, id"),
        posDb.query("SELECT id, product_name, sale_price, category, quantity, description FROM products WHERE quantity > 0 ORDER BY product_name"),
      ]),
      timeout,
    ]);

    let text = '';

    if (knowledgeResult.rows.length) {
      const lines = knowledgeResult.rows.map(r => `[${r.category}] ${r.title}: ${r.content}`).join('\n');
      text += `\n\n=== معلومات مخزّنة من إدارة المتجر — التزم بها تماماً وأجب منها مباشرةً ===\n${lines}\n===`;
    }

    if (productsResult.rows.length) {
      // Cap the number of products and the length of each line so the system
      // prompt stays well under Groq's tokens-per-minute limit (12000 TPM on
      // some models). Sending all products unbounded caused every chat
      // request to be rejected with "Request too large" once the catalog
      // grew past ~150 items.
      const MAX_PRODUCTS = 120;
      const MAX_DESC_LEN = 60;
      const productLines = productsResult.rows.slice(0, MAX_PRODUCTS).map(r => {
        let line = `- [ID:${r.id}] ${r.product_name}`;
        if (r.category) line += ` (${r.category})`;
        if (r.sale_price) line += ` — السعر: ${r.sale_price} جنيه`;
        if (r.description) line += ` — ${String(r.description).slice(0, MAX_DESC_LEN)}`;
        return line;
      }).join('\n');
      const truncatedNote = productsResult.rows.length > MAX_PRODUCTS
        ? `\n(+ ${productsResult.rows.length - MAX_PRODUCTS} منتج إضافي غير مذكور هنا)`
        : '';
      text += `\n\n=== قائمة المنتجات المتوفرة حالياً في المخزون ===\n${productLines}${truncatedNote}\n===`;
    }

    _knowledgeCache = text;
    _knowledgeCacheAt = now;
    return _knowledgeCache;
  } catch { return ''; }
}

// Language restriction — always prepended to every system prompt
const LANG_INSTRUCTION = 'IMPORTANT: You must respond ONLY in Arabic or English. If the user writes in Arabic, reply in Arabic. If the user writes in English, reply in English. Never use any other language under any circumstances.\n\n';

// Hard safety cap on the combined system prompt sent to Gemini.
// Gemini 2.0 Flash supports up to 1M tokens context — 20000 chars
// gives ample room for full product catalogs, knowledge base entries,
// and conversation history without hitting any limits.
const MAX_SYSTEM_CHARS = 20000;
function capSystemContent(content) {
  if (!content || content.length <= MAX_SYSTEM_CHARS) return content;
  return content.slice(0, MAX_SYSTEM_CHARS) + '\n(تم اختصار باقي القائمة لتوفير المساحة)';
}

// Cap the completion budget. Gemini 2.0 Flash supports generous output —
// 800 tokens gives detailed, helpful responses without waste.
const MAX_COMPLETION_TOKENS = 4096;
function capMaxTokens(requested) {
  const n = Number(requested) || MAX_COMPLETION_TOKENS;
  return Math.min(n, MAX_COMPLETION_TOKENS);
}

// ── AI – shared helper ────────────────────────────────────────────────────────
// Dynamic free-model cache — refreshed from OpenRouter every hour
let _freeModelCache = null;
let _freeModelCacheAt = 0;

// Stable high-quality free models — always tried first
const PREFERRED_FREE_MODELS = [
  'nvidia/nemotron-3-ultra:free',
  'openai/gpt-oss-120b:free',
  'google/gemma-4-31b-it:free',
  'nvidia/nemotron-3-super-120b-a12b:free',
];

// Keywords that mark a model as code/math-only — bad for Arabic chat
const CODE_MODEL_RE = /code|math|coder|sql|starcoder|wizard.*math/i;
// Keywords that mark a model as good for general chat
const CHAT_MODEL_RE = /llama|qwen|mistral|gemma|deepseek|phi|command|hermes|nous|zephyr|solar|openchat|smollm|internlm/i;

function sortFreeModels(ids) {
  // preferred (known-good) first, then general chat, then neutral, then code last
  const top      = PREFERRED_FREE_MODELS.filter(p => ids.includes(p));
  const rest     = ids.filter(id => !PREFERRED_FREE_MODELS.includes(id));
  const chatGood = rest.filter(id => CHAT_MODEL_RE.test(id) && !CODE_MODEL_RE.test(id));
  const neutral  = rest.filter(id => !CHAT_MODEL_RE.test(id) && !CODE_MODEL_RE.test(id));
  const codeLast = rest.filter(id => CODE_MODEL_RE.test(id));
  return [...top, ...chatGood, ...neutral, ...codeLast];
}

async function fetchFreeModels() {
  if (_freeModelCache && Date.now() - _freeModelCacheAt < 3600_000) return _freeModelCache;
  try {
    const r = await fetch('https://openrouter.ai/api/v1/models', {
      headers: { Authorization: `Bearer ${OPENROUTER_KEY}` },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) throw new Error(`models list ${r.status}`);
    const { data } = await r.json();
    const all = (data || []).map(m => m.id).filter(id => id.endsWith(':free'));
    // vision-capable models (those mentioning vision/vl/multimodal in id or architecture)
    const vision = all.filter(id => /vision|vl\b|multimodal/i.test(id));
    const text   = sortFreeModels(all.filter(id => !vision.includes(id)));
    _freeModelCache = { text: text.length ? text : sortFreeModels(all), vision: vision.length ? vision : all };
    _freeModelCacheAt = Date.now();
    console.log(`[AI] free text models: ${_freeModelCache.text.length}, first: ${_freeModelCache.text[0]}, vision: ${_freeModelCache.vision.length}`);
    return _freeModelCache;
  } catch (e) {
    console.warn('[AI] fetchFreeModels failed:', e.message, '— using fallback list');
    return {
      text: [
        'nvidia/nemotron-3-ultra:free',
        'openai/gpt-oss-120b:free',
        'google/gemma-4-31b-it:free',
        'nvidia/nemotron-3-super-120b-a12b:free',
        'meta-llama/llama-3.3-70b-instruct:free',
        'qwen/qwen-2.5-72b-instruct:free',
      ],
      vision: [
        'meta-llama/llama-3.2-11b-vision-instruct:free',
        'qwen/qwen2.5-vl-72b-instruct:free',
      ],
    };
  }
}

async function callOpenRouter(payload) {
  const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${OPENROUTER_KEY}`,
      'Content-Type': 'application/json',
      'HTTP-Referer': 'https://dentrust.site',
      'X-Title': 'DenTrust DenBot',
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(30000),
  });
  return resp.json();
}

// Tries each free model in order; skips on 429/402/404/error-body, returns first success
async function callOpenRouterFree(payload, modelList) {
  // if no explicit list provided, fetch dynamically from OpenRouter
  let models = modelList;
  if (!models) {
    const cache = await fetchFreeModels();
    models = cache.text;
  }
  let lastErr = 'no models available';
  for (const model of models) {
    let resp;
    try {
      resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${OPENROUTER_KEY}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'https://dentrust.site',
          'X-Title': 'DenTrust DenBot',
        },
        body: JSON.stringify({ ...payload, model }),
        signal: AbortSignal.timeout(12000),
      });
    } catch (e) { lastErr = `${model} → ${e.message}`; continue; }
    // Any non-2xx means this model can't serve the request right now (rate
    // limited, unavailable, payload too large, auth issue, etc.) — try the
    // next free model instead of forwarding the error to the caller.
    if (!resp.ok) {
      lastErr = `${model} → ${resp.status}`;
      continue;
    }
    /* check for error body or empty content on 200 */
    const clone = resp.clone();
    try {
      const json = await clone.json();
      if (json.error) { lastErr = `${model} → ${json.error.message}`; continue; }
      const content = json.choices?.[0]?.message?.content;
      if (content !== undefined && content !== null && String(content).trim() === '') {
        lastErr = `${model} → empty response`; continue;
      }
    } catch (_) { /* not JSON — treat as success */ }
    return { resp, model };
  }
  throw new Error(`All free models failed: ${lastErr}`);
}


// بيقرأ Groq SSE ويعيد إرساله بنفس الـ format البسيط اللي الـ frontend بيتوقعه
// Parses and re-emits an OpenAI-compatible SSE stream (works for both Groq
// and OpenRouter — same {choices:[{delta:{content}}]} chunk shape).
async function pipeGroqStream(groqResp, res, providerLabel = 'Groq') {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Accel-Buffering', 'no');
  if (!groqResp.ok) {
    const errBody = await groqResp.json().catch(() => ({}));
    const errMsg = errBody?.error?.message || `${providerLabel} error ${groqResp.status}`;
    console.error(`[${providerLabel}] stream HTTP ${groqResp.status} — ${errMsg}`);
    // Some frontends (denbot widget) only render chunks shaped like
    // {choices:[{delta:{content}}]} — a bare {error} chunk is silently
    // swallowed and the user sees nothing at all. Send both shapes so the
    // failure is always visible instead of a silent empty bubble.
    const visibleMsg = `عذرًا، هناك تحميل كبير على الموقع 🙏 أكثر من ${randomVisitors()} شخص يتصفح الآن — يرجى المحاولة مرة أخرى بعد لحظات.`;
    res.write(`data: ${JSON.stringify({ error: errMsg, choices: [{ delta: { content: visibleMsg }, finish_reason: 'stop' }] })}\r\n\r\n`);
    res.write('data: [DONE]\r\n\r\n');
    return res.end();
  }
  const reader = groqResp.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const lines = buf.split('\n');
    buf = lines.pop(); // احتفظ بالسطر غير المكتمل
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('data:')) continue;
      const raw = trimmed.slice(5).trim();
      if (raw === '[DONE]') { res.write('data: [DONE]\r\n\r\n'); continue; }
      try {
        const parsed = JSON.parse(raw);
        const content = parsed.choices?.[0]?.delta?.content;
        if (!content) continue;
        const chunk = JSON.stringify({ choices: [{ delta: { content }, finish_reason: null }] });
        res.write(`data: ${chunk}\r\n\r\n`);
      } catch (_) {}
    }
  }
  res.write('data: [DONE]\r\n\r\n');
  res.end();
}

// Random visitor count for error messages (>300, changes every call)
const randomVisitors = () => Math.floor(Math.random() * 700) + 301;

// Get best available free text model from live cache
async function getBestFreeModel() {
  return 'nvidia/nemotron-3-super-120b-a12b:free';
}

// GET /api/ai/test  — diagnostic endpoint
// Add ?live=1 to force a real API call
app.get('/api/ai/test', async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  if (!OPENROUTER_KEY) return res.json({ ok: false, error: 'Set OPENROUTER_API_KEY on Render' });
  if (req.query.live === '1') {
    try {
      const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: `Bearer ${OPENROUTER_KEY}`, 'Content-Type': 'application/json', 'HTTP-Referer': 'https://dentrust.site', 'X-Title': 'DenTrust DenBot' },
        body: JSON.stringify({ model: await getBestFreeModel(), max_tokens: 20, messages: [{ role: 'user', content: 'قل مرحبا' }] }),
        signal: AbortSignal.timeout(20000),
      });
      const data = await resp.json();
      if (data.error) return res.json({ ok: false, model: await getBestFreeModel(), error: data.error });
      const reply = data.choices?.[0]?.message?.content || '(no content)';
      return res.json({ ok: true, provider: 'openrouter', model: await getBestFreeModel(), reply, live: true });
    } catch (err) {
      return res.json({ ok: false, error: err.message, live: true });
    }
  }
  return res.json({ ok: true, provider: 'openrouter', model: await getBestFreeModel(), keyConfigured: true, note: 'Add ?live=1 to test a real API call' });
});


// POST /api/ai/fashion-chat  (text chat)
app.post('/api/ai/fashion-chat', webCors, async (req, res) => {
  if (!OPENROUTER_KEY) return res.status(503).json({ error: 'No AI provider configured.' });
  try {
    const { messages = [], system = '', max_tokens = 350 } = req.body;
    const knowledge = await getBotKnowledgeText();
    const combinedSystem = capSystemContent(LANG_INSTRUCTION + system + knowledge);
    const cappedTokens = capMaxTokens(max_tokens);
    const fullMessages = combinedSystem ? [{ role: 'system', content: combinedSystem }, ...messages] : messages;
    const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${OPENROUTER_KEY}`, 'Content-Type': 'application/json', 'HTTP-Referer': 'https://dentrust.site', 'X-Title': 'DenTrust DenBot' },
      body: JSON.stringify({ model: await getBestFreeModel(), messages: fullMessages, max_tokens: cappedTokens }),
      signal: AbortSignal.timeout(30000),
    });
    const data = await resp.json();
    return res.json(data);
  } catch (err) {
    console.error('[AI] fashion-chat error:', err.message);
    res.status(503).json({ error: `عذرًا، هناك تحميل كبير على الموقع 🙏 أكثر من ${randomVisitors()} شخص يتصفح الآن — يرجى المحاولة مرة أخرى بعد لحظات.` });
  }
});


// POST /api/ai/fashion-tryon  (vision)
app.post('/api/ai/fashion-tryon', webCors, async (req, res) => {
  if (!OPENROUTER_KEY) return res.status(503).json({ error: 'No AI provider configured.' });
  try {
    const { messages = [], max_tokens = 500 } = req.body;
    const cappedTokens = capMaxTokens(max_tokens);
    const cache = await fetchFreeModels();
    const visionModel = (cache.vision?.length ? cache.vision[0] : await getBestFreeModel());
    const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${OPENROUTER_KEY}`, 'Content-Type': 'application/json', 'HTTP-Referer': 'https://dentrust.site', 'X-Title': 'DenTrust DenBot' },
      body: JSON.stringify({ model: visionModel, messages, max_tokens: cappedTokens }),
      signal: AbortSignal.timeout(30000),
    });
    const data = await resp.json();
    return res.json(data);
  } catch (err) {
    console.error('[AI] fashion-tryon error:', err.message);
    res.status(503).json({ error: `عذرًا، هناك تحميل كبير على الموقع 🙏 أكثر من ${randomVisitors()} شخص يتصفح الآن — يرجى المحاولة مرة أخرى بعد لحظات.` });
  }
});


// POST /api/ai/fashion-chat-stream  (SSE streaming)
app.post('/api/ai/fashion-chat-stream', webCors, async (req, res) => {
  if (!OPENROUTER_KEY) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.write('data: ' + JSON.stringify({ choices: [{ delta: { content: 'عذرًا، الذكاء الاصطناعي غير مهيّأ.' }, finish_reason: 'stop' }] }) + '\r\n\r\n');
    return res.end();
  }
  try {
    const { messages = [], system = '', max_tokens = 400 } = req.body;
    const knowledge = await getBotKnowledgeText();
    const combinedSystem = capSystemContent(LANG_INSTRUCTION + system + knowledge);
    const cappedTokens = capMaxTokens(max_tokens);
    const fullMessages = combinedSystem ? [{ role: 'system', content: combinedSystem }, ...messages] : messages;
    const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${OPENROUTER_KEY}`, 'Content-Type': 'application/json', 'HTTP-Referer': 'https://dentrust.site', 'X-Title': 'DenTrust DenBot' },
      body: JSON.stringify({ model: await getBestFreeModel(), messages: fullMessages, max_tokens: cappedTokens, stream: true }),
      signal: AbortSignal.timeout(30000),
    });
    return pipeGroqStream(resp, res, 'OpenRouter');
  } catch (err) {
    console.error('[AI] stream error:', err.message);
    res.setHeader('Content-Type', 'text/event-stream');
    res.write('data: ' + JSON.stringify({ choices: [{ delta: { content: `عذرًا، هناك تحميل كبير على الموقع 🙏 أكثر من ${randomVisitors()} شخص يتصفح الآن — يرجى المحاولة مرة أخرى بعد لحظات.` }, finish_reason: 'stop' }] }) + '\r\n\r\n');
    res.write('data: [DONE]\r\n\r\n');
    res.end();
  }
});


// POST /api/ai/stylebot
app.post('/api/ai/stylebot', webCors, async (req, res) => {
  if (!OPENROUTER_KEY) return res.status(503).json({ error: 'No AI provider configured.' });
  try {
    const { messages = [], system = '', max_tokens = 400, stream = false } = req.body;
    const knowledge = await getBotKnowledgeText();
    const combinedSystem = capSystemContent(LANG_INSTRUCTION + system + knowledge);
    const cappedTokens = capMaxTokens(max_tokens);
    const fullMessages = combinedSystem ? [{ role: 'system', content: combinedSystem }, ...messages] : messages;
    if (stream) {
      const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: `Bearer ${OPENROUTER_KEY}`, 'Content-Type': 'application/json', 'HTTP-Referer': 'https://dentrust.site', 'X-Title': 'DenTrust DenBot' },
        body: JSON.stringify({ model: await getBestFreeModel(), messages: fullMessages, max_tokens: cappedTokens, stream: true }),
        signal: AbortSignal.timeout(30000),
      });
      return pipeGroqStream(resp, res, 'OpenRouter');
    }
    const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${OPENROUTER_KEY}`, 'Content-Type': 'application/json', 'HTTP-Referer': 'https://dentrust.site', 'X-Title': 'DenTrust DenBot' },
      body: JSON.stringify({ model: await getBestFreeModel(), messages: fullMessages, max_tokens: cappedTokens }),
      signal: AbortSignal.timeout(30000),
    });
    const data = await resp.json();
    return res.json(data);
  } catch (err) {
    console.error('[AI] stylebot error:', err.message);
    res.status(503).json({ error: `عذرًا، هناك تحميل كبير على الموقع 🙏 أكثر من ${randomVisitors()} شخص يتصفح الآن — يرجى المحاولة مرة أخرى بعد لحظات.` });
  }
});


app.get(`${BASE}/api/bot-knowledge`, async (req, res) => {
  if (!req.session?.user_id) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { rows } = await posDb.query(
      'SELECT * FROM bot_knowledge ORDER BY category, id'
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// POST — add new knowledge entry
app.post(`${BASE}/api/bot-knowledge`, async (req, res) => {
  if (!req.session?.user_id) return res.status(401).json({ error: 'Unauthorized' });
  const { category = 'general', title, content } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'title and content required' });
  try {
    const { rows: [row] } = await posDb.query(
      'INSERT INTO bot_knowledge (category, title, content) VALUES ($1,$2,$3) RETURNING *',
      [category.trim(), title.trim(), content.trim()]
    );
    _knowledgeCache = null; // invalidate cache immediately
    res.status(201).json(row);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// PUT — update existing entry
app.put(`${BASE}/api/bot-knowledge/:id`, async (req, res) => {
  if (!req.session?.user_id) return res.status(401).json({ error: 'Unauthorized' });
  const { category, title, content, active } = req.body;
  try {
    const { rows: [row] } = await posDb.query(
      `UPDATE bot_knowledge SET
         category = COALESCE($1, category),
         title    = COALESCE($2, title),
         content  = COALESCE($3, content),
         active   = COALESCE($4, active),
         updated_at = NOW()
       WHERE id=$5 RETURNING *`,
      [category ?? null, title ?? null, content ?? null, active ?? null, req.params.id]
    );
    _knowledgeCache = null;
    res.json(row || { ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// DELETE — remove entry
app.delete(`${BASE}/api/bot-knowledge/:id`, async (req, res) => {
  if (!req.session?.user_id) return res.status(401).json({ error: 'Unauthorized' });
  try {
    await posDb.query('DELETE FROM bot_knowledge WHERE id=$1', [req.params.id]);
    _knowledgeCache = null;
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── Price Tracker ─────────────────────────────────────────────────────────────
const PT_INIT_SQL = `
  CREATE TABLE IF NOT EXISTS pt_sites (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS pt_products (
    id SERIAL PRIMARY KEY,
    site_id INTEGER REFERENCES pt_sites(id) ON DELETE CASCADE,
    title TEXT,
    price NUMERIC,
    url TEXT,
    image_url TEXT,
    scraped_at TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS pt_matches (
    id SERIAL PRIMARY KEY,
    our_product_id INTEGER,
    pt_product_id INTEGER REFERENCES pt_products(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'pending',
    matched_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(our_product_id, pt_product_id)
  );

  CREATE TABLE IF NOT EXISTS website_order_alerts (
    id SERIAL PRIMARY KEY,
    customer_name TEXT,
    customer_phone TEXT,
    customer_city TEXT,
    customer_address TEXT,
    dentrust_order_id TEXT,
    total_amount NUMERIC DEFAULT 0,
    items_count INTEGER DEFAULT 0,
    items_summary TEXT,
    status TEXT DEFAULT 'pending',
    notes TEXT,
    seen BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );
  ALTER TABLE website_order_alerts ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending';
  ALTER TABLE website_order_alerts ADD COLUMN IF NOT EXISTS notes TEXT;
  ALTER TABLE website_order_alerts ADD COLUMN IF NOT EXISTS customer_city TEXT;
  ALTER TABLE website_order_alerts ADD COLUMN IF NOT EXISTS customer_address TEXT;
  ALTER TABLE website_order_alerts ADD COLUMN IF NOT EXISTS dentrust_order_id TEXT;
  ALTER TABLE sales ADD COLUMN IF NOT EXISTS discount_amount NUMERIC DEFAULT 0;
  ALTER TABLE sales ADD COLUMN IF NOT EXISTS delivery_amount NUMERIC DEFAULT 0;
  ALTER TABLE website_order_alerts ADD COLUMN IF NOT EXISTS promo_code TEXT;
  ALTER TABLE website_order_alerts ADD COLUMN IF NOT EXISTS discount_amount NUMERIC DEFAULT 0;
  ALTER TABLE website_order_alerts ADD COLUMN IF NOT EXISTS delivery_amount NUMERIC DEFAULT 0;
  CREATE TABLE IF NOT EXISTS pt_history (
    id SERIAL PRIMARY KEY,
    our_product_id INTEGER,
    our_price NUMERIC,
    competitor_price NUMERIC,
    site_name TEXT,
    recorded_at TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS bot_knowledge (
    id SERIAL PRIMARY KEY,
    category TEXT NOT NULL DEFAULT 'general',
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
  );
`;

async function initPriceTracker() {
  try { await posDb.query(PT_INIT_SQL); }
  catch (e) { console.error('Price tracker init error:', e.message); }
}

// ── Medical Text Normalization & Smart Overlap Matcher ───────────────────────
function normalizeProductText(text) {
  if (!text) return '';
  return String(text)
    .toLowerCase()
    // Arabic character normalization
    .replace(/[إأآا]/g, 'ا')
    .replace(/ة/g, 'ه')
    .replace(/ى/g, 'ي')
    .replace(/ؤ/g, 'و')
    .replace(/ئ/g, 'ي')
    .replace(/ـ/g, '')
    // Medical gauge sizes: 20 gauge, 20g, gauge 20 -> 20g
    .replace(/(\d+)\s*(?:gauge|g)\b/gi, '$1g')
    .replace(/\bgauge\s*(\d+)\b/gi, '$1g')
    // Shades: shade a1, a2, a3, b1 -> a1, a2, a3, b1
    .replace(/\bshade\s*([a-d]\d+)\b/gi, '$1')
    // Weights & volumes: 4 gm, 4gm, 4g -> 4g; 5 ml, 5ml -> 5ml
    .replace(/(\d+)\s*(?:gm|gram|g)\b/gi, '$1g')
    .replace(/(\d+)\s*(?:ml|milliliter)\b/gi, '$1ml')
    .replace(/(\d+)\s*(?:pcs|pieces|قطعة|حبة)\b/gi, '$1pcs')
    // Strip non-alphanumeric except spaces
    .replace(/[^\u0600-\u06FFa-z0-9\s]/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokenizeProduct(text) {
  const norm = normalizeProductText(text);
  if (!norm) return [];
  const stopwords = new Set([
    'the', 'and', 'for', 'with', 'box', 'set', 'pack', 'piece', 'dental', 'teeth',
    'من', 'في', 'على', 'مع', 'علبة', 'طقم', 'باكت', 'اسنان', 'طب', 'طبي', 'اصلية', 'اصلي'
  ]);
  return norm.split(/\s+/).filter(w => w.length >= 2 && !stopwords.has(w));
}

// Overlap coefficient with token containment bonus:
// Computes |A ∩ B| / min(|A|, |B|).
function titleSimilarity(a, b) {
  const ta = tokenizeProduct(a);
  const tb = tokenizeProduct(b);
  if (ta.length === 0 || tb.length === 0) return 0;
  const setA = new Set(ta);
  const setB = new Set(tb);
  const intersection = [...setA].filter(w => setB.has(w)).length;
  if (intersection === 0) return 0;
  const minSize = Math.min(setA.size, setB.size);
  const overlap = intersection / minSize;

  // Bonus if key model/gauge/shade identifiers match (e.g. 20g, a2, cx, 3m)
  const keyTokensA = ta.filter(w => /^\d+[a-z]+|[a-z]\d+$/i.test(w) || w.length >= 4);
  const keyTokensB = new Set(tb);
  const keyMatches = keyTokensA.filter(w => keyTokensB.has(w)).length;
  const keyBonus = keyTokensA.length > 0 ? (keyMatches / keyTokensA.length) * 0.2 : 0;

  return Math.min(1.0, overlap * 0.8 + keyBonus);
}

// AI Semantic Matcher using OpenRouter
async function aiSemanticMatch(competitorTitle, candidates) {
  if (!OPENROUTER_KEY || !candidates || candidates.length === 0) return null;
  try {
    const candidateList = candidates.slice(0, 15).map((c, i) => `${i + 1}. [ID: ${c.id}] ${c.product_name}`).join('\n');
    const prompt = `You are an expert dental supply product matching AI.
A competitor lists a product titled: "${competitorTitle}"
Here are our dental inventory products:
${candidateList}

Find the SINGLE best matching product from our list that represents the exact same product (accounting for Arabic/English translation, brand abbreviations, or shade/gauge codes).
Respond ONLY with a JSON object:
{"match_id": <our_product_id or null>, "confidence": <0.0 to 1.0>}
If no clear match exists, return {"match_id": null, "confidence": 0.0}.`;

    const aiRes = await callOpenRouter({
      model: await getBestFreeModel(),
      max_tokens: 150,
      messages: [{ role: 'system', content: prompt }]
    });
    const raw = aiRes.choices?.[0]?.message?.content || '';
    const jsonMatch = raw.match(/\{[\s\S]*?\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      if (parsed.match_id && parsed.confidence >= 0.5) {
        const found = candidates.find(c => String(c.id) === String(parsed.match_id));
        if (found) return found;
      }
    }
  } catch (err) {
    console.error('AI Semantic Match error:', err.message);
  }
  return null;
}

// Find the best matching product in our DB for a competitor title.
async function findBestOurProduct(competitorTitle, minScore = 0.40) {
  if (!competitorTitle || !competitorTitle.trim()) return null;
  const rawTokens = tokenizeProduct(competitorTitle);
  if (rawTokens.length === 0) return null;

  // Search DB for candidate products using key words
  const searchWords = rawTokens.slice(0, 8);
  const likes = searchWords.map((_, i) => `LOWER(product_name) LIKE $${i + 1}`).join(' OR ');
  const params = searchWords.map(w => `%${w.toLowerCase()}%`);

  let candidates = [];
  try {
    const { rows } = await posDb.query(
      `SELECT id, product_name, sale_price FROM products WHERE ${likes} LIMIT 30`, params
    );
    candidates = rows;
  } catch (_) {}

  // If no LIKE candidates, load a small sample of active products for AI matching
  if (candidates.length === 0) {
    try {
      const { rows } = await posDb.query(
        'SELECT id, product_name, sale_price FROM products ORDER BY id DESC LIMIT 50'
      );
      candidates = rows;
    } catch (_) {}
  }

  if (candidates.length === 0) return null;

  // Step 1: Fast Overlap Similarity scoring
  let best = null, bestScore = 0;
  for (const c of candidates) {
    const score = titleSimilarity(competitorTitle, c.product_name);
    if (score > bestScore) { bestScore = score; best = c; }
  }

  // If high confidence match found by overlap algorithm, return immediately
  if (bestScore >= minScore && best) return best;

  // Step 2: If low score or uncertain, use AI Semantic Matching as fallback
  if (OPENROUTER_KEY && candidates.length > 0) {
    const aiMatched = await aiSemanticMatch(competitorTitle, candidates);
    if (aiMatched) return aiMatched;
  }

  return bestScore >= 0.30 ? best : null;
}

// AI-powered scraper — JSON-LD → meta tags → OpenRouter AI → regex fallback
async function scrapePageProducts(siteUrl) {
  const products = [];
  let html = '';

  // ── Step 1: Fetch HTML ───────────────────────────────────────────────────
  try {
    const r = await fetch(siteUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'ar,en;q=0.9',
      },
      signal: AbortSignal.timeout(20000),
    });
    html = await r.text();
  } catch (e) {
    console.error('Scrape fetch error for', siteUrl, ':', e.message);
    return [];
  }

  // ── Step 2: JSON-LD / Schema.org (most reliable) ─────────────────────────
  const jsonLdRe = /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = jsonLdRe.exec(html)) !== null && products.length < 100) {
    try {
      const data = JSON.parse(m[1].trim());
      const items = Array.isArray(data) ? data : [data];
      for (const item of items) {
        const type = (item['@type'] || '').toLowerCase();
        if (type === 'product') {
          const name = item.name || '';
          const offers = item.offers;
          let price = null;
          if (offers) {
            const o = Array.isArray(offers) ? offers[0] : offers;
            price = parseFloat(o.price || o.lowPrice || 0);
          }
          if (name && price > 0) products.push({ title: name, price, url: item.url || siteUrl });
        }
        if (type === 'itemlist' && item.itemListElement) {
          for (const el of item.itemListElement) {
            const prod = el.item || el;
            const name = prod.name || '';
            const offers = prod.offers;
            let price = null;
            if (offers) {
              const o = Array.isArray(offers) ? offers[0] : offers;
              price = parseFloat(o.price || o.lowPrice || 0);
            }
            if (name && price > 0) products.push({ title: name, price, url: prod.url || siteUrl });
          }
        }
      }
    } catch (_) {}
  }

  // ── Step 3: OpenGraph / meta price tags ──────────────────────────────────
  if (products.length === 0) {
    const ogTitle = (/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']/i.exec(html) || [])[1];
    const ogPrice = (/<meta[^>]+(?:property=["']product:price:amount["']|name=["']price["'])[^>]+content=["']([^"']+)["']/i.exec(html) || [])[1];
    if (ogTitle && ogPrice) {
      const price = parseFloat(ogPrice.replace(/[^\d.]/g, ''));
      if (price > 0) products.push({ title: ogTitle, price, url: siteUrl });
    }
  }

  // ── Step 4: AI extraction (OpenRouter) ──────────────────────────────────
  if (products.length < 3 && OPENROUTER_KEY) {
    try {
      const visibleText = html
        .replace(/<script[\s\S]*?<\/script>/gi, '')
        .replace(/<style[\s\S]*?<\/style>/gi, '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&')
        .replace(/\s+/g, ' ').trim().slice(0, 7000);

      const prompt = 'You are a product price extractor for dental supply websites. Extract ALL product names and prices from the given text. Return ONLY a JSON array: [{"title":"product name","price":123.50}]. Prices must be numbers only (no currency). Return [] if nothing found.';
      const aiData = await callOpenRouter({
        model: await getBestFreeModel(),
        max_tokens: 1500,
        messages: [{ role: 'system', content: prompt }, { role: 'user', content: `Extract products and prices:\n\n${visibleText}` }]
      });
      const raw = aiData.choices?.[0]?.message?.content || '[]';

      const jsonMatch = raw.match(/\[[\s\S]*\]/);
      if (jsonMatch) {
        const aiProducts = JSON.parse(jsonMatch[0]);
        for (const p of aiProducts) {
          const price = parseFloat(p.price);
          if (p.title && price > 0 && products.length < 100)
            products.push({ title: String(p.title).slice(0, 200), price, url: siteUrl });
        }
      }
    } catch (e) { console.error('AI scraper error:', e.message); }
  }


  // ── Step 5: Regex fallback (last resort) ─────────────────────────────────
  if (products.length === 0) {
    const titleRe = /class=["'][^"']*(?:product[_-]?(?:name|title)|item[_-]?name|card[_-]?title)[^"']*["'][^>]*>\s*([^<]{3,120})/gi;
    const extractedTitles = [];
    while ((m = titleRe.exec(html)) !== null && extractedTitles.length < 80) {
      const t = m[1].trim();
      if (t) extractedTitles.push(t);
    }
    const priceRe = /(?:جنيه|EGP|LE|ج\.م|L\.E\.?)[\s]*(\d[\d\s,\.]{0,10})|(\d[\d\s,\.]{1,10})[\s]*(?:جنيه|EGP|LE|ج\.م|L\.E\.?)/gi;
    let pi = 0;
    while ((m = priceRe.exec(html)) !== null && pi < 80) {
      const price = parseFloat((m[1] || m[2] || '').replace(/[\s,]/g, ''));
      if (price >= 1 && price < 2000000) {
        if (extractedTitles[pi]) products.push({ title: extractedTitles[pi], price, url: siteUrl });
        pi++;
      }
    }
  }

  return products.slice(0, 100);
}

// GET  /api/admin/price-tracker/sites
app.get('/api/admin/price-tracker/sites', webCors, async (req, res) => {
  try {
    const { rows } = await posDb.query('SELECT * FROM pt_sites ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// POST /api/admin/price-tracker/sites
app.post('/api/admin/price-tracker/sites', webCors, async (req, res) => {
  const { name, url } = req.body;
  if (!name || !url) return res.status(400).json({ error: 'name and url required' });
  try {
    const { rows: [site] } = await posDb.query(
      `INSERT INTO pt_sites (name, url) VALUES ($1,$2)
       ON CONFLICT (url) DO UPDATE SET name=EXCLUDED.name RETURNING *`,
      [name, url]
    );
    res.json(site);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// DELETE /api/admin/price-tracker/sites/:id
app.delete('/api/admin/price-tracker/sites/:id', webCors, async (req, res) => {
  await posDb.query('DELETE FROM pt_sites WHERE id=$1', [req.params.id]).catch(() => {});
  res.json({ ok: true });
});

// GET  /api/admin/price-tracker/sites/:id/products
app.get('/api/admin/price-tracker/sites/:id/products', webCors, async (req, res) => {
  try {
    const { rows } = await posDb.query(
      'SELECT * FROM pt_products WHERE site_id=$1 ORDER BY scraped_at DESC LIMIT 200',
      [req.params.id]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// POST /api/admin/price-tracker/sites/:id/crawl
app.post('/api/admin/price-tracker/sites/:id/crawl', webCors, async (req, res) => {
  try {
    const { rows: [site] } = await posDb.query('SELECT * FROM pt_sites WHERE id=$1', [req.params.id]);
    if (!site) return res.status(404).json({ error: 'Site not found' });
    const scraped = await scrapePageProducts(site.url);
    await posDb.query('DELETE FROM pt_products WHERE site_id=$1', [site.id]);
    let newMatches = 0;
    for (const p of scraped) {
      const { rows: [pp] } = await posDb.query(
        'INSERT INTO pt_products (site_id, title, price, url) VALUES ($1,$2,$3,$4) RETURNING id',
        [site.id, p.title, p.price, p.url]
      );
      if (pp && p.title && p.title.trim() && parseFloat(p.price) > 0) {
        const ourProd = await findBestOurProduct(p.title);
        if (ourProd) {
          await posDb.query(
            'INSERT INTO pt_matches (our_product_id, pt_product_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
            [ourProd.id, pp.id]
          );
          newMatches++;
        }
      }
    }
    res.json({ scraped: scraped.length, newMatches });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// Search the competitor's own website for a product name
async function searchCompetitorSite(siteUrl, productName) {
  const base = siteUrl.replace(/\/$/, '');
  const q = encodeURIComponent(productName);
  // Try common search URL patterns used by Shopify, WooCommerce, OpenCart, custom sites
  const searchUrls = [
    `${base}/search?q=${q}`,
    `${base}/?s=${q}`,
    `${base}/search?query=${q}`,
    `${base}/search?term=${q}`,
    `${base}/catalogsearch/result/?q=${q}`,
    `${base}/index.php?route=product/search&search=${q}`,
    `${base}/products?q=${q}`,
  ];
  for (const url of searchUrls) {
    try {
      const r = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'ar,en;q=0.9',
        },
        signal: AbortSignal.timeout(15000),
        redirect: 'follow',
      });
      if (!r.ok) continue;
      const html = await r.text();
      // If we got redirected to a product page or a results page with products
      if (html.length < 500) continue;
      const products = await scrapePageProducts(url);
      if (products.length > 0) return { products, searchUrl: url };
    } catch (_) { continue; }
  }
  return { products: [], searchUrl: null };
}

// POST /api/admin/price-tracker/sites/:id/search-by-name
// Searches the competitor's OWN website for a given product name
app.post('/api/admin/price-tracker/sites/:id/search-by-name', webCors, async (req, res) => {
  const { name = '' } = req.body;
  if (!name.trim()) return res.json({ searched: 0, matched: 0, skipped: 0, results: [] });
  try {
    const { rows: [site] } = await posDb.query('SELECT * FROM pt_sites WHERE id=$1', [req.params.id]);
    if (!site) return res.status(404).json({ error: 'Site not found' });

    const { products, searchUrl } = await searchCompetitorSite(site.url, name.trim());

    // Save found products and try to match to our product
    const results = [];
    for (const p of products.slice(0, 10)) {
      const { rows: [pp] } = await posDb.query(
        `INSERT INTO pt_products (site_id, title, price, url)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT DO NOTHING RETURNING *`,
        [site.id, p.title, p.price, p.url || searchUrl]
      );
      if (pp) results.push(pp);
    }

    res.json({ searched: 1, matched: results.length, skipped: 0, results, searchUrl });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// POST /api/admin/price-tracker/sites/:id/search-all-products
// Auto-searches competitor site for ALL our products one by one
app.post('/api/admin/price-tracker/sites/:id/search-all-products', webCors, async (req, res) => {
  try {
    const { rows: [site] } = await posDb.query('SELECT * FROM pt_sites WHERE id=$1', [req.params.id]);
    if (!site) return res.status(404).json({ error: 'Site not found' });

    const { rows: ourProducts } = await posDb.query(
      'SELECT id, product_name, sale_price FROM products ORDER BY product_name LIMIT 200'
    );

    let matched = 0, skipped = 0;
    const deadline = Date.now() + 25000; // hard 25s wall-clock limit

    for (const myProd of ourProducts) {
      if (Date.now() > deadline) break; // stop before proxy timeout
      try {
        const { products } = await searchCompetitorSite(site.url, myProd.product_name);
        if (products.length === 0) { skipped++; continue; }

        // Pick the scraped result most similar to our product name (must score >= 0.3)
        let best = null, bestScore = 0;
        for (const p of products) {
          if (!p.title || parseFloat(p.price) <= 0) continue;
          const score = titleSimilarity(myProd.product_name, p.title);
          if (score > bestScore) { bestScore = score; best = p; }
        }
        if (!best || bestScore < 0.3) { skipped++; continue; }
        const { rows: [pp] } = await posDb.query(
          `INSERT INTO pt_products (site_id, title, price, url)
           VALUES ($1,$2,$3,$4)
           ON CONFLICT DO NOTHING RETURNING id`,
          [site.id, best.title, best.price, best.url || site.url]
        );
        if (pp) {
          await posDb.query(
            'INSERT INTO pt_matches (our_product_id, pt_product_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
            [myProd.id, pp.id]
          );
          matched++;
        } else { skipped++; }
      } catch (_) { skipped++; }
    }

    res.json({ total: ourProducts.length, matched, skipped, partial: Date.now() > deadline });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// POST /api/admin/price-tracker/sites/:id/rematch
app.post('/api/admin/price-tracker/sites/:id/rematch', webCors, async (req, res) => {
  try {
    const { rows: prods } = await posDb.query('SELECT * FROM pt_products WHERE site_id=$1', [req.params.id]);
    let matched = 0;
    for (const p of prods) {
      if (!p.title || parseFloat(p.price) <= 0) continue;
      const ourProd = await findBestOurProduct(p.title);
      if (ourProd) {
        await posDb.query(
          'INSERT INTO pt_matches (our_product_id, pt_product_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
          [ourProd.id, p.id]
        );
        matched++;
      }
    }
    res.json({ matched, skipped: prods.length - matched });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// GET  /api/admin/price-tracker/matches/pending
app.get('/api/admin/price-tracker/matches/pending', webCors, async (req, res) => {
  try {
    const { rows } = await posDb.query(`
      SELECT m.id, m.our_product_id, m.status, m.matched_at,
             COALESCE(pp.title, '')            AS competitor_title,
             COALESCE(pp.price::numeric, 0)    AS competitor_price,
             COALESCE(pp.url, '')              AS competitor_url,
             COALESCE(s.name, '')              AS site_name,
             COALESCE(p.product_name, '')      AS our_product_name,
             COALESCE(p.sale_price::numeric, 0) AS our_price,
             COALESCE(p.image_url, '')         AS our_image_url
      FROM pt_matches m
      LEFT JOIN pt_products pp ON pp.id = m.pt_product_id
      LEFT JOIN pt_sites    s  ON s.id  = pp.site_id
      LEFT JOIN products    p  ON p.id  = m.our_product_id
      WHERE m.status = 'pending'
      ORDER BY m.matched_at DESC
      LIMIT 100
    `);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// GET  /api/admin/price-tracker/matches/count
app.get('/api/admin/price-tracker/matches/count', webCors, async (req, res) => {
  try {
    const { rows: [r] } = await posDb.query("SELECT COUNT(*) AS count FROM pt_matches WHERE status='pending'");
    res.json({ count: parseInt(r.count, 10) });
  } catch { res.json({ count: 0 }); }
});

// GET  /api/admin/price-tracker/history/:productId
app.get('/api/admin/price-tracker/history/:productId', webCors, async (req, res) => {
  try {
    const { rows } = await posDb.query(
      'SELECT * FROM pt_history WHERE our_product_id=$1 ORDER BY recorded_at DESC LIMIT 90',
      [req.params.productId]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});


// PUT /api/admin/price-tracker/matches/:id  (approve / reject)
app.put('/api/admin/price-tracker/matches/:id', webCors, async (req, res) => {
  const { status } = req.body;
  if (!['approved', 'rejected'].includes(status))
    return res.status(400).json({ error: 'status must be approved or rejected' });
  try {
    const { rows: [match] } = await posDb.query(
      'UPDATE pt_matches SET status=$1 WHERE id=$2 RETURNING *',
      [status, req.params.id]
    );
    if (!match) return res.status(404).json({ error: 'Match not found' });

    if (status === 'approved') {
      const { rows: [pp] } = await posDb.query('SELECT * FROM pt_products WHERE id=$1', [match.pt_product_id]);
      const { rows: [p] }  = await posDb.query('SELECT sale_price FROM products WHERE id=$1', [match.our_product_id]);
      const { rows: [s] }  = await posDb.query('SELECT name FROM pt_sites WHERE id=(SELECT site_id FROM pt_products WHERE id=$1)', [match.pt_product_id]);
      if (pp && p) {
        await posDb.query(
          'INSERT INTO pt_history (our_product_id, our_price, competitor_price, site_name) VALUES ($1,$2,$3,$4)',
          [match.our_product_id, p.sale_price || 0, pp.price || 0, s?.name || 'Unknown']
        );
      }
    }
    res.json({ ok: true, status });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// POST /api/admin/price-tracker/manual-match
app.post('/api/admin/price-tracker/manual-match', webCors, async (req, res) => {
  const { ourProductId, competitorTitle, siteName, competitorPrice } = req.body;
  try {
    if (ourProductId && competitorPrice) {
      const { rows: [p] } = await posDb.query('SELECT sale_price FROM products WHERE id=$1', [ourProductId]);
      await posDb.query(
        'INSERT INTO pt_history (our_product_id, our_price, competitor_price, site_name) VALUES ($1,$2,$3,$4)',
        [ourProductId, p?.sale_price || 0, competitorPrice, siteName || 'Manual']
      );
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// GET  /api/admin/price-tracker/analytics
app.get('/api/admin/price-tracker/analytics', webCors, async (req, res) => {
  try {
    const { rows: history } = await posDb.query(`
      SELECT h.our_product_id, p.product_name, h.our_price, h.competitor_price,
             h.site_name, h.recorded_at,
             CASE WHEN h.our_price > 0 AND h.competitor_price > 0
                  THEN ROUND((h.competitor_price / h.our_price)::numeric, 2) END AS ratio
      FROM pt_history h
      LEFT JOIN products p ON p.id = h.our_product_id
      ORDER BY h.recorded_at DESC LIMIT 200
    `);
    const { rows: [totals] } = await posDb.query(
      'SELECT COUNT(DISTINCT our_product_id) AS tracked_products, COUNT(*) AS total_records FROM pt_history'
    );
    res.json({ history, totals });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});



// ── Website Order Alerts (POS staff notifications) ───────────────────────────
// GET unseen alerts count and latest item (for badge & sound alert)
app.get(`${BASE}/api/website-orders/alerts/count`, async (req, res) => {
  if (!req.session?.user_id) return res.json({ count: 0, latest: null });
  try {
    const { rows: [r] } = await posDb.query('SELECT COUNT(*) AS count FROM website_order_alerts WHERE seen=false');
    const cnt = parseInt(r?.count || 0, 10);
    let latest = null;
    if (cnt > 0) {
      const { rows: [l] } = await posDb.query('SELECT * FROM website_order_alerts WHERE seen=false ORDER BY created_at DESC, id DESC LIMIT 1');
      latest = l || null;
    }
    res.json({ count: cnt, latest });
  } catch { res.json({ count: 0, latest: null }); }
});

// GET unseen alerts (for popup)
app.get(`${BASE}/api/website-orders/alerts`, async (req, res) => {
  if (!req.session?.user_id) return res.json([]);
  try {
    const { rows } = await posDb.query(
      'SELECT * FROM website_order_alerts WHERE seen=false ORDER BY created_at DESC LIMIT 20'
    );
    res.json(rows);
  } catch (err) { res.json([]); }
});

// POST mark all as seen
app.post(`${BASE}/api/website-orders/alerts/dismiss`, async (req, res) => {
  if (!req.session?.user_id) return res.json({ ok: false });
  try {
    await posDb.query('UPDATE website_order_alerts SET seen=true WHERE seen=false');
    res.json({ ok: true });
  } catch (err) { res.json({ ok: false }); }
});


// ─── WhatsApp notification message builder ────────────────────────────────────
// Templates stored in store_settings key='whatsapp_templates' (editable via /whatsapp-settings)
// Placeholders: {name} {total} {tracking} {reason}
const WA_DEFAULTS = {
  pending:   'مرحباً {name} 👋\nتم استلام طلبك بنجاح وجارٍ مراجعته.\nإجمالي الطلب: {total} ج.م\nسنتواصل معك قريباً.\n\n— دينتراست 🌸',
  confirmed: 'مرحباً {name} ✅\nتم تأكيد طلبك وجارٍ التجهيز للشحن.\nإجمالي الطلب: {total} ج.م\nشكراً لثقتك فينا!\n\n— دينتراست 🌸',
  shipped:   'مرحباً {name} 🚚\nطلبك في الطريق إليك الآن!\nإجمالي الطلب: {total} ج.م\n{tracking}نراك قريباً 😊\n\n— دينتراست 🌸',
  delivered: 'مرحباً {name} 📦\nتم توصيل طلبك بنجاح!\nنتمنى أن تكون سعيداً بمنتجاتك.\nشاركنا رأيك وساعد الآخرين 🌟\n\n— دينتراست 🌸',
  cancelled: 'مرحباً {name}\nنأسف، تم إلغاء طلبك.\n{reason}للاستفسار تواصل معنا.\n\n— دينتراست 🌸',
};

async function getWaTemplates() {
  try {
    const { rows } = await posDb.query(
      "SELECT value FROM store_settings WHERE key='whatsapp_templates' LIMIT 1"
    );
    if (rows.length && rows[0].value) return { ...WA_DEFAULTS, ...JSON.parse(rows[0].value) };
  } catch (_) {}
  return { ...WA_DEFAULTS };
}

async function buildWhatsAppMsg(status, name, total, notes) {
  const templates = await getWaTemplates();
  const tmpl = templates[status] || '';
  if (!tmpl) return '';
  const t = parseFloat(total || 0).toLocaleString('ar-EG');
  const n = name || 'عميل';
  return tmpl
    .replace(/{name}/g, n)
    .replace(/{total}/g, t)
    .replace(/{tracking}/g, notes ? 'رقم التتبع: ' + notes + '\n' : '')
    .replace(/{reason}/g, notes ? 'السبب: ' + notes + '\n' : '');
}

// ── WhatsApp Templates API ────────────────────────────────────────────────────
app.get(`${BASE}/api/settings/whatsapp-templates`, async (req, res) => {
  if (!req.session?.user_id) return res.status(401).json({ error: 'Unauthorized' });
  try { res.json(await getWaTemplates()); }
  catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/settings/whatsapp-templates`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'مسموح للمدير فقط' });
  try {
    const allowed = ['pending','confirmed','shipped','delivered','cancelled'];
    const toSave  = {};
    for (const k of allowed) { if (typeof req.body[k] === 'string') toSave[k] = req.body[k]; }
    await posDb.query(
      "INSERT INTO store_settings (key,value) VALUES ('whatsapp_templates',$1) ON CONFLICT (key) DO UPDATE SET value=$1",
      [JSON.stringify(toSave)]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── WhatsApp Settings Page ────────────────────────────────────────────────────
app.get(`${BASE}/whatsapp-settings`, (req, res) => {
  if (!req.session?.user_id) return res.redirect(`${BASE}/login`);
  return renderPage(req, res, 'whatsapp_settings');
});

// ── Bot Knowledge Management Page ────────────────────────────────────────────
app.get(`${BASE}/bot-knowledge`, (req, res) => {
  if (!req.session?.user_id) return res.redirect(`${BASE}/login`);
  return renderPage(req, res, 'bot_knowledge');
});

// ── Website Orders Dashboard (page) ──────────────────────────────────────────
app.get(`${BASE}/website-orders`, (req, res) => {
  if (!req.session?.user_id) return res.redirect(`${BASE}/login`);
  return renderPage(req, res, 'website_orders');
});

// GET all orders — paginated + filtered
app.get(`${BASE}/api/website-orders/all`, async (req, res) => {
  if (!req.session?.user_id) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const status = req.query.status || 'all';
    const search = (req.query.search || '').trim();
    const page   = Math.max(1, parseInt(req.query.page || '1', 10));
    const limit  = 20;
    const offset = (page - 1) * limit;

    let where = 'WHERE 1=1';
    const params = [];
    if (status !== 'all') { params.push(status); where += ` AND status=$${params.length}`; }
    if (search) {
      params.push(`%${search}%`);
      where += ` AND (customer_name ILIKE $${params.length} OR customer_phone ILIKE $${params.length})`;
    }
    const { rows } = await posDb.query(
      `SELECT * FROM website_order_alerts ${where} ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`,
      params
    );
    const { rows: [{ count }] } = await posDb.query(
      `SELECT COUNT(*) AS count FROM website_order_alerts ${where}`, params
    );
    res.json({ orders: rows, total: parseInt(count, 10), page, limit });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// PATCH order status — returns WhatsApp message + optional Twilio auto-send
app.patch(`${BASE}/api/website-orders/:id/status`, async (req, res) => {
  if (!req.session?.user_id) return res.status(401).json({ error: 'Unauthorized' });
  const { id } = req.params;
  const { status, notes } = req.body;
  const allowed = ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    const { rows: [order] } = await posDb.query('SELECT * FROM website_order_alerts WHERE id=$1', [id]);
    await posDb.query(
      'UPDATE website_order_alerts SET status=$1, notes=$2, seen=true WHERE id=$3',
      [status, notes || null, id]
    );
    const waMsg  = await buildWhatsAppMsg(status, order?.customer_name, order?.total_amount, notes);
    const rawPhone = (order?.customer_phone || '').replace(/[^0-9+]/g, '');
    const phone = rawPhone.startsWith('+')
      ? rawPhone.slice(1)
      : (rawPhone.startsWith('0') && rawPhone.length === 11)
        ? '20' + rawPhone
        : rawPhone;
    const waLink = phone
      ? `https://wa.me/${phone}?text=${encodeURIComponent(waMsg)}`
      : null;

    // Optional Twilio auto-send
    let twilioSent = false;
    let twilioError = null;
    const TWILIO_SID  = process.env.TWILIO_ACCOUNT_SID;
    const TWILIO_AUTH = process.env.TWILIO_AUTH_TOKEN;
    const TWILIO_FROM = process.env.TWILIO_WHATSAPP_FROM;
    if (TWILIO_SID && TWILIO_AUTH && TWILIO_FROM && phone && waMsg) {
      try {
        const body = new URLSearchParams({
          From: TWILIO_FROM,
          To:   `whatsapp:+${phone.replace(/^\+/, '')}`,
          Body: waMsg,
        });
        const twRes = await fetch(
          `https://api.twilio.com/2010-04-01/Accounts/${TWILIO_SID}/Messages.json`,
          {
            method: 'POST',
            headers: {
              Authorization: 'Basic ' + Buffer.from(`${TWILIO_SID}:${TWILIO_AUTH}`).toString('base64'),
              'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: body.toString(),
          }
        );
        if (twRes.ok) { twilioSent = true; } else {
          const eb = await twRes.json().catch(() => ({}));
          twilioError = `${twRes.status}: ${eb?.message || eb?.code || 'unknown'}`;
          console.warn('[Twilio]', twilioError);
        }
      } catch(e) { twilioError = e.message; }
    }
    res.json({ ok: true, wa_message: waMsg, wa_link: waLink, twilio_sent: twilioSent, twilio_error: twilioError||null });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// DELETE order alert
app.get(`${BASE}/api/website-orders/:id`, async (req, res) => {
  if (!req.session?.user_id) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { rows: [order] } = await posDb.query('SELECT * FROM website_order_alerts WHERE id=$1', [req.params.id]);
    if (!order) return res.status(404).json({ error: 'الطلب غير موجود' });
    let items = [];
    if (order.dentrust_order_id) {
      try {
        const dtClient = await dentrustDb.connect();
        try {
          const { rows } = await dtClient.query(
            `SELECT oi.product_name, oi.quantity, oi.unit_price, oi.selected_option, oi.total_price,
                    p.photos
             FROM order_items oi
             LEFT JOIN products p ON p.id = oi.product_id
             WHERE oi.order_id=$1`, [order.dentrust_order_id]
          );
          items = rows;
        } finally { dtClient.release(); }
      } catch (_) {}
    }
    res.json({ order, items });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.delete(`${BASE}/api/website-orders/:id`, async (req, res) => {
  if (!req.session?.user_id) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const { rows: [order] } = await posDb.query('SELECT dentrust_order_id FROM website_order_alerts WHERE id=$1', [req.params.id]);
    await posDb.query('DELETE FROM website_order_alerts WHERE id=$1', [req.params.id]);
    // Also delete from website DB and linked POS sale
    if (order?.dentrust_order_id) {
      try {
        const dtClient = await dentrustDb.connect();
        try { await dtClient.query('DELETE FROM orders WHERE id=$1', [order.dentrust_order_id]); }
        finally { dtClient.release(); }
      } catch (_) {}
      try { await posDb.query('UPDATE sales SET dentrust_order_id=NULL WHERE dentrust_order_id=$1', [String(order.dentrust_order_id)]); } catch (_) {}
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});


// ══════════════════════════════════════════════════════════════════════════════
// ── Push Notifications ────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

// Helper: send push to all subscribed devices
async function sendPushToAll(title, body, url = null, tag = 'dentrust-notif') {
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) return;
  try {
    const { rows: subs } = await posDb.query('SELECT * FROM push_subscriptions');
    const payload = JSON.stringify({ title, body, icon: `${BASE}/static/icon-192.png`, badge: `${BASE}/static/icon-192.png`, tag, url });
    const results = await Promise.allSettled(
      subs.map(sub => {
        const subscription = { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } };
        return webpush.sendNotification(subscription, payload).catch(async err => {
          // Remove expired/invalid subscriptions (410 Gone)
          if (err.statusCode === 410 || err.statusCode === 404) {
            await posDb.query('DELETE FROM push_subscriptions WHERE endpoint=$1', [sub.endpoint]).catch(() => {});
          }
          throw err;
        });
      })
    );
    const ok = results.filter(r => r.status === 'fulfilled').length;
    console.log(`[Push] Sent to ${ok}/${subs.length} devices`);
  } catch (err) {
    console.error('[Push] sendPushToAll error:', err.message);
  }
}

// Helper: send low-stock push notification
async function sendLowStockPush(lowStockItems) {
  if (!lowStockItems?.length) return;
  const names = lowStockItems.map(i => `${i.name} (${i.qty}/${i.min})`).join('، ');
  const title = `⚠️ مخزون منخفض — ${lowStockItems.length} منتج`;
  const body = names.length > 120 ? names.slice(0, 117) + '...' : names;
  await sendPushToAll(title, body, `${BASE}/inventory`, 'low-stock');
}

// Helper: send push only to devices belonging to managers
async function sendPushToManagers(title, body, url = null, tag = 'dentrust-notif') {
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) return;
  try {
    const { rows: subs } = await posDb.query(
      `SELECT ps.* FROM push_subscriptions ps
       JOIN users u ON u.id = ps.user_id
       WHERE u.role = 'manager'`
    );
    if (!subs.length) return;
    const payload = JSON.stringify({ title, body, icon: `${BASE}/static/icon-192.png`, badge: `${BASE}/static/icon-192.png`, tag, url });
    const results = await Promise.allSettled(
      subs.map(sub => {
        const subscription = { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } };
        return webpush.sendNotification(subscription, payload).catch(async err => {
          if (err.statusCode === 410 || err.statusCode === 404) {
            await posDb.query('DELETE FROM push_subscriptions WHERE endpoint=$1', [sub.endpoint]).catch(() => {});
          }
          throw err;
        });
      })
    );
    const ok = results.filter(r => r.status === 'fulfilled').length;
    console.log(`[Push] Sent to ${ok}/${subs.length} manager devices`);
  } catch (err) {
    console.error('[Push] sendPushToManagers error:', err.message);
  }
}

// Helper: check products nearing expiry (خلال 3 شهور) and push-notify everيone (مثل تنبيه المخزون المنخفض)
async function checkExpiryAndNotify() {
  try {
    const { rows } = await posDb.query(
      `SELECT product_name, expiry_date FROM products
       WHERE expiry_date IS NOT NULL AND expiry_date::date BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '3 months'
       ORDER BY expiry_date`
    );
    if (!rows.length) return;
    const names = rows.map(r => `${r.product_name} (${String(r.expiry_date).substring(0, 10)})`).join('، ');
    const title = `⏳ منتجات هتنتهي خلال 3 شهور — ${rows.length} منتج`;
    const body = names.length > 120 ? names.slice(0, 117) + '...' : names;
    await sendPushToAll(title, body, `${BASE}/expiry`, 'expiry-alert');
  } catch (err) {
    console.error('[Expiry Push] error:', err.message);
  }
}

// GET /api/push/vapid-public-key  — returns public VAPID key to client (open, no auth needed)
app.get(`${BASE}/api/push/vapid-public-key`, (req, res) => {
  if (!VAPID_PUBLIC_KEY) return res.status(503).json({ error: 'Push notifications not configured on server' });
  res.json({ publicKey: VAPID_PUBLIC_KEY });
});

// POST /api/push/subscribe  — save device push subscription
app.post(`${BASE}/api/push/subscribe`, async (req, res) => {
  const { endpoint, keys } = req.body || {};
  if (!endpoint || !keys?.p256dh || !keys?.auth) {
    return res.status(400).json({ error: 'بيانات الاشتراك ناقصة' });
  }
  try {
    const uid = req.session?.user_id || null;
    await posDb.query(
      `INSERT INTO push_subscriptions (endpoint, p256dh, auth, user_id)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (endpoint) DO UPDATE SET p256dh=$2, auth=$3, user_id=$4, updated_at=NOW()`,
      [endpoint, keys.p256dh, keys.auth, uid]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// DELETE /api/push/unsubscribe  — remove device subscription
app.delete(`${BASE}/api/push/unsubscribe`, async (req, res) => {
  const { endpoint } = req.body || {};
  if (!endpoint) return res.status(400).json({ error: 'endpoint مطلوب' });
  try {
    await posDb.query('DELETE FROM push_subscriptions WHERE endpoint=$1', [endpoint]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// POST /api/push/test  — manager-only test notification
app.post(`${BASE}/api/push/test`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'مسموح للمدير فقط' });
  if (!VAPID_PUBLIC_KEY) return res.status(503).json({ error: 'Push notifications غير مفعّلة' });
  try {
    await sendPushToAll('🔔 اختبار الإشعارات', 'إشعارات الـ Push تعمل بنجاح! ✅', `${BASE}/`, 'test-notif');
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// 🏢 WAREHOUSE & PRODUCT MOVEMENT AUDIT LOG & TOP-SELLING ANALYTICS
// ══════════════════════════════════════════════════════════════════════════════

// Helper: Log product movement safely
async function logProductMovement({
  productId = null,
  productName = '',
  movementType = 'adjustment', // 'sale', 'return', 'transfer_to_store', 'warehouse_in', 'damage', 'adjustment'
  referenceId = null,
  referenceTitle = '',
  selectedOption = null,
  quantityChange = 0,
  quantityBefore = 0,
  quantityAfter = 0,
  unitPrice = 0,
  unitCost = 0,
  userName = 'النظام',
  notes = ''
}, client = posDb) {
  try {
    const prodId = productId ? parseInt(productId, 10) || null : null;
    const refId = referenceId ? parseInt(referenceId, 10) || null : null;
    const qChange = parseInt(quantityChange || 0, 10) || 0;
    const qBefore = parseInt(quantityBefore || 0, 10) || 0;
    const qAfter = parseInt(quantityAfter || 0, 10) || 0;
    const uPrice = parseFloat(unitPrice || 0) || 0;
    const uCost = parseFloat(unitCost || 0) || 0;

    await client.query(
      `INSERT INTO product_movement_logs (
        product_id, product_name, movement_type, reference_id, reference_title,
        selected_option, quantity_change, quantity_before, quantity_after,
        unit_price, unit_cost, user_name, notes
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [
        prodId,
        productName || 'صنف',
        movementType || 'adjustment',
        refId,
        referenceTitle || '',
        selectedOption || null,
        qChange,
        qBefore,
        qAfter,
        uPrice,
        uCost,
        userName || 'النظام',
        notes || ''
      ]
    );
  } catch (err) {
    console.error('Movement log error:', err.message);
  }
}

// ── Warehouse APIs ────────────────────────────────────────────────────────────

// GET /api/warehouse/products — list all warehouse items and shop products
app.get(`${BASE}/api/warehouse/products`, async (req, res) => {
  try {
    // Self-heal: ensure tables exist
    await posDb.query(`CREATE TABLE IF NOT EXISTS warehouse_items (
      id SERIAL PRIMARY KEY, product_id INTEGER, product_name TEXT NOT NULL,
      barcode TEXT, category TEXT, cost_price NUMERIC DEFAULT 0, sale_price NUMERIC DEFAULT 0,
      quantity INTEGER DEFAULT 0, variants JSONB, checkbox_values JSONB, description TEXT DEFAULT '', expiry_date TEXT DEFAULT '', notes TEXT,
      created_at TEXT DEFAULT (NOW()::text), updated_at TEXT DEFAULT (NOW()::text)
    )`).catch(() => {});
    await posDb.query(`ALTER TABLE warehouse_items ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''`).catch(() => {});
    await posDb.query(`ALTER TABLE warehouse_items ADD COLUMN IF NOT EXISTS expiry_date TEXT DEFAULT ''`).catch(() => {});
    await posDb.query(`CREATE TABLE IF NOT EXISTS warehouse_batches (
      id SERIAL PRIMARY KEY, warehouse_item_id INTEGER, product_id INTEGER, batch_number TEXT,
      quantity INTEGER NOT NULL DEFAULT 0, cost_price NUMERIC DEFAULT 0, expiry_date TEXT, notes TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`).catch(() => {});

    // Fetch warehouse items
    const { rows: items } = await posDb.query(`
      SELECT w.*, 
        p.quantity AS shop_quantity,
        p.sale_price AS shop_sale_price
      FROM warehouse_items w
      LEFT JOIN products p ON p.id = w.product_id
      ORDER BY w.id DESC
    `).catch(async () => {
      const { rows } = await posDb.query('SELECT * FROM warehouse_items ORDER BY id DESC');
      return { rows };
    });

    // Fetch batches for each warehouse item
    const { rows: batches } = await posDb.query(`
      SELECT * FROM warehouse_batches WHERE quantity > 0 ORDER BY id ASC
    `).catch(() => ({ rows: [] }));

    const batchMap = {};
    (batches || []).forEach(b => {
      if (!batchMap[b.warehouse_item_id]) batchMap[b.warehouse_item_id] = [];
      batchMap[b.warehouse_item_id].push(b);
    });

    items.forEach(it => {
      it.batches = batchMap[it.id] || [];
    });

    // Fetch shop products
    const { rows: shop_products } = await posDb.query(
      `SELECT * FROM products ORDER BY product_name`
    ).catch(async () => {
      const { rows } = await posDb.query(`SELECT id, product_name, barcode, category, sale_price, purchase_price, quantity, variants, checkbox_values FROM products ORDER BY product_name`);
      return { rows };
    });

    res.json({ items: items || [], shop_products: shop_products || [] });
  } catch (err) {
    console.error('Get warehouse products error:', err.message);
    res.json({ items: [], shop_products: [], error: err.message });
  }
});

// GET /api/products/:pid/cost-batches — get cost & expiry batches for a store product
app.get(`${BASE}/api/products/:pid/cost-batches`, async (req, res, next) => {
  const pid = parseInt(req.params.pid, 10);
  if (isNaN(pid)) return next();
  try {
    await posDb.query(`CREATE TABLE IF NOT EXISTS product_cost_batches (
      id SERIAL PRIMARY KEY, product_id INTEGER NOT NULL, selected_option TEXT, quantity INTEGER NOT NULL DEFAULT 0,
      remaining_quantity INTEGER NOT NULL DEFAULT 0, cost_price NUMERIC DEFAULT 0, expiry_date TEXT,
      source TEXT DEFAULT 'warehouse_transfer', reference_id INTEGER, created_at TIMESTAMPTZ DEFAULT NOW()
    )`).catch(() => {});
    await posDb.query(`ALTER TABLE product_cost_batches ADD COLUMN IF NOT EXISTS selected_option TEXT`).catch(() => {});

    // Fetch product's current stock and checkbox_values
    const { rows: [prod] } = await posDb.query('SELECT quantity, purchase_price, expiry_date, checkbox_values FROM products WHERE id=$1', [pid]).catch(() => ({ rows: [] }));
    const currentTotalQty = parseInt(prod?.quantity || 0, 10);

    // If current total stock in shop is 0, auto-zero out all remaining batches
    if (currentTotalQty <= 0) {
      await posDb.query('UPDATE product_cost_batches SET remaining_quantity = 0 WHERE product_id = $1', [pid]).catch(() => {});
      return res.json({ batches: [] });
    }

    // If product has checkbox_values, zero out batches for variants that currently have 0 stock
    if (prod?.checkbox_values) {
      try {
        const cbv = typeof prod.checkbox_values === 'string' ? JSON.parse(prod.checkbox_values) : prod.checkbox_values;
        for (const [key, val] of Object.entries(cbv)) {
          const vStock = (typeof val === 'object' && val !== null && val.stock != null) ? parseInt(val.stock, 10) : (typeof val === 'number' ? val : 0);
          if (vStock <= 0) {
            const shortKey = key.includes('::') ? key.split('::').pop() : key;
            await posDb.query(
              `UPDATE product_cost_batches SET remaining_quantity = 0 WHERE product_id = $1 AND (selected_option = $2 OR selected_option = $3)`,
              [pid, key, shortKey]
            ).catch(() => {});
          }
        }
      } catch (_) {}
    }

    let { rows } = await posDb.query(
      `SELECT * FROM product_cost_batches WHERE product_id = $1 AND remaining_quantity > 0 ORDER BY id ASC`,
      [pid]
    ).catch(() => ({ rows: [] }));

    // If no batches exist yet, but shop product has existing stock, show initial active batch
    if ((!rows || rows.length === 0) && currentTotalQty > 0) {
      rows = [{
        id: 0,
        product_id: pid,
        selected_option: null,
        quantity: currentTotalQty,
        remaining_quantity: currentTotalQty,
        cost_price: parseFloat(prod?.purchase_price || 0),
        expiry_date: prod?.expiry_date || null,
        source: 'initial_stock'
      }];
    }

    res.json({ batches: rows || [] });
  } catch (err) {
    res.json({ batches: [] });
  }
});

// DELETE /api/products/:pid/cost-batches/:bid — remove or return batch to warehouse
app.delete(`${BASE}/api/products/:pid/cost-batches/:bid`, async (req, res) => {
  const pid = parseInt(req.params.pid, 10);
  const bid = parseInt(req.params.bid, 10);
  const returnToWh = req.query.return_to_wh === 'true';

  const client = await posDb.connect();
  try {
    await client.query('BEGIN');
    const { rows: [batch] } = await client.query('SELECT * FROM product_cost_batches WHERE id=$1 AND product_id=$2', [bid, pid]);
    if (!batch) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'الشحنة غير موجودة' });
    }

    const remQty = parseInt(batch.remaining_quantity || 0, 10);

    // 1. Deduct from store product
    const { rows: [prod] } = await client.query('SELECT * FROM products WHERE id=$1', [pid]);
    if (prod) {
      if (batch.selected_option) {
        let scbv = prod.checkbox_values ? (typeof prod.checkbox_values === 'string' ? JSON.parse(prod.checkbox_values) : { ...prod.checkbox_values }) : {};
        const { newCbv } = updateCbvStock(scbv, batch.selected_option, -remQty);
        const totalCb = sumCbvStock(newCbv);
        await client.query('UPDATE products SET quantity=$1, checkbox_values=$2 WHERE id=$3', [totalCb, JSON.stringify(newCbv), pid]);
      } else {
        await client.query('UPDATE products SET quantity = GREATEST(0, quantity - $1) WHERE id=$2', [remQty, pid]);
      }
    }

    // 2. Return to warehouse if requested
    if (returnToWh && remQty > 0) {
      const { rows: [whItem] } = await client.query('SELECT * FROM warehouse_items WHERE product_id=$1 LIMIT 1', [pid]);
      if (whItem) {
        if (batch.selected_option && whItem.checkbox_values) {
          let wcbv = typeof whItem.checkbox_values === 'string' ? JSON.parse(whItem.checkbox_values) : { ...whItem.checkbox_values };
          const { newCbv } = updateCbvStock(wcbv, batch.selected_option, remQty);
          const totalCb = sumCbvStock(newCbv);
          await client.query('UPDATE warehouse_items SET quantity=$1, checkbox_values=$2 WHERE id=$3', [totalCb, JSON.stringify(newCbv), whItem.id]);
        } else {
          await client.query('UPDATE warehouse_items SET quantity = quantity + $1 WHERE id=$2', [remQty, whItem.id]);
        }

        // Restore into warehouse_batches
        await client.query(
          `INSERT INTO warehouse_batches (warehouse_item_id, product_id, batch_number, quantity, cost_price, expiry_date, notes)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [whItem.id, pid, `إرجاع من المحل #${Date.now().toString().slice(-4)}`, remQty, batch.cost_price, batch.expiry_date, 'إرجاع شحنة ملغاة من المحل']
        ).catch(() => {});
      }
    }

    // 3. Delete from product_cost_batches
    await client.query('DELETE FROM product_cost_batches WHERE id=$1', [bid]);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'خطأ أثناء حذف الشحنة: ' + err.message });
  } finally {
    client.release();
  }
});

// POST /api/warehouse/products — add new warehouse item or add a new batch
app.post(`${BASE}/api/warehouse/products`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
  try {
    // Ensure table & columns exist
    await posDb.query(`CREATE TABLE IF NOT EXISTS warehouse_items (
      id SERIAL PRIMARY KEY,
      product_id INTEGER,
      product_name TEXT NOT NULL,
      barcode TEXT DEFAULT '',
      category TEXT DEFAULT 'عام',
      cost_price NUMERIC DEFAULT 0,
      sale_price NUMERIC DEFAULT 0,
      quantity INTEGER DEFAULT 0,
      variants TEXT,
      checkbox_values TEXT,
      description TEXT DEFAULT '',
      expiry_date TEXT DEFAULT '',
      notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`).catch(() => {});
    await posDb.query(`ALTER TABLE warehouse_items ADD COLUMN IF NOT EXISTS checkbox_values TEXT`).catch(() => {});
    await posDb.query(`ALTER TABLE warehouse_items ADD COLUMN IF NOT EXISTS variants TEXT`).catch(() => {});
    await posDb.query(`ALTER TABLE warehouse_items ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''`).catch(() => {});
    await posDb.query(`ALTER TABLE warehouse_items ADD COLUMN IF NOT EXISTS expiry_date TEXT DEFAULT ''`).catch(() => {});
    await posDb.query(`ALTER TABLE warehouse_items ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT ''`).catch(() => {});
    await posDb.query(`CREATE TABLE IF NOT EXISTS warehouse_batches (
      id SERIAL PRIMARY KEY, warehouse_item_id INTEGER, product_id INTEGER, batch_number TEXT,
      quantity INTEGER NOT NULL DEFAULT 0, cost_price NUMERIC DEFAULT 0, expiry_date TEXT, notes TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`).catch(() => {});

    const { product_id, product_name, barcode, category, cost_price, sale_price, quantity, variants_json, checkbox_values_json, notes, description, expiry_date, batch_number } = req.body;
    if (!product_name || !product_name.trim()) {
      return res.status(400).json({ error: 'اسم الصنف مطلوب' });
    }
    const qty = parseInt(quantity || 0, 10);
    const cost = parseFloat(cost_price || 0);
    const price = parseFloat(sale_price || 0);

    let finalDesc = description || '';
    let finalCategory = category || 'عام';
    let finalBarcode = barcode || '';
    let finalCbv = checkbox_values_json ? (typeof checkbox_values_json === 'string' ? checkbox_values_json : JSON.stringify(checkbox_values_json)) : null;
    let finalVars = variants_json ? (typeof variants_json === 'string' ? variants_json : JSON.stringify(variants_json)) : null;

    // If linked to a shop product, sync metadata
    if (product_id) {
      try {
        const { rows: [p] } = await posDb.query('SELECT * FROM products WHERE id=$1', [product_id]);
        if (p) {
          if (!finalVars && p.variants) finalVars = typeof p.variants === 'string' ? p.variants : JSON.stringify(p.variants);
          if (!finalCbv && p.checkbox_values) finalCbv = typeof p.checkbox_values === 'string' ? p.checkbox_values : JSON.stringify(p.checkbox_values);
          if (!finalDesc) finalDesc = p.description || p.details || '';
          if (!finalCategory || finalCategory === 'عام') finalCategory = p.category || 'عام';
          if (!finalBarcode) finalBarcode = p.barcode || '';
        }
      } catch (_) {}
    }

    // Check if item already exists in warehouse
    let item = null;
    let existingItem = null;
    if (product_id) {
      const { rows: [ex] } = await posDb.query('SELECT * FROM warehouse_items WHERE product_id = $1 LIMIT 1', [product_id]).catch(() => ({ rows: [] }));
      existingItem = ex || null;
    }
    if (!existingItem) {
      const { rows: [exByName] } = await posDb.query('SELECT * FROM warehouse_items WHERE LOWER(product_name) = LOWER($1) LIMIT 1', [product_name.trim()]).catch(() => ({ rows: [] }));
      existingItem = exByName || null;
    }

    if (existingItem) {
      // Add quantity to existing item and update cost & metadata
      const { rows: [upd] } = await posDb.query(
        `UPDATE warehouse_items 
         SET quantity = quantity + $1, cost_price = $2, sale_price = CASE WHEN $3 > 0 THEN $3 ELSE sale_price END, 
             checkbox_values = COALESCE($4, checkbox_values), variants = COALESCE($5, variants),
             description = CASE WHEN $6 != '' THEN $6 ELSE description END,
             expiry_date = CASE WHEN $7 != '' THEN $7 ELSE expiry_date END,
             category = CASE WHEN $8 != '' AND $8 != 'عام' THEN $8 ELSE category END,
             barcode = CASE WHEN $9 != '' THEN $9 ELSE barcode END,
             notes = COALESCE($10, notes), updated_at = NOW()
         WHERE id = $11 RETURNING *`,
        [qty, cost, price, finalCbv, finalVars, finalDesc, expiry_date || '', finalCategory, finalBarcode, notes || '', existingItem.id]
      );
      item = upd;
    } else {
      const { rows: [ins] } = await posDb.query(
        `INSERT INTO warehouse_items (product_id, product_name, barcode, category, cost_price, sale_price, quantity, variants, checkbox_values, description, expiry_date, notes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
        [product_id || null, product_name.trim(), finalBarcode, finalCategory, cost, price, qty, finalVars, finalCbv, finalDesc, expiry_date || '', notes || '']
      );
      item = ins;
    }

    // Insert batch record in warehouse_batches
    await posDb.query(
      `INSERT INTO warehouse_batches (warehouse_item_id, product_id, batch_number, quantity, cost_price, expiry_date, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [item.id, product_id || null, batch_number || `شحنة #${Date.now().toString().slice(-6)}`, qty, cost, expiry_date || null, notes || 'توريد مستودع']
    ).catch(() => {});

    // Log movement
    try {
      await logProductMovement({
        productId: product_id || null,
        productName: item.product_name,
        movementType: 'warehouse_in',
        referenceTitle: `إدخال مستودع #${item.id}`,
        quantityChange: qty,
        quantityBefore: existingItem ? parseInt(existingItem.quantity || 0) : 0,
        quantityAfter: (existingItem ? parseInt(existingItem.quantity || 0) : 0) + qty,
        unitPrice: price,
        unitCost: cost,
        userName: req.session?.username || 'المدير',
        notes: notes || `توريد شحنة جديدة (صلاحية: ${expiry_date || 'غير محددة'})`
      });
    } catch (_) {}

    res.status(201).json(item);
  } catch (err) {
    console.error('Add warehouse item error:', err);
    res.status(500).json({ error: 'خطأ داخلي: ' + err.message });
  }
});

// PUT /api/warehouse/products/:id — edit warehouse item details, stock, or remove/modify variants
app.put(`${BASE}/api/warehouse/products/:id`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
  const id = parseInt(req.params.id, 10);
  try {
    const { product_name, barcode, category, cost_price, sale_price, quantity, checkbox_values_json, variants_json, description, expiry_date, notes } = req.body;
    const qty = parseInt(quantity || 0, 10);
    const cost = parseFloat(cost_price || 0);
    const price = parseFloat(sale_price || 0);
    const finalCbv = checkbox_values_json !== undefined ? (typeof checkbox_values_json === 'string' ? checkbox_values_json : JSON.stringify(checkbox_values_json)) : null;
    const finalVars = variants_json !== undefined ? (typeof variants_json === 'string' ? variants_json : JSON.stringify(variants_json)) : null;

    const { rows: [upd] } = await posDb.query(
      `UPDATE warehouse_items
       SET product_name = COALESCE(NULLIF($1, ''), product_name),
           barcode = $2,
           category = COALESCE(NULLIF($3, ''), 'عام'),
           cost_price = $4,
           sale_price = $5,
           quantity = $6,
           checkbox_values = $7,
           variants = $8,
           description = $9,
           expiry_date = $10,
           notes = $11,
           updated_at = NOW()
       WHERE id = $12 RETURNING *`,
      [product_name?.trim(), barcode || '', category || 'عام', cost, price, qty, finalCbv, finalVars, description || '', expiry_date || '', notes || '', id]
    );

    if (!upd) return res.status(404).json({ error: 'الصنف غير موجود بالمستودع' });
    res.json({ ok: true, item: upd });
  } catch (err) {
    console.error('Update warehouse item error:', err);
    res.status(500).json({ error: 'خطأ داخلي: ' + err.message });
  }
});

// DELETE /api/warehouse/products/:id — delete item from warehouse
app.delete(`${BASE}/api/warehouse/products/:id`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
  const id = parseInt(req.params.id, 10);
  try {
    await posDb.query('DELETE FROM warehouse_batches WHERE warehouse_item_id=$1', [id]).catch(() => {});
    await posDb.query('DELETE FROM warehouse_items WHERE id=$1', [id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'خطأ داخلي: ' + err.message });
  }
});

// Helper to update variant stock in checkbox_values (handles both grouped and flat structures)
function updateCbvStock(cbv, optKey, changeQty) {
  if (!cbv || typeof cbv !== 'object') {
    if (changeQty > 0) {
      return { updated: true, newCbv: { [optKey]: { checked: true, stock: changeQty, disabled: false } } };
    }
    return { updated: false, newCbv: cbv || {} };
  }
  let found = false;
  let newCbv = JSON.parse(JSON.stringify(cbv));

  // 1. Direct key match (flat structure)
  if (newCbv[optKey] && typeof newCbv[optKey] === 'object') {
    const cur = parseInt(newCbv[optKey].stock || 0);
    newCbv[optKey].stock = Math.max(0, cur + changeQty);
    newCbv[optKey].disabled = false;
    newCbv[optKey].checked = true;
    found = true;
  }

  // 2. Search inside groups (grouped structure)
  if (!found) {
    for (const grp of Object.keys(newCbv)) {
      if (typeof newCbv[grp] === 'object' && newCbv[grp] !== null && newCbv[grp][optKey]) {
        const cur = parseInt(newCbv[grp][optKey].stock || 0);
        newCbv[grp][optKey].stock = Math.max(0, cur + changeQty);
        newCbv[grp][optKey].disabled = false;
        newCbv[grp][optKey].checked = true;
        found = true;
        break;
      }
    }
  }

  // 3. If not found in store product and we are adding stock (+changeQty > 0): create it
  if (!found && changeQty > 0) {
    newCbv[optKey] = { checked: true, stock: changeQty, disabled: false };
    found = true;
  }

  return { updated: found, newCbv };
}

function sumCbvStock(cbv) {
  if (!cbv || typeof cbv !== 'object') return 0;
  let sum = 0;
  for (const k of Object.keys(cbv)) {
    const val = cbv[k];
    if (typeof val === 'object' && val !== null) {
      if (val.stock != null) {
        sum += Math.max(0, parseInt(val.stock || 0));
      } else {
        for (const subK of Object.keys(val)) {
          if (typeof val[subK] === 'object' && val[subK] !== null && val[subK].stock != null) {
            sum += Math.max(0, parseInt(val[subK].stock || 0));
          }
        }
      }
    }
  }
  return sum;
}

// POST /api/warehouse/transfer — transfer quantity/variant from warehouse to store
app.post(`${BASE}/api/warehouse/transfer`, async (req, res) => {
  const { warehouse_item_id, quantity, selected_option, batch_id, note } = req.body;
  const transferQty = parseInt(quantity || 0, 10);
  if (!warehouse_item_id || transferQty <= 0) {
    return res.status(400).json({ error: 'حدد كمية صحيحة للتحويل' });
  }

  const client = await posDb.connect();
  try {
    await client.query('BEGIN');
    const { rows: [whItem] } = await client.query('SELECT * FROM warehouse_items WHERE id=$1 FOR UPDATE', [warehouse_item_id]);
    if (!whItem) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'الصنف غير موجود بالمستودع' });
    }

    if (whItem.quantity < transferQty) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `الكمية المتاحة بالمستودع (${whItem.quantity}) أقل من المطلوب (${transferQty})` });
    }

    // 1. Deduct from warehouse
    if (selected_option && whItem.checkbox_values) {
      const cbv = typeof whItem.checkbox_values === 'string' ? JSON.parse(whItem.checkbox_values) : { ...whItem.checkbox_values };
      const { updated, newCbv } = updateCbvStock(cbv, selected_option, -transferQty);
      if (updated) {
        const totalCb = sumCbvStock(newCbv);
        await client.query('UPDATE warehouse_items SET quantity=$1, checkbox_values=$2 WHERE id=$3', [totalCb, JSON.stringify(newCbv), whItem.id]);
      } else {
        await client.query('UPDATE warehouse_items SET quantity = GREATEST(0, quantity - $1) WHERE id=$2', [transferQty, whItem.id]);
      }
    } else {
      await client.query('UPDATE warehouse_items SET quantity = GREATEST(0, quantity - $1) WHERE id=$2', [transferQty, whItem.id]);
    }

    // Deduct from warehouse_batches (specific batch or FIFO)
    let transferCost = parseFloat(whItem.cost_price || 0);
    let transferExpiry = whItem.expiry_date || null;

    if (batch_id) {
      const { rows: [b] } = await client.query('SELECT * FROM warehouse_batches WHERE id=$1 FOR UPDATE', [batch_id]);
      if (b) {
        transferCost = parseFloat(b.cost_price || transferCost);
        transferExpiry = b.expiry_date || transferExpiry;
        await client.query('UPDATE warehouse_batches SET quantity = GREATEST(0, quantity - $1) WHERE id=$2', [transferQty, batch_id]);
      }
    } else {
      // Deduct from oldest batch FIFO
      const { rows: batches } = await client.query('SELECT * FROM warehouse_batches WHERE warehouse_item_id=$1 AND quantity > 0 ORDER BY id ASC FOR UPDATE', [whItem.id]);
      let rem = transferQty;
      for (const b of batches) {
        if (rem <= 0) break;
        const take = Math.min(b.quantity, rem);
        await client.query('UPDATE warehouse_batches SET quantity = quantity - $1 WHERE id=$2', [take, b.id]);
        transferCost = parseFloat(b.cost_price || transferCost);
        transferExpiry = b.expiry_date || transferExpiry;
        rem -= take;
      }
    }

    // 2. Add to Shop Products (and sync description & category)
    let shopProdId = whItem.product_id;
    let beforeShopQty = 0;

    if (shopProdId) {
      const { rows: [sp] } = await client.query('SELECT id, quantity, variants, checkbox_values, purchase_price, expiry_date, description, category FROM products WHERE id=$1', [shopProdId]);
      if (sp) {
        beforeShopQty = parseInt(sp.quantity || 0);

        // If size option was transferred, increase or create that size in shop product
        if (selected_option) {
          let scbv = sp.checkbox_values ? (typeof sp.checkbox_values === 'string' ? JSON.parse(sp.checkbox_values) : { ...sp.checkbox_values }) : {};
          const { newCbv } = updateCbvStock(scbv, selected_option, transferQty);
          const totalCb = sumCbvStock(newCbv);
          await client.query('UPDATE products SET quantity=$1, checkbox_values=$2 WHERE id=$3', [totalCb, JSON.stringify(newCbv), shopProdId]);
        } else {
          await client.query('UPDATE products SET quantity = quantity + $1 WHERE id=$2', [transferQty, shopProdId]);
        }

        // Sync description & category if shop product was missing them
        if (whItem.description && (!sp.description || sp.description.trim() === '')) {
          await client.query('UPDATE products SET description = $1 WHERE id=$2', [whItem.description, shopProdId]);
        }
        if (whItem.category && (!sp.category || sp.category === 'عام')) {
          await client.query('UPDATE products SET category = $1 WHERE id=$2', [whItem.category, shopProdId]);
        }

        // Update purchase price and expiry if shop didn't have one
        if (!sp.purchase_price || parseFloat(sp.purchase_price) === 0) {
          await client.query('UPDATE products SET purchase_price = $1 WHERE id=$2', [transferCost, shopProdId]);
        }
        if (transferExpiry && (!sp.expiry_date || sp.expiry_date > transferExpiry)) {
          await client.query('UPDATE products SET expiry_date = $1 WHERE id=$2', [transferExpiry, shopProdId]);
        }
      } else {
        shopProdId = null;
      }
    }

    // If no linked shop product, create one with description and category
    if (!shopProdId) {
      const { rows: [existingByName] } = await client.query('SELECT id, quantity FROM products WHERE LOWER(product_name)=LOWER($1) LIMIT 1', [whItem.product_name]);
      if (existingByName) {
        shopProdId = existingByName.id;
        beforeShopQty = parseInt(existingByName.quantity || 0);
        await client.query('UPDATE products SET quantity = quantity + $1 WHERE id=$2', [transferQty, shopProdId]);
      } else {
        const { rows: [newProd] } = await client.query(
          `INSERT INTO products (product_name, sale_price, purchase_price, quantity, barcode, category, description, expiry_date)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
          [whItem.product_name, whItem.sale_price, transferCost, transferQty, whItem.barcode || '', whItem.category || 'عام', whItem.description || '', transferExpiry || null]
        );
        shopProdId = newProd.id;
        beforeShopQty = 0;
      }
      await client.query('UPDATE warehouse_items SET product_id=$1 WHERE id=$2', [shopProdId, whItem.id]);
    }

    // 3. Record transfer record in warehouse_transfers
    const { rows: [transRecord] } = await client.query(
      `INSERT INTO warehouse_transfers (warehouse_item_id, product_id, product_name, selected_option, quantity, cost_price, sale_price, transferred_by, transferred_by_name, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
      [whItem.id, shopProdId, whItem.product_name, selected_option || null, transferQty, transferCost, whItem.sale_price, req.session?.user_id || null, req.session?.username || 'المدير', note || '']
    );

    // 4. Create product_cost_batches record for store inventory FIFO tracking
    try {
      await client.query(`CREATE TABLE IF NOT EXISTS product_cost_batches (
        id SERIAL PRIMARY KEY, product_id INTEGER NOT NULL, selected_option TEXT, quantity INTEGER NOT NULL DEFAULT 0,
        remaining_quantity INTEGER NOT NULL DEFAULT 0, cost_price NUMERIC DEFAULT 0, expiry_date TEXT,
        source TEXT DEFAULT 'warehouse_transfer', reference_id INTEGER, created_at TIMESTAMPTZ DEFAULT NOW()
      )`).catch(() => {});
      await client.query(`ALTER TABLE product_cost_batches ADD COLUMN IF NOT EXISTS selected_option TEXT`).catch(() => {});

      // If this shop product previously had stock before this transfer, but had no initial batch record, create initial active batch first
      if (beforeShopQty > 0) {
        const { rows: existingBatches } = await client.query('SELECT id FROM product_cost_batches WHERE product_id=$1 LIMIT 1', [shopProdId]).catch(() => ({ rows: [] }));
        if (!existingBatches || existingBatches.length === 0) {
          const { rows: [spOriginal] } = await client.query('SELECT purchase_price, expiry_date FROM products WHERE id=$1', [shopProdId]);
          await client.query(
            `INSERT INTO product_cost_batches (product_id, selected_option, quantity, remaining_quantity, cost_price, expiry_date, source, reference_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
            [shopProdId, null, beforeShopQty, beforeShopQty, parseFloat(spOriginal?.purchase_price || transferCost), spOriginal?.expiry_date || null, 'initial_stock', null]
          ).catch(() => {});
        }
      }

      // Insert incoming transfer batch
      await client.query(
        `INSERT INTO product_cost_batches (product_id, selected_option, quantity, remaining_quantity, cost_price, expiry_date, source, reference_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [shopProdId, selected_option || null, transferQty, transferQty, transferCost, transferExpiry || null, 'warehouse_transfer', transRecord.id]
      );
    } catch (batchErr) {
      console.error('[Cost Batch Insert Error]', batchErr.message);
    }

    // 5. Log Movement Audit Record
    await logProductMovement({
      productId: shopProdId,
      productName: whItem.product_name,
      movementType: 'transfer_to_store',
      referenceId: transRecord.id,
      referenceTitle: `إذن تحويل #${transRecord.id}`,
      selectedOption: selected_option || null,
      quantityChange: transferQty,
      quantityBefore: beforeShopQty,
      quantityAfter: beforeShopQty + transferQty,
      unitPrice: whItem.sale_price,
      unitCost: transferCost,
      userName: req.session?.username || 'المدير',
      notes: note || `تحويل من المستودع للمحل (تكلفة: ${transferCost} ج | صلاحية: ${transferExpiry || '—'})`
    }, client);

    await client.query('COMMIT');

    // 6. Sync shop product with website immediately
    if (shopProdId) {
      syncProductsNow([shopProdId]).catch(() => {});
    }

    res.json({ ok: true, transferred_qty: transferQty, product_id: shopProdId, cost_price: transferCost, expiry_date: transferExpiry });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Warehouse transfer error:', err);
    res.status(500).json({ error: 'خطأ أثناء التحويل: ' + err.message });
  } finally {
    client.release();
  }
});

// POST /api/warehouse/return-from-store — return stock from shop back to warehouse
app.post(`${BASE}/api/warehouse/return-from-store`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
  const { product_id, quantity, selected_option, reason } = req.body;
  const returnQty = parseInt(quantity || 0, 10);
  if (!product_id || returnQty <= 0) {
    return res.status(400).json({ error: 'حدد منتجاً وكمية صحيحة للإرجاع' });
  }

  const client = await posDb.connect();
  try {
    await client.query('BEGIN');
    const { rows: [shopProd] } = await client.query('SELECT * FROM products WHERE id=$1 FOR UPDATE', [product_id]);
    if (!shopProd) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'المنتج غير موجود بالمحل' });
    }

    if (shopProd.quantity < returnQty) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `الرصيد المتاح بالمحل (${shopProd.quantity}) أقل من الكمية المراد إرجاعها (${returnQty})` });
    }

    // 1. Deduct from Shop
    let beforeShopQty = parseInt(shopProd.quantity || 0);
    if (selected_option && shopProd.checkbox_values) {
      const scbv = typeof shopProd.checkbox_values === 'string' ? JSON.parse(shopProd.checkbox_values) : { ...shopProd.checkbox_values };
      if (scbv[selected_option] && typeof scbv[selected_option] === 'object') {
        const avail = scbv[selected_option].stock != null ? parseInt(scbv[selected_option].stock) : shopProd.quantity;
        if (avail < returnQty) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: `رصيد المقاس (${selected_option}) بالمحل أقل من المطلوب` });
        }
        scbv[selected_option].stock = Math.max(0, avail - returnQty);
        const totalCb = Object.values(scbv).reduce((s, v) => s + (typeof v === 'object' && v.stock != null ? Math.max(0, v.stock) : 0), 0);
        await client.query('UPDATE products SET quantity=$1, checkbox_values=$2 WHERE id=$3', [totalCb, JSON.stringify(scbv), shopProd.id]);
      } else {
        await client.query('UPDATE products SET quantity = quantity - $1 WHERE id=$2', [returnQty, shopProd.id]);
      }
    } else {
      await client.query('UPDATE products SET quantity = quantity - $1 WHERE id=$2', [returnQty, shopProd.id]);
    }

    // 2. Add back to Warehouse item (find or create)
    const { rows: [whItem] } = await client.query('SELECT * FROM warehouse_items WHERE product_id=$1 OR LOWER(product_name)=LOWER($2) LIMIT 1 FOR UPDATE', [shopProd.id, shopProd.product_name]);
    let whItemId;
    if (whItem) {
      whItemId = whItem.id;
      if (selected_option && whItem.checkbox_values) {
        const wcbv = typeof whItem.checkbox_values === 'string' ? JSON.parse(whItem.checkbox_values) : { ...whItem.checkbox_values };
        if (wcbv[selected_option] && typeof wcbv[selected_option] === 'object') {
          wcbv[selected_option].stock = (wcbv[selected_option].stock || 0) + returnQty;
          const totalWcb = Object.values(wcbv).reduce((s, v) => s + (typeof v === 'object' && v.stock != null ? Math.max(0, v.stock) : 0), 0);
          await client.query('UPDATE warehouse_items SET quantity=$1, checkbox_values=$2 WHERE id=$3', [totalWcb, JSON.stringify(wcbv), whItem.id]);
        } else {
          await client.query('UPDATE warehouse_items SET quantity = quantity + $1 WHERE id=$2', [returnQty, whItem.id]);
        }
      } else {
        await client.query('UPDATE warehouse_items SET quantity = quantity + $1 WHERE id=$2', [returnQty, whItem.id]);
      }
    } else {
      const { rows: [newWh] } = await client.query(
        `INSERT INTO warehouse_items (product_id, product_name, barcode, category, cost_price, sale_price, quantity, variants, checkbox_values, description, expiry_date, notes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
        [shopProd.id, shopProd.product_name, shopProd.barcode || '', shopProd.category || 'عام', shopProd.purchase_price || 0, shopProd.sale_price || 0, returnQty, shopProd.variants || null, shopProd.checkbox_values || null, shopProd.description || '', shopProd.expiry_date || null, 'مرتجع من المحل']
      );
      whItemId = newWh.id;
    }

    // Insert batch record in warehouse_batches as store return
    await client.query(
      `INSERT INTO warehouse_batches (warehouse_item_id, product_id, batch_number, quantity, cost_price, expiry_date, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [whItemId, shopProd.id, `مرتجع محل #${Date.now().toString().slice(-6)}`, returnQty, shopProd.purchase_price || 0, shopProd.expiry_date || null, reason || 'مرتجع من المحل إلى المستودع']
    ).catch(() => {});

    // 3. Log movement audit
    await logProductMovement({
      productId: shopProd.id,
      productName: shopProd.product_name,
      movementType: 'adjustment',
      referenceTitle: `إرجاع للمستودع #${whItemId}`,
      selectedOption: selected_option || null,
      quantityChange: -returnQty,
      quantityBefore: beforeShopQty,
      quantityAfter: beforeShopQty - returnQty,
      unitPrice: shopProd.sale_price,
      unitCost: shopProd.purchase_price,
      userName: req.session?.username || 'المدير',
      notes: reason || 'إرجاع بضاعة من المحل إلى المستودع الرئيسي'
    }, client);

    await client.query('COMMIT');

    // 4. Sync website
    syncProductsNow([shopProd.id]).catch(() => {});

    res.json({ ok: true, returned_qty: returnQty });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Return to warehouse error:', err);
    res.status(500).json({ error: 'خطأ أثناء الإرجاع: ' + err.message });
  } finally {
    client.release();
  }
});

// POST /api/products/movements/backfill — force sync/backfill all past sales and returns into movement logs
app.post(`${BASE}/api/products/movements/backfill`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
  try {
    // Self-heal: ensure table exists before backfill
    await posDb.query(`CREATE TABLE IF NOT EXISTS product_movement_logs (
      id SERIAL PRIMARY KEY, product_id INTEGER, product_name TEXT NOT NULL, movement_type TEXT NOT NULL,
      reference_id INTEGER, reference_title TEXT, selected_option TEXT, quantity_change INTEGER NOT NULL,
      quantity_before INTEGER NOT NULL DEFAULT 0, quantity_after INTEGER NOT NULL DEFAULT 0,
      unit_price NUMERIC DEFAULT 0, unit_cost NUMERIC DEFAULT 0, user_name TEXT, notes TEXT,
      date TEXT DEFAULT (NOW()::text), created_at TIMESTAMPTZ DEFAULT NOW()
    )`).catch(() => {});
    const count = await backfillHistoricalMovements(true);
    res.json({ ok: true, synced: count || 0 });
  } catch (err) {
    console.error('[Movements] Manual backfill error:', err.message);
    res.json({ ok: false, synced: 0, error: err.message });
  }
});

// GET /api/products/movements — get product movement audit logs
app.get(`${BASE}/api/products/movements`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
  try {
    // Self-heal: ensure table exists
    try {
      await posDb.query(`CREATE TABLE IF NOT EXISTS product_movement_logs (
        id SERIAL PRIMARY KEY, product_id INTEGER, product_name TEXT NOT NULL, movement_type TEXT NOT NULL,
        reference_id INTEGER, reference_title TEXT, selected_option TEXT, quantity_change INTEGER NOT NULL,
        quantity_before INTEGER NOT NULL DEFAULT 0, quantity_after INTEGER NOT NULL DEFAULT 0,
        unit_price NUMERIC DEFAULT 0, unit_cost NUMERIC DEFAULT 0, user_name TEXT, notes TEXT,
        date TEXT DEFAULT (NOW()::text), created_at TIMESTAMPTZ DEFAULT NOW()
      )`);
    } catch (tblErr) {
      console.error('[Movements] Table creation error (non-fatal):', tblErr.message);
    }

    // Auto-backfill if empty (non-blocking, won't crash)
    try {
      const { rows: [chk] } = await posDb.query('SELECT COUNT(*) as count FROM product_movement_logs');
      if (parseInt(chk?.count || 0, 10) === 0) {
        try { await backfillHistoricalMovements(true); } catch (bfErr) {
          console.error('[Movements] Backfill error (non-fatal):', bfErr.message);
        }
      }
    } catch (_) {}

    // Build query with filters
    const { q, type, date_from, date_to, limit = 500 } = req.query;
    let where = 'WHERE 1=1';
    const params = [];

    if (q && q.trim()) {
      params.push(`%${q.trim().toLowerCase()}%`);
      where += ` AND (LOWER(product_name) LIKE $${params.length} OR LOWER(COALESCE(selected_option,'')) LIKE $${params.length} OR LOWER(COALESCE(reference_title,'')) LIKE $${params.length})`;
    }
    if (type && type.trim()) {
      params.push(type.trim());
      where += ` AND movement_type = $${params.length}`;
    }
    if (date_from) {
      params.push(date_from);
      where += ` AND COALESCE(created_at, NOW())::date >= $${params.length}::date`;
    }
    if (date_to) {
      params.push(date_to);
      where += ` AND COALESCE(created_at, NOW())::date <= $${params.length}::date`;
    }

    params.push(parseInt(limit, 10) || 500);
    const sql = `SELECT * FROM product_movement_logs ${where} ORDER BY id DESC LIMIT $${params.length}`;
    const { rows } = await posDb.query(sql, params);
    return res.json({ logs: rows || [] });
  } catch (err) {
    console.error('[Movements] GET error:', err.message);
    // NEVER return 500 — always return valid empty result
    return res.json({ logs: [], error: err.message });
  }
});

// GET /api/reports/top-variants — Top-Selling Products & Variant Velocity Analytics
app.get(`${BASE}/api/reports/top-variants`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
  try {
    const period = req.query.period || 'month';
    const df = periodFilter(period, 's.date');

    // Aggregate sales grouped by product and selected_option
    const { rows: itemRows } = await posDb.query(
      `SELECT
         si.product_id,
         si.product_name,
         COALESCE(si.selected_option, '') as selected_option,
         SUM(si.quantity) as sold_qty,
         SUM(si.quantity * si.unit_price) as revenue,
         SUM(si.quantity * (si.unit_price - COALESCE(si.snapshot_purchase_price, 0))) as profit
       FROM sale_items si
       JOIN sales s ON s.id = si.sale_id
       WHERE ${df}
       GROUP BY si.product_id, si.product_name, COALESCE(si.selected_option, '')
       ORDER BY sold_qty DESC`
    );

    // Group by main product
    const productMap = {};
    for (const r of itemRows) {
      const pName = r.product_name;
      if (!productMap[pName]) {
        productMap[pName] = {
          product_id: r.product_id,
          product_name: pName,
          total_quantity: 0,
          total_revenue: 0,
          total_profit: 0,
          category: 'عام',
          current_stock: 0,
          variants_breakdown: []
        };
      }
      const q = parseInt(r.sold_qty || 0, 10);
      const rev = parseFloat(r.revenue || 0);
      const prof = parseFloat(r.profit || 0);

      productMap[pName].total_quantity += q;
      productMap[pName].total_revenue += rev;
      productMap[pName].total_profit += prof;

      if (r.selected_option) {
        productMap[pName].variants_breakdown.push({
          selected_option: r.selected_option,
          quantity: q,
          revenue: rev,
          profit: prof
        });
      }
    }

    // Attach current stock and category for products
    const productList = Object.values(productMap);
    if (productList.length > 0) {
      const pIds = productList.map(p => p.product_id).filter(Boolean);
      if (pIds.length > 0) {
        const placeholders = pIds.map((_, i) => `$${i + 1}`).join(',');
        const { rows: stockRows } = await posDb.query(
          `SELECT id, quantity, category FROM products WHERE id IN (${placeholders})`,
          pIds
        );
        const stockMap = {};
        stockRows.forEach(sr => { stockMap[sr.id] = sr; });
        productList.forEach(p => {
          if (p.product_id && stockMap[p.product_id]) {
            p.current_stock = stockMap[p.product_id].quantity || 0;
            p.category = stockMap[p.product_id].category || 'عام';
          }
        });
      }
    }

    // Sort by total quantity descending
    productList.sort((a, b) => b.total_quantity - a.total_quantity);

    res.json({ products: productList });
  } catch (err) {
    console.error('Top variants report error:', err);
    res.status(500).json({ error: 'خطأ داخلي' });
  }
});

// ── Backfill Historical Movements from existing Sales & Returns ───────────────
async function backfillHistoricalMovements(force = false) {
  try {
    const { rows: [chk] } = await posDb.query('SELECT COUNT(*) as count FROM product_movement_logs');
    const existingCount = parseInt(chk?.count || 0, 10);
    if (existingCount === 0 || force) {
      console.log('[Movements] Syncing historical product movements from past sales and returns...');
      
      // 1. Backfill Sales
      const { rowCount: salesAdded } = await posDb.query(`
        INSERT INTO product_movement_logs (
          product_id, product_name, movement_type, reference_id, reference_title,
          selected_option, quantity_change, quantity_before, quantity_after,
          unit_price, unit_cost, user_name, notes, date, created_at
        )
        SELECT
          si.product_id,
          COALESCE(si.product_name, 'صنف'),
          'sale' AS movement_type,
          s.id AS reference_id,
          'فاتورة مبيعات #' || s.id AS reference_title,
          si.selected_option,
          -COALESCE(si.quantity, 1) AS quantity_change,
          0 AS quantity_before,
          0 AS quantity_after,
          COALESCE(si.unit_price, 0) AS unit_price,
          COALESCE(si.snapshot_purchase_price, 0) AS unit_cost,
          COALESCE(u.username, 'كاشير') AS user_name,
          'مبيعات سابقة للعميل: ' || COALESCE(s.customer_name, 'نقدي') AS notes,
          COALESCE(s.date, NOW()::text) AS date,
          NOW() AS created_at
        FROM sale_items si
        JOIN sales s ON s.id = si.sale_id
        LEFT JOIN users u ON u.id = s.cashier_id
        WHERE NOT EXISTS (
          SELECT 1 FROM product_movement_logs pml
          WHERE pml.movement_type = 'sale'
            AND pml.reference_id = s.id
            AND (pml.product_id = si.product_id OR (pml.product_id IS NULL AND si.product_id IS NULL))
            AND COALESCE(pml.selected_option, '') = COALESCE(si.selected_option, '')
        )
        ORDER BY s.id ASC
      `).catch(e => { console.error('Sales backfill err:', e.message); return { rowCount: 0 }; });

      // 2. Backfill Returns
      const { rowCount: returnsAdded } = await posDb.query(`
        INSERT INTO product_movement_logs (
          product_id, product_name, movement_type, reference_id, reference_title,
          selected_option, quantity_change, quantity_before, quantity_after,
          unit_price, unit_cost, user_name, notes, date, created_at
        )
        SELECT
          ri.product_id,
          COALESCE(ri.product_name, 'صنف'),
          'return' AS movement_type,
          r.sale_id AS reference_id,
          'مرتجع إذن #' || r.id || ' فاتورة #' || r.sale_id AS reference_title,
          NULL AS selected_option,
          COALESCE(ri.quantity, 1) AS quantity_change,
          0 AS quantity_before,
          0 AS quantity_after,
          COALESCE(ri.unit_price, 0) AS unit_price,
          0 AS unit_cost,
          COALESCE(u.username, 'كاشير') AS user_name,
          'مرتجع سابق: ' || COALESCE(r.reason, 'بدون سبب') AS notes,
          COALESCE(r.date, NOW()::text) AS date,
          NOW() AS created_at
        FROM return_items ri
        JOIN returns r ON r.id = ri.return_id
        LEFT JOIN users u ON u.id = r.processed_by
        WHERE NOT EXISTS (
          SELECT 1 FROM product_movement_logs pml
          WHERE pml.movement_type = 'return'
            AND pml.reference_id = r.sale_id
            AND (pml.product_id = ri.product_id OR (pml.product_id IS NULL AND ri.product_id IS NULL))
        )
        ORDER BY r.id ASC
      `).catch(e => { console.error('Returns backfill err:', e.message); return { rowCount: 0 }; });

      const totalSynced = (salesAdded || 0) + (returnsAdded || 0);
      console.log(`[Movements] Sync complete: ${totalSynced} rows inserted ✓`);
      return totalSynced;
    }
    return 0;
  } catch (err) {
    console.error('Backfill movements error:', err.message);
    return 0;
  }
}

// ── Start Server ──────────────────────────────────────────────────────────────

async function main() {
  if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
    console.error('FATAL: SESSION_SECRET environment variable is not set. Set it before running in production.');
    process.exit(1);
  }
  if (!process.env.DATABASE_URL) {
    console.error('FATAL: DATABASE_URL environment variable is not set.');
    process.exit(1);
  }
  try {
    await initDb();

    // Ensure new warehouse & movement logs tables exist on posDb schema
    await posDb.query(`CREATE TABLE IF NOT EXISTS warehouse_items (
      id SERIAL PRIMARY KEY, product_id INTEGER, product_name TEXT NOT NULL,
      barcode TEXT, category TEXT, cost_price NUMERIC DEFAULT 0, sale_price NUMERIC DEFAULT 0,
      quantity INTEGER DEFAULT 0, variants JSONB, checkbox_values JSONB, description TEXT DEFAULT '', expiry_date TEXT DEFAULT '', notes TEXT,
      created_at TEXT DEFAULT (NOW()::text), updated_at TEXT DEFAULT (NOW()::text)
    )`).catch(() => {});
    await posDb.query(`ALTER TABLE warehouse_items ADD COLUMN IF NOT EXISTS description TEXT DEFAULT ''`).catch(() => {});
    await posDb.query(`ALTER TABLE warehouse_items ADD COLUMN IF NOT EXISTS expiry_date TEXT DEFAULT ''`).catch(() => {});

    await posDb.query(`CREATE TABLE IF NOT EXISTS warehouse_batches (
      id SERIAL PRIMARY KEY,
      warehouse_item_id INTEGER REFERENCES warehouse_items(id) ON DELETE CASCADE,
      product_id INTEGER,
      batch_number TEXT,
      quantity INTEGER NOT NULL DEFAULT 0,
      cost_price NUMERIC DEFAULT 0,
      expiry_date TEXT,
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`).catch(() => {});

    await posDb.query(`CREATE TABLE IF NOT EXISTS product_cost_batches (
      id SERIAL PRIMARY KEY,
      product_id INTEGER NOT NULL,
      selected_option TEXT,
      quantity INTEGER NOT NULL DEFAULT 0,
      remaining_quantity INTEGER NOT NULL DEFAULT 0,
      cost_price NUMERIC DEFAULT 0,
      expiry_date TEXT,
      source TEXT DEFAULT 'warehouse_transfer',
      reference_id INTEGER,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`).catch(() => {});
    await posDb.query(`ALTER TABLE product_cost_batches ADD COLUMN IF NOT EXISTS selected_option TEXT`).catch(() => {});

    await posDb.query(`CREATE TABLE IF NOT EXISTS warehouse_transfers (
      id SERIAL PRIMARY KEY, warehouse_item_id INTEGER, product_id INTEGER, product_name TEXT NOT NULL,
      selected_option TEXT, quantity INTEGER NOT NULL, cost_price NUMERIC DEFAULT 0, sale_price NUMERIC DEFAULT 0,
      transferred_by INTEGER, transferred_by_name TEXT, notes TEXT, date TEXT DEFAULT (NOW()::text)
    )`).catch(() => {});

    await posDb.query(`CREATE TABLE IF NOT EXISTS product_movement_logs (
      id SERIAL PRIMARY KEY, product_id INTEGER, product_name TEXT NOT NULL, movement_type TEXT NOT NULL,
      reference_id INTEGER, reference_title TEXT, selected_option TEXT, quantity_change INTEGER NOT NULL,
      quantity_before INTEGER NOT NULL DEFAULT 0, quantity_after INTEGER NOT NULL DEFAULT 0,
      unit_price NUMERIC DEFAULT 0, unit_cost NUMERIC DEFAULT 0, user_name TEXT, notes TEXT,
      date TEXT DEFAULT (NOW()::text), created_at TIMESTAMPTZ DEFAULT NOW()
    )`).catch(() => {});

    await backfillHistoricalMovements(false).catch(() => {});

    // Fix: ensure 'reason' column exists on customer_manual_debts
    await posDb.query(`ALTER TABLE customer_manual_debts ADD COLUMN IF NOT EXISTS reason TEXT DEFAULT ''`).catch(() => {});
    // Fix: ensure extra_profits table exists (fallback if initDb ran before this migration)
    await posDb.query(`CREATE TABLE IF NOT EXISTS extra_profits (id SERIAL PRIMARY KEY, title TEXT NOT NULL, amount NUMERIC NOT NULL, date TEXT DEFAULT (CURRENT_DATE::text))`).catch(() => {});

    // Fix: ensure 'details' and 'is_hidden_from_website' columns exist on posDb.products with safe defaults
    await posDb.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS details TEXT NOT NULL DEFAULT ''`).catch(() => {});
    await posDb.query(`ALTER TABLE products ALTER COLUMN details SET DEFAULT ''`).catch(() => {});
    await posDb.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS is_hidden_from_website BOOLEAN DEFAULT FALSE`).catch(() => {});

    await posDb.query(`CREATE TABLE IF NOT EXISTS customer_manual_debts (
      id SERIAL PRIMARY KEY,
      customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      amount DECIMAL(10,2) NOT NULL,
      reason TEXT DEFAULT '',
      date TIMESTAMPTZ DEFAULT NOW()
    )`);
    await posDb.query(`CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      endpoint TEXT UNIQUE NOT NULL,
      p256dh TEXT NOT NULL,
      auth TEXT NOT NULL,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await initPriceTracker();
    await seedManager();
    // ── Sync Queue table — تسجّل الـ sales اللي فشل sync بتاعتها ──
    await posDb.query(`
      CREATE TABLE IF NOT EXISTS sync_queue (
        id SERIAL PRIMARY KEY,
        type TEXT NOT NULL,
        payload JSONB NOT NULL,
        attempts INTEGER DEFAULT 0,
        last_error TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        next_retry_at TIMESTAMPTZ DEFAULT NOW()
      )
    `).catch(() => {});

    // ── Retry cron: كل 5 دقايق يحاول يبعت اللي في القايمة ──
    setInterval(async () => {
      try {
        const { rows } = await posDb.query(
          `SELECT * FROM sync_queue WHERE next_retry_at <= NOW() AND attempts < 10 ORDER BY created_at LIMIT 10`
        );
        for (const row of rows) {
          try {
            const d = row.payload;
            if (row.type === 'sale_to_supabase') {
              await syncSaleToSupabase(d.posCustomerId, d.posCustomerName, d.saleId, d.totalAmount, d.paymentMethod, d.splitData, d.items);
            }
            // نجح — امسحه من القايمة
            await posDb.query('DELETE FROM sync_queue WHERE id=$1', [row.id]).catch(() => {});
          } catch (retryErr) {
            // فشل تاني — زوّد المحاولات وأجّل الـ retry
            const nextRetry = new Date(Date.now() + Math.min(300000 * (row.attempts + 1), 3600000));
            await posDb.query(
              'UPDATE sync_queue SET attempts=$1, last_error=$2, next_retry_at=$3 WHERE id=$4',
              [row.attempts + 1, retryErr.message, nextRetry.toISOString(), row.id]
            ).catch(() => {});
          }
        }
      } catch (_) {}
    }, 5 * 60 * 1000); // كل 5 دقايق

    // ── تنبيه انتهاء الصلاحية: يشتغل يوميًا الساعة 8 الصبح (توقيت السيرفر) ──
    cron.schedule('0 8 * * *', () => { checkExpiryAndNotify().catch(() => {}); });

    app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now() }));
    app.get('/api/healthz', (req, res) => res.json({ status: 'ok', ts: Date.now() }));
    // pre-warm AI model list so first user request is fast
    if (OPENROUTER_KEY) { fetchFreeModels().catch(() => {}); console.log('[AI] OpenRouter enabled — dynamic free model'); }
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`POS server running on port ${PORT} at ${BASE}`);
      const RENDER_URL = process.env.RENDER_EXTERNAL_URL;
      if (RENDER_URL) {
        const _m = RENDER_URL.startsWith('https') ? require('https') : require('http');
        setInterval(() => { _m.get(`${RENDER_URL}/health`, () => {}).on('error', () => {}); }, 14 * 60 * 1000);
        console.log('Keep-alive enabled:', RENDER_URL);
      }
    });
  } catch (err) {
    console.error('Startup error:', err);
    process.exit(1);
  }
}

main();
