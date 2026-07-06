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
const { posDb, dentrustDb, isSingleDb, initDb, seedManager, verifyPassword, hashPassword, getSettings, ALL_PERMS, EMPLOYEE_DEFAULT_PERMS } = require('./db');

const BASE = (process.env.BASE_PATH || '/pos-system').replace(/\/$/, '');
const PORT = parseInt(process.env.PORT || '5000', 10);
const DATABASE_URL = process.env.DATABASE_URL;
const SUPABASE_DATABASE_URL = process.env.SUPABASE_DATABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';

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
// HAS_WEBSITE_DB: true when connected to website DB (Supabase or single-DB mode)
const HAS_WEBSITE_DB = !!(SUPABASE_DATABASE_URL || isSingleDb);
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

const sessionStore = new PgSession({
  pool: posDb,
  schemaName: 'pos_data',
  tableName: 'session',
  createTableIfMissing: true,
});

app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'pos-dev-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' },
}));

// ── Rate Limiters ─────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts — try again in 15 minutes.' } });
const apiLimiter = rateLimit({ windowMs: 60*1000, max: 200, standardHeaders: true, legacyHeaders: false, skip: (req) => !!req.session?.user_id, message: { error: 'Too many requests.' } });

// ── Helpers ──────────────────────────────────────────────────────────────────

function isMgr(req) { return req.session?.role === 'manager'; }
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
];

function authGuard(req, res, next) {
  if (req.session?.user_id) return next();
  const p = req.path;
  if (OPEN_PATHS.has(req.originalUrl.split('?')[0])) return next();
  if (OPEN_API.some(a => p.endsWith(a) || p.includes(a))) return next();
  if (p.startsWith(`${BASE}/static/`) || p.includes('/static/')) return next();
  if (req.xhr || req.headers.accept?.includes('application/json')) {
    return res.status(401).json({ error: 'غير مصرح' });
  }
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
  if (!hasPerm(req, 'pos')) return res.redirect(`${BASE}/login`);
  return renderPage(req, res, 'pos');
});
app.get(`${BASE}/inventory`, (req, res) => {
  if (!hasPerm(req, 'inventory')) return res.redirect(`${BASE}/`);
  return renderPage(req, res, 'inventory');
});
app.get(`${BASE}/customers`, (req, res) => {
  if (!hasPerm(req, 'customers')) return res.redirect(`${BASE}/`);
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
    req.session.user_id = user.id;
    req.session.username = user.username;
    req.session.role = user.role;
    req.session.permissions = perms;
    await posDb.query(
      'INSERT INTO user_sessions (user_id, ip_address) VALUES ($1, $2)',
      [user.id, req.ip]
    ).catch(() => {});
    res.redirect(`${BASE}/`);
  } catch (err) {
    console.error(err);
    res.render('login', { base: BASE, error: 'خطأ في الخادم' });
  }
});

app.get(`${BASE}/logout`, async (req, res) => {
  if (req.session?.user_id) {
    await posDb.query(
      "UPDATE user_sessions SET logout_at=NOW()::text WHERE user_id=$1 AND logout_at IS NULL",
      [req.session.user_id]
    ).catch(() => {});
  }
  req.session.destroy(() => res.redirect(`${BASE}/login`));
});

app.get(`${BASE}/sw.js`, (req, res) => res.type('js').send(''));

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
  // Fallback: base64 data-URL (no Supabase key configured)
  const dataUrl = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
  res.json({ ok: true, url: dataUrl });
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
  dentrust_id, (image_url IS NOT NULL AND (image_url LIKE 'http%' OR image_url LIKE 'data:%')) AS has_image,
  CASE WHEN image_url LIKE 'http%' THEN image_url ELSE NULL END AS image_url`;

app.get(`${BASE}/api/products`, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    let rows;
    if (q) {
      ({ rows } = await posDb.query(
        `SELECT ${PRODUCT_LIST_COLS} FROM products WHERE barcode=$1 OR product_name ILIKE $2 ORDER BY product_name`,
        [q, `%${q}%`]
      ));
    } else {
      ({ rows } = await posDb.query(`SELECT ${PRODUCT_LIST_COLS} FROM products ORDER BY product_name`));
    }
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// Serves just the image for a product (base64 → raw image response, cached)
app.get(`${BASE}/api/products/:pid/image`, async (req, res) => {
  try {
    const { rows: [p] } = await posDb.query('SELECT image_url FROM products WHERE id=$1', [req.params.pid]);
    if (!p?.image_url) return res.status(404).end();
    if (p.image_url.startsWith('http')) return res.redirect(p.image_url);
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
    const { rows: [ins] } = await posDb.query(
      `INSERT INTO products (barcode, product_name, quantity, purchase_price, sale_price, expiry_date, image_url, category, min_stock, description, variants, section, checkbox_values)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`,
      [d.barcode || null, d.product_name, d.quantity || 0,
       d.purchase_price || 0, d.sale_price || 0,
       d.expiry_date || null, d.image_url || null,
       d.category || null, parseInt(d.min_stock || 0, 10),
       d.description || null, variantsJson, d.section || 'dental', cbJson]
    );
    const posId = ins.id;
    let syncError = null;
    try { await syncNewProductToDentrust(posId, d); } catch (e) { syncError = e.message; }
    const resp = { ok: true };
    if (syncError) resp.sync_warning = `تم الحفظ في POS لكن فشل الربط بـ DenTrust: ${syncError}`;
    res.status(201).json(resp);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'الباركود مسجل مسبقاً' });
    res.status(500).json({ error: 'خطأ داخلي' });
  }
});

app.get(`${BASE}/api/products/:pid`, async (req, res) => {
  try {
    const { rows: [p] } = await posDb.query('SELECT * FROM products WHERE id=$1', [req.params.pid]);
    if (!p) return res.status(404).json({ error: 'المنتج غير موجود' });
    res.json(p);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.put(`${BASE}/api/products/:pid`, async (req, res) => {
  const pid = parseInt(req.params.pid, 10);
  const d = req.body;
  try {
    const variantsJson = d.variants ? JSON.stringify(d.variants) : null;
    const cbJson = d.checkbox_values ? JSON.stringify(d.checkbox_values) : null;
    // Only update image_url if a new one was explicitly sent (empty string = no change)
    let updateQuery, params;
    if (d.image_url) {
      params = [
        d.barcode || null, d.product_name, d.quantity || 0,
        d.purchase_price || 0, d.sale_price || 0,
        d.expiry_date || null, d.category || null,
        parseInt(d.min_stock || 0, 10), d.description || null,
        variantsJson, d.section || 'dental', cbJson, d.image_url, pid,
      ];
      updateQuery = `UPDATE products SET barcode=$1, product_name=$2, quantity=$3, purchase_price=$4,
        sale_price=$5, expiry_date=$6, category=$7, min_stock=$8, description=$9, variants=$10,
        section=$11, checkbox_values=$12, image_url=$13 WHERE id=$14`;
    } else {
      params = [
        d.barcode || null, d.product_name, d.quantity || 0,
        d.purchase_price || 0, d.sale_price || 0,
        d.expiry_date || null, d.category || null,
        parseInt(d.min_stock || 0, 10), d.description || null,
        variantsJson, d.section || 'dental', cbJson, pid,
      ];
      updateQuery = `UPDATE products SET barcode=$1, product_name=$2, quantity=$3, purchase_price=$4,
        sale_price=$5, expiry_date=$6, category=$7, min_stock=$8, description=$9, variants=$10,
        section=$11, checkbox_values=$12 WHERE id=$13`;
    }
    await posDb.query(updateQuery, params);
    try {
      await syncUpdateProductToDentrust(pid, d);
    } catch (syncErr) {
      console.error('[SYNC ERROR] syncUpdateProductToDentrust failed for pid', pid, ':', syncErr.message, syncErr.stack);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('[PRODUCT UPDATE ERROR] pid:', pid, 'body:', JSON.stringify(d), 'error:', err.message, err.stack);
    res.status(500).json({ error: 'خطأ داخلي' });
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
  await posDb.query('UPDATE products SET sale_price=$1 WHERE id=$2', [parseFloat(req.body.new_price || 0), pid]);
  res.json({ ok: true });
});

app.post(`${BASE}/api/products/:pid/mark-damaged`, async (req, res) => {
  const pid = parseInt(req.params.pid, 10);
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
});

app.put(`${BASE}/api/products/:pid/supplier`, async (req, res) => {
  const pid = parseInt(req.params.pid, 10);
  await posDb.query('UPDATE products SET supplier_id=$1 WHERE id=$2', [req.body.supplier_id || null, pid]);
  res.json({ ok: true });
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
      await client.query(
        `INSERT INTO sale_items (sale_id, product_id, product_name, quantity, unit_price, snapshot_purchase_price, snapshot_unit_price, selected_option)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [saleId, item.product_id, item.product_name, item.quantity, item.unit_price, snapPp, parseFloat(item.unit_price),
         item.selected_option || item.selectedOption || item._checkbox || null]
      );
      const stockUpdate = await client.query(
        'UPDATE products SET quantity = GREATEST(0, quantity - $1) WHERE id=$2 AND quantity >= $1 RETURNING id',
        [item.quantity, item.product_id]
      );
      if (!stockUpdate.rows.length) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: `المنتج "${item.product_name}" نفد من المخزن أو الكمية غير كافية` });
      }
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
      `SELECT si.product_id, si.quantity, si.selected_option, COALESCE(ri_sum.returned,0) AS returned
       FROM sale_items si
       LEFT JOIN (SELECT ri.sale_item_id, SUM(ri.quantity) AS returned FROM return_items ri
                  JOIN returns r ON r.id=ri.return_id WHERE r.sale_id=$1 GROUP BY ri.sale_item_id) ri_sum
         ON ri_sum.sale_item_id=si.id WHERE si.sale_id=$1`, [sid]
    );
    for (const item of items) {
      const netRestore = item.quantity - item.returned;
      if (netRestore > 0) await posDb.query('UPDATE products SET quantity = quantity + $1 WHERE id=$2', [netRestore, item.product_id]);
      // Restore checkbox option stock if tracked
      if (netRestore > 0 && item.selected_option) {
        try {
          const { rows: [pcb] } = await posDb.query('SELECT checkbox_values FROM products WHERE id=$1', [item.product_id]);
          if (pcb?.checkbox_values) {
            const cbv = typeof pcb.checkbox_values === 'string' ? JSON.parse(pcb.checkbox_values) : { ...pcb.checkbox_values };
            if (cbv[item.selected_option] && typeof cbv[item.selected_option] === 'object' && cbv[item.selected_option].stock != null) {
              cbv[item.selected_option].stock = (cbv[item.selected_option].stock || 0) + netRestore;
              cbv[item.selected_option].disabled = false;
              // Recalculate main quantity from sum of all checkbox stocks to stay in sync
              const totalCbQty = Object.values(cbv).reduce((sum, v) =>
                sum + (typeof v === 'object' && v.stock != null ? Math.max(0, v.stock) : 0), 0);
              await posDb.query(
                'UPDATE products SET quantity=$1, checkbox_values=$2 WHERE id=$3',
                [totalCbQty, JSON.stringify(cbv), item.product_id]
              );
            }
          }
        } catch (_cbErr) {}
      }
    }
    if (sale.customer_id && ['credit','split'].includes(sale.payment_method)) {
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
    await client.query('UPDATE customer_manual_debts SET customer_id=$1 WHERE customer_id=$2', [keepId, dropId]);
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
  try {
    const { rows: [debt] } = await posDb.query('SELECT * FROM customer_manual_debts WHERE id=$1 AND customer_id=$2', [did, cid]);
    if (!debt) return res.status(404).json({ error: 'غير موجود' });
    await posDb.query('DELETE FROM customer_manual_debts WHERE id=$1', [did]);
    await posDb.query('UPDATE customers SET total_debt = GREATEST(0, total_debt - $1) WHERE id=$2', [parseFloat(debt.amount), cid]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
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
  await posDb.query('DELETE FROM expenses WHERE id=$1', [parseInt(req.params.eid, 10)]);
  res.json({ ok: true });
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
    const rev = parseFloat(sd.r || 0), cost = parseFloat(sd.c || 0), exp = parseFloat(et.t || 0), refunds = parseFloat(rt.t || 0);
    const netRev = Math.max(0, rev - refunds);
    const gross = netRev - cost;
    const netProfit = gross - exp;
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
      cost: r2(cost), gross_profit: r2(gross), expenses: r2(exp), net_profit: r2(netProfit),
      sales_count: parseInt(sc.cnt, 10),
      payment_breakdown: payRows.map(r => ({ ...r, cnt: parseInt(r.cnt, 10), total: parseFloat(r.total || 0) })),
      cash_revenue: r2(cashRev), instapay_revenue: r2(instaRev),
    });
  } catch (err) { console.error(err); res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/expiry-alerts`, async (req, res) => {
  const months = parseInt(req.query.months || 3, 10);
  try {
    const { rows } = await posDb.query(
      `SELECT * FROM products WHERE expiry_date IS NOT NULL AND expiry_date::date <= CURRENT_DATE + INTERVAL '${months * 30} days' ORDER BY expiry_date`
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
              COALESCE(ret.return_count,0) AS return_count
       FROM sales s
       LEFT JOIN customers c ON s.customer_id = c.id
       LEFT JOIN (SELECT sale_id, SUM(total_refund) AS total_refunded, COUNT(*) AS return_count FROM returns GROUP BY sale_id) ret ON ret.sale_id = s.id
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
      [sid, totalRefund, reason, req.session.user_id]
    );
    const returnId = ret.id;
    for (const v of validated) {
      const { item, quantity } = v;
      await client.query(
        'INSERT INTO return_items (return_id, sale_item_id, product_id, product_name, quantity, unit_price) VALUES ($1,$2,$3,$4,$5,$6)',
        [returnId, item.id, item.product_id, item.product_name, quantity, item.unit_price]
      );
      if (item.product_id) await client.query('UPDATE products SET quantity = quantity + $1 WHERE id=$2', [quantity, item.product_id]);
      // Restore checkbox_values stock if the returned item had a checkbox option
      if (item.product_id && item.selected_option) {
        try {
          const { rows: [pcb] } = await client.query('SELECT checkbox_values FROM products WHERE id=$1', [item.product_id]);
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
                [totalCbQty, JSON.stringify(cbv), item.product_id]
              );
            }
          }
        } catch (_cbErr) {}
      }
    }
    if (sale.customer_id && ['credit','split'].includes(sale.payment_method)) {
      await client.query('UPDATE customers SET total_debt = GREATEST(0, total_debt - $1) WHERE id=$2', [totalRefund, sale.customer_id]);
    }
    await client.query('INSERT INTO expenses (title, amount, date) VALUES ($1,$2,CURRENT_DATE::text)',
      [`مردود #${returnId} فاتورة #${sid}${reason ? ` (${reason})` : ''}`, totalRefund]);
    await client.query('COMMIT');
    syncProductsNow(validated.filter(v => v.item.product_id).map(v => v.item.product_id)).catch(() => {});
    res.status(201).json({ ok: true, refund_amount: totalRefund });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    res.status(500).json({ error: 'خطأ داخلي' });
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
            const { rows: [pcb] } = await client.query('SELECT checkbox_values FROM products WHERE id=$1', [ri.product_id]);
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
    for (const item of items) {
      const prodId = item.product_id;
      const qty = parseInt(item.quantity || 1, 10);
      const price = parseFloat(item.unit_price || 0);
      const name = item.product_name || '';
      let prod = null;
      if (prodId) {
        const { rows: [p] } = await client.query('SELECT * FROM products WHERE id=$1', [prodId]);
        if (!p) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'المنتج غير موجود' }); }
        if (p.quantity < qty) { await client.query('ROLLBACK'); return res.status(400).json({ error: `مخزون غير كافٍ لـ ${p.product_name}` }); }
        prod = p;
      }
      const snapPp = prod ? parseFloat(prod.purchase_price || 0) : 0;
      await client.query(
        'INSERT INTO sale_items (sale_id, product_id, product_name, quantity, unit_price, snapshot_purchase_price, snapshot_unit_price) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [sid, prodId, name, qty, price, snapPp, price]
      );
      if (prodId) await client.query('UPDATE products SET quantity = quantity - $1 WHERE id=$2', [qty, prodId]);
      extraTotal += qty * price;
    }
    await client.query('UPDATE sales SET total_amount = total_amount + $1 WHERE id=$2', [extraTotal, sid]);
    if (sale.payment_method === 'credit' && sale.customer_id) {
      await client.query('UPDATE customers SET total_debt = total_debt + $1 WHERE id=$2', [extraTotal, sale.customer_id]);
    }
    await client.query('COMMIT');
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
  await posDb.query('UPDATE suppliers SET name=$1, phone=$2, address=$3, notes=$4 WHERE id=$5', [d.name, d.phone || '', d.address || '', d.notes || '', req.params.sid]);
  res.json({ ok: true });
});

app.delete(`${BASE}/api/suppliers/:sid`, async (req, res) => {
  await posDb.query('UPDATE products SET supplier_id=NULL WHERE supplier_id=$1', [req.params.sid]);
  await posDb.query('DELETE FROM suppliers WHERE id=$1', [req.params.sid]);
  res.json({ ok: true });
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
  await posDb.query('DELETE FROM installment_schedules WHERE id=$1', [req.params.iid]);
  res.json({ ok: true });
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
          const firstPhoto = Array.isArray(webProd?.photos) && webProd.photos.length
            ? webProd.photos[0] : null;

          if (cbJson) {
            await posDb.query(
              'UPDATE products SET stock=$1, is_sold_out=$2, checkbox_values=$3, image_url=COALESCE(NULLIF($4,\'\'), image_url) WHERE dentrust_id=$5',
              [p.quantity, p.quantity <= 0, cbJson, firstPhoto || '', p.dentrust_id]
            );
          } else if (varJson) {
            await posDb.query(
              'UPDATE products SET stock=$1, is_sold_out=$2, variants=$3, image_url=COALESCE(NULLIF($4,\'\'), image_url) WHERE dentrust_id=$5',
              [p.quantity, p.quantity <= 0, varJson, firstPhoto || '', p.dentrust_id]
            );
          } else {
            await posDb.query(
              'UPDATE products SET stock=$1, is_sold_out=$2, image_url=COALESCE(NULLIF($3,\'\'), image_url) WHERE dentrust_id=$4',
              [p.quantity, p.quantity <= 0, firstPhoto || '', p.dentrust_id]
            );
          }
        } catch (_) {}
      }
      cacheDel('site_products');
    } finally { client.release(); }
  } catch (_) {}
}

async function doPushStockToSite() {
  if (!HAS_WEBSITE_DB) return;
  try {
    const { rows: linked } = await posDb.query('SELECT id, dentrust_id, quantity, checkbox_values FROM products WHERE dentrust_id IS NOT NULL');
    if (!linked.length) return;
    const client = await dentrustDb.connect();
    try {
      for (const p of linked) {
        try {
          const cbJson = p.checkbox_values ? (typeof p.checkbox_values === 'string' ? p.checkbox_values : JSON.stringify(p.checkbox_values)) : null;
          if (cbJson) {
            await client.query('UPDATE products SET stock=$1, is_sold_out=$2, checkbox_values=$3 WHERE id=$4', [p.quantity, p.quantity <= 0, cbJson, p.dentrust_id]);
          } else {
            await client.query('UPDATE products SET stock=$1, is_sold_out=$2 WHERE id=$3', [p.quantity, p.quantity <= 0, p.dentrust_id]);
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
  const { rows: [row] } = await posDb.query('SELECT dentrust_id FROM products WHERE id=$1', [pid]);
  if (!row?.dentrust_id) return;
  const client = await dentrustDb.connect();
  try {
    const variantsJson = d.variants ? JSON.stringify(d.variants) : null;
    const cbJson = d.checkbox_values ? JSON.stringify(d.checkbox_values) : null;
    // Upload new image to Supabase Storage if one was provided
    let newPhotoUrl = null;
    if (d.image_url && d.image_url.startsWith('data:')) {
      newPhotoUrl = await uploadBase64ToSupabase(d.image_url);
    } else if (d.image_url && d.image_url.startsWith('http')) {
      newPhotoUrl = d.image_url;
    }
    if (newPhotoUrl) {
      await client.query(
        'UPDATE products SET name=$1, price=$2, stock=$3, expiry_date=$4, purchase_price=$5, variants=$6, section=$7, checkbox_values=$8, photos=$9 WHERE id=$10',
        [d.product_name, d.sale_price || 0, d.quantity || 0, d.expiry_date || null,
         d.purchase_price ? String(d.purchase_price) : null, variantsJson,
         d.section || 'dental', cbJson, JSON.stringify([newPhotoUrl]), row.dentrust_id]);
    } else {
      await client.query(
        'UPDATE products SET name=$1, price=$2, stock=$3, expiry_date=$4, purchase_price=$5, variants=$6, section=$7, checkbox_values=$8 WHERE id=$9',
        [d.product_name, d.sale_price || 0, d.quantity || 0, d.expiry_date || null,
         d.purchase_price ? String(d.purchase_price) : null, variantsJson,
         d.section || 'dental', cbJson, row.dentrust_id]);
    }
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
    'SELECT name, phone FROM customers WHERE id=$1', [posCustomerId]
  );
  // Fix: لو مفيش تليفون، نستخدم identifier بديل بدل ما نوقف الـ sync
  const phone = cust?.phone?.trim() || `pos_customer_${posCustomerId}`;
  const custName = cust?.name || posCustomerName || 'عميل نقدي';
  const client = await dentrustDb.connect();
  try {
    const instapayAmt = parseFloat(splitData?.instapay || 0);
    const { rows: [order] } = await client.query(
      `INSERT INTO orders (customer_name, phone, total_price, payment_method, status, shipping_fee, instapay_amount)
       VALUES ($1,$2,$3,$4,'completed',0,$5) RETURNING id`,
      [custName, phone, totalAmount, paymentMethod, instapayAmt]
    );
    if (!order) return;
    for (const item of items) {
      await client.query(
        'INSERT INTO order_items (order_id, product_name, quantity, unit_price) VALUES ($1,$2,$3,$4)',
        [order.id, item.product_name || item.product_name, item.quantity, item.unit_price]
      ).catch(() => {});
    }
    await posDb.query('UPDATE sales SET dentrust_order_id=$1 WHERE id=$2', [String(order.id), saleId]).catch(() => {});
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
  try {
    const { rows } = await posDb.query('SELECT id, product_name, quantity, dentrust_id FROM products ORDER BY product_name');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get(`${BASE}/api/sync/dentrust-customers`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
  try {
    const { rows } = await posDb.query('SELECT id, name, phone, dentrust_id FROM customers ORDER BY name');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/link`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
  // Support both payload formats: {pos_id, dentrust_id} and {pos_product_id, dentrust_product_id}
  const posId      = req.body.pos_id       || req.body.pos_product_id;
  const dentrustId = req.body.dentrust_id  || req.body.dentrust_product_id;
  await posDb.query('UPDATE products SET dentrust_id=$1 WHERE id=$2', [dentrustId || null, posId]);
  res.json({ ok: true });
});

app.post(`${BASE}/api/sync/push-unlinked`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
              `INSERT INTO products (product_name, sale_price, purchase_price, quantity, category, expiry_date, description, dentrust_id, image_url)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
              [p.name, p.price || 0, p.purchase_price || 0, p.stock || 0, p.cat_name || '', p.expiry_date || null, p.details || '', p.id, photoUrl]
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
  res.json({
    lastPull: syncStatus.lastPull,
    lastPush: syncStatus.lastPush,
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
            `INSERT INTO products (product_name, sale_price, purchase_price, quantity, category, expiry_date, description, dentrust_id, image_url, checkbox_values)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`,
            [p.name, p.price || 0, p.purchase_price || 0, p.stock || 0, p.cat_name || '', p.expiry_date || null, p.details || '', p.id, photoUrl, cbJson]
          );
        } else {
          await posDb.query(
            `UPDATE products SET product_name=$1, sale_price=$2, quantity=$3, category=$4,
             image_url=COALESCE($5, image_url), checkbox_values=COALESCE($6, checkbox_values),
             purchase_price=$7, expiry_date=COALESCE($8, expiry_date) WHERE id=$9`,
            [p.name, p.price || 0, p.stock || 0, p.cat_name || '', photoUrl, cbJson, p.purchase_price || 0, p.expiry_date || null, ex.id]);
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
  try {
    const result = await doFullSync();
    res.json({ ok: true, ...result });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post(`${BASE}/api/sync/force-full`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
  try {
    const result = await doFullSync();
    res.json({ ok: true, ...result });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ── Bulk push: POS customers → Supabase ──────────────────────────────────────
app.post(`${BASE}/api/sync/push-customers-to-supabase`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
  if (!isMgr(req)) return res.status(403).json({ error: 'غير مصرح' });
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
  const purchasePrice = d.purchase_price || d.cost_price || 0;
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
        await posDb.query(
          'UPDATE products SET product_name=$1, sale_price=$2, quantity=$3, expiry_date=$4, purchase_price=COALESCE(NULLIF($5,0), purchase_price), category=COALESCE($6, category), checkbox_values=COALESCE($8, checkbox_values) WHERE dentrust_id=$7',
          [name, price, stock, expiry, purchasePrice, category, d.dentrust_id, _cbJsonUp]
        );
      } else {
        await posDb.query(
          'INSERT INTO products (product_name, sale_price, quantity, expiry_date, dentrust_id, purchase_price, category) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING',
          [name, price, stock, expiry, d.dentrust_id, purchasePrice, category]
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

// ── Background Sync ───────────────────────────────────────────────────────────

async function doProductSync(incremental = true) {
  try {
    const client = await dentrustDb.connect();
    try {
      let sql = 'SELECT p.*, c.name as cat_name FROM products p LEFT JOIN categories c ON c.id=p.category_id';
      if (incremental) sql += " WHERE p.updated_at >= NOW() - INTERVAL '10 minutes'";
      sql += ' ORDER BY p.id';
      const { rows: dtProducts } = await client.query(sql);
      for (const p of dtProducts) {
        try {
          // photos is a Supabase Storage URL array — use first photo as POS image_url.
          // These URLs are persistent (survive Render restarts), unlike local disk files.
          const photoUrl = Array.isArray(p.photos) && p.photos.length > 0
            ? p.photos[0]
            : (typeof p.photos === 'string' ? p.photos : null);

          const { rows: [ex] } = await posDb.query('SELECT id FROM products WHERE dentrust_id=$1', [p.id]);
          if (ex) {
            const cbJsonSync = p.checkbox_values
              ? (typeof p.checkbox_values === 'string' ? p.checkbox_values : JSON.stringify(p.checkbox_values))
              : null;
            await posDb.query(
              `UPDATE products
                  SET product_name=$1, sale_price=$2, quantity=$3,
                      checkbox_values=COALESCE($5, checkbox_values),
                      image_url=COALESCE($6, image_url)
                WHERE dentrust_id=$4`,
              [p.name, p.price || 0, p.stock || 0, p.id, cbJsonSync, photoUrl]);
          } else {
            await posDb.query(
              `INSERT INTO products
                 (product_name, sale_price, purchase_price, quantity, category, expiry_date, dentrust_id, image_url)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
              [p.name, p.price || 0, p.purchase_price || 0, p.stock || 0,
               p.cat_name || '', p.expiry_date || null, p.id, photoUrl]
            );
          }
        } catch (_) {}
      }
    } finally { client.release(); }
  } catch (_) {}
}

// ── Sync status tracking ──────────────────────────────────────────────────────
const syncStatus = {
  lastPull: null,   // ISO string — when DenTrust → POS pull last ran
  lastPush: null,   // ISO string — when POS → DenTrust push last ran
  pullCount: 0,     // how many products were touched in last pull
  pushCount: 0,     // how many products were pushed in last push
};

// Wrap doProductSync to record timing
async function doProductSyncTracked(incremental = true) {
  await doProductSync(incremental);
  syncStatus.lastPull = new Date().toISOString();
}

// Wrap doPushStockToSite to record timing
async function doPushStockTracked() {
  await doPushStockToSite();
  syncStatus.lastPush = new Date().toISOString();
}

// Pull: DenTrust → POS every 1 minute (incremental)
cron.schedule('* * * * *', () => doProductSyncTracked(true).catch(() => {}));
// Push: POS → DenTrust every 1 minute (was 3 min — tightened for real-time feel)
cron.schedule('* * * * *', () => doPushStockTracked().catch(() => {}));

// ── Utility ───────────────────────────────────────────────────────────────────

function r2(n) { return Math.round(parseFloat(n || 0) * 100) / 100; }


// ═══════════════════════════════════════════════════════════════════════════════
// ── WEBSITE API (called from dentrust.site — no POS session required) ─────────
// ═══════════════════════════════════════════════════════════════════════════════

const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY || '';
const GROQ_API_KEY   = process.env.GROQ_API_KEY || '';
const GROQ_MODEL     = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
const GROQ_BASE      = 'https://api.groq.com/openai/v1/chat/completions';
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
                p.image_url, p.expiry_date, p.description,
                c.name AS category_name, p.category_id
         FROM products p
         LEFT JOIN categories c ON c.id = p.category_id
         ORDER BY p.name`
      );
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
      const productLines = productsResult.rows.map(r => {
        let line = `- [ID:${r.id}] ${r.product_name}`;
        if (r.category) line += ` (${r.category})`;
        if (r.sale_price) line += ` — السعر: ${r.sale_price} جنيه`;
        if (r.description) line += ` — ${r.description}`;
        return line;
      }).join('\n');
      text += `\n\n=== قائمة المنتجات المتوفرة حالياً في المخزون ===\n${productLines}\n===`;
    }

    _knowledgeCache = text;
    _knowledgeCacheAt = now;
    return _knowledgeCache;
  } catch { return ''; }
}

// ── AI – shared helper ────────────────────────────────────────────────────────
// Dynamic free-model cache — refreshed from OpenRouter every hour
let _freeModelCache = null;
let _freeModelCacheAt = 0;

// Stable high-quality free models — always tried first
const PREFERRED_FREE_MODELS = [
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
    if (resp.status === 429 || resp.status === 402 || resp.status === 404 || resp.status >= 500) {
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

// ── Gemini Direct API helper ───────────────────────────────────────────────
// يحوّل messages بتاعة OpenAI format لـ Gemini format ويرجع response بـ OpenAI format

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function isQuotaError(status, msg = '') {
  return status === 429 || msg.includes('quota') || msg.includes('RESOURCE_EXHAUSTED');
}

function extractRetryDelay(errMsg = '') {
  // Gemini بيقول "retry in X.XXs" في رسالة الخطأ
  const match = errMsg.match(/retry in ([\d.]+)s/i);
  if (match) return Math.ceil(parseFloat(match[1]) * 1000);
  return 15000; // default 15 ثانية
}

async function callGroq(messages, { max_tokens = 800, stream = false } = {}) {
  const key = GROQ_API_KEY;
  if (!key) throw new Error('GROQ_API_KEY is not set');

  // Groq لا يدعم صور في llama-3.3 — نحوّل array content لنص فقط
  const normalizedMsgs = messages.map(m => {
    if (Array.isArray(m.content)) {
      const text = m.content
        .filter(p => p.type === 'text')
        .map(p => p.text)
        .join('\n') || '[image]';
      return { ...m, content: text };
    }
    return m;
  });

  const body = {
    model: GROQ_MODEL,
    messages: normalizedMsgs,
    max_tokens,
    temperature: 0.7,
    stream,
  };

  const resp = await fetch(GROQ_BASE, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${key}`,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(stream ? 30000 : 20000),
  });

  if (stream) return resp;

  if (!resp.ok) {
    const rawBody = await resp.text().catch(() => '');
    let errBody = {};
    try { errBody = JSON.parse(rawBody); } catch (_) {}
    const errMsg = errBody?.error?.message || rawBody.slice(0, 300) || `Groq ${resp.status}`;
    console.error(`[Groq] HTTP ${resp.status} — body:`, rawBody.slice(0, 500));
    throw new Error(errMsg);
  }

  return resp.json();
}

// بيقرأ Groq SSE ويعيد إرساله بنفس الـ format البسيط اللي الـ frontend بيتوقعه
async function pipeGroqStream(groqResp, res) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Accel-Buffering', 'no');
  if (!groqResp.ok) {
    const errBody = await groqResp.json().catch(() => ({}));
    const errMsg = errBody?.error?.message || `Groq error ${groqResp.status}`;
    res.write(`data: ${JSON.stringify({ error: errMsg })}\r\n\r\n`);
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

// GET /api/ai/test  — diagnostic endpoint
// Add ?live=1 to force a real API call
app.get('/api/ai/test', async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  if (GROQ_API_KEY) {
    if (req.query.live === '1') {
      try {
        const data = await callGroq([{ role: 'user', content: 'قل مرحبا باختصار' }], { max_tokens: 30 });
        const reply = data.choices?.[0]?.message?.content || '(no content)';
        return res.json({ ok: true, provider: 'groq', model: GROQ_MODEL, reply, live: true });
      } catch (err) {
        return res.json({ ok: false, provider: 'groq', model: GROQ_MODEL, error: err.message, live: true });
      }
    }
    return res.json({ ok: true, provider: 'groq', model: GROQ_MODEL, keyConfigured: true, note: 'Add ?live=1 to test a real API call' });
  }
  const key = OPENROUTER_KEY;
  if (!key) return res.json({ ok: false, step: 'key', error: 'Set GROQ_API_KEY on Render' });
  try {
    const cache = await fetchFreeModels();
    const firstText = cache.text[0] || null;
    if (!firstText) return res.json({ ok: false, step: 'models', error: 'No free text models found on OpenRouter', cache });
    const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${key}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://dentrust.site',
        'X-Title': 'DenTrust DenBot',
      },
      body: JSON.stringify({ model: firstText, max_tokens: 20, messages: [{ role: 'user', content: 'say hi in arabic' }] }),
      signal: AbortSignal.timeout(20000),
    });
    const data = await resp.json();
    if (data.error) return res.json({ ok: false, step: 'chat', model: firstText, error: data.error });
    const reply = data.choices?.[0]?.message?.content || '(no content)';
    res.json({ ok: true, model: firstText, reply, availableText: cache.text.length });
  } catch (err) {
    res.json({ ok: false, step: 'fetch', error: err.message });
  }
});

// POST /api/ai/fashion-chat  (text chat)
app.post('/api/ai/fashion-chat', webCors, async (req, res) => {
  if (!GROQ_API_KEY && !OPENROUTER_KEY) return res.status(503).json({ error: 'Set GROQ_API_KEY on Render.' });
  try {
    const { messages = [], system = '', max_tokens = 350 } = req.body;
    const knowledge = await getBotKnowledgeText();
    const fullSystem = DENTRUST_BOT_SYSTEM + (system ? '\n' + system : '') + knowledge;
    const allMsgs = [{ role: 'system', content: fullSystem }, ...messages];
    if (GROQ_API_KEY) {
      const data = await callGroq(allMsgs, { max_tokens });
      return res.json(data);
    }
    const { resp } = await callOpenRouterFree({ max_tokens, messages: allMsgs });
    res.json(await resp.json());
  } catch (err) { res.status(500).json({ error: `خطأ داخلي: ${err.message}` }); }
});

// POST /api/ai/fashion-tryon  (vision — Groq يدعم النصوص فقط، الصورة تُتجاهل)
app.post('/api/ai/fashion-tryon', webCors, async (req, res) => {
  if (!GROQ_API_KEY && !OPENROUTER_KEY) return res.status(503).json({ error: 'Set GROQ_API_KEY on Render.' });
  try {
    const { prompt = '', system = '' } = req.body;
    const knowledge = await getBotKnowledgeText();
    const sysContent = DENTRUST_BOT_SYSTEM + (system ? '\n' + system : '') + knowledge;
    const visionMsgs = [
      { role: 'system', content: sysContent },
      { role: 'user', content: prompt },
    ];
    if (GROQ_API_KEY) {
      const data = await callGroq(visionMsgs, { max_tokens: 900 });
      return res.json(data);
    }
    const visionModels = (await fetchFreeModels()).vision;
    const { resp: visionResp } = await callOpenRouterFree({ max_tokens: 900, messages: visionMsgs }, visionModels);
    const data = await visionResp.json();
    res.json(data);
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

const DENTRUST_BOT_SYSTEM = `أنت DenBot — مساعد ذكي ومتخصص لمتجر Dentrust للمستلزمات الطبية والأسنان في مصر. شخصيتك ودودة وذكية وواثقة. تجاوب بالعامية المصرية أو بالفرانكو عربي حسب أسلوب السؤال. تساعد في: أسئلة المنتجات، الأسعار، الشحن والتوصيل، العروض، وطرق الدفع. لو مش عارف الإجابة قول بصراحة واقترح يتواصلوا على الواتساب أو بالإيميل. لا تتكلم في مواضيع سياسية أو دينية. كن مختصراً ومفيداً — لا تطول من غير داعي.

قاعدة مهمة جداً للمنتجات: لما تذكر أي منتج متوفر عندنا، اكتب الـ ID بتاعه بالشكل ده بالظبط: [[P:ID]] — استخدم الرقم اللي جنب [ID:] في قائمة المنتجات. ده بيخلي المنتج يظهر كـ card للعميل. مثال: لو المنتج عنده [ID:42] اكتب [[P:42]]. لو المنتج مش موجود في قائمتنا خالص، متكتبش الـ tag ده.`;

// POST /api/ai/fashion-chat-stream  (DenBot – streaming chat proxy, Groq-powered)
app.post('/api/ai/fashion-chat-stream', webCors, async (req, res) => {
  if (!GROQ_API_KEY && !OPENROUTER_KEY) return res.status(503).json({ error: 'Set GROQ_API_KEY on Render.' });
  try {
    const { messages = [], max_tokens = 800, stream = true } = req.body;
    const knowledge = await getBotKnowledgeText();
    const sysContent = DENTRUST_BOT_SYSTEM + knowledge;
    let patchedMessages = [...messages];
    if (sysContent) {
      const sysIdx = patchedMessages.findIndex(m => m.role === 'system');
      if (sysIdx >= 0) {
        patchedMessages[sysIdx] = { ...patchedMessages[sysIdx], content: sysContent + '\n' + patchedMessages[sysIdx].content };
      } else {
        patchedMessages = [{ role: 'system', content: sysContent }, ...patchedMessages];
      }
    }
    if (GROQ_API_KEY) {
      if (stream) {
        const groqResp = await callGroq(patchedMessages, { max_tokens, stream: true });
        return await pipeGroqStream(groqResp, res);
      }
      const data = await callGroq(patchedMessages, { max_tokens });
      return res.json(data);
    }
    const { resp } = await callOpenRouterFree({ messages: patchedMessages, max_tokens, stream });
    if (stream) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('X-Accel-Buffering', 'no');
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(decoder.decode(value).replace(/\r\n|\r|\n/g, '\r\n'));
      }
      res.end();
    } else {
      res.json(await resp.json());
    }
  } catch (err) {
    if (!res.headersSent) res.status(500).json({ error: `خطأ داخلي: ${err.message}` });
    else res.end();
  }
});

// POST /api/ai/stylebot  (StyleBot – vision + chat proxy, Groq-powered)
app.post('/api/ai/stylebot', webCors, async (req, res) => {
  if (!GROQ_API_KEY && !OPENROUTER_KEY) return res.status(503).json({ error: 'Set GROQ_API_KEY on Render.' });
  try {
    const { messages = [], max_tokens = 800, stream = true } = req.body;
    const knowledge = await getBotKnowledgeText();
    let patchedMessages = [...messages];
    if (knowledge) {
      const sysIdx = patchedMessages.findIndex(m => m.role === 'system');
      if (sysIdx >= 0) {
        patchedMessages[sysIdx] = {
          ...patchedMessages[sysIdx],
          content: patchedMessages[sysIdx].content + '\n' + knowledge,
        };
      } else {
        patchedMessages = [{ role: 'system', content: knowledge }, ...patchedMessages];
      }
    }
    if (GROQ_API_KEY) {
      if (stream) {
        const groqResp = await callGroq(patchedMessages, { max_tokens, stream: true });
        return await pipeGroqStream(groqResp, res);
      }
      const data = await callGroq(patchedMessages, { max_tokens });
      return res.json(data);
    }
    const freeModels = await fetchFreeModels();
    const { resp } = await callOpenRouterFree({ messages: patchedMessages, max_tokens, stream }, freeModels.text);
    if (stream) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('X-Accel-Buffering', 'no');
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(decoder.decode(value).replace(/\r\n|\r|\n/g, '\r\n'));
      }
      res.end();
    } else {
      res.json(await resp.json());
    }
  } catch (err) {
    if (!res.headersSent) res.status(500).json({ error: `خطأ داخلي: ${err.message}` });
    else res.end();
  }
});

// ── Bot Knowledge CRUD (POS admin) ────────────────────────────────────────────

// GET all knowledge entries
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

// ── Title similarity (Jaccard token overlap) ─────────────────────────────────
// Returns 0.0–1.0.  >= 0.35 considered a real match.
function titleSimilarity(a, b) {
  const tokenize = s => s
    .toLowerCase()
    .replace(/[^\u0600-\u06FFa-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 2);
  const ta = new Set(tokenize(String(a || '')));
  const tb = new Set(tokenize(String(b || '')));
  if (ta.size === 0 || tb.size === 0) return 0;
  const intersection = [...ta].filter(w => tb.has(w)).length;
  const union = new Set([...ta, ...tb]).size;
  return union === 0 ? 0 : intersection / union;
}

// Find the best matching product in our DB for a competitor title.
// Returns { id } or null. Requires similarity >= minScore (default 0.35).
async function findBestOurProduct(competitorTitle, minScore = 0.35) {
  if (!competitorTitle || !competitorTitle.trim()) return null;
  const words = competitorTitle
    .replace(/[^\u0600-\u06FFa-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 2)
    .slice(0, 6);
  if (words.length === 0) return null;
  const likes = words.map((_, i) => `LOWER(product_name) LIKE $${i + 1}`).join(' OR ');
  const params = words.map(w => `%${w.toLowerCase()}%`);
  const { rows: candidates } = await posDb.query(
    `SELECT id, product_name FROM products WHERE ${likes} LIMIT 20`, params
  );
  if (candidates.length === 0) return null;
  let best = null, bestScore = 0;
  for (const c of candidates) {
    const score = titleSimilarity(competitorTitle, c.product_name);
    if (score > bestScore) { bestScore = score; best = c; }
  }
  return bestScore >= minScore ? best : null;
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

  // ── Step 4: OpenRouter AI extraction (key fallback) ───────────────────────
  if (products.length < 3 && OPENROUTER_KEY) {
    try {
      const visibleText = html
        .replace(/<script[\s\S]*?<\/script>/gi, '')
        .replace(/<style[\s\S]*?<\/style>/gi, '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&')
        .replace(/\s+/g, ' ').trim().slice(0, 7000);

      const aiData = await callOpenRouter({
        model: 'google/gemini-1.5-flash',
        max_tokens: 1500,
        messages: [
          {
            role: 'system',
            content: 'You are a product price extractor for dental supply websites. Extract ALL product names and prices from the given text. Return ONLY a JSON array: [{"title":"product name","price":123.50}]. Prices must be numbers only (no currency). Return [] if nothing found.',
          },
          { role: 'user', content: `Extract products and prices:\n\n${visibleText}` },
        ],
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
// GET unseen alerts count (for badge)
app.get(`${BASE}/api/website-orders/alerts/count`, async (req, res) => {
  if (!req.session?.user_id) return res.json({ count: 0 });
  try {
    const { rows: [r] } = await posDb.query('SELECT COUNT(*) AS count FROM website_order_alerts WHERE seen=false');
    res.json({ count: parseInt(r.count, 10) });
  } catch { res.json({ count: 0 }); }
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
    const payload = JSON.stringify({ title, body, icon: '/pos-system/static/icon-192.png', badge: '/pos-system/static/icon-192.png', tag, url });
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
  await sendPushToAll(title, body, '/pos-system/inventory', 'low-stock');
}

// GET /api/push/vapid-public-key  — returns public VAPID key to client (open, no auth needed)
app.get(`${BASE}/api/push/vapid-public-key`, (req, res) => {
  if (!VAPID_PUBLIC_KEY) return res.status(503).json({ error: 'Push notifications not configured on server' });
  res.json({ publicKey: VAPID_PUBLIC_KEY });
});

// POST /api/push/subscribe  — save device push subscription
app.post(`${BASE}/api/push/subscribe`, async (req, res) => {
  if (!req.session?.user_id) return res.status(401).json({ error: 'غير مصرح' });
  const { endpoint, keys } = req.body || {};
  if (!endpoint || !keys?.p256dh || !keys?.auth) {
    return res.status(400).json({ error: 'بيانات الاشتراك ناقصة' });
  }
  try {
    await posDb.query(
      `INSERT INTO push_subscriptions (endpoint, p256dh, auth, user_id)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (endpoint) DO UPDATE SET p256dh=$2, auth=$3, user_id=$4, updated_at=NOW()`,
      [endpoint, keys.p256dh, keys.auth, req.session.user_id]
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
    await sendPushToAll('🔔 اختبار الإشعارات', 'إشعارات الـ Push تعمل بنجاح! ✅', '/pos-system/', 'test-notif');
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/push/send  — manager-only: send custom notification to all devices
app.post(`${BASE}/api/push/send`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'مسموح للمدير فقط' });
  const { title, body, url } = req.body;
  if (!title || !body) return res.status(400).json({ error: 'title و body مطلوبان' });
  try {
    await sendPushToAll(title, body, url || null);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/push/subscriptions  — manager only: how many devices subscribed
app.get(`${BASE}/api/push/subscriptions`, async (req, res) => {
  if (!isMgr(req)) return res.status(403).json({ error: 'مسموح للمدير فقط' });
  try {
    const { rows: [r] } = await posDb.query('SELECT COUNT(*) as count FROM push_subscriptions');
    res.json({ count: parseInt(r.count, 10) });
  } catch (err) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

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

    app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now() }));
    app.get('/api/healthz', (req, res) => res.json({ status: 'ok', ts: Date.now() }));
    // pre-warm AI model list so first user request is fast
    if (OPENROUTER_KEY) fetchFreeModels().catch(() => {});
    if (GROQ_API_KEY) console.log(`[AI] Groq enabled — model: ${GROQ_MODEL}`);
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
