'use strict';
const { Pool, types } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

types.setTypeParser(1700, val => val === null ? null : parseFloat(val));
types.setTypeParser(20, val => val === null ? null : parseInt(val, 10));

const DATABASE_URL = process.env.DATABASE_URL;
const POS_SCHEMA = 'pos_data';

const sslConfig = process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false;

// posDb: POS-specific tables under pos_data schema
const posDb = new Pool({ connectionString: DATABASE_URL, ssl: sslConfig, max: 5, idleTimeoutMillis: 30000, connectionTimeoutMillis: 5000 });
posDb.on('connect', client => {
  client.query(`SET search_path TO ${POS_SCHEMA}, public`);
});

// dentrustDb: public schema (products, orders, categories…)
// نفس قاعدة البيانات — pool منفصل بدون search_path override
const dentrustDb = new Pool({ connectionString: DATABASE_URL, ssl: sslConfig, max: 4, idleTimeoutMillis: 30000, connectionTimeoutMillis: 5000 });
// No search_path override → defaults to public schema ✓

const ALL_PERMS = {
  pos: true, inventory: true, expiry: true,
  customers: true, accounting: true, invoices: true,
  edit_prices: true, process_returns: true,
};
const EMPLOYEE_DEFAULT_PERMS = {
  pos: true, inventory: true, expiry: true,
  customers: true, accounting: false, invoices: false,
  edit_prices: false, process_returns: false,
};

// NOTE: products table is removed from pos_data schema.
// pos_data.products is now a VIEW pointing to public.products.
// All POS product queries run unchanged — the VIEW + INSTEAD OF triggers handle translation.
const PG_SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'employee',
    permissions TEXT NOT NULL DEFAULT '{}',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT DEFAULT (NOW()::text)
  );
  CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    login_at TEXT DEFAULT (NOW()::text),
    logout_at TEXT,
    ip_address TEXT
  );
  CREATE TABLE IF NOT EXISTS customers (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT,
    total_debt NUMERIC DEFAULT 0,
    installment_plan TEXT,
    address TEXT,
    city TEXT,
    region TEXT,
    street TEXT,
    building_number TEXT,
    landmark TEXT,
    dentrust_phone TEXT,
    dentrust_id INTEGER,
    created_at TEXT DEFAULT (NOW()::text)
  );
  CREATE TABLE IF NOT EXISTS sales (
    id SERIAL PRIMARY KEY,
    total_amount NUMERIC NOT NULL,
    payment_method TEXT DEFAULT 'cash',
    customer_id INTEGER REFERENCES customers(id),
    cashier_id INTEGER REFERENCES users(id),
    source TEXT DEFAULT 'pos',
    customer_name TEXT,
    amount_received NUMERIC,
    change_due NUMERIC,
    payment_split TEXT,
    dentrust_order_id INTEGER,
    credit_paid INTEGER DEFAULT 0,
    date TEXT DEFAULT (NOW()::text)
  );
  CREATE TABLE IF NOT EXISTS sale_items (
    id SERIAL PRIMARY KEY,
    sale_id INTEGER REFERENCES sales(id),
    product_id INTEGER,
    product_name TEXT,
    quantity INTEGER,
    unit_price NUMERIC,
    sale_item_id INTEGER,
    snapshot_purchase_price NUMERIC,
    snapshot_unit_price NUMERIC,
    selected_option TEXT
  );
  CREATE TABLE IF NOT EXISTS expenses (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    amount NUMERIC NOT NULL,
    date TEXT DEFAULT (CURRENT_DATE::text)
  );
  CREATE TABLE IF NOT EXISTS returns (
    id SERIAL PRIMARY KEY,
    sale_id INTEGER NOT NULL REFERENCES sales(id),
    total_refund NUMERIC NOT NULL,
    reason TEXT,
    processed_by INTEGER REFERENCES users(id),
    date TEXT DEFAULT (NOW()::text)
  );
  CREATE TABLE IF NOT EXISTS return_items (
    id SERIAL PRIMARY KEY,
    return_id INTEGER NOT NULL REFERENCES returns(id),
    sale_item_id INTEGER REFERENCES sale_items(id),
    product_id INTEGER,
    product_name TEXT,
    quantity INTEGER,
    unit_price NUMERIC
  );
  CREATE TABLE IF NOT EXISTS customer_payments (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    amount NUMERIC NOT NULL,
    cash_amount NUMERIC DEFAULT 0,
    instapay_amount NUMERIC DEFAULT 0,
    note TEXT,
    date TEXT DEFAULT (NOW()::text)
  );
  CREATE TABLE IF NOT EXISTS store_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
  );
  CREATE TABLE IF NOT EXISTS suppliers (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT,
    address TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (NOW()::text)
  );
  CREATE TABLE IF NOT EXISTS installment_schedules (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    sale_id INTEGER REFERENCES sales(id),
    installment_number INTEGER NOT NULL DEFAULT 1,
    amount NUMERIC NOT NULL,
    due_date TEXT NOT NULL,
    paid_date TEXT,
    status TEXT DEFAULT 'pending',
    notes TEXT,
    created_at TEXT DEFAULT (NOW()::text)
  );
  CREATE TABLE IF NOT EXISTS bot_knowledge (
    id SERIAL PRIMARY KEY,
    category TEXT NOT NULL DEFAULT 'general',
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS website_order_alerts (
    id SERIAL PRIMARY KEY,
    customer_name TEXT,
    customer_phone TEXT,
    customer_city TEXT,
    customer_address TEXT,
    dentrust_order_id INTEGER,
    total_amount NUMERIC,
    items_count INTEGER DEFAULT 0,
    items_summary TEXT,
    promo_code TEXT,
    discount_amount NUMERIC,
    delivery_amount NUMERIC,
    status TEXT DEFAULT 'pending',
    notes TEXT,
    seen BOOLEAN NOT NULL DEFAULT false,
    sale_item_id INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS cash_sessions (
    id SERIAL PRIMARY KEY,
    cashier_id INTEGER,
    date TEXT,
    opening_balance NUMERIC NOT NULL DEFAULT 0,
    closing_balance NUMERIC,
    expected_cash NUMERIC,
    discrepancy NUMERIC,
    status TEXT DEFAULT 'open',
    notes TEXT,
    opened_at TEXT,
    closed_at TEXT,
    cash_sales NUMERIC,
    instapay_sales NUMERIC,
    instapay_closing NUMERIC,
    instapay_discrepancy NUMERIC,
    opening_instapay NUMERIC DEFAULT 0
  );
`;

const MIGRATIONS = [
  "ALTER TABLE customers ADD COLUMN IF NOT EXISTS dentrust_id INTEGER",
  "ALTER TABLE sales ADD COLUMN IF NOT EXISTS source TEXT DEFAULT 'pos'",
  "ALTER TABLE sales ADD COLUMN IF NOT EXISTS customer_name TEXT",
  "ALTER TABLE sales ADD COLUMN IF NOT EXISTS amount_received NUMERIC",
  "ALTER TABLE sales ADD COLUMN IF NOT EXISTS change_due NUMERIC",
  "ALTER TABLE sales ADD COLUMN IF NOT EXISTS payment_split TEXT",
  "ALTER TABLE sales ADD COLUMN IF NOT EXISTS dentrust_order_id INTEGER",
  "ALTER TABLE sales ADD COLUMN IF NOT EXISTS credit_paid INTEGER DEFAULT 0",
  "ALTER TABLE customers ADD COLUMN IF NOT EXISTS address TEXT",
  "ALTER TABLE customers ADD COLUMN IF NOT EXISTS city TEXT",
  "ALTER TABLE customers ADD COLUMN IF NOT EXISTS region TEXT",
  "ALTER TABLE customers ADD COLUMN IF NOT EXISTS street TEXT",
  "ALTER TABLE customers ADD COLUMN IF NOT EXISTS building_number TEXT",
  "ALTER TABLE customers ADD COLUMN IF NOT EXISTS landmark TEXT",
  "ALTER TABLE customers ADD COLUMN IF NOT EXISTS dentrust_phone TEXT",
  "ALTER TABLE cash_sessions ADD COLUMN IF NOT EXISTS cash_sales NUMERIC",
  "ALTER TABLE cash_sessions ADD COLUMN IF NOT EXISTS instapay_sales NUMERIC",
  "ALTER TABLE cash_sessions ADD COLUMN IF NOT EXISTS instapay_closing NUMERIC",
  "ALTER TABLE cash_sessions ADD COLUMN IF NOT EXISTS instapay_discrepancy NUMERIC",
  "ALTER TABLE cash_sessions ADD COLUMN IF NOT EXISTS opening_instapay NUMERIC DEFAULT 0",
  "ALTER TABLE sale_items ADD COLUMN IF NOT EXISTS sale_item_id INTEGER",
  "ALTER TABLE sale_items ADD COLUMN IF NOT EXISTS snapshot_purchase_price NUMERIC",
  "ALTER TABLE sale_items ADD COLUMN IF NOT EXISTS snapshot_unit_price NUMERIC",
  "ALTER TABLE customer_payments ADD COLUMN IF NOT EXISTS cash_amount NUMERIC DEFAULT 0",
  "ALTER TABLE customer_payments ADD COLUMN IF NOT EXISTS instapay_amount NUMERIC DEFAULT 0",
  "ALTER TABLE return_items ADD COLUMN IF NOT EXISTS sale_item_id INTEGER",
  "ALTER TABLE website_order_alerts ADD COLUMN IF NOT EXISTS promo_code TEXT",
  "ALTER TABLE website_order_alerts ADD COLUMN IF NOT EXISTS discount_amount NUMERIC",
  "ALTER TABLE website_order_alerts ADD COLUMN IF NOT EXISTS delivery_amount NUMERIC",
  "ALTER TABLE website_order_alerts ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending'",
  "ALTER TABLE website_order_alerts ADD COLUMN IF NOT EXISTS notes TEXT",
  "ALTER TABLE sale_items ADD COLUMN IF NOT EXISTS selected_option TEXT",
  "ALTER TABLE sales ADD COLUMN IF NOT EXISTS discount_amount NUMERIC DEFAULT 0",
  "ALTER TABLE sales ADD COLUMN IF NOT EXISTS delivery_amount NUMERIC DEFAULT 0",
];

// Migrations that run on the PUBLIC schema (Supabase website DB) — customers table.
// Adds the "token" column used by syncCustomerToSupabase() to create website-login accounts.
const PUBLIC_CUSTOMERS_MIGRATIONS = [
  "ALTER TABLE public.customers ADD COLUMN IF NOT EXISTS token TEXT",
];

// Migrations that run on the PUBLIC schema (Supabase website DB).
// Adds POS-specific columns to public.products so the VIEW can expose them.
const PUBLIC_PRODUCTS_MIGRATIONS = [
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS barcode TEXT",
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS min_stock INTEGER DEFAULT 0",
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS supplier_id INTEGER",
  // The following are read/written by PRODUCTS_VIEW_SQL and the INSTEAD OF
  // triggers below. In single-DB mode, public.products is the website's own
  // table and may not already have these POS-specific columns — without them
  // the VIEW/trigger creation fails silently and every sale throws "خطأ داخلي".
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS purchase_price NUMERIC DEFAULT 0",
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS photos TEXT[]",
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS details TEXT",
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS variants JSONB",
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS section TEXT DEFAULT 'dental'",
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS checkbox_values JSONB",
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS is_sold_out BOOLEAN DEFAULT false",
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS is_offer BOOLEAN DEFAULT false",
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS category_id INTEGER",
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS stock INTEGER DEFAULT 0",
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS price NUMERIC DEFAULT 0",
  "ALTER TABLE public.products ADD COLUMN IF NOT EXISTS expiry_date TEXT",
];

// The VIEW that makes pos_data.products a transparent window into public.products.
// Column mapping: product_name=name, sale_price=price, quantity=stock,
//                 image_url=first element of photos[], category=categories.name,
//                 description=details, dentrust_id=id (same DB, id is universal now)
const PRODUCTS_VIEW_SQL = `
CREATE OR REPLACE VIEW pos_data.products AS
SELECT
  p.id,
  p.barcode,
  p.name                                                           AS product_name,
  COALESCE(p.stock, 0)                                            AS quantity,
  COALESCE(p.purchase_price, 0)                                   AS purchase_price,
  COALESCE(p.price, 0)                                            AS sale_price,
  p.expiry_date,
  p.id                                                            AS dentrust_id,
  CASE
    WHEN p.photos IS NOT NULL
     AND array_length(p.photos, 1) > 0
    THEN (p.photos[1])
    ELSE NULL
  END                                                             AS image_url,
  c.name                                                          AS category,
  COALESCE(p.min_stock, 0)                                        AS min_stock,
  p.supplier_id,
  p.details                                                       AS description,
  p.variants,
  COALESCE(p.section, 'dental')                                   AS section,
  p.checkbox_values,
  p.is_sold_out,
  COALESCE(p.created_at::text, NOW()::text)                       AS created_at
FROM public.products p
LEFT JOIN public.categories c ON c.id = p.category_id
`;

// INSTEAD OF INSERT — translates POS column names to public.products columns
const INSERT_TRIGGER_FN_SQL = `
CREATE OR REPLACE FUNCTION pos_data.products_insert_fn()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
  v_cat_id  INTEGER;
  v_new_id  INTEGER;
  v_photos  TEXT[];
BEGIN
  -- Resolve category name → category_id
  IF NEW.category IS NOT NULL AND TRIM(NEW.category) <> '' THEN
    SELECT id INTO v_cat_id
      FROM public.categories
     WHERE LOWER(TRIM(name)) = LOWER(TRIM(NEW.category))
     LIMIT 1;
    IF v_cat_id IS NULL THEN
      BEGIN
        INSERT INTO public.categories (name, section)
        VALUES (TRIM(NEW.category), COALESCE(NEW.section, 'dental'))
        RETURNING id INTO v_cat_id;
      EXCEPTION WHEN unique_violation THEN
        SELECT id INTO v_cat_id
          FROM public.categories
         WHERE LOWER(TRIM(name)) = LOWER(TRIM(NEW.category))
         LIMIT 1;
      END;
    END IF;
  END IF;

  -- Build photos JSON array from image_url string
  IF NEW.image_url IS NOT NULL AND NEW.image_url <> '' THEN
    v_photos := ARRAY[NEW.image_url];
  ELSE
    v_photos := ARRAY[]::TEXT[];
  END IF;

  INSERT INTO public.products (
    barcode, name, stock, purchase_price, price,
    expiry_date, photos, category_id, min_stock, supplier_id,
    details, variants, section, checkbox_values, is_offer, is_sold_out
  ) VALUES (
    NEW.barcode,
    NEW.product_name,
    COALESCE(NEW.quantity, 0),
    COALESCE(NEW.purchase_price, 0),
    COALESCE(NEW.sale_price, 0),
    NEW.expiry_date,
    v_photos,
    v_cat_id,
    COALESCE(NEW.min_stock, 0),
    NEW.supplier_id,
    NEW.description,
    NEW.variants,
    COALESCE(NEW.section, 'dental'),
    NEW.checkbox_values,
    false,
    (COALESCE(NEW.quantity, 0) <= 0)
  ) RETURNING id INTO v_new_id;

  NEW.id         := v_new_id;
  NEW.dentrust_id := v_new_id;
  RETURN NEW;
END;
$$
`;

const INSERT_TRIGGER_SQL = `
CREATE OR REPLACE TRIGGER products_instead_of_insert
INSTEAD OF INSERT ON pos_data.products
FOR EACH ROW EXECUTE FUNCTION pos_data.products_insert_fn()
`;

// INSTEAD OF UPDATE — translates updates back to public.products
const UPDATE_TRIGGER_FN_SQL = `
CREATE OR REPLACE FUNCTION pos_data.products_update_fn()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
  v_cat_id  INTEGER;
  v_photos  TEXT[];
BEGIN
  -- Resolve category if it changed
  IF NEW.category IS DISTINCT FROM OLD.category
     AND NEW.category IS NOT NULL AND TRIM(NEW.category) <> '' THEN
    SELECT id INTO v_cat_id
      FROM public.categories
     WHERE LOWER(TRIM(name)) = LOWER(TRIM(NEW.category))
     LIMIT 1;
    IF v_cat_id IS NULL THEN
      BEGIN
        INSERT INTO public.categories (name, section)
        VALUES (TRIM(NEW.category), COALESCE(NEW.section, 'dental'))
        RETURNING id INTO v_cat_id;
      EXCEPTION WHEN unique_violation THEN
        SELECT id INTO v_cat_id
          FROM public.categories
         WHERE LOWER(TRIM(name)) = LOWER(TRIM(NEW.category))
         LIMIT 1;
      END;
    END IF;
  ELSIF NEW.category IS NULL OR TRIM(NEW.category) = '' THEN
    v_cat_id := NULL;
  ELSE
    SELECT category_id INTO v_cat_id FROM public.products WHERE id = NEW.id;
  END IF;

  -- Only update photos if image_url actually changed
  IF NEW.image_url IS DISTINCT FROM OLD.image_url THEN
    IF NEW.image_url IS NOT NULL AND NEW.image_url <> '' THEN
      v_photos := ARRAY[NEW.image_url];
    ELSE
      v_photos := ARRAY[]::TEXT[];
    END IF;
  ELSE
    SELECT photos INTO v_photos FROM public.products WHERE id = NEW.id;
    IF v_photos IS NULL THEN v_photos := ARRAY[]::TEXT[]; END IF;
  END IF;

  UPDATE public.products SET
    barcode        = NEW.barcode,
    name           = NEW.product_name,
    stock          = COALESCE(NEW.quantity, 0),
    purchase_price = COALESCE(NEW.purchase_price, 0),
    price          = COALESCE(NEW.sale_price, 0),
    expiry_date    = NEW.expiry_date,
    photos         = v_photos,
    category_id    = v_cat_id,
    min_stock      = COALESCE(NEW.min_stock, 0),
    supplier_id    = NEW.supplier_id,
    details        = NEW.description,
    variants       = NEW.variants,
    section        = COALESCE(NEW.section, 'dental'),
    checkbox_values= NEW.checkbox_values,
    is_sold_out    = (COALESCE(NEW.quantity, 0) <= 0)
  WHERE id = NEW.id;

  RETURN NEW;
END;
$$
`;

const UPDATE_TRIGGER_SQL = `
CREATE OR REPLACE TRIGGER products_instead_of_update
INSTEAD OF UPDATE ON pos_data.products
FOR EACH ROW EXECUTE FUNCTION pos_data.products_update_fn()
`;

// INSTEAD OF DELETE
const DELETE_TRIGGER_FN_SQL = `
CREATE OR REPLACE FUNCTION pos_data.products_delete_fn()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM public.products WHERE id = OLD.id;
  RETURN OLD;
END;
$$
`;

const DELETE_TRIGGER_SQL = `
CREATE OR REPLACE TRIGGER products_instead_of_delete
INSTEAD OF DELETE ON pos_data.products
FOR EACH ROW EXECUTE FUNCTION pos_data.products_delete_fn()
`;

const DEFAULT_SETTINGS = {
  store_name: 'اسم المحل',
  store_name_en: 'Store Name',
  store_phone: '',
  store_address: '',
  store_address_en: '',
  invoice_title: 'فاتورة ضريبية',
  invoice_title_en: 'TAX INVOICE',
  invoice_footer: 'شكراً لتعاملكم معنا 🙏\nالبضاعة المباعة لا ترد ولا تستبدل',
  invoice_footer_en: 'Thank you for your business 🙏\nNo returns or exchanges',
  invoice_lang: 'ar',
  logo_url: '',
  currency: 'جنيه',
  currency_en: 'EGP',
  auto_print: '1',
};

async function initDb() {
  const client = await posDb.connect();
  try {
    // 1. Create pos_data schema
    await client.query(`CREATE SCHEMA IF NOT EXISTS ${POS_SCHEMA}`);
    await client.query(`SET search_path TO ${POS_SCHEMA}, public`);

    // 2. Create POS-specific tables (products is a VIEW — not created here)
    const stmts = PG_SCHEMA_SQL.split(';').map(s => s.trim()).filter(Boolean);
    for (const stmt of stmts) {
      await client.query(stmt);
    }

    // 3. Seed default settings
    for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
      await client.query(
        `INSERT INTO store_settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING`,
        [k, String(v)]
      );
    }

    // 4. Run POS migrations (sales, customers, etc. — products removed)
    for (const migration of MIGRATIONS) {
      try { await client.query(migration); } catch (_) {}
    }

    // 5. Add POS-specific columns to public.products (barcode, min_stock, supplier_id)
    for (const migration of PUBLIC_PRODUCTS_MIGRATIONS) {
      try { await client.query(migration); } catch (_) {}
    }

    // 5b. Add "token" column to public.customers (needed by syncCustomerToSupabase
    //     to create website-login accounts) — runs on the same physical DB as
    //     products in single-DB mode.
    for (const migration of PUBLIC_CUSTOMERS_MIGRATIONS) {
      try { await client.query(migration); } catch (_) {}
    }

    // 6. Create pos_data.products VIEW + INSTEAD OF triggers
    //    These make the POS see public.products as if it were pos_data.products.
    //    All existing server.js product queries work unchanged.
    try { await client.query(PRODUCTS_VIEW_SQL); } catch (e) {
      // If a real table named products exists in pos_data, rename it first
      if (e.message && e.message.includes('already exists')) {
        try {
          await client.query('ALTER TABLE pos_data.products RENAME TO products_old_backup');
          await client.query(PRODUCTS_VIEW_SQL);
        } catch (e2) {
          console.error('[initDb] Failed to create pos_data.products VIEW after rename:', e2.message);
        }
      } else {
        // Any other failure (e.g. a missing column on public.products) must NOT
        // be swallowed silently — without the VIEW, every "SELECT ... FROM products"
        // in server.js falls back to public.products directly, whose column names
        // (name/price/stock) don't match what POS queries expect (product_name/
        // sale_price/quantity), so every sale then fails with "خطأ داخلي".
        console.error('[initDb] FAILED to create pos_data.products VIEW — POS sales will break until this is fixed:', e.message);
      }
    }
    try { await client.query(INSERT_TRIGGER_FN_SQL); } catch (e) { console.error('[initDb] Failed to create products_insert_fn:', e.message); }
    try { await client.query(INSERT_TRIGGER_SQL);    } catch (e) { console.error('[initDb] Failed to create products_instead_of_insert trigger:', e.message); }
    try { await client.query(UPDATE_TRIGGER_FN_SQL); } catch (e) { console.error('[initDb] Failed to create products_update_fn:', e.message); }
    try { await client.query(UPDATE_TRIGGER_SQL);    } catch (e) { console.error('[initDb] Failed to create products_instead_of_update trigger:', e.message); }
    try { await client.query(DELETE_TRIGGER_FN_SQL); } catch (e) { console.error('[initDb] Failed to create products_delete_fn:', e.message); }
    try { await client.query(DELETE_TRIGGER_SQL);    } catch (e) { console.error('[initDb] Failed to create products_instead_of_delete trigger:', e.message); }

  } finally {
    client.release();
  }
}

async function seedManager() {
  const { rows } = await posDb.query('SELECT id FROM users WHERE username=$1', ['dr.shahin']);
  if (!rows.length) {
    const hash = await bcrypt.hash('255205', 12);
    await posDb.query(
      'INSERT INTO users (username, password_hash, role, permissions) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING',
      ['dr.shahin', hash, 'manager', JSON.stringify(ALL_PERMS)]
    );
  }
}

function checkWerkzeugPbkdf2(password, storedHash) {
  try {
    const parts = storedHash.split('$');
    if (parts.length !== 3) return false;
    const [method, salt, hexHash] = parts;
    const methodParts = method.split(':');
    if (methodParts[0] !== 'pbkdf2') return false;
    const hashName = methodParts[1];
    const iterations = parseInt(methodParts[2], 10);
    const derived = crypto.pbkdf2Sync(password, salt, iterations, 32, hashName);
    return crypto.timingSafeEqual(derived, Buffer.from(hexHash, 'hex'));
  } catch (_) {
    return false;
  }
}

function checkWerkzeugScrypt(password, storedHash) {
  try {
    const parts = storedHash.split('$');
    if (parts.length !== 3) return false;
    const [methodStr, saltStr, hashB64] = parts;
    const params = methodStr.split(':');
    if (params[0] !== 'scrypt') return false;
    const N = parseInt(params[1], 10);
    const r = parseInt(params[2], 10);
    const p = parseInt(params[3], 10);
    const salt = Buffer.from(saltStr, 'utf8');
    const isHex = /^[0-9a-f]+$/i.test(hashB64);
    const expected = Buffer.from(hashB64, isHex ? 'hex' : 'base64');
    const derived = crypto.scryptSync(password, salt, expected.length, { N, r, p, maxmem: 128 * 1024 * 1024 });
    return crypto.timingSafeEqual(derived, expected);
  } catch (_) {
    return false;
  }
}

async function verifyPassword(password, storedHash) {
  if (!storedHash) return false;
  if (storedHash.startsWith('$2b$') || storedHash.startsWith('$2a$') || storedHash.startsWith('$2y$')) {
    return bcrypt.compare(password, storedHash);
  }
  if (storedHash.startsWith('scrypt:')) {
    return checkWerkzeugScrypt(password, storedHash);
  }
  if (storedHash.startsWith('pbkdf2:')) {
    return checkWerkzeugPbkdf2(password, storedHash);
  }
  return false;
}

async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

async function getSettings() {
  const { rows } = await posDb.query('SELECT key, value FROM store_settings');
  const settings = {};
  for (const r of rows) settings[r.key] = r.value;
  return settings;
}

module.exports = {
  posDb, dentrustDb,
  initDb, seedManager,
  verifyPassword, hashPassword,
  getSettings,
  ALL_PERMS, EMPLOYEE_DEFAULT_PERMS,
};
