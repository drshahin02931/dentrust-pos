'use strict';
const { Pool, types } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

types.setTypeParser(1700, val => val === null ? null : parseFloat(val));
types.setTypeParser(20, val => val === null ? null : parseInt(val, 10));

const DATABASE_URL = process.env.DATABASE_URL;
const SUPABASE_DATABASE_URL = process.env.SUPABASE_DATABASE_URL;
const POS_SCHEMA = 'pos_data';

const sslConfig = process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false;

// posDb: POS-specific tables under pos_data schema
const posDb = new Pool({ connectionString: DATABASE_URL, ssl: sslConfig, max: 10, idleTimeoutMillis: 30000, connectionTimeoutMillis: 5000 });
posDb.on('connect', client => {
  client.query(`SET search_path TO ${POS_SCHEMA}, public`);
});

// dentrustDb: website public schema (products, orders, categories…)
// In single-DB mode (DATABASE_URL = Supabase) this is the SAME database,
// but a separate pool with no search_path override → defaults to public schema.
const WEBSITE_DB_URL = SUPABASE_DATABASE_URL || DATABASE_URL;
const isSingleDb = !SUPABASE_DATABASE_URL || SUPABASE_DATABASE_URL === DATABASE_URL;
const dentrustDb = new Pool({ connectionString: WEBSITE_DB_URL, ssl: sslConfig, max: 8, idleTimeoutMillis: 30000, connectionTimeoutMillis: 5000 });
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
  CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    barcode TEXT UNIQUE,
    product_name TEXT NOT NULL,
    quantity INTEGER DEFAULT 0,
    purchase_price NUMERIC DEFAULT 0,
    sale_price NUMERIC DEFAULT 0,
    expiry_date TEXT,
    dentrust_id INTEGER,
    image_url TEXT,
    category TEXT,
    min_stock INTEGER DEFAULT 0,
    supplier_id INTEGER,
    description TEXT,
    variants TEXT,
    section TEXT DEFAULT 'dental',
    checkbox_values TEXT,
    created_at TEXT DEFAULT (NOW()::text)
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
    product_id INTEGER REFERENCES products(id),
    product_name TEXT,
    quantity INTEGER,
    unit_price NUMERIC,
    sale_item_id INTEGER,
    snapshot_purchase_price NUMERIC,
    snapshot_unit_price NUMERIC
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
    product_id INTEGER REFERENCES products(id),
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
  "ALTER TABLE products ADD COLUMN IF NOT EXISTS variants TEXT",
  "ALTER TABLE products ADD COLUMN IF NOT EXISTS expiry_date TEXT",
  "ALTER TABLE products ADD COLUMN IF NOT EXISTS supplier_id INTEGER",
  "ALTER TABLE products ADD COLUMN IF NOT EXISTS description TEXT",
  "ALTER TABLE products ADD COLUMN IF NOT EXISTS min_stock INTEGER DEFAULT 0",
  "ALTER TABLE products ADD COLUMN IF NOT EXISTS image_url TEXT",
  "ALTER TABLE products ADD COLUMN IF NOT EXISTS category TEXT",
  "ALTER TABLE products ADD COLUMN IF NOT EXISTS dentrust_id INTEGER",
  "ALTER TABLE products ADD COLUMN IF NOT EXISTS section TEXT DEFAULT 'dental'",
  "ALTER TABLE products ADD COLUMN IF NOT EXISTS checkbox_values TEXT",
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
];

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
    await client.query(`CREATE SCHEMA IF NOT EXISTS ${POS_SCHEMA}`);
    await client.query(`SET search_path TO ${POS_SCHEMA}, public`);
    const stmts = PG_SCHEMA_SQL.split(';').map(s => s.trim()).filter(Boolean);
    for (const stmt of stmts) {
      await client.query(stmt);
    }
    for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
      await client.query(
        `INSERT INTO store_settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING`,
        [k, String(v)]
      );
    }
    for (const migration of MIGRATIONS) {
      try { await client.query(migration); } catch (_) {}
    }
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
  posDb, dentrustDb, isSingleDb, WEBSITE_DB_URL,
  initDb, seedManager,
  verifyPassword, hashPassword,
  getSettings,
  ALL_PERMS, EMPLOYEE_DEFAULT_PERMS,
};
