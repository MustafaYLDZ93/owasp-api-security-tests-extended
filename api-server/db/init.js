'use strict';

const fs = require('fs');
const Database = require('better-sqlite3');
const { hashPassword } = require('../lib/hash');

const SCHEMA = `
CREATE TABLE users (
  id               INTEGER PRIMARY KEY,
  email            TEXT UNIQUE NOT NULL,
  password_hash    TEXT NOT NULL,
  name             TEXT NOT NULL,
  role             TEXT NOT NULL DEFAULT 'user',
  phone            TEXT,
  credits          INTEGER NOT NULL DEFAULT 0,
  verified         INTEGER NOT NULL DEFAULT 0,
  referral_code    TEXT UNIQUE,
  security_question TEXT,
  security_answer  TEXT
);

CREATE TABLE products (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  description TEXT,
  stock       INTEGER NOT NULL,
  price       REAL NOT NULL
);

CREATE TABLE orders (
  id          TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL,
  product_id  TEXT NOT NULL,
  quantity    INTEGER NOT NULL,
  status      TEXT NOT NULL DEFAULT 'created',
  created_at  TEXT NOT NULL
);

CREATE TABLE comments (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id  TEXT NOT NULL,
  user_id     INTEGER NOT NULL,
  body_html   TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE webhooks (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id  INTEGER NOT NULL,
  url      TEXT NOT NULL
);

CREATE TABLE files (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id    INTEGER NOT NULL,
  filename    TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  uploaded_at TEXT NOT NULL
);

CREATE TABLE coupons (
  code             TEXT PRIMARY KEY,
  discount_percent INTEGER NOT NULL,
  max_uses         INTEGER NOT NULL,
  used_count       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE coupon_redemptions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  code       TEXT NOT NULL,
  user_id    INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE oauth_clients (
  client_id     TEXT PRIMARY KEY,
  client_secret TEXT NOT NULL,
  redirect_uris TEXT NOT NULL, -- JSON array
  scopes        TEXT NOT NULL  -- JSON array
);

CREATE TABLE oauth_codes (
  code         TEXT PRIMARY KEY,
  client_id    TEXT NOT NULL,
  user_id      INTEGER NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope        TEXT NOT NULL,
  expires_at   INTEGER NOT NULL,
  used         INTEGER NOT NULL DEFAULT 0
);
`;

function seed(db) {
  const insertUser = db.prepare(`
    INSERT INTO users (id, email, password_hash, name, role, credits, verified, referral_code, security_question, security_answer)
    VALUES (@id, @email, @password_hash, @name, @role, @credits, @verified, @referral_code, @security_question, @security_answer)
  `);

  insertUser.run({
    id: 10, email: 'user_a@test.com', password_hash: hashPassword('Password123!'),
    name: 'User A', role: 'user', credits: 0, verified: 0,
    referral_code: 'REF_USER_A', security_question: 'What is your favorite color?', security_answer: 'blue',
  });
  insertUser.run({
    id: 2, email: 'user_b@test.com', password_hash: hashPassword('Password123!'),
    name: 'User B', role: 'user', credits: 0, verified: 0,
    referral_code: 'REF_USER_B', security_question: 'What is your favorite color?', security_answer: 'green',
  });
  insertUser.run({
    id: 3, email: 'admin@test.com', password_hash: hashPassword('AdminPass123!'),
    name: 'Admin', role: 'admin', credits: 0, verified: 1,
    referral_code: 'REF_ADMIN', security_question: 'What is your favorite color?', security_answer: 'red',
  });

  const insertProduct = db.prepare(`
    INSERT INTO products (id, name, description, stock, price) VALUES (@id, @name, @description, @stock, @price)
  `);
  insertProduct.run({ id: 'product-001', name: 'Regular Product', description: 'A regular catalog item.', stock: 100, price: 29.99 });
  insertProduct.run({ id: 'product-002', name: 'Another Product', description: 'Another catalog item.', stock: 50, price: 19.99 });
  insertProduct.run({ id: 'promo-item-001', name: 'Limited Promo Item', description: 'Only 1 in stock — race condition target.', stock: 1, price: 9.99 });

  db.prepare(`INSERT INTO orders (id, user_id, product_id, quantity, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
    .run('order-001', 10, 'product-001', 2, 'completed', new Date().toISOString());
  db.prepare(`INSERT INTO orders (id, user_id, product_id, quantity, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
    .run('order-002', 2, 'product-002', 1, 'completed', new Date().toISOString());

  db.prepare(`INSERT INTO coupons (code, discount_percent, max_uses, used_count) VALUES (?, ?, ?, ?)`)
    .run('WELCOME10', 10, 1, 0);

  db.prepare(`
    INSERT INTO oauth_clients (client_id, client_secret, redirect_uris, scopes)
    VALUES (?, ?, ?, ?)
  `).run(
    'demo-client',
    'demo-secret',
    JSON.stringify(['http://localhost:3000/oauth/callback', 'http://localhost:3001/oauth/callback']),
    JSON.stringify(['profile', 'orders']),
  );
}

/**
 * Creates a fresh SQLite database file at dbPath (deleting any previous one),
 * applies the schema and seeds deterministic fixture data. Both server.js and
 * server-vulnerable.js call this at startup so every test run starts clean.
 */
function createDb(dbPath) {
  if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.exec(SCHEMA);
  seed(db);
  return db;
}

module.exports = { createDb };
