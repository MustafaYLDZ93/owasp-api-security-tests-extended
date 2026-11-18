'use strict';

/**
 * SECURE API server — hardened reference implementation.
 * Every route here has a mirror in server-vulnerable.js with the same
 * shape but the opposite (insecure) control. See DESIGN.md for the full
 * endpoint↔CWE↔test-ID map.
 *
 * Pre-seeded users (same on both servers):
 *   user_a@test.com  / Password123!  (id=10, role=user)
 *   user_b@test.com  / Password123!  (id=2,  role=user)
 *   admin@test.com   / AdminPass123! (id=3,  role=admin)
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const { rateLimit } = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const multer = require('multer');
const JSZip = require('jszip');

const { createDb } = require('./db/init');
const { verifyPassword, hashPassword } = require('./lib/hash');
const { matchesSecure } = require('./lib/nosql-match');
const { echoSecure } = require('./lib/system-exec');
const { renderSecure } = require('./lib/template-engine');
const { resolveXmlEntities, extractTag, XmlPolicyError } = require('./lib/xml-resolver');
const { isInternalUrl } = require('./lib/ssrf-guard');
const { createGraphQLHandler } = require('./lib/graphql-schema');
const { authorize, exchangeToken, OAuthError } = require('./lib/oauth');
const { SlidingWindowCounter } = require('./lib/rate-window');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'test-secret-key-for-security-testing';
const SESSION_SECRET = process.env.SESSION_SECRET || 'test-session-secret';
const IS_VULNERABLE = false;

// ─── Database ─────────────────────────────────────────────────────────────
const db = createDb(path.join(__dirname, 'db', `data-${PORT}.sqlite`));

// ─── Body parsers ───────────────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: false, sameSite: 'strict', maxAge: 30 * 60 * 1000 },
}));

// ─── Security headers ────────────────────────────────────────────────────
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// ─── CORS — no wildcard on authenticated endpoints ────────────────────────
const ALLOWED_ORIGINS = ['http://localhost:3000', 'http://localhost:4000', 'http://localhost:8080'];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-CSRF-Token');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ─── Static client-side demo pages (TC-C* family) ─────────────────────────
app.use(express.static(path.join(__dirname, '..', 'public', 'secure')));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

// ─── Rate limiters & sliding-window counters ──────────────────────────────
const meLimiter = rateLimit({
  windowMs: 2000, max: 15, standardHeaders: true, legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: 'Too many requests. Rate limit exceeded.' }),
});

const failedLogins = new SlidingWindowCounter(15_000);
const graphqlOps = new SlidingWindowCounter(10_000);
const smsBudget = new SlidingWindowCounter(60_000);

// ─── Helpers ──────────────────────────────────────────────────────────────

function sanitize(user) {
  if (!user) return null;
  const { password_hash, security_answer, ...safe } = user;
  return { ...safe, verified: !!safe.verified };
}

/** JWT auth middleware — strict algorithm + full claim validation (CWE-347/287). */
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'owasp-api-extended',
      audience: 'owasp-api-extended-clients',
    });
    const row = db.prepare('SELECT * FROM users WHERE id = ?').get(decoded.userId);
    if (!row) return res.status(401).json({ error: 'User not found' });
    req.user = row;
    req.tokenClaims = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/** Same as requireAuth but does not reject when no/invalid token is present (used by /graphql). */
function optionalAuth(req, _res, next) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(header.slice(7), JWT_SECRET, {
        algorithms: ['HS256'], issuer: 'owasp-api-extended', audience: 'owasp-api-extended-clients',
      });
      req.user = db.prepare('SELECT * FROM users WHERE id = ?').get(decoded.userId);
    } catch { /* ignore invalid token for optional auth */ }
  }
  next();
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

function requireSession(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Session authentication required' });
  req.sessionUser = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  next();
}

function issueJwt(user) {
  return jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '24h', issuer: 'owasp-api-extended', audience: 'owasp-api-extended-clients' },
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Core: auth, users, orders, admin  (ported/hardened from the original repo)
// ═══════════════════════════════════════════════════════════════════════

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body ?? {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (user && verifyPassword(password ?? '', user.password_hash)) {
    failedLogins.reset(email);
    return res.json({ token: issueJwt(user) });
  }

  if (failedLogins.get(email) >= 5) {
    return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
  }
  failedLogins.increment(email);
  res.status(401).json({ error: 'Invalid credentials' });
});

// Legacy in-memory "NoSQL style" login — demonstrates CWE-943 in isolation
// from the real SQL-backed login above (see lib/nosql-match.js).
app.post('/api/auth/login-legacy', (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== 'string') return res.status(400).json({ error: 'email must be a string' });
  const snapshot = db.prepare('SELECT id, email, role, password_hash FROM users').all();
  const match = snapshot.find(u => matchesSecure(u, { email, _passwordProbe: password }) && verifyPassword(password ?? '', u.password_hash));
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: issueJwt(match) });
});

// Registration — also used by tests to create disposable users for
// destructive BOLA checks without touching the shared seed accounts.
// CWE-521: minimum password strength is enforced (TC-S08).
function isStrongPassword(pw) {
  return typeof pw === 'string' && pw.length >= 8 && /[a-zA-Z]/.test(pw) && /[0-9]/.test(pw);
}
app.post('/api/auth/register', (req, res) => {
  const { email, password, name } = req.body ?? {};
  if (!email || !name) return res.status(400).json({ error: 'email and name required' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) {
    return res.status(409).json({ error: 'Email already registered' });
  }
  if (!isStrongPassword(password)) {
    return res.status(400).json({ error: 'Password must be at least 8 characters and include a letter and a number' });
  }
  const id = db.prepare('SELECT COALESCE(MAX(id), 0) + 1 AS nextId FROM users').get().nextId;
  db.prepare(`
    INSERT INTO users (id, email, password_hash, name, role, credits, verified, referral_code)
    VALUES (?, ?, ?, ?, 'user', 0, 0, ?)
  `).run(id, email, hashPassword(password), name, `REF_${id}_${crypto.randomBytes(3).toString('hex')}`);
  res.status(201).json({ id, email, token: issueJwt({ id, email, role: 'user' }) });
});

app.get('/api/users/me', meLimiter, requireAuth, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json(sanitize(req.user));
});

app.put('/api/users/me', requireAuth, (req, res) => {
  const { name, phone } = req.body ?? {};
  db.prepare('UPDATE users SET name = COALESCE(?, name), phone = COALESCE(?, phone) WHERE id = ?')
    .run(name, phone, req.user.id);
  res.json(sanitize(db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)));
});

app.patch('/api/users/me', requireAuth, (req, res) => {
  const { name, phone } = req.body ?? {};
  db.prepare('UPDATE users SET name = COALESCE(?, name), phone = COALESCE(?, phone) WHERE id = ?')
    .run(name, phone, req.user.id);
  res.json(sanitize(db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)));
});

// Prototype-pollution-focused endpoint (CWE-1321): secure version uses an
// explicit allow-list instead of a generic object merge.
const PROFILE_ALLOWED_FIELDS = ['name', 'phone'];
app.patch('/api/users/me/profile', requireAuth, (req, res) => {
  const patch = {};
  for (const key of PROFILE_ALLOWED_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(req.body ?? {}, key)) patch[key] = req.body[key];
  }
  if (patch.name !== undefined || patch.phone !== undefined) {
    db.prepare('UPDATE users SET name = COALESCE(?, name), phone = COALESCE(?, phone) WHERE id = ?')
      .run(patch.name, patch.phone, req.user.id);
  }
  res.json({ ok: true, polluted: ({}).polluted === true });
});

// API2 Scenario #2: changing email/password requires the CURRENT password.
app.put('/api/users/me/email', requireAuth, (req, res) => {
  const { newEmail, currentPassword } = req.body ?? {};
  if (!newEmail) return res.status(400).json({ error: 'newEmail required' });
  if (!verifyPassword(currentPassword ?? '', req.user.password_hash)) {
    return res.status(401).json({ error: 'Current password confirmation required' });
  }
  db.prepare('UPDATE users SET email = ? WHERE id = ?').run(newEmail, req.user.id);
  res.json({ ok: true, email: newEmail });
});

app.post('/api/users/me/security-question', requireAuth, (req, res) => {
  const { question, answer } = req.body ?? {};
  if (!question || !answer) return res.status(400).json({ error: 'question and answer required' });
  db.prepare('UPDATE users SET security_question = ?, security_answer = ? WHERE id = ?')
    .run(question, answer, req.user.id);
  res.json({ ok: true });
});

// CWE-307/640 — guessing the (often weak/predictable) security-question
// answer is itself rate-limited, same as password brute force (TC-S09).
const securityAnswerAttempts = new SlidingWindowCounter(15_000);
app.post('/api/auth/security-answer/attempt', (req, res) => {
  const { email, answer } = req.body ?? {};
  if (securityAnswerAttempts.get(email) >= 5) {
    return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  }
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (user && user.security_answer === answer) {
    securityAnswerAttempts.reset(email);
    return res.json({ ok: true, recoveryToken: crypto.randomBytes(16).toString('hex') });
  }
  securityAnswerAttempts.increment(email);
  res.status(401).json({ ok: false });
});

app.get('/api/users', requireAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);
  const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
  const rows = db.prepare('SELECT * FROM users LIMIT ? OFFSET ?').all(limit, (page - 1) * limit);
  const total = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  res.json({ data: rows.map(sanitize), total, page, limit });
});

app.get('/api/users/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!target) return res.status(404).json({ error: 'Not found' });
  if (req.user.role !== 'admin' && req.user.id !== id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(sanitize(target));
});

app.put('/api/users/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (req.user.role !== 'admin' && req.user.id !== id) return res.status(403).json({ error: 'Forbidden' });
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!target) return res.status(404).json({ error: 'Not found' });
  const { name, phone } = req.body ?? {};
  db.prepare('UPDATE users SET name = COALESCE(?, name), phone = COALESCE(?, phone) WHERE id = ?').run(name, phone, id);
  res.json(sanitize(db.prepare('SELECT * FROM users WHERE id = ?').get(id)));
});

app.delete('/api/users/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (req.user.role !== 'admin' && req.user.id !== id) return res.status(403).json({ error: 'Forbidden' });
  const info = db.prepare('DELETE FROM users WHERE id = ?').run(id);
  if (info.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.sendStatus(204);
});

app.get('/api/orders', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM orders WHERE user_id = ?').all(req.user.id));
});

app.get('/api/orders/:id', requireAuth, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  if (req.user.role !== 'admin' && order.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  res.json(order);
});

app.post('/api/orders', requireAuth, (req, res) => {
  const { productId, quantity } = req.body ?? {};
  if (!quantity || quantity < 1) return res.status(400).json({ error: 'Invalid quantity' });

  // Atomic stock check-and-decrement inside an IMMEDIATE transaction — the
  // real fix for the stock-overselling race condition (CWE-362, TC-B17).
  const purchase = db.transaction(() => {
    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(productId);
    if (!product) throw Object.assign(new Error('Product not found'), { status: 404 });
    if (product.stock < quantity) throw Object.assign(new Error('Insufficient stock'), { status: 409 });
    db.prepare('UPDATE products SET stock = stock - ? WHERE id = ?').run(quantity, productId);
    const id = `order-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    db.prepare('INSERT INTO orders (id, user_id, product_id, quantity, status, created_at) VALUES (?,?,?,?,?,?)')
      .run(id, req.user.id, productId, quantity, 'created', new Date().toISOString());
    return { id, userId: req.user.id, productId, quantity, status: 'created' };
  });
  db.pragma('busy_timeout = 2000');

  try {
    const order = purchase.immediate();
    res.status(201).json(order);
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

// Two-step workflow — secure version enforces the state machine
// (CWE-841, TC-B06): you cannot confirm an order that was never reserved.
app.post('/api/orders/:id/reserve', requireAuth, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order || order.user_id !== req.user.id) return res.status(404).json({ error: 'Not found' });
  db.prepare("UPDATE orders SET status = 'reserved' WHERE id = ?").run(order.id);
  res.json({ ...order, status: 'reserved' });
});

app.post('/api/orders/:id/confirm', requireAuth, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order || order.user_id !== req.user.id) return res.status(404).json({ error: 'Not found' });
  if (order.status !== 'reserved') {
    return res.status(409).json({ error: `Cannot confirm an order in status "${order.status}" — it must be reserved first` });
  }
  db.prepare("UPDATE orders SET status = 'confirmed' WHERE id = ?").run(order.id);
  res.json({ ...order, status: 'confirmed' });
});

app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM users').all().map(sanitize));
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, (req, res) => {
  const info = db.prepare('DELETE FROM users WHERE id = ?').run(parseInt(req.params.id, 10));
  if (info.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.sendStatus(204);
});

app.all('/api/admin/config', requireAuth, requireAdmin, (req, res) => {
  if (!['GET', 'HEAD'].includes(req.method)) return res.status(405).json({ error: 'Method not allowed' });
  res.json({ config: 'admin-only-settings' });
});

app.post('/api/referrals/apply', requireAuth, (req, res) => {
  const { code } = req.body ?? {};
  if (!code) return res.status(400).json({ error: 'Referral code required' });
  if (req.user.referral_code === code) return res.status(400).json({ error: 'Cannot use your own referral code' });
  const referrer = db.prepare('SELECT * FROM users WHERE referral_code = ?').get(code);
  if (!referrer) return res.status(404).json({ error: 'Invalid referral code' });
  res.json({ message: 'Referral applied' });
});

// Coupon redemption — atomic, max_uses-bounded (CWE-362 double-spend, TC-B16).
app.post('/api/coupons/:code/redeem', requireAuth, (req, res) => {
  const redeem = db.transaction((code, userId) => {
    const coupon = db.prepare('SELECT * FROM coupons WHERE code = ?').get(code);
    if (!coupon) throw Object.assign(new Error('Invalid coupon'), { status: 404 });
    if (coupon.used_count >= coupon.max_uses) throw Object.assign(new Error('Coupon has already been fully redeemed'), { status: 409 });
    db.prepare('UPDATE coupons SET used_count = used_count + 1 WHERE code = ?').run(code);
    db.prepare('INSERT INTO coupon_redemptions (code, user_id, created_at) VALUES (?,?,?)').run(code, userId, new Date().toISOString());
    return { code, discountPercent: coupon.discount_percent };
  });
  try {
    res.json(redeem.immediate(req.params.code, req.user.id));
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// Injection family
// ═══════════════════════════════════════════════════════════════════════

// CWE-89: parametric query — the `q` value is always bound, never concatenated.
app.get('/api/products/search', (req, res) => {
  const q = String(req.query.q ?? '');
  const rows = db.prepare('SELECT * FROM products WHERE name LIKE ?').all(`%${q}%`);
  res.json({ results: rows });
});

// CWE-235 HTTP Parameter Pollution: a repeated query param is rejected
// outright instead of silently picking "the last one wins".
app.get('/api/search', (req, res) => {
  const tag = req.query.tag;
  if (Array.isArray(tag)) return res.status(400).json({ error: 'Repeated "tag" parameter is not allowed' });
  const rows = tag ? db.prepare('SELECT * FROM products WHERE name LIKE ?').all(`%${tag}%`) : db.prepare('SELECT * FROM products').all();
  res.json({ results: rows, tagApplied: tag ?? null });
});

// CWE-78/77 — real shell sink, allow-listed message characters (see lib/system-exec.js).
app.post('/api/system/echo', requireAuth, async (req, res) => {
  try {
    const out = await echoSecure(req.body?.message);
    res.json({ output: out.trim() });
  } catch (e) {
    res.status(400).json({ error: e.code === 'INVALID_MESSAGE' ? e.message : 'Command failed' });
  }
});

// CWE-94 SSTI — only whitelisted variable interpolation, never eval (see lib/template-engine.js).
app.post('/api/templates/render', requireAuth, (req, res) => {
  const { template } = req.body ?? {};
  if (typeof template !== 'string') return res.status(400).json({ error: 'template must be a string' });
  res.json({ rendered: renderSecure(template, { user: { name: req.user.name }, now: new Date().toISOString() }) });
});

// CWE-79 Stored XSS — comments are HTML-escaped before storage.
function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
app.post('/api/comments', requireAuth, (req, res) => {
  const { productId, body } = req.body ?? {};
  if (!productId || !body) return res.status(400).json({ error: 'productId and body required' });
  const safe = escapeHtml(body);
  const info = db.prepare('INSERT INTO comments (product_id, user_id, body_html, created_at) VALUES (?,?,?,?)')
    .run(productId, req.user.id, safe, new Date().toISOString());
  res.status(201).json({ id: info.lastInsertRowid, productId, bodyHtml: safe });
});
app.get('/api/products/:id/comments', (req, res) => {
  res.json(db.prepare('SELECT * FROM comments WHERE product_id = ?').all(req.params.id));
});

app.get('/api/products', (_req, res) => {
  res.json(db.prepare('SELECT * FROM products').all());
});

app.post('/api/products/import', requireAuth, (req, res) => {
  const { name, source } = req.body ?? {};
  const safe = (name ?? '')
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<[^>]*>/g, '')
    .replace(/</g, '&lt;').replace(/>/g, '&gt;');
  res.status(201).json({ id: `product-${Date.now()}`, name: safe, source: source ?? 'internal' });
});

app.post('/api/data', requireAuth, (_req, res) => res.json({ received: true }));

// ═══════════════════════════════════════════════════════════════════════
// SSRF / files / resource consumption
// ═══════════════════════════════════════════════════════════════════════

app.post('/api/webhooks', requireAuth, (req, res) => {
  const { url } = req.body ?? {};
  if (isInternalUrl(url, { normalizeObfuscation: true })) {
    return res.status(400).json({ error: 'URL not allowed: internal/private addresses are blocked' });
  }
  db.prepare('INSERT INTO webhooks (user_id, url) VALUES (?,?)').run(req.user.id, url);
  res.json({ message: 'Webhook registered', url });
});

// Real outbound fetch — never follows redirects, decodes IP obfuscation before validating (CWE-918, TC-S01/S02).
app.post('/api/webhooks/fetch', requireAuth, async (req, res) => {
  const { url } = req.body ?? {};
  if (isInternalUrl(url, { normalizeObfuscation: true })) {
    return res.status(400).json({ error: 'URL not allowed: internal/private/obfuscated addresses are blocked' });
  }
  try {
    const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(3000) });
    const text = await response.text().catch(() => '');
    res.json({ status: response.status, followedRedirect: false, bodyPreview: text.slice(0, 200) });
  } catch (e) {
    res.status(502).json({ error: `Fetch failed: ${e.message}` });
  }
});

const INTEGRATION_ALLOWLIST = ['example.com', 'hooks.trusted.com', 'api.example.com', 'webhook.site'];
app.post('/api/integrations/webhook', requireAuth, (req, res) => {
  const { callbackUrl } = req.body ?? {};
  if (!callbackUrl) return res.status(400).json({ error: 'callbackUrl required' });
  if (isInternalUrl(callbackUrl, { normalizeObfuscation: true })) return res.status(400).json({ error: 'URL not allowed' });
  let parsedUrl;
  try { parsedUrl = new URL(callbackUrl); } catch { return res.status(400).json({ error: 'Invalid URL' }); }
  const host = parsedUrl.hostname.toLowerCase();
  const allowed = INTEGRATION_ALLOWLIST.some(d => host === d || host.endsWith(`.${d}`));
  if (!allowed) return res.status(403).json({ error: 'Domain not in allowlist' });
  res.json({ message: 'Webhook integration configured' });
});

app.get('/api/auth/callback', (req, res) => {
  const { redirect } = req.query;
  if (!redirect) return res.status(200).json({ message: 'ok' });
  try {
    const url = new URL(redirect);
    if (!['localhost', '127.0.0.1'].includes(url.hostname)) {
      return res.status(400).json({ error: 'Invalid redirect: external URLs not allowed' });
    }
    return res.redirect(redirect);
  } catch {
    return res.redirect(String(redirect));
  }
});

// "Denial of Wallet" simulation — NO real SMS is ever sent; a per-user
// sliding-window counter stands in for a paid third-party provider's bill
// (CWE-770/400, API4 Scenario #1).
const SMS_COST_CENTS = 7;
const SMS_SECURE_MAX_PER_MINUTE = 3;
app.post('/api/notifications/sms', requireAuth, (req, res) => {
  const key = `user:${req.user.id}`;
  if (smsBudget.get(key) >= SMS_SECURE_MAX_PER_MINUTE) {
    return res.status(429).json({ error: 'SMS rate limit exceeded for this account' });
  }
  const count = smsBudget.increment(key);
  res.json({ simulated: true, phoneNumber: req.body?.phoneNumber, simulatedCostCents: SMS_COST_CENTS, totalSimulatedCostCents: count * SMS_COST_CENTS });
});

// Generic file upload → DB-tracked, BOLA-protected download.
app.post('/api/files/upload', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'file required' });
  const diskName = crypto.randomUUID(); // only used to avoid on-disk filename collisions
  const storedPath = path.join(__dirname, 'uploads', `${PORT}-${diskName}`);
  fs.writeFileSync(storedPath, req.file.buffer);
  const info = db.prepare('INSERT INTO files (owner_id, filename, stored_path, uploaded_at) VALUES (?,?,?,?)')
    .run(req.user.id, req.file.originalname, storedPath, new Date().toISOString());
  res.status(201).json({ id: info.lastInsertRowid, filename: req.file.originalname });
});

app.get('/api/files/:id/download', requireAuth, (req, res) => {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!file) return res.status(404).json({ error: 'Not found' });
  if (file.owner_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  res.sendFile(file.stored_path);
});

// CWE-22 Path Traversal — the requested name is resolved and MUST stay
// inside PUBLIC_DOWNLOADS_DIR (TC-A12).
const PUBLIC_DOWNLOADS_DIR = path.join(__dirname, 'public-downloads');
app.get('/api/files/by-name/:name', (req, res) => {
  const target = path.normalize(path.join(PUBLIC_DOWNLOADS_DIR, req.params.name));
  if (!target.startsWith(PUBLIC_DOWNLOADS_DIR + path.sep) && target !== PUBLIC_DOWNLOADS_DIR) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  if (!fs.existsSync(target)) return res.status(404).json({ error: 'Not found' });
  res.type('text/plain').send(fs.readFileSync(target, 'utf8'));
});

// CWE-611/776 XXE & entity-expansion — external entities disabled, tight limits.
const XML_FIXTURES_DIR = path.join(__dirname, 'fixtures');
app.post('/api/files/upload-xml', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'file required' });
  try {
    const expanded = resolveXmlEntities(req.file.buffer.toString('utf8'), {
      allowExternalEntities: false,
      maxExpandedLength: 100_000,
      maxEntityDepth: 8,
      baseDir: XML_FIXTURES_DIR,
    });
    res.json({ name: extractTag(expanded, 'name') ?? null });
  } catch (e) {
    if (e instanceof XmlPolicyError) return res.status(400).json({ error: e.message, code: e.code });
    res.status(400).json({ error: 'Invalid XML' });
  }
});

// CWE-409 zip-bomb — decompressed size is capped (TC-S07).
const ZIP_SECURE_MAX_DECOMPRESSED_BYTES = 1 * 1024 * 1024; // 1 MB
app.post('/api/files/upload-archive', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'file required' });
  try {
    const zip = await JSZip.loadAsync(req.file.buffer);
    let totalBytes = 0;
    const names = [];
    for (const [name, entry] of Object.entries(zip.files)) {
      if (entry.dir) continue;
      // eslint-disable-next-line no-await-in-loop
      const buf = await entry.async('nodebuffer');
      totalBytes += buf.length;
      names.push(name);
      if (totalBytes > ZIP_SECURE_MAX_DECOMPRESSED_BYTES) {
        return res.status(413).json({ error: `Decompressed archive exceeds ${ZIP_SECURE_MAX_DECOMPRESSED_BYTES} bytes` });
      }
    }
    res.json({ files: names, totalDecompressedBytes: totalBytes });
  } catch {
    res.status(400).json({ error: 'Invalid archive' });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// GraphQL (BOLA/introspection/batching — CWE-285,639,799)
// ═══════════════════════════════════════════════════════════════════════

const GRAPHQL_SECURE_MAX_BATCH = 5;
app.post('/graphql', optionalAuth, (req, res, next) => {
  const body = req.body;
  const opCount = Array.isArray(body) ? body.length : 1;
  const key = req.user ? `user:${req.user.id}` : `ip:${req.ip}`;
  if (graphqlOps.increment(key, opCount) > 30) {
    return res.status(429).json({ errors: [{ message: 'GraphQL operation rate limit exceeded' }] });
  }
  next();
}, createGraphQLHandler(db, { allowIntrospection: false, allowBolaBypass: false, maxBatchSize: GRAPHQL_SECURE_MAX_BATCH }));

// ═══════════════════════════════════════════════════════════════════════
// OAuth2 (redirect_uri / scope — CWE-601,285, TC-A16/A17)
// ═══════════════════════════════════════════════════════════════════════

const OAUTH_POLICY = { strictRedirectMatch: true, enforceScopeAllowlist: true, verifyRedirectUriOnExchange: true, lockScopeToAuthorization: true };

app.get('/oauth/authorize', requireAuth, (req, res) => {
  const { client_id: clientId, redirect_uri: redirectUri, scope, state } = req.query;
  try {
    const code = authorize(db, { clientId, redirectUri, scope, userId: req.user.id }, OAUTH_POLICY);
    const url = new URL(redirectUri);
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state);
    res.redirect(url.toString());
  } catch (e) {
    res.status(e instanceof OAuthError ? e.status : 400).json({ error: e.message });
  }
});

app.post('/oauth/token', (req, res) => {
  const { code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, scope } = req.body ?? {};
  try {
    const token = exchangeToken(db, { code, clientId, clientSecret, redirectUri, requestedScope: scope }, OAUTH_POLICY, JWT_SECRET);
    res.json(token);
  } catch (e) {
    res.status(e instanceof OAuthError ? e.status : 400).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// Cookie/session family (CSRF, session fixation/hijacking — CWE-352,384,613,1275)
// ═══════════════════════════════════════════════════════════════════════

// Harmless pre-auth endpoint that forces a session cookie to be issued so
// tests can capture a "before login" session ID for the fixation test (TC-S14).
app.get('/api/session/touch', (req, res) => {
  req.session.touchedAt = Date.now();
  res.json({ ok: true });
});

app.post('/api/session/login', (req, res) => {
  const { email, password } = req.body ?? {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !verifyPassword(password ?? '', user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  // CWE-384 Session Fixation fix: regenerate the session ID on privilege change.
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.userId = user.id;
    req.session.csrfToken = crypto.randomBytes(16).toString('hex');
    res.json({ ok: true, csrfToken: req.session.csrfToken });
  });
});

app.post('/api/session/logout', requireSession, (req, res) => {
  // CWE-613: destroy server-side session state, not just the cookie.
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

app.get('/api/session/csrf-token', requireSession, (req, res) => {
  res.json({ csrfToken: req.session.csrfToken });
});

app.post('/api/session/change-email', requireSession, (req, res) => {
  const token = req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({ error: 'Missing or invalid CSRF token' });
  }
  const { newEmail } = req.body ?? {};
  if (!newEmail) return res.status(400).json({ error: 'newEmail required' });
  db.prepare('UPDATE users SET email = ? WHERE id = ?').run(newEmail, req.sessionUser.id);
  res.json({ ok: true, email: newEmail });
});

// ═══════════════════════════════════════════════════════════════════════
// Misconfiguration / inventory
// ═══════════════════════════════════════════════════════════════════════

app.get('/api/health', (_req, res) => res.json({ status: 'ok', version: '2.0.0' }));

app.all(/^\/api\/v1(\/.*)?$/, (_req, res) => res.status(410).json({ error: 'API v1 is deprecated. Please use the current API.' }));
app.all(/^\/api\/(internal|v0|beta)(\/.*)?$/, (_req, res) => res.status(404).end());
app.all(/^\/(swagger|swagger-ui|api-docs|graphql-playground|__debug|actuator|metrics)(\/.*)?$/, (_req, res) => res.status(404).end());

// ─── Error handler — no stack traces ──────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (err?.type === 'entity.too.large' || err?.status === 413) {
    return res.status(413).json({ error: 'Payload too large' });
  }
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: 'Upload error' });
  }
  console.error('[server]', err?.message);
  res.status(err?.status || 500).json({ error: 'Internal server error' });
});

app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Secure API server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
