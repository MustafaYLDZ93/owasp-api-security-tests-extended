'use strict';

/**
 * VULNERABLE API server — intentionally insecure mirror of server.js.
 * Every route exists on both servers with the identical shape; only the
 * control logic differs. Used to prove the test suite actually detects
 * each planted vulnerability (expected result against this server: most
 * tests in the extended suite FAIL). See DESIGN.md for the full map.
 *
 * DO NOT deploy this anywhere reachable — it is a test fixture only.
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const multer = require('multer');
const JSZip = require('jszip');

const { createDb } = require('./db/init');
const { verifyPassword, hashPassword } = require('./lib/hash');
const { matchesVulnerable } = require('./lib/nosql-match');
const { echoVulnerable } = require('./lib/system-exec');
const { renderVulnerable } = require('./lib/template-engine');
const { resolveXmlEntities, extractTag, XmlPolicyError } = require('./lib/xml-resolver');
const { isInternalUrl } = require('./lib/ssrf-guard');
const { createGraphQLHandler } = require('./lib/graphql-schema');
const { authorize, exchangeToken, OAuthError } = require('./lib/oauth');
const { SlidingWindowCounter } = require('./lib/rate-window');

const app = express();
const PORT = process.env.PORT || 3001;
// VULNERABILITY: hardcoded, predictable signing secret (CWE-798/326) —
// ignored on purpose even if a strong JWT_SECRET env var is set.
const JWT_SECRET = 'weak-secret-123';

const db = createDb(path.join(__dirname, 'db', `data-${PORT}.sqlite`));

// VULNERABILITY: no meaningful body size limit (TC-CONS-01 analogue FAILS).
// NOT: express.json()'ın kendi dahili varsayılanı zaten ~100kb'dir — bunu
// gerçekten "sınırsız" göstermek için yüksek bir limit açıkça belirtilir,
// yoksa Express'in kendi varsayılanı yanlışlıkla bir "güvenlik kontrolü"
// gibi görünüp testi anlamsızlaştırır.
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
app.use(session({
  secret: 'weak-session-secret',
  resave: false,
  saveUninitialized: false,
  // VULNERABILITY: no httpOnly/secure hardening, loose SameSite (CWE-1275/614).
  cookie: { httpOnly: false, secure: false, sameSite: 'none', maxAge: 30 * 60 * 1000 },
}));

// VULNERABILITY: no security headers at all (X-Frame-Options, HSTS, nosniff missing).
// VULNERABILITY: CORS wildcard, even with credentials implied (CWE-942).
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-CSRF-Token');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.static(path.join(__dirname, '..', 'public', 'vulnerable')));
// VULNERABILITY: directory listing of the uploads folder is reachable (no index, static serving only — see README for the serve-index note).

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

const smsBudget = new SlidingWindowCounter(60_000);

// ─── Helpers ──────────────────────────────────────────────────────────────

// VULNERABILITY: decode-only, no signature/algorithm/exp/iss/aud verification
// (CWE-347/287) — alg:none and expired/foreign tokens are all accepted.
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Authentication required' });
  const decoded = jwt.decode(header.slice(7));
  if (!decoded) return res.status(401).json({ error: 'Bad token' });
  req.user = db.prepare('SELECT * FROM users WHERE id = ?').get(decoded.userId)
    || { id: decoded.userId, role: decoded.role ?? 'user' };
  next();
}

function optionalAuth(req, _res, next) {
  const header = req.headers.authorization;
  if (header?.startsWith('Bearer ')) {
    const decoded = jwt.decode(header.slice(7));
    if (decoded) req.user = db.prepare('SELECT * FROM users WHERE id = ?').get(decoded.userId);
  }
  next();
}

function requireSession(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Session authentication required' });
  req.sessionUser = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  next();
}

function issueJwt(user) {
  return jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '24h' });
}

const WRITABLE_USER_COLUMNS = ['name', 'phone', 'email', 'role', 'credits', 'verified', 'referral_code'];

/** better-sqlite3 only binds numbers/strings/bigints/buffers/null — coerce booleans so the
 *  mass-assignment vulnerability below actually persists instead of throwing a bind error. */
function sqliteBindable(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[k] = typeof v === 'boolean' ? (v ? 1 : 0) : v;
  return out;
}

/** VULNERABILITY: naive recursive merge — enables Object.prototype pollution (CWE-1321). */
function vulnerableDeepMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      if (!target[key] || typeof target[key] !== 'object') target[key] = {};
      vulnerableDeepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// ═══════════════════════════════════════════════════════════════════════
// Core: auth, users, orders, admin
// ═══════════════════════════════════════════════════════════════════════

// VULNERABILITY: no brute-force lockout (CWE-307).
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body ?? {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !verifyPassword(password ?? '', user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({ token: issueJwt(user) });
});

// VULNERABILITY: CWE-943 operator injection on an in-memory snapshot.
app.post('/api/auth/login-legacy', (req, res) => {
  const { email, password } = req.body ?? {};
  const snapshot = db.prepare('SELECT id, email, role, password_hash FROM users').all();
  const match = snapshot.find(u => matchesVulnerable(u, { email }));
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });
  // BUG: password is not actually re-verified once the (possibly operator-injected) email filter matches.
  res.json({ token: issueJwt(match) });
});

// VULNERABILITY: no password strength requirement at all (CWE-521, TC-S08).
app.post('/api/auth/register', (req, res) => {
  const { email, password, name } = req.body ?? {};
  if (!email || !name) return res.status(400).json({ error: 'email and name required' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) {
    return res.status(409).json({ error: 'Email already registered' });
  }
  const id = db.prepare('SELECT COALESCE(MAX(id), 0) + 1 AS nextId FROM users').get().nextId;
  db.prepare(`
    INSERT INTO users (id, email, password_hash, name, role, credits, verified, referral_code)
    VALUES (?, ?, ?, ?, 'user', 0, 0, ?)
  `).run(id, email, hashPassword(password ?? ''), name, `REF_${id}_${crypto.randomBytes(3).toString('hex')}`);
  res.status(201).json({ id, email, token: issueJwt({ id, email, role: 'user' }) });
});

// VULNERABILITY: returns the FULL row including password_hash/security_answer (CWE-200, BOPLA).
app.get('/api/users/me', requireAuth, (req, res) => {
  res.json(req.user);
});

app.put('/api/users/me', requireAuth, (req, res) => {
  const cols = Object.keys(req.body ?? {}).filter(k => WRITABLE_USER_COLUMNS.includes(k));
  if (cols.length) {
    // VULNERABILITY: mass assignment — role/credits/verified/email are all writable (CWE-915).
    const setClause = cols.map(c => `${c} = @${c}`).join(', ');
    db.prepare(`UPDATE users SET ${setClause} WHERE id = @id`).run({ ...sqliteBindable(req.body), id: req.user.id });
  }
  res.json(db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id));
});

app.patch('/api/users/me', requireAuth, (req, res) => {
  const cols = Object.keys(req.body ?? {}).filter(k => WRITABLE_USER_COLUMNS.includes(k));
  if (cols.length) {
    const setClause = cols.map(c => `${c} = @${c}`).join(', ');
    db.prepare(`UPDATE users SET ${setClause} WHERE id = @id`).run({ ...sqliteBindable(req.body), id: req.user.id });
  }
  res.json(db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id));
});

app.patch('/api/users/me/profile', requireAuth, (req, res) => {
  const profile = {};
  vulnerableDeepMerge(profile, req.body ?? {});
  if (profile.name !== undefined || profile.phone !== undefined) {
    db.prepare('UPDATE users SET name = COALESCE(?, name), phone = COALESCE(?, phone) WHERE id = ?')
      .run(profile.name, profile.phone, req.user.id);
  }
  res.json({ ok: true, polluted: ({}).polluted === true });
});

// VULNERABILITY: no current-password confirmation (API2 Scenario #2).
app.put('/api/users/me/email', requireAuth, (req, res) => {
  const { newEmail } = req.body ?? {};
  if (!newEmail) return res.status(400).json({ error: 'newEmail required' });
  db.prepare('UPDATE users SET email = ? WHERE id = ?').run(newEmail, req.user.id);
  res.json({ ok: true, email: newEmail });
});

app.post('/api/users/me/security-question', requireAuth, (req, res) => {
  const { question, answer } = req.body ?? {};
  if (!question || !answer) return res.status(400).json({ error: 'question and answer required' });
  db.prepare('UPDATE users SET security_question = ?, security_answer = ? WHERE id = ?').run(question, answer, req.user.id);
  res.json({ ok: true });
});

// VULNERABILITY: no rate limit on security-answer guessing — combined with
// the predictable seed answers ("blue"/"green"/"red") this is brute-forceable (CWE-307/640).
app.post('/api/auth/security-answer/attempt', (req, res) => {
  const { email, answer } = req.body ?? {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (user && user.security_answer === answer) {
    return res.json({ ok: true, recoveryToken: crypto.randomBytes(16).toString('hex') });
  }
  res.status(401).json({ ok: false });
});

// VULNERABILITY: no max page-size cap (CWE-770).
app.get('/api/users', requireAuth, (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 20;
  const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
  const rows = db.prepare('SELECT * FROM users LIMIT ? OFFSET ?').all(limit, (page - 1) * limit);
  const total = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  res.json({ data: rows, total, page, limit });
});

// VULNERABILITY: no object-level ownership check (CWE-639/862, BOLA).
app.get('/api/users/:id', requireAuth, (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(parseInt(req.params.id, 10));
  if (!target) return res.status(404).json({ error: 'Not found' });
  res.json(target);
});

app.put('/api/users/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!target) return res.status(404).json({ error: 'Not found' });
  const { name, phone } = req.body ?? {};
  db.prepare('UPDATE users SET name = COALESCE(?, name), phone = COALESCE(?, phone) WHERE id = ?').run(name, phone, id);
  res.json(db.prepare('SELECT * FROM users WHERE id = ?').get(id));
});

app.delete('/api/users/:id', requireAuth, (req, res) => {
  const info = db.prepare('DELETE FROM users WHERE id = ?').run(parseInt(req.params.id, 10));
  if (info.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.sendStatus(204);
});

app.get('/api/orders', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM orders WHERE user_id = ?').all(req.user.id));
});

// VULNERABILITY: no ownership check on order lookup.
app.get('/api/orders/:id', requireAuth, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order);
});

// VULNERABILITY: no negative-quantity validation + genuine TOCTOU race
// condition via an artificial async gap between the stock check and the
// stock write (CWE-362/20, TC-B17 / TC-FLOW-01, TC-FLOW-03).
app.post('/api/orders', requireAuth, (req, res) => {
  const { productId, quantity } = req.body ?? {};
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(productId);
  if (!product) return res.status(404).json({ error: 'Product not found' });
  setTimeout(() => {
    const fresh = db.prepare('SELECT * FROM products WHERE id = ?').get(productId); // re-read, stale by design
    db.prepare('UPDATE products SET stock = ? WHERE id = ?').run(fresh.stock - (quantity ?? 1), productId);
    const id = `order-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    db.prepare('INSERT INTO orders (id, user_id, product_id, quantity, status, created_at) VALUES (?,?,?,?,?,?)')
      .run(id, req.user.id, productId, quantity ?? 1, 'created', new Date().toISOString());
    res.status(201).json({ id, userId: req.user.id, productId, quantity, status: 'created' });
  }, 25); // geniş bir pencere: yoğun eşzamanlı test yükünde bile yarışı güvenilir şekilde ortaya çıkarır
});

app.post('/api/orders/:id/reserve', requireAuth, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  db.prepare("UPDATE orders SET status = 'reserved' WHERE id = ?").run(order.id);
  res.json({ ...order, status: 'reserved' });
});

// VULNERABILITY: workflow step can be skipped — confirms regardless of
// current status (CWE-841, TC-B06).
app.post('/api/orders/:id/confirm', requireAuth, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  db.prepare("UPDATE orders SET status = 'confirmed' WHERE id = ?").run(order.id);
  res.json({ ...order, status: 'confirmed' });
});

// VULNERABILITY: no admin check on any admin-only endpoint (BFLA).
app.get('/api/admin/users', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM users').all());
});
app.delete('/api/admin/users/:id', requireAuth, (req, res) => {
  const info = db.prepare('DELETE FROM users WHERE id = ?').run(parseInt(req.params.id, 10));
  if (info.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.sendStatus(204);
});
app.all('/api/admin/config', requireAuth, (_req, res) => {
  res.json({ config: 'all-settings-exposed' });
});

// VULNERABILITY: self-referral allowed.
app.post('/api/referrals/apply', requireAuth, (req, res) => {
  const { code } = req.body ?? {};
  const referrer = db.prepare('SELECT * FROM users WHERE referral_code = ?').get(code);
  if (!referrer) return res.status(404).json({ error: 'Invalid referral code' });
  res.json({ message: 'Referral applied' });
});

// VULNERABILITY: TOCTOU race on coupon redemption — the increment happens
// after an artificial async gap, so concurrent requests can all pass the
// `used_count >= max_uses` check before any of them persists (CWE-362).
app.post('/api/coupons/:code/redeem', requireAuth, (req, res) => {
  const coupon = db.prepare('SELECT * FROM coupons WHERE code = ?').get(req.params.code);
  if (!coupon) return res.status(404).json({ error: 'Invalid coupon' });
  if (coupon.used_count >= coupon.max_uses) return res.status(409).json({ error: 'Coupon has already been fully redeemed' });
  setTimeout(() => {
    db.prepare('UPDATE coupons SET used_count = used_count + 1 WHERE code = ?').run(req.params.code);
    db.prepare('INSERT INTO coupon_redemptions (code, user_id, created_at) VALUES (?,?,?)')
      .run(req.params.code, req.user.id, new Date().toISOString());
    res.json({ code: req.params.code, discountPercent: coupon.discount_percent });
  }, 25);
});

// ═══════════════════════════════════════════════════════════════════════
// Injection family
// ═══════════════════════════════════════════════════════════════════════

// VULNERABILITY: classic string-concatenated SQL query (CWE-89).
app.get('/api/products/search', (req, res) => {
  const q = String(req.query.q ?? '');
  try {
    const sql = `SELECT * FROM products WHERE name LIKE '%${q}%'`;
    res.json({ results: db.prepare(sql).all() });
  } catch (e) {
    next_(e, res); // surfaces the raw DB error — see error handler below
  }
});
function next_(e, res) { res.status(500).json({ error: e.message, stack: e.stack }); }

// VULNERABILITY: repeated query params silently resolve to "last one wins" (CWE-235).
app.get('/api/search', (req, res) => {
  const tagParam = req.query.tag;
  const tag = Array.isArray(tagParam) ? tagParam[tagParam.length - 1] : tagParam;
  const rows = tag ? db.prepare('SELECT * FROM products WHERE name LIKE ?').all(`%${tag}%`) : db.prepare('SELECT * FROM products').all();
  res.json({ results: rows, tagApplied: tag ?? null });
});

// VULNERABILITY: real shell command injection (CWE-78/77).
app.post('/api/system/echo', requireAuth, async (req, res) => {
  try {
    const out = await echoVulnerable(req.body?.message ?? '');
    res.json({ output: out.trim() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// VULNERABILITY: real SSTI via `new Function` (CWE-94).
app.post('/api/templates/render', requireAuth, (req, res) => {
  const { template } = req.body ?? {};
  if (typeof template !== 'string') return res.status(400).json({ error: 'template must be a string' });
  res.json({ rendered: renderVulnerable(template, { user: { name: req.user.name }, now: new Date().toISOString() }) });
});

// VULNERABILITY: stored XSS — comment body is saved and echoed back raw (CWE-79).
app.post('/api/comments', requireAuth, (req, res) => {
  const { productId, body } = req.body ?? {};
  if (!productId || !body) return res.status(400).json({ error: 'productId and body required' });
  const info = db.prepare('INSERT INTO comments (product_id, user_id, body_html, created_at) VALUES (?,?,?,?)')
    .run(productId, req.user.id, body, new Date().toISOString());
  res.status(201).json({ id: info.lastInsertRowid, productId, bodyHtml: body });
});
app.get('/api/products/:id/comments', (req, res) => {
  res.json(db.prepare('SELECT * FROM comments WHERE product_id = ?').all(req.params.id));
});

app.get('/api/products', (_req, res) => res.json(db.prepare('SELECT * FROM products').all()));

app.post('/api/products/import', requireAuth, (req, res) => {
  const { name, source } = req.body ?? {};
  res.status(201).json({ id: `product-${Date.now()}`, name, source }); // BUG: raw payload stored
});

app.post('/api/data', requireAuth, (_req, res) => res.json({ received: true }));

// ═══════════════════════════════════════════════════════════════════════
// SSRF / files / resource consumption
// ═══════════════════════════════════════════════════════════════════════

// VULNERABILITY: no URL validation whatsoever (CWE-918).
app.post('/api/webhooks', requireAuth, (req, res) => {
  const { url } = req.body ?? {};
  db.prepare('INSERT INTO webhooks (user_id, url) VALUES (?,?)').run(req.user.id, url ?? '');
  res.json({ message: 'Webhook registered', url });
});

// VULNERABILITY: real outbound fetch, no validation, blindly follows redirects (CWE-918).
app.post('/api/webhooks/fetch', requireAuth, async (req, res) => {
  const { url } = req.body ?? {};
  try {
    let current = url;
    let response;
    for (let hop = 0; hop < 5; hop++) {
      // eslint-disable-next-line no-await-in-loop
      response = await fetch(current, { redirect: 'manual', signal: AbortSignal.timeout(3000) });
      const location = response.headers.get('location');
      if (response.status >= 300 && response.status < 400 && location) {
        current = new URL(location, current).toString(); // BUG: never re-validated
        continue;
      }
      break;
    }
    const text = await response.text().catch(() => '');
    res.json({ status: response.status, finalUrl: current, bodyPreview: text.slice(0, 200) });
  } catch (e) {
    res.status(502).json({ error: `Fetch failed: ${e.message}` });
  }
});

app.post('/api/integrations/webhook', requireAuth, (req, res) => {
  const { callbackUrl } = req.body ?? {};
  res.json({ message: 'Integration configured', callbackUrl }); // BUG: no allowlist
});

app.get('/api/auth/callback', (req, res) => {
  const { redirect } = req.query;
  if (redirect) return res.redirect(String(redirect)); // BUG: no validation
  res.status(200).json({ message: 'ok' });
});

// VULNERABILITY: no budget cap — simulated third-party SMS spend grows unbounded ("Denial of Wallet").
const SMS_COST_CENTS = 7;
app.post('/api/notifications/sms', requireAuth, (req, res) => {
  const count = smsBudget.increment(`user:${req.user.id}`);
  res.json({ simulated: true, phoneNumber: req.body?.phoneNumber, simulatedCostCents: SMS_COST_CENTS, totalSimulatedCostCents: count * SMS_COST_CENTS });
});

app.post('/api/files/upload', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'file required' });
  const diskName = crypto.randomUUID();
  const storedPath = path.join(__dirname, 'uploads', `${PORT}-${diskName}`);
  fs.writeFileSync(storedPath, req.file.buffer);
  const info = db.prepare('INSERT INTO files (owner_id, filename, stored_path, uploaded_at) VALUES (?,?,?,?)')
    .run(req.user.id, req.file.originalname, storedPath, new Date().toISOString());
  res.status(201).json({ id: info.lastInsertRowid, filename: req.file.originalname });
});

// VULNERABILITY: no ownership check — any authenticated user can download any file (BOLA on files).
app.get('/api/files/:id/download', requireAuth, (req, res) => {
  const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!file) return res.status(404).json({ error: 'Not found' });
  res.sendFile(file.stored_path);
});

// VULNERABILITY: CWE-22 Path Traversal — the name is joined without any
// containment check, so `../../fixtures/secret.txt` escapes the intended directory.
const PUBLIC_DOWNLOADS_DIR = path.join(__dirname, 'public-downloads');
app.get('/api/files/by-name/:name', (req, res) => {
  const target = path.join(PUBLIC_DOWNLOADS_DIR, req.params.name);
  if (!fs.existsSync(target)) return res.status(404).json({ error: 'Not found' });
  res.type('text/plain').send(fs.readFileSync(target, 'utf8'));
});

// VULNERABILITY: CWE-611/776 — external entities and unlimited expansion allowed.
const XML_FIXTURES_DIR = path.join(__dirname, 'fixtures');
app.post('/api/files/upload-xml', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'file required' });
  try {
    const expanded = resolveXmlEntities(req.file.buffer.toString('utf8'), {
      allowExternalEntities: true,
      maxExpandedLength: 50_000_000,
      maxEntityDepth: 30,
      baseDir: XML_FIXTURES_DIR,
    });
    res.json({ name: extractTag(expanded, 'name') ?? null });
  } catch (e) {
    if (e instanceof XmlPolicyError) return res.status(400).json({ error: e.message, code: e.code });
    res.status(400).json({ error: 'Invalid XML' });
  }
});

// VULNERABILITY: CWE-409 — no decompressed-size cap (bounded here only for
// this demo process's own safety, far above anything the test suite sends).
const ZIP_VULNERABLE_MAX_DECOMPRESSED_BYTES = 200 * 1024 * 1024; // 200 MB safety net
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
      if (totalBytes > ZIP_VULNERABLE_MAX_DECOMPRESSED_BYTES) break; // safety net only, not a security control
    }
    res.json({ files: names, totalDecompressedBytes: totalBytes });
  } catch {
    res.status(400).json({ error: 'Invalid archive' });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// GraphQL — introspection open, BOLA bypass, unlimited/uncounted batching
// ═══════════════════════════════════════════════════════════════════════

app.post('/graphql', optionalAuth, createGraphQLHandler(db, { allowIntrospection: true, allowBolaBypass: true, maxBatchSize: 10_000 }));

// ═══════════════════════════════════════════════════════════════════════
// OAuth2 — loose redirect_uri match, no scope allow-list, scope escalation
// ═══════════════════════════════════════════════════════════════════════

const OAUTH_POLICY = { strictRedirectMatch: false, enforceScopeAllowlist: false, verifyRedirectUriOnExchange: false, lockScopeToAuthorization: false };

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
// Cookie/session family
// ═══════════════════════════════════════════════════════════════════════

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
  // VULNERABILITY: session ID is NOT regenerated on login (CWE-384 Session Fixation).
  req.session.userId = user.id;
  req.session.csrfToken = crypto.randomBytes(16).toString('hex');
  res.json({ ok: true, csrfToken: req.session.csrfToken });
});

app.post('/api/session/logout', requireSession, (req, res) => {
  // VULNERABILITY: only clears the cookie client-side; the server-side
  // session record is left intact and the same session ID still works (CWE-613).
  res.clearCookie('connect.sid');
  res.json({ ok: true });
});

app.get('/api/session/csrf-token', requireSession, (req, res) => {
  res.json({ csrfToken: req.session.csrfToken });
});

// VULNERABILITY: no CSRF token check at all (CWE-352).
app.post('/api/session/change-email', requireSession, (req, res) => {
  const { newEmail } = req.body ?? {};
  if (!newEmail) return res.status(400).json({ error: 'newEmail required' });
  db.prepare('UPDATE users SET email = ? WHERE id = ?').run(newEmail, req.sessionUser.id);
  res.json({ ok: true, email: newEmail });
});

// ═══════════════════════════════════════════════════════════════════════
// Misconfiguration / inventory
// ═══════════════════════════════════════════════════════════════════════

app.get('/api/health', (_req, res) => res.json({ status: 'ok' })); // BUG: no security headers either way

// VULNERABILITY: v1 is fully active, no Deprecation header/notice (CWE-1059).
app.get('/api/v1/users/me', requireAuth, (req, res) => res.json(req.user));

// VULNERABILITY: undocumented internal/shadow routes are reachable (CWE-1059).
app.get('/api/internal/users', requireAuth, (_req, res) => res.json(db.prepare('SELECT * FROM users').all()));
app.get('/api/v0/users', requireAuth, (_req, res) => res.json(db.prepare('SELECT * FROM users').all()));
app.get('/api/beta/admin', requireAuth, (_req, res) => res.json({ admin: true }));

// VULNERABILITY: debug/swagger endpoints open, one leaks process.env (CWE-200/16).
app.get('/swagger', (_req, res) => res.json({ swagger: '2.0', info: { title: 'API' } }));
app.get('/api-docs', (_req, res) => res.json({ openapi: '3.0' }));
app.get('/__debug', (_req, res) => res.json({ debug: true, env: process.env }));
app.get('/metrics', (_req, res) => res.send('# metrics\nhttp_requests_total 42\n'));

// VULNERABILITY: error handler leaks stack traces and internal messages (CWE-209).
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  res.status(err?.status || 500).json({ error: err?.message, stack: err?.stack, 'Error:': String(err) });
});

app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n⚠️  VULNERABLE API server running on http://localhost:${PORT}`);
    console.log('⚠️  DO NOT expose this anywhere — intentionally insecure test fixture.\n');
  });
}

module.exports = app;
