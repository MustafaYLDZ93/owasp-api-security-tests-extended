import { test, expect } from '@playwright/test';
import jwt from 'jsonwebtoken';
import { USERS, authHeader, extractCookieValue } from './helpers';

/**
 * Kimlik Doğrulama / Oturum Yönetimi ailesi — bkz. DESIGN.md §2.2.
 * PDF kaynağı: "Kimlik Doğrulama ve Oturum Yönetimi Zafiyetleri" (TC-S01–S22).
 *
 * Test dosyası boyunca aynı sunucu süreci paylaşıldığından (globalSetup tüm
 * dosya için TEK süreç başlatır), kalıcı seed verisini (email, vb.) mutasyona
 * uğratan testler finally bloğunda geri alır — bkz. injection.security.spec.ts'te
 * keşfedilen state-sızıntısı dersi.
 */

// global-setup.ts bu değeri her iki config için de varsayılan olarak geçirir
// (server-vulnerable.js kendi sabit 'weak-secret-123' anahtarını kullandığı
// için bu sabitten etkilenmez — onun requireAuth'u zaten imzayı hiç doğrulamaz).
const SECURE_JWT_SECRET = 'test-secret-key-for-security-testing';

test.describe('Auth — Brute-force / Kilitleme (CWE-307, TC-S03)', () => {
  test('5 başarısız denemeden sonra giriş kilitlenmeli', async ({ request }) => {
    const email = 'lockout-probe@test.com';
    let lastStatus = 0;
    for (let i = 0; i < 6; i++) {
      // eslint-disable-next-line no-await-in-loop
      const res = await request.post('/api/auth/login', { data: { email, password: 'wrong-password' } });
      lastStatus = res.status();
    }
    expect(lastStatus).toBe(429);
  });
});

test.describe('Auth — Güvenlik sorusu cevabı tahmini (CWE-307/640, TC-S09)', () => {
  test('zayıf güvenlik sorusu cevabı sınırsız denenememeli', async ({ request }) => {
    let lastStatus = 0;
    for (let i = 0; i < 6; i++) {
      // eslint-disable-next-line no-await-in-loop
      const res = await request.post('/api/auth/security-answer/attempt', {
        data: { email: USERS.userA.email, answer: 'definitely-wrong-guess' },
      });
      lastStatus = res.status();
    }
    expect(lastStatus).toBe(429);
  });
});

test.describe('Auth — JWT claim doğrulaması (CWE-347/287, TC-S20/S21)', () => {
  test('alg:none (imzasız) token kabul edilmemeli', async ({ request }) => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ userId: USERS.admin.id, role: 'admin' })).toString('base64url');
    const forged = `${header}.${payload}.`;
    const res = await request.get('/api/users/me', { headers: { Authorization: `Bearer ${forged}` } });
    expect(res.status()).toBe(401);
  });

  test('süresi dolmuş token kabul edilmemeli', async ({ request }) => {
    const expired = jwt.sign(
      { userId: USERS.userA.id, email: USERS.userA.email, role: 'user' },
      SECURE_JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '-10s', issuer: 'owasp-api-extended', audience: 'owasp-api-extended-clients' },
    );
    const res = await request.get('/api/users/me', { headers: { Authorization: `Bearer ${expired}` } });
    expect(res.status()).toBe(401);
  });

  test('yanlış audience ile üretilmiş token kabul edilmemeli', async ({ request }) => {
    const wrongAudience = jwt.sign(
      { userId: USERS.userA.id, email: USERS.userA.email, role: 'user' },
      SECURE_JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h', issuer: 'owasp-api-extended', audience: 'some-other-service' },
    );
    const res = await request.get('/api/users/me', { headers: { Authorization: `Bearer ${wrongAudience}` } });
    expect(res.status()).toBe(401);
  });

  test('claim içinde role manipülasyonu (imza doğruysa bile) sunucu DB kaydını geçersiz kılmamalı', async ({ request }) => {
    // Token içindeki role claim'i "admin" olsa bile requireAuth gerçek kullanıcı
    // satırını DB'den tekrar okur; sunucu claim'deki role'e asla güvenmemeli.
    const forged = jwt.sign(
      { userId: USERS.userA.id, email: USERS.userA.email, role: 'admin' },
      SECURE_JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h', issuer: 'owasp-api-extended', audience: 'owasp-api-extended-clients' },
    );
    const res = await request.get('/api/admin/users', { headers: { Authorization: `Bearer ${forged}` } });
    expect(res.status()).toBe(403);
  });
});

test.describe('Auth — Hassas Değişiklik Doğrulaması (CWE-620, TC-S10 / API2 Senaryo #2)', () => {
  test('e-posta değişikliği mevcut parola olmadan kabul edilmemeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    try {
      const res = await request.put('/api/users/me/email', { headers, data: { newEmail: 'no-password-confirm@test.com' } });
      expect(res.status()).toBe(401);
    } finally {
      // Yanlışlıkla değiştiyse (açıklı sunucu) seed e-postasını geri yükle.
      await request.put('/api/users/me/email', {
        headers, data: { newEmail: USERS.userA.email, currentPassword: USERS.userA.password },
      });
    }
  });
});

test.describe('Auth — Oturum Sabitleme (Session Fixation, CWE-384, TC-S14)', () => {
  test('login sonrası oturum ID\'si yenilenmeli', async ({ baseURL }) => {
    const touchRes = await fetch(new URL('/api/session/touch', baseURL), { method: 'GET' });
    const preLoginSid = extractCookieValue(touchRes, 'connect.sid');
    expect(preLoginSid).not.toBeNull();

    const loginRes = await fetch(new URL('/api/session/login', baseURL), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: `connect.sid=${preLoginSid}` },
      body: JSON.stringify(USERS.userA),
    });
    const postLoginSid = extractCookieValue(loginRes, 'connect.sid');

    // Güvenli: login sırasında session.regenerate() çağrılır → farklı bir ID.
    // Açıklı: aynı ID korunur (saldırganın önceden bildiği ID login sonrası da geçerli).
    expect(postLoginSid).not.toBeNull();
    expect(postLoginSid).not.toBe(preLoginSid);
  });

  test('oturum çerezi HttpOnly ve SameSite ile işaretlenmeli', async ({ baseURL }) => {
    const loginRes = await fetch(new URL('/api/session/login', baseURL), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(USERS.userA),
    });
    const raw = (loginRes.headers as any).getSetCookie
      ? (loginRes.headers as any).getSetCookie().find((c: string) => c.startsWith('connect.sid='))
      : loginRes.headers.get('set-cookie');
    expect(raw ?? '').toMatch(/HttpOnly/i);
    expect(raw ?? '').toMatch(/SameSite=(Strict|Lax)/i);
  });
});

test.describe('Auth — Logout Geçersiz Kılma (CWE-613, TC-S17)', () => {
  test('logout sonrası eski oturum ID\'si tekrar kullanılamamalı', async ({ baseURL }) => {
    const loginRes = await fetch(new URL('/api/session/login', baseURL), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(USERS.userA),
    });
    const sid = extractCookieValue(loginRes, 'connect.sid');
    expect(sid).not.toBeNull();

    // Oturumun gerçekten çalıştığını doğrula.
    const before = await fetch(new URL('/api/session/csrf-token', baseURL), { headers: { Cookie: `connect.sid=${sid}` } });
    expect(before.status).toBe(200);

    await fetch(new URL('/api/session/logout', baseURL), { method: 'POST', headers: { Cookie: `connect.sid=${sid}` } });

    // Saldırgan logout'tan ÖNCE çaldığı aynı oturum ID'sini tekrar gönderir.
    const replay = await fetch(new URL('/api/session/csrf-token', baseURL), { headers: { Cookie: `connect.sid=${sid}` } });
    // Güvenli: session.destroy() sunucu tarafı kaydı sildi → 401.
    // Açıklı: yalnızca istemci çerezi temizlendi, sunucu kaydı hâlâ geçerli → 200.
    expect(replay.status).toBe(401);
  });
});

test.describe('Auth — CSRF Koruması (CWE-352, TC-S16/TC-C16)', () => {
  test('durum değiştiren istek CSRF token\'sız kabul edilmemeli', async ({ request }) => {
    const loginRes = await request.post('/api/session/login', { data: USERS.userA });
    const { csrfToken } = await loginRes.json();
    expect(csrfToken).toBeTruthy();

    try {
      // Saldırganın sayfası CSRF token'ı bilemez; yalnızca oturum çerezi
      // tarayıcı tarafından otomatik eklenir (burada `request` fixture'ının
      // kendi çerez kavanozu login çağrısından sonra bu rolü üstlenir).
      const res = await request.post('/api/session/change-email', { data: { newEmail: 'csrf-victim@test.com' } });
      expect(res.status()).toBe(403);
    } finally {
      await request.post('/api/session/change-email', {
        headers: { 'X-CSRF-Token': csrfToken },
        data: { newEmail: USERS.userA.email },
      });
    }
  });
});
