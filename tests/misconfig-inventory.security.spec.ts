import { test, expect } from '@playwright/test';
import { USERS, authHeader } from './helpers';

/**
 * Güvenlik Yanlış Yapılandırması / Envanter ailesi — bkz. DESIGN.md §2.6.
 * PDF kaynağı: "Güvenlik Yanlış Yapılandırması ve Bilgi İfşası / Envanter
 * Zafiyetleri" (TC-M01–M22) + orijinal repodaki MISCONF/INV testleri
 * (CONF/INFO/ERRH WSTG bölümleri).
 */

test.describe('Misconfig — Güvenlik Header\'ları (CWE-16, TC-M01/MISCONF-01)', () => {
  test('X-Content-Type-Options, X-Frame-Options ve HSTS mevcut olmalı', async ({ request }) => {
    const res = await request.get('/api/health');
    const headers = res.headers();
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['strict-transport-security']).toContain('max-age=');
  });
});

test.describe('Misconfig — CORS (CWE-942, TC-MISCONF-04)', () => {
  test('Access-Control-Allow-Origin asla joker karakter (*) olmamalı', async ({ request }) => {
    const res = await request.get('/api/health', { headers: { Origin: 'http://evil.com' } });
    expect(res.headers()['access-control-allow-origin']).not.toBe('*');
  });
});

test.describe('Misconfig — Hata Yönetimi / Stack Trace Sızıntısı (CWE-209, TC-M16/M17)', () => {
  test("SQLi probe'u ile tetiklenen gerçek sunucu hatası bile stack trace sızdırmamalı", async ({ request }) => {
    const res = await request.get(`/api/products/search?q=${encodeURIComponent("'")}`);
    const body = await res.json().catch(() => ({}));
    expect(body.stack).toBeUndefined();
  });
});

test.describe('Misconfig — Debug/Swagger Endpoint\'leri (CWE-16, TC-MISCONF-03)', () => {
  for (const path of ['/swagger', '/api-docs', '/__debug', '/metrics']) {
    test(`${path} erişilebilir olmamalı`, async ({ request }) => {
      const res = await request.get(path);
      expect([401, 403, 404]).toContain(res.status());
    });
  }
});

test.describe('Misconfig — Cache-Control (CWE-525, API8 Senaryo #2)', () => {
  test('hassas /api/users/me yanıtı önbelleğe alınmamalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.get('/api/users/me', { headers });
    expect(res.headers()['cache-control']).toContain('no-store');
  });
});

test.describe('Envanter — Eski API Sürümü (CWE-1059, TC-INV-01)', () => {
  test('/api/v1/* artık aktif olmamalı (deprecated)', async ({ request }) => {
    const res = await request.get('/api/v1/users/me');
    expect([404, 410]).toContain(res.status());
  });
});

test.describe('Envanter — Belgelenmemiş/Shadow Endpoint\'ler (CWE-1059, TC-INV-02)', () => {
  for (const path of ['/api/internal/users', '/api/v0/users', '/api/beta/admin']) {
    test(`${path} erişilebilir olmamalı`, async ({ request }) => {
      const headers = await authHeader(request, USERS.userA);
      const res = await request.get(path, { headers });
      expect([401, 403, 404]).toContain(res.status());
    });
  }
});

test.describe('Envanter — GraphQL endpoint\'i de envanter kontrolüne dahil (TC-A19 analogu)', () => {
  test('GraphQL introspection ile şema keşfi production\'da kapalı olmalı', async ({ request }) => {
    const res = await request.post('/graphql', { data: { query: '{ __type(name: "Query") { name } }' } });
    const body = await res.json();
    expect(body.errors?.length ?? 0).toBeGreaterThan(0);
  });
});
