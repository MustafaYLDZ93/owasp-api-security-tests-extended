import { test, expect } from '@playwright/test';
import { USERS, authHeader, registerDisposableUser } from './helpers';

/**
 * Yetkilendirme / Erişim Kontrolü ailesi — bkz. DESIGN.md §2.3.
 * PDF kaynağı: "Yetkilendirme ve Erişim Kontrolü Zafiyetleri" (BOLA/BFLA/BOPLA,
 * TC-A01–A20) + "İstemci Tarafı" raporunun IDOR/JWT maddeleri.
 */

test.describe('Authorization — BOLA (CWE-639/862, TC-A01/A02/A09)', () => {
  test('bir kullanıcı başka kullanıcının profilini okuyamamalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.get(`/api/users/${USERS.userB.id}`, { headers });
    expect(res.status()).toBe(403);
  });

  test('bir kullanıcı başka kullanıcının profilini güncelleyememeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.put(`/api/users/${USERS.userB.id}`, { headers, data: { name: 'Hacked' } });
    expect(res.status()).toBe(403);
  });

  test('bir kullanıcı başka kullanıcının hesabını silememeli', async ({ request }) => {
    // Sabit seed kullanıcılarını değil, atılabilir (disposable) hesapları kullan.
    const victim = await registerDisposableUser(request);
    const attacker = await registerDisposableUser(request);
    const res = await request.delete(`/api/users/${victim.id}`, { headers: attacker.headers });
    expect(res.status()).toBe(403);
    // Doğrulama: kurban hâlâ var mı? (admin ile kontrol)
    const adminHeaders = await authHeader(request, USERS.admin);
    const check = await request.get(`/api/users/${victim.id}`, { headers: adminHeaders });
    expect(check.status()).toBe(200);
  });

  test('bir kullanıcı başka kullanıcının siparişini okuyamamalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.get('/api/orders/order-002', { headers }); // order-002 → user_b'ye ait (seed)
    expect(res.status()).toBe(403);
  });

  test('admin her kullanıcıya erişebilmeli (pozitif kontrol)', async ({ request }) => {
    const headers = await authHeader(request, USERS.admin);
    const res = await request.get(`/api/users/${USERS.userA.id}`, { headers });
    expect(res.status()).toBe(200);
  });
});

test.describe('Authorization — BFLA (CWE-862, TC-A04/A05)', () => {
  test('normal kullanıcı /api/admin/users listesine erişememeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.get('/api/admin/users', { headers });
    expect(res.status()).toBe(403);
  });

  test('normal kullanıcı admin config endpoint\'ine POST/PUT ile yazamamalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.post('/api/admin/config', { headers, data: {} });
    expect([403, 405]).toContain(res.status());
  });
});

test.describe('Authorization — BOPLA / Excessive Data Exposure (CWE-200/915, TC-A08)', () => {
  test('/api/users/me yanıtı password_hash veya security_answer içermemeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const me = await (await request.get('/api/users/me', { headers })).json();
    expect(me.password_hash).toBeUndefined();
    expect(me.security_answer).toBeUndefined();
  });
});

test.describe('Authorization — Path Traversal (CWE-22, TC-A12)', () => {
  test('".." dizileriyle kök dizin dışına çıkılamamalı', async ({ request }) => {
    const res = await request.get('/api/files/by-name/..%2ffixtures%2fsecret.txt');
    if (res.status() === 200) {
      const body = await res.text();
      expect(body).not.toContain('XXE-FIXTURE-SECRET-1234');
    } else {
      expect([400, 403, 404]).toContain(res.status());
    }
  });

  test('izin verilen genel dosya normal şekilde erişilebilir olmalı (pozitif kontrol)', async ({ request }) => {
    const res = await request.get('/api/files/by-name/welcome.txt');
    expect(res.status()).toBe(200);
  });
});

test.describe('Authorization — Files BOLA (CWE-639)', () => {
  test('bir kullanıcı başka kullanıcının yüklediği dosyayı indirememeli', async ({ request }) => {
    const owner = await authHeader(request, USERS.userA);
    const upload = await request.post('/api/files/upload', {
      headers: owner,
      multipart: { file: { name: 'private.txt', mimeType: 'text/plain', buffer: Buffer.from('owner-only content') } },
    });
    const { id } = await upload.json();

    const other = await authHeader(request, USERS.userB);
    const res = await request.get(`/api/files/${id}/download`, { headers: other });
    expect(res.status()).toBe(403);
  });
});

test.describe('Authorization — GraphQL (CWE-285/639/799, TC-A03/A10/A11)', () => {
  test('introspection sorgusu reddedilmeli', async ({ request }) => {
    const res = await request.post('/graphql', { data: { query: '{ __schema { types { name } } }' } });
    const body = await res.json();
    expect(body.errors?.length ?? 0).toBeGreaterThan(0);
    expect(body.data?.__schema).toBeFalsy();
  });

  test('user(id) sorgusu ownerlık dışı erişime izin vermemeli (GraphQL BOLA)', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.post('/graphql', {
      headers, data: { query: `{ user(id: ${USERS.userB.id}) { email role } }` },
    });
    const body = await res.json();
    expect(body.data?.user).toBeFalsy();
  });

  test('batch işlem sayısı sınırsız olmamalı', async ({ request }) => {
    const batch = Array.from({ length: 50 }, (_, i) => ({ query: `{ ping(message: "${i}") }` }));
    const res = await request.post('/graphql', { data: batch });
    // 400 (maxBatchSize aşıldı) veya 429 (operasyon sayısı rate-limit'i aştı) —
    // ikisi de CWE-799'un geçerli bir savunmasıdır.
    expect([400, 429]).toContain(res.status());
  });
});

test.describe('Authorization — OAuth2 (CWE-601/285, TC-A16/A17)', () => {
  test('kayıtlı olmayan (host eşleşse bile farklı yol) redirect_uri reddedilmeli', async ({ request, baseURL }) => {
    const headers = await authHeader(request, USERS.userA);
    const looseRedirect = new URL('/oauth/callback/evil-path', baseURL).toString();
    const res = await request.get('/oauth/authorize', {
      headers,
      params: { client_id: 'demo-client', redirect_uri: looseRedirect, scope: 'profile', state: 'xyz' },
      maxRedirects: 0,
    });
    expect(res.status()).toBe(400);
  });

  test('token değişiminde redirect_uri, authorize adımıyla eşleşmeli', async ({ request, baseURL }) => {
    const headers = await authHeader(request, USERS.userA);
    const correctRedirect = new URL('/oauth/callback', baseURL).toString();
    const otherRegisteredRedirect = baseURL?.includes('3000')
      ? 'http://localhost:3001/oauth/callback'
      : 'http://localhost:3000/oauth/callback';

    const authRes = await request.get('/oauth/authorize', {
      headers,
      params: { client_id: 'demo-client', redirect_uri: correctRedirect, scope: 'profile', state: 'xyz' },
      maxRedirects: 0,
    });
    const location = authRes.headers()['location'];
    const code = new URL(location).searchParams.get('code');

    const tokenRes = await request.post('/oauth/token', {
      data: {
        grant_type: 'authorization_code', code,
        client_id: 'demo-client', client_secret: 'demo-secret',
        redirect_uri: otherRegisteredRedirect, // authorize adımında kullanılandan FARKLI
      },
    });
    expect(tokenRes.status()).not.toBe(200);
  });

  test('token isteğinde scope yükseltme (escalation) kabul edilmemeli', async ({ request, baseURL }) => {
    const headers = await authHeader(request, USERS.userA);
    const redirectUri = new URL('/oauth/callback', baseURL).toString();

    const authRes = await request.get('/oauth/authorize', {
      headers,
      params: { client_id: 'demo-client', redirect_uri: redirectUri, scope: 'profile', state: 'xyz' },
      maxRedirects: 0,
    });
    const code = new URL(authRes.headers()['location']).searchParams.get('code');

    const tokenRes = await request.post('/oauth/token', {
      data: {
        grant_type: 'authorization_code', code,
        client_id: 'demo-client', client_secret: 'demo-secret',
        redirect_uri: redirectUri, scope: 'profile orders admin',
      },
    });
    const body = await tokenRes.json();
    expect(body.scope).toBe('profile');
  });
});
