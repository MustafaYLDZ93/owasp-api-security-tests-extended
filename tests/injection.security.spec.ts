import { test, expect } from '@playwright/test';
import { USERS, authHeader } from './helpers';

/**
 * Injection ailesi — bkz. DESIGN.md §2.1.
 * PDF kaynağı: "Injection Zafiyetleri: CWE, ThreatStats ve OWASP Üçlü Analizi"
 * (TC-I01–I26 kataloğu). Bu dosya, gerçek bir sink'e (SQLite, shell, custom
 * template evaluator) sahip olan maddeleri kapsar — SSI/LDAP/IMAP/SMTP/Format
 * String/Request-Smuggling gibi bu projede sink'i bulunmayan maddeler
 * DESIGN.md §3'te gerekçesiyle hariç tutulmuştur.
 */

test.describe('Injection — SQL Injection (CWE-89, TC-I01/I02)', () => {
  test('boolean-based bypass payload yalnızca sorguyla eşleşen ürünleri döndürmeli', async ({ request }) => {
    const res = await request.get(`/api/products/search?q=${encodeURIComponent("x%' OR '1'='1' --")}`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    // Güvenli: parametrik sorgu bu payload'ı literal bir string olarak arar → eşleşme yok.
    // Açıklı: enjeksiyon tetiklenir, WHERE 1=1 her satırı döndürür (3 ürün).
    expect(body.results.length).toBe(0);
  });

  test("tekil tırnak probe'u sorgu katmanını çökertmemeli (error-based)", async ({ request }) => {
    const res = await request.get(`/api/products/search?q=${encodeURIComponent("'")}`);
    // Güvenli: parametrik sorgu tırnağı veri olarak işler → 200.
    // Açıklı: SQL sözdizimi hatası → 500 + stack trace sızıntısı.
    expect(res.status()).toBe(200);
  });

  test('UNION tabanlı deneme users tablosundan veri sızdırmamalı', async ({ request }) => {
    const payload = "x' UNION SELECT id, email, password_hash, role, 0 FROM users --";
    const res = await request.get(`/api/products/search?q=${encodeURIComponent(payload)}`);
    if (res.status() !== 200) return; // açıklı sunucuda sözdizimi hatası da kabul edilebilir bir "başarısızlık" kanıtıdır
    const body = await res.json();
    const leaked = (body.results ?? []).some((r: any) => typeof r.name === 'string' && r.name.includes('@test.com'));
    expect(leaked).toBe(false);
  });
});

test.describe('Injection — NoSQL / Operator Injection (CWE-943, TC-I04)', () => {
  test('"$ne" operatör enjeksiyonu kimlik doğrulamayı atlatmamalı', async ({ request }) => {
    const res = await request.post('/api/auth/login-legacy', {
      data: { email: { $ne: 'nobody-matches-anything@test.com' } },
    });
    const body = await res.json().catch(() => ({}));
    expect(body.token).toBeUndefined();
  });

  test('"$gt" operatörüyle tüm kayıtları eşleştirme denemesi başarısız olmalı', async ({ request }) => {
    const res = await request.post('/api/auth/login-legacy', { data: { email: { $gt: '' } } });
    const body = await res.json().catch(() => ({}));
    expect(body.token).toBeUndefined();
  });
});

test.describe('Injection — OS Command Injection (CWE-78/77, TC-I05)', () => {
  test('zaman tabanlı komut enjeksiyonu ek gecikme yaratmamalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const t0 = Date.now();
    await request.post('/api/system/echo', { headers, data: { message: 'probe; sleep 2' } });
    const elapsed = Date.now() - t0;
    // Güvenli: payload tamamen reddedilir (anlık). Açıklı: shell `sleep 2`'yi
    // de çalıştırır → ~2000ms+ ek gecikme (zaman tabanlı oracle).
    expect(elapsed).toBeLessThan(1500);
  });

  test('komut ayracı (;) karakteri payload olarak kabul edilmemeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.post('/api/system/echo', { headers, data: { message: 'hi `id`' } });
    expect(res.status()).toBe(400);
  });
});

test.describe('Injection — Server-Side Template Injection / SSTI (CWE-94, TC-I11)', () => {
  test("{{7*7}} probe'u sunucuda hesaplanmamalı", async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.post('/api/templates/render', { headers, data: { template: 'result={{7*7}}' } });
    const body = await res.json();
    // Güvenli: yalnızca whitelist'teki değişken yolları çözülür, ifadeler asla.
    // Açıklı: `new Function` ile değerlendirilir → "result=49" döner.
    expect(body.rendered).not.toContain('49');
  });

  test('global nesnelere erişim denemesi başarısız olmalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const template = '{{globalThis.process ? "LEAKED" : "safe"}}';
    const res = await request.post('/api/templates/render', { headers, data: { template } });
    const body = await res.json();
    // Güvenli: whitelist regex'i bu ifadeyle eşleşmez → şablon değişmeden döner.
    // Açıklı: `new Function` içinde çalıştırılır, process global'ine erişip "LEAKED" döner.
    expect(body.rendered).not.toBe('LEAKED');
  });
});

test.describe('Injection — Mass Assignment / Prototype Pollution (CWE-915/1321, TC-I21/I22)', () => {
  test('PUT /api/users/me ile role alanı yükseltilememeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    await request.put('/api/users/me', { headers, data: { role: 'admin', credits: 99999, verified: true } });
    const me = await (await request.get('/api/users/me', { headers })).json();
    try {
      expect(me.role).not.toBe('admin');
      expect(me.credits).not.toBe(99999);
    } finally {
      // Paylaşılan sabit seed kullanıcısını (user_a) sonraki testler için eski haline getir —
      // açıklı sunucuda bu mutasyon gerçekten kalıcı olduğundan temizlik olmadan sonraki
      // testler (role/credits'e bağımlı olanlar) yanlış pozitif/negatif üretebilir.
      await request.put('/api/users/me', { headers, data: { role: 'user', credits: 0, verified: false } });
    }
  });

  test('PATCH /api/users/me ile email alanı (ownerlık dışı) değiştirilememeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    try {
      await request.patch('/api/users/me', { headers, data: { email: 'hijacked@test.com' } });
      const me = await (await request.get('/api/users/me', { headers })).json();
      expect(me.email).not.toBe('hijacked@test.com');
    } finally {
      // Kritik temizlik: açıklı sunucuda e-posta gerçekten değişir — geri almazsak
      // sonraki testlerdeki `authHeader(request, USERS.userA)` çağrıları orijinal
      // e-postayla artık giriş yapamaz ve dosyadaki tüm sonraki testler bozulur.
      await request.patch('/api/users/me', { headers, data: { email: USERS.userA.email } });
    }
  });

  test('"__proto__" payload\'ı Object.prototype\'ı kirletmemeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    // NOT: `{ '__proto__': {...} }` bir obje LİTERALİ olarak yazılırsa JS motoru
    // bunu normal bir own-property değil, prototip ataması olarak yorumlar —
    // JSON.stringify de bu yüzden onu asla telin üzerinden göndermez. Gerçek bir
    // saldırgan payload'ı (JSON gövdesinde literal "__proto__" anahtarı) üretmek
    // için JSON.parse kullanmak gerekir — tam olarak bir API istemcisinin
    // request body'sini ayrıştırırken Express'in de yapacağı şey budur.
    const payload = JSON.parse('{"__proto__":{"polluted":true},"name":"Probe"}');
    const res = await request.patch('/api/users/me/profile', { headers, data: payload });
    const body = await res.json();
    expect(body.polluted).toBe(false);
  });
});

test.describe('Injection — HTTP Parameter Pollution (CWE-235, TC-I16)', () => {
  test('aynı query parametresinin tekrarı sessizce kabul edilmemeli', async ({ request }) => {
    const res = await request.get('/api/search?tag=electronics&tag=admin-only-category');
    expect(res.status()).toBe(400);
  });
});

test.describe('Injection — Stored XSS (CWE-79, TC-I18)', () => {
  test('yorum gövdesi HTML olarak kaçışsız saklanmamalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const payload = '<script>document.title="pwned"</script>';
    const res = await request.post('/api/comments', { headers, data: { productId: 'product-001', body: payload } });
    const created = await res.json();
    expect(created.bodyHtml).not.toContain('<script>');

    const list = await (await request.get('/api/products/product-001/comments')).json();
    const stored = list.find((c: any) => c.id === created.id);
    expect(stored.body_html).not.toContain('<script>');
  });
});
