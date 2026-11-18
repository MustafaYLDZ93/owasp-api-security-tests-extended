import { test, expect } from '@playwright/test';
import { USERS, authHeader } from './helpers';

/**
 * İş Mantığı / Hassas İş Akışı İstismarı ailesi — bkz. DESIGN.md §2.4.
 * PDF kaynağı: "İş Mantığı ve Hassas İş Akışı İstismarı (Business Logic
 * Abuse)" (TC-B01–B20) + orijinal BOLA raporundaki FLOW testleri.
 *
 * Bu ailenin testleri PAYLAŞILAN, TEK SEFERLİK kaynakları (stok=1 ürün,
 * max_uses=1 kupon) tüketir — her kaynak yalnızca bu dosyada ve yalnızca bir
 * testte kullanılır, böylece testler arası state çakışması olmaz.
 */

test.describe('Business Logic — Stok Yarış Durumu / Race Condition (CWE-362, TC-B17)', () => {
  test('stoğu 1 olan üründen eşzamanlı 10 satın alma isteğinden yalnızca 1\'i başarılı olmalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const attempts = Array.from({ length: 10 }, () =>
      request.post('/api/orders', { headers, data: { productId: 'promo-item-001', quantity: 1 } }),
    );
    const results = await Promise.all(attempts);
    const successCount = results.filter(r => r.status() === 201).length;
    // Güvenli: IMMEDIATE transaction stok kontrolü+düşümünü atomik yapar → tam 1.
    // Açıklı: oku-sonra-yaz arasındaki yapay gecikme (setTimeout) sayesinde
    // tüm istekler stoğu "yeterli" görür → 10'a kadar "başarılı" satın alma (oversell).
    expect(successCount).toBe(1);
  });
});

test.describe('Business Logic — Negatif Miktar (CWE-20, TC-FLOW-03)', () => {
  test('negatif miktarla sipariş oluşturulamamalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.post('/api/orders', { headers, data: { productId: 'product-001', quantity: -5 } });
    expect(res.status()).toBe(400);
  });
});

test.describe('Business Logic — Self-Referral (TC-FLOW-02)', () => {
  test('kullanıcı kendi referans kodunu kullanamamalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.post('/api/referrals/apply', { headers, data: { code: 'REF_USER_A' } });
    expect(res.status()).toBe(400);
  });
});

test.describe('Business Logic — İş Akışı Sırası Atlanması (CWE-841, TC-B06)', () => {
  test('rezerve edilmemiş bir sipariş onaylanamamalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const created = await (await request.post('/api/orders', { headers, data: { productId: 'product-002', quantity: 1 } })).json();
    const res = await request.post(`/api/orders/${created.id}/confirm`, { headers });
    expect(res.status()).toBe(409);
  });

  test('rezerve edilmiş bir sipariş normal şekilde onaylanabilmeli (pozitif kontrol)', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const created = await (await request.post('/api/orders', { headers, data: { productId: 'product-002', quantity: 1 } })).json();
    await request.post(`/api/orders/${created.id}/reserve`, { headers });
    const res = await request.post(`/api/orders/${created.id}/confirm`, { headers });
    expect(res.status()).toBe(200);
  });
});

test.describe('Business Logic — Kupon Çifte Harcama / Race Condition (CWE-362, TC-B16)', () => {
  test('max_uses=1 kuponun eşzamanlı 8 denemeden yalnızca 1\'i başarılı olmalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const attempts = Array.from({ length: 8 }, () => request.post('/api/coupons/WELCOME10/redeem', { headers }));
    const results = await Promise.all(attempts);
    const successCount = results.filter(r => r.status() === 200).length;
    expect(successCount).toBe(1);
  });
});
