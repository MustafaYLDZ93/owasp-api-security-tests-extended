import { test, expect } from '@playwright/test';
import JSZip from 'jszip';
import { USERS, authHeader } from './helpers';

/**
 * SSRF / Dosya Yükleme / Kaynak Tüketimi ailesi — bkz. DESIGN.md §2.5.
 * PDF kaynağı: "Dosya Yükleme, SSRF ve Kaynak Tüketimi: CWE, ThreatStats ve
 * OWASP Üçlü Analizi" (TC-S01–S20) + orijinal repodaki SSRF/CONS testleri.
 */

test.describe('SSRF — İç Adres Engeli (CWE-918, TC-S01/S20)', () => {
  test('bulut metadata adresi webhook olarak kaydedilememeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.post('/api/webhooks', { headers, data: { url: 'http://169.254.169.254/latest/meta-data/' } });
    expect(res.status()).toBe(400);
  });

  test('localhost/file:// adresleri webhook olarak kaydedilememeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.post('/api/webhooks', { headers, data: { url: 'file:///etc/passwd' } });
    expect(res.status()).toBe(400);
  });
});

test.describe('SSRF — IP Gizleme / Filtre Atlatma (CWE-918, filtre bypass)', () => {
  test('ondalık (decimal) kodlanmış 127.0.0.1 adresi tanınmalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.post('/api/webhooks/fetch', { headers, data: { url: 'http://2130706433/secret' } });
    expect(res.status()).toBe(400);
  });

  test('onaltılık (hex) kodlanmış 127.0.0.1 adresi tanınmalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.post('/api/webhooks/fetch', { headers, data: { url: 'http://0x7f000001/secret' } });
    expect(res.status()).toBe(400);
  });
});

test.describe('SSRF — Domain Allowlist (TC-UNSAFE-01)', () => {
  test('izin listesi dışındaki domain webhook entegrasyonu için reddedilmeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.post('/api/integrations/webhook', { headers, data: { callbackUrl: 'http://attacker.com/collect' } });
    expect(res.status()).toBe(403);
  });
});

test.describe('Open Redirect (CWE-601, TC-UNSAFE-03)', () => {
  test('dış URL\'e yönlendirme reddedilmeli', async ({ request }) => {
    const res = await request.get('/api/auth/callback?redirect=http://evil.com/phish', { maxRedirects: 0 });
    expect(res.status()).toBe(400);
  });
});

test.describe('XXE — Yerel Dosya Okuma (CWE-611, TC-S04)', () => {
  test('SYSTEM entity ile yerel dosya okunamamalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const xml = `<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file://secret.txt"> ]>\n<product><name>&xxe;</name></product>`;
    const res = await request.post('/api/files/upload-xml', {
      headers,
      multipart: { file: { name: 'probe.xml', mimeType: 'application/xml', buffer: Buffer.from(xml) } },
    });
    if (res.status() === 200) {
      const body = await res.json();
      expect(body.name).not.toContain('XXE-FIXTURE-SECRET-1234');
    } else {
      expect(res.status()).toBe(400);
    }
  });
});

test.describe('XXE — Entity Expansion / "Billion Laughs" (CWE-776, TC-S06)', () => {
  test('iç içe entity genişlemesi sınırsız kabul edilmemeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    let doctype = '<!DOCTYPE lolz [<!ENTITY lol0 "lol">';
    for (let i = 1; i <= 5; i++) {
      doctype += `<!ENTITY lol${i} "&lol${i - 1};&lol${i - 1};&lol${i - 1};&lol${i - 1};&lol${i - 1};&lol${i - 1};&lol${i - 1};&lol${i - 1};&lol${i - 1};&lol${i - 1};">`;
    }
    doctype += ']>';
    const xml = `${doctype}<root><name>&lol5;</name></root>`; // genişletilince ~300.000 karakter
    const res = await request.post('/api/files/upload-xml', {
      headers,
      multipart: { file: { name: 'bomb.xml', mimeType: 'application/xml', buffer: Buffer.from(xml) } },
    });
    expect(res.status()).toBe(400);
  });
});

test.describe('Zip Bomb / Sıkıştırma Bombası (CWE-409, TC-S07)', () => {
  test('açıldığında aşırı büyüyen arşiv reddedilmeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const zip = new JSZip();
    zip.file('big.bin', Buffer.alloc(5 * 1024 * 1024, 0)); // açıldığında 5MB, sıkıştırılmış birkaç KB
    const zipBuffer: Buffer = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });

    const res = await request.post('/api/files/upload-archive', {
      headers,
      multipart: { file: { name: 'bomb.zip', mimeType: 'application/zip', buffer: zipBuffer } },
    });
    expect(res.status()).toBe(413);
  });
});

test.describe('Kaynak Tüketimi — Sayfalama Sınırı (CWE-770, TC-CONS-02)', () => {
  test('aşırı büyük limit isteği azami sayfa boyutunu aşmamalı', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await (await request.get('/api/users?limit=10000', { headers })).json();
    // Döndürülen veri sayısı yerine sunucunun UYGULADIĞI `limit` değerine
    // bakıyoruz: seed veri hacmi (100'den az kullanıcı) data.length'i
    // güvenilmez kılar — vulnerable sunucuda bile az veri varsa sonuç 100'ün altında kalabilir.
    expect(res.limit).toBeLessThanOrEqual(100);
    expect(res.data.length).toBeLessThanOrEqual(100);
  });
});

test.describe('Kaynak Tüketimi — Payload Boyutu Sınırı (CWE-770, TC-CONS-01)', () => {
  test('1MB üzeri gövde 413 ile reddedilmeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    const res = await request.post('/api/data', { headers, data: { blob: 'x'.repeat(2 * 1024 * 1024) } });
    expect(res.status()).toBe(413);
  });
});

test.describe('"Denial of Wallet" — SMS Bütçe Simülasyonu (CWE-770/400, API4 Senaryo #1)', () => {
  test('aynı hesaptan sınırsız SMS tetiklenememeli', async ({ request }) => {
    const headers = await authHeader(request, USERS.userA);
    let lastStatus = 0;
    for (let i = 0; i < 6; i++) {
      // eslint-disable-next-line no-await-in-loop
      const res = await request.post('/api/notifications/sms', { headers, data: { phoneNumber: '+10000000000' } });
      lastStatus = res.status();
    }
    expect(lastStatus).toBe(429);
  });
});
