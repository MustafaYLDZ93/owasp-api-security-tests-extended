import { test, expect } from '@playwright/test';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * İstemci Tarafı Manipülasyon / DevTools ailesi — bkz. DESIGN.md §2.7.
 * PDF kaynağı: "İstemci Tarafı Manipülasyon ve Tarayıcı Tabanlı Test
 * Teknikleri" (WSTG-CLNT, TC-C01–C20).
 *
 * Bu dosya, diğerlerinin aksine GERÇEK bir tarayıcı (chromium projesi,
 * playwright.config.ts) kullanır — APIRequestContext değil, `page` fixture'ı.
 * Her sayfanın `public/secure/*.html` ve `public/vulnerable/*.html` olmak
 * üzere iki ayrı sürümü vardır; hangi API sunucusuna karşı çalıştırıldığına
 * göre ilgili statik klasör servis edilir (bkz. server.js / server-vulnerable.js).
 */

test.describe('Client-side — DOM Tabanlı XSS (CWE-79, TC-C01)', () => {
  test('URL fragment\'i innerHTML olarak yorumlanmamalı', async ({ page, baseURL }) => {
    const payload = '<img src=x onerror="window.__xssFired=true">';
    const hash = new URLSearchParams({ name: payload }).toString();
    await page.goto(`${baseURL}/profile.html#${hash}`);
    await page.waitForTimeout(150);
    const fired = await page.evaluate(() => (window as any).__xssFired === true);
    expect(fired).toBe(false);
    // Pozitif kontrol: değer yine de (kaçışlı biçimde) sayfada görünmeli.
    await expect(page.locator('#greeting')).toContainText('img');
  });
});

test.describe('Client-side — İstemci Tarafı Açık Yönlendirme (CWE-601, TC-C04)', () => {
  test('dış domain\'e yönlendirme kararı reddedilmeli', async ({ page, baseURL }) => {
    // `to` parametresiz git ki sayfa gerçek bir navigasyon BAŞLATMASIN;
    // karar mantığını saf fonksiyon üzerinden doğrudan çağırıyoruz.
    await page.goto(`${baseURL}/redirect.html`);
    const decision = await page.evaluate(
      to => (window as any).evaluateRedirect(to),
      'https://evil.example.com/phish',
    );
    expect(decision.allowed).toBe(false);
  });
});

test.describe('Client-side — Clickjacking (CWE-1021, TC-C08)', () => {
  test('hassas sayfa iframe içine gömülememeli (X-Frame-Options)', async ({ page, baseURL }) => {
    const blockedUrls: string[] = [];
    page.on('requestfailed', req => blockedUrls.push(req.url()));

    await page.setContent(`<iframe id="f" src="${baseURL}/frame-target.html" style="width:300px;height:200px"></iframe>`);
    await page.waitForTimeout(400);

    const blocked = blockedUrls.some(u => u.includes('frame-target.html'));
    let frameHasButton = false;
    try {
      const frame = page.frames().find(f => f.url().includes('frame-target.html'));
      frameHasButton = frame ? (await frame.locator('#delete-account-btn').count()) > 0 : false;
    } catch {
      frameHasButton = false;
    }

    // Güvenli: X-Frame-Options: DENY → istek engellenir, buton erişilemez.
    // Açıklı: header yok → iframe normal şekilde yüklenir, buton erişilebilir.
    expect(blocked || !frameHasButton).toBe(true);
  });
});

test.describe('Client-side — postMessage Origin Doğrulaması (CWE-346, TC-C10)', () => {
  test('farklı origin\'den gelen mesaj işlenmemeli', async ({ page, context, baseURL }) => {
    // Gerçek bir çapraz-origin saldırgan sayfası simüle etmek için app
    // sunucularından BAĞIMSIZ, ayrı bir origin'de (farklı port) geçici bir
    // HTTP sunucusu açıyoruz — bu sayede event.origin gerçekten farklı olur.
    const attackerServer = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!doctype html><script>
        const target = window.open(${JSON.stringify(baseURL + '/postmessage.html')}, 'victim');
        window.addEventListener('message', () => {}); // noop
        setTimeout(() => { target.postMessage('ATTACKER_PAYLOAD', '*'); }, 300);
      </script>`);
    });
    await new Promise<void>(resolve => attackerServer.listen(0, '127.0.0.1', resolve));
    const attackerPort = (attackerServer.address() as AddressInfo).port;

    try {
      const popupPromise = context.waitForEvent('page');
      await page.goto(`http://127.0.0.1:${attackerPort}/`);
      const popup = await popupPromise;
      await popup.waitForLoadState();
      await popup.waitForTimeout(600);

      const accepted = await popup.evaluate(() => (window as any).__lastMessageAccepted);
      // Güvenli: event.origin app'in kendi origin'i değil → mesaj yok sayılır.
      // Açıklı: origin kontrolü yok → mesaj kabul edilir, title değişir.
      expect(accepted).not.toBe(true);
    } finally {
      attackerServer.close();
    }
  });
});

test.describe('Client-side — localStorage\'a Güvenerek Yetki Kararı (CWE-602/565, TC-C11/C12)', () => {
  test('localStorage\'da sahte "admin" rolü gerçek yetki vermemeli', async ({ page, baseURL }) => {
    await page.goto(`${baseURL}/storage.html`);
    await page.evaluate(() => { localStorage.setItem('role', 'admin'); localStorage.removeItem('token'); });
    await page.reload();
    await page.waitForTimeout(200);
    const visible = await page.locator('#admin-panel').isVisible();
    // Güvenli: sayfa yetkiyi sunucudan (geçerli token olmadan) doğrular → gizli kalır.
    // Açıklı: yalnızca localStorage'a bakar → panel hemen görünür olur.
    expect(visible).toBe(false);
  });
});

test.describe('Client-side — Reverse Tabnabbing (CWE-1022, TC-C14)', () => {
  test('target="_blank" linki rel="noopener" içermeli', async ({ page, baseURL }) => {
    await page.goto(`${baseURL}/tabnabbing.html`);
    const rel = await page.locator('#ext-link').getAttribute('rel');
    expect(rel ?? '').toContain('noopener');
  });
});
