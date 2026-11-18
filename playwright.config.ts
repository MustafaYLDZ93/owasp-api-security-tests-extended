import { defineConfig, devices } from '@playwright/test';

/**
 * Secure API configuration — runs the full test suite against the hardened
 * server (server.js, port 3000). All security tests should PASS.
 *
 *   npx playwright test
 */
process.env.PORT = process.env.PORT ?? '3000';
process.env.TARGET_SCRIPT = 'server.js';
process.env.API_BASE_URL = process.env.API_BASE_URL ?? 'http://localhost:3000';

export default defineConfig({
  testDir: './tests',
  testMatch: ['**/*.security.spec.ts'],

  globalSetup:    './global-setup.ts',
  globalTeardown: './global-teardown.ts',

  // Sequential execution prevents cross-spec rate-limit/DB state interference
  workers: 1,
  fullyParallel: false,

  timeout: 30_000,
  expect: { timeout: 10_000 },

  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
  ],

  use: {
    baseURL: process.env.API_BASE_URL,
    // NOT: burada sabit bir `Content-Type: application/json` extraHTTPHeaders
    // KASITLI OLARAK yok — Playwright zaten `data:` ile gönderilen plain
    // objeler için bu header'ı otomatik ekler; global olarak zorlamak
    // multipart/form-data (dosya yükleme) isteklerinin Content-Type'ını da
    // ezer ve body-parser'ın multipart gövdeyi JSON sanıp patlamasına yol açar.
  },

  projects: [
    {
      // Pure API tests (APIRequestContext) — no browser needed.
      name: 'api',
      testIgnore: ['client-side.security.spec.ts'],
    },
    {
      // Client-side/DevTools family needs a real DOM (XSS rendering, clickjacking,
      // postMessage, localStorage, CORS from a page, reverse tabnabbing, etc.).
      // PW_CHROMIUM_PATH lets a sandboxed dev container point at its own
      // pre-installed Chromium; CI (GitHub Actions) runs `playwright install`
      // and uses Playwright's own managed browser (no override needed).
      name: 'chromium',
      testMatch: ['client-side.security.spec.ts'],
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: process.env.PW_CHROMIUM_PATH
          ? { executablePath: process.env.PW_CHROMIUM_PATH, args: ['--no-sandbox'] }
          : { args: ['--no-sandbox'] },
      },
    },
  ],
});
