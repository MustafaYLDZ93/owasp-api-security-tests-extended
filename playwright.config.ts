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
    extraHTTPHeaders: { 'Content-Type': 'application/json' },
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
      // Uses the pre-installed Chromium in this container instead of downloading one.
      name: 'chromium',
      testMatch: ['client-side.security.spec.ts'],
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: {
          executablePath: process.env.PW_CHROMIUM_PATH || '/opt/pw-browsers/chromium',
          args: ['--no-sandbox'],
        },
      },
    },
  ],
});
