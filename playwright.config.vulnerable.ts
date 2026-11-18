import { defineConfig, devices } from '@playwright/test';

/**
 * Vulnerable API configuration — runs the test suite against the intentionally
 * insecure server (server-vulnerable.js, port 3001). Most security tests
 * should FAIL, proving the suite actually detects the planted vulnerabilities.
 *
 *   npx playwright test --config=playwright.config.vulnerable.ts
 */
process.env.PORT = '3001';
process.env.TARGET_SCRIPT = 'server-vulnerable.js';
process.env.API_BASE_URL = 'http://localhost:3001';

export default defineConfig({
  testDir: './tests',
  testMatch: ['**/*.security.spec.ts'],

  globalSetup:    './global-setup.ts',
  globalTeardown: './global-teardown.ts',

  workers: 1,
  fullyParallel: false,

  timeout: 30_000,
  expect: { timeout: 10_000 },

  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report-vulnerable', open: 'never' }],
  ],

  use: {
    baseURL: process.env.API_BASE_URL,
    // bkz. playwright.config.ts'teki not: global Content-Type zorlaması yok.
  },

  projects: [
    {
      name: 'api',
      testIgnore: ['client-side.security.spec.ts'],
    },
    {
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
