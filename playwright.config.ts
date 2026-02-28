import { defineConfig, devices } from '@playwright/test'

/**
 * E2E tests run against the deployed Cloudflare Worker.
 * No local dev server — tests hit the live URL.
 *
 * Auth: Clerk session is pre-saved via `npm run test:auth`.
 * Run that once to generate playwright/.auth/user.json, then tests use it.
 */
export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: [
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
    ['list'],
  ],
  use: {
    baseURL: process.env.BASE_URL || 'https://urlstogo.cloud',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    actionTimeout: 15000,
    navigationTimeout: 30000,
  },
  projects: [
    // Auth setup — runs first, generates playwright/.auth/user.json
    {
      name: 'setup',
      testMatch: '**/auth.setup.ts',
    },
    // Main tests — depend on auth setup
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        storageState: 'playwright/.auth/user.json',
      },
      dependencies: ['setup'],
    },
  ],
})
