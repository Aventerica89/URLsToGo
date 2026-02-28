import { test as setup, expect } from '@playwright/test'
import path from 'path'

const authFile = path.join(__dirname, '../../playwright/.auth/user.json')

/**
 * Auth setup — signs in via Clerk and saves session cookies to
 * playwright/.auth/user.json so all other tests skip the login flow.
 *
 * Requires CLERK_TEST_EMAIL and CLERK_TEST_PASSWORD env vars, OR run
 * manually: npx playwright codegen https://urlstogo.cloud/admin
 * and save the auth state from the browser.
 */
setup('authenticate', async ({ page }) => {
  const email = process.env.CLERK_TEST_EMAIL
  const password = process.env.CLERK_TEST_PASSWORD

  if (!email || !password) {
    throw new Error(
      'Set CLERK_TEST_EMAIL and CLERK_TEST_PASSWORD to run auth setup.\n' +
      'Or generate auth state manually: npx playwright codegen https://urlstogo.cloud/admin'
    )
  }

  await page.goto('/admin')

  // Wait for Clerk login form
  await page.waitForSelector('input[name="identifier"], input[type="email"]', { timeout: 15000 })

  await page.fill('input[name="identifier"], input[type="email"]', email)
  await page.click('button[type="submit"], button:has-text("Continue")')

  // Password step
  await page.waitForSelector('input[type="password"]', { timeout: 10000 })
  await page.fill('input[type="password"]', password)
  await page.click('button[type="submit"], button:has-text("Sign in")')

  // Wait for admin dashboard to load (sidebar is the reliable indicator)
  await page.waitForSelector('.sidebar', { timeout: 20000 })
  await expect(page).toHaveURL(/admin/)

  await page.context().storageState({ path: authFile })
})
