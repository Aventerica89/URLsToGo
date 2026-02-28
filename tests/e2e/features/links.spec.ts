import { test, expect } from '@playwright/test'

/**
 * Smoke tests for the links dashboard.
 *
 * These tests catch the class of bug where getUserEmail() returns a user ID
 * instead of an email, causing the /api/links query to return 0 results.
 *
 * Assumes the test account has at least 1 link stored.
 */
test.describe('Links dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin')
    // Wait for the links table to be present in the DOM
    await page.waitForSelector('#linksTable', { timeout: 15000 })
  })

  test('admin page loads and shows sidebar', async ({ page }) => {
    await expect(page.locator('.sidebar')).toBeVisible()
    await expect(page.locator('#linksTable')).toBeVisible()
  })

  test('links table is not empty after auth', async ({ page }) => {
    // Wait for rows — guards against the user_email mismatch bug
    // (empty table = getUserEmail returned wrong value, or API error)
    await page.waitForSelector('#linksTable tr[data-code]', { timeout: 10000 })
    const rows = page.locator('#linksTable tr[data-code]')
    await expect(rows.first()).toBeVisible()
    const count = await rows.count()
    expect(count).toBeGreaterThan(0)
  })

  test('API /api/links returns an array', async ({ page, request }) => {
    // Pull session cookies from the page context
    const cookies = await page.context().cookies()
    const cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join('; ')

    const res = await request.get('/api/links?sort=newest', {
      headers: { Cookie: cookieHeader },
    })

    expect(res.ok()).toBe(true)
    const body = await res.json()
    expect(Array.isArray(body)).toBe(true)
    expect(body.length).toBeGreaterThan(0)
  })

  test('tag filter chips are visible', async ({ page }) => {
    await expect(page.locator('#tagFilterChips')).toBeVisible()
    // "All" chip is always present
    await expect(page.locator('#tagFilterChips .tag-chip').first()).toContainText('All')
  })

  test('search filters links by code', async ({ page }) => {
    await page.waitForSelector('#linksTable tr[data-code]')
    const totalRows = await page.locator('#linksTable tr[data-code]').count()

    // Type a query that won't match anything
    await page.fill('#tableSearch', 'xyznonexistent_abc123')
    await page.waitForTimeout(300)

    const visibleRows = await page.locator('#linksTable tr[data-code]:visible').count()
    // Either 0 rows visible or table shows empty state
    expect(visibleRows).toBeLessThan(totalRows)
  })

  test('create link sheet opens', async ({ page }) => {
    await page.waitForSelector('#linksTable tr[data-code]')
    await page.click('button:has-text("Create Link")')
    // Bottom sheet or modal should appear
    await expect(page.locator('.sheet, .modal, [id*="create"], [id*="sheet"]').first()).toBeVisible({ timeout: 5000 })
  })
})
