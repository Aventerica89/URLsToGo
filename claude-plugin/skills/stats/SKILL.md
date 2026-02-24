---
description: View click analytics for your URLsToGo shortlinks.
---

# URLsToGo Stats

Show click analytics for a specific link or your account overview.

## Arguments

- If the user provides a link code (e.g., `my-slug` or `go.urlstogo.cloud/my-slug`), show stats for that specific link.
- If no argument, show the account overview (top links by clicks).

## Steps

### For a specific link:

1. **Extract the code.** If the user provided a full URL like `go.urlstogo.cloud/my-slug`, extract just `my-slug`. If they provided just the code, use it directly.

2. **Fetch analytics.** Run:
   ```bash
   curl -s -H "Authorization: Bearer $URLSTOGO_API_KEY" \
     "https://go.urlstogo.cloud/api/analytics/my-slug"
   ```

3. **Display results.** Parse the JSON and show a readable summary:
   - Total clicks
   - Clicks by country (top 5)
   - Clicks by device type
   - Clicks by browser (top 5)
   - Clicks by referrer (top 5)
   - Recent click trend (last 7 days if available)

### For account overview:

1. **Fetch overview stats.** Run:
   ```bash
   curl -s -H "Authorization: Bearer $URLSTOGO_API_KEY" \
     "https://go.urlstogo.cloud/api/stats"
   ```

2. **Fetch top links.** Run:
   ```bash
   curl -s -H "Authorization: Bearer $URLSTOGO_API_KEY" \
     "https://go.urlstogo.cloud/api/links?sort=clicks&order=desc&limit=10"
   ```

3. **Display results.** Show:
   - Total links
   - Total clicks (all time)
   - Top 10 links by clicks (code, destination, click count)
