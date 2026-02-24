---
description: Import links from Bitly, Dub.co, Short.io, or CSV into URLsToGo. Switch providers in seconds.
---

# URLsToGo Import

Import links from another URL shortener or a CSV/JSON file.

## Arguments

The user may provide a file path as an argument (e.g., `/urlstogo import ~/Downloads/bitly-export.csv`). If not, ask them to provide the path to their export file.

## Supported Formats

Detect the source automatically by checking CSV column headers:

| Provider | Key Columns | Mapping |
|----------|------------|---------|
| **Bitly** | `long_url`, `link`, `title`, `created_at` | destination=long_url, customCode=extract from link, title=title |
| **Dub.co** | `key`, `url`, `title`, `clicks` | destination=url, customCode=key, title=title |
| **Short.io** | `originalURL`, `shortURL`, `title` | destination=originalURL, customCode=extract from shortURL, title=title |
| **Generic CSV** | `url` or `destination`, optional `slug` or `code` | destination=url/destination, customCode=slug/code |
| **JSON** | Array of objects with `destination` field | Direct mapping |

## Steps

1. **Read the file.** Use the Read tool to read the file the user specified. Determine if it's CSV or JSON by the file extension or content.

2. **Detect the source.** For CSV files, read the header row. Match column names against the provider table above. Tell the user: "Detected Bitly export format" (or whichever provider).

3. **Parse and map.** For each row/entry:
   - Extract the destination URL (required -- skip rows without one)
   - Extract the custom slug if available (strip the domain prefix from full short URLs)
   - Extract the title if available
   - Skip rows where the destination URL is empty or invalid

4. **Show preview.** Display the first 10 links in a table:
   ```
   | # | Slug | Destination | Title |
   |---|------|-------------|-------|
   | 1 | my-link | https://example.com | My Link |
   | 2 | (auto) | https://other.com | Other Page |
   ```
   Show total count: "Found 247 links to import."

5. **Confirm.** Ask the user: "Import these 247 links into URLsToGo? Any duplicate slugs will be skipped."

6. **Import in batches.** For each link, call the API:
   ```bash
   curl -s -X POST \
     -H "Authorization: Bearer $URLSTOGO_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"destination":"URL","customCode":"SLUG"}' \
     https://go.urlstogo.cloud/api/links
   ```
   Process sequentially. Track successes, failures, and skipped (duplicates).

7. **Report results.** Show:
   - "Imported 244 links successfully."
   - "3 skipped (duplicate slugs): my-link, old-page, test"
   - "0 failed."

## Error Handling

- If the file doesn't exist, tell the user and ask for the correct path.
- If the format isn't recognized, fall back to generic CSV mapping and ask the user to confirm the column mapping.
- If the API key is missing, tell the user to run `/urlstogo setup` first.
- If a link fails to create (not a duplicate), log the error and continue with the rest.
