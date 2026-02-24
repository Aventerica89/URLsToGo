---
description: Create a URLsToGo shortlink from the command line.
---

# URLsToGo Create Link

Create a new shortlink.

## Arguments

The user may provide arguments after the command. Parse them:
- First argument or a URL in the text = destination URL (required)
- `--slug <slug>` or `--code <code>` = custom short code (optional)
- `--category <name>` = category to file under (optional)

If no destination URL is provided, ask the user for it.

## Steps

1. **Get the API key.** Check for `URLSTOGO_API_KEY` in the environment or `.env`/`.env.local`. If not found, tell the user to run `/urlstogo setup` first.

2. **Build the request body.** Construct a JSON payload:
   ```json
   {
     "destination": "https://example.com",
     "customCode": "my-slug",
     "category": "dev"
   }
   ```
   Only include `customCode` and `category` if the user provided them. If no custom slug, URLsToGo auto-generates one.

3. **Create the link.** Run:
   ```bash
   curl -s -X POST \
     -H "Authorization: Bearer $URLSTOGO_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"destination":"URL","customCode":"SLUG","category":"CAT"}' \
     https://go.urlstogo.cloud/api/links
   ```

4. **Show the result.** Parse the JSON response and display:
   - Short URL: `go.urlstogo.cloud/{code}`
   - Destination: the original URL
   - Category: if assigned

   If the API returns an error (duplicate slug, invalid URL), show the error message clearly.
