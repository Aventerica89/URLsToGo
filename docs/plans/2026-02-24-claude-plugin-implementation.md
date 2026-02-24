# URLsToGo Claude Code Plugin — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Claude Code plugin inside the URLsToGo repo that gives developers `/urlstogo` commands for preview link setup, link creation, analytics, and competitor import.

**Architecture:** Plugin uses the official Claude Code plugin structure (`.claude-plugin/plugin.json` + `marketplace.json` + SKILL.md files). Each command is a skill that instructs Claude to call the URLsToGo REST API using `curl` via Bash. Auth via `URLSTOGO_API_KEY` env var.

**Tech Stack:** Claude Code plugin system, SKILL.md files (markdown), URLsToGo REST API, `curl`, `gh` CLI for GitHub secrets.

---

### Task 1: Scaffold Plugin Directory and Manifests

**Files:**
- Create: `claude-plugin/.claude-plugin/plugin.json`
- Create: `claude-plugin/.claude-plugin/marketplace.json`

**Step 1: Create plugin manifest**

Create `claude-plugin/.claude-plugin/plugin.json`:

```json
{
  "name": "urlstogo",
  "description": "URLsToGo CLI tools — create shortlinks, set up preview links, import from competitors, and view analytics from Claude Code.",
  "version": "1.0.0",
  "author": {
    "name": "JBMD Creations",
    "email": "jb@jbcloud.app"
  },
  "homepage": "https://urlstogo.cloud",
  "repository": "https://github.com/Aventerica89/URLsToGo",
  "license": "MIT",
  "keywords": ["url-shortener", "shortlinks", "preview-links", "analytics", "developer-tools"]
}
```

**Step 2: Create marketplace catalog**

Create `claude-plugin/.claude-plugin/marketplace.json`:

```json
{
  "name": "urlstogo-marketplace",
  "owner": {
    "name": "JBMD Creations",
    "email": "jb@jbcloud.app"
  },
  "metadata": {
    "description": "URLsToGo developer tools for Claude Code",
    "version": "1.0.0"
  },
  "plugins": [
    {
      "name": "urlstogo",
      "source": "./",
      "description": "URLsToGo CLI tools — create shortlinks, set up preview links, import from competitors, and view analytics."
    }
  ]
}
```

Note: `"source": "./"` points to the `claude-plugin/` directory itself (the marketplace.json is inside `.claude-plugin/` which is inside `claude-plugin/`).

**Step 3: Create skill and agent directories**

```bash
mkdir -p claude-plugin/skills/setup
mkdir -p claude-plugin/skills/setup-preview
mkdir -p claude-plugin/skills/create-link
mkdir -p claude-plugin/skills/stats
mkdir -p claude-plugin/skills/import
mkdir -p claude-plugin/agents
```

**Step 4: Commit scaffold**

```bash
git add claude-plugin/
git commit -m "feat: scaffold URLsToGo Claude Code plugin structure"
```

---

### Task 2: /urlstogo setup Command

**Files:**
- Create: `claude-plugin/skills/setup/SKILL.md`

**Step 1: Write the setup skill**

Create `claude-plugin/skills/setup/SKILL.md`:

```markdown
---
description: Connect Claude Code to your URLsToGo account. Sets up API key for all other /urlstogo commands.
---

# URLsToGo Setup

Connect this project to your URLsToGo account.

## Steps

1. **Check for existing API key.** Look for `URLSTOGO_API_KEY` in the environment, `.env`, or `.env.local` files in the current project. If found, skip to step 3.

2. **Ask the user for their API key.** Tell them:
   - Go to https://go.urlstogo.cloud/admin and sign in
   - Click Settings in the sidebar, then API Keys
   - Create a new key with **Write** scope
   - Copy the key (starts with `utg_`)
   - Paste it here

3. **Validate the key.** Run this curl command to confirm it works:

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $URLSTOGO_API_KEY" \
  https://go.urlstogo.cloud/api/links?limit=1
```

If the response is `200`, the key is valid. If `401` or `403`, tell the user the key is invalid and ask them to try again.

4. **Store the key.** If the project has a `.env` or `.env.local` file, append `URLSTOGO_API_KEY=utg_...` to it. If neither exists, create `.env.local` with the key. Make sure `.env.local` is in `.gitignore`.

5. **Confirm success.** Tell the user:
   - "Connected to URLsToGo! Your API key is stored in `.env.local`."
   - "You can now use `/urlstogo create-link`, `/urlstogo stats`, `/urlstogo setup-preview`, and `/urlstogo import`."
```

**Step 2: Commit**

```bash
git add claude-plugin/skills/setup/
git commit -m "feat: add /urlstogo setup command"
```

---

### Task 3: /urlstogo setup-preview Command (Hero)

**Files:**
- Create: `claude-plugin/skills/setup-preview/SKILL.md`

**Step 1: Write the setup-preview skill**

Create `claude-plugin/skills/setup-preview/SKILL.md`:

```markdown
---
description: Set up automatic preview link updates — one command to wire GitHub Actions, API key, and workflow file.
---

# URLsToGo Setup Preview Links

Wire up automatic preview link updates so `go.urlstogo.cloud/{repo}--preview` always points to your latest deployment.

## Prerequisites

- `gh` CLI must be installed and authenticated (`gh auth status`)
- Project must be a git repo with a GitHub remote
- User must have a URLsToGo API key (run `/urlstogo setup` first if not)

## Steps

1. **Check prerequisites.** Verify `gh` is installed by running `gh auth status`. If not authenticated, tell the user to run `gh auth login` first. Also check that the current directory is a git repo with a GitHub remote by running `git remote get-url origin`.

2. **Get the URLsToGo API key.** Check for `URLSTOGO_API_KEY` in the environment or `.env`/`.env.local`. If not found, tell the user to run `/urlstogo setup` first and stop.

3. **Detect the deployment platform.** Check these files in order:
   - `vercel.json` or `.vercel/project.json` exists → **Vercel**
   - `wrangler.toml` exists → **Cloudflare Pages**
   - `.github/workflows/pages.yml` or `.github/workflows/deploy-pages.yml` exists → **GitHub Pages**
   - None found → ask the user which platform they use

4. **Get the repo name.** Parse it from the GitHub remote URL:
   ```bash
   basename -s .git $(git remote get-url origin)
   ```

5. **Store the API key as a GitHub secret.** Run:
   ```bash
   echo "$URLSTOGO_API_KEY" | gh secret set URLSTOGO_API_KEY
   ```
   If this fails, tell the user they may not have permission to set secrets on this repo.

6. **Create the workflow file.** Create `.github/workflows/update-preview-link.yml` with the following content. This is the standard URLsToGo preview link workflow:

   ```yaml
   name: Update Preview Link

   on:
     deployment_status:
     push:
       branches: [preview, staging, 'preview/**', 'feat/**']
     workflow_dispatch:

   env:
     REPO_NAME: ${{ github.event.repository.name }}
     URLSTOGO_DOMAIN: go.urlstogo.cloud
     DEPLOYMENT_PLATFORM: auto

   jobs:
     update-preview-link:
       name: Update Preview Link
       runs-on: ubuntu-latest
       if: |
         github.event_name == 'push' ||
         (github.event_name == 'deployment_status' && github.event.deployment_status.state == 'success') ||
         github.event_name == 'workflow_dispatch'
       steps:
         - uses: actions/checkout@v4

         - name: Detect deployment URL
           id: detect-url
           env:
             GH_REF_NAME: ${{ github.ref_name }}
             GH_REPO_NAME: ${{ github.event.repository.name }}
             GH_REPO_OWNER: ${{ github.repository_owner }}
             GH_EVENT_NAME: ${{ github.event_name }}
             GH_DEPLOYMENT_URL: ${{ github.event.deployment_status.environment_url }}
             PLATFORM: ${{ env.DEPLOYMENT_PLATFORM }}
           run: |
             set -euo pipefail
             DEPLOYMENT_URL=""
             if [ "$PLATFORM" = "auto" ]; then
               if [ -f "vercel.json" ] || [ -f ".vercel/project.json" ]; then
                 PLATFORM="vercel"
               elif [ -f "wrangler.toml" ]; then
                 PLATFORM="cloudflare-pages"
               elif [ -f ".github/workflows/pages.yml" ] || [ -f ".github/workflows/deploy-pages.yml" ]; then
                 PLATFORM="github-pages"
               fi
             fi
             slugify() {
               tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-//' | sed 's/-$//'
             }
             case "$PLATFORM" in
               vercel)
                 if [ "$GH_EVENT_NAME" = "deployment_status" ] && [ -n "$GH_DEPLOYMENT_URL" ]; then
                   DEPLOYMENT_URL="$GH_DEPLOYMENT_URL"
                 else
                   REPO_SLUG=$(echo "$GH_REPO_NAME" | slugify)
                   BRANCH_SLUG=$(echo "$GH_REF_NAME" | slugify)
                   OWNER_SLUG=$(echo "$GH_REPO_OWNER" | slugify)
                   DEPLOYMENT_URL="https://${REPO_SLUG}-git-${BRANCH_SLUG}-${OWNER_SLUG}.vercel.app"
                 fi ;;
               cloudflare-pages)
                 CF_PROJECT=$(echo "$GH_REPO_NAME" | slugify)
                 BRANCH_SLUG=$(echo "$GH_REF_NAME" | slugify)
                 DEPLOYMENT_URL="https://${BRANCH_SLUG}.${CF_PROJECT}.pages.dev" ;;
               github-pages)
                 OWNER_SLUG=$(echo "$GH_REPO_OWNER" | slugify)
                 REPO_SLUG=$(echo "$GH_REPO_NAME" | slugify)
                 DEPLOYMENT_URL="https://${OWNER_SLUG}.github.io/${REPO_SLUG}" ;;
               *)
                 echo "Could not detect platform. Set DEPLOYMENT_PLATFORM in the workflow."
                 exit 1 ;;
             esac
             { echo "url=$DEPLOYMENT_URL"; echo "platform=$PLATFORM"; } >> "$GITHUB_OUTPUT"

         - name: Update URLsToGo preview link
           env:
             URLSTOGO_API_KEY: ${{ secrets.URLSTOGO_API_KEY }}
             PREVIEW_CODE: ${{ github.event.repository.name }}--preview
             DEPLOYMENT_URL: ${{ steps.detect-url.outputs.url }}
           run: |
             set -euo pipefail
             RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
               -H "Authorization: Bearer $URLSTOGO_API_KEY" \
               -H "Content-Type: application/json" \
               --data "$(printf '{"destination":"%s"}' "$DEPLOYMENT_URL")" \
               "https://go.urlstogo.cloud/api/preview-links/${PREVIEW_CODE}")
             HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
             if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
               echo "Preview link updated: https://go.urlstogo.cloud/${PREVIEW_CODE}"
             else
               echo "Failed (HTTP $HTTP_CODE)"; exit 1
             fi
   ```

7. **Commit and push.** Stage the workflow file and commit:
   ```bash
   git add .github/workflows/update-preview-link.yml
   git commit -m "feat: add URLsToGo preview link workflow"
   git push
   ```

8. **Confirm success.** Tell the user:
   - "Done! Your preview link is set up."
   - "Short URL: `go.urlstogo.cloud/{repo-name}--preview`"
   - "It will auto-update on every deployment to {detected platform}."
   - "Test it by pushing to a preview branch or running the workflow manually."
```

**Step 2: Commit**

```bash
git add claude-plugin/skills/setup-preview/
git commit -m "feat: add /urlstogo setup-preview command (hero feature)"
```

---

### Task 4: /urlstogo create-link Command

**Files:**
- Create: `claude-plugin/skills/create-link/SKILL.md`

**Step 1: Write the create-link skill**

Create `claude-plugin/skills/create-link/SKILL.md`:

```markdown
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
```

**Step 2: Commit**

```bash
git add claude-plugin/skills/create-link/
git commit -m "feat: add /urlstogo create-link command"
```

---

### Task 5: /urlstogo stats Command

**Files:**
- Create: `claude-plugin/skills/stats/SKILL.md`

**Step 1: Write the stats skill**

Create `claude-plugin/skills/stats/SKILL.md`:

```markdown
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
```

**Step 2: Commit**

```bash
git add claude-plugin/skills/stats/
git commit -m "feat: add /urlstogo stats command"
```

---

### Task 6: /urlstogo import Command

**Files:**
- Create: `claude-plugin/skills/import/SKILL.md`

**Step 1: Write the import skill**

Create `claude-plugin/skills/import/SKILL.md`:

```markdown
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
   - Extract the destination URL (required — skip rows without one)
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
```

**Step 2: Commit**

```bash
git add claude-plugin/skills/import/
git commit -m "feat: add /urlstogo import command (competitor migration)"
```

---

### Task 7: URLsToGo Assistant Agent

**Files:**
- Create: `claude-plugin/agents/urlstogo-assistant.md`

**Step 1: Write the agent definition**

Create `claude-plugin/agents/urlstogo-assistant.md`:

```markdown
---
name: urlstogo-assistant
description: URLsToGo helper — answers questions, queries data, manages links and categories via the API.
tools: Bash, Read, Grep, Glob
---

# URLsToGo Assistant

You are a helpful assistant for URLsToGo, a URL shortener running on Cloudflare Workers.

## Authentication

All API calls require the `URLSTOGO_API_KEY` environment variable. Check for it in the environment or in `.env`/`.env.local` files. If not found, tell the user to run `/urlstogo setup`.

Use it as a Bearer token:
```
Authorization: Bearer $URLSTOGO_API_KEY
```

## API Base URL

`https://go.urlstogo.cloud`

## Available API Endpoints

### Links
- `GET /api/links` — List links. Query params: `category`, `tag`, `favorite=true`, `search`, `sort`, `order`, `limit`, `offset`
- `POST /api/links` — Create link. Body: `{destination, customCode?, category?}`
- `PUT /api/links/:code` — Update link. Body: `{destination?, title?, description?}`
- `PATCH /api/links/:code` — Partial update. Body: `{title?, description?, is_featured?, is_archived?}`
- `DELETE /api/links/:code` — Delete link
- `POST /api/links/bulk-delete` — Delete multiple. Body: `{codes: [...]}`
- `POST /api/links/bulk-move` — Move to category. Body: `{codes: [...], category: "slug"}`
- `POST /api/links/:code/favorite` — Toggle favorite. Body: `{favorite: true|false}`

### Preview Links
- `PUT /api/preview-links/:code` — Create/update preview link (code must end with `--preview`). Body: `{destination}`

### Categories
- `GET /api/categories` — List categories with link counts
- `POST /api/categories` — Create category. Body: `{name, slug?}`
- `DELETE /api/categories/:slug` — Delete category

### Tags
- `GET /api/tags` — List all tags

### Analytics
- `GET /api/stats` — Account overview (total links, clicks, etc.)
- `GET /api/analytics/overview` — Dashboard analytics with period breakdown
- `GET /api/analytics/:code` — Per-link click analytics (geo, device, browser, referrer)

### Sharing
- `POST /api/categories/:slug/share` — Create public share for category
- `GET /api/categories/:slug/share` — Get share token
- `DELETE /api/categories/:slug/share` — Remove share

### Data
- `GET /api/export` — Export all links as JSON
- `POST /api/import` — Import links from JSON

### API Keys
- `GET /api/keys` — List API keys (session auth only)
- `POST /api/keys` — Create API key (session auth only)
- `DELETE /api/keys/:id` — Delete API key (session auth only)

## How to Help

- Answer questions about URLsToGo features by referencing the API docs above
- Query data using curl commands with the API key
- Help organize links (create categories, move links, tag links)
- Analyze click data and provide insights
- Help set up integrations (preview links, shared collections)

## Important Notes

- Always use `curl -s` for clean output
- Parse JSON responses with `python3 -c "import json,sys; ..."` or `jq` if available
- When creating links, destination URLs must include the protocol (https://)
- Preview link codes must end with `--preview`
- API key management (create/delete) requires session auth — direct users to the dashboard for those
```

**Step 2: Commit**

```bash
git add claude-plugin/agents/
git commit -m "feat: add urlstogo-assistant agent"
```

---

### Task 8: Test Plugin Locally

**Step 1: Add marketplace locally**

```bash
cd /Users/jb/URLsToGo
# In Claude Code:
/plugin marketplace add ./claude-plugin
```

**Step 2: Install the plugin**

```bash
/plugin install urlstogo@urlstogo-marketplace
```

**Step 3: Verify commands are available**

Try each command:
- `/urlstogo setup` — should prompt for API key
- `/urlstogo create-link https://example.com --slug test-plugin` — should create a link
- `/urlstogo stats` — should show account overview
- `/urlstogo import` — should ask for file path

**Step 4: Verify agent is available**

Ask: "What are my most clicked links?" — the urlstogo-assistant agent should handle it.

**Step 5: Clean up test link**

Delete the test link created in step 3.

**Step 6: Commit any fixes**

If any skills needed tweaking during testing, commit the fixes.

---

### Task 9: Update Marketplace Source for GitHub Distribution

**Files:**
- Modify: `claude-plugin/.claude-plugin/marketplace.json`

**Step 1: Verify marketplace.json source path**

The marketplace needs to work when users add it via `Aventerica89/URLsToGo`. The `.claude-plugin/marketplace.json` is inside `claude-plugin/`, so the marketplace root is `claude-plugin/`. The plugin source `"./"` should resolve to the `claude-plugin/` directory containing the skills and agents.

Test by temporarily removing the local marketplace and adding via the repo path structure. If the relative path doesn't resolve correctly, update to an explicit path.

**Step 2: Commit if changed**

```bash
git add claude-plugin/
git commit -m "fix: ensure marketplace source resolves for GitHub distribution"
```

---

### Task 10: Final Commit and Push

**Step 1: Verify all files exist**

```
claude-plugin/
  .claude-plugin/
    plugin.json
    marketplace.json
  skills/
    setup/SKILL.md
    setup-preview/SKILL.md
    create-link/SKILL.md
    stats/SKILL.md
    import/SKILL.md
  agents/
    urlstogo-assistant.md
```

**Step 2: Push to main**

```bash
git push origin main
```

This auto-deploys the URLsToGo worker (existing CI/CD) and makes the plugin available for marketplace installation.

**Step 3: Test remote installation**

In a separate project directory:
```bash
/plugin marketplace add Aventerica89/URLsToGo
/plugin install urlstogo@urlstogo-marketplace
/urlstogo setup
```

---

## Post-Implementation

After all tasks complete:
- Update CLAUDE.md with plugin section
- Update the marketing/plan.md to reference the plugin
- The landing page "Works with Claude Code" section is a separate task (v1.1)
