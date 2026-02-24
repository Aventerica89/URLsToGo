# URLsToGo Claude Code Plugin — Design

**Date:** 2026-02-24
**Status:** Approved
**Author:** JB + Claude

---

## Overview

A Claude Code plugin that ships inside the URLsToGo repo. Developers install it to automate URLsToGo setup, link management, competitor migration, and analytics — all from the CLI.

**Installation:**
```
/plugin marketplace add Aventerica89/URLsToGo
/plugin install urlstogo@urlstogo-marketplace
```

## Target User

Developers who use Claude Code. Starting with developer-focused automation commands, expanding to onboarding and AI features later.

## Distribution

Plugin lives inside the URLsToGo repo at `claude-plugin/`. Ships with the product. Updates come with repo updates. Users add the marketplace via `Aventerica89/URLsToGo`.

## Authentication

`URLSTOGO_API_KEY` environment variable. User creates a write-scoped key in the URLsToGo dashboard, stores it once. Every command reads it automatically. The `/urlstogo setup` command walks through this.

---

## v1 Commands

### /urlstogo setup
Interactive first-run wizard:
1. Prompts for API key (or detects from env)
2. Validates against `GET /api/links` (confirms key works)
3. Stores as `URLSTOGO_API_KEY` in project `.env` or env var
4. Confirms connection with account info

### /urlstogo setup-preview (Hero Command)
One command to wire up automatic preview link updates:
1. Detects deployment platform (Vercel/Cloudflare Pages/GitHub Pages) from config files
2. Generates `.github/workflows/update-preview-link.yml`
3. Stores API key as `URLSTOGO_API_KEY` GitHub Actions secret via `gh secret set`
4. Pushes the workflow file
5. Confirms: "Done. Your preview link `go.urlstogo.cloud/{repo}--preview` will update on every deploy."

### /urlstogo create-link
Create a shortlink from CLI:
- Accepts: destination URL, optional custom slug, optional category
- Returns: the short URL (`go.urlstogo.cloud/my-slug`)
- Uses: `POST /api/links`

### /urlstogo stats
Show click analytics:
- For a specific link: `go.urlstogo.cloud/my-slug` or just `my-slug`
- Or all links (top 10 by clicks)
- Shows: total clicks, geo breakdown, device/browser, referrer, time series
- Uses: `GET /api/analytics/:code` and `GET /api/analytics/overview`

### /urlstogo import (Competitor Killer)
Bulk import links from other URL shortener providers:

| Provider | Export Format | Detection Method |
|----------|-------------|-----------------|
| Bitly | CSV with `long_url`, `link`, `created_at` | Column headers |
| Dub.co | CSV with `key`, `url`, `clicks` | Column headers |
| Short.io | CSV with `originalURL`, `shortURL` | Column headers |
| TinyURL | No bulk export — manual URL list | User pastes URLs |
| Generic | CSV with `url`/`destination` + optional `slug` | Fallback |

Flow:
1. User provides file path or pastes data
2. Plugin auto-detects source format
3. Shows preview table (first 10 rows)
4. Maps columns to URLsToGo fields
5. Confirms count and creates via `POST /api/links` in batches
6. Reports: "Imported 247 links. 3 skipped (duplicate slugs)."

**In-app complement:** Dashboard also gets drag-and-drop CSV upload on the import page (web feature, separate from plugin).

---

## v1 Agent

### urlstogo-assistant
General-purpose helper agent that knows the full URLsToGo API. Handles:
- Questions about features ("how do I share a category?")
- Data queries ("what's my most clicked link this week?")
- Multi-step operations that don't fit a single command

---

## Plugin File Structure

```
URLsToGo/
  claude-plugin/
    .claude-plugin/
      plugin.json            # Plugin manifest (name, version, description)
      marketplace.json       # Marketplace catalog
    skills/
      setup/SKILL.md         # /urlstogo setup
      setup-preview/SKILL.md # /urlstogo setup-preview
      create-link/SKILL.md   # /urlstogo create-link
      stats/SKILL.md         # /urlstogo stats
      import/SKILL.md        # /urlstogo import
    agents/
      urlstogo-assistant.md  # General helper agent
```

---

## Landing Page

New section: "Works with Claude Code" featuring:
- Terminal mockup showing `/urlstogo setup-preview` in action
- One-command pitch: "Set up preview links in 30 seconds"
- Installation instructions
- Link to plugin docs

---

## Future Roadmap (v2+)

### Dev URL Dashboard (v2)
Shared collection of local dev URLs with live/dead status indicators:
- Green = responding (200)
- Yellow = slow (>2s) or non-200
- Red = unreachable
- Cloaked behind a short link: `go.urlstogo.cloud/my-dev-urls`
- Share with Claude or teammates as working context
- Health checks via periodic HEAD requests

### AI Chatbot in Dashboard (v2)
In-app chatbot (Claude-powered) for:
- Natural language link creation ("shorten my Vercel preview")
- Click data analysis ("which links got the most traffic this month?")
- Category suggestions based on link patterns
- Bulk reorganization ("move all GitHub links to a Dev category")
- Onboarding assistance for new users

### Additional Commands (v1.x)
- `/urlstogo share` — Create/manage shared collections from CLI
- `/urlstogo domains` — Custom domain setup wizard
- `/urlstogo export` — Export for migration away (builds trust)
- `/urlstogo list` — List links with filters (category, tag, favorites)

---

## API Endpoints Used

| Command | Endpoints |
|---------|-----------|
| setup | `GET /api/links` (validation) |
| setup-preview | `POST /api/keys`, `PUT /api/preview-links/:code` |
| create-link | `POST /api/links` |
| stats | `GET /api/analytics/:code`, `GET /api/analytics/overview`, `GET /api/stats` |
| import | `POST /api/links` (batch) |
| assistant agent | All read endpoints + write endpoints as needed |

---

## Success Criteria

- User can go from zero to working preview links in under 2 minutes
- Import from Bitly works with their standard CSV export
- Plugin installs cleanly from the marketplace
- Featured on landing page with clear installation path
