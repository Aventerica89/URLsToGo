# Claude Instructions for URLsToGo

## CRITICAL: Deployment is Fully Automatic

**DO NOT** tell the user to manually run database migrations or deploy via dashboard.

### How Deployment Works

1. **Push to `main` branch** triggers GitHub Actions
2. GitHub Actions automatically:
   - Runs `migrations.sql` against D1 database
   - Deploys worker code via `wrangler deploy`
3. **No manual steps required** after initial GitHub secrets setup

### Workflow Location

`.github/workflows/deploy.yml` handles everything:
- D1 migrations via: `wrangler d1 execute url-shortener --remote --file=migrations.sql`
- Worker deployment via: `wrangler deploy`

### Adding Schema Changes

1. Add SQL to `migrations.sql` using `CREATE TABLE IF NOT EXISTS` or `CREATE INDEX IF NOT EXISTS`
2. Push to main
3. Done - migrations run automatically

### One-Time Setup (Already Done)

User only needs to set these GitHub secrets once:
- `CLOUDFLARE_API_TOKEN` - with D1 Edit permission
- `CLOUDFLARE_ACCOUNT_ID` - from Cloudflare dashboard

### Files

| File | Purpose |
|------|---------|
| `src/index.js` | Main worker (npm-based, uses @clerk/backend) |
| `worker-multiuser.js` | Legacy file (kept for reference, not deployed) |
| `package.json` | npm dependencies (@clerk/backend, wrangler) |
| `migrations.sql` | Auto-runs on every deploy |
| `schema-multiuser.sql` | Full schema reference |
| `design-system.html` | UI playground for testing changes |
| `.github/workflows/deploy.yml` | CI/CD pipeline (includes npm ci) |

---

## CLERK AUTHENTICATION (January 2026)

### Overview

Replaced Cloudflare Access with Clerk for authentication. Provides custom-branded login UI with Google OAuth.

### Architecture

- **Frontend:** Clerk JS SDK via CDN (`@clerk/clerk-js@5`)
- **Backend:** Official `@clerk/backend` SDK for JWT verification
- **OAuth:** Google sign-in configured in Clerk dashboard

### Environment Variables (Cloudflare Dashboard)

| Variable | Type | Description |
|----------|------|-------------|
| `CLERK_PUBLISHABLE_KEY` | Text | `pk_test_...` or `pk_live_...` |
| `CLERK_SECRET_KEY` | Secret | `sk_test_...` or `sk_live_...` |

**Important:** `keep_vars = true` in wrangler.toml preserves these during deploy.

### Clerk Dashboard Settings

- **App URL:** urlstogo.cloud
- **Clerk Domain:** fit-ocelot-92.clerk.accounts.dev
- **SSO:** Google OAuth enabled with shared credentials

### Key Code Locations

| Location | Purpose |
|----------|---------|
| `src/index.js:1-3` | @clerk/backend import |
| `src/index.js:~815-890` | JWT verification with verifyToken |
| `src/index.js:~1400-1700` | Login/signup page HTML (getAuthPageHTML) |
| `src/index.js:~4400-4430` | Admin page Clerk initialization |

### Pending Migration

User switched from Cloudflare Access to Clerk. Links are associated with old email. To transfer:

```sql
-- Run in Cloudflare D1 Console (Storage & Databases → D1 → url-shortener → Console)
UPDATE links SET user_email = 'NEW_EMAIL' WHERE user_email = 'admin@jbmdcreations.com';
UPDATE categories SET user_email = 'NEW_EMAIL' WHERE user_email = 'admin@jbmdcreations.com';
UPDATE tags SET user_email = 'NEW_EMAIL' WHERE user_email = 'admin@jbmdcreations.com';
```

Replace `NEW_EMAIL` with the user's Clerk/Google email.

### Design System

The UI uses Shadcn-style CSS variables. To test UI changes:
1. Edit `design-system.html`
2. Open in browser to preview
3. Copy styles to `worker-multiuser.js` when ready
4. Push to main to deploy

### Database

- **D1 database name:** `url-shortener`
- **Tables:** links, categories, tags, link_tags
- **Multi-user:** Each user's data is isolated by `user_email`

### Remember

- Merging to `main` = automatic deploy
- Schema changes go in `migrations.sql`
- Never ask user to run wrangler commands or edit Cloudflare dashboard

---

## ARTIFACT MANAGER APP (January 2026)

### What It Is

A **separate** Cloudflare Worker app for tracking Claude.ai artifacts. Lives in `artifacts-app/` directory.

### Architecture - Two Separate Apps

| App | Directory | Worker Name | D1 Database ID | URL |
|-----|-----------|-------------|----------------|-----|
| URL Shortener | root | `url-shortener` | (see wrangler.toml) | (your custom domain) |
| Artifact Manager | `artifacts-app/` | `artifact-manager` | (see artifacts-app/wrangler.toml) | (your-subdomain.workers.dev) |

### Deployment - Two Separate Workflows

- `.github/workflows/deploy.yml` - URL shortener (any push to main)
- `.github/workflows/deploy-artifacts.yml` - Artifact Manager (only `artifacts-app/**` changes)

### Artifact Manager Features

- Track published artifacts (claude.site URLs)
- Track downloaded artifacts (local files)
- Collections (folders) and Tags
- Search, favorites, filtering
- Export/Import JSON backup
- Multi-user via Cloudflare Access
- Dark Shadcn-style UI

### Artifact Manager Files

| File | Purpose |
|------|---------|
| `artifacts-app/worker.js` | Main worker (~2100 lines) |
| `artifacts-app/migrations.sql` | D1 schema (collections, artifacts, tags, artifact_tags) |
| `artifacts-app/wrangler.toml` | Worker config |
| `artifacts-app/README.md` | Setup docs |

### Security (Fixed via Gemini Review)

All XSS vulnerabilities fixed:
- `escapeAttr()` for JS string contexts (onclick handlers)
- `escapeHtmlServer()` for server-side templating
- `escapeHtml()` for client-side innerHTML

### Known Issues / TODO

1. **Logout button** - Email in sidebar footer needs logout functionality
2. **Import button** - Needs testing (uploads JSON to restore artifacts)
3. **Default collections** - Auto-creates on first visit via `/api/init`

### User Info

- Account: (see Cloudflare dashboard)
- Email: (from Cloudflare Access JWT)
- Workers subdomain: (your-subdomain.workers.dev)

---

## CHROME EXTENSION (January 2026)

### What It Is

A Chrome extension that adds a "Save to Artifact Manager" button on Claude.ai, allowing one-click saving of artifacts.

### Location

`chrome-extension/` directory (not deployed - local browser extension)

### Files

| File | Purpose |
|------|---------|
| `chrome-extension/manifest.json` | Extension configuration (MV3) |
| `chrome-extension/content.js` | Runs on Claude.ai, adds save buttons |
| `chrome-extension/content.css` | Styles for save buttons |
| `chrome-extension/background.js` | Service worker for API calls |
| `chrome-extension/popup.html` | Extension popup UI |
| `chrome-extension/popup.js` | Popup logic |
| `chrome-extension/generate-icons.html` | Tool to generate PNG icons |
| `chrome-extension/README.md` | Installation & usage docs |

### Installation

1. Open `chrome-extension/generate-icons.html` in browser
2. Download icons and place in `chrome-extension/icons/`
3. Go to `chrome://extensions/`
4. Enable Developer Mode
5. Click "Load unpacked" and select `chrome-extension/` folder
6. Configure Artifact Manager URL in extension popup

### How It Works

1. Content script detects artifacts on Claude.ai pages
2. Adds purple "Save" button to each artifact
3. Click sends artifact data to Artifact Manager API
4. CORS headers on API allow cross-origin requests from claude.ai

### CORS Configuration

The Artifact Manager worker includes CORS headers to allow the extension to make API calls from claude.ai:

```javascript
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': 'https://claude.ai',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Cf-Access-Jwt-Assertion',
  'Access-Control-Allow-Credentials': 'true'
};
```

### Limitations

- Claude.ai UI changes may require content script updates
- User must be logged into Cloudflare Access first
- Artifact detection is heuristic-based (may miss some artifacts)
