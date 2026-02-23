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
3. Copy styles to `src/index.js` when ready
4. Push to main to deploy

### Database

- **D1 database name:** `url-shortener`
- **Tables:** links, categories, tags, link_tags, api_keys
- **Multi-user:** Each user's data is isolated by `user_email`

### Remember

- Merging to `main` = automatic deploy
- Schema changes go in `migrations.sql`
- Never ask user to run wrangler commands or edit Cloudflare dashboard

---

## HELP HUB (February 2026)

### Overview

Three-tab help/onboarding section added to the admin dashboard: Getting Started, Feature Guide, Connections Guide.

### Navigation

- **URL hash:** `#help` opens the help view; `#help/feature-guide`, `#help/connections` deep-link to specific tabs
- **Nav:** Help link added to sidebar and mobile bottom nav
- **Behavior:** `history.replaceState` used (not `location.hash =`) to avoid triggering `hashchange` feedback loops

### Key Code Locations

| Location | Purpose |
|----------|---------|
| `src/index.js` | `showHelpView()` function — renders the three-tab help panel |
| `src/index.js` | `handleHashChange()` — routes `#help/*` and `#settings/*` hash patterns |
| `src/index.js` | `initDeepLinks()` — called on page load to handle initial hash state |

### Layout Fix

Help view is a sibling to `<main class="main">` inside `.app-layout` (flex container). Needs same flex props as settings view: `flex: 1; margin-left: 256px`. Hiding `.main` when help is open (same pattern as settings).

---

## URL HASH DEEP LINKING (February 2026)

### Pattern

SPA navigation state stored in URL hash. Pattern: `#section/subsection`

Examples:
- `#settings/api-keys` — opens settings, API Keys tab active
- `#settings/git-sync` — opens settings, Git Sync tab active
- `#help/feature-guide` — opens help, Feature Guide tab active
- `#help/connections` — opens help, Connections Guide tab active

### Implementation Notes

- Use `history.replaceState(null, '', '#hash')` NOT `location.hash = '#hash'`
- `location.hash =` triggers `hashchange` event → infinite loop if handler re-navigates
- `replaceState` updates URL bar silently without firing events
- `hashchange` listener handles browser back/forward navigation

---

## FAVORITES (February 2026)

### Overview

Users can star/unstar individual links. Favorites persist in D1.

### Database

`is_favorite` column (INTEGER DEFAULT 0) on `links` table — added in `migrations.sql`.

### API

```
POST /api/links/:code/favorite    { favorite: true|false }
GET  /api/links?favorite=true     # filter to favorites only
```

### Key Code Locations

| Location | Purpose |
|----------|---------|
| `migrations.sql` | `ALTER TABLE links ADD COLUMN is_favorite INTEGER DEFAULT 0` |
| `src/index.js` | Favorite toggle endpoint, links query filter |
| `src/index.js` | Star icon render in links table row |

---

## DYNAMIC PREVIEW LINKS (February 2026)

### Overview

Automatically update URLsToGo shortlinks when preview deployments complete. Works with Vercel, Cloudflare Pages, and GitHub Pages.

### How It Works

1. User pushes code to a preview branch
2. GitHub Actions triggers deployment
3. Deployment completes on platform (Vercel/Cloudflare/GitHub Pages)
4. Workflow calls URLsToGo API to update `{repo-name}--preview` shortlink
5. Shortlink now points to latest preview URL

### Architecture

- **Pattern:** `go.urlstogo.cloud/{repo-name}--preview`
- **Example:** `go.urlstogo.cloud/bricks-cc--preview`
- **API Endpoint:** `PUT /api/preview-links/{code}` (requires API key auth)
- **Database:** Links table has `is_preview_link` column (INTEGER, default 0)

### Key Code Locations

| Location | Purpose |
|----------|---------|
| `src/index.js:~567-630` | Preview links API endpoint (PUT /api/preview-links/:code) |
| `migrations.sql:97` | is_preview_link column added to links table |
| `templates/update-preview-link.yml` | Reusable GitHub Actions workflow |
| `docs/preview-links.md` | Full documentation and setup guide |

### API Endpoint

**Request:**
```
PUT /api/preview-links/{code}
Authorization: Bearer utg_xxxxx
Content-Type: application/json

{
  "destination": "https://app-git-branch-user.vercel.app"
}
```

**Requirements:**
- Code must end with `--preview`
- Must be authenticated with valid API key
- Creates new link if doesn't exist, updates if exists
- Only owner can update existing preview link

**Response:**
```json
{
  "success": true,
  "action": "created", // or "updated"
  "code": "my-app--preview",
  "destination": "https://app-git-branch-user.vercel.app",
  "url": "https://go.urlstogo.cloud/my-app--preview"
}
```

### Setup for New Repos

To add dynamic preview links to a new repository:

1. **Create API Key** (in URLsToGo admin):
   - Go to go.urlstogo.cloud/admin → API Keys
   - Create key with name like "bricks-cc-preview"
   - Save the key (format: `utg_xxxxxxx...`)

2. **Add GitHub Secret** (in project repo):
   - Go to repo Settings → Secrets → Actions
   - Add `URLSTOGO_API_KEY` with the key from step 1

3. **Copy Workflow Template**:
   ```bash
   cp templates/update-preview-link.yml /path/to/project/.github/workflows/
   ```

4. **Push to test**:
   - Workflow auto-detects repo name and platform
   - Creates/updates `{repo-name}--preview` link
   - No customization needed for basic setup

### Supported Platforms

| Platform | Detection Method | Preview URL Pattern |
|----------|-----------------|-------------------|
| Vercel | Auto (vercel.json) | `{repo}-git-{branch}-{owner}.vercel.app` |
| Cloudflare Pages | Auto (wrangler.toml) | `{branch}.{project}.pages.dev` |
| GitHub Pages | Auto (.github/workflows/pages.yml) | `{owner}.github.io/{repo}` |

### User's Projects

- **bricks-cc** (Vercel): `go.urlstogo.cloud/bricks-cc--preview`
- **jb-cloud-app-tracker** (TBD): `go.urlstogo.cloud/jb-cloud-app-tracker--preview`

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

---

## SHARED COLLECTIONS (February 2026)

### Overview

Owner can share a category as a public read-only dashboard. Clients get a styled page showing all links in that category. Owner can edit and curate the page inline without going back to admin.

### How It Works

1. Hover a category in the sidebar — share icon appears
2. Click it → share modal generates a `category_shares` token → URL: `go.urlstogo.cloud/share/{token}`
3. Share the URL with clients — no auth required to view
4. Owner visits the same URL while logged in → sees editing controls

### Routes

```
GET  /share/:token                    — Public share page (HTML)
GET  /api/shares/:token               — Public share data (JSON, no auth)
POST /api/categories/:slug/share      — Create share token (auth required)
GET  /api/categories/:slug/share      — Get existing token (auth required)
DELETE /api/categories/:slug/share    — Remove share (auth required)
PATCH /api/links/:code                — Partial update: title, description, is_featured, is_archived (auth required)
```

### Database

```
category_shares: id, token (UNIQUE), user_email, category_id, created_at
links.title:        TEXT DEFAULT NULL — display name shown above /shortcode
links.is_featured:  INTEGER DEFAULT 0 — jumps to Featured group at top (amber star)
links.is_archived:  INTEGER DEFAULT 0 — removed from client view, shown in owner-only table at bottom
```

### Share Page Features

| Feature | Owner | Client |
|---------|-------|--------|
| View Featured + All Links cards | Yes | Yes |
| View archived table | Yes | No |
| Edit title & description inline | Yes | No |
| Toggle Featured (star) | Yes | No |
| Archive / Restore links | Yes | No |
| Hero link count | Excludes archived | Excludes archived |

### Owner Editing

Owner is detected server-side: `userEmail === share.user_email`. Owner gets:
- Purple "Owner editing mode" bar at top with `← Admin` link
- Per-card controls (top-right): star (Featured), pencil (Edit), box (Archive)
- Inline edit form expands in-card (title input + description textarea)
- All saves use `PATCH /api/links/:code` with `credentials: 'include'` (session cookie auth)
- Page reloads after star/archive toggles; edit saves patch DOM in place

### Key Code Locations

| Location | Purpose |
|----------|---------|
| `src/index.js:~277` | `GET /share/:token` route — queries links with title, is_featured, is_archived |
| `src/index.js:~647` | `PATCH /api/links/:code` — partial update endpoint |
| `src/index.js:~9087` | `getSharePageHTML(share, links, isOwner)` — full share page renderer |
| `migrations.sql` | `category_shares` table + `is_featured`, `is_archived`, `title` ALTER TABLEs |

### Routing Guard

Short-code redirect handler excludes share paths:
```javascript
if (path && !path.startsWith('admin') && !path.startsWith('api/') && !path.startsWith('share/')) {
```

Category DELETE handler guards against eating share DELETE requests:
```javascript
if (path.startsWith('api/categories/') && !path.endsWith('/share') && request.method === 'DELETE') {
```

### CSS / Design

- Dark page: `#09090b` bg, `#111113` cards, `#8b5cf6` purple accent
- Featured section: amber (`#f59e0b`) star icon, amber border on cards
- Archived section: owner-only compact table, `#0d0d0f` row bg, muted zinc palette
- Restore button: zinc default → purple hover
- All inline CSS (no external stylesheets) — standalone page, no CSS variable dependencies
