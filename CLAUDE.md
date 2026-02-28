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

**Create a new migration file** — do NOT edit existing migration files (hookify rule enforces this).

1. Create `migrations-{feature}.sql` with `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`
2. Add a step to `deploy.yml` to run it:
   ```yaml
   command: d1 execute url-shortener --remote --file=migrations-{feature}.sql
   ```
3. Push to main — runs automatically

**Existing migration files (append-only reference):**
- `migrations.sql` — core schema
- `migrations-billing.sql` — Stripe subscriptions table

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
| `migrations.sql` | Core schema (append-only) |
| `migrations-billing.sql` | Stripe subscriptions schema |
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

Search `src/index.js` for: `getUserEmail`, `verifyToken`, `getAuthPageHTML`, `initClerk`

### Legacy Data Migration (if needed)

If links still show under `admin@jbmdcreations.com` (old Cloudflare Access email), run in D1 Console:
```sql
UPDATE links SET user_email = 'YOUR_GOOGLE_EMAIL' WHERE user_email = 'admin@jbmdcreations.com';
UPDATE categories SET user_email = 'YOUR_GOOGLE_EMAIL' WHERE user_email = 'admin@jbmdcreations.com';
UPDATE tags SET user_email = 'YOUR_GOOGLE_EMAIL' WHERE user_email = 'admin@jbmdcreations.com';
```

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
- Schema changes → create new migration file (see above)
- Never ask user to run wrangler commands or edit Cloudflare dashboard

---

## GIT WORKFLOW

**Cannot push directly to `main`** — branch is protected.

```bash
# Always work on a claude branch
git checkout -b claude/{feature}-{sessionID}
git add ... && git commit -m "feat: ..."
git push -u origin claude/{feature}-{sessionID}
gh pr create   # merge triggers auto-deploy
```

Admin URL: `urlstogo.cloud/admin` (NOT `go.urlstogo.cloud` — that's for shortlinks only)

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
   - Go to urlstogo.cloud/admin → API Keys
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

## STRIPE BILLING (February 2026)

### Plans

| Plan | Price | Links | Analytics |
|------|-------|-------|-----------|
| Free | $0 | 25 | None |
| Pro | $12/mo | 200 | Full (geo, device, browser) |

Limits defined in `src/index.js`: `const PLAN_LIMITS = { free: { links: 25 }, pro: { links: 200 } }`

### Stripe Resources

- **Product:** `prod_U3Qqpfwus7EuD9` (URLsToGo Pro)
- **Price:** `price_1T5Jz1H6aZ92e8Txu9tLJnRI` ($12/mo)
- **Webhook:** `we_1T5JzHH6aZ92e8TxrS4EWSNU` → `urlstogo.cloud/api/billing/webhook`

### Environment Variables (Cloudflare Dashboard — already set)

| Variable | Description |
|----------|-------------|
| `STRIPE_SECRET_KEY` | Live secret key |
| `STRIPE_WEBHOOK_SECRET` | Webhook signing secret (URLsToGo-specific) |
| `STRIPE_PRO_PRICE_ID` | `price_1T5Jz1H6aZ92e8Txu9tLJnRI` |

All keys in 1Password: App Dev vault, tagged `#urlstogo`.

### API Routes

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/api/billing/webhook` | Stripe HMAC | Subscription lifecycle |
| `GET` | `/api/billing/status` | Clerk | Current plan + usage |
| `POST` | `/api/billing/checkout` | Clerk | Start Stripe Checkout |
| `GET` | `/api/billing/portal` | Clerk | Manage/cancel subscription |

### Enforcement

- Link creation (`POST /api/links`) checks count vs `PLAN_LIMITS[plan].links`
- Returns `{ error: 'plan_limit', upgrade: true }` with HTTP 402 on limit hit
- Frontend shows upgrade modal; billing tab at `urlstogo.cloud/admin#billing`

### Key Code

Search `src/index.js` for: `getUserPlan`, `stripeRequest`, `verifyStripeSignature`, `showUpgradeModal`

---

## 1P-LOCAL-AUTH PLUGIN — UPSELL ANGLE (February 2026)

### What It Is

`1p-local-auth` is a free Claude Code plugin (published at `https://github.com/Aventerica89/1p-local-auth`) that helps developers manage local dev OAuth credentials via 1Password. It provides 5 skills: `/setup-local-auth`, `/auth-status`, `/auth-inject`, `/auth-rotate`, `/teardown-local-auth`.

Target audience: developers building OAuth-enabled apps with Better Auth or NextAuth v5 — Google, GitHub, Todoist providers.

### The Upsell Connection

These developers are the **core URLsToGo buyer persona**:
- They're building apps that need URL management (tracking links, preview environments, staged rollouts)
- They already use the URLsToGo GitHub integration pattern (auto-update preview shortlinks on deploy)
- They need API-accessible link management for their app's CI/CD workflows
- They're Claude Code power users — already comfortable with developer tooling at $12/mo price points

### Cross-Promotion Hooks

**In 1p-local-auth → URLsToGo:** The plugin's `references/providers.md` and README could mention: "Track your OAuth app's deployed preview URLs with [URLsToGo](https://urlstogo.cloud) — the dev-friendly URL shortener with GitHub Actions integration."

**In URLsToGo → 1p-local-auth:** Email sequence Email 4 (API power users) and Email 2 (features tour) are natural spots to mention: "If you're building an OAuth app, our creator also published `1p-local-auth` — a free Claude Code plugin for managing dev credentials."

**Marketing angle:** Both tools target the same "solo dev building something real with Claude Code" niche. Owning that niche across multiple free tools (1p-local-auth, the URLsToGo Claude Code plugin, artifact-manager) builds authority and drives URLsToGo sign-ups organically.

### Pitch Copy

> "Built URLsToGo and the 1p-local-auth Claude Code plugin. If you're a developer using Claude Code to build OAuth apps, I've got a free tool for your local dev workflow and a $12/mo URL shortener with a proper API. Come check out what else I'm building."

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

1. **Logout button** — sidebar footer email needs logout functionality
2. **Import button** — needs testing
3. **Default collections** — auto-creates on first visit via `/api/init`

---

## CHROME EXTENSION (January 2026)

Local-only Chrome extension in `chrome-extension/` — adds "Save" button on Claude.ai to send artifacts to Artifact Manager.

**Install:** Open `chrome-extension/generate-icons.html` → download icons → load unpacked at `chrome://extensions/`

See `chrome-extension/README.md` for full setup. CORS on Artifact Manager allows `claude.ai` origin.

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
