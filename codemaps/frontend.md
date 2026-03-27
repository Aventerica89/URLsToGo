# URLsToGo — Frontend Codemap
_Updated: 2026-03-27_

## Architecture

Vanilla JS SPA — no framework. All HTML/CSS/JS rendered server-side as template strings in `src/index.js`. State is in-memory JS globals; navigation via URL hash (`#section/subsection`).

## Pages

| Route | Function | Notes |
|-------|----------|-------|
| `/` | `getLandingPageHTML()` ~3247 | Marketing landing page |
| `/login` | `getAuthPageHTML()` ~2835 | Clerk sign-in UI |
| `/admin` | `getAdminHTML()` ~4003 | Main app SPA |
| `/share/:token` | `getSharePageHTML()` ~10200 | Public category share page |
| `/design-system` | `getDesignSystemHTML()` ~10509 | Dev UI playground |

## Admin SPA Views (src/index.js ~4003+)

Hash-based navigation — `history.replaceState` (NOT `location.hash =` — causes hashchange loop).

| Hash | View Function | Description |
|------|--------------|-------------|
| *(default)* | All Links | Main links table |
| `#settings` | `showSettingsView()` | Settings tabs |
| `#settings/api-keys` | `showSettingsView('api-keys')` | API Keys tab |
| `#settings/git-sync` | `showSettingsView('git-sync')` | Git Sync tab |
| `#help` | `showHelpView()` | Help Hub |
| `#help/feature-guide` | `showHelpView('feature-guide')` | Feature Guide tab |
| `#help/connections` | `showHelpView('connections')` | Connections tab |
| `#billing` | `showBillingView()` | Plan/billing tab |

## Key UI Components (inline in getAdminHTML)

| Component | CSS Class | Notes |
|-----------|-----------|-------|
| Sidebar nav | `.sidebar` | 256px fixed; categories list, nav links |
| Links table | `.links-table` | Click row = copy shortlink |
| Add Link sheet | `.sheet` / `.sheet-overlay` | Desktop: centered 500px dialog; Mobile: bottom sheet |
| Edit modal | `.modal` | Centered dialog, max-width 500px |
| FAB | `.fab` | Purple floating action button (opens create sheet) |
| Onboarding tour | `.tour-overlay`, `.tour-popover` | Spotlight tour on first login |
| Upgrade modal | `.upgrade-modal` | Shows on plan limit hit |

## Add Link Modal (PR #137)

- **Desktop** (≥769px): `.sheet` becomes centered dialog via `@media (min-width: 769px)` — `position: relative`, `max-width: 500px`, scale-in animation
- **Mobile**: bottom sheet slides up (unchanged)
- **Shuffle button**: `.btn-icon-sm` next to slug input → `generateRandomSlug()` (6-char alphanumeric)
- **Advanced accordion**: `.advanced-toggle` / `.advanced-content` — exposes tags chip input, expiry presets, password field

## Design System

CSS custom properties using `oklch()` color space. Variables defined at `:root` in `getAdminHTML()`.

| Variable | Purpose |
|----------|---------|
| `--background` | Page background |
| `--foreground` | Primary text |
| `--muted` | Muted backgrounds |
| `--muted-foreground` | Secondary text |
| `--border` | Border color |
| `--accent` | Hover states |
| `--primary` | Purple `#8b5cf6` |
| `--radius` | Border radius |

Landing page uses hex values (standalone, no CSS variable dependency).

## Key JS Globals (src/index.js client-side)

| Global | Purpose |
|--------|---------|
| `sheetTags` | Tag array for create form |
| `currentCategory` | Active category filter |
| `clerkInstance` | Clerk JS SDK instance |
| `TOUR_STEPS` | Onboarding tour step definitions |

## Key Client Functions

| Function | Purpose |
|----------|---------|
| `openCreateSheet()` | Open Add Link modal, wire tag/expiry listeners |
| `closeCreateSheet()` | Reset all create form state |
| `createLinkFromSheet()` | POST /api/links with all fields |
| `generateRandomSlug()` | 6-char random code → #sheetNewCode |
| `toggleAdvancedCreate()` | Accordion open/close |
| `showSettingsView()` | Render settings panel, hide .main |
| `showHelpView()` | Render help panel, hide .main |
| `handleHashChange()` | Hash routing dispatcher |
| `startTour()` | Begin onboarding spotlight tour |
| `checkOnboarding()` | GET /api/onboarding/status on load |
| `showUpgradeModal()` | Display plan limit modal |
| `getUserPlanDisplay()` | Render billing tab UI |

## CSP Policy

`unsafe-inline` used (nonce approach was removed — blocked onclick handlers). See `getSecurityHeaders()` ~159.
