# Changelog

## Unreleased - February 19-21, 2026

### New Features

- Added favorites (star/unstar) for individual links
- Added help hub with Getting Started, Feature Guide, and Connections Guide tabs
- Added URL hash deep linking for navigation state (`#settings/api-keys`, `#help/connections`, etc.)
- Added copy-for-Claude prompt cards to Git Sync and API Keys settings panels
- Added repo search and pagination in Git Sync panel for large GitHub accounts

### Improvements

- Added plain-English instructions to API Keys and Git Sync settings panels
- Connections Guide includes integration tier summary table (Required/Recommended/Optional)

### Bug Fixes

- Fixed help view rendering outside app-layout flex container (was breaking layout)
- Fixed CSP to allow Cloudflare beacon script and Clerk Web Workers

### Security

- CORS origin-locked with dynamic preflight via `getCorsHeaders(request)` helper
- SSRF blocklist covers RFC 1918, IPv6 loopback/link-local, and cloud metadata (169.254.169.254)
- HTTP security headers applied universally via `htmlResponse()` helper on all HTML routes
- API key scope enforcement (`read`/`write`) enforced at API gateway level
- Rate limits: password brute-force (10/5min), waitlist (5/hr), API key name max 100 chars
- Referrer-Policy: no-referrer on all 302 redirects
- Enumeration fix: password-protected links return 200 (not 401)

---

## Unreleased - February 9, 2026

### New Features

- Added 4 new feature showcase cards to the landing page (API Keys, Password Protection, Expiration & UTM, QR Codes)
- Added API key management for programmatic access and CI/CD integration
- Added dynamic preview links that auto-update from GitHub Actions deployments
- Added iOS-style mobile UI with bottom tab navigation and swipe gestures
- Added mobile companion app mockup and Expo demo for iPhone testing
- Added Clerk authentication with Google sign-in (replaced Cloudflare Access)
- Added dedicated shortlink domain at go.urlstogo.cloud
- Added public landing page with hero section and How It Works walkthrough
- Added link password protection, expiration dates, and UTM parameter builder
- Added QR code generation and export/import for all link data
- Added real-time click analytics with referrer and geographic breakdowns
- Added categories, tags, and powerful search for link organization
- Added PWA support with installable app experience
- Added mobile-responsive links table with optimized column visibility
- Added custom SVG favicons and branding
- Added Chrome extension for saving Claude.ai artifacts to Artifact Manager
- Added Artifact Manager with collections, tags, search, favorites, and JSON backup
- Added content viewer for inspecting artifact HTML and code

### Improvements

- Styled table checkboxes with custom dark-theme appearance and focus states
- Improved landing page SVG icon rendering (fixed broken template literal escapes)
- Upgraded admin UI to vibrant purple/blue color scheme with OKLCH colors
- Improved mobile light mode card visibility
- Improved links table responsiveness across screen sizes
- Added floating dev tools button with design resource links
- Restructured Create Link form to a cleaner 3-column grid layout
- Added CSS tooltips on destination URLs replacing slow browser tooltips
- Shortened date display format in links table (omits year for current year)

### Bug Fixes

- Fixed API keys modal failing with 500 error (api_keys table was missing from D1 database)
- Fixed database migration ordering so CREATE TABLE runs before ALTER TABLE statements
- Fixed checkbox visibility against dark backgrounds (lighter border color)
- Fixed OKLCH color conversion across all mobile UI components
- Fixed string escaping in escapeJs function to prevent XSS and template literal issues
- Fixed Clerk SDK loading for Brave browser compatibility
- Fixed environment variables being wiped during deploys (added keep_vars)
- Fixed analytics crash on invalid referrer URLs
- Fixed regex escaping in attribute sanitization
- Fixed various button and logout functionality in Artifact Manager

### Security

- Added comprehensive XSS prevention with escapeHtml, escapeAttr, and escapeJs functions
- Added rate limiting on redirect and API endpoints
- Added input validation for short codes and destination URLs
- Added CORS headers scoped to trusted origins

### Documentation

- Updated CLAUDE.md with Clerk auth setup, preview links, and deployment docs
- Added comprehensive platform documentation
- Added user management guide for Cloudflare Access
