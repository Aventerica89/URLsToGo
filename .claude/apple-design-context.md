# Apple Design Context — URLsToGo

**App:** URLsToGo
**Type:** Existing web app (Single-file Cloudflare Worker, vanilla HTML/CSS/JS)
**URL:** urlstogo.cloud/admin
**Platform targets:** Mobile + iPad + macOS Desktop (PWA)

---

## Design System

**Color tokens (oklch):**
- `--background: 0.1430 0.0219 293.0857` → `#09090b` (near-black, dark bg)
- `--card: 0.1831 0.0284 289.8409` → sidebar/card bg
- `--primary: 0.6056 0.2189 292.7172` → `#8b5cf6` violet (brand)
- `--secondary: 0.2352 0.0362 290.5754` → muted zinc
- `--border: 0.2352 0.0362 290.5754`
- `--ring: 0.6056 0.2189 292.7172`
- `--indigo: 0.6056 0.2189 292.7172` → `#6366f1`
- `--purple: 0.6368 0.2078 307.3313` → `#a855f7`
- `--radius: 0.75rem`

**Brand gradient:** `linear-gradient(135deg, #6366f1 0%, #a855f7 100%)`

**Font:** Inter (Google Fonts CDN), `-apple-system` fallback
**Dark mode:** Default. Light mode via `.light` class.

**Category dot colors:**
- Work: `oklch(0.685 0.219 307)`
- Personal: `oklch(0.652 0.245 340)`
- Social: `oklch(0.600 0.170 210)`
- Marketing: `oklch(0.680 0.200 50)`
- Docs: `oklch(0.580 0.150 165)`

---

## Layout

**Sidebar:** Fixed, 256px wide (hardcoded — NOT tokenized yet)
**Sidebar header:** 56px height
**App shell:** `.app-layout { display: flex; min-height: 100vh }`
**Mobile:** Bottom tab nav (visible on small screens, sidebar hidden)

---

## PWA Status

**Already implemented:**
- `manifest.json` with `display: standalone`, `theme_color: #8b5cf6`, `background_color: #09090b`
- Service worker (network-first, caches `/admin`, `/login`, `/manifest.json`)
- `<meta name="apple-mobile-web-app-capable" content="yes">`
- `<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">`
- `<meta name="apple-mobile-web-app-title" content="URLsToGo">`
- `<meta name="theme-color" content="#8b5cf6">`
- `<link rel="apple-touch-icon" href="/icon-192.png">`

**Missing / gaps:**
- `id` field in manifest.json
- `display_override: ["standalone"]` in manifest
- `mobile-web-app-capable` meta (non-Apple)
- `min-height: 100dvh` (uses `100vh` — breaks on mobile Safari with browser chrome)
- Sidebar width not tokenized (256px hardcoded)
- `/icon-192.png`, `/icon-512.png` — referenced in manifest but may not exist as static files (Worker serves them from code or they're missing)

---

## Current Logo / Favicon

Chain-link SVG (`ADMIN_FAVICON`): Two curved paths forming interlocked rings, violet stroke (`#8b5cf6`) on near-black rounded rect (`#09090b`, `rx=6`).

---

## HIG Pass History

- **2026-02-28:** Initial pass. Context file created.
