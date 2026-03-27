# URLsToGo — Architecture Codemap
_Updated: 2026-03-27_

## Overview

Single-file Cloudflare Worker SaaS URL shortener. All server logic, HTML/CSS/JS, routing, and templates live in one file (`src/index.js`, ~10,700 lines). No build step — direct deployment via `wrangler deploy`.

## Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Cloudflare Workers (Node.js compat mode) |
| Database | Cloudflare D1 (SQLite) — binding: `DB` |
| Auth | Clerk (`@clerk/backend` v2, `@clerk/clerk-js@5` CDN) |
| Payments | Stripe (REST API, no SDK) |
| Git sync | GitHub OAuth + REST API |
| Deployment | GitHub Actions → `wrangler deploy` (auto on merge to `main`) |
| DNS | `urlstogo.cloud` (admin), `go.urlstogo.cloud` (shortlinks) |

## Entry Point

```
fetch(request, env) in src/index.js
  └── URL path routing (if/else chain, ~250–2095)
       ├── Public routes (/, /login, /share/*, shortlinks)
       ├── Webhook routes (/api/billing/webhook — no auth)
       └── Protected routes (Clerk JWT or API key auth)
```

## Auth Flow

```
Request
  ├── /__clerk/* → Clerk FAPI proxy (frontend-api.clerk.services)
  ├── API key header? → validateApiKey() → scoped access
  └── Cookie/JWT → getUserEmail() → Clerk verifyToken()
                     └── ADMIN_EMAIL match → 9999 link limit bypass
```

## Deployment Pipeline

```
git push → PR → merge to main
  └── .github/workflows/deploy.yml
       ├── npm ci
       ├── wrangler d1 execute (migrations.sql, migrations-billing.sql, etc.)
       └── wrangler deploy → urlstogo.cloud
```

## Domain Architecture

- `urlstogo.cloud/admin` — Admin SPA
- `urlstogo.cloud/` — Landing page
- `urlstogo.cloud/login` — Clerk login UI
- `go.urlstogo.cloud/{code}` — Shortlink redirects
- `urlstogo.cloud/share/{token}` — Public shared collections
- `urlstogo.cloud/__clerk/*` — Clerk FAPI proxy

## File Map

| File | Purpose |
|------|---------|
| `src/index.js` | Entire application (~10,700 lines) |
| `wrangler.toml` | Worker config, D1 binding, keep_vars |
| `migrations.sql` | Core schema (append-only) |
| `migrations-billing.sql` | Stripe subscriptions |
| `migrations-onboarding.sql` | user_preferences table |
| `migrations-feedback.sql` | Feedback table |
| `migrations-ai.sql` | AI provider settings |
| `design-system.html` | Local UI playground (not deployed) |
| `templates/update-preview-link.yml` | Reusable GH Actions workflow |
| `tests/e2e/` | Playwright E2E tests |
| `.github/workflows/deploy.yml` | CI/CD pipeline |
