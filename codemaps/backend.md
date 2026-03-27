# URLsToGo — Backend Codemap
_Updated: 2026-03-27_

## All logic in `src/index.js`

### Core Utilities (lines ~92–2095)

| Function | Line | Purpose |
|----------|------|---------|
| `escapeHtml` | ~108 | XSS prevention for innerHTML |
| `escapeAttr` | ~119 | XSS prevention for onclick/attr contexts |
| `escapeJs` | ~133 | XSS prevention for JS string injection |
| `getSecurityHeaders` | ~159 | CSP, HSTS, X-Frame-Options headers |
| `getCorsHeaders` | ~206 | CORS for API endpoints |
| `jsonResponse` | ~214 | Standard JSON response helper |
| `errorResponse` | ~229 | Error response helper |

### Auth & Plans (lines ~2096–2235)

| Function | Line | Purpose |
|----------|------|---------|
| `getUserPlan` | ~2108 | D1 lookup → free/pro/business; ADMIN_EMAIL = 9999 limit |
| `getUserEmail` | ~2159 | Clerk JWT verification (cookie or Bearer) |
| `getUserEmailWithFallback` | ~2224 | getUserEmail + API key fallback |
| `validateApiKey` | ~2258 | Hash+compare API key, return scopes |
| `stripeRequest` | ~2120 | Raw Stripe REST wrapper |
| `verifyStripeSignature` | ~2140 | Webhook HMAC verification |

### Rate Limiting (lines ~2466–2545)

| Function | Line | Purpose |
|----------|------|---------|
| `getRateLimits` | ~2466 | Per-endpoint limits from env or defaults |
| `checkRateLimit` | ~2489 | D1-backed sliding window counter |

### Validation (lines ~2546–2644)

| Function | Line | Purpose |
|----------|------|---------|
| `validateUrl` | ~2546 | URL safety check (blocks localhost, private IPs) |
| `validateCode` | ~2611 | Slug format validation |

### Password Protection (lines ~2645–2833)

| Function | Line | Purpose |
|----------|------|---------|
| `hashPassword` | ~2650 | Argon2-style hash via Web Crypto |
| `verifyPassword` | ~2684 | Constant-time verification |
| `timingSafeEqual` | ~2744 | Timing-safe byte comparison |

### API Routes (lines ~553–2095)

#### Links
| Method | Path | Auth | Notes |
|--------|------|------|-------|
| `GET` | `/api/links` | Clerk | Supports ?category, ?favorite, ?search, ?tag filters |
| `POST` | `/api/links` | Clerk | Plan limit enforced; supports tags, expires_at, password |
| `PUT` | `/api/links/:code` | Clerk | Full update |
| `PATCH` | `/api/links/:code` | Clerk | Partial update (title, is_featured, is_archived) |
| `DELETE` | `/api/links/:code` | Clerk | Soft delete |
| `POST` | `/api/links/bulk-delete` | Clerk | Multi-select delete |
| `POST` | `/api/links/bulk-move` | Clerk | Move links to category |
| `PUT` | `/api/preview-links/:code` | API key | Auto-create/update `--preview` links |

#### Categories
| Method | Path | Auth |
|--------|------|------|
| `GET` | `/api/categories` | Clerk |
| `POST` | `/api/categories` | Clerk |
| `DELETE` | `/api/categories/:slug` | Clerk |
| `POST` | `/api/categories/:slug/share` | Clerk |
| `GET` | `/api/categories/:slug/share` | Clerk |
| `DELETE` | `/api/categories/:slug/share` | Clerk |

#### Analytics
| Method | Path | Auth |
|--------|------|------|
| `GET` | `/api/analytics/overview` | Clerk |
| `GET` | `/api/analytics/:code` | Clerk |
| `GET` | `/api/stats` | Clerk |

#### Billing (Stripe)
| Method | Path | Auth |
|--------|------|------|
| `POST` | `/api/billing/webhook` | Stripe HMAC (no Clerk) |
| `GET` | `/api/billing/status` | Clerk |
| `POST` | `/api/billing/checkout` | Clerk |
| `GET` | `/api/billing/portal` | Clerk |
| `GET` | `/api/billing/founding` | Clerk |

#### GitHub Git Sync
| Method | Path | Auth |
|--------|------|------|
| `GET` | `/api/github/authorize` | Clerk |
| `GET` | `/api/github/callback` | Clerk |
| `GET` | `/api/github/repos` | Clerk |
| `POST` | `/api/github/repo-syncs` | Clerk |
| `DELETE` | `/api/github/repo-syncs/:id` | Clerk |
| `POST` | `/api/github/deploy/:id` | Clerk |

#### Other
| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/keys` | List API keys |
| `POST` | `/api/keys` | Create API key |
| `DELETE` | `/api/keys/:id` | Revoke API key |
| `GET/PUT` | `/api/settings` | User settings |
| `GET/POST/DELETE` | `/api/settings/github-token` | GitHub PAT management |
| `GET` | `/api/export` | JSON export |
| `POST` | `/api/import` | JSON import |
| `GET/POST` | `/api/onboarding/status\|complete` | Onboarding state |
| `POST` | `/api/feedback` | Landing page feedback |
| `POST` | `/api/waitlist` | Email waitlist |
| `GET/POST/DELETE` | `/api/ai-providers` | AI provider config |
