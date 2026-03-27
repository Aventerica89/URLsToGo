# URLsToGo — Data Models Codemap
_Updated: 2026-03-27_

## Database: Cloudflare D1 (SQLite)
Binding: `DB` | Name: `url-shortener`

---

## Core Tables (`migrations.sql`)

### `links`
Primary URL shortlink record. All columns per user (`user_email` isolation).

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | Auto-increment |
| `code` | TEXT UNIQUE | Slug (e.g. `my-link`) |
| `destination` | TEXT | Full URL |
| `user_email` | TEXT | Owner (Clerk email) |
| `category_id` | INTEGER FK | → categories.id |
| `description` | TEXT | Optional note |
| `password_hash` | TEXT | Argon2-style hash if password-protected |
| `expires_at` | TEXT | ISO 8601 or NULL |
| `click_count` | INTEGER | Denormalized total |
| `created_at` | TEXT | ISO timestamp |
| `is_favorite` | INTEGER | 0/1 |
| `is_preview_link` | INTEGER | 0/1 — preview auto-update links |
| `title` | TEXT | Display name for share pages |
| `is_featured` | INTEGER | 0/1 — amber star in share page |
| `is_archived` | INTEGER | 0/1 — owner-only in share page |

### `categories`
| Column | Type |
|--------|------|
| `id` | INTEGER PK |
| `name` | TEXT |
| `slug` | TEXT UNIQUE per user |
| `user_email` | TEXT |
| `created_at` | TEXT |

### `tags`
| Column | Type |
|--------|------|
| `id` | INTEGER PK |
| `name` | TEXT |
| `user_email` | TEXT |

### `link_tags`
Join table: links ↔ tags (many-to-many).

### `clicks`
Per-click analytics. Queried by `code` and `user_email`.

| Column | Type |
|--------|------|
| `id` | INTEGER PK |
| `link_id` | INTEGER FK |
| `user_email` | TEXT |
| `clicked_at` | TEXT |
| `country` | TEXT |
| `device_type` | TEXT |
| `browser` | TEXT |
| `referer` | TEXT |

### `api_keys`
| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `user_email` | TEXT | |
| `key_hash` | TEXT | SHA-256 hash of raw key |
| `name` | TEXT | User-assigned label |
| `scopes` | TEXT | JSON array of allowed scopes |
| `created_at` | TEXT | |
| `last_used_at` | TEXT | |

### `category_shares`
| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `token` | TEXT UNIQUE | Random share token |
| `user_email` | TEXT | |
| `category_id` | INTEGER FK | |
| `created_at` | TEXT | |

---

## Billing Tables (`migrations-billing.sql`)

### `subscriptions`
| Column | Type | Notes |
|--------|------|-------|
| `user_email` | TEXT PK | |
| `stripe_customer_id` | TEXT | |
| `stripe_subscription_id` | TEXT | |
| `plan` | TEXT | `free` \| `pro` \| `business` |
| `status` | TEXT | `active` \| `canceled` \| `past_due` |
| `current_period_end` | TEXT | ISO timestamp |

---

## Onboarding Tables (`migrations-onboarding.sql`)

### `user_preferences`
| Column | Type |
|--------|------|
| `user_email` | TEXT PK |
| `onboarding_completed_at` | TEXT |

---

## Feedback Tables (`migrations-feedback.sql`)

### `feedback`
| Column | Type |
|--------|------|
| `id` | INTEGER PK |
| `email` | TEXT |
| `message` | TEXT |
| `created_at` | TEXT |

---

## Plan Limits

Defined in `src/index.js` as `PLAN_LIMITS`:

| Plan | Links (concurrent) | Analytics |
|------|--------------------|-----------|
| `free` | 25 | None |
| `pro` | 500 | Full |
| `business` | 2000 | Full |

**Concurrent model:** limit is active count. Delete one, add one = net zero.

**Admin bypass:** `ADMIN_EMAIL` env var → 9999 links, no upgrade prompts.

---

## User Data Isolation

All queries filtered by `user_email` (from Clerk JWT or API key lookup). No row-level security at DB level — enforced in application code.

---

## Stripe Resources

| Resource | ID |
|----------|----|
| Pro product | `prod_U3Qqpfwus7EuD9` |
| Pro price ($12/mo) | `price_1T5Jz1H6aZ92e8Txu9tLJnRI` |
| Founding coupon (25% off) | `v4YhDxgz` |
| Webhook | `we_1T5JzHH6aZ92e8TxrS4EWSNU` |
