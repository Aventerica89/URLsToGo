# Plan: Proxy / Cloaking Mode for Preview Links

## Problem

Preview links (`go.urlstogo.cloud/app--preview`) redirect to the underlying deployment URL (Vercel, CF Pages, etc.). After the redirect, the address bar shows the Vercel URL — not the short link.

This breaks OAuth: providers like Google only allow whitelisted redirect URIs. Since preview URLs change on every deployment, you'd need to re-add each new URL to the OAuth console. Not practical.

## Goal

A stable origin that never changes, even as the underlying deployment rotates. OAuth registered once, works forever.

## Approaches

### Option A: Proxy Mode (full cloaking)

Requests to `go.urlstogo.cloud/app--preview/*` are proxied to the destination URL. Address bar never changes.

**Pros:** True cloaking, OAuth just works, no CNAME setup needed
**Cons:** CF Worker can't proxy cross-origin responses with credentials (cookies) — OAuth redirect flows use cookies, so the session won't propagate back to the actual app domain. This likely breaks auth callback handling.

### Option B: Custom Subdomain Alias (CNAME)

User maps `clarity-preview.jbcloud.app` → Vercel project alias that always tracks the branch. URLsToGo stores the subdomain mapping and makes it easy to configure.

**Pros:** True stable origin with correct domain, OAuth and cookies work normally
**Cons:** Requires user to own the domain and configure DNS; Vercel alias needs to be set via API

### Option C: Stable Vercel Alias (simplest)

URLsToGo provides instructions + a helper to assign a permanent Vercel branch alias (e.g. `clarity-preview.vercel.app`) and registers it automatically when the preview link is created.

**Pros:** Minimal infrastructure, Vercel handles it
**Cons:** `*.vercel.app` subdomain, not a custom domain

## Recommended Approach

**Option B** — custom subdomain, first-class support in URLsToGo:

1. User creates a preview link as normal
2. Optionally assigns a custom subdomain (e.g. `clarity-preview.jbcloud.app`)
3. URLsToGo stores the subdomain → destination mapping
4. Worker serves a `301` for the short link and also handles requests on the custom subdomain
5. User points their CNAME at URLsToGo worker once — never touches DNS again

## API Design

```
POST /api/preview-links/{code}/alias
Authorization: Bearer utg_xxxxx
Content-Type: application/json

{
  "subdomain": "clarity-preview.jbcloud.app"
}
```

Worker hostname routing already exists (custom domains on CF Workers). Just needs the subdomain → preview link lookup on incoming requests.

## Schema Change

```sql
ALTER TABLE links ADD COLUMN custom_subdomain TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_links_subdomain ON links(custom_subdomain) WHERE custom_subdomain IS NOT NULL;
```

## UI

Add "Custom domain" field to the preview link edit panel in admin. Show the CNAME target (`go.urlstogo.cloud` worker IP / CNAME target) after setup.

## Effort

Medium. Routing logic is the main lift — CF Worker needs to check incoming `Host` header against the `custom_subdomain` column and serve the destination or proxy it.
