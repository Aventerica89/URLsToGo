# Developer Log

Technical log. Updated on every deploy.

<!-- Entries added automatically by deploy hook -->

### 2026-02-23 02:24 · 8851c92 · v0.0.0
FIX      migrations — remove applied ALTER TABLE statements from migrations.sql

### 2026-02-23 02:09 · a45cd89 · v0.0.0
DOCS     shared-collections — add SHARED COLLECTIONS section to CLAUDE.md

### 2026-02-23 02:04 · 335d50e · v0.0.0
FEAT     share-page — archive links on share page with table view

### 2026-02-23 01:16 · e840df4 · v0.0.0
FEAT     share-page — share page owner editing - title, description, featured grouping

### 2026-02-23 01:02 · 6d41ed1 · v0.0.0
FEAT     share-page — redesign shared collection page with dark theme

### 2026-02-23 00:50 · 7dc33d5 · v0.0.0
FEAT     categories — add shared collection pages for categories

### 2026-02-21 06:34 · f6c1689 · v0.0.0
DOCS     preview-links — add proxy/cloaking plan for preview links

### 2026-02-21 02:44 · 8c5a2c5 · v0.0.0
CHORE    docs — app-sync — update docs and changelog for Feb 19-21 features

### 2026-02-21 00:05 · 4863d06 · v0.0.0
FEAT     settings — repo search, pagination, favorites + URL hash deep linking

### 2026-02-20 23:39 · f02f540 · v0.0.0
FEAT     settings — add copy-for-Claude prompt cards to Git Sync and API Keys pages

### 2026-02-20 23:24 · fbd3666 · v0.0.0
DOCS     settings — plain-English instructions for API Keys and Git Sync panels

### 2026-02-20 23:12 · e0724c6 · v0.0.0
FIX      layout — move helpView inside app-layout (was rendering outside flex container)

### 2026-02-20 23:08 · e0ea59b · v0.0.0
FIX      security — CSP — allow Cloudflare beacon and Clerk Web Workers

### 2026-02-20 23:06 · 30ea1f9 · v0.0.0
FIX      api — clearer workflow 404 error + API key usage instructions

### 2026-02-20 22:53 · 67d3aea · v0.0.0
FEAT     help — add in-app help hub with Getting Started, Feature Guide, and Connections tabs

### 2026-02-19 17:08 · 1e01f56 · v0.0.0
SECURITY api-keys — enforce API key scopes and fix enumeration via status codes

### 2026-02-19 17:01 · 99503a9 · v0.0.0
SECURITY headers — add HTTP security headers to all HTML responses

### 2026-02-19 16:54 · 5f4a2f4 · v0.0.0
FIX      security — rate limiting gaps + input validation

### 2026-02-19 16:36 · 382a1ec · v0.0.0
FIX      security — security hardening — CORS lockdown + SSRF private IP blocklist

### 2026-02-19 14:25 · 142ff3c · v0.0.0
FIX      mobile — apply Apple HIG mobile layout corrections

### 2026-02-19 13:47 · 46105b9 · v0.0.0
FEAT     landing — update landing page features and fix outdated copy

### 2026-02-19 13:42 · 6c8243a · v0.0.0
FEAT     settings — add About settings tab with feature list and beta roadmap

### 2026-02-19 12:43 · 3f71a65 · v0.0.0
FEAT     legal — replace GPL license with proprietary + add beta waitlist

### 2026-02-13 06:36 · d2de976 · v0.0.0
FEAT     dx — add hookify rules for code safety and best practices

### 2026-02-09 03:50 · c774d00 · v0.0.0
FIX      migrations — remove ALTER TABLE statements that block D1 migrations

### 2026-02-09 03:42 · 4f3310b · v0.0.0
FIX      settings — settings view layout fills content area properly

### 2026-02-09 03:38 · 7f2ed9d · v0.0.0
FEAT     settings — add Settings page with Git Sync, Profile, and Appearance tabs

### 2026-02-09 01:44 · 0383461 · v0.0.0
FIX      ui — improve checkbox visibility with lighter border color

### 2026-02-09 01:28 · e99eef4 · v0.0.0
FIX      ui — style checkboxes with custom dark-theme appearance

### 2026-02-09 00:22 · 9883416 · v0.0.0
FIX      migrations — reorder migrations to prevent D1 abort on ALTER TABLE

### 2026-02-08 23:42 · 16e9030 · v0.0.0
FEAT     admin — fix landing page icons, add feature cards, fix API keys modal & admin UI

### 2026-02-06 18:00 · f3f8ed5 · v0.0.0
FIX      ui — convert all HSL colors to OKLCH in mobile UI (#72)

### 2026-02-06 17:51 · 3d3645b · v0.0.0
FIX      security — use charCodeAt() for all special characters in escapeJs (#71)

### 2026-02-06 16:52 · 5817adc · v0.0.0
FIX      security — fix escapeJs charcode handling (#70)

### 2026-02-06 15:49 · 104fae9 · v0.0.0
FIX      security — use charCode to avoid template literal newline issue (#69)

### 2026-02-06 15:06 · 2717b8e · v0.0.0
FIX      security — use character loop instead of regex in escapeJs (#68)

### 2026-02-06 13:31 · 11dea2f · v0.0.0
FEAT     security — implement escapeJs function for string escaping

### 2026-02-06 11:13 · 7cc9916 · v0.0.0
FEAT     preview-links — add dynamic preview links with GitHub Actions integration (#67)

### 2026-02-04 14:12 · 6b6c91c · v0.0.0
DOCS     readme — update logo to match existing SaaS favicon style

### 2026-02-04 14:08 · d2da758 · v0.0.0
DOCS     readme — add custom logo and enhanced badges to README

### 2026-02-03 21:14 · 18deb0a · v0.0.0
FEAT     api-keys — add API Keys management UI (#66)

### 2026-02-03 20:43 · fcf399f · v0.0.0
FIX      mobile — mobile UX improvements for PWA (#65)

### 2026-02-02 20:01 · cbe69ff · v0.0.0
FIX      mobile — improve light mode visibility for mobile UI cards (#64)

### 2026-02-02 16:54 · 01899ac · v0.0.0
FEAT     mobile — add iOS-style mobile UI with bottom tab navigation (#63)

### 2026-02-02 16:53 · 14951e2 · v0.0.0
FEAT     mobile — add iOS-style mobile UI with bottom tab navigation (#62)

### 2026-02-02 15:04 · 2ee1676 · v0.0.0
REFACTOR admin — extract hardcoded admin path into ADMIN_PATH constant (#60)

### 2026-02-02 14:25 · ced1fa1 · v0.0.0
FIX      auth — fetch user email from Clerk API and update branding to URLsToGo (#61)

### 2026-02-02 02:42 · e4120f1 · v0.0.0
FEAT     domain — use go.urlstogo.cloud for shortlinks, keep app at urlstogo.cloud

### 2026-02-02 02:30 · 9678f68 · v0.0.0
FEAT     domain — change shortlink domain to go.urlstogo.cloud

### 2026-02-02 02:23 · 051026e · v0.0.0
CHORE    dx — add worktree setup script

### 2026-02-01 23:53 · b4bf9ad · v0.0.0
CHORE    merge — Combative crocodile 13f267 (#59)

### 2026-02-01 23:37 · 37ad9ff · v0.0.0
REFACTOR artifacts — remove Artifact Manager pieces (moved to separate repo)

### 2026-02-01 23:29 · ece9930 · v0.0.0
CHORE    merge — Combative crocodile 13f267 (#58)

### 2026-02-01 23:25 · 40bee2a · v0.0.0
CHORE    merge — Combative crocodile 13f267 (#57)

### 2026-02-01 23:19 · f049a05 · v0.0.0
FEAT     artifacts — add HTML artifact sharing and extension v1.1.0

### 2026-01-30 19:34 · 37e9a3b · v0.0.0
FIX      ui — OKLCH color fixes and branding updates

### 2026-01-30 19:00 · 369cc6d · v0.0.0
CHORE    merge — Merge pull request #55

### 2026-01-30 18:57 · 3b759a1 · v0.0.0
FEAT     admin — upgrade admin UI to vibrant purple/blue color scheme

### 2026-01-30 23:29 · 6fda9f7 · v0.0.0
DOCS     claude-md — update CLAUDE.md with Clerk auth setup and npm structure

### 2026-01-30 22:14 · f634fb0 · v0.0.0
FIX      auth — replace deprecated Clerk redirect props

### 2026-01-30 21:41 · 1bfef5d · v0.0.0
FIX      deploy — add keep_vars to preserve dashboard environment variables

### 2026-01-30 21:32 · 0aace0e · v0.0.0
FIX      auth — address PR review feedback for Clerk initialization and package.json

### 2026-01-30 20:55 · 05d7acb · v0.0.0
FEAT     build — convert to npm-based project with official @clerk/backend SDK

### 2026-01-30 20:20 · 3536328 · v0.0.0
FIX      auth — add data-clerk-publishable-key attribute to admin page Clerk script

### 2026-01-30 20:17 · 6839f90 · v0.0.0
FIX      auth — clear timeout when Clerk loads successfully

### 2026-01-30 20:11 · 4a25f8f · v0.0.0
FIX      auth — remove extra closing brace causing JavaScript syntax error in login page

### 2026-01-30 19:56 · 57c9fe9 · v0.0.0
FIX      auth — improve Clerk SDK loading for Brave browser compatibility

### 2026-01-30 19:28 · c7127f3 · v0.0.0
FIX      security — address security and code quality review feedback

### 2026-01-30 18:33 · f331672 · v0.0.0
FEAT     auth — add Clerk authentication integration

### 2026-01-30 18:02 · 36e866b · v0.0.0
FIX      landing — address PR review feedback for landing page

### 2026-01-30 15:13 · 4cab02b · v0.0.0
FEAT     landing — add How It Works section to landing page

### 2026-01-30 13:42 · 37f5dd9 · v0.0.0
FEAT     landing — add modern hero section with SaaS dashboard mockup

### 2026-01-29 23:56 · 55c04a8 · v0.0.0
FEAT     landing — add public landing page for root path

### 2026-01-29 23:37 · 829cd41 · v0.0.0
REFACTOR core — rename project to URLsToGo and update domain

### 2026-01-28 17:01 · 463e892 · v0.0.0
FEAT     validation — add placeholder name validation and cleanup utility

### 2026-01-28 03:53 · a04b5b7 · v0.0.0
FEAT     mobile — connect to real API with Cloudflare Access auth

### 2026-01-28 03:51 · 6f30690 · v0.0.0
FEAT     api — add CORS support for mobile app

### 2026-01-28 02:59 · 68ecf3c · v0.0.0
CHORE    merge — merge branch claude/fix-session-crash-zdvsZ

### 2026-01-28 02:50 · cf84ae4 · v0.0.0
SECURITY core — critical security improvements

### 2026-01-28 01:38 · 8521cc6 · v0.0.0
FEAT     mobile — update Snack demo to match mockup design

### 2026-01-28 01:11 · b2b3b3d · v0.0.0
FEAT     mobile — add Expo Snack demo for iPhone testing

### 2026-01-27 22:39 · 356e506 · v0.0.0
CHORE    mobile — add EAS config, assets, and lock file

### 2026-01-27 22:09 · 48251c3 · v0.0.0
CHORE    mobile — add EAS project ID and bundle identifier

### 2026-01-27 21:18 · 7b83ec2 · v0.0.0
FEAT     mobile — scaffold Expo React Native companion app

### 2026-01-27 21:13 · 8e8afa8 · v0.0.0
DOCS     core — add comprehensive documentation for URL shortener platform

### 2026-01-27 20:34 · 391841a · v0.0.0
FIX      templates — remove escaped backticks in getMobileMockupHTML function

### 2026-01-27 19:25 · 48d0207 · v0.0.0
FEAT     admin — add floating dev tools button with design resource links

### 2026-01-27 19:15 · 64fbf4b · v0.0.0
FEAT     mobile — add iPhone mobile app mockup for companion app design

### 2026-01-27 19:00 · ae87c0d · v0.0.0
FEAT     mobile — improve links table responsiveness

### 2026-01-27 18:15 · b2014c1 · v0.0.0
FIX      analytics — handle invalid referrer URLs in recent clicks view

### 2026-01-27 17:16 · c9cff72 · v0.0.0
CHORE    docs — remove personal info from CLAUDE.md

### 2026-01-27 17:14 · 8431f14 · v0.0.0
FEAT     mobile — add mobile navigation to URL shortener app

### 2026-01-27 15:09 · ade35aa · v0.0.0
FIX      artifacts — address PR review feedback

### 2026-01-27 15:00 · 7edb344 · v0.0.0
FEAT     artifacts — add PWA support and mobile optimization

### 2026-01-26 23:10 · 596bd83 · v0.0.0
FEAT     artifacts — add tag editor with autocomplete and management

### 2026-01-26 22:51 · d101edb · v0.0.0
FEAT     artifacts — improve search and filter functionality

### 2026-01-26 22:23 · d1f97c0 · v0.0.0
FIX      core — fix escaped backticks in helper functions

### 2026-01-26 22:14 · 2fed74a · v0.0.0
FIX      artifacts — add HTML/code content textarea for downloaded artifacts

### 2026-01-26 21:29 · b547b15 · v0.0.0
FIX      core — address PR review feedback

### 2026-01-26 21:03 · 61b1220 · v0.0.0
FEAT     core — add major URL shortener improvements
