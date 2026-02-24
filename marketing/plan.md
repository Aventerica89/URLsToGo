# URLsToGo — Go-To-Market Plan

**Product:** URLsToGo — Fast, developer-friendly URL shortener on Cloudflare's edge
**Domain:** urlstogo.cloud | go.urlstogo.cloud
**Entity:** JBMD Creations, LLC
**Target Launch:** Q1 2026

---

## 1. Product Readiness

### What Exists Today

| Feature | Status | Notes |
|---------|--------|-------|
| URL shortening + 302 redirects | LIVE | ~50ms edge latency |
| Click analytics (geo, device, browser, referrer) | LIVE | Per-link + global dashboard |
| Google OAuth (Clerk) | LIVE | 10K MAU free tier |
| API keys (scoped read/write) | LIVE | Programmatic access |
| Categories + tags | LIVE | Full organization system |
| Shared collections (public pages) | LIVE | Token-based sharing |
| GitHub integration (preview links) | LIVE | Auto-deploy workflows |
| Link expiration + password protection | LIVE | Per-link settings |
| Waitlist | LIVE | Email + geolocation capture |
| Import/export (JSON) | LIVE | Full data portability |
| Dark theme dashboard | LIVE | Responsive desktop + mobile |
| CI/CD (GitHub Actions) | LIVE | Push to main = auto-deploy |

### What's Needed for Launch

| Item | Priority | Effort | Notes |
|------|----------|--------|-------|
| Stripe billing integration | P0 | 2-3 days | Subscriptions, billing portal, webhooks |
| Usage limits enforcement | P0 | 1-2 days | Link count caps per tier, API rate limits per plan |
| Landing page polish | P0 | 1-2 days | Pricing section, testimonials area, CTA flow |
| Onboarding flow | P1 | 1 day | First-link wizard, quick tour |
| Custom domain support (user domains) | P1 | 2-3 days | CNAME verification, SSL provisioning |
| Email notifications (Resend/Postmark) | P1 | 1 day | Welcome, usage alerts, conversion reminders |
| Team/org support | P2 | 3-5 days | Shared workspaces, role-based access |
| Public API docs | P2 | 1 day | OpenAPI spec, interactive explorer |

**Estimated time to MVP billing launch: 5-7 days of focused work.**

---

## 2. Pricing Strategy

### Competitive Landscape

| Service | Free | Pro | Business | Enterprise |
|---------|------|-----|----------|------------|
| Bitly | 10 links/mo | $35/mo | $300/mo | Custom |
| Dub.co | 25 links/mo | $24/mo | $59/mo | Custom |
| Short.io | 50 links | $19/mo | $49/mo | Custom |
| TinyURL | Basic | $12.99/mo | — | — |
| **URLsToGo** | **25 links** | **$12/mo** | **$29/mo** | **Custom** |

### URLsToGo Tier Breakdown

**Free Tier ($0/mo)**
- 25 short links
- Basic click counts
- URLsToGo-branded links (go.urlstogo.cloud/code)
- 1 category
- No API access

**Pro Tier ($12/mo)**
- 1,000 short links
- Full analytics (geo, device, browser, referrer, time series)
- Custom slugs
- Unlimited categories + tags
- API access (scoped keys)
- Link expiration + password protection
- Shared collections
- Import/export
- Priority support

**Business Tier ($29/mo)**
- Unlimited short links
- Everything in Pro
- Custom domains (bring your own domain)
- Team workspaces (up to 5 members)
- Webhook events (click notifications)
- Advanced analytics (CSV export, date range queries)
- GitHub integration (preview link automation)
- SLA: 99.9% uptime

### Why This Pricing Wins

- Undercuts Bitly by 66% on Pro tier
- Undercuts Dub.co by 50% on Pro tier
- Cloudflare infrastructure = near-zero marginal cost per user
- Users who need API access (developers) will pay $12/mo gladly
- Business tier captures agencies/teams at $29/mo

---

## 3. Cost Infrastructure

### Per-User Cost Analysis

| Resource | Free Tier Limit | Paid Plan ($5/mo) | Cost per 100 Users | Cost per 500 Users | Cost per 1000 Users |
|----------|----------------|--------------------|--------------------|--------------------|--------------------|
| CF Workers | 100K req/day | 10M req/mo | $0 (free tier) | $5/mo | $5/mo |
| CF D1 reads | 5M/day | 25B/mo | $0 (free tier) | $0 (free tier) | $0-2/mo |
| CF D1 writes | 100K/day | 50M/mo | $0 (free tier) | $0 (free tier) | $0-1/mo |
| CF D1 storage | 5GB | 5GB + $0.75/GB | $0 (free tier) | $0 (free tier) | $0-1/mo |
| Clerk auth | 10K MAU free | $0.02/MAU after 10K | $0 (free tier) | $0 (free tier) | $0 (free tier) |
| Domain (urlstogo.cloud) | — | ~$10/year | $0.83/mo | $0.83/mo | $0.83/mo |
| **Total** | — | — | **$0.83/mo** | **$5.83/mo** | **$8.83/mo** |

### Google OAuth Costs

- Google OAuth through Clerk: **$0**
- Google does not charge for OAuth consent/sign-in
- Google API quotas for OAuth are generous (no practical limit for our scale)
- Clerk handles all the OAuth complexity, we just pay Clerk's pricing
- At 10,000+ MAU, Clerk charges $0.02/user/month = $200/mo at 10K users
- **Decision point:** If we exceed 10K MAU, evaluate self-hosted auth vs Clerk cost

### Break-Even Analysis

| Scenario | Monthly Cost | Revenue (Pro $12) | Revenue (Mix) | Profit |
|----------|-------------|-------------------|---------------|--------|
| 100 free users | $0.83 | $0 | $0 | -$0.83 |
| 50 free + 50 Pro | $0.83 | $600 | $600 | +$599 |
| 100 Pro users | $5 | $1,200 | $1,200 | +$1,195 |
| 200 Pro + 50 Biz | $5.83 | $2,400 + $1,450 | $3,850 | +$3,844 |
| 500 Pro + 100 Biz | $8.83 | $6,000 + $2,900 | $8,900 | +$8,891 |

**Break-even: 1 paying user covers 14 months of infrastructure.**

---

## 4. Launch Strategy — The Founding 100

### Phase 1: Founding 100 (Weeks 1-2)

**Goal:** Get 100 users on a free 6-month Pro plan to build word-of-mouth and gather feedback.

**Mechanics:**
- Founding 100 members get full Pro features for 6 months free
- After 6 months, auto-convert to "Founding Member" rate: $9/mo (25% off Pro forever)
- Links never break — even if they don't convert, their links stay active on the Free tier
- Waitlist already exists in the product (waitlist table with email + geolocation)

**Acquisition channels:**
1. Reddit posts (see Marketing Channels section)
2. Personal network + existing projects (Clarity, VaporForge, WP Dispatch users)
3. Product Hunt launch (time for maximum impact)
4. Indie Hackers community post

**Trust signal:** "Your links never break. Even if you don't subscribe, your short links keep working forever."

### Phase 2: Next 100 at 50% Off (Weeks 3-6)

Once Founding 100 slots are filled:
- Display "Founding 100 is full!" on landing page
- Offer next 100 signups 50% off for life ($6/mo Pro, $14.50/mo Business)
- Creates urgency + FOMO ("only 73 spots remaining at this price")
- Countdown/progress bar on landing page

### Phase 3: General Availability (Month 2+)

- Full pricing ($12/mo Pro, $29/mo Business)
- Free tier always available (25 links)
- Referral program: give 1 month free for every referral who subscribes

### Conversion Funnel

```
Landing Page Visit
    |
    v (CTA: "Get Started Free" or "Join Founding 100")
Sign Up (Google OAuth — one click)
    |
    v (Onboarding: create first short link in <30 seconds)
Active Free User
    |
    v (Hit link limit, want analytics, need API)
Pro Subscriber ($12/mo)
    |
    v (Need custom domains, team access)
Business Subscriber ($29/mo)
```

---

## 5. Marketing Channels

### Reddit (Primary Channel — Zero Budget)

**Target Subreddits:**

| Subreddit | Angle | Post Type |
|-----------|-------|-----------|
| r/SideProject | "I built a URL shortener on CF Workers" | Show & Tell |
| r/webdev | Technical deep-dive on the architecture | Technical |
| r/selfhosted | "Open-source URL shortener alternative" | Technical |
| r/Entrepreneur | "My SaaS costs $5/mo to run for 1000 users" | Business |
| r/SaaS | "Launching my first SaaS — here's the pricing math" | Business |
| r/startups | "From side project to SaaS in 30 days" | Story |
| r/CloudFlare | "Building a full SaaS on Workers + D1" | Technical |

**Posting Strategy:**
- Post at 8-9am EST, Tuesday-Thursday (peak Reddit engagement)
- Be genuine — show the build story, don't be salesy
- Respond to every comment within 2 hours (algorithm boost)
- Include screenshots of the dashboard
- Never use the word "startup" — say "side project" or "tool I built"

**Post Templates:**

**r/SideProject (Show & Tell):**
> Title: "I built a URL shortener that runs on Cloudflare's edge for <$5/mo"
>
> Body: Show the dashboard, explain the tech stack, mention the founding 100 program, link to the site. End with "What would you want to see added?"

**r/webdev (Technical):**
> Title: "How I built a full-featured URL shortener with Cloudflare Workers + D1 (no framework, vanilla JS)"
>
> Body: Architecture breakdown, D1 schema design, Clerk auth integration, analytics pipeline, CI/CD with GitHub Actions. Include code snippets.

**r/Entrepreneur (Business):**
> Title: "My SaaS infrastructure costs $5/month for 1000 users — here's the math"
>
> Body: Cost breakdown table, Cloudflare pricing analysis, comparison to competitors, why edge computing makes micro-SaaS viable.

### Product Hunt

**Timing:** Launch on a Tuesday (highest traffic day)
**Tagline:** "Fast, developer-friendly URL shortener on Cloudflare's edge"
**Maker Comment:** Focus on the cost story and the developer-first approach

**Preparation:**
- 5+ high-quality screenshots
- 60-second demo video (Loom)
- Ask 10+ people to leave authentic reviews on launch day
- Prepare for traffic spike (Cloudflare auto-scales, so no concern)

### Indie Hackers

- Post in "Show IH" with revenue transparency
- Share the exact cost breakdown
- Update monthly with MRR numbers (IH community loves transparency)

### Twitter/X Build-in-Public

- Thread: "I'm launching a URL shortener. Here's every decision I made and why."
- Share screenshots of dashboard, analytics, revenue
- Use hashtags: #buildinpublic #indiehackers #cloudflare #saas
- Post 2-3 times/week during launch phase

### Dev.to / Hashnode

- Technical articles about building on Cloudflare Workers
- "How I replaced Bitly with my own URL shortener for $5/month"
- These get indexed by Google and drive long-tail SEO traffic

---

## 6. Email Campaign — Beta User Sequence

### Email Provider

Use Resend or Postmark (both have generous free tiers):
- Resend: 3,000 emails/month free, then $20/mo for 50K
- Postmark: 100 emails/month free, then $15/mo for 10K

### Sequence (8 Emails Over 6 Months)

**Email 1: Welcome (Day 0 — Immediately after signup)**
- Subject: "Welcome to the Founding 100"
- Key points: What they get (6 months Pro free), how to create first link, support channel
- CTA: "Create your first short link"

**Email 2: Onboarding (Day 2)**
- Subject: "3 things you can do with URLsToGo today"
- Key points: Analytics dashboard, categories, API keys
- CTA: "Explore your dashboard"

**Email 3: Feature Highlight (Week 1)**
- Subject: "Did you know? Your links have built-in analytics"
- Key points: Click analytics, geo data, device breakdown, how to read the charts
- CTA: "View your analytics"

**Email 4: Power User (Week 2)**
- Subject: "Unlock the API — automate your short links"
- Key points: API key creation, example cURL commands, GitHub integration
- CTA: "Generate your API key"

**Email 5: Check-In (Month 1)**
- Subject: "How's it going? Quick feedback request"
- Key points: Quick survey (3 questions), feature requests welcome
- CTA: "Take 30-second survey"

**Email 6: Conversion Notice (Month 3)**
- Subject: "Your Founding 100 membership — 3 months to go"
- Key points: Reminder of what they get, preview of founding member pricing ($9/mo), what happens after
- CTA: "Lock in your founding rate"

**Email 7: Urgency (Month 5)**
- Subject: "1 month left on your free Pro plan"
- Key points: Usage stats (X links, Y clicks), founding member price vs full price, links never break even without Pro
- CTA: "Subscribe now at $9/mo (founding rate)"

**Email 8: Conversion (Month 6)**
- Subject: "Your free period ends tomorrow — keep your Pro features"
- Key points: Final reminder, comparison of Free vs Pro features, founding rate expires with this cohort
- CTA: "Continue with Pro at $9/mo"

### Post-Conversion Emails

- Monthly usage digest (top links, total clicks, new milestones)
- Feature announcements (new capabilities, integrations)
- Annual renewal reminder with discount for yearly ($99/year vs $108)

---

## 7. Metrics to Track

### North Star Metrics

| Metric | Target (Month 1) | Target (Month 3) | Target (Month 6) |
|--------|------------------|-------------------|-------------------|
| Total Users | 100 (Founding) | 200 | 500 |
| Paying Users | 0 | 20-30 | 100-150 |
| MRR | $0 | $240-$360 | $1,200-$1,800 |
| Links Created | 500 | 3,000 | 15,000 |
| Monthly Clicks | 5,000 | 50,000 | 250,000 |
| Churn Rate | N/A | <5% | <5% |

### Leading Indicators

- Daily active users (DAU)
- Links created per user per week
- API key creation rate (power user signal)
- Shared collection creation rate (virality signal)
- Waitlist signups (demand signal)

---

## 8. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| No one signs up | Low | High | Already validated by own usage; Reddit posts have predictable traffic |
| Free users never convert | Medium | Medium | 6-month trial builds habit; founding rate is attractive; links never break (reduces fear) |
| Cloudflare pricing increases | Low | Low | Margins so high (95%+) that even 2x increase is fine |
| Clerk pricing at scale | Medium | Medium | At 10K MAU, evaluate migration to self-hosted auth |
| Competitor launches similar | Low | Low | Developer-first, edge-native, and API-first differentiation |
| Abuse (spam links) | Medium | Medium | Rate limiting exists; add link scanning/blacklist |

---

## 9. 30-Day Launch Checklist

### Week 1: Infrastructure
- [ ] Implement Stripe billing (subscriptions, webhooks, billing portal)
- [ ] Add usage limit enforcement (link count per tier)
- [ ] Set up email provider (Resend) for transactional + marketing emails
- [ ] Write welcome email template

### Week 2: Polish
- [ ] Redesign landing page with pricing section and CTA
- [ ] Add onboarding flow (first-link wizard)
- [ ] Create "Founding 100" badge/branding
- [ ] Prepare 5 screenshots for Product Hunt

### Week 3: Launch
- [ ] Post on r/SideProject (Tuesday 8am EST)
- [ ] Post on r/webdev (Thursday 8am EST)
- [ ] Launch on Product Hunt (Tuesday)
- [ ] Post on Indie Hackers
- [ ] Send founding invite to waitlist

### Week 4: Iterate
- [ ] Respond to all feedback
- [ ] Fix top 3 reported issues
- [ ] Post Month 1 progress update on Indie Hackers
- [ ] Start email sequence for all signups
- [ ] If Founding 100 full, activate "50% off for life" tier
