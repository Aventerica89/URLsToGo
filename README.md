<p align="center">
  <img src="assets/logo.svg" alt="URLsToGo" width="128" height="128">
</p>

<h1 align="center">URLsToGo</h1>

<p align="center">
  <strong>Fast, free URL shortener on Cloudflare's edge network</strong>
</p>

<p align="center">
  <a href="https://github.com/Aventerica89/URLsToGo/stargazers"><img src="https://img.shields.io/github/stars/Aventerica89/URLsToGo?style=flat&color=f97316" alt="Stars"></a>
  <a href="https://github.com/Aventerica89/URLsToGo/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-green" alt="License"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white" alt="Cloudflare Workers">
  <img src="https://img.shields.io/badge/Cloudflare-D1-F38020?logo=cloudflare&logoColor=white" alt="D1 Database">
  <img src="https://img.shields.io/badge/Clerk-Auth-6C47FF?logo=clerk&logoColor=white" alt="Clerk Auth">
  <img src="https://img.shields.io/badge/GitHub-Actions-2088FF?logo=githubactions&logoColor=white" alt="GitHub Actions">
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#costs">Costs</a>
</p>

---

## Quick Start (with Claude Code)

The fastest way to deploy your own instance:

1. **Fork this repo** to your GitHub account

2. **Open Claude Code** and run:
   ```
   claude "Help me deploy URLsToGo to my Cloudflare account"
   ```

3. **Follow Claude's prompts** - it will:
   - Create your D1 database
   - Set up your custom domain
   - Configure GitHub secrets
   - Deploy everything automatically

That's it. Claude handles all the Cloudflare configuration.

---

## What You'll Need

- **Cloudflare account** (free) - [Sign up](https://dash.cloudflare.com/sign-up)
- **GitHub account** (free) - For the repo and Actions
- **A domain on Cloudflare** - For your custom short link domain (e.g., `links.yourdomain.com`)

---

## Features

| Feature | Description |
|---------|-------------|
| ![fast](https://img.shields.io/badge/-Fast-f97316) | Runs on Cloudflare's global edge network (<50ms) |
| ![multiuser](https://img.shields.io/badge/-Multi--user-8b5cf6) | Each user has private links via Clerk auth |
| ![categories](https://img.shields.io/badge/-Categories-3b82f6) | Organize links with color coding |
| ![tags](https://img.shields.io/badge/-Tags-22c55e) | Flexible tagging system |
| ![search](https://img.shields.io/badge/-Search-06b6d4) | Instant search with Cmd+K |
| ![tracking](https://img.shields.io/badge/-Tracking-eab308) | Click analytics per link |
| ![backup](https://img.shields.io/badge/-Backup-64748b) | Import/Export as JSON |
| ![dark](https://img.shields.io/badge/-Dark_UI-18181b) | Clean Shadcn-style theme |
| ![free](https://img.shields.io/badge/-Free-10b981) | Runs on Cloudflare's free tier |

---

## How It Works

```
User clicks: links.example.com/gh
         ↓
Cloudflare Worker (edge, <50ms)
         ↓
D1 Database lookup
         ↓
302 Redirect → github.com/user/repo
```

### Stack

| Component | Technology |
|-----------|------------|
| Compute | Cloudflare Workers (serverless) |
| Database | Cloudflare D1 (SQLite at edge) |
| Auth | Clerk (Google OAuth) |
| CI/CD | GitHub Actions (auto-deploy) |

---

## After Deployment

### Admin Dashboard
Visit `https://your-domain.com/admin` to:
- Create, edit, delete links
- Organize with categories and tags
- Search your links
- View click statistics
- Export/import data

### Creating Links
Your links work like: `https://links.example.com/shortcode` → redirects to destination

### API
Full REST API available at `/api/*` - see [MANUAL.md](MANUAL.md) for endpoints.

---

## Costs

Everything runs on **Cloudflare's free tier**:

| Resource | Free Limit |
|----------|------------|
| Workers | 100,000 requests/day |
| D1 Database | 5GB storage |
| Clerk | 10,000 MAU |

![free](https://img.shields.io/badge/Cost-$0%2Fmonth-10b981) No credit card required. No surprise bills.

---

## Manual Setup

Prefer to set things up yourself? See **[MANUAL.md](MANUAL.md)** for:
- Step-by-step Cloudflare configuration
- GitHub Actions setup
- API documentation
- Database schema
- Troubleshooting

---

## Project Structure

```
URLsToGo/
├── src/
│   └── index.js        # Main Cloudflare Worker
├── migrations.sql      # D1 database schema
├── wrangler.toml       # Cloudflare config
├── .github/
│   └── workflows/
│       └── deploy.yml  # Auto-deploy on push
└── MANUAL.md           # Full documentation
```

---

## License

GPL-3.0 - See [LICENSE](LICENSE) for details.
