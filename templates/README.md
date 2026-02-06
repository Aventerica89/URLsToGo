# URLsToGo GitHub Actions Templates

Reusable workflow templates for integrating URLsToGo with your projects.

## Available Templates

### update-preview-link.yml

Automatically update URLsToGo shortlinks when preview deployments complete.

**Supports:**
- ✅ Vercel
- ✅ Cloudflare Pages
- ✅ GitHub Pages

**Quick Start:**

```bash
# Copy to your project repo
cp update-preview-link.yml /path/to/your-repo/.github/workflows/

# Add GitHub secret: URLSTOGO_API_KEY
# (Get from go.urlstogo.cloud/admin → API Keys)

# Push to any branch and watch the magic! ✨
```

**Full Documentation:** [docs/preview-links.md](../docs/preview-links.md)

## Contributing

Have a useful workflow template? Submit a PR!

Ideas:
- Slack notifications when links are clicked
- Weekly analytics reports
- Automatic link expiration for old previews
- Multi-environment support (staging, qa, etc.)
