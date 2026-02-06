# For Next Claude Session

## What This Project Is
URLsToGo - Fast, free URL shortener on Cloudflare Workers with dynamic preview link support

## Current State (2026-02-06)
🚧 **BROKEN:** Admin page has syntax error in escapeJs function
✅ **DONE:** Dynamic preview links feature merged
📋 **PENDING:** Merge PR with charCode fix

## Tech Stack
- Cloudflare Workers (edge compute)
- D1 Database (SQLite)
- Clerk Authentication (Google OAuth)
- GitHub Actions (CI/CD)
- Domain: go.urlstogo.cloud

## Critical Open Issue
**PR to merge:** https://github.com/Aventerica89/URLsToGo/pull/new/claude/fix-escapejs-charcode-lYOO5
**Problem:** Template literal escape sequences causing syntax errors
**Solution:** Use charCodeAt() for special character detection
**Impact:** Admin page completely broken until fixed

## Next Actions
1. Create and merge PR for charCode fix
2. Verify admin page works after deployment
3. Create API keys for preview link setup:
   - `bricks-cc-preview`
   - `jb-cloud-app-tracker-preview`
4. Add workflow files to those repos

## Key Files to Know
| File | Purpose |
|------|---------|
| `src/index.js` | Main worker code (~6500 lines) |
| `migrations.sql` | Auto-runs on deploy |
| `CLAUDE.md` | Full instructions (READ THIS!) |
| `SESSION_LOG.md` | Detailed session notes |
| `templates/update-preview-link.yml` | Preview link workflow |

## Git Workflow Rules
- ❌ Can't push to `main` (403 error)
- ✅ Must push to `claude/*-{sessionID}` branches
- 🔄 Merge via PR → auto-deploy (~2 min)

## Quick Reference Commands
```bash
# Check deployment status
git log --oneline -3

# View GitHub Actions
# https://github.com/Aventerica89/URLsToGo/actions

# Test admin page
curl -I https://go.urlstogo.cloud/admin

# After admin is fixed, create API key at:
# https://go.urlstogo.cloud/admin
```

## Important Context
- User tried editing in Cloudflare dashboard → syntax errors
- Multiple attempts at fixing escapeJs function failed
- Template literal escaping is tricky - use charCode approach
- Always review Gemini/Cubic bot feedback on PRs
- Deployment is automatic via GitHub Actions

**Start Here:** Read SESSION_LOG.md for full details, then merge the pending PR!
