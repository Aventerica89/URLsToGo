---
name: block-migration-edits
enabled: true
event: file
action: block
conditions:
  - field: file_path
    operator: regex_match
    pattern: (migrations?/|migration.*\.sql|.*\.migration\.|migrate/)
---

🚫 **Blocked: Database migration file edit**

You requested protection for database migration files.

**Why this is blocked:**
- Migration files should be append-only (create new migrations, don't edit old ones)
- Editing applied migrations can cause database inconsistencies
- Team members may have already run these migrations

**Recommended approach:**
1. Create a NEW migration file instead
2. Add your changes to the new migration
3. Apply the new migration: `wrangler d1 execute --file=migrations.sql`

**URLsToGo-specific:**
- Edit `migrations.sql` to ADD new statements (don't modify existing ones)
- Use `CREATE TABLE IF NOT EXISTS` for safety
- GitHub Actions will auto-apply on push to main

**To override this rule (not recommended):**
Edit `.claude/hookify.migration-files.local.md` and set `enabled: false`
