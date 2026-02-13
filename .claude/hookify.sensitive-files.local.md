---
name: block-sensitive-files
enabled: true
event: file
action: block
conditions:
  - field: file_path
    operator: regex_match
    pattern: (\.env|\.env\.|credentials|secrets|\.password|api[_-]?keys?|\.pem|\.key|\.crt)
---

🔒 **Blocked: Sensitive file edit detected**

You requested protection for credentials and secrets files.

**This rule blocks edits to files containing:**
- `.env` or `.env.*` (environment variables)
- `credentials` or `secrets`
- `api_key` or `api-key`
- `.pem`, `.key`, `.crt` (certificates/keys)

**To edit these files:**
1. Temporarily disable this rule: Edit `.claude/hookify.sensitive-files.local.md`
2. Set `enabled: false`
3. Make your changes
4. Re-enable the rule: Set `enabled: true`

**Security reminder:** Never commit these files to git!
