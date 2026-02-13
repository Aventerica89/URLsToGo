---
name: warn-dangerous-rm
enabled: true
event: bash
pattern: rm\s+-rf|rm\s+-fr
action: warn
---

⚠️ **Dangerous rm command detected**

You're about to run a recursive delete operation (`rm -rf`).

**Please verify:**
- The path is correct and specific (not `/`, `/home`, `/workspace`, etc.)
- You have backups if needed
- This is intentional

Consider using more specific paths or `trash` command for safer deletion.
