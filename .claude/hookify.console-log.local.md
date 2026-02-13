---
name: warn-console-log
enabled: true
event: file
pattern: console\.log\(|console\.debug\(|console\.warn\(
action: warn
---

⚠️ **Console logging detected**

You're adding `console.log()` or similar debugging statements.

**Reminders:**
- Remove debug logging before committing to production
- Consider using a proper logging library instead
- Use debugger or IDE breakpoints for debugging

**Common alternatives:**
- Production: Winston, Pino, or custom logger
- Development: Debugger, VSCode breakpoints
- Testing: Test framework assertions

This is just a reminder - the operation will proceed.
