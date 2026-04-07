# GitHub OAuth for Git Sync — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace manual GitHub PAT entry with OAuth App authorization flow, keeping PAT as a fallback.

**Architecture:** Standard OAuth 2.0 Authorization Code flow via a GitHub OAuth App. Two new API routes handle the redirect and callback. The access token is encrypted and stored in the existing `github_token_encrypted` column — no schema changes needed.

**Tech Stack:** Cloudflare Workers (vanilla JS), GitHub OAuth API, Web Crypto API (existing encryption utils)

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `src/index.js` | Modify | Add 2 API routes + update UI rendering function |
| `wrangler.toml` | Modify | Add `GITHUB_OAUTH_CLIENT_ID` var |
| `CLAUDE.md` | Modify | Document GitHub OAuth section |

No new files. No schema changes. No new dependencies.

---

## Pre-requisites (manual, before coding)

- [ ] **Create GitHub OAuth App** at https://github.com/settings/developers
  - Application name: `URLsToGo`
  - Homepage URL: `https://urlstogo.cloud`
  - Authorization callback URL: `https://urlstogo.cloud/api/github/callback`
  - Note the Client ID and Client Secret
- [ ] **Store credentials**
  - `GITHUB_OAUTH_CLIENT_ID` → add to `wrangler.toml` `[vars]`
  - `GITHUB_OAUTH_CLIENT_SECRET` → `wrangler secret put GITHUB_OAUTH_CLIENT_SECRET`
  - Both → 1Password `urlstogo` item (App Dev vault)

---

### Task 1: Add OAuth authorize route

**Files:**
- Modify: `src/index.js` (add route near line ~1550, after the `DELETE github-token` route)

- [ ] **Step 1: Add `GET /api/github/authorize` route**

Insert after the `DELETE /api/settings/github-token` handler:

```javascript
// GitHub OAuth: redirect to GitHub authorization
if (path === 'api/github/authorize' && request.method === 'GET') {
  const clientId = env.GITHUB_OAUTH_CLIENT_ID;
  if (!clientId) return jsonResponse({ error: 'GitHub OAuth not configured' }, { status: 500 });

  // Generate random state for CSRF protection
  const state = crypto.randomUUID();
  const redirectUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&scope=repo,workflow&state=${state}`;

  return new Response(null, {
    status: 302,
    headers: {
      'Location': redirectUrl,
      'Set-Cookie': `gh_oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`,
    },
  });
}
```

- [ ] **Step 2: Verify route is reachable**

Deploy with `npx wrangler deploy`, then:
```bash
curl -sI "https://urlstogo.cloud/api/github/authorize" -H "Cookie: __session=..." | head -5
```
Expected: `302` redirect to `github.com/login/oauth/authorize`

- [ ] **Step 3: Commit**

```bash
git add src/index.js
git commit -m "feat: add GitHub OAuth authorize redirect route"
```

---

### Task 2: Add OAuth callback route

**Files:**
- Modify: `src/index.js` (add route immediately after the authorize route)

- [ ] **Step 1: Add `GET /api/github/callback` route**

```javascript
// GitHub OAuth: callback — exchange code for token
if (path === 'api/github/callback' && request.method === 'GET') {
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  // Verify CSRF state
  const cookies = request.headers.get('Cookie') || '';
  const stateMatch = cookies.match(/gh_oauth_state=([^;]+)/);
  const savedState = stateMatch ? stateMatch[1] : null;

  if (!code || !state || state !== savedState) {
    return htmlResponse('<html><body><h1>Authorization failed</h1><p>Invalid state parameter. <a href="/admin#settings/git-sync">Try again</a></p></body></html>', 400);
  }

  // Exchange code for access token
  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      client_id: env.GITHUB_OAUTH_CLIENT_ID,
      client_secret: env.GITHUB_OAUTH_CLIENT_SECRET,
      code,
    }),
  });

  const tokenData = await tokenRes.json();
  if (tokenData.error || !tokenData.access_token) {
    return htmlResponse(`<html><body><h1>Authorization failed</h1><p>${tokenData.error_description || 'Unknown error'}. <a href="/admin#settings/git-sync">Try again</a></p></body></html>`, 400);
  }

  // Get GitHub username
  const ghRes = await fetch('https://api.github.com/user', {
    headers: { 'Authorization': `token ${tokenData.access_token}`, 'User-Agent': 'URLsToGo/1.0' },
  });
  const ghUser = await ghRes.json();

  // Encrypt and store (same as PAT flow)
  const { encrypted, iv } = await encryptToken(tokenData.access_token, env.GITHUB_TOKEN_ENCRYPTION_KEY);
  await env.DB.prepare(`
    INSERT INTO user_settings (user_email, github_token_encrypted, github_token_iv, github_username, updated_at)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(user_email) DO UPDATE SET
      github_token_encrypted = excluded.github_token_encrypted,
      github_token_iv = excluded.github_token_iv,
      github_username = excluded.github_username,
      updated_at = CURRENT_TIMESTAMP
  `).bind(userEmail, encrypted, iv, ghUser.login).run();

  // Clear state cookie and redirect to settings
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/admin#settings/git-sync',
      'Set-Cookie': 'gh_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0',
    },
  });
}
```

- [ ] **Step 2: Test the full OAuth flow manually**

1. Visit `https://urlstogo.cloud/api/github/authorize`
2. Authorize on GitHub
3. Verify redirect back to `/admin#settings/git-sync`
4. Verify GitHub username shows as connected

- [ ] **Step 3: Commit**

```bash
git add src/index.js
git commit -m "feat: add GitHub OAuth callback route with token exchange"
```

---

### Task 3: Update UI — OAuth button + PAT fallback

**Files:**
- Modify: `src/index.js` — `renderGitSyncSetup()` function (~line 9101)

- [ ] **Step 1: Replace `renderGitSyncSetup` function**

Replace the existing function with:

```javascript
function renderGitSyncSetup(container) {
  container.textContent = '';
  const card = document.createElement('div');
  card.className = 'settings-card';

  const title = document.createElement('div');
  title.style.cssText = 'font-weight:500;margin-bottom:8px';
  title.textContent = 'Connect GitHub';
  card.appendChild(title);

  const desc = document.createElement('p');
  desc.style.cssText = 'font-size:13px;color:oklch(var(--muted-foreground));margin-bottom:16px';
  desc.textContent = 'Connect your GitHub account to automatically update preview links when you push code.';
  card.appendChild(desc);

  // OAuth button
  const oauthBtn = document.createElement('a');
  oauthBtn.href = '/api/github/authorize';
  oauthBtn.className = 'btn btn-default';
  oauthBtn.style.cssText = 'display:inline-flex;align-items:center;gap:8px;text-decoration:none;margin-bottom:16px';
  oauthBtn.innerHTML = '<svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg> Connect with GitHub';
  card.appendChild(oauthBtn);

  // PAT fallback (collapsed)
  const toggle = document.createElement('div');
  toggle.style.cssText = 'font-size:12px;color:oklch(var(--muted-foreground));cursor:pointer;margin-bottom:8px';
  toggle.textContent = 'Or use a personal access token instead';
  toggle.onclick = () => { patSection.style.display = patSection.style.display === 'none' ? 'block' : 'none'; };
  card.appendChild(toggle);

  const patSection = document.createElement('div');
  patSection.style.display = 'none';

  const patLink = document.createElement('a');
  patLink.href = 'https://github.com/settings/tokens/new?scopes=repo,workflow&description=URLsToGo+Git+Sync';
  patLink.target = '_blank';
  patLink.rel = 'noopener';
  patLink.style.cssText = 'color:oklch(var(--indigo));text-decoration:underline;font-size:13px;display:inline-block;margin-bottom:8px';
  patLink.textContent = 'Create token on GitHub';
  patSection.appendChild(patLink);

  const row = document.createElement('div');
  row.style.cssText = 'display:flex;gap:8px';
  const input = document.createElement('input');
  input.type = 'password';
  input.className = 'input';
  input.id = 'githubTokenInput';
  input.placeholder = 'ghp_xxxxxxxxxxxx';
  input.style.flex = '1';
  row.appendChild(input);
  const btn = document.createElement('button');
  btn.className = 'btn btn-default';
  btn.textContent = 'Connect';
  btn.onclick = saveGitHubToken;
  row.appendChild(btn);
  patSection.appendChild(row);

  card.appendChild(patSection);
  container.appendChild(card);
}
```

- [ ] **Step 2: Update Guide tab step 1 text**

Find the setup steps array (~line 6599) and update step 1:
```javascript
{ n: 1, t: 'Connect GitHub above', d: 'Click "Connect with GitHub" to authorize via OAuth. Or expand "Use a personal access token" if you prefer manual setup.' },
```

- [ ] **Step 3: Deploy and verify UI**

```bash
npx wrangler deploy
```

Visit `/admin#settings/git-sync`, verify:
- "Connect with GitHub" button visible
- "Or use a personal access token instead" collapsed link
- Clicking PAT link expands the token input
- OAuth button links to `/api/github/authorize`

- [ ] **Step 4: Commit**

```bash
git add src/index.js
git commit -m "feat: update Git Sync UI with OAuth button and PAT fallback"
```

---

### Task 4: Add env vars to wrangler.toml + CSP update

**Files:**
- Modify: `wrangler.toml` — add `GITHUB_OAUTH_CLIENT_ID` to `[vars]`
- Modify: `src/index.js` — CSP `connect-src` add `https://github.com`

- [ ] **Step 1: Add client ID to wrangler.toml**

```toml
[vars]
CLERK_PUBLISHABLE_KEY = "pk_live_Y2xlcmsudXJsc3RvZ28uY2xvdWQk"
GITHUB_OAUTH_CLIENT_ID = "<client-id-from-github>"
```

- [ ] **Step 2: Set client secret via wrangler**

```bash
echo "<client-secret>" | npx wrangler secret put GITHUB_OAUTH_CLIENT_SECRET
```

- [ ] **Step 3: Store in 1Password**

Add `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET` fields to `urlstogo` item in App Dev vault.

- [ ] **Step 4: Commit**

```bash
git add wrangler.toml src/index.js
git commit -m "chore: add GitHub OAuth env vars"
```

---

### Task 5: End-to-end test + PR

- [ ] **Step 1: Full OAuth flow test**

1. Go to `/admin#settings/git-sync`
2. Click "Connect with GitHub"
3. Authorize on GitHub
4. Verify redirect back with "Connected as @username"
5. Verify repo list loads
6. Disconnect, verify cleanup
7. Re-connect via PAT fallback, verify it still works

- [ ] **Step 2: Push and create PR**

```bash
git push -u origin claude/github-oauth-...
gh pr create --title "feat: GitHub OAuth for Git Sync" --body "..."
```
