---
description: Connect Claude Code to your URLsToGo account. Sets up API key for all other /urlstogo commands.
---

# URLsToGo Setup

Connect this project to your URLsToGo account.

## Steps

1. **Check for existing API key.** Look for `URLSTOGO_API_KEY` in the environment, `.env`, or `.env.local` files in the current project. If found, skip to step 3.

2. **Ask the user for their API key.** Tell them:
   - Go to https://go.urlstogo.cloud/admin and sign in
   - Click Settings in the sidebar, then API Keys
   - Create a new key with **Write** scope
   - Copy the key (starts with `utg_`)
   - Paste it here

3. **Validate the key.** Run this curl command to confirm it works:

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $URLSTOGO_API_KEY" \
  https://go.urlstogo.cloud/api/links?limit=1
```

If the response is `200`, the key is valid. If `401` or `403`, tell the user the key is invalid and ask them to try again.

4. **Store the key.** If the project has a `.env` or `.env.local` file, append `URLSTOGO_API_KEY=utg_...` to it. If neither exists, create `.env.local` with the key. Make sure `.env.local` is in `.gitignore`.

5. **Confirm success.** Tell the user:
   - "Connected to URLsToGo! Your API key is stored in `.env.local`."
   - "You can now use `/urlstogo create-link`, `/urlstogo stats`, `/urlstogo setup-preview`, and `/urlstogo import`."
