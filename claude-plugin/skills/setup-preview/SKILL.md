---
description: Set up automatic preview link updates -- one command to wire GitHub Actions, API key, and workflow file.
---

# URLsToGo Setup Preview Links

Wire up automatic preview link updates so `go.urlstogo.cloud/{repo}--preview` always points to your latest deployment.

## Prerequisites

- `gh` CLI must be installed and authenticated (`gh auth status`)
- Project must be a git repo with a GitHub remote
- User must have a URLsToGo API key (run `/urlstogo setup` first if not)

## Steps

1. **Check prerequisites.** Verify `gh` is installed by running `gh auth status`. If not authenticated, tell the user to run `gh auth login` first. Also check that the current directory is a git repo with a GitHub remote by running `git remote get-url origin`.

2. **Get the URLsToGo API key.** Check for `URLSTOGO_API_KEY` in the environment or `.env`/`.env.local`. If not found, tell the user to run `/urlstogo setup` first and stop.

3. **Detect the deployment platform.** Check these files in order:
   - `vercel.json` or `.vercel/project.json` exists -> **Vercel**
   - `wrangler.toml` exists -> **Cloudflare Pages**
   - `.github/workflows/pages.yml` or `.github/workflows/deploy-pages.yml` exists -> **GitHub Pages**
   - None found -> ask the user which platform they use

4. **Get the repo name.** Parse it from the GitHub remote URL:
   ```bash
   basename -s .git $(git remote get-url origin)
   ```

5. **Store the API key as a GitHub secret.** Run:
   ```bash
   echo "$URLSTOGO_API_KEY" | gh secret set URLSTOGO_API_KEY
   ```
   If this fails, tell the user they may not have permission to set secrets on this repo.

6. **Create the workflow file.** Create `.github/workflows/update-preview-link.yml` with the content below. Make sure the `.github/workflows/` directory exists first.

   ```yaml
   name: Update Preview Link

   on:
     deployment_status:
     push:
       branches: [preview, staging, 'preview/**', 'feat/**']
     workflow_dispatch:

   env:
     REPO_NAME: ${{ github.event.repository.name }}
     URLSTOGO_DOMAIN: go.urlstogo.cloud
     DEPLOYMENT_PLATFORM: auto

   jobs:
     update-preview-link:
       name: Update Preview Link
       runs-on: ubuntu-latest
       if: |
         github.event_name == 'push' ||
         (github.event_name == 'deployment_status' && github.event.deployment_status.state == 'success') ||
         github.event_name == 'workflow_dispatch'
       steps:
         - uses: actions/checkout@v4

         - name: Detect deployment URL
           id: detect-url
           env:
             GH_REF_NAME: ${{ github.ref_name }}
             GH_REPO_NAME: ${{ github.event.repository.name }}
             GH_REPO_OWNER: ${{ github.repository_owner }}
             GH_EVENT_NAME: ${{ github.event_name }}
             GH_DEPLOYMENT_URL: ${{ github.event.deployment_status.environment_url }}
             PLATFORM: ${{ env.DEPLOYMENT_PLATFORM }}
           run: |
             set -euo pipefail
             DEPLOYMENT_URL=""
             if [ "$PLATFORM" = "auto" ]; then
               if [ -f "vercel.json" ] || [ -f ".vercel/project.json" ]; then
                 PLATFORM="vercel"
               elif [ -f "wrangler.toml" ]; then
                 PLATFORM="cloudflare-pages"
               elif [ -f ".github/workflows/pages.yml" ] || [ -f ".github/workflows/deploy-pages.yml" ]; then
                 PLATFORM="github-pages"
               fi
             fi
             slugify() {
               tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-//' | sed 's/-$//'
             }
             case "$PLATFORM" in
               vercel)
                 if [ "$GH_EVENT_NAME" = "deployment_status" ] && [ -n "$GH_DEPLOYMENT_URL" ]; then
                   DEPLOYMENT_URL="$GH_DEPLOYMENT_URL"
                 else
                   REPO_SLUG=$(echo "$GH_REPO_NAME" | slugify)
                   BRANCH_SLUG=$(echo "$GH_REF_NAME" | slugify)
                   OWNER_SLUG=$(echo "$GH_REPO_OWNER" | slugify)
                   DEPLOYMENT_URL="https://${REPO_SLUG}-git-${BRANCH_SLUG}-${OWNER_SLUG}.vercel.app"
                 fi ;;
               cloudflare-pages)
                 CF_PROJECT=$(echo "$GH_REPO_NAME" | slugify)
                 BRANCH_SLUG=$(echo "$GH_REF_NAME" | slugify)
                 DEPLOYMENT_URL="https://${BRANCH_SLUG}.${CF_PROJECT}.pages.dev" ;;
               github-pages)
                 OWNER_SLUG=$(echo "$GH_REPO_OWNER" | slugify)
                 REPO_SLUG=$(echo "$GH_REPO_NAME" | slugify)
                 DEPLOYMENT_URL="https://${OWNER_SLUG}.github.io/${REPO_SLUG}" ;;
               *)
                 echo "Could not detect platform. Set DEPLOYMENT_PLATFORM in the workflow."
                 exit 1 ;;
             esac
             { echo "url=$DEPLOYMENT_URL"; echo "platform=$PLATFORM"; } >> "$GITHUB_OUTPUT"

         - name: Update URLsToGo preview link
           env:
             URLSTOGO_API_KEY: ${{ secrets.URLSTOGO_API_KEY }}
             PREVIEW_CODE: ${{ github.event.repository.name }}--preview
             DEPLOYMENT_URL: ${{ steps.detect-url.outputs.url }}
           run: |
             set -euo pipefail
             RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
               -H "Authorization: Bearer $URLSTOGO_API_KEY" \
               -H "Content-Type: application/json" \
               --data "$(printf '{"destination":"%s"}' "$DEPLOYMENT_URL")" \
               "https://go.urlstogo.cloud/api/preview-links/${PREVIEW_CODE}")
             HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
             if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
               echo "Preview link updated: https://go.urlstogo.cloud/${PREVIEW_CODE}"
             else
               echo "Failed (HTTP $HTTP_CODE)"; exit 1
             fi
   ```

7. **Commit and push.** Stage the workflow file and commit:
   ```bash
   git add .github/workflows/update-preview-link.yml
   git commit -m "feat: add URLsToGo preview link workflow"
   git push
   ```

8. **Confirm success.** Tell the user:
   - "Done! Your preview link is set up."
   - Short URL: `go.urlstogo.cloud/{repo-name}--preview`
   - It will auto-update on every deployment to the detected platform.
   - Test by pushing to a preview branch or running the workflow manually from GitHub Actions.
