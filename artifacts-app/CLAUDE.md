# Artifact Manager - Web Version

A Cloudflare Worker app to track and organize Claude.ai artifacts.

## Project Sync Rule (CRITICAL)

**This project has a companion macOS app** at `/Users/jb/artifact-manager-mac/`

When making changes to core functionality, **ALWAYS apply the same changes to both projects**:

### Core Features That Must Stay in Sync:

1. **Name Validation** (`NameValidator`)
   - Web: JavaScript in `worker.js` (line ~2370) + Server function (line ~607)
   - macOS: Swift in `Artifact Manager/NameValidator.swift`

2. **Placeholder Patterns**
   - Must detect: "Saving...", "Loading...", "Downloading...", "Untitled", empty strings
   - Both projects should reject the same patterns

3. **Cleanup Utility**
   - Web: Cleanup modal + API endpoints (`/api/cleanup/scan`, `/api/cleanup/fix`)
   - macOS: `CleanupUtility.swift` with UI

4. **Artifact Model**
   - Web: Database schema in `migrations.sql`
   - macOS: SwiftData model in `Item.swift`

### When Adding Features:

1. Implement in the web version first (faster to test)
2. Translate to macOS Swift version
3. Test both versions
4. Deploy web version: `wrangler deploy`
5. Build and test macOS version: `swift build && swift test`

### Key Differences (These DON'T need to sync):

- **Storage**: Web uses D1 (SQLite), macOS uses SwiftData
- **Auth**: Web uses Cloudflare Access, macOS is local-only
- **UI Framework**: Web uses vanilla HTML/JS, macOS uses SwiftUI
- **Deployment**: Web via Wrangler, macOS via Xcode

## Deployment

### Web Version (This Project)
```bash
CLOUDFLARE_ACCOUNT_ID=e2613c1c17024c32ab14618614e2b309 wrangler deploy
```

### macOS Version
```bash
cd /Users/jb/artifact-manager-mac
swift build
swift test
# Then build in Xcode and distribute
```

## Testing

### Web
```bash
wrangler dev  # Local development
```

### macOS
```bash
swift test    # Run unit tests
```

## Recent Changes

### 2026-01-28: Placeholder Name Validation
- Added NameValidator to prevent "Saving...", "Loading...", "Downloading..." names
- Added cleanup utility UI with scan and fix functionality
- Server-side validation in POST/PUT endpoints
- ✅ Synced to macOS version
