# Changelog

All notable changes to the Artifact Manager Chrome Extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-02-01

### Fixed
- Save button placement now integrates with existing UI instead of overlapping title
- Button uses 3-strategy placement: existing container > action area > new row at bottom

### Changed
- Made Save button styling more compact (6px/12px padding, 12px font) to fit inline
- Removed absolute positioning that caused overlap issues

### Added
- Unit tests for button placement logic (`content.test.js`)
- CSS class `.artifact-manager-btn-row` for new button containers
- Version display in extension popup footer

## [1.0.0] - 2026-01-28

### Added
- Initial release
- Save artifacts from Claude.ai with one click
- Automatic artifact detection via MutationObserver
- Content extraction via clipboard, iframe, and code blocks
- Placeholder name validation (rejects "Saving...", "Loading...", etc.)
- Support for both published URLs and downloaded content
- Multi-method content extraction with fallbacks
- Connection status and statistics in popup
- Configurable Artifact Manager URL
