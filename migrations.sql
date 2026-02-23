-- URL Shortener Migrations (safe to run multiple times)
-- This file runs automatically on every deploy via GitHub Actions
--
-- IMPORTANT: CREATE TABLE/INDEX IF NOT EXISTS statements are idempotent and safe.
-- ALTER TABLE ADD COLUMN is NOT idempotent (fails if column exists) and will abort
-- remaining statements. Keep all ALTER TABLE at the END of this file.

-- Create categories table
CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  color TEXT DEFAULT 'gray',
  user_email TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(slug, user_email)
);

-- Create tags table
CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  user_email TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(name, user_email)
);

-- Create link_tags junction table
CREATE TABLE IF NOT EXISTS link_tags (
  link_id INTEGER NOT NULL,
  tag_id INTEGER NOT NULL,
  PRIMARY KEY (link_id, tag_id),
  FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE,
  FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

-- Click events table for detailed analytics
CREATE TABLE IF NOT EXISTS click_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_id INTEGER NOT NULL,
  clicked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  referrer TEXT,
  user_agent TEXT,
  country TEXT,
  city TEXT,
  device_type TEXT,
  browser TEXT,
  FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE
);

-- Rate limiting table
CREATE TABLE IF NOT EXISTS rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  identifier TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  request_count INTEGER DEFAULT 1,
  window_start DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(identifier, endpoint)
);

-- API keys table for programmatic access
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_email TEXT NOT NULL,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  scopes TEXT DEFAULT 'read,write',
  last_used_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME DEFAULT NULL,
  UNIQUE(key_hash)
);

-- User settings table (GitHub token, display name, etc.)
CREATE TABLE IF NOT EXISTS user_settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_email TEXT NOT NULL UNIQUE,
  github_token_encrypted TEXT DEFAULT NULL,
  github_token_iv TEXT DEFAULT NULL,
  github_username TEXT DEFAULT NULL,
  display_name TEXT DEFAULT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Repository sync tracking for Git Sync feature
CREATE TABLE IF NOT EXISTS repo_syncs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_email TEXT NOT NULL,
  repo_full_name TEXT NOT NULL,
  repo_name TEXT NOT NULL,
  repo_owner TEXT NOT NULL,
  is_active INTEGER DEFAULT 1,
  api_key_id INTEGER DEFAULT NULL,
  workflow_deployed INTEGER DEFAULT 0,
  secret_deployed INTEGER DEFAULT 0,
  last_sync_at DATETIME DEFAULT NULL,
  last_error TEXT DEFAULT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_email, repo_full_name),
  FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL
);

-- All indexes (idempotent with IF NOT EXISTS)
CREATE INDEX IF NOT EXISTS idx_links_user_email ON links(user_email);
CREATE INDEX IF NOT EXISTS idx_links_category ON links(category_id);
CREATE INDEX IF NOT EXISTS idx_categories_user ON categories(user_email);
CREATE INDEX IF NOT EXISTS idx_tags_user ON tags(user_email);
CREATE INDEX IF NOT EXISTS idx_link_tags_link ON link_tags(link_id);
CREATE INDEX IF NOT EXISTS idx_link_tags_tag ON link_tags(tag_id);
CREATE INDEX IF NOT EXISTS idx_click_events_link ON click_events(link_id);
CREATE INDEX IF NOT EXISTS idx_click_events_date ON click_events(clicked_at);
CREATE INDEX IF NOT EXISTS idx_click_events_country ON click_events(country);
CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier ON rate_limits(identifier);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_email);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_user_settings_email ON user_settings(user_email);
CREATE INDEX IF NOT EXISTS idx_repo_syncs_user ON repo_syncs(user_email);

-- Waitlist table for beta signups
CREATE TABLE IF NOT EXISTS waitlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  ip TEXT,
  country TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_waitlist_email ON waitlist(email);
CREATE INDEX IF NOT EXISTS idx_waitlist_created ON waitlist(created_at);

-- Shared category collections (public link to view all links in a category)
CREATE TABLE IF NOT EXISTS category_shares (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT NOT NULL UNIQUE,
  user_email TEXT NOT NULL,
  category_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_category_shares_token ON category_shares(token);
CREATE INDEX IF NOT EXISTS idx_category_shares_user ON category_shares(user_email);

-- =============================================================================
-- NOTE: The following ALTER TABLE columns already exist in production and
-- were removed from this file because D1 runs the entire file as a single
-- transaction -- a failing ALTER rolls back ALL statements including new
-- CREATE TABLE IF NOT EXISTS above. Columns present on links table:
--   expires_at, password_hash, description, is_preview_link
-- =============================================================================
