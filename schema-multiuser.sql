-- URL Shortener Database Schema (Multi-user version with Categories & Tags)
-- Run this to initialize or migrate the D1 database

-- Categories table
CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  color TEXT DEFAULT 'gray',
  user_email TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(slug, user_email)
);

-- Tags table
CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  user_email TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(name, user_email)
);

-- Links table (updated with category support)
CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  destination TEXT NOT NULL,
  clicks INTEGER DEFAULT 0,
  user_email TEXT NOT NULL,
  category_id INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
);

-- Junction table for link-tag many-to-many relationship
CREATE TABLE IF NOT EXISTS link_tags (
  link_id INTEGER NOT NULL,
  tag_id INTEGER NOT NULL,
  PRIMARY KEY (link_id, tag_id),
  FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE,
  FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

-- Indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_links_user_email ON links(user_email);
CREATE INDEX IF NOT EXISTS idx_links_category ON links(category_id);
CREATE INDEX IF NOT EXISTS idx_categories_user ON categories(user_email);
CREATE INDEX IF NOT EXISTS idx_tags_user ON tags(user_email);
CREATE INDEX IF NOT EXISTS idx_link_tags_link ON link_tags(link_id);
CREATE INDEX IF NOT EXISTS idx_link_tags_tag ON link_tags(tag_id);

-- Default categories (run after creating tables, replace YOUR_EMAIL)
-- INSERT INTO categories (name, slug, color, user_email) VALUES
--   ('Work', 'work', 'violet', 'YOUR_EMAIL'),
--   ('Personal', 'personal', 'pink', 'YOUR_EMAIL'),
--   ('Social Media', 'social', 'cyan', 'YOUR_EMAIL'),
--   ('Marketing', 'marketing', 'orange', 'YOUR_EMAIL'),
--   ('Documentation', 'docs', 'green', 'YOUR_EMAIL');

-- Migration from old schema:
-- ALTER TABLE links ADD COLUMN category_id INTEGER;
