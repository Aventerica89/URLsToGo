-- URL Shortener Database Schema
-- Run this to initialize the D1 database

CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  destination TEXT NOT NULL,
  clicks INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Example insert
-- INSERT INTO links (code, destination) VALUES ('test', 'https://example.com');
