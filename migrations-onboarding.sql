CREATE TABLE IF NOT EXISTS user_preferences (
  user_email TEXT PRIMARY KEY,
  onboarding_completed_at TEXT DEFAULT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);
