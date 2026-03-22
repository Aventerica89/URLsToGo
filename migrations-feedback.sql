-- Feedback table for landing page and in-app feedback forms
CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message TEXT NOT NULL,
  email TEXT,
  page TEXT DEFAULT 'landing',
  source TEXT DEFAULT 'form',
  user_agent TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at);
