-- AI provider integrations: encrypted API keys per user per provider
CREATE TABLE IF NOT EXISTS ai_integrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_email TEXT NOT NULL,
  provider TEXT NOT NULL,
  key_encrypted TEXT NOT NULL,
  key_iv TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(user_email, provider)
);

CREATE INDEX IF NOT EXISTS idx_ai_integrations_user ON ai_integrations(user_email);
