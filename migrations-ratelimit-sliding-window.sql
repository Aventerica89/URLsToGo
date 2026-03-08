-- Add prev_count column to rate_limits for sliding window counter approximation
ALTER TABLE rate_limits ADD COLUMN prev_count INTEGER NOT NULL DEFAULT 0;
