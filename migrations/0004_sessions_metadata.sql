-- R261: extend sessions with device metadata for the Active Sessions UI.
-- Existing rows get empty defaults (UI shows generic "Unknown device").

ALTER TABLE sessions ADD COLUMN device_type TEXT NOT NULL DEFAULT 'web';
ALTER TABLE sessions ADD COLUMN device_name TEXT NOT NULL DEFAULT 'Unknown device';
ALTER TABLE sessions ADD COLUMN user_agent TEXT;
ALTER TABLE sessions ADD COLUMN ip_hash TEXT;

-- Index for the /api/account/sessions list (most recent first per user).
CREATE INDEX IF NOT EXISTS sessions_user_created ON sessions (user_id, created_at DESC);
