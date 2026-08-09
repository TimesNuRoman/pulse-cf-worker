-- R260: separate table for resend attempts (was sharing signup_attempts).
-- This lets us tune limits independently and not count resends against
-- the signup rate ceiling.
--
-- Cleanup: a scheduled Worker (TODO: cron trigger) should DELETE rows
-- older than 24h every hour to keep the table bounded.

CREATE TABLE IF NOT EXISTS resend_attempts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ip         TEXT NOT NULL,
  email      TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS resend_attempts_ip_time ON resend_attempts (ip, created_at DESC);
CREATE INDEX IF NOT EXISTS resend_attempts_email_time ON resend_attempts (lower(email), created_at DESC);
