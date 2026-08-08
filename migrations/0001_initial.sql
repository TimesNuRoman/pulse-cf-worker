-- R257: Pulse auth schema (D1 / SQLite)
-- Migration: 0001_initial.sql
-- Tables: users, email_verifications, signup_attempts, sessions, login_attempts
-- D1 quirks: BOOLEAN stored as INTEGER (0/1), UUIDs as TEXT, TIMESTAMPTZ as TEXT (ISO 8601).

CREATE TABLE IF NOT EXISTS users (
  id              TEXT PRIMARY KEY,
  email           TEXT UNIQUE NOT NULL,
  email_verified  INTEGER NOT NULL DEFAULT 0,
  name            TEXT NOT NULL,
  password_hash   TEXT NOT NULL,
  created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  last_login_at   TEXT
);
CREATE INDEX IF NOT EXISTS users_email_idx ON users (lower(email));

CREATE TABLE IF NOT EXISTS email_verifications (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash   TEXT UNIQUE NOT NULL,  -- sha256(raw token); raw only in user's email
  expires_at   TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS email_verifications_user_idx ON email_verifications (user_id);

CREATE TABLE IF NOT EXISTS signup_attempts (
  ip         TEXT NOT NULL,
  email      TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS signup_attempts_ip_time ON signup_attempts (ip, created_at DESC);
CREATE INDEX IF NOT EXISTS signup_attempts_email_time ON signup_attempts (email, created_at DESC);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash     TEXT PRIMARY KEY,   -- sha256(raw session id)
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS login_attempts (
  ip         TEXT NOT NULL,
  email      TEXT,
  success    INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS login_attempts_ip_time ON login_attempts (ip, created_at DESC);
