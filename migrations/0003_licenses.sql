-- R260: Pulse license keys (Polar.sh as Merchant of Record).
--
-- Flow:
--   1. User buys PRO on Polar.sh (customer_email captured at checkout)
--   2. Polar webhook → POST /api/polar/webhook with event license_key.created
--   3. Worker stores license keyed by sha256(raw_key); raw_key never in DB
--   4. User logs in (or registers with same email) and claims: POST /api/auth/license/claim {key}
--   5. Worker sets user_id on the license row (only if customer_email matches user.email)
--   6. Desktop app validates key on launch: POST /api/auth/license/validate {key}
--
-- `user_id` is nullable so the license row can be created before the user
-- registers. The claim endpoint matches by customer_email.

CREATE TABLE IF NOT EXISTS licenses (
  id                  TEXT PRIMARY KEY,
  key_hash            TEXT UNIQUE NOT NULL,        -- sha256(raw key)
  polar_license_id    TEXT UNIQUE NOT NULL,        -- id from Polar
  polar_subscription_id TEXT,                      -- for subscription events
  user_id             TEXT REFERENCES users(id) ON DELETE SET NULL,
  customer_email      TEXT NOT NULL,              -- from Polar checkout
  plan                TEXT NOT NULL,              -- 'monthly' | 'annual'
  status              TEXT NOT NULL DEFAULT 'active', -- 'active' | 'revoked' | 'expired'
  expires_at          TEXT,                       -- nullable for one-time keys
  created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS licenses_user_idx ON licenses (user_id);
CREATE INDEX IF NOT EXISTS licenses_email_idx ON licenses (lower(customer_email));
CREATE INDEX IF NOT EXISTS licenses_status_idx ON licenses (status);

CREATE TABLE IF NOT EXISTS license_validations (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  key_hash    TEXT NOT NULL,
  ip          TEXT,
  valid       INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS license_validations_ip_time ON license_validations (ip, created_at DESC);
CREATE INDEX IF NOT EXISTS license_validations_key_time ON license_validations (key_hash, created_at DESC);
