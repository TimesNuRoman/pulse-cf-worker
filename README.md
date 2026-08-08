# pulse-cf-worker

Cloudflare Worker for `ownlocalml.com`. Two jobs in one bundle:

1. **Static site** — serves the Pulse landing site from Workers Static Assets
   (built output of `../pulse-landing/dist`).
2. **Auth API** — handles `/api/auth/*` (signup, verify, login, logout, resend)
   on D1 `pulse-auth`, sends transactional email via Resend.

Both deploy together with one `wrangler deploy` — Worker code + static assets
in a single bundle, one URL, one deploy.

## Architecture

```
request → worker.fetch
  ├── /api/auth/*   → handleApi() → D1 + Resend
  └── everything else → env.ASSETS.fetch() → static files
```

Custom `fetch` handler in `src/worker.ts`:
- `[[assets]]` in `wrangler.toml` declares the static directory
  (`../pulse-landing/dist`).
- `main = "src/worker.ts"` runs the Worker.
- `[[d1_databases]]` binding `DB` to D1 database `pulse-auth`.

## Local dev

```pwsh
cd H:\.sandbox\projects\pulse-cf-worker
npm install
npx wrangler d1 execute pulse-auth --local --file=./migrations/0001_initial.sql
npx wrangler dev --local --port 8787
```

The Astro landing site is served automatically from `../pulse-landing/dist`
(re-run `npx astro build` in `pulse-landing` to refresh).

## Required secrets

Set these before deploying to production (one-time, via Wrangler):

```pwsh
wrangler secret put RESEND_API_KEY       # from resend.com
wrangler secret put FROM_EMAIL           # e.g. "Pulse <noreply@ownlocalml.com>"
wrangler secret put PUBLIC_APP_URL       # e.g. "https://ownlocalml.com"
```

For dev, set `DEV_LOG_EMAIL=1` (regular env var, not secret) to log emails
to console instead of calling Resend.

## Deploy

```pwsh
# 1. Build the Astro site (if landing changed)
cd ../pulse-landing
npx astro build

# 2. Deploy worker + assets together
cd ../pulse-cf-worker
npx wrangler deploy
```

## D1 migrations

```pwsh
# Local
npx wrangler d1 execute pulse-auth --local --file=./migrations/0001_initial.sql

# Production
npx wrangler d1 execute pulse-auth --remote --file=./migrations/0001_initial.sql
```

## Auth flow

1. `POST /api/auth/signup` — create user, hash password (PBKDF2-SHA256 600k),
   store verification token (sha256-hashed), send email via Resend.
2. User clicks link in email → `GET /api/auth/verify?token=...` — mark verified,
   issue session cookie, redirect.
3. `POST /api/auth/login` — verify password (timing-safe), check verified,
   issue session.
4. `POST /api/auth/logout` — clear cookie + delete session row.
5. `POST /api/auth/resend` — regenerate verification token (silent 200).

Rate limits: 5/h per IP, 3/h per email for signup; 10/15min per IP for failed
login. Sessions: opaque 32-byte tokens stored as sha256 in `sessions` table,
TTL 30 days, cookie `HttpOnly; Secure; SameSite=Lax`.

## Security

- PBKDF2-SHA256 600k iterations (OWASP 2024 baseline) — Web Crypto, no WASM
- Tokens and session IDs stored as sha256, never in plaintext
- Honeypot field on signup form — silent 200, no account created
- Constant-time comparison for password and token equality
- Security headers on all API responses (CSP, HSTS, X-Frame-Options, etc.)
- Same-origin only by default; CORS allow-list for `ownlocalml.com` and `localhost`
- Email enumeration prevented (resend always returns 200)

## Related repos

- `pulse-landing` — Astro static site (input to this worker)
- `pulse-desktop` — Tauri v2 desktop app (TBD: integrate with auth for sync)
- `pulse-android` — Capacitor Android app (TBD: integrate with auth for sync)
