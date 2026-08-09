// R260: license endpoints.
//   POST /api/auth/license/validate {key} — public, rate limited; for desktop offline check
//   POST /api/auth/license/claim    {key} — session required; bind unclaimed license to user
//   GET  /api/auth/license             — session required; return current user's license

import type { Env } from '../../worker';
import { hashToken } from '../lib/tokens';
import { getSession, readSessionId } from '../lib/session';
import { log } from '../lib/logger';

const VALIDATE_LIMIT_PER_HOUR = 30; // per IP

function jsonResp(body: unknown, status: number, extraHeaders: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
			...extraHeaders,
		},
	});
}

interface LicenseRow {
	id: string;
	user_id: string | null;
	customer_email: string;
	plan: string;
	status: string;
	expires_at: string | null;
	created_at: string;
}

function isExpired(row: LicenseRow, nowMs: number): boolean {
	if (!row.expires_at) return false;
	return new Date(row.expires_at).getTime() < nowMs;
}

function presentLicense(row: LicenseRow) {
	return {
		plan: row.plan,
		status: row.status,
		expires_at: row.expires_at,
		created_at: row.created_at,
	};
}

// POST /api/auth/license/validate {key}  (public, rate-limited)
export async function handleLicenseValidate(request: Request, env: Env, _requestId: string, ip: string): Promise<Response> {
	// 1. Rate limit per IP (cheap DOS prevention).
	const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
	const rl = await env.DB.prepare(
		`SELECT COUNT(*) AS n FROM license_validations WHERE ip = ? AND created_at >= ?`,
	).bind(ip, since).first<{ n: number }>();
	if ((rl?.n ?? 0) >= VALIDATE_LIMIT_PER_HOUR) {
		return jsonResp({ error: 'rate_limited' }, 429, { 'retry-after': '3600' });
	}

	// 2. Parse.
	let body: { key?: string };
	try {
		body = (await request.json()) as { key?: string };
	} catch {
		return jsonResp({ error: 'invalid_json' }, 400);
	}
	const key = (body.key ?? '').trim();
	if (!key) {
		return jsonResp({ error: 'key_required' }, 400);
	}

	// 3. Lookup by hash.
	const keyHash = await hashToken(key);
	const nowMs = Date.now();
	const row = await env.DB.prepare(
		`SELECT id, user_id, customer_email, plan, status, expires_at, created_at
		 FROM licenses WHERE key_hash = ? LIMIT 1`,
	).bind(keyHash).first<LicenseRow>();

	const valid = !!row && row.status === 'active' && !isExpired(row, nowMs);

	// 4. Record attempt (always — even for invalid keys — for forensics).
	await env.DB.prepare(
		`INSERT INTO license_validations (key_hash, ip, valid) VALUES (?, ?, ?)`,
	).bind(keyHash, ip, valid ? 1 : 0).run();

	if (!valid || !row) {
		return jsonResp({ valid: false }, 200);
	}

	return jsonResp({ valid: true, ...presentLicense(row) }, 200);
}

// POST /api/auth/license/claim {key}  (session required)
export async function handleLicenseClaim(request: Request, env: Env, requestId: string, ip: string): Promise<Response> {
	const sessionId = readSessionId(request);
	if (!sessionId) return jsonResp({ error: 'unauthorized' }, 401);

	const session = await getSession(env, sessionId);
	if (!session) return jsonResp({ error: 'unauthorized' }, 401);

	const user = await env.DB.prepare(
		`SELECT id, email FROM users WHERE id = ? LIMIT 1`,
	).bind(session.user_id).first<{ id: string; email: string }>();
	if (!user) return jsonResp({ error: 'unauthorized' }, 401);

	let body: { key?: string };
	try {
		body = (await request.json()) as { key?: string };
	} catch {
		return jsonResp({ error: 'invalid_json' }, 400);
	}
	const key = (body.key ?? '').trim();
	if (!key) return jsonResp({ error: 'key_required' }, 400);

	const keyHash = await hashToken(key);
	const row = await env.DB.prepare(
		`SELECT id, user_id, customer_email, plan, status, expires_at, created_at
		 FROM licenses WHERE key_hash = ? LIMIT 1`,
	).bind(keyHash).first<LicenseRow>();

	if (!row) {
		return jsonResp({ error: 'invalid_key' }, 404);
	}
	if (row.status !== 'active' || isExpired(row, Date.now())) {
		return jsonResp({ error: 'license_inactive' }, 410);
	}
	// Email must match — prevents grabbing someone else's key.
	if (row.customer_email.toLowerCase() !== user.email.toLowerCase()) {
		log.warn('license_claim_email_mismatch', { requestId, userId: user.id });
		return jsonResp({ error: 'email_mismatch' }, 403);
	}
	if (row.user_id && row.user_id !== user.id) {
		return jsonResp({ error: 'already_claimed' }, 409);
	}

	const now = new Date().toISOString();
	await env.DB.prepare(
		`UPDATE licenses SET user_id = ?, updated_at = ? WHERE id = ? AND user_id IS NULL`,
	).bind(user.id, now, row.id).run();

	log.info('license_claimed', { requestId, userId: user.id, licenseId: row.id });
	return jsonResp({ ok: true, ...presentLicense({ ...row, user_id: user.id }) }, 200);
}

// GET /api/auth/license  (session required)
export async function handleLicenseStatus(request: Request, env: Env, requestId: string, _ip: string): Promise<Response> {
	const sessionId = readSessionId(request);
	if (!sessionId) return jsonResp({ error: 'unauthorized' }, 401);

	const session = await getSession(env, sessionId);
	if (!session) return jsonResp({ error: 'unauthorized' }, 401);

	const rows = await env.DB.prepare(
		`SELECT id, user_id, customer_email, plan, status, expires_at, created_at
		 FROM licenses WHERE user_id = ? ORDER BY created_at DESC LIMIT 5`,
	).bind(session.user_id).all<LicenseRow>();

	const nowMs = Date.now();
	const result = (rows.results ?? []).map((r) => ({
		...presentLicense(r),
		expired: isExpired(r, nowMs),
	}));

	return jsonResp({ licenses: result }, 200);
}
