// R257 + R260: GET /api/auth/verify?token=... — mark user verified, issue session cookie.
//
// Returns JSON: { ok: true, redirect: '/?welcome=1' } or { error: 'invalid|expired|missing_token' }.
// The Astro /verify page does the fetch and handles the redirect — keeps the Worker
// as a pure JSON API and avoids circular redirect through env.ASSETS in local dev.

import type { Env } from '../../worker';
import { hashToken } from '../lib/tokens';
import { createSession, buildSetCookie } from '../lib/session';
import { log } from '../lib/logger';

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

export async function handleVerify(request: Request, env: Env, requestId: string, ip: string): Promise<Response> {
	const url = new URL(request.url);
	const token = url.searchParams.get('token') ?? '';
	if (!token) {
		return jsonResp({ error: 'missing_token' }, 400);
	}

	const tokenHash = await hashToken(token);
	const now = new Date().toISOString();

	// 1. Look up the verification row.
	const row = await env.DB.prepare(
		`SELECT ev.user_id, ev.expires_at, u.email_verified
		 FROM email_verifications ev
		 JOIN users u ON u.id = ev.user_id
		 WHERE ev.token_hash = ? LIMIT 1`,
	)
		.bind(tokenHash)
		.first<{ user_id: string; expires_at: string; email_verified: number }>();

	if (!row) {
		log.info('verify_invalid_token', { requestId, ip });
		return jsonResp({ error: 'invalid' }, 400);
	}
	if (row.expires_at < now) {
		// Expired — clean up the token.
		await env.DB.prepare(`DELETE FROM email_verifications WHERE token_hash = ?`).bind(tokenHash).run();
		log.info('verify_expired_token', { requestId, ip, userId: row.user_id });
		return jsonResp({ error: 'expired' }, 400);
	}

	// 2. Mark user as verified (idempotent — if already verified, just create session).
	if (row.email_verified === 0) {
		await env.DB.prepare(
			`UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ?`,
		)
			.bind(now, row.user_id)
			.run();
	}

	// 3. Delete the verification token (one-time use).
	await env.DB.prepare(`DELETE FROM email_verifications WHERE token_hash = ?`).bind(tokenHash).run();

	// 4. Issue session cookie.
	const session = await createSession(env, row.user_id);
	const isHttps = new URL(request.url).protocol === 'https:';
	const cookie = buildSetCookie(session.id, session.expiresAt, isHttps);

	log.info('verify_success', { requestId, ip, userId: row.user_id });

	// 5. Return JSON — Astro /verify page handles redirect.
	return jsonResp({ ok: true, redirect: '/?welcome=1' }, 200, { 'set-cookie': cookie });
}
