// R257: GET /api/auth/verify?token=... — mark user verified, issue session cookie, redirect to /chat.

import type { Env } from '../../worker';
import { hashToken, tokensEqual } from '../lib/tokens';
import { createSession, buildSetCookie } from '../lib/session';

function clientIp(request: Request): string {
	return request.headers.get('CF-Connecting-IP') ?? 'unknown';
}

export async function handleVerify(request: Request, env: Env): Promise<Response> {
	const url = new URL(request.url);
	const token = url.searchParams.get('token') ?? '';
	if (!token) {
		return Response.redirect(`${env.PUBLIC_APP_URL}/verify?error=missing_token`, 302);
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
		return Response.redirect(`${env.PUBLIC_APP_URL}/verify?error=invalid`, 302);
	}
	if (row.expires_at < now) {
		// Expired — clean up the token.
		await env.DB.prepare(`DELETE FROM email_verifications WHERE token_hash = ?`).bind(tokenHash).run();
		return Response.redirect(`${env.PUBLIC_APP_URL}/verify?error=expired`, 302);
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

	// 5. Redirect to /chat (we don't have /chat yet — redirect to / for now).
	const dest = `${env.PUBLIC_APP_URL}/?welcome=1`;
	return new Response(null, {
		status: 302,
		headers: {
			'location': dest,
			'set-cookie': cookie,
		},
	});
}

// Defensive: tokensEqual kept imported for future constant-time checks in the lookup path.
export { tokensEqual };
