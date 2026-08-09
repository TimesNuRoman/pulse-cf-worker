// R257 + R260: POST /api/auth/login — email + password, returns session cookie.
//
// Security: returns generic 401 for both wrong-password and unverified-email
// to prevent email enumeration. Verification status is logged server-side.

import type { Env } from '../../worker';
import { verifyPassword } from '../lib/password';
import { createSession, buildSetCookie } from '../lib/session';
import { checkFailedLogin, recordLoginAttempt } from '../lib/rate-limit';
import { log } from '../lib/logger';

interface LoginBody {
	email?: string;
	password?: string;
}

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

export async function handleLogin(request: Request, env: Env, requestId: string, ip: string): Promise<Response> {
	// 1. Rate limit (per IP — failed attempts).
	const limit = await checkFailedLogin(env, ip);
	if (!limit.allowed) {
		return jsonResp({ error: 'rate_limited', retryAfter: limit.retryAfterSec }, 429, {
			'retry-after': String(limit.retryAfterSec ?? 60),
		});
	}

	// 2. Parse body.
	let body: LoginBody;
	try {
		body = (await request.json()) as LoginBody;
	} catch {
		return jsonResp({ error: 'invalid_json' }, 400);
	}
	const email = (body.email ?? '').trim();
	const password = body.password ?? '';
	if (!email || !password) {
		return jsonResp({ error: 'invalid_credentials' }, 401);
	}

	// 3. Find user.
	const user = await env.DB.prepare(
		`SELECT id, password_hash, email_verified FROM users WHERE lower(email) = lower(?) LIMIT 1`,
	)
		.bind(email)
		.first<{ id: string; password_hash: string; email_verified: number }>();

	// 4. Verify password (always run a hash even if user missing — prevent timing leak).
	const stored = user?.password_hash ?? 'pbkdf2$100000$AAAA$AAAA';
	const valid = await verifyPassword(password, stored);

	if (!user || !valid) {
		await recordLoginAttempt(env, ip, email, false);
		// Generic message — never say "user not found" vs "wrong password".
		return jsonResp({ error: 'invalid_credentials' }, 401);
	}

	// 5. Block login if not verified — but return SAME generic 401 to prevent enumeration.
	if (user.email_verified === 0) {
		await recordLoginAttempt(env, ip, email, false);
		log.info('login_unverified_attempt', { requestId, ip, userId: user.id });
		return jsonResp({ error: 'invalid_credentials' }, 401);
	}

	// 6. Issue session.
	const session = await createSession(env, user.id, request);
	const isHttps = new URL(request.url).protocol === 'https:';
	const cookie = buildSetCookie(session.id, session.expiresAt, isHttps);

	// 7. Update last_login_at.
	await env.DB.prepare(
		`UPDATE users SET last_login_at = ? WHERE id = ?`,
	)
		.bind(new Date().toISOString(), user.id)
		.run();

	await recordLoginAttempt(env, ip, email, true);
	log.info('login_success', { requestId, ip, userId: user.id });

	return jsonResp({ ok: true }, 200, { 'set-cookie': cookie });
}
