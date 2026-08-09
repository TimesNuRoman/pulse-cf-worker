// R257 + R260: POST /api/auth/signup — create account, send verification email.
// Spec §5.2: returns JSON { ok } or { error, field? }.
//
// Security: cleanup of old verification tokens before insert prevents token
// accumulation on repeated signups. D1 batch (db.batch) runs INSERT into users
// and email_verifications atomically — if one fails, neither persists.

import type { Env } from '../../worker';
import { hashPassword, isValidEmail, isValidPassword } from '../lib/password';
import { randomToken, hashToken } from '../lib/tokens';
import { sendEmail, buildVerificationEmail } from '../lib/email';
import { checkSignupIp, checkSignupEmail, recordSignupAttempt } from '../lib/rate-limit';
import { log } from '../lib/logger';
import { appUrl } from '../lib/app-url';

interface SignupBody {
	name?: string;
	email?: string;
	password?: string;
	agreedToTerms?: boolean;
	company?: string; // honeypot
}

function jsonResp(body: unknown, status: number, request: Request, extraHeaders: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
			...extraHeaders,
		},
	});
}

export async function handleSignup(request: Request, env: Env, requestId: string, ip: string): Promise<Response> {
	// 1. Parse body.
	let body: SignupBody;
	try {
		body = (await request.json()) as SignupBody;
	} catch {
		return jsonResp({ error: 'invalid_json' }, 400, request);
	}

	// 2. Honeypot — silent 200, no user created, no log noise.
	if (typeof body.company === 'string' && body.company.length > 0) {
		log.info('honeypot_triggered', { requestId, ip });
		return jsonResp({ ok: true }, 200, request);
	}

	// 3. Validate fields.
	const name = (body.name ?? '').trim();
	const email = (body.email ?? '').trim();
	const password = body.password ?? '';

	if (name.length === 0 || name.length > 80) {
		return jsonResp({ error: 'name_required', field: 'name' }, 400, request);
	}
	if (!isValidEmail(email)) {
		return jsonResp({ error: 'invalid_email', field: 'email' }, 400, request);
	}
	if (!isValidPassword(password)) {
		return jsonResp({ error: 'weak_password', field: 'password' }, 400, request);
	}
	if (body.agreedToTerms !== true) {
		return jsonResp({ error: 'terms_required', field: 'terms' }, 400, request);
	}

	// 4. Rate limit (per IP and per email).
	const ipLimit = await checkSignupIp(env, ip);
	if (!ipLimit.allowed) {
		return jsonResp({ error: 'rate_limited', retryAfter: ipLimit.retryAfterSec }, 429, request, {
			'retry-after': String(ipLimit.retryAfterSec ?? 60),
		});
	}
	const emailLimit = await checkSignupEmail(env, email);
	if (!emailLimit.allowed) {
		return jsonResp({ error: 'rate_limited', retryAfter: emailLimit.retryAfterSec }, 429, request, {
			'retry-after': String(emailLimit.retryAfterSec ?? 60),
		});
	}

	// 5. Record attempt (success or not — counts against both limits).
	await recordSignupAttempt(env, ip, email);

	// 6. Check if email already exists.
	const existing = await env.DB.prepare(
		`SELECT id FROM users WHERE lower(email) = lower(?) LIMIT 1`,
	)
		.bind(email)
		.first<{ id: string }>();
	if (existing) {
		// Generic 409 — already documented as email_taken. Keeping for UX;
		// rate limit per email + per IP prevents enumeration at scale.
		return jsonResp({ error: 'email_taken' }, 409, request);
	}

	// 7. Create user + cleanup old verification tokens + create new one — atomically.
	const userId = crypto.randomUUID();
	const passwordHash = await hashPassword(password);
	const now = new Date().toISOString();
	const token = randomToken();
	const tokenHash = await hashToken(token);
	const verificationId = crypto.randomUUID();
	const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

	try {
		await env.DB.batch([
			env.DB.prepare(
				`INSERT INTO users (id, email, name, password_hash, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, 0, ?, ?)`,
			).bind(userId, email, name, passwordHash, now, now),
			env.DB.prepare(
				`DELETE FROM email_verifications WHERE user_id = (SELECT id FROM users WHERE lower(email) = lower(?))`,
			).bind(email),
			env.DB.prepare(
				`INSERT INTO email_verifications (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)`,
			).bind(verificationId, userId, tokenHash, expiresAt),
		]);
	} catch (err) {
		log.error('signup_insert_failed', { requestId, ip, email: email.replace(/(?<=.).(?=[^@]*?@)/g, '*') }, err);
		// UNIQUE collision on email = race condition; surface as 409.
		const msg = err instanceof Error ? err.message : String(err);
		if (/UNIQUE/i.test(msg)) {
			return jsonResp({ error: 'email_taken' }, 409, request);
		}
		return jsonResp({ error: 'server_error' }, 500, request);
	}

	// 8. Send email.
	const verifyUrl = `${appUrl(env, request)}/verify?token=${encodeURIComponent(token)}`;
	const tmpl = buildVerificationEmail(name, verifyUrl);
	tmpl.to = email;
	const sent = await sendEmail(env, tmpl, requestId);
	if (!sent.ok) {
		log.error('verification_email_failed', { requestId, userId, error: sent.error });
	}

	return jsonResp({ ok: true }, 200, request);
}
