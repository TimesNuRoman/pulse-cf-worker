// R257: POST /api/auth/signup — create account, send verification email.
// Spec §5.2: returns JSON { ok } or { error, field? }.

import type { Env } from '../../worker';
import { hashPassword, isValidEmail, isValidPassword } from '../lib/password';
import { randomToken, hashToken } from '../lib/tokens';
import { sendEmail, buildVerificationEmail } from '../lib/email';
import { checkSignupIp, checkSignupEmail, recordSignupAttempt } from '../lib/rate-limit';

interface SignupBody {
	name?: string;
	email?: string;
	password?: string;
	agreedToTerms?: boolean;
	company?: string; // honeypot
}

function clientIp(request: Request): string {
	return (
		request.headers.get('CF-Connecting-IP') ??
		request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
		'unknown'
	);
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

export async function handleSignup(request: Request, env: Env): Promise<Response> {
	const ip = clientIp(request);

	// 1. Parse body.
	let body: SignupBody;
	try {
		body = (await request.json()) as SignupBody;
	} catch {
		return jsonResp({ error: 'invalid_json' }, 400, request);
	}

	// 2. Honeypot — silent 200, no user created.
	if (typeof body.company === 'string' && body.company.length > 0) {
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
		return jsonResp({ error: 'email_taken' }, 409, request);
	}

	// 7. Create user.
	const userId = crypto.randomUUID();
	const passwordHash = await hashPassword(password);
	const now = new Date().toISOString();
	await env.DB.prepare(
		`INSERT INTO users (id, email, name, password_hash, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, 0, ?, ?)`,
	)
		.bind(userId, email, name, passwordHash, now, now)
		.run();

	// 8. Generate verification token (32 bytes, base64url).
	const token = randomToken();
	const tokenHash = await hashToken(token);
	const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
	await env.DB.prepare(
		`INSERT INTO email_verifications (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)`,
	)
		.bind(crypto.randomUUID(), userId, tokenHash, expiresAt)
		.run();

	// 9. Send email.
	const verifyUrl = `${env.PUBLIC_APP_URL}/verify?token=${encodeURIComponent(token)}`;
	const tmpl = buildVerificationEmail(name, verifyUrl);
	tmpl.to = email;
	const sent = await sendEmail(env, tmpl);
	if (!sent.ok) {
		// User created, email failed — log and still return 200 (don't leak email state).
		console.error('Failed to send verification email', { userId, error: sent.error });
	}

	return jsonResp({ ok: true }, 200, request);
}
