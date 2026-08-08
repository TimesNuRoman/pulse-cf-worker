// R257: POST /api/auth/resend — generate new verification token + email.
// Always returns 200 unless rate-limited (prevents email enumeration).

import type { Env } from '../../worker';
import { randomToken, hashToken } from '../lib/tokens';
import { sendEmail, buildVerificationEmail } from '../lib/email';
import { checkResendCount, recordSignupAttempt } from '../lib/rate-limit';

interface ResendBody {
	email?: string;
}

function clientIp(request: Request): string {
	return request.headers.get('CF-Connecting-IP') ?? 'unknown';
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

export async function handleResend(request: Request, env: Env): Promise<Response> {
	const ip = clientIp(request);

	// 1. Parse.
	let body: ResendBody;
	try {
		body = (await request.json()) as ResendBody;
	} catch {
		// Silent 200 even on bad JSON.
		return jsonResp({ ok: true }, 200);
	}
	const email = (body.email ?? '').trim();
	if (!email) {
		return jsonResp({ ok: true }, 200);
	}

	// 2. Rate limit.
	const limit = await checkResendCount(env, email);
	if (!limit.allowed) {
		return jsonResp({ ok: true }, 200, {
			'retry-after': String(limit.retryAfterSec ?? 60),
		});
	}

	// 3. Find user.
	const user = await env.DB.prepare(
		`SELECT id, name, email_verified FROM users WHERE lower(email) = lower(?) LIMIT 1`,
	)
		.bind(email)
		.first<{ id: string; name: string; email_verified: number }>();

	// 4. If user doesn't exist OR already verified, return 200 silently.
	if (!user || user.email_verified === 1) {
		return jsonResp({ ok: true }, 200);
	}

	// 5. Invalidate old tokens + create new one.
	await env.DB.prepare(`DELETE FROM email_verifications WHERE user_id = ?`).bind(user.id).run();

	const token = randomToken();
	const tokenHash = await hashToken(token);
	const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
	await env.DB.prepare(
		`INSERT INTO email_verifications (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)`,
	)
		.bind(crypto.randomUUID(), user.id, tokenHash, expiresAt)
		.run();

	await recordSignupAttempt(env, ip, email); // count this as a signup attempt

	// 6. Send email.
	const verifyUrl = `${env.PUBLIC_APP_URL}/verify?token=${encodeURIComponent(token)}`;
	const tmpl = buildVerificationEmail(user.name, verifyUrl);
	tmpl.to = email;
	const sent = await sendEmail(env, tmpl);
	if (!sent.ok) {
		console.error('Resend verification email failed', { userId: user.id, error: sent.error });
	}

	return jsonResp({ ok: true }, 200);
}
