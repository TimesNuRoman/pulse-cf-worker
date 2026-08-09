// R257 + R260: POST /api/auth/resend — generate new verification token + email.
// Always returns 200 unless rate-limited (prevents email enumeration).
//
// Security: rate-limited per email AND per IP. Resend counter is separate
// from signup counter to allow re-sends without hitting signup limit.

import type { Env } from '../../worker';
import { randomToken, hashToken } from '../lib/tokens';
import { sendEmail, buildVerificationEmail } from '../lib/email';
import { checkResendCount, checkResendIp, recordResendAttempt } from '../lib/rate-limit';
import { log } from '../lib/logger';
import { appUrl } from '../lib/app-url';

interface ResendBody {
	email?: string;
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

export async function handleResend(request: Request, env: Env, requestId: string, ip: string): Promise<Response> {
	// 1. Parse — silent 200 on bad JSON (anti-enumeration).
	let body: ResendBody;
	try {
		body = (await request.json()) as ResendBody;
	} catch {
		return jsonResp({ ok: true }, 200);
	}
	const email = (body.email ?? '').trim();
	if (!email) {
		return jsonResp({ ok: true }, 200);
	}

	// 2. Rate limit per IP first (cheap DOS prevention).
	const ipLimit = await checkResendIp(env, ip);
	if (!ipLimit.allowed) {
		// Silent 200 — but include retry-after so legitimate clients back off.
		return jsonResp({ ok: true }, 200, {
			'retry-after': String(ipLimit.retryAfterSec ?? 60),
		});
	}

	// 3. Rate limit per email.
	const emailLimit = await checkResendCount(env, email);
	if (!emailLimit.allowed) {
		return jsonResp({ ok: true }, 200, {
			'retry-after': String(emailLimit.retryAfterSec ?? 60),
		});
	}

	// 4. Find user.
	const user = await env.DB.prepare(
		`SELECT id, name, email_verified FROM users WHERE lower(email) = lower(?) LIMIT 1`,
	)
		.bind(email)
		.first<{ id: string; name: string; email_verified: number }>();

	// 5. If user doesn't exist OR already verified, return 200 silently.
	if (!user || user.email_verified === 1) {
		return jsonResp({ ok: true }, 200);
	}

	// 6. Record attempt BEFORE doing work (covers failed DB ops too).
	await recordResendAttempt(env, ip, email);

	// 7. Invalidate old tokens + create new one — atomically.
	const token = randomToken();
	const tokenHash = await hashToken(token);
	const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

	try {
		await env.DB.batch([
			env.DB.prepare(`DELETE FROM email_verifications WHERE user_id = ?`).bind(user.id),
			env.DB.prepare(
				`INSERT INTO email_verifications (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)`,
			).bind(crypto.randomUUID(), user.id, tokenHash, expiresAt),
		]);
	} catch (err) {
		log.error('resend_insert_failed', { requestId, ip, userId: user.id }, err);
		return jsonResp({ ok: true }, 200);
	}

	// 8. Send email.
	const verifyUrl = `${appUrl(env, request)}/verify?token=${encodeURIComponent(token)}`;
	const tmpl = buildVerificationEmail(user.name, verifyUrl);
	tmpl.to = email;
	const sent = await sendEmail(env, tmpl, requestId);
	if (!sent.ok) {
		log.error('resend_email_failed', { requestId, userId: user.id, error: sent.error });
	}

	return jsonResp({ ok: true }, 200);
}
