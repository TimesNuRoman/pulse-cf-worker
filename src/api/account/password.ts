// R260: POST /api/account/password — change password.
// Spec §H.1: verify current password, hash new password, invalidate
// other sessions, send "your password was changed" email.
//
// Re-wrap of encrypted blobs (sync) is deferred — Pulse desktop app
// stores notes locally in SQLite, and sync is PRO-only. When sync
// lands, password change will trigger a re-encrypt job here.

import type { Env } from '../../worker';
import { getSession } from '../lib/session';
import { hashPassword, verifyPassword, isValidPassword } from '../lib/password';
import { sendEmail, buildPasswordChanged } from '../lib/email';
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

interface PasswordBody {
	current_password?: string;
	new_password?: string;
}

export async function handleAccountPassword(request: Request, env: Env, requestId?: string, ip?: string): Promise<Response> {
	// 1. Parse.
	let body: PasswordBody;
	try {
		body = (await request.json()) as PasswordBody;
	} catch {
		return jsonResp({ error: 'invalid_json' }, 400);
	}
	const current = body.current_password ?? '';
	const next = body.new_password ?? '';
	if (!current || !isValidPassword(next)) {
		return jsonResp({ error: 'invalid_password' }, 400);
	}

	// 2. Identify user from session.
	const cookie = request.headers.get('Cookie') ?? '';
	let sessionId: string | null = null;
	for (const part of cookie.split(/;\s*/)) {
		const eq = part.indexOf('=');
		if (eq < 0) continue;
		if (part.slice(0, eq).trim() === 'pulse_session') sessionId = part.slice(eq + 1).trim();
	}
	if (!sessionId) return jsonResp({ error: 'unauthorized' }, 401);
	const session = await getSession(env, sessionId);
	if (!session) return jsonResp({ error: 'unauthorized' }, 401);

	// 3. Look up user + verify current password.
	const user = await env.DB.prepare(
		`SELECT id, email, name, password_hash FROM users WHERE id = ? AND deleted_at IS NULL LIMIT 1`,
	)
		.bind(session.user_id)
		.first<{ id: string; email: string; name: string; password_hash: string }>();
	if (!user) return jsonResp({ error: 'unauthorized' }, 401);

	const currentOk = await verifyPassword(current, user.password_hash);
	if (!currentOk) {
		if (requestId) log.warn('account_password_wrong_current', { requestId, ip: ip ?? 'unknown', userId: user.id });
		return jsonResp({ error: 'wrong_password' }, 401);
	}

	// 4. Hash new password + update.
	const newHash = await hashPassword(next);
	const now = new Date().toISOString();
	await env.DB.prepare(
		`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`,
	)
		.bind(newHash, now, user.id)
		.run();

	// 5. Invalidate all other sessions (keep the current one active).
	const { hashToken } = await import('../lib/tokens');
	const currentIdHash = await hashToken(sessionId);
	await env.DB.prepare(
		`DELETE FROM sessions WHERE user_id = ? AND id_hash != ?`,
	)
		.bind(user.id, currentIdHash)
		.run();

	// 6. Send notification email.
	const tmpl = buildPasswordChanged(user.name || user.email, new Date().toUTCString());
	tmpl.to = user.email;
	await sendEmail(env, tmpl);

	if (requestId) log.info('account_password_changed', { requestId, ip: ip ?? 'unknown', userId: user.id });

	return jsonResp({ ok: true }, 200);
}
