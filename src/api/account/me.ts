// R259: GET /api/account/me — return current user info (used by AccountLayout
// client-side to populate avatar + name + enforce auth).
// PATCH /api/account/profile — update name and/or email.

import type { Env } from '../../worker';
import { getSession } from '../lib/session';
import { isValidEmail } from '../lib/password';
import { sendEmail, buildEmailChangeConfirm } from '../lib/email';
import { randomToken, hashToken } from '../lib/tokens';

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

async function requireUser(request: Request, env: Env): Promise<{ id: string; email: string; name: string; email_verified: number; created_at: string } | null> {
	const cookie = request.headers.get('Cookie') ?? '';
	let sessionId: string | null = null;
	for (const part of cookie.split(/;\s*/)) {
		const eq = part.indexOf('=');
		if (eq < 0) continue;
		if (part.slice(0, eq).trim() === 'pulse_session') sessionId = part.slice(eq + 1).trim();
	}
	if (!sessionId) return null;
	const session = await getSession(env, sessionId);
	if (!session) return null;
	const user = await env.DB.prepare(
		`SELECT id, email, name, email_verified, created_at FROM users WHERE id = ? AND deleted_at IS NULL LIMIT 1`,
	)
		.bind(session.user_id)
		.first<{ id: string; email: string; name: string; email_verified: number; created_at: string }>();
	return user ?? null;
}

// GET /api/account/me
export async function handleAccountMe(request: Request, env: Env, _requestId?: string, _ip?: string): Promise<Response> {
	const user = await requireUser(request, env);
	if (!user) return jsonResp({ error: 'unauthorized' }, 401);
	return jsonResp({
		id: user.id,
		email: user.email,
		name: user.name,
		email_verified: user.email_verified === 1,
		created_at: user.created_at,
	}, 200);
}

interface ProfilePatch {
	name?: string;
	email?: string;
}

// PATCH /api/account/profile
export async function handleAccountProfile(request: Request, env: Env, _requestId?: string, _ip?: string): Promise<Response> {
	const user = await requireUser(request, env);
	if (!user) return jsonResp({ error: 'unauthorized' }, 401);

	let body: ProfilePatch;
	try {
		body = (await request.json()) as ProfilePatch;
	} catch {
		return jsonResp({ error: 'invalid_json' }, 400);
	}

	const updates: string[] = [];
	const params: unknown[] = [];
	const now = new Date().toISOString();

	// Name update.
	if (typeof body.name === 'string') {
		const name = body.name.trim();
		if (name.length === 0 || name.length > 80) {
			return jsonResp({ error: 'invalid_name' }, 400);
		}
		updates.push('name = ?');
		params.push(name);
	}

	// Email update — require re-verification.
	let emailChanged = false;
	let pendingEmail: string | null = null;
	if (typeof body.email === 'string') {
		const email = body.email.trim();
		if (email === user.email) {
			// No-op.
		} else if (!isValidEmail(email)) {
			return jsonResp({ error: 'invalid_email' }, 400);
		} else {
			// Check uniqueness.
			const existing = await env.DB.prepare(
				`SELECT id FROM users WHERE lower(email) = lower(?) AND id != ? LIMIT 1`,
			)
				.bind(email, user.id)
				.first<{ id: string }>();
			if (existing) {
				return jsonResp({ error: 'email_taken' }, 409);
			}
			pendingEmail = email;
			emailChanged = true;
			updates.push('pending_email = ?');
			params.push(email);
			updates.push('email_verified = 0');
		}
	}

	if (updates.length === 0) {
		return jsonResp({ ok: true, no_change: true }, 200);
	}

	updates.push('updated_at = ?');
	params.push(now);
	params.push(user.id);

	await env.DB.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).bind(...params).run();

	// If email changed, send a confirmation link to the new address.
	if (emailChanged && pendingEmail) {
		const token = randomToken();
		const tokenHash = await hashToken(token);
		const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
		await env.DB.prepare(
			`INSERT INTO email_verifications (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)`,
		)
			.bind(crypto.randomUUID(), user.id, tokenHash, expiresAt)
			.run();

		const verifyUrl = `${env.PUBLIC_APP_URL}/verify-email?token=${encodeURIComponent(token)}`;
		const tmpl = buildEmailChangeConfirm(pendingEmail, verifyUrl);
		tmpl.to = pendingEmail;
		await sendEmail(env, tmpl);
	}

	const updated = await env.DB.prepare(
		`SELECT id, email, name, email_verified, created_at FROM users WHERE id = ? LIMIT 1`,
	)
		.bind(user.id)
		.first<{ id: string; email: string; name: string; email_verified: number; created_at: string }>();

	return jsonResp({
		ok: true,
		email_changed: emailChanged,
		user: updated ? {
			id: updated.id,
			email: updated.email,
			name: updated.name,
			email_verified: updated.email_verified === 1,
		} : null,
	}, 200);
}
