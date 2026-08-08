// R257: session cookies — opaque random session ID, HttpOnly + Secure + SameSite=Lax.
// Server stores the session row in D1 with expiry; client just carries the ID.

import type { Env } from '../../worker';
import { randomToken, hashToken } from './tokens';

export const SESSION_COOKIE = 'pulse_session';
const SESSION_TTL_DAYS = 30;

export interface SessionRow {
	id: string;
	user_id: string;
	expires_at: string; // ISO
	created_at: string;
}

export async function createSession(env: Env, userId: string): Promise<{ id: string; expiresAt: Date }> {
	const id = randomToken();
	const idHash = await hashToken(id); // store hash, not raw
	const now = new Date();
	const expiresAt = new Date(now.getTime() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);

	await env.DB.prepare(
		`INSERT INTO sessions (id_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`,
	)
		.bind(idHash, userId, expiresAt.toISOString(), now.toISOString())
		.run();

	return { id, expiresAt };
}

export async function getSession(env: Env, sessionId: string): Promise<{ user_id: string } | null> {
	const idHash = await hashToken(sessionId);
	const row = await env.DB.prepare(
		`SELECT user_id, expires_at FROM sessions WHERE id_hash = ? LIMIT 1`,
	)
		.bind(idHash)
		.first<{ user_id: string; expires_at: string }>();

	if (!row) return null;
	if (new Date(row.expires_at) < new Date()) {
		// Expired — clean up.
		await env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`).bind(idHash).run();
		return null;
	}
	return { user_id: row.user_id };
}

export async function deleteSession(env: Env, sessionId: string): Promise<void> {
	const idHash = await hashToken(sessionId);
	await env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`).bind(idHash).run();
}

export function buildSetCookie(value: string, expiresAt: Date, secure: boolean): string {
	// SameSite=Lax: allows top-level navigations (clicking the verify link)
	// but blocks cross-site POSTs. HttpOnly: no JS access. Secure: HTTPS only.
	const parts = [
		`${SESSION_COOKIE}=${value}`,
		`Path=/`,
		`HttpOnly`,
		`SameSite=Lax`,
		`Expires=${expiresAt.toUTCString()}`,
	];
	if (secure) parts.push('Secure');
	return parts.join('; ');
}

export function buildClearCookie(secure: boolean): string {
	const parts = [
		`${SESSION_COOKIE}=`,
		`Path=/`,
		`HttpOnly`,
		`SameSite=Lax`,
		`Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
	];
	if (secure) parts.push('Secure');
	return parts.join('; ');
}

export function readSessionId(request: Request): string | null {
	const cookieHeader = request.headers.get('Cookie') ?? '';
	for (const part of cookieHeader.split(/;\s*/)) {
		const eq = part.indexOf('=');
		if (eq < 0) continue;
		const name = part.slice(0, eq).trim();
		if (name === SESSION_COOKIE) return part.slice(eq + 1).trim();
	}
	return null;
}
