// R257: session cookies — opaque random session ID, HttpOnly + Secure + SameSite=Lax.
// Server stores the session row in D1 with expiry; client just carries the ID.
// R261: extended to record device metadata (type, name, user-agent, ip hash)
// so the /account/sessions UI can show "Windows · Pulse v3.1 · 2 min ago".

import type { Env } from '../../worker';
import { randomToken, hashToken } from './tokens';

export const SESSION_COOKIE = 'pulse_session';
const SESSION_TTL_DAYS = 30;

export interface SessionRow {
	id: string;
	user_id: string;
	expires_at: string; // ISO
	created_at: string;
	device_type?: string;
	device_name?: string;
	user_agent?: string;
	ip_hash?: string;
}

export interface DeviceMeta {
	device_type: 'windows' | 'android' | 'web';
	device_name: string;
	user_agent?: string;
	ip?: string;
}

function parseUserAgent(ua: string | null | undefined): DeviceMeta {
	if (!ua) return { device_type: 'web', device_name: 'Web' };
	const lower = ua.toLowerCase();
	if (lower.includes('windows')) return { device_type: 'windows', device_name: 'Windows · Pulse' };
	if (lower.includes('android')) {
		const match = lower.match(/android\s*([\d.]+)?/);
		return { device_type: 'android', device_name: 'Android · Pulse Notes' };
	}
	if (lower.includes('mac os') || lower.includes('macintosh')) {
		return { device_type: 'web', device_name: 'macOS · Web' };
	}
	if (lower.includes('iphone') || lower.includes('ipad')) {
		return { device_type: 'web', device_name: 'iOS · Web' };
	}
	return { device_type: 'web', device_name: 'Web' };
}

async function sha256Hex(s: string): Promise<string> {
	const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
	return Array.from(new Uint8Array(buf))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

export async function createSession(
	env: Env,
	userId: string,
	request?: Request,
): Promise<{ id: string; expiresAt: Date }> {
	const id = randomToken();
	const idHash = await hashToken(id); // store hash, not raw
	const now = new Date();
	const expiresAt = new Date(now.getTime() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);

	// R261: capture device metadata for the sessions list UI.
	const ua = request?.headers.get('User-Agent') ?? null;
	const ip = request?.headers.get('CF-Connecting-IP') ?? null;
	const device = parseUserAgent(ua);
	const ipHash = ip ? await sha256Hex(ip) : null;

	await env.DB.prepare(
		`INSERT INTO sessions (id_hash, user_id, expires_at, created_at, device_type, device_name, user_agent, ip_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
	)
		.bind(
			idHash,
			userId,
			expiresAt.toISOString(),
			now.toISOString(),
			device.device_type,
			device.device_name,
			ua,
			ipHash,
		)
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
