// R261: GET /api/account/sessions — list all active sessions for the user.
// DELETE /api/account/sessions/[id] — revoke a specific session.
// Spec §H.2.

import type { Env } from '../../worker';
import { getSession, deleteSession, readSessionId } from '../lib/session';
import { hashToken } from '../lib/tokens';
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

async function requireUserId(request: Request, env: Env): Promise<{ userId: string; sessionId: string } | null> {
	const sessionId = readSessionId(request);
	if (!sessionId) return null;
	const session = await getSession(env, sessionId);
	if (!session) return null;
	return { userId: session.user_id, sessionId };
}

export interface SessionInfo {
	id: string;
	device_type: string;
	device_name: string;
	created_at: string;
	last_active_at: string | null;
	is_current: boolean;
}

export async function handleAccountSessionsList(request: Request, env: Env, requestId?: string, ip?: string): Promise<Response> {
	const me = await requireUserId(request, env);
	if (!me) return jsonResp({ error: 'unauthorized' }, 401);

	const currentIdHash = await hashToken(me.sessionId);
	const rows = await env.DB.prepare(
		`SELECT id_hash, device_type, device_name, created_at, expires_at
		 FROM sessions
		 WHERE user_id = ? AND expires_at > datetime('now')
		 ORDER BY created_at DESC`,
	)
		.bind(me.userId)
		.all<{ id_hash: string; device_type: string; device_name: string; created_at: string; expires_at: string }>();

	const sessions: SessionInfo[] = (rows.results || []).map((r) => ({
		id: r.id_hash, // opaque; UI uses this for DELETE
		device_type: r.device_type,
		device_name: r.device_name,
		created_at: r.created_at,
		last_active_at: r.created_at, // we don't track last_active yet; use created_at as proxy
		is_current: r.id_hash === currentIdHash,
	}));

	if (requestId) log.info('account_sessions_listed', { requestId, ip: ip ?? 'unknown', userId: me.userId, count: sessions.length });
	return jsonResp({ sessions }, 200);
}

export async function handleAccountSessionRevoke(request: Request, env: Env, sessionIdHash: string, requestId?: string, ip?: string): Promise<Response> {
	const me = await requireUserId(request, env);
	if (!me) return jsonResp({ error: 'unauthorized' }, 401);

	// Refuse to revoke the current session — user should use /api/auth/logout instead.
	const currentIdHash = await hashToken(me.sessionId);
	if (sessionIdHash === currentIdHash) {
		return jsonResp({ error: 'cannot_revoke_current' }, 400);
	}

	// Verify the session belongs to this user.
	const target = await env.DB.prepare(
		`SELECT user_id FROM sessions WHERE id_hash = ? LIMIT 1`,
	)
		.bind(sessionIdHash)
		.first<{ user_id: string }>();
	if (!target || target.user_id !== me.userId) {
		return jsonResp({ error: 'not_found' }, 404);
	}

	await env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`).bind(sessionIdHash).run();

	if (requestId) log.info('account_session_revoked', { requestId, ip: ip ?? 'unknown', userId: me.userId });
	return jsonResp({ ok: true }, 200);
}
