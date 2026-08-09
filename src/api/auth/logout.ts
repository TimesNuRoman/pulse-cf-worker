// R257: POST /api/auth/logout — clear session cookie + delete session row.

import type { Env } from '../../worker';
import { deleteSession, buildClearCookie, readSessionId } from '../lib/session';
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

export async function handleLogout(request: Request, env: Env, requestId: string, ip: string): Promise<Response> {
	const sessionId = readSessionId(request);
	if (sessionId) {
		await deleteSession(env, sessionId);
		log.info('logout', { requestId, ip });
	}
	const isHttps = new URL(request.url).protocol === 'https:';
	return jsonResp({ ok: true }, 200, { 'set-cookie': buildClearCookie(isHttps) });
}
