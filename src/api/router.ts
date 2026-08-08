// R257: API router — dispatches /api/auth/* endpoints to handlers.
// All endpoints return JSON. Errors are normalized to { error, field? }
// with appropriate HTTP status codes (see spec §5.2).
//
// Important: this file runs in the Cloudflare Workers runtime.
// We use Web Crypto API (crypto.subtle) — NO Node-only modules.

import type { Env } from '../worker';
import { handleSignup } from './auth/signup';
import { handleVerify } from './auth/verify';
import { handleLogin } from './auth/login';
import { handleLogout } from './auth/logout';
import { handleResend } from './auth/resend';

export async function handleApi(
	request: Request,
	env: Env,
	_ctx: ExecutionContext,
): Promise<Response> {
	const url = new URL(request.url);
	const path = url.pathname;
	const method = request.method.toUpperCase();

	// CORS preflight — same-origin only, but support OPTIONS cleanly.
	if (method === 'OPTIONS') {
		return new Response(null, {
			status: 204,
			headers: corsHeaders(request),
		});
	}

	try {
		// POST /api/auth/signup
		if (path === '/api/auth/signup' && method === 'POST') {
			return await handleSignup(request, env);
		}
		// GET /api/auth/verify?token=...
		if (path === '/api/auth/verify' && method === 'GET') {
			return await handleVerify(request, env);
		}
		// POST /api/auth/login
		if (path === '/api/auth/login' && method === 'POST') {
			return await handleLogin(request, env);
		}
		// POST /api/auth/logout
		if (path === '/api/auth/logout' && method === 'POST') {
			return await handleLogout(request, env);
		}
		// POST /api/auth/resend
		if (path === '/api/auth/resend' && method === 'POST') {
			return await handleResend(request, env);
		}

		return json({ error: 'not_found' }, 404, request);
	} catch (err) {
		// Don't leak internal error details; log them server-side.
		const message = err instanceof Error ? err.message : String(err);
		const stack = err instanceof Error ? err.stack : undefined;
		console.error('API error', { path, method, message, stack });
		return json({ error: 'server_error', message }, 500, request);
	}
}

function json(body: unknown, status: number, request: Request): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
			...corsHeaders(request),
		},
	});
}

function corsHeaders(request: Request): Record<string, string> {
	const origin = request.headers.get('Origin') ?? '';
	// Same-origin only. For cross-origin dev, allow the local Astro dev server.
	const allowed = origin.endsWith('ownlocalml.com') || origin.startsWith('http://localhost');
	return {
		'access-control-allow-origin': allowed ? origin : 'https://ownlocalml.com',
		'access-control-allow-credentials': 'true',
		'access-control-allow-methods': 'GET, POST, OPTIONS',
		'access-control-allow-headers': 'content-type',
		'access-control-max-age': '600',
		// Security headers (applies to all API responses).
		'x-content-type-options': 'nosniff',
		'x-frame-options': 'DENY',
		'referrer-policy': 'no-referrer',
		'strict-transport-security': 'max-age=31536000; includeSubDomains',
	};
}
