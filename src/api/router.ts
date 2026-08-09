// R257 + R260: API router — dispatches /api/auth/* endpoints to handlers.
// All endpoints return JSON. Errors are normalized to { error, field? }
// with appropriate HTTP status codes (see spec §5.2).
//
// Security middleware applied here:
//   1. Request size limit (defense against memory pressure)
//   2. Origin allow-list (defense-in-depth CSRF — SameSite=Lax is primary)
//   3. Structured logging on every request
//
// Important: this file runs in the Cloudflare Workers runtime.
// We use Web Crypto API (crypto.subtle) — NO Node-only modules.

import type { Env } from '../worker';
import { handleSignup } from './auth/signup';
import { handleVerify } from './auth/verify';
import { handleLogin } from './auth/login';
import { handleLogout } from './auth/logout';
import { handleResend } from './auth/resend';
import { handleAccountMe, handleAccountProfile } from './account/me';
import { handleLicenseValidate, handleLicenseClaim, handleLicenseStatus } from './auth/license';
import { handlePolarWebhook } from './polar/webhook';
import { log, newRequestId } from './lib/logger';

const MAX_BODY_BYTES = 4096; // signup form is ~200 bytes; 4KB is generous
const ALLOWED_ORIGINS = new Set([
	'https://ownlocalml.com',
	'https://www.ownlocalml.com',
]);

function isLocalOrigin(origin: string): boolean {
	// Allow http://localhost:<port> and http://127.0.0.1:<port> for dev.
	return /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
}

function originAllowed(request: Request): boolean {
	const origin = request.headers.get('Origin');
	if (!origin) return true; // server-to-server (curl, Workers, etc.) — no Origin header is fine
	if (ALLOWED_ORIGINS.has(origin)) return true;
	if (isLocalOrigin(origin)) return true;
	return false;
}

function corsHeaders(request: Request, allowed: boolean): Record<string, string> {
	const origin = request.headers.get('Origin') ?? '';
	const headers: Record<string, string> = {
		'access-control-allow-methods': 'GET, POST, OPTIONS',
		'access-control-allow-headers': 'content-type',
		'access-control-max-age': '600',
		'vary': 'Origin',
		'x-content-type-options': 'nosniff',
		'x-frame-options': 'DENY',
		'referrer-policy': 'no-referrer',
		'strict-transport-security': 'max-age=31536000; includeSubDomains',
	};
	if (allowed && origin) {
		headers['access-control-allow-origin'] = origin;
		headers['access-control-allow-credentials'] = 'true';
	}
	// No CORS headers if origin is not allowed — browser will block, that's correct.
	return headers;
}

function clientIp(request: Request): string {
	return (
		request.headers.get('CF-Connecting-IP') ??
		request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
		'unknown'
	);
}

function json(body: unknown, status: number, request: Request, extraHeaders: Record<string, string> = {}): Response {
	const allowed = originAllowed(request);
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
			...corsHeaders(request, allowed),
			...extraHeaders,
		},
	});
}

export async function handleApi(
	request: Request,
	env: Env,
	_ctx: ExecutionContext,
): Promise<Response> {
	const url = new URL(request.url);
	const path = url.pathname;
	const method = request.method.toUpperCase();
	const requestId = newRequestId();
	const ip = clientIp(request);
	const allowed = originAllowed(request);

	// 1. CORS preflight — short-circuit before origin check (browsers send preflight cross-origin).
	if (method === 'OPTIONS') {
		return new Response(null, {
			status: allowed ? 204 : 403,
			headers: corsHeaders(request, allowed),
		});
	}

	// 2. Origin check (defense-in-depth CSRF; SameSite=Lax is primary).
	if (!allowed) {
		log.warn('origin_blocked', { requestId, path, method, ip, origin: request.headers.get('Origin') ?? '' });
		return json({ error: 'forbidden' }, 403, request);
	}

	// 3. Body size limit (POST only).
	if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
		const cl = request.headers.get('Content-Length');
		if (cl !== null) {
			const n = Number.parseInt(cl, 10);
			if (!Number.isFinite(n) || n > MAX_BODY_BYTES) {
				log.warn('body_too_large', { requestId, path, method, ip, contentLength: cl });
				return json({ error: 'body_too_large' }, 413, request);
			}
		}
	}

	const started = Date.now();
	try {
		let response: Response;

		if (path === '/api/auth/signup' && method === 'POST') {
			response = await handleSignup(request, env, requestId, ip);
		} else if (path === '/api/auth/verify' && method === 'GET') {
			response = await handleVerify(request, env, requestId, ip);
		} else if (path === '/api/auth/login' && method === 'POST') {
			response = await handleLogin(request, env, requestId, ip);
		} else if (path === '/api/auth/logout' && method === 'POST') {
			response = await handleLogout(request, env, requestId, ip);
		} else if (path === '/api/auth/resend' && method === 'POST') {
			response = await handleResend(request, env, requestId, ip);
		} else if (path === '/api/auth/license' && method === 'GET') {
			response = await handleLicenseStatus(request, env, requestId, ip);
		} else if (path === '/api/auth/license/validate' && method === 'POST') {
			response = await handleLicenseValidate(request, env, requestId, ip);
		} else if (path === '/api/auth/license/claim' && method === 'POST') {
			response = await handleLicenseClaim(request, env, requestId, ip);
		} else if (path === '/api/account/me' && method === 'GET') {
			response = await handleAccountMe(request, env, requestId, ip);
		} else if (path === '/api/account/profile' && method === 'PATCH') {
			response = await handleAccountProfile(request, env, requestId, ip);
		} else if (path === '/api/polar/webhook' && method === 'POST') {
			response = await handlePolarWebhook(request, env, requestId, ip);
		} else {
			response = json({ error: 'not_found' }, 404, request);
		}

		const ms = Date.now() - started;
		log.info('request', {
			requestId,
			path,
			method,
			ip,
			status: response.status,
			ms,
		});
		return response;
	} catch (err) {
		const ms = Date.now() - started;
		log.error('api_error', { requestId, path, method, ip, ms }, err);
		return json({ error: 'server_error' }, 500, request);
	}
}
