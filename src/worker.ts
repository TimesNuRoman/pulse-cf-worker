// R257 + R265: pulse-cf-worker — fetch handler routing.
//
// Three routing rules (first match wins):
//   1. /api/*         → handleApi (D1 + Resend + Polar + license auth)
//   2. /downloads/*   → R2 bucket `pulse-landing` (APKs, no Worker bundle bloat)
//   3. /updates/*     → R2 bucket `pulse-landing` (manifests)
//   4. else           → Static Assets (Astro build output)
//
// Why /downloads and /updates skip the asset bundle: those are mutable,
// uploaded via `wrangler r2 object put`. Putting them through [[assets]] would
// force a `wrangler deploy` on every APK release. R2 binding reads the live bucket.

import { handleApi } from './api/router';

export interface Env {
	DB: D1Database;
	RESEND_API_KEY: string;
	FROM_EMAIL: string;
	PUBLIC_APP_URL: string;
	POLAR_WEBHOOK_SECRET?: string;
	DEV_LOG_EMAIL?: string;
	ASSETS: Fetcher;
	// R2 binding for downloads + updates. Same bucket as the public `pulse-landing`,
	// but read here as a private binding (not via the r2.dev public URL).
	PULSE_LANDING: R2Bucket;
}

const R2_PREFIX_RE = /^\/(downloads|updates)\//;

export default {
	async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);

		// 1. API
		if (url.pathname.startsWith('/api/')) {
			return handleApi(request, env, _ctx);
		}

		// 2 + 3. R2 (downloads, updates)
		if (R2_PREFIX_RE.test(url.pathname)) {
			return serveFromR2(env, request, url.pathname);
		}

		// 4. Static assets
		return env.ASSETS.fetch(request);
	},
} satisfies ExportedHandler<Env>;

async function serveFromR2(env: Env, request: Request, pathname: string): Promise<Response> {
	const key = decodeURIComponent(pathname.slice(1)); // strip leading '/'
	const obj = await env.PULSE_LANDING.get(key);
	if (!obj) {
		return new Response('Not Found', { status: 404, headers: { 'content-type': 'text/plain' } });
	}
	const headers = new Headers();
	headers.set('etag', obj.httpEtag);
	headers.set('cache-control', 'public, max-age=300');
	if (obj.httpMetadata?.contentType) headers.set('content-type', obj.httpMetadata.contentType);
	// Pass through request headers (e.g. If-None-Match) for conditional GETs.
	const ifNoneMatch = request.headers.get('If-None-Match');
	if (ifNoneMatch && ifNoneMatch === obj.httpEtag) {
		return new Response(null, { status: 304, headers });
	}
	return new Response(obj.body, { status: 200, headers });
}
