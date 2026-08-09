// R260: app URL helper — derives PUBLIC_APP_URL with safe fallbacks for local dev.
// In production, PUBLIC_APP_URL is required (e.g. https://ownlocalml.com).
// In dev, if it's missing or malformed, fall back to the request's origin
// so redirects and email links still work.

export function appUrl(env: { PUBLIC_APP_URL?: string }, request: Request): string {
	const fromEnv = env.PUBLIC_APP_URL?.trim();
	if (fromEnv && /^https?:\/\//.test(fromEnv)) {
		return fromEnv.replace(/\/+$/, ''); // strip trailing slashes
	}
	// Fallback: derive from request URL (works for wrangler dev on 127.0.0.1).
	return new URL(request.url).origin;
}
