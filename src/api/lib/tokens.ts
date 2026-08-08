// R257: token generation for email verification and session IDs.
// Uses Web Crypto (crypto.getRandomValues) — 32 random bytes, base64url-encoded.

const TOKEN_BYTES = 32;

function toB64Url(bytes: Uint8Array): string {
	let s = '';
	for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
	return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function randomToken(): string {
	return toB64Url(crypto.getRandomValues(new Uint8Array(TOKEN_BYTES)));
}

// SHA-256 hash of a token — what we actually store in D1.
// Raw token only ever exists in the user's email; DB column holds the hash.
const enc = new TextEncoder();
export async function hashToken(token: string): Promise<string> {
	const buf = await crypto.subtle.digest('SHA-256', enc.encode(token));
	const bytes = new Uint8Array(buf);
	let s = '';
	for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
	return btoa(s);
}

// Constant-time equality check for tokens (defense in depth).
export function tokensEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}
