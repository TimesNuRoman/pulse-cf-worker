// R257: password hashing using PBKDF2 via Web Crypto API.
//
// Why PBKDF2 not argon2: Cloudflare Workers runtime supports Web Crypto
// (subtle) but NOT node:crypto or external argon2 WASM (without bundling
// ~3MB of WASM). PBKDF2 with 600k iterations is OWASP-recommended for
// 2024+ and avoids the WASM bundle cost.
//
// Parameters (OWASP Password Storage Cheat Sheet, 2024):
//   - algorithm: SHA-256
//   - iterations: 600_000
//   - salt: 16 random bytes (per-user)
//   - key length: 32 bytes
//
// Storage format: pbkdf2$<iterations>$<saltB64>$<hashB64>

const ITERATIONS = 600_000;
const KEY_LEN = 32;
const SALT_LEN = 16;

const enc = new TextEncoder();

function toB64(bytes: Uint8Array): string {
	let s = '';
	for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
	return btoa(s);
}

function fromB64(s: string): Uint8Array {
	const bin = atob(s);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

async function pbkdf2(password: string, salt: Uint8Array, iters: number): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey(
		'raw',
		enc.encode(password),
		{ name: 'PBKDF2' },
		false,
		['deriveBits'],
	);
	const bits = await crypto.subtle.deriveBits(
		{
			name: 'PBKDF2',
			salt: salt as BufferSource,
			iterations: iters,
			hash: 'SHA-256',
		},
		key,
		KEY_LEN * 8,
	);
	return new Uint8Array(bits);
}

export async function hashPassword(password: string): Promise<string> {
	const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
	const hash = await pbkdf2(password, salt, ITERATIONS);
	return `pbkdf2$${ITERATIONS}$${toB64(salt)}$${toB64(hash)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
	const parts = stored.split('$');
	if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
	const iters = Number.parseInt(parts[1], 10);
	const salt = fromB64(parts[2]);
	const expected = fromB64(parts[3]);
	if (!Number.isFinite(iters) || iters < 100_000) return false;

	const actual = await pbkdf2(password, salt, iters);
	// Constant-time comparison.
	if (actual.length !== expected.length) return false;
	let diff = 0;
	for (let i = 0; i < actual.length; i++) {
		diff |= actual[i] ^ expected[i];
	}
	return diff === 0;
}

// Email validation (RFC 5322 simplified — covers 99% of real addresses).
// Server-side check on top of the more permissive client regex.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
export function isValidEmail(s: string): boolean {
	const trimmed = s.trim();
	if (trimmed.length === 0 || trimmed.length > 254) return false;
	return EMAIL_RE.test(trimmed);
}

// Server-side password rule (matches client): ≥8 chars, ≤128.
export function isValidPassword(pw: string): boolean {
	return typeof pw === 'string' && pw.length >= 8 && pw.length <= 128;
}
