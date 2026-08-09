// Polar.sh webhook signature verification.
// Reference: https://docs.polar.sh/api-reference/webhooks/structure
//
// Polar sends three headers on every webhook:
//   Webhook-Id        — unique id for replay protection
//   Webhook-Timestamp — Unix seconds, used in HMAC payload
//   Webhook-Signature — "v1,<base64-hmac>" (multiple v1 signatures may be space-separated)
//
// HMAC payload: `${webhookId}.${webhookTimestamp}.${rawBody}`
// Secret:      the webhook secret from Polar.sh dashboard (POLAR_WEBHOOK_SECRET)
//
// We use Web Crypto HMAC-SHA256 — no Node crypto, no external deps.

const enc = new TextEncoder();

function toB64(bytes: ArrayBuffer): string {
	const view = new Uint8Array(bytes);
	let s = '';
	for (let i = 0; i < view.length; i++) s += String.fromCharCode(view[i]);
	return btoa(s);
}

function fromB64(s: string): Uint8Array {
	const bin = atob(s);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
	return diff === 0;
}

async function hmacSha256(secret: string, message: string): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey(
		'raw',
		enc.encode(secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign'],
	);
	const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
	return new Uint8Array(sig);
}

export interface VerifyResult {
	ok: boolean;
	reason?: 'missing_headers' | 'bad_timestamp' | 'bad_signature';
}

export async function verifyPolarSignature(
	request: Request,
	rawBody: string,
	secret: string,
): Promise<VerifyResult> {
	const id = request.headers.get('Webhook-Id');
	const ts = request.headers.get('Webhook-Timestamp');
	const sigHeader = request.headers.get('Webhook-Signature');

	if (!id || !ts || !sigHeader) {
		return { ok: false, reason: 'missing_headers' };
	}

	// Reject timestamps older than 5 minutes (replay protection).
	const tsNum = Number.parseInt(ts, 10);
	if (!Number.isFinite(tsNum)) {
		return { ok: false, reason: 'bad_timestamp' };
	}
	const nowSec = Math.floor(Date.now() / 1000);
	if (Math.abs(nowSec - tsNum) > 300) {
		return { ok: false, reason: 'bad_timestamp' };
	}

	const expected = await hmacSha256(secret, `${id}.${ts}.${rawBody}`);
	const expectedB64 = toB64(expected.buffer);

	// Signature header may contain multiple space-separated sigs (key rotation).
	// Accept if any matches.
	for (const part of sigHeader.split(' ')) {
		const [version, b64] = part.split(',', 2);
		if (version !== 'v1' || !b64) continue;
		const provided = fromB64(b64);
		const expectedBytes = fromB64(expectedB64);
		if (timingSafeEqual(provided, expectedBytes)) {
			return { ok: true };
		}
	}

	return { ok: false, reason: 'bad_signature' };
}

// Polar event types we care about.
export type PolarEventType =
	| 'license_key.created'
	| 'license_key.revoked'
	| (string & {}); // forward-compat

export interface PolarEvent {
	type: PolarEventType;
	data: Record<string, unknown>;
}

export async function readPolarEvent(request: Request, secret: string): Promise<{ ok: true; event: PolarEvent; raw: string } | { ok: false; reason: string }> {
	const raw = await request.text();
	const verify = await verifyPolarSignature(request, raw, secret);
	if (!verify.ok) {
		return { ok: false, reason: verify.reason ?? 'unknown' };
	}
	try {
		const event = JSON.parse(raw) as PolarEvent;
		return { ok: true, event, raw };
	} catch {
		return { ok: false, reason: 'bad_json' };
	}
}
