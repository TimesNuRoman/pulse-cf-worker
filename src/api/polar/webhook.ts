// R260: Polar.sh webhook receiver.
// Handles license_key.created and license_key.revoked events.
// Signature verified via lib/polar.ts before any DB write.

import type { Env } from '../../worker';
import { readPolarEvent, type PolarEvent } from '../lib/polar';
import { hashToken } from '../lib/tokens';
import { log } from '../lib/logger';

function jsonResp(body: unknown, status: number): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
		},
	});
}

export async function handlePolarWebhook(request: Request, env: Env, requestId: string, ip: string): Promise<Response> {
	const secret = env.POLAR_WEBHOOK_SECRET;
	if (!secret) {
		log.error('polar_no_secret', { requestId });
		return jsonResp({ error: 'misconfigured' }, 500);
	}

	const result = await readPolarEvent(request, secret);
	if (!result.ok) {
		log.warn('polar_signature_failed', { requestId, ip, reason: result.reason });
		return jsonResp({ error: 'invalid_signature' }, 400);
	}

	const event = result.event;
	log.info('polar_event', { requestId, type: event.type });

	try {
		switch (event.type) {
			case 'license_key.created':
				await onLicenseCreated(env, event, requestId);
				break;
			case 'license_key.revoked':
				await onLicenseRevoked(env, event, requestId);
				break;
			default:
				// Unknown event type — accept (200) so Polar doesn't retry, but log.
				log.info('polar_event_ignored', { requestId, type: event.type });
		}
		return jsonResp({ ok: true }, 200);
	} catch (err) {
		log.error('polar_handler_failed', { requestId, type: event.type }, err);
		// Return 500 so Polar retries — but only for known handler errors.
		return jsonResp({ error: 'handler_failed' }, 500);
	}
}

async function onLicenseCreated(env: Env, event: PolarEvent, requestId: string): Promise<void> {
	const data = event.data as {
		id?: string;
		key?: string;
		customer_email?: string;
		product_id?: string;
		expires_at?: string | null;
		subscription_id?: string | null;
	};
	if (!data.id || !data.key || !data.customer_email) {
		log.warn('polar_license_created_missing_fields', { requestId, data: { id: data.id, hasKey: !!data.key, hasEmail: !!data.customer_email } });
		return;
	}

	const keyHash = await hashToken(data.key);
	const plan = inferPlan(data.product_id, data.subscription_id);
	const licenseId = crypto.randomUUID();
	const now = new Date().toISOString();

	await env.DB.batch([
		env.DB.prepare(
			`INSERT OR REPLACE INTO licenses
			 (id, key_hash, polar_license_id, polar_subscription_id, customer_email, plan, status, expires_at, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
		).bind(
			licenseId,
			keyHash,
			data.id,
			data.subscription_id ?? null,
			data.customer_email.toLowerCase(),
			plan,
			data.expires_at ?? null,
			now,
			now,
		),
		// If the user is already registered with this email, auto-attach.
		env.DB.prepare(
			`UPDATE licenses
			 SET user_id = (SELECT id FROM users WHERE lower(email) = lower(?)),
			     updated_at = ?
			 WHERE key_hash = ? AND user_id IS NULL`,
		).bind(data.customer_email, now, keyHash),
	]);

	log.info('polar_license_created', { requestId, polarLicenseId: data.id, email: data.customer_email, plan });
}

async function onLicenseRevoked(env: Env, event: PolarEvent, requestId: string): Promise<void> {
	const data = event.data as { id?: string };
	if (!data.id) {
		log.warn('polar_license_revoked_missing_id', { requestId });
		return;
	}
	const now = new Date().toISOString();
	await env.DB.prepare(
		`UPDATE licenses SET status = 'revoked', updated_at = ? WHERE polar_license_id = ?`,
	).bind(now, data.id).run();
	log.info('polar_license_revoked', { requestId, polarLicenseId: data.id });
}

function inferPlan(productId: string | undefined, subscriptionId: string | null | undefined): string {
	// Polar product IDs are configured per workspace; we map them to plans.
	// Falls back to 'monthly' for any unrecognized product — caller can override
	// later if needed. This is a hint, not a security boundary.
	if (!productId) return subscriptionId ? 'monthly' : 'monthly';
	if (productId.includes('annual')) return 'annual';
	if (productId.includes('yearly')) return 'annual';
	return 'monthly';
}
