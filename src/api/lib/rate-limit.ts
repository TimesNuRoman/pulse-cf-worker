// R257: rate limiting for signup/resend/login.
// Uses D1 signup_attempts / login_attempts tables. In-memory would not
// survive across Worker isolates; D1 (eventually-consistent) is fine
// for our scale (≤5/h per IP is a hard ceiling, not a precise SLA).
//
// Limits from spec §6.3:
//   - Signup: 5/h per IP, 3/h per email
//   - Resend: 3 per token TTL (24h) per email
//   - Failed login: 10/15min per IP

import type { Env } from '../../worker';

export interface LimitResult {
	allowed: boolean;
	retryAfterSec?: number;
}

const HOUR_MS = 60 * 60 * 1000;
const MIN15_MS = 15 * 60 * 1000;

export async function checkSignupIp(env: Env, ip: string): Promise<LimitResult> {
	const since = new Date(Date.now() - HOUR_MS).toISOString();
	const row = await env.DB.prepare(
		`SELECT COUNT(*) AS n FROM signup_attempts WHERE ip = ? AND created_at >= ?`,
	)
		.bind(ip, since)
		.first<{ n: number }>();
	const n = row?.n ?? 0;
	if (n >= 5) return { allowed: false, retryAfterSec: HOUR_MS / 1000 };
	return { allowed: true };
}

export async function checkSignupEmail(env: Env, email: string): Promise<LimitResult> {
	const since = new Date(Date.now() - HOUR_MS).toISOString();
	const row = await env.DB.prepare(
		`SELECT COUNT(*) AS n FROM signup_attempts WHERE lower(email) = lower(?) AND created_at >= ?`,
	)
		.bind(email, since)
		.first<{ n: number }>();
	const n = row?.n ?? 0;
	if (n >= 3) return { allowed: false, retryAfterSec: HOUR_MS / 1000 };
	return { allowed: true };
}

export async function checkResendCount(env: Env, email: string): Promise<LimitResult> {
	// Count of resend attempts in the last 24h (capped to 3).
	const since = new Date(Date.now() - 24 * HOUR_MS).toISOString();
	const row = await env.DB.prepare(
		`SELECT COUNT(*) AS n FROM signup_attempts WHERE lower(email) = lower(?) AND created_at >= ?`,
	)
		.bind(email, since)
		.first<{ n: number }>();
	const n = row?.n ?? 0;
	if (n >= 3) return { allowed: false, retryAfterSec: 24 * HOUR_MS / 1000 };
	return { allowed: true };
}

export async function checkFailedLogin(env: Env, ip: string): Promise<LimitResult> {
	const since = new Date(Date.now() - MIN15_MS).toISOString();
	const row = await env.DB.prepare(
		`SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND success = 0 AND created_at >= ?`,
	)
		.bind(ip, since)
		.first<{ n: number }>();
	const n = row?.n ?? 0;
	if (n >= 10) return { allowed: false, retryAfterSec: MIN15_MS / 1000 };
	return { allowed: true };
}

export async function recordSignupAttempt(env: Env, ip: string, email: string): Promise<void> {
	await env.DB.prepare(
		`INSERT INTO signup_attempts (ip, email) VALUES (?, ?)`,
	)
		.bind(ip, email)
		.run();
}

export async function recordLoginAttempt(env: Env, ip: string, email: string, success: boolean): Promise<void> {
	await env.DB.prepare(
		`INSERT INTO login_attempts (ip, email, success) VALUES (?, ?, ?)`,
	)
		.bind(ip, email, success ? 1 : 0)
		.run();
}
