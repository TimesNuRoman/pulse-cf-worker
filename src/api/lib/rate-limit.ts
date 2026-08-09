// R257 + R260: rate limiting for signup/resend/login.
// Uses D1 signup_attempts / resend_attempts / login_attempts tables.
// D1 is eventually consistent — these are ceilings, not SLAs.
//
// Limits from spec §6.3:
//   - Signup: 5/h per IP, 3/h per email
//   - Resend: 3/24h per email, 10/h per IP (new)
//   - Failed login: 10/15min per IP

import type { Env } from '../../worker';

export interface LimitResult {
	allowed: boolean;
	retryAfterSec?: number;
}

const HOUR_MS = 60 * 60 * 1000;
const MIN15_MS = 15 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

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
	// 3 resends per 24h per email.
	const since = new Date(Date.now() - DAY_MS).toISOString();
	const row = await env.DB.prepare(
		`SELECT COUNT(*) AS n FROM resend_attempts WHERE lower(email) = lower(?) AND created_at >= ?`,
	)
		.bind(email, since)
		.first<{ n: number }>();
	const n = row?.n ?? 0;
	if (n >= 3) return { allowed: false, retryAfterSec: DAY_MS / 1000 };
	return { allowed: true };
}

export async function checkResendIp(env: Env, ip: string): Promise<LimitResult> {
	// 10 resends per hour per IP — cheap DOS prevention.
	const since = new Date(Date.now() - HOUR_MS).toISOString();
	const row = await env.DB.prepare(
		`SELECT COUNT(*) AS n FROM resend_attempts WHERE ip = ? AND created_at >= ?`,
	)
		.bind(ip, since)
		.first<{ n: number }>();
	const n = row?.n ?? 0;
	if (n >= 10) return { allowed: false, retryAfterSec: HOUR_MS / 1000 };
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

export async function recordResendAttempt(env: Env, ip: string, email: string): Promise<void> {
	await env.DB.prepare(
		`INSERT INTO resend_attempts (ip, email) VALUES (?, ?)`,
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
