// R257 + R260: email sender via Resend API.
// Reference: https://resend.com/docs/api-reference/emails/send-email
//
// Security: 5s timeout on the Resend fetch — Workers have a 30s CPU limit
// per request, but we don't want to block the request for that long waiting
// on a third-party that may be down. If Resend fails, the request still
// returns 200 (caller decides whether to alert user via different channel).

import type { Env } from '../../worker';
import { log } from './logger';

export interface EmailMessage {
	to: string;
	subject: string;
	html: string;
	text: string;
}

const RESEND_TIMEOUT_MS = 5000;

export async function sendEmail(env: Env, msg: EmailMessage, requestId?: string): Promise<{ ok: boolean; id?: string; error?: string }> {
	if (env.DEV_LOG_EMAIL === '1' || !env.RESEND_API_KEY) {
		// Dev mode: log to console. Wrangler `tail` picks these up.
		console.log('[email dev]', { to: msg.to, subject: msg.subject, text: msg.text });
		return { ok: true, id: 'dev-' + Date.now() };
	}

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), RESEND_TIMEOUT_MS);

	try {
		const res = await fetch('https://api.resend.com/emails', {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${env.RESEND_API_KEY}`,
				'content-type': 'application/json',
			},
			body: JSON.stringify({
				from: env.FROM_EMAIL,
				to: msg.to,
				subject: msg.subject,
				html: msg.html,
				text: msg.text,
			}),
			signal: controller.signal,
		});

		clearTimeout(timer);

		if (!res.ok) {
			const errText = await res.text();
			log.error('resend_api_error', { requestId, status: res.status, body: errText.slice(0, 500) });
			return { ok: false, error: errText };
		}

		const data = (await res.json()) as { id?: string };
		return { ok: true, id: data.id };
	} catch (err) {
		clearTimeout(timer);
		const isAbort = err instanceof Error && err.name === 'AbortError';
		log.error('resend_fetch_failed', { requestId, aborted: isAbort }, err);
		return { ok: false, error: isAbort ? 'timeout' : 'fetch_error' };
	}
}

// R257: verification email template.
export function buildVerificationEmail(name: string, verifyUrl: string): EmailMessage {
	const subject = 'Verify your Pulse account';
	const text = [
		`Hi ${name},`,
		'',
		'Welcome to Pulse. Click the link below to activate your account.',
		'This link expires in 24 hours.',
		'',
		verifyUrl,
		'',
		"If you didn't create this account, you can safely ignore this email.",
		'',
		'— Pulse',
	].join('\n');

	const html = `<!doctype html>
<html><body style="background:#1a1b26;color:#c0caf5;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:32px 20px;margin:0;">
  <div style="max-width:480px;margin:0 auto;background:#24283b;border:1px solid #2f334d;padding:32px;">
    <h1 style="font-size:1.4rem;margin:0 0 16px;color:#c0caf5;">Verify your Pulse account</h1>
    <p style="margin:0 0 12px;line-height:1.6;">Hi ${escapeHtml(name)},</p>
    <p style="margin:0 0 16px;line-height:1.6;">Welcome to Pulse. Click the button below to activate your account. This link expires in 24 hours.</p>
    <p style="margin:24px 0;">
      <a href="${verifyUrl}" style="display:inline-block;background:#bb9af7;color:#1a1b26;padding:12px 24px;text-decoration:none;font-weight:600;">Verify my email</a>
    </p>
    <p style="margin:24px 0 0;font-size:0.85rem;color:#9aa5ce;">Or paste this link into your browser:</p>
    <p style="margin:0;font-family:ui-monospace,monospace;font-size:0.78rem;color:#7dcfff;word-break:break-all;">${verifyUrl}</p>
    <p style="margin:32px 0 0;font-size:0.85rem;color:#9aa5ce;">If you didn't create this account, you can safely ignore this email.</p>
    <p style="margin:16px 0 0;font-size:0.85rem;color:#9aa5ce;">— Pulse</p>
  </div>
</body></html>`;

	return { to: '', subject, html, text };
}

function escapeHtml(s: string): string {
	return s
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

// R259: email change confirmation template.
export function buildEmailChangeConfirm(newEmail: string, confirmUrl: string): EmailMessage {
	const subject = 'Confirm your new Pulse email';
	const text = [
		`Hi,`,
		'',
		`Click the link below to confirm that this is your new email for Pulse.`,
		`The link expires in 24 hours.`,
		'',
		confirmUrl,
		'',
		`If this wasn't you, ignore this email. Your current email stays active.`,
		'',
		`— Pulse team`,
	].join('\n');

	const html = `<!doctype html>
<html><body style="background:#1a1b26;color:#c0caf5;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:32px 20px;margin:0;">
  <div style="max-width:480px;margin:0 auto;background:#24283b;border:1px solid #2f334d;padding:32px;">
    <h1 style="font-size:1.4rem;margin:0 0 16px;color:#c0caf5;">Confirm your new Pulse email</h1>
    <p style="margin:0 0 16px;line-height:1.6;">Click the button below to confirm that this is your new email for Pulse. The link expires in 24 hours.</p>
    <p style="margin:24px 0;">
      <a href="${confirmUrl}" style="display:inline-block;background:#bb9af7;color:#1a1b26;padding:12px 24px;text-decoration:none;font-weight:600;">Confirm new email</a>
    </p>
    <p style="margin:24px 0 0;font-size:0.85rem;color:#9aa5ce;">Or paste this link into your browser:</p>
    <p style="margin:0;font-family:ui-monospace,monospace;font-size:0.78rem;color:#7dcfff;word-break:break-all;">${confirmUrl}</p>
    <p style="margin:32px 0 0;font-size:0.85rem;color:#9aa5ce;">If this wasn't you, ignore this email. Your current email stays active.</p>
    <p style="margin:16px 0 0;font-size:0.85rem;color:#9aa5ce;">— Pulse team</p>
  </div>
</body></html>`;

	return { to: '', subject, html, text };
}
