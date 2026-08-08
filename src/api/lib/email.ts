// R257: email sender via Resend API.
// Reference: https://resend.com/docs/api-reference/emails/send-email
//
// In dev (DEV_LOG_EMAIL=1), emails are logged to console instead of
// being sent. This lets us deploy the worker before we have a Resend
// key configured.

import type { Env } from '../../worker';

export interface EmailMessage {
	to: string;
	subject: string;
	html: string;
	text: string;
}

export async function sendEmail(env: Env, msg: EmailMessage): Promise<{ ok: boolean; id?: string; error?: string }> {
	if (env.DEV_LOG_EMAIL === '1' || !env.RESEND_API_KEY) {
		// Dev mode: log to console. Wrangler `tail` picks these up.
		console.log('[email dev]', { to: msg.to, subject: msg.subject, text: msg.text });
		return { ok: true, id: 'dev-' + Date.now() };
	}

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
	});

	if (!res.ok) {
		const errText = await res.text();
		console.error('Resend error', { status: res.status, body: errText });
		return { ok: false, error: errText };
	}

	const data = (await res.json()) as { id?: string };
	return { ok: true, id: data.id };
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
		'— Pulse team',
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
    <p style="margin:16px 0 0;font-size:0.85rem;color:#9aa5ce;">— Pulse team</p>
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
