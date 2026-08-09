// Structured JSON logging for Workers.
// All logs are emitted as single-line JSON to stdout; wrangler tail picks them up
// and Workers Logs / Logpush can parse them. Never logs secrets or full PII.

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogContext {
	requestId?: string;
	path?: string;
	method?: string;
	ip?: string;
	userId?: string;
	[key: string]: unknown;
}

const LEVELS: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

function emit(level: LogLevel, message: string, ctx?: LogContext, err?: unknown): void {
	const entry: Record<string, unknown> = {
		ts: new Date().toISOString(),
		level,
		msg: message,
		...ctx,
	};
	if (err !== undefined) {
		entry.error = err instanceof Error ? { name: err.name, message: err.message, stack: err.stack } : String(err);
	}
	// Workers runtime uses console.log/error; Logpush parses JSON if first char is '{'.
	const line = JSON.stringify(entry);
	if (level === 'error' || level === 'warn') {
		console.error(line);
	} else {
		console.log(line);
	}
}

export const log = {
	debug: (msg: string, ctx?: LogContext) => emit('debug', msg, ctx),
	info: (msg: string, ctx?: LogContext) => emit('info', msg, ctx),
	warn: (msg: string, ctx?: LogContext) => emit('warn', msg, ctx),
	error: (msg: string, ctx?: LogContext, err?: unknown) => emit('error', msg, ctx, err),
};

export function newRequestId(): string {
	return crypto.randomUUID();
}
