/**
 * Petra Logger — Sovereign structured logger (replaces pino + pino-http + pino-pretty)
 * Zero external dependencies — uses only node:fs, node:path, node:util.
 *
 * API-compatible with pino:
 *   logger.info(obj, msg?)
 *   logger.warn(obj, msg?)
 *   logger.error(obj, msg?)
 *   logger.debug(obj, msg?)
 *
 * Also exports httpLogger middleware compatible with pino-http:
 *   app.use(httpLogger)
 */

import { appendFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Request, Response, NextFunction } from 'express';

// ─── ANSI Colors ──────────────────────────────────────────────────────────────

const C = {
  reset:   '\x1b[0m',
  dim:     '\x1b[2m',
  bold:    '\x1b[1m',
  red:     '\x1b[31m',
  yellow:  '\x1b[33m',
  cyan:    '\x1b[36m',
  green:   '\x1b[32m',
  magenta: '\x1b[35m',
  blue:    '\x1b[34m',
  gray:    '\x1b[90m',
} as const;

function color(text: string, c: keyof typeof C): string {
  return `${C[c]}${text}${C.reset}`;
}

// ─── Level config ─────────────────────────────────────────────────────────────

type Level = 'debug' | 'info' | 'warn' | 'error';

const LEVELS: Record<Level, number> = {
  debug: 10,
  info:  20,
  warn:  30,
  error: 40,
};

const LEVEL_LABELS: Record<Level, string> = {
  debug: color('DBG', 'gray'),
  info:  color('INF', 'cyan'),
  warn:  color('WRN', 'yellow'),
  error: color('ERR', 'red'),
};

const LEVEL_LABELS_PLAIN: Record<Level, string> = {
  debug: 'DBG',
  info:  'INF',
  warn:  'WRN',
  error: 'ERR',
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function timestamp(): string {
  const d = new Date();
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}

function safeStringify(val: unknown): string {
  try {
    return JSON.stringify(val, (_k, v) => {
      if (v instanceof Error) return { message: v.message, stack: v.stack };
      return v;
    });
  } catch {
    return String(val);
  }
}

function formatExtra(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).filter(k => k !== 'msg' && k !== 'level' && k !== 'time');
  if (keys.length === 0) return '';
  const parts = keys.map(k => `${k}=${safeStringify(obj[k])}`);
  return ' ' + parts.join(' ');
}

// ─── File sink ────────────────────────────────────────────────────────────────

let _logFile: string | null = null;
let _logFileReady = false;

function initLogFile(logDir: string, filename = 'server.log'): void {
  try {
    mkdirSync(logDir, { recursive: true });
    _logFile = join(logDir, filename);
    _logFileReady = true;
  } catch {
    _logFileReady = false;
  }
}

function writeToFile(line: string): void {
  if (!_logFileReady || !_logFile) return;
  try {
    appendFileSync(_logFile, line + '\n', 'utf8');
  } catch {
    // Silently ignore file write errors
  }
}

// ─── Core log function ────────────────────────────────────────────────────────

function log(level: Level, minLevel: Level, obj: Record<string, unknown> | string, msg?: string): void {
  if (LEVELS[level] < LEVELS[minLevel]) return;

  const ts = timestamp();
  let message: string;
  let extra: Record<string, unknown>;

  if (typeof obj === 'string') {
    message = obj;
    extra = {};
  } else {
    message = msg ?? (typeof obj.msg === 'string' ? obj.msg : '');
    extra = obj;
  }

  const extraStr = typeof extra === 'object' ? formatExtra(extra as Record<string, unknown>) : '';

  // Console (colored)
  const consoleLine = `${color(ts, 'dim')} ${LEVEL_LABELS[level]} ${message}${color(extraStr, 'gray')}`;
  if (level === 'error') {
    process.stderr.write(consoleLine + '\n');
  } else {
    process.stdout.write(consoleLine + '\n');
  }

  // File (plain text)
  const fileLine = `${ts} ${LEVEL_LABELS_PLAIN[level]} ${message}${extraStr}`;
  writeToFile(fileLine);
}

// ─── Logger factory ───────────────────────────────────────────────────────────

export interface PetraLogger {
  level: string;
  debug(obj: Record<string, unknown> | string, msg?: string): void;
  info(obj: Record<string, unknown> | string, msg?: string): void;
  warn(obj: Record<string, unknown> | string, msg?: string): void;
  error(obj: Record<string, unknown> | string, msg?: string): void;
}

function createLogger(opts: { level?: Level; logDir?: string; logFile?: string } = {}): PetraLogger {
  const minLevel: Level = opts.level ?? 'debug';

  if (opts.logDir) {
    initLogFile(opts.logDir, opts.logFile ?? 'server.log');
  }

  return {
    level: minLevel,
    debug: (obj, msg) => log('debug', minLevel, obj as Record<string, unknown> | string, msg),
    info:  (obj, msg) => log('info',  minLevel, obj as Record<string, unknown> | string, msg),
    warn:  (obj, msg) => log('warn',  minLevel, obj as Record<string, unknown> | string, msg),
    error: (obj, msg) => log('error', minLevel, obj as Record<string, unknown> | string, msg),
  };
}

// ─── HTTP Middleware (pino-http compatible) ───────────────────────────────────

export type HttpLoggerMiddleware = (req: Request, res: Response, next: NextFunction) => void;

function createHttpLogger(baseLogger: PetraLogger): HttpLoggerMiddleware {
  return (req: Request, res: Response, next: NextFunction) => {
    const startMs = Date.now();

    res.on('finish', () => {
      const durationMs = Date.now() - startMs;
      const status = res.statusCode;
      const method = req.method;
      const url = req.url ?? req.path;

      const statusStr = status >= 500 ? color(String(status), 'red')
        : status >= 400 ? color(String(status), 'yellow')
        : color(String(status), 'green');

      const ctx = (res as { __errorContext?: { error?: { message?: string }; reqBody?: unknown; reqParams?: unknown; reqQuery?: unknown } }).__errorContext;

      const extra: Record<string, unknown> = {
        status,
        duration: `${durationMs}ms`,
      };

      if (status >= 400 && ctx) {
        if (ctx.error?.message) extra.errorMessage = ctx.error.message;
        if (ctx.reqBody) extra.reqBody = ctx.reqBody;
        if (ctx.reqParams) extra.reqParams = ctx.reqParams;
        if (ctx.reqQuery) extra.reqQuery = ctx.reqQuery;
      } else if (status >= 400) {
        const body = (req as { body?: unknown }).body;
        const params = (req as { params?: unknown }).params;
        const query = (req as { query?: unknown }).query;
        if (body && typeof body === 'object' && Object.keys(body as object).length > 0) extra.reqBody = body;
        if (params && typeof params === 'object' && Object.keys(params as object).length > 0) extra.reqParams = params;
        if (query && typeof query === 'object' && Object.keys(query as object).length > 0) extra.reqQuery = query;
      }

      const msg = `${method} ${url} ${statusStr}`;

      if (status >= 500) {
        baseLogger.error(extra, `${method} ${url} ${status} — ${(extra.errorMessage as string | undefined) ?? 'internal error'}`);
      } else if (status >= 400) {
        baseLogger.warn(extra, msg);
      } else {
        baseLogger.info(extra, msg);
      }
    });

    next();
  };
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export { createLogger, createHttpLogger, initLogFile };
