/**
 * PetraHTTP — Sovereign Native HTTP Router
 *
 * Drop-in replacement for Hono 4. Built on node:http with zero external deps.
 * Implements the full Hono API surface used across petraniumdev/sovereign/:
 *   - new Hono() / new PetraHTTP()
 *   - app.get/post/put/delete/patch/all/use/route/notFound/onError
 *   - Context: c.json/text/html/body/redirect/notFound, c.status, c.header
 *   - Request: c.req.param/query/header/json/text/formData/raw/method/path/url
 *   - Variables: c.set/get (typed via ContextVariableMap augmentation)
 *   - serve() — creates node:http server (replaces @hono/node-server)
 *
 * Ring 0 — PetraNode Pure (zero external dependencies)
 */

import * as http from 'node:http';
import { URL } from 'node:url';

// ─── Types ───────────────────────────────────────────────────────────────────

export type HTTPMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD' | 'ALL';

export type StatusCode = number;

// Hono-compatible context variable map — augmented by route files via declare module
// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface ContextVariableMap {}

export type Next = () => Promise<void>;

export type Handler<V extends ContextVariableMap = ContextVariableMap> = (
  c: Context<V>,
  next: Next
) => Response | void | Promise<Response | void>;

type RouteEntry = {
  method: HTTPMethod;
  pattern: string;
  paramNames: string[];
  regex: RegExp;
  handlers: Handler[];
};

// ─── Route Pattern Compiler ───────────────────────────────────────────────────

function compilePattern(pattern: string): { regex: RegExp; paramNames: string[] } {
  const paramNames: string[] = [];

  // Escape special regex chars except our route specials
  let regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // escape all except * and :
    .replace(/\\\*/g, '(.*)')               // unescape * → wildcard group
    .replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, (_match, name: string) => {
      paramNames.push(name);
      return '([^/]+)';
    });

  // Exact match (anchor end) unless pattern ends with * wildcard
  const trailingWild = pattern.endsWith('*');
  if (!trailingWild) {
    // Allow optional trailing slash
    regexStr = regexStr + '(?:\\/)?';
  }

  const regex = new RegExp(`^${regexStr}$`);
  return { regex, paramNames };
}

// ─── PetraRequest ─────────────────────────────────────────────────────────────

export class PetraRequest {
  readonly raw: Request;
  readonly method: string;
  readonly url: string;
  readonly path: string;

  /** @internal — not private so the router can merge params without unsafe casts */
  _params: Record<string, string> = {};
  private _query: Record<string, string> = {};
  private _bodyCache: unknown = undefined;
  private _bodyRead = false;
  private _textCache: string | undefined = undefined;
  private _textRead = false;

  constructor(raw: Request, params: Record<string, string> = {}) {
    this.raw = raw;
    this.method = raw.method.toUpperCase();
    this.url = raw.url;
    const u = new URL(raw.url);
    this.path = u.pathname;
    this._params = params;
    // Parse query string
    u.searchParams.forEach((value, key) => {
      this._query[key] = value;
    });
  }

  /** Get a named path parameter, e.g. c.req.param('id') */
  param(name: string): string;
  /** Get all path params */
  param(): Record<string, string>;
  param(name?: string): string | Record<string, string> {
    if (name === undefined) return { ...this._params };
    return this._params[name] ?? '';
  }

  /** Get a query string parameter, e.g. c.req.query('page') */
  query(name: string): string;
  /** Get all query params */
  query(): Record<string, string>;
  query(name?: string): string | Record<string, string> {
    if (name === undefined) return { ...this._query };
    return this._query[name] ?? '';
  }

  /** Get a request header value */
  header(name: string): string | undefined;
  /** Get all headers as a plain object */
  header(): Record<string, string>;
  header(name?: string): string | undefined | Record<string, string> {
    if (name === undefined) {
      const result: Record<string, string> = {};
      this.raw.headers.forEach((value, key) => {
        result[key.toLowerCase()] = value;
      });
      return result;
    }
    return this.raw.headers.get(name) ?? undefined;
  }

  /** Parse request body as JSON */
  async json<T = unknown>(): Promise<T> {
    if (this._bodyRead) return this._bodyCache as T;
    this._bodyRead = true;
    this._bodyCache = await this.raw.json();
    return this._bodyCache as T;
  }

  /** Read request body as text */
  async text(): Promise<string> {
    if (this._textRead) return this._textCache!;
    this._textRead = true;
    this._textCache = await this.raw.text();
    return this._textCache;
  }

  /** Read request body as FormData */
  async formData(): Promise<FormData> {
    return this.raw.formData();
  }

  /** Read request body as ArrayBuffer */
  async arrayBuffer(): Promise<ArrayBuffer> {
    return this.raw.arrayBuffer();
  }
}

// ─── PetraContext ─────────────────────────────────────────────────────────────

export class PetraContext<V extends ContextVariableMap = ContextVariableMap> {
  readonly req: PetraRequest;
  /** Bound environment — passed through for Hono compatibility (c.env) */
  readonly env: Record<string, unknown> = {};

  private _vars: Map<string, unknown> = new Map();
  private _status: StatusCode = 200;
  private _headers: Headers = new Headers();
  private _response: Response | null = null;

  constructor(req: PetraRequest, env?: Record<string, unknown>) {
    this.req = req;
    if (env) this.env = env;
  }

  // ── Variable store (c.set / c.get) ──────────────────────────────────────

  set<K extends keyof V>(key: K, value: V[K]): void;
  set(key: string, value: unknown): void;
  set(key: string, value: unknown): void {
    this._vars.set(key, value);
  }

  get<K extends keyof V>(key: K): V[K];
  get(key: string): unknown;
  get(key: string): unknown {
    return this._vars.get(key);
  }

  // ── Status / Headers ─────────────────────────────────────────────────────

  /** Set response status code */
  status(code: StatusCode): void {
    this._status = code;
  }

  /** Set a response header */
  header(name: string, value: string): void {
    this._headers.set(name, value);
  }

  // ── Response helpers ─────────────────────────────────────────────────────

  /** Send a JSON response */
  json<T = unknown>(data: T, status?: StatusCode): Response {
    const s = status ?? this._status;
    const headers = new Headers(this._headers);
    headers.set('Content-Type', 'application/json');
    const body = JSON.stringify(data);
    this._response = new Response(body, { status: s, headers });
    return this._response;
  }

  /** Send a plain text response */
  text(data: string, status?: StatusCode): Response {
    const s = status ?? this._status;
    const headers = new Headers(this._headers);
    headers.set('Content-Type', 'text/plain; charset=utf-8');
    this._response = new Response(data, { status: s, headers });
    return this._response;
  }

  /** Send an HTML response */
  html(data: string, status?: StatusCode): Response {
    const s = status ?? this._status;
    const headers = new Headers(this._headers);
    headers.set('Content-Type', 'text/html; charset=utf-8');
    this._response = new Response(data, { status: s, headers });
    return this._response;
  }

  /** Send raw body (binary-compatible) */
  body(
    data: Uint8Array | ArrayBuffer | string | ReadableStream | null,
    init?: ResponseInit | { headers?: Record<string, string> }
  ): Response {
    const s = (init as ResponseInit)?.status ?? this._status;
    const merged = new Headers(this._headers);
    const extraHeaders = (init as { headers?: Record<string, string> })?.headers;
    if (extraHeaders) {
      Object.entries(extraHeaders).forEach(([k, v]) => merged.set(k, v));
    }
    this._response = new Response(data, { status: s, headers: merged });
    return this._response;
  }

  /** Send a redirect response */
  redirect(location: string, status: StatusCode = 302): Response {
    const headers = new Headers(this._headers);
    headers.set('Location', location);
    this._response = new Response(null, { status, headers });
    return this._response;
  }

  /** Return a 404 Not Found response */
  notFound(): Response {
    this._response = new Response(
      JSON.stringify({ error: 'Not Found' }),
      {
        status: 404,
        headers: new Headers({ 'Content-Type': 'application/json' }),
      }
    );
    return this._response;
  }

  /** Expose the current response (Hono compatibility: c.res) */
  get res(): Response {
    if (!this._response) {
      this._response = new Response(null, { status: this._status, headers: this._headers });
    }
    return this._response;
  }

  /** Internal: get the built response (after all middleware ran) */
  _getResponse(): Response | null {
    return this._response;
  }

  /** Internal: allow middleware to replace the response object */
  _setResponse(res: Response): void {
    this._response = res;
  }
}

// ─── PetraHTTP Router ─────────────────────────────────────────────────────────

export class PetraHTTP<V extends ContextVariableMap = ContextVariableMap> {
  private _routes: RouteEntry[] = [];
  private _notFoundHandler: Handler<V> | null = null;
  private _errorHandler: ((err: Error, c: Context<V>) => Response | Promise<Response>) | null = null;

  // ── Route registration ────────────────────────────────────────────────────

  private _addRoute(method: HTTPMethod, path: string, ...handlers: Handler<V>[]): this {
    const { regex, paramNames } = compilePattern(path);
    this._routes.push({ method, pattern: path, paramNames, regex, handlers: handlers as Handler[] });
    return this;
  }

  get(path: string, ...handlers: Handler<V>[]): this {
    return this._addRoute('GET', path, ...handlers);
  }

  post(path: string, ...handlers: Handler<V>[]): this {
    return this._addRoute('POST', path, ...handlers);
  }

  put(path: string, ...handlers: Handler<V>[]): this {
    return this._addRoute('PUT', path, ...handlers);
  }

  delete(path: string, ...handlers: Handler<V>[]): this {
    return this._addRoute('DELETE', path, ...handlers);
  }

  patch(path: string, ...handlers: Handler<V>[]): this {
    return this._addRoute('PATCH', path, ...handlers);
  }

  options(path: string, ...handlers: Handler<V>[]): this {
    return this._addRoute('OPTIONS', path, ...handlers);
  }

  /** Register a handler for ALL HTTP methods */
  all(path: string, ...handlers: Handler<V>[]): this {
    return this._addRoute('ALL', path, ...handlers);
  }

  /** Register middleware — called for every request matching the path prefix */
  use(path: string, ...handlers: Handler<V>[]): this;
  use(...handlers: Handler<V>[]): this;
  use(pathOrHandler: string | Handler<V>, ...rest: Handler<V>[]): this {
    if (typeof pathOrHandler === 'string') {
      // Middleware on a prefix — treat as ALL with wildcard
      const prefix = pathOrHandler.endsWith('*') ? pathOrHandler : `${pathOrHandler}*`;
      return this._addRoute('ALL', prefix, ...rest);
    }
    // Global middleware — add as ALL/*
    return this._addRoute('ALL', '*', pathOrHandler, ...rest);
  }

  /** Mount a sub-router at a path prefix */
  route(prefix: string, subApp: PetraHTTP<V>): this {
    // Transfer all routes from subApp with adjusted patterns
    for (const entry of subApp._routes) {
      // Merge prefix + sub-pattern
      const normalizedPrefix = prefix.replace(/\/$/, '');
      let subPattern = entry.pattern;
      // sub-pattern '/' → just the prefix (or prefix/)
      if (subPattern === '/') {
        subPattern = '';
      } else if (!subPattern.startsWith('/')) {
        subPattern = '/' + subPattern;
      }

      const combined = normalizedPrefix + subPattern || '/';
      const { regex, paramNames } = compilePattern(combined);

      this._routes.push({
        method: entry.method,
        pattern: combined,
        paramNames,
        regex,
        handlers: entry.handlers,
      });
    }

    // Also transfer not-found / error handlers only if this app doesn't have one yet
    if (!this._notFoundHandler && subApp._notFoundHandler) {
      // Don't inherit sub-app not-found globally
    }

    return this;
  }

  /** Set custom 404 handler */
  notFound(handler: Handler<V>): this {
    this._notFoundHandler = handler;
    return this;
  }

  /** Set global error handler */
  onError(handler: (err: Error, c: Context<V>) => Response | Promise<Response>): this {
    this._errorHandler = handler;
    return this;
  }

  // ── Request dispatch ──────────────────────────────────────────────────────

  /** The fetch handler — compatible with Hono's app.fetch */
  fetch = async (request: Request, env?: Record<string, unknown>): Promise<Response> => {
    const u = new URL(request.url);
    const method = request.method.toUpperCase() as HTTPMethod;
    const path = u.pathname;

    // Collect all matching handlers in order
    type MatchedHandler = { handler: Handler; params: Record<string, string> };
    const matched: MatchedHandler[] = [];

    for (const route of this._routes) {
      // Match method
      const methodMatch =
        route.method === 'ALL' ||
        route.method === method ||
        (method === 'HEAD' && route.method === 'GET');

      if (!methodMatch) continue;

      // Match path
      const m = path.match(route.regex);
      if (!m) continue;

      // Extract named params
      const params: Record<string, string> = {};
      route.paramNames.forEach((name, i) => {
        params[name] = m[i + 1] ?? '';
      });

      for (const handler of route.handlers) {
        matched.push({ handler, params });
      }
    }

    // Build context with merged params from first matching route
    // (params get filled in per-handler below)
    const petraReq = new PetraRequest(request, {});
    const c = new PetraContext<V>(petraReq, env) as unknown as Context<V>;

    // Run matched handlers in order (middleware chain)
    let index = 0;
    let finalResponse: Response | null = null;

    const next = async (): Promise<void> => {
      if (index >= matched.length) return;

      const { handler, params } = matched[index++];

      // Merge this route's params into the shared request context
      Object.assign((c as unknown as PetraContext<V>).req._params, params);

      try {
        const result = await handler(c, next);
        if (result instanceof Response) {
          (c as unknown as PetraContext<V>)._setResponse(result);
          finalResponse = result;
        }
      } catch (err) {
        if (this._errorHandler) {
          const errorResponse = await this._errorHandler(
            err instanceof Error ? err : new Error(String(err)),
            c
          );
          (c as unknown as PetraContext<V>)._setResponse(errorResponse);
          finalResponse = errorResponse;
        } else {
          throw err;
        }
      }
    };

    try {
      await next();
    } catch (err) {
      if (this._errorHandler) {
        const errorResponse = await this._errorHandler(
          err instanceof Error ? err : new Error(String(err)),
          c
        );
        return errorResponse;
      }
      return new Response(
        JSON.stringify({ error: 'Internal Server Error', message: String(err) }),
        { status: 500, headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Check for a built response on the context
    const ctxResponse = (c as unknown as PetraContext<V>)._getResponse();
    if (ctxResponse) return ctxResponse;
    if (finalResponse) return finalResponse;

    // No route matched — 404
    if (this._notFoundHandler) {
      const nfResult = await this._notFoundHandler(c, async () => {});
      if (nfResult instanceof Response) return nfResult;
      const ctxR = (c as unknown as PetraContext<V>)._getResponse();
      if (ctxR) return ctxR;
    }

    return new Response(
      JSON.stringify({
        error: 'Not Found',
        message: `${method} ${path} is not a known sovereign endpoint`,
      }),
      { status: 404, headers: { 'Content-Type': 'application/json' } }
    );
  };
}

// ─── Context type alias (Hono-compatible) ────────────────────────────────────

/** Context type — mirrors Hono's Context<V> */
export type Context<V extends ContextVariableMap = ContextVariableMap> = PetraContext<V>;

// ─── Hono compatibility alias ─────────────────────────────────────────────────

/**
 * Hono — drop-in alias for PetraHTTP.
 * Allows `import { Hono } from './petranode/petra-http.js'` as a direct swap.
 */
export class Hono<V extends ContextVariableMap = ContextVariableMap> extends PetraHTTP<V> {}

// ─── serve() — Node:http adapter ─────────────────────────────────────────────

export interface ServeOptions {
  fetch: (req: Request, env?: Record<string, unknown>) => Promise<Response>;
  port?: number;
  hostname?: string;
}

export type ServeInfo = { address: string; port: number; family: string };

/**
 * serve() — starts a node:http server using the app's fetch handler.
 * Drop-in replacement for `@hono/node-server`.
 */
export function serve(
  options: ServeOptions,
  callback?: (info: ServeInfo) => void
): http.Server {
  const { fetch: fetchHandler, port = 3000, hostname = '0.0.0.0' } = options;

  const server = http.createServer(async (req, res) => {
    try {
      // Build a Fetch API Request from the node:http IncomingMessage
      const protocol = 'http';
      const host = req.headers.host ?? `${hostname}:${port}`;
      const url = `${protocol}://${host}${req.url ?? '/'}`;

      // Buffer the request body
      const bodyChunks: Uint8Array[] = [];
      for await (const chunk of req) {
        bodyChunks.push(chunk as Uint8Array);
      }
      const body = bodyChunks.length > 0 ? Buffer.concat(bodyChunks) : null;

      // Convert node headers to Fetch API Headers
      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers)) {
        if (Array.isArray(value)) {
          value.forEach((v) => headers.append(key, v));
        } else if (value !== undefined) {
          headers.set(key, value);
        }
      }

      const request = new Request(url, {
        method: req.method ?? 'GET',
        headers,
        body: body && body.length > 0 ? body : null,
        // @ts-ignore — duplex required in Node 18+ for request with body
        duplex: body && body.length > 0 ? 'half' : undefined,
      });

      const response = await fetchHandler(request);

      // Write status line + headers
      res.statusCode = response.status;
      response.headers.forEach((value, key) => {
        res.setHeader(key, value);
      });

      // Stream response body back
      if (response.body) {
        const reader = response.body.getReader();
        const write = (): void => {
          reader.read().then(({ done, value }) => {
            if (done) {
              res.end();
              return;
            }
            res.write(value, write as () => void);
          }).catch((err: unknown) => {
            console.error('[PetraHTTP] Response stream error:', err);
            res.end();
          });
        };
        write();
      } else {
        res.end();
      }
    } catch (err) {
      console.error('[PetraHTTP] Unhandled server error:', err);
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Internal Server Error', message: String(err) }));
    }
  });

  server.listen(port, hostname, () => {
    const addr = server.address();
    const info: ServeInfo = {
      address: typeof addr === 'object' && addr ? addr.address : hostname,
      port: typeof addr === 'object' && addr ? addr.port : port,
      family: 'IPv4',
    };
    callback?.(info);
  });

  return server;
}

// ─── Re-exports for convenience ───────────────────────────────────────────────

/** Default export — the PetraHTTP class (Hono-compatible) */
export default Hono;
