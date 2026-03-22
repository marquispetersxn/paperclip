/**
 * PetraBridge — Express-to-PetraHTTP compatibility layer
 *
 * Allows all existing Express-style route handlers (req, res, next) to run
 * on top of PetraHTTP's sovereign runtime without any changes to routes,
 * middleware, or business logic.
 *
 * Architecture:
 *   http.createServer(app.requestListener)
 *       ↓
 *   PetraApp (sovereign HTTP router)
 *       ↓
 *   Express-style handlers (req, res, next) — UNCHANGED
 *       ↓
 *   Express Router instances (from route files) — called as (req, res, next)
 *
 * This is TERRAFORMING — Express is removed at the server/app layer while
 * all sub-route and middleware code continues using Express-compatible req/res
 * objects. Express Routers are still valid callable handlers when invoked with
 * augmented IncomingMessage/ServerResponse objects that have the extra fields
 * Express expects (body, params, query, actor, header(), etc.).
 */

import * as http from "node:http";
import { Readable } from "node:stream";

// ─── Types ────────────────────────────────────────────────────────────────────

export type NextFunction = (err?: unknown) => void;

/** Express-compatible Request — augmented IncomingMessage */
export interface PetraRequest extends http.IncomingMessage {
  body: unknown;
  params: Record<string, string>;
  query: Record<string, string | string[]>;
  originalUrl: string;
  path: string;
  actor: {
    type: "board" | "agent" | "none";
    userId?: string;
    agentId?: string;
    companyId?: string;
    companyIds?: string[];
    isInstanceAdmin?: boolean;
    keyId?: string;
    runId?: string;
    source?: "local_implicit" | "session" | "agent_key" | "agent_jwt" | "none";
  };
  header(name: string): string | undefined;
  get(name: string): string | undefined;
}

/** Express-compatible Response — augmented ServerResponse */
export interface PetraResponse extends http.ServerResponse {
  json(data: unknown): this;
  status(code: number): this;
  type(mime: string): this;
  set(name: string, value: string): this;
  set(headers: Record<string, string>): this;
  send(data: unknown): this;
  accepts(types: string | string[]): string | false;
}

export type ExpressHandler = (
  req: PetraRequest,
  res: PetraResponse,
  next: NextFunction,
) => void | Promise<void>;

export type ExpressErrorHandler = (
  err: unknown,
  req: PetraRequest,
  res: PetraResponse,
  next: NextFunction,
) => void | Promise<void>;

// ─── Utilities ────────────────────────────────────────────────────────────────

function mimeType(type: string): string {
  if (type === "html") return "text/html; charset=utf-8";
  if (type === "json") return "application/json";
  if (type === "plain" || type === "text") return "text/plain; charset=utf-8";
  if (type.includes("/")) return type;
  return type;
}

function parseQuery(qs: string): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  const raw = qs.startsWith("?") ? qs.slice(1) : qs;
  if (!raw) return result;
  for (const part of raw.split("&")) {
    if (!part) continue;
    const eq = part.indexOf("=");
    const key = decodeURIComponent(eq >= 0 ? part.slice(0, eq) : part);
    const val = decodeURIComponent(eq >= 0 ? part.slice(eq + 1) : "");
    const existing = result[key];
    if (existing !== undefined) {
      if (Array.isArray(existing)) existing.push(val);
      else result[key] = [existing, val];
    } else {
      result[key] = val;
    }
  }
  return result;
}

/** Compile an Express-style path pattern to regex + param names */
function compileRoute(pattern: string): { regex: RegExp; paramNames: string[] } {
  const paramNames: string[] = [];
  let regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\\\*/g, "(.*)")
    .replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, (_m, name: string) => {
      paramNames.push(name);
      return "([^/]+)";
    });
  // Allow optional trailing slash
  regexStr += "(?:\\/)?";
  return { regex: new RegExp(`^${regexStr}$`), paramNames };
}

/** Returns true if path matches the given prefix (for middleware mounting) */
function matchesPrefix(prefix: string, path: string): boolean {
  if (prefix === "/" || prefix === "") return true;
  const norm = prefix.replace(/\/\*$/, "").replace(/\/$/, "");
  return path === norm || path.startsWith(norm + "/");
}

// ─── Layer types ──────────────────────────────────────────────────────────────

type RouteLayer = {
  kind: "route";
  method: string | null;
  pattern: string;
  regex: RegExp;
  paramNames: string[];
  handlers: ExpressHandler[];
};

type MiddlewareLayer = {
  kind: "middleware";
  prefix: string | null;
  handler: ExpressHandler;
};

type SubrouterLayer = {
  kind: "subrouter";
  prefix: string;
  router: PetraRouter;
};

type ErrorLayer = {
  kind: "error";
  handler: ExpressErrorHandler;
};

type Layer = RouteLayer | MiddlewareLayer | SubrouterLayer | ErrorLayer;

// ─── PetraRouter ──────────────────────────────────────────────────────────────

export class PetraRouter {
  protected _layers: Layer[] = [];
  private _paramHandlers: Map<
    string,
    Array<(req: PetraRequest, res: PetraResponse, next: NextFunction, value: string) => void | Promise<void>>
  > = new Map();

  // ── Route registration ────────────────────────────────────────────────────

  private _route(method: string | null, pattern: string, handlers: ExpressHandler[]): this {
    const { regex, paramNames } = compileRoute(pattern);
    this._layers.push({ kind: "route", method, pattern, regex, paramNames, handlers });
    return this;
  }

  get(path: string, ...handlers: ExpressHandler[]): this { return this._route("GET", path, handlers); }
  post(path: string, ...handlers: ExpressHandler[]): this { return this._route("POST", path, handlers); }
  put(path: string, ...handlers: ExpressHandler[]): this { return this._route("PUT", path, handlers); }
  delete(path: string, ...handlers: ExpressHandler[]): this { return this._route("DELETE", path, handlers); }
  patch(path: string, ...handlers: ExpressHandler[]): this { return this._route("PATCH", path, handlers); }
  all(path: string, ...handlers: ExpressHandler[]): this { return this._route(null, path, handlers); }

  /** Register middleware or mount sub-router */
  use(handler: ExpressHandler): this;
  use(...handlers: ExpressHandler[]): this;
  use(path: string, ...handlers: (ExpressHandler | PetraRouter)[]): this;
  use(pathOrHandler: string | ExpressHandler | PetraRouter, ...rest: (ExpressHandler | PetraRouter)[]): this {
    if (typeof pathOrHandler === "string") {
      const prefix = pathOrHandler;
      const items = rest.length > 0 ? rest : [];
      for (const item of items) {
        if (item instanceof PetraRouter) {
          this._layers.push({ kind: "subrouter", prefix, router: item });
        } else {
          this._layers.push({ kind: "middleware", prefix, handler: item as ExpressHandler });
        }
      }
    } else if (pathOrHandler instanceof PetraRouter) {
      this._layers.push({ kind: "subrouter", prefix: "/", router: pathOrHandler });
    } else {
      const handlers = [pathOrHandler as ExpressHandler, ...(rest as ExpressHandler[])];
      for (const h of handlers) {
        this._layers.push({ kind: "middleware", prefix: null, handler: h });
      }
    }
    return this;
  }

  /** Register error-handling middleware (4 params) */
  useError(handler: ExpressErrorHandler): this {
    this._layers.push({ kind: "error", handler });
    return this;
  }

  /** Express router.param() */
  param(
    name: string,
    handler: (req: PetraRequest, res: PetraResponse, next: NextFunction, value: string) => void | Promise<void>,
  ): this {
    const list = this._paramHandlers.get(name) ?? [];
    list.push(handler);
    this._paramHandlers.set(name, list);
    return this;
  }

  // ── Dispatch ──────────────────────────────────────────────────────────────

  /**
   * Internal dispatch — runs all matching handlers for the current request.
   * Returns after the response is sent or all handlers have been called.
   */
  async _dispatch(
    req: PetraRequest,
    res: PetraResponse,
    outerNext?: NextFunction,
  ): Promise<void> {
    const method = (req.method ?? "GET").toUpperCase();
    const reqPath = req.path;

    // Collect matched handler descriptors in order
    type Call = () => Promise<void>;
    const calls: Call[] = [];

    for (const layer of this._layers) {
      if (layer.kind === "error") continue; // handled separately

      if (layer.kind === "middleware") {
        if (layer.prefix === null || matchesPrefix(layer.prefix, reqPath)) {
          const h = layer.handler;
          const prefix = layer.prefix;
          calls.push(() => {
            // Strip prefix from req.path and req.url so Express Routers see
            // relative paths (e.g. "/companies" prefix → handler sees "/foo")
            if (!prefix || prefix === "/" || prefix === "") {
              return runHandler(h, {});
            }
            const norm = prefix.replace(/\/\*$/, "").replace(/\/$/, "");
            const strippedPath = reqPath.slice(norm.length) || "/";
            const origPath = req.path;
            const origUrl = req.url;
            req.path = strippedPath;
            if (origUrl) {
              const qIdx = origUrl.indexOf("?");
              req.url = strippedPath + (qIdx >= 0 ? origUrl.slice(qIdx) : "");
            }
            return runHandler(h, {}).finally(() => {
              req.path = origPath;
              req.url = origUrl;
            });
          });
        }
        continue;
      }

      if (layer.kind === "subrouter") {
        if (matchesPrefix(layer.prefix, reqPath)) {
          const sub = layer.router;
          const strippedPath =
            layer.prefix === "/" || layer.prefix === ""
              ? reqPath
              : reqPath.slice(layer.prefix.replace(/\/$/, "").length) || "/";
          calls.push(() => {
            const origPath = req.path;
            const origUrl = req.url;
            req.path = strippedPath;
            // Also update req.url for Express Router compatibility
            if (origUrl) {
              const qIdx = origUrl.indexOf("?");
              req.url = strippedPath + (qIdx >= 0 ? origUrl.slice(qIdx) : "");
            }
            return sub._dispatch(req, res).finally(() => {
              req.path = origPath;
              req.url = origUrl;
            });
          });
        }
        continue;
      }

      if (layer.kind === "route") {
        const methodMatch =
          layer.method === null ||
          layer.method === method ||
          (method === "HEAD" && layer.method === "GET");
        if (!methodMatch) continue;
        const m = reqPath.match(layer.regex);
        if (!m) continue;
        const params: Record<string, string> = {};
        layer.paramNames.forEach((n, i) => {
          params[n] = decodeURIComponent(m[i + 1] ?? "");
        });
        for (const h of layer.handlers) {
          const capturedParams = { ...params };
          calls.push(() => {
            Object.assign(req.params, capturedParams);
            return runParamHandlers(capturedParams).then(() => runHandler(h, capturedParams));
          });
        }
        continue;
      }
    }

    // Collect error handlers (4-arg) for this router
    const errorHandlers: ExpressErrorHandler[] = this._layers
      .filter((l): l is ErrorLayer => l.kind === "error")
      .map((l) => l.handler);

    const runParamHandlers = async (params: Record<string, string>): Promise<void> => {
      for (const [name, value] of Object.entries(params)) {
        const handlers = this._paramHandlers.get(name) ?? [];
        for (const h of handlers) {
          await new Promise<void>((resolve, reject) => {
            try {
              const p = h(req, res, (err) => { if (err) reject(err); else resolve(); }, value);
              if (p instanceof Promise) p.catch(reject);
            } catch (e) { reject(e); }
          });
        }
      }
    };

    const runHandler = (h: ExpressHandler, _params: Record<string, string>): Promise<void> => {
      return new Promise<void>((resolve, reject) => {
        if (res.writableEnded || res.headersSent) {
          resolve();
          return;
        }
        let settled = false;
        const next: NextFunction = (err?: unknown) => {
          if (settled) return;
          settled = true;
          if (err !== undefined) reject(err);
          else resolve();
        };
        try {
          const result = h(req, res, next);
          if (result instanceof Promise) {
            result.then(() => {
              // Handler returned a promise and may have ended the response
              if (!settled) {
                if (res.writableEnded || res.headersSent) { settled = true; resolve(); }
                // else: waiting for next() call
              }
            }).catch((err) => {
              if (!settled) { settled = true; reject(err); }
            });
          } else {
            // Synchronous handler — check if response was ended
            setImmediate(() => {
              if (!settled) {
                if (res.writableEnded || res.headersSent) { settled = true; resolve(); }
                // else still waiting for async next()
              }
            });
          }
        } catch (e) {
          if (!settled) { settled = true; reject(e); }
        }
      });
    };

    let pendingError: unknown = undefined;

    for (const call of calls) {
      if (res.writableEnded || res.headersSent) break;
      try {
        await call();
      } catch (err) {
        pendingError = err;
        break;
      }
    }

    // Run error handlers
    if (pendingError !== undefined) {
      for (const h of errorHandlers) {
        if (res.writableEnded || res.headersSent) break;
        await new Promise<void>((resolve) => {
          try {
            const p = h(pendingError, req, res, () => { resolve(); });
            if (p instanceof Promise) p.then(() => resolve()).catch(() => resolve());
            else setImmediate(resolve);
          } catch { resolve(); }
        });
      }
      if (!res.writableEnded && !res.headersSent) {
        if (outerNext) {
          outerNext(pendingError);
        } else {
          res.statusCode = 500;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ error: "Internal server error" }));
        }
      }
    }
  }
}

// ─── PetraApp ─────────────────────────────────────────────────────────────────

/**
 * PetraApp — sovereign HTTP application (drop-in for `express()`).
 *
 * Exposes a `requestListener` compatible with `http.createServer()`.
 * JSON body parsing is built-in. All route handlers keep Express signatures.
 */
export class PetraApp extends PetraRouter {
  readonly requestListener: http.RequestListener = async (nodeReq, nodeRes) => {
    // Buffer request body
    const chunks: Buffer[] = [];
    for await (const chunk of nodeReq) {
      chunks.push(chunk as Buffer);
    }
    const rawBody = Buffer.concat(chunks);

    // Parse URL
    const urlStr = nodeReq.url ?? "/";
    const qIdx = urlStr.indexOf("?");
    const reqPath = qIdx >= 0 ? urlStr.slice(0, qIdx) : urlStr;
    const queryStr = qIdx >= 0 ? urlStr.slice(qIdx + 1) : "";

    // Build Express-compatible req facade over IncomingMessage
    const req = nodeReq as PetraRequest;
    req.path = reqPath;
    req.originalUrl = urlStr;
    req.method = (nodeReq.method ?? "GET").toUpperCase();
    req.params = {};
    req.query = parseQuery(queryStr);

    // Parse JSON body (built-in — replaces express.json() middleware)
    const contentType = ((nodeReq.headers["content-type"] ?? "") as string).toLowerCase();
    if (rawBody.length > 0 && contentType.includes("application/json")) {
      try { req.body = JSON.parse(rawBody.toString("utf-8")); } catch { req.body = undefined; }
    } else {
      req.body = undefined;
      // Restore stream for multer and other body parsers (multipart/form-data, etc.)
      // Multer reads req as a Readable stream; replay buffered bytes back into it.
      if (rawBody.length > 0) {
        (nodeReq as any).__petraRawBody = rawBody;
        // Recreate the readable stream so multer can consume it
        const replay = new Readable({ read() {} });
        replay.push(rawBody);
        replay.push(null); // EOF
        // Copy replay methods onto nodeReq so multer's busboy can read it
        (nodeReq as any).pipe = replay.pipe.bind(replay);
        (nodeReq as any)[Symbol.asyncIterator] = replay[Symbol.asyncIterator]?.bind(replay);
        // Patch the 'readable' event and 'on' for busboy compatibility
        const origOn = nodeReq.on.bind(nodeReq);
        (nodeReq as any).on = (event: string, listener: (...args: any[]) => void) => {
          if (event === "data" || event === "end" || event === "error" || event === "close") {
            replay.on(event, listener);
          } else {
            origOn(event, listener);
          }
          return nodeReq;
        };
      }
    }

    // Initialize actor
    if (!req.actor) {
      req.actor = { type: "none", source: "none" };
    }

    // Header helpers (Express-compatible)
    req.header = (name: string) => {
      const v = nodeReq.headers[name.toLowerCase()];
      return Array.isArray(v) ? v[0] : v;
    };
    req.get = req.header;

    // Build Express-compatible res facade over ServerResponse
    const res = nodeRes as PetraResponse;
    let _statusCode = 200;

    res.status = (code: number) => {
      _statusCode = code;
      nodeRes.statusCode = code;
      return res;
    };

    res.json = (data: unknown) => {
      if (!nodeRes.headersSent) {
        nodeRes.statusCode = _statusCode;
        nodeRes.setHeader("Content-Type", "application/json");
      }
      nodeRes.end(JSON.stringify(data));
      return res;
    };

    res.send = (data: unknown) => {
      if (!nodeRes.headersSent) nodeRes.statusCode = _statusCode;
      if (data === null || data === undefined) nodeRes.end();
      else if (typeof data === "string") nodeRes.end(data);
      else if (Buffer.isBuffer(data)) nodeRes.end(data);
      else {
        nodeRes.setHeader("Content-Type", "application/json");
        nodeRes.end(JSON.stringify(data));
      }
      return res;
    };

    res.type = (mime: string) => {
      nodeRes.setHeader("Content-Type", mimeType(mime));
      return res;
    };

    res.set = ((name: string | Record<string, string>, value?: string) => {
      if (typeof name === "string" && value !== undefined) {
        nodeRes.setHeader(name, value);
      } else if (typeof name === "object") {
        for (const [k, v] of Object.entries(name)) nodeRes.setHeader(k, v);
      }
      return res;
    }) as PetraResponse["set"];

    res.accepts = (types: string | string[]) => {
      const accept = ((nodeReq.headers["accept"] as string) ?? "").toLowerCase();
      const list = Array.isArray(types) ? types : [types];
      for (const t of list) {
        if (accept.includes(t.toLowerCase()) || t === "*/*") return t;
      }
      return false;
    };

    // Dispatch through the router
    await this._dispatch(req, res);

    // Fallthrough 404
    if (!nodeRes.writableEnded && !nodeRes.headersSent) {
      nodeRes.statusCode = 404;
      nodeRes.setHeader("Content-Type", "application/json");
      nodeRes.end(JSON.stringify({ error: "Not Found" }));
    }
  };
}

// ─── Factory functions ────────────────────────────────────────────────────────

/** Create a sovereign PetraApp — drop-in for `express()` */
export function createPetraApp(): PetraApp {
  return new PetraApp();
}

/** Create a sovereign PetraRouter — drop-in for `express.Router()` */
export function Router(): PetraRouter {
  return new PetraRouter();
}

export default createPetraApp;
