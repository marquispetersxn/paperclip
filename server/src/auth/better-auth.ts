/**
 * Sovereign Session Auth — replaces better-auth
 *
 * Implements the exact same exported API shape as the previous better-auth module
 * so all consumers (index.ts, app.ts, live-events-ws.ts, middleware/auth.ts) work
 * unchanged.
 *
 * Handles:
 *   POST /api/auth/sign-in/email  — email + password sign-in
 *   POST /api/auth/sign-up/email  — register (unless disableSignUp)
 *   POST /api/auth/sign-out       — clear session cookie
 *   GET  /api/auth/get-session    — resolve session from cookie (also inline in app.ts)
 *
 * Session storage: existing DB tables (user, session, account) — same schema as better-auth.
 * Cookie name: better-auth.session_token (matches what the UI already expects).
 * Password hashing: bcryptjs (no native bindings).
 */

import { createHash, randomBytes } from "node:crypto";
import type { Request, RequestHandler } from "express";
import type { IncomingHttpHeaders } from "node:http";
import { eq, and } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import {
  authAccounts,
  authSessions,
  authUsers,
} from "@paperclipai/db";
import type { Config } from "../config.js";

// ─── Types (public API — unchanged from better-auth) ──────────────────────────

export type BetterAuthSessionUser = {
  id: string;
  email?: string | null;
  name?: string | null;
};

export type BetterAuthSessionResult = {
  session: { id: string; userId: string } | null;
  user: BetterAuthSessionUser | null;
};

// ─── Internal instance type ───────────────────────────────────────────────────

export type BetterAuthInstance = {
  db: Db;
  secret: string;
  disableSignUp: boolean;
  useSecureCookies: boolean;
  trustedOrigins: string[];
};

// ─── Bcrypt (pure JS, zero native deps) ──────────────────────────────────────
// Use dynamic import to avoid loading on every parse
async function getBcrypt() {
  const { hash, compare } = await import("bcryptjs");
  return { hash, compare };
}

// ─── Cookie helpers ───────────────────────────────────────────────────────────

const COOKIE_NAME = "better-auth.session_token";
const SESSION_TTL_DAYS = 30;
const SESSION_TTL_MS = SESSION_TTL_DAYS * 24 * 60 * 60 * 1000;

function buildSetCookieHeader(token: string, opts: { secure: boolean; expires: Date }): string {
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    `Path=/`,
    `HttpOnly`,
    `SameSite=Lax`,
    `Expires=${opts.expires.toUTCString()}`,
  ];
  if (opts.secure) parts.push("Secure");
  return parts.join("; ");
}

function buildClearCookieHeader(opts: { secure: boolean }): string {
  const parts = [
    `${COOKIE_NAME}=`,
    `Path=/`,
    `HttpOnly`,
    `SameSite=Lax`,
    `Max-Age=0`,
    `Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
  ];
  if (opts.secure) parts.push("Secure");
  return parts.join("; ");
}

function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  if (!cookieHeader) return {};
  const result: Record<string, string> = {};
  for (const part of cookieHeader.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key) result[key.trim()] = decodeURIComponent(rest.join("=").trim());
  }
  return result;
}

function extractSessionToken(headers: Headers | IncomingHttpHeaders): string | null {
  // Try cookie header
  let cookieHeader: string | undefined;
  if (headers instanceof Headers) {
    cookieHeader = headers.get("cookie") ?? undefined;
  } else {
    const raw = headers.cookie;
    cookieHeader = Array.isArray(raw) ? raw.join("; ") : raw;
  }

  const cookies = parseCookies(cookieHeader);
  const fromCookie = cookies[COOKIE_NAME];
  if (fromCookie) return fromCookie;

  // Try Authorization: Bearer <token>
  let authHeader: string | undefined;
  if (headers instanceof Headers) {
    authHeader = headers.get("authorization") ?? undefined;
  } else {
    const raw = headers.authorization;
    authHeader = Array.isArray(raw) ? raw[0] : raw;
  }
  if (authHeader?.toLowerCase().startsWith("bearer ")) {
    const token = authHeader.slice("bearer ".length).trim();
    if (token) return token;
  }

  return null;
}

// ─── Session DB operations ────────────────────────────────────────────────────

function generateId(): string {
  return randomBytes(16).toString("hex");
}

async function createSession(db: Db, userId: string, ipAddress?: string, userAgent?: string): Promise<{ id: string; token: string }> {
  const id = generateId();
  const token = randomBytes(32).toString("hex");
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_MS);

  await db.insert(authSessions).values({
    id,
    token,
    userId,
    expiresAt,
    createdAt: now,
    updatedAt: now,
    ipAddress: ipAddress ?? null,
    userAgent: userAgent ?? null,
  });

  return { id, token };
}

async function resolveSessionFromToken(db: Db, token: string): Promise<BetterAuthSessionResult | null> {
  const now = new Date();

  const sessionRow = await db
    .select({
      sessionId: authSessions.id,
      sessionUserId: authSessions.userId,
      sessionExpiresAt: authSessions.expiresAt,
      userId: authUsers.id,
      userEmail: authUsers.email,
      userName: authUsers.name,
    })
    .from(authSessions)
    .innerJoin(authUsers, eq(authSessions.userId, authUsers.id))
    .where(eq(authSessions.token, token))
    .then((rows) => rows[0] ?? null);

  if (!sessionRow) return null;
  if (sessionRow.sessionExpiresAt < now) return null;

  return {
    session: { id: sessionRow.sessionId, userId: sessionRow.sessionUserId },
    user: {
      id: sessionRow.userId,
      email: sessionRow.userEmail ?? null,
      name: sessionRow.userName ?? null,
    },
  };
}

async function deleteSession(db: Db, token: string): Promise<void> {
  await db.delete(authSessions).where(eq(authSessions.token, token));
}

// ─── Auth request handlers ────────────────────────────────────────────────────

async function handleSignUp(
  db: Db,
  body: unknown,
  disableSignUp: boolean,
): Promise<{ status: number; body: unknown; userId?: string }> {
  if (disableSignUp) {
    return { status: 403, body: { error: { message: "Sign up is disabled" } } };
  }

  const parsed = body as { name?: string; email?: string; password?: string } | null;
  const email = parsed?.email?.trim().toLowerCase();
  const name = parsed?.name?.trim();
  const password = parsed?.password;

  if (!email || !name || !password) {
    return { status: 400, body: { error: { message: "name, email, and password are required" } } };
  }
  if (password.length < 8) {
    return { status: 400, body: { error: { message: "Password must be at least 8 characters" } } };
  }

  const existing = await db
    .select({ id: authUsers.id })
    .from(authUsers)
    .where(eq(authUsers.email, email))
    .then((rows) => rows[0] ?? null);

  if (existing) {
    return { status: 400, body: { error: { message: "An account with this email already exists" } } };
  }

  const { hash } = await getBcrypt();
  const passwordHash = await hash(password, 10);

  const now = new Date();
  const userId = generateId();

  await db.insert(authUsers).values({
    id: userId,
    name,
    email,
    emailVerified: false,
    image: null,
    createdAt: now,
    updatedAt: now,
  });

  await db.insert(authAccounts).values({
    id: generateId(),
    accountId: userId,
    providerId: "credential",
    userId,
    password: passwordHash,
    createdAt: now,
    updatedAt: now,
  });

  return { status: 200, body: { id: userId, email, name }, userId };
}

async function handleSignIn(
  db: Db,
  body: unknown,
): Promise<{ status: number; body: unknown; userId?: string }> {
  const parsed = body as { email?: string; password?: string } | null;
  const email = parsed?.email?.trim().toLowerCase();
  const password = parsed?.password;

  if (!email || !password) {
    return { status: 400, body: { error: { message: "email and password are required" } } };
  }

  const userRow = await db
    .select({ id: authUsers.id, name: authUsers.name, email: authUsers.email })
    .from(authUsers)
    .where(eq(authUsers.email, email))
    .then((rows) => rows[0] ?? null);

  if (!userRow) {
    return { status: 401, body: { error: { message: "Invalid email or password" } } };
  }

  const accountRow = await db
    .select({ password: authAccounts.password })
    .from(authAccounts)
    .where(
      and(
        eq(authAccounts.userId, userRow.id),
        eq(authAccounts.providerId, "credential"),
      ),
    )
    .then((rows) => rows[0] ?? null);

  if (!accountRow?.password) {
    return { status: 401, body: { error: { message: "Invalid email or password" } } };
  }

  const { compare } = await getBcrypt();
  const valid = await compare(password, accountRow.password);
  if (!valid) {
    return { status: 401, body: { error: { message: "Invalid email or password" } } };
  }

  return {
    status: 200,
    body: { id: userRow.id, email: userRow.email, name: userRow.name },
    userId: userRow.id,
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function deriveAuthTrustedOrigins(config: Config): string[] {
  const baseUrl = config.authBaseUrlMode === "explicit" ? config.authPublicBaseUrl : undefined;
  const trustedOrigins = new Set<string>();

  if (baseUrl) {
    try {
      trustedOrigins.add(new URL(baseUrl).origin);
    } catch {
      // invalid base URL
    }
  }
  if (config.deploymentMode === "authenticated") {
    for (const hostname of config.allowedHostnames) {
      const trimmed = hostname.trim().toLowerCase();
      if (!trimmed) continue;
      trustedOrigins.add(`https://${trimmed}`);
      trustedOrigins.add(`http://${trimmed}`);
    }
  }

  return Array.from(trustedOrigins);
}

export function createBetterAuthInstance(
  db: Db,
  config: Config,
  trustedOrigins?: string[],
): BetterAuthInstance {
  const secret =
    process.env.BETTER_AUTH_SECRET?.trim() ??
    process.env.PAPERCLIP_AGENT_JWT_SECRET?.trim() ??
    "paperclip-dev-secret";

  const publicUrl =
    process.env.PAPERCLIP_PUBLIC_URL?.trim() ??
    (config.authBaseUrlMode === "explicit" ? config.authPublicBaseUrl : undefined);

  const isHttpOnly = publicUrl ? publicUrl.startsWith("http://") : false;

  return {
    db,
    secret,
    disableSignUp: config.authDisableSignUp,
    useSecureCookies: !isHttpOnly,
    trustedOrigins: trustedOrigins ?? deriveAuthTrustedOrigins(config),
  };
}

export function createBetterAuthHandler(auth: BetterAuthInstance): RequestHandler {
  return async (req, res, next) => {
    // Only handle /api/auth/* routes
    if (!req.path.startsWith("/sign-in") && !req.path.startsWith("/sign-up") && !req.path.startsWith("/sign-out") && !req.path.startsWith("/get-session")) {
      next();
      return;
    }

    const method = req.method.toUpperCase();
    const path = req.path;

    try {
      // POST /api/auth/sign-up/email
      if (method === "POST" && path.startsWith("/sign-up/email")) {
        const result = await handleSignUp(auth.db, req.body, auth.disableSignUp);
        if (result.status !== 200 || !result.userId) {
          res.status(result.status).json(result.body);
          return;
        }

        const session = await createSession(
          auth.db,
          result.userId,
          req.ip,
          req.headers["user-agent"] ?? undefined,
        );

        const expires = new Date(Date.now() + SESSION_TTL_MS);
        res.setHeader("Set-Cookie", buildSetCookieHeader(session.token, { secure: auth.useSecureCookies, expires }));
        res.status(200).json({ ...result.body as object, token: session.token });
        return;
      }

      // POST /api/auth/sign-in/email
      if (method === "POST" && path.startsWith("/sign-in/email")) {
        const result = await handleSignIn(auth.db, req.body);
        if (result.status !== 200 || !result.userId) {
          res.status(result.status).json(result.body);
          return;
        }

        const session = await createSession(
          auth.db,
          result.userId,
          req.ip,
          req.headers["user-agent"] ?? undefined,
        );

        const expires = new Date(Date.now() + SESSION_TTL_MS);
        res.setHeader("Set-Cookie", buildSetCookieHeader(session.token, { secure: auth.useSecureCookies, expires }));
        res.status(200).json({ ...result.body as object, token: session.token });
        return;
      }

      // POST /api/auth/sign-out
      if (method === "POST" && path.startsWith("/sign-out")) {
        const token = extractSessionToken(req.headers);
        if (token) {
          await deleteSession(auth.db, token);
        }
        res.setHeader("Set-Cookie", buildClearCookieHeader({ secure: auth.useSecureCookies }));
        res.status(200).json({ success: true });
        return;
      }

      // GET /api/auth/get-session
      if (method === "GET" && path.startsWith("/get-session")) {
        const token = extractSessionToken(req.headers);
        if (!token) {
          res.status(401).json({ error: "Unauthorized" });
          return;
        }

        const sessionResult = await resolveSessionFromToken(auth.db, token);
        if (!sessionResult?.session || !sessionResult.user) {
          res.status(401).json({ error: "Unauthorized" });
          return;
        }

        res.status(200).json(sessionResult);
        return;
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}

function headersToNodeHeaders(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

export async function resolveBetterAuthSessionFromHeaders(
  auth: BetterAuthInstance,
  headers: Headers,
): Promise<BetterAuthSessionResult | null> {
  const token = extractSessionToken(headers);
  if (!token) return null;
  return resolveSessionFromToken(auth.db, token);
}

export async function resolveBetterAuthSession(
  auth: BetterAuthInstance,
  req: Request,
): Promise<BetterAuthSessionResult | null> {
  const token = extractSessionToken(req.headers);
  if (!token) return null;
  return resolveSessionFromToken(auth.db, token);
}
