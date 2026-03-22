// [PetraTerraform] Express replaced with PetraHTTP via PetraBridge
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import type { Db } from "@paperclipai/db";
import type { DeploymentExposure, DeploymentMode } from "@paperclipai/shared";
import type { StorageService } from "./storage/types.js";
import { httpLogger, errorHandler } from "./middleware/index.js";
import { actorMiddleware } from "./middleware/auth.js";
import { boardMutationGuard } from "./middleware/board-mutation-guard.js";
import { privateHostnameGuard, resolvePrivateHostnameAllowSet } from "./middleware/private-hostname-guard.js";
import { healthRoutes } from "./routes/health.js";
import { companyRoutes } from "./routes/companies.js";
import { agentRoutes } from "./routes/agents.js";
import { projectRoutes } from "./routes/projects.js";
import { issueRoutes } from "./routes/issues.js";
import { goalRoutes } from "./routes/goals.js";
import { approvalRoutes } from "./routes/approvals.js";
import { secretRoutes } from "./routes/secrets.js";
import { costRoutes } from "./routes/costs.js";
import { activityRoutes } from "./routes/activity.js";
import { dashboardRoutes } from "./routes/dashboard.js";
import { sidebarBadgeRoutes } from "./routes/sidebar-badges.js";
import { llmRoutes } from "./routes/llms.js";
import { assetRoutes } from "./routes/assets.js";
import { accessRoutes } from "./routes/access.js";
import { applyUiBranding } from "./ui-branding.js";
import type { BetterAuthSessionResult } from "./auth/better-auth.js";
import { createPetraApp, Router, type ExpressHandler } from "./petra-bridge.js";
import type { PetraRequest, PetraResponse } from "./petra-bridge.js";
import * as http from "node:http";

type UiMode = "none" | "static" | "vite-dev";

// ─── Connect-middleware adapter ───────────────────────────────────────────────
// Vite's dev middleware and express.static use the Connect interface:
// (req: IncomingMessage, res: ServerResponse, next: () => void)
// We bridge those into our ExpressHandler type.

type ConnectHandler = (
  req: http.IncomingMessage,
  res: http.ServerResponse,
  next: (err?: unknown) => void,
) => void;

function connectToExpress(handler: ConnectHandler): ExpressHandler {
  return (req, res, next) => {
    handler(req as http.IncomingMessage, res as http.ServerResponse, next);
  };
}

// ─── Static file serving ──────────────────────────────────────────────────────

function serveStatic(dir: string): ExpressHandler {
  // Minimal static file server (replaces express.static)
  return (req, res, next) => {
    if (req.method !== "GET" && req.method !== "HEAD") {
      next();
      return;
    }
    const urlPath = req.path ?? "/";
    const safePath = path.normalize(urlPath).replace(/^(\.\.[/\\])+/, "");
    const filePath = path.join(dir, safePath);

    // Try exact path, then path + /index.html
    const candidates = [filePath, path.join(filePath, "index.html")];
    for (const candidate of candidates) {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        const ext = path.extname(candidate).toLowerCase();
        const mimeMap: Record<string, string> = {
          ".html": "text/html; charset=utf-8",
          ".js": "application/javascript",
          ".mjs": "application/javascript",
          ".css": "text/css",
          ".json": "application/json",
          ".png": "image/png",
          ".jpg": "image/jpeg",
          ".jpeg": "image/jpeg",
          ".gif": "image/gif",
          ".svg": "image/svg+xml",
          ".ico": "image/x-icon",
          ".woff": "font/woff",
          ".woff2": "font/woff2",
          ".ttf": "font/ttf",
          ".webp": "image/webp",
          ".map": "application/json",
          ".txt": "text/plain",
          ".xml": "application/xml",
        };
        const contentType = mimeMap[ext] ?? "application/octet-stream";
        const content = fs.readFileSync(candidate);
        res.status(200);
        (res as http.ServerResponse).setHeader("Content-Type", contentType);
        (res as http.ServerResponse).end(content);
        return;
      }
    }
    next();
  };
}

// ─── createApp ────────────────────────────────────────────────────────────────

export async function createApp(
  db: Db,
  opts: {
    uiMode: UiMode;
    serverPort: number;
    storageService: StorageService;
    deploymentMode: DeploymentMode;
    deploymentExposure: DeploymentExposure;
    allowedHostnames: string[];
    bindHost: string;
    authReady: boolean;
    companyDeletionEnabled: boolean;
    betterAuthHandler?: ExpressHandler;
    resolveSession?: (req: PetraRequest) => Promise<BetterAuthSessionResult | null>;
  },
) {
  // [PetraTerraform] sovereign app — replaces express()
  const app = createPetraApp();

  // Body parsing is handled by PetraApp.requestListener (built-in JSON parser)
  // No need for express.json() middleware

  // HTTP request logger
  app.use(connectToExpress(httpLogger as unknown as ConnectHandler));

  const privateHostnameGateEnabled =
    opts.deploymentMode === "authenticated" && opts.deploymentExposure === "private";
  const privateHostnameAllowSet = resolvePrivateHostnameAllowSet({
    allowedHostnames: opts.allowedHostnames,
    bindHost: opts.bindHost,
  });

  app.use(
    privateHostnameGuard({
      enabled: privateHostnameGateEnabled,
      allowedHostnames: opts.allowedHostnames,
      bindHost: opts.bindHost,
    }) as unknown as ExpressHandler,
  );

  app.use(
    actorMiddleware(db, {
      deploymentMode: opts.deploymentMode,
      resolveSession: opts.resolveSession as any,
    }) as unknown as ExpressHandler,
  );

  app.get("/api/auth/get-session", (req, res) => {
    if (req.actor.type !== "board" || !req.actor.userId) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }
    res.json({
      session: {
        id: `paperclip:${req.actor.source}:${req.actor.userId}`,
        userId: req.actor.userId,
      },
      user: {
        id: req.actor.userId,
        email: null,
        name: req.actor.source === "local_implicit" ? "Local Board" : null,
      },
    });
  });

  if (opts.betterAuthHandler) {
    app.all("/api/auth/*", opts.betterAuthHandler);
  }

  app.use(llmRoutes(db) as unknown as ExpressHandler);

  // Mount API routes
  const api = Router();
  api.use(boardMutationGuard() as unknown as ExpressHandler);
  api.use(
    "/health",
    healthRoutes(db, {
      deploymentMode: opts.deploymentMode,
      deploymentExposure: opts.deploymentExposure,
      authReady: opts.authReady,
      companyDeletionEnabled: opts.companyDeletionEnabled,
    }) as unknown as ExpressHandler,
  );
  api.use("/companies", companyRoutes(db) as unknown as ExpressHandler);
  api.use(agentRoutes(db) as unknown as ExpressHandler);
  api.use(assetRoutes(db, opts.storageService) as unknown as ExpressHandler);
  api.use(projectRoutes(db) as unknown as ExpressHandler);
  api.use(issueRoutes(db, opts.storageService) as unknown as ExpressHandler);
  api.use(goalRoutes(db) as unknown as ExpressHandler);
  api.use(approvalRoutes(db) as unknown as ExpressHandler);
  api.use(secretRoutes(db) as unknown as ExpressHandler);
  api.use(costRoutes(db) as unknown as ExpressHandler);
  api.use(activityRoutes(db) as unknown as ExpressHandler);
  api.use(dashboardRoutes(db) as unknown as ExpressHandler);
  api.use(sidebarBadgeRoutes(db) as unknown as ExpressHandler);
  api.use(
    accessRoutes(db, {
      deploymentMode: opts.deploymentMode,
      deploymentExposure: opts.deploymentExposure,
      bindHost: opts.bindHost,
      allowedHostnames: opts.allowedHostnames,
    }) as unknown as ExpressHandler,
  );
  // Mount API sub-router at /api prefix
  app.use("/api", api);
  // Fallback for unmatched /api routes
  app.use("/api", (_req, res) => {
    res.status(404).json({ error: "API route not found" });
  });

  const __dirname = path.dirname(fileURLToPath(import.meta.url));

  if (opts.uiMode === "static") {
    const candidates = [
      path.resolve(__dirname, "../ui-dist"),
      path.resolve(__dirname, "../../ui/dist"),
    ];
    const uiDist = candidates.find((p) => fs.existsSync(path.join(p, "index.html")));
    if (uiDist) {
      const indexHtml = applyUiBranding(fs.readFileSync(path.join(uiDist, "index.html"), "utf-8"));
      // [PetraTerraform] sovereign static file serving (replaces express.static)
      app.use(serveStatic(uiDist));
      app.get("/*", (_req, res) => {
        res.status(200);
        (res as http.ServerResponse).setHeader("Content-Type", "text/html");
        (res as http.ServerResponse).end(indexHtml);
      });
    } else {
      console.warn("[paperclip] UI dist not found; running in API-only mode");
    }
  }

  if (opts.uiMode === "vite-dev") {
    const uiRoot = path.resolve(__dirname, "../../ui");
    const hmrPort = opts.serverPort + 10000;
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      root: uiRoot,
      appType: "spa",
      server: {
        middlewareMode: true,
        hmr: {
          host: opts.bindHost,
          port: hmrPort,
          clientPort: hmrPort,
        },
        allowedHosts: privateHostnameGateEnabled ? Array.from(privateHostnameAllowSet) : undefined,
      },
    });

    // vite.middlewares is a Connect-compatible handler
    app.use(connectToExpress(vite.middlewares as unknown as ConnectHandler));
    app.get("/*", async (req, res, next) => {
      try {
        const templatePath = path.resolve(uiRoot, "index.html");
        const template = fs.readFileSync(templatePath, "utf-8");
        const html = applyUiBranding(await vite.transformIndexHtml(req.originalUrl, template));
        res.status(200);
        (res as http.ServerResponse).setHeader("Content-Type", "text/html");
        (res as http.ServerResponse).end(html);
      } catch (err) {
        next(err);
      }
    });
  }

  // [PetraTerraform] error handler registered as 4-arg error middleware
  app.useError(errorHandler as unknown as import("./petra-bridge.js").ExpressErrorHandler);

  return app;
}
