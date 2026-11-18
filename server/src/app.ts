import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import fastifyStatic from "@fastify/static";
import fastifyWebsocket from "@fastify/websocket";
import Fastify, { type FastifyInstance } from "fastify";
import type { Config } from "./config.ts";
import { createLimits, type AppContext } from "./context.ts";
import { HttpError } from "./http.ts";
import { Relay } from "./relay.ts";
import { authRoutes } from "./routes/auth.ts";
import { directoryRoutes } from "./routes/directory.ts";
import { Store } from "./store.ts";

const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self' ws: wss:",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

export interface App {
  app: FastifyInstance;
  ctx: AppContext;
}

export async function buildApp(config: Config): Promise<App> {
  const app = Fastify({
    logger: config.logLevel === "silent" ? false : { level: config.logLevel },
    trustProxy: config.trustProxy,
    bodyLimit: 256 * 1024,
  });

  const store = new Store(config.databasePath);
  const relay = new Relay(store, config);
  const ctx: AppContext = { config, store, relay, limits: createLimits() };

  app.decorateRequest("user", null);
  app.decorateRequest("token", null);

  app.setErrorHandler((err: Error & { statusCode?: number; validation?: unknown }, request, reply) => {
    if (err instanceof HttpError) {
      return reply.code(err.statusCode).send({ error: err.code, message: err.message });
    }
    const status = err.statusCode ?? 500;
    if (status === 400 && err.validation) {
      return reply.code(400).send({ error: "validation", message: err.message });
    }
    if (status >= 500) request.log.error(err);
    return reply.code(status).send({ error: "error", message: status >= 500 ? "Internal error" : err.message });
  });

  app.addHook("onSend", async (_request, reply, payload) => {
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("Cross-Origin-Opener-Policy", "same-origin");
    reply.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    reply.header("Content-Security-Policy", CONTENT_SECURITY_POLICY);
    return payload;
  });

  await app.register(fastifyWebsocket, { options: { maxPayload: 128 * 1024 } });

  app.get("/api/health", async () => ({ ok: true, online: relay.onlineCount() }));
  app.get("/api/config", async () => ({ iceServers: config.iceServers }));
  app.get("/api/ws", { websocket: true }, (socket) => relay.accept(socket));
  authRoutes(app, ctx);
  directoryRoutes(app, ctx);

  const staticDir = config.staticDir ? resolve(config.staticDir) : null;
  if (staticDir && existsSync(join(staticDir, "index.html"))) {
    await app.register(fastifyStatic, { root: staticDir, wildcard: false });
    app.setNotFoundHandler((request, reply) => {
      if (request.method === "GET" && !request.url.startsWith("/api/")) {
        return reply.type("text/html").sendFile("index.html");
      }
      return reply.code(404).send({ error: "not_found", message: "Not found" });
    });
  } else {
    app.setNotFoundHandler((_request, reply) => reply.code(404).send({ error: "not_found", message: "Not found" }));
  }

  const cleanup = setInterval(() => store.purgeExpired(config.mailboxTtlMs), 10 * 60 * 1000);
  cleanup.unref();
  app.addHook("onClose", async () => {
    clearInterval(cleanup);
    relay.close();
    store.close();
  });

  return { app, ctx };
}
