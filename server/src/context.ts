import type { FastifyReply, FastifyRequest } from "fastify";
import type { Config } from "./config.ts";
import { HttpError } from "./http.ts";
import { RateLimiter } from "./rate-limit.ts";
import type { Relay } from "./relay.ts";
import type { Store, UserRow } from "./store.ts";

declare module "fastify" {
  interface FastifyRequest {
    user: UserRow | null;
    token: string | null;
  }
}

export interface AppContext {
  config: Config;
  store: Store;
  relay: Relay;
  limits: {
    auth: RateLimiter;
    bundles: RateLimiter;
    search: RateLimiter;
  };
}

export function createLimits(): AppContext["limits"] {
  return {
    auth: new RateLimiter(20, 20 / 60), // 20 per minute per IP
    // Every bundle fetch burns one of the target's one-time pre-keys, so throttle it hard.
    bundles: new RateLimiter(20, 10 / 60),
    search: new RateLimiter(30, 2),
  };
}

export function bearerToken(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  if (!header?.startsWith("Bearer ")) return null;
  return header.slice(7).trim() || null;
}

/** preHandler: requires a valid session token. */
export function requireAuth(ctx: AppContext) {
  return async (request: FastifyRequest, _reply: FastifyReply) => {
    const token = bearerToken(request);
    const user = token ? ctx.store.userForToken(token) : undefined;
    if (!token || !user) throw new HttpError(401, "unauthorized", "Sign in required");
    request.user = user;
    request.token = token;
  };
}

export function rateLimit(limiter: RateLimiter, key: string): void {
  if (!limiter.take(key)) throw new HttpError(429, "rate_limited", "Too many requests, slow down");
}

export function currentUser(request: FastifyRequest): UserRow {
  if (!request.user) throw new HttpError(401, "unauthorized", "Sign in required");
  return request.user;
}
