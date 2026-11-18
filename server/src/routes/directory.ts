/**
 * The key directory: user lookup, pre-key bundles and pre-key maintenance.
 * Clients verify every signature themselves; the server is not trusted with key authenticity,
 * which is why users compare safety numbers.
 */

import { fromBase64, verifySignedPreKey } from "@parley/crypto";
import type { FastifyInstance } from "fastify";
import { currentUser, rateLimit, requireAuth, type AppContext } from "../context.ts";
import {
  HANDLE_PATTERN,
  HttpError,
  oneTimePreKeysSchema,
  publicUser,
  signedPreKeySchema,
  userIdentity,
} from "../http.ts";

const LOW_PREKEY_THRESHOLD = 20;
const UUID_PATTERN = "^[0-9a-f-]{36}$";

export function directoryRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store, config, relay } = ctx;
  const auth = { preHandler: requireAuth(ctx) };

  app.get<{ Querystring: { q: string } }>(
    "/api/users",
    {
      ...auth,
      schema: {
        querystring: {
          type: "object",
          required: ["q"],
          properties: { q: { type: "string", minLength: 1, maxLength: 24, pattern: "^[a-z0-9_]+$" } },
        },
      },
    },
    async (request) => {
      const me = currentUser(request);
      rateLimit(ctx.limits.search, me.id);
      return store.searchUsers(request.query.q, me.id).map((u) => ({
        ...publicUser(u),
        online: relay.isOnline(u.id),
      }));
    },
  );

  app.get<{ Params: { handle: string } }>(
    "/api/users/by-handle/:handle",
    { ...auth, schema: { params: { type: "object", properties: { handle: { type: "string", pattern: HANDLE_PATTERN } } } } },
    async (request) => {
      const user = store.userByHandle(request.params.handle);
      if (!user) throw new HttpError(404, "not_found", "No user with that handle");
      return { ...userIdentity(user), online: relay.isOnline(user.id) };
    },
  );

  app.get<{ Params: { id: string } }>(
    "/api/users/:id",
    { ...auth, schema: { params: { type: "object", properties: { id: { type: "string", pattern: UUID_PATTERN } } } } },
    async (request) => {
      const user = store.userById(request.params.id);
      if (!user) throw new HttpError(404, "not_found", "User not found");
      return { ...userIdentity(user), online: relay.isOnline(user.id) };
    },
  );

  /** Hands out a pre-key bundle, consuming one one-time pre-key. */
  app.get<{ Params: { id: string } }>(
    "/api/users/:id/bundle",
    { ...auth, schema: { params: { type: "object", properties: { id: { type: "string", pattern: UUID_PATTERN } } } } },
    async (request) => {
      const me = currentUser(request);
      rateLimit(ctx.limits.bundles, me.id);
      const target = store.userById(request.params.id);
      if (!target) throw new HttpError(404, "not_found", "User not found");
      if (target.id === me.id) throw new HttpError(400, "self", "Cannot start a session with yourself");

      const signedPreKey = store.latestSignedPreKey(target.id);
      if (!signedPreKey) throw new HttpError(409, "no_prekeys", "User has not published keys");
      const oneTimePreKey = store.takeOneTimePreKey(target.id) ?? null;

      const remaining = store.countOneTimePreKeys(target.id);
      if (remaining < LOW_PREKEY_THRESHOLD) relay.notify(target.id, { t: "prekeys_low", remaining });

      return {
        userId: target.id,
        signingKey: target.signingKey,
        identityKey: target.identityKey,
        identityKeySignature: target.identityKeySignature,
        signedPreKey: { id: signedPreKey.id, publicKey: signedPreKey.publicKey, signature: signedPreKey.signature },
        oneTimePreKey,
      };
    },
  );

  app.get("/api/keys", auth, async (request) => {
    const me = currentUser(request);
    const spk = store.latestSignedPreKey(me.id);
    return {
      signedPreKey: spk ? { id: spk.id, createdAt: spk.createdAt } : null,
      oneTimePreKeys: store.countOneTimePreKeys(me.id),
      maxOneTimePreKeys: config.maxOneTimePreKeys,
    };
  });

  app.post<{ Body: { preKeys: { id: number; publicKey: string }[] } }>(
    "/api/keys/one-time",
    {
      ...auth,
      schema: {
        body: {
          type: "object",
          required: ["preKeys"],
          additionalProperties: false,
          properties: { preKeys: oneTimePreKeysSchema },
        },
      },
    },
    async (request) => {
      const me = currentUser(request);
      const current = store.countOneTimePreKeys(me.id);
      const room = Math.max(0, config.maxOneTimePreKeys - current);
      const added = store.addOneTimePreKeys(me.id, request.body.preKeys.slice(0, room));
      return { added, total: current + added };
    },
  );

  app.put<{ Body: { signedPreKey: { id: number; publicKey: string; signature: string } } }>(
    "/api/keys/signed",
    {
      ...auth,
      schema: {
        body: {
          type: "object",
          required: ["signedPreKey"],
          additionalProperties: false,
          properties: { signedPreKey: signedPreKeySchema },
        },
      },
    },
    async (request) => {
      const me = currentUser(request);
      const key = request.body.signedPreKey;
      try {
        verifySignedPreKey(fromBase64(me.signingKey), {
          id: key.id,
          publicKey: fromBase64(key.publicKey),
          signature: fromBase64(key.signature),
        });
      } catch {
        throw new HttpError(400, "invalid_keys", "Signed pre-key signature is invalid");
      }
      store.putSignedPreKey(me.id, { ...key, createdAt: Date.now() });
      return { ok: true };
    },
  );
}
