/**
 * Challenge/response authentication. There are no passwords: the account is the Ed25519
 * signing key generated in the browser, and every sign-in is a fresh signature.
 */

import {
  fromBase64,
  verifyChallenge,
  verifyPublicIdentity,
  verifySignedPreKey,
  type AuthPurpose,
} from "@parley/crypto";
import type { FastifyInstance } from "fastify";
import { currentUser, rateLimit, requireAuth, type AppContext } from "../context.ts";
import {
  BASE64_32,
  BASE64_64,
  HANDLE_PATTERN,
  HttpError,
  cleanDisplayName,
  oneTimePreKeysSchema,
  publicUser,
  signedPreKeySchema,
} from "../http.ts";

const CHALLENGE_TTL_MS = 2 * 60 * 1000;
const CHALLENGE_PATTERN = "^[A-Za-z0-9_-]{43}$";

interface ChallengeBody {
  purpose: AuthPurpose;
  handle: string;
}

interface RegisterBody {
  handle: string;
  displayName: string;
  challenge: string;
  signature: string;
  signingKey: string;
  identityKey: string;
  identityKeySignature: string;
  signedPreKey: { id: number; publicKey: string; signature: string };
  oneTimePreKeys: { id: number; publicKey: string }[];
}

interface LoginBody {
  handle: string;
  challenge: string;
  signature: string;
}

export function authRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store, config } = ctx;

  app.post<{ Body: ChallengeBody }>(
    "/api/auth/challenge",
    {
      schema: {
        body: {
          type: "object",
          required: ["purpose", "handle"],
          additionalProperties: false,
          properties: {
            purpose: { enum: ["register", "login"] },
            handle: { type: "string", pattern: HANDLE_PATTERN },
          },
        },
      },
    },
    async (request) => {
      rateLimit(ctx.limits.auth, request.ip);
      const { purpose, handle } = request.body;
      if (purpose === "register" && store.userByHandle(handle)) {
        throw new HttpError(409, "handle_taken", "That handle is already taken");
      }
      // Login challenges are issued for unknown handles too; the login itself fails later.
      return {
        challenge: store.createChallenge(purpose, handle, CHALLENGE_TTL_MS),
        expiresInMs: CHALLENGE_TTL_MS,
      };
    },
  );

  app.post<{ Body: RegisterBody }>(
    "/api/auth/register",
    {
      schema: {
        body: {
          type: "object",
          required: [
            "handle",
            "displayName",
            "challenge",
            "signature",
            "signingKey",
            "identityKey",
            "identityKeySignature",
            "signedPreKey",
            "oneTimePreKeys",
          ],
          additionalProperties: false,
          properties: {
            handle: { type: "string", pattern: HANDLE_PATTERN },
            displayName: { type: "string", minLength: 1, maxLength: 64 },
            challenge: { type: "string", pattern: CHALLENGE_PATTERN },
            signature: { type: "string", pattern: BASE64_64 },
            signingKey: { type: "string", pattern: BASE64_32 },
            identityKey: { type: "string", pattern: BASE64_32 },
            identityKeySignature: { type: "string", pattern: BASE64_64 },
            signedPreKey: signedPreKeySchema,
            oneTimePreKeys: oneTimePreKeysSchema,
          },
        },
      },
    },
    async (request, reply) => {
      rateLimit(ctx.limits.auth, request.ip);
      const body = request.body;
      const displayName = cleanDisplayName(body.displayName);

      if (!store.consumeChallenge(body.challenge, "register", body.handle)) {
        throw new HttpError(401, "invalid_challenge", "Challenge expired or invalid, try again");
      }
      const signingKey = fromBase64(body.signingKey);
      if (!verifyChallenge(signingKey, "register", body.handle, body.challenge, fromBase64(body.signature))) {
        throw new HttpError(401, "invalid_signature", "Signature does not match the signing key");
      }
      try {
        verifyPublicIdentity({
          signingKey,
          identityKey: fromBase64(body.identityKey),
          identityKeySignature: fromBase64(body.identityKeySignature),
        });
        verifySignedPreKey(signingKey, {
          id: body.signedPreKey.id,
          publicKey: fromBase64(body.signedPreKey.publicKey),
          signature: fromBase64(body.signedPreKey.signature),
        });
      } catch (err) {
        throw new HttpError(400, "invalid_keys", (err as Error).message);
      }
      if (store.handleTaken(body.handle, body.signingKey)) {
        throw new HttpError(409, "handle_taken", "That handle is already taken");
      }

      const user = store.createUser({
        handle: body.handle,
        displayName,
        signingKey: body.signingKey,
        identityKey: body.identityKey,
        identityKeySignature: body.identityKeySignature,
        signedPreKey: { ...body.signedPreKey, createdAt: Date.now() },
        oneTimePreKeys: body.oneTimePreKeys,
      });
      reply.code(201);
      return { token: store.createSession(user.id, config.sessionTtlMs), user: publicUser(user) };
    },
  );

  app.post<{ Body: LoginBody }>(
    "/api/auth/login",
    {
      schema: {
        body: {
          type: "object",
          required: ["handle", "challenge", "signature"],
          additionalProperties: false,
          properties: {
            handle: { type: "string", pattern: HANDLE_PATTERN },
            challenge: { type: "string", pattern: CHALLENGE_PATTERN },
            signature: { type: "string", pattern: BASE64_64 },
          },
        },
      },
    },
    async (request) => {
      rateLimit(ctx.limits.auth, request.ip);
      const { handle, challenge, signature } = request.body;
      const validChallenge = store.consumeChallenge(challenge, "login", handle);
      const user = store.userByHandle(handle);
      const ok =
        validChallenge &&
        !!user &&
        verifyChallenge(fromBase64(user.signingKey), "login", handle, challenge, fromBase64(signature));
      if (!ok || !user) throw new HttpError(401, "invalid_login", "Sign-in failed");
      return { token: store.createSession(user.id, config.sessionTtlMs), user: publicUser(user) };
    },
  );

  app.post("/api/auth/logout", { preHandler: requireAuth(ctx) }, async (request, reply) => {
    store.deleteSession(request.token!);
    ctx.relay.disconnect(currentUser(request).id, "signed out");
    reply.code(204);
  });

  app.get("/api/me", { preHandler: requireAuth(ctx) }, async (request) => publicUser(currentUser(request)));
}
