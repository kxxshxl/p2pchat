import {
  bundleFromWire,
  generateIdentity,
  generateSignedPreKey,
  signChallenge,
  signedPreKeyToWire,
  toBase64,
  verifyBundle,
} from "@parley/crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api, register, startServer, type Server } from "./helpers.ts";

let server: Server;

beforeEach(async () => {
  server = await startServer();
});

afterEach(async () => {
  await server.app.close();
});

async function loginChallenge(handle: string) {
  const res = await api(server, "POST", "/api/auth/challenge", { purpose: "login", handle });
  return res.body.challenge as string;
}

describe("registration", () => {
  it("registers with a signed challenge and returns a working session", async () => {
    const alice = await register(server, "alice");
    const me = await api(server, "GET", "/api/me", undefined, alice.token);
    expect(me.status).toBe(200);
    expect(me.body).toMatchObject({ handle: "alice", displayName: "ALICE" });
  });

  it("rejects a taken handle", async () => {
    await register(server, "alice");
    const res = await api(server, "POST", "/api/auth/challenge", { purpose: "register", handle: "alice" });
    expect(res.status).toBe(409);
  });

  it("rejects invalid handles", async () => {
    for (const handle of ["ab", "Alice", "a b", "x".repeat(25)]) {
      const res = await api(server, "POST", "/api/auth/challenge", { purpose: "register", handle });
      expect(res.status).toBe(400);
    }
  });

  it("rejects a registration signed by a different key", async () => {
    const identity = generateIdentity();
    const other = generateIdentity();
    const { body } = await api(server, "POST", "/api/auth/challenge", { purpose: "register", handle: "eve" });
    const res = await api(server, "POST", "/api/auth/register", {
      handle: "eve",
      displayName: "Eve",
      challenge: body.challenge,
      signature: toBase64(signChallenge(other.signing, "register", "eve", body.challenge)),
      signingKey: toBase64(identity.signing.publicKey),
      identityKey: toBase64(identity.dh.publicKey),
      identityKeySignature: toBase64(identity.dhSignature),
      signedPreKey: signedPreKeyToWire(generateSignedPreKey(identity, 1)),
      oneTimePreKeys: [],
    });
    expect(res.status).toBe(401);
  });

  it("rejects a signed pre-key not signed by the identity", async () => {
    const identity = generateIdentity();
    const { body } = await api(server, "POST", "/api/auth/challenge", { purpose: "register", handle: "eve" });
    const res = await api(server, "POST", "/api/auth/register", {
      handle: "eve",
      displayName: "Eve",
      challenge: body.challenge,
      signature: toBase64(signChallenge(identity.signing, "register", "eve", body.challenge)),
      signingKey: toBase64(identity.signing.publicKey),
      identityKey: toBase64(identity.dh.publicKey),
      identityKeySignature: toBase64(identity.dhSignature),
      signedPreKey: signedPreKeyToWire(generateSignedPreKey(generateIdentity(), 1)),
      oneTimePreKeys: [],
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_keys");
  });

  it("strips control and bidi characters from display names", async () => {
    const identity = generateIdentity();
    const { body } = await api(server, "POST", "/api/auth/challenge", { purpose: "register", handle: "zed" });
    const res = await api(server, "POST", "/api/auth/register", {
      handle: "zed",
      displayName: "Z‮ed\u0007",
      challenge: body.challenge,
      signature: toBase64(signChallenge(identity.signing, "register", "zed", body.challenge)),
      signingKey: toBase64(identity.signing.publicKey),
      identityKey: toBase64(identity.dh.publicKey),
      identityKeySignature: toBase64(identity.dhSignature),
      signedPreKey: signedPreKeyToWire(generateSignedPreKey(identity, 1)),
      oneTimePreKeys: [],
    });
    expect(res.status).toBe(201);
    expect(res.body.user.displayName).toBe("Zed");
  });
});

describe("login", () => {
  it("signs in with a fresh challenge signature", async () => {
    const alice = await register(server, "alice");
    const challenge = await loginChallenge("alice");
    const res = await api(server, "POST", "/api/auth/login", {
      handle: "alice",
      challenge,
      signature: toBase64(signChallenge(alice.identity.signing, "login", "alice", challenge)),
    });
    expect(res.status).toBe(200);
    expect(res.body.user.id).toBe(alice.id);
  });

  it("rejects a replayed challenge", async () => {
    const alice = await register(server, "alice");
    const challenge = await loginChallenge("alice");
    const payload = {
      handle: "alice",
      challenge,
      signature: toBase64(signChallenge(alice.identity.signing, "login", "alice", challenge)),
    };
    expect((await api(server, "POST", "/api/auth/login", payload)).status).toBe(200);
    expect((await api(server, "POST", "/api/auth/login", payload)).status).toBe(401);
  });

  it("rejects a challenge issued for another handle", async () => {
    const alice = await register(server, "alice");
    await register(server, "bob");
    const challenge = await loginChallenge("bob");
    const res = await api(server, "POST", "/api/auth/login", {
      handle: "alice",
      challenge,
      signature: toBase64(signChallenge(alice.identity.signing, "login", "alice", challenge)),
    });
    expect(res.status).toBe(401);
  });

  it("rejects the wrong key", async () => {
    await register(server, "alice");
    const challenge = await loginChallenge("alice");
    const res = await api(server, "POST", "/api/auth/login", {
      handle: "alice",
      challenge,
      signature: toBase64(signChallenge(generateIdentity().signing, "login", "alice", challenge)),
    });
    expect(res.status).toBe(401);
  });

  it("logout revokes the token", async () => {
    const alice = await register(server, "alice");
    expect((await api(server, "POST", "/api/auth/logout", undefined, alice.token)).status).toBe(204);
    expect((await api(server, "GET", "/api/me", undefined, alice.token)).status).toBe(401);
  });

  it("rate limits authentication attempts", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 25; i++) {
      statuses.push((await api(server, "POST", "/api/auth/challenge", { purpose: "login", handle: "nobody" })).status);
    }
    expect(statuses).toContain(429);
  });
});

describe("key directory", () => {
  it("hands out verifiable bundles and consumes each one-time pre-key once", async () => {
    const alice = await register(server, "alice");
    const bob = await register(server, "bob", 3);
    const ids: (number | null)[] = [];
    for (let i = 0; i < 4; i++) {
      const res = await api(server, "GET", `/api/users/${bob.id}/bundle`, undefined, alice.token);
      expect(res.status).toBe(200);
      verifyBundle(bundleFromWire(res.body));
      ids.push(res.body.oneTimePreKey?.id ?? null);
    }
    expect(ids).toEqual([1, 2, 3, null]); // falls back to signed pre-key only when exhausted
    const status = await api(server, "GET", "/api/keys", undefined, bob.token);
    expect(status.body.oneTimePreKeys).toBe(0);
  });

  it("lets users replenish one-time pre-keys and rotate the signed pre-key", async () => {
    const bob = await register(server, "bob", 0);
    const add = await api(
      server,
      "POST",
      "/api/keys/one-time",
      { preKeys: [{ id: 50, publicKey: toBase64(generateIdentity().dh.publicKey) }] },
      bob.token,
    );
    expect(add.body).toEqual({ added: 1, total: 1 });

    const rotated = signedPreKeyToWire(generateSignedPreKey(bob.identity, 2));
    expect((await api(server, "PUT", "/api/keys/signed", { signedPreKey: rotated }, bob.token)).status).toBe(200);
    const forged = signedPreKeyToWire(generateSignedPreKey(generateIdentity(), 3));
    expect((await api(server, "PUT", "/api/keys/signed", { signedPreKey: forged }, bob.token)).status).toBe(400);

    const alice = await register(server, "alice");
    const bundle = await api(server, "GET", `/api/users/${bob.id}/bundle`, undefined, alice.token);
    expect(bundle.body.signedPreKey.id).toBe(2);
  });

  it("searches users by handle prefix, excluding yourself", async () => {
    const alice = await register(server, "alice");
    await register(server, "alfred");
    await register(server, "bob");
    const res = await api(server, "GET", "/api/users?q=al", undefined, alice.token);
    expect(res.body.map((u: { handle: string }) => u.handle)).toEqual(["alfred"]);
    expect(res.body[0]).not.toHaveProperty("signingKey");
  });

  it("treats LIKE wildcards literally", async () => {
    const alice = await register(server, "alice");
    await register(server, "bob");
    const res = await api(server, "GET", "/api/users?q=_", undefined, alice.token);
    expect(res.body).toEqual([]);
  });

  it("requires authentication", async () => {
    expect((await api(server, "GET", "/api/users?q=a")).status).toBe(401);
    expect((await api(server, "GET", "/api/keys", undefined, "nonsense")).status).toBe(401);
  });

  it("sets security headers", async () => {
    const res = await server.app.inject({ method: "GET", url: "/api/health" });
    expect(res.headers["content-security-policy"]).toContain("frame-ancestors 'none'");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
  });
});
