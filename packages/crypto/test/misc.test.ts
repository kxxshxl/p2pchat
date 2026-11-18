import { describe, expect, it } from "vitest";
import {
  formatSafetyNumber,
  fromBase64,
  generateIdentity,
  pad,
  randomBytes,
  safetyNumber,
  signChallenge,
  toBase64,
  unpad,
  verifyChallenge,
} from "../src/index.ts";

describe("base64", () => {
  it("matches Node's encoder for every length", () => {
    for (let n = 0; n < 40; n++) {
      const bytes = randomBytes(n);
      const expected = Buffer.from(bytes).toString("base64");
      expect(toBase64(bytes)).toBe(expected);
      expect(Buffer.from(fromBase64(expected)).equals(Buffer.from(bytes))).toBe(true);
    }
  });

  it("rejects invalid input", () => {
    expect(() => fromBase64("abc")).toThrow();
    expect(() => fromBase64("ab!d")).toThrow();
    expect(() => fromBase64("a=bc")).toThrow();
  });
});

describe("padding", () => {
  it("round-trips data of any length, including trailing zeros", () => {
    for (const n of [0, 1, 127, 128, 129, 500]) {
      const data = new Uint8Array(n);
      if (n > 2) data[0] = 7;
      const padded = pad(data);
      expect(padded.length % 128).toBe(0);
      expect(padded.length).toBeGreaterThan(n);
      expect(Array.from(unpad(padded))).toEqual(Array.from(data));
    }
  });

  it("rejects corrupt padding", () => {
    expect(() => unpad(new Uint8Array(16))).toThrow();
  });
});

describe("safety numbers", () => {
  const a = generateIdentity();
  const b = generateIdentity();
  const subjectA = { userId: "alice-id", signingKey: a.signing.publicKey, identityKey: a.dh.publicKey };
  const subjectB = { userId: "bob-id", signingKey: b.signing.publicKey, identityKey: b.dh.publicKey };

  it("is the same 60 digits on both sides", () => {
    const n1 = safetyNumber(subjectA, subjectB);
    expect(safetyNumber(subjectB, subjectA)).toBe(n1);
    expect(n1).toMatch(/^\d{60}$/);
    expect(formatSafetyNumber(n1)).toHaveLength(12);
  });

  it("changes when either key changes", () => {
    const swapped = { ...subjectB, identityKey: generateIdentity().dh.publicKey };
    expect(safetyNumber(subjectA, swapped)).not.toBe(safetyNumber(subjectA, subjectB));
  });
});

describe("challenge signatures", () => {
  const id = generateIdentity();

  it("verify only for the same purpose, handle and challenge", () => {
    const sig = signChallenge(id.signing, "login", "alice", "nonce-1");
    expect(verifyChallenge(id.signing.publicKey, "login", "alice", "nonce-1", sig)).toBe(true);
    expect(verifyChallenge(id.signing.publicKey, "register", "alice", "nonce-1", sig)).toBe(false);
    expect(verifyChallenge(id.signing.publicKey, "login", "mallory", "nonce-1", sig)).toBe(false);
    expect(verifyChallenge(id.signing.publicKey, "login", "alice", "nonce-2", sig)).toBe(false);
  });
});
