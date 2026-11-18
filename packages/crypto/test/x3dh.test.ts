import { describe, expect, it } from "vitest";
import { equal, x3dhInitiate, x3dhRespond, verifyBundle, CryptoError } from "../src/index.ts";
import { makeUser } from "./helpers.ts";

describe("X3DH", () => {
  it.each([true, false])("derives the same secret on both sides (one-time pre-key: %s)", (oneTime) => {
    const alice = makeUser();
    const bob = makeUser();
    const bundle = bob.bundle({ oneTime });
    const init = x3dhInitiate(alice.identity, bundle);

    const opk = init.header.oneTimePreKeyId === undefined
      ? undefined
      : bob.oneTimePreKeys.get(init.header.oneTimePreKeyId);
    const resp = x3dhRespond(bob.identity, init.header, bob.signedPreKeys.get(1)!, opk);

    expect(equal(init.sharedKey, resp.sharedKey)).toBe(true);
    expect(equal(init.associatedData, resp.associatedData)).toBe(true);
    expect(init.header.oneTimePreKeyId !== undefined).toBe(oneTime);
  });

  it("produces a different secret for every initiation", () => {
    const alice = makeUser();
    const bob = makeUser();
    const a = x3dhInitiate(alice.identity, bob.bundle());
    const b = x3dhInitiate(alice.identity, bob.bundle());
    expect(equal(a.sharedKey, b.sharedKey)).toBe(false);
  });

  it("rejects a bundle whose signed pre-key was swapped by the server", () => {
    const bob = makeUser();
    const mallory = makeUser();
    const bundle = bob.bundle();
    bundle.signedPreKey = mallory.bundle().signedPreKey;
    expect(() => verifyBundle(bundle)).toThrow(CryptoError);
    expect(() => x3dhInitiate(makeUser().identity, bundle)).toThrow(/signed pre-key/);
  });

  it("rejects a bundle whose identity key was swapped", () => {
    const bundle = makeUser().bundle();
    bundle.identityKey = makeUser().identity.dh.publicKey;
    expect(() => verifyBundle(bundle)).toThrow(/identity key/);
  });

  it("rejects a signed pre-key re-labelled with a different id", () => {
    const bundle = makeUser().bundle();
    bundle.signedPreKey = { ...bundle.signedPreKey, id: 2 };
    expect(() => verifyBundle(bundle)).toThrow(CryptoError);
  });

  it("rejects small-order (all-zero) keys", () => {
    const bundle = makeUser().bundle();
    bundle.signingKey = new Uint8Array(32);
    bundle.identityKeySignature = new Uint8Array(64);
    expect(() => verifyBundle(bundle)).toThrow(CryptoError);
  });

  it("responder rejects mismatched one-time pre-key usage", () => {
    const alice = makeUser();
    const bob = makeUser();
    const init = x3dhInitiate(alice.identity, bob.bundle({ oneTime: true }));
    expect(() => x3dhRespond(bob.identity, init.header, bob.signedPreKeys.get(1)!, undefined)).toThrow(
      /one-time/,
    );
  });
});
