import {
  generateIdentity,
  generateOneTimePreKeys,
  generateSignedPreKey,
  type Identity,
  type OneTimePreKey,
  type PreKeyBundle,
  type PreKeyStore,
  type SignedPreKey,
} from "../src/index.ts";

export interface TestUser {
  identity: Identity;
  signedPreKeys: Map<number, SignedPreKey>;
  oneTimePreKeys: Map<number, OneTimePreKey>;
  store: PreKeyStore;
  bundle(options?: { oneTime?: boolean }): PreKeyBundle;
}

export function makeUser(): TestUser {
  const identity = generateIdentity();
  const spk = generateSignedPreKey(identity, 1);
  const signedPreKeys = new Map([[spk.id, spk]]);
  const oneTimePreKeys = new Map(generateOneTimePreKeys(100, 5).map((k) => [k.id, k]));
  let currentSpk = spk;

  return {
    identity,
    signedPreKeys,
    oneTimePreKeys,
    store: {
      identity,
      signedPreKey: (id) => signedPreKeys.get(id),
      oneTimePreKey: (id) => oneTimePreKeys.get(id),
    },
    bundle({ oneTime = true } = {}) {
      const bundle: PreKeyBundle = {
        signingKey: identity.signing.publicKey,
        identityKey: identity.dh.publicKey,
        identityKeySignature: identity.dhSignature,
        signedPreKey: {
          id: currentSpk.id,
          publicKey: currentSpk.keyPair.publicKey,
          signature: currentSpk.signature,
        },
      };
      if (oneTime) {
        const [first] = oneTimePreKeys.values();
        if (first) bundle.oneTimePreKey = { id: first.id, publicKey: first.keyPair.publicKey };
      }
      return bundle;
    },
  };
}
