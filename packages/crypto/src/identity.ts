/**
 * Long-term identity keys and pre-keys.
 *
 * Every account owns two long-term keys:
 *   - an Ed25519 *signing* key — it authenticates the account (challenge/response login)
 *     and signs every public key the account publishes;
 *   - an X25519 *identity* key — the long-term Diffie-Hellman key used in X3DH.
 * The X25519 key is signed by the Ed25519 key so the pair can't be split by a malicious server.
 */

import { concat, fromBase64Exact, toBase64, u32be, utf8 } from "./bytes.ts";
import {
  CryptoError,
  KEY_LEN,
  SIG_LEN,
  generateDhKeyPair,
  generateSigningKeyPair,
  sign,
  verify,
  type KeyPair,
} from "./primitives.ts";

const IDENTITY_DH_CONTEXT = utf8("Parley/identity-dh/v1");
const SIGNED_PREKEY_CONTEXT = utf8("Parley/signed-prekey/v1");

export interface Identity {
  signing: KeyPair;
  dh: KeyPair;
  dhSignature: Uint8Array;
}

/** The public half of an identity, as other people see it. */
export interface PublicIdentity {
  signingKey: Uint8Array;
  identityKey: Uint8Array;
  identityKeySignature: Uint8Array;
}

export interface SignedPreKey {
  id: number;
  keyPair: KeyPair;
  signature: Uint8Array;
  createdAt: number;
}

export interface OneTimePreKey {
  id: number;
  keyPair: KeyPair;
}

export interface PreKeyBundle extends PublicIdentity {
  signedPreKey: { id: number; publicKey: Uint8Array; signature: Uint8Array };
  oneTimePreKey?: { id: number; publicKey: Uint8Array };
}

// ---------------------------------------------------------------- generation

export function generateIdentity(): Identity {
  const signing = generateSigningKeyPair();
  const dhPair = generateDhKeyPair();
  return {
    signing,
    dh: dhPair,
    dhSignature: sign(signing.privateKey, concat(IDENTITY_DH_CONTEXT, dhPair.publicKey)),
  };
}

export function publicIdentity(identity: Identity): PublicIdentity {
  return {
    signingKey: identity.signing.publicKey,
    identityKey: identity.dh.publicKey,
    identityKeySignature: identity.dhSignature,
  };
}

function signedPreKeyMessage(id: number, publicKey: Uint8Array): Uint8Array {
  return concat(SIGNED_PREKEY_CONTEXT, u32be(id), publicKey);
}

export function generateSignedPreKey(identity: Identity, id: number, now = Date.now()): SignedPreKey {
  const keyPair = generateDhKeyPair();
  return {
    id,
    keyPair,
    signature: sign(identity.signing.privateKey, signedPreKeyMessage(id, keyPair.publicKey)),
    createdAt: now,
  };
}

export function generateOneTimePreKeys(startId: number, count: number): OneTimePreKey[] {
  return Array.from({ length: count }, (_, i) => ({
    id: (startId + i) >>> 0,
    keyPair: generateDhKeyPair(),
  }));
}

// ---------------------------------------------------------------- verification

export function verifyPublicIdentity(identity: PublicIdentity): void {
  const ok = verify(
    identity.signingKey,
    concat(IDENTITY_DH_CONTEXT, identity.identityKey),
    identity.identityKeySignature,
  );
  if (!ok) throw new CryptoError("identity key is not signed by the account's signing key");
}

export function verifySignedPreKey(
  signingKey: Uint8Array,
  preKey: { id: number; publicKey: Uint8Array; signature: Uint8Array },
): void {
  if (!verify(signingKey, signedPreKeyMessage(preKey.id, preKey.publicKey), preKey.signature)) {
    throw new CryptoError("signed pre-key signature is invalid");
  }
}

/** Checks every signature in a bundle. Clients must never trust the directory server. */
export function verifyBundle(bundle: PreKeyBundle): void {
  verifyPublicIdentity(bundle);
  verifySignedPreKey(bundle.signingKey, bundle.signedPreKey);
}

// ---------------------------------------------------------------- wire format (JSON / base64)

export interface PublicIdentityWire {
  signingKey: string;
  identityKey: string;
  identityKeySignature: string;
}

export interface SignedPreKeyWire {
  id: number;
  publicKey: string;
  signature: string;
}

export interface OneTimePreKeyWire {
  id: number;
  publicKey: string;
}

export interface PreKeyBundleWire extends PublicIdentityWire {
  signedPreKey: SignedPreKeyWire;
  oneTimePreKey?: OneTimePreKeyWire | null;
}

function keyId(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new CryptoError(`${label}: invalid key id`);
  }
  return value;
}

export function publicIdentityToWire(identity: PublicIdentity): PublicIdentityWire {
  return {
    signingKey: toBase64(identity.signingKey),
    identityKey: toBase64(identity.identityKey),
    identityKeySignature: toBase64(identity.identityKeySignature),
  };
}

export function publicIdentityFromWire(wire: PublicIdentityWire): PublicIdentity {
  return {
    signingKey: fromBase64Exact(wire.signingKey, KEY_LEN, "signingKey"),
    identityKey: fromBase64Exact(wire.identityKey, KEY_LEN, "identityKey"),
    identityKeySignature: fromBase64Exact(wire.identityKeySignature, SIG_LEN, "identityKeySignature"),
  };
}

export function signedPreKeyToWire(spk: SignedPreKey): SignedPreKeyWire {
  return { id: spk.id, publicKey: toBase64(spk.keyPair.publicKey), signature: toBase64(spk.signature) };
}

export function signedPreKeyFromWire(wire: SignedPreKeyWire) {
  return {
    id: keyId(wire.id, "signedPreKey"),
    publicKey: fromBase64Exact(wire.publicKey, KEY_LEN, "signedPreKey.publicKey"),
    signature: fromBase64Exact(wire.signature, SIG_LEN, "signedPreKey.signature"),
  };
}

export function oneTimePreKeyToWire(opk: OneTimePreKey): OneTimePreKeyWire {
  return { id: opk.id, publicKey: toBase64(opk.keyPair.publicKey) };
}

export function oneTimePreKeyFromWire(wire: OneTimePreKeyWire) {
  return {
    id: keyId(wire.id, "oneTimePreKey"),
    publicKey: fromBase64Exact(wire.publicKey, KEY_LEN, "oneTimePreKey.publicKey"),
  };
}

export function bundleFromWire(wire: PreKeyBundleWire): PreKeyBundle {
  const bundle: PreKeyBundle = {
    ...publicIdentityFromWire(wire),
    signedPreKey: signedPreKeyFromWire(wire.signedPreKey),
  };
  if (wire.oneTimePreKey) bundle.oneTimePreKey = oneTimePreKeyFromWire(wire.oneTimePreKey);
  return bundle;
}

export function bundleToWire(bundle: PreKeyBundle): PreKeyBundleWire {
  return {
    signingKey: toBase64(bundle.signingKey),
    identityKey: toBase64(bundle.identityKey),
    identityKeySignature: toBase64(bundle.identityKeySignature),
    signedPreKey: {
      id: bundle.signedPreKey.id,
      publicKey: toBase64(bundle.signedPreKey.publicKey),
      signature: toBase64(bundle.signedPreKey.signature),
    },
    oneTimePreKey: bundle.oneTimePreKey
      ? { id: bundle.oneTimePreKey.id, publicKey: toBase64(bundle.oneTimePreKey.publicKey) }
      : null,
  };
}
