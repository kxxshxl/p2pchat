/**
 * Thin, opinionated wrappers over audited primitives (noble-curves / noble-hashes / noble-ciphers).
 * Everything above this file speaks in these functions only, so the primitive suite can be
 * swapped (e.g. for WebCrypto) in one place.
 */

import { gcm } from "@noble/ciphers/aes.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf as nobleHkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { randomBytes as nobleRandomBytes } from "@noble/hashes/utils.js";

export const KEY_LEN = 32;
export const SIG_LEN = 64;

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export class CryptoError extends Error {
  override name = "CryptoError";
}

export function randomBytes(length: number): Uint8Array {
  return nobleRandomBytes(length);
}

// ---------------------------------------------------------------- X25519

export function generateDhKeyPair(): KeyPair {
  const privateKey = x25519.utils.randomSecretKey();
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

/** X25519 with a contributory-behaviour check: an all-zero shared secret is rejected. */
export function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== KEY_LEN) throw new CryptoError("bad X25519 public key length");
  try {
    return x25519.getSharedSecret(privateKey, publicKey);
  } catch {
    // noble throws when the result is the all-zero point (low-order public key)
    throw new CryptoError("X25519 produced a degenerate shared secret");
  }
}

// ---------------------------------------------------------------- Ed25519

export function generateSigningKeyPair(): KeyPair {
  const { secretKey, publicKey } = ed25519.keygen();
  return { privateKey: secretKey, publicKey };
}

export function sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey);
}

/**
 * Strict RFC 8032 verification. ZIP-215 (noble's default) accepts small-order keys and the
 * all-zero signature for them, which would let an attacker "sign" anything with a junk identity.
 */
export function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== KEY_LEN || signature.length !== SIG_LEN) return false;
  try {
    if (ed25519.Point.fromBytes(publicKey).isSmallOrder()) return false;
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- hashing / KDFs

export function hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return nobleHkdf(sha256, ikm, salt, info, length);
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

export { sha256, sha512 };

// ---------------------------------------------------------------- AEAD

export const GCM_NONCE_LEN = 12;

export function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array {
  return gcm(key, nonce, associatedData).encrypt(plaintext);
}

export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array {
  try {
    return gcm(key, nonce, associatedData).decrypt(ciphertext);
  } catch {
    throw new CryptoError("message authentication failed");
  }
}
