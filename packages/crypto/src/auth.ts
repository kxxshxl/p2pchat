/**
 * Password-less authentication: an account *is* its Ed25519 signing key. The server issues a
 * single-use random challenge and the client signs a domain-separated statement over it.
 */

import { utf8 } from "./bytes.ts";
import { sign, verify, type KeyPair } from "./primitives.ts";

export type AuthPurpose = "register" | "login";

export function authStatement(purpose: AuthPurpose, handle: string, challenge: string): Uint8Array {
  // newline-separated; handle and challenge are validated server-side to contain no newlines
  return utf8(`Parley/auth/v1\n${purpose}\n${handle}\n${challenge}`);
}

export function signChallenge(
  signing: KeyPair,
  purpose: AuthPurpose,
  handle: string,
  challenge: string,
): Uint8Array {
  return sign(signing.privateKey, authStatement(purpose, handle, challenge));
}

export function verifyChallenge(
  signingKey: Uint8Array,
  purpose: AuthPurpose,
  handle: string,
  challenge: string,
  signature: Uint8Array,
): boolean {
  return verify(signingKey, authStatement(purpose, handle, challenge), signature);
}
