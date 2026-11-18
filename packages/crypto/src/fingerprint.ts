/**
 * Safety numbers: a 60-digit code two people compare out of band (in person, on a call) to
 * prove no one substituted keys in transit. Each side contributes 30 digits derived from an
 * iterated hash of its public keys; the halves are sorted so both people see the same number.
 */

import { concat, toHex, u32be, utf8 } from "./bytes.ts";
import { sha256, sha512 } from "./primitives.ts";

const VERSION = utf8("Parley/fingerprint/v1");
const ITERATIONS = 5200;

export interface FingerprintSubject {
  userId: string;
  signingKey: Uint8Array;
  identityKey: Uint8Array;
}

function fingerprintDigits(subject: FingerprintSubject): string {
  const keys = concat(subject.signingKey, subject.identityKey);
  let hash = sha512(concat(VERSION, u32be(utf8(subject.userId).length), utf8(subject.userId), keys));
  for (let i = 0; i < ITERATIONS; i++) hash = sha512(concat(hash, keys));

  let digits = "";
  for (let chunk = 0; chunk < 6; chunk++) {
    let value = 0;
    for (let j = 0; j < 5; j++) value = value * 256 + hash[chunk * 5 + j]!;
    digits += String(value % 100000).padStart(5, "0");
  }
  return digits;
}

/** 60 digits, identical on both sides of the conversation. */
export function safetyNumber(a: FingerprintSubject, b: FingerprintSubject): string {
  return [fingerprintDigits(a), fingerprintDigits(b)].sort().join("");
}

/** "12345 67890 …" — 12 groups of 5 for display. */
export function formatSafetyNumber(digits: string): string[] {
  return digits.match(/.{1,5}/g) ?? [];
}

/** Short, human-friendly identifier for a public key (e.g. in the protocol inspector). */
export function keyId(publicKey: Uint8Array): string {
  return toHex(sha256(publicKey).slice(0, 8)).match(/.{4}/g)!.join(" ");
}
