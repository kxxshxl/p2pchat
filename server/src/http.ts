/** Shared HTTP helpers: errors, validation patterns and response shapes. */

import type { UserRow } from "./store.ts";

export class HttpError extends Error {
  readonly statusCode: number;
  readonly code: string;
  constructor(statusCode: number, code: string, message: string) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

export const HANDLE_PATTERN = "^[a-z0-9_]{3,24}$";
export const BASE64_32 = "^[A-Za-z0-9+/]{43}=$";
export const BASE64_64 = "^[A-Za-z0-9+/]{86}==$";
export const KEY_ID = { type: "integer", minimum: 0, maximum: 4294967295 } as const;

export const signedPreKeySchema = {
  type: "object",
  required: ["id", "publicKey", "signature"],
  additionalProperties: false,
  properties: {
    id: KEY_ID,
    publicKey: { type: "string", pattern: BASE64_32 },
    signature: { type: "string", pattern: BASE64_64 },
  },
} as const;

export const oneTimePreKeysSchema = {
  type: "array",
  maxItems: 100,
  items: {
    type: "object",
    required: ["id", "publicKey"],
    additionalProperties: false,
    properties: {
      id: KEY_ID,
      publicKey: { type: "string", pattern: BASE64_32 },
    },
  },
} as const;

/** Display names: printable, no control or bidi-override characters. */
export function cleanDisplayName(name: string): string {
  const cleaned = name.normalize("NFC").replace(/[\p{Cc}\p{Cf}]/gu, "").trim();
  if (cleaned.length < 1 || cleaned.length > 40) {
    throw new HttpError(400, "invalid_display_name", "Display name must be 1–40 characters");
  }
  return cleaned;
}

export function publicUser(user: UserRow) {
  return { id: user.id, handle: user.handle, displayName: user.displayName };
}

export function userIdentity(user: UserRow) {
  return {
    ...publicUser(user),
    signingKey: user.signingKey,
    identityKey: user.identityKey,
    identityKeySignature: user.identityKeySignature,
  };
}
