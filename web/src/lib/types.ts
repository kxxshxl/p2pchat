import type { EnvelopeWire } from "@parley/crypto";

export interface Account {
  userId: string;
  handle: string;
  displayName: string;
  createdAt: number;
}

export interface Contact {
  id: string;
  handle: string;
  displayName: string;
  /** Pinned on first contact (trust on first use); base64. */
  signingKey: string;
  identityKey: string;
  verified: boolean;
  /** Set when the peer's identity key no longer matches the pinned one; blocks sending until acknowledged. */
  keyChangedAt: number | null;
  addedAt: number;
  lastActivityAt: number;
  unread: number;
}

export type Transport = "p2p" | "relay";
export type MessageStatus = "pending" | "sent" | "delivered" | "read" | "failed";

/** Protocol details shown in the inspector. Never includes key material. */
export interface CryptoMeta {
  sessionId: string;
  ratchetKey: string;
  counter: number;
  previousCounter: number;
  preKey: boolean;
  ciphertextBytes: number;
  newSession?: boolean;
}

export interface ChatMessage {
  id: string;
  kind: "text" | "system";
  direction: "in" | "out";
  body: string;
  sentAt: number;
  receivedAt?: number;
  status?: MessageStatus;
  transport?: Transport;
  crypto?: CryptoMeta;
  /** Encrypted envelope waiting for a connection. */
  outbox?: EnvelopeWire;
  error?: string;
  /** For incoming messages: the strongest receipt we have sent back. */
  receipt?: "delivered" | "read";
}

/** What travels *inside* the encryption. The server never sees any of this. */
export type Payload =
  | { k: "text"; id: string; body: string; ts: number }
  | { k: "receipt"; status: "delivered" | "read"; ids: string[] }
  | { k: "typing"; on: boolean };

export interface Settings {
  /** Never open direct WebRTC links (hides your IP address from peers). */
  relayOnly: boolean;
  readReceipts: boolean;
  typingIndicators: boolean;
}

export const DEFAULT_SETTINGS: Settings = { relayOnly: false, readReceipts: true, typingIndicators: true };

export const MAX_MESSAGE_LENGTH = 4000;

export function parsePayload(text: string): Payload | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (!value || typeof value !== "object") return null;
  const p = value as Record<string, unknown>;
  switch (p.k) {
    case "text":
      return typeof p.id === "string" &&
        p.id.length <= 64 &&
        typeof p.body === "string" &&
        p.body.length <= MAX_MESSAGE_LENGTH &&
        typeof p.ts === "number"
        ? { k: "text", id: p.id, body: p.body, ts: p.ts }
        : null;
    case "receipt":
      return (p.status === "delivered" || p.status === "read") &&
        Array.isArray(p.ids) &&
        p.ids.length <= 500 &&
        p.ids.every((id) => typeof id === "string")
        ? { k: "receipt", status: p.status, ids: p.ids as string[] }
        : null;
    case "typing":
      return typeof p.on === "boolean" ? { k: "typing", on: p.on } : null;
    default:
      return null;
  }
}
