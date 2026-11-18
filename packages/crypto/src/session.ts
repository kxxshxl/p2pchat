/**
 * Per-peer session management and the on-the-wire envelope.
 *
 * A peer can have several sessions (e.g. both people started a conversation at the same moment,
 * or someone reinstalled). We keep a short list, send on the most recently *working* one, and
 * trial-decrypt incoming messages against each — the same approach Signal uses. Two sides that
 * initiate simultaneously therefore converge on one session after a single round trip.
 */

import { fromBase64, fromBase64Exact, toBase64, toHex } from "./bytes.ts";
import { pad, unpad } from "./padding.ts";
import { CryptoError, KEY_LEN, SIG_LEN } from "./primitives.ts";
import {
  type Identity,
  type OneTimePreKey,
  type PreKeyBundle,
  type PublicIdentity,
  type SignedPreKey,
} from "./identity.ts";
import { HEADER_LEN, decodeHeader, initReceiver, initSender, ratchetDecrypt, ratchetEncrypt, type MessageHeader, type RatchetState } from "./ratchet.ts";
import { x3dhInitiate, x3dhRespond, type PreKeyHeader } from "./x3dh.ts";

export const ENVELOPE_VERSION = 1;
export const MAX_SESSIONS_PER_PEER = 5;
export const MAX_CIPHERTEXT_BYTES = 48 * 1024;

export interface Session {
  /** Hex of the initiator's X3DH ephemeral key — uniquely names the session on both sides. */
  id: string;
  role: "initiator" | "responder";
  remote: PublicIdentity;
  ratchet: RatchetState;
  /** Initiators attach this to every message until the first reply proves the peer has the session. */
  pendingPreKey: PreKeyHeader | null;
  createdAt: number;
  lastUsedAt: number;
}

/** All sessions with one peer; index 0 is the active (sending) session. */
export interface SessionRecord {
  sessions: Session[];
}

export interface Envelope {
  v: typeof ENVELOPE_VERSION;
  preKey?: PreKeyHeader;
  header: Uint8Array;
  ciphertext: Uint8Array;
}

/** Private key material the receiver needs to answer an X3DH initiation. */
export interface PreKeyStore {
  identity: Identity;
  signedPreKey(id: number): SignedPreKey | undefined;
  oneTimePreKey(id: number): OneTimePreKey | undefined;
}

// ---------------------------------------------------------------- session lifecycle

export function startSession(identity: Identity, bundle: PreKeyBundle, now = Date.now()): Session {
  const init = x3dhInitiate(identity, bundle);
  return {
    id: toHex(init.header.ephemeralKey),
    role: "initiator",
    remote: {
      signingKey: bundle.signingKey,
      identityKey: bundle.identityKey,
      identityKeySignature: bundle.identityKeySignature,
    },
    ratchet: initSender(init.sharedKey, init.remoteRatchetKey, init.associatedData),
    pendingPreKey: init.header,
    createdAt: now,
    lastUsedAt: now,
  };
}

function withActive(record: SessionRecord | null, session: Session): SessionRecord {
  const others = (record?.sessions ?? []).filter((s) => s.id !== session.id);
  return { sessions: [session, ...others].slice(0, MAX_SESSIONS_PER_PEER) };
}

export function addSession(record: SessionRecord | null, session: Session): SessionRecord {
  return withActive(record, session);
}

export function activeSession(record: SessionRecord | null): Session | undefined {
  return record?.sessions[0];
}

// ---------------------------------------------------------------- encrypt

export interface EncryptResult {
  record: SessionRecord;
  envelope: Envelope;
  session: Session;
  header: MessageHeader;
}

export function encryptMessage(record: SessionRecord, plaintext: Uint8Array, now = Date.now()): EncryptResult {
  const current = activeSession(record);
  if (!current) throw new CryptoError("no session with this peer");
  const { state, message } = ratchetEncrypt(current.ratchet, pad(plaintext));
  const session: Session = { ...current, ratchet: state, lastUsedAt: now };
  const envelope: Envelope = { v: ENVELOPE_VERSION, header: message.headerBytes, ciphertext: message.ciphertext };
  if (session.pendingPreKey) envelope.preKey = session.pendingPreKey;
  return { record: withActive(record, session), envelope, session, header: message.header };
}

// ---------------------------------------------------------------- decrypt

export interface DecryptResult {
  record: SessionRecord;
  plaintext: Uint8Array;
  session: Session;
  header: MessageHeader;
  /** True when this message created a brand-new session (an X3DH initiation). */
  newSession: boolean;
  /** One-time pre-key consumed by this message — delete it once the result is persisted. */
  usedOneTimePreKeyId?: number;
}

function tryDecrypt(session: Session, envelope: Envelope, now: number) {
  const { state, plaintext } = ratchetDecrypt(session.ratchet, envelope.header, envelope.ciphertext);
  const updated: Session = {
    ...session,
    ratchet: state,
    // Any successful decrypt proves the peer holds this session: stop sending the X3DH header.
    pendingPreKey: null,
    lastUsedAt: now,
  };
  return { session: updated, plaintext: unpad(plaintext) };
}

export function decryptMessage(
  record: SessionRecord | null,
  envelope: Envelope,
  keys: PreKeyStore,
  now = Date.now(),
): DecryptResult {
  const header = decodeHeader(envelope.header);

  if (envelope.preKey) {
    const id = toHex(envelope.preKey.ephemeralKey);
    const existing = record?.sessions.find((s) => s.id === id);
    if (existing) {
      const { session, plaintext } = tryDecrypt(existing, envelope, now);
      return { record: withActive(record, session), plaintext, session, header, newSession: false };
    }

    const pk = envelope.preKey;
    const signedPreKey = keys.signedPreKey(pk.signedPreKeyId);
    if (!signedPreKey) throw new CryptoError("unknown signed pre-key (expired or never issued)");
    let oneTimePreKey: OneTimePreKey | undefined;
    if (pk.oneTimePreKeyId !== undefined) {
      oneTimePreKey = keys.oneTimePreKey(pk.oneTimePreKeyId);
      if (!oneTimePreKey) throw new CryptoError("one-time pre-key already used (possible replay)");
    }

    const x3dh = x3dhRespond(keys.identity, pk, signedPreKey, oneTimePreKey);
    const fresh: Session = {
      id,
      role: "responder",
      remote: {
        signingKey: pk.signingKey,
        identityKey: pk.identityKey,
        identityKeySignature: pk.identityKeySignature,
      },
      ratchet: initReceiver(x3dh.sharedKey, signedPreKey.keyPair, x3dh.associatedData),
      pendingPreKey: null,
      createdAt: now,
      lastUsedAt: now,
    };
    const { session, plaintext } = tryDecrypt(fresh, envelope, now);
    const result: DecryptResult = {
      record: withActive(record, session),
      plaintext,
      session,
      header,
      newSession: true,
    };
    if (pk.oneTimePreKeyId !== undefined) result.usedOneTimePreKeyId = pk.oneTimePreKeyId;
    return result;
  }

  if (!record || record.sessions.length === 0) throw new CryptoError("no session with this peer");
  let lastError: unknown;
  for (const candidate of record.sessions) {
    try {
      const { session, plaintext } = tryDecrypt(candidate, envelope, now);
      return { record: withActive(record, session), plaintext, session, header, newSession: false };
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError instanceof CryptoError ? lastError : new CryptoError("unable to decrypt message");
}

// ---------------------------------------------------------------- wire format

export interface PreKeyHeaderWire {
  signingKey: string;
  identityKey: string;
  identityKeySignature: string;
  ephemeralKey: string;
  signedPreKeyId: number;
  oneTimePreKeyId?: number;
}

export interface EnvelopeWire {
  v: number;
  preKey?: PreKeyHeaderWire;
  header: string;
  ciphertext: string;
}

export function envelopeToWire(envelope: Envelope): EnvelopeWire {
  const wire: EnvelopeWire = {
    v: envelope.v,
    header: toBase64(envelope.header),
    ciphertext: toBase64(envelope.ciphertext),
  };
  if (envelope.preKey) {
    const pk = envelope.preKey;
    wire.preKey = {
      signingKey: toBase64(pk.signingKey),
      identityKey: toBase64(pk.identityKey),
      identityKeySignature: toBase64(pk.identityKeySignature),
      ephemeralKey: toBase64(pk.ephemeralKey),
      signedPreKeyId: pk.signedPreKeyId,
    };
    if (pk.oneTimePreKeyId !== undefined) wire.preKey.oneTimePreKeyId = pk.oneTimePreKeyId;
  }
  return wire;
}

function isKeyId(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

/** Strictly validates untrusted input from the network. */
export function envelopeFromWire(input: unknown): Envelope {
  if (!input || typeof input !== "object") throw new CryptoError("envelope must be an object");
  const wire = input as Partial<EnvelopeWire>;
  if (wire.v !== ENVELOPE_VERSION) throw new CryptoError(`unsupported envelope version ${String(wire.v)}`);
  if (typeof wire.ciphertext !== "string") throw new CryptoError("missing ciphertext");

  const ciphertext = fromBase64(wire.ciphertext);
  if (ciphertext.length > MAX_CIPHERTEXT_BYTES) throw new CryptoError("ciphertext too large");
  const envelope: Envelope = {
    v: ENVELOPE_VERSION,
    header: fromBase64Exact(wire.header, HEADER_LEN, "header"),
    ciphertext,
  };

  if (wire.preKey !== undefined) {
    const pk = wire.preKey;
    if (!pk || typeof pk !== "object" || !isKeyId(pk.signedPreKeyId)) {
      throw new CryptoError("malformed pre-key header");
    }
    if (pk.oneTimePreKeyId !== undefined && !isKeyId(pk.oneTimePreKeyId)) {
      throw new CryptoError("malformed one-time pre-key id");
    }
    envelope.preKey = {
      signingKey: fromBase64Exact(pk.signingKey, KEY_LEN, "preKey.signingKey"),
      identityKey: fromBase64Exact(pk.identityKey, KEY_LEN, "preKey.identityKey"),
      identityKeySignature: fromBase64Exact(pk.identityKeySignature, SIG_LEN, "preKey.identityKeySignature"),
      ephemeralKey: fromBase64Exact(pk.ephemeralKey, KEY_LEN, "preKey.ephemeralKey"),
      signedPreKeyId: pk.signedPreKeyId,
    };
    if (pk.oneTimePreKeyId !== undefined) envelope.preKey.oneTimePreKeyId = pk.oneTimePreKeyId;
  }
  return envelope;
}
