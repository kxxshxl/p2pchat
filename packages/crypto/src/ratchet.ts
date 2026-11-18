/**
 * Double Ratchet.
 *
 *  - Symmetric-key ratchet: every message gets a fresh key from a hash chain, so stealing one
 *    message key reveals nothing about earlier ones (forward secrecy).
 *  - DH ratchet: every time the conversation changes direction a new X25519 exchange is mixed
 *    into the root key, so a compromised state heals itself (post-compromise security).
 *  - Skipped message keys are cached (bounded) so messages can arrive late or out of order.
 *
 * All operations are pure: they take a state and return a *new* state. A message that fails
 * to authenticate therefore can never corrupt a session — the caller simply keeps the old state.
 */

import { concat, equal, readU32be, toHex, u32be, utf8 } from "./bytes.ts";
import {
  CryptoError,
  GCM_NONCE_LEN,
  KEY_LEN,
  aeadDecrypt,
  aeadEncrypt,
  dh,
  generateDhKeyPair,
  hkdf,
  hmacSha256,
  type KeyPair,
} from "./primitives.ts";

/** Maximum number of message keys we will derive-and-store to reach one incoming message. */
export const MAX_SKIP = 1000;
/** Upper bound on cached skipped keys across all chains (oldest evicted first). */
export const MAX_STORED_SKIPPED = 2000;

const ROOT_INFO = utf8("Parley/Ratchet/root/v1");
const MESSAGE_INFO = utf8("Parley/Ratchet/message/v1");
const CHAIN_MESSAGE = new Uint8Array([0x01]);
const CHAIN_NEXT = new Uint8Array([0x02]);
const ZERO_SALT = new Uint8Array(32);

export const HEADER_LEN = KEY_LEN + 4 + 4;

export interface MessageHeader {
  /** Sender's current ratchet public key. */
  publicKey: Uint8Array;
  /** Length of the sender's previous sending chain. */
  previousCount: number;
  /** Index of this message in the current sending chain. */
  count: number;
}

export interface SkippedKey {
  ratchetKey: string; // hex of the remote ratchet public key
  count: number;
  messageKey: Uint8Array;
}

export interface RatchetState {
  rootKey: Uint8Array;
  sendingKeyPair: KeyPair;
  remoteKey: Uint8Array | null;
  sendingChainKey: Uint8Array | null;
  receivingChainKey: Uint8Array | null;
  sendCount: number;
  receiveCount: number;
  previousSendCount: number;
  skipped: SkippedKey[];
  associatedData: Uint8Array;
}

// ---------------------------------------------------------------- KDFs

function kdfRoot(rootKey: Uint8Array, dhOutput: Uint8Array): [rootKey: Uint8Array, chainKey: Uint8Array] {
  const out = hkdf(dhOutput, rootKey, ROOT_INFO, 64);
  return [out.slice(0, 32), out.slice(32)];
}

function kdfChain(chainKey: Uint8Array): [chainKey: Uint8Array, messageKey: Uint8Array] {
  return [hmacSha256(chainKey, CHAIN_NEXT), hmacSha256(chainKey, CHAIN_MESSAGE)];
}

/** Expand a one-use message key into an AES-256 key and a nonce. Deterministic nonces are safe
 *  here because every message key is used for exactly one encryption. */
function messageCipherParams(messageKey: Uint8Array): [key: Uint8Array, nonce: Uint8Array] {
  const out = hkdf(messageKey, ZERO_SALT, MESSAGE_INFO, 32 + GCM_NONCE_LEN);
  return [out.slice(0, 32), out.slice(32)];
}

// ---------------------------------------------------------------- header encoding

export function encodeHeader(header: MessageHeader): Uint8Array {
  return concat(header.publicKey, u32be(header.previousCount), u32be(header.count));
}

export function decodeHeader(bytes: Uint8Array): MessageHeader {
  if (bytes.length !== HEADER_LEN) throw new CryptoError("malformed message header");
  return {
    publicKey: bytes.slice(0, KEY_LEN),
    previousCount: readU32be(bytes, KEY_LEN),
    count: readU32be(bytes, KEY_LEN + 4),
  };
}

// ---------------------------------------------------------------- initialisation

/** Initiator (Alice): she already knows Bob's first ratchet key — his signed pre-key. */
export function initSender(
  sharedKey: Uint8Array,
  remoteRatchetKey: Uint8Array,
  associatedData: Uint8Array,
): RatchetState {
  const sendingKeyPair = generateDhKeyPair();
  const [rootKey, sendingChainKey] = kdfRoot(sharedKey, dh(sendingKeyPair.privateKey, remoteRatchetKey));
  return {
    rootKey,
    sendingKeyPair,
    remoteKey: remoteRatchetKey,
    sendingChainKey,
    receivingChainKey: null,
    sendCount: 0,
    receiveCount: 0,
    previousSendCount: 0,
    skipped: [],
    associatedData,
  };
}

/** Responder (Bob): his signed pre-key pair is his first ratchet key pair. */
export function initReceiver(
  sharedKey: Uint8Array,
  ownRatchetKeyPair: KeyPair,
  associatedData: Uint8Array,
): RatchetState {
  return {
    rootKey: sharedKey,
    sendingKeyPair: ownRatchetKeyPair,
    remoteKey: null,
    sendingChainKey: null,
    receivingChainKey: null,
    sendCount: 0,
    receiveCount: 0,
    previousSendCount: 0,
    skipped: [],
    associatedData,
  };
}

export function cloneState(state: RatchetState): RatchetState {
  return {
    ...state,
    sendingKeyPair: { ...state.sendingKeyPair },
    skipped: state.skipped.map((s) => ({ ...s })),
  };
}

// ---------------------------------------------------------------- encrypt / decrypt

export interface EncryptedMessage {
  header: MessageHeader;
  headerBytes: Uint8Array;
  ciphertext: Uint8Array;
}

export function ratchetEncrypt(
  current: RatchetState,
  plaintext: Uint8Array,
): { state: RatchetState; message: EncryptedMessage } {
  if (!current.sendingChainKey) {
    throw new CryptoError("session cannot send before it has received a message");
  }
  const state = cloneState(current);
  const [nextChainKey, messageKey] = kdfChain(state.sendingChainKey!);
  const header: MessageHeader = {
    publicKey: state.sendingKeyPair.publicKey,
    previousCount: state.previousSendCount,
    count: state.sendCount,
  };
  const headerBytes = encodeHeader(header);
  const [key, nonce] = messageCipherParams(messageKey);
  const ciphertext = aeadEncrypt(key, nonce, plaintext, concat(state.associatedData, headerBytes));

  state.sendingChainKey = nextChainKey;
  state.sendCount += 1;
  return { state, message: { header, headerBytes, ciphertext } };
}

export function ratchetDecrypt(
  current: RatchetState,
  headerBytes: Uint8Array,
  ciphertext: Uint8Array,
): { state: RatchetState; plaintext: Uint8Array } {
  const header = decodeHeader(headerBytes);
  const state = cloneState(current);
  const ad = concat(state.associatedData, headerBytes);
  const ratchetKeyHex = toHex(header.publicKey);

  // 1. A message we skipped earlier?
  const skippedIndex = state.skipped.findIndex(
    (s) => s.ratchetKey === ratchetKeyHex && s.count === header.count,
  );
  if (skippedIndex >= 0) {
    const [entry] = state.skipped.splice(skippedIndex, 1);
    const [key, nonce] = messageCipherParams(entry!.messageKey);
    return { state, plaintext: aeadDecrypt(key, nonce, ciphertext, ad) };
  }

  // 2. A new ratchet key from the other side: finish the old chain, then step the DH ratchet.
  if (!state.remoteKey || !equal(header.publicKey, state.remoteKey)) {
    skipMessageKeys(state, header.previousCount);
    dhRatchetStep(state, header.publicKey);
  }

  // 3. Advance the receiving chain to this message.
  skipMessageKeys(state, header.count);
  const [nextChainKey, messageKey] = kdfChain(state.receivingChainKey!);
  const [key, nonce] = messageCipherParams(messageKey);
  const plaintext = aeadDecrypt(key, nonce, ciphertext, ad); // throws -> caller keeps old state
  state.receivingChainKey = nextChainKey;
  state.receiveCount += 1;
  return { state, plaintext };
}

function skipMessageKeys(state: RatchetState, until: number): void {
  if (!state.receivingChainKey) return; // no receiving chain yet (first message for responder)
  if (until < state.receiveCount) {
    // An old message whose key is no longer cached: replay, or we evicted it.
    throw new CryptoError("message key unavailable (duplicate or expired message)");
  }
  if (until - state.receiveCount > MAX_SKIP) throw new CryptoError("too many skipped messages");

  const ratchetKey = toHex(state.remoteKey!);
  while (state.receiveCount < until) {
    const [nextChainKey, messageKey] = kdfChain(state.receivingChainKey);
    state.skipped.push({ ratchetKey, count: state.receiveCount, messageKey });
    state.receivingChainKey = nextChainKey;
    state.receiveCount += 1;
  }
  if (state.skipped.length > MAX_STORED_SKIPPED) {
    state.skipped.splice(0, state.skipped.length - MAX_STORED_SKIPPED);
  }
}

function dhRatchetStep(state: RatchetState, remoteKey: Uint8Array): void {
  state.previousSendCount = state.sendCount;
  state.sendCount = 0;
  state.receiveCount = 0;
  state.remoteKey = remoteKey;

  [state.rootKey, state.receivingChainKey] = kdfRoot(
    state.rootKey,
    dh(state.sendingKeyPair.privateKey, remoteKey),
  );
  state.sendingKeyPair = generateDhKeyPair();
  [state.rootKey, state.sendingChainKey] = kdfRoot(
    state.rootKey,
    dh(state.sendingKeyPair.privateKey, remoteKey),
  );
}
