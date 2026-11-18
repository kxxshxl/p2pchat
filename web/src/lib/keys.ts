/**
 * The account's private key material and its upkeep: one-time pre-keys are consumed as people
 * start conversations, so we top them up; the signed pre-key is rotated weekly (older ones are
 * kept for a while so late-arriving first messages can still be decrypted).
 */

import {
  generateIdentity,
  generateOneTimePreKeys,
  generateSignedPreKey,
  oneTimePreKeyToWire,
  signedPreKeyToWire,
  type Identity,
  type OneTimePreKey,
  type PreKeyStore,
  type SignedPreKey,
} from "@parley/crypto";
import type { Api, KeyStatus } from "./api";

export const INITIAL_ONE_TIME_PREKEYS = 100;
const REFILL_BELOW = 40;
const REFILL_TARGET = 100;
const MAX_LOCAL_ONE_TIME_PREKEYS = 1000;
const SIGNED_PREKEY_ROTATE_MS = 7 * 24 * 60 * 60 * 1000;
const SIGNED_PREKEY_RETAIN_MS = 30 * 24 * 60 * 60 * 1000;

export interface KeyMaterial {
  identity: Identity;
  signedPreKeys: SignedPreKey[]; // oldest first
  oneTimePreKeys: OneTimePreKey[];
  nextOneTimeId: number;
  nextSignedId: number;
}

export function createKeyMaterial(): KeyMaterial {
  const identity = generateIdentity();
  return {
    identity,
    signedPreKeys: [generateSignedPreKey(identity, 1)],
    oneTimePreKeys: generateOneTimePreKeys(1, INITIAL_ONE_TIME_PREKEYS),
    nextOneTimeId: INITIAL_ONE_TIME_PREKEYS + 1,
    nextSignedId: 2,
  };
}

export function preKeyStore(keys: KeyMaterial): PreKeyStore {
  return {
    identity: keys.identity,
    signedPreKey: (id) => keys.signedPreKeys.find((k) => k.id === id),
    oneTimePreKey: (id) => keys.oneTimePreKeys.find((k) => k.id === id),
  };
}

export function currentSignedPreKey(keys: KeyMaterial): SignedPreKey {
  return keys.signedPreKeys[keys.signedPreKeys.length - 1]!;
}

export function withoutOneTimePreKey(keys: KeyMaterial, id: number): KeyMaterial {
  return { ...keys, oneTimePreKeys: keys.oneTimePreKeys.filter((k) => k.id !== id) };
}

/**
 * Brings the server's view of our pre-keys up to date. New private keys are always handed to
 * `persist` *before* their public halves are published, so a crash can never leave the server
 * advertising a key we no longer have.
 */
export async function maintainKeys(
  api: Api,
  keys: KeyMaterial,
  persist: (keys: KeyMaterial) => Promise<void>,
  now = Date.now(),
): Promise<{ keys: KeyMaterial; status: KeyStatus }> {
  let status = await api.keyStatus();
  let next = keys;
  let changed = false;

  const current = currentSignedPreKey(next);
  if (now - current.createdAt > SIGNED_PREKEY_ROTATE_MS) {
    const fresh = generateSignedPreKey(next.identity, next.nextSignedId, now);
    next = {
      ...next,
      signedPreKeys: [...next.signedPreKeys.filter((k) => now - k.createdAt < SIGNED_PREKEY_RETAIN_MS), fresh],
      nextSignedId: next.nextSignedId + 1,
    };
    await persist(next);
    await api.rotateSignedPreKey(signedPreKeyToWire(fresh));
    changed = true;
  } else if (status.signedPreKey?.id !== current.id) {
    // e.g. restored from a backup on a server that lost our latest key
    await api.rotateSignedPreKey(signedPreKeyToWire(current));
    changed = true;
  }

  if (status.oneTimePreKeys < REFILL_BELOW) {
    const count = Math.min(REFILL_TARGET, status.maxOneTimePreKeys) - status.oneTimePreKeys;
    const fresh = generateOneTimePreKeys(next.nextOneTimeId, count);
    next = {
      ...next,
      oneTimePreKeys: [...next.oneTimePreKeys, ...fresh].slice(-MAX_LOCAL_ONE_TIME_PREKEYS),
      nextOneTimeId: next.nextOneTimeId + count,
    };
    await persist(next);
    await api.uploadOneTimePreKeys(fresh.map(oneTimePreKeyToWire));
    changed = true;
  }

  if (changed) status = await api.keyStatus();
  return { keys: next, status };
}
