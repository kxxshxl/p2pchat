/**
 * X3DH ("Extended Triple Diffie-Hellman") asynchronous key agreement.
 *
 * Lets an initiator derive a shared secret with someone who is offline, using only the
 * pre-key bundle that person left on the server:
 *
 *   DH1 = DH(IK_A, SPK_B)   mutual authentication (A's identity, B's signed pre-key)
 *   DH2 = DH(EK_A, IK_B)    mutual authentication (B's identity)
 *   DH3 = DH(EK_A, SPK_B)   forward secrecy
 *   DH4 = DH(EK_A, OPK_B)   optional; protects the first message against replay and
 *                           against later compromise of the signed pre-key
 *   SK  = HKDF(0xFF*32 || DH1 || DH2 || DH3 [|| DH4])
 */

import { concat, utf8 } from "./bytes.ts";
import { CryptoError, dh, generateDhKeyPair, hkdf } from "./primitives.ts";
import {
  publicIdentity,
  verifyBundle,
  verifyPublicIdentity,
  type Identity,
  type OneTimePreKey,
  type PreKeyBundle,
  type PublicIdentity,
  type SignedPreKey,
} from "./identity.ts";

const X3DH_INFO = utf8("Parley/X3DH/v1");
const AD_PREFIX = utf8("Parley/AD/v1");
const DOMAIN_SEPARATOR = new Uint8Array(32).fill(0xff);
const ZERO_SALT = new Uint8Array(32);

/** Sent (in the clear but authenticated) with the initiator's messages until the responder replies. */
export interface PreKeyHeader extends PublicIdentity {
  ephemeralKey: Uint8Array;
  signedPreKeyId: number;
  oneTimePreKeyId?: number;
}

export interface X3DHResult {
  sharedKey: Uint8Array;
  /** Bound into every message's AEAD so both identities are authenticated end to end. */
  associatedData: Uint8Array;
}

export interface X3DHInitiation extends X3DHResult {
  header: PreKeyHeader;
  /** The responder's signed pre-key: the first ratchet public key. */
  remoteRatchetKey: Uint8Array;
}

export function associatedData(initiator: PublicIdentity, responder: PublicIdentity): Uint8Array {
  return concat(
    AD_PREFIX,
    initiator.signingKey,
    initiator.identityKey,
    responder.signingKey,
    responder.identityKey,
  );
}

function deriveSharedKey(parts: Uint8Array[]): Uint8Array {
  return hkdf(concat(DOMAIN_SEPARATOR, ...parts), ZERO_SALT, X3DH_INFO, 32);
}

export function x3dhInitiate(self: Identity, bundle: PreKeyBundle): X3DHInitiation {
  verifyBundle(bundle);
  const ephemeral = generateDhKeyPair();
  const parts = [
    dh(self.dh.privateKey, bundle.signedPreKey.publicKey),
    dh(ephemeral.privateKey, bundle.identityKey),
    dh(ephemeral.privateKey, bundle.signedPreKey.publicKey),
  ];
  if (bundle.oneTimePreKey) parts.push(dh(ephemeral.privateKey, bundle.oneTimePreKey.publicKey));

  const header: PreKeyHeader = {
    ...publicIdentity(self),
    ephemeralKey: ephemeral.publicKey,
    signedPreKeyId: bundle.signedPreKey.id,
  };
  if (bundle.oneTimePreKey) header.oneTimePreKeyId = bundle.oneTimePreKey.id;

  return {
    sharedKey: deriveSharedKey(parts),
    associatedData: associatedData(publicIdentity(self), bundle),
    header,
    remoteRatchetKey: bundle.signedPreKey.publicKey,
  };
}

export function x3dhRespond(
  self: Identity,
  header: PreKeyHeader,
  signedPreKey: SignedPreKey,
  oneTimePreKey: OneTimePreKey | undefined,
): X3DHResult {
  verifyPublicIdentity(header);
  if (signedPreKey.id !== header.signedPreKeyId) throw new CryptoError("signed pre-key id mismatch");
  if ((header.oneTimePreKeyId === undefined) !== (oneTimePreKey === undefined)) {
    throw new CryptoError("one-time pre-key mismatch");
  }
  if (oneTimePreKey && oneTimePreKey.id !== header.oneTimePreKeyId) {
    throw new CryptoError("one-time pre-key id mismatch");
  }

  const parts = [
    dh(signedPreKey.keyPair.privateKey, header.identityKey),
    dh(self.dh.privateKey, header.ephemeralKey),
    dh(signedPreKey.keyPair.privateKey, header.ephemeralKey),
  ];
  if (oneTimePreKey) parts.push(dh(oneTimePreKey.keyPair.privateKey, header.ephemeralKey));

  return {
    sharedKey: deriveSharedKey(parts),
    associatedData: associatedData(header, publicIdentity(self)),
  };
}
