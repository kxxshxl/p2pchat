/** Account creation and unlocking. */

import { oneTimePreKeyToWire, signChallenge, signedPreKeyToWire, toBase64 } from "@parley/crypto";
import { ApiError, type Api } from "./api";
import { createKeyMaterial, currentSignedPreKey, type KeyMaterial } from "./keys";
import { DEFAULT_SETTINGS, type Account } from "./types";
import { Vault } from "./vault";

export interface Session {
  vault: Vault;
  account: Account;
  keys: KeyMaterial;
  token: string | null;
}

export type Progress = (step: string) => void;

const yieldToUi = () => new Promise((r) => setTimeout(r, 0));

export async function createAccount(
  api: Api,
  input: { handle: string; displayName: string; passphrase: string },
  progress: Progress,
): Promise<Session> {
  const handle = input.handle.trim().toLowerCase();
  progress("Checking handle");
  const { challenge } = await api.challenge("register", handle);

  progress("Generating identity and pre-keys");
  await yieldToUi();
  const keys = createKeyMaterial();

  // Persist the private keys *before* publishing the public halves.
  progress("Encrypting your keys on this device");
  const vault = await Vault.create(input.passphrase);
  await vault.write({ keys, settings: DEFAULT_SETTINGS, contacts: [] });

  progress("Registering public keys");
  try {
    const result = await api.register({
      handle,
      displayName: input.displayName.trim(),
      challenge,
      signature: toBase64(signChallenge(keys.identity.signing, "register", handle, challenge)),
      signingKey: toBase64(keys.identity.signing.publicKey),
      identityKey: toBase64(keys.identity.dh.publicKey),
      identityKeySignature: toBase64(keys.identity.dhSignature),
      signedPreKey: signedPreKeyToWire(currentSignedPreKey(keys)),
      oneTimePreKeys: keys.oneTimePreKeys.map(oneTimePreKeyToWire),
    });
    const account: Account = {
      userId: result.user.id,
      handle: result.user.handle,
      displayName: result.user.displayName,
      createdAt: Date.now(),
    };
    await vault.put("account", account);
    return { vault, account, keys, token: result.token };
  } catch (err) {
    await Vault.wipe();
    throw err;
  }
}

export async function unlockAccount(passphrase: string, progress: Progress): Promise<Session> {
  progress("Deriving key from passphrase");
  await yieldToUi();
  const vault = await Vault.unlock(passphrase);
  progress("Loading keys");
  const [account, keys] = await Promise.all([vault.get<Account>("account"), vault.get<KeyMaterial>("keys")]);
  if (!account || !keys) throw new Error("This device's vault is incomplete; restore a backup or start over");
  return { vault, account, keys, token: null };
}

export function describeError(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.code === "handle_taken") return "That handle is already taken.";
    if (err.code === "rate_limited") return "Too many attempts. Wait a minute and try again.";
    return err.message;
  }
  return err instanceof Error ? err.message : String(err);
}
