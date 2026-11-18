/**
 * Encrypted local storage.
 *
 * Everything Parley keeps in the browser (private keys, ratchet sessions, message history,
 * contacts) is encrypted with AES-256-GCM under a key derived from the user's passphrase with
 * PBKDF2-SHA256. The derived key is a non-extractable WebCrypto key held only in memory.
 * Each record's key name is bound in as associated data, so records can't be swapped around.
 */

import { deserialize, serialize, utf8 } from "@parley/crypto";
import { idbClear, idbEntries, idbGet, idbWrite } from "./idb";

const META_KEY = "__vault_meta";
const CHECK_TEXT = "parley-vault-check";
const BACKUP_FORMAT = "parley-backup";
export const DEFAULT_ITERATIONS = 600_000;

interface Sealed {
  iv: Uint8Array;
  data: Uint8Array;
}

interface VaultMeta {
  v: 1;
  salt: Uint8Array;
  iterations: number;
  check: Sealed;
}

export class WrongPassphraseError extends Error {
  override name = "WrongPassphraseError";
  constructor() {
    super("Wrong passphrase");
  }
}

function ad(key: string): Uint8Array<ArrayBuffer> {
  return utf8(`parley-vault/v1:${key}`) as Uint8Array<ArrayBuffer>;
}

async function deriveKey(passphrase: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", utf8(passphrase.normalize("NFKC")) as Uint8Array<ArrayBuffer>, "PBKDF2", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as Uint8Array<ArrayBuffer>, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function seal(key: CryptoKey, name: string, plaintext: Uint8Array): Promise<Sealed> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: ad(name) },
    key,
    plaintext as Uint8Array<ArrayBuffer>,
  );
  return { iv, data: new Uint8Array(data) };
}

async function open(key: CryptoKey, name: string, sealed: Sealed): Promise<Uint8Array> {
  const data = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: sealed.iv as Uint8Array<ArrayBuffer>, additionalData: ad(name) },
    key,
    sealed.data as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(data);
}

export class Vault {
  private readonly key: CryptoKey;

  private constructor(key: CryptoKey) {
    this.key = key;
  }

  static async exists(): Promise<boolean> {
    return (await idbGet<VaultMeta>(META_KEY)) !== undefined;
  }

  static async create(passphrase: string, iterations = DEFAULT_ITERATIONS): Promise<Vault> {
    await idbClear();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(passphrase, salt, iterations);
    const meta: VaultMeta = { v: 1, salt, iterations, check: await seal(key, META_KEY, utf8(CHECK_TEXT)) };
    await idbWrite([[META_KEY, meta]]);
    return new Vault(key);
  }

  static async unlock(passphrase: string): Promise<Vault> {
    const meta = await idbGet<VaultMeta>(META_KEY);
    if (!meta) throw new Error("No account on this device");
    const key = await deriveKey(passphrase, meta.salt, meta.iterations);
    try {
      await open(key, META_KEY, meta.check);
    } catch {
      throw new WrongPassphraseError();
    }
    return new Vault(key);
  }

  static async wipe(): Promise<void> {
    await idbClear();
  }

  async get<T>(name: string): Promise<T | undefined> {
    const sealed = await idbGet<Sealed>(name);
    if (!sealed) return undefined;
    return deserialize<T>(new TextDecoder().decode(await open(this.key, name, sealed)));
  }

  /** Encrypts every value first, then writes them all in one IndexedDB transaction. */
  async write(puts: Record<string, unknown>, deletes: string[] = []): Promise<void> {
    const sealed: [string, Sealed][] = [];
    for (const [name, value] of Object.entries(puts)) {
      sealed.push([name, await seal(this.key, name, utf8(serialize(value)))]);
    }
    await idbWrite(sealed, deletes);
  }

  async put(name: string, value: unknown): Promise<void> {
    await this.write({ [name]: value });
  }

  async names(prefix = ""): Promise<string[]> {
    const entries = await idbEntries<unknown>();
    return entries.map(([k]) => k).filter((k) => k !== META_KEY && k.startsWith(prefix));
  }

  // ------------------------------------------------------------ backups

  /** The backup is the raw encrypted vault: it is only as readable as the passphrase is strong. */
  static async exportBackup(): Promise<string> {
    const entries = await idbEntries<Sealed | VaultMeta>();
    return serialize({ format: BACKUP_FORMAT, v: 1, exportedAt: Date.now(), entries });
  }

  static async importBackup(text: string): Promise<void> {
    let parsed: { format?: string; v?: number; entries?: [string, Sealed | VaultMeta][] };
    try {
      parsed = deserialize(text);
    } catch {
      throw new Error("Not a Parley backup file");
    }
    if (parsed.format !== BACKUP_FORMAT || parsed.v !== 1 || !Array.isArray(parsed.entries)) {
      throw new Error("Not a Parley backup file");
    }
    if (!parsed.entries.some(([k]) => k === META_KEY)) throw new Error("Backup is missing its key material");
    await idbClear();
    await idbWrite(parsed.entries);
  }
}
