import { generateIdentity } from "@parley/crypto";
import { beforeEach, describe, expect, it } from "vitest";
import { idbEntries, idbGet, idbWrite } from "../src/lib/idb";
import { Vault, WrongPassphraseError } from "../src/lib/vault";

const FAST = 1_000; // PBKDF2 iterations for tests only

beforeEach(async () => {
  await Vault.wipe();
});

describe("Vault", () => {
  it("round-trips values, including binary key material", async () => {
    const vault = await Vault.create("correct horse battery", FAST);
    const identity = generateIdentity();
    await vault.write({ keys: identity, list: [1, "two", { three: true }] });

    const reopened = await Vault.unlock("correct horse battery");
    const keys = await reopened.get<typeof identity>("keys");
    expect(keys!.signing.publicKey).toBeInstanceOf(Uint8Array);
    expect(Array.from(keys!.signing.privateKey)).toEqual(Array.from(identity.signing.privateKey));
    expect(await reopened.get("list")).toEqual([1, "two", { three: true }]);
    expect(await reopened.get("missing")).toBeUndefined();
  });

  it("rejects a wrong passphrase", async () => {
    await Vault.create("correct horse battery", FAST);
    await expect(Vault.unlock("wrong horse battery")).rejects.toBeInstanceOf(WrongPassphraseError);
  });

  it("stores nothing in plaintext", async () => {
    const vault = await Vault.create("correct horse battery", FAST);
    await vault.put("contacts", [{ handle: "very-secret-handle" }]);
    const raw = JSON.stringify(await idbEntries(), (_k, v) => (v instanceof Uint8Array ? Array.from(v) : v));
    expect(raw).not.toContain("very-secret-handle");
    const sealed = await idbGet<{ iv: Uint8Array; data: Uint8Array }>("contacts");
    expect(new TextDecoder().decode(sealed!.data)).not.toContain("very-secret");
  });

  it("detects records moved to a different key", async () => {
    const vault = await Vault.create("correct horse battery", FAST);
    await vault.write({ "session:alice": { n: 1 }, "session:bob": { n: 2 } });
    const alice = await idbGet("session:alice");
    await idbWrite([["session:bob", alice]]); // attacker with disk access swaps records
    await expect(vault.get("session:bob")).rejects.toThrow();
    expect(await vault.get("session:alice")).toEqual({ n: 1 });
  });

  it("writes several records atomically and supports deletes", async () => {
    const vault = await Vault.create("correct horse battery", FAST);
    await vault.write({ a: 1, b: 2 });
    await vault.write({ c: 3 }, ["a"]);
    expect((await vault.names()).sort()).toEqual(["b", "c"]);
  });

  it("exports and restores an encrypted backup", async () => {
    const vault = await Vault.create("correct horse battery", FAST);
    await vault.put("account", { handle: "ada" });
    const backup = await Vault.exportBackup();
    expect(backup).not.toContain("ada");

    await Vault.wipe();
    expect(await Vault.exists()).toBe(false);
    await Vault.importBackup(backup);
    const restored = await Vault.unlock("correct horse battery");
    expect(await restored.get("account")).toEqual({ handle: "ada" });
  });

  it("rejects files that are not backups", async () => {
    await expect(Vault.importBackup("{}")).rejects.toThrow(/Not a Parley backup/);
    await expect(Vault.importBackup("garbage")).rejects.toThrow(/Not a Parley backup/);
  });
});
