/**
 * Persistence (node:sqlite, synchronous). The server stores only *public* keys and opaque
 * ciphertext — it never sees a private key or a plaintext message.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

const MIGRATIONS: string[] = [
  `
  CREATE TABLE users (
    id                TEXT PRIMARY KEY,
    handle            TEXT NOT NULL UNIQUE,
    display_name      TEXT NOT NULL,
    signing_key       TEXT NOT NULL UNIQUE,
    identity_key      TEXT NOT NULL,
    identity_key_sig  TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    last_seen_at      INTEGER
  );

  CREATE TABLE signed_prekeys (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id      INTEGER NOT NULL,
    public_key  TEXT NOT NULL,
    signature   TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (user_id, key_id)
  );

  CREATE TABLE one_time_prekeys (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id      INTEGER NOT NULL,
    public_key  TEXT NOT NULL,
    PRIMARY KEY (user_id, key_id)
  );

  CREATE TABLE challenges (
    nonce       TEXT PRIMARY KEY,
    purpose     TEXT NOT NULL,
    handle      TEXT NOT NULL,
    expires_at  INTEGER NOT NULL
  );

  CREATE TABLE auth_sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
  );

  CREATE TABLE mailbox (
    id            TEXT PRIMARY KEY,
    sender_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    envelope      TEXT NOT NULL,
    created_at    INTEGER NOT NULL
  );
  CREATE INDEX mailbox_by_recipient ON mailbox(recipient_id, created_at);
  `,
];

export interface UserRow {
  id: string;
  handle: string;
  displayName: string;
  signingKey: string;
  identityKey: string;
  identityKeySignature: string;
  createdAt: number;
  lastSeenAt: number | null;
}

export interface SignedPreKeyRow {
  id: number;
  publicKey: string;
  signature: string;
  createdAt: number;
}

export interface OneTimePreKeyRow {
  id: number;
  publicKey: string;
}

export interface MailboxRow {
  id: string;
  senderId: string;
  envelope: string;
  createdAt: number;
}

export interface NewUser {
  handle: string;
  displayName: string;
  signingKey: string;
  identityKey: string;
  identityKeySignature: string;
  signedPreKey: SignedPreKeyRow;
  oneTimePreKeys: OneTimePreKeyRow[];
}

function userColumns(t = ""): string {
  const p = t ? `${t}.` : "";
  return `${p}id AS id, ${p}handle AS handle, ${p}display_name AS displayName,
    ${p}signing_key AS signingKey, ${p}identity_key AS identityKey,
    ${p}identity_key_sig AS identityKeySignature, ${p}created_at AS createdAt,
    ${p}last_seen_at AS lastSeenAt`;
}
const USER_COLUMNS = userColumns();

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export class Store {
  readonly db: DatabaseSync;

  constructor(path: string) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
    this.migrate();
  }

  private migrate(): void {
    const { user_version: version } = this.db.prepare("PRAGMA user_version").get() as { user_version: number };
    for (let i = version; i < MIGRATIONS.length; i++) {
      this.transaction(() => {
        this.db.exec(MIGRATIONS[i]!);
        this.db.exec(`PRAGMA user_version = ${i + 1}`);
      });
    }
  }

  transaction<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  close(): void {
    this.db.close();
  }

  // ------------------------------------------------------------ users

  createUser(user: NewUser, now = Date.now()): UserRow {
    const id = randomUUID();
    this.transaction(() => {
      this.db
        .prepare(
          `INSERT INTO users (id, handle, display_name, signing_key, identity_key, identity_key_sig, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(id, user.handle, user.displayName, user.signingKey, user.identityKey, user.identityKeySignature, now);
      this.putSignedPreKey(id, user.signedPreKey);
      this.addOneTimePreKeys(id, user.oneTimePreKeys);
    });
    return this.userById(id)!;
  }

  userById(id: string): UserRow | undefined {
    return this.db.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`).get(id) as UserRow | undefined;
  }

  userByHandle(handle: string): UserRow | undefined {
    return this.db.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE handle = ?`).get(handle) as
      | UserRow
      | undefined;
  }

  handleTaken(handle: string, signingKey: string): boolean {
    return !!this.db
      .prepare("SELECT 1 FROM users WHERE handle = ? OR signing_key = ?")
      .get(handle, signingKey);
  }

  searchUsers(prefix: string, excludeId: string, limit = 20): UserRow[] {
    const escaped = prefix.replace(/[\\%_]/g, (c) => `\\${c}`);
    return this.db
      .prepare(
        `SELECT ${USER_COLUMNS} FROM users
         WHERE handle LIKE ? ESCAPE '\\' AND id != ?
         ORDER BY handle LIMIT ?`,
      )
      .all(`${escaped}%`, excludeId, limit) as unknown as UserRow[];
  }

  touchUser(id: string, now = Date.now()): void {
    this.db.prepare("UPDATE users SET last_seen_at = ? WHERE id = ?").run(now, id);
  }

  // ------------------------------------------------------------ pre-keys

  putSignedPreKey(userId: string, key: SignedPreKeyRow): void {
    this.db
      .prepare(
        `INSERT INTO signed_prekeys (user_id, key_id, public_key, signature, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (user_id, key_id) DO NOTHING`,
      )
      .run(userId, key.id, key.publicKey, key.signature, key.createdAt);
  }

  latestSignedPreKey(userId: string): SignedPreKeyRow | undefined {
    return this.db
      .prepare(
        `SELECT key_id AS id, public_key AS publicKey, signature, created_at AS createdAt
         FROM signed_prekeys WHERE user_id = ? ORDER BY created_at DESC, key_id DESC LIMIT 1`,
      )
      .get(userId) as SignedPreKeyRow | undefined;
  }

  /** Inserts keys, ignoring ids that already exist. Returns how many were added. */
  addOneTimePreKeys(userId: string, keys: OneTimePreKeyRow[]): number {
    const insert = this.db.prepare(
      `INSERT INTO one_time_prekeys (user_id, key_id, public_key) VALUES (?, ?, ?)
       ON CONFLICT (user_id, key_id) DO NOTHING`,
    );
    let added = 0;
    for (const key of keys) added += Number(insert.run(userId, key.id, key.publicKey).changes);
    return added;
  }

  countOneTimePreKeys(userId: string): number {
    const row = this.db.prepare("SELECT COUNT(*) AS n FROM one_time_prekeys WHERE user_id = ?").get(userId) as {
      n: number;
    };
    return row.n;
  }

  /** Atomically removes and returns one one-time pre-key (each may be handed out only once). */
  takeOneTimePreKey(userId: string): OneTimePreKeyRow | undefined {
    return this.db
      .prepare(
        `DELETE FROM one_time_prekeys
         WHERE rowid = (SELECT rowid FROM one_time_prekeys WHERE user_id = ? ORDER BY key_id LIMIT 1)
         RETURNING key_id AS id, public_key AS publicKey`,
      )
      .get(userId) as OneTimePreKeyRow | undefined;
  }

  // ------------------------------------------------------------ challenges & sessions

  createChallenge(purpose: string, handle: string, ttlMs: number, now = Date.now()): string {
    const nonce = randomBytes(32).toString("base64url");
    this.db
      .prepare("INSERT INTO challenges (nonce, purpose, handle, expires_at) VALUES (?, ?, ?, ?)")
      .run(nonce, purpose, handle, now + ttlMs);
    return nonce;
  }

  /** Single use: the challenge is deleted whether or not it is valid for this request. */
  consumeChallenge(nonce: string, purpose: string, handle: string, now = Date.now()): boolean {
    const row = this.db
      .prepare("DELETE FROM challenges WHERE nonce = ? RETURNING purpose, handle, expires_at AS expiresAt")
      .get(nonce) as { purpose: string; handle: string; expiresAt: number } | undefined;
    return !!row && row.purpose === purpose && row.handle === handle && row.expiresAt > now;
  }

  createSession(userId: string, ttlMs: number, now = Date.now()): string {
    const token = randomBytes(32).toString("base64url");
    this.db
      .prepare("INSERT INTO auth_sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
      .run(hashToken(token), userId, now, now + ttlMs);
    return token;
  }

  userForToken(token: string, now = Date.now()): UserRow | undefined {
    return this.db
      .prepare(
        `SELECT ${userColumns("u")}
         FROM auth_sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.expires_at > ?`,
      )
      .get(hashToken(token), now) as UserRow | undefined;
  }

  deleteSession(token: string): void {
    this.db.prepare("DELETE FROM auth_sessions WHERE token_hash = ?").run(hashToken(token));
  }

  // ------------------------------------------------------------ mailbox

  enqueue(senderId: string, recipientId: string, envelope: string, now = Date.now()): MailboxRow {
    const id = randomUUID();
    this.db
      .prepare("INSERT INTO mailbox (id, sender_id, recipient_id, envelope, created_at) VALUES (?, ?, ?, ?, ?)")
      .run(id, senderId, recipientId, envelope, now);
    return { id, senderId, envelope, createdAt: now };
  }

  mailboxSize(recipientId: string): number {
    const row = this.db.prepare("SELECT COUNT(*) AS n FROM mailbox WHERE recipient_id = ?").get(recipientId) as {
      n: number;
    };
    return row.n;
  }

  pending(recipientId: string, limit = 500): MailboxRow[] {
    return this.db
      .prepare(
        `SELECT id, sender_id AS senderId, envelope, created_at AS createdAt
         FROM mailbox WHERE recipient_id = ? ORDER BY created_at, rowid LIMIT ?`,
      )
      .all(recipientId, limit) as unknown as MailboxRow[];
  }

  /** Deletes acknowledged messages. Only the recipient can acknowledge. */
  acknowledge(recipientId: string, ids: string[]): number {
    const del = this.db.prepare("DELETE FROM mailbox WHERE id = ? AND recipient_id = ?");
    let removed = 0;
    this.transaction(() => {
      for (const id of ids) removed += Number(del.run(id, recipientId).changes);
    });
    return removed;
  }

  // ------------------------------------------------------------ housekeeping

  purgeExpired(mailboxTtlMs: number, now = Date.now()): void {
    this.db.prepare("DELETE FROM challenges WHERE expires_at <= ?").run(now);
    this.db.prepare("DELETE FROM auth_sessions WHERE expires_at <= ?").run(now);
    this.db.prepare("DELETE FROM mailbox WHERE created_at <= ?").run(now - mailboxTtlMs);
  }
}
