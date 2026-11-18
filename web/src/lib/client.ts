/**
 * ChatClient: everything between the UI and the network.
 *
 *   UI ──► ChatClient ──► Double Ratchet (per peer, serialised by a mutex)
 *                   │            │
 *                   │            └─► Vault (encrypted IndexedDB, atomic multi-record writes)
 *                   ├─► PeerLinks  (WebRTC data channel, preferred when open)
 *                   └─► RelaySocket (store-and-forward fallback + signalling + presence)
 *
 * Invariants:
 *  - A ratchet step is persisted (with the message it produced) before anything is sent,
 *    so a crash can never cause a message key to be reused.
 *  - Incoming relay messages are acknowledged only after the decrypted result is persisted.
 *  - The server is never trusted with key authenticity: identity keys are pinned on first
 *    contact and any change blocks sending until the user acknowledges it.
 */

import {
  addSession,
  bundleFromWire,
  decryptMessage,
  encryptMessage,
  envelopeFromWire,
  envelopeToWire,
  fromBase64,
  fromUtf8,
  keyId,
  safetyNumber,
  sha256,
  signChallenge,
  startSession,
  toBase64,
  toHex,
  utf8,
  concat,
  type EnvelopeWire,
  type PreKeyBundle,
  type PublicIdentity,
  type SessionRecord,
} from "@parley/crypto";
import { ApiError, type Api, type UserIdentity } from "./api";
import { maintainKeys, preKeyStore, withoutOneTimePreKey, type KeyMaterial } from "./keys";
import { PeerLinks, type LinkFrame, type LinkState, type Signal } from "./p2p";
import { RelaySocket, type ServerMessage, type SocketStatus } from "./socket";
import {
  DEFAULT_SETTINGS,
  MAX_MESSAGE_LENGTH,
  parsePayload,
  type Account,
  type ChatMessage,
  type Contact,
  type CryptoMeta,
  type MessageStatus,
  type Payload,
  type Settings,
  type Transport,
} from "./types";
import { KeyedMutex, Observable, uuid } from "./util";
import type { Vault } from "./vault";

const MAX_STORED_MESSAGES = 1000;
const MAX_SEEN_DIGESTS = 2000;
const TYPING_RESEND_MS = 3000;
const TYPING_EXPIRE_MS = 6000;

export interface SessionSummary {
  id: string;
  role: "initiator" | "responder";
  sessionCount: number;
  sendCount: number;
  receiveCount: number;
  previousSendCount: number;
  skippedKeys: number;
  localRatchetKey: string;
  remoteRatchetKey: string | null;
  awaitingReply: boolean;
  createdAt: number;
  lastUsedAt: number;
}

export interface KeyHealth {
  localOneTime: number;
  serverOneTime: number;
  signedPreKeyId: number;
  signedPreKeyCreatedAt: number;
}

export interface ClientState {
  account: Account;
  connection: SocketStatus;
  authError: string | null;
  contacts: Contact[];
  messages: Record<string, ChatMessage[]>;
  presence: Record<string, { online: boolean; lastSeenAt: number | null }>;
  typing: Record<string, boolean>;
  links: Record<string, LinkState>;
  sessions: Record<string, SessionSummary>;
  settings: Settings;
  keyHealth: KeyHealth | null;
  activePeer: string | null;
}

const STATUS_RANK: Record<MessageStatus, number> = { failed: 0, pending: 1, sent: 2, delivered: 3, read: 4 };

function summarize(record: SessionRecord | null | undefined): SessionSummary | undefined {
  const s = record?.sessions[0];
  if (!s) return undefined;
  return {
    id: s.id.slice(0, 16),
    role: s.role,
    sessionCount: record!.sessions.length,
    sendCount: s.ratchet.sendCount,
    receiveCount: s.ratchet.receiveCount,
    previousSendCount: s.ratchet.previousSendCount,
    skippedKeys: s.ratchet.skipped.length,
    localRatchetKey: keyId(s.ratchet.sendingKeyPair.publicKey),
    remoteRatchetKey: s.ratchet.remoteKey ? keyId(s.ratchet.remoteKey) : null,
    awaitingReply: s.pendingPreKey !== null,
    createdAt: s.createdAt,
    lastUsedAt: s.lastUsedAt,
  };
}

function sameIdentity(contact: Contact, identity: PublicIdentity): boolean {
  return contact.signingKey === toBase64(identity.signingKey) && contact.identityKey === toBase64(identity.identityKey);
}

export interface ClientInit {
  api: Api;
  vault: Vault;
  account: Account;
  keys: KeyMaterial;
  token?: string | null;
}

export class ChatClient {
  readonly store: Observable<ClientState>;
  private readonly api: Api;
  private readonly vault: Vault;
  private keys: KeyMaterial;
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly mutex = new KeyedMutex();
  private readonly socket: RelaySocket;
  private readonly links: PeerLinks;
  private iceServers: RTCIceServer[] = [];
  /** Digests of recently processed envelopes: makes redelivery (relay or resend) idempotent. */
  private seenDigests: string[] = [];
  /** relay `ref` → message awaiting the server's "sent" confirmation */
  private readonly pendingRefs = new Map<string, { peerId: string; messageId: string | null }>();
  private readonly typingSentAt = new Map<string, number>();
  private readonly typingTimers = new Map<string, ReturnType<typeof setTimeout>>();
  private stopped = false;

  constructor(init: ClientInit) {
    this.api = init.api;
    this.vault = init.vault;
    this.keys = init.keys;
    if (init.token) this.api.token = init.token;
    this.store = new Observable<ClientState>({
      account: init.account,
      connection: "connecting",
      authError: null,
      contacts: [],
      messages: {},
      presence: {},
      typing: {},
      links: {},
      sessions: {},
      settings: DEFAULT_SETTINGS,
      keyHealth: null,
      activePeer: null,
    });
    this.socket = new RelaySocket({
      getToken: (refresh) => this.ensureToken(refresh),
      onMessage: (message) => void this.onServerMessage(message),
      onStatus: (connection) => this.patch({ connection }),
    });
    this.links = new PeerLinks({
      selfId: init.account.userId,
      iceServers: () => this.iceServers,
      sendSignal: (peerId, signal) => this.socket.send({ t: "signal", to: peerId, data: signal }),
      onFrame: (peerId, frame) => void this.onLinkFrame(peerId, frame),
      onState: (peerId, state) => this.onLinkState(peerId, state),
    });
  }

  get state(): ClientState {
    return this.store.state;
  }

  private patch(partial: Partial<ClientState>): void {
    this.store.update((s) => ({ ...s, ...partial }));
  }

  // ================================================================ lifecycle

  async start(): Promise<void> {
    const [contacts, settings, seen] = await Promise.all([
      this.vault.get<Contact[]>("contacts"),
      this.vault.get<Settings>("settings"),
      this.vault.get<string[]>("seen"),
    ]);
    this.seenDigests = seen ?? [];
    const messages: Record<string, ChatMessage[]> = {};
    const summaries: Record<string, SessionSummary> = {};
    for (const contact of contacts ?? []) {
      const [history, record] = await Promise.all([
        this.vault.get<ChatMessage[]>(`messages:${contact.id}`),
        this.vault.get<SessionRecord>(`session:${contact.id}`),
      ]);
      messages[contact.id] = history ?? [];
      if (record) {
        this.sessions.set(contact.id, record);
        const summary = summarize(record);
        if (summary) summaries[contact.id] = summary;
      }
    }
    this.patch({
      contacts: contacts ?? [],
      settings: { ...DEFAULT_SETTINGS, ...settings },
      messages,
      sessions: summaries,
    });
    this.socket.start();
    window.addEventListener("online", this.onBrowserOnline);
    document.addEventListener("visibilitychange", this.onVisibility);
  }

  stop(): void {
    this.stopped = true;
    this.socket.stop();
    this.links.closeAll();
    window.removeEventListener("online", this.onBrowserOnline);
    document.removeEventListener("visibilitychange", this.onVisibility);
  }

  private onBrowserOnline = () => this.socket.nudge();
  private onVisibility = () => {
    if (document.visibilityState === "visible" && this.state.activePeer) void this.markRead(this.state.activePeer);
  };

  /** Session tokens live only in memory; signing in again is just another challenge signature. */
  private async ensureToken(refresh: boolean): Promise<string> {
    if (this.api.token && !refresh) return this.api.token;
    const { handle } = this.state.account;
    try {
      const { challenge } = await this.api.challenge("login", handle);
      const signature = signChallenge(this.keys.identity.signing, "login", handle, challenge);
      const { token } = await this.api.login(handle, challenge, toBase64(signature));
      this.api.token = token;
      this.patch({ authError: null });
      return token;
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        this.patch({ authError: "The server no longer recognises this account." });
      }
      throw err;
    }
  }

  async signOut(): Promise<void> {
    try {
      await this.api.logout();
    } catch {
      /* best effort */
    }
    this.api.token = null;
    this.stop();
  }

  // ================================================================ server events

  private async onServerMessage(message: ServerMessage): Promise<void> {
    switch (message.t) {
      case "ready":
        this.iceServers = message.iceServers ?? [];
        this.pendingRefs.clear(); // anything unconfirmed on the old connection gets resent
        this.watchContacts();
        void this.refreshKeys();
        void this.flushOutbox();
        return;
      case "message":
        return this.receive(message.from, message.envelope, {
          relayId: message.id,
          transport: "relay",
          transient: !!message.transient,
        });
      case "sent":
        return this.onRelaySent(message.ref, true);
      case "error":
        if (message.ref) this.onRelaySent(message.ref, false, message.message);
        return;
      case "presence":
        return this.onPresence(message.userId, message.online, message.lastSeenAt);
      case "signal":
        return this.onSignal(message.from, message.data as Signal);
      case "prekeys_low":
        void this.refreshKeys();
        return;
      default:
        return;
    }
  }

  private watchContacts(): void {
    this.socket.send({ t: "watch", users: this.state.contacts.map((c) => c.id) });
  }

  private onPresence(userId: string, online: boolean, lastSeenAt: number | null): void {
    this.store.update((s) => ({ ...s, presence: { ...s.presence, [userId]: { online, lastSeenAt } } }));
    if (!online) {
      this.links.close(userId, false);
      this.showTyping(userId, false);
    } else if (userId === this.state.activePeer) {
      this.maybeDial(userId);
    }
  }

  private async refreshKeys(): Promise<void> {
    try {
      const { keys, status } = await this.mutex.run("__keys", () =>
        maintainKeys(this.api, this.keys, async (next) => {
          this.keys = next;
          await this.vault.put("keys", next);
        }),
      );
      this.keys = keys;
      const spk = keys.signedPreKeys[keys.signedPreKeys.length - 1]!;
      this.patch({
        keyHealth: {
          localOneTime: keys.oneTimePreKeys.length,
          serverOneTime: status.oneTimePreKeys,
          signedPreKeyId: spk.id,
          signedPreKeyCreatedAt: spk.createdAt,
        },
      });
    } catch {
      /* retried on next connect */
    }
  }

  // ================================================================ direct links

  private maybeDial(peerId: string): void {
    if (this.state.settings.relayOnly || !this.state.presence[peerId]?.online) return;
    if (!this.contact(peerId)) return;
    this.links.connect(peerId);
  }

  private onSignal(from: string, signal: Signal): void {
    // Only people already in your contacts may open a direct link (it reveals your IP address).
    if (this.state.settings.relayOnly || !this.contact(from)) {
      if (signal?.kind === "description") this.socket.send({ t: "signal", to: from, data: { kind: "bye" } });
      return;
    }
    void this.links.handleSignal(from, signal);
  }

  private onLinkState(peerId: string, state: LinkState | null): void {
    this.store.update((s) => {
      const links = { ...s.links };
      if (state) links[peerId] = state;
      else delete links[peerId];
      return { ...s, links };
    });
    if (state === "open") void this.flushOutbox(peerId);
  }

  private onLinkFrame(peerId: string, frame: LinkFrame): void {
    void this.receive(peerId, frame.envelope as EnvelopeWire, {
      relayId: null,
      transport: "p2p",
      transient: !!frame.transient,
    });
  }

  // ================================================================ contacts

  contact(peerId: string): Contact | undefined {
    return this.state.contacts.find((c) => c.id === peerId);
  }

  private upsertContact(contact: Contact): Contact[] {
    const others = this.state.contacts.filter((c) => c.id !== contact.id);
    const contacts = [contact, ...others].sort((a, b) => b.lastActivityAt - a.lastActivityAt);
    this.patch({ contacts });
    return contacts;
  }

  private contactFromDirectory(user: UserIdentity): Contact {
    const now = Date.now();
    return {
      id: user.id,
      handle: user.handle,
      displayName: user.displayName,
      signingKey: user.signingKey,
      identityKey: user.identityKey,
      verified: false,
      keyChangedAt: null,
      addedAt: now,
      lastActivityAt: now,
      unread: 0,
    };
  }

  /** Adds someone by handle (trust on first use: their keys are pinned now). */
  async addContactByHandle(handle: string): Promise<Contact> {
    const normalized = handle.trim().replace(/^@/, "").toLowerCase();
    if (normalized === this.state.account.handle) throw new Error("That's you!");
    const existing = this.state.contacts.find((c) => c.handle === normalized);
    if (existing) return existing;
    const user = await this.api.userByHandle(normalized);
    return this.mutex.run(user.id, async () => {
      const already = this.contact(user.id);
      if (already) return already;
      const contact = this.contactFromDirectory(user);
      const contacts = this.upsertContact(contact);
      this.store.update((s) => ({ ...s, messages: { ...s.messages, [contact.id]: s.messages[contact.id] ?? [] } }));
      await this.vault.write({ contacts, [`messages:${contact.id}`]: this.state.messages[contact.id] ?? [] });
      this.watchContacts();
      return contact;
    });
  }

  async searchUsers(query: string) {
    const q = query.trim().replace(/^@/, "").toLowerCase();
    if (!/^[a-z0-9_]{1,24}$/.test(q)) return [];
    return this.api.searchUsers(q);
  }

  /** Must be called inside the peer's mutex. */
  private async ensureContact(peerId: string): Promise<Contact> {
    const known = this.contact(peerId);
    if (known) return known;
    const contact = this.contactFromDirectory(await this.api.user(peerId));
    const contacts = this.upsertContact(contact);
    await this.vault.put("contacts", contacts);
    this.watchContacts();
    return contact;
  }

  /**
   * Compare a peer's identity with the pinned one. A mismatch means either the person
   * reinstalled or someone (possibly the server) is substituting keys; either way the user
   * must re-verify before we send anything else.
   */
  private checkIdentity(contact: Contact, identity: PublicIdentity, messages: ChatMessage[]) {
    if (sameIdentity(contact, identity)) return { contact, messages, changed: false };
    const updated: Contact = {
      ...contact,
      signingKey: toBase64(identity.signingKey),
      identityKey: toBase64(identity.identityKey),
      verified: false,
      keyChangedAt: Date.now(),
    };
    const notice = this.systemMessage(
      `${contact.displayName}'s safety number changed. Verify it before trusting new messages.`,
    );
    return { contact: updated, messages: [...messages, notice], changed: true };
  }

  async acknowledgeKeyChange(peerId: string): Promise<void> {
    await this.mutex.run(peerId, async () => {
      const contact = this.contact(peerId);
      if (!contact) return;
      const contacts = this.upsertContact({ ...contact, keyChangedAt: null });
      await this.vault.put("contacts", contacts);
    });
  }

  async setVerified(peerId: string, verified: boolean): Promise<void> {
    await this.mutex.run(peerId, async () => {
      const contact = this.contact(peerId);
      if (!contact) return;
      const contacts = this.upsertContact({ ...contact, verified, keyChangedAt: verified ? null : contact.keyChangedAt });
      const messages = [
        ...(this.state.messages[peerId] ?? []),
        this.systemMessage(verified ? `You marked ${contact.displayName} as verified.` : `You removed verification for ${contact.displayName}.`),
      ];
      this.setMessages(peerId, messages);
      await this.vault.write({ contacts, [`messages:${peerId}`]: messages });
    });
  }

  safetyNumberWith(peerId: string): string | null {
    const contact = this.contact(peerId);
    if (!contact) return null;
    return safetyNumber(
      {
        userId: this.state.account.userId,
        signingKey: this.keys.identity.signing.publicKey,
        identityKey: this.keys.identity.dh.publicKey,
      },
      { userId: contact.id, signingKey: fromBase64(contact.signingKey), identityKey: fromBase64(contact.identityKey) },
    );
  }

  ownKeyId(): string {
    return keyId(this.keys.identity.signing.publicKey);
  }

  // ================================================================ conversations

  openConversation(peerId: string | null): void {
    this.patch({ activePeer: peerId });
    if (!peerId) return;
    this.maybeDial(peerId);
    void this.markRead(peerId);
  }

  private setMessages(peerId: string, messages: ChatMessage[]): void {
    this.store.update((s) => ({ ...s, messages: { ...s.messages, [peerId]: messages.slice(-MAX_STORED_MESSAGES) } }));
  }

  private systemMessage(body: string): ChatMessage {
    const now = Date.now();
    return { id: uuid(), kind: "system", direction: "in", body, sentAt: now, receivedAt: now };
  }

  async clearHistory(peerId: string): Promise<void> {
    await this.mutex.run(peerId, async () => {
      this.setMessages(peerId, []);
      await this.vault.put(`messages:${peerId}`, []);
    });
  }

  // ================================================================ sending

  async sendText(peerId: string, text: string): Promise<void> {
    const body = text.trim();
    if (!body) return;
    if (body.length > MAX_MESSAGE_LENGTH) throw new Error(`Messages are limited to ${MAX_MESSAGE_LENGTH} characters`);
    const message: ChatMessage = {
      id: uuid(),
      kind: "text",
      direction: "out",
      body,
      sentAt: Date.now(),
      status: "pending",
    };
    this.setMessages(peerId, [...(this.state.messages[peerId] ?? []), message]);
    this.typingSentAt.delete(peerId);
    await this.deliver(peerId, message);
  }

  async retry(peerId: string, messageId: string): Promise<void> {
    const message = this.state.messages[peerId]?.find((m) => m.id === messageId);
    if (!message || message.status !== "failed") return;
    await this.deliver(peerId, { ...message, status: "pending", error: undefined, outbox: undefined });
  }

  private async deliver(peerId: string, message: ChatMessage): Promise<void> {
    let prepared: ChatMessage;
    try {
      prepared = await this.mutex.run(peerId, async () => {
        const contact = this.contact(peerId);
        if (contact?.keyChangedAt) {
          throw new Error("Safety number changed: review it before sending");
        }
        const payload: Payload = { k: "text", id: message.id, body: message.body, ts: message.sentAt };
        const { envelope, meta, record } = await this.encryptFor(peerId, payload);
        const updated: ChatMessage = { ...message, crypto: meta, outbox: envelope, status: "pending" };
        const messages = this.replaceMessage(peerId, updated);
        const touched = this.touchContact(peerId);
        await this.vault.write({
          [`session:${peerId}`]: record,
          [`messages:${peerId}`]: messages,
          ...(touched ? { contacts: touched } : {}),
        });
        this.commitSession(peerId, record);
        this.setMessages(peerId, messages);
        return updated;
      });
    } catch (err) {
      const failed = { ...message, status: "failed" as const, error: (err as Error).message };
      this.setMessages(peerId, this.replaceMessage(peerId, failed));
      await this.vault.put(`messages:${peerId}`, this.state.messages[peerId]);
      return;
    }
    this.transmit(peerId, prepared);
  }

  /** Must run inside the peer's mutex. Persisting `record` is the caller's job. */
  private async encryptFor(peerId: string, payload: Payload) {
    let record = this.sessions.get(peerId) ?? null;
    if (!record || record.sessions.length === 0) {
      const contact = await this.ensureContact(peerId);
      const bundle: PreKeyBundle = bundleFromWire(await this.api.bundle(peerId));
      if (!sameIdentity(contact, bundle)) {
        const check = this.checkIdentity(contact, bundle, this.state.messages[peerId] ?? []);
        const contacts = this.upsertContact(check.contact);
        this.setMessages(peerId, check.messages);
        await this.vault.write({ contacts, [`messages:${peerId}`]: check.messages });
        throw new Error("Safety number changed: review it before sending");
      }
      record = addSession(null, startSession(this.keys.identity, bundle));
    }
    const result = encryptMessage(record, utf8(JSON.stringify(payload)));
    const envelope = envelopeToWire(result.envelope);
    const meta: CryptoMeta = {
      sessionId: result.session.id.slice(0, 16),
      ratchetKey: keyId(result.header.publicKey),
      counter: result.header.count,
      previousCounter: result.header.previousCount,
      preKey: !!result.envelope.preKey,
      ciphertextBytes: result.envelope.ciphertext.length,
    };
    return { envelope, meta, record: result.record };
  }

  private commitSession(peerId: string, record: SessionRecord): void {
    this.sessions.set(peerId, record);
    const summary = summarize(record);
    this.store.update((s) => {
      const sessions = { ...s.sessions };
      if (summary) sessions[peerId] = summary;
      return { ...s, sessions };
    });
  }

  private replaceMessage(peerId: string, message: ChatMessage): ChatMessage[] {
    const list = this.state.messages[peerId] ?? [];
    const index = list.findIndex((m) => m.id === message.id);
    if (index === -1) return [...list, message].slice(-MAX_STORED_MESSAGES);
    const next = list.slice();
    next[index] = message;
    return next;
  }

  private touchContact(peerId: string, unreadDelta = 0): Contact[] | null {
    const contact = this.contact(peerId);
    if (!contact) return null;
    return this.upsertContact({
      ...contact,
      lastActivityAt: Date.now(),
      unread: unreadDelta === 0 ? contact.unread : contact.unread + unreadDelta,
    });
  }

  /** Hand an encrypted envelope to the best available transport. */
  private transmit(peerId: string, message: ChatMessage): void {
    if (!message.outbox) return;
    if (!this.state.settings.relayOnly && this.links.send(peerId, { t: "env", envelope: message.outbox })) {
      void this.markSent(peerId, message.id, "p2p");
      return;
    }
    const ref = uuid();
    if (this.socket.send({ t: "send", ref, to: peerId, envelope: message.outbox })) {
      this.pendingRefs.set(ref, { peerId, messageId: message.id });
    }
    // otherwise it stays in the outbox until we reconnect
  }

  private async flushOutbox(onlyPeer?: string): Promise<void> {
    for (const [peerId, list] of Object.entries(this.state.messages)) {
      if (onlyPeer && peerId !== onlyPeer) continue;
      for (const message of list) {
        if (message.status === "pending" && message.outbox && ![...this.pendingRefs.values()].some((p) => p.messageId === message.id)) {
          this.transmit(peerId, message);
        }
      }
    }
  }

  private onRelaySent(ref: string | null, ok: boolean, error?: string): void {
    if (!ref) return;
    const pending = this.pendingRefs.get(ref);
    if (!pending) return;
    this.pendingRefs.delete(ref);
    if (!pending.messageId) return;
    if (ok) void this.markSent(pending.peerId, pending.messageId, "relay");
    else void this.markFailed(pending.peerId, pending.messageId, error ?? "Relay rejected the message");
  }

  private async markSent(peerId: string, messageId: string, transport: Transport): Promise<void> {
    await this.mutex.run(peerId, async () => {
      const message = this.state.messages[peerId]?.find((m) => m.id === messageId);
      if (!message) return;
      const updated: ChatMessage = {
        ...message,
        outbox: undefined,
        transport,
        status: STATUS_RANK[message.status ?? "pending"] >= STATUS_RANK.sent ? message.status : "sent",
      };
      const messages = this.replaceMessage(peerId, updated);
      this.setMessages(peerId, messages);
      await this.vault.put(`messages:${peerId}`, messages);
    });
  }

  private async markFailed(peerId: string, messageId: string, error: string): Promise<void> {
    await this.mutex.run(peerId, async () => {
      const message = this.state.messages[peerId]?.find((m) => m.id === messageId);
      if (!message) return;
      const messages = this.replaceMessage(peerId, { ...message, outbox: undefined, status: "failed", error });
      this.setMessages(peerId, messages);
      await this.vault.put(`messages:${peerId}`, messages);
    });
  }

  /** Receipts and typing indicators: encrypted like everything else, but not shown as messages. */
  private async sendControl(peerId: string, payload: Payload, transient: boolean): Promise<void> {
    let envelope: EnvelopeWire;
    try {
      envelope = await this.mutex.run(peerId, async () => {
        if (this.contact(peerId)?.keyChangedAt) throw new Error("identity unverified");
        const result = await this.encryptFor(peerId, payload);
        await this.vault.put(`session:${peerId}`, result.record);
        this.commitSession(peerId, result.record);
        return result.envelope;
      });
    } catch {
      return;
    }
    if (!this.state.settings.relayOnly && this.links.send(peerId, { t: "env", envelope, transient })) return;
    this.socket.send({ t: "send", ref: uuid(), to: peerId, envelope, transient });
  }

  setTyping(peerId: string, on: boolean): void {
    if (!this.state.settings.typingIndicators || !this.state.presence[peerId]?.online) return;
    if (!this.sessions.get(peerId)) return; // don't create a session just to say "typing"
    const last = this.typingSentAt.get(peerId);
    if (on && last && Date.now() - last < TYPING_RESEND_MS) return;
    if (!on && !last) return;
    if (on) this.typingSentAt.set(peerId, Date.now());
    else this.typingSentAt.delete(peerId);
    void this.sendControl(peerId, { k: "typing", on }, true);
  }

  private showTyping(peerId: string, on: boolean): void {
    clearTimeout(this.typingTimers.get(peerId));
    if (on) this.typingTimers.set(peerId, setTimeout(() => this.showTyping(peerId, false), TYPING_EXPIRE_MS));
    this.store.update((s) => ({ ...s, typing: { ...s.typing, [peerId]: on } }));
  }

  private async markRead(peerId: string): Promise<void> {
    if (document.visibilityState !== "visible") return;
    const ids = await this.mutex.run(peerId, async () => {
      const list = this.state.messages[peerId] ?? [];
      const unread = list.filter((m) => m.kind === "text" && m.direction === "in" && m.receipt !== "read");
      const contact = this.contact(peerId);
      if (unread.length === 0 && !contact?.unread) return [];
      const ids = new Set(unread.map((m) => m.id));
      const messages = list.map((m) => (ids.has(m.id) ? { ...m, receipt: "read" as const } : m));
      const contacts = contact ? this.upsertContact({ ...contact, unread: 0 }) : this.state.contacts;
      this.setMessages(peerId, messages);
      await this.vault.write({ contacts, [`messages:${peerId}`]: messages });
      return [...ids];
    });
    if (ids.length && this.state.settings.readReceipts) {
      await this.sendControl(peerId, { k: "receipt", status: "read", ids }, false);
    }
  }

  // ================================================================ receiving

  private async receive(
    from: string,
    wire: EnvelopeWire,
    opts: { relayId: string | null; transport: Transport; transient: boolean },
  ): Promise<void> {
    if (this.stopped) return;
    let envelope;
    try {
      envelope = envelopeFromWire(wire);
    } catch {
      if (opts.relayId) this.socket.send({ t: "ack", ids: [opts.relayId] }); // malformed: drop it
      return;
    }
    const digest = toHex(sha256(concat(envelope.header, envelope.ciphertext)).slice(0, 16));

    const followUp = await this.mutex.run(from, async () => {
      if (this.seenDigests.includes(digest)) {
        return { ack: true } as const; // duplicate delivery (dropped ack, or resent after reconnect)
      }
      let contact: Contact;
      try {
        contact = await this.ensureContact(from);
      } catch {
        return { ack: false } as const; // can't look the sender up right now; retry on reconnect
      }

      let messages = this.state.messages[from] ?? [];
      const writes: Record<string, unknown> = {};
      let result;
      try {
        result = decryptMessage(this.sessions.get(from) ?? null, envelope, preKeyStore(this.keys));
      } catch (err) {
        if (opts.transient) return { ack: false } as const;
        messages = [...messages, this.systemMessage(`A message from ${contact.displayName} could not be decrypted (${(err as Error).message}).`)];
        this.setMessages(from, messages);
        writes[`messages:${from}`] = messages;
        this.rememberDigest(digest, writes);
        await this.vault.write(writes);
        return { ack: true } as const;
      }

      if (result.newSession) {
        const check = this.checkIdentity(contact, result.session.remote, messages);
        contact = check.contact;
        messages = check.messages;
      }
      if (result.usedOneTimePreKeyId !== undefined) {
        this.keys = withoutOneTimePreKey(this.keys, result.usedOneTimePreKeyId);
        writes.keys = this.keys;
      }
      writes[`session:${from}`] = result.record;

      const payload = parsePayload(fromUtf8(result.plaintext));
      let receipt: "delivered" | "read" | null = null;
      let unreadDelta = 0;
      if (payload?.k === "text") {
        if (!messages.some((m) => m.id === payload.id)) {
          const visible = this.state.activePeer === from && document.visibilityState === "visible";
          receipt = visible ? "read" : "delivered";
          unreadDelta = visible ? 0 : 1;
          messages = [
            ...messages,
            {
              id: payload.id,
              kind: "text",
              direction: "in",
              body: payload.body,
              sentAt: Math.min(payload.ts, Date.now()),
              receivedAt: Date.now(),
              transport: opts.transport,
              receipt,
              crypto: {
                sessionId: result.session.id.slice(0, 16),
                ratchetKey: keyId(result.header.publicKey),
                counter: result.header.count,
                previousCounter: result.header.previousCount,
                preKey: !!wire.preKey,
                ciphertextBytes: envelope.ciphertext.length,
                newSession: result.newSession,
              },
            },
          ];
        }
        this.showTyping(from, false);
      } else if (payload?.k === "receipt") {
        const ids = new Set(payload.ids);
        messages = messages.map((m) =>
          m.direction === "out" && ids.has(m.id) && STATUS_RANK[payload.status] > STATUS_RANK[m.status ?? "pending"]
            ? { ...m, status: payload.status, outbox: undefined }
            : m,
        );
      } else if (payload?.k === "typing") {
        this.showTyping(from, payload.on);
      }

      const contacts = this.upsertContact({
        ...contact,
        lastActivityAt: payload?.k === "text" ? Date.now() : contact.lastActivityAt,
        unread: contact.unread + unreadDelta,
      });
      writes.contacts = contacts;
      writes[`messages:${from}`] = messages.slice(-MAX_STORED_MESSAGES);
      if (!opts.transient) this.rememberDigest(digest, writes);

      await this.vault.write(writes); // persist before acknowledging
      this.commitSession(from, result.record);
      this.setMessages(from, messages);
      return { ack: true, receipt, id: payload?.k === "text" ? payload.id : null } as const;
    });

    if (followUp.ack && opts.relayId) this.socket.send({ t: "ack", ids: [opts.relayId] });
    if ("receipt" in followUp && followUp.receipt && followUp.id) {
      const status = followUp.receipt === "read" && !this.state.settings.readReceipts ? "delivered" : followUp.receipt;
      await this.sendControl(from, { k: "receipt", status, ids: [followUp.id] }, false);
    }
    if (opts.transport === "relay" && this.state.activePeer === from) this.maybeDial(from);
  }

  private rememberDigest(digest: string, writes: Record<string, unknown>): void {
    this.seenDigests = [...this.seenDigests, digest].slice(-MAX_SEEN_DIGESTS);
    writes.seen = this.seenDigests;
  }

  // ================================================================ settings

  async updateSettings(patch: Partial<Settings>): Promise<void> {
    const settings = { ...this.state.settings, ...patch };
    this.patch({ settings });
    await this.vault.put("settings", settings);
    if (settings.relayOnly) this.links.closeAll();
    else if (this.state.activePeer) this.maybeDial(this.state.activePeer);
  }
}
