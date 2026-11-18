/**
 * Real-time hub (one WebSocket per signed-in user).
 *
 *  - Store-and-forward relay for encrypted envelopes when a direct peer-to-peer channel isn't
 *    available. Envelopes are opaque; they sit in the mailbox until the recipient acknowledges.
 *  - WebRTC signalling (SDP offers/answers, ICE candidates) so peers can connect directly.
 *  - Presence for the users each client has asked to watch.
 */

import { envelopeFromWire } from "@parley/crypto";
import type { WebSocket } from "ws";
import type { Config } from "./config.ts";
import { RateLimiter } from "./rate-limit.ts";
import type { Store } from "./store.ts";

const AUTH_TIMEOUT_MS = 10_000;
const HEARTBEAT_MS = 30_000;
const MAX_WATCH = 1000;
const MAX_SIGNAL_BYTES = 16 * 1024;
const MAX_ACK_IDS = 500;
const MAX_BUFFERED_BYTES = 8 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export const CLOSE_UNAUTHORIZED = 4401;
export const CLOSE_REPLACED = 4001;
export const CLOSE_SIGNED_OUT = 4002;
export const CLOSE_PROTOCOL = 4400;

type Outgoing = Record<string, unknown> & { t: string };

interface Connection {
  socket: WebSocket;
  userId: string | null;
  watching: Set<string>;
  alive: boolean;
}

export class Relay {
  private readonly store: Store;
  private readonly config: Config;
  private readonly online = new Map<string, Connection>();
  private readonly watchers = new Map<string, Set<Connection>>();
  private readonly sendLimiter = new RateLimiter(60, 20);
  private readonly signalLimiter = new RateLimiter(120, 30);
  private readonly heartbeat: NodeJS.Timeout;
  private closing = false;

  constructor(store: Store, config: Config) {
    this.store = store;
    this.config = config;
    this.heartbeat = setInterval(() => this.checkHeartbeats(), HEARTBEAT_MS);
    this.heartbeat.unref();
  }

  // ------------------------------------------------------------ public API

  isOnline(userId: string): boolean {
    return this.online.has(userId);
  }

  onlineCount(): number {
    return this.online.size;
  }

  notify(userId: string, message: Outgoing): void {
    const conn = this.online.get(userId);
    if (conn) this.send(conn, message);
  }

  disconnect(userId: string, reason: string): void {
    this.online.get(userId)?.socket.close(CLOSE_SIGNED_OUT, reason);
  }

  close(): void {
    this.closing = true;
    clearInterval(this.heartbeat);
    for (const conn of this.online.values()) conn.socket.close(1001, "server shutting down");
  }

  accept(socket: WebSocket): void {
    if (this.closing) return socket.close(1001, "server shutting down");
    const conn: Connection = { socket, userId: null, watching: new Set(), alive: true };
    const authTimer = setTimeout(() => {
      if (!conn.userId) socket.close(CLOSE_UNAUTHORIZED, "authentication timeout");
    }, AUTH_TIMEOUT_MS);

    socket.on("pong", () => {
      conn.alive = true;
    });
    socket.on("message", (data, isBinary) => {
      if (isBinary) return socket.close(CLOSE_PROTOCOL, "text frames only");
      let message: unknown;
      try {
        message = JSON.parse(data.toString());
      } catch {
        return socket.close(CLOSE_PROTOCOL, "invalid JSON");
      }
      if (!message || typeof message !== "object") return socket.close(CLOSE_PROTOCOL, "invalid message");
      try {
        this.handle(conn, message as Record<string, unknown>);
      } catch (err) {
        this.send(conn, { t: "error", code: "internal", message: (err as Error).message });
      }
    });
    socket.on("close", () => {
      clearTimeout(authTimer);
      this.drop(conn);
    });
    socket.on("error", () => socket.terminate());
  }

  // ------------------------------------------------------------ protocol

  private handle(conn: Connection, msg: Record<string, unknown>): void {
    if (!conn.userId) {
      if (msg.t !== "auth" || typeof msg.token !== "string") {
        return conn.socket.close(CLOSE_UNAUTHORIZED, "authenticate first");
      }
      return this.authenticate(conn, msg.token);
    }

    switch (msg.t) {
      case "send":
        return this.handleSend(conn, msg);
      case "ack":
        return this.handleAck(conn, msg);
      case "signal":
        return this.handleSignal(conn, msg);
      case "watch":
        return this.handleWatch(conn, msg);
      case "ping":
        return this.send(conn, { t: "pong", at: Date.now() });
      default:
        return this.send(conn, { t: "error", code: "unknown_type", message: `unknown message type` });
    }
  }

  private authenticate(conn: Connection, token: string): void {
    const user = this.store.userForToken(token);
    if (!user) return conn.socket.close(CLOSE_UNAUTHORIZED, "invalid session");

    // One live connection per account: a second tab/device takes over the first.
    const previous = this.online.get(user.id);
    if (previous) {
      this.online.delete(user.id);
      previous.socket.close(CLOSE_REPLACED, "connected elsewhere");
    }
    conn.userId = user.id;
    this.online.set(user.id, conn);
    this.store.touchUser(user.id);
    this.broadcastPresence(user.id, true);

    this.send(conn, { t: "ready", userId: user.id, iceServers: this.config.iceServers });
    for (const row of this.store.pending(user.id, this.config.mailboxLimit)) {
      this.send(conn, {
        t: "message",
        id: row.id,
        from: row.senderId,
        envelope: JSON.parse(row.envelope),
        sentAt: row.createdAt,
        queued: true,
      });
    }
  }

  private handleSend(conn: Connection, msg: Record<string, unknown>): void {
    const from = conn.userId!;
    const ref = typeof msg.ref === "string" ? msg.ref.slice(0, 64) : null;
    const fail = (code: string, message: string) => this.send(conn, { t: "error", ref, code, message });

    if (!this.sendLimiter.take(from)) return fail("rate_limited", "Sending too fast");
    if (typeof msg.to !== "string" || !UUID.test(msg.to)) return fail("bad_request", "Invalid recipient");
    if (msg.to === from) return fail("bad_request", "Cannot message yourself");
    try {
      envelopeFromWire(msg.envelope); // structural validation only; contents stay opaque
    } catch (err) {
      return fail("bad_envelope", (err as Error).message);
    }
    if (!this.store.userById(msg.to)) return fail("not_found", "Recipient does not exist");

    const envelope = JSON.stringify(msg.envelope);
    const recipient = this.online.get(msg.to);

    if (msg.transient === true) {
      // Typing indicators etc.: delivered only if the recipient is connected right now.
      if (recipient) {
        this.send(recipient, { t: "message", id: null, from, envelope: msg.envelope, sentAt: Date.now(), transient: true });
      }
      return this.send(conn, { t: "sent", ref, id: null, delivered: !!recipient });
    }

    if (this.store.mailboxSize(msg.to) >= this.config.mailboxLimit) {
      return fail("mailbox_full", "Recipient mailbox is full");
    }
    const row = this.store.enqueue(from, msg.to, envelope);
    if (recipient) {
      this.send(recipient, { t: "message", id: row.id, from, envelope: msg.envelope, sentAt: row.createdAt });
    }
    this.send(conn, { t: "sent", ref, id: row.id, delivered: !!recipient, sentAt: row.createdAt });
  }

  private handleAck(conn: Connection, msg: Record<string, unknown>): void {
    if (!Array.isArray(msg.ids)) return;
    const ids = msg.ids.filter((id): id is string => typeof id === "string").slice(0, MAX_ACK_IDS);
    this.store.acknowledge(conn.userId!, ids);
  }

  private handleSignal(conn: Connection, msg: Record<string, unknown>): void {
    const from = conn.userId!;
    if (!this.signalLimiter.take(from)) return;
    if (typeof msg.to !== "string" || !UUID.test(msg.to) || msg.to === from) return;
    if (!msg.data || typeof msg.data !== "object") return;
    if (JSON.stringify(msg.data).length > MAX_SIGNAL_BYTES) {
      return this.send(conn, { t: "error", code: "too_large", message: "Signal payload too large" });
    }
    const target = this.online.get(msg.to);
    if (!target) return this.send(conn, { t: "signal_failed", to: msg.to, reason: "offline" });
    this.send(target, { t: "signal", from, data: msg.data });
  }

  private handleWatch(conn: Connection, msg: Record<string, unknown>): void {
    if (!Array.isArray(msg.users)) return;
    const wanted = new Set(
      msg.users.filter((u): u is string => typeof u === "string" && UUID.test(u)).slice(0, MAX_WATCH),
    );
    for (const id of conn.watching) {
      if (!wanted.has(id)) this.watchers.get(id)?.delete(conn);
    }
    conn.watching = wanted;
    for (const id of wanted) {
      let set = this.watchers.get(id);
      if (!set) this.watchers.set(id, (set = new Set()));
      set.add(conn);
      const user = this.store.userById(id);
      if (user) {
        this.send(conn, { t: "presence", userId: id, online: this.online.has(id), lastSeenAt: user.lastSeenAt });
      }
    }
  }

  // ------------------------------------------------------------ plumbing

  private drop(conn: Connection): void {
    for (const id of conn.watching) {
      const set = this.watchers.get(id);
      set?.delete(conn);
      if (set?.size === 0) this.watchers.delete(id);
    }
    const userId = conn.userId;
    if (userId && this.online.get(userId) === conn) {
      this.online.delete(userId);
      if (this.closing) return; // store is shutting down; nobody left to notify
      this.store.touchUser(userId);
      this.broadcastPresence(userId, false);
    }
  }

  private broadcastPresence(userId: string, online: boolean): void {
    const set = this.watchers.get(userId);
    if (!set) return;
    const message = { t: "presence", userId, online, lastSeenAt: Date.now() };
    for (const watcher of set) this.send(watcher, message);
  }

  private send(conn: Connection, message: Outgoing): void {
    if (conn.socket.readyState !== conn.socket.OPEN) return;
    if (conn.socket.bufferedAmount > MAX_BUFFERED_BYTES) {
      conn.socket.terminate(); // slow consumer; it will resync from the mailbox on reconnect
      return;
    }
    conn.socket.send(JSON.stringify(message));
  }

  private checkHeartbeats(): void {
    for (const conn of this.online.values()) {
      if (!conn.alive) {
        conn.socket.terminate();
        continue;
      }
      conn.alive = false;
      conn.socket.ping();
    }
  }
}
