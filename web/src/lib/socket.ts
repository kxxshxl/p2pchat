/** WebSocket connection to the relay with authentication, keep-alive and backoff reconnects. */

import type { EnvelopeWire } from "@parley/crypto";

export type ServerMessage =
  | { t: "ready"; userId: string; iceServers: RTCIceServer[] }
  | {
      t: "message";
      id: string | null;
      from: string;
      envelope: EnvelopeWire;
      sentAt: number;
      transient?: boolean;
      queued?: boolean;
    }
  | { t: "sent"; ref: string | null; id: string | null; delivered: boolean; sentAt?: number }
  | { t: "error"; ref?: string | null; code: string; message: string }
  | { t: "presence"; userId: string; online: boolean; lastSeenAt: number | null }
  | { t: "signal"; from: string; data: unknown }
  | { t: "signal_failed"; to: string; reason: string }
  | { t: "prekeys_low"; remaining: number }
  | { t: "pong"; at: number };

export type SocketStatus = "connecting" | "online" | "offline" | "replaced";

const CLOSE_REPLACED = 4001;
const CLOSE_SIGNED_OUT = 4002;
const CLOSE_UNAUTHORIZED = 4401;
const PING_EVERY_MS = 25_000;
const PONG_TIMEOUT_MS = 10_000;

export interface SocketOptions {
  /** Returns a session token; `refresh` asks for a brand-new one (re-sign a login challenge). */
  getToken(refresh: boolean): Promise<string>;
  onMessage(message: ServerMessage): void;
  onStatus(status: SocketStatus): void;
}

export class RelaySocket {
  private readonly options: SocketOptions;
  private ws: WebSocket | null = null;
  private ready = false;
  private stopped = true;
  private attempts = 0;
  private refreshToken = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  private pingTimer: ReturnType<typeof setInterval> | undefined;
  private pongTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(options: SocketOptions) {
    this.options = options;
  }

  /** True once the socket is open *and* authenticated. */
  get connected(): boolean {
    return this.ready && this.ws?.readyState === WebSocket.OPEN;
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    void this.connect();
  }

  stop(): void {
    this.stopped = true;
    clearTimeout(this.reconnectTimer);
    this.clearKeepAlive();
    this.ws?.close(1000, "bye");
    this.ws = null;
    this.ready = false;
  }

  /** Returns false when the message could not be handed to an open socket. */
  send(message: object): boolean {
    if (!this.connected) return false;
    this.ws!.send(JSON.stringify(message));
    return true;
  }

  private async connect(): Promise<void> {
    if (this.stopped) return;
    this.options.onStatus("connecting");
    let token: string;
    try {
      token = await this.options.getToken(this.refreshToken);
      this.refreshToken = false;
    } catch {
      return this.scheduleReconnect();
    }
    if (this.stopped) return;

    const url = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/ws`;
    const ws = new WebSocket(url);
    this.ws = ws;

    ws.onopen = () => ws.send(JSON.stringify({ t: "auth", token }));
    ws.onmessage = (event) => {
      let message: ServerMessage;
      try {
        message = JSON.parse(String(event.data)) as ServerMessage;
      } catch {
        return;
      }
      if (message.t === "ready") {
        this.ready = true;
        this.attempts = 0;
        this.startKeepAlive();
        this.options.onStatus("online");
      }
      if (message.t === "pong") clearTimeout(this.pongTimer);
      this.options.onMessage(message);
    };
    ws.onclose = (event) => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.ready = false;
      this.clearKeepAlive();
      if (this.stopped) return;
      if (event.code === CLOSE_REPLACED || event.code === CLOSE_SIGNED_OUT) {
        this.stopped = true;
        this.options.onStatus("replaced");
        return;
      }
      if (event.code === CLOSE_UNAUTHORIZED) this.refreshToken = true;
      this.scheduleReconnect();
    };
  }

  private scheduleReconnect(): void {
    if (this.stopped) return;
    this.options.onStatus("offline");
    const delay = Math.min(30_000, 1000 * 2 ** this.attempts) * (0.75 + Math.random() * 0.5);
    this.attempts += 1;
    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => void this.connect(), delay);
  }

  /** Reconnect immediately (e.g. the browser just came back online). */
  nudge(): void {
    if (this.stopped || this.ws) return;
    this.attempts = 0;
    clearTimeout(this.reconnectTimer);
    void this.connect();
  }

  private startKeepAlive(): void {
    this.clearKeepAlive();
    this.pingTimer = setInterval(() => {
      if (!this.send({ t: "ping" })) return;
      clearTimeout(this.pongTimer);
      this.pongTimer = setTimeout(() => this.ws?.close(4000, "keep-alive timeout"), PONG_TIMEOUT_MS);
    }, PING_EVERY_MS);
  }

  private clearKeepAlive(): void {
    clearInterval(this.pingTimer);
    clearTimeout(this.pongTimer);
  }
}
