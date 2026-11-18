import {
  addSession,
  bundleFromWire,
  encryptMessage,
  envelopeToWire,
  generateIdentity,
  generateOneTimePreKeys,
  generateSignedPreKey,
  oneTimePreKeyToWire,
  signChallenge,
  signedPreKeyToWire,
  startSession,
  toBase64,
  utf8,
  type Identity,
} from "@parley/crypto";
import { WebSocket } from "ws";
import { buildApp } from "../src/app.ts";
import { loadConfig, type Config } from "../src/config.ts";

export async function startServer(overrides: Partial<Config> = {}) {
  const config = loadConfig({ databasePath: ":memory:", logLevel: "silent", host: "127.0.0.1", port: 0, ...overrides });
  const { app, ctx } = await buildApp(config);
  await app.listen({ host: "127.0.0.1", port: 0 });
  const address = app.server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return { app, ctx, base: `http://127.0.0.1:${port}`, wsUrl: `ws://127.0.0.1:${port}/api/ws` };
}

export type Server = Awaited<ReturnType<typeof startServer>>;

export interface TestAccount {
  id: string;
  handle: string;
  token: string;
  identity: Identity;
}

export async function api<T = any>(
  server: Server,
  method: string,
  path: string,
  body?: unknown,
  token?: string,
): Promise<{ status: number; body: T }> {
  const res = await server.app.inject({
    method: method as "GET",
    url: path,
    headers: token ? { authorization: `Bearer ${token}` } : {},
    ...(body === undefined ? {} : { payload: body as object }),
  });
  return { status: res.statusCode, body: res.body ? (res.json() as T) : (undefined as T) };
}

export async function register(server: Server, handle: string, opkCount = 5): Promise<TestAccount> {
  const identity = generateIdentity();
  const { body } = await api(server, "POST", "/api/auth/challenge", { purpose: "register", handle });
  const res = await api(server, "POST", "/api/auth/register", {
    handle,
    displayName: handle.toUpperCase(),
    challenge: body.challenge,
    signature: toBase64(signChallenge(identity.signing, "register", handle, body.challenge)),
    signingKey: toBase64(identity.signing.publicKey),
    identityKey: toBase64(identity.dh.publicKey),
    identityKeySignature: toBase64(identity.dhSignature),
    signedPreKey: signedPreKeyToWire(generateSignedPreKey(identity, 1)),
    oneTimePreKeys: generateOneTimePreKeys(1, opkCount).map(oneTimePreKeyToWire),
  });
  if (res.status !== 201) throw new Error(`register failed: ${JSON.stringify(res.body)}`);
  return { id: res.body.user.id, handle, token: res.body.token, identity };
}

/** A real encrypted envelope from `from` to `to`, built the way the browser client does. */
export async function envelopeFor(server: Server, from: TestAccount, to: TestAccount, text = "hi") {
  const bundle = await api(server, "GET", `/api/users/${to.id}/bundle`, undefined, from.token);
  const record = addSession(null, startSession(from.identity, bundleFromWire(bundle.body)));
  return envelopeToWire(encryptMessage(record, utf8(text)).envelope);
}

/** WebSocket client that queues incoming messages so tests can await them in order. */
export class Socket {
  readonly ws: WebSocket;
  private readonly queue: any[] = [];
  private readonly waiters: ((m: any) => void)[] = [];
  closed: Promise<{ code: number; reason: string }>;

  constructor(url: string) {
    this.ws = new WebSocket(url);
    this.ws.on("message", (data) => {
      const msg = JSON.parse(data.toString());
      const waiter = this.waiters.shift();
      if (waiter) waiter(msg);
      else this.queue.push(msg);
    });
    this.closed = new Promise((resolve) =>
      this.ws.on("close", (code, reason) => resolve({ code, reason: reason.toString() })),
    );
  }

  static async connect(server: Server, token?: string): Promise<Socket> {
    const socket = new Socket(server.wsUrl);
    await new Promise((resolve, reject) => {
      socket.ws.once("open", resolve);
      socket.ws.once("error", reject);
    });
    if (token) {
      socket.send({ t: "auth", token });
      const ready = await socket.next();
      if (ready.t !== "ready") throw new Error(`expected ready, got ${JSON.stringify(ready)}`);
    }
    return socket;
  }

  send(message: unknown): void {
    this.ws.send(JSON.stringify(message));
  }

  next(timeoutMs = 2000): Promise<any> {
    const queued = this.queue.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timed out waiting for message")), timeoutMs);
      this.waiters.push((m) => {
        clearTimeout(timer);
        resolve(m);
      });
    });
  }

  /** Waits for the next message of a given type, discarding others. */
  async nextOf(type: string, timeoutMs = 2000): Promise<any> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const msg = await this.next(Math.max(1, deadline - Date.now()));
      if (msg.t === type) return msg;
    }
  }

  close(): void {
    this.ws.close();
  }
}
