import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CLOSE_REPLACED, CLOSE_UNAUTHORIZED } from "../src/relay.ts";
import { Socket, api, envelopeFor, register, startServer, type Server, type TestAccount } from "./helpers.ts";

let server: Server;
let alice: TestAccount;
let bob: TestAccount;
const sockets: Socket[] = [];

async function connect(account?: TestAccount) {
  const socket = await Socket.connect(server, account?.token);
  sockets.push(socket);
  return socket;
}

beforeEach(async () => {
  server = await startServer();
  alice = await register(server, "alice");
  bob = await register(server, "bob");
});

afterEach(async () => {
  for (const s of sockets.splice(0)) s.close();
  await server.app.close();
});

describe("relay", () => {
  it("rejects connections that do not authenticate", async () => {
    const socket = await connect();
    socket.send({ t: "send", to: bob.id });
    expect((await socket.closed).code).toBe(CLOSE_UNAUTHORIZED);

    const bad = await connect();
    bad.send({ t: "auth", token: "not-a-token" });
    expect((await bad.closed).code).toBe(CLOSE_UNAUTHORIZED);
  });

  it("delivers to an online recipient and keeps the envelope until acknowledged", async () => {
    const a = await connect(alice);
    const b = await connect(bob);
    const envelope = await envelopeFor(server, alice, bob, "hello");

    a.send({ t: "send", ref: "r1", to: bob.id, envelope });
    const sent = await a.nextOf("sent");
    expect(sent).toMatchObject({ ref: "r1", delivered: true });

    const incoming = await b.nextOf("message");
    expect(incoming).toMatchObject({ id: sent.id, from: alice.id, envelope });

    // not acknowledged yet: a reconnect gets it again
    b.close();
    await b.closed;
    const b2 = await connect(bob);
    expect((await b2.nextOf("message")).id).toBe(sent.id);

    b2.send({ t: "ack", ids: [sent.id] });
    await new Promise((r) => setTimeout(r, 50));
    b2.close();
    await b2.closed;
    const b3 = await connect(bob);
    await expect(b3.nextOf("message", 300)).rejects.toThrow(/timed out/);
  });

  it("queues messages for offline recipients and flushes them in order on connect", async () => {
    const a = await connect(alice);
    const envelopes = [];
    for (let i = 0; i < 3; i++) {
      const envelope = await envelopeFor(server, alice, bob, `m${i}`);
      envelopes.push(envelope);
      a.send({ t: "send", ref: `r${i}`, to: bob.id, envelope });
      expect(await a.nextOf("sent")).toMatchObject({ ref: `r${i}`, delivered: false });
    }
    const b = await connect(bob);
    for (let i = 0; i < 3; i++) {
      const msg = await b.nextOf("message");
      expect(msg.envelope).toEqual(envelopes[i]);
      expect(msg.queued).toBe(true);
    }
  });

  it("only lets the recipient acknowledge a message", async () => {
    const carol = await register(server, "carol");
    const a = await connect(alice);
    a.send({ t: "send", ref: "r", to: bob.id, envelope: await envelopeFor(server, alice, bob) });
    const { id } = await a.nextOf("sent");

    const c = await connect(carol);
    c.send({ t: "ack", ids: [id] });
    await new Promise((r) => setTimeout(r, 50));
    expect(server.ctx.store.pending(bob.id).map((m) => m.id)).toEqual([id]);
  });

  it("drops transient messages for offline users without storing them", async () => {
    const a = await connect(alice);
    a.send({ t: "send", ref: "typing", to: bob.id, envelope: await envelopeFor(server, alice, bob), transient: true });
    expect(await a.nextOf("sent")).toMatchObject({ id: null, delivered: false });
    expect(server.ctx.store.mailboxSize(bob.id)).toBe(0);
  });

  it("validates envelopes and recipients", async () => {
    const a = await connect(alice);
    a.send({ t: "send", ref: "x", to: bob.id, envelope: { v: 1, header: "nope", ciphertext: "" } });
    expect(await a.nextOf("error")).toMatchObject({ ref: "x", code: "bad_envelope" });
    a.send({ t: "send", ref: "y", to: "00000000-0000-4000-8000-000000000000", envelope: await envelopeFor(server, alice, bob) });
    expect(await a.nextOf("error")).toMatchObject({ ref: "y", code: "not_found" });
    a.send({ t: "send", ref: "z", to: alice.id, envelope: await envelopeFor(server, alice, bob) });
    expect(await a.nextOf("error")).toMatchObject({ ref: "z", code: "bad_request" });
  });

  it("enforces the mailbox limit", async () => {
    await server.app.close();
    server = await startServer({ mailboxLimit: 2 });
    alice = await register(server, "alice");
    bob = await register(server, "bob");
    const a = await connect(alice);
    const envelope = await envelopeFor(server, alice, bob);
    for (let i = 0; i < 2; i++) {
      a.send({ t: "send", ref: `${i}`, to: bob.id, envelope });
      await a.nextOf("sent");
    }
    a.send({ t: "send", ref: "full", to: bob.id, envelope });
    expect(await a.nextOf("error")).toMatchObject({ code: "mailbox_full" });
  });

  it("forwards WebRTC signalling only between online users", async () => {
    const a = await connect(alice);
    a.send({ t: "signal", to: bob.id, data: { kind: "offer", sdp: "v=0" } });
    expect(await a.nextOf("signal_failed")).toMatchObject({ to: bob.id });

    const b = await connect(bob);
    a.send({ t: "signal", to: bob.id, data: { kind: "offer", sdp: "v=0" } });
    expect(await b.nextOf("signal")).toEqual({ t: "signal", from: alice.id, data: { kind: "offer", sdp: "v=0" } });
  });

  it("reports presence to watchers", async () => {
    const a = await connect(alice);
    a.send({ t: "watch", users: [bob.id] });
    expect(await a.nextOf("presence")).toMatchObject({ userId: bob.id, online: false });

    const b = await connect(bob);
    expect(await a.nextOf("presence")).toMatchObject({ userId: bob.id, online: true });
    b.close();
    expect(await a.nextOf("presence")).toMatchObject({ userId: bob.id, online: false });
  });

  it("replaces an older connection for the same account", async () => {
    const first = await connect(alice);
    await connect(alice);
    expect((await first.closed).code).toBe(CLOSE_REPLACED);
  });

  it("notifies a user when their one-time pre-keys run low", async () => {
    const b = await connect(bob);
    await api(server, "GET", `/api/users/${bob.id}/bundle`, undefined, alice.token);
    expect(await b.nextOf("prekeys_low")).toMatchObject({ remaining: 4 });
  });
});
