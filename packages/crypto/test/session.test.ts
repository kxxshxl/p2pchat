import { describe, expect, it } from "vitest";
import {
  addSession,
  decryptMessage,
  deserialize,
  encryptMessage,
  envelopeFromWire,
  envelopeToWire,
  fromUtf8,
  serialize,
  startSession,
  utf8,
  type Envelope,
  type SessionRecord,
} from "../src/index.ts";
import { makeUser, type TestUser } from "./helpers.ts";

/** A tiny client: sessions keyed by peer name; consumes one-time pre-keys only on success. */
class Client {
  records = new Map<string, SessionRecord>();
  user: TestUser;
  name: string;
  constructor(user: TestUser, name: string) {
    this.user = user;
    this.name = name;
  }

  send(peer: Client, text: string): Envelope {
    let record = this.records.get(peer.name) ?? null;
    if (!record) record = addSession(null, startSession(this.user.identity, peer.user.bundle()));
    const result = encryptMessage(record, utf8(text));
    this.records.set(peer.name, result.record);
    return result.envelope;
  }

  receive(from: Client, envelope: Envelope) {
    const result = decryptMessage(this.records.get(from.name) ?? null, envelope, this.user.store);
    this.records.set(from.name, result.record);
    if (result.usedOneTimePreKeyId !== undefined) {
      this.user.oneTimePreKeys.delete(result.usedOneTimePreKeyId);
    }
    return { text: fromUtf8(result.plaintext), result };
  }
}

function clients() {
  return { alice: new Client(makeUser(), "alice"), bob: new Client(makeUser(), "bob") };
}

describe("sessions", () => {
  it("establishes a session from a bundle and drops the X3DH header after a reply", () => {
    const { alice, bob } = clients();
    const first = alice.send(bob, "hello bob");
    const second = alice.send(bob, "still there?");
    expect(first.preKey).toBeDefined();
    expect(second.preKey).toBeDefined();

    const r1 = bob.receive(alice, first);
    expect(r1.text).toBe("hello bob");
    expect(r1.result.newSession).toBe(true);
    expect(r1.result.usedOneTimePreKeyId).toBe(100);
    expect(bob.receive(alice, second).text).toBe("still there?");

    expect(alice.receive(bob, bob.send(alice, "hi alice")).text).toBe("hi alice");
    const third = alice.send(bob, "great");
    expect(third.preKey).toBeUndefined();
    expect(bob.receive(alice, third).text).toBe("great");
  });

  it("accepts the initiator's messages out of order", () => {
    const { alice, bob } = clients();
    const m1 = alice.send(bob, "one");
    const m2 = alice.send(bob, "two");
    expect(bob.receive(alice, m2).text).toBe("two");
    expect(bob.receive(alice, m1).text).toBe("one");
    expect(bob.records.get("alice")!.sessions).toHaveLength(1);
  });

  it("rejects a replayed initial message once the one-time key is gone", () => {
    const { alice, bob } = clients();
    const m1 = alice.send(bob, "one");
    bob.receive(alice, m1);
    expect(() => bob.receive(alice, m1)).toThrow(); // same session: duplicate
    bob.records.delete("alice"); // e.g. the session was pruned
    expect(() => bob.receive(alice, m1)).toThrow(/already used/);
  });

  it("converges when both sides initiate at the same time", () => {
    const { alice, bob } = clients();
    const fromAlice = alice.send(bob, "hi from alice");
    const fromBob = bob.send(alice, "hi from bob");

    expect(bob.receive(alice, fromAlice).text).toBe("hi from alice");
    expect(alice.receive(bob, fromBob).text).toBe("hi from bob");

    for (let i = 0; i < 4; i++) {
      expect(bob.receive(alice, alice.send(bob, `a${i}`)).text).toBe(`a${i}`);
      expect(alice.receive(bob, bob.send(alice, `b${i}`)).text).toBe(`b${i}`);
    }
    expect(alice.records.get("bob")!.sessions[0]!.id).toBe(bob.records.get("alice")!.sessions[0]!.id);
  });

  it("rejects a pre-key message whose sender identity was swapped", () => {
    const { alice, bob } = clients();
    const mallory = makeUser();
    const env = alice.send(bob, "hello");
    env.preKey = {
      ...env.preKey!,
      signingKey: mallory.identity.signing.publicKey,
      identityKey: mallory.identity.dh.publicKey,
      identityKeySignature: mallory.identity.dhSignature,
    };
    expect(() => bob.receive(alice, env)).toThrow(/authentication/);
    expect(bob.records.has("alice")).toBe(false);
    expect(bob.user.oneTimePreKeys.has(100)).toBe(true); // not consumed by a failed attempt
  });

  it("errors on an unknown signed pre-key", () => {
    const { alice, bob } = clients();
    const env = alice.send(bob, "hello");
    bob.user.signedPreKeys.clear();
    expect(() => bob.receive(alice, env)).toThrow(/unknown signed pre-key/);
  });

  it("pads plaintext so short messages are indistinguishable by size", () => {
    const { alice, bob } = clients();
    const short = alice.send(bob, "k");
    const longer = alice.send(bob, "x".repeat(100));
    expect(short.ciphertext.length).toBe(longer.ciphertext.length);
  });

  it("round-trips envelopes through the wire format and sessions through storage", () => {
    const { alice, bob } = clients();
    const wire = JSON.parse(JSON.stringify(envelopeToWire(alice.send(bob, "over the wire"))));
    expect(bob.receive(alice, envelopeFromWire(wire)).text).toBe("over the wire");

    bob.records.set("alice", deserialize<SessionRecord>(serialize(bob.records.get("alice"))));
    expect(alice.receive(bob, bob.send(alice, "after restore")).text).toBe("after restore");
  });

  it.each([
    [null],
    [{ v: 2, header: "", ciphertext: "" }],
    [{ v: 1, header: "AAAA", ciphertext: "" }],
    [{ v: 1, header: "A".repeat(56), ciphertext: 5 }],
    [{ v: 1, header: "A".repeat(52) + "AAA=", ciphertext: "", preKey: { signedPreKeyId: -1 } }],
  ])("rejects malformed envelope %#", (input) => {
    expect(() => envelopeFromWire(input)).toThrow();
  });
});
