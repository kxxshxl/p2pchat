import { describe, expect, it } from "vitest";
import {
  MAX_SKIP,
  MAX_STORED_SKIPPED,
  fromUtf8,
  generateDhKeyPair,
  initReceiver,
  initSender,
  ratchetDecrypt,
  ratchetEncrypt,
  randomBytes,
  utf8,
  type EncryptedMessage,
  type RatchetState,
} from "../src/index.ts";

class Party {
  state: RatchetState;
  constructor(state: RatchetState) {
    this.state = state;
  }
  send(text: string): EncryptedMessage {
    const { state, message } = ratchetEncrypt(this.state, utf8(text));
    this.state = state;
    return message;
  }
  receive(message: EncryptedMessage): string {
    const { state, plaintext } = ratchetDecrypt(this.state, message.headerBytes, message.ciphertext);
    this.state = state;
    return fromUtf8(plaintext);
  }
}

function parties() {
  const sharedKey = randomBytes(32);
  const ad = utf8("test-associated-data");
  const bobRatchet = generateDhKeyPair();
  return {
    a: new Party(initSender(sharedKey, bobRatchet.publicKey, ad)),
    b: new Party(initReceiver(sharedKey, bobRatchet, ad)),
  };
}

function flipByte(bytes: Uint8Array, index: number): Uint8Array {
  const copy = bytes.slice();
  copy[index] = copy[index]! ^ 1;
  return copy;
}

describe("Double Ratchet", () => {
  it("handles a long ping-pong conversation", () => {
    const { a, b } = parties();
    for (let i = 0; i < 25; i++) {
      expect(b.receive(a.send(`a${i}`))).toBe(`a${i}`);
      expect(a.receive(b.send(`b${i}`))).toBe(`b${i}`);
    }
  });

  it("handles bursts in one direction", () => {
    const { a, b } = parties();
    for (let i = 0; i < 60; i++) expect(b.receive(a.send(`m${i}`))).toBe(`m${i}`);
    for (let i = 0; i < 60; i++) expect(a.receive(b.send(`r${i}`))).toBe(`r${i}`);
  });

  it("responder cannot send before receiving", () => {
    const { b } = parties();
    expect(() => b.send("too early")).toThrow(/cannot send/);
  });

  it("encrypts identical plaintexts differently", () => {
    const { a } = parties();
    const m1 = a.send("same");
    const m2 = a.send("same");
    expect(Buffer.from(m1.ciphertext).equals(Buffer.from(m2.ciphertext))).toBe(false);
  });

  it("decrypts messages delivered out of order within a chain", () => {
    const { a, b } = parties();
    const msgs = [0, 1, 2, 3, 4].map((i) => a.send(`m${i}`));
    for (const i of [4, 2, 0, 1, 3]) expect(b.receive(msgs[i]!)).toBe(`m${i}`);
    expect(b.state.skipped).toHaveLength(0);
  });

  it("decrypts late messages from a previous ratchet chain", () => {
    const { a, b } = parties();
    const m0 = a.send("m0");
    const m1 = a.send("m1"); // delayed in transit
    expect(b.receive(m0)).toBe("m0");
    expect(a.receive(b.send("reply"))).toBe("reply");
    const m2 = a.send("m2"); // Alice is on a new chain now
    expect(b.receive(m2)).toBe("m2");
    expect(b.receive(m1)).toBe("m1");
  });

  it("rejects replays without changing state", () => {
    const { a, b } = parties();
    const m = a.send("once");
    expect(b.receive(m)).toBe("once");
    const before = b.state;
    expect(() => b.receive(m)).toThrow(/duplicate|authentication/);
    expect(b.state).toBe(before);
    expect(b.receive(a.send("next"))).toBe("next");
  });

  it("rejects tampered ciphertext and headers but keeps working afterwards", () => {
    const { a, b } = parties();
    const m = a.send("hello");
    expect(() => b.receive({ ...m, ciphertext: flipByte(m.ciphertext, 0) })).toThrow(/authentication/);
    expect(() => b.receive({ ...m, headerBytes: flipByte(m.headerBytes, 39) })).toThrow();
    expect(() => b.receive({ ...m, headerBytes: flipByte(m.headerBytes, 3) })).toThrow();
    expect(b.receive(m)).toBe("hello");
  });

  it("refuses to skip more than MAX_SKIP messages", () => {
    const { a, b } = parties();
    let last: EncryptedMessage | undefined;
    for (let i = 0; i < MAX_SKIP + 2; i++) last = a.send(`m${i}`);
    expect(() => b.receive(last!)).toThrow(/too many skipped/);
  });

  it("bounds the skipped-key cache", () => {
    const { a, b } = parties();
    for (let round = 0; round < 3; round++) {
      let last: EncryptedMessage | undefined;
      for (let i = 0; i < MAX_SKIP; i++) last = a.send(`r${round}m${i}`);
      b.receive(last!);
      a.receive(b.send("ack"));
    }
    expect(b.state.skipped.length).toBeLessThanOrEqual(MAX_STORED_SKIPPED);
  });

  it("heals after a state compromise (post-compromise security)", () => {
    const { a, b } = parties();
    b.receive(a.send("hi"));
    const stolen = new Party(b.state); // attacker copies Bob's entire state

    // The conversation continues; each change of direction mixes in fresh DH output.
    a.receive(b.send("one"));
    b.receive(a.send("two"));
    a.receive(b.send("three"));
    const secret = a.send("after healing");

    expect(b.receive(secret)).toBe("after healing");
    expect(() => stolen.receive(secret)).toThrow();
  });
});
