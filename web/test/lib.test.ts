import { describe, expect, it } from "vitest";
import { parsePayload } from "../src/lib/types";
import { KeyedMutex } from "../src/lib/util";

describe("parsePayload", () => {
  it("accepts well-formed payloads", () => {
    expect(parsePayload(JSON.stringify({ k: "text", id: "m1", body: "hi", ts: 1 }))).toEqual({
      k: "text",
      id: "m1",
      body: "hi",
      ts: 1,
    });
    expect(parsePayload(JSON.stringify({ k: "receipt", status: "read", ids: ["a"] }))).toMatchObject({ k: "receipt" });
    expect(parsePayload(JSON.stringify({ k: "typing", on: true }))).toEqual({ k: "typing", on: true });
  });

  it.each([
    "not json",
    "null",
    JSON.stringify({ k: "text", id: 5, body: "x", ts: 1 }),
    JSON.stringify({ k: "text", id: "m", body: "x".repeat(5000), ts: 1 }),
    JSON.stringify({ k: "receipt", status: "seen", ids: [] }),
    JSON.stringify({ k: "receipt", status: "read", ids: [1] }),
    JSON.stringify({ k: "typing", on: "yes" }),
    JSON.stringify({ k: "unknown" }),
  ])("rejects malformed payload %#", (text) => {
    expect(parsePayload(text)).toBeNull();
  });

  it("drops unexpected extra fields", () => {
    const parsed = parsePayload(JSON.stringify({ k: "typing", on: false, __proto__: { evil: 1 }, extra: 1 }));
    expect(parsed).toEqual({ k: "typing", on: false });
  });
});

describe("KeyedMutex", () => {
  it("serialises work per key and keeps going after failures", async () => {
    const mutex = new KeyedMutex();
    const order: string[] = [];
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

    const a1 = mutex.run("a", async () => {
      await sleep(20);
      order.push("a1");
    });
    const a2 = mutex.run("a", async () => {
      order.push("a2");
      throw new Error("boom");
    });
    const a3 = mutex.run("a", async () => order.push("a3"));
    const b1 = mutex.run("b", async () => order.push("b1"));

    await Promise.allSettled([a1, a2, a3, b1]);
    expect(order).toEqual(["b1", "a1", "a2", "a3"]);
    await expect(a2).rejects.toThrow("boom");
  });
});
