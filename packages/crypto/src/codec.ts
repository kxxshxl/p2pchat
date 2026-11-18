/**
 * JSON serialisation that round-trips Uint8Array values — used to persist sessions and keys.
 */

import { fromBase64, toBase64 } from "./bytes.ts";

const TAG = "$bytes";

export function serialize(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v instanceof Uint8Array ? { [TAG]: toBase64(v) } : v,
  );
}

export function deserialize<T>(text: string): T {
  return JSON.parse(text, (_key, v: unknown) => {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const keys = Object.keys(v);
      if (keys.length === 1 && keys[0] === TAG) {
        return fromBase64((v as Record<string, string>)[TAG]!);
      }
    }
    return v;
  }) as T;
}
