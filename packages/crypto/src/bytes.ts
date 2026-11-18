/** Small, dependency-free byte helpers shared by every module. */

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Constant-time comparison (for equal-length inputs). */
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function u32be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError(`not a u32: ${value}`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

export function readU32be(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false);
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_LOOKUP = new Map([...B64].map((c, i) => [c, i]));

/** Standard base64 with padding. Implemented here so it behaves identically in browsers and Node. */
export function toBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = bytes[i + 1];
    const c = bytes[i + 2];
    const n = (a << 16) | ((b ?? 0) << 8) | (c ?? 0);
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]!;
    out += b === undefined ? "=" : B64[(n >> 6) & 63]!;
    out += c === undefined ? "=" : B64[n & 63]!;
  }
  return out;
}

export function fromBase64(text: string): Uint8Array {
  if (text.length % 4 !== 0) throw new Error("invalid base64 length");
  const padding = text.endsWith("==") ? 2 : text.endsWith("=") ? 1 : 0;
  const out = new Uint8Array((text.length / 4) * 3 - padding);
  let o = 0;
  for (let i = 0; i < text.length; i += 4) {
    let n = 0;
    for (let j = 0; j < 4; j++) {
      const ch = text[i + j]!;
      if (ch === "=") {
        if (i + j < text.length - padding) throw new Error("invalid base64 padding");
        n <<= 6;
        continue;
      }
      const v = B64_LOOKUP.get(ch);
      if (v === undefined) throw new Error("invalid base64 character");
      n = (n << 6) | v;
    }
    if (o < out.length) out[o++] = (n >> 16) & 255;
    if (o < out.length) out[o++] = (n >> 8) & 255;
    if (o < out.length) out[o++] = n & 255;
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Decode base64 and require an exact length — used for every key received from the network. */
export function fromBase64Exact(text: unknown, length: number, label: string): Uint8Array {
  if (typeof text !== "string") throw new Error(`${label}: expected base64 string`);
  const bytes = fromBase64(text);
  if (bytes.length !== length) throw new Error(`${label}: expected ${length} bytes, got ${bytes.length}`);
  return bytes;
}
