/**
 * Length hiding. Plaintexts are padded to a multiple of PAD_BLOCK bytes (ISO/IEC 7816-4 style:
 * a single 0x80 marker followed by zeros) so ciphertext sizes don't reveal exact message length.
 */

import { CryptoError } from "./primitives.ts";

export const PAD_BLOCK = 128;

export function pad(data: Uint8Array, block = PAD_BLOCK): Uint8Array {
  const length = Math.ceil((data.length + 1) / block) * block;
  const out = new Uint8Array(length);
  out.set(data);
  out[data.length] = 0x80;
  return out;
}

export function unpad(data: Uint8Array): Uint8Array {
  let i = data.length - 1;
  while (i >= 0 && data[i] === 0) i--;
  if (i < 0 || data[i] !== 0x80) throw new CryptoError("invalid padding");
  return data.slice(0, i);
}
