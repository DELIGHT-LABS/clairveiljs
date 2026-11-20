import { unsignedInteger } from '../public/encoding.js';
export { unsignedInteger };

export function integerBytes(value, size) {
  let number = BigInt(value);
  if (!Number.isSafeInteger(size) || size < 1 || number < 0n || number >= 1n << BigInt(size * 8)) {
    throw new Error("integer does not fit the encoded byte width");
  }
  const output = new Uint8Array(size);
  for (let i = size - 1; i >= 0; i--) { output[i] = Number(number & 255n); number >>= 8n; }
  return output;
}

export function equalBytes(left, right) {
  if (left.length !== right.length) return false;
  let different = 0;
  for (let i = 0; i < left.length; i++) different |= left[i] ^ right[i];
  return different === 0;
}

export function requireObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value;
}

export function rejectAliases(value, aliases, label) {
  if (aliases.some(key => Object.hasOwn(value, key))) throw new Error(`${label} contains unsupported legacy fields; canonical fields are required`);
}
