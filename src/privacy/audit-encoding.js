import { base64FromBytes, bytesFromBase64 } from "../core/browser-crypto.js";
import { unsignedInteger } from "../core/encoding.js";
export { requireObject as object, equalBytes as equal, integerBytes as be } from "../core/encoding.js";
export const maxUint64 = (1n << 64n) - 1n;
export const maxHeight = (1n << 63n) - 1n;

export function bytes(value, label, size) {
  if (!(value instanceof Uint8Array) || (size !== undefined && value.length !== size)) {
    throw new Error(`${label} must be ${size === undefined ? "" : `exactly ${size} `}bytes`);
  }
  return Uint8Array.from(value);
}
export function wireBytes(value, label) {
  if (value instanceof Uint8Array) return bytes(value, label);
  if (typeof value !== "string") throw new Error(`${label} must be bytes or canonical base64`);
  const raw = bytesFromBase64(value, label);
  if (base64FromBytes(raw) !== value) throw new Error(`${label} must be canonical base64`);
  return raw;
}
export function integer(value, label, maximum = maxUint64, minimum = 0n) {
  return unsignedInteger(value, label, maximum, minimum).toString();
}
export function hexDigest(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new Error(`${label} must be lowercase SHA256 hex`);
  return value;
}
export function text(value, label) {
  if (typeof value !== "string" || !value) throw new Error(`${label} must be a nonempty string`);
  return value;
}
export function alias(value, snake, camel, normalize = text) {
  const a = value[snake], b = value[camel];
  const first = normalize(a === undefined ? b : a, snake);
  if (a !== undefined && b !== undefined && JSON.stringify(first) !== JSON.stringify(normalize(b, camel))) {
    throw new Error(`${snake} aliases conflict`);
  }
  return first;
}
