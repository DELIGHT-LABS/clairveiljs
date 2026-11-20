import { FIELD_MODULUS, packPoint, unpackPoint } from "./crypto.js";

export function canonicalField(value, label, nonZero = false) {
  if (typeof value !== "bigint" && !(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value))) {
    throw new Error(`${label} must be a canonical field integer`);
  }
  const number = BigInt(value);
  if (number < 0n || number >= FIELD_MODULUS || (nonZero && number === 0n)) {
    throw new Error(`${label} must be a${nonZero ? " non-zero" : ""} canonical BN254 field element`);
  }
  return number;
}

export function canonicalPoint(x, y, label) {
  const input = { x: canonicalField(x, `${label} x`), y: canonicalField(y, `${label} y`) };
  const result = unpackPoint(packPoint(input));
  if (result.x !== input.x || result.y !== input.y || (result.x === 0n && result.y === 1n)) {
    throw new Error(`${label} must be a canonical non-identity prime-subgroup point`);
  }
  return result;
}
