import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes as nobleRandomBytes } from "@noble/ciphers/utils.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

export function bytes(value) {
  if (value instanceof Uint8Array) return Uint8Array.from(value);
  if (ArrayBuffer.isView(value)) return Uint8Array.from(value.buffer, value.byteOffset, value.byteLength);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (typeof value === "string") return new TextEncoder().encode(value);
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new Error("value must be bytes or string");
}

export function utf8Bytes(value) {
  return new TextEncoder().encode(String(value));
}

export function utf8String(value) {
  return new TextDecoder().decode(bytes(value));
}

export function bytesFromHex(value, label = "hex") {
  const text = String(value || "").trim().replace(/^0x/i, "").toLowerCase();
  if (!text || text.length % 2 !== 0 || !/^[0-9a-f]+$/.test(text)) {
    throw new Error(`${label} must be valid hex`);
  }
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function hexFromBytes(value) {
  return [...bytes(value)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

export function bytesFromBase64(value, label = "base64") {
  const text = String(value || "").trim();
  try {
    if (typeof atob === "function") {
      const binary = atob(text);
      const out = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
      return out;
    }
    if (typeof Buffer !== "undefined") {
      return Uint8Array.from(Buffer.from(text, "base64"));
    }
  } catch {
    // Fall through to the shared error below.
  }
  throw new Error(`${label} must be valid base64`);
}

export function base64FromBytes(value) {
  const input = bytes(value);
  if (typeof btoa === "function") {
    let binary = "";
    for (const byte of input) binary += String.fromCharCode(byte);
    return btoa(binary);
  }
  if (typeof Buffer !== "undefined") {
    return Buffer.from(input).toString("base64");
  }
  throw new Error("base64 encoding is unavailable in this runtime");
}

export function concatBytes(...values) {
  const arrays = values.map(bytes);
  const total = arrays.reduce((sum, value) => sum + value.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const value of arrays) {
    out.set(value, offset);
    offset += value.length;
  }
  return out;
}

export function randomBytes(length) {
  return nobleRandomBytes(length);
}

export function sha256(value) {
  return nobleSha256(bytes(value));
}

export function sha256Hex(value) {
  return hexFromBytes(sha256(value));
}

export function hash160(value) {
  return ripemd160(sha256(value));
}

export function aesGcmEncrypt({ key, nonce, plaintext }) {
  return gcm(bytes(key), bytes(nonce)).encrypt(bytes(plaintext));
}

export function aesGcmDecrypt({ key, nonce, ciphertext }) {
  return gcm(bytes(key), bytes(nonce)).decrypt(bytes(ciphertext));
}
