import { fromBech32, toBech32 } from "@cosmjs/encoding";
import sha3 from "js-sha3";
import {
  aesGcmDecrypt,
  bytesFromBase64,
  bytesFromHex as rawBytesFromHex,
  hexFromBytes as rawHexFromBytes,
  sha256,
  sha256Hex,
  utf8Bytes
} from "./browser-crypto.js";

const { keccak_256: keccak256 } = sha3;

export const FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const CURVE_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
export const CURVE_D = 12181644023421730124874158521699555681764249180949974110617291017600649128846n;
export const CURVE_A = -1n;
export const CURVE_BASE = {
  x: 9671717474070082183213120605117400219616337014328744928644933853176787189663n,
  y: 16950150798460657717958625567821834550301663161624707787222815936182638968203n
};
export const CURVE_IDENTITY = { x: 0n, y: 1n };

export const rootSigningDomain = "clairveil-root-v1";
export const spendDomain = "privacy-spend";
export const viewDomain = "privacy-view";
export const disclosureDomain = "privacy-disclosure";
export const defaultAccountPrefix = "clair";
export const defaultShieldedPrefix = "clairs";

const fieldHalf = (FIELD_MODULUS - 1n) / 2n;
const mimcRounds = 110;
let mimcConstants;

function mod(value, modulus = FIELD_MODULUS) {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

function modPow(base, exponent, modulus = FIELD_MODULUS) {
  let result = 1n;
  let x = mod(base, modulus);
  let e = BigInt(exponent);
  while (e > 0n) {
    if (e & 1n) result = (result * x) % modulus;
    x = (x * x) % modulus;
    e >>= 1n;
  }
  return result;
}

function modInv(value, modulus = FIELD_MODULUS) {
  const normalized = mod(value, modulus);
  if (normalized === 0n) {
    throw new Error("field inverse of zero");
  }
  return modPow(normalized, modulus - 2n, modulus);
}

function modSqrt(value) {
  const n = mod(value);
  if (n === 0n) return 0n;
  if (modPow(n, (FIELD_MODULUS - 1n) / 2n) !== 1n) {
    throw new Error("point is not on the Clairveil disclosure curve");
  }

  let q = FIELD_MODULUS - 1n;
  let s = 0n;
  while ((q & 1n) === 0n) {
    q >>= 1n;
    s += 1n;
  }

  if (s === 1n) {
    return modPow(n, (FIELD_MODULUS + 1n) / 4n);
  }

  let z = 2n;
  while (modPow(z, (FIELD_MODULUS - 1n) / 2n) !== FIELD_MODULUS - 1n) {
    z += 1n;
  }

  let c = modPow(z, q);
  let x = modPow(n, (q + 1n) / 2n);
  let t = modPow(n, q);
  let m = s;

  while (t !== 1n) {
    let i = 1n;
    let candidate = (t * t) % FIELD_MODULUS;
    while (candidate !== 1n) {
      candidate = (candidate * candidate) % FIELD_MODULUS;
      i += 1n;
      if (i >= m) {
        throw new Error("field square root failed");
      }
    }

    const b = modPow(c, 1n << (m - i - 1n));
    x = (x * b) % FIELD_MODULUS;
    const b2 = (b * b) % FIELD_MODULUS;
    t = (t * b2) % FIELD_MODULUS;
    c = b2;
    m = i;
  }

  return x;
}

export function normalizeHex(value, label = "hex") {
  if (typeof value !== "string") {
    throw new Error(`${label} must be a hex string`);
  }
  const normalized = value.trim().replace(/^0x/i, "").toLowerCase();
  if (normalized.length === 0 || normalized.length % 2 !== 0 || !/^[0-9a-f]+$/.test(normalized)) {
    throw new Error(`${label} must be valid hex`);
  }
  return normalized;
}

export function bytesFromHex(value, label = "hex") {
  return rawBytesFromHex(normalizeHex(value, label), label);
}

export function hexFromBytes(bytes) {
  return rawHexFromBytes(bytes);
}

export function bytesToBigIntBE(bytes) {
  const hex = hexFromBytes(bytes);
  return hex ? BigInt(`0x${hex}`) : 0n;
}

export function bytesToBigIntLE(bytes) {
  const reversed = Uint8Array.from(bytes).reverse();
  return bytesToBigIntBE(reversed);
}

export function bigIntToBytesBE(value, size = 32) {
  const normalized = mod(BigInt(value), FIELD_MODULUS);
  const hex = normalized.toString(16).padStart(size * 2, "0");
  if (hex.length > size * 2) {
    throw new Error(`integer does not fit in ${size} bytes`);
  }
  return rawBytesFromHex(hex, "integer bytes");
}

export function bigIntToBytesLE(value, size = 32) {
  return Uint8Array.from(bigIntToBytesBE(value, size)).reverse();
}

export function toField(value) {
  if (value == null) return 0n;
  if (typeof value === "bigint") return mod(value);
  if (typeof value === "number") return mod(BigInt(value));
  if (typeof value === "string") return mod(BigInt(value));
  return mod(bytesToBigIntBE(value));
}

export function canonicalFieldBytes(value) {
  return bigIntToBytesBE(toField(value), 32);
}

export function canonicalFieldHex(value) {
  return hexFromBytes(canonicalFieldBytes(value));
}

export function decodeCanonicalFieldHex(value, label = "field element") {
  const bytes = bytesFromHex(value, label);
  if (bytes.length > 32) {
    throw new Error(`${label} exceeds 32 bytes`);
  }
  const padded = new Uint8Array(32);
  padded.set(bytes, 32 - bytes.length);
  const asBigInt = bytesToBigIntBE(padded);
  if (asBigInt >= FIELD_MODULUS) {
    throw new Error(`${label} is not canonical`);
  }
  return padded;
}

function pointSign(point) {
  return mod(point.x) > fieldHalf;
}

function assertNonIdentityPoint(point) {
  if (mod(point.x) === 0n && mod(point.y) === 1n) {
    throw new Error("point identity is not allowed");
  }
  return point;
}

function assertPrimeOrderPoint(point) {
  const multiplied = scalarMultiply(point, CURVE_ORDER);
  if (mod(multiplied.x) !== 0n || mod(multiplied.y) !== 1n) {
    throw new Error("point is not in the prime-order subgroup");
  }
  return point;
}

function assertPrimeOrderNonIdentityPoint(point) {
  assertNonIdentityPoint(point);
  return assertPrimeOrderPoint(point);
}

export function packPoint(point) {
  const out = bigIntToBytesLE(point.y, 32);
  if (pointSign(point)) {
    out[31] |= 0x80;
  }
  return out;
}

export function packPointHex(point) {
  return hexFromBytes(packPoint(point));
}

export function unpackPoint(bytesLike) {
  const bytes = Uint8Array.from(bytesLike);
  if (bytes.length !== 32) {
    throw new Error("compressed disclosure public key must be 32 bytes");
  }

  const yBytes = Uint8Array.from(bytes);
  const sign = (yBytes[31] & 0x80) !== 0;
  yBytes[31] &= 0x7f;

  const y = bytesToBigIntLE(yBytes);
  if (y >= FIELD_MODULUS) {
    throw new Error("compressed disclosure public key has non-canonical y");
  }

  const y2 = (y * y) % FIELD_MODULUS;
  const numerator = mod(1n - y2);
  const denominator = mod(CURVE_A - CURVE_D * y2);
  let x = modSqrt(numerator * modInv(denominator));
  if (pointSign({ x, y }) !== sign) {
    x = mod(-x);
  }
  return assertPrimeOrderPoint({ x, y });
}

export function unpackPointHex(hex) {
  return unpackPoint(bytesFromHex(hex, "compressed disclosure public key"));
}

export function pointAdd(p, q) {
  const x1 = mod(p.x);
  const y1 = mod(p.y);
  const x2 = mod(q.x);
  const y2 = mod(q.y);
  const x1x2 = (x1 * x2) % FIELD_MODULUS;
  const y1y2 = (y1 * y2) % FIELD_MODULUS;
  const dxxyy = (((CURVE_D * x1x2) % FIELD_MODULUS) * y1y2) % FIELD_MODULUS;
  const xNum = mod(x1 * y2 + y1 * x2);
  const xDen = modInv(1n + dxxyy);
  const yNum = mod(y1y2 - CURVE_A * x1x2);
  const yDen = modInv(1n - dxxyy);
  return {
    x: (xNum * xDen) % FIELD_MODULUS,
    y: (yNum * yDen) % FIELD_MODULUS
  };
}

function extendedPoint(point) {
  const x = mod(point.x);
  const y = mod(point.y);
  return {
    X: x,
    Y: y,
    Z: 1n,
    T: (x * y) % FIELD_MODULUS
  };
}

function extendedIdentity() {
  return { X: 0n, Y: 1n, Z: 1n, T: 0n };
}

// Complete extended-coordinate formulas for the a=-1 twisted Edwards curve.
// Keeping the scalar-multiplication loop projective avoids hundreds of field
// inversions; only the final conversion back to affine coordinates inverts Z.
function extendedAdd(p, q) {
  const a = mod((p.Y - p.X) * (q.Y - q.X));
  const b = mod((p.Y + p.X) * (q.Y + q.X));
  const c = mod(2n * CURVE_D * p.T * q.T);
  const d = mod(2n * p.Z * q.Z);
  const e = mod(b - a);
  const f = mod(d - c);
  const g = mod(d + c);
  const h = mod(b + a);
  return {
    X: mod(e * f),
    Y: mod(g * h),
    Z: mod(f * g),
    T: mod(e * h)
  };
}

function extendedDouble(point) {
  const a = mod(point.X * point.X);
  const b = mod(point.Y * point.Y);
  const c = mod(2n * point.Z * point.Z);
  const d = mod(-a);
  const e = mod((point.X + point.Y) * (point.X + point.Y) - a - b);
  const g = mod(d + b);
  const f = mod(g - c);
  const h = mod(d - b);
  return {
    X: mod(e * f),
    Y: mod(g * h),
    Z: mod(f * g),
    T: mod(e * h)
  };
}

function affinePoint(point) {
  const inverseZ = modInv(point.Z);
  return {
    x: mod(point.X * inverseZ),
    y: mod(point.Y * inverseZ)
  };
}

export function scalarMultiply(point, scalar) {
  let k = BigInt(scalar);
  if (k < 0n) {
    throw new Error("scalar must be non-negative");
  }
  let result = extendedIdentity();
  let addend = extendedPoint(point);
  while (k > 0n) {
    if (k & 1n) result = extendedAdd(result, addend);
    addend = extendedDouble(addend);
    k >>= 1n;
  }
  return affinePoint(result);
}

export function deriveScalarFromSeed(seed) {
  let scalar = bytesToBigIntBE(seed) % CURVE_ORDER;
  if (scalar === 0n) scalar = 1n;
  return scalar;
}

export function scalarToFixedHex(scalar) {
  const normalized = BigInt(scalar);
  if (normalized < 0n) {
    throw new Error("scalar must be non-negative");
  }
  return normalized.toString(16).padStart(64, "0");
}

export function derivePubKeyFromScalar(scalar) {
  return scalarMultiply(CURVE_BASE, scalar);
}

export function buildRootSigningMessage(address, pubKeyHex) {
  return [
    rootSigningDomain,
    `address:${address}`,
    `pubkey:${normalizeHex(pubKeyHex, "pubKeyHex")}`
  ].join("\n");
}

export function computeRootSeed(address, pubKeyBytes, signatureBytes) {
  const pubKeyHex = hexFromBytes(pubKeyBytes);
  const signatureHex = hexFromBytes(signatureBytes);
  const material = [
    `${rootSigningDomain}/root`,
    `address:${address}`,
    `pubkey:${pubKeyHex}`,
    `signature:${signatureHex}`
  ].join("\n");
  return sha256(material);
}

export function deriveDomainSeed(rootSeed, domain) {
  const material = [
    `${rootSigningDomain}/derive`,
    `domain:${domain}`,
    `root:${hexFromBytes(rootSeed)}`
  ].join("\n");
  return sha256(material);
}

export function deriveKeyPair(rootSeed, domain) {
  const seed = deriveDomainSeed(rootSeed, domain);
  const scalar = deriveScalarFromSeed(seed);
  const pubKey = derivePubKeyFromScalar(scalar);
  return {
    seed,
    scalar,
    scalarHex: scalarToFixedHex(scalar),
    pubKey,
    pubKeyHex: packPointHex(pubKey)
  };
}

export function deriveSpendKeys(rootSeed) {
  return deriveKeyPair(rootSeed, spendDomain);
}

export function deriveViewKeys(rootSeed) {
  return deriveKeyPair(rootSeed, viewDomain);
}

export function deriveDisclosureKeys(rootSeed) {
  return deriveKeyPair(rootSeed, disclosureDomain);
}

export function normalizeBech32Prefix(value, label = "bech32 prefix") {
  const text = String(value || "").trim().toLowerCase();
  if (!/^[a-z0-9]+$/.test(text) || text.includes("1")) {
    throw new Error(`${label} must be a lowercase bech32 prefix without separator`);
  }
  return text;
}

function shieldedPrefixFromOptions(options = {}) {
  const value = typeof options === "string"
    ? options
    : options.shieldedPrefix ?? options.prefix ?? defaultShieldedPrefix;
  return normalizeBech32Prefix(value, "shielded prefix");
}

export function encodeShieldedAddress(spendPubKey, viewPubKey, options = {}) {
  const shieldedPrefix = shieldedPrefixFromOptions(options);
  const payload = new Uint8Array(64);
  payload.set(packPoint(spendPubKey), 0);
  payload.set(packPoint(viewPubKey), 32);
  return toBech32(shieldedPrefix, payload, 200);
}

export function decodeShieldedAddress(address, options = {}) {
  const shieldedPrefix = shieldedPrefixFromOptions(options);
  const decoded = fromBech32(String(address || "").trim());
  if (decoded.prefix !== shieldedPrefix) {
    throw new Error(`invalid shielded address prefix: expected ${shieldedPrefix}, got ${decoded.prefix}`);
  }
  if (decoded.data.length !== 64) {
    throw new Error(`invalid shielded address length: ${decoded.data.length}`);
  }
  return {
    spendPubKey: assertNonIdentityPoint(unpackPoint(decoded.data.slice(0, 32))),
    viewPubKey: assertNonIdentityPoint(unpackPoint(decoded.data.slice(32, 64)))
  };
}

function unpackPointForGoOperationHash(bytesLike) {
  const bytes = Uint8Array.from(bytesLike);
  if (bytes.length !== 32) {
    throw new Error("compressed disclosure public key must be 32 bytes");
  }
  const yBytes = Uint8Array.from(bytes);
  const sign = (yBytes[31] & 0x80) !== 0;
  yBytes[31] &= 0x7f;
  const y = bytesToBigIntLE(yBytes);
  if (y >= FIELD_MODULUS) {
    throw new Error("compressed disclosure public key has non-canonical y");
  }
  const y2 = (y * y) % FIELD_MODULUS;
  const numerator = mod(1n - y2);
  const denominator = mod(CURVE_A - CURVE_D * y2);
  const ratio = mod(numerator * modInv(denominator));
  let x = modSqrt(ratio);
  if (pointSign({ x, y }) !== sign) x = mod(-x);
  return assertPrimeOrderNonIdentityPoint({ x, y });
}

// canonicalizeShieldedAddressForOperationHash mirrors the Go payroll hash
// helper and rejects compressed points that do not decode onto the curve.
export function canonicalizeShieldedAddressForOperationHash(address, options = {}) {
  const shieldedPrefix = shieldedPrefixFromOptions(options);
  const decoded = fromBech32(String(address || "").trim());
  if (decoded.prefix !== shieldedPrefix || decoded.data.length !== 64) {
    throw new Error("invalid shielded address");
  }
  return encodeShieldedAddress(
    unpackPointForGoOperationHash(decoded.data.slice(0, 32)),
    unpackPointForGoOperationHash(decoded.data.slice(32, 64)),
    { shieldedPrefix }
  );
}

export function deriveShieldedAddress(rootSeed, options = {}) {
  const spend = deriveSpendKeys(rootSeed);
  const view = deriveViewKeys(rootSeed);
  return encodeShieldedAddress(spend.pubKey, view.pubKey, options);
}

export function derivePrivacyMaterial({ address, pubKeyHex, signatureBase64, shieldedPrefix } = {}) {
  const pubKeyBytes = bytesFromHex(pubKeyHex, "pubKeyHex");
  const signatureBytes = bytesFromBase64(signatureBase64, "signatureBase64");
  if (signatureBytes.length === 0) {
    throw new Error("signatureBase64 must decode to bytes");
  }
  const normalizedPubKeyHex = hexFromBytes(pubKeyBytes);
  const signingMessage = buildRootSigningMessage(address, normalizedPubKeyHex);
  const rootSeed = computeRootSeed(address, pubKeyBytes, signatureBytes);
  const disclosure = deriveDisclosureKeys(rootSeed);
  return {
    address,
    pubKeyHex: normalizedPubKeyHex,
    signatureBase64,
    signingMessage,
    rootSeed,
    rootSeedHex: hexFromBytes(rootSeed),
    rootSignatureHash: sha256Hex(signatureBytes),
    shieldedAddress: deriveShieldedAddress(rootSeed, { shieldedPrefix }),
    disclosureScalar: disclosure.scalar,
    disclosureScalarHex: disclosure.scalarHex,
    disclosurePubKey: disclosure.pubKey,
    disclosurePubKeyHex: disclosure.pubKeyHex
  };
}

function keccak256Bytes(input) {
  return Uint8Array.from(keccak256.array(input));
}

function getMimcConstants() {
  if (mimcConstants) return mimcConstants;
  let rnd = keccak256Bytes(utf8Bytes("seed"));
  const constants = [];
  for (let i = 0; i < mimcRounds; i += 1) {
    rnd = keccak256Bytes(rnd);
    constants.push(toField(rnd));
  }
  mimcConstants = constants;
  return constants;
}

function mimcEncrypt(message, key) {
  let m = toField(message);
  const h = toField(key);
  for (const constant of getMimcConstants()) {
    const tmp = mod(m + h + constant);
    const tmp2 = (tmp * tmp) % FIELD_MODULUS;
    const tmp4 = (tmp2 * tmp2) % FIELD_MODULUS;
    m = (tmp4 * tmp) % FIELD_MODULUS;
  }
  return mod(m + h);
}

export function mimcHash(...data) {
  let h = 0n;
  for (const item of data) {
    const message = toField(item);
    const r = mimcEncrypt(message, h);
    h = mod(r + h + message);
  }
  return h;
}

export function hashStringToField(value) {
  const digest = sha256(String(value));
  return toField(digest);
}

export function asymDecrypt(ciphertextBytes, scalar) {
  const bytes = Uint8Array.from(ciphertextBytes);
  if (bytes.length < 32 + 12 + 16) {
    throw new Error("invalid ciphertext length");
  }

  const ephemeralPub = assertNonIdentityPoint(unpackPoint(bytes.slice(0, 32)));
  const nonce = bytes.slice(32, 44);
  const ciphertextAndTag = bytes.slice(44);
  const sharedPoint = scalarMultiply(ephemeralPub, BigInt(scalar));
  const sharedSecret = sha256(packPoint(sharedPoint));

  try {
    return aesGcmDecrypt({
      key: sharedSecret,
      nonce,
      ciphertext: ciphertextAndTag
    });
  } catch {
    throw new Error("decryption failed (wrong key or corrupted data)");
  }
}

export function asymDecryptHex(ciphertextHex, scalar) {
  return asymDecrypt(bytesFromHex(ciphertextHex, "ciphertext"), scalar);
}
