import { CURVE_BASE, CURVE_ORDER, bytesToBigIntBE, pointAdd, scalarMultiply } from "../core/crypto.js";
import { concatBytes, hexFromBytes, sha256, utf8Bytes } from "../core/browser-crypto.js";
import { canonicalPoint } from "../core/curve-validation.js";
import { bytes, integer, be, equal, maxHeight } from "./audit-encoding.js";
import { auditCircuitSetIdV2 } from "./audit-circuit-v2.js";

function point(raw) {
  if (raw.length !== 64) throw new Error("audit point must be exactly 64 bytes");
  return canonicalPoint(bytesToBigIntBE(raw.subarray(0, 32)), bytesToBigIntBE(raw.subarray(32)), "audit point");
}

/** Public Point64 and deterministic key ID validation; no epoch/PoP claim. */
export function validateAuditPublicKeyV2(publicKey, expectedKeyId) {
  const raw=bytes(publicKey,"audit public key",64);
  point(raw);
  const id=sha256(concatBytes("clairveil.audit.key.v1",be(2,2),raw));
  if(expectedKeyId!==undefined&&!equal(id,bytes(expectedKeyId,"audit key ID",32)))throw new Error("audit key ID mismatch");
  return id;
}

/** Public namespace derivation only; the caller authenticates its chain view. */
export function computeAuditNetworkDigestV2(chainId, networkNonce) {
  if (typeof chainId !== "string" || !/^[\x20-\x7e]+$/.test(chainId) || chainId.length > 0xffffffff) {
    throw new Error("chainId must be nonempty printable ASCII");
  }
  const nonce = bytes(networkNonce, "networkNonce", 32);
  const chain = utf8Bytes(chainId), set = utf8Bytes(auditCircuitSetIdV2);
  return sha256(concatBytes("clairveil.audit.network.v1", be(chain.length, 4), chain, nonce, be(set.length, 4), set));
}

/** Parse Core's exact 261-byte key record and verify the public Schnorr PoP.
 * Only public arithmetic is performed here. This is not a key generation API. */
export function parseAuditKeyRecordV2(raw, { networkDigest, initialHeight } = {}) {
  const data = bytes(raw, "audit key record", 261);
  const network = bytes(networkDigest, "networkDigest", 32);
  const initial = BigInt(integer(initialHeight, "initialHeight", maxHeight, 1n));
  const u = (offset, size) => bytesToBigIntBE(data.subarray(offset, offset + size));
  if (u(0, 2) !== 1n || u(42, 2) !== 2n) throw new Error("invalid audit key record version or suite");
  const epoch = u(2, 8), activation = u(108, 8), registered = u(116, 8), kind = data[124], originHeight = u(157, 8);
  if (epoch === 0n || activation > maxHeight || registered > maxHeight || originHeight !== registered || kind < 1 || kind > 3) throw new Error("invalid audit key record metadata");
  if (kind === 3) {
    if (epoch !== 1n || activation !== initial - 1n || registered !== initial - 1n) throw new Error("invalid initial audit key record");
  } else if (activation <= registered) throw new Error("audit key activation must be after registration");
  const publicRaw = data.subarray(44, 108), pk = point(publicRaw), r = point(data.subarray(165, 229));
  const keyId = validateAuditPublicKeyV2(publicRaw,data.subarray(10,42));
  const s = u(229, 32);
  if (s >= CURVE_ORDER) throw new Error("audit PoP response must be a canonical scalar");
  const challenge = bytesToBigIntBE(sha256(concatBytes("clairveil.audit.key-pop.v1", network, be(epoch, 8), be(activation, 8), be(2, 2), publicRaw, data.subarray(165, 229)))) % CURVE_ORDER;
  const left = scalarMultiply(CURVE_BASE, s), right = pointAdd(r, scalarMultiply(pk, challenge));
  if (left.x !== right.x || left.y !== right.y) throw new Error("invalid audit key possession proof (PoP)");
  return Object.freeze({ epoch: epoch.toString(), keyId: hexFromBytes(keyId), publicKey: hexFromBytes(publicRaw),
    activationHeight: activation.toString(), registeredHeight: registered.toString(),
    origin: Object.freeze({ kind, anchor: hexFromBytes(data.subarray(125, 157)), height: registered.toString() }),
    possessionProof: hexFromBytes(data.subarray(165)) });
}
