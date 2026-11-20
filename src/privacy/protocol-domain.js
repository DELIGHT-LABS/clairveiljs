import { FIELD_MODULUS, bytesToBigIntBE } from "../core/crypto.js";
import { concatBytes, sha256, utf8Bytes } from "../core/browser-crypto.js";
import { integerBytes } from "../core/encoding.js";
import { canonicalAssetDenomV1 } from "./asset-denom.js";

// Core retains these hash domains across fixed wire versions. They are not
// a dependency on the retired fixed-v1 codec.
function hashDomainText(domain, value) {
  const encoded = utf8Bytes(value);
  return bytesToBigIntBE(sha256(concatBytes(utf8Bytes(domain), integerBytes(encoded.length, 4), encoded))) % FIELD_MODULUS;
}
export function domainField(label) {
  return hashDomainText("clairveil.field-domain.v1", String(label || ""));
}
export function computeAssetId(denom) {
  return hashDomainText("clairveil.asset-id.v1", canonicalAssetDenomV1(denom));
}
