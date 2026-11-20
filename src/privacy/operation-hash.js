import { canonicalizeShieldedAddressForOperationHash } from "../core/crypto.js";
import { hexFromBytes, sha256, utf8Bytes } from "../core/browser-crypto.js";

/** Go-compatible SHA-256 commitment used by payment/payroll operation evidence. */
export function hashRecipient(recipient, options = {}) {
  const normalizedRecipient = String(recipient ?? "").trim();
  if (!normalizedRecipient) {
    throw new Error("recipient is required");
  }
  let canonicalRecipient;
  try {
    canonicalRecipient = canonicalizeShieldedAddressForOperationHash(normalizedRecipient, options);
  } catch {
    throw new Error("recipient must be a valid shielded address");
  }
  return hexFromBytes(sha256(utf8Bytes(canonicalRecipient)));
}
