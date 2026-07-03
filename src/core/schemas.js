import {
  defaultAccountPrefix,
  defaultShieldedPrefix,
  normalizeBech32Prefix
} from "./crypto.js";

export function assertObject(value, label = "value") {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

export function assertString(value, label = "value") {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value.trim();
}

export function assertDecimalString(value, label = "value") {
  const text = assertString(String(value ?? ""), label);
  if (!/^(0|[1-9][0-9]*)$/.test(text)) {
    throw new Error(`${label} must be a non-negative decimal string`);
  }
  return text;
}

export function assertHex(value, byteLength, label = "hex value") {
  const text = assertString(value, label).replace(/^0x/i, "").toLowerCase();
  const pattern = byteLength == null
    ? /^[0-9a-f]+$/
    : new RegExp(`^[0-9a-f]{${byteLength * 2}}$`);
  if (!pattern.test(text)) {
    throw new Error(`${label} must be ${byteLength ? `a ${byteLength}-byte ` : ""}hex string`);
  }
  return text;
}

function labelAndOptions(label, options, defaultLabel) {
  if (label && typeof label === "object") {
    return { label: defaultLabel, options: label };
  }
  return { label, options };
}

function assertBech32AddressWithPrefix(value, prefix, label) {
  const text = assertString(value, label);
  const normalizedPrefix = normalizeBech32Prefix(prefix, `${label} prefix`);
  const pattern = new RegExp(`^${normalizedPrefix}1[0-9a-z]{20,}$`);
  if (!pattern.test(text)) {
    throw new Error(`${label} must be a ${normalizedPrefix} bech32 address`);
  }
  return text;
}

export function assertClairAddress(value, label = "account address", options = {}) {
  const resolved = labelAndOptions(label, options, "account address");
  return assertBech32AddressWithPrefix(
    value,
    resolved.options.accountPrefix ?? resolved.options.bech32Prefix ?? defaultAccountPrefix,
    resolved.label
  );
}

export function assertShieldedAddress(value, label = "shielded address", options = {}) {
  const resolved = labelAndOptions(label, options, "shielded address");
  return assertBech32AddressWithPrefix(
    value,
    resolved.options.shieldedPrefix ?? defaultShieldedPrefix,
    resolved.label
  );
}

export function assertDisclosurePubKeyHex(value, label = "disclosure pubkey") {
  return assertHex(value, 32, label);
}

export function assertFoundNoteShape(value, label = "found note") {
  const found = assertObject(value, label);
  const note = assertObject(found.note, `${label}.note`);
  assertDecimalString(note.amount ?? note.am, `${label}.note.amount`);
  assertDecimalString(note.assetID ?? note.assetId ?? note.as, `${label}.note.assetID`);
  assertDecimalString(note.randomness ?? note.rn, `${label}.note.randomness`);
  return found;
}

export function assertPreparedTransferPayloadShape(value, label = "prepared transfer payload", options = {}) {
  const payload = assertObject(value, label);
  if (payload.version !== "v1" && payload.version !== "v2") {
    throw new Error(`${label}.version must be v1 or v2`);
  }
  assertClairAddress(payload.creator, `${label}.creator`, options);
  assertHex(payload.root_hex, 32, `${label}.root_hex`);
  assertHex(payload.asset_id_hex, 32, `${label}.asset_id_hex`);
  if (!Array.isArray(payload.inputs) || payload.inputs.length !== 2) {
    throw new Error(`${label}.inputs must contain exactly 2 input notes`);
  }
  if (!Array.isArray(payload.outputs) || payload.outputs.length !== 2) {
    throw new Error(`${label}.outputs must contain exactly 2 output notes`);
  }
  if (!Array.isArray(payload.cipher_text_hexes) || payload.cipher_text_hexes.length !== 2) {
    throw new Error(`${label}.cipher_text_hexes must contain exactly 2 ciphertexts`);
  }
  assertHex(payload.audit_disclosure_digest_hex, 32, `${label}.audit_disclosure_digest_hex`);
  assertDisclosurePubKeyHex(payload.audit_disclosure_target_pubkey_hex, `${label}.audit_disclosure_target_pubkey_hex`);
  if (payload.version === "v2") {
    const selfViewDigest = String(payload.self_view_disclosure_digest_hex || "").trim();
    const selfViewPayload = String(payload.self_view_disclosure_payload_hex || "").trim();
    if (selfViewDigest || selfViewPayload) {
      assertHex(selfViewDigest, 32, `${label}.self_view_disclosure_digest_hex`);
      assertHex(selfViewPayload, undefined, `${label}.self_view_disclosure_payload_hex`);
    }
  } else if (payload.self_view_disclosure_digest_hex || payload.self_view_disclosure_payload_hex) {
    throw new Error(`${label}.self_view_disclosure_* fields require version v2`);
  }
  assertHex(payload.payload_hash, 32, `${label}.payload_hash`);
  return payload;
}

export function assertPreparedWithdrawProverPayloadShape(value, label = "prepared withdraw prover payload", options = {}) {
  const payload = assertObject(value, label);
  if (payload.version !== "v1") throw new Error(`${label}.version must be v1`);
  assertHex(payload.root_hex, 32, `${label}.root_hex`);
  assertHex(payload.nullifier_hex, 32, `${label}.nullifier_hex`);
  assertDecimalString(payload.amount, `${label}.amount`);
  assertString(payload.asset_denom, `${label}.asset_denom`);
  assertHex(payload.asset_id_hex, 32, `${label}.asset_id_hex`);
  assertClairAddress(payload.recipient, `${label}.recipient`, options);
  assertHex(payload.recipient_bytes_hex, undefined, `${label}.recipient_bytes_hex`);
  assertString(payload.chain_id, `${label}.chain_id`);
  assertDecimalString(String(payload.expires_at_unix), `${label}.expires_at_unix`);
  assertHex(payload.note_randomness_hex, 32, `${label}.note_randomness_hex`);
  assertHex(payload.spend_pubkey_hex, 32, `${label}.spend_pubkey_hex`);
  assertHex(payload.view_pubkey_hex, 32, `${label}.view_pubkey_hex`);
  if (!Array.isArray(payload.merkle_path)) throw new Error(`${label}.merkle_path must be an array`);
  if (!Array.isArray(payload.merkle_path_helper)) throw new Error(`${label}.merkle_path_helper must be an array`);
  assertHex(payload.spend_note_hash_signature_hex, undefined, `${label}.spend_note_hash_signature_hex`);
  assertHex(payload.payload_hash, 32, `${label}.payload_hash`);
  return payload;
}
