import {
  asymDecryptHex,
  bytesToBigIntBE,
  decodeCanonicalFieldHex,
  deriveSpendKeys,
  deriveViewKeys,
  unpackPoint
} from "../core/crypto.js";
import {
  computeNoteCommitmentHex,
  computeNoteNullifierHex,
  decryptWithRootSeed,
  normalizeFoundNote,
  normalizeNote
} from "../core/note.js";
import {
  bytesFromBase64,
  bytesFromHex,
  hexFromBytes,
  utf8String
} from "../core/browser-crypto.js";
import {
  activeCircuitSetIdV1,
  computeNoteCommitmentV1,
  computeNoteNullifierV1,
  decryptDepositNoteV1,
  decryptTransferNoteV1,
  encryptedEnvelopeKindV1,
  fieldHexV1,
  privacyFixedV1,
  unwrapEncryptedEnvelopeV1,
  unmarshalNotePlaintextV1
} from "./protocol-v1.js";

export const privacyScanSchemaVersionV2 = "privacy-scan-v2";
export const privacyScanEventTypeV2 = Object.freeze({
  deposit: "deposit",
  shieldedTransfer: "shielded_transfer",
  batchTransfer: "batch_transfer",
  withdraw: "withdraw"
});
export const privacyScanValidationStateVersionV2 = "privacy-scan-validation-v2";

// Kept module-private: a batch disclosure decoder may only consume an output
// produced by this validator, never an arbitrary protobuf-shaped object.
const validatedPrivacyScanOutputBrandV2 = Symbol("validatedPrivacyScanOutputV2");

const maxUint64 = (1n << 64n) - 1n;

export function parseNullifierUsage(value) {
  if (typeof value === "boolean") return value;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const hasUsed = Object.prototype.hasOwnProperty.call(value, "used");
  const hasAlias = Object.prototype.hasOwnProperty.call(value, "Used");
  if (!hasUsed && !hasAlias) return null;
  if ((hasUsed && typeof value.used !== "boolean") ||
      (hasAlias && typeof value.Used !== "boolean")) return null;
  if (hasUsed && hasAlias && value.used !== value.Used) return null;
  return hasUsed ? value.used : value.Used;
}

function eventAttribute(event, key) {
  return (event?.attributes || []).find(attribute => attribute.key === key)?.value || "";
}

function stripQuotes(value) {
  const text = String(value || "").trim();
  if (text.length >= 2 && text.startsWith("\"") && text.endsWith("\"")) {
    return text.slice(1, -1);
  }
  return text;
}

function parseBigIntField(text, key) {
  const match = new RegExp(`"${key}"\\s*:\\s*(-?\\d+)`).exec(text);
  if (!match) {
    throw new Error(`note JSON is missing ${key}`);
  }
  return BigInt(match[1]);
}

function parseStringField(text, key) {
  const match = new RegExp(`"${key}"\\s*:\\s*("(?:\\\\.|[^"\\\\])*")`).exec(text);
  if (!match) return "";
  return JSON.parse(match[1]);
}

export function parseNoteBytes(bytes) {
  try {
    return unmarshalNotePlaintextV1(bytes);
  } catch {
    // Historical scan events can be retained locally, but all current
    // Clairveil 0.2.0 network payloads take the fixed-binary branch above.
  }
  const text = utf8String(bytes).trim();
  return normalizeNote({
    rsx: parseBigIntField(text, "rsx"),
    rsy: parseBigIntField(text, "rsy"),
    rvx: parseBigIntField(text, "rvx"),
    rvy: parseBigIntField(text, "rvy"),
    am: parseBigIntField(text, "am"),
    as: parseBigIntField(text, "as"),
    rn: parseBigIntField(text, "rn"),
    mm: parseStringField(text, "mm")
  });
}

function foundNoteFromEvent(note, event) {
  return {
    note,
    nullifier: fieldHexV1(computeNoteNullifierV1(note)).toLowerCase(),
    isSpent: false,
    nullifierStatus: "unverified",
    txHash: String(event?.tx_hash_hex ?? event?.txHashHex ?? "").toUpperCase(),
    height: event?.height ?? 0,
    sequence: event?.sequence ?? 0
  };
}

function outputField(output, snake, camel) {
  return output?.[snake] ?? output?.[camel] ?? "";
}

function noteCommitmentMatches(note, commitmentHex) {
  const text = String(commitmentHex || "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(text)) return false;
  try {
    return fieldHexV1(computeNoteCommitmentV1(note)).toLowerCase() === text;
  } catch {
    return false;
  }
}

function processDepositEvent(event, rootSeed) {
  const encryptedNoteHex = stripQuotes(eventAttribute(event, "encrypted_note"));
  const commitmentHex = stripQuotes(eventAttribute(event, "commitment"));
  if (!encryptedNoteHex || !commitmentHex) return [];
  try {
    const note = decryptDepositNoteV1(bytesFromHex(encryptedNoteHex, "encrypted note"), rootSeed);
    return noteCommitmentMatches(note, commitmentHex)
      ? [foundNoteFromEvent(note, event)]
      : [];
  } catch {
    return [];
  }
}

function processTransferEvent(event, spendScalar, viewScalar) {
  const found = [];
  for (const [key, commitmentKey] of [["cipher_text_1", "commitment_1"], ["cipher_text_2", "commitment_2"]]) {
    const cipherTextHex = stripQuotes(eventAttribute(event, key));
    const commitmentHex = stripQuotes(eventAttribute(event, commitmentKey));
    if (!cipherTextHex || !commitmentHex) continue;

    let note;
    try {
      note = decryptTransferNoteV1(bytesFromHex(cipherTextHex, "transfer ciphertext"), viewScalar);
    } catch {
      if (spendScalar == null || spendScalar === viewScalar) continue;
      try {
        note = decryptTransferNoteV1(bytesFromHex(cipherTextHex, "transfer ciphertext"), spendScalar);
      } catch {
        continue;
      }
    }

    try {
      if (noteCommitmentMatches(note, commitmentHex)) {
        found.push(foundNoteFromEvent(note, event));
      }
    } catch {
      // Ignore ciphertexts that decrypt but do not contain a note payload.
    }
  }
  return found;
}

function processScanProjectionEvent(event, rootSeed, spendScalar, viewScalar) {
  const found = [];
  for (const output of event?.outputs || event?.Outputs || []) {
    if (event?.event_type === "deposit" || event?.eventType === "deposit") {
      const encryptedNoteHex = outputField(output, "encrypted_note_hex", "encryptedNoteHex");
      if (!encryptedNoteHex) continue;
      try {
        const note = decryptDepositNoteV1(bytesFromHex(encryptedNoteHex, "encrypted note"), rootSeed);
        if (!noteCommitmentMatches(note, outputField(output, "commitment_hex", "commitmentHex"))) continue;
        found.push(foundNoteFromEvent(note, event));
      } catch {
        // Ignore projection outputs that do not belong to this wallet.
      }
      continue;
    }

    if (event?.event_type === "shielded_transfer" || event?.eventType === "shielded_transfer") {
      const cipherTextHex = outputField(output, "cipher_text_hex", "cipherTextHex");
      if (!cipherTextHex) continue;

      let note;
      try {
        // View tags are untrusted scan hints. Safe default is full trial decrypt.
        note = decryptTransferNoteV1(bytesFromHex(cipherTextHex, "transfer ciphertext"), viewScalar);
      } catch {
        if (spendScalar == null || spendScalar === viewScalar) continue;
        try {
          note = decryptTransferNoteV1(bytesFromHex(cipherTextHex, "transfer ciphertext"), spendScalar);
        } catch {
          continue;
        }
      }

      try {
        if (!noteCommitmentMatches(note, outputField(output, "commitment_hex", "commitmentHex"))) continue;
        found.push(foundNoteFromEvent(note, event));
      } catch {
        // Ignore ciphertexts that decrypt but do not contain a note payload.
      }
    }
  }
  return found;
}

export function processPrivacyEvent(event, { rootSeed, spendScalar, viewScalar } = {}) {
  if (Array.isArray(event?.outputs) || Array.isArray(event?.Outputs)) {
    return processScanProjectionEvent(event, rootSeed, spendScalar, viewScalar);
  }
  const eventType = event?.event_type ?? event?.eventType;
  if (eventType === "deposit") {
    return processDepositEvent(event, rootSeed);
  }
  if (eventType === "shielded_transfer") {
    return processTransferEvent(event, spendScalar, viewScalar);
  }
  return [];
}

function foundNoteIdentityKey(found) {
  const nullifier = String(found?.nullifier || "").trim().toLowerCase();
  if (nullifier) return `nullifier:${nullifier}`;
  return `fallback:${found.height}:${String(found.txHash || "").toLowerCase()}:${found.note.amount}`;
}

export function normalizeFoundNotes(notes) {
  const byKey = new Map();
  for (const foundLike of notes) {
    const found = normalizeFoundNote(foundLike);
    const key = foundNoteIdentityKey(found);
    if (!byKey.has(key)) byKey.set(key, found);
  }
  return [...byKey.values()].sort((left, right) => {
    const leftHeight = BigInt(left.height);
    const rightHeight = BigInt(right.height);
    if (leftHeight !== rightHeight) return leftHeight < rightHeight ? -1 : 1;
    const leftSequence = BigInt(left.sequence);
    const rightSequence = BigInt(right.sequence);
    if (leftSequence !== rightSequence) return leftSequence < rightSequence ? -1 : 1;
    const txCompare = String(left.txHash).localeCompare(String(right.txHash));
    if (txCompare !== 0) return txCompare;
    const nullifierCompare = String(left.nullifier).localeCompare(String(right.nullifier));
    if (nullifierCompare !== 0) return nullifierCompare;
    return left.note.amount < right.note.amount ? -1 : left.note.amount > right.note.amount ? 1 : 0;
  });
}

function noteResponse(found, index) {
  const verifiedUnspent = found.nullifierStatus === "unspent" && !found.isSpent;
  return {
    index: index + 1,
    status: found.isSpent ? "spent" : (verifiedUnspent ? "spendable" : "unverified"),
    nullifier_status: found.nullifierStatus,
    amount: found.note.amount.toString(),
    nullifier: found.nullifier,
    tx_hash: found.txHash,
    height: found.height,
    sequence: found.sequence
  };
}

function scanUint64(value, label) {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a non-negative safe integer, bigint, or canonical uint64 string`);
    return BigInt(value);
  }
  if (typeof value === "bigint") {
    if (value < 0n || value > maxUint64) throw new Error(`${label} must be within uint64 range`);
    return value;
  }
  const text = String(value ?? "");
  if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error(`${label} must be a canonical uint64 decimal string`);
  const parsed = BigInt(text);
  if (parsed > maxUint64) throw new Error(`${label} must be within uint64 range`);
  return parsed;
}

function scanUint64Value(value, label) {
  const parsed = scanUint64(value, label);
  return parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : parsed.toString();
}

function scanUint32(value, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 0xffffffff) {
    throw new Error(`${label} must be an unsigned 32-bit integer`);
  }
  return parsed;
}

function scanBytes(value, label) {
  if (value instanceof Uint8Array) return Uint8Array.from(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
  if (value instanceof ArrayBuffer) return new Uint8Array(value).slice();
  if (Array.isArray(value)) return Uint8Array.from(value);
  if (typeof value === "string") return bytesFromBase64(value, label);
  throw new Error(`${label} must be protobuf bytes`);
}

function equalScanBytes(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameScanValue(left, right) {
  if (left instanceof Uint8Array && right instanceof Uint8Array) return equalScanBytes(left, right);
  if (Array.isArray(left) && Array.isArray(right)) {
    return left.length === right.length && left.every((value, index) => sameScanValue(value, right[index]));
  }
  if (left && right && typeof left === "object" && typeof right === "object") {
    const leftKeys = Object.keys(left).sort();
    const rightKeys = Object.keys(right).sort();
    return leftKeys.length === rightKeys.length && leftKeys.every((key, index) =>
      key === rightKeys[index] && sameScanValue(left[key], right[key])
    );
  }
  return Object.is(left, right);
}

function aliasedScanValue(input, keys, label, normalize, { required = true, fallback } = {}) {
  const values = keys
    .filter(key => Object.prototype.hasOwnProperty.call(input || {}, key))
    .map(key => input[key])
    .filter(value => value !== undefined && value !== null);
  if (!values.length) {
    if (required) throw new Error(`${label} is required`);
    return fallback;
  }
  const normalized = values.map(value => normalize(value));
  if (normalized.some(value => !sameScanValue(normalized[0], value))) {
    throw new Error(`${label} aliases do not match`);
  }
  return normalized[0];
}

function scanCanonicalField(value, label, { nonZero = false } = {}) {
  const raw = value instanceof Uint8Array ? value : scanBytes(value, label);
  if (raw.length !== 32) throw new Error(`${label} must be exactly 32 bytes`);
  const hex = hexFromBytes(raw);
  const canonical = decodeCanonicalFieldHex(hex, label);
  const field = bytesToBigIntBE(canonical);
  if (nonZero && field === 0n) throw new Error(`${label} must be a non-zero canonical field`);
  return { bytes: canonical, hex, field };
}

function scanNonZeroHash(value, label) {
  const raw = value instanceof Uint8Array ? value : scanBytes(value, label);
  if (raw.length !== 32) throw new Error(`${label} must be exactly 32 bytes`);
  if (raw.every(byte => byte === 0)) throw new Error(`${label} must be non-zero`);
  return raw;
}

function scanCursor(value, label = "privacy scan cursor", { required = true } = {}) {
  if (value == null) {
    if (required) throw new Error(`${label} is required`);
    return Object.freeze({ height: 0, global_sequence: 0, output_index: 0 });
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const height = aliasedScanValue(value, ["height"], `${label} height`, raw => scanUint64Value(raw, `${label} height`), { required: false, fallback: 0 });
  if (scanUint64(height, `${label} height`) > ((1n << 63n) - 1n)) {
    throw new Error(`${label} height exceeds int64`);
  }
  const globalSequence = aliasedScanValue(value, ["globalSequence", "global_sequence"], `${label} global sequence`, raw => scanUint64Value(raw, `${label} global sequence`), { required: false, fallback: 0 });
  const outputIndex = aliasedScanValue(value, ["outputIndex", "output_index"], `${label} output index`, raw => scanUint32(raw, `${label} output index`), { required: false, fallback: 0 });
  return Object.freeze({ height, global_sequence: globalSequence, output_index: outputIndex });
}

function compareScanCursor(left, right) {
  const leftHeight = scanUint64(left.height, "privacy scan cursor height");
  const rightHeight = scanUint64(right.height, "privacy scan cursor height");
  if (leftHeight !== rightHeight) return leftHeight < rightHeight ? -1 : 1;
  const leftSequence = scanUint64(left.global_sequence, "privacy scan cursor global sequence");
  const rightSequence = scanUint64(right.global_sequence, "privacy scan cursor global sequence");
  if (leftSequence !== rightSequence) return leftSequence < rightSequence ? -1 : 1;
  return left.output_index < right.output_index ? -1 : left.output_index > right.output_index ? 1 : 0;
}

function eventCursor(cursor) {
  return { height: cursor.height, global_sequence: cursor.global_sequence, output_index: 0 };
}

function scanEventKey(value) {
  return `${value.height}/${value.global_sequence}`;
}

function scanString(value, label) {
  const text = String(value ?? "");
  if (!text) throw new Error(`${label} is required`);
  return text;
}

function scanOptionalBytes(input, keys, label) {
  return aliasedScanValue(input, keys, label, raw => scanBytes(raw, label), { required: false, fallback: new Uint8Array() });
}

function scanOutputCount(value, label) {
  return scanUint32(value, label);
}

function scanNonIdentityPoint(value, label) {
  if (value.length !== 32) throw new Error(`${label} must be a canonical non-identity point`);
  try {
    const point = unpackPoint(value);
    if (point.x === 0n && point.y === 1n) throw new Error("identity point is not allowed");
  } catch {
    throw new Error(`${label} must be a canonical non-identity point`);
  }
}

function scanZeroAuditSentinel(summary, label) {
  if (summary.audit_key_id || scanUint64(summary.audit_key_epoch, `${label} audit key epoch`) !== 0n || summary.audit_target_pubkey.length) {
    throw new Error(`${label} must use the zero audit sentinel`);
  }
}

function scanSummary(input, index) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error(`privacy scan summary ${index} is required`);
  const height = aliasedScanValue(input, ["height"], `privacy scan summary ${index} height`, raw => scanUint64Value(raw, `privacy scan summary ${index} height`));
  if (scanUint64(height, `privacy scan summary ${index} height`) > ((1n << 63n) - 1n)) throw new Error(`privacy scan summary ${index} height exceeds int64`);
  const globalSequence = aliasedScanValue(input, ["globalSequence", "global_sequence"], `privacy scan summary ${index} global sequence`, raw => scanUint64Value(raw, `privacy scan summary ${index} global sequence`));
  if (scanUint64(globalSequence, `privacy scan summary ${index} global sequence`) === 0n) throw new Error(`privacy scan summary ${index} global sequence must be positive`);
  const eventType = aliasedScanValue(input, ["eventType", "event_type"], `privacy scan summary ${index} event type`, raw => scanString(raw, `privacy scan summary ${index} event type`));
  const outputCount = aliasedScanValue(input, ["outputCount", "output_count"], `privacy scan summary ${index} output count`, raw => scanOutputCount(raw, `privacy scan summary ${index} output count`), { required: false, fallback: 0 });
  const circuitSetId = aliasedScanValue(input, ["circuitSetId", "circuit_set_id"], `privacy scan summary ${index} circuit set`, raw => scanString(raw, `privacy scan summary ${index} circuit set`));
  const payloadVersion = aliasedScanValue(input, ["payloadVersion", "payload_version"], `privacy scan summary ${index} payload version`, raw => scanString(raw, `privacy scan summary ${index} payload version`));
  const scanSchemaVersion = aliasedScanValue(input, ["scanSchemaVersion", "scan_schema_version"], `privacy scan summary ${index} schema version`, raw => scanString(raw, `privacy scan summary ${index} schema version`));
  if (circuitSetId !== activeCircuitSetIdV1 || payloadVersion !== privacyFixedV1 || scanSchemaVersion !== privacyScanSchemaVersionV2) {
    throw new Error(`privacy scan summary ${index} has unsupported version identity`);
  }
  const txHash = scanOptionalBytes(input, ["txHash", "tx_hash"], `privacy scan summary ${index} tx hash`);
  if (txHash.length && txHash.length !== 32) throw new Error(`privacy scan summary ${index} tx hash must be 32 bytes when present`);
  const effectId = scanOptionalBytes(input, ["effectId", "effect_id"], `privacy scan summary ${index} effect ID`);
  const nullifiers = aliasedScanValue(input, ["nullifiers"], `privacy scan summary ${index} nullifiers`, raw => {
    if (!Array.isArray(raw)) throw new Error(`privacy scan summary ${index} nullifiers must be an array`);
    return raw.map((value, nullifierIndex) => scanCanonicalField(value, `privacy scan summary ${index} nullifier ${nullifierIndex}`, { nonZero: true }));
  }, { required: false, fallback: [] });
  const auditKeyId = aliasedScanValue(input, ["auditKeyId", "audit_key_id"], `privacy scan summary ${index} audit key ID`, raw => String(raw ?? ""), { required: false, fallback: "" });
  const auditKeyEpoch = aliasedScanValue(input, ["auditKeyEpoch", "audit_key_epoch"], `privacy scan summary ${index} audit key epoch`, raw => scanUint64Value(raw, `privacy scan summary ${index} audit key epoch`), { required: false, fallback: 0 });
  const auditTargetPubkey = scanOptionalBytes(input, ["auditTargetPubkey", "audit_target_pubkey"], `privacy scan summary ${index} audit target`);
  const summary = Object.freeze({
    height,
    global_sequence: globalSequence,
    tx_hash: txHash,
    event_type: eventType,
    nullifiers: Object.freeze(nullifiers.map(value => value.bytes)),
    output_count: outputCount,
    circuit_set_id: circuitSetId,
    payload_version: payloadVersion,
    scan_schema_version: scanSchemaVersion,
    audit_key_id: auditKeyId,
    audit_key_epoch: auditKeyEpoch,
    audit_target_pubkey: auditTargetPubkey,
    effect_id: effectId
  });
  if (new Set(nullifiers.map(value => value.hex)).size !== nullifiers.length) {
    throw new Error(`privacy scan summary ${index} nullifiers must be distinct`);
  }
  if (eventType === privacyScanEventTypeV2.deposit) {
    if (outputCount !== 1 || nullifiers.length || effectId.length) throw new Error(`privacy scan summary ${index} has invalid deposit framing`);
    scanZeroAuditSentinel(summary, `privacy scan summary ${index} deposit`);
  } else if (eventType === privacyScanEventTypeV2.shieldedTransfer) {
    if (outputCount !== 2 || nullifiers.length !== 2 || effectId.length) throw new Error(`privacy scan summary ${index} has invalid shielded-transfer framing`);
    if (auditKeyId || scanUint64(auditKeyEpoch, `privacy scan summary ${index} audit key epoch`) !== 0n) {
      throw new Error(`privacy scan summary ${index} shielded transfer must use the zero audit ID/epoch sentinel`);
    }
    scanNonIdentityPoint(auditTargetPubkey, `privacy scan summary ${index} shielded transfer audit target`);
  } else if (eventType === privacyScanEventTypeV2.batchTransfer) {
    if (outputCount < 1 || outputCount > 32 || nullifiers.length < 1 || nullifiers.length > 16) {
      throw new Error(`privacy scan summary ${index} has invalid batch counts`);
    }
    scanNonZeroHash(effectId, `privacy scan summary ${index} effect ID`);
    if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(auditKeyId) ||
        scanUint64(auditKeyEpoch, `privacy scan summary ${index} audit key epoch`) === 0n ||
        auditTargetPubkey.length !== 32) {
      throw new Error(`privacy scan summary ${index} has invalid batch audit identity`);
    }
    scanNonIdentityPoint(auditTargetPubkey, `privacy scan summary ${index} batch audit target`);
  } else if (eventType === privacyScanEventTypeV2.withdraw) {
    if (outputCount !== 0 || nullifiers.length !== 1 || effectId.length) throw new Error(`privacy scan summary ${index} has invalid withdraw framing`);
    scanZeroAuditSentinel(summary, `privacy scan summary ${index} withdraw`);
  } else {
    throw new Error(`privacy scan summary ${index} has unsupported event type ${JSON.stringify(eventType)}`);
  }
  return summary;
}

function scanUserDisclosureMode(value) {
  const mode = String(value ?? "");
  if (!["USER_DISCLOSURE_MODE_NONE", "USER_DISCLOSURE_MODE_PUBLIC", "USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED"].includes(mode)) {
    throw new Error("privacy scan batch user disclosure mode is invalid");
  }
  return mode;
}

function scanZeroDisclosureSentinel(output, label) {
  if (output.user_privacy_policy !== 0 || output.user_disclosure_mode ||
      output.user_disclosure_digest.length || output.user_disclosure_target_pubkey.length || output.user_disclosure_payload.length ||
      output.full_disclosure_digest.length || output.audit_disclosure_payload.length || output.self_view_disclosure_payload.length) {
    throw new Error(`${label} must use exact zero disclosure sentinels`);
  }
}

function scanBatchOutputDisclosure(output, label) {
  const policy = output.user_privacy_policy;
  if (!Number.isInteger(policy) || policy < 0 || policy > 7) throw new Error(`${label} user privacy policy is invalid`);
  scanCanonicalField(output.full_disclosure_digest, `${label} full disclosure digest`, { nonZero: true });
  unwrapEncryptedEnvelopeV1(output.audit_disclosure_payload, encryptedEnvelopeKindV1.auditDisclosure);
  if (output.self_view_disclosure_payload.length) {
    unwrapEncryptedEnvelopeV1(output.self_view_disclosure_payload, encryptedEnvelopeKindV1.selfViewDisclosure);
  }
  const mode = scanUserDisclosureMode(output.user_disclosure_mode);
  if (policy === 0) {
    if (mode !== "USER_DISCLOSURE_MODE_NONE" || output.user_disclosure_digest.length || output.user_disclosure_target_pubkey.length || output.user_disclosure_payload.length) {
      throw new Error(`${label} all-private disclosure framing is invalid`);
    }
  } else if (mode === "USER_DISCLOSURE_MODE_PUBLIC") {
    scanCanonicalField(output.user_disclosure_digest, `${label} user disclosure digest`, { nonZero: true });
    if (output.user_disclosure_target_pubkey.length || output.user_disclosure_payload.length !== 392) {
      throw new Error(`${label} public user disclosure framing is invalid`);
    }
  } else if (mode === "USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED") {
    scanCanonicalField(output.user_disclosure_digest, `${label} user disclosure digest`, { nonZero: true });
    scanNonIdentityPoint(output.user_disclosure_target_pubkey, `${label} encrypted disclosure target`);
    unwrapEncryptedEnvelopeV1(output.user_disclosure_payload, encryptedEnvelopeKindV1.userDisclosure);
  } else {
    throw new Error(`${label} user disclosure mode is invalid for the selected policy`);
  }
}

function scanOutput(input, index, summaries) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error(`privacy scan output ${index} is required`);
  const height = aliasedScanValue(input, ["height"], `privacy scan output ${index} height`, raw => scanUint64Value(raw, `privacy scan output ${index} height`));
  if (scanUint64(height, `privacy scan output ${index} height`) > ((1n << 63n) - 1n)) throw new Error(`privacy scan output ${index} height exceeds int64`);
  const globalSequence = aliasedScanValue(input, ["globalSequence", "global_sequence"], `privacy scan output ${index} global sequence`, raw => scanUint64Value(raw, `privacy scan output ${index} global sequence`));
  const outputIndex = aliasedScanValue(input, ["outputIndex", "output_index"], `privacy scan output ${index} output index`, raw => scanUint32(raw, `privacy scan output ${index} output index`), { required: false, fallback: 0 });
  const eventType = aliasedScanValue(input, ["eventType", "event_type"], `privacy scan output ${index} event type`, raw => scanString(raw, `privacy scan output ${index} event type`));
  const summary = summaries.get(scanEventKey({ height, global_sequence: globalSequence }));
  if (!summary) throw new Error(`privacy scan output ${index} has no page summary`);
  const effectId = scanOptionalBytes(input, ["effectId", "effect_id"], `privacy scan output ${index} effect ID`);
  const txHash = scanOptionalBytes(input, ["txHash", "tx_hash"], `privacy scan output ${index} tx hash`);
  const circuitSetId = aliasedScanValue(input, ["circuitSetId", "circuit_set_id"], `privacy scan output ${index} circuit set`, raw => scanString(raw, `privacy scan output ${index} circuit set`));
  const payloadVersion = aliasedScanValue(input, ["payloadVersion", "payload_version"], `privacy scan output ${index} payload version`, raw => scanString(raw, `privacy scan output ${index} payload version`));
  const scanSchemaVersion = aliasedScanValue(input, ["scanSchemaVersion", "scan_schema_version"], `privacy scan output ${index} schema version`, raw => scanString(raw, `privacy scan output ${index} schema version`));
  if (eventType !== summary.event_type || outputIndex >= summary.output_count || !equalScanBytes(effectId, summary.effect_id) || !equalScanBytes(txHash, summary.tx_hash) ||
      circuitSetId !== summary.circuit_set_id || payloadVersion !== summary.payload_version || scanSchemaVersion !== summary.scan_schema_version) {
    throw new Error(`privacy scan output ${index} does not match its summary identity`);
  }
  const commitment = scanCanonicalField(
    aliasedScanValue(input, ["commitment"], `privacy scan output ${index} commitment`, raw => scanBytes(raw, `privacy scan output ${index} commitment`)),
    `privacy scan output ${index} commitment`,
    { nonZero: true }
  ).bytes;
  const leafIndexFound = aliasedScanValue(input, ["leafIndexFound", "leaf_index_found"], `privacy scan output ${index} leaf index marker`, raw => {
    if (typeof raw !== "boolean") throw new Error(`privacy scan output ${index} leaf index marker must be boolean`);
    return raw;
  });
  if (!leafIndexFound) throw new Error(`privacy scan output ${index} leaf index is absent`);
  const leafIndex = aliasedScanValue(input, ["leafIndex", "leaf_index"], `privacy scan output ${index} leaf index`, raw => scanUint64Value(raw, `privacy scan output ${index} leaf index`), { required: false, fallback: 0 });
  const output = {
    height,
    global_sequence: globalSequence,
    output_index: outputIndex,
    effect_id: effectId,
    commitment,
    ciphertext: scanOptionalBytes(input, ["ciphertext"], `privacy scan output ${index} ciphertext`),
    encrypted_note: scanOptionalBytes(input, ["encryptedNote", "encrypted_note"], `privacy scan output ${index} encrypted note`),
    view_tag: scanOptionalBytes(input, ["viewTag", "view_tag"], `privacy scan output ${index} view tag`),
    leaf_index: leafIndex,
    leaf_index_found: leafIndexFound,
    user_privacy_policy: aliasedScanValue(input, ["userPrivacyPolicy", "user_privacy_policy"], `privacy scan output ${index} user privacy policy`, raw => scanUint32(raw, `privacy scan output ${index} user privacy policy`), { required: false, fallback: 0 }),
    user_disclosure_mode: aliasedScanValue(input, ["userDisclosureMode", "user_disclosure_mode"], `privacy scan output ${index} user disclosure mode`, raw => String(raw ?? "").trim(), { required: false, fallback: "" }),
    user_disclosure_digest: scanOptionalBytes(input, ["userDisclosureDigest", "user_disclosure_digest"], `privacy scan output ${index} user disclosure digest`),
    user_disclosure_target_pubkey: scanOptionalBytes(input, ["userDisclosureTargetPubkey", "user_disclosure_target_pubkey"], `privacy scan output ${index} user disclosure target`),
    user_disclosure_payload: scanOptionalBytes(input, ["userDisclosurePayload", "user_disclosure_payload"], `privacy scan output ${index} user disclosure payload`),
    full_disclosure_digest: scanOptionalBytes(input, ["fullDisclosureDigest", "full_disclosure_digest"], `privacy scan output ${index} full disclosure digest`),
    audit_disclosure_payload: scanOptionalBytes(input, ["auditDisclosurePayload", "audit_disclosure_payload"], `privacy scan output ${index} audit disclosure payload`),
    self_view_disclosure_payload: scanOptionalBytes(input, ["selfViewDisclosurePayload", "self_view_disclosure_payload"], `privacy scan output ${index} self-view disclosure payload`),
    circuit_set_id: circuitSetId,
    payload_version: payloadVersion,
    scan_schema_version: scanSchemaVersion,
    audit_key_id: aliasedScanValue(input, ["auditKeyId", "audit_key_id"], `privacy scan output ${index} audit key ID`, raw => String(raw ?? ""), { required: false, fallback: "" }),
    audit_key_epoch: aliasedScanValue(input, ["auditKeyEpoch", "audit_key_epoch"], `privacy scan output ${index} audit key epoch`, raw => scanUint64Value(raw, `privacy scan output ${index} audit key epoch`), { required: false, fallback: 0 }),
    audit_target_pubkey: scanOptionalBytes(input, ["auditTargetPubkey", "audit_target_pubkey"], `privacy scan output ${index} audit target`),
    tx_hash: txHash,
    event_type: eventType
  };
  Object.defineProperty(output, validatedPrivacyScanOutputBrandV2, { value: true });
  Object.freeze(output);
  if (output.audit_key_id !== summary.audit_key_id || String(output.audit_key_epoch) !== String(summary.audit_key_epoch) || !equalScanBytes(output.audit_target_pubkey, summary.audit_target_pubkey)) {
    throw new Error(`privacy scan output ${index} does not match its summary audit identity`);
  }
  if (eventType === privacyScanEventTypeV2.deposit) {
    if (output.ciphertext.length || output.view_tag.length) throw new Error(`privacy scan output ${index} deposit framing is invalid`);
    unwrapEncryptedEnvelopeV1(output.encrypted_note, encryptedEnvelopeKindV1.depositNote);
    scanZeroDisclosureSentinel(output, `privacy scan output ${index} deposit`);
  } else if (eventType === privacyScanEventTypeV2.shieldedTransfer || eventType === privacyScanEventTypeV2.batchTransfer) {
    if (output.encrypted_note.length || output.view_tag.length !== 2) throw new Error(`privacy scan output ${index} transfer framing is invalid`);
    unwrapEncryptedEnvelopeV1(output.ciphertext, encryptedEnvelopeKindV1.transferNote);
    if (eventType === privacyScanEventTypeV2.shieldedTransfer && output.output_index === 1) {
      scanZeroDisclosureSentinel(output, `privacy scan output ${index} shielded-transfer change`);
    } else {
      scanBatchOutputDisclosure(output, `privacy scan output ${index}`);
    }
  } else {
    throw new Error(`privacy scan output ${index} has unsupported event type ${JSON.stringify(eventType)}`);
  }
  return output;
}

/** True only for an output emitted by validatePrivacyScanPageV2 in this SDK instance. */
export function isValidatedPrivacyScanOutputV2(value) {
  return Boolean(value && typeof value === "object" && value[validatedPrivacyScanOutputBrandV2] === true);
}

function scanRequest(input = {}) {
  const after = scanCursor(input.after, "privacy scan request after", { required: false });
  const outputLimit = aliasedScanValue(input, ["outputLimit", "output_limit"], "privacy scan request output limit", raw => scanUint32(raw, "privacy scan request output limit"), { required: false, fallback: 0 });
  const eventLimit = aliasedScanValue(input, ["eventLimit", "event_limit"], "privacy scan request event limit", raw => scanUint32(raw, "privacy scan request event limit"), { required: false, fallback: 0 });
  const maxEncodedBytes = aliasedScanValue(input, ["maxEncodedBytes", "max_encoded_bytes"], "privacy scan request byte limit", raw => scanUint64Value(raw, "privacy scan request byte limit"), { required: false, fallback: 0 });
  const eventTypes = aliasedScanValue(input, ["eventTypes", "event_types"], "privacy scan request event types", raw => {
    if (!Array.isArray(raw)) throw new Error("privacy scan request event types must be an array");
    return raw.map(value => String(value || "").trim()).filter(Boolean);
  }, { required: false, fallback: [] });
  return Object.freeze({ after, output_limit: outputLimit, event_limit: eventLimit, max_encoded_bytes: maxEncodedBytes, event_types: Object.freeze(eventTypes) });
}

/** Create mutable validation state for checking typed pages across a cursor sequence. */
export function createPrivacyScanValidationStateV2() {
  return {
    version: privacyScanValidationStateVersionV2,
    batch_self_view_by_event: new Map()
  };
}

function scanValidationEventKey(value) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)\/[1-9][0-9]*$/.test(value)) {
    throw new Error("privacy scan validation state event key is invalid");
  }
  const [height, sequence] = value.split("/");
  scanUint64Value(height, "privacy scan validation state event height");
  scanUint64Value(sequence, "privacy scan validation state event sequence");
  return value;
}

function scanValidationState(input = {}) {
  const camel = input.validationState;
  const snake = input.validation_state;
  if (camel != null && snake != null && camel !== snake) throw new Error("privacy scan validation state aliases do not match");
  const state = camel ?? snake ?? null;
  if (state == null) return null;
  if (!state || typeof state !== "object" || state.version !== privacyScanValidationStateVersionV2 || !(state.batch_self_view_by_event instanceof Map)) {
    throw new Error("privacy scan validation state is invalid");
  }
  for (const [key, enabled] of state.batch_self_view_by_event) {
    scanValidationEventKey(key);
    if (typeof enabled !== "boolean") throw new Error("privacy scan validation state is invalid");
  }
  return state;
}

/** Serialize page-validation state so an interrupted cursor sequence stays fail-closed after restart. */
export function serializePrivacyScanValidationStateV2(input) {
  const state = scanValidationState({ validationState: input });
  const entries = [...state.batch_self_view_by_event]
    .map(([event_key, self_view_enabled]) => Object.freeze({ event_key, self_view_enabled }))
    .sort((left, right) => left.event_key.localeCompare(right.event_key));
  return Object.freeze({
    version: privacyScanValidationStateVersionV2,
    batch_self_view_by_event: Object.freeze(entries)
  });
}

/** Restore serialized page-validation state supplied by a durable scan cursor. */
export function restorePrivacyScanValidationStateV2(input) {
  if (!input || typeof input !== "object" || Array.isArray(input) || input.version !== privacyScanValidationStateVersionV2 || !Array.isArray(input.batch_self_view_by_event)) {
    throw new Error("privacy scan validation state snapshot is invalid");
  }
  const entries = input.batch_self_view_by_event;
  const state = createPrivacyScanValidationStateV2();
  for (const entry of entries) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry) || Object.keys(entry).length !== 2 || !("event_key" in entry) || !("self_view_enabled" in entry)) {
      throw new Error("privacy scan validation state snapshot is invalid");
    }
    const eventKey = scanValidationEventKey(entry.event_key);
    if (typeof entry.self_view_enabled !== "boolean" || state.batch_self_view_by_event.has(eventKey)) {
      throw new Error("privacy scan validation state snapshot is invalid");
    }
    state.batch_self_view_by_event.set(eventKey, entry.self_view_enabled);
  }
  return state;
}

function validateBatchSelfViewDisclosurePage(outputs, summaries, state) {
  const selfViewByEvent = new Map(state?.batch_self_view_by_event);
  for (const output of outputs) {
    if (output.event_type !== privacyScanEventTypeV2.batchTransfer) continue;
    const key = scanEventKey(output);
    const enabled = output.self_view_disclosure_payload.length !== 0;
    if (selfViewByEvent.has(key) && selfViewByEvent.get(key) !== enabled) {
      throw new Error("privacy scan batch self-view disclosure must be all-or-none");
    }
    selfViewByEvent.set(key, enabled);
  }
  for (const summary of summaries) {
    if (summary.event_type !== privacyScanEventTypeV2.batchTransfer) continue;
    const key = scanEventKey(summary);
    if (outputs.some(output => scanEventKey(output) === key && output.output_index === summary.output_count - 1)) {
      selfViewByEvent.delete(key);
    }
  }
  return selfViewByEvent;
}

function commitBatchSelfViewValidationState(state, next) {
  if (!state) return;
  state.batch_self_view_by_event.clear();
  for (const [key, enabled] of next) state.batch_self_view_by_event.set(key, enabled);
}

function validateCompletedPrivacyScanPage(request, page) {
  if (page.has_more) return;
  const outputsByEvent = new Map();
  for (const output of page.outputs) {
    const key = scanEventKey(output);
    if (!outputsByEvent.has(key)) outputsByEvent.set(key, new Set());
    outputsByEvent.get(key).add(output.output_index);
  }
  const afterEvent = eventCursor(request.after);
  for (const summary of page.summaries) {
    const summaryCursor = eventCursor(summary);
    const comparison = compareScanCursor(summaryCursor, afterEvent);
    if (comparison < 0) throw new Error("privacy scan completed page includes a summary before the cursor");
    let firstRequiredIndex = 0;
    if (comparison === 0) {
      if (request.after.output_index >= summary.output_count - 1) continue;
      firstRequiredIndex = request.after.output_index + 1;
    }
    const returned = outputsByEvent.get(scanEventKey(summary)) ?? new Set();
    for (let outputIndex = firstRequiredIndex; outputIndex < summary.output_count; outputIndex += 1) {
      if (!returned.has(outputIndex)) {
        throw new Error("privacy scan completed page omits an output from a summarized event");
      }
    }
  }
}

function validatePrivacyScanNextCursor(request, page, summaries) {
  const after = request.after;
  const last = page.outputs.at(-1);
  if (!last) {
    if (compareScanCursor(page.next_cursor, after) > 0 && request.event_types.length === 0) {
      const nextSummary = summaries.get(scanEventKey(page.next_cursor));
      if (page.next_cursor.output_index !== 0 || !nextSummary || nextSummary.output_count !== 0) {
        throw new Error("privacy scan cursor advance lacks a zero-output summary boundary");
      }
    }
    return;
  }
  const lastCursor = { height: last.height, global_sequence: last.global_sequence, output_index: last.output_index };
  const comparison = compareScanCursor(page.next_cursor, lastCursor);
  if (comparison < 0) throw new Error("privacy scan next cursor precedes the final output");
  const lastSummary = summaries.get(scanEventKey(lastCursor));
  if (!page.has_more && (!lastSummary || last.output_index + 1 !== lastSummary.output_count)) {
    throw new Error("privacy scan completed page ends with an incomplete output event");
  }
  if (comparison === 0) return;
  if (!lastSummary || last.output_index + 1 !== lastSummary.output_count) {
    throw new Error("privacy scan next cursor advances past an incomplete output event");
  }
  const fromEvent = eventCursor(lastCursor);
  const nextEvent = eventCursor(page.next_cursor);
  const nextSummary = summaries.get(scanEventKey(nextEvent));
  if (page.next_cursor.output_index !== 0 || compareScanCursor(nextEvent, fromEvent) <= 0 || !nextSummary || nextSummary.output_count !== 0) {
    throw new Error("privacy scan cursor advance is not a zero-output event boundary");
  }
  for (const summary of page.summaries) {
    const summaryCursor = eventCursor(summary);
    if (compareScanCursor(summaryCursor, fromEvent) > 0 && compareScanCursor(summaryCursor, nextEvent) <= 0 && summary.output_count !== 0) {
      throw new Error("privacy scan next cursor skips an output-bearing summary");
    }
  }
}

/** Validate a privacy-scan-v2 page before decrypting or persisting any output. */
export function validatePrivacyScanPageV2(response, request = {}) {
  if (!response || typeof response !== "object" || Array.isArray(response)) throw new Error("privacy scan response is required");
  const normalizedRequest = scanRequest(request);
  const validationState = scanValidationState(request);
  const schemaVersion = aliasedScanValue(response, ["scanSchemaVersion", "scan_schema_version"], "privacy scan response schema version", raw => scanString(raw, "privacy scan response schema version"));
  if (schemaVersion !== privacyScanSchemaVersionV2) throw new Error(`unsupported privacy scan schema version ${JSON.stringify(schemaVersion)}`);
  const summariesValue = aliasedScanValue(response, ["summaries"], "privacy scan response summaries", raw => {
    if (!Array.isArray(raw)) throw new Error("privacy scan response summaries must be an array");
    return raw;
  }, { required: false, fallback: [] });
  const summaries = summariesValue.map(scanSummary);
  const summariesByEvent = new Map();
  let previousSummary = null;
  for (const summary of summaries) {
    const cursor = eventCursor(summary);
    if (previousSummary && compareScanCursor(previousSummary, cursor) >= 0) throw new Error("privacy scan summaries are not strictly ordered");
    previousSummary = cursor;
    const key = scanEventKey(cursor);
    if (summariesByEvent.has(key)) throw new Error(`privacy scan has duplicate summary ${key}`);
    summariesByEvent.set(key, summary);
  }
  const outputsValue = aliasedScanValue(response, ["outputs"], "privacy scan response outputs", raw => {
    if (!Array.isArray(raw)) throw new Error("privacy scan response outputs must be an array");
    return raw;
  }, { required: false, fallback: [] });
  if (normalizedRequest.output_limit && outputsValue.length > normalizedRequest.output_limit) {
    throw new Error("privacy scan response exceeds the requested output limit");
  }
  const outputs = outputsValue.map((value, index) => scanOutput(value, index, summariesByEvent));
  const nextBatchSelfViewState = validateBatchSelfViewDisclosurePage(outputs, summaries, validationState);
  let previous = normalizedRequest.after;
  const seen = new Set();
  for (const output of outputs) {
    const cursor = { height: output.height, global_sequence: output.global_sequence, output_index: output.output_index };
    if (compareScanCursor(previous, cursor) >= 0) throw new Error("privacy scan outputs are not strictly ordered after the cursor");
    if (previous.height === cursor.height && previous.global_sequence === cursor.global_sequence && cursor.output_index !== previous.output_index + 1) {
      throw new Error("privacy scan output indexes are not contiguous");
    }
    if ((previous.height !== cursor.height || previous.global_sequence !== cursor.global_sequence) && cursor.output_index !== 0) {
      throw new Error("privacy scan output event must begin at index zero");
    }
    const key = `${scanEventKey(cursor)}/${cursor.output_index}`;
    if (seen.has(key)) throw new Error(`privacy scan has duplicate output ${key}`);
    seen.add(key);
    previous = cursor;
  }
  const nextCursor = aliasedScanValue(response, ["nextCursor", "next_cursor"], "privacy scan next cursor", raw => scanCursor(raw, "privacy scan next cursor"));
  if (compareScanCursor(nextCursor, normalizedRequest.after) < 0) throw new Error("privacy scan next cursor regressed");
  const hasMore = aliasedScanValue(response, ["hasMore", "has_more"], "privacy scan has_more", raw => {
    if (typeof raw !== "boolean") throw new Error("privacy scan has_more must be boolean");
    return raw;
  }, { required: false, fallback: false });
  const scannedEventCount = aliasedScanValue(response, ["scannedEventCount", "scanned_event_count"], "privacy scan scanned event count", raw => scanUint32(raw, "privacy scan scanned event count"), { required: false, fallback: 0 });
  const encodedBytes = aliasedScanValue(response, ["encodedBytes", "encoded_bytes"], "privacy scan encoded bytes", raw => scanUint64Value(raw, "privacy scan encoded bytes"), { required: false, fallback: 0 });
  if (normalizedRequest.event_limit && scannedEventCount > normalizedRequest.event_limit) throw new Error("privacy scan response exceeds the requested event limit");
  if (scanUint64(normalizedRequest.max_encoded_bytes, "privacy scan request byte limit") > 0n && scanUint64(encodedBytes, "privacy scan encoded bytes") > scanUint64(normalizedRequest.max_encoded_bytes, "privacy scan request byte limit")) {
    throw new Error("privacy scan response exceeds the requested byte limit");
  }
  const page = Object.freeze({
    scan_schema_version: schemaVersion,
    summaries: Object.freeze(summaries),
    outputs: Object.freeze(outputs),
    next_cursor: nextCursor,
    has_more: hasMore,
    scanned_event_count: scannedEventCount,
    encoded_bytes: encodedBytes
  });
  validatePrivacyScanNextCursor(normalizedRequest, page, summariesByEvent);
  validateCompletedPrivacyScanPage(normalizedRequest, page);
  if (hasMore && compareScanCursor(nextCursor, normalizedRequest.after) <= 0) throw new Error("privacy scan has_more page did not advance the cursor");
  commitBatchSelfViewValidationState(validationState, nextBatchSelfViewState);
  return page;
}

/** Trial-decrypt one already-validated privacy-scan-v2 output. Returns null when it is not owned. */
export function processPrivacyScanOutputV2(output, { rootSeed, spendScalar, viewScalar } = {}) {
  if (!output || typeof output !== "object") throw new Error("validated privacy scan output is required");
  if (!rootSeed) throw new Error("rootSeed is required for privacy scan output decryption");
  let note;
  if (output.event_type === privacyScanEventTypeV2.deposit) {
    try {
      note = decryptDepositNoteV1(output.encrypted_note, rootSeed);
    } catch {
      return null;
    }
  } else if (output.event_type === privacyScanEventTypeV2.shieldedTransfer || output.event_type === privacyScanEventTypeV2.batchTransfer) {
    let viewError;
    try {
      note = decryptTransferNoteV1(output.ciphertext, viewScalar);
    } catch (error) {
      viewError = error;
      if (spendScalar == null || spendScalar === viewScalar) return null;
      try {
        note = decryptTransferNoteV1(output.ciphertext, spendScalar);
      } catch {
        // An authenticated ciphertext for another recipient is indistinguishable
        // from a trial-decrypt miss at this boundary; the page framing was
        // already validated before decryption.
        if (viewError?.message?.includes("NotePlaintextV1")) throw viewError;
        return null;
      }
    }
  } else {
    throw new Error(`unsupported privacy scan output event type ${JSON.stringify(output.event_type)}`);
  }
  const commitment = fieldHexV1(computeNoteCommitmentV1(note));
  if (commitment !== hexFromBytes(output.commitment)) throw new Error("privacy scan NoteV1 commitment mismatch");
  return Object.freeze({
    note,
    nullifier: fieldHexV1(computeNoteNullifierV1(note)),
    isSpent: false,
    nullifierStatus: "unverified",
    txHash: hexFromBytes(output.tx_hash).toUpperCase(),
    height: output.height,
    sequence: output.global_sequence,
    output_index: output.output_index,
    commitment_hex: commitment
  });
}

/** Decrypt the owned notes from one validated unified scan page. */
export function processPrivacyScanPageV2(page, { rootSeed, spendScalar, viewScalar } = {}) {
  if (!page || typeof page !== "object" || !Array.isArray(page.outputs)) throw new Error("validated privacy scan page is required");
  const spend = spendScalar ?? deriveSpendKeys(rootSeed).scalar;
  const view = viewScalar ?? deriveViewKeys(rootSeed).scalar;
  const found = [];
  for (const output of page.outputs) {
    const note = processPrivacyScanOutputV2(output, { rootSeed, spendScalar: spend, viewScalar: view });
    if (note) found.push(note);
  }
  return normalizeFoundNotes(found);
}

export async function scanNotes({
  rootSeed,
  events,
  preprocessedFoundNotes,
  checkNullifier,
  checkNullifiers,
  includeFoundNotes = false
} = {}) {
  if (!rootSeed) {
    throw new Error("rootSeed is required for note scan");
  }
  const spendScalar = deriveSpendKeys(rootSeed).scalar;
  const viewScalar = deriveViewKeys(rootSeed).scalar;
  let found = [];
  if (preprocessedFoundNotes !== undefined) {
    if (!Array.isArray(preprocessedFoundNotes)) throw new Error("preprocessedFoundNotes must be an array");
    found = normalizeFoundNotes(preprocessedFoundNotes);
  } else {
    for (const event of events || []) {
      found.push(...processPrivacyEvent(event, { rootSeed, spendScalar, viewScalar }));
    }
  }

  found = normalizeFoundNotes(found);

  let batchSpentRefreshSucceeded = false;
  let missingBatchNullifiers = null;
  if (checkNullifiers && found.length) {
    try {
      const nullifiers = [...new Set(found.map(note => String(note.nullifier || "").toLowerCase()).filter(Boolean))];
      const result = await checkNullifiers(nullifiers);
      const statuses = new Map();
      const invalidStatuses = new Set();
      const addStatus = (nullifier, value) => {
        const key = String(nullifier || "").trim().toLowerCase();
        if (!key || invalidStatuses.has(key)) return;
        const used = parseNullifierUsage(value);
        if (used === null || (statuses.has(key) && statuses.get(key) !== used)) {
          statuses.delete(key);
          invalidStatuses.add(key);
          return;
        }
        statuses.set(key, used);
      };
      if (result instanceof Map) {
        for (const [nullifier, value] of result) addStatus(nullifier, value);
      } else {
        if (Array.isArray(result?.statuses)) {
          for (const status of result.statuses) {
            const canonical = status?.nullifier;
            const alias = status?.Nullifier;
            if (canonical != null && alias != null &&
                String(canonical).trim().toLowerCase() !== String(alias).trim().toLowerCase()) {
              addStatus(canonical, null);
              addStatus(alias, null);
            } else {
              addStatus(canonical ?? alias, status);
            }
          }
        } else if (result && typeof result === "object") {
          for (const [key, value] of Object.entries(result)) {
            addStatus(key, value);
          }
        }
      }
      const missing = nullifiers.filter(nullifier => !statuses.has(nullifier));
      for (const note of found) {
        if (statuses.has(note.nullifier)) {
          note.isSpent = statuses.get(note.nullifier);
          note.nullifierStatus = note.isSpent ? "spent" : "unspent";
        }
      }
      batchSpentRefreshSucceeded = missing.length === 0;
      if (!batchSpentRefreshSucceeded) {
        missingBatchNullifiers = new Set(missing);
      }
    } catch {
      // Fall back to individual checks below when the batch path is unavailable.
    }
  }

  if (!batchSpentRefreshSucceeded && checkNullifier && (
    missingBatchNullifiers?.size || found.some(note => !note.isSpent)
  )) {
    for (const note of found) {
      if (missingBatchNullifiers) {
        if (!missingBatchNullifiers.has(note.nullifier)) continue;
      } else if (note.isSpent) {
        continue;
      }
      try {
        const result = await checkNullifier(note.nullifier);
        const used = parseNullifierUsage(result);
        if (used === null) {
          note.isSpent = false;
          note.nullifierStatus = "unknown";
        } else {
          note.isSpent = used;
          note.nullifierStatus = used ? "spent" : "unspent";
        }
      } catch {
        note.isSpent = false;
        note.nullifierStatus = "unknown";
      }
    }
  }

  const summary = {
    total_spendable: "0",
    spendable_count: 0,
    spent_count: 0,
    total_count: found.length
  };
  let total = 0n;
  for (const note of found) {
    if (note.isSpent) {
      summary.spent_count += 1;
    } else if (note.nullifierStatus === "unspent") {
      summary.spendable_count += 1;
      total += note.note.amount;
    }
  }
  summary.total_spendable = total.toString();

  const result = {
    notes: found.map(noteResponse),
    summary,
    diagnostics: {
      scanned_events: (events || []).length,
      new_notes_found: found.length,
      unverified_nullifier_count: found.filter(note =>
        note.nullifierStatus === "unknown" || note.nullifierStatus === "unverified"
      ).length
    }
  };
  if (includeFoundNotes) {
    result.foundNotes = found;
  }
  return result;
}
