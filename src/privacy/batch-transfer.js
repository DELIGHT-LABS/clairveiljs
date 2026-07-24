import { base64FromBytes, bytesFromBase64, bytesFromHex, hexFromBytes, sha256Hex } from "../core/browser-crypto.js";
import { CURVE_ORDER, FIELD_MODULUS, bytesToBigIntBE, normalizeHex, packPoint, unpackPoint } from "../core/crypto.js";
import {
  canonicalBatchTransferPayloadBytesV1,
  computeBatchFullDisclosureDigestV1,
  computeBatchTransferIntentV1,
  computeBatchTransferPayloadDigestV1,
  computeBatchUserDisclosureDigestV1,
  computeBatchUserDisclosureVectorRootV1,
  computeBatchVectorRootV1,
  computeChainDomainV1,
  computeNoteCommitmentV1,
  computeNoteNullifierV1,
  computeNoteTreeNodeV1,
  encryptDisclosureV1,
  encryptNoteForTransferV1,
  encryptedEnvelopeKindV1,
  marshalDisclosurePlaintextV1,
  validateBatchTransferEffectsV1,
  validateNoteV1
} from "./protocol-v1.js";

export const preparedBatchTransferPayloadVersion = "batch-transfer-payload-v1";
export const preparedBatchTransferProofVersion = "batch-transfer-proof-v1";
export const batchTransferCircuitSetId = "privacy-note-v1";
export const batchTransferProofRequestVersion = "v1";
export const batchTransferProofResponseVersion = "v1";
export const batchTransferProofPath = "/v1/proofs/batch-transfer";
export const batchTransferProofSize = 164;

const preparedBatchTransferPayloadHashDomain = "clairveil.prepared-batch-transfer.v1";

function byteValue(value, label) {
  if (value instanceof Uint8Array) return Uint8Array.from(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
  if (value instanceof ArrayBuffer) return new Uint8Array(value).slice();
  if (typeof value === "string") return bytesFromHex(value, label);
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new Error(`${label} must be bytes`);
}

function integer(value, label, { bits, nonZero = false } = {}) {
  let parsed;
  if (typeof value === "bigint") parsed = value;
  else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error(`${label} must be a safe integer or canonical decimal string`);
    parsed = BigInt(value);
  } else {
    const text = String(value ?? "");
    if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error(`${label} must be a canonical non-negative decimal integer`);
    parsed = BigInt(text);
  }
  if (bits != null && parsed >= (1n << BigInt(bits))) throw new Error(`${label} exceeds ${bits} bits`);
  if (nonZero && parsed === 0n) throw new Error(`${label} must be non-zero`);
  return parsed;
}

function canonicalField(value, label, { nonZero = false } = {}) {
  const parsed = integer(value, label, { nonZero });
  if (parsed >= FIELD_MODULUS) throw new Error(`${label} must be a canonical BN254 field element`);
  return parsed;
}

function canonicalFieldBytes(value, label, options) {
  const raw = typeof value === "string" || value instanceof Uint8Array || ArrayBuffer.isView(value) || value instanceof ArrayBuffer
    ? byteValue(value, label)
    : null;
  if (raw) {
    if (raw.length !== 32) throw new Error(`${label} must be exactly 32 bytes`);
    const parsed = bytesToBigIntBE(raw);
    if (parsed >= FIELD_MODULUS || (options?.nonZero && parsed === 0n)) throw new Error(`${label} must be a${options?.nonZero ? " non-zero" : ""} canonical BN254 field element`);
    return { bytes: raw, value: parsed };
  }
  const parsed = canonicalField(value, label, options);
  const output = new Uint8Array(32);
  let cursor = parsed;
  for (let index = 31; index >= 0; index -= 1) {
    output[index] = Number(cursor & 0xffn);
    cursor >>= 8n;
  }
  return { bytes: output, value: parsed };
}

function pointValue(value, label) {
  let raw;
  if (value && typeof value === "object" && !(value instanceof Uint8Array) && !ArrayBuffer.isView(value) && !(value instanceof ArrayBuffer) && !Array.isArray(value) && Object.hasOwn(value, "x")) {
    raw = packPoint({ x: canonicalField(value.x, `${label} x`), y: canonicalField(value.y, `${label} y`) });
  } else {
    raw = byteValue(value, label);
    if (raw.length !== 32) throw new Error(`${label} must be exactly 32 bytes`);
  }
  try {
    const point = unpackPoint(raw);
    if (point.x === 0n && point.y === 1n) throw new Error("point identity is not allowed");
    return { point, bytes: raw };
  } catch (error) {
    throw new Error(`${label} must be a canonical prime-subgroup point: ${error.message}`);
  }
}

function noteFromPayload(value, label) {
  if (!value || typeof value !== "object") throw new Error(`${label} note is required`);
  return validateNoteV1({
    receiverSpendPubKeyX: value.receiverSpendPubKeyX ?? value.rsx,
    receiverSpendPubKeyY: value.receiverSpendPubKeyY ?? value.rsy,
    receiverViewPubKeyX: value.receiverViewPubKeyX ?? value.rvx,
    receiverViewPubKeyY: value.receiverViewPubKeyY ?? value.rvy,
    amount: value.amount ?? value.am,
    assetID: value.assetID ?? value.asset_id ?? value.as,
    randomness: value.randomness ?? value.rn,
    memo: value.memo ?? value.mm ?? ""
  });
}

function noteForGoJson(note) {
  return {
    rsx: note.receiverSpendPubKeyX.toString(), rsy: note.receiverSpendPubKeyY.toString(),
    rvx: note.receiverViewPubKeyX.toString(), rvy: note.receiverViewPubKeyY.toString(),
    am: note.amount.toString(), as: note.assetID.toString(), rn: note.randomness.toString(), mm: note.memo
  };
}

function sameOwner(left, right) {
  return left.receiverSpendPubKeyX === right.receiverSpendPubKeyX
    && left.receiverSpendPubKeyY === right.receiverSpendPubKeyY
    && left.receiverViewPubKeyX === right.receiverViewPubKeyX
    && left.receiverViewPubKeyY === right.receiverViewPubKeyY;
}

function fixedFieldBytes(value) {
  const output = new Uint8Array(32);
  let cursor = value;
  for (let index = 31; index >= 0; index -= 1) {
    output[index] = Number(cursor & 0xffn);
    cursor >>= 8n;
  }
  return output;
}

function sameBytes(left, right) {
  const a = Uint8Array.from(left ?? []);
  const b = Uint8Array.from(right ?? []);
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function frozenBytes(value) {
  return Uint8Array.from(value ?? []);
}

function signingNote(note) {
  const normalized = validateNoteV1(note);
  return Object.freeze({
    receiverSpendPubKeyX: normalized.receiverSpendPubKeyX,
    receiverSpendPubKeyY: normalized.receiverSpendPubKeyY,
    receiverViewPubKeyX: normalized.receiverViewPubKeyX,
    receiverViewPubKeyY: normalized.receiverViewPubKeyY,
    amount: normalized.amount,
    assetID: normalized.assetID,
    randomness: normalized.randomness,
    memo: normalized.memo
  });
}

function notePointBytes(note, kind) {
  const normalized = validateNoteV1(note);
  return frozenBytes(packPoint(kind === "spend"
    ? { x: normalized.receiverSpendPubKeyX, y: normalized.receiverSpendPubKeyY }
    : { x: normalized.receiverViewPubKeyX, y: normalized.receiverViewPubKeyY }));
}

function cloneBatchWireOutput(output) {
  return Object.freeze({
    commitment: frozenBytes(output.commitment),
    ciphertext: frozenBytes(output.ciphertext),
    viewTag: frozenBytes(output.viewTag),
    userPrivacyPolicy: Number(output.userPrivacyPolicy),
    userDisclosureMode: Number(output.userDisclosureMode),
    userDisclosureDigest: frozenBytes(output.userDisclosureDigest),
    userDisclosureTargetPubkey: frozenBytes(output.userDisclosureTargetPubkey),
    userDisclosurePayload: frozenBytes(output.userDisclosurePayload),
    fullDisclosureDigest: frozenBytes(output.fullDisclosureDigest),
    auditDisclosurePayload: frozenBytes(output.auditDisclosurePayload),
    selfViewDisclosurePayload: frozenBytes(output.selfViewDisclosurePayload)
  });
}

function sameBatchWireOutput(left, right) {
  if (!left || !right || typeof left !== "object" || typeof right !== "object") return false;
  return Number(left.userPrivacyPolicy) === Number(right.userPrivacyPolicy) &&
    Number(left.userDisclosureMode) === Number(right.userDisclosureMode) &&
    [
      "commitment", "ciphertext", "viewTag", "userDisclosureDigest",
      "userDisclosureTargetPubkey", "userDisclosurePayload", "fullDisclosureDigest",
      "auditDisclosurePayload", "selfViewDisclosurePayload"
    ].every(field => sameBytes(left[field], right[field]));
}

function decimalField(value, label, options) {
  return canonicalField(value, label, options).toString();
}

function safePositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${label} must be a positive safe integer`);
  return value;
}

function positiveUint64(value, label) {
  const parsed = integer(value, label, { bits: 64, nonZero: true });
  if (parsed < 0n) throw new Error(`${label} must be a positive uint64`);
  return parsed;
}

function goString(value) {
  return JSON.stringify(String(value)).replace(/[<>&\u2028\u2029]/g, character => ({ "<": "\\u003c", ">": "\\u003e", "&": "\\u0026", "\u2028": "\\u2028", "\u2029": "\\u2029" })[character]);
}

function goObject(entries) {
  return `{${entries.filter(([, value]) => value !== undefined).map(([name, value]) => `${goString(name)}:${value}`).join(",")}}`;
}

function goArray(values) {
  return `[${values.join(",")}]`;
}

function canonicalBase64(value, label, { allowEmpty = false } = {}) {
  const text = String(value ?? "");
  if (!text && allowEmpty) return new Uint8Array();
  let decoded;
  try {
    decoded = bytesFromBase64(text, label);
  } catch (error) {
    throw new Error(`${label} must be standard base64: ${error.message}`);
  }
  if (base64FromBytes(decoded) !== text) throw new Error(`${label} must be canonical standard base64`);
  return decoded;
}

function exactBase64(value, label, length, options) {
  const decoded = canonicalBase64(value, label, options);
  if (decoded.length !== length) throw new Error(`${label} must be exactly ${length} bytes`);
  return decoded;
}

function fieldHex(value, label) {
  const normalized = normalizeHex(value, label);
  if (normalized.length !== 64) throw new Error(`${label} must be a 32-byte hex string`);
  return normalized;
}

function parseMessageOutput(output, index) {
  if (!output || typeof output !== "object") throw new Error(`batch message output ${index} is required`);
  const policy = Number(output.user_privacy_policy);
  const mode = Number(output.user_disclosure_mode);
  if (!Number.isInteger(policy) || policy < 0 || policy > 7) throw new Error(`batch message output ${index} has invalid user privacy policy`);
  if (!Number.isInteger(mode) || mode < 0 || mode > 2) throw new Error(`batch message output ${index} has invalid user disclosure mode`);
  return {
    commitment: exactBase64(output.commitment, `batch message output ${index} commitment`, 32),
    ciphertext: exactBase64(output.ciphertext, `batch message output ${index} ciphertext`, 430),
    viewTag: exactBase64(output.view_tag, `batch message output ${index} view tag`, 2),
    userPrivacyPolicy: policy,
    userDisclosureMode: mode,
    userDisclosureDigest: canonicalBase64(output.user_disclosure_digest, `batch message output ${index} user disclosure digest`, { allowEmpty: true }),
    userDisclosureTargetPubkey: canonicalBase64(output.user_disclosure_target_pubkey, `batch message output ${index} user disclosure target`, { allowEmpty: true }),
    userDisclosurePayload: canonicalBase64(output.user_disclosure_payload, `batch message output ${index} user disclosure payload`, { allowEmpty: true }),
    fullDisclosureDigest: exactBase64(output.full_disclosure_digest, `batch message output ${index} full disclosure digest`, 32),
    auditDisclosurePayload: exactBase64(output.audit_disclosure_payload, `batch message output ${index} audit disclosure payload`, 472),
    selfViewDisclosurePayload: canonicalBase64(output.self_view_disclosure_payload, `batch message output ${index} self-view disclosure payload`, { allowEmpty: true })
  };
}

function parsedBatchEffect(payload, { creator = "", proof = new Uint8Array() } = {}) {
  if (!payload || typeof payload !== "object") throw new Error("prepared batch transfer payload is required");
  if (payload.version !== preparedBatchTransferPayloadVersion) throw new Error(`unsupported prepared batch transfer payload version ${JSON.stringify(payload.version)}`);
  if (payload.circuit_set_id !== batchTransferCircuitSetId) throw new Error(`unsupported prepared batch transfer circuit set ${JSON.stringify(payload.circuit_set_id)}`);
  if (!String(payload.chain_id ?? "").trim()) throw new Error("prepared batch transfer chain ID is required");
  const expiresAtUnix = safePositiveInteger(payload.expires_at_unix, "prepared batch transfer expires_at_unix");
  if (!Array.isArray(payload.inputs) || payload.inputs.length < 1 || payload.inputs.length > 16) throw new Error("prepared batch transfer requires 1..16 inputs");
  if (!Array.isArray(payload.outputs) || payload.outputs.length < 1 || payload.outputs.length > 32) throw new Error("prepared batch transfer requires 1..32 outputs");
  if (!Array.isArray(payload.message_outputs) || payload.message_outputs.length !== payload.outputs.length) throw new Error("prepared batch transfer message output count mismatch");
  const message = {
    creator,
    proof,
    root: exactBase64(payload.root, "prepared batch transfer root", 32),
    nullifiers: payload.inputs.map((input, index) => exactBase64(input?.nullifier, `prepared batch transfer input ${index} nullifier`, 32)),
    outputs: payload.message_outputs.map(parseMessageOutput),
    auditKeyId: String(payload.audit_key_id ?? ""),
    auditKeyEpoch: positiveUint64(payload.audit_key_epoch, "prepared batch transfer audit key epoch"),
    auditDisclosureTargetPubkey: exactBase64(payload.audit_disclosure_target_pubkey, "prepared batch transfer audit disclosure target", 32),
    expiresAtUnix: BigInt(expiresAtUnix)
  };
  validateBatchTransferEffectsV1(message);
  return message;
}

function normalizePreparedInput(input, index, expectedRoot) {
  if (!input || typeof input !== "object") throw new Error(`prepared batch input ${index} is required`);
  const note = noteFromPayload(input.note ?? input, `prepared batch input ${index}`);
  if (!Array.isArray(input.merklePath ?? input.merkle_path) || !Array.isArray(input.merklePathHelper ?? input.merkle_path_helper)) {
    throw new Error(`prepared batch input ${index} merkle path and helper are required`);
  }
  const merklePath = input.merklePath ?? input.merkle_path;
  const merklePathHelper = input.merklePathHelper ?? input.merkle_path_helper;
  if (merklePath.length !== 32 || merklePathHelper.length !== 32) throw new Error(`prepared batch input ${index} requires a 32-level merkle path`);
  let current = computeNoteCommitmentV1(note);
  const path = merklePath.map((entry, level) => {
    const normalized = fieldHex(entry, `prepared batch input ${index} merkle path ${level}`);
    const sibling = bytesToBigIntBE(bytesFromHex(normalized, `prepared batch input ${index} merkle path ${level}`));
    const helper = Number(merklePathHelper[level]);
    if (helper !== 0 && helper !== 1) throw new Error(`prepared batch input ${index} merkle helper ${level} must be 0 or 1`);
    current = helper === 0 ? computeNoteTreeNodeV1(level, current, sibling) : computeNoteTreeNodeV1(level, sibling, current);
    return normalized;
  });
  const root = fixedFieldBytes(current);
  if (expectedRoot && hexFromBytes(root) !== hexFromBytes(expectedRoot)) throw new Error("batch transfer input roots differ; wallet sync and replan are required");
  const nullifier = fixedFieldBytes(computeNoteNullifierV1(note));
  return {
    note,
    root,
    nullifier,
    merklePath: path,
    merklePathHelper: merklePathHelper.map(Number),
    json: { note: noteForGoJson(note), merkle_path: path, merkle_path_helper: merklePathHelper.map(Number), nullifier: base64FromBytes(nullifier) }
  };
}

function normalizePreparedOutput(output, index, owner) {
  if (!output || typeof output !== "object") throw new Error(`prepared batch output ${index} is required`);
  const kind = String(output.kind ?? "");
  if (!["payment", "change", "padding"].includes(kind)) throw new Error(`prepared batch output ${index} kind is invalid`);
  const note = noteFromPayload(output.note ?? output, `prepared batch output ${index}`);
  const privacyPolicy = Number(output.privacyPolicy ?? output.privacy_policy ?? 0);
  const disclosureMode = Number(output.disclosureMode ?? output.disclosure_mode ?? 0);
  if (!Number.isInteger(privacyPolicy) || privacyPolicy < 0 || privacyPolicy > 7) throw new Error(`prepared batch output ${index} privacy policy must be in 0..7`);
  if (!Number.isInteger(disclosureMode) || disclosureMode < 0 || disclosureMode > 2) throw new Error(`prepared batch output ${index} disclosure mode must be in 0..2`);
  const providedTarget = output.disclosureTargetPubKey ?? output.disclosure_target_pubkey;
  let disclosureTarget;
  if (privacyPolicy === 0) {
    if (disclosureMode !== 0 || providedTarget != null) throw new Error(`prepared batch output ${index} all-private disclosure is not canonical`);
  } else if (disclosureMode === 1) {
    if (providedTarget != null) throw new Error(`prepared batch output ${index} public disclosure must not include a target`);
  } else if (disclosureMode === 2) {
    if (providedTarget == null) throw new Error(`prepared batch output ${index} recipient-encrypted disclosure requires a target`);
    disclosureTarget = pointValue(providedTarget, `prepared batch output ${index} disclosure target`);
  } else {
    throw new Error(`prepared batch output ${index} disclosed output requires public or recipient-encrypted mode`);
  }
  const userDisclosureBlinding = canonicalField(output.userDisclosureBlinding ?? output.user_disclosure_blinding ?? 0, `prepared batch output ${index} user disclosure blinding`, { nonZero: privacyPolicy !== 0 });
  if (privacyPolicy === 0 && userDisclosureBlinding !== 0n) throw new Error(`prepared batch output ${index} all-private user blinding must be zero`);
  const fullDisclosureBlinding = canonicalField(output.fullDisclosureBlinding ?? output.full_disclosure_blinding, `prepared batch output ${index} full disclosure blinding`, { nonZero: true });
  if (kind === "payment") {
    if (note.amount === 0n) throw new Error(`prepared batch payment output ${index} must be positive`);
  } else if (!sameOwner(owner, note) || privacyPolicy !== 0) {
    throw new Error(`prepared batch ${kind} output ${index} must be all-private and owned by the sender`);
  } else if ((kind === "change" && note.amount === 0n) || (kind === "padding" && note.amount !== 0n)) {
    throw new Error(`prepared batch ${kind} output ${index} amount is not canonical`);
  }
  return {
    kind, note, privacyPolicy, disclosureMode, disclosureTarget, userDisclosureBlinding, fullDisclosureBlinding,
    commitment: computeNoteCommitmentV1(note),
    json: {
      kind,
      note: noteForGoJson(note),
      privacy_policy: privacyPolicy,
      disclosure_mode: disclosureMode,
      ...(disclosureTarget ? { disclosure_target_pubkey: base64FromBytes(disclosureTarget.bytes) } : {}),
      user_disclosure_blinding: userDisclosureBlinding.toString(),
      full_disclosure_blinding: fullDisclosureBlinding.toString()
    }
  };
}

function validateOutputOrderAndConservation(inputs, outputs) {
  const inputTotal = inputs.reduce((total, input) => total + input.note.amount, 0n);
  const outputTotal = outputs.reduce((total, output) => total + output.note.amount, 0n);
  let payment = false;
  let change = false;
  let padding = false;
  for (const [index, output] of outputs.entries()) {
    if (output.kind === "payment") {
      if (change || padding) throw new Error(`prepared batch payment output ${index} must be a prefix`);
      payment = true;
    } else if (output.kind === "change") {
      if (change || padding) throw new Error(`prepared batch change output ${index} is not canonical`);
      change = true;
    } else {
      padding = true;
    }
  }
  if (!payment || inputTotal !== outputTotal) throw new Error("prepared batch transfer input/output conservation failed");
}

function validateSecretIndependence(inputs, outputs) {
  const seen = new Set();
  const register = (secret, label, { nonZero = false } = {}) => {
    const value = canonicalField(secret, label, { nonZero });
    const encoded = value.toString();
    if (seen.has(encoded)) throw new Error(`${label} reuses an input/output secret; randomness and disclosure blindings must be independent`);
    seen.add(encoded);
  };
  inputs.forEach((input, index) => register(input.note.randomness, `prepared batch input ${index} randomness`));
  outputs.forEach((output, index) => {
    register(output.note.randomness, `prepared batch output ${index} randomness`, { nonZero: true });
    register(output.fullDisclosureBlinding, `prepared batch output ${index} full disclosure blinding`, { nonZero: true });
    if (output.privacyPolicy !== 0) register(output.userDisclosureBlinding, `prepared batch output ${index} user disclosure blinding`, { nonZero: true });
  });
}

function disclosureForOutput(output, owner, index, full) {
  const zero = 0n;
  const base = {
    plane: full ? 2 : 1,
    outputIndex: index,
    policy: full ? 0xffffffff : output.privacyPolicy,
    disclosedFieldBitmap: full ? 7 : output.privacyPolicy,
    commitment: output.commitment,
    amount: zero,
    assetID: zero,
    senderSpendKeyX: zero, senderSpendKeyY: zero, senderViewKeyX: zero, senderViewKeyY: zero,
    recipientSpendKeyX: zero, recipientSpendKeyY: zero, recipientViewKeyX: zero, recipientViewKeyY: zero,
    disclosureBlinding: output.userDisclosureBlinding
  };
  if (full) {
    Object.assign(base, {
      amount: output.note.amount,
      assetID: output.note.assetID,
      senderSpendKeyX: owner.receiverSpendPubKeyX, senderSpendKeyY: owner.receiverSpendPubKeyY,
      senderViewKeyX: owner.receiverViewPubKeyX, senderViewKeyY: owner.receiverViewPubKeyY,
      recipientSpendKeyX: output.note.receiverSpendPubKeyX, recipientSpendKeyY: output.note.receiverSpendPubKeyY,
      recipientViewKeyX: output.note.receiverViewPubKeyX, recipientViewKeyY: output.note.receiverViewPubKeyY,
      disclosureBlinding: output.fullDisclosureBlinding
    });
    return {
      plaintext: base,
      digest: computeBatchFullDisclosureDigestV1({
        outputIndex: index, commitment: output.commitment, amount: output.note.amount, assetID: output.note.assetID,
        sender: { x: owner.receiverSpendPubKeyX, y: owner.receiverSpendPubKeyY },
        senderSpendKeyX: owner.receiverSpendPubKeyX, senderSpendKeyY: owner.receiverSpendPubKeyY,
        senderViewKeyX: owner.receiverViewPubKeyX, senderViewKeyY: owner.receiverViewPubKeyY,
        recipient: { x: output.note.receiverSpendPubKeyX, y: output.note.receiverSpendPubKeyY },
        recipientSpendKeyX: output.note.receiverSpendPubKeyX, recipientSpendKeyY: output.note.receiverSpendPubKeyY,
        recipientViewKeyX: output.note.receiverViewPubKeyX, recipientViewKeyY: output.note.receiverViewPubKeyY,
        fullDisclosureBlinding: output.fullDisclosureBlinding
      })
    };
  }
  if (output.privacyPolicy === 0) return { plaintext: null, digest: 0n };
  base.assetID = output.note.assetID;
  if (output.privacyPolicy & 1) base.amount = output.note.amount;
  if (output.privacyPolicy & 4) {
    base.senderSpendKeyX = owner.receiverSpendPubKeyX; base.senderSpendKeyY = owner.receiverSpendPubKeyY;
    base.senderViewKeyX = owner.receiverViewPubKeyX; base.senderViewKeyY = owner.receiverViewPubKeyY;
  }
  if (output.privacyPolicy & 2) {
    base.recipientSpendKeyX = output.note.receiverSpendPubKeyX; base.recipientSpendKeyY = output.note.receiverSpendPubKeyY;
    base.recipientViewKeyX = output.note.receiverViewPubKeyX; base.recipientViewKeyY = output.note.receiverViewPubKeyY;
  }
  return {
    plaintext: base,
    digest: computeBatchUserDisclosureDigestV1({
      outputIndex: index, commitment: output.commitment, policy: output.privacyPolicy, disclosedFieldBitmap: output.privacyPolicy,
      selectedAmount: base.amount,
      selectedFromSpendKeyX: base.senderSpendKeyX, selectedFromSpendKeyY: base.senderSpendKeyY,
      selectedFromViewKeyX: base.senderViewKeyX, selectedFromViewKeyY: base.senderViewKeyY,
      selectedToSpendKeyX: base.recipientSpendKeyX, selectedToSpendKeyY: base.recipientSpendKeyY,
      selectedToViewKeyX: base.recipientViewKeyX, selectedToViewKeyY: base.recipientViewKeyY,
      assetID: base.assetID, userDisclosureBlinding: output.userDisclosureBlinding
    })
  };
}

function serializeGoNote(value, label) {
  const note = noteFromPayload(value, label);
  return goObject([
    ["rsx", decimalField(note.receiverSpendPubKeyX, `${label} rsx`)],
    ["rsy", decimalField(note.receiverSpendPubKeyY, `${label} rsy`)],
    ["rvx", decimalField(note.receiverViewPubKeyX, `${label} rvx`)],
    ["rvy", decimalField(note.receiverViewPubKeyY, `${label} rvy`)],
    ["am", integer(note.amount, `${label} amount`, { bits: 64 }).toString()],
    ["as", decimalField(note.assetID, `${label} asset ID`)],
    ["rn", decimalField(note.randomness, `${label} randomness`)],
    ["mm", goString(note.memo)]
  ]);
}

function serializedBase64(value, label, length, { allowEmpty = false } = {}) {
  const raw = length == null ? canonicalBase64(value, label, { allowEmpty }) : exactBase64(value, label, length, { allowEmpty });
  return goString(base64FromBytes(raw));
}

function serializePreparedInput(value, index) {
  if (!value || typeof value !== "object") throw new Error(`prepared batch transfer input ${index} is required`);
  const path = value.merkle_path;
  const helpers = value.merkle_path_helper;
  if (!Array.isArray(path) || !Array.isArray(helpers) || path.length !== 32 || helpers.length !== 32) {
    throw new Error(`prepared batch transfer input ${index} requires a 32-level merkle path`);
  }
  const canonicalPath = path.map((entry, level) => goString(fieldHex(entry, `prepared batch transfer input ${index} path ${level}`)));
  const canonicalHelpers = helpers.map((entry, level) => {
    if (entry !== 0 && entry !== 1) throw new Error(`prepared batch transfer input ${index} helper ${level} must be 0 or 1`);
    return String(entry);
  });
  return goObject([
    ["note", serializeGoNote(value.note, `prepared batch transfer input ${index}`)],
    ["merkle_path", goArray(canonicalPath)],
    ["merkle_path_helper", goArray(canonicalHelpers)],
    ["nullifier", serializedBase64(value.nullifier, `prepared batch transfer input ${index} nullifier`, 32)]
  ]);
}

function serializePreparedOutput(value, index) {
  if (!value || typeof value !== "object") throw new Error(`prepared batch transfer output ${index} is required`);
  const policy = Number(value.privacy_policy);
  const mode = Number(value.disclosure_mode);
  if (!Number.isInteger(policy) || policy < 0 || policy > 7 || !Number.isInteger(mode) || mode < 0 || mode > 2) {
    throw new Error(`prepared batch transfer output ${index} disclosure metadata is invalid`);
  }
  const target = String(value.disclosure_target_pubkey ?? "");
  return goObject([
    ["kind", goString(value.kind)],
    ["note", serializeGoNote(value.note, `prepared batch transfer output ${index}`)],
    ["privacy_policy", String(policy)],
    ["disclosure_mode", String(mode)],
    ["disclosure_target_pubkey", target ? serializedBase64(target, `prepared batch transfer output ${index} disclosure target`, 32) : undefined],
    ["user_disclosure_blinding", decimalField(value.user_disclosure_blinding, `prepared batch transfer output ${index} user disclosure blinding`)],
    ["full_disclosure_blinding", decimalField(value.full_disclosure_blinding, `prepared batch transfer output ${index} full disclosure blinding`, { nonZero: true })]
  ]);
}

function serializeMessageOutput(value, index) {
  const output = parseMessageOutput(value, index);
  return goObject([
    ["commitment", goString(base64FromBytes(output.commitment))],
    ["ciphertext", goString(base64FromBytes(output.ciphertext))],
    ["view_tag", goString(base64FromBytes(output.viewTag))],
    ["user_privacy_policy", output.userPrivacyPolicy ? String(output.userPrivacyPolicy) : undefined],
    ["user_disclosure_mode", output.userDisclosureMode ? String(output.userDisclosureMode) : undefined],
    ["user_disclosure_digest", output.userDisclosureDigest.length ? goString(base64FromBytes(output.userDisclosureDigest)) : undefined],
    ["user_disclosure_target_pubkey", output.userDisclosureTargetPubkey.length ? goString(base64FromBytes(output.userDisclosureTargetPubkey)) : undefined],
    ["user_disclosure_payload", output.userDisclosurePayload.length ? goString(base64FromBytes(output.userDisclosurePayload)) : undefined],
    ["full_disclosure_digest", goString(base64FromBytes(output.fullDisclosureDigest))],
    ["audit_disclosure_payload", goString(base64FromBytes(output.auditDisclosurePayload))],
    ["self_view_disclosure_payload", output.selfViewDisclosurePayload.length ? goString(base64FromBytes(output.selfViewDisclosurePayload)) : undefined]
  ]);
}

function canonicalOwnerSignature(value) {
  const signature = exactBase64(value, "prepared batch transfer owner signature", 64);
  try {
    unpackPoint(signature.slice(0, 32));
  } catch (error) {
    throw new Error(`prepared batch transfer owner signature point is invalid: ${error.message}`);
  }
  if (bytesToBigIntBE(signature.slice(32)) >= CURVE_ORDER) throw new Error("prepared batch transfer owner signature scalar is not canonical");
  return signature;
}

function serializePreparedBatchTransferPayloadJson(payload, { forHash = false } = {}) {
  if (!payload || typeof payload !== "object") throw new Error("prepared batch transfer payload is required");
  if (payload.version !== preparedBatchTransferPayloadVersion || payload.circuit_set_id !== batchTransferCircuitSetId) {
    throw new Error("unsupported prepared batch transfer payload version or circuit");
  }
  if (!String(payload.chain_id ?? "").trim()) throw new Error("prepared batch transfer chain ID is required");
  const expiresAtUnix = safePositiveInteger(payload.expires_at_unix, "prepared batch transfer expires_at_unix");
  if (!Array.isArray(payload.inputs) || payload.inputs.length < 1 || payload.inputs.length > 16 || !Array.isArray(payload.outputs) || payload.outputs.length < 1 || payload.outputs.length > 32 || !Array.isArray(payload.message_outputs) || payload.message_outputs.length !== payload.outputs.length) {
    throw new Error("prepared batch transfer payload has invalid input/output counts");
  }
  const root = serializedBase64(payload.root, "prepared batch transfer root", 32);
  const assetID = decimalField(payload.asset_id, "prepared batch transfer asset ID", { nonZero: true });
  const auditEpoch = positiveUint64(payload.audit_key_epoch, "prepared batch transfer audit key epoch");
  const auditTarget = serializedBase64(payload.audit_disclosure_target_pubkey, "prepared batch transfer audit disclosure target", 32);
  const signature = canonicalOwnerSignature(payload.owner_signature);
  const payloadHash = forHash ? "" : fieldHex(payload.payload_hash, "prepared batch transfer payload hash");
  return goObject([
    ["version", goString(payload.version)],
    ["circuit_set_id", goString(payload.circuit_set_id)],
    ["creator", !forHash && String(payload.creator ?? "") ? goString(payload.creator) : undefined],
    ["chain_id", goString(payload.chain_id)],
    ["expires_at_unix", String(expiresAtUnix)],
    ["root", root],
    ["asset_id", assetID],
    ["inputs", goArray(payload.inputs.map(serializePreparedInput))],
    ["outputs", goArray(payload.outputs.map(serializePreparedOutput))],
    ["message_outputs", goArray(payload.message_outputs.map(serializeMessageOutput))],
    ["audit_key_id", goString(payload.audit_key_id ?? "")],
    ["audit_key_epoch", auditEpoch.toString()],
    ["audit_disclosure_target_pubkey", auditTarget],
    ["nullifier_root", decimalField(payload.nullifier_root, "prepared batch transfer nullifier root")],
    ["commitment_root", decimalField(payload.commitment_root, "prepared batch transfer commitment root")],
    ["user_disclosure_root", decimalField(payload.user_disclosure_root, "prepared batch transfer user disclosure root")],
    ["full_disclosure_root", decimalField(payload.full_disclosure_root, "prepared batch transfer full disclosure root")],
    ["payload_digest_hi", decimalField(payload.payload_digest_hi, "prepared batch transfer payload digest hi")],
    ["payload_digest_lo", decimalField(payload.payload_digest_lo, "prepared batch transfer payload digest lo")],
    ["expected_intent", decimalField(payload.expected_intent, "prepared batch transfer expected intent")],
    ["owner_signature", goString(base64FromBytes(signature))],
    ["payload_hash", goString(payloadHash)]
  ]);
}

export function computePreparedBatchTransferPayloadHash(payload) {
  return sha256Hex(`${preparedBatchTransferPayloadHashDomain}${serializePreparedBatchTransferPayloadJson(payload, { forHash: true })}`);
}

export function serializePreparedBatchTransferPayload(payload) {
  return serializePreparedBatchTransferPayloadJson(payload);
}

export function serializeBatchTransferProofRequest(payload) {
  validatePreparedBatchTransferPayloadEnvelope(payload);
  return goObject([["version", goString(batchTransferProofRequestVersion)], ["payload", serializePreparedBatchTransferPayloadJson(payload)]]);
}

function structuredFieldBytes(value, label, options) {
  return canonicalFieldBytes(value, label, options).bytes;
}

function structuredBatchEffect(request) {
  const effect = request?.canonicalEffect ?? request?.message;
  if (!effect || typeof effect !== "object") throw new Error("batch transfer structured canonical effect is required");
  if (request?.canonicalEffect && request?.message) {
    if (!sameBytes(canonicalBatchTransferPayloadBytesV1(request.canonicalEffect), canonicalBatchTransferPayloadBytesV1(request.message))) {
      throw new Error("batch transfer structured canonical effect aliases disagree");
    }
  }
  if (String(effect.creator ?? "") !== "" || byteValue(effect.proof ?? new Uint8Array(), "batch transfer structured effect proof").length !== 0) {
    throw new Error("batch transfer structured canonical effect must exclude creator and proof");
  }
  return effect;
}

function structuredPointBytes(value, label) {
  return pointValue(value, label).bytes;
}

function structuredInput(entry, index, ownerSpend, ownerView, assetID, expectedNullifier) {
  if (!entry || typeof entry !== "object") throw new Error(`batch transfer structured input ${index} is required`);
  const note = signingNote(entry.note);
  const commitment = fixedFieldBytes(computeNoteCommitmentV1(note));
  const nullifier = fixedFieldBytes(computeNoteNullifierV1(note));
  if (!sameBytes(structuredFieldBytes(entry.commitment, `batch transfer structured input ${index} commitment`), commitment) ||
      !sameBytes(byteValue(entry.nullifier, `batch transfer structured input ${index} nullifier`), nullifier) ||
      !sameBytes(expectedNullifier, nullifier)) {
    throw new Error(`batch transfer structured input ${index} does not match the final effect nullifier`);
  }
  if (!sameBytes(structuredPointBytes(entry.spendPubKey, `batch transfer structured input ${index} spend public key`), ownerSpend) ||
      !sameBytes(structuredPointBytes(entry.viewPubKey, `batch transfer structured input ${index} view public key`), ownerView) ||
      !sameBytes(notePointBytes(note, "spend"), ownerSpend) || !sameBytes(notePointBytes(note, "view"), ownerView) ||
      canonicalField(entry.amount, `batch transfer structured input ${index} amount`) !== note.amount ||
      canonicalField(entry.assetID, `batch transfer structured input ${index} asset ID`, { nonZero: true }) !== assetID ||
      note.assetID !== assetID || canonicalField(entry.randomness, `batch transfer structured input ${index} randomness`) !== note.randomness) {
    throw new Error(`batch transfer structured input ${index} owner/amount/asset projection is invalid`);
  }
  return { note, nullifier };
}

function structuredOutput(entry, index, owner, assetID, effectOutput) {
  if (!entry || typeof entry !== "object") throw new Error(`batch transfer structured output ${index} is required`);
  const note = signingNote(entry.note);
  const kind = String(entry.kind ?? "");
  const privacyPolicy = Number(entry.privacyPolicy);
  const disclosureMode = Number(entry.disclosureMode);
  if (!["payment", "change", "padding"].includes(kind) || !Number.isInteger(privacyPolicy) || privacyPolicy < 0 || privacyPolicy > 7 || !Number.isInteger(disclosureMode) || disclosureMode < 0 || disclosureMode > 2) {
    throw new Error(`batch transfer structured output ${index} metadata is invalid`);
  }
  const commitment = fixedFieldBytes(computeNoteCommitmentV1(note));
  if (note.assetID !== assetID || !sameBytes(structuredFieldBytes(entry.commitment, `batch transfer structured output ${index} commitment`), commitment) || !sameBytes(commitment, effectOutput.commitment)) {
    throw new Error(`batch transfer structured output ${index} commitment or asset does not match the final effect`);
  }
  if (!sameBytes(structuredPointBytes(entry.recipientSpendPubKey, `batch transfer structured output ${index} spend public key`), notePointBytes(note, "spend")) ||
      !sameBytes(structuredPointBytes(entry.recipientViewPubKey, `batch transfer structured output ${index} view public key`), notePointBytes(note, "view")) ||
      canonicalField(entry.amount, `batch transfer structured output ${index} amount`) !== note.amount ||
      canonicalField(entry.assetID, `batch transfer structured output ${index} asset ID`, { nonZero: true }) !== assetID ||
      canonicalField(entry.randomness, `batch transfer structured output ${index} randomness`) !== note.randomness) {
    throw new Error(`batch transfer structured output ${index} NoteV1 projection is invalid`);
  }
  const userDisclosureBlinding = canonicalField(entry.userDisclosureBlinding, `batch transfer structured output ${index} user disclosure blinding`, { nonZero: privacyPolicy !== 0 });
  const fullDisclosureBlinding = canonicalField(entry.fullDisclosureBlinding, `batch transfer structured output ${index} full disclosure blinding`, { nonZero: true });
  if ((privacyPolicy === 0 && userDisclosureBlinding !== 0n) || privacyPolicy !== effectOutput.userPrivacyPolicy || disclosureMode !== effectOutput.userDisclosureMode || !sameBatchWireOutput(entry.wireOutput, effectOutput)) {
    throw new Error(`batch transfer structured output ${index} does not match the final effect`);
  }
  const output = { kind, note, privacyPolicy, disclosureMode, userDisclosureBlinding, fullDisclosureBlinding, commitment: bytesToBigIntBE(commitment) };
  const user = disclosureForOutput(output, owner, index, false);
  const full = disclosureForOutput(output, owner, index, true);
  if ((privacyPolicy === 0 && effectOutput.userDisclosureDigest.length !== 0) ||
      (privacyPolicy !== 0 && !sameBytes(fixedFieldBytes(user.digest), effectOutput.userDisclosureDigest)) ||
      !sameBytes(fixedFieldBytes(full.digest), effectOutput.fullDisclosureDigest)) {
    throw new Error(`batch transfer structured output ${index} disclosure digest does not match the final effect`);
  }
  return output;
}

/** Recompute every one-proof batch signing field before releasing an owner signature. */
export function validateBatchTransferSigningRequestV1(request) {
  if (!request || typeof request !== "object") throw new Error("batch transfer signing request is required");
  if (request.version !== preparedBatchTransferPayloadVersion || request.circuitSetId !== batchTransferCircuitSetId) throw new Error("unsupported batch transfer signing request version or circuit");
  const chainId = String(request.chainId ?? "").trim();
  if (!chainId) throw new Error("batch transfer structured chain ID is required");
  const expiresAtUnix = safePositiveInteger(request.expiresAtUnix, "batch transfer structured expiry");
  const effect = structuredBatchEffect(request);
  const normalizedEffect = validateBatchTransferEffectsV1(effect);
  if (Number(normalizedEffect.expiresAtUnix) !== expiresAtUnix) throw new Error("batch transfer structured effect expiry mismatch");
  const root = structuredFieldBytes(request.root, "batch transfer structured root", { nonZero: true });
  if (!sameBytes(root, normalizedEffect.root)) throw new Error("batch transfer structured effect root mismatch");
  if (!sameBytes(byteValue(request.canonicalPayload, "batch transfer structured canonical payload"), canonicalBatchTransferPayloadBytesV1(effect))) {
    throw new Error("batch transfer structured canonical payload does not match the final effect");
  }
  if (!Array.isArray(request.orderedInputs) || !Array.isArray(request.orderedInputNullifiers) || request.orderedInputs.length < 1 || request.orderedInputs.length > 16 || request.orderedInputs.length !== request.orderedInputNullifiers.length || request.orderedInputs.length !== normalizedEffect.nullifiers.length) {
    throw new Error("batch transfer structured input count mismatch");
  }
  if (!Array.isArray(request.orderedOutputs) || request.orderedOutputs.length < 1 || request.orderedOutputs.length > 32 || request.orderedOutputs.length !== normalizedEffect.outputs.length) {
    throw new Error("batch transfer structured output count mismatch");
  }
  const assetID = canonicalField(request.assetID, "batch transfer structured asset ID", { nonZero: true });
  const ownerSpend = structuredPointBytes(request.ownerSpendPubKey, "batch transfer structured owner spend public key");
  const ownerView = structuredPointBytes(request.ownerViewPubKey, "batch transfer structured owner view public key");
  const inputs = request.orderedInputs.map((entry, index) => {
    const input = structuredInput(entry, index, ownerSpend, ownerView, assetID, normalizedEffect.nullifiers[index]);
    if (!sameBytes(byteValue(request.orderedInputNullifiers[index], `batch transfer structured ordered nullifier ${index}`), input.nullifier)) {
      throw new Error(`batch transfer structured ordered nullifier ${index} mismatch`);
    }
    return input;
  });
  const owner = inputs[0].note;
  const inputTotal = inputs.reduce((total, input) => total + input.note.amount, 0n);
  if (canonicalField(request.inputTotal, "batch transfer structured input total") !== inputTotal) throw new Error("batch transfer structured input total mismatch");
  // Enforce global freshness before checking any digest projection so an
  // external signer never reaches its callback with a reused secret.
  const outputSecrets = request.orderedOutputs.map((entry, index) => ({
    note: signingNote(entry?.note),
    privacyPolicy: Number(entry?.privacyPolicy),
    userDisclosureBlinding: canonicalField(entry?.userDisclosureBlinding, `batch transfer structured output ${index} user disclosure blinding`, { nonZero: Number(entry?.privacyPolicy) !== 0 }),
    fullDisclosureBlinding: canonicalField(entry?.fullDisclosureBlinding, `batch transfer structured output ${index} full disclosure blinding`, { nonZero: true })
  }));
  validateSecretIndependence(inputs, outputSecrets);
  const outputs = request.orderedOutputs.map((entry, index) => structuredOutput(entry, index, owner, assetID, normalizedEffect.outputs[index]));
  validateOutputOrderAndConservation(inputs, outputs);
  validateSecretIndependence(inputs, outputs);
  const selfViewEnabled = normalizedEffect.outputs[0].selfViewDisclosurePayload.length !== 0;
  if (Boolean(request.selfViewEnabled) !== selfViewEnabled) throw new Error("batch transfer structured self-view all-or-none mismatch");
  if (String(request.auditKeyId ?? "") !== normalizedEffect.auditKeyId || positiveUint64(request.auditKeyEpoch, "batch transfer structured audit key epoch") !== normalizedEffect.auditKeyEpoch || !sameBytes(structuredPointBytes(request.auditDisclosureTargetPubKey, "batch transfer structured audit target"), normalizedEffect.auditDisclosureTargetPubkey)) {
    throw new Error("batch transfer structured audit identity mismatch");
  }
  const nullifierRoot = computeBatchVectorRootV1("nullifier", inputs.length, [...inputs.map(input => bytesToBigIntBE(input.nullifier)), ...Array(16 - inputs.length).fill(0n)]);
  const commitments = Array(32).fill(0n);
  const userDigests = Array(32).fill(0n);
  const fullDigests = Array(32).fill(0n);
  const policies = Array(32).fill(0);
  normalizedEffect.outputs.forEach((output, index) => {
    commitments[index] = bytesToBigIntBE(output.commitment);
    userDigests[index] = bytesToBigIntBE(output.userDisclosureDigest);
    fullDigests[index] = bytesToBigIntBE(output.fullDisclosureDigest);
    policies[index] = output.userPrivacyPolicy;
  });
  const commitmentRoot = computeBatchVectorRootV1("commitment", outputs.length, commitments);
  const userDisclosureRoot = computeBatchUserDisclosureVectorRootV1(outputs.length, policies, userDigests);
  const fullDisclosureRoot = computeBatchVectorRootV1("full_disclosure", outputs.length, fullDigests);
  for (const [field, expected] of [["nullifierRoot", nullifierRoot], ["commitmentRoot", commitmentRoot], ["userDisclosureRoot", userDisclosureRoot], ["fullDisclosureRoot", fullDisclosureRoot]]) {
    if (canonicalField(request[field], `batch transfer structured ${field}`) !== expected) throw new Error(`batch transfer structured ${field} mismatch`);
  }
  const digest = computeBatchTransferPayloadDigestV1(effect);
  if (canonicalField(request.payloadDigestHi, "batch transfer structured payload digest hi") !== digest.hi || canonicalField(request.payloadDigestLo, "batch transfer structured payload digest lo") !== digest.lo) {
    throw new Error("batch transfer structured payload digest mismatch");
  }
  const chainDomain = computeChainDomainV1(chainId, batchTransferCircuitSetId);
  const expectedIntent = computeBatchTransferIntentV1({
    chainDomainHi: chainDomain.hi, chainDomainLo: chainDomain.lo, merkleRoot: bytesToBigIntBE(root), inputCount: inputs.length, outputCount: outputs.length,
    assetID, nullifierRoot, commitmentRoot, userDisclosureRoot, fullDisclosureRoot, payloadDigestHi: digest.hi, payloadDigestLo: digest.lo, expiresAtUnix
  });
  if (canonicalField(request.expectedIntent, "batch transfer structured expected intent") !== expectedIntent) throw new Error("batch transfer structured expected intent does not match the final effect");
  return Object.freeze({ expected_intent: expectedIntent });
}

/** Invoke an external signer only after the complete one-proof effect is validated. */
export async function signValidatedBatchTransferIntentV1(signer, request, { allowLegacyNoteHashSigner = false } = {}) {
  if (!signer) throw new Error("a structured batch signer is required");
  const validated = validateBatchTransferSigningRequestV1(request);
  let signature;
  if (typeof signer.signBatchTransfer === "function") signature = await signer.signBatchTransfer(request);
  else if (allowLegacyNoteHashSigner) {
    const sign = signer.signSpendNoteHash || signer.signNoteHash;
    if (typeof sign !== "function") throw new Error("a structured batch signer or note hash signer is required");
    signature = await sign.call(signer, validated.expected_intent);
  } else throw new Error("a structured batch signer with signBatchTransfer(request) is required");
  const raw = byteValue(signature, "batch transfer owner signature");
  if (raw.length !== 64) throw new Error("batch transfer owner signature must be 64 bytes");
  try {
    unpackPoint(raw.slice(0, 32));
  } catch (error) {
    throw new Error(`batch transfer owner signature point is invalid: ${error.message}`);
  }
  if (bytesToBigIntBE(raw.slice(32)) >= CURVE_ORDER) throw new Error("batch transfer owner signature scalar is not canonical");
  return raw;
}

function buildBatchTransferSigningRequest({ chainId, expiresAtUnix, root, assetID, inputs, outputs, messageOutputs, auditKeyId, auditKeyEpoch, auditTarget, nullifierRoot, commitmentRoot, userDisclosureRoot, fullDisclosureRoot, digest, expectedIntent }) {
  const effect = Object.freeze({
    creator: "",
    proof: new Uint8Array(),
    root: frozenBytes(root),
    nullifiers: Object.freeze(inputs.map(entry => frozenBytes(entry.nullifier))),
    outputs: Object.freeze(messageOutputs.map(cloneBatchWireOutput)),
    auditKeyId,
    auditKeyEpoch: BigInt(auditKeyEpoch),
    auditDisclosureTargetPubkey: frozenBytes(auditTarget.bytes),
    expiresAtUnix: BigInt(expiresAtUnix)
  });
  const owner = inputs[0].note;
  return Object.freeze({
    version: preparedBatchTransferPayloadVersion,
    circuitSetId: batchTransferCircuitSetId,
    chainId,
    expiresAtUnix,
    orderedInputs: Object.freeze(inputs.map(entry => Object.freeze({
      note: signingNote(entry.note),
      commitment: fixedFieldBytes(computeNoteCommitmentV1(entry.note)),
      nullifier: frozenBytes(entry.nullifier),
      spendPubKey: notePointBytes(entry.note, "spend"),
      viewPubKey: notePointBytes(entry.note, "view"),
      amount: entry.note.amount,
      assetID: entry.note.assetID,
      randomness: entry.note.randomness
    }))),
    orderedInputNullifiers: Object.freeze(inputs.map(entry => frozenBytes(entry.nullifier))),
    orderedOutputs: Object.freeze(outputs.map((entry, index) => Object.freeze({
      kind: entry.kind,
      note: signingNote(entry.note),
      commitment: fixedFieldBytes(entry.commitment),
      recipientSpendPubKey: notePointBytes(entry.note, "spend"),
      recipientViewPubKey: notePointBytes(entry.note, "view"),
      amount: entry.note.amount,
      assetID: entry.note.assetID,
      randomness: entry.note.randomness,
      privacyPolicy: entry.privacyPolicy,
      disclosureMode: entry.disclosureMode,
      userDisclosureBlinding: entry.userDisclosureBlinding,
      fullDisclosureBlinding: entry.fullDisclosureBlinding,
      wireOutput: cloneBatchWireOutput(messageOutputs[index])
    }))),
    ownerSpendPubKey: notePointBytes(owner, "spend"),
    ownerViewPubKey: notePointBytes(owner, "view"),
    root: frozenBytes(root),
    assetID,
    inputTotal: inputs.reduce((total, entry) => total + entry.note.amount, 0n),
    auditKeyId,
    auditKeyEpoch,
    auditDisclosureTargetPubKey: frozenBytes(auditTarget.bytes),
    selfViewEnabled: effect.outputs[0].selfViewDisclosurePayload.length !== 0,
    nullifierRoot,
    commitmentRoot,
    userDisclosureRoot,
    fullDisclosureRoot,
    canonicalPayload: canonicalBatchTransferPayloadBytesV1(effect),
    payloadDigestHi: digest.hi,
    payloadDigestLo: digest.lo,
    expectedIntent,
    canonicalEffect: effect,
    // `message` is retained as an identical alias for existing signer adapters.
    message: effect
  });
}

export async function buildPreparedBatchTransferPayload(input) {
  if (!input || typeof input !== "object") throw new Error("prepared batch transfer build input is required");
  if (!Array.isArray(input.inputs) || !Array.isArray(input.outputs)) throw new Error("prepared batch transfer inputs and outputs are required");
  if (input.inputs.length < 1 || input.inputs.length > 16 || input.outputs.length < 1 || input.outputs.length > 32) throw new Error("prepared batch transfer requires 1..16 inputs and 1..32 outputs");
  const declaredRoot = input.root == null ? null : canonicalFieldBytes(input.root, "prepared batch transfer root").bytes;
  const inputs = input.inputs.map((entry, index) => normalizePreparedInput(entry, index, declaredRoot ?? (index === 0 ? null : undefined)));
  const root = declaredRoot ?? inputs[0].root;
  for (const entry of inputs) if (hexFromBytes(entry.root) !== hexFromBytes(root)) throw new Error("batch transfer input roots differ; wallet sync and replan are required");
  const owner = inputs[0].note;
  const assetID = owner.assetID;
  for (const [index, entry] of inputs.entries()) {
    if (!sameOwner(owner, entry.note)) throw new Error(`prepared batch input ${index} does not belong to the common owner`);
    if (entry.note.assetID !== assetID) throw new Error(`prepared batch input ${index} asset mismatch`);
  }
  if (new Set(inputs.map(entry => hexFromBytes(entry.nullifier))).size !== inputs.length) throw new Error("prepared batch input nullifiers must be distinct");
  const outputs = input.outputs.map((entry, index) => normalizePreparedOutput(entry, index, owner));
  for (const [index, entry] of outputs.entries()) if (entry.note.assetID !== assetID) throw new Error(`prepared batch output ${index} asset mismatch`);
  if (new Set(outputs.map(entry => entry.commitment.toString())).size !== outputs.length) throw new Error("prepared batch output commitments must be distinct");
  validateOutputOrderAndConservation(inputs, outputs);
  validateSecretIndependence(inputs, outputs);
  const chainId = String(input.chainId ?? input.chain_id ?? "").trim();
  if (!chainId) throw new Error("prepared batch transfer chain ID is required");
  const expiresAtUnix = safePositiveInteger(input.expiresAtUnix ?? input.expires_at_unix, "prepared batch transfer expires_at_unix");
  const auditKeyId = String(input.auditKeyId ?? input.audit_key_id ?? "");
  const auditKeyEpoch = positiveUint64(input.auditKeyEpoch ?? input.audit_key_epoch, "prepared batch transfer audit key epoch");
  const auditTarget = pointValue(input.auditDisclosureTargetPubKey ?? input.audit_disclosure_target_pubkey, "prepared batch transfer audit disclosure target");
  const disableSelfViewDisclosure = input.disableSelfViewDisclosure === true;
  const selfViewTarget = disableSelfViewDisclosure ? null : pointValue(input.selfViewDisclosureTargetPubKey ?? input.self_view_disclosure_target_pubkey, "prepared batch transfer self-view target");
  const messageOutputs = [];
  const userDigests = Array(32).fill(0n);
  const fullDigests = Array(32).fill(0n);
  const commitments = Array(32).fill(0n);
  const policies = Array(32).fill(0);
  for (const [index, output] of outputs.entries()) {
    const commitment = fixedFieldBytes(output.commitment);
    const encryptedNote = encryptNoteForTransferV1(output.note, commitment, index);
    const user = disclosureForOutput(output, owner, index, false);
    const full = disclosureForOutput(output, owner, index, true);
    const auditPayload = encryptDisclosureV1(full.plaintext, auditTarget.point, encryptedEnvelopeKindV1.auditDisclosure);
    const selfPayload = selfViewTarget ? encryptDisclosureV1(full.plaintext, selfViewTarget.point, encryptedEnvelopeKindV1.selfViewDisclosure) : new Uint8Array();
    const message = {
      commitment,
      ciphertext: encryptedNote.ciphertext,
      viewTag: encryptedNote.viewTag,
      userPrivacyPolicy: output.privacyPolicy,
      userDisclosureMode: output.disclosureMode,
      userDisclosureDigest: output.privacyPolicy ? fixedFieldBytes(user.digest) : new Uint8Array(),
      userDisclosureTargetPubkey: new Uint8Array(),
      userDisclosurePayload: new Uint8Array(),
      fullDisclosureDigest: fixedFieldBytes(full.digest),
      auditDisclosurePayload: auditPayload,
      selfViewDisclosurePayload: selfPayload
    };
    if (output.privacyPolicy) {
      if (output.disclosureMode === 1) message.userDisclosurePayload = marshalDisclosurePlaintextV1(user.plaintext);
      else {
        message.userDisclosureTargetPubkey = output.disclosureTarget.bytes;
        message.userDisclosurePayload = encryptDisclosureV1(user.plaintext, output.disclosureTarget.point, encryptedEnvelopeKindV1.userDisclosure);
      }
    }
    messageOutputs.push(message);
    commitments[index] = output.commitment;
    userDigests[index] = user.digest;
    fullDigests[index] = full.digest;
    policies[index] = output.privacyPolicy;
  }
  const message = {
    creator: "", proof: new Uint8Array(), root, nullifiers: inputs.map(entry => entry.nullifier), outputs: messageOutputs,
    auditKeyId, auditKeyEpoch: BigInt(auditKeyEpoch), auditDisclosureTargetPubkey: auditTarget.bytes, expiresAtUnix: BigInt(expiresAtUnix)
  };
  validateBatchTransferEffectsV1(message);
  const nullifierRoot = computeBatchVectorRootV1("nullifier", inputs.length, [...inputs.map(entry => bytesToBigIntBE(entry.nullifier)), ...Array(16 - inputs.length).fill(0n)]);
  const commitmentRoot = computeBatchVectorRootV1("commitment", outputs.length, commitments);
  const userDisclosureRoot = computeBatchUserDisclosureVectorRootV1(outputs.length, policies, userDigests);
  const fullDisclosureRoot = computeBatchVectorRootV1("full_disclosure", outputs.length, fullDigests);
  const digest = computeBatchTransferPayloadDigestV1(message);
  const chainDomain = computeChainDomainV1(chainId, batchTransferCircuitSetId);
  const expectedIntent = computeBatchTransferIntentV1({
    chainDomainHi: chainDomain.hi, chainDomainLo: chainDomain.lo, merkleRoot: bytesToBigIntBE(root), inputCount: inputs.length, outputCount: outputs.length,
    assetID, nullifierRoot, commitmentRoot, userDisclosureRoot, fullDisclosureRoot, payloadDigestHi: digest.hi, payloadDigestLo: digest.lo, expiresAtUnix
  });
  const signingRequest = buildBatchTransferSigningRequest({
    chainId, expiresAtUnix, root, assetID, inputs, outputs, messageOutputs,
    auditKeyId, auditKeyEpoch, auditTarget, nullifierRoot, commitmentRoot,
    userDisclosureRoot, fullDisclosureRoot, digest, expectedIntent
  });
  const ownerSignature = await signValidatedBatchTransferIntentV1(input.signer, signingRequest, {
    allowLegacyNoteHashSigner: input.allowLegacyNoteHashSigner === true
  });
  const payload = {
    version: preparedBatchTransferPayloadVersion,
    circuit_set_id: batchTransferCircuitSetId,
    ...(String(input.creator ?? "") ? { creator: String(input.creator) } : {}),
    chain_id: chainId,
    expires_at_unix: expiresAtUnix,
    root: base64FromBytes(root),
    asset_id: assetID.toString(),
    inputs: inputs.map(entry => entry.json),
    outputs: outputs.map(entry => entry.json),
    message_outputs: messageOutputs.map(output => ({
      commitment: base64FromBytes(output.commitment), ciphertext: base64FromBytes(output.ciphertext), view_tag: base64FromBytes(output.viewTag),
      user_privacy_policy: output.userPrivacyPolicy, user_disclosure_mode: output.userDisclosureMode,
      user_disclosure_digest: base64FromBytes(output.userDisclosureDigest), user_disclosure_target_pubkey: base64FromBytes(output.userDisclosureTargetPubkey), user_disclosure_payload: base64FromBytes(output.userDisclosurePayload),
      full_disclosure_digest: base64FromBytes(output.fullDisclosureDigest), audit_disclosure_payload: base64FromBytes(output.auditDisclosurePayload), self_view_disclosure_payload: base64FromBytes(output.selfViewDisclosurePayload)
    })),
    audit_key_id: auditKeyId,
    audit_key_epoch: auditKeyEpoch.toString(),
    audit_disclosure_target_pubkey: base64FromBytes(auditTarget.bytes),
    nullifier_root: nullifierRoot.toString(),
    commitment_root: commitmentRoot.toString(),
    user_disclosure_root: userDisclosureRoot.toString(),
    full_disclosure_root: fullDisclosureRoot.toString(),
    payload_digest_hi: digest.hi.toString(),
    payload_digest_lo: digest.lo.toString(),
    expected_intent: expectedIntent.toString(),
    owner_signature: base64FromBytes(ownerSignature),
    payload_hash: ""
  };
  payload.payload_hash = computePreparedBatchTransferPayloadHash(payload);
  validatePreparedBatchTransferPayloadEnvelope(payload);
  return payload;
}

export function validatePreparedBatchTransferPayloadEnvelope(payload, { nowUnix } = {}) {
  parsedBatchEffect(payload);
  fieldHex(payload.payload_hash, "prepared batch transfer payload hash");
  if (payload.payload_hash !== computePreparedBatchTransferPayloadHash(payload)) {
    throw new Error("prepared batch transfer payload hash mismatch; the payload may have been modified after preparation");
  }
  const validationNow = nowUnix ?? Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(validationNow)) throw new Error("prepared batch transfer validation time must be a safe integer");
  if (validationNow >= payload.expires_at_unix) throw new Error("prepared batch transfer payload expired; regenerate it before requesting a proof");
  return true;
}

export function normalizePreparedBatchTransferProof(payload, proof, { nowUnix } = {}) {
  validatePreparedBatchTransferPayloadEnvelope(payload, { nowUnix });
  if (!proof || typeof proof !== "object") throw new Error("prepared batch transfer proof is required");
  if (proof.version !== preparedBatchTransferProofVersion) throw new Error(`unsupported prepared batch transfer proof version ${JSON.stringify(proof.version)}`);
  if (proof.request_payload_hash !== payload.payload_hash) throw new Error("prepared batch transfer proof payload hash mismatch");
  if (proof.circuit_set_id && proof.circuit_set_id !== payload.circuit_set_id) throw new Error("prepared batch transfer proof circuit set mismatch");
  const proofBytes = exactBase64(proof.proof, "prepared batch transfer proof", batchTransferProofSize);
  return {
    ...proof,
    proof: base64FromBytes(proofBytes),
    proof_bytes: proofBytes
  };
}

export function buildMsgBatchTransferFromPrepared(payload, proof, { creator, nowUnix } = {}) {
  const normalizedProof = normalizePreparedBatchTransferProof(payload, proof, { nowUnix });
  const sender = String(creator ?? payload.creator ?? "").trim();
  if (!sender) throw new Error("batch transfer creator is required");
  return parsedBatchEffect(payload, { creator: sender, proof: normalizedProof.proof_bytes });
}

export function preparedBatchTransferEffectHex(payload) {
  const effect = parsedBatchEffect(payload);
  return {
    root_hex: hexFromBytes(effect.root),
    nullifier_hexes: effect.nullifiers.map(hexFromBytes),
    output_commitment_hexes: effect.outputs.map(output => hexFromBytes(output.commitment))
  };
}
