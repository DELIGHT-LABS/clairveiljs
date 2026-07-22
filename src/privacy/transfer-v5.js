import {
  CURVE_ORDER,
  FIELD_MODULUS,
  bytesFromHex,
  bytesToBigIntBE,
  canonicalFieldHex,
  decodeShieldedAddress,
  decodeCanonicalFieldHex,
  deriveDisclosureKeys,
  deriveSpendKeys,
  deriveViewKeys,
  hexFromBytes,
  hashStringToField,
  normalizeHex,
  packPoint,
  unpackPointHex
} from "../core/crypto.js";
import { randomBytes, sha256Hex } from "../core/browser-crypto.js";
import {
  createNote,
  createSpendNoteHashSigner,
  normalizeFoundNote,
  normalizeNote,
  parseCoin
} from "../core/note.js";
import {
  activeCircuitSetIdV1,
  computeAssetIdV1,
  computeChainDomainV1,
  computeNoteCommitmentV1,
  computeNoteNullifierV1,
  computeTransferFullDisclosureDigestV2,
  computeTransferIntentV2,
  computeTransferPayloadDigestV1,
  computeTransferUserDisclosureDigestV2,
  disclosurePlaintextV1Size,
  encryptDisclosureV1,
  encryptNoteForTransferV1,
  encryptedEnvelopeKindV1,
  marshalDisclosurePlaintextV1,
  unmarshalDisclosurePlaintextV1,
  unwrapEncryptedEnvelopeV1,
  validateNoteV1
} from "./protocol-v1.js";

export const preparedTransferV5PayloadVersion = "v5";
export const preparedTransferV5ProofVersion = "v2";
export const transferV5ProofRequestVersion = "v2";
export const transferV5ProofResponseVersion = "v2";
export const joinSplitOwnerIntentSigningRequestV1Version = "joinsplit-owner-intent-signing-request-v1";

const maxShieldedAmount = (1n << 64n) - 1n;

function randomNonZeroField(excluded = new Set()) {
  while (true) {
    const candidate = bytesToBigIntBE(randomBytes(32));
    if (candidate === 0n || candidate >= FIELD_MODULUS || excluded.has(candidate)) continue;
    return candidate;
  }
}

function canonicalExpiryFromInput(expiresAtUnix, chainNowUnix) {
  const now = chainNowUnix == null ? Math.floor(Date.now() / 1000) : Number(chainNowUnix);
  if (!Number.isSafeInteger(now) || now < 0) throw new Error("transfer chainNowUnix must be a non-negative safe integer");
  const expiry = expiresAtUnix == null ? now + 1800 : Number(expiresAtUnix);
  if (!Number.isSafeInteger(expiry) || expiry <= now) throw new Error("transfer expires_at_unix must be a future safe integer");
  return expiry;
}

function positiveAmount(value, label) {
  const amount = BigInt(canonicalAmount(value, label));
  if (amount === 0n) throw new Error(`${label} must be positive`);
  return amount;
}

function normalizedMerklePath(result, label) {
  const root = canonicalFieldHex(bytesToBigIntBE(decodeCanonicalFieldHex(result?.root ?? result?.Root ?? "", `${label} root`)));
  const path = [...(result?.path ?? result?.Path ?? [])].map((entry, index) => opaqueHex(entry, `${label} path ${index}`));
  const helper = [...(result?.path_helper ?? result?.pathHelper ?? result?.PathHelper ?? [])].map((entry, index) => {
    const value = Number(entry);
    if (value !== 0 && value !== 1) throw new Error(`${label} path helper ${index} must be 0 or 1`);
    return value;
  });
  if (path.length !== helper.length) throw new Error(`${label} merkle path and helper lengths must match`);
  return { root, path, helper };
}

async function lookupMerklePath(provider, commitmentHex) {
  if (!provider) throw new Error("a merkle path provider is required");
  if (typeof provider === "function") return provider(commitmentHex);
  if (typeof provider.lookupMerklePath === "function") return provider.lookupMerklePath(commitmentHex);
  if (typeof provider.LookupMerklePath === "function") return provider.LookupMerklePath(commitmentHex);
  throw new Error("merkle path provider must expose lookupMerklePath(commitmentHex)");
}

function disclosureFields(fromNote, recipientNote, commitment, blinding, { policy, full = false } = {}) {
  const from = normalizeNote(fromNote);
  const recipient = normalizeNote(recipientNote);
  const field = {
    commitment,
    amount: (full || (policy & 1) !== 0) ? recipient.amount : 0n,
    assetID: recipient.assetID,
    senderSpendKeyX: (full || (policy & 4) !== 0) ? from.receiverSpendPubKeyX : 0n,
    senderSpendKeyY: (full || (policy & 4) !== 0) ? from.receiverSpendPubKeyY : 0n,
    senderViewKeyX: (full || (policy & 4) !== 0) ? from.receiverViewPubKeyX : 0n,
    senderViewKeyY: (full || (policy & 4) !== 0) ? from.receiverViewPubKeyY : 0n,
    recipientSpendKeyX: (full || (policy & 2) !== 0) ? recipient.receiverSpendPubKeyX : 0n,
    recipientSpendKeyY: (full || (policy & 2) !== 0) ? recipient.receiverSpendPubKeyY : 0n,
    recipientViewKeyX: (full || (policy & 2) !== 0) ? recipient.receiverViewPubKeyX : 0n,
    recipientViewKeyY: (full || (policy & 2) !== 0) ? recipient.receiverViewPubKeyY : 0n,
    disclosureBlinding: blinding
  };
  return field;
}

function disclosureDigestFields(fromNote, recipientNote, commitment, blinding) {
  const from = normalizeNote(fromNote);
  const recipient = normalizeNote(recipientNote);
  return {
    commitment,
    amount: recipient.amount,
    assetID: recipient.assetID,
    fromSpendPubKeyX: from.receiverSpendPubKeyX,
    fromSpendPubKeyY: from.receiverSpendPubKeyY,
    fromViewPubKeyX: from.receiverViewPubKeyX,
    fromViewPubKeyY: from.receiverViewPubKeyY,
    toSpendPubKeyX: recipient.receiverSpendPubKeyX,
    toSpendPubKeyY: recipient.receiverSpendPubKeyY,
    toViewPubKeyX: recipient.receiverViewPubKeyX,
    toViewPubKeyY: recipient.receiverViewPubKeyY,
    disclosureBlinding: blinding
  };
}

function plaintextHex(value) {
  return hexFromBytes(value);
}

function notePublicKeyHex(note, kind) {
  const normalized = normalizeNote(note);
  const point = kind === "spend"
    ? { x: normalized.receiverSpendPubKeyX, y: normalized.receiverSpendPubKeyY }
    : { x: normalized.receiverViewPubKeyX, y: normalized.receiverViewPubKeyY };
  return hexFromBytes(packPoint(point));
}

function writeLines(values) {
  return values.map(value => `${value}\n`).join("");
}

function canonicalAmount(value, label) {
  const text = String(value ?? "");
  if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error(`${label} must be a canonical non-negative decimal string`);
  if (BigInt(text) > maxShieldedAmount) throw new Error(`${label} exceeds 64-bit shielded amount limit`);
  return text;
}

function fieldHex(value, label, { nonZero = false } = {}) {
  const canonical = normalizeHex(value, label);
  if (canonical.length !== 64) throw new Error(`${label} must be exactly 32 bytes`);
  const decoded = decodeCanonicalFieldHex(canonical, label);
  if (nonZero && decoded.every(byte => byte === 0)) throw new Error(`${label} must be non-zero`);
  return canonical;
}

function optionalFieldHex(value, label) {
  const text = String(value ?? "").trim();
  return text ? fieldHex(text, label) : "";
}

function opaqueHex(value, label, { exactLength } = {}) {
  const canonical = normalizeHex(value, label);
  if (exactLength != null && canonical.length !== exactLength * 2) throw new Error(`${label} must be exactly ${exactLength} bytes`);
  return canonical;
}

function optionalOpaqueHex(value, label) {
  const text = String(value ?? "").trim();
  return text ? opaqueHex(text, label) : "";
}

function pointHex(value, label) {
  const canonical = opaqueHex(value, label, { exactLength: 32 });
  try {
    unpackPointHex(canonical);
  } catch (error) {
    throw new Error(`${label} must be a canonical prime-subgroup point: ${error.message}`);
  }
  return canonical;
}

function canonicalExpiry(value) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error("transfer expires_at_unix must be a positive safe integer");
  return value;
}

function validateOwnerSignature(value) {
  const signature = opaqueHex(value, "transfer owner signature", { exactLength: 64 });
  try {
    unpackPointHex(signature.slice(0, 64));
  } catch (error) {
    throw new Error(`transfer owner signature point is invalid: ${error.message}`);
  }
  const scalar = BigInt(`0x${signature.slice(64)}`);
  if (scalar >= CURVE_ORDER) throw new Error("transfer owner signature scalar is not canonical");
  return signature;
}

function normalizeV5Input(input, index) {
  if (!input || typeof input !== "object") throw new Error(`transfer v5 input ${index} is required`);
  if (!Array.isArray(input.merkle_path) || !Array.isArray(input.merkle_path_helper) || input.merkle_path.length !== input.merkle_path_helper.length) {
    throw new Error(`transfer v5 input ${index} merkle path and helper lengths must match`);
  }
  input.merkle_path_helper.forEach((entry, pathIndex) => {
    if (entry !== 0 && entry !== 1) throw new Error(`transfer v5 input ${index} path helper ${pathIndex} must be 0 or 1`);
  });
  return {
    amount: canonicalAmount(input.amount, `transfer v5 input ${index} amount`),
    randomness_hex: fieldHex(input.randomness_hex, `transfer v5 input ${index} randomness`),
    spend_pubkey_hex: pointHex(input.spend_pubkey_hex, `transfer v5 input ${index} spend public key`),
    view_pubkey_hex: pointHex(input.view_pubkey_hex, `transfer v5 input ${index} view public key`),
    merkle_path: [...input.merkle_path].map((entry, pathIndex) => opaqueHex(entry, `transfer v5 input ${index} merkle path ${pathIndex}`)),
    merkle_path_helper: [...input.merkle_path_helper],
    nullifier_hex: fieldHex(input.nullifier_hex, `transfer v5 input ${index} nullifier`, { nonZero: true })
  };
}

function normalizeV5Output(output, index) {
  if (!output || typeof output !== "object") throw new Error(`transfer v5 output ${index} is required`);
  return {
    amount: canonicalAmount(output.amount, `transfer v5 output ${index} amount`),
    randomness_hex: fieldHex(output.randomness_hex, `transfer v5 output ${index} randomness`),
    spend_pubkey_hex: pointHex(output.spend_pubkey_hex, `transfer v5 output ${index} spend public key`),
    view_pubkey_hex: pointHex(output.view_pubkey_hex, `transfer v5 output ${index} view public key`),
    commitment_hex: fieldHex(output.commitment_hex, `transfer v5 output ${index} commitment`, { nonZero: true })
  };
}

function disclosureBlindingError(code, field, detail) {
  const error = new Error(`${code}: ${detail}`);
  error.code = code;
  error.field = field;
  return error;
}

function disclosureBlindingField(value, field) {
  let parsed;
  try {
    const text = typeof value === "bigint" ? value.toString() : String(value ?? "");
    if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error("not canonical");
    parsed = BigInt(text);
  } catch {
    throw disclosureBlindingError("DBS_NON_CANONICAL_FIELD", field, `${field} must be a canonical field decimal`);
  }
  if (parsed >= FIELD_MODULUS) {
    throw disclosureBlindingError("DBS_NON_CANONICAL_FIELD", field, `${field} is outside the scalar field`);
  }
  return parsed;
}

/**
 * Validates the v0.2 disclosure-blinding separation contract independently of
 * a transfer payload. This lets callers fail closed before serializing a
 * payload and preserves the fixture's machine-readable error codes.
 */
export function validateDisclosureBlindingSeparationV1(input = {}) {
  const enabled = input.enabled ?? true;
  if (typeof enabled !== "boolean") {
    throw disclosureBlindingError("DBS_DISABLED_SENTINEL", "enabled", "enabled must be a boolean");
  }
  const policyValue = input.privacyPolicy ?? input.privacy_policy;
  const privacyPolicy = Number(policyValue);
  if (!Number.isInteger(privacyPolicy) || privacyPolicy < 0 || privacyPolicy > 7) {
    throw disclosureBlindingError("DBS_INVALID_POLICY", "privacy_policy", "privacy policy must be in [0, 7]");
  }

  const outputRandomness = disclosureBlindingField(
    input.outputRandomness ?? input.output_randomness,
    "output_randomness"
  );
  const userDisclosureBlinding = disclosureBlindingField(
    input.userDisclosureBlinding ?? input.user_disclosure_blinding,
    "user_disclosure_blinding"
  );
  const fullDisclosureBlinding = disclosureBlindingField(
    input.fullDisclosureBlinding ?? input.full_disclosure_blinding,
    "full_disclosure_blinding"
  );

  if (!enabled) {
    if (privacyPolicy !== 0) throw disclosureBlindingError("DBS_DISABLED_SENTINEL", "privacy_policy", "disabled disclosure must use policy 0");
    if (outputRandomness !== 0n) throw disclosureBlindingError("DBS_DISABLED_SENTINEL", "output_randomness", "disabled disclosure requires zero output randomness");
    if (userDisclosureBlinding !== 0n) throw disclosureBlindingError("DBS_DISABLED_SENTINEL", "user_disclosure_blinding", "disabled disclosure requires zero user blinding");
    if (fullDisclosureBlinding !== 0n) throw disclosureBlindingError("DBS_DISABLED_SENTINEL", "full_disclosure_blinding", "disabled disclosure requires zero full blinding");
    return true;
  }

  if (privacyPolicy === 0) {
    if (userDisclosureBlinding !== 0n) throw disclosureBlindingError("DBS_ALL_PRIVATE_USER_SENTINEL", "user_disclosure_blinding", "all-private disclosure requires the zero user blinding sentinel");
    if (fullDisclosureBlinding === 0n) throw disclosureBlindingError("DBS_FULL_BLINDING_REQUIRED", "full_disclosure_blinding", "enabled disclosure requires a non-zero full blinding");
    if (fullDisclosureBlinding === outputRandomness) throw disclosureBlindingError("DBS_FULL_RANDOMNESS_REUSE", "full_disclosure_blinding", "full disclosure blinding must differ from output randomness");
    return true;
  }

  if (userDisclosureBlinding === 0n) throw disclosureBlindingError("DBS_USER_BLINDING_REQUIRED", "user_disclosure_blinding", "disclosed output requires a non-zero user blinding");
  if (fullDisclosureBlinding === 0n) throw disclosureBlindingError("DBS_FULL_BLINDING_REQUIRED", "full_disclosure_blinding", "enabled disclosure requires a non-zero full blinding");
  if (userDisclosureBlinding === outputRandomness) throw disclosureBlindingError("DBS_USER_RANDOMNESS_REUSE", "user_disclosure_blinding", "user disclosure blinding must differ from output randomness");
  if (fullDisclosureBlinding === outputRandomness) throw disclosureBlindingError("DBS_FULL_RANDOMNESS_REUSE", "full_disclosure_blinding", "full disclosure blinding must differ from output randomness");
  if (fullDisclosureBlinding === userDisclosureBlinding) throw disclosureBlindingError("DBS_USER_FULL_BLINDING_REUSE", "full_disclosure_blinding", "user and full disclosure blindings must differ");
  return true;
}

function validateDisclosureBlindings(payload, policy, outputs) {
  const outputRandomness = BigInt(`0x${outputs[0].randomness_hex}`);
  const full = BigInt(`0x${fieldHex(payload.full_disclosure_blinding_hex, "transfer full disclosure blinding", { nonZero: true })}`);
  if (full === outputRandomness) throw new Error("DBS-02: transfer full disclosure blinding must differ from recipient output randomness");
  const encodedUser = String(payload.user_disclosure_blinding_hex ?? "").trim();
  if (policy === 0) {
    if (encodedUser) throw new Error("all-private transfer payload must omit the zero user disclosure blinding sentinel");
    return;
  }
  const user = BigInt(`0x${fieldHex(encodedUser, "transfer user disclosure blinding", { nonZero: true })}`);
  if (user === outputRandomness) throw new Error("DBS-01: transfer user disclosure blinding must differ from recipient output randomness");
  if (user === full) throw new Error("DBS-03: transfer user and full disclosure blindings must differ");
}

function validateDisclosures(payload, policy, mode, outputs) {
  const userDigest = optionalFieldHex(payload.user_disclosure_digest_hex, "transfer user disclosure digest");
  const userTarget = optionalOpaqueHex(payload.user_disclosure_target_pubkey_hex, "transfer user disclosure target public key");
  const userPayload = optionalOpaqueHex(payload.user_disclosure_payload_hex, "transfer user disclosure payload");
  if (policy === 0) {
    if (mode !== 0 || userDigest || userTarget || userPayload) throw new Error("all-private transfer must use empty user disclosure fields and NONE mode");
  } else {
    if (![1, 2].includes(mode) || !userDigest) throw new Error("transfer user disclosure is incomplete");
    if (mode === 1) {
      if (userTarget || !userPayload || userPayload.length !== disclosurePlaintextV1Size * 2) throw new Error("public transfer disclosure must use fixed plaintext and no target");
      const plaintext = unmarshalDisclosurePlaintextV1(bytesFromHex(userPayload, "public transfer disclosure"));
      if (plaintext.plane !== 1 || plaintext.outputIndex !== 0 || plaintext.policy !== policy || plaintext.commitment !== BigInt(`0x${outputs[0].commitment_hex}`)) {
        throw new Error("public transfer disclosure metadata does not match recipient output");
      }
    } else {
      pointHex(userTarget, "transfer user disclosure target public key");
      unwrapEncryptedEnvelopeV1(bytesFromHex(userPayload, "transfer user disclosure payload"), encryptedEnvelopeKindV1.userDisclosure);
    }
  }
  const auditDigest = fieldHex(payload.audit_disclosure_digest_hex, "transfer audit disclosure digest", { nonZero: true });
  pointHex(payload.audit_disclosure_target_pubkey_hex, "transfer audit disclosure target public key");
  unwrapEncryptedEnvelopeV1(bytesFromHex(opaqueHex(payload.audit_disclosure_payload_hex, "transfer audit disclosure payload"), "transfer audit disclosure payload"), encryptedEnvelopeKindV1.auditDisclosure);
  const selfDigest = optionalFieldHex(payload.self_view_disclosure_digest_hex, "transfer self-view disclosure digest");
  const selfPayload = optionalOpaqueHex(payload.self_view_disclosure_payload_hex, "transfer self-view disclosure payload");
  if (Boolean(selfDigest) !== Boolean(selfPayload)) throw new Error("transfer self-view disclosure digest and payload must be provided together");
  if (selfPayload) unwrapEncryptedEnvelopeV1(bytesFromHex(selfPayload, "transfer self-view disclosure payload"), encryptedEnvelopeKindV1.selfViewDisclosure);
  return { userDigest, userTarget, userPayload, auditDigest, selfDigest, selfPayload };
}

function normalizedPayloadForValidation(payload) {
  if (!payload || typeof payload !== "object") throw new Error("prepared transfer v5 payload is required");
  if (payload.version !== preparedTransferV5PayloadVersion) throw new Error(`unsupported transfer payload version ${JSON.stringify(payload.version)} (expected "${preparedTransferV5PayloadVersion}")`);
  if (!String(payload.creator ?? "").trim()) throw new Error("transfer creator is required");
  if (!String(payload.chain_id ?? "").trim()) throw new Error("transfer chain ID is required");
  const expiresAtUnix = canonicalExpiry(payload.expires_at_unix);
  const rootHex = fieldHex(payload.root_hex, "transfer root", { nonZero: true });
  const assetIdHex = fieldHex(payload.asset_id_hex, "transfer asset ID", { nonZero: true });
  const policy = Number(payload.user_privacy_policy);
  const mode = Number(payload.user_disclosure_mode);
  if (!Number.isInteger(policy) || policy < 0 || policy > 7) throw new Error("transfer user privacy policy must be in 0..7");
  if (!Number.isInteger(mode) || mode < 0 || mode > 2) throw new Error("transfer user disclosure mode must be in 0..2");
  if (!Array.isArray(payload.inputs) || payload.inputs.length !== 2) throw new Error("transfer v5 payload requires exactly 2 inputs");
  if (!Array.isArray(payload.outputs) || payload.outputs.length !== 2) throw new Error("transfer v5 payload requires exactly 2 outputs");
  if (!Array.isArray(payload.cipher_text_hexes) || payload.cipher_text_hexes.length !== 2) throw new Error("transfer v5 payload requires exactly 2 ciphertexts");
  if (!Array.isArray(payload.view_tag_hexes) || payload.view_tag_hexes.length !== 2) throw new Error("transfer v5 payload requires exactly 2 view tags");
  const inputs = payload.inputs.map(normalizeV5Input);
  const outputs = payload.outputs.map(normalizeV5Output);
  const nullifiers = inputs.map(input => input.nullifier_hex);
  const commitments = outputs.map(output => output.commitment_hex);
  if (new Set(nullifiers).size !== nullifiers.length) throw new Error("transfer v5 input nullifiers must be distinct");
  if (new Set(commitments).size !== commitments.length) throw new Error("transfer v5 output commitments must be distinct");
  payload.cipher_text_hexes.forEach((value, index) => unwrapEncryptedEnvelopeV1(bytesFromHex(opaqueHex(value, `transfer ciphertext ${index}`), `transfer ciphertext ${index}`), encryptedEnvelopeKindV1.transferNote));
  payload.view_tag_hexes.forEach((value, index) => opaqueHex(value, `transfer view tag ${index}`, { exactLength: 2 }));
  validateDisclosures(payload, policy, mode, outputs);
  validateDisclosureBlindings(payload, policy, outputs);
  validateOwnerSignature(payload.owner_signature_hex);
  return { expiresAtUnix, rootHex, assetIdHex, policy, mode, inputs, outputs };
}

function signingNote(note) {
  // This is the external signer boundary, so do not rely on the more
  // permissive generic note normalizer. In particular, reject field aliases
  // that would otherwise reduce to the same MiMC inputs.
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

function sameNote(left, right) {
  return left.receiverSpendPubKeyX === right.receiverSpendPubKeyX &&
    left.receiverSpendPubKeyY === right.receiverSpendPubKeyY &&
    left.receiverViewPubKeyX === right.receiverViewPubKeyX &&
    left.receiverViewPubKeyY === right.receiverViewPubKeyY &&
    left.amount === right.amount &&
    left.assetID === right.assetID &&
    left.randomness === right.randomness &&
    left.memo === right.memo;
}

function ownerSignaturePlaceholder(payload) {
  const key = payload?.inputs?.[0]?.spend_pubkey_hex;
  return `${pointHex(key, "transfer signing request input 0 spend public key")}${"0".repeat(63)}1`;
}

function requiredRequestText(value, label) {
  const text = String(value ?? "").trim();
  if (!text) throw new Error(`${label} is required`);
  return text;
}

function expectedTransferFinalEffect(payload, payloadDigest, intent) {
  return Object.freeze({
    root_hex: payload.root_hex,
    asset_id_hex: payload.asset_id_hex,
    nullifier_hexes: Object.freeze(payload.inputs.map(input => input.nullifier_hex)),
    commitment_hexes: Object.freeze(payload.outputs.map(output => output.commitment_hex)),
    user_disclosure_digest_hex: payload.user_disclosure_digest_hex,
    full_disclosure_digest_hex: payload.audit_disclosure_digest_hex,
    expires_at_unix: payload.expires_at_unix,
    payload_digest_hex: opaqueHex(payloadDigest?.hex, "transfer payload digest", { exactLength: 32 }),
    intent_hex: canonicalFieldHex(intent)
  });
}

function validateFinalEffect(actual, expected) {
  if (!actual || typeof actual !== "object") throw new Error("JoinSplit owner intent final_effect is required");
  const fields = [
    "root_hex",
    "asset_id_hex",
    "user_disclosure_digest_hex",
    "full_disclosure_digest_hex",
    "payload_digest_hex",
    "intent_hex"
  ];
  for (const field of fields) {
    if (String(actual[field] ?? "") !== expected[field]) throw new Error(`JoinSplit owner intent final_effect.${field} does not match the canonical effect`);
  }
  if (Number(actual.expires_at_unix) !== expected.expires_at_unix) throw new Error("JoinSplit owner intent final_effect.expires_at_unix does not match the canonical effect");
  for (const field of ["nullifier_hexes", "commitment_hexes"]) {
    if (!Array.isArray(actual[field]) || actual[field].length !== expected[field].length || actual[field].some((value, index) => String(value) !== expected[field][index])) {
      throw new Error(`JoinSplit owner intent final_effect.${field} does not match the canonical effect`);
    }
  }
}

/**
 * Rebuild the signed JoinSplit intent from full NoteV1 values and the final
 * effect. This is deliberately secret-free and must run before a hardware or
 * external wallet callback receives the request.
 */
export function validateJoinSplitOwnerIntentSigningRequestV1(request) {
  if (!request || typeof request !== "object") throw new Error("JoinSplit owner intent signing request is required");
  if (request.version !== joinSplitOwnerIntentSigningRequestV1Version) throw new Error(`unsupported JoinSplit owner intent signing request version ${JSON.stringify(request.version)}`);
  if (request.circuit_set_id !== activeCircuitSetIdV1) throw new Error("JoinSplit owner intent signing request circuit set is invalid");
  const payload = request.payload;
  if (!payload || typeof payload !== "object") throw new Error("JoinSplit owner intent signing request payload is required");
  const unsignedPayload = { ...payload, owner_signature_hex: ownerSignaturePlaceholder(payload) };
  const normalized = normalizedPayloadForValidation(unsignedPayload);
  if (!Array.isArray(request.input_notes) || request.input_notes.length !== 2 || !Array.isArray(request.output_notes) || request.output_notes.length !== 2) {
    throw new Error("JoinSplit owner intent signing request requires two input and two output NoteV1 values");
  }
  const inputs = request.input_notes.map(signingNote);
  const outputs = request.output_notes.map(signingNote);
  if (inputs.some((note, index) => (
    note.amount.toString() !== normalized.inputs[index].amount ||
    canonicalFieldHex(note.randomness) !== normalized.inputs[index].randomness_hex ||
    notePublicKeyHex(note, "spend") !== normalized.inputs[index].spend_pubkey_hex ||
    notePublicKeyHex(note, "view") !== normalized.inputs[index].view_pubkey_hex ||
    canonicalFieldHex(computeNoteNullifierV1(note)) !== normalized.inputs[index].nullifier_hex
  ))) throw new Error("JoinSplit owner intent signing request input Notes do not match the final effect");
  if (outputs.some((note, index) => (
    note.amount.toString() !== normalized.outputs[index].amount ||
    canonicalFieldHex(note.randomness) !== normalized.outputs[index].randomness_hex ||
    notePublicKeyHex(note, "spend") !== normalized.outputs[index].spend_pubkey_hex ||
    notePublicKeyHex(note, "view") !== normalized.outputs[index].view_pubkey_hex ||
    canonicalFieldHex(computeNoteCommitmentV1(note)) !== normalized.outputs[index].commitment_hex
  ))) throw new Error("JoinSplit owner intent signing request output Notes do not match the final effect");
  if (inputs[0].assetID !== inputs[1].assetID || outputs.some(note => note.assetID !== inputs[0].assetID) || canonicalFieldHex(inputs[0].assetID) !== normalized.assetIdHex) {
    throw new Error("JoinSplit owner intent signing request asset identity is invalid");
  }
  if (inputs.some(note => note.receiverSpendPubKeyX !== inputs[0].receiverSpendPubKeyX || note.receiverSpendPubKeyY !== inputs[0].receiverSpendPubKeyY || note.receiverViewPubKeyX !== inputs[0].receiverViewPubKeyX || note.receiverViewPubKeyY !== inputs[0].receiverViewPubKeyY) ||
    !sameNote(outputs[1], signingNote({ ...outputs[1], receiverSpendPubKeyX: inputs[0].receiverSpendPubKeyX, receiverSpendPubKeyY: inputs[0].receiverSpendPubKeyY, receiverViewPubKeyX: inputs[0].receiverViewPubKeyX, receiverViewPubKeyY: inputs[0].receiverViewPubKeyY }))) {
    throw new Error("JoinSplit owner intent signing request change ownership is invalid");
  }
  if (inputs.reduce((total, note) => total + note.amount, 0n) !== outputs.reduce((total, note) => total + note.amount, 0n)) {
    throw new Error("JoinSplit owner intent signing request value conservation is invalid");
  }
  const senderSpendPubKeyHex = pointHex(request.sender_spend_pubkey_hex, "JoinSplit owner intent sender spend public key");
  if (senderSpendPubKeyHex !== notePublicKeyHex(inputs[0], "spend")) throw new Error("JoinSplit owner intent signing request sender projection is invalid");
  if (fieldHex(request.recipient_output_randomness_hex, "JoinSplit owner intent recipient output randomness") !== normalized.outputs[0].randomness_hex) {
    throw new Error("JoinSplit owner intent signing request recipient output randomness is invalid");
  }
  if (String(request.user_disclosure_blinding_hex ?? "") !== String(payload.user_disclosure_blinding_hex ?? "") || String(request.full_disclosure_blinding_hex ?? "") !== String(payload.full_disclosure_blinding_hex ?? "")) {
    throw new Error("JoinSplit owner intent signing request disclosure blindings do not match the final effect");
  }
  const fullBlinding = BigInt(`0x${fieldHex(payload.full_disclosure_blinding_hex, "transfer full disclosure blinding", { nonZero: true })}`);
  const fullDigest = computeTransferFullDisclosureDigestV2(disclosureDigestFields(inputs[0], outputs[0], computeNoteCommitmentV1(outputs[0]), fullBlinding));
  if (canonicalFieldHex(fullDigest) !== payload.audit_disclosure_digest_hex || (payload.self_view_disclosure_digest_hex && payload.self_view_disclosure_digest_hex !== canonicalFieldHex(fullDigest))) {
    throw new Error("JoinSplit owner intent signing request full disclosure digest is invalid");
  }
  if (normalized.policy !== 0) {
    const userBlinding = BigInt(`0x${fieldHex(payload.user_disclosure_blinding_hex, "transfer user disclosure blinding", { nonZero: true })}`);
    const userDigest = computeTransferUserDisclosureDigestV2({
      ...disclosureDigestFields(inputs[0], outputs[0], computeNoteCommitmentV1(outputs[0]), userBlinding),
      policy: normalized.policy,
      disclosureBlinding: userBlinding
    });
    if (canonicalFieldHex(userDigest) !== payload.user_disclosure_digest_hex) throw new Error("JoinSplit owner intent signing request user disclosure digest is invalid");
  }
  const effect = buildTransferV5Effect(payload);
  const payloadDigest = computeTransferPayloadDigestV1(effect);
  const chainDomain = computeChainDomainV1(requiredRequestText(request.chain_id, "JoinSplit owner intent chain_id"), activeCircuitSetIdV1);
  if (request.chain_id !== payload.chain_id || Number(request.expires_at_unix) !== normalized.expiresAtUnix) throw new Error("JoinSplit owner intent signing request chain or expiry is invalid");
  const intent = computeTransferIntentV2({
    chainDomain,
    root: bytesToBigIntBE(bytesFromHex(normalized.rootHex, "transfer root")),
    assetId: inputs[0].assetID,
    nullifiers: normalized.inputs.map(input => bytesToBigIntBE(bytesFromHex(input.nullifier_hex, "transfer nullifier"))),
    commitments: normalized.outputs.map(output => bytesToBigIntBE(bytesFromHex(output.commitment_hex, "transfer commitment"))),
    userDisclosureDigest: normalized.policy === 0 ? 0n : bytesToBigIntBE(bytesFromHex(payload.user_disclosure_digest_hex, "transfer user disclosure digest")),
    fullDisclosureDigest: fullDigest,
    payloadDigest,
    expiresAtUnix: normalized.expiresAtUnix
  });
  const finalEffect = expectedTransferFinalEffect(payload, payloadDigest, intent);
  validateFinalEffect(request.final_effect, finalEffect);
  if (fieldHex(request.expected_intent_hex, "JoinSplit owner intent expected intent") !== finalEffect.intent_hex) throw new Error("JoinSplit owner intent signing request expected intent is invalid");
  return Object.freeze({ expected_intent: intent, final_effect: finalEffect });
}

/** Build the complete secret-free request expected by an external transfer signer. */
export function buildJoinSplitOwnerIntentSigningRequestV1({ payload, inputNotes, outputNotes, intent, payloadDigest }) {
  const finalEffect = expectedTransferFinalEffect(payload, payloadDigest, intent);
  return Object.freeze({
    version: joinSplitOwnerIntentSigningRequestV1Version,
    circuit_set_id: activeCircuitSetIdV1,
    chain_id: payload.chain_id,
    expires_at_unix: payload.expires_at_unix,
    input_notes: Object.freeze(inputNotes.map(signingNote)),
    output_notes: Object.freeze(outputNotes.map(signingNote)),
    sender_spend_pubkey_hex: notePublicKeyHex(inputNotes[0], "spend"),
    recipient_output_randomness_hex: canonicalFieldHex(normalizeNote(outputNotes[0]).randomness),
    user_disclosure_blinding_hex: payload.user_disclosure_blinding_hex,
    full_disclosure_blinding_hex: payload.full_disclosure_blinding_hex,
    payload: Object.freeze({ ...payload }),
    final_effect: finalEffect,
    expected_intent_hex: finalEffect.intent_hex
  });
}

/** Invoke a signer only after the complete final effect has been rebuilt and verified. */
export async function signValidatedJoinSplitOwnerIntentV1(signer, request, { allowLegacyNoteHashSigner = false } = {}) {
  if (!signer) throw new Error("an owner intent signer is required");
  const validated = validateJoinSplitOwnerIntentSigningRequestV1(request);
  let signature;
  if (typeof signer.signJoinSplitOwnerIntent === "function") signature = await signer.signJoinSplitOwnerIntent(request);
  else if (typeof signer.signOwnerIntent === "function") signature = await signer.signOwnerIntent(request);
  else if (allowLegacyNoteHashSigner) {
    const sign = signer.signSpendNoteHash || signer.signNoteHash;
    if (typeof sign !== "function") throw new Error("owner intent signer must expose signJoinSplitOwnerIntent(request)");
    signature = await sign.call(signer, validated.expected_intent);
  } else throw new Error("owner intent signer must expose signJoinSplitOwnerIntent(request)");
  const bytes = Uint8Array.from(signature);
  if (bytes.length !== 64) throw new Error("transfer owner intent signature must be 64 bytes");
  return hexFromBytes(bytes);
}

export function computePreparedTransferV5PayloadHash(payload) {
  const inputs = Array.isArray(payload?.inputs) ? payload.inputs : [];
  const outputs = Array.isArray(payload?.outputs) ? payload.outputs : [];
  const cipherTexts = Array.isArray(payload?.cipher_text_hexes) ? payload.cipher_text_hexes : [];
  const viewTags = Array.isArray(payload?.view_tag_hexes) ? payload.view_tag_hexes : [];
  const lines = [
    payload?.version ?? "",
    payload?.creator ?? "",
    payload?.chain_id ?? "",
    payload?.expires_at_unix ?? "",
    payload?.root_hex ?? "",
    payload?.asset_id_hex ?? "",
    payload?.user_privacy_policy ?? "",
    payload?.user_disclosure_mode ?? "",
    payload?.user_disclosure_digest_hex ?? "",
    payload?.user_disclosure_target_pubkey_hex ?? "",
    payload?.user_disclosure_payload_hex ?? "",
    payload?.audit_disclosure_digest_hex ?? "",
    payload?.audit_disclosure_target_pubkey_hex ?? "",
    payload?.audit_disclosure_payload_hex ?? "",
    payload?.self_view_disclosure_digest_hex ?? "",
    payload?.self_view_disclosure_payload_hex ?? "",
    payload?.user_disclosure_blinding_hex ?? "",
    payload?.full_disclosure_blinding_hex ?? "",
    payload?.owner_signature_hex ?? "",
    inputs.length
  ];
  for (const input of inputs) {
    const merklePath = Array.isArray(input?.merkle_path) ? input.merkle_path : [];
    const helpers = Array.isArray(input?.merkle_path_helper) ? input.merkle_path_helper : [];
    lines.push(input?.amount ?? "", input?.randomness_hex ?? "", input?.spend_pubkey_hex ?? "", input?.view_pubkey_hex ?? "", merklePath.length, ...merklePath, helpers.length, ...helpers, input?.nullifier_hex ?? "");
  }
  lines.push(outputs.length);
  for (const output of outputs) lines.push(output?.amount ?? "", output?.randomness_hex ?? "", output?.spend_pubkey_hex ?? "", output?.view_pubkey_hex ?? "", output?.commitment_hex ?? "");
  lines.push(cipherTexts.length, ...cipherTexts, viewTags.length, ...viewTags);
  return sha256Hex(writeLines(lines));
}

/**
 * Builds the 0.2.0 JoinSplit 2x2 prover artifact. This intentionally emits
 * only the fixed `privacy-fixed-v1` encodings and V5/V2 wire contract.
 */
export async function buildPreparedTransferV5Payload({
  creator,
  chainId,
  expiresAtUnix,
  chainNowUnix,
  inputs,
  recipient,
  amount,
  transferAmount,
  transferDenom,
  denom,
  rootSeed,
  senderSpendPubKey,
  senderViewPubKey,
  merklePathProvider,
  ownerIntentSigner,
  noteHashSigner,
  userPrivacyPolicy = 0,
  userDisclosureMode,
  userDisclosureTargetPubKeyHex = "",
  auditDisclosureTargetPubKeyHex,
  disableSelfViewDisclosure = false,
  selfViewDisclosureTargetPubKeyHex,
  shieldedPrefix
} = {}) {
  const sender = String(creator ?? "").trim();
  if (!sender) throw new Error("transfer creator is required");
  const normalizedChainId = String(chainId ?? "").trim();
  if (!normalizedChainId) throw new Error("chainId is required for transfer");
  const expiry = canonicalExpiryFromInput(expiresAtUnix, chainNowUnix);
  const coin = parseCoin(amount ?? transferAmount, transferDenom ?? denom);
  const targetAmount = positiveAmount(coin.amount, "transfer amount");
  const foundInputs = [...(inputs ?? [])].map(normalizeFoundNote);
  if (foundInputs.length !== 2) throw new Error(`transfer prepared payload requires exactly 2 input notes; got ${foundInputs.length}`);

  const first = normalizeNote(foundInputs[0].note);
  const second = normalizeNote(foundInputs[1].note);
  const expectedAssetID = computeAssetIdV1(coin.denom);
  for (const [index, note] of [first, second].entries()) {
    if (note.assetID !== expectedAssetID) throw new Error(`transfer input ${index} asset does not match requested denom ${coin.denom}`);
    if (note.receiverSpendPubKeyX !== first.receiverSpendPubKeyX || note.receiverSpendPubKeyY !== first.receiverSpendPubKeyY || note.receiverViewPubKeyX !== first.receiverViewPubKeyX || note.receiverViewPubKeyY !== first.receiverViewPubKeyY) {
      throw new Error("transfer inputs must share the same owner");
    }
  }
  const total = first.amount + second.amount;
  if (total < targetAmount) throw new Error(`insufficient selected input total ${total} for transfer amount ${targetAmount}`);

  const recipientKeys = decodeShieldedAddress(recipient, { shieldedPrefix });
  const senderSpend = senderSpendPubKey ?? (rootSeed ? deriveSpendKeys(rootSeed).pubKey : null);
  const senderView = senderViewPubKey ?? (rootSeed ? deriveViewKeys(rootSeed).pubKey : null);
  if (!senderSpend || !senderView) throw new Error("sender spend/view public keys or rootSeed are required");
  const signer = ownerIntentSigner ?? noteHashSigner ?? (rootSeed ? createSpendNoteHashSigner(rootSeed) : null);
  if (!signer) throw new Error("ownerIntentSigner, noteHashSigner, or rootSeed is required");

  const recipientNote = createNote({
    spendPubKey: recipientKeys.spendPubKey,
    viewPubKey: recipientKeys.viewPubKey,
    amount: targetAmount,
    assetId: first.assetID,
    memo: "Transfer"
  });
  const changeNote = createNote({
    spendPubKey: senderSpend,
    viewPubKey: senderView,
    amount: total - targetAmount,
    assetId: first.assetID,
    memo: "Change"
  });
  const outputNotes = [recipientNote, changeNote];
  const outputCommitments = outputNotes.map(note => computeNoteCommitmentV1(note));
  if (outputCommitments[0] === outputCommitments[1]) throw new Error("transfer output commitments must be distinct");

  const preparedInputs = [];
  let rootHex = "";
  for (const [index, found] of foundInputs.entries()) {
    const note = normalizeNote(found.note);
    const commitmentHex = canonicalFieldHex(computeNoteCommitmentV1(note));
    const merkle = normalizedMerklePath(await lookupMerklePath(merklePathProvider, commitmentHex), `transfer input ${index}`);
    if (!rootHex) rootHex = merkle.root;
    else if (rootHex !== merkle.root) throw new Error("merkle root mismatch across transfer inputs");
    preparedInputs.push({
      amount: note.amount.toString(),
      randomness_hex: canonicalFieldHex(note.randomness),
      spend_pubkey_hex: notePublicKeyHex(note, "spend"),
      view_pubkey_hex: notePublicKeyHex(note, "view"),
      merkle_path: merkle.path,
      merkle_path_helper: merkle.helper,
      nullifier_hex: canonicalFieldHex(computeNoteNullifierV1(note))
    });
  }
  if (preparedInputs[0].nullifier_hex === preparedInputs[1].nullifier_hex) throw new Error("transfer input nullifiers must be distinct");

  const policy = Number(userPrivacyPolicy);
  if (!Number.isInteger(policy) || policy < 0 || policy > 7) throw new Error("transfer user privacy policy must be in 0..7");
  const mode = policy === 0
    ? 0
    : Number(userDisclosureMode ?? 2);
  if (policy === 0 && mode !== 0) throw new Error("all-private transfer must use disclosure mode NONE");
  if (policy !== 0 && mode !== 1 && mode !== 2) throw new Error("disclosed transfer must use public or recipient-encrypted disclosure mode");

  const outputRandomness = normalizeNote(recipientNote).randomness;
  const fullBlinding = randomNonZeroField(new Set([outputRandomness]));
  const userBlinding = policy === 0 ? 0n : randomNonZeroField(new Set([outputRandomness, fullBlinding]));
  const common = disclosureDigestFields(first, recipientNote, outputCommitments[0], fullBlinding);
  const fullDigest = computeTransferFullDisclosureDigestV2(common);
  const fullDisclosure = {
    plane: 2,
    outputIndex: 0,
    policy: 0xffffffff,
    disclosedFieldBitmap: 7,
    ...disclosureFields(first, recipientNote, outputCommitments[0], fullBlinding, { policy: 7, full: true })
  };
  const auditTarget = unpackPointHex(auditDisclosureTargetPubKeyHex);
  const auditPayload = encryptDisclosureV1(fullDisclosure, auditTarget, encryptedEnvelopeKindV1.auditDisclosure);

  let userDigestHex = "";
  let userTargetHex = "";
  let userPayloadHex = "";
  if (policy !== 0) {
    const userDigest = computeTransferUserDisclosureDigestV2({ ...common, policy, disclosureBlinding: userBlinding });
    const userDisclosure = {
      plane: 1,
      outputIndex: 0,
      policy,
      disclosedFieldBitmap: policy,
      ...disclosureFields(first, recipientNote, outputCommitments[0], userBlinding, { policy })
    };
    userDigestHex = canonicalFieldHex(userDigest);
    if (mode === 1) userPayloadHex = plaintextHex(marshalDisclosurePlaintextV1(userDisclosure));
    else {
      const targetHex = pointHex(userDisclosureTargetPubKeyHex, "transfer user disclosure target public key");
      userTargetHex = targetHex;
      userPayloadHex = plaintextHex(encryptDisclosureV1(userDisclosure, unpackPointHex(targetHex), encryptedEnvelopeKindV1.userDisclosure));
    }
  }

  let selfViewDigestHex = "";
  let selfViewPayloadHex = "";
  if (!disableSelfViewDisclosure) {
    const targetHex = String(selfViewDisclosureTargetPubKeyHex ?? "").trim() || (rootSeed ? deriveDisclosureKeys(rootSeed).pubKeyHex : "");
    if (!targetHex) throw new Error("transfer self-view disclosure requires rootSeed or selfViewDisclosureTargetPubKeyHex; set disableSelfViewDisclosure only for an explicit opt-out");
    selfViewDigestHex = canonicalFieldHex(fullDigest);
    selfViewPayloadHex = plaintextHex(encryptDisclosureV1(fullDisclosure, unpackPointHex(pointHex(targetHex, "transfer self-view disclosure target public key")), encryptedEnvelopeKindV1.selfViewDisclosure));
  }

  const cipherOutputs = outputNotes.map((note, index) => encryptNoteForTransferV1(note, canonicalFieldHex(outputCommitments[index]), index));
  const payload = {
    version: preparedTransferV5PayloadVersion,
    creator: sender,
    chain_id: normalizedChainId,
    expires_at_unix: expiry,
    root_hex: rootHex,
    asset_id_hex: canonicalFieldHex(first.assetID),
    inputs: preparedInputs,
    outputs: outputNotes.map((note, index) => {
      const normalized = normalizeNote(note);
      return {
        amount: normalized.amount.toString(),
        randomness_hex: canonicalFieldHex(normalized.randomness),
        spend_pubkey_hex: notePublicKeyHex(normalized, "spend"),
        view_pubkey_hex: notePublicKeyHex(normalized, "view"),
        commitment_hex: canonicalFieldHex(outputCommitments[index])
      };
    }),
    cipher_text_hexes: cipherOutputs.map(output => plaintextHex(output.ciphertext)),
    view_tag_hexes: cipherOutputs.map(output => plaintextHex(output.viewTag)),
    user_privacy_policy: policy,
    user_disclosure_mode: mode,
    user_disclosure_digest_hex: userDigestHex,
    user_disclosure_target_pubkey_hex: userTargetHex,
    user_disclosure_payload_hex: userPayloadHex,
    audit_disclosure_digest_hex: canonicalFieldHex(fullDigest),
    audit_disclosure_target_pubkey_hex: pointHex(auditDisclosureTargetPubKeyHex, "transfer audit disclosure target public key"),
    audit_disclosure_payload_hex: plaintextHex(auditPayload),
    self_view_disclosure_digest_hex: selfViewDigestHex,
    self_view_disclosure_payload_hex: selfViewPayloadHex,
    user_disclosure_blinding_hex: policy === 0 ? "" : canonicalFieldHex(userBlinding),
    full_disclosure_blinding_hex: canonicalFieldHex(fullBlinding),
    owner_signature_hex: "",
    payload_hash: ""
  };
  const effect = buildTransferV5Effect(payload);
  const payloadDigest = computeTransferPayloadDigestV1(effect);
  const chainDomain = computeChainDomainV1(normalizedChainId, activeCircuitSetIdV1);
  const intent = computeTransferIntentV2({
    chainDomain,
    root: bytesToBigIntBE(bytesFromHex(rootHex, "transfer root")),
    assetId: first.assetID,
    nullifiers: preparedInputs.map(input => bytesToBigIntBE(bytesFromHex(input.nullifier_hex, "transfer nullifier"))),
    commitments: outputCommitments,
    userDisclosureDigest: userDigestHex ? bytesToBigIntBE(bytesFromHex(userDigestHex, "transfer user disclosure digest")) : 0n,
    fullDisclosureDigest: fullDigest,
    payloadDigest,
    expiresAtUnix: expiry
  });
  const signingRequest = buildJoinSplitOwnerIntentSigningRequestV1({
    payload,
    inputNotes: [first, second],
    outputNotes,
    intent,
    payloadDigest
  });
  payload.owner_signature_hex = await signValidatedJoinSplitOwnerIntentV1(signer, signingRequest, {
    allowLegacyNoteHashSigner: !ownerIntentSigner
  });
  payload.payload_hash = computePreparedTransferV5PayloadHash(payload);
  validatePreparedTransferV5PayloadMetadata(payload);
  return payload;
}

function buildTransferV5Effect(payload) {
  return {
    creator: payload.creator,
    proof: new Uint8Array(),
    root: bytesFromHex(payload.root_hex, "transfer root"),
    nullifiers: payload.inputs.map((input, index) => bytesFromHex(input.nullifier_hex, `transfer nullifier ${index}`)),
    newCommitments: payload.outputs.map((output, index) => bytesFromHex(output.commitment_hex, `transfer commitment ${index}`)),
    cipherTexts: payload.cipher_text_hexes.map((value, index) => bytesFromHex(value, `transfer ciphertext ${index}`)),
    viewTags: payload.view_tag_hexes.map((value, index) => bytesFromHex(value, `transfer view tag ${index}`)),
    userPrivacyPolicy: payload.user_privacy_policy,
    userDisclosureDigest: payload.user_disclosure_digest_hex ? bytesFromHex(payload.user_disclosure_digest_hex, "transfer user disclosure digest") : new Uint8Array(),
    userDisclosureMode: payload.user_disclosure_mode,
    userDisclosureTargetPubkey: payload.user_disclosure_target_pubkey_hex ? bytesFromHex(payload.user_disclosure_target_pubkey_hex, "transfer user disclosure target") : new Uint8Array(),
    userDisclosurePayload: payload.user_disclosure_payload_hex ? bytesFromHex(payload.user_disclosure_payload_hex, "transfer user disclosure payload") : new Uint8Array(),
    auditDisclosureDigest: bytesFromHex(payload.audit_disclosure_digest_hex, "transfer audit disclosure digest"),
    auditDisclosureTargetPubkey: bytesFromHex(payload.audit_disclosure_target_pubkey_hex, "transfer audit disclosure target"),
    auditDisclosurePayload: bytesFromHex(payload.audit_disclosure_payload_hex, "transfer audit disclosure payload"),
    selfViewDisclosureDigest: payload.self_view_disclosure_digest_hex ? bytesFromHex(payload.self_view_disclosure_digest_hex, "transfer self-view disclosure digest") : new Uint8Array(),
    selfViewDisclosurePayload: payload.self_view_disclosure_payload_hex ? bytesFromHex(payload.self_view_disclosure_payload_hex, "transfer self-view disclosure payload") : new Uint8Array(),
    expiresAtUnix: BigInt(payload.expires_at_unix)
  };
}

export function validatePreparedTransferV5PayloadMetadata(payload) {
  normalizedPayloadForValidation(payload);
  if (!payload.payload_hash || payload.payload_hash !== computePreparedTransferV5PayloadHash(payload)) {
    throw new Error("transfer v5 payload hash mismatch; the file may have been modified after preparation");
  }
  return true;
}

export function validatePreparedTransferV5PayloadAt(payload, nowUnix = Math.floor(Date.now() / 1000)) {
  validatePreparedTransferV5PayloadMetadata(payload);
  if (!Number.isSafeInteger(nowUnix)) throw new Error("transfer v5 validation time must be a safe integer");
  if (nowUnix >= payload.expires_at_unix) throw new Error("transfer v5 payload expired; regenerate it before requesting a proof");
  return true;
}

export function validatePreparedTransferV5Proof(payload, proof, { nowUnix } = {}) {
  if (nowUnix == null) validatePreparedTransferV5PayloadMetadata(payload);
  else validatePreparedTransferV5PayloadAt(payload, nowUnix);
  if (!proof || proof.version !== preparedTransferV5ProofVersion) throw new Error(`unsupported transfer v5 proof version ${JSON.stringify(proof?.version)}`);
  if (proof.payload_hash !== payload.payload_hash) throw new Error("transfer v5 proof payload hash mismatch");
  const proofHex = opaqueHex(proof.proof_hex, "transfer v5 proof", { exactLength: 164 });
  const proofBytes = bytesFromHex(proofHex, "transfer v5 proof");
  for (const offset of [0, 32, 96, 132]) {
    if ((proofBytes[offset] & 0xc0) === 0) throw new Error(`transfer v5 proof point at offset ${offset} is not compressed`);
  }
  if (proofBytes.slice(128, 132).some(byte => byte !== 0)) throw new Error("transfer v5 proof commitments are not supported");
  return true;
}

export function buildTransferV5MsgFromPayloadAndProof(payload, proof, { nowUnix } = {}) {
  validatePreparedTransferV5Proof(payload, proof, { nowUnix });
  return {
    creator: payload.creator,
    proof: bytesFromHex(proof.proof_hex, "transfer v5 proof"),
    root: bytesFromHex(payload.root_hex, "transfer v5 root"),
    nullifiers: payload.inputs.map((input, index) => bytesFromHex(input.nullifier_hex, `transfer v5 nullifier ${index}`)),
    newCommitments: payload.outputs.map((output, index) => bytesFromHex(output.commitment_hex, `transfer v5 commitment ${index}`)),
    cipherTexts: payload.cipher_text_hexes.map((value, index) => bytesFromHex(value, `transfer v5 ciphertext ${index}`)),
    viewTags: payload.view_tag_hexes.map((value, index) => bytesFromHex(value, `transfer v5 view tag ${index}`)),
    userPrivacyPolicy: payload.user_privacy_policy,
    userDisclosureDigest: payload.user_disclosure_digest_hex ? bytesFromHex(payload.user_disclosure_digest_hex, "transfer v5 user disclosure digest") : new Uint8Array(),
    userDisclosureMode: payload.user_disclosure_mode,
    userDisclosureTargetPubkey: payload.user_disclosure_target_pubkey_hex ? bytesFromHex(payload.user_disclosure_target_pubkey_hex, "transfer v5 user disclosure target") : new Uint8Array(),
    userDisclosurePayload: payload.user_disclosure_payload_hex ? bytesFromHex(payload.user_disclosure_payload_hex, "transfer v5 user disclosure payload") : new Uint8Array(),
    auditDisclosureDigest: bytesFromHex(payload.audit_disclosure_digest_hex, "transfer v5 audit disclosure digest"),
    auditDisclosureTargetPubkey: bytesFromHex(payload.audit_disclosure_target_pubkey_hex, "transfer v5 audit disclosure target"),
    auditDisclosurePayload: bytesFromHex(payload.audit_disclosure_payload_hex, "transfer v5 audit disclosure payload"),
    selfViewDisclosureDigest: payload.self_view_disclosure_digest_hex ? bytesFromHex(payload.self_view_disclosure_digest_hex, "transfer v5 self-view disclosure digest") : new Uint8Array(),
    selfViewDisclosurePayload: payload.self_view_disclosure_payload_hex ? bytesFromHex(payload.self_view_disclosure_payload_hex, "transfer v5 self-view disclosure payload") : new Uint8Array(),
    expiresAtUnix: BigInt(payload.expires_at_unix)
  };
}
