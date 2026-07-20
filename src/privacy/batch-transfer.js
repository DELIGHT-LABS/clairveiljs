import { base64FromBytes, bytesFromBase64, bytesFromHex, hexFromBytes } from "../core/browser-crypto.js";
import { normalizeHex } from "../core/crypto.js";
import { validateBatchTransferEffectsV1 } from "./protocol-v1.js";

export const preparedBatchTransferPayloadVersion = "batch-transfer-payload-v1";
export const preparedBatchTransferProofVersion = "batch-transfer-proof-v1";
export const batchTransferCircuitSetId = "privacy-note-v1";
export const batchTransferProofRequestVersion = "v1";
export const batchTransferProofResponseVersion = "v1";
export const batchTransferProofPath = "/v1/proofs/batch-transfer";
export const batchTransferProofSize = 164;

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

function positiveSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${label} must be a positive safe integer`);
  return value;
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
  const expiresAtUnix = positiveSafeInteger(payload.expires_at_unix, "prepared batch transfer expires_at_unix");
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
    auditKeyEpoch: BigInt(positiveSafeInteger(payload.audit_key_epoch, "prepared batch transfer audit key epoch")),
    auditDisclosureTargetPubkey: exactBase64(payload.audit_disclosure_target_pubkey, "prepared batch transfer audit disclosure target", 32),
    expiresAtUnix: BigInt(expiresAtUnix)
  };
  validateBatchTransferEffectsV1(message);
  return message;
}

export function validatePreparedBatchTransferPayloadEnvelope(payload, { nowUnix } = {}) {
  parsedBatchEffect(payload);
  fieldHex(payload.payload_hash, "prepared batch transfer payload hash");
  if (nowUnix != null) {
    if (!Number.isSafeInteger(nowUnix)) throw new Error("prepared batch transfer validation time must be a safe integer");
    if (nowUnix >= payload.expires_at_unix) throw new Error("prepared batch transfer payload expired; regenerate it before requesting a proof");
  }
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
