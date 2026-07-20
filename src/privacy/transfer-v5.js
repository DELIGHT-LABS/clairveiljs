import {
  CURVE_ORDER,
  bytesFromHex,
  decodeCanonicalFieldHex,
  normalizeHex,
  unpackPointHex
} from "../core/crypto.js";
import { sha256Hex } from "../core/browser-crypto.js";
import {
  disclosurePlaintextV1Size,
  encryptedEnvelopeKindV1,
  unmarshalDisclosurePlaintextV1,
  unwrapEncryptedEnvelopeV1
} from "./protocol-v1.js";

export const preparedTransferV5PayloadVersion = "v5";
export const preparedTransferV5ProofVersion = "v2";
export const transferV5ProofRequestVersion = "v2";
export const transferV5ProofResponseVersion = "v2";

const maxShieldedAmount = (1n << 64n) - 1n;

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

function validateDisclosureBlindings(payload, policy, outputs) {
  const outputRandomness = BigInt(`0x${outputs[0].randomness_hex}`);
  const full = BigInt(`0x${fieldHex(payload.full_disclosure_blinding_hex, "transfer full disclosure blinding", { nonZero: true })}`);
  if (full === outputRandomness) throw new Error("transfer full disclosure blinding must differ from recipient output randomness");
  const encodedUser = String(payload.user_disclosure_blinding_hex ?? "").trim();
  if (policy === 0) {
    if (encodedUser) throw new Error("all-private transfer payload must omit the zero user disclosure blinding sentinel");
    return;
  }
  const user = BigInt(`0x${fieldHex(encodedUser, "transfer user disclosure blinding", { nonZero: true })}`);
  if (user === outputRandomness) throw new Error("transfer user disclosure blinding must differ from recipient output randomness");
  if (user === full) throw new Error("transfer user and full disclosure blindings must differ");
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
