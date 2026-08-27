import { toBech32 } from "@cosmjs/encoding";
import { Registry, encodePubkey, makeAuthInfoBytes, makeSignDoc } from "@cosmjs/proto-signing";
import { BroadcastTxError, defaultRegistryTypes, StargateClient } from "@cosmjs/stargate";
import { TxBody, TxRaw } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import {
  MsgBatchTransfer as GeneratedMsgBatchTransfer,
  MsgDeposit as GeneratedMsgDeposit,
  MsgTransfer as GeneratedMsgTransfer,
  MsgWithdraw as GeneratedMsgWithdraw,
  UserDisclosureMode
} from "../generated/clairveil/privacy/v1/tx.js";
import {
  bytesFromHex,
  bytesToBigIntBE,
  decodeShieldedAddress,
  defaultAccountPrefix,
  deriveDisclosureKeys,
  derivePrivacyMaterial,
  deriveSpendKeys,
  deriveViewKeys,
  FIELD_MODULUS,
  normalizeBech32Prefix
} from "../core/crypto.js";
import {
  decodeAuditDisclosureFromEvent,
  decodeAuditDisclosureFromScanOutput,
  decodeBatchAuditDisclosureFromScanOutput,
  decodeBatchSelfViewDisclosureFromScanOutput,
  decodeBatchUserDisclosureFromScanOutput,
  decodeSelfViewDisclosureFromEvent,
  decodeSelfViewDisclosureFromScanOutput,
  decodeUserDisclosureFromEvent,
  decodeUserDisclosureFromScanOutput,
  disclosureScalarFromHex
} from "../core/disclosure.js";
import {
  buildDepositMaterial as buildDepositMaterialCore,
  defaultAssetDenom,
  createNote,
  createSpendNoteHashSigner,
  parseCoin
} from "../core/note.js";
import {
  buildPreparedTransferPayload as buildPreparedTransferPayloadCore,
  buildTransferMessage as buildTransferMessageCore,
  buildPreparedWithdrawProverPayload as buildPreparedWithdrawProverPayloadCore,
  buildRelayWithdrawMsgFromPayload as buildRelayWithdrawMsgFromPayloadCore,
  buildRelayWithdrawPayload as buildRelayWithdrawPayloadCore,
  buildWithdrawMessage as buildWithdrawMessageCore,
  validateRelayWithdrawPayload
} from "../privacy/payload.js";
import {
  canonicalAssetDenomV1,
  canonicalAssetIDHexV1,
  normalizeAssetRegistryQueryResponseV1
} from "../privacy/asset-registry.js";
import {
  batchTransferProofSize,
  batchTransferProofResponseVersion,
  buildMsgBatchTransferFromPrepared,
  buildPreparedBatchTransferPayload,
  normalizePreparedBatchTransferProof,
  preparedBatchTransferEffectHex,
  validatePreparedBatchTransferPayloadEnvelope
} from "../privacy/batch-transfer.js";
import {
  normalizeAuditConfigV1,
  normalizeDisclosureConfigV1,
  normalizeReserveResponseV1
} from "../privacy/network-config.js";
import {
  validateCircuitConfigV1,
  validateExpectedCircuitIdentityV1
} from "../privacy/circuit-config.js";
import {
  computeAssetIdV1,
  computeNoteCommitmentV1,
  fieldHexV1,
  validateBatchTransferEffectsV1
} from "../privacy/protocol-v1.js";
import {
  assertPlanCanBuildTx,
  planTransferBatchNotes,
  planTransferNotes,
  planWithdrawNotes
} from "../privacy/planner.js";
import {
  assertBatchTransferNullifiersUnspent,
  getBroadcastReservationRecords,
  hashAmount,
  hashRecipient,
  hashTransparentRecipient,
  preparePlanReservation,
  reservationStatuses,
  rollbackPlanReservation,
  rollbackPlanReservationPreservingError
} from "../privacy/reservation.js";
import {
  appendReservationCleanupErrors,
  markReservationProofReady,
  reservationAvailableNotes,
  reservationBatchSummary,
  reservationReconciliationFields,
  withReservationHeartbeat
} from "../privacy/reservation-workflow.js";
import {
  aliasedValueProvided as operationEvidenceAliasProvided,
  normalizeCosmosFeeCoins,
  resolveAliasedString as resolveOperationEvidenceAlias,
  resolveCosmosFeeAmount,
  resolveCosmosGasLimit,
  resolveDirectOperationEvidenceHashes,
  transferProofReadyMetadata
} from "./cosmos-options.js";
import {
  createPrivacyScanValidationStateV2,
  parseNullifierUsage,
  processPrivacyScanPageV2,
  restorePrivacyScanValidationStateV2,
  scanNotes as scanNotesCore,
  serializePrivacyScanValidationStateV2,
  validatePrivacyScanPageV2
} from "../privacy/scan.js";
import {
  createCommitmentPathSnapshotProvider,
  normalizeCommitmentPathsAtRootRequest,
  normalizeCommitmentPathsAtRootResponse
} from "../privacy/merkle-path.js";
import {
  createWalletAdapter,
  derivePrivacyMaterialFromWallet
} from "../wallet/adapter.js";
import {
  base64FromBytes,
  bytesFromBase64,
  bytesFromHex as rawBytesFromHex,
  hash160,
  randomBytes,
  hexFromBytes,
  sha256Hex
} from "../core/browser-crypto.js";
import {
  checkPrivacyStateAdapterNullifiers,
  createPrivacyStateAdapter,
  invokePrivacyStateAdapter,
  normalizePrivacyNullifierStatuses
} from "./privacy-state.js";

export * from "../core/crypto.js";
export * from "../core/disclosure.js";
export * from "../core/errors.js";
export * from "../core/note.js";
export * from "../privacy/payload.js";
export * from "../privacy/circuit-config.js";
export * from "../privacy/network-config.js";
export * from "../privacy/planner.js";
export * from "../privacy/prover.js";

export * from "../privacy/reservation.js";
export * from "../privacy/scan.js";
export * from "../privacy/merkle-path.js";
export * from "../privacy/note-store.js";
export * from "../core/schemas.js";
export * from "../wallet/adapter.js";
export * from "./privacy-state.js";
export {
  userDisclosureModeFromJSON,
  userDisclosureModeToJSON
} from "../generated/clairveil/privacy/v1/tx.js";

export const msgDepositTypeUrl = GeneratedMsgDeposit.typeUrl;
export const msgBatchTransferTypeUrl = GeneratedMsgBatchTransfer.typeUrl;
export const msgTransferTypeUrl = GeneratedMsgTransfer.typeUrl;
export const msgWithdrawTypeUrl = GeneratedMsgWithdraw.typeUrl;
const defaultPrepareScanMaxPages = 1000;
// A typed scan event contains at most 32 outputs. A caller page budget may
// stop at an event prefix, but spendable notes must never escape until the
// remaining pages prove the complete event framing.
const maxPrivacyScanEventCompletionPages = 32;
const cosmosSignDocMetadataField = "__clairveilCosmosSignDoc";
const cosmosReservationRequiredMemoMarker = "[clairveil-reservation-required:v1]";
const maxBatchTransferMessageBytesV1 = 128 << 10;
const defaultFetchTimeoutMs = 30000;
const maxUint64 = (1n << 64n) - 1n;
const defaultRetryStatuses = Object.freeze([408, 429, 502, 503, 504]);
const defaultQueryRetry = Object.freeze({
  retries: 2,
  baseDelayMs: 250,
  maxDelayMs: 1500,
  jitter: true,
  retryStatuses: defaultRetryStatuses
});
const transferPrivacyPolicyNames = Object.freeze([
  "all-private",
  "amount",
  "to",
  "amount-to",
  "from",
  "amount-from",
  "from-to",
  "amount-from-to"
]);
const transferPrivacyPolicyAliases = Object.freeze({
  "to-from": "from-to",
  "amount-to-from": "amount-from-to"
});
const transferDisclosureModeNames = Object.freeze([
  "none",
  "public",
  "recipient-encrypted"
]);
const transferDisclosureModeAliases = Object.freeze({
  USER_DISCLOSURE_MODE_NONE: "none",
  USER_DISCLOSURE_MODE_PUBLIC: "public",
  USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED: "recipient-encrypted"
});
export const batchTransferOperationEvidenceVersion = "batch-transfer-operation-evidence-v1";

function canonicalTransferPrivacyPolicyName(value) {
  let policy;
  if (typeof value === "number") policy = value;
  else if (typeof value === "bigint") policy = Number(value);
  else {
    const text = String(value ?? "all-private").trim() || "all-private";
    const alias = transferPrivacyPolicyAliases[text] || text;
    policy = /^[0-7]$/.test(alias) ? Number(alias) : transferPrivacyPolicyNames.indexOf(alias);
  }
  if (!Number.isInteger(policy) || policy < 0 || policy >= transferPrivacyPolicyNames.length) {
    throw new Error("unsupported transfer privacy policy");
  }
  return transferPrivacyPolicyNames[policy];
}

function canonicalTransferDisclosureModeName(value, policy) {
  if (policy === "all-private") return "none";
  let mode;
  if (typeof value === "number") mode = value;
  else if (typeof value === "bigint") mode = Number(value);
  else {
    const text = String(value ?? "recipient-encrypted").trim() || "recipient-encrypted";
    const alias = transferDisclosureModeAliases[text] || text;
    mode = /^[0-2]$/.test(alias) ? Number(alias) : transferDisclosureModeNames.indexOf(alias);
  }
  if (!Number.isInteger(mode) || mode < 1 || mode >= transferDisclosureModeNames.length) {
    throw new Error("disclosure mode must be public or recipient-encrypted when disclosure is enabled");
  }
  return transferDisclosureModeNames[mode];
}

function randomBatchField({ nonZero = true } = {}) {
  while (true) {
    const candidate = bytesToBigIntBE(randomBytes(32));
    if (candidate < FIELD_MODULUS && (!nonZero || candidate !== 0n)) return candidate;
  }
}

function normalizedBatchNowUnix(value) {
  const nowUnix = Number(value);
  if (!Number.isSafeInteger(nowUnix) || nowUnix < 0) {
    throw new Error("batch transfer chainNowUnix must be a non-negative safe integer");
  }
  return nowUnix;
}

function normalizedTransferUnix(value, label) {
  const unix = value;
  if (!Number.isSafeInteger(unix) || unix < 0) {
    throw new Error(`transfer ${label} must be a non-negative safe integer`);
  }
  return unix;
}

function aliasedTransferUnix(camelValue, snakeValue, label) {
  const hasCamel = camelValue !== undefined && camelValue !== null;
  const hasSnake = snakeValue !== undefined && snakeValue !== null;
  const camel = hasCamel ? normalizedTransferUnix(camelValue, label) : undefined;
  const snake = hasSnake ? normalizedTransferUnix(snakeValue, label) : undefined;
  if (hasCamel && hasSnake && camel !== snake) {
    throw new Error(`${label} aliases conflict`);
  }
  return hasCamel ? camel : snake;
}

function requiredTransferPreparationTime(chainNowUnix, expiresAtUnix) {
  if (chainNowUnix === undefined) {
    throw new Error("transfer chainNowUnix is required from authoritative chain time");
  }
  const expiry = expiresAtUnix ?? chainNowUnix + 1800;
  if (!Number.isSafeInteger(expiry)) {
    throw new Error("transfer expiresAtUnix must be a non-negative safe integer");
  }
  if (expiry <= chainNowUnix) {
    throw new Error("transfer expiresAtUnix must be later than chainNowUnix");
  }
  return { chainNowUnix, expiresAtUnix: expiry };
}

function normalizeBatchTransferOutputMode(value) {
  const mode = String(value ?? "compact").trim() || "compact";
  if (mode === "compact") return "compact";
  if (mode === "exact32" || mode === "exact-32") return "exact32";
  throw new Error("batch transfer outputMode must be compact, exact32, or exact-32");
}

function comparableBatchHex(value) {
  return String(value ?? "").trim().toLowerCase().replace(/^0x/, "");
}

function normalizeBatchTransferInputCommitments(inputCommitmentHexes, input_commitment_hexes) {
  const normalize = (value, label) => {
    if (!Array.isArray(value) || value.length < 1 || value.length > 16) {
      throw new Error(`${label} must contain 1..16 input commitments`);
    }
    const commitments = value.map((item, index) => {
      const commitment = comparableBatchHex(item);
      if (!/^[0-9a-f]{64}$/.test(commitment) || BigInt(`0x${commitment}`) >= FIELD_MODULUS) {
        throw new Error(`${label}[${index}] must be a canonical BN254 field commitment`);
      }
      return commitment;
    });
    if (new Set(commitments).size !== commitments.length) {
      throw new Error(`${label} must not contain duplicate commitments`);
    }
    return commitments;
  };
  const camel = inputCommitmentHexes == null
    ? null
    : normalize(inputCommitmentHexes, "inputCommitmentHexes");
  const snake = input_commitment_hexes == null
    ? null
    : normalize(input_commitment_hexes, "input_commitment_hexes");
  if (camel && snake &&
      (camel.length !== snake.length || camel.some((value, index) => value !== snake[index]))) {
    throw new Error("inputCommitmentHexes aliases conflict");
  }
  return camel ?? snake;
}

function batchPaymentValue(payment, names, fallback) {
  const values = names
    .filter(name => payment?.[name] !== undefined && payment?.[name] !== null)
    .map(name => payment[name]);
  if (values.length > 1 && values.some(value => String(value) !== String(values[0]))) {
    throw new Error(`batch payment ${names[0]} aliases conflict`);
  }
  return values.length ? values[0] : fallback;
}

function normalizeBatchTransferPayments({
  payments,
  amounts,
  recipient,
  userPrivacyPolicy,
  userDisclosureMode,
  userDisclosureTargetPubKeyHex
} = {}) {
  if (payments != null) {
    if (!Array.isArray(payments) || payments.length < 1 || payments.length > 32) {
      throw new Error("batch transfer payments must contain 1..32 items");
    }
    if (amounts != null || recipient != null) {
      throw new Error("batch transfer payments cannot be combined with legacy amounts/recipient");
    }
  } else {
    if (!Array.isArray(amounts) || amounts.length < 1 || amounts.length > 32) {
      throw new Error("batch transfer amounts must contain 1..32 items");
    }
    if (!String(recipient || "").trim()) throw new Error("batch transfer recipient is required");
  }
  const source = payments ?? amounts.map(amount => ({ amount, recipient }));
  const normalized = source.map((payment, index) => {
    if (!payment || typeof payment !== "object" || Array.isArray(payment)) {
      throw new Error(`batch transfer payment ${index} must be an object`);
    }
    const amount = batchPaymentValue(payment, ["amount"], "");
    const paymentRecipient = String(batchPaymentValue(
      payment,
      ["recipient", "recipientAddress", "recipient_address"],
      ""
    ) || "").trim();
    if (!amount) throw new Error(`batch transfer payment ${index} amount is required`);
    if (!paymentRecipient) throw new Error(`batch transfer payment ${index} recipient is required`);
    const policy = batchPaymentValue(
      payment,
      ["userPrivacyPolicy", "user_privacy_policy", "privacyPolicy", "privacy_policy"],
      userPrivacyPolicy
    );
    const mode = batchPaymentValue(
      payment,
      ["userDisclosureMode", "user_disclosure_mode", "disclosureMode", "disclosure_mode"],
      userDisclosureMode
    );
    const disclosureTarget = String(batchPaymentValue(
      payment,
      [
        "userDisclosureTargetPubKeyHex",
        "user_disclosure_target_pubkey_hex",
        "disclosurePubKeyHex",
        "disclosure_pubkey_hex"
      ],
      userDisclosureTargetPubKeyHex
    ) || "").trim();
    return Object.freeze({
      itemId: String(batchPaymentValue(payment, ["itemId", "item_id"], `batch-item-${index}`) || "").trim() || `batch-item-${index}`,
      amount,
      recipient: paymentRecipient,
      userPrivacyPolicy: policy,
      userDisclosureMode: mode,
      userDisclosureTargetPubKeyHex: disclosureTarget,
      expectedRecipientHash: String(batchPaymentValue(payment, ["expectedRecipientHash", "expected_recipient_hash"], "") || "").trim(),
      expectedAmountHash: String(batchPaymentValue(payment, ["expectedAmountHash", "expected_amount_hash"], "") || "").trim(),
      expectedOutputCommitment: String(batchPaymentValue(payment, ["expectedOutputCommitment", "expected_output_commitment"], "") || "").trim(),
      expectedUserDisclosureDigest: String(batchPaymentValue(payment, ["expectedUserDisclosureDigest", "expected_user_disclosure_digest"], "") || "").trim(),
      expectedAuditDisclosureDigest: String(batchPaymentValue(payment, ["expectedAuditDisclosureDigest", "expected_audit_disclosure_digest", "expectedDisclosureDigest", "expected_disclosure_digest"], "") || "").trim(),
      expectedSelfViewDisclosureDigest: String(batchPaymentValue(payment, ["expectedSelfViewDisclosureDigest", "expected_self_view_disclosure_digest"], "") || "").trim(),
      memo: String(batchPaymentValue(payment, ["memo"], "Transfer") ?? "Transfer")
    });
  });
  if (new Set(normalized.map(payment => payment.itemId)).size !== normalized.length) {
    throw new Error("batch transfer payment item IDs must be unique");
  }
  return normalized;
}

function canonicalBatchEvidenceDigest(value, label, { optional = false } = {}) {
  const text = String(value || "").trim().toLowerCase().replace(/^0x/, "");
  if (optional && !text) return "";
  if (!/^[0-9a-f]{64}$/.test(text)) throw new Error(`${label} must be exactly 32 bytes of hex`);
  return text;
}

function assertExpectedBatchEvidence(expected, actual, label) {
  const normalized = canonicalBatchEvidenceDigest(expected, label, { optional: true });
  if (normalized && normalized !== actual) {
    throw new Error(`${label} does not match the final prepared batch payload`);
  }
}

function batchWireDigest(wire, field, label, { optional = false } = {}) {
  const encoded = String(wire?.[field] || "");
  if (!encoded && optional) return "";
  const bytes = bytesFromBase64(encoded, label);
  if (bytes.length === 0 && optional) return "";
  if (bytes.length !== 32) throw new Error(`${label} must be exactly 32 bytes`);
  return hexFromBytes(bytes);
}

function buildBatchTransferExpectedOutputEvidence({
  payload,
  payments,
  operationId,
  denom,
  shieldedPrefix,
  nowUnix
}) {
  validatePreparedBatchTransferPayloadEnvelope(payload, { nowUnix });
  if (!Array.isArray(payments) || !payments.length ||
      payload.outputs.length < payments.length ||
      payload.message_outputs.length !== payload.outputs.length) {
    throw new Error("batch transfer payment evidence does not match the prepared output shape");
  }
  const assetIDHex = BigInt(payload.asset_id).toString(16).padStart(64, "0");
  const resolvedOperationID = String(operationId || `batch:${payload.payload_hash}`);
  return Object.freeze(payments.map((payment, index) => {
    const output = payload.outputs[index];
    const wire = payload.message_outputs[index];
    if (output?.kind !== "payment" || String(output?.note?.am ?? "") !== String(payment.coin.amount)) {
      throw new Error(`prepared batch payment output ${index} does not match its payment`);
    }
    const recipient = decodeShieldedAddress(payment.recipient, { shieldedPrefix });
    if (
      String(output.note.rsx) !== String(recipient.spendPubKey.x) ||
      String(output.note.rsy) !== String(recipient.spendPubKey.y) ||
      String(output.note.rvx) !== String(recipient.viewPubKey.x) ||
      String(output.note.rvy) !== String(recipient.viewPubKey.y)
    ) {
      throw new Error(`prepared batch payment output ${index} recipient keys do not match its payment`);
    }
    if (
      Number(output.privacy_policy) !== Number(payment.privacyPolicy) ||
      Number(output.disclosure_mode) !== Number(payment.disclosureMode)
    ) {
      throw new Error(`prepared batch payment output ${index} disclosure policy does not match its payment`);
    }
    const commitment = batchWireDigest(wire, "commitment", `batch output ${index} commitment`);
    const userDigest = batchWireDigest(wire, "user_disclosure_digest", `batch output ${index} user disclosure digest`, { optional: true });
    const fullDigest = batchWireDigest(wire, "full_disclosure_digest", `batch output ${index} full disclosure digest`);
    const selfViewPayload = bytesFromBase64(
      String(wire?.self_view_disclosure_payload || ""),
      `batch output ${index} self-view disclosure payload`
    );
    const selfViewDigest = selfViewPayload.length ? fullDigest : "";
    const recipientHash = hashRecipient(payment.recipient, { shieldedPrefix });
    const amountHash = hashAmount(denom, payment.coin.amount);
    const assertedRecipientHash = canonicalBatchEvidenceDigest(payment.expectedRecipientHash, `batch payment ${index} expected recipient hash`, { optional: true });
    const assertedAmountHash = canonicalBatchEvidenceDigest(payment.expectedAmountHash, `batch payment ${index} expected amount hash`, { optional: true });
    if (assertedRecipientHash && assertedRecipientHash !== recipientHash) {
      throw new Error(`batch payment ${index} expected recipient hash does not match its recipient`);
    }
    if (assertedAmountHash && assertedAmountHash !== amountHash) {
      throw new Error(`batch payment ${index} expected amount hash does not match its amount`);
    }
    assertExpectedBatchEvidence(payment.expectedOutputCommitment, commitment, `batch payment ${index} expected output commitment`);
    assertExpectedBatchEvidence(payment.expectedUserDisclosureDigest, userDigest, `batch payment ${index} expected user disclosure digest`);
    assertExpectedBatchEvidence(payment.expectedAuditDisclosureDigest, fullDigest, `batch payment ${index} expected audit disclosure digest`);
    assertExpectedBatchEvidence(payment.expectedSelfViewDisclosureDigest, selfViewDigest, `batch payment ${index} expected self-view disclosure digest`);
    return Object.freeze({
      operation_id: resolvedOperationID,
      item_id: payment.itemId,
      batch_item_index: index,
      role: "payment",
      expected_output_commitment: commitment,
      expected_user_disclosure_digest: userDigest,
      expected_audit_disclosure_digest: fullDigest,
      expected_self_view_disclosure_digest: selfViewDigest,
      expected_recipient_hash: recipientHash,
      expected_amount: String(payment.coin.amount),
      expected_amount_hash: amountHash,
      expected_denom: denom,
      asset_id_hex: assetIDHex,
      user_privacy_policy: payment.privacyPolicy,
      user_disclosure_mode: payment.disclosureMode,
      audit_key_id: payload.audit_key_id,
      audit_key_epoch: String(payload.audit_key_epoch)
    });
  }));
}

function buildBatchTransferOperationEvidence({
  payload,
  proof,
  payments,
  expectedOutputs,
  operationId,
  denom,
  shieldedPrefix,
  nowUnix
}) {
  validatePreparedBatchTransferPayloadEnvelope(payload, { nowUnix });
  const resolvedExpectedOutputs = expectedOutputs || buildBatchTransferExpectedOutputEvidence({
    payload,
    payments,
    operationId,
    denom,
    shieldedPrefix,
    nowUnix
  });
  const resolvedOperationID = String(
    operationId || resolvedExpectedOutputs[0]?.operation_id || `batch:${payload.payload_hash}`
  );
  const effects = preparedBatchTransferEffectHex(payload);
  const evidence = Object.freeze({
    version: batchTransferOperationEvidenceVersion,
    operation_id: resolvedOperationID,
    circuit_set_id: payload.circuit_set_id,
    payload_hash: payload.payload_hash,
    proof_payload_hash: proof.request_payload_hash,
    proof_hash: sha256Hex(proof.proof_bytes),
    input_nullifier_hexes: Object.freeze([...effects.nullifier_hexes]),
    expected_outputs: Object.freeze([...resolvedExpectedOutputs])
  });
  return Object.freeze({
    evidence,
    evidenceHash: sha256Hex(JSON.stringify(evidence))
  });
}

/**
 * Bind a checkpointed batch payload to the same authoritative network
 * configuration used at preparation time. Reusing this at proof-resume and
 * finalization keeps an old checkpoint from becoming signable after an asset,
 * audit, or disclosure-policy change.
 */
function assertPreparedBatchTransferMatchesActiveConfig(payload, transferProtocolConfig, denom) {
  if (String(payload.asset_id) !== computeAssetIdV1(denom).toString()) {
    throw new Error("prepared batch transfer asset ID does not match the authoritative denom");
  }
  const activeAuditConfig = transferProtocolConfig.audit_config;
  if (String(payload.audit_key_id) !== String(activeAuditConfig.audit_key_id) ||
      String(payload.audit_key_epoch) !== String(activeAuditConfig.audit_key_epoch) ||
      hexFromBytes(bytesFromBase64(
        payload.audit_disclosure_target_pubkey,
        "prepared batch transfer audit disclosure target"
      )) !== String(activeAuditConfig.audit_master_pubkey_hex).toLowerCase()) {
    throw new Error("prepared batch transfer audit identity does not match the active chain config");
  }
  for (const [index, output] of payload.outputs.entries()) {
    try {
      assertTransferDisclosureCapabilities(transferProtocolConfig.disclosure_config, {
        userPrivacyPolicy: output.privacy_policy,
        userDisclosureMode: output.disclosure_mode
      });
    } catch (error) {
      throw new Error(`prepared batch transfer output ${index} is incompatible with the active disclosure config`, {
        cause: error
      });
    }
  }
}

export function assertTransferDisclosureCapabilities(disclosureConfig, {
  userPrivacyPolicy,
  userDisclosureMode
} = {}) {
  const policy = canonicalTransferPrivacyPolicyName(userPrivacyPolicy);
  const mode = canonicalTransferDisclosureModeName(userDisclosureMode, policy);
  if (!disclosureConfig.supported_user_policies.includes(policy)) {
    throw new Error(`disclosure config does not support transfer privacy policy ${policy}`);
  }
  if (!disclosureConfig.supported_user_modes.includes(mode)) {
    throw new Error(`disclosure config does not support user disclosure mode ${mode}`);
  }
  return Object.freeze({ policy, mode });
}

function bindRawTransferBuilderProtocolConfig(input, transferProtocolConfig) {
  const camelAuditTarget = input?.auditDisclosureTargetPubKeyHex;
  const snakeAuditTarget = input?.audit_disclosure_target_pubkey_hex;
  if (camelAuditTarget != null && snakeAuditTarget != null &&
      String(camelAuditTarget).trim().toLowerCase() !== String(snakeAuditTarget).trim().toLowerCase()) {
    throw new Error("auditDisclosureTargetPubKeyHex aliases conflict");
  }
  const requestedAuditTarget = String(camelAuditTarget ?? snakeAuditTarget ?? "").trim().toLowerCase();
  const activeAuditTarget = String(
    transferProtocolConfig.audit_config.audit_master_pubkey_hex || ""
  ).trim().toLowerCase();
  if (requestedAuditTarget && requestedAuditTarget !== activeAuditTarget) {
    throw new Error("transfer audit disclosure target must exactly match the active chain audit config");
  }
  assertTransferDisclosureCapabilities(transferProtocolConfig.disclosure_config, {
    userPrivacyPolicy: input?.userPrivacyPolicy ?? input?.user_privacy_policy ?? "all-private",
    userDisclosureMode: input?.userDisclosureMode ?? input?.user_disclosure_mode ?? "none"
  });
  return {
    ...input,
    auditDisclosureTargetPubKeyHex: transferProtocolConfig.audit_config.audit_master_pubkey_hex
  };
}

function normalizeTimeoutMs(value, label = "timeoutMs") {
  const timeoutMs = Number(value);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error(`${label} must be positive`);
  }
  return timeoutMs;
}

function normalizeNonNegativeInteger(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return number;
}

function uint64CursorBigInt(value, label) {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative safe integer, bigint, or canonical uint64 string`);
    }
    return BigInt(value);
  }
  if (typeof value === "bigint") {
    if (value < 0n || value > maxUint64) {
      throw new Error(`${label} must be within uint64 range`);
    }
    return value;
  }
  const text = String(value ?? "").trim();
  if (!/^(0|[1-9][0-9]*)$/.test(text)) {
    throw new Error(`${label} must be a canonical uint64 decimal string`);
  }
  const parsed = BigInt(text);
  if (parsed > maxUint64) {
    throw new Error(`${label} must be within uint64 range`);
  }
  return parsed;
}

function uint64CursorValue(value, label) {
  const parsed = uint64CursorBigInt(value, label);
  return parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : parsed.toString();
}

function compareUint64Cursor(left, right, label) {
  const leftValue = uint64CursorBigInt(left, `${label} left value`);
  const rightValue = uint64CursorBigInt(right, `${label} right value`);
  return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
}

function maxUint64Cursor(values, label) {
  let maximum = 0n;
  for (const value of values) {
    const parsed = uint64CursorBigInt(value ?? 0, label);
    if (parsed > maximum) maximum = parsed;
  }
  return maximum <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(maximum) : maximum.toString();
}

function decrementUint64Cursor(value, label) {
  const parsed = uint64CursorBigInt(value ?? 0, label);
  const decremented = parsed > 0n ? parsed - 1n : 0n;
  return decremented <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(decremented) : decremented.toString();
}

function normalizeDelayMs(value, label) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) {
    throw new Error(`${label} must be non-negative`);
  }
  return number;
}

function normalizeQueryRetry(value = {}) {
  if (value === false) {
    return {
      retries: 0,
      baseDelayMs: defaultQueryRetry.baseDelayMs,
      maxDelayMs: defaultQueryRetry.maxDelayMs,
      jitter: false,
      retryStatuses: new Set(defaultRetryStatuses)
    };
  }
  const retry = value || {};
  return {
    retries: normalizeNonNegativeInteger(retry.retries ?? defaultQueryRetry.retries, "queryRetry.retries"),
    baseDelayMs: normalizeDelayMs(retry.baseDelayMs ?? defaultQueryRetry.baseDelayMs, "queryRetry.baseDelayMs"),
    maxDelayMs: normalizeDelayMs(retry.maxDelayMs ?? defaultQueryRetry.maxDelayMs, "queryRetry.maxDelayMs"),
    jitter: retry.jitter ?? defaultQueryRetry.jitter,
    retryStatuses: new Set(retry.retryStatuses ?? defaultRetryStatuses)
  };
}

function retryDelayMs(attemptNumber, retry) {
  const base = retry.baseDelayMs * (attemptNumber <= 1 ? 1 : 3 ** (attemptNumber - 1));
  const capped = Math.min(retry.maxDelayMs, base);
  if (!retry.jitter || capped <= 0) return capped;
  return Math.round(capped + (Math.random() * capped * 0.2));
}

function sleep(ms) {
  return ms > 0 ? new Promise(resolve => setTimeout(resolve, ms)) : Promise.resolve();
}

function isRetryableFetchError(error, retry) {
  if (error?.name === "AbortError" || error?.code === "FETCH_TIMEOUT") return true;
  if (error?.status != null) return retry.retryStatuses.has(Number(error.status));
  return true;
}

function normalizeRestEndpoints(primary, restEndpoints = [], { allowEmpty = false } = {}) {
  const endpoints = [];
  for (const endpoint of [primary, ...(Array.isArray(restEndpoints) ? restEndpoints : [])]) {
    const normalized = normalizeRestEndpoint(String(endpoint || ""));
    if (normalized && !endpoints.includes(normalized)) {
      endpoints.push(normalized);
    }
  }
  if (!endpoints.length && !allowEmpty) {
    throw new Error("rest endpoint is required");
  }
  return endpoints;
}

function requiredDepositProof(input = {}) {
  if (input?.proof != null) {
    const proof = typeof input.proof === "string"
      ? bytesFromHex(input.proof, "deposit proof")
      : Uint8Array.from(input.proof);
    if (proof.length) return proof;
  }
  const proofHex = input?.proofHex ?? input?.proof_hex;
  if (proofHex != null && String(proofHex).trim()) {
    const proof = bytesFromHex(proofHex, "deposit proof");
    if (proof.length) return proof;
  }
  throw new Error("deposit proof is required; provide proof or proofHex");
}

export const MsgDeposit = GeneratedMsgDeposit;
export const MsgBatchTransfer = GeneratedMsgBatchTransfer;
export const MsgTransfer = GeneratedMsgTransfer;
export const MsgWithdraw = GeneratedMsgWithdraw;
export { UserDisclosureMode };

export function createClairveilRegistry(extraTypes = []) {
  return new Registry([
    ...defaultRegistryTypes,
    [msgDepositTypeUrl, MsgDeposit],
    [msgBatchTransferTypeUrl, MsgBatchTransfer],
    [msgTransferTypeUrl, MsgTransfer],
    [msgWithdrawTypeUrl, MsgWithdraw],
    ...extraTypes
  ]);
}

export function normalizeRpcEndpoint(rpc) {
  return String(rpc || "").replace(/^tcp:\/\//, "http://").replace(/\/$/, "");
}

export function normalizeRestEndpoint(rest) {
  return rest.replace(/\/$/, "");
}

export function buildRootSigningMessage(address, pubKeyHex) {
  return [
    "clairveil-root-v1",
    `address:${address}`,
    `pubkey:${pubKeyHex}`
  ].join("\n");
}

export function cosmosAddressFromPubKey(pubKeyHex, prefix = "clair") {
  return toBech32(prefix, hash160(rawBytesFromHex(pubKeyHex, "pubKeyHex")));
}

export function verifySignerPubKey(address, pubKeyHex, prefix = defaultAccountPrefix) {
  const expectedAddress = cosmosAddressFromPubKey(pubKeyHex, prefix);
  return {
    address,
    expectedAddress,
    matches: address === expectedAddress
  };
}

export function assertSignerPubKey(address, pubKeyHex, prefix = defaultAccountPrefix) {
  const signerCheck = verifySignerPubKey(address, pubKeyHex, prefix);
  if (!signerCheck.matches) {
    throw new Error(`signer address/pubKey mismatch. ${address} maps to ${signerCheck.expectedAddress}`);
  }
  return signerCheck;
}

export function eventAttribute(event, key) {
  return (event?.attributes || []).find(attribute => attribute.key === key)?.value || "";
}

function transactionEvents(tx) {
  return [
    ...(Array.isArray(tx?.events) ? tx.events : []),
    ...(Array.isArray(tx?.tx_result?.events) ? tx.tx_result.events : []),
    ...(Array.isArray(tx?.tx?.events) ? tx.tx.events : [])
  ];
}

function transactionEventType(event) {
  return String(event?.type ?? event?.event_type ?? event?.eventType ?? "").trim().toLowerCase();
}

function transactionEventAttribute(event, key) {
  const attributes = Array.isArray(event?.attributes)
    ? event.attributes
    : Array.isArray(event?.Attributes)
      ? event.Attributes
      : [];
  return attributes.find(attribute => String(attribute?.key ?? attribute?.Key ?? "") === key)?.value ??
    attributes.find(attribute => String(attribute?.key ?? attribute?.Key ?? "") === key)?.Value ??
    "";
}

function normalizedDepositHex(value, label) {
  const raw = value instanceof Uint8Array
    ? hexFromBytes(value)
    : String(value ?? "").trim().replace(/^"|"$/g, "").replace(/^0x/i, "");
  if (!raw || !/^[0-9a-f]+$/i.test(raw) || raw.length % 2 !== 0) {
    throw new Error(`${label} must be non-empty hex`);
  }
  return raw.toLowerCase();
}

function depositExpectedMaterial({ prepared, material, depositMaterial, deposit_material, message, expectedCommitment, expected_commitment, expectedEncryptedNote, expected_encrypted_note } = {}) {
  const resolvedMaterial = depositMaterial ?? deposit_material ?? material ?? prepared?.material ?? null;
  const resolvedMessage = message ?? prepared?.message ?? null;
  const commitment = expectedCommitment ?? expected_commitment ??
    resolvedMaterial?.note_commitment_hex ?? resolvedMaterial?.noteCommitmentHex ??
    resolvedMaterial?.note_commitment ?? resolvedMaterial?.noteCommitment ??
    resolvedMessage?.noteCommitment ?? resolvedMessage?.note_commitment;
  const encryptedNote = expectedEncryptedNote ?? expected_encrypted_note ??
    resolvedMaterial?.encrypted_note_hex ?? resolvedMaterial?.encryptedNoteHex ??
    resolvedMaterial?.encrypted_note ?? resolvedMaterial?.encryptedNote ??
    resolvedMessage?.encryptedNote ?? resolvedMessage?.encrypted_note;
  return {
    commitment: normalizedDepositHex(commitment, "expected deposit commitment"),
    encryptedNote: normalizedDepositHex(encryptedNote, "expected deposit encrypted note")
  };
}

function explicitTransactionCode(tx) {
  const raw = tx?.code ?? tx?.tx_result?.code;
  if (typeof raw === "number" && Number.isSafeInteger(raw) && raw >= 0) return raw;
  if (typeof raw === "string" && /^(0|[1-9][0-9]*)$/.test(raw.trim())) return Number(raw);
  return null;
}

export function isAuditableTransfer(event) {
  return event?.event_type === "shielded_transfer" && Boolean(eventAttribute(event, "audit_disclosure_payload"));
}

function toBase64(bytes) {
  return base64FromBytes(bytes);
}

function fromBase64(value, label = "base64") {
  return bytesFromBase64(value, label);
}

function attachBroadcastEvidence(error, { txHash = "", txBytesHash = "" } = {}) {
  const original = error && typeof error === "object"
    ? error
    : new Error(String(error || "broadcast failed"));
  try {
    // These canonical fields identify the exact signed TxRaw bytes. Preserve
    // transport-specific aliases for diagnostics, but never let an arbitrary
    // remote decoration suppress or replace the deterministic recovery key.
    if (txHash) original.txHash = txHash;
    if (txBytesHash) original.txBytesHash = txBytesHash;
    return original;
  } catch {
    const wrapped = new Error(
      String(original?.message || error || "broadcast failed"),
      { cause: original }
    );
    const originalPrototype = Object.getPrototypeOf(original);
    if (originalPrototype && originalPrototype !== Object.prototype) {
      Object.setPrototypeOf(wrapped, originalPrototype);
    }
    if (typeof original?.name === "string" && original.name) {
      wrapped.name = original.name;
    }
    for (const field of ["code", "codespace", "log"]) {
      if (original?.[field] !== undefined) wrapped[field] = original[field];
    }
    if (txHash) wrapped.txHash = txHash;
    if (txBytesHash) wrapped.txBytesHash = txBytesHash;
    return wrapped;
  }
}

function attachBroadcastDisposition(error, fields = {}) {
  const original = error && typeof error === "object"
    ? error
    : new Error(String(error || "broadcast failed"));
  try {
    Object.assign(original, fields);
    return original;
  } catch {
    const wrapped = new Error(
      String(original?.message || error || "broadcast failed"),
      { cause: original }
    );
    const originalPrototype = Object.getPrototypeOf(original);
    if (originalPrototype && originalPrototype !== Object.prototype) {
      Object.setPrototypeOf(wrapped, originalPrototype);
    }
    if (typeof original?.name === "string" && original.name) wrapped.name = original.name;
    for (const field of ["code", "codespace", "log", "txHash", "txBytesHash"]) {
      if (original?.[field] !== undefined) wrapped[field] = original[field];
    }
    Object.assign(wrapped, fields);
    return wrapped;
  }
}

function isExplicitCheckTxRejection(error) {
  if (error instanceof BroadcastTxError) return true;
  return error?.name === "BroadcastTxError" &&
    Number.isSafeInteger(error?.code) &&
    Number(error.code) !== 0 &&
    typeof error?.codespace === "string";
}

function normalizedCosmosTxHash(value) {
  const normalized = String(value || "").trim().replace(/^0x/i, "");
  return /^[0-9a-fA-F]{64}$/.test(normalized) ? normalized.toUpperCase() : "";
}

function runSynchronousBeforeBroadcast(options = {}, evidence = {}) {
  const callback = options?.beforeBroadcast;
  if (callback == null) return;
  if (typeof callback !== "function") {
    throw new TypeError("beforeBroadcast must be a function");
  }
  const result = callback(Object.freeze({
    txHash: String(evidence.txHash || ""),
    txBytesHash: String(evidence.txBytesHash || ""),
    signDocHash: String(evidence.signDocHash || "")
  }));
  if (
    result != null &&
    (typeof result === "object" || typeof result === "function") &&
    typeof result.then === "function"
  ) {
    // Observe a rejected async callback without ever awaiting it. The
    // broadcast remains blocked and the durable attempt is reconciled below.
    void Promise.resolve(result).catch(() => {});
    throw new TypeError("beforeBroadcast must be synchronous and must not return a Promise");
  }
}

function directSignDocFromBase64(signDoc) {
  return {
    bodyBytes: fromBase64(signDoc.bodyBytes, "bodyBytes"),
    authInfoBytes: fromBase64(signDoc.authInfoBytes, "authInfoBytes"),
    chainId: signDoc.chainId,
    accountNumber: BigInt(signDoc.accountNumber)
  };
}

function markCosmosSignDocReservationRequired(
  signDoc,
  reservationBatch
) {
  if (
    !signDoc ||
    typeof signDoc !== "object" ||
    !reservationBatch?.reservation_ids?.length
  ) {
    return signDoc;
  }
  const current = signDoc[cosmosSignDocMetadataField] || {};
  const bindingHash = cosmosSignDocBindingHash(signDoc);
  Object.defineProperty(signDoc, cosmosSignDocMetadataField, {
    value: Object.freeze({
      ...current,
      reservationRequired: true,
      bindingHash
    }),
    enumerable: true,
    configurable: true
  });
  return signDoc;
}

function cosmosSignDocMetadata(signDoc) {
  return signDoc?.[cosmosSignDocMetadataField] || {};
}

function reservationRequiredCosmosMemo(memo = "") {
  const lines = String(memo || "")
    .trim()
    .split("\n")
    .map(line => line.trim())
    .filter(Boolean);
  if (!lines.includes(cosmosReservationRequiredMemoMarker)) {
    lines.push(cosmosReservationRequiredMemoMarker);
  }
  return lines.join("\n");
}

function cosmosTxBodyRequiresReservation(signDoc) {
  try {
    const body = TxBody.decode(fromBase64(signDoc?.bodyBytes, "bodyBytes"));
    return String(body.memo || "")
      .split("\n")
      .some(line => line.trim() === cosmosReservationRequiredMemoMarker);
  } catch {
    return false;
  }
}

function externalCosmosSignDoc(signDoc) {
  if (!signDoc || typeof signDoc !== "object") return signDoc;
  const external = { ...signDoc };
  delete external[cosmosSignDocMetadataField];
  return external;
}

function directBroadcastContext(input = {}) {
  const {
    wallet,
    signDoc,
    waitOptions,
    attempts,
    intervalMs,
    reservationManager,
    reservation_manager,
    reservation,
    reservationBatch,
    reservation_batch
  } = input;
  if (attempts !== undefined && waitOptions?.attempts !== undefined && attempts !== waitOptions.attempts) {
    throw new Error("attempts conflicts with waitOptions.attempts");
  }
  if (intervalMs !== undefined && waitOptions?.intervalMs !== undefined && intervalMs !== waitOptions.intervalMs) {
    throw new Error("intervalMs conflicts with waitOptions.intervalMs");
  }
  const resolvedWaitOptions = {
    ...(waitOptions || {}),
    ...(attempts !== undefined ? { attempts } : {}),
    ...(intervalMs !== undefined ? { intervalMs } : {})
  };
  const resolvedReservation = reservation ?? reservationBatch ?? reservation_batch;
  const reservationContext = broadcastReservationContext({
    ...resolvedWaitOptions,
    reservationManager: reservationManager ?? reservation_manager ?? null,
    reservation: resolvedReservation
  });
  const walletSignDoc = externalCosmosSignDoc(signDoc);
  const broadcastOptions = {
    ...resolvedWaitOptions,
    reservationManager: reservationManager ?? reservation_manager ?? null,
    reservation: resolvedReservation,
    relayPayload: input.relayPayload ?? input.relay_payload,
    getChainNowUnix: input.getChainNowUnix,
    get_chain_now_unix: input.get_chain_now_unix,
    chainNowUnix: input.chainNowUnix,
    chain_now_unix: input.chain_now_unix,
    expectedChainId: input.expectedChainId ?? input.expected_chain_id,
    expectedRecipient: input.expectedRecipient ?? input.expected_recipient,
    accountPrefix: input.accountPrefix ?? input.account_prefix,
    beforeBroadcast: input.beforeBroadcast
  };
  return {
    wallet,
    signDoc,
    walletSignDoc,
    reservation: resolvedReservation,
    reservationContext,
    signDocHash: cosmosSignDocBindingHash(signDoc),
    broadcastOptions
  };
}

function fromHex(value, label = "hex") {
  return rawBytesFromHex(value, label);
}

async function fetchJson(url, {
  timeoutMs = defaultFetchTimeoutMs,
  fetchImpl = globalThis.fetch,
  method = "GET",
  body,
  headers
} = {}) {
  const resolvedTimeoutMs = normalizeTimeoutMs(timeoutMs, "fetch timeoutMs");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), resolvedTimeoutMs);
  const requestHeaders = {
    accept: "application/json",
    ...(body != null ? { "content-type": "application/json" } : {}),
    ...(headers || {})
  };
  try {
    const response = await fetchImpl(url, {
      method,
      headers: requestHeaders,
      body,
      signal: controller.signal
    });
    if (!response.ok) {
      const error = new Error(`${response.status} ${response.statusText}`);
      error.status = response.status;
      error.statusText = response.statusText;
      throw error;
    }
    return response.json();
  } catch (error) {
    if (error?.name === "AbortError") {
      // Query URLs may contain nullifiers, commitments, or account material.
      // Keep timeout diagnostics useful without copying the request target.
      const timeoutError = new Error(`fetch request timed out after ${resolvedTimeoutMs}ms`);
      timeoutError.code = "FETCH_TIMEOUT";
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchJsonWithRetry(urlForEndpoint, endpoints, {
  timeoutMs,
  retry,
  fetchImpl,
  method,
  body,
  headers,
  failoverStatuses = []
} = {}) {
  const normalizedRetry = normalizeQueryRetry(retry);
  const normalizedFailoverStatuses = new Set(failoverStatuses || []);
  let lastError = null;
  let lastNonCapabilityError = null;
  for (let endpointIndex = 0; endpointIndex < endpoints.length; endpointIndex += 1) {
    const endpoint = endpoints[endpointIndex];
    for (let attempt = 0; attempt <= normalizedRetry.retries; attempt += 1) {
      try {
        return {
          data: await fetchJson(urlForEndpoint(endpoint), { timeoutMs, fetchImpl, method, body, headers }),
          endpoint
        };
      } catch (error) {
        lastError = error;
        if (normalizedFailoverStatuses.has(Number(error?.status))) {
          if (endpointIndex < endpoints.length - 1) break;
          throw lastNonCapabilityError || error;
        }
        const retryable = isRetryableFetchError(error, normalizedRetry);
        if (!retryable) {
          throw error;
        }
        lastNonCapabilityError = error;
        const canRetry = attempt < normalizedRetry.retries && retryable;
        if (!canRetry) break;
        await sleep(retryDelayMs(attempt + 1, normalizedRetry));
      }
    }
  }
  throw lastNonCapabilityError || lastError;
}

function unwrapBaseAccount(value) {
  let current = value;
  const seen = new Set();
  // Auth QueryAccount returns BaseAccount fields directly for common accounts,
  // but vesting/module account Any values wrap those fields one or two levels
  // below base_vesting_account/base_account. Keep this bounded and accept only
  // the exact account-number/sequence pair needed by direct signing.
  for (let depth = 0; depth < 8 && current && typeof current === "object"; depth += 1) {
    if (seen.has(current)) return null;
    seen.add(current);
    if (current.account_number != null && current.sequence != null) return current;
    current = current.base_account ?? current.baseAccount ??
      current.base_vesting_account ?? current.baseVestingAccount ?? null;
  }
  return null;
}

function privacyEventsQuery({
  afterHeight,
  after_height,
  page,
  limit,
  eventTypes,
  event_types
} = {}) {
  const params = new URLSearchParams();
  const resolvedAfterHeight = afterHeight ?? after_height;
  if (resolvedAfterHeight != null) {
    params.set("after_height", String(resolvedAfterHeight));
  }
  if (page != null) {
    params.set("page", String(page));
  }
  if (limit != null) {
    params.set("limit", String(limit));
  }
  const resolvedEventTypes = eventTypes ?? event_types;
  if (Array.isArray(resolvedEventTypes)) {
    for (const eventType of resolvedEventTypes) {
      if (String(eventType || "").trim()) {
        params.append("event_types", String(eventType).trim());
      }
    }
  } else if (resolvedEventTypes != null && String(resolvedEventTypes).trim()) {
    params.set("event_types", String(resolvedEventTypes).trim());
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

function scanEventsQuery({
  afterHeight,
  after_height,
  afterSequence,
  after_sequence,
  limit,
  eventTypes,
  event_types
} = {}) {
  const params = new URLSearchParams();
  const resolvedAfterHeight = afterHeight ?? after_height;
  if (resolvedAfterHeight != null) {
    params.set("after_height", String(resolvedAfterHeight));
  }
  const resolvedAfterSequence = afterSequence ?? after_sequence;
  if (resolvedAfterSequence != null) {
    params.set("after_sequence", String(resolvedAfterSequence));
  }
  if (limit != null) {
    params.set("limit", String(limit));
  }
  const resolvedEventTypes = eventTypes ?? event_types;
  if (Array.isArray(resolvedEventTypes)) {
    for (const eventType of resolvedEventTypes) {
      if (String(eventType || "").trim()) {
        params.append("event_types", String(eventType).trim());
      }
    }
  } else if (resolvedEventTypes != null && String(resolvedEventTypes).trim()) {
    params.set("event_types", String(resolvedEventTypes).trim());
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

function jsonRequestBody(value) {
  return JSON.stringify(value, (_key, item) => typeof item === "bigint" ? item.toString() : item);
}

function privacyScanRequestBody({
  after,
  outputLimit,
  output_limit,
  eventLimit,
  event_limit,
  maxEncodedBytes,
  max_encoded_bytes,
  eventTypes,
  event_types
} = {}) {
  const cursor = after && typeof after === "object"
    ? {
      height: after.height ?? 0,
      globalSequence: after.globalSequence ?? after.global_sequence ?? 0,
      outputIndex: after.outputIndex ?? after.output_index ?? 0
    }
    : undefined;
  return {
    ...(cursor ? { after: cursor } : {}),
    ...(outputLimit ?? output_limit) != null ? { outputLimit: outputLimit ?? output_limit } : {},
    ...(eventLimit ?? event_limit) != null ? { eventLimit: eventLimit ?? event_limit } : {},
    ...(maxEncodedBytes ?? max_encoded_bytes) != null ? { maxEncodedBytes: maxEncodedBytes ?? max_encoded_bytes } : {},
    ...(eventTypes ?? event_types) != null ? { eventTypes: eventTypes ?? event_types } : {}
  };
}

function commitmentPathsAtRootRequestBody({
  commitmentHexes,
  commitment_hexes,
  rootHex,
  root_hex,
  snapshotHeight,
  snapshot_height
} = {}) {
  const commitments = commitmentHexes ?? commitment_hexes;
  if (!Array.isArray(commitments) || commitments.length === 0 || commitments.length > 16) {
    throw new Error("commitmentHexes must contain 1..16 commitments");
  }
  const normalizedRoot = String(rootHex ?? root_hex ?? "").trim();
  if (!normalizedRoot) throw new Error("rootHex is required");
  const height = snapshotHeight ?? snapshot_height;
  return {
    commitmentHexes: commitments.map(value => String(value || "").trim()),
    rootHex: normalizedRoot,
    ...(height == null || String(height).trim() === "" ? {} : { snapshotHeight: height })
  };
}

function comparableCosmosTxHash(value) {
  return String(value ?? "").trim().replace(/^0x/i, "").toUpperCase();
}

function normalizedCosmosTxHash(value, label = "txHash") {
  const normalized = comparableCosmosTxHash(value);
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function privacyEventsCursor(data, request = {}) {
  const events = data?.events || [];
  let latestHeight = 0;
  let latestTxHash = "";
  for (const event of events) {
    const height = uint64CursorValue(event?.height ?? 0, "privacy event height");
    if (compareUint64Cursor(height, latestHeight, "privacy event height") >= 0) {
      latestHeight = height;
      latestTxHash = String(event?.tx_hash_hex || "").toUpperCase();
    }
  }
  return {
    source: "privacy_events",
    after_height: uint64CursorValue(request.afterHeight ?? request.after_height ?? 0, "privacy events after height"),
    page: Number(data?.page ?? request.page ?? 1),
    limit: Number(data?.limit ?? request.limit ?? events.length),
    event_types: request.eventTypes ?? request.event_types ?? [],
    has_more: Boolean(data?.has_more),
    latest_height: latestHeight,
    latest_tx_hash: latestTxHash
  };
}

function scanEventsCursor(data, request = {}) {
  const events = data?.events || [];
  let latestHeight = 0;
  let latestSequence = 0;
  let latestTxHash = "";
  for (const event of events) {
    const height = uint64CursorValue(event?.height ?? 0, "scan event height");
    const sequence = uint64CursorValue(event?.sequence ?? 0, "scan event sequence");
    const heightComparison = compareUint64Cursor(height, latestHeight, "scan event height");
    if (heightComparison > 0 || (
      heightComparison === 0 &&
      compareUint64Cursor(sequence, latestSequence, "scan event sequence") >= 0
    )) {
      latestHeight = height;
      latestSequence = sequence;
      latestTxHash = String(event?.tx_hash_hex ?? event?.txHashHex ?? "").toUpperCase();
    }
  }
  return {
    source: "scan_events",
    after_height: uint64CursorValue(request.afterHeight ?? request.after_height ?? 0, "scan events after height"),
    after_sequence: uint64CursorValue(request.afterSequence ?? request.after_sequence ?? 0, "scan events after sequence"),
    limit: Number(data?.limit ?? request.limit ?? events.length),
    event_types: request.eventTypes ?? request.event_types ?? [],
    has_more: Boolean(data?.has_more),
    next_height: uint64CursorValue(data?.next_height ?? data?.nextHeight ?? request.afterHeight ?? request.after_height ?? 0, "scan events next height"),
    next_sequence: uint64CursorValue(data?.next_sequence ?? data?.nextSequence ?? request.afterSequence ?? request.after_sequence ?? 0, "scan events next sequence"),
    latest_height: latestHeight,
    latest_sequence: latestSequence,
    latest_tx_hash: latestTxHash,
    scan_format_version: Number(data?.scan_format_version ?? data?.scanFormatVersion ?? 0),
    view_tag_version: Number(data?.view_tag_version ?? data?.viewTagVersion ?? 0)
  };
}

function assertScanEventsVersions(data) {
  const scanFormatVersion = Number(data?.scan_format_version ?? data?.scanFormatVersion ?? 0);
  const viewTagVersion = Number(data?.view_tag_version ?? data?.viewTagVersion ?? 0);
  if (scanFormatVersion !== 1) {
    const error = new Error(`unsupported scan_format_version ${scanFormatVersion}; expected 1`);
    error.code = "UNSUPPORTED_SCAN_EVENTS_VERSION";
    throw error;
  }
  if (viewTagVersion !== 1) {
    const error = new Error(`unsupported view_tag_version ${viewTagVersion}; expected 1`);
    error.code = "UNSUPPORTED_SCAN_EVENTS_VERSION";
    throw error;
  }
}

function requiredScanEventsField(value, field, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !(field in value)) {
    throw new Error(`${label}.${field} is required`);
  }
  return value[field];
}

function scanEventsHex(value, label, length) {
  if (typeof value !== "string" || !/^[0-9a-fA-F]+$/.test(value) ||
      (length != null && value.length !== length)) {
    throw new Error(`${label} must be ${length == null ? "a non-empty hex string" : `${length} hex characters`}`);
  }
  return value;
}

function scanEventsNonNegativeInteger(value, label) {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) return value;
  throw new Error(`${label} must be a non-negative integer`);
}

function compareScanEventsPosition(leftHeight, leftSequence, rightHeight, rightSequence) {
  const heightComparison = compareUint64Cursor(leftHeight, rightHeight, "scan events height");
  return heightComparison === 0
    ? compareUint64Cursor(leftSequence, rightSequence, "scan events sequence")
    : heightComparison;
}

function validateScanEventsResponse(data, request = {}) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("scan_events response must be an object");
  }
  assertScanEventsVersions(data);
  const events = requiredScanEventsField(data, "events", "scan_events response");
  if (!Array.isArray(events)) throw new Error("scan_events response.events must be an array");
  const nextHeight = scanEventsNonNegativeInteger(
    requiredScanEventsField(data, "next_height", "scan_events response"),
    "scan_events response.next_height"
  );
  const nextSequence = scanEventsNonNegativeInteger(
    requiredScanEventsField(data, "next_sequence", "scan_events response"),
    "scan_events response.next_sequence"
  );
  const responseLimit = scanEventsNonNegativeInteger(
    requiredScanEventsField(data, "limit", "scan_events response"),
    "scan_events response.limit"
  );
  if (compareUint64Cursor(responseLimit, 0, "scan_events response limit") <= 0) {
    throw new Error("scan_events response.limit must be a positive integer");
  }
  const hasMore = requiredScanEventsField(data, "has_more", "scan_events response");
  if (typeof hasMore !== "boolean") throw new Error("scan_events response.has_more must be a boolean");

  const afterHeight = scanEventsNonNegativeInteger(
    request.afterHeight ?? request.after_height ?? 0,
    "scan_events request.after_height"
  );
  const afterSequence = scanEventsNonNegativeInteger(
    request.afterSequence ?? request.after_sequence ?? 0,
    "scan_events request.after_sequence"
  );
  const requestedEventTypes = new Set((request.eventTypes ?? request.event_types ?? [])
    .map(value => String(value || "").trim())
    .filter(Boolean));
  let previousHeight = afterHeight;
  let previousSequence = afterSequence;
  for (let eventIndex = 0; eventIndex < events.length; eventIndex += 1) {
    const event = events[eventIndex];
    const label = `scan_events response.events[${eventIndex}]`;
    const height = scanEventsNonNegativeInteger(requiredScanEventsField(event, "height", label), `${label}.height`);
    const sequence = scanEventsNonNegativeInteger(requiredScanEventsField(event, "sequence", label), `${label}.sequence`);
    if (compareScanEventsPosition(height, sequence, previousHeight, previousSequence) <= 0) {
      throw new Error(`${label} is not strictly after the preceding scan cursor`);
    }
    previousHeight = height;
    previousSequence = sequence;
    scanEventsHex(requiredScanEventsField(event, "tx_hash_hex", label), `${label}.tx_hash_hex`);
    const eventType = requiredScanEventsField(event, "event_type", label);
    if (typeof eventType !== "string" || !eventType.trim()) throw new Error(`${label}.event_type must be a non-empty string`);
    if (requestedEventTypes.size && !requestedEventTypes.has(eventType)) {
      throw new Error(`${label}.event_type was not requested`);
    }
    const nullifiers = requiredScanEventsField(event, "nullifier_hexes", label);
    if (!Array.isArray(nullifiers)) throw new Error(`${label}.nullifier_hexes must be an array`);
    nullifiers.forEach((nullifier, index) => scanEventsHex(nullifier, `${label}.nullifier_hexes[${index}]`, 64));
    const outputs = requiredScanEventsField(event, "outputs", label);
    if (!Array.isArray(outputs)) throw new Error(`${label}.outputs must be an array`);
    if (eventType === "deposit" && outputs.length !== 1) throw new Error(`${label}.outputs must contain exactly one deposit output`);
    if (eventType === "shielded_transfer" && outputs.length !== 2) throw new Error(`${label}.outputs must contain exactly two transfer outputs`);
    const outputIndexes = new Set();
    for (let outputIndex = 0; outputIndex < outputs.length; outputIndex += 1) {
      const output = outputs[outputIndex];
      const outputLabel = `${label}.outputs[${outputIndex}]`;
      const index = requiredScanEventsField(output, "output_index", outputLabel);
      if (!Number.isSafeInteger(index) || index < 0) throw new Error(`${outputLabel}.output_index must be a non-negative integer`);
      if (outputIndexes.has(index)) throw new Error(`${label}.outputs contains duplicate output_index ${index}`);
      outputIndexes.add(index);
      if (eventType === "deposit") {
        scanEventsHex(requiredScanEventsField(output, "commitment_hex", outputLabel), `${outputLabel}.commitment_hex`, 64);
        scanEventsHex(requiredScanEventsField(output, "encrypted_note_hex", outputLabel), `${outputLabel}.encrypted_note_hex`);
      } else if (eventType === "shielded_transfer") {
        scanEventsHex(requiredScanEventsField(output, "commitment_hex", outputLabel), `${outputLabel}.commitment_hex`, 64);
        scanEventsHex(requiredScanEventsField(output, "cipher_text_hex", outputLabel), `${outputLabel}.cipher_text_hex`);
        scanEventsHex(requiredScanEventsField(output, "view_tag_hex", outputLabel), `${outputLabel}.view_tag_hex`, 4);
      }
      if ("leaf_index_found" in output && typeof output.leaf_index_found !== "boolean") {
        throw new Error(`${outputLabel}.leaf_index_found must be a boolean`);
      }
      if ("leaf_index" in output) scanEventsNonNegativeInteger(output.leaf_index, `${outputLabel}.leaf_index`);
    }
  }
  if (compareScanEventsPosition(nextHeight, nextSequence, previousHeight, previousSequence) < 0) {
    throw new Error("scan_events next cursor precedes the final event");
  }
  if (hasMore && compareScanEventsPosition(nextHeight, nextSequence, afterHeight, afterSequence) <= 0) {
    throw new Error("scan_events next cursor did not advance");
  }
  return data;
}

export function nextPrivacyScanOptions(scanOrCursor = {}, defaults = {}) {
  const cursor = scanOrCursor?.scanCursor || scanOrCursor || {};
  if (cursor.source === "privacy_scan" || cursor.next_cursor != null || cursor.nextCursor != null) {
    const hasMore = Boolean(cursor.has_more ?? cursor.hasMore);
    const nextCursor = cursor.next_cursor ?? cursor.nextCursor ?? cursor.after ?? cursor.afterCursor ?? {
      height: 0,
      global_sequence: 0,
      output_index: 0
    };
    const normalized = validatePrivacyScanPageV2({
      scanSchemaVersion: "privacy-scan-v2",
      summaries: [],
      outputs: [],
      nextCursor,
      hasMore: false
    }, { after: nextCursor }).next_cursor;
    const next = {
      after: {
        height: normalized.height,
        globalSequence: normalized.global_sequence,
        outputIndex: normalized.output_index
      },
      limit: Number(cursor.output_limit ?? cursor.outputLimit ?? defaults.limit ?? 200),
      outputLimit: Number(cursor.output_limit ?? cursor.outputLimit ?? defaults.outputLimit ?? defaults.output_limit ?? 200),
      eventLimit: cursor.event_limit ?? cursor.eventLimit ?? defaults.eventLimit ?? defaults.event_limit,
      maxEncodedBytes: cursor.max_encoded_bytes ?? cursor.maxEncodedBytes ?? defaults.maxEncodedBytes ?? defaults.max_encoded_bytes,
      eventTypes: [],
      scanSource: "privacy_scan",
      hasMore,
      completed: !hasMore
    };
    const validationState = cursor.validation_state ?? cursor.validationState;
    if (validationState != null) {
      // Parse before returning it so a corrupt durable cursor cannot silently
      // downgrade the cross-page all-or-none batch disclosure guarantee.
      next.validationStateSnapshot = serializePrivacyScanValidationStateV2(
        restorePrivacyScanValidationStateV2(validationState)
      );
    }
    const maxPages = resolveScanMaxPagesAlias(defaults.maxPages, defaults.max_pages);
    if (maxPages != null) next.maxPages = maxPages;
    const includeFoundNotes = defaults.includeFoundNotes ?? defaults.include_found_notes;
    if (includeFoundNotes != null) next.includeFoundNotes = Boolean(includeFoundNotes);
    return next;
  }
  if (cursor.source === "scan_events" || cursor.next_sequence != null || cursor.nextSequence != null) {
    const hasMore = Boolean(cursor.has_more ?? cursor.hasMore);
    const next = {
      afterHeight: uint64CursorValue(
        hasMore
          ? cursor.next_height ?? cursor.nextHeight ?? cursor.after_height ?? cursor.afterHeight ?? 0
          : cursor.next_height ?? cursor.nextHeight ?? cursor.latest_height ?? cursor.latestHeight ?? cursor.after_height ?? cursor.afterHeight ?? 0,
        "scan resume height"
      ),
      afterSequence: uint64CursorValue(
        hasMore
          ? cursor.next_sequence ?? cursor.nextSequence ?? cursor.after_sequence ?? cursor.afterSequence ?? 0
          : cursor.next_sequence ?? cursor.nextSequence ?? cursor.latest_sequence ?? cursor.latestSequence ?? cursor.after_sequence ?? cursor.afterSequence ?? 0,
        "scan resume sequence"
      ),
      limit: Number(cursor.limit ?? defaults.limit ?? 200),
      eventTypes: cursor.event_types ?? cursor.eventTypes ?? defaults.eventTypes ?? defaults.event_types ?? [],
      hasMore,
      completed: !hasMore
    };
    next.scanSource = "scan_events";
    const maxPages = resolveScanMaxPagesAlias(defaults.maxPages, defaults.max_pages);
    if (maxPages != null) next.maxPages = maxPages;
    const includeFoundNotes = defaults.includeFoundNotes ?? defaults.include_found_notes;
    if (includeFoundNotes != null) next.includeFoundNotes = Boolean(includeFoundNotes);
    return next;
  }
  const afterHeight = uint64CursorValue(cursor.after_height ?? cursor.afterHeight ?? defaults.afterHeight ?? defaults.after_height ?? 0, "privacy events after height");
  const latestHeight = uint64CursorValue(cursor.latest_height ?? cursor.latestHeight ?? 0, "privacy events latest height");
  const hasMore = Boolean(cursor.has_more ?? cursor.hasMore);
  const nextPage = hasMore
    ? Number(cursor.next_page ?? cursor.nextPage ?? (Number(cursor.page || 1) + 1))
    : 1;
  const nextAfterHeight = hasMore
    ? afterHeight
    : maxUint64Cursor([afterHeight, latestHeight], "privacy events resume height");
  const next = {
    afterHeight: nextAfterHeight,
    page: nextPage,
    limit: Number(cursor.limit ?? defaults.limit ?? 200),
    eventTypes: cursor.event_types ?? cursor.eventTypes ?? defaults.eventTypes ?? defaults.event_types ?? [],
    scanSource: cursor.source === "privacy_events" ? "privacy_events" : defaults.scanSource ?? defaults.scan_source ?? "privacy_events"
  };
  const maxPages = resolveScanMaxPagesAlias(defaults.maxPages, defaults.max_pages);
  if (maxPages != null) next.maxPages = maxPages;
  const includeFoundNotes = defaults.includeFoundNotes ?? defaults.include_found_notes;
  if (includeFoundNotes != null) next.includeFoundNotes = Boolean(includeFoundNotes);
  next.hasMore = hasMore;
  next.completed = !hasMore;
  return next;
}

function normalizeScanMaxPages(value, label) {
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return normalized;
}

function resolveScanMaxPagesAlias(maxPages, max_pages) {
  const camelProvided = maxPages !== undefined && maxPages !== null;
  const snakeProvided = max_pages !== undefined && max_pages !== null;
  const camel = camelProvided ? normalizeScanMaxPages(maxPages, "maxPages") : null;
  const snake = snakeProvided ? normalizeScanMaxPages(max_pages, "max_pages") : null;
  if (camel !== null && snake !== null && camel !== snake) {
    throw new Error("maxPages aliases conflict");
  }
  return camel ?? snake;
}

function resolveScanOptions({
  scan,
  after,
  afterHeight,
  after_height,
  afterSequence,
  after_sequence,
  page,
  limit,
  maxPages,
  max_pages,
  eventTypes,
  event_types,
  outputLimit,
  output_limit,
  eventLimit,
  event_limit,
  maxEncodedBytes,
  max_encoded_bytes,
  validationStateSnapshot,
  validation_state_snapshot,
  scanSource,
  scan_source,
  strictPrivacyScan,
  strict_privacy_scan
} = {}) {
  const resolvedEventTypes = scan?.eventTypes ?? scan?.event_types ?? eventTypes ?? event_types;
  if (resolvedEventTypes != null) {
    if (!Array.isArray(resolvedEventTypes)) {
      throw new Error("wallet and spend scan eventTypes must be an array");
    }
    if (resolvedEventTypes.some(value => String(value || "").trim())) {
      throw new Error("wallet and spend scans must not filter event types; typed privacy_scan summaries are required");
    }
  }
  const resolvedScanSource = scan?.scanSource ?? scan?.scan_source ?? scanSource ?? scan_source;
  if (resolvedScanSource != null && resolvedScanSource !== "privacy_scan") {
    throw new Error("wallet and spend scans only support the typed privacy_scan source");
  }
  return {
    after: scan?.after ?? after,
    afterHeight: scan?.afterHeight ?? scan?.after_height ?? afterHeight ?? after_height,
    afterSequence: scan?.afterSequence ?? scan?.after_sequence ?? afterSequence ?? after_sequence,
    page: scan?.page ?? page,
    limit: scan?.limit ?? limit,
    maxPages: scan?.maxPages ?? scan?.max_pages ?? maxPages ?? max_pages,
    eventTypes: [],
    outputLimit: scan?.outputLimit ?? scan?.output_limit ?? outputLimit ?? output_limit,
    eventLimit: scan?.eventLimit ?? scan?.event_limit ?? eventLimit ?? event_limit,
    maxEncodedBytes: scan?.maxEncodedBytes ?? scan?.max_encoded_bytes ?? maxEncodedBytes ?? max_encoded_bytes,
    validationStateSnapshot: scan?.validationStateSnapshot ?? scan?.validation_state_snapshot ?? validationStateSnapshot ?? validation_state_snapshot,
    scanSource: "privacy_scan",
    // High-level wallet and spend selection must never turn an unavailable or
    // malformed typed endpoint into a cursor-bearing legacy scan.
    strictPrivacyScan: true
  };
}

function indexedTxToRestish(tx) {
  if (!tx) return null;
  return {
    height: String(tx.height),
    txhash: tx.hash,
    code: tx.code,
    raw_log: tx.rawLog,
    events: tx.events || [],
    tx: tx.tx
  };
}

function publicPrivacyAccount(material) {
  return {
    address: material.address,
    pubKeyHex: material.pubKeyHex,
    signing_message: material.signingMessage,
    shielded_address: material.shieldedAddress,
    disclosure_pubkey_hex: material.disclosurePubKeyHex,
    root_signature_hash: material.rootSignatureHash
  };
}

function broadcastReservationContext(options = {}) {
  const reservationManager = options.reservationManager ?? options.reservation_manager ?? null;
  const reservation = options.reservation ?? options.reservationBatch ?? options.reservation_batch ?? null;
  const reservationIDs = [...(reservation?.reservation_ids || [])].filter(Boolean).map(String);
  if (!reservationManager && !reservation) return null;
  if (!reservationIDs.length) {
    throw new Error("reserved-note broadcast requires reservation ids");
  }
  if (!reservationManager || typeof reservationManager.markBroadcastAttempting !== "function") {
    throw new Error("reservationManager.markBroadcastAttempting is required for reserved-note broadcast");
  }
  const leaseToken = String(
    reservation?.lease_token || reservation?.reservations?.[0]?.lease_token || ""
  );
  if (!leaseToken) {
    throw new Error("reserved-note broadcast requires the current lease token");
  }
  return { reservationManager, reservationIDs, leaseToken };
}

function signedWithdrawMessage(signedTx) {
  const body = TxBody.decode(fromBase64(signedTx?.bodyBytes, "bodyBytes"));
  const withdrawals = body.messages.filter(message => message.typeUrl === msgWithdrawTypeUrl);
  if (!withdrawals.length) return null;
  if (body.messages.length !== 1 || withdrawals.length !== 1) {
    throw new Error("withdraw broadcast must contain exactly one MsgWithdraw");
  }
  return GeneratedMsgWithdraw.decode(withdrawals[0].value);
}

function signedTransferMessage(signedTx) {
  const body = TxBody.decode(fromBase64(signedTx?.bodyBytes, "bodyBytes"));
  const transfers = body.messages.filter(message => message.typeUrl === msgTransferTypeUrl);
  if (!transfers.length) return null;
  if (body.messages.length !== 1 || transfers.length !== 1) {
    throw new Error("transfer broadcast must contain exactly one MsgTransfer");
  }
  return GeneratedMsgTransfer.decode(transfers[0].value);
}

function signedBatchTransferMessage(signedTx) {
  const body = TxBody.decode(fromBase64(signedTx?.bodyBytes, "bodyBytes"));
  const transfers = body.messages.filter(message => message.typeUrl === msgBatchTransferTypeUrl);
  if (!transfers.length) return null;
  if (body.messages.length !== 1 || transfers.length !== 1) {
    throw new Error("batch transfer broadcast must contain exactly one MsgBatchTransfer");
  }
  const message = GeneratedMsgBatchTransfer.decode(transfers[0].value);
  if (!String(message.creator || "").trim()) {
    throw new Error("signed MsgBatchTransfer creator is required");
  }
  if (message.proof.length !== batchTransferProofSize) {
    throw new Error(`signed MsgBatchTransfer proof must be exactly ${batchTransferProofSize} bytes`);
  }
  if (GeneratedMsgBatchTransfer.encode(message).finish().length > maxBatchTransferMessageBytesV1) {
    throw new Error(`signed MsgBatchTransfer exceeds the ${maxBatchTransferMessageBytesV1}-byte hard cap`);
  }
  const effects = validateBatchTransferEffectsV1(message);
  return { message, effects };
}

function aliasedBroadcastChainTimeProvider(options = {}) {
  const camel = options.getChainNowUnix;
  const snake = options.get_chain_now_unix;
  if (camel != null && snake != null && camel !== snake) {
    throw new Error("getChainNowUnix aliases conflict");
  }
  const provider = camel ?? snake;
  if (provider != null && typeof provider !== "function") {
    throw new Error("getChainNowUnix must be a function");
  }
  return provider;
}

async function authoritativeBroadcastChainNowUnix(options = {}, label = "signed privacy transaction") {
  if (options?.chainNowUnix != null || options?.chain_now_unix != null) {
    throw new Error(`${label} broadcast does not accept chainNowUnix; use getChainNowUnix for a fresh authoritative expiry check`);
  }
  const chainTimeProvider = aliasedBroadcastChainTimeProvider(options);
  if (!chainTimeProvider) {
    throw new Error(`${label} broadcast requires getChainNowUnix for a fresh authoritative expiry check`);
  }
  let value;
  try {
    value = await chainTimeProvider();
  } catch (error) {
    throw new Error(`${label} authoritative chain time query failed`, { cause: error });
  }
  const chainNowUnix = value;
  if (!Number.isSafeInteger(chainNowUnix) || chainNowUnix < 0) {
    throw new Error(`${label} authoritative chain time must be a non-negative safe integer`);
  }
  return chainNowUnix;
}

function signedDirectPrivacyInputNullifiers(signedTx) {
  const body = TxBody.decode(fromBase64(signedTx?.bodyBytes, "bodyBytes"));
  const transfers = body.messages.filter(message => message.typeUrl === msgTransferTypeUrl);
  const withdrawals = body.messages.filter(message => message.typeUrl === msgWithdrawTypeUrl);
  if (!transfers.length && !withdrawals.length) return null;
  if (body.messages.length !== 1 || transfers.length + withdrawals.length !== 1) {
    throw new Error("reserved direct privacy broadcast must contain exactly one MsgTransfer or MsgWithdraw");
  }
  const nullifiers = transfers.length
    ? GeneratedMsgTransfer.decode(transfers[0].value).nullifiers
    : [GeneratedMsgWithdraw.decode(withdrawals[0].value).nullifier];
  return nullifiers.map((nullifier, index) => {
    if (!(nullifier instanceof Uint8Array) || nullifier.length !== 32) {
      throw new Error(`reserved direct privacy input nullifier at index ${index} must be exactly 32 bytes`);
    }
    return hexFromBytes(nullifier);
  });
}

function normalizedTxRawBytes(value) {
  if (!(value instanceof Uint8Array)) {
    throw new Error("signed TxRaw bytes must be a Uint8Array");
  }
  if (!value.length) {
    throw new Error("signed TxRaw bytes must not be empty");
  }
  const txBytes = Uint8Array.from(value);
  try {
    TxRaw.decode(txBytes);
  } catch (error) {
    throw new Error(`signed TxRaw bytes are invalid: ${error.message}`);
  }
  return txBytes;
}

function signedTxFromRawBytes(txBytes) {
  const txRaw = TxRaw.decode(txBytes);
  return {
    bodyBytes: toBase64(txRaw.bodyBytes),
    authInfoBytes: toBase64(txRaw.authInfoBytes),
    // Relay/reservation validation only binds TxBody and AuthInfo. Keep this
    // field for the familiar SignedTxBase64 shape without rewriting TxRaw.
    signature: toBase64(txRaw.signatures[0] || new Uint8Array())
  };
}

export function cosmosSignDocBindingHash({ bodyBytes, authInfoBytes } = {}) {
  const txRaw = TxRaw.fromPartial({
    bodyBytes: fromBase64(bodyBytes, "bodyBytes"),
    authInfoBytes: fromBase64(authInfoBytes, "authInfoBytes"),
    signatures: []
  });
  return sha256Hex(TxRaw.encode(txRaw).finish());
}

async function authoritativeReservationRecords(context) {
  if (!context) return [];
  if (typeof context.reservationManager.getReservation !== "function") {
    throw new Error("reservationManager.getReservation is required for reserved-note broadcast validation");
  }
  return Promise.all(context.reservationIDs.map(id => context.reservationManager.getReservation(id)));
}

function batchTransferNullifierHexesFromReservationRecords(records) {
  const values = records.map(record => record?.metadata?.batch_transfer_nullifier_hexes);
  if (!values.some(value => value != null)) return [];
  if (values.some(value => !Array.isArray(value))) {
    throw new Error("batch transfer reservation is missing its persisted input nullifiers");
  }
  const normalized = values.map(value => value.map((nullifier, index) => {
    const hex = String(nullifier ?? "").trim().replace(/^0x/i, "").toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hex)) {
      throw new Error(`batch transfer reservation nullifier at index ${index} is invalid`);
    }
    return hex;
  }));
  if (!normalized[0]?.length || normalized.some(value =>
    value.length !== normalized[0].length || value.some((nullifier, index) => nullifier !== normalized[0][index])
  )) {
    throw new Error("batch transfer reservations disagree on their persisted input nullifiers");
  }
  return normalized[0];
}

async function recheckReservedBatchTransferNullifiers(context, signedTx, checkNullifiers) {
  const signed = signedBatchTransferMessage(signedTx);
  if (!signed) return null;
  if (!context) {
    throw new Error("signed MsgBatchTransfer broadcast requires reservationManager and reservation");
  }
  if (typeof context.reservationManager.lookupKeyForNote !== "function") {
    throw new Error("reservationManager.lookupKeyForNote is required for batch transfer broadcast validation");
  }
  const records = await authoritativeReservationRecords(context);
  const persistedNullifiers = batchTransferNullifierHexesFromReservationRecords(records);
  const signedNullifiers = signed.effects.nullifiers.map(hexFromBytes);
  if (persistedNullifiers.length && (
    signedNullifiers.length !== persistedNullifiers.length ||
    signedNullifiers.some((nullifier, index) => nullifier !== persistedNullifiers[index])
  )) {
    throw new Error("batch transfer reservations do not match the signed transaction nullifiers");
  }
  const persistedLookupKeys = records.map(record => String(record?.nullifier_lookup_key || ""));
  const signedLookupKeys = (await Promise.all(signedNullifiers.map(nullifier =>
    context.reservationManager.lookupKeyForNote({ nullifier })
  ))).map(value => String(value || ""));
  if (
    records.length !== signedNullifiers.length ||
    persistedLookupKeys.some(value => !value) ||
    signedLookupKeys.some(value => !value) ||
    new Set(persistedLookupKeys).size !== persistedLookupKeys.length ||
    new Set(signedLookupKeys).size !== signedLookupKeys.length ||
    signedLookupKeys.some((value, index) => value !== persistedLookupKeys[index])
  ) {
    throw new Error("batch transfer reservations do not match the signed transaction inputs");
  }
  batchTransferNullifiersUnspent(await checkNullifiers(signedNullifiers), signedNullifiers);
  return signed;
}

async function recheckReservedDirectPrivacyNullifiers(context, signedTx, checkNullifiers) {
  const candidates = signedDirectPrivacyInputNullifiers(signedTx);
  if (candidates == null) return;
  if (context) {
    if (typeof context.reservationManager.lookupKeyForNote !== "function") {
      throw new Error("reservationManager.lookupKeyForNote is required for reserved direct privacy broadcast validation");
    }
    const records = await authoritativeReservationRecords(context);
    const persistedLookupKeys = records.map(record => String(record?.nullifier_lookup_key || ""));
    if (!persistedLookupKeys.length || persistedLookupKeys.some(key => !key) ||
        new Set(persistedLookupKeys).size !== persistedLookupKeys.length) {
      throw new Error("reserved direct privacy inputs have invalid persisted nullifier lookup keys");
    }
    const candidateLookupKeys = (await Promise.all(candidates.map(nullifier =>
      context.reservationManager.lookupKeyForNote({ nullifier })
    ))).map(key => String(key || ""));
    const persistedLookupKeySet = new Set(persistedLookupKeys);
    if (candidates.length !== persistedLookupKeys.length ||
        candidateLookupKeys.some(key => !key || !persistedLookupKeySet.has(key)) ||
        new Set(candidateLookupKeys).size !== candidateLookupKeys.length ||
        new Set(candidates).size !== candidates.length) {
      throw new Error("reserved direct privacy inputs do not match the signed transaction nullifiers");
    }
  }
  const statuses = await checkNullifiers(candidates);
  const statusFor = nullifier => statuses instanceof Map
    ? statuses.get(nullifier) ?? statuses.get(`0x${nullifier}`)
    : statuses?.[nullifier] ?? statuses?.[`0x${nullifier}`];
  for (const [index, nullifier] of candidates.entries()) {
    if (statusFor(nullifier) !== false) {
      throw new Error(`reserved direct privacy input nullifier at index ${index} is spent, missing, or has an invalid status`);
    }
  }
}

function assertReservationPayloadMatches(records, payload) {
  if (!records.length) return;
  const payloadHash = String(payload?.payload_hash || "").trim();
  const storedHashes = records.map(record => String(record?.payload_hash ?? record?.payloadHash ?? "").trim());
  if (!payloadHash || storedHashes.some(hash => !hash || hash !== payloadHash)) {
    throw new Error("relay payload does not match the reserved payload hash");
  }
}

function assertReservationSignDocMatches(records, signDocHash, { allowPayloadBinding = false } = {}) {
  if (!records.length) return;
  const mismatched = records.some(record => {
    const storedHash = String(record?.sign_doc_hash ?? record?.signDocHash ?? "").trim();
    if (storedHash) return storedHash !== signDocHash;
    return !(allowPayloadBinding && String(record?.payload_hash ?? record?.payloadHash ?? "").trim());
  });
  if (!signDocHash || mismatched) {
    throw new Error("Cosmos sign doc does not match the reservation ProofReady artifact");
  }
}

function assertSignedWithdrawMatchesPayload(message, payload) {
  const normalizedPayloadHex = value => String(value || "").trim().replace(/^0x/i, "").toLowerCase();
  const matches =
    hexFromBytes(message.proof) === normalizedPayloadHex(payload.proof_hex) &&
    hexFromBytes(message.root) === normalizedPayloadHex(payload.root_hex) &&
    hexFromBytes(message.nullifier) === normalizedPayloadHex(payload.nullifier_hex) &&
    String(message.amount) === String(payload.amount) &&
    String(message.recipient) === String(payload.recipient) &&
    String(message.chainId) === String(payload.chain_id) &&
    BigInt(message.expiresAtUnix) === BigInt(payload.expires_at_unix);
  if (!matches) {
    throw new Error("relay payload does not match the Cosmos signed transaction being broadcast");
  }
}

async function validateRelayBroadcastContext(options, {
  expectedChainId,
  accountPrefix,
  signedTx,
  reservationContext,
  signDocHash
} = {}) {
  const payload = options?.relayPayload ?? options?.relay_payload ?? null;
  const reservationRecords = await getBroadcastReservationRecords(reservationContext);
  assertReservationSignDocMatches(reservationRecords, signDocHash, { allowPayloadBinding: Boolean(payload) });
  const withdrawMessage = signedWithdrawMessage(signedTx);
  if (options?.chainNowUnix != null || options?.chain_now_unix != null) {
    throw new Error("Cosmos broadcast does not accept chainNowUnix; use getChainNowUnix at the final submission boundary");
  }
  if (!payload) {
    if (withdrawMessage) {
      throw new Error("withdraw broadcast requires relayPayload and authoritative chain time");
    }
    return;
  }
  assertReservationPayloadMatches(reservationRecords, payload);
  if (!withdrawMessage) {
    throw new Error("relayPayload does not match a Cosmos MsgWithdraw transaction");
  }
  if (!aliasedBroadcastChainTimeProvider(options)) {
    throw new Error("signed MsgWithdraw broadcast requires getChainNowUnix for a fresh authoritative expiry check");
  }
  assertSignedWithdrawMatchesPayload(withdrawMessage, payload);
}

async function assertSignedPrivacyFreshAtBroadcast(signedTx, options = {}, {
  expectedChainId,
  accountPrefix
} = {}) {
  const transferMessage = signedTransferMessage(signedTx);
  const withdrawMessage = signedWithdrawMessage(signedTx);
  const batchTransfer = signedBatchTransferMessage(signedTx);
  if (!transferMessage && !withdrawMessage && !batchTransfer) return;
  const label = withdrawMessage
    ? "signed MsgWithdraw"
    : batchTransfer
      ? "signed MsgBatchTransfer"
      : "signed MsgTransfer";
  const chainNowUnix = await authoritativeBroadcastChainNowUnix(options, label);
  if (withdrawMessage) {
    const payload = options?.relayPayload ?? options?.relay_payload ?? null;
    validateRelayWithdrawPayload(payload, {
      chainNowUnix,
      expectedChainId: options.expectedChainId ?? options.expected_chain_id ?? expectedChainId,
      expectedRecipient: options.expectedRecipient ?? options.expected_recipient,
      accountPrefix: options.accountPrefix ?? options.account_prefix ?? accountPrefix
    });
    assertSignedWithdrawMatchesPayload(withdrawMessage, payload);
    return;
  }
  const expiresAtUnix = transferMessage
    ? BigInt(transferMessage.expiresAtUnix)
    : batchTransfer.effects.expiresAtUnix;
  if (BigInt(chainNowUnix) >= expiresAtUnix) {
    throw new Error(`${label} expired at the final broadcast fence`);
  }
}

function attachReservationBookkeepingError(error, bookkeepingError) {
  const original = error && typeof error === "object"
    ? error
    : new Error(String(error || "broadcast failed"));
  try {
    original.reservationBookkeepingError = bookkeepingError;
    original.reservationReconciliationRequired = true;
    return original;
  } catch {
    const wrapped = new Error(
      String(original?.message || error || "broadcast failed"),
      { cause: original }
    );
    if (typeof original?.name === "string" && original.name) {
      wrapped.name = original.name;
    }
    wrapped.reservationBookkeepingError = bookkeepingError;
    wrapped.reservationReconciliationRequired = true;
    return wrapped;
  }
}

async function beginBroadcastReservation(context, reason, evidence = {}) {
  if (!context) return;
  await context.reservationManager.markBroadcastAttempting(context.reservationIDs, {
    leaseToken: context.leaseToken,
    reason,
    txHash: evidence.txHash || "",
    txBytesHash: evidence.txBytesHash || "",
    signDocHash: evidence.signDocHash || ""
  });
}

async function markBroadcastReservationUnknown(context, error, evidence = {}) {
  if (!context) return;
  try {
    await context.reservationManager.markUnknown(context.reservationIDs, {
      leaseToken: context.leaseToken,
      txHash: evidence.txHash || "",
      txBytesHash: evidence.txBytesHash || "",
      signDocHash: evidence.signDocHash || "",
      error: "sdk_broadcast_result_unknown",
      metadata: { reconcile_reason: "sdk_broadcast_result_unknown" }
    });
  } catch (bookkeepingError) {
    throw attachReservationBookkeepingError(error, bookkeepingError);
  }
}

async function markBroadcastReservationSubmitted(context, evidence = {}) {
  if (!context) return;
  try {
    await context.reservationManager.markSubmitted(context.reservationIDs, {
      leaseToken: context.leaseToken,
      txHash: evidence.txHash || "",
      txBytesHash: evidence.txBytesHash || "",
      signDocHash: evidence.signDocHash || ""
    });
  } catch (bookkeepingError) {
    const error = new Error("transaction was broadcast but reservation submission could not be recorded");
    error.txHash = evidence.txHash || "";
    error.txBytesHash = evidence.txBytesHash || "";
    throw attachReservationBookkeepingError(error, bookkeepingError);
  }
}

async function markBroadcastReservationRejected(context, error, {
  kind,
  providerCode = "",
  providerCodespace = "",
  providerLog = ""
} = {}) {
  if (!context) return;
  try {
    if (typeof context.reservationManager.markBroadcastRejected !== "function") {
      throw new Error("reservationManager.markBroadcastRejected is required for definitive broadcast rejection");
    }
    const beforeRpc = kind === "before_rpc";
    const checkTx = kind === "check_tx";
    await context.reservationManager.markBroadcastRejected(context.reservationIDs, {
      leaseToken: context.leaseToken,
      error: beforeRpc ? "broadcast_aborted_before_rpc" : "check_tx_rejected",
      providerCode,
      providerCodespace,
      providerLog,
      rpcInvoked: checkTx,
      checkTxRejected: checkTx,
      broadcastAbortedBeforeRpc: beforeRpc,
      walletRejectedBeforeBroadcast: false,
      metadata: {
        reconcile_reason: beforeRpc ? "broadcast_aborted_before_rpc" : "check_tx_rejected"
      }
    });
  } catch (bookkeepingError) {
    throw attachReservationBookkeepingError(error, bookkeepingError);
  }
}

function isExplicitWalletRejection(error) {
  return String(error?.code ?? error?.data?.code ?? "") === "4001";
}

async function markSigningReservationRejected(context, error) {
  if (!context) return;
  try {
    if (typeof context.reservationManager.markBroadcastRejected !== "function") {
      throw new Error("reservationManager.markBroadcastRejected is required for pre-broadcast wallet rejection");
    }
    await context.reservationManager.markBroadcastRejected(context.reservationIDs, {
      leaseToken: context.leaseToken,
      error: "wallet_rejected_before_broadcast",
      providerCode: "4001",
      rpcInvoked: false,
      walletRejectedBeforeBroadcast: true,
      metadata: {
        wallet_rejected_before_broadcast: true,
        provider_rejection_code: "4001",
        reconcile_reason: "wallet_rejected_before_broadcast"
      }
    });
  } catch (bookkeepingError) {
    throw attachReservationBookkeepingError(error, bookkeepingError);
  }
}

function resolveDisclosureAssetDenom(assetDenom, asset_denom, defaultDenom) {
  return resolveOperationEvidenceAlias(assetDenom, asset_denom, "assetDenom") || defaultDenom;
}

function resolveDisclosureOutputAlias(output, scanOutput, label) {
  if (output != null && scanOutput != null && output !== scanOutput) {
    throw new Error(`${label} aliases conflict`);
  }
  return output ?? scanOutput;
}

function resolveOperationEvidenceArrayAlias(camelValue, snakeValue, name) {
  const camelProvided = camelValue !== undefined && camelValue !== null;
  const snakeProvided = snakeValue !== undefined && snakeValue !== null;
  if (camelProvided && !Array.isArray(camelValue)) {
    throw new Error(`${name} must be an array`);
  }
  if (snakeProvided && !Array.isArray(snakeValue)) {
    throw new Error(`${name} must be an array`);
  }
  if (camelProvided && snakeProvided) {
    const camelItems = camelValue.map(String);
    const snakeItems = snakeValue.map(String);
    if (camelItems.length !== snakeItems.length ||
        camelItems.some((value, index) => value !== snakeItems[index])) {
      throw new Error(`${name} aliases conflict`);
    }
  }
  return camelProvided ? camelValue : snakeProvided ? snakeValue : [];
}

function resolveBatchOperationEvidence({
  amounts = [],
  expectedRecipientHash,
  expected_recipient_hash,
  expectedRecipientHashes,
  expected_recipient_hashes,
  expectedAmountHashes,
  expected_amount_hashes
} = {}) {
  const recipientHashScalarProvided = operationEvidenceAliasProvided(
    expectedRecipientHash,
    expected_recipient_hash
  );
  const recipientHashArrayProvided = operationEvidenceAliasProvided(
    expectedRecipientHashes,
    expected_recipient_hashes
  );
  const amountHashArrayProvided = operationEvidenceAliasProvided(
    expectedAmountHashes,
    expected_amount_hashes
  );
  const recipientHashScalar = resolveOperationEvidenceAlias(
    expectedRecipientHash,
    expected_recipient_hash,
    "expectedRecipientHash"
  );
  const recipientHashArray = resolveOperationEvidenceArrayAlias(
    expectedRecipientHashes,
    expected_recipient_hashes,
    "expectedRecipientHashes"
  );
  const amountHashArray = resolveOperationEvidenceArrayAlias(
    expectedAmountHashes,
    expected_amount_hashes,
    "expectedAmountHashes"
  );
  const evidenceProvided = recipientHashScalarProvided ||
    recipientHashArrayProvided || amountHashArrayProvided;
  if (!evidenceProvided) {
    return {
      enabled: false,
      recipientHashes: [],
      amountHashes: []
    };
  }
  if (recipientHashArrayProvided && recipientHashArray.length !== amounts.length) {
    throw new Error("expectedRecipientHashes length must match batch amounts length");
  }
  if (amountHashArray.length !== amounts.length) {
    throw new Error("expectedAmountHashes length must match batch amounts length when batch operation evidence is provided");
  }
  const recipientHashes = amounts.map((_, index) =>
    String(recipientHashArray[index] || recipientHashScalar || "").trim()
  );
  const amountHashes = amounts.map((_, index) => String(amountHashArray[index] || "").trim());
  const missingRecipientIndex = recipientHashes.findIndex(value => !value);
  if (missingRecipientIndex >= 0) {
    throw new Error(`expected recipient hash is required for batch item ${missingRecipientIndex}`);
  }
  const missingAmountIndex = amountHashes.findIndex(value => !value);
  if (missingAmountIndex >= 0) {
    throw new Error(`expected amount hash is required for batch item ${missingAmountIndex}`);
  }
  return {
    enabled: true,
    recipientHashes,
    amountHashes
  };
}

function withdrawProofReadyMetadata(built, context = {}) {
  const payload = built?.payload || built?.proverPayload || {};
  const expiresAtUnix = String(
    payload.expires_at_unix ||
    payload.expiresAtUnix ||
    ""
  );
  const bindOperationSuccess = context.bindOperationSuccess === true ||
    context.bind_operation_success === true;
  const coin = bindOperationSuccess && payload.amount
    ? parseCoin(payload.amount, payload.asset_denom || payload.assetDenom || context.denom || "")
    : null;
  const amount = coin?.amount || "";
  const denom = coin?.denom || "";
  const recipient = bindOperationSuccess ? String(payload.recipient || "") : "";
  if (bindOperationSuccess && (!amount || !denom || !recipient)) {
    throw new Error("withdraw success binding requires recipient, amount, and denom");
  }
  return {
    payloadHash: payload.payload_hash || "",
    signDocHash: context.signDocHash ?? context.sign_doc_hash ?? "",
    txBytesHash: context.txBytesHash ?? context.tx_bytes_hash ?? "",
    ...(executionTransport ? { executionTransport } : {}),
    expectedOutputCommitment: "",
    expectedDisclosureDigest: "",
    expectedRecipientHash: bindOperationSuccess
      ? hashTransparentRecipient(recipient, { accountPrefix: context.accountPrefix })
      : "",
    expectedAmount: amount,
    expectedAmountHash: bindOperationSuccess ? hashAmount(denom, amount) : "",
    expectedDenom: denom,
    operationSuccessEvidenceRequired: bindOperationSuccess,
    metadata: expiresAtUnix ? { payload_expires_at_unix: expiresAtUnix } : {}
  };
}

async function authoritativeBatchRecoveryReservation(
  reservationManager,
  batch,
  { operationId, nullifierHexes } = {}
) {
  if (typeof reservationManager?.getReservations !== "function" ||
      typeof reservationManager?.lookupKeyForNote !== "function") {
    throw new Error("finalizePreparedBatchTransfer requires authoritative reservation-set lookup support");
  }
  const reservationIDs = [...(batch?.reservation_ids || [])].map(value => String(value || "").trim());
  if (!reservationIDs.length || reservationIDs.some(id => !id) ||
      new Set(reservationIDs).size !== reservationIDs.length) {
    throw new Error("prepared batch transfer recovery requires unique reservation IDs");
  }
  const normalizedNullifiers = [...(nullifierHexes || [])].map(value => String(value || "").trim().toLowerCase());
  if (reservationIDs.length !== normalizedNullifiers.length ||
      new Set(normalizedNullifiers).size !== normalizedNullifiers.length) {
    throw new Error("prepared batch transfer reservation set does not match its input nullifiers");
  }
  const leaseToken = String(batch?.lease_token || batch?.leaseToken || "").trim();
  const leaseOwner = String(
    batch?.lease_owner || batch?.leaseOwner || batch?.reservations?.[0]?.lease_owner || ""
  ).trim();
  if (!leaseToken || !leaseOwner) {
    throw new Error("prepared batch transfer recovery requires the original lease owner and token");
  }
  if (String(reservationManager.leaseOwner || "") !== leaseOwner) {
    throw new Error("prepared batch transfer reservation lease owner does not match the recovery manager");
  }
  const loaded = await reservationManager.getReservations(reservationIDs);
  if (!Array.isArray(loaded)) {
    throw new Error("prepared batch transfer recovery did not load the exact reservation set");
  }
  const byID = new Map(loaded.map(record => [String(record?.reservation_id || ""), record]));
  if (loaded.length !== reservationIDs.length || byID.size !== reservationIDs.length ||
      reservationIDs.some(id => !byID.has(id))) {
    throw new Error("prepared batch transfer recovery did not load the exact reservation set");
  }
  const reservations = reservationIDs.map(id => byID.get(id));
  const normalizedOperationID = String(operationId || "").trim();
  if (reservations.some(record =>
    String(record.operation_id || "") !== normalizedOperationID ||
    String(record.kind || "") !== "batch_transfer"
  )) {
    throw new Error("prepared batch transfer reservations do not belong to the recovered operation");
  }
  if (reservations.some(record =>
    String(record.status || "") !== reservationStatuses.Proving ||
    String(record.lease_owner || "") !== leaseOwner ||
    String(record.lease_token || "") !== leaseToken
  )) {
    throw new Error("prepared batch transfer reservations do not have the recovered Proving lease");
  }
  const expectedLookupKeys = await Promise.all(normalizedNullifiers.map(nullifier =>
    reservationManager.lookupKeyForNote({ nullifier })
  ));
  const actualLookupKeys = reservations.map(record => String(record.nullifier_lookup_key || ""));
  if (new Set(expectedLookupKeys).size !== expectedLookupKeys.length ||
      new Set(actualLookupKeys).size !== actualLookupKeys.length ||
      expectedLookupKeys.some(key => !actualLookupKeys.includes(key))) {
    throw new Error("prepared batch transfer reservation inputs do not match the payload nullifiers");
  }
  return {
    ...batch,
    operation_id: normalizedOperationID,
    lease_owner: leaseOwner,
    lease_token: leaseToken,
    reservation_ids: reservationIDs,
    reservations
  };
}

async function reservationIDsForNotes(reservationManager, batch, notes) {
  if (!reservationManager || !batch?.reservation_ids?.length) return [];
  if (typeof reservationManager.lookupKeyForNote !== "function") {
    throw new Error("reservationManager.lookupKeyForNote is required");
  }
  const lookupKeys = new Set();
  for (const note of notes || []) {
    lookupKeys.add(await reservationManager.lookupKeyForNote(note));
  }
  const reservationIDs = (batch.reservations || [])
    .filter(reservation => lookupKeys.has(reservation.nullifier_lookup_key))
    .map(reservation => reservation.reservation_id);
  return reservationIDs;
}

function mergeBatchReservations(batch, updated) {
  const updatedByID = new Map(updated.map(reservation => [reservation.reservation_id, reservation]));
  batch.reservations = (batch.reservations || []).map(reservation =>
    updatedByID.get(reservation.reservation_id) || reservation
  );
  batch.lease_until = updated[0]?.lease_until || batch.lease_until;
}

async function markReservationProofReadyForNotes(reservationManager, batch, notes, metadata) {
  const reservationIDs = await reservationIDsForNotes(reservationManager, batch, notes);
  if (!reservationIDs.length) return [];
  const updated = await reservationManager.markProofReady(reservationIDs, {
    ...metadata,
    leaseToken: batch.lease_token || batch.reservations?.[0]?.lease_token || ""
  });
  mergeBatchReservations(batch, updated);
  return updated;
}

async function markReservationProofReadyForBatchItems(reservationManager, batch, items) {
  if (!reservationManager || !batch?.reservation_ids?.length) return [];
  if (typeof reservationManager.markProofReadyBatch !== "function") {
    throw new Error("reservationManager.markProofReadyBatch is required for atomic batch transfer preparation");
  }
  const entries = [];
  for (const item of items || []) {
    const reservationIDs = await reservationIDsForNotes(reservationManager, batch, item?.notes);
    if (!reservationIDs.length) continue;
    entries.push({
      reservationIDs,
      metadata: {
        ...(item?.metadata || {}),
        leaseToken: batch.lease_token || batch.reservations?.[0]?.lease_token || ""
      }
    });
  }
  if (!entries.length) return [];
  const updated = await reservationManager.markProofReadyBatch(entries);
  mergeBatchReservations(batch, updated);
  return updated;
}

async function replanProofReadyReservations(reservationManager, batch, error, reason) {
  if (!reservationManager || !batch?.reservation_ids?.length) return [];
  if (typeof reservationManager.getReservation !== "function" || typeof reservationManager.markReplanRequired !== "function") {
    return [];
  }
  const proofReadyIDs = [];
  for (const reservationID of batch.reservation_ids || []) {
    try {
      const reservation = await reservationManager.getReservation(reservationID);
      if (reservation.status === reservationStatuses.ProofReady) {
        proofReadyIDs.push(reservationID);
      }
    } catch (_) {
      // Best-effort cleanup should not hide the original prepare failure.
    }
  }
  if (!proofReadyIDs.length) return [];
  return reservationManager.markReplanRequired(proofReadyIDs, {
    leaseToken: batch.lease_token || batch.reservations?.[0]?.lease_token || "",
    error: reason,
    metadata: {
      reconcile_reason: reason,
      no_broadcast_attempt: true,
      proof_discarded: true
    }
  });
}

export class ClairveilJS {
  constructor({
    rpc,
    rest,
    restEndpoints,
    chainId,
    accountPrefix,
    bech32Prefix,
    shieldedPrefix,
    defaultDenom = defaultAssetDenom,
    assetDenom,
    registry = createClairveilRegistry(),
    queryTimeoutMs = defaultFetchTimeoutMs,
    fetchTimeoutMs,
    queryRetry,
    nullifierFailover = false,
    merklePathFailover = false,
    privacyStateAdapter,
    expectedCircuitIdentity,
    enableExperimentalBatchTransfer = false,
    enable_experimental_batch_transfer
  } = {}) {
    this.privacyStateAdapter = privacyStateAdapter == null
      ? null
      : createPrivacyStateAdapter(privacyStateAdapter);
    this.rpc = normalizeRpcEndpoint(rpc);
    if (!this.rpc && !this.privacyStateAdapter) {
      throw new Error("rpc endpoint is required unless privacyStateAdapter is configured");
    }
    this.restEndpoints = normalizeRestEndpoints(rest, restEndpoints, {
      allowEmpty: Boolean(this.privacyStateAdapter)
    });
    this.rest = this.restEndpoints[0] || "";
    this.activeRestEndpoint = this.rest;
    this.chainId = chainId;
    this.accountPrefix = normalizeBech32Prefix(accountPrefix ?? bech32Prefix ?? defaultAccountPrefix, "accountPrefix");
    this.bech32Prefix = this.accountPrefix;
    this.shieldedPrefix = normalizeBech32Prefix(shieldedPrefix ?? `${this.accountPrefix}s`, "shieldedPrefix");
    this.defaultDenom = String(assetDenom ?? defaultDenom ?? defaultAssetDenom);
    this.registry = registry;
    this.queryTimeoutMs = normalizeTimeoutMs(fetchTimeoutMs ?? queryTimeoutMs, "queryTimeoutMs");
    this.queryRetry = normalizeQueryRetry(queryRetry);
    this.nullifierFailover = Boolean(nullifierFailover);
    this.merklePathFailover = Boolean(merklePathFailover);
    this.enableExperimentalBatchTransfer = Boolean(
      enable_experimental_batch_transfer ?? enableExperimentalBatchTransfer
    );
    this.expectedCircuitIdentity = expectedCircuitIdentity == null
      ? null
      : validateExpectedCircuitIdentityV1(expectedCircuitIdentity);
    this.clientPromise = null;
  }

  async connect() {
    if (!this.rpc) {
      throw new Error("rpc endpoint is required for Cosmos transaction and balance queries");
    }
    if (!this.clientPromise) {
      this.clientPromise = StargateClient.connect(this.rpc);
    }
    return this.clientPromise;
  }

  async disconnect() {
    if (!this.clientPromise) return;
    const client = await this.clientPromise;
    client.disconnect();
    this.clientPromise = null;
  }

  restUrl(path, endpoint = this.activeRestEndpoint) {
    if (!endpoint) {
      throw new Error("rest endpoint is required for this query; implement the corresponding PrivacyStateAdapter method");
    }
    return `${endpoint}${path}`;
  }

  async queryPrivacyStateAdapter(method, args, restQuery) {
    const adapterMethod = this.privacyStateAdapter?.[method];
    if (typeof adapterMethod === "function") {
      return invokePrivacyStateAdapter(this.privacyStateAdapter, method, args, {
        timeoutMs: this.queryTimeoutMs,
        retry: this.queryRetry
      });
    }
    if (!this.restEndpoints.length) {
      throw new Error(`PrivacyStateAdapter.${method} is required because no REST endpoint is configured`);
    }
    return restQuery();
  }

  async fetchJson(pathOrUrl, {
    failover = false,
    retry = this.queryRetry,
    method,
    body,
    headers,
    endpoint,
    updateActiveEndpoint = endpoint == null,
    failoverStatuses
  } = {}) {
    const text = String(pathOrUrl || "");
    const isAbsolute = /^https?:\/\//i.test(text);
    if (isAbsolute) {
      const result = await fetchJsonWithRetry(
        url => url,
        [text],
        {
          timeoutMs: this.queryTimeoutMs,
          retry,
          method,
          body,
          headers,
          failoverStatuses
        }
      );
      return result.data;
    }
    const path = text;
    const initialEndpoint = endpoint || this.activeRestEndpoint;
    if (!initialEndpoint) {
      throw new Error("rest endpoint is required for this query");
    }
    const endpoints = failover
      ? [initialEndpoint, ...this.restEndpoints.filter(candidate => candidate !== initialEndpoint)]
      : [initialEndpoint];
    const result = await fetchJsonWithRetry(
      endpoint => this.restUrl(path, endpoint),
      endpoints,
      {
        timeoutMs: this.queryTimeoutMs,
        retry,
        method,
        body,
        headers,
        failoverStatuses
      }
    );
    if (updateActiveEndpoint) this.activeRestEndpoint = result.endpoint;
    return result.data;
  }

  async fetchNullifierJson(path, options = {}) {
    return this.fetchJson(path, {
      ...options,
      failover: this.nullifierFailover,
      // Normal queries may fail over. Sensitive nullifier queries stay on the
      // configured endpoint unless the caller explicitly opted into failover.
      ...(this.nullifierFailover ? {} : {
        endpoint: this.rest,
        updateActiveEndpoint: false
      })
    });
  }

  async fetchMerklePathJson(path, options = {}) {
    return this.fetchJson(path, {
      ...options,
      failover: this.merklePathFailover,
      // Merkle witnesses reveal the commitments a wallet is attempting to
      // spend. Keep those requests on the configured endpoint unless the
      // application explicitly accepts cross-endpoint disclosure.
      ...(this.merklePathFailover ? {} : {
        endpoint: this.rest,
        updateActiveEndpoint: false
      })
    });
  }

  async getAccountInfo(address) {
    const data = await this.fetchJson(`/cosmos/auth/v1beta1/accounts/${address}`, { failover: true });
    const info = unwrapBaseAccount(data.account ?? data.info);
    if (info?.account_number == null || info.sequence == null) {
      throw new Error("account not found on-chain; fund it first");
    }
    return {
      accountNumber: BigInt(info.account_number),
      sequence: BigInt(info.sequence)
    };
  }

  async getBalances(address) {
    const client = await this.connect();
    const balances = await client.getAllBalances(address);
    return {
      balances: balances.map(balance => ({ denom: balance.denom, amount: balance.amount })),
      pagination: null
    };
  }

  async getTx(txHash) {
    const client = await this.connect();
    return indexedTxToRestish(await client.getTx(txHash));
  }

  async waitForTx(txHash, { attempts = 20, intervalMs = 1500 } = {}) {
    for (let i = 0; i < attempts; i += 1) {
      const tx = await this.getTx(txHash);
      if (tx) return tx;
      await new Promise(resolve => setTimeout(resolve, intervalMs));
    }
    return null;
  }

  async fetchPrivacyEvents(options = {}) {
    return this.queryPrivacyStateAdapter(
      "fetchPrivacyEvents",
      [options],
      () => this.fetchJson(`/clairveil/privacy/v1/events${privacyEventsQuery(options)}`, { failover: true })
    );
  }

  async fetchScanEvents(options = {}) {
    const data = await this.queryPrivacyStateAdapter(
      "fetchScanEvents",
      [options],
      () => this.fetchJson(`/clairveil/privacy/v1/scan_events${scanEventsQuery(options)}`, { failover: true })
    );
    return validateScanEventsResponse(data, options);
  }

  async fetchPrivacyScan(options = {}) {
    return this.queryPrivacyStateAdapter(
      "fetchPrivacyScan",
      [options],
      () => this.fetchJson("/clairveil/privacy/v1/privacy_scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: jsonRequestBody(privacyScanRequestBody(options)),
        failover: true,
        failoverStatuses: [404, 405, 501]
      })
    );
  }

  /** Fetch a typed privacy-scan-v2 page and fail closed before it is consumed. */
  async queryPrivacyScan(options = {}) {
    const {
      validationState,
      validation_state,
      ...request
    } = options || {};
    return validatePrivacyScanPageV2(
      await this.fetchPrivacyScan(request),
      {
        ...request,
        ...(validationState ?? validation_state
          ? { validationState: validationState ?? validation_state }
          : {})
      }
    );
  }

  async fetchTreeState() {
    return this.queryPrivacyStateAdapter(
      "fetchTreeState",
      [],
      () => this.fetchJson("/clairveil/privacy/v1/tree_state", { failover: true })
    );
  }

  async fetchCommitmentInfo(commitmentHex) {
    return this.queryPrivacyStateAdapter(
      "fetchCommitmentInfo",
      [commitmentHex],
      () => this.fetchJson(`/clairveil/privacy/v1/commitment/${commitmentHex}`, { failover: true })
    );
  }

  async lookupMerklePath(commitmentHex) {
    return this.queryPrivacyStateAdapter(
      "lookupMerklePath",
      [commitmentHex],
      () => this.fetchMerklePathJson(`/clairveil/privacy/v1/merkle_path/${commitmentHex}`)
    );
  }

  async fetchAuditConfig() {
    return this.queryPrivacyStateAdapter(
      "fetchAuditConfig",
      [],
      () => this.fetchJson("/clairveil/privacy/v1/audit_config", { failover: true })
    );
  }

  async fetchDisclosureConfig() {
    return this.queryPrivacyStateAdapter(
      "fetchDisclosureConfig",
      [],
      () => this.fetchJson("/clairveil/privacy/v1/disclosure_config", { failover: true })
    );
  }

  /** Fetch and fail-closed validate the active audit recipient identity. */
  async queryAuditConfig() {
    return normalizeAuditConfigV1(await this.fetchAuditConfig());
  }

  /** Fetch and fail-closed validate disclosure policy/mode compatibility. */
  async queryDisclosureConfig() {
    return normalizeDisclosureConfigV1(await this.fetchDisclosureConfig());
  }

  async fetchCircuitConfig({ expectedCircuitIdentity } = {}) {
    return validateCircuitConfigV1(
      await this.queryPrivacyStateAdapter(
        "fetchCircuitConfig",
        [],
        () => this.fetchJson("/clairveil/privacy/v1/circuit_config", { failover: true })
      ),
      { expectedCircuitIdentity: expectedCircuitIdentity ?? this.expectedCircuitIdentity ?? undefined }
    );
  }

  /** Fetch and fail-closed validate the consensus identity used by every proof circuit. */
  async assertCircuitConfig(options) {
    return this.fetchCircuitConfig(options);
  }

  async fetchReserve(denom) {
    const normalizedDenom = String(denom || "").trim();
    if (!normalizedDenom) {
      throw new Error("reserve denom is required");
    }
    return this.queryPrivacyStateAdapter(
      "fetchReserve",
      [normalizedDenom],
      () => this.fetchJson(`/clairveil/privacy/v1/reserve/${encodeURIComponent(normalizedDenom)}`, { failover: true })
    );
  }

  /** Fetch and independently check reserve accounting before relying on it. */
  async queryReserve(denom) {
    const canonicalDenom = canonicalAssetDenomV1(denom);
    return normalizeReserveResponseV1(await this.fetchReserve(canonicalDenom), canonicalDenom);
  }

  async fetchAssetByDenom(denom) {
    const canonicalDenom = String(denom || "").trim();
    if (!canonicalDenom) throw new Error("asset denom is required");
    return this.queryPrivacyStateAdapter(
      "fetchAssetByDenom",
      [canonicalDenom],
      () => this.fetchJson(
        `/clairveil/privacy/v1/assets/by_denom/${encodeURIComponent(canonicalDenom)}`,
        { failover: true }
      )
    );
  }

  async fetchAssetByID(assetIdHex) {
    const canonicalAssetID = String(assetIdHex || "").trim();
    if (!canonicalAssetID) throw new Error("asset ID is required");
    return this.queryPrivacyStateAdapter(
      "fetchAssetByID",
      [canonicalAssetID],
      () => this.fetchJson(
        `/clairveil/privacy/v1/assets/by_id/${encodeURIComponent(canonicalAssetID)}`,
        { failover: true }
      )
    );
  }

  /** Fetch and fail-closed validate an AssetRegistryV1 denom lookup. */
  async queryAssetByDenom(denom) {
    const canonicalDenom = canonicalAssetDenomV1(denom);
    return normalizeAssetRegistryQueryResponseV1(
      await this.fetchAssetByDenom(canonicalDenom),
      { canonical_denom: canonicalDenom }
    );
  }

  /** Fetch and fail-closed validate an AssetRegistryV1 reverse lookup. */
  async queryAssetByID(assetIdHex) {
    const canonicalAssetID = canonicalAssetIDHexV1(assetIdHex);
    return normalizeAssetRegistryQueryResponseV1(
      await this.fetchAssetByID(canonicalAssetID),
      { asset_id_hex: canonicalAssetID }
    );
  }

  /** Resolver shape consumed by one-proof payroll preparation. */
  async resolveAsset(denom) {
    return (await this.queryAssetByDenom(denom)).asset;
  }

  async resolveAssetByDenom(denom) {
    return this.resolveAsset(denom);
  }

  async resolveAssetByID(assetIdHex) {
    return (await this.queryAssetByID(assetIdHex)).asset;
  }

  /**
   * Fail closed before a proof is requested: the active consensus circuit set
   * and the authoritative denom/asset mapping must agree with this SDK.
   */
  async assertProtocolPreflight(denom) {
    const canonicalDenom = canonicalAssetDenomV1(denom);
    const [circuitConfig, asset] = await Promise.all([
      this.assertCircuitConfig(),
      this.resolveAsset(canonicalDenom)
    ]);
    const reverseAsset = await this.resolveAssetByID(asset.asset_id_hex);
    if (reverseAsset.canonical_denom !== asset.canonical_denom ||
        reverseAsset.asset_id_hex !== asset.asset_id_hex) {
      throw new Error("AssetRegistryV1 forward and reverse mappings do not agree");
    }
    return Object.freeze({ circuit_config: circuitConfig, asset });
  }

  /**
   * Bind a transfer operation to the active circuit/asset and typed
   * audit/disclosure configuration. Reserve accounting is exposed separately
   * through queryReserve because its value changes with operations.
   */
  async assertTransferProtocolConfig(denom) {
    const canonicalDenom = canonicalAssetDenomV1(denom);
    const [preflight, auditConfig, disclosureConfig] = await Promise.all([
      this.assertProtocolPreflight(canonicalDenom),
      this.queryAuditConfig(),
      this.queryDisclosureConfig()
    ]);
    return Object.freeze({
      ...preflight,
      audit_config: auditConfig,
      disclosure_config: disclosureConfig
    });
  }

  async fetchCommitmentPathsAtRoot(options = {}) {
    return this.queryPrivacyStateAdapter(
      "fetchCommitmentPathsAtRoot",
      [options],
      () => this.fetchMerklePathJson("/clairveil/privacy/v1/commitment_paths_at_root", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: jsonRequestBody(commitmentPathsAtRootRequestBody(options))
      })
    );
  }

  /** Fetch, validate, and root-recompute a single exact-root, optionally height-pinned Merkle snapshot. */
  async queryCommitmentPathsAtRoot(options = {}) {
    const request = normalizeCommitmentPathsAtRootRequest(options);
    const response = await this.fetchCommitmentPathsAtRoot(request);
    return normalizeCommitmentPathsAtRootResponse(response, request);
  }

  /** Build a lookupMerklePath provider pinned to one verified root/height snapshot. */
  async createCommitmentPathSnapshotProvider(options = {}) {
    return createCommitmentPathSnapshotProvider(await this.queryCommitmentPathsAtRoot(options));
  }

  /**
   * Build the default witness provider for a native 2x2 transfer. Both
   * selected commitments are resolved through one verified exact-root
   * snapshot rather than two mutable merkle_path reads.
   */
  async createTransferMerklePathSnapshotProvider(inputs) {
    if (!Array.isArray(inputs) || inputs.length !== 2) return this;
    const commitmentHexes = inputs.map(found => fieldHexV1(computeNoteCommitmentV1(found?.note)));
    const treeState = await this.fetchTreeState();
    const rootHex = String(treeState?.root ?? treeState?.root_hex ?? treeState?.rootHex ?? "").trim();
    if (!rootHex) throw new Error("transfer requires a verified current tree root");
    return this.createCommitmentPathSnapshotProvider({ commitmentHexes, rootHex });
  }

  async checkNullifier(nullifierHex) {
    const normalized = String(nullifierHex || "").trim().toLowerCase();
    if (this.privacyStateAdapter) {
      if (typeof this.privacyStateAdapter.checkNullifier === "function") {
        const result = await invokePrivacyStateAdapter(
          this.privacyStateAdapter,
          "checkNullifier",
          [normalized],
          { timeoutMs: this.queryTimeoutMs, retry: this.queryRetry }
        );
        const used = parseNullifierUsage(result);
        if (used === null) {
          throw new Error("privacyStateAdapter.checkNullifier returned an ambiguous status");
        }
        return { nullifier: normalized, used };
      }
      const statuses = normalizePrivacyNullifierStatuses(
        await invokePrivacyStateAdapter(
          this.privacyStateAdapter,
          "checkNullifiers",
          [[normalized]],
          { timeoutMs: this.queryTimeoutMs, retry: this.queryRetry }
        ),
        [normalized]
      );
      return { nullifier: normalized, used: statuses.get(normalized) };
    }
    const result = await this.fetchNullifierJson(
      `/clairveil/privacy/v1/nullifier/${encodeURIComponent(normalized)}`
    );
    const used = parseNullifierUsage(result);
    if (used === null) {
      throw new Error("nullifier response returned an ambiguous status");
    }
    return { nullifier: normalized, used };
  }

  async checkNullifiers(nullifierHexes = []) {
    const normalized = [...new Set((nullifierHexes || []).map(value => String(value || "").trim().toLowerCase()).filter(Boolean))];
    if (normalized.length === 0) return new Map();
    if (this.privacyStateAdapter) {
      return checkPrivacyStateAdapterNullifiers(
        this.privacyStateAdapter,
        normalized,
        { timeoutMs: this.queryTimeoutMs, retry: this.queryRetry }
      );
    }
    const usedByNullifier = new Map();
    const invalidNullifiers = new Set();
    const addStatus = (nullifier, value) => {
      const key = String(nullifier || "").trim().toLowerCase();
      if (!key || invalidNullifiers.has(key)) return;
      const used = parseNullifierUsage(value);
      if (used === null || (usedByNullifier.has(key) && usedByNullifier.get(key) !== used)) {
        usedByNullifier.delete(key);
        invalidNullifiers.add(key);
        return;
      }
      usedByNullifier.set(key, used);
    };
    const chunkSize = 1000;
    for (let start = 0; start < normalized.length; start += chunkSize) {
      const chunk = normalized.slice(start, start + chunkSize);
      const response = await this.fetchNullifierJson("/clairveil/privacy/v1/nullifiers", {
        method: "POST",
        body: JSON.stringify({ nullifiers: chunk })
      });
      for (const status of [
        ...(Array.isArray(response?.statuses) ? response.statuses : []),
        ...(Array.isArray(response?.Statuses) ? response.Statuses : [])
      ]) {
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
    }
    return usedByNullifier;
  }

  async deriveWalletPrivacyMaterial(wallet) {
    return derivePrivacyMaterialFromWallet(wallet, {
      shieldedPrefix: this.shieldedPrefix
    });
  }

  async scanNotes({
    rootSeed,
    after,
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page = 1,
    limit = 200,
    maxPages,
    max_pages,
    outputLimit,
    output_limit,
    eventLimit,
    event_limit,
    maxEncodedBytes,
    max_encoded_bytes,
    validationStateSnapshot,
    validation_state_snapshot,
    eventTypes,
    event_types,
    includeFoundNotes = false,
    scanSource,
    scan_source,
    strictPrivacyScan = false,
    strict_privacy_scan
  } = {}) {
    for (const [value, label] of [
      [strictPrivacyScan, "strictPrivacyScan"],
      [strict_privacy_scan, "strict_privacy_scan"]
    ]) {
      if (value != null && typeof value !== "boolean") {
        throw new Error(`${label} must be a boolean`);
      }
    }
    if (strictPrivacyScan != null && strict_privacy_scan != null &&
        strictPrivacyScan !== strict_privacy_scan) {
      throw new Error("strictPrivacyScan aliases conflict");
    }
    const strictTypedScan = Boolean(strictPrivacyScan ?? strict_privacy_scan ?? false);
    const resolvedMaxPages = resolveScanMaxPagesAlias(maxPages, max_pages) ?? 1;
    const requestedEventTypes = event_types ?? eventTypes;
    const resolvedEventTypes = requestedEventTypes ?? ["deposit", "shielded_transfer"];
    const pageLimit = Math.max(1, Number(limit || 200));
    const pageBudget = resolvedMaxPages;
    // `privacy_scan` intentionally rejects event filters so its cursor proves
    // progress across zero-output events. Legacy sources remain available only
    // when a low-level diagnostic caller selects one explicitly.
    const source = scan_source ?? scanSource ?? "privacy_scan";
    if (source !== "privacy_scan" && resolvedEventTypes.some(value => String(value || "").trim() === "batch_transfer")) {
      throw new Error("batch_transfer outputs require the typed privacy-scan-v2 source");
    }

    if (source === "privacy_scan") {
      if ((event_types ?? eventTypes) != null && (event_types ?? eventTypes).some(value => String(value || "").trim())) {
        throw new Error("unified privacy scan must not filter event types; zero-output summaries are required for safe cursor advancement");
      }
      const legacyHeight = afterHeight ?? after_height;
      const requestedAfter = after ?? (legacyHeight == null
        ? { height: 0, globalSequence: 0, outputIndex: 0 }
        // The legacy cursors cannot prove an exact typed-output position.
        // Rewind a height and deduplicate locally rather than skipping a
        // partial typed event during migration.
        : { height: decrementUint64Cursor(legacyHeight, "unified scan migration height"), globalSequence: 0, outputIndex: 0 });
      const initialAfter = validatePrivacyScanPageV2({
        scanSchemaVersion: "privacy-scan-v2",
        summaries: [],
        outputs: [],
        nextCursor: requestedAfter,
        hasMore: false
      }, { after: requestedAfter }).next_cursor;
      let currentAfter = {
        height: initialAfter.height,
        globalSequence: initialAfter.global_sequence,
        outputIndex: initialAfter.output_index
      };
      let pagesScanned = 0;
      let scannedEvents = 0;
      let hasMore = false;
      let found = [];
      const requestedValidationState = validationStateSnapshot ?? validation_state_snapshot;
      const validationState = requestedValidationState == null
        ? createPrivacyScanValidationStateV2()
        : restorePrivacyScanValidationStateV2(requestedValidationState);
      try {
        let eventCompletionPages = 0;
        for (;;) {
          const pendingEntries = [...validationState.pending_summary_by_event.values()];
          if (pendingEntries.length > 1) {
            throw new Error("privacy scan validation state contains multiple partial events");
          }
          const pendingSummary = pendingEntries[0];
          if (pagesScanned >= pageBudget && !pendingSummary) break;
          if (pagesScanned >= pageBudget && eventCompletionPages >= maxPrivacyScanEventCompletionPages) {
            throw new Error("privacy scan could not complete the current event within the bounded continuation budget");
          }
          const configuredOutputLimit = Number(outputLimit ?? output_limit ?? pageLimit);
          const remainingEventOutputs = pendingSummary
            ? pendingSummary.output_count - pendingSummary.last_output_index - 1
            : 0;
          const request = {
            after: currentAfter,
            outputLimit: pendingSummary
              ? configuredOutputLimit > 0
                ? Math.min(configuredOutputLimit, remainingEventOutputs)
                : remainingEventOutputs
              : configuredOutputLimit,
            eventLimit: eventLimit ?? event_limit,
            maxEncodedBytes: maxEncodedBytes ?? max_encoded_bytes,
            // Deliberately request every event: zero-output summaries prove
            // cursor progress across withdraws and filtered wallet outputs.
            eventTypes: []
          };
          const pageResult = await this.queryPrivacyScan({ ...request, validationState });
          found.push(...processPrivacyScanPageV2(pageResult, { rootSeed }));
          currentAfter = {
            height: pageResult.next_cursor.height,
            globalSequence: pageResult.next_cursor.global_sequence,
            outputIndex: pageResult.next_cursor.output_index
          };
          scannedEvents += pageResult.scanned_event_count;
          pagesScanned += 1;
          if (pendingSummary && pagesScanned > pageBudget) eventCompletionPages += 1;
          hasMore = pageResult.has_more;
          if (!hasMore) break;
        }
      } catch (error) {
        const canFallback = error?.status === 404 || error?.status === 405 || error?.status === 501;
        if (!canFallback) throw error;
        if (Boolean(strict_privacy_scan ?? strictPrivacyScan) || this.enableExperimentalBatchTransfer) {
          throw new Error("typed privacy-scan-v2 is required; legacy scan fallback is disabled", { cause: error });
        }
      } catch (error) {
        const endpointIsAbsent = pagesScanned === 0 && (
          error?.status === 404 || error?.status === 405 || error?.status === 501
        );
        if (!endpointIsAbsent) throw error;
        if (requireTypedScan) throw error;
        if (this.enableExperimentalBatchTransfer) {
          throw new Error(
            "typed privacy-scan-v2 is required while one-proof batch transfer support is enabled",
            { cause: error }
          );
        }
        // Wallet/spend scans are otherwise strict, but the contract permits a
        // one-time capability downgrade before any typed cursor state exists.
        // Never translate a persisted typed cursor or validation snapshot.
        const hasTypedResumeState = after != null || requestedValidationState != null;
        if (strictTypedScan && (!allowInitialPrivacyScanFallback || hasTypedResumeState)) {
          throw error;
        }
        // A typed cursor may point inside an event's output list, while the
        // compatibility endpoint only has an event-level cursor. Rewind one
        // height only when translating an actual typed cursor. If the caller
        // supplied a legacy (height, sequence) cursor, preserve it exactly:
        // the typed probe already rewound it and a missing typed endpoint must
        // not make repeated compatibility syncs walk backwards.
        const fallbackFromLegacyCursor = after == null && legacyHeight != null;
        const fallbackAfterHeight = fallbackFromLegacyCursor
          ? uint64CursorValue(legacyHeight, "unified scan legacy fallback height")
          : decrementUint64Cursor(initialAfter.height ?? 0, "unified scan fallback height");
        const fallbackAfterSequence = fallbackFromLegacyCursor
          ? uint64CursorValue(afterSequence ?? after_sequence ?? 0, "unified scan legacy fallback sequence")
          : 0;
        return this.scanNotes({
          rootSeed,
          afterHeight: fallbackAfterHeight,
          afterSequence: fallbackAfterSequence,
          page: 1,
          limit: pageLimit,
          maxPages: pageBudget,
          eventTypes: resolvedEventTypes,
          includeFoundNotes,
          scanSource: "scan_events"
        });
      }
      const result = await scanNotesCore({
        rootSeed,
        preprocessedFoundNotes: found,
        checkNullifiers: nullifiers => this.checkNullifiers(nullifiers),
        checkNullifier: nullifierHex => this.checkNullifier(nullifierHex),
        includeFoundNotes
      });
      const cursor = {
        source: "privacy_scan",
        after: initialAfter,
        output_limit: Number(outputLimit ?? output_limit ?? pageLimit),
        event_limit: eventLimit ?? event_limit ?? 0,
        max_encoded_bytes: maxEncodedBytes ?? max_encoded_bytes ?? 0,
        event_types: [],
        has_more: hasMore,
        next_cursor: {
          height: currentAfter.height,
          global_sequence: currentAfter.globalSequence,
          output_index: currentAfter.outputIndex
        },
        latest_height: currentAfter.height,
        latest_sequence: currentAfter.globalSequence,
        latest_output_index: currentAfter.outputIndex,
        pages_scanned: pagesScanned,
        completed: !hasMore,
        ...(validationState.batch_self_view_by_event.size ||
          validationState.pending_summary_by_event?.size
          ? { validation_state: serializePrivacyScanValidationStateV2(validationState) }
          : {})
      };
      return {
        ...result,
        diagnostics: {
          ...result.diagnostics,
          scanned_events: scannedEvents,
          pages_scanned: pagesScanned,
          max_pages: pageBudget
        },
        scanCursor: cursor,
        nextScanOptions: nextPrivacyScanOptions(cursor, {
          maxPages: pageBudget,
          includeFoundNotes
        })
      };
    }

    let legacyAfterHeight = afterHeight;
    let legacyAfterHeightAlias = after_height;
    let legacyPage = page;
    if (source !== "privacy_events") {
      const startAfterHeight = uint64CursorValue(afterHeight ?? after_height ?? 0, "scan after height");
      const startAfterSequence = uint64CursorValue(afterSequence ?? after_sequence ?? 0, "scan after sequence");
      const events = [];
      let currentAfterHeight = startAfterHeight;
      let currentAfterSequence = startAfterSequence;
      let pagesScanned = 0;
      let hasMore = false;
      let lastData = null;
      try {
        for (; pagesScanned < pageBudget;) {
          const request = {
            afterHeight: currentAfterHeight,
            afterSequence: currentAfterSequence,
            limit: pageLimit,
            eventTypes: resolvedEventTypes
          };
          const data = validateScanEventsResponse(await this.fetchScanEvents(request), request);
          lastData = data;
          events.push(...(data.events || []));
          pagesScanned += 1;
          hasMore = Boolean(data.has_more ?? data.hasMore);
          const nextHeight = uint64CursorValue(data.next_height ?? data.nextHeight ?? currentAfterHeight, "scan next height");
          const nextSequence = uint64CursorValue(data.next_sequence ?? data.nextSequence ?? currentAfterSequence, "scan next sequence");
          if (
            hasMore &&
            compareUint64Cursor(nextHeight, currentAfterHeight, "scan height") === 0 &&
            compareUint64Cursor(nextSequence, currentAfterSequence, "scan sequence") === 0
          ) {
            throw new Error("scan events cursor did not advance");
          }
          currentAfterHeight = nextHeight;
          currentAfterSequence = nextSequence;
          if (!hasMore) break;
        }

        const result = await scanNotesCore({
          rootSeed,
          events,
          checkNullifiers: nullifiers => this.checkNullifiers(nullifiers),
          checkNullifier: nullifierHex => this.checkNullifier(nullifierHex),
          includeFoundNotes
        });
        const cursor = scanEventsCursor(lastData || {
          events,
          limit: pageLimit,
          has_more: hasMore,
          next_height: currentAfterHeight,
          next_sequence: currentAfterSequence,
          scan_format_version: 1,
          view_tag_version: 1
        }, {
          afterHeight: startAfterHeight,
          afterSequence: startAfterSequence,
          limit: pageLimit,
          eventTypes: resolvedEventTypes
        });
        return {
          ...result,
          diagnostics: {
            ...result.diagnostics,
            pages_scanned: pagesScanned,
            max_pages: pageBudget
          },
          scanCursor: {
            ...cursor,
            pages_scanned: pagesScanned,
            completed: !hasMore
          },
          nextScanOptions: nextPrivacyScanOptions({
            ...cursor,
            pages_scanned: pagesScanned,
            completed: !hasMore
          }, {
            maxPages: pageBudget,
            includeFoundNotes,
            eventTypes: resolvedEventTypes
          })
        };
      } catch (error) {
        const canFallback = pagesScanned === 0 && (
          error?.status === 404 || error?.status === 405 || error?.status === 501
        );
        if (!canFallback) throw error;
        // The legacy endpoint begins at after_height + 1 and has no sequence
        // cursor. Rewind one block so a mid-block scan_events cursor cannot
        // skip the remaining events at that height.
        const rewindHeight = decrementUint64Cursor(startAfterHeight, "scan fallback height");
        legacyAfterHeight = rewindHeight;
        legacyAfterHeightAlias = rewindHeight;
        legacyPage = 1;
      }
    }

    const startPage = Math.max(1, Number(legacyPage || 1));
    const baseRequest = {
      afterHeight: legacyAfterHeight,
      after_height: legacyAfterHeightAlias,
      limit: pageLimit,
      eventTypes: resolvedEventTypes
    };
    const events = [];
    let currentPage = startPage;
    let pagesScanned = 0;
    let hasMore = false;
    let lastData = null;

    for (; pagesScanned < pageBudget;) {
      const request = { ...baseRequest, page: currentPage };
      const data = await this.fetchPrivacyEvents(request);
      lastData = data;
      events.push(...(data.events || []));
      pagesScanned += 1;
      hasMore = Boolean(data.has_more);
      if (!hasMore) break;
      currentPage = Number(data.page || currentPage) + 1;
    }

    const result = await scanNotesCore({
      rootSeed,
      events,
      checkNullifiers: nullifiers => this.checkNullifiers(nullifiers),
      checkNullifier: nullifierHex => this.checkNullifier(nullifierHex),
      includeFoundNotes
    });
    const cursor = privacyEventsCursor({
      ...(lastData || {}),
      events,
      has_more: hasMore
    }, { ...baseRequest, page: lastData?.page ?? currentPage });
    return {
      ...result,
      diagnostics: {
        ...result.diagnostics,
        pages_scanned: pagesScanned,
        max_pages: pageBudget
      },
      scanCursor: {
        ...cursor,
        pages_scanned: pagesScanned,
        next_page: hasMore ? currentPage : 1,
        completed: !hasMore
      },
      nextScanOptions: nextPrivacyScanOptions({
        ...cursor,
        pages_scanned: pagesScanned,
        next_page: hasMore ? currentPage : 1,
        completed: !hasMore
      }, {
        maxPages: pageBudget,
        includeFoundNotes,
        eventTypes: resolvedEventTypes
      })
    };
  }

  async fetchAuditableTransfers(options = {}) {
    const data = await this.fetchPrivacyEvents(options);
    return {
      ...data,
      events: (data.events || []).filter(isAuditableTransfer)
    };
  }

  async fetchAuditableBatchTransfers(options = {}) {
    const requestedTypes = options.eventTypes ?? options.event_types;
    if (requestedTypes != null && (
      !Array.isArray(requestedTypes) ||
      requestedTypes.some(value => String(value || "").trim() !== "batch_transfer")
    )) {
      throw new Error("auditable batch transfer query only accepts the batch_transfer event type");
    }
    const {
      validationState,
      validation_state,
      ...transportOptions
    } = options || {};
    const request = { ...transportOptions, eventTypes: ["batch_transfer"] };
    delete request.event_types;
    const page = validatePrivacyScanPageV2(
      await this.fetchPrivacyScan(request),
      {
        ...request,
        ...(validationState ?? validation_state
          ? { validationState: validationState ?? validation_state }
          : {})
      }
    );
    if (page.summaries.some(summary => summary.event_type !== "batch_transfer") ||
        page.outputs.some(output => output.event_type !== "batch_transfer")) {
      throw new Error("auditable batch transfer response contains a non-batch event");
    }
    return page;
  }

  async findPrivacyEventByTxHash(txHash, {
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page = 1,
    limit = 200,
    maxPages,
    max_pages,
    eventTypes = ["shielded_transfer"],
    event_types,
    scanSource,
    scan_source
  } = {}) {
    const normalizedTxHash = normalizedCosmosTxHash(txHash);
    const pageBudget = resolveScanMaxPagesAlias(maxPages, max_pages) ?? defaultPrepareScanMaxPages;
    const pageLimit = Math.max(1, Number(limit || 200));
    const resolvedEventTypes = event_types ?? eventTypes;
    const source = scan_source ?? scanSource ?? "privacy_events";
    if (source !== "privacy_events") {
      let currentAfterHeight = uint64CursorValue(afterHeight ?? after_height ?? 0, "event lookup after height");
      let currentAfterSequence = uint64CursorValue(afterSequence ?? after_sequence ?? 0, "event lookup after sequence");
      for (let pagesScanned = 0; pagesScanned < pageBudget; pagesScanned += 1) {
        const request = {
          afterHeight: currentAfterHeight,
          afterSequence: currentAfterSequence,
          limit: pageLimit,
          eventTypes: resolvedEventTypes
        };
        const data = validateScanEventsResponse(await this.fetchScanEvents(request), request);
        const event = (data.events || []).find(item =>
          comparableCosmosTxHash(item.tx_hash_hex ?? item.txHashHex) === normalizedTxHash
        );
        if (event) return event;
        if (!Boolean(data.has_more ?? data.hasMore)) break;
        const nextHeight = uint64CursorValue(data.next_height ?? data.nextHeight ?? currentAfterHeight, "event lookup next height");
        const nextSequence = uint64CursorValue(data.next_sequence ?? data.nextSequence ?? currentAfterSequence, "event lookup next sequence");
        if (
          compareUint64Cursor(nextHeight, currentAfterHeight, "event lookup height") === 0 &&
          compareUint64Cursor(nextSequence, currentAfterSequence, "event lookup sequence") === 0
        ) {
          throw new Error("scan events cursor did not advance");
        }
        currentAfterHeight = nextHeight;
        currentAfterSequence = nextSequence;
      }
      throw new Error(`transfer event not found for tx ${normalizedTxHash}`);
    }
    let currentPage = Math.max(1, Number(page || 1));

    for (let pagesScanned = 0; pagesScanned < pageBudget; pagesScanned += 1) {
      const data = await this.fetchPrivacyEvents({
        afterHeight,
        after_height,
        page: currentPage,
        limit: pageLimit,
        eventTypes: resolvedEventTypes
      });
      const event = (data.events || []).find(item =>
        comparableCosmosTxHash(item.tx_hash_hex ?? item.txHashHex) === normalizedTxHash
      );
      if (event) {
        return event;
      }
      if (!data.has_more) break;
      currentPage = Number(data.page || currentPage) + 1;
    }
    throw new Error(`transfer event not found for tx ${normalizedTxHash}`);
  }

  derivePrivacyAccount({ address, pubKeyHex, pub_key_hex, signatureBase64, signature_base64 }) {
    const material = derivePrivacyMaterial({
      address,
      pubKeyHex: pubKeyHex ?? pub_key_hex,
      signatureBase64: signatureBase64 ?? signature_base64,
      shieldedPrefix: this.shieldedPrefix
    });
    return {
      signing_message: material.signingMessage,
      shielded_address: material.shieldedAddress,
      disclosure_pubkey_hex: material.disclosurePubKeyHex,
      root_signature_hash: material.rootSignatureHash
    };
  }

  buildDepositMaterial(input) {
    return buildDepositMaterialCore({
      shieldedPrefix: this.shieldedPrefix,
      assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
      ...input
    });
  }

  buildDepositMessage(input) {
    const material = input?.depositMaterial ?? input?.deposit_material ?? (
      input?.material?.note_commitment && input?.material?.encrypted_note
        ? input.material
        : buildDepositMaterialCore({
          shieldedPrefix: this.shieldedPrefix,
          assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
          ...input
        })
    );
    const expectedCreator = String(input?.creator || "").trim();
    if (expectedCreator && String(material.creator || "").trim() !== expectedCreator) {
      throw new Error(`deposit material creator mismatch: expected ${expectedCreator}, got ${material.creator || ""}`);
    }
    const expectedAmount = input?.amount == null
      ? ""
      : parseCoin(input.amount, input?.assetDenom ?? input?.denom ?? this.defaultDenom).raw;
    if (expectedAmount && String(material.amount || "").trim() !== expectedAmount) {
      throw new Error(`deposit material amount mismatch: expected ${expectedAmount}, got ${material.amount || ""}`);
    }
    const proof = requiredDepositProof(input);
    return {
      material,
      message: {
        creator: material.creator,
        amount: material.amount,
        noteCommitment: material.note_commitment,
        encryptedNote: material.encrypted_note,
        proof
      }
    };
  }

  async scanWalletNotes({
    wallet,
    material,
    after,
    limit = 200,
    maxPages,
    max_pages,
    noteStore,
    includeFoundNotes = false,
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page,
    eventTypes,
    event_types,
    outputLimit,
    output_limit,
    eventLimit,
    event_limit,
    maxEncodedBytes,
    max_encoded_bytes,
    validationStateSnapshot,
    validation_state_snapshot,
    scanSource,
    scan_source,
    strictPrivacyScan = false,
    strict_privacy_scan
  } = {}) {
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const requestedEventTypes = event_types ?? eventTypes;
    if (requestedEventTypes != null) {
      if (!Array.isArray(requestedEventTypes)) {
        throw new Error("wallet scan eventTypes must be an array");
      }
      if (requestedEventTypes.some(value => String(value || "").trim())) {
        throw new Error("wallet scans must not filter event types; typed privacy_scan summaries are required");
      }
    }
    const requestedScanSource = scan_source ?? scanSource;
    if (requestedScanSource != null && requestedScanSource !== "privacy_scan") {
      throw new Error("wallet scans only support the typed privacy_scan source");
    }
    let resolvedAfter = after;
    let resolvedAfterHeight = afterHeight ?? after_height;
    let resolvedAfterSequence = afterSequence ?? after_sequence;
    let resolvedPage = page;
    let resolvedScanSource = "privacy_scan";
    let resolvedValidationStateSnapshot = validationStateSnapshot ?? validation_state_snapshot;
    if (resolvedAfter == null && resolvedAfterHeight == null && noteStore) {
      const cached = await noteStore.load();
      const cachedCursor = cached.scanCursor || {};
      if (cachedCursor.source === "privacy_scan") {
        const next = nextPrivacyScanOptions(cachedCursor, { limit, maxPages });
        resolvedAfter = next.after;
        resolvedValidationStateSnapshot = resolvedValidationStateSnapshot ?? next.validationStateSnapshot;
      } else if (cachedCursor.source === "scan_events" || cachedCursor.source === "privacy_events") {
        const next = nextPrivacyScanOptions(cachedCursor, { limit, maxPages });
        // A legacy cursor cannot prove an output position. Migrate by rewinding
        // one height and deduplicating typed outputs locally; never continue to
        // persist a legacy wallet cursor.
        resolvedAfter = {
          height: decrementUint64Cursor(next.afterHeight ?? cached.lastScannedHeight ?? 0, "typed wallet scan migration height"),
          globalSequence: 0,
          outputIndex: 0
        };
        resolvedAfterHeight = undefined;
        resolvedAfterSequence = undefined;
        resolvedPage = undefined;
      } else if (cachedCursor.has_more && (cachedCursor.next_sequence != null || cachedCursor.nextSequence != null)) {
        resolvedAfter = {
          height: decrementUint64Cursor(
            cachedCursor.next_height ?? cachedCursor.nextHeight ?? cached.lastScannedHeight ?? 0,
            "typed wallet scan migration height"
          ),
          globalSequence: 0,
          outputIndex: 0
        };
      } else if (cachedCursor.has_more && (cachedCursor.next_page || cachedCursor.nextPage)) {
        resolvedAfter = {
          height: decrementUint64Cursor(
            cachedCursor.after_height ?? cachedCursor.afterHeight ?? cached.lastScannedHeight ?? 0,
            "typed wallet scan migration height"
          ),
          globalSequence: 0,
          outputIndex: 0
        };
      } else {
        resolvedAfter = {
          height: decrementUint64Cursor(cached.lastScannedHeight || 0, "typed wallet scan migration height"),
          globalSequence: 0,
          outputIndex: 0
        };
      }
    }
    const scan = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      after: resolvedAfter,
      limit,
      maxPages: resolvedMaxPages,
      afterHeight: resolvedAfterHeight,
      afterSequence: resolvedAfterSequence,
      page: resolvedPage,
      scanSource: resolvedScanSource,
      eventTypes: [],
      outputLimit: output_limit ?? outputLimit,
      eventLimit: event_limit ?? eventLimit,
      maxEncodedBytes: max_encoded_bytes ?? maxEncodedBytes,
      validationStateSnapshot: resolvedValidationStateSnapshot,
      strictPrivacyScan: true,
      includeFoundNotes: true
    });
    if (noteStore) {
      await noteStore.mergeScanResult(scan, { owner: privacy.address });
      await this.refreshNoteStoreSpentStatuses(noteStore);
    }
    if (includeFoundNotes) {
      return {
        ...scan,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    const { foundNotes: _foundNotes, ...safeScan } = scan;
    return {
      ...safeScan,
      privacyAccount: publicPrivacyAccount(privacy)
    };
  }

  async refreshNoteStoreSpentStatuses(noteStore) {
    if (!noteStore) return null;
    let current = await noteStore.load();
    const nullifiers = [];
    for (const note of current.notes || []) {
      const nullifier = String(note?.nullifier || "").trim().toLowerCase();
      if (!nullifier) continue;
      nullifiers.push(nullifier);
    }
    if (!nullifiers.length) return current;
    const nullifierStatuses = new Map();
    try {
      const statuses = await this.checkNullifiers(nullifiers);
      for (const nullifier of nullifiers) {
        if (statuses.has(nullifier)) {
          const used = parseNullifierUsage(statuses.get(nullifier));
          if (used !== null) {
            nullifierStatuses.set(nullifier, used ? "spent" : "unspent");
          }
        }
      }
      const missing = nullifiers.filter(nullifier => !nullifierStatuses.has(nullifier));
      if (!missing.length) {
        return typeof noteStore.setNullifierStatuses === "function"
          ? noteStore.setNullifierStatuses(nullifierStatuses)
          : current;
      }
      nullifiers.length = 0;
      nullifiers.push(...missing);
    } catch {
      // Check every note individually before marking a cached nullifier as unknown.
    }
    for (const nullifier of nullifiers) {
      try {
        const result = await this.checkNullifier(nullifier);
        const used = parseNullifierUsage(result);
        nullifierStatuses.set(nullifier, used === null ? "unknown" : used ? "spent" : "unspent");
      } catch {
        nullifierStatuses.set(nullifier, "unknown");
      }
    }
    return typeof noteStore.setNullifierStatuses === "function"
      ? noteStore.setNullifierStatuses(nullifierStatuses)
      : current;
  }

  async planWalletTransfer({ wallet, material, amount, denom, limit = 200, maxPages = defaultPrepareScanMaxPages, scan: scanOptions, scanSource, scan_source, strictPrivacyScan, strict_privacy_scan } = {}) {
    const resolvedScanOptions = resolveScanOptions({ scan: scanOptions, limit, maxPages, scanSource, scan_source, strictPrivacyScan, strict_privacy_scan });
    const scan = await this.scanWalletNotes({
      wallet,
      material,
      ...resolvedScanOptions,
      limit: resolvedScanOptions.limit ?? 200,
      maxPages: resolvedScanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    return {
      plan: planTransferNotes({
        notes: scan.foundNotes,
        amount,
        denom: denom ?? this.defaultDenom
      }),
      scan
    };
  }

  async planWalletWithdraw({ wallet, material, amount, denom, limit = 200, maxPages = defaultPrepareScanMaxPages, scan: scanOptions, scanSource, scan_source, strictPrivacyScan, strict_privacy_scan } = {}) {
    const resolvedScanOptions = resolveScanOptions({ scan: scanOptions, limit, maxPages, scanSource, scan_source, strictPrivacyScan, strict_privacy_scan });
    const scan = await this.scanWalletNotes({
      wallet,
      material,
      ...resolvedScanOptions,
      limit: resolvedScanOptions.limit ?? 200,
      maxPages: resolvedScanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    return {
      plan: planWithdrawNotes({
        notes: scan.foundNotes,
        amount,
        denom: denom ?? this.defaultDenom
      }),
      scan
    };
  }

  async prepareDeposit({
    wallet,
    material,
    depositMaterial,
    deposit_material,
    amount,
    memo = "Clairveil deposit",
    gasLimit,
    gas_limit,
    feeAmount,
    fee_amount,
    denom,
    assetDenom,
    proof,
    proofHex,
    proof_hex
  } = {}) {
    const resolvedGasLimit = resolveCosmosGasLimit(gasLimit, gas_limit, 2500000);
    const resolvedFeeAmount = resolveCosmosFeeAmount(feeAmount, fee_amount);
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const prepared = this.buildDepositMessage({
      depositMaterial: depositMaterial ?? deposit_material,
      creator: privacy.address,
      rootSeed: privacy.rootSeed,
      amount,
      assetDenom: assetDenom ?? denom ?? this.defaultDenom,
      memo,
      proof,
      proofHex: proofHex ?? proof_hex
    });
    await this.assertProtocolPreflight(assetDenom ?? denom ?? this.defaultDenom);
    const signDoc = await this.buildDirectSignDoc({
      signer: privacy.address,
      pubKeyHex: privacy.pubKeyHex,
      gasLimit: resolvedGasLimit,
      feeAmount: resolvedFeeAmount,
      messages: [
        {
          typeUrl: msgDepositTypeUrl,
          value: prepared.message
        }
      ],
      memo
    });

    return {
      status: "ready",
      signDoc,
      message: prepared.message,
      material: prepared.material,
      privacyAccount: publicPrivacyAccount(privacy)
    };
  }

  /**
   * Wait for a prepared deposit transaction and fail closed unless its
   * successful tx result contains the exact commitment and encrypted note
   * that were prepared for the wallet.
   */
  async confirmDeposit({
    txHash,
    tx_hash,
    prepared,
    material,
    depositMaterial,
    deposit_material,
    message,
    expectedCommitment,
    expected_commitment,
    expectedEncryptedNote,
    expected_encrypted_note,
    waitOptions,
    attempts,
    intervalMs
  } = {}) {
    const normalizedTxHash = normalizedCosmosTxHash(txHash ?? tx_hash);
    const expected = depositExpectedMaterial({
      prepared,
      material,
      depositMaterial,
      deposit_material,
      message,
      expectedCommitment,
      expected_commitment,
      expectedEncryptedNote,
      expected_encrypted_note
    });
    const tx = await this.waitForTx(normalizedTxHash, {
      ...(waitOptions || {}),
      ...(attempts == null ? {} : { attempts }),
      ...(intervalMs == null ? {} : { intervalMs })
    });
    if (!tx) throw new Error(`deposit transaction was not found: ${normalizedTxHash}`);
    const code = explicitTransactionCode(tx);
    if (code !== 0) {
      throw new Error(`deposit transaction did not succeed: ${code == null ? "missing or malformed code" : `code ${code}`}`);
    }

    const event = transactionEvents(tx).find(candidate => {
      const type = transactionEventType(candidate);
      if (type !== "deposit" && type !== "shielded_deposit") return false;
      const commitment = String(transactionEventAttribute(candidate, "commitment"))
        .trim().replace(/^"|"$/g, "").replace(/^0x/i, "").toLowerCase();
      const encryptedNote = String(transactionEventAttribute(candidate, "encrypted_note"))
        .trim().replace(/^"|"$/g, "").replace(/^0x/i, "").toLowerCase();
      return commitment === expected.commitment && encryptedNote === expected.encryptedNote;
    });
    if (!event) {
      throw new Error("deposit tx result does not contain the prepared commitment and encrypted note");
    }
    return {
      status: "confirmed",
      txHash: normalizedTxHash,
      tx,
      event,
      commitment: expected.commitment,
      encryptedNote: expected.encryptedNote
    };
  }

  async prepareTransfer({
    wallet,
    material,
    amount,
    recipient,
    proverAdapter,
    signal,
    userPrivacyPolicy = "all-private",
    userDisclosureMode,
    userDisclosureTargetPubKeyHex = "",
    disableSelfViewDisclosure,
    disable_self_view_disclosure,
    selfViewDisclosureTargetPubKeyHex,
    self_view_disclosure_target_pubkey,
    auditDisclosureTargetPubKeyHex,
    expectedRecipientHash,
    expected_recipient_hash,
    expectedAmountHash,
    expected_amount_hash,
    denom,
    expiresAtUnix,
    expires_at_unix,
    chainNowUnix,
    chain_now_unix,
    allowPlanStep = false,
    scan,
    after,
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page,
    limit = 200,
    maxPages,
    max_pages,
    eventTypes,
    event_types,
    outputLimit,
    output_limit,
    eventLimit,
    event_limit,
    maxEncodedBytes,
    max_encoded_bytes,
    scanSource,
    scan_source,
    strictPrivacyScan,
    strict_privacy_scan,
    gasLimit,
    gas_limit,
    feeAmount,
    fee_amount,
    reservationManager,
    reservation_manager,
    executionBuilder
  } = {}) {
    if (executionBuilder != null && typeof executionBuilder !== "function") {
      throw new Error("executionBuilder must be a function");
    }
    const resolvedGasLimit = resolveCosmosGasLimit(gasLimit, gas_limit, 8000000);
    const resolvedFeeAmount = resolveCosmosFeeAmount(feeAmount, fee_amount);
    const resolvedExpiresAtUnix = resolveOperationEvidenceAlias(
      expiresAtUnix,
      expires_at_unix,
      "expiresAtUnix"
    );
    const resolvedChainNowUnix = resolveOperationEvidenceAlias(
      chainNowUnix,
      chain_now_unix,
      "chainNowUnix"
    );
    for (const [value, label] of [
      [disableSelfViewDisclosure, "disableSelfViewDisclosure"],
      [disable_self_view_disclosure, "disable_self_view_disclosure"]
    ]) {
      if (value != null && typeof value !== "boolean") {
        throw new Error(`${label} must be a boolean`);
      }
    }
    if (disableSelfViewDisclosure != null && disable_self_view_disclosure != null &&
        disableSelfViewDisclosure !== disable_self_view_disclosure) {
      throw new Error("disableSelfViewDisclosure aliases conflict");
    }
    if (selfViewDisclosureTargetPubKeyHex != null &&
        self_view_disclosure_target_pubkey != null &&
        comparableBatchHex(selfViewDisclosureTargetPubKeyHex) !==
          comparableBatchHex(self_view_disclosure_target_pubkey)) {
      throw new Error("selfViewDisclosureTargetPubKeyHex aliases conflict");
    }
    const resolvedReservationManager = reservationManager ?? reservation_manager ?? null;
    const resolvedGasLimit = resolveCosmosGasLimit(gasLimit, gas_limit, 8000000);
    // Snapshot and canonicalize fee coins before any scan/prover await. The
    // caller/profile can therefore choose a production fee without a mutable
    // array changing the ProofReady sign-doc later in preparation.
    const resolvedFeeAmount = resolveCosmosFeeAmount(feeAmount, fee_amount);
    const requestedChainNowUnix = aliasedTransferUnix(
      chainNowUnix,
      chain_now_unix,
      "chainNowUnix"
    );
    const requestedExpiresAtUnix = aliasedTransferUnix(
      expiresAtUnix,
      expires_at_unix,
      "expiresAtUnix"
    );
    for (const [value, label] of [
      [disableSelfViewDisclosure, "disableSelfViewDisclosure"],
      [disable_self_view_disclosure, "disable_self_view_disclosure"]
    ]) {
      if (value != null && typeof value !== "boolean") {
        throw new Error(`${label} must be a boolean`);
      }
    }
    if (disableSelfViewDisclosure != null && disable_self_view_disclosure != null &&
        disableSelfViewDisclosure !== disable_self_view_disclosure) {
      throw new Error("disableSelfViewDisclosure aliases conflict");
    }
    if (selfViewDisclosureTargetPubKeyHex != null &&
        self_view_disclosure_target_pubkey != null &&
        comparableBatchHex(selfViewDisclosureTargetPubKeyHex) !==
          comparableBatchHex(self_view_disclosure_target_pubkey)) {
      throw new Error("selfViewDisclosureTargetPubKeyHex aliases conflict");
    }
    const resolvedDisableSelfViewDisclosure = disableSelfViewDisclosure ?? disable_self_view_disclosure ?? false;
    const resolvedSelfViewDisclosureTargetPubKeyHex = selfViewDisclosureTargetPubKeyHex ??
      self_view_disclosure_target_pubkey;
    const operationEvidence = resolveDirectOperationEvidenceHashes({
      expectedRecipientHash,
      expected_recipient_hash,
      expectedAmountHash,
      expected_amount_hash
    });
    // Validate and bind the caller's final intent before planning can prepare
    // an intermediate self-merge. Only final transfers persist these hashes.
    const finalOperationEvidence = buildDirectOperationEvidenceHashes({
      assertions: operationEvidenceAssertions,
      recipient,
      amount,
      denom: denom ?? this.defaultDenom,
      shieldedPrefix: this.shieldedPrefix
    });
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const scanOptions = resolveWalletScanOptions({
      scan,
      after,
      afterHeight,
      after_height,
      afterSequence,
      after_sequence,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types,
      outputLimit,
      output_limit,
      eventLimit,
      event_limit,
      maxEncodedBytes,
      max_encoded_bytes,
      scanSource,
      scan_source,
      strictPrivacyScan,
      strict_privacy_scan
    });
    const transferProtocolConfig = await this.assertTransferProtocolConfig(
      denom ?? this.defaultDenom
    );
    const scanResult = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      allowInitialPrivacyScanFallback: true,
      includeFoundNotes: true
    });
    const availableFoundNotes = await reservationAvailableNotes(resolvedReservationManager, scanResult.foundNotes);
    const plan = planTransferNotes({
      notes: availableFoundNotes,
      amount,
      denom: denom ?? this.defaultDenom
    });
    if (plan.status === "self_merge_required" && !allowPlanStep) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    if (!plan.canBuildTx) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    const isFinal = plan.status === "final_transfer_ready";
    assertPlanCanBuildTx(plan);
    const transferTime = requiredTransferPreparationTime(
      requestedChainNowUnix,
      requestedExpiresAtUnix
    );
    const transferProtocolConfig = await this.assertTransferProtocolConfig(denom ?? this.defaultDenom);
    assertTransferDisclosureCapabilities(transferProtocolConfig.disclosure_config, {
      userPrivacyPolicy: isFinal ? userPrivacyPolicy : "all-private",
      userDisclosureMode: isFinal ? userDisclosureMode : "none"
    });

    const requestedAuditPubKeyHex = String(auditDisclosureTargetPubKeyHex ?? "").trim().toLowerCase();
    const configuredAuditPubKeyHex = String(
      transferProtocolConfig.audit_config.audit_master_pubkey_hex || ""
    ).toLowerCase();
    if (requestedAuditPubKeyHex && requestedAuditPubKeyHex !== configuredAuditPubKeyHex) {
      throw new Error("transfer audit disclosure target must exactly match the active chain audit config");
    }
    const auditPubKeyHex = transferProtocolConfig.audit_config.audit_master_pubkey_hex;
    const stepRecipient = isFinal ? recipient : privacy.shieldedAddress;
    const stepAmount = isFinal ? amount : plan.nextAmount;
    const operationEvidence = isFinal
      ? finalOperationEvidence
      : buildDirectOperationEvidenceHashes({
          assertions: {},
          recipient: stepRecipient,
          amount: stepAmount,
          denom: denom ?? this.defaultDenom,
          shieldedPrefix: this.shieldedPrefix
        });
    let reservationBatch = null;
    try {
      reservationBatch = await preparePlanReservation(resolvedReservationManager, {
        plan,
        kind: isFinal ? "transfer" : "self_merge",
        metadata: {
          amount: stepAmount,
          recipient: stepRecipient,
          finalAmount: amount,
          finalRecipient: recipient
        }
      });
      const heartbeatResult = await withReservationHeartbeat(resolvedReservationManager, reservationBatch, async ({ assertHeartbeatHealthy, heartbeatNow }) => {
        const built = await this.buildTransferMessage({
          proverAdapter,
          creator: privacy.address,
          inputs: plan.selection.inputs,
          recipient: stepRecipient,
          amount: stepAmount,
          transferDenom: denom ?? this.defaultDenom,
          rootSeed: privacy.rootSeed,
          shieldedPrefix: this.shieldedPrefix,
          userPrivacyPolicy: isFinal ? userPrivacyPolicy : "all-private",
          userDisclosureMode: isFinal ? userDisclosureMode : "none",
          userDisclosureTargetPubKeyHex: isFinal ? userDisclosureTargetPubKeyHex : "",
          disableSelfViewDisclosure: resolvedDisableSelfViewDisclosure,
          selfViewDisclosureTargetPubKeyHex: resolvedSelfViewDisclosureTargetPubKeyHex,
          auditDisclosureTargetPubKeyHex: auditPubKeyHex,
          expiresAtUnix: transferTime.expiresAtUnix,
          chainNowUnix: transferTime.chainNowUnix,
          signal
        });
        assertHeartbeatHealthy();
        const signDoc = await this.buildDirectSignDoc({
          signer: privacy.address,
          pubKeyHex: privacy.pubKeyHex,
          gasLimit: resolvedGasLimit,
          feeAmount: resolvedFeeAmount,
          messages: [
            {
              typeUrl: msgTransferTypeUrl,
              value: built.message
            }
          ],
          memo: reservationBatch
            ? reservationRequiredCosmosMemo("Clairveil veiled transfer")
            : "Clairveil veiled transfer"
        });
        await heartbeatNow();
        await markReservationProofReady(resolvedReservationManager, reservationBatch, transferProofReadyMetadata(built, {
          amount: stepAmount,
          denom: denom ?? this.defaultDenom,
          expectedRecipientHash: isFinal ? operationEvidence.expectedRecipientHash : "",
          expectedAmountHash: isFinal ? operationEvidence.expectedAmountHash : "",
          signDocHash
        }, "signDocHash"));
        return {
          built,
          ...(artifact.signDoc ? {
            signDoc: markCosmosSignDocReservationRequired(
              artifact.signDoc,
              reservationBatch
            )
          } : {}),
          ...(artifact.execution ? { execution: artifact.execution } : {})
        };
      });
      const { built, signDoc, execution } = heartbeatResult;

      return {
        ...reservationReconciliationFields(heartbeatResult),
        status: "ready",
        plan,
        scan: scanResult,
        ...(signDoc ? { signDoc } : {}),
        ...(execution ? { execution } : {}),
        payload: built.payload,
        proof: built.proof,
        message: built.message,
        reservation: reservationBatchSummary(reservationBatch),
        prepared: {
          planAction: isFinal ? "final_transfer" : "self_merge",
          isFinal,
          amount: stepAmount,
          recipient: stepRecipient,
          finalAmount: amount,
          finalRecipient: recipient,
          selectedInputTotal: plan.selection.total.toString(),
          expiresAtUnix: transferTime.expiresAtUnix,
          chainNowUnix: transferTime.chainNowUnix,
          reservation: reservationBatchSummary(reservationBatch)
        },
        privacyAccount: publicPrivacyAccount(privacy)
      };
    } catch (error) {
      await rollbackPlanReservationPreservingError(resolvedReservationManager, reservationBatch, error);
      throw error;
    }
  }

  async prepareTransferBatch({
    wallet,
    material,
    payments,
    amounts,
    recipient,
    proverAdapter,
    signal,
    userPrivacyPolicy = "all-private",
    userDisclosureMode = "none",
    userDisclosureTargetPubKeyHex = "",
    auditDisclosureTargetPubKeyHex,
    audit_disclosure_target_pubkey_hex,
    expectedRecipientHash,
    expected_recipient_hash,
    expectedRecipientHashes,
    expected_recipient_hashes,
    expectedAmountHashes,
    expected_amount_hashes,
    outputMode,
    output_mode,
    onPreparedPayload,
    on_prepared_payload,
    onPreparedProof,
    on_prepared_proof,
    denom,
    scan,
    after,
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page,
    limit = 200,
    maxPages,
    max_pages,
    eventTypes,
    event_types,
    outputLimit,
    output_limit,
    eventLimit,
    event_limit,
    maxEncodedBytes,
    max_encoded_bytes,
    scanSource,
    scan_source,
    strictPrivacyScan,
    strict_privacy_scan,
    gasLimit,
    gas_limit,
    feeAmount,
    fee_amount,
    expiresAtUnix,
    expires_at_unix,
    chainNowUnix,
    chain_now_unix,
    rootHex,
    root_hex,
    snapshotHeight,
    snapshot_height,
    inputCommitmentHexes,
    input_commitment_hexes,
    disableSelfViewDisclosure,
    disable_self_view_disclosure,
    selfViewDisclosureTargetPubKeyHex,
    self_view_disclosure_target_pubkey,
    reservationManager,
    reservation_manager,
    executionBuilder
  } = {}) {
    if (!this.enableExperimentalBatchTransfer) {
      throw new Error("one-proof batch transfer is feature-gated; construct the client with enableExperimentalBatchTransfer: true after completing downstream conformance and localnet validation");
    }
    const resolvedGasLimit = resolveCosmosGasLimit(gasLimit, gas_limit, 25000000);
    // Freeze the exact profile fee before scanning, proving, or either durable
    // checkpoint callback can yield back to mutable application state.
    const resolvedFeeAmount = resolveCosmosFeeAmount(feeAmount, fee_amount);
    if (outputMode != null && output_mode != null &&
        normalizeBatchTransferOutputMode(outputMode) !== normalizeBatchTransferOutputMode(output_mode)) {
      throw new Error("outputMode aliases conflict");
    }
    if (chainNowUnix != null && chain_now_unix != null &&
        normalizedBatchNowUnix(chainNowUnix) !== normalizedBatchNowUnix(chain_now_unix)) {
      throw new Error("chainNowUnix aliases conflict");
    }
    if (expiresAtUnix != null && expires_at_unix != null &&
        normalizedBatchNowUnix(expiresAtUnix) !== normalizedBatchNowUnix(expires_at_unix)) {
      throw new Error("expiresAtUnix aliases conflict");
    }
    if (rootHex != null && root_hex != null &&
        comparableBatchHex(rootHex) !== comparableBatchHex(root_hex)) {
      throw new Error("rootHex aliases conflict");
    }
    if (snapshotHeight != null && snapshot_height != null &&
        String(uint64CursorValue(snapshotHeight, "snapshotHeight")) !==
          String(uint64CursorValue(snapshot_height, "snapshot_height"))) {
      throw new Error("snapshotHeight aliases conflict");
    }
    const suppliedRootHex = rootHex ?? root_hex;
    const suppliedSnapshotHeight = snapshotHeight ?? snapshot_height;
    const hasPinnedRoot = suppliedRootHex != null && String(suppliedRootHex).trim() !== "";
    const hasPinnedSnapshotHeight = suppliedSnapshotHeight != null &&
      String(suppliedSnapshotHeight).trim() !== "";
    if (hasPinnedRoot !== hasPinnedSnapshotHeight) {
      throw new Error("rootHex and snapshotHeight must be supplied together for an exact Merkle snapshot");
    }
    const resolvedInputCommitments = normalizeBatchTransferInputCommitments(
      inputCommitmentHexes,
      input_commitment_hexes
    );
    for (const [value, label] of [
      [disableSelfViewDisclosure, "disableSelfViewDisclosure"],
      [disable_self_view_disclosure, "disable_self_view_disclosure"]
    ]) {
      if (value != null && typeof value !== "boolean") {
        throw new Error(`${label} must be a boolean`);
      }
    }
    if (disableSelfViewDisclosure != null && disable_self_view_disclosure != null &&
        disableSelfViewDisclosure !== disable_self_view_disclosure) {
      throw new Error("disableSelfViewDisclosure aliases conflict");
    }
    if (selfViewDisclosureTargetPubKeyHex != null &&
        self_view_disclosure_target_pubkey != null &&
        comparableBatchHex(selfViewDisclosureTargetPubKeyHex) !==
          comparableBatchHex(self_view_disclosure_target_pubkey)) {
      throw new Error("selfViewDisclosureTargetPubKeyHex aliases conflict");
    }
    if (reservationManager != null && reservation_manager != null &&
        reservationManager !== reservation_manager) {
      throw new Error("reservationManager aliases conflict");
    }
    const resolvedReservationManager = reservationManager ?? reservation_manager ?? null;
    const normalizedPayments = normalizeBatchTransferPayments({
      payments,
      amounts,
      recipient,
      userPrivacyPolicy,
      userDisclosureMode,
      userDisclosureTargetPubKeyHex
    });
    const normalizedAmounts = normalizedPayments.map(payment => payment.amount);
    const legacyOperationEvidence = resolveBatchOperationEvidence({
      amounts: normalizedAmounts,
      expectedRecipientHash,
      expected_recipient_hash,
      expectedRecipientHashes,
      expected_recipient_hashes,
      expectedAmountHashes,
      expected_amount_hashes
    });
    const resolvedPayments = normalizedPayments.map((payment, index) => {
      const legacyRecipientHash = legacyOperationEvidence.recipientHashes[index] || "";
      const legacyAmountHash = legacyOperationEvidence.amountHashes[index] || "";
      if (payment.expectedRecipientHash && legacyRecipientHash &&
          canonicalBatchEvidenceDigest(payment.expectedRecipientHash, `batch payment ${index} expected recipient hash`) !==
          canonicalBatchEvidenceDigest(legacyRecipientHash, `batch payment ${index} legacy expected recipient hash`)) {
        throw new Error(`batch payment ${index} expected recipient hash conflicts with the top-level evidence`);
      }
      if (payment.expectedAmountHash && legacyAmountHash &&
          canonicalBatchEvidenceDigest(payment.expectedAmountHash, `batch payment ${index} expected amount hash`) !==
          canonicalBatchEvidenceDigest(legacyAmountHash, `batch payment ${index} legacy expected amount hash`)) {
        throw new Error(`batch payment ${index} expected amount hash conflicts with the top-level evidence`);
      }
      return Object.freeze({
        ...payment,
        expectedRecipientHash: payment.expectedRecipientHash || legacyRecipientHash,
        expectedAmountHash: payment.expectedAmountHash || legacyAmountHash
      });
    });
    const resolvedOutputMode = normalizeBatchTransferOutputMode(outputMode ?? output_mode);
    if (onPreparedPayload != null && on_prepared_payload != null &&
        onPreparedPayload !== on_prepared_payload) {
      throw new Error("onPreparedPayload aliases conflict");
    }
    if (onPreparedProof != null && on_prepared_proof != null &&
        onPreparedProof !== on_prepared_proof) {
      throw new Error("onPreparedProof aliases conflict");
    }
    const persistPreparedPayload = onPreparedPayload ?? on_prepared_payload;
    const persistPreparedProof = onPreparedProof ?? on_prepared_proof;
    if (persistPreparedPayload != null && typeof persistPreparedPayload !== "function") {
      throw new Error("onPreparedPayload must be a function");
    }
    if (persistPreparedProof != null && typeof persistPreparedProof !== "function") {
      throw new Error("onPreparedProof must be a function");
    }
    if (!resolvedReservationManager) {
      throw new Error("one-proof batch transfer requires a reservationManager for atomic input reservation");
    }
    if (typeof persistPreparedPayload !== "function") {
      throw new Error("one-proof batch transfer requires onPreparedPayload to durably persist the private payload before proving");
    }
    if (typeof persistPreparedProof !== "function") {
      throw new Error("one-proof batch transfer requires onPreparedProof to durably persist the private proof before signing");
    }
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const scanOptions = resolveWalletScanOptions({
      scan,
      after,
      afterHeight,
      after_height,
      afterSequence,
      after_sequence,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types,
      outputLimit,
      output_limit,
      eventLimit,
      event_limit,
      maxEncodedBytes,
      max_encoded_bytes,
      scanSource,
      scan_source,
      strictPrivacyScan,
      strict_privacy_scan
    });
    if (scanOptions.scanSource != null &&
        String(scanOptions.scanSource).trim() !== "privacy_scan") {
      throw new Error("one-proof batch transfer only supports the typed privacy_scan source");
    }
    const scanResult = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      ...scanOptions,
      scanSource: "privacy_scan",
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      requireTypedScan: true,
      includeFoundNotes: true
    });
    if (scanResult.scanCursor?.source !== "privacy_scan") {
      throw new Error("one-proof batch transfer requires the typed privacy-scan-v2 source; legacy scan fallback cannot recover batch outputs safely");
    }
    const availableFoundNotes = await reservationAvailableNotes(resolvedReservationManager, scanResult.foundNotes);
    let planNotes = availableFoundNotes;
    if (resolvedInputCommitments) {
      const availableByCommitment = new Map(availableFoundNotes.map(found => [
        fieldHexV1(computeNoteCommitmentV1(found.note)),
        found
      ]));
      const missingIndex = resolvedInputCommitments.findIndex(
        commitment => !availableByCommitment.has(commitment)
      );
      if (missingIndex !== -1) {
        throw new Error(`inputCommitmentHexes[${missingIndex}] is unavailable or unverified`);
      }
      planNotes = resolvedInputCommitments.map(commitment => availableByCommitment.get(commitment));
    }
    let plan = planTransferBatchNotes({
      notes: planNotes,
      amounts: normalizedAmounts,
      denom: denom ?? this.defaultDenom
    });
    if (!plan.canBuildTx) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    assertPlanCanBuildTx(plan);
    const batchDenom = denom ?? this.defaultDenom;
    if (resolvedInputCommitments) {
      const selectedTotal = planNotes.reduce((sum, found) => sum + found.note.amount, 0n);
      const requestedTotal = BigInt(plan.facts.requestedAmountValue);
      const change = selectedTotal - requestedTotal;
      const outputCount = normalizedAmounts.length + (change > 0n ? 1 : 0);
      if (change < 0n) {
        throw new Error("inputCommitmentHexes total is insufficient for the requested payments");
      }
      if (change > maxUint64) {
        throw new Error("inputCommitmentHexes would create change above the uint64 NoteV1 range");
      }
      if (outputCount > 32) {
        throw new Error("inputCommitmentHexes would exceed the 32-output batch capacity");
      }
      const selection = Object.freeze({
        inputs: Object.freeze([...planNotes]),
        total: selectedTotal,
        isFinal: true,
        needsZeroDummy: false
      });
      plan = {
        ...plan,
        facts: {
          ...plan.facts,
          selectedInputTotal: `${selectedTotal}${batchDenom}`,
          selectedInputTotalValue: selectedTotal.toString()
        },
        selection,
        selections: [selection]
      };
    }
    const transferProtocolConfig = await this.assertTransferProtocolConfig(denom ?? this.defaultDenom);
    const paymentPolicies = resolvedPayments.map((payment, index) => {
      const capabilities = assertTransferDisclosureCapabilities(transferProtocolConfig.disclosure_config, {
        userPrivacyPolicy: payment.userPrivacyPolicy,
        userDisclosureMode: payment.userDisclosureMode
      });
      const policy = transferPrivacyPolicyNames.indexOf(capabilities.policy);
      const disclosureMode = transferDisclosureModeNames.indexOf(capabilities.mode);
      if (policy !== 0 && disclosureMode === 2 && !payment.userDisclosureTargetPubKeyHex) {
        throw new Error(`batch transfer payment ${index} recipient-encrypted disclosure requires a disclosure target public key`);
      }
      return Object.freeze({ ...payment, policyName: capabilities.policy, modeName: capabilities.mode, privacyPolicy: policy, disclosureMode });
    });

    if (!proverAdapter || typeof proverAdapter.proveBatchTransfer !== "function") {
      throw new Error("prepareTransferBatch requires a proverAdapter with proveBatchTransfer(payload)");
    }
    const resolvedDisableSelfViewDisclosure = disableSelfViewDisclosure ?? disable_self_view_disclosure ?? false;
    const coins = paymentPolicies.map((payment, index) => {
      const coin = parseCoin(payment.amount, batchDenom);
      if (coin.denom !== batchDenom) {
        throw new Error(`batch transfer payment ${index} denom must equal ${batchDenom}`);
      }
      return coin;
    });
    const preparedPayments = paymentPolicies.map((payment, index) => Object.freeze({
      ...payment,
      coin: coins[index]
    }));
    const requestedTotal = coins.reduce((sum, coin) => sum + BigInt(coin.amount), 0n);
    const selectedInputs = plan.selection?.inputs || plan.selections?.[0]?.inputs || [];
    if (selectedInputs.length < 1 || selectedInputs.length > 16) {
      throw new Error("one-proof batch transfer requires 1..16 selected input notes");
    }
    const selectedTotal = selectedInputs.reduce((sum, found) => sum + found.note.amount, 0n);
    const change = selectedTotal - requestedTotal;
    if (change < 0n) throw new Error("one-proof batch transfer selected input total is insufficient");
    const compactOutputCount = coins.length + (change > 0n ? 1 : 0);
    if (compactOutputCount < 1 || compactOutputCount > 32) {
      throw new Error("one-proof batch transfer requires 1..32 outputs including change");
    }
    const outputCount = resolvedOutputMode === "exact32" ? 32 : compactOutputCount;

    const auditConfig = transferProtocolConfig.audit_config;
    if (auditDisclosureTargetPubKeyHex != null &&
        audit_disclosure_target_pubkey_hex != null &&
        String(auditDisclosureTargetPubKeyHex).trim().toLowerCase() !==
          String(audit_disclosure_target_pubkey_hex).trim().toLowerCase()) {
      throw new Error("auditDisclosureTargetPubKeyHex aliases conflict");
    }
    const requestedAuditPubKeyHex = String(
      auditDisclosureTargetPubKeyHex ?? audit_disclosure_target_pubkey_hex ?? ""
    ).trim().toLowerCase();
    if (requestedAuditPubKeyHex &&
        requestedAuditPubKeyHex !== String(auditConfig.audit_master_pubkey_hex || "").toLowerCase()) {
      throw new Error("batch transfer audit disclosure target must exactly match the active chain audit config");
    }
    const auditPubKeyHex = auditConfig.audit_master_pubkey_hex;
    const resolvedNowUnix = normalizedBatchNowUnix(
      chainNowUnix ?? chain_now_unix ?? Math.floor(Date.now() / 1000)
    );
    const resolvedExpiresAtUnix = expiresAtUnix ?? expires_at_unix ?? resolvedNowUnix + 1800;
    const expiry = normalizedBatchNowUnix(resolvedExpiresAtUnix);
    if (expiry <= resolvedNowUnix) throw new Error("batch transfer expiresAtUnix must be later than chainNowUnix");
    let reservationBatch = null;
    let payloadCheckpointStarted = false;
    let proofCheckpointStarted = false;
    let checkpointedPayloadHash = "";
    try {
      reservationBatch = await preparePlanReservation(resolvedReservationManager, {
        plan,
        kind: "batch_transfer",
        metadata: {
          batch_transfer_payment_count: preparedPayments.length,
          batch_transfer_output_mode: resolvedOutputMode,
          // CircuitConfig v1 exposes the active identity as a structured
          // `circuit_set_identity`.  Reservation metadata is deliberately
          // JSON-only, so never persist the absent legacy shorthand here:
          // `undefined` causes the reservation to fail before the prover is
          // called and hides an otherwise valid batch behind a generic UI
          // preparation error.
          circuit_set_id:
            transferProtocolConfig.circuit_config.circuit_set_identity
              .circuit_set_id,
          max_inputs: 16,
          max_outputs: 32
        }
      });
      const heartbeatResult = await withReservationHeartbeat(resolvedReservationManager, reservationBatch, async ({ assertHeartbeatHealthy, heartbeatNow }) => {
        const commitmentHexes = selectedInputs.map(found => fieldHexV1(computeNoteCommitmentV1(found.note)));
        const treeState = hasPinnedRoot ? null : await this.fetchTreeState();
        const resolvedRootHex = String(suppliedRootHex || treeState?.root || treeState?.root_hex || treeState?.rootHex || "").trim();
        if (!resolvedRootHex) throw new Error("one-proof batch transfer requires a verified current tree root");
        const pathProvider = await this.createCommitmentPathSnapshotProvider({
          commitmentHexes,
          rootHex: resolvedRootHex,
          ...(hasPinnedSnapshotHeight ? { snapshotHeight: suppliedSnapshotHeight } : {})
        });
        const preparedInputs = await Promise.all(selectedInputs.map(async found => {
          const path = await pathProvider.lookupMerklePath(fieldHexV1(computeNoteCommitmentV1(found.note)));
          return {
            note: found.note,
            merklePath: path.path,
            merklePathHelper: path.path_helper
          };
        }));
        const ownerSpend = deriveSpendKeys(privacy.rootSeed).pubKey;
        const ownerView = deriveViewKeys(privacy.rootSeed).pubKey;
        const assetID = computeAssetIdV1(batchDenom);
        const outputs = preparedPayments.map(payment => {
          const recipientKeys = decodeShieldedAddress(payment.recipient, { shieldedPrefix: this.shieldedPrefix });
          return {
            kind: "payment",
            note: createNote({
              spendPubKey: recipientKeys.spendPubKey,
              viewPubKey: recipientKeys.viewPubKey,
              amount: payment.coin.amount,
              assetId: assetID,
              randomness: randomBatchField(),
              memo: payment.memo
            }),
            privacyPolicy: payment.privacyPolicy,
            disclosureMode: payment.disclosureMode,
            ...(payment.privacyPolicy !== 0 && payment.disclosureMode === 2
              ? { disclosureTargetPubKey: payment.userDisclosureTargetPubKeyHex }
              : {}),
            userDisclosureBlinding: payment.privacyPolicy === 0 ? 0n : randomBatchField(),
            fullDisclosureBlinding: randomBatchField()
          };
        });
        if (change > 0n) {
          outputs.push({
            kind: "change",
            note: createNote({
              spendPubKey: ownerSpend,
              viewPubKey: ownerView,
              amount: change,
              assetId: assetID,
              randomness: randomBatchField(),
              memo: "Change"
            }),
            privacyPolicy: 0,
            disclosureMode: 0,
            userDisclosureBlinding: 0n,
            fullDisclosureBlinding: randomBatchField()
          });
        }
        while (outputs.length < outputCount) {
          outputs.push({
            kind: "padding",
            note: createNote({
              spendPubKey: ownerSpend,
              viewPubKey: ownerView,
              amount: 0n,
              assetId: assetID,
              randomness: randomBatchField(),
              memo: "Padding"
            }),
            privacyPolicy: 0,
            disclosureMode: 0,
            userDisclosureBlinding: 0n,
            fullDisclosureBlinding: randomBatchField()
          });
        }
        const spendSigner = createSpendNoteHashSigner(privacy.rootSeed);
        const selfViewTarget = selfViewDisclosureTargetPubKeyHex
          || self_view_disclosure_target_pubkey
          || deriveDisclosureKeys(privacy.rootSeed).pubKey;
        const payload = await buildPreparedBatchTransferPayload({
          creator: privacy.address,
          chainId: this.chainId,
          expiresAtUnix: expiry,
          root: resolvedRootHex,
          inputs: preparedInputs,
          outputs,
          auditKeyId: auditConfig.audit_key_id,
          auditKeyEpoch: auditConfig.audit_key_epoch,
          auditDisclosureTargetPubKey: auditPubKeyHex,
          selfViewDisclosureTargetPubKey: selfViewTarget,
          disableSelfViewDisclosure: resolvedDisableSelfViewDisclosure,
          signer: {
            signBatchTransfer: request => spendSigner.signNoteHash(request.expectedIntent)
          }
        });
        validatePreparedBatchTransferPayloadEnvelope(payload, { nowUnix: resolvedNowUnix });
        const operationId = reservationBatch?.operation_id || `batch:${payload.payload_hash}`;
        const expectedOutputs = buildBatchTransferExpectedOutputEvidence({
          payload,
          payments: preparedPayments,
          operationId,
          denom: batchDenom,
          shieldedPrefix: this.shieldedPrefix,
          nowUnix: resolvedNowUnix
        });
        if (persistPreparedPayload) {
          payloadCheckpointStarted = true;
          checkpointedPayloadHash = payload.payload_hash;
          await persistPreparedPayload(payload, {
            operationId,
            reservation: reservationBatchSummary(reservationBatch)
          });
        }
        const {
          proof,
          message,
          effects
        } = await this.provePreparedBatchTransfer({
          payload,
          proverAdapter,
          creator: privacy.address,
          denom: batchDenom,
          operationId,
          reservation: reservationBatchSummary(reservationBatch),
          nowUnix: resolvedNowUnix,
          signal,
          onPreparedProof: persistPreparedProof
            ? preparedProof => {
                proofCheckpointStarted = true;
                checkpointedPayloadHash = payload.payload_hash;
                return persistPreparedProof(preparedProof, {
                  payload,
                  operationId,
                  reservation: reservationBatchSummary(reservationBatch)
                });
              }
            : undefined
        });
        assertHeartbeatHealthy();
        const signDoc = await this.buildDirectSignDoc({
          signer: privacy.address,
          pubKeyHex: privacy.pubKeyHex,
          gasLimit: resolvedGasLimit,
          feeAmount: resolvedFeeAmount,
          messages: [{
            typeUrl: msgBatchTransferTypeUrl,
            value: MsgBatchTransfer.fromPartial(message)
          }],
          memo: reservationBatch
            ? reservationRequiredCosmosMemo("Clairveil batch veiled transfer")
            : "Clairveil batch veiled transfer"
        });
        const signDocHash = cosmosSignDocBindingHash(signDoc);
        const operationEvidence = buildBatchTransferOperationEvidence({
          payload,
          proof,
          payments: preparedPayments,
          expectedOutputs,
          operationId,
          denom: batchDenom,
          shieldedPrefix: this.shieldedPrefix,
          nowUnix: resolvedNowUnix
        });
        const artifact = await buildPreparedExecutionArtifact({
          executionBuilder,
          executionInput: {
            payload,
            proof,
            message,
            operationEvidence: operationEvidence.evidence,
            operationEvidenceHash: operationEvidence.evidenceHash,
            reservation: reservationBatchSummary(reservationBatch)
          },
          buildSignDoc: () => this.buildDirectSignDoc({
            signer: privacy.address,
            pubKeyHex: privacy.pubKeyHex,
            gasLimit,
            feeAmount: resolvedFeeAmount,
            messages: [{
              typeUrl: msgBatchTransferTypeUrl,
              value: MsgBatchTransfer.fromPartial(message)
            }],
            memo: reservationBatch
              ? reservationRequiredCosmosMemo("Clairveil batch veiled transfer")
              : "Clairveil batch veiled transfer"
          })
        });
        await heartbeatNow();
        await markReservationProofReadyForBatchItems(resolvedReservationManager, reservationBatch, [{
          notes: selectedInputs,
          metadata: {
            payloadHash: payload.payload_hash,
            ...artifact.executionBinding,
            expectedOperationEvidenceHash: operationEvidence.evidenceHash,
            operationSuccessEvidenceRequired: true,
            metadata: {
              payload_expires_at_unix: String(payload.expires_at_unix),
              batch_transfer_input_count: selectedInputs.length,
              batch_transfer_output_count: payload.outputs.length,
              batch_transfer_output_mode: resolvedOutputMode,
              input_nullifier_hexes: effects.nullifier_hexes,
              batch_transfer_nullifier_hexes: effects.nullifier_hexes,
              batch_transfer_output_commitment_hexes: effects.output_commitment_hexes,
              batch_transfer_operation_evidence: operationEvidence.evidence,
              batch_transfer_operation_evidence_hash: operationEvidence.evidenceHash
            }
          }
        }]);
        return {
          payload,
          proof,
          message,
          operationEvidence: operationEvidence.evidence,
          operationEvidenceHash: operationEvidence.evidenceHash,
          ...(artifact.signDoc ? {
            signDoc: markCosmosSignDocReservationRequired(artifact.signDoc, reservationBatch)
          } : {}),
          ...(artifact.execution ? { execution: artifact.execution } : {})
        };
      });
      const {
        payload,
        proof,
        message,
        signDoc,
        execution,
        operationEvidence,
        operationEvidenceHash
      } = heartbeatResult;

      return {
        ...reservationReconciliationFields(heartbeatResult),
        status: "ready",
        plan,
        scan: scanResult,
        ...(signDoc ? { signDoc } : {}),
        ...(execution ? { execution } : {}),
        payload,
        proof,
        message,
        operationEvidence,
        operationEvidenceHash,
        reservation: reservationBatchSummary(reservationBatch),
        prepared: {
          planAction: "batch_transfer",
          payments: preparedPayments.map(payment => ({
            itemId: payment.itemId,
            amount: payment.coin.raw,
            recipient: payment.recipient,
            privacyPolicy: payment.policyName,
            disclosureMode: payment.modeName
          })),
          amounts: preparedPayments.map(payment => payment.coin.raw),
          ...(preparedPayments.every(payment => payment.recipient === preparedPayments[0].recipient)
            ? { recipient: preparedPayments[0].recipient }
            : {}),
          outputMode: resolvedOutputMode,
          selectedInputTotal: selectedTotal.toString(),
          inputCount: selectedInputs.length,
          outputCount: payload.outputs.length,
          reservation: reservationBatchSummary(reservationBatch)
        },
        privacyAccount: publicPrivacyAccount(privacy)
      };
    } catch (error) {
      const cleanupErrors = [];
      if ((payloadCheckpointStarted || proofCheckpointStarted) && reservationBatch?.reservation_ids?.length) {
        try {
          if (typeof resolvedReservationManager?.markManualReview !== "function") {
            throw new Error("reservationManager.markManualReview is required after a batch artifact checkpoint starts");
          }
          await resolvedReservationManager.markManualReview(reservationBatch.reservation_ids, {
            leaseToken: reservationBatch.lease_token || reservationBatch.reservations?.[0]?.lease_token || "",
            error: "batch_checkpointed_artifact_requires_recovery",
            metadata: {
              reconcile_reason: "batch_checkpointed_artifact_requires_recovery",
              batch_payload_checkpoint_started: payloadCheckpointStarted,
              batch_proof_checkpoint_started: proofCheckpointStarted,
              ...(checkpointedPayloadHash ? { batch_transfer_payload_hash: checkpointedPayloadHash } : {})
            }
          });
        } catch (cleanupError) {
          cleanupErrors.push(cleanupError);
        }
        appendReservationCleanupErrors(error, cleanupErrors);
        throw error;
      }
      try {
        await replanProofReadyReservations(resolvedReservationManager, reservationBatch, error, "batch_prepare_failed_after_partial_proof_ready");
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
      try {
        await rollbackPlanReservation(resolvedReservationManager, reservationBatch);
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
      appendReservationCleanupErrors(error, cleanupErrors);
      throw error;
    }
  }

  /**
   * Resume only the proof stage of a durably checkpointed batch payload without
   * rebuilding or re-signing its owner intent. The caller must restore the
   * original operation/reservations and complete ProofReady finalization before
   * signing or broadcasting. The same selected prover is called once.
   */
  async provePreparedBatchTransfer({
    payload,
    proverAdapter,
    creator,
    denom,
    operationId,
    operation_id,
    reservation,
    reservationBatch,
    reservation_batch,
    nowUnix,
    chainNowUnix,
    chain_now_unix,
    signal,
    onPreparedProof,
    on_prepared_proof
  } = {}) {
    if (!this.enableExperimentalBatchTransfer) {
      throw new Error("one-proof batch transfer is feature-gated; construct the client with enableExperimentalBatchTransfer: true after completing downstream conformance and localnet validation");
    }
    if (!proverAdapter || typeof proverAdapter.proveBatchTransfer !== "function") {
      throw new Error("provePreparedBatchTransfer requires a proverAdapter with proveBatchTransfer(payload)");
    }
    if (operationId != null && operation_id != null &&
        String(operationId) !== String(operation_id)) {
      throw new Error("operationId aliases conflict");
    }
    const reservationAliases = [reservation, reservationBatch, reservation_batch]
      .filter(value => value != null);
    if (reservationAliases.length > 1 &&
        reservationAliases.some(value => value !== reservationAliases[0])) {
      throw new Error("reservation aliases conflict");
    }
    if (onPreparedProof != null && on_prepared_proof != null &&
        onPreparedProof !== on_prepared_proof) {
      throw new Error("onPreparedProof aliases conflict");
    }
    const persistPreparedProof = onPreparedProof ?? on_prepared_proof;
    if (typeof persistPreparedProof !== "function") {
      throw new Error("provePreparedBatchTransfer requires onPreparedProof to durably persist the private proof");
    }
    const resolvedOperationID = String(operationId ?? operation_id ?? "").trim();
    if (!resolvedOperationID) {
      throw new Error("provePreparedBatchTransfer requires the original operationId");
    }
    const resolvedReservation = reservation ?? reservationBatch ?? reservation_batch ?? null;
    if (!resolvedReservation) {
      throw new Error("provePreparedBatchTransfer requires the original reservation batch");
    }
    const reservationOperationID = String(
      resolvedReservation.operation_id ?? resolvedReservation.operationId ?? ""
    ).trim();
    if (reservationOperationID && reservationOperationID !== resolvedOperationID) {
      throw new Error("prepared batch transfer operationId does not match the reservation batch");
    }
    const resolvedNowUnix = normalizedBatchNowUnix(
      chainNowUnix ?? chain_now_unix ?? nowUnix ?? Math.floor(Date.now() / 1000)
    );
    validatePreparedBatchTransferPayloadEnvelope(payload, { nowUnix: resolvedNowUnix });
    const resolvedDenom = canonicalAssetDenomV1(denom ?? this.defaultDenom);
    const transferProtocolConfig = await this.assertTransferProtocolConfig(resolvedDenom);
    assertPreparedBatchTransferMatchesActiveConfig(payload, transferProtocolConfig, resolvedDenom);
    const effects = preparedBatchTransferEffectHex(payload);
    assertBatchTransferNullifiersUnspent(
      await this.checkNullifiers(effects.nullifier_hexes),
      effects.nullifier_hexes
    );
    const proofResponse = await proverAdapter.proveBatchTransfer(payload, { signal });
    if (proofResponse?.proof && typeof proofResponse.proof === "object" &&
        proofResponse.version !== batchTransferProofResponseVersion) {
      throw new Error(`unsupported batch transfer proof response version ${JSON.stringify(proofResponse.version)}`);
    }
    const proof = normalizePreparedBatchTransferProof(
      payload,
      proofResponse?.proof && typeof proofResponse.proof === "object" ? proofResponse.proof : proofResponse,
      { nowUnix: resolvedNowUnix }
    );
    await persistPreparedProof(proof, {
      payload,
      operationId: resolvedOperationID,
      reservation: resolvedReservation
    });
    assertBatchTransferNullifiersUnspent(
      await this.checkNullifiers(effects.nullifier_hexes),
      effects.nullifier_hexes
    );
    const message = buildMsgBatchTransferFromPrepared(payload, proof, {
      creator,
      nowUnix: resolvedNowUnix
    });
    return {
      payload,
      proof,
      message,
      effects,
      proofStageOnly: true,
      reservationFinalizationRequired: true
    };
  }

  /**
   * Complete the local stage after a checkpointed batch proof has been
   * restored. This derives the message and operation evidence from the exact
   * payload/proof, creates either the reservation-bound Cosmos sign doc or a
   * caller-supplied execution artifact, and atomically advances every reserved
   * input to ProofReady. It performs no broadcast request.
   */
  async finalizePreparedBatchTransfer({
    payload,
    proof,
    signer,
    pubKeyHex,
    gasLimit,
    gas_limit,
    feeAmount,
    fee_amount,
    memo = "Clairveil batch veiled transfer",
    payments,
    amounts,
    recipient,
    userPrivacyPolicy = "all-private",
    userDisclosureMode = "none",
    userDisclosureTargetPubKeyHex = "",
    expectedRecipientHash,
    expected_recipient_hash,
    expectedRecipientHashes,
    expected_recipient_hashes,
    expectedAmountHashes,
    expected_amount_hashes,
    denom,
    operationId,
    operation_id,
    reservationManager,
    reservation_manager,
    reservation,
    reservationBatch,
    reservation_batch,
    chainNowUnix,
    chain_now_unix,
    executionBuilder
  } = {}) {
    if (!this.enableExperimentalBatchTransfer) {
      throw new Error("one-proof batch transfer is feature-gated; construct the client with enableExperimentalBatchTransfer: true after completing downstream conformance and localnet validation");
    }
    const resolvedGasLimit = resolveCosmosGasLimit(gasLimit, gas_limit, 25000000);
    const resolvedFeeAmount = resolveCosmosFeeAmount(feeAmount, fee_amount);
    if (operationId != null && operation_id != null && String(operationId) !== String(operation_id)) {
      throw new Error("operationId aliases conflict");
    }
    if (chainNowUnix != null && chain_now_unix != null && Number(chainNowUnix) !== Number(chain_now_unix)) {
      throw new Error("batch transfer chainNowUnix aliases conflict");
    }
    if (reservationManager != null && reservation_manager != null && reservationManager !== reservation_manager) {
      throw new Error("reservationManager aliases conflict");
    }
    const reservationAliases = [reservation, reservationBatch, reservation_batch]
      .filter(value => value != null);
    if (reservationAliases.length > 1 && reservationAliases.some(value => value !== reservationAliases[0])) {
      throw new Error("reservation aliases conflict");
    }
    const resolvedReservationManager = reservationManager ?? reservation_manager ?? null;
    if (!resolvedReservationManager) {
      throw new Error("finalizePreparedBatchTransfer requires the original reservationManager");
    }
    const resolvedReservation = reservation ?? reservationBatch ?? reservation_batch ?? null;
    if (!resolvedReservation?.reservation_ids?.length) {
      throw new Error("finalizePreparedBatchTransfer requires the original reservation batch");
    }
    const resolvedOperationID = String(operationId ?? operation_id ?? "").trim();
    if (!resolvedOperationID) {
      throw new Error("finalizePreparedBatchTransfer requires the original operationId");
    }
    const reservationOperationID = String(
      resolvedReservation.operation_id ?? resolvedReservation.operationId ?? ""
    ).trim();
    if (reservationOperationID && reservationOperationID !== resolvedOperationID) {
      throw new Error("prepared batch transfer operationId does not match the reservation batch");
    }
    const currentReservations = typeof resolvedReservationManager.getReservations === "function"
      ? await resolvedReservationManager.getReservations(resolvedReservation.reservation_ids)
      : resolvedReservation.reservations || [];
    if (currentReservations.some(item => item.status === reservationStatuses.ManualReview)) {
      throw new Error("ManualReview reservations require operator resolution before a new batch proof can be finalized");
    }
    const resolvedSigner = String(signer || "").trim();
    if (!resolvedSigner) {
      throw new Error(
        executionBuilder
          ? "finalizePreparedBatchTransfer requires the original batch creator"
          : "finalizePreparedBatchTransfer requires the original Cosmos signer"
      );
    }
    const resolvedNowUnix = normalizedBatchNowUnix(
      chainNowUnix ?? chain_now_unix ?? Math.floor(Date.now() / 1000)
    );
    validatePreparedBatchTransferPayloadEnvelope(payload, { nowUnix: resolvedNowUnix });
    const resolvedDenom = canonicalAssetDenomV1(denom ?? this.defaultDenom);
    const transferProtocolConfig = await this.assertTransferProtocolConfig(resolvedDenom);
    assertPreparedBatchTransferMatchesActiveConfig(payload, transferProtocolConfig, resolvedDenom);

    const normalizedPayments = normalizeBatchTransferPayments({
      payments,
      amounts,
      recipient,
      userPrivacyPolicy,
      userDisclosureMode,
      userDisclosureTargetPubKeyHex
    });
    const legacyOperationEvidence = resolveBatchOperationEvidence({
      amounts: normalizedPayments.map(payment => payment.amount),
      expectedRecipientHash,
      expected_recipient_hash,
      expectedRecipientHashes,
      expected_recipient_hashes,
      expectedAmountHashes,
      expected_amount_hashes
    });
    const resolvedPayments = normalizedPayments.map((payment, index) => {
      const legacyRecipientHash = legacyOperationEvidence.recipientHashes[index] || "";
      const legacyAmountHash = legacyOperationEvidence.amountHashes[index] || "";
      if (payment.expectedRecipientHash && legacyRecipientHash &&
          canonicalBatchEvidenceDigest(payment.expectedRecipientHash, `batch payment ${index} expected recipient hash`) !==
            canonicalBatchEvidenceDigest(legacyRecipientHash, `batch payment ${index} legacy expected recipient hash`)) {
        throw new Error(`batch payment ${index} expected recipient hash conflicts with the top-level evidence`);
      }
      if (payment.expectedAmountHash && legacyAmountHash &&
          canonicalBatchEvidenceDigest(payment.expectedAmountHash, `batch payment ${index} expected amount hash`) !==
            canonicalBatchEvidenceDigest(legacyAmountHash, `batch payment ${index} legacy expected amount hash`)) {
        throw new Error(`batch payment ${index} expected amount hash conflicts with the top-level evidence`);
      }
      return Object.freeze({
        ...payment,
        expectedRecipientHash: payment.expectedRecipientHash || legacyRecipientHash,
        expectedAmountHash: payment.expectedAmountHash || legacyAmountHash
      });
    });
    const preparedPayments = resolvedPayments.map((payment, index) => {
      const capabilities = assertTransferDisclosureCapabilities(transferProtocolConfig.disclosure_config, {
        userPrivacyPolicy: payment.userPrivacyPolicy,
        userDisclosureMode: payment.userDisclosureMode
      });
      const privacyPolicy = transferPrivacyPolicyNames.indexOf(capabilities.policy);
      const disclosureMode = transferDisclosureModeNames.indexOf(capabilities.mode);
      if (privacyPolicy !== 0 && disclosureMode === 2 && !payment.userDisclosureTargetPubKeyHex) {
        throw new Error(`batch transfer payment ${index} recipient-encrypted disclosure requires a disclosure target public key`);
      }
      const coin = parseCoin(payment.amount, resolvedDenom);
      if (coin.denom !== resolvedDenom) {
        throw new Error(`batch transfer payment ${index} denom must equal ${resolvedDenom}`);
      }
      return Object.freeze({ ...payment, privacyPolicy, disclosureMode, coin });
    });
    const normalizedProof = normalizePreparedBatchTransferProof(payload, proof, { nowUnix: resolvedNowUnix });
    const message = buildMsgBatchTransferFromPrepared(payload, normalizedProof, {
      creator: resolvedSigner,
      nowUnix: resolvedNowUnix
    });
    const expectedOutputs = buildBatchTransferExpectedOutputEvidence({
      payload,
      payments: preparedPayments,
      operationId: resolvedOperationID,
      denom: resolvedDenom,
      shieldedPrefix: this.shieldedPrefix,
      nowUnix: resolvedNowUnix
    });
    const operationEvidence = buildBatchTransferOperationEvidence({
      payload,
      proof: normalizedProof,
      expectedOutputs,
      operationId: resolvedOperationID,
      denom: resolvedDenom,
      shieldedPrefix: this.shieldedPrefix,
      nowUnix: resolvedNowUnix
    });
    const signDoc = await this.createBatchTransferSignDoc({
      signer: resolvedSigner,
      pubKeyHex,
      gasLimit: resolvedGasLimit,
      feeAmount: resolvedFeeAmount,
      message,
      memo,
      expectedCircuitIdentity:
        transferProtocolConfig.circuit_config.circuit_set_identity,
      chainNowUnix: resolvedNowUnix
    });
    const effects = preparedBatchTransferEffectHex(payload);
    const authoritativeReservation = await authoritativeBatchRecoveryReservation(
      resolvedReservationManager,
      resolvedReservation,
      {
        operationId: resolvedOperationID,
        nullifierHexes: effects.nullifier_hexes
      }
    );
    batchTransferNullifiersUnspent(
      await this.checkNullifiers(effects.nullifier_hexes),
      effects.nullifier_hexes
    );
    const artifact = await buildPreparedExecutionArtifact({
      executionBuilder,
      executionInput: {
        payload,
        proof: normalizedProof,
        message,
        operationEvidence: operationEvidence.evidence,
        operationEvidenceHash: operationEvidence.evidenceHash,
        reservation: reservationBatchSummary(resolvedReservation)
      },
      buildSignDoc: () => this.createBatchTransferSignDoc({
        signer: resolvedSigner,
        pubKeyHex,
        gasLimit,
        feeAmount: resolvedFeeAmount,
        message,
        memo,
        expectedCircuitIdentity:
          transferProtocolConfig.circuit_config.circuit_set_identity,
        chainNowUnix: resolvedNowUnix
      })
    });
    const persistedOutputMode = String(
      authoritativeReservation.reservations?.[0]?.metadata?.batch_transfer_output_mode ||
      (payload.outputs.length === 32 ? "exact32" : "compact")
    );
    await markReservationProofReady(resolvedReservationManager, authoritativeReservation, {
      payloadHash: payload.payload_hash,
      ...artifact.executionBinding,
      expectedOperationEvidenceHash: operationEvidence.evidenceHash,
      operationSuccessEvidenceRequired: true,
      metadata: {
        payload_expires_at_unix: String(payload.expires_at_unix),
        batch_transfer_input_count: effects.nullifier_hexes.length,
        batch_transfer_output_count: payload.outputs.length,
        batch_transfer_output_mode: persistedOutputMode,
        input_nullifier_hexes: effects.nullifier_hexes,
        batch_transfer_nullifier_hexes: effects.nullifier_hexes,
        batch_transfer_output_commitment_hexes: effects.output_commitment_hexes,
        batch_transfer_operation_evidence: operationEvidence.evidence,
        batch_transfer_operation_evidence_hash: operationEvidence.evidenceHash
      }
    });
    return {
      payload,
      proof: normalizedProof,
      message,
      effects,
      operationEvidence: operationEvidence.evidence,
      operationEvidenceHash: operationEvidence.evidenceHash,
      signDoc: markCosmosSignDocReservationRequired(signDoc, authoritativeReservation),
      reservation: reservationBatchSummary(authoritativeReservation)
    };
  }

  async prepareWithdraw({
    wallet,
    material,
    amount,
    recipient,
    proverAdapter,
    signal,
    denom,
    assetDenom,
    scan,
    after,
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page,
    limit = 200,
    maxPages,
    max_pages,
    eventTypes,
    event_types,
    outputLimit,
    output_limit,
    eventLimit,
    event_limit,
    maxEncodedBytes,
    max_encoded_bytes,
    scanSource,
    scan_source,
    strictPrivacyScan,
    strict_privacy_scan,
    expiresAtUnix,
    expires_at_unix,
    chainNowUnix,
    chain_now_unix,
    gasLimit,
    gas_limit,
    feeAmount,
    fee_amount,
    reservationManager,
    reservation_manager,
    executionBuilder
  } = {}) {
    if (executionBuilder != null && typeof executionBuilder !== "function") {
      throw new Error("executionBuilder must be a function");
    }
    const resolvedGasLimit = resolveCosmosGasLimit(gasLimit, gas_limit, 5000000);
    const resolvedFeeAmount = resolveCosmosFeeAmount(feeAmount, fee_amount);
    const resolvedExpiresAtUnix = resolveUnixTimestampAlias(
      expiresAtUnix,
      expires_at_unix,
      "expiresAtUnix"
    );
    const resolvedChainNowUnix = resolveUnixTimestampAlias(
      chainNowUnix,
      chain_now_unix,
      "chainNowUnix"
    );
    const resolvedReservationManager = reservationManager ?? reservation_manager ?? null;
    const resolvedGasLimit = resolveCosmosGasLimit(gasLimit, gas_limit, 5000000);
    const resolvedFeeAmount = resolveCosmosFeeAmount(feeAmount, fee_amount);
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const scanOptions = resolveWalletScanOptions({
      scan,
      after,
      afterHeight,
      after_height,
      afterSequence,
      after_sequence,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types,
      outputLimit,
      output_limit,
      eventLimit,
      event_limit,
      maxEncodedBytes,
      max_encoded_bytes,
      scanSource,
      scan_source,
      strictPrivacyScan,
      strict_privacy_scan
    });
    const scanResult = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      allowInitialPrivacyScanFallback: true,
      includeFoundNotes: true
    });
    const availableFoundNotes = await reservationAvailableNotes(resolvedReservationManager, scanResult.foundNotes);
    const plan = planWithdrawNotes({
      notes: availableFoundNotes,
      amount,
      denom: assetDenom ?? denom ?? this.defaultDenom
    });
    if (!plan.canBuildTx) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    assertPlanCanBuildTx(plan);
    await this.assertProtocolPreflight(assetDenom ?? denom ?? this.defaultDenom);

    let reservationBatch = null;
    try {
      reservationBatch = await preparePlanReservation(resolvedReservationManager, {
        plan,
        kind: "withdraw",
        metadata: {
          amount,
          recipient
        }
      });
      const heartbeatResult = await withReservationHeartbeat(resolvedReservationManager, reservationBatch, async ({ assertHeartbeatHealthy, heartbeatNow }) => {
        const built = await this.buildWithdrawMessage({
          proverAdapter,
          creator: privacy.address,
          notes: [plan.selectedNote],
          amount,
          assetDenom: assetDenom ?? denom ?? this.defaultDenom,
          recipient,
          rootSeed: privacy.rootSeed,
          chainId: this.chainId,
          expiresAtUnix: resolvedExpiresAtUnix,
          chainNowUnix: resolvedChainNowUnix,
          signal
        });
        assertHeartbeatHealthy();
        const signDoc = await this.buildDirectSignDoc({
          signer: privacy.address,
          pubKeyHex: privacy.pubKeyHex,
          gasLimit: resolvedGasLimit,
          feeAmount: resolvedFeeAmount,
          messages: [
            {
              typeUrl: msgWithdrawTypeUrl,
              value: built.message
            }
          ],
          memo: reservationBatch
            ? reservationRequiredCosmosMemo("Clairveil veiled withdraw")
            : "Clairveil veiled withdraw"
        });
        await heartbeatNow();
        await markReservationProofReady(
          resolvedReservationManager,
          reservationBatch,
          withdrawProofReadyMetadata(built, {
            signDocHash,
            accountPrefix: this.accountPrefix,
            bindOperationSuccess: Boolean(reservationBatch)
          })
        );
        return {
          built,
          ...(artifact.signDoc ? {
            signDoc: markCosmosSignDocReservationRequired(
              artifact.signDoc,
              reservationBatch
            )
          } : {}),
          ...(artifact.execution ? { execution: artifact.execution } : {})
        };
      });
      const { built, signDoc, execution } = heartbeatResult;

      return {
        ...reservationReconciliationFields(heartbeatResult),
        status: "ready",
        plan,
        scan: scanResult,
        ...(signDoc ? { signDoc } : {}),
        ...(execution ? { execution } : {}),
        proverPayload: built.proverPayload,
        proof: built.proof,
        payload: built.payload,
        message: built.message,
        selectedNote: built.selectedNote,
        reservation: reservationBatchSummary(reservationBatch),
        privacyAccount: publicPrivacyAccount(privacy)
      };
    } catch (error) {
      await rollbackPlanReservationPreservingError(resolvedReservationManager, reservationBatch, error);
      throw error;
    }
  }

  async prepareRelayWithdraw({
    wallet,
    material,
    amount,
    recipient,
    proverAdapter,
    signal,
    denom,
    assetDenom,
    scan,
    after,
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page,
    limit = 200,
    maxPages,
    max_pages,
    eventTypes,
    event_types,
    outputLimit,
    output_limit,
    eventLimit,
    event_limit,
    maxEncodedBytes,
    max_encoded_bytes,
    scanSource,
    scan_source,
    strictPrivacyScan,
    strict_privacy_scan,
    expiresAtUnix,
    expires_at_unix,
    chainNowUnix,
    chain_now_unix,
    reservationManager,
    reservation_manager,
    executionBuilder
  } = {}) {
    const resolvedExpiresAtUnix = resolveUnixTimestampAlias(
      expiresAtUnix,
      expires_at_unix,
      "expiresAtUnix"
    );
    const resolvedChainNowUnix = resolveUnixTimestampAlias(
      chainNowUnix,
      chain_now_unix,
      "chainNowUnix"
    );
    const resolvedReservationManager = reservationManager ?? reservation_manager ?? null;
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const scanOptions = resolveWalletScanOptions({
      scan,
      after,
      afterHeight,
      after_height,
      afterSequence,
      after_sequence,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types,
      outputLimit,
      output_limit,
      eventLimit,
      event_limit,
      maxEncodedBytes,
      max_encoded_bytes,
      scanSource,
      scan_source,
      strictPrivacyScan,
      strict_privacy_scan
    });
    const scanResult = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      allowInitialPrivacyScanFallback: true,
      includeFoundNotes: true
    });
    const availableFoundNotes = await reservationAvailableNotes(resolvedReservationManager, scanResult.foundNotes);
    const plan = planWithdrawNotes({
      notes: availableFoundNotes,
      amount,
      denom: assetDenom ?? denom ?? this.defaultDenom
    });
    if (!plan.canBuildTx) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    assertPlanCanBuildTx(plan);
    await this.assertProtocolPreflight(assetDenom ?? denom ?? this.defaultDenom);

    let reservationBatch = null;
    try {
      reservationBatch = await preparePlanReservation(resolvedReservationManager, {
        plan,
        kind: "relay_withdraw"
      });
      const heartbeatResult = await withReservationHeartbeat(resolvedReservationManager, reservationBatch, async ({ assertHeartbeatHealthy, heartbeatNow }) => {
        const built = await this.buildRelayWithdrawPayload({
          proverAdapter,
          notes: [plan.selectedNote],
          amount,
          assetDenom: assetDenom ?? denom ?? this.defaultDenom,
          recipient,
          rootSeed: privacy.rootSeed,
          chainId: this.chainId,
          expiresAtUnix: resolvedExpiresAtUnix,
          chainNowUnix: resolvedChainNowUnix,
          signal
        });
        assertHeartbeatHealthy();
        let artifact = null;
        if (executionBuilder) {
          artifact = await buildPreparedExecutionArtifact({
            executionBuilder,
            executionInput: {
              payload: built.payload,
              proof: built.proof,
              proverPayload: built.proverPayload,
              selectedNote: built.selectedNote,
              plan,
              reservation: reservationBatchSummary(reservationBatch)
            },
            // A relayed Cosmos withdrawal remains a payload handoff until the
            // relayer is known. This callback is unreachable when the optional
            // execution builder is present and documents that boundary.
            buildSignDoc: () => {
              throw new Error("relay withdraw execution preparation requires executionBuilder");
            }
          });
        }
        await heartbeatNow();
        await markReservationProofReady(
          resolvedReservationManager,
          reservationBatch,
          withdrawProofReadyMetadata(built, {
            accountPrefix: this.accountPrefix,
            bindOperationSuccess: Boolean(reservationBatch)
          })
        );
        return { built };
      });
      const { built, execution } = heartbeatResult;

      return {
        ...reservationReconciliationFields(heartbeatResult),
        status: "ready",
        plan,
        scan: scanResult,
        proverPayload: built.proverPayload,
        proof: built.proof,
        payload: built.payload,
        selectedNote: built.selectedNote,
        ...(execution ? { execution } : {}),
        reservation: reservationBatchSummary(reservationBatch),
        privacyAccount: publicPrivacyAccount(privacy)
      };
    } catch (error) {
      await rollbackPlanReservationPreservingError(resolvedReservationManager, reservationBatch, error);
      throw error;
    }
  }

  async createDepositSignDoc(input) {
    return this.prepareDeposit(input);
  }

  async createTransferSignDoc(input) {
    if (input?.executionBuilder != null) {
      throw new Error("createTransferSignDoc does not accept executionBuilder");
    }
    const result = await this.prepareTransfer(input);
    if (result.status !== "ready") {
      throw new Error(result.plan?.message || `transfer is not ready: ${result.status}`);
    }
    if (!result.signDoc) throw new Error("transfer preparation did not produce a Cosmos sign doc");
    return result;
  }

  async createTransferBatchSignDoc(input) {
    if (input?.executionBuilder != null) {
      throw new Error("createTransferBatchSignDoc does not accept executionBuilder");
    }
    const result = await this.prepareTransferBatch(input);
    if (result.status !== "ready") {
      throw new Error(result.plan?.message || `transfer batch is not ready: ${result.status}`);
    }
    if (!result.signDoc) throw new Error("transfer batch preparation did not produce a Cosmos sign doc");
    return result;
  }

  async createBatchTransferSignDoc({
    signer,
    pubKeyHex,
    gasLimit,
    gas_limit,
    feeAmount,
    fee_amount,
    message,
    memo = "Clairveil batch veiled transfer",
    expectedCircuitIdentity,
    chainNowUnix,
    chain_now_unix
  } = {}) {
    if (!this.enableExperimentalBatchTransfer) {
      throw new Error("one-proof batch transfer is feature-gated; construct the client with enableExperimentalBatchTransfer: true after completing downstream conformance and localnet validation");
    }
    const resolvedGasLimit = resolveCosmosGasLimit(gasLimit, gas_limit, 25000000);
    const resolvedFeeAmount = resolveCosmosFeeAmount(feeAmount, fee_amount);
    if (!message || typeof message !== "object") {
      throw new Error("MsgBatchTransfer message is required");
    }
    const resolvedFeeAmount = resolveCosmosFeeAmount(feeAmount, fee_amount);
    if (chainNowUnix != null && chain_now_unix != null &&
        Number(chainNowUnix) !== Number(chain_now_unix)) {
      throw new Error("batch transfer chainNowUnix aliases conflict");
    }
    const normalizedMessage = MsgBatchTransfer.fromPartial(message);
    const normalizedSigner = String(signer || "").trim();
    const creator = String(normalizedMessage.creator || "").trim();
    if (!normalizedSigner || !creator || creator !== normalizedSigner) {
      throw new Error("MsgBatchTransfer creator must match the Cosmos sign-doc signer");
    }
    if (normalizedMessage.proof.length !== batchTransferProofSize) {
      throw new Error(`batch proof must be exactly ${batchTransferProofSize} bytes`);
    }
    const effects = validateBatchTransferEffectsV1(normalizedMessage);
    const resolvedNowUnix = normalizedBatchNowUnix(
      chainNowUnix ?? chain_now_unix ?? Math.floor(Date.now() / 1000)
    );
    if (BigInt(resolvedNowUnix) >= effects.expiresAtUnix) {
      throw new Error("MsgBatchTransfer expired before sign-doc creation");
    }
    const encodedMessage = MsgBatchTransfer.encode(normalizedMessage).finish();
    if (encodedMessage.length > maxBatchTransferMessageBytesV1) {
      throw new Error(`MsgBatchTransfer exceeds the ${maxBatchTransferMessageBytesV1}-byte hard cap`);
    }
    await this.assertCircuitConfig({ expectedCircuitIdentity });
    return this.buildDirectSignDoc({
      signer,
      pubKeyHex,
      gasLimit: resolvedGasLimit,
      feeAmount: resolvedFeeAmount,
      messages: [{
        typeUrl: msgBatchTransferTypeUrl,
        value: normalizedMessage
      }],
      memo
    });
  }

  async createWithdrawSignDoc(input) {
    if (input?.executionBuilder != null) {
      throw new Error("createWithdrawSignDoc does not accept executionBuilder");
    }
    const result = await this.prepareWithdraw(input);
    if (result.status !== "ready") {
      throw new Error(result.plan?.message || `withdraw is not ready: ${result.status}`);
    }
    if (!result.signDoc) throw new Error("withdraw preparation did not produce a Cosmos sign doc");
    return result;
  }

  async createRelayWithdrawPayload(input) {
    const result = await this.prepareRelayWithdraw(input);
    if (result.status !== "ready") {
      throw new Error(result.plan?.message || `relay withdraw is not ready: ${result.status}`);
    }
    return result;
  }

  async buildPreparedTransferPayload(input) {
    const transferDenom = input?.transferDenom ?? input?.denom ?? this.defaultDenom;
    const transferProtocolConfig = await this.assertTransferProtocolConfig(transferDenom);
    const boundInput = bindRawTransferBuilderProtocolConfig(input, transferProtocolConfig);
    const merklePathProvider = input?.merklePathProvider ??
      await this.createTransferMerklePathSnapshotProvider(input?.inputs);
    return buildPreparedTransferPayloadCore({
      ...boundInput,
      merklePathProvider,
      shieldedPrefix: this.shieldedPrefix,
      transferDenom,
      chainId: input?.chainId ?? this.chainId
    });
  }

  async buildTransferMessage(input) {
    const transferDenom = input?.transferDenom ?? input?.denom ?? this.defaultDenom;
    const transferProtocolConfig = await this.assertTransferProtocolConfig(transferDenom);
    const boundInput = bindRawTransferBuilderProtocolConfig(input, transferProtocolConfig);
    const merklePathProvider = input?.merklePathProvider ??
      await this.createTransferMerklePathSnapshotProvider(input?.inputs);
    return buildTransferMessageCore({
      ...boundInput,
      merklePathProvider,
      shieldedPrefix: this.shieldedPrefix,
      transferDenom,
      chainId: input?.chainId ?? this.chainId,
      checkNullifiers: input?.checkNullifiers ?? (nullifiers => this.checkNullifiers(nullifiers))
    });
  }

  async buildPreparedWithdrawProverPayload(input) {
    const assetDenom = input?.assetDenom ?? input?.denom ?? this.defaultDenom;
    await this.assertProtocolPreflight(assetDenom);
    return buildPreparedWithdrawProverPayloadCore({
      merklePathProvider: this,
      accountPrefix: this.accountPrefix,
      assetDenom,
      ...input,
      chainId: input?.chainId ?? this.chainId
    });
  }

  async buildRelayWithdrawPayload(input) {
    const assetDenom = input?.assetDenom ?? input?.denom ?? this.defaultDenom;
    await this.assertProtocolPreflight(assetDenom);
    return buildRelayWithdrawPayloadCore({
      merklePathProvider: this,
      accountPrefix: this.accountPrefix,
      assetDenom,
      ...input,
      chainId: input?.chainId ?? this.chainId,
      checkNullifiers: input?.checkNullifiers ?? (nullifiers => this.checkNullifiers(nullifiers))
    });
  }

  async buildWithdrawMessage(input) {
    const assetDenom = input?.assetDenom ?? input?.denom ?? this.defaultDenom;
    await this.assertProtocolPreflight(assetDenom);
    return buildWithdrawMessageCore({
      merklePathProvider: this,
      accountPrefix: this.accountPrefix,
      assetDenom,
      ...input,
      chainId: input?.chainId ?? this.chainId,
      checkNullifiers: input?.checkNullifiers ?? (nullifiers => this.checkNullifiers(nullifiers))
    });
  }

  buildRelayWithdrawMessageFromPayload({
    payload,
    relayer,
    creator,
    chainNowUnix,
    nowUnix,
    expectedChainId,
    expectedRecipient,
    accountPrefix
  } = {}) {
    if (!payload) {
      throw new Error("payload is required for relay withdraw");
    }
    return buildRelayWithdrawMsgFromPayloadCore(payload, relayer ?? creator, {
      chainNowUnix: chainNowUnix ?? nowUnix,
      expectedChainId: expectedChainId ?? this.chainId,
      expectedRecipient,
      accountPrefix: accountPrefix ?? this.accountPrefix
    });
  }

  async createRelayWithdrawSignDoc({
    payload,
    relayer,
    creator,
    pubKeyHex,
    pub_key_hex,
    gasLimit = 5000000,
    feeAmount = [],
    memo = "Clairveil relay withdraw",
    chainNowUnix,
    nowUnix,
    expectedChainId,
    expectedRecipient,
    accountPrefix
  } = {}) {
    const signer = relayer ?? creator;
    const message = this.buildRelayWithdrawMessageFromPayload({
      payload,
      relayer: signer,
      chainNowUnix: chainNowUnix ?? nowUnix,
      expectedChainId,
      expectedRecipient,
      accountPrefix
    });
    const signDoc = await this.buildDirectSignDoc({
      signer: String(signer || ""),
      pubKeyHex: pubKeyHex ?? pub_key_hex,
      gasLimit,
      feeAmount,
      messages: [
        {
          typeUrl: msgWithdrawTypeUrl,
          value: message
        }
      ],
      memo
    });
    return {
      status: "ready",
      relayer: message.creator,
      payload,
      message,
      signDoc
    };
  }

  async decodeUserDisclosure({
    output,
    scanOutput,
    txHash,
    tx_hash,
    address,
    pubKeyHex,
    pub_key_hex,
    signatureBase64,
    signature_base64,
    skipSignerPubKeyCheck,
    skip_signer_pubkey_check,
    disclosureScalar,
    disclosure_scalar,
    disclosureScalarHex,
    disclosure_scalar_hex,
    disclosurePubKeyHex,
    disclosure_pubkey_hex,
    assetDenom,
    asset_denom,
    ...eventQuery
  }) {
    const selectedOutput = output ?? scanOutput;
    const normalizedTxHash = String(txHash ?? tx_hash ?? "").trim().toUpperCase();
    const event = selectedOutput
      ? null
      : await this.findPrivacyEventByTxHash(normalizedTxHash, eventQuery);
    const disclosureAssetDenom = resolveDisclosureAssetDenom(assetDenom, asset_denom, this.defaultDenom);
    const publicMode = selectedOutput
      ? (selectedOutput.userDisclosureMode ?? selectedOutput.user_disclosure_mode) === "USER_DISCLOSURE_MODE_PUBLIC"
      : eventAttribute(event, "user_disclosure_mode") === "USER_DISCLOSURE_MODE_PUBLIC";
    if (publicMode) {
      const decode = selectedOutput ? decodeUserDisclosureFromScanOutput : decodeUserDisclosureFromEvent;
      return decode(
        selectedOutput ?? event,
        1n,
        "",
        normalizedTxHash,
        { shieldedPrefix: this.shieldedPrefix, assetDenom: disclosureAssetDenom }
      );
    }
    const signerPubKeyHex = pubKeyHex ?? pub_key_hex;
    const skipSignerCheck = Boolean(skipSignerPubKeyCheck ?? skip_signer_pubkey_check);
    if (!skipSignerCheck) {
      assertSignerPubKey(address, signerPubKeyHex, this.bech32Prefix);
    }
    const material = derivePrivacyMaterial({
      address,
      pubKeyHex: signerPubKeyHex,
      signatureBase64: signatureBase64 ?? signature_base64,
      shieldedPrefix: this.shieldedPrefix
    });
    const decode = selectedOutput ? decodeUserDisclosureFromScanOutput : decodeUserDisclosureFromEvent;
    return decode(
      selectedOutput ?? event,
      material.disclosureScalar,
      material.disclosurePubKeyHex,
      normalizedTxHash,
      { shieldedPrefix: this.shieldedPrefix, assetDenom: disclosureAssetDenom }
    );
  }

  async decodeSelfViewDisclosure({
    output,
    scanOutput,
    txHash,
    tx_hash,
    address,
    pubKeyHex,
    pub_key_hex,
    signatureBase64,
    signature_base64,
    skipSignerPubKeyCheck,
    skip_signer_pubkey_check,
    disclosureScalar,
    disclosure_scalar,
    disclosureScalarHex,
    disclosure_scalar_hex,
    assetDenom,
    asset_denom,
    ...eventQuery
  }) {
    const selectedOutput = output ?? scanOutput;
    const normalizedTxHash = String(txHash ?? tx_hash ?? "").trim().toUpperCase();
    const event = selectedOutput
      ? null
      : await this.findPrivacyEventByTxHash(normalizedTxHash, eventQuery);
    const disclosureAssetDenom = resolveDisclosureAssetDenom(assetDenom, asset_denom, this.defaultDenom);
    const directScalar = disclosureScalar ?? disclosure_scalar;
    const directScalarHex = disclosureScalarHex ?? disclosure_scalar_hex;
    const selectedOutput = resolveDisclosureOutputAlias(output, scanOutput, "disclosure output");
    const normalizedTxHash = selectedOutput && txHash == null && tx_hash == null
      ? undefined
      : normalizedCosmosTxHash(txHash ?? tx_hash);
    if (selectedOutput && (directScalar != null || directScalarHex != null)) {
      return decodeSelfViewDisclosureFromScanOutput(selectedOutput, {
        disclosureScalar: directScalar != null ? directScalar : disclosureScalarFromHex(directScalarHex),
        txHash: normalizedTxHash,
        shieldedPrefix: this.shieldedPrefix,
        assetDenom: disclosureAssetDenom
      });
    }
    if (directScalar != null || directScalarHex != null) {
      const decode = selectedOutput ? decodeSelfViewDisclosureFromScanOutput : decodeSelfViewDisclosureFromEvent;
      return decode(
        selectedOutput ?? event,
        directScalar != null ? directScalar : disclosureScalarFromHex(directScalarHex),
        normalizedTxHash,
        { shieldedPrefix: this.shieldedPrefix, assetDenom: disclosureAssetDenom }
      );
    }
    const signerPubKeyHex = pubKeyHex ?? pub_key_hex;
    const skipSignerCheck = Boolean(skipSignerPubKeyCheck ?? skip_signer_pubkey_check);
    if (!skipSignerCheck) {
      assertSignerPubKey(address, signerPubKeyHex, this.bech32Prefix);
    }
    const material = derivePrivacyMaterial({
      address,
      pubKeyHex: signerPubKeyHex,
      signatureBase64: signatureBase64 ?? signature_base64,
      shieldedPrefix: this.shieldedPrefix
    });
    const decode = selectedOutput ? decodeSelfViewDisclosureFromScanOutput : decodeSelfViewDisclosureFromEvent;
    return decode(
      selectedOutput ?? event,
      material.disclosureScalar,
      normalizedTxHash,
      { shieldedPrefix: this.shieldedPrefix, assetDenom: disclosureAssetDenom }
    );
  }

  async decodeAuditDisclosure({
    output,
    scanOutput,
    txHash,
    tx_hash,
    disclosurePrivKeyHex,
    disclosure_privkey_hex,
    assetDenom,
    asset_denom,
    ...eventQuery
  }) {
    const selectedOutput = output ?? scanOutput;
    const normalizedTxHash = String(txHash ?? tx_hash ?? "").trim().toUpperCase();
    const event = selectedOutput
      ? null
      : await this.findPrivacyEventByTxHash(normalizedTxHash, eventQuery);
    const disclosureAssetDenom = resolveDisclosureAssetDenom(assetDenom, asset_denom, this.defaultDenom);
    const decode = selectedOutput ? decodeAuditDisclosureFromScanOutput : decodeAuditDisclosureFromEvent;
    return decode(
      selectedOutput ?? event,
      disclosureScalarFromHex(disclosurePrivKeyHex ?? disclosure_privkey_hex),
      normalizedTxHash,
      { shieldedPrefix: this.shieldedPrefix, assetDenom: disclosureAssetDenom }
    );
  }

  /**
   * Decode a Batch V1 user disclosure from a validated PrivacyScanOutputV2
   * record. Public records need no wallet material; recipient-encrypted
   * records can use either an explicit scalar/key pair or wallet-derived
   * privacy material.
   */
  async decodeBatchUserDisclosure({
    output,
    scanOutput,
    txHash,
    tx_hash,
    address,
    pubKeyHex,
    pub_key_hex,
    signatureBase64,
    signature_base64,
    skipSignerPubKeyCheck,
    skip_signer_pubkey_check,
    disclosureScalar,
    disclosure_scalar,
    disclosureScalarHex,
    disclosure_scalar_hex,
    disclosurePubKeyHex,
    disclosure_pubkey_hex,
    assetDenom,
    asset_denom
  } = {}) {
    const selectedOutput = resolveDisclosureOutputAlias(output, scanOutput, "batch disclosure output");
    if (!selectedOutput) throw new Error("Batch user disclosure requires a PrivacyScanOutputV2 output");
    const mode = selectedOutput.userDisclosureMode ?? selectedOutput.user_disclosure_mode;
    const isPublic = mode === 1 || mode === "1" || mode === "USER_DISCLOSURE_MODE_PUBLIC";
    const common = {
      txHash: txHash ?? tx_hash,
      shieldedPrefix: this.shieldedPrefix,
      assetDenom: resolveDisclosureAssetDenom(assetDenom, asset_denom, this.defaultDenom)
    };
    if (isPublic) return decodeBatchUserDisclosureFromScanOutput(selectedOutput, common);

    const directScalar = disclosureScalar ?? disclosure_scalar;
    const directScalarHex = disclosureScalarHex ?? disclosure_scalar_hex;
    const directPubKey = disclosurePubKeyHex ?? disclosure_pubkey_hex;
    if (directScalar != null || directScalarHex != null || directPubKey != null) {
      return decodeBatchUserDisclosureFromScanOutput(selectedOutput, {
        ...common,
        disclosureScalar: directScalar != null ? directScalar : disclosureScalarFromHex(directScalarHex),
        disclosurePubKeyHex: directPubKey
      });
    }
    const signerPubKeyHex = pubKeyHex ?? pub_key_hex;
    const skipSignerCheck = Boolean(skipSignerPubKeyCheck ?? skip_signer_pubkey_check);
    if (!skipSignerCheck) assertSignerPubKey(address, signerPubKeyHex, this.bech32Prefix);
    const material = derivePrivacyMaterial({
      address,
      pubKeyHex: signerPubKeyHex,
      signatureBase64: signatureBase64 ?? signature_base64,
      shieldedPrefix: this.shieldedPrefix
    });
    return decodeBatchUserDisclosureFromScanOutput(selectedOutput, {
      ...common,
      disclosureScalar: material.disclosureScalar,
      disclosurePubKeyHex: material.disclosurePubKeyHex
    });
  }

  /** Decode a Batch V1 self-view disclosure from a validated PrivacyScanOutputV2 record. */
  async decodeBatchSelfViewDisclosure({
    output,
    scanOutput,
    txHash,
    tx_hash,
    address,
    pubKeyHex,
    pub_key_hex,
    signatureBase64,
    signature_base64,
    skipSignerPubKeyCheck,
    skip_signer_pubkey_check,
    disclosureScalar,
    disclosure_scalar,
    disclosureScalarHex,
    disclosure_scalar_hex,
    assetDenom,
    asset_denom
  } = {}) {
    const selectedOutput = resolveDisclosureOutputAlias(output, scanOutput, "batch disclosure output");
    if (!selectedOutput) throw new Error("Batch self-view disclosure requires a PrivacyScanOutputV2 output");
    const common = {
      txHash: txHash ?? tx_hash,
      shieldedPrefix: this.shieldedPrefix,
      assetDenom: resolveDisclosureAssetDenom(assetDenom, asset_denom, this.defaultDenom)
    };
    const directScalar = disclosureScalar ?? disclosure_scalar;
    const directScalarHex = disclosureScalarHex ?? disclosure_scalar_hex;
    if (directScalar != null || directScalarHex != null) {
      return decodeBatchSelfViewDisclosureFromScanOutput(selectedOutput, {
        ...common,
        disclosureScalar: directScalar != null ? directScalar : disclosureScalarFromHex(directScalarHex)
      });
    }
    const signerPubKeyHex = pubKeyHex ?? pub_key_hex;
    const skipSignerCheck = Boolean(skipSignerPubKeyCheck ?? skip_signer_pubkey_check);
    if (!skipSignerCheck) assertSignerPubKey(address, signerPubKeyHex, this.bech32Prefix);
    const material = derivePrivacyMaterial({
      address,
      pubKeyHex: signerPubKeyHex,
      signatureBase64: signatureBase64 ?? signature_base64,
      shieldedPrefix: this.shieldedPrefix
    });
    return decodeBatchSelfViewDisclosureFromScanOutput(selectedOutput, {
      ...common,
      disclosureScalar: material.disclosureScalar
    });
  }

  /** Decode a Batch V1 auditor disclosure from a validated PrivacyScanOutputV2 record. */
  async decodeBatchAuditDisclosure({
    output,
    scanOutput,
    txHash,
    tx_hash,
    disclosurePrivKeyHex,
    disclosure_privkey_hex,
    disclosureScalar,
    disclosure_scalar,
    disclosureScalarHex,
    disclosure_scalar_hex,
    assetDenom,
    asset_denom
  } = {}) {
    const selectedOutput = resolveDisclosureOutputAlias(output, scanOutput, "batch disclosure output");
    if (!selectedOutput) throw new Error("Batch audit disclosure requires a PrivacyScanOutputV2 output");
    const directScalar = disclosureScalar ?? disclosure_scalar;
    const directScalarHex = disclosureScalarHex ?? disclosure_scalar_hex;
    return decodeBatchAuditDisclosureFromScanOutput(selectedOutput, {
      txHash: txHash ?? tx_hash,
      shieldedPrefix: this.shieldedPrefix,
      assetDenom: resolveDisclosureAssetDenom(assetDenom, asset_denom, this.defaultDenom),
      disclosureScalar: directScalar != null
        ? directScalar
        : disclosureScalarFromHex(directScalarHex ?? disclosurePrivKeyHex ?? disclosure_privkey_hex)
    });
  }

  async buildDirectSignDoc({ signer, pubKeyHex, messages, memo = "", gasLimit = 200000, feeAmount = [] }) {
    const resolvedGasLimit = normalizeCosmosGasLimit(gasLimit);
    const resolvedFeeAmount = normalizeCosmosFeeCoins(feeAmount);
    assertSignerPubKey(signer, pubKeyHex, this.bech32Prefix);
    const account = await this.getAccountInfo(signer);
    const pubkey = encodePubkey({
      type: "tendermint/PubKeySecp256k1",
      value: toBase64(fromHex(pubKeyHex, "pubKeyHex"))
    });
    const bodyBytes = this.registry.encodeTxBody({
      messages,
      memo
    });
    const authInfoBytes = makeAuthInfoBytes(
      [{ pubkey, sequence: account.sequence }],
      resolvedFeeAmount,
      resolvedGasLimit,
      undefined,
      undefined
    );
    const signDoc = makeSignDoc(bodyBytes, authInfoBytes, this.chainId, account.accountNumber);
    return {
      bodyBytes: toBase64(signDoc.bodyBytes),
      authInfoBytes: toBase64(signDoc.authInfoBytes),
      chainId: signDoc.chainId,
      accountNumber: signDoc.accountNumber.toString()
    };
  }

  buildTxRawBytes({ bodyBytes, authInfoBytes, signature }) {
    const txRaw = TxRaw.fromPartial({
      bodyBytes: fromBase64(bodyBytes, "bodyBytes"),
      authInfoBytes: fromBase64(authInfoBytes, "authInfoBytes"),
      signatures: [fromBase64(signature, "signature")]
    });
    return TxRaw.encode(txRaw).finish();
  }

  async _broadcastTxRawBytes(txBytes, signedTx, waitOptions) {
    const reservationContext = broadcastReservationContext(waitOptions || signedTx || {});
    const signDocHash = cosmosSignDocBindingHash(signedTx);
    const signedBatchTransfer = signedBatchTransferMessage(signedTx);
    const reservationRequired = cosmosSignDocMetadata(signedTx).reservationRequired ||
      cosmosTxBodyRequiresReservation(signedTx) ||
      Boolean(signedBatchTransfer);
    if (reservationRequired && !reservationContext) {
      throw new Error("prepared reserved Cosmos signed transaction requires reservationManager and reservation");
    }
    const txBytesHash = sha256Hex(txBytes);
    // A Cosmos transaction hash is SHA-256 over the exact TxRaw bytes. Keep
    // that network identity durable before the RPC boundary; the node may
    // accept these bytes even when its broadcast response is lost.
    const signedTxHash = txBytesHash.toUpperCase();
    const broadcastIdentity = {
      txHash: signedTxHash,
      txBytesHash,
      signDocHash
    };
    await validateRelayBroadcastContext(waitOptions || signedTx || {}, {
      expectedChainId: this.chainId,
      accountPrefix: this.accountPrefix,
      signedTx,
      reservationContext,
      signDocHash
    });
    const client = await this.connect();
    // Proof preparation checks nullifiers, but wallet signing can take
    // arbitrarily long. Re-read the exact reserved inputs at the final
    // broadcast boundary so a stale proof can never be submitted.
    await recheckReservedBatchTransferNullifiers(
      reservationContext,
      signedTx,
      nullifiers => this.checkNullifiers(nullifiers)
    );
    await recheckReservedDirectPrivacyNullifiers(
      reservationContext,
      signedTx,
      nullifiers => this.checkNullifiers(nullifiers)
    );
    // The exact wallet-produced privacy message is authoritative. Re-read
    // chain time only after the final nullifier check and block stale signed
    // bytes before either the durable attempt marker or the broadcast RPC.
    await assertSignedPrivacyFreshAtBroadcast(signedTx, waitOptions || signedTx || {}, {
      expectedChainId: this.chainId,
      accountPrefix: this.accountPrefix
    });
    await beginBroadcastReservation(
      reservationContext,
      "cosmos_broadcast_tx_sync",
      broadcastIdentity
    );
    let txhash = signedTxHash;
    let tx;
    try {
      // This hook is deliberately synchronous and directly adjacent to the
      // RPC invocation. All asynchronous validation and the durable attempt
      // marker have completed, so callers can fence session invalidation
      // without opening a new await gap before submission.
      runSynchronousBeforeBroadcast(waitOptions, broadcastIdentity);
    } catch (error) {
      const wrapped = attachBroadcastDisposition(
        attachBroadcastEvidence(error, broadcastIdentity),
        { rpcInvoked: false, broadcastAbortedBeforeRpc: true }
      );
      await markBroadcastReservationRejected(
        reservationContext,
        wrapped,
        { kind: "before_rpc" }
      );
      throw wrapped;
    }
    let rpcTxHash = "";
    try {
      // Do not reconstruct TxRaw here: callers may have checkpointed the
      // exact wallet-produced bytes for crash-safe retransmission.
      rpcTxHash = String(await client.broadcastTxSync(Uint8Array.from(txBytes)) || "").trim();
    } catch (error) {
      if (isExplicitCheckTxRejection(error)) {
        const wrapped = attachBroadcastDisposition(
          attachBroadcastEvidence(error, broadcastIdentity),
          { rpcInvoked: true, checkTxRejected: true }
        );
        await markBroadcastReservationRejected(reservationContext, wrapped, {
          kind: "check_tx",
          providerCode: error.code,
          providerCodespace: error.codespace,
          providerLog: error.log || ""
        });
        throw wrapped;
      }
      const wrapped = attachBroadcastDisposition(
        attachBroadcastEvidence(error, broadcastIdentity),
        { rpcInvoked: true }
      );
      await markBroadcastReservationUnknown(reservationContext, wrapped, broadcastIdentity);
      throw wrapped;
    }
    try {
      const normalizedRpcTxHash = normalizedCosmosTxHash(rpcTxHash);
      if (rpcTxHash && normalizedRpcTxHash !== signedTxHash) {
        const error = new Error("Cosmos broadcast returned a transaction hash that does not match the signed TxRaw bytes");
        error.code = "COSMOS_TX_HASH_MISMATCH";
        error.rpcTxHash = rpcTxHash;
        throw error;
      }
      txhash = signedTxHash;
      tx = await this.waitForTx(txhash, waitOptions);
      if (tx) {
        const indexedTxHash = normalizedCosmosTxHash(tx.txhash);
        if (!indexedTxHash || indexedTxHash !== signedTxHash) {
          const error = new Error("Indexed Cosmos transaction hash does not match the signed TxRaw bytes");
          error.code = "COSMOS_TX_HASH_MISMATCH";
          error.indexedTxHash = String(tx.txhash || "");
          error.tx = tx;
          throw error;
        }
      }
    } catch (error) {
      const wrapped = attachBroadcastDisposition(
        attachBroadcastEvidence(error, broadcastIdentity),
        { rpcInvoked: true }
      );
      await markBroadcastReservationUnknown(reservationContext, wrapped, broadcastIdentity);
      throw wrapped;
    }
    const rawTxCode = tx?.code;
    const txCode = typeof rawTxCode === "number"
      ? Number.isSafeInteger(rawTxCode) && rawTxCode >= 0 ? rawTxCode : null
      : typeof rawTxCode === "string" && /^(0|[1-9][0-9]*)$/.test(rawTxCode)
        ? Number(rawTxCode)
        : null;
    const rawLog = String(tx?.raw_log || "");
    const broadcast = {
      txhash,
      code: txCode,
      raw_log: tx ? rawLog : `transaction was broadcast but not found yet: ${txhash}`
    };
    if (tx && txCode !== 0) {
      const detail = txCode == null
        ? "missing or malformed code"
        : `code ${txCode}: ${rawLog || "no raw log"}`;
      const error = new Error(`broadcasted transaction did not include an explicit successful result (${detail})`);
      error.txhash = txhash;
      error.txHash = signedTxHash;
      error.txBytesHash = txBytesHash;
      error.broadcast = broadcast;
      error.tx = tx;
      await markBroadcastReservationUnknown(reservationContext, error, broadcastIdentity);
      throw error;
    }
    const result = {
      ok: Boolean(tx && txCode === 0),
      txHash: signedTxHash,
      broadcast,
      tx,
      txBytesHash,
      error: tx ? "" : broadcast.raw_log
    };
    if (result.ok) {
      await markBroadcastReservationSubmitted(reservationContext, broadcastIdentity);
    } else {
      await markBroadcastReservationUnknown(
        reservationContext,
        new Error(result.error),
        broadcastIdentity
      );
    }
    return result;
  }

  /**
   * Broadcast an exact pre-encoded TxRaw checkpoint. The bytes are decoded
   * only for reservation and relay validation and are never re-encoded before
   * the RPC boundary.
   */
  async broadcastTxRawBytes(txRawBytes, waitOptions) {
    const txBytes = normalizedTxRawBytes(txRawBytes);
    return this._broadcastTxRawBytes(txBytes, signedTxFromRawBytes(txBytes), waitOptions);
  }

  async broadcastSignedTx(signedTx, waitOptions) {
    const txBytes = this.buildTxRawBytes(signedTx);
    // Treat the encoded TxRaw checkpoint as authoritative. The caller-owned
    // SignedTx object remains mutable while async validation runs; decoding
    // the exact bytes prevents validation from drifting away from what the
    // RPC will receive.
    return this._broadcastTxRawBytes(txBytes, signedTxFromRawBytes(txBytes), waitOptions);
  }

  /**
   * Ask the wallet to sign, then return a checkpoint containing the exact
   * TxRaw bytes. Persist txRawBytes before calling broadcastTxRawBytes when a
   * process restart must be able to retransmit the same signed transaction.
   */
  async signDirect(input = {}) {
    const {
      wallet,
      walletSignDoc,
      reservationContext,
      signDocHash,
      broadcastOptions
    } = directBroadcastContext(input);
    const reservationRequired = cosmosSignDocMetadata(input.signDoc).reservationRequired ||
      cosmosTxBodyRequiresReservation(input.signDoc);
    if (reservationRequired && !reservationContext) {
      throw new Error("prepared reserved Cosmos sign doc requires reservationManager and reservation");
    }
    await validateRelayBroadcastContext(broadcastOptions, {
      expectedChainId: this.chainId,
      accountPrefix: this.accountPrefix,
      signedTx: walletSignDoc,
      reservationContext,
      signDocHash
    });
    const adapter = createWalletAdapter(wallet);
    let signed;
    try {
      signed = await adapter.signDirect(directSignDocFromBase64(walletSignDoc), {
        signDoc: walletSignDoc
      });
    } catch (error) {
      if (isExplicitWalletRejection(error)) {
        await markSigningReservationRejected(reservationContext, error);
      }
      throw error;
    }
    const signedDoc = signed.signed || {};
    const signature = signed.signature?.signature || signed.signature;
    const signedTx = {
      bodyBytes: toBase64(signedDoc.bodyBytes || fromBase64(walletSignDoc.bodyBytes, "bodyBytes")),
      authInfoBytes: toBase64(signedDoc.authInfoBytes || fromBase64(walletSignDoc.authInfoBytes, "authInfoBytes")),
      signature
    };
    const signedTxSignDocHash = cosmosSignDocBindingHash(signedTx);
    await validateRelayBroadcastContext(broadcastOptions, {
      expectedChainId: this.chainId,
      accountPrefix: this.accountPrefix,
      signedTx,
      reservationContext,
      signDocHash: signedTxSignDocHash
    });
    const txRawBytes = this.buildTxRawBytes(signedTx);
    const txBytesHash = sha256Hex(txRawBytes);
    return Object.freeze({
      signedTx: Object.freeze({ ...signedTx }),
      txRawBytes: Uint8Array.from(txRawBytes),
      txHash: txBytesHash.toUpperCase(),
      txBytesHash,
      signDocHash: signedTxSignDocHash
    });
  }

  async signDirectAndBroadcast(input = {}) {
    const {
      reservation,
      reservationContext,
      broadcastOptions
    } = directBroadcastContext(input);
    const signAndBroadcast = async ({ assertHeartbeatHealthy, heartbeatNow }) => {
      const checkpoint = await this.signDirect(input);
      // Wallet approval is unbounded. Renew once after it returns so a failed
      // timer cannot leave a stale worker crossing the durable RPC boundary.
      await heartbeatNow();
      assertHeartbeatHealthy();
      return this.broadcastTxRawBytes(checkpoint.txRawBytes, broadcastOptions);
    };
    if (!reservationContext) {
      return signAndBroadcast({
        assertHeartbeatHealthy() {},
        async heartbeatNow() {}
      });
    }
    if (typeof reservationContext.reservationManager.renewLease !== "function") {
      throw new Error("reservationManager.renewLease is required to keep the Cosmos reservation lease alive through wallet signing and broadcast");
    }
    return withReservationHeartbeat(
      reservationContext.reservationManager,
      reservation,
      signAndBroadcast,
      {
        acceptBroadcastTerminal: true,
        phase: "wallet signing and broadcast"
      }
    );
  }
}

export function createClairveilClient(options) {
  return new ClairveilJS(options);
}
