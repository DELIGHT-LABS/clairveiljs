import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  bytes,
  bytesFromHex,
  hexFromBytes,
  randomBytes,
  utf8Bytes
} from "../core/browser-crypto.js";
import {
  normalizeFoundNote
} from "../core/note.js";
import {
  canonicalizeShieldedAddressForOperationHash
} from "../core/crypto.js";

export const reservationStatuses = Object.freeze({
  Discovered: "Discovered",
  Available: "Available",
  Reserved: "Reserved",
  Proving: "Proving",
  ProofReady: "ProofReady",
  Submitted: "Submitted",
  ConfirmedSpent: "ConfirmedSpent",
  Failed: "Failed",
  ReplanRequired: "ReplanRequired",
  Released: "Released",
  Unknown: "Unknown",
  ManualReview: "ManualReview"
});

export const operationStatuses = Object.freeze({
  Planned: "Planned",
  Proving: "Proving",
  ProofReady: "ProofReady",
  Submitted: "Submitted",
  Succeeded: "Succeeded",
  Failed: "Failed",
  ReplanRequired: "ReplanRequired",
  Unknown: "Unknown",
  ManualReview: "ManualReview",
  ConflictSpent: "ConflictSpent"
});

export const activeReservationStatuses = Object.freeze([
  reservationStatuses.Reserved,
  reservationStatuses.Proving,
  reservationStatuses.ProofReady,
  reservationStatuses.Submitted,
  reservationStatuses.Unknown,
  reservationStatuses.ManualReview
]);

const activeReservationStatusSet = new Set(activeReservationStatuses);
const reservationStatusSet = new Set(Object.values(reservationStatuses));

const allowedReservationTransitions = new Set([
  "Discovered\x00Available",
  "Discovered\x00Failed",
  "Available\x00Reserved",
  "Reserved\x00Proving",
  "Reserved\x00Released",
  "Reserved\x00ReplanRequired",
  "Reserved\x00ManualReview",
  "Proving\x00ProofReady",
  "Proving\x00Reserved",
  "Proving\x00ReplanRequired",
  "Proving\x00ManualReview",
  "ProofReady\x00Submitted",
  "ProofReady\x00Unknown",
  "ProofReady\x00ConfirmedSpent",
  "ProofReady\x00ReplanRequired",
  "ProofReady\x00ManualReview",
  "Submitted\x00ConfirmedSpent",
  "Submitted\x00Failed",
  "Submitted\x00Unknown",
  "Submitted\x00ReplanRequired",
  "Submitted\x00ManualReview",
  "Unknown\x00ConfirmedSpent",
  "Unknown\x00Failed",
  "Unknown\x00ReplanRequired",
  "Unknown\x00ManualReview",
  "ManualReview\x00ConfirmedSpent",
  "ManualReview\x00Failed",
  "ManualReview\x00Released",
  "ManualReview\x00ReplanRequired",
  "Failed\x00ReplanRequired",
  "Released\x00Available",
  "ReplanRequired\x00Reserved",
  "ReplanRequired\x00Failed",
  "ReplanRequired\x00ManualReview"
]);

const leaseRequiredTransitions = new Set([
  "Reserved\x00Proving",
  "Proving\x00Reserved",
  "Proving\x00ProofReady",
  "Proving\x00ReplanRequired",
  "Proving\x00ManualReview",
  "ProofReady\x00Submitted",
  "ProofReady\x00Unknown",
  "ProofReady\x00ReplanRequired",
  "ProofReady\x00ManualReview"
]);

const expiredLeaseRecoveryTransitions = new Set([
  "Proving\x00ReplanRequired",
  "Proving\x00ManualReview",
  "ProofReady\x00ManualReview"
]);

const defaultLeaseDurationMs = 15 * 60 * 1000;
const defaultHeartbeatIntervalMs = 60 * 1000;
const reservationClaimTokenHashField = "reservation_claim_token_hash";
const reconciledSpentTransition = Symbol("reconciledSpentTransition");
const managedReservationEvidenceMutation = Symbol("managedReservationEvidenceMutation");
const managedOperationReconciliation = Symbol("managedOperationReconciliation");
const managedReservationCreation = Symbol("managedReservationCreation");
const inProcessMutationQueues = new Map();

function withInProcessMutationLock(lockName, callback) {
  const previous = inProcessMutationQueues.get(lockName) || Promise.resolve();
  let release;
  const current = new Promise(resolve => {
    release = resolve;
  });
  const queueTail = previous.catch(() => {}).then(() => current);
  inProcessMutationQueues.set(lockName, queueTail);
  return previous
    .catch(() => {})
    .then(callback)
    .finally(() => {
      release();
      if (inProcessMutationQueues.get(lockName) === queueTail) {
        inProcessMutationQueues.delete(lockName);
      }
    });
}

function transitionKey(from, to) {
  return `${from}\x00${to}`;
}

export function isActiveReservationStatus(status) {
  return activeReservationStatusSet.has(String(status || ""));
}

export function canTransitionReservation(from, to) {
  return allowedReservationTransitions.has(transitionKey(String(from || ""), String(to || "")));
}

export function canRecoverReservationAfterLeaseExpiry(from, to) {
  return expiredLeaseRecoveryTransitions.has(
    transitionKey(String(from || ""), String(to || ""))
  );
}

export function requiresReservationLeaseToken(from, to) {
  return leaseRequiredTransitions.has(transitionKey(String(from || ""), String(to || "")));
}

export function reservationHeartbeatIntervalMs({
  leaseDurationMs,
  lease_duration_ms,
  leaseUntil,
  lease_until,
  minIntervalMs = 100,
  maxIntervalMs = defaultHeartbeatIntervalMs,
  now = new Date()
} = {}) {
  const durationMs = Number(leaseDurationMs ?? lease_duration_ms ?? 0);
  const leaseUntilMs = Date.parse(leaseUntil || lease_until || "");
  const nowMs = new Date(now).getTime();
  const remainingMs = Number.isFinite(leaseUntilMs) ? leaseUntilMs - nowMs : 0;
  const windows = [durationMs, remainingMs]
    .filter(value => Number.isFinite(value) && value > 0);
  const budgetMs = windows.length ? Math.min(...windows) : defaultLeaseDurationMs;
  const requestedMax = Number(maxIntervalMs) > 0 ? Number(maxIntervalMs) : defaultHeartbeatIntervalMs;
  const requestedMin = Number(minIntervalMs) > 0 ? Number(minIntervalMs) : 1;
  const interval = Math.max(1, Math.floor(budgetMs / 3));
  const safeMinimum = Math.min(requestedMin, interval);
  return Math.max(1, Math.min(requestedMax, Math.max(safeMinimum, interval)));
}

export function nullifierLookupKey(indexKey, nullifier) {
  const keyBytes = bytes(indexKey);
  if (typeof nullifier === "string" && /^(0x)?[0-9a-f]{64}$/i.test(nullifier.trim())) {
    throw new Error("nullifier hex strings must use nullifierLookupKeyFromHex");
  }
  const nullifierBytes = bytes(nullifier);
  if (!keyBytes.length) {
    throw new Error("index key is required");
  }
  if (!nullifierBytes.length) {
    throw new Error("nullifier is required");
  }
  return hexFromBytes(hmac(sha256, keyBytes, nullifierBytes));
}

export function nullifierLookupKeyFromHex(indexKey, nullifierHex) {
  const normalized = String(nullifierHex ?? "").trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(normalized)) {
    throw new Error("nullifier must be exactly 32 bytes of hex");
  }
  return nullifierLookupKey(indexKey, bytesFromHex(normalized, "nullifier"));
}

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

/** Go-compatible SHA-256 commitment over the canonical `denom:amount` string. */
export function hashAmount(denom, amount) {
  if (typeof denom !== "string") {
    throw new Error("denom must be a valid Cosmos SDK denomination string");
  }
  const rawDenom = denom;
  const normalizedDenom = rawDenom.trim();
  if (
    rawDenom !== normalizedDenom ||
    !/^[A-Za-z][A-Za-z0-9/:._-]{2,127}$/.test(normalizedDenom)
  ) {
    throw new Error("denom must be a valid Cosmos SDK denomination");
  }
  if (amount === undefined || amount === null || amount === "") {
    throw new Error("amount is required");
  }
  if (!["bigint", "number", "string"].includes(typeof amount)) {
    throw new Error("amount must be a safe integer, bigint, or canonical uint64 string");
  }
  if (typeof amount === "number" && !Number.isSafeInteger(amount)) {
    throw new Error("amount must be a safe integer, bigint, or canonical uint64 string");
  }
  if (typeof amount === "string" && !/^(0|[1-9][0-9]*)$/.test(amount)) {
    throw new Error("amount must be a canonical uint64 decimal string");
  }
  let normalizedAmount;
  try {
    normalizedAmount = BigInt(amount);
  } catch {
    throw new Error("amount must be a safe integer, bigint, or canonical uint64 string");
  }
  if (normalizedAmount < 0n || normalizedAmount > 18446744073709551615n) {
    throw new Error("amount must be within uint64 range");
  }
  return hexFromBytes(sha256(utf8Bytes(`${normalizedDenom}:${normalizedAmount}`)));
}

function nowIso(now = new Date()) {
  return new Date(now).toISOString();
}

function randomHex(bytesLength = 16) {
  return hexFromBytes(randomBytes(bytesLength));
}

function futureIso(now, durationMs = defaultLeaseDurationMs) {
  return new Date(new Date(now).getTime() + durationMs).toISOString();
}

function normalizedBatchItemIndex(value) {
  const provided = value !== undefined && value !== null && value !== "";
  if (!provided) {
    return { value: 0, valid: true, provided: false };
  }
  if (typeof value !== "number" && typeof value !== "string") {
    return { value: 0, valid: false, provided: true };
  }
  if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/.test(value)) {
    return { value: 0, valid: false, provided: true };
  }
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    return { value: 0, valid: false, provided: true };
  }
  return { value: parsed, valid: true, provided: true };
}

function normalizedBooleanAlias(input, canonicalKey, aliasKey, fallback = false) {
  const hasCanonical = Object.prototype.hasOwnProperty.call(input, canonicalKey);
  const hasAlias = Object.prototype.hasOwnProperty.call(input, aliasKey);
  const canonicalValue = input[canonicalKey];
  const aliasValue = input[aliasKey];
  if (hasCanonical && typeof canonicalValue !== "boolean") {
    throw new Error(`${canonicalKey} must be a boolean`);
  }
  if (hasAlias && typeof aliasValue !== "boolean") {
    throw new Error(`${aliasKey} must be a boolean`);
  }
  if (hasCanonical && hasAlias && canonicalValue !== aliasValue) {
    throw new Error(`${canonicalKey} aliases conflict`);
  }
  if (hasCanonical) return canonicalValue;
  if (hasAlias) return aliasValue;
  return fallback;
}

function normalizedNonNegativeSafeIntegerAlias(input, canonicalKey, aliasKey, fallback = 0) {
  const hasCanonical = Object.prototype.hasOwnProperty.call(input, canonicalKey);
  const hasAlias = Object.prototype.hasOwnProperty.call(input, aliasKey);
  const parse = (value, key) => {
    if (typeof value !== "number" && typeof value !== "string") {
      throw new Error(`${key} must be a non-negative safe integer`);
    }
    if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/.test(value)) {
      throw new Error(`${key} must be a non-negative safe integer`);
    }
    const parsed = typeof value === "number" ? value : Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < 0) {
      throw new Error(`${key} must be a non-negative safe integer`);
    }
    return parsed;
  };
  const canonicalValue = hasCanonical ? parse(input[canonicalKey], canonicalKey) : null;
  const aliasValue = hasAlias ? parse(input[aliasKey], aliasKey) : null;
  if (hasCanonical && hasAlias && canonicalValue !== aliasValue) {
    throw new Error(`${canonicalKey} aliases conflict`);
  }
  if (hasCanonical) return canonicalValue;
  if (hasAlias) return aliasValue;
  return fallback;
}

function normalizedUint64Value(value, label) {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative safe integer, bigint, or canonical uint64 string`);
    }
    return value;
  }
  let parsed;
  if (typeof value === "bigint") {
    parsed = value;
  } else {
    const text = String(value ?? 0).trim();
    if (!/^(0|[1-9][0-9]*)$/.test(text)) {
      throw new Error(`${label} must be a canonical uint64 decimal string`);
    }
    parsed = BigInt(text);
  }
  if (parsed < 0n || parsed > ((1n << 64n) - 1n)) {
    throw new Error(`${label} must be within uint64 range`);
  }
  return parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : parsed.toString();
}

function normalizeStatus(status, fallback = reservationStatuses.Reserved) {
  const normalized = String(status || fallback);
  if (!reservationStatusSet.has(normalized)) {
    throw new Error(`unsupported reservation status: ${normalized}`);
  }
  return normalized;
}

function cloneJSON(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function assertReservationMetadataValue(value, path = "metadata", seen = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (typeof value !== "object") {
    throw new Error(`reservation metadata must contain only JSON values: ${path}`);
  }
  if (seen.has(value)) {
    throw new Error(`reservation metadata must not contain cycles: ${path}`);
  }
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertReservationMetadataValue(item, `${path}[${index}]`, seen));
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error(`reservation metadata must contain only plain JSON objects: ${path}`);
    }
    for (const [key, item] of Object.entries(value)) {
      assertReservationMetadataValue(item, `${path}.${key}`, seen);
    }
  }
  seen.delete(value);
}

function cloneReservationMetadata(value) {
  const metadata = value ?? {};
  if (typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new Error("reservation metadata must be a plain JSON object");
  }
  assertReservationMetadataValue(metadata);
  return cloneJSON(metadata);
}

export function noteNullifierHex(noteLike) {
  const direct = noteLike?.nullifier_hex ?? noteLike?.nullifierHex ?? noteLike?.nullifier;
  if (direct) {
    return String(direct).trim().replace(/^0x/i, "").toLowerCase();
  }
  return String(normalizeFoundNote(noteLike).nullifier || "").trim().replace(/^0x/i, "").toLowerCase();
}

export function noteReservationIdentity(noteLike) {
  const found = normalizeFoundNote(noteLike);
  const nullifierHex = noteNullifierHex(noteLike);
  if (!nullifierHex) {
    throw new Error("note nullifier is required for reservation");
  }
  const height = found.height;
  const sequence = found.sequence;
  const txHash = String(found.txHash || noteLike?.tx_hash || "").toUpperCase();
  return {
    nullifierHex,
    noteId: String(
      noteLike?.note_id ??
      noteLike?.noteId ??
      `${height}:${sequence}:${txHash}`
    ),
    amount: found.note.amount.toString(),
    height,
    sequence,
    txHash
  };
}

export function selectedReservationNotesFromPlan(plan) {
  if (!plan) return [];
  if (Array.isArray(plan.selection?.inputs)) {
    return plan.selection.inputs;
  }
  if (Array.isArray(plan.selections)) {
    return plan.selections.flatMap(selection => selection?.inputs || []);
  }
  if (plan.selectedNote) {
    return [plan.selectedNote];
  }
  return [];
}

function operationSuccessEvidenceRequiredMetadataState(metadata = {}) {
  const hasCanonical = Object.prototype.hasOwnProperty.call(
    metadata,
    "operation_success_evidence_required"
  );
  const hasAlias = Object.prototype.hasOwnProperty.call(
    metadata,
    "operationSuccessEvidenceRequired"
  );
  const canonicalValue = metadata.operation_success_evidence_required;
  const aliasValue = metadata.operationSuccessEvidenceRequired;
  if (hasCanonical && typeof canonicalValue !== "boolean") {
    throw new Error("operation_success_evidence_required metadata must be a boolean");
  }
  if (hasAlias && typeof aliasValue !== "boolean") {
    throw new Error("operationSuccessEvidenceRequired metadata must be a boolean");
  }
  const canonical = hasCanonical ? canonicalValue : null;
  const alias = hasAlias ? aliasValue : null;
  if (hasCanonical && hasAlias && canonical !== alias) {
    throw new Error("operation_success_evidence_required metadata aliases conflict");
  }
  return {
    present: hasCanonical || hasAlias,
    value: hasCanonical ? canonical : alias
  };
}

function operationSuccessEvidenceRequiredInputState(metadata = {}) {
  const direct = operationSuccessEvidenceRequiredMetadataState(metadata);
  const nested = operationSuccessEvidenceRequiredMetadataState(metadata.metadata || {});
  if (direct.present && nested.present && direct.value !== nested.value) {
    throw new Error("operation success evidence required aliases conflict");
  }
  return direct.present ? direct : nested;
}

function normalizeReservationMetadata(value) {
  const metadata = cloneReservationMetadata(value);
  const evidenceRequired = operationSuccessEvidenceRequiredMetadataState(metadata);
  if (evidenceRequired.present) {
    metadata.operation_success_evidence_required = evidenceRequired.value;
    delete metadata.operationSuccessEvidenceRequired;
  }
  return metadata;
}

function normalizeReservation(input = {}) {
  const status = normalizeStatus(input.status);
  const createdAt = input.created_at || input.createdAt || nowIso();
  const updatedAt = input.updated_at || input.updatedAt || createdAt;
  const reservationID = String(input.reservation_id || input.reservationID || input.reservationId || "");
  const operationID = String(input.operation_id || input.operationID || input.operationId || "");
  const ownerKeyID = String(input.owner_key_id || input.ownerKeyID || input.ownerKeyId || "");
  const nullifierLookupKeyValue = String(input.nullifier_lookup_key || input.nullifierLookupKey || "");
  const batchItemIndex = normalizedBatchItemIndex(
    firstDefined(input.batch_item_index, input.batchItemIndex, "")
  );
  const batchItemIndexKnown = normalizedBooleanAlias(
    input,
    "batch_item_index_known",
    "batchItemIndexKnown"
  );
  const broadcastAttemptCount = normalizedNonNegativeSafeIntegerAlias(
    input,
    "broadcast_attempt_count",
    "broadcastAttemptCount"
  );
  const broadcastInFlight = normalizedBooleanAlias(
    input,
    "broadcast_in_flight",
    "broadcastInFlight"
  );
  if (!reservationID) throw new Error("reservation_id is required");
  if (!ownerKeyID) throw new Error("owner_key_id is required");
  if (!nullifierLookupKeyValue) throw new Error("nullifier_lookup_key is required");
  if (batchItemIndexKnown && (!batchItemIndex.valid || !batchItemIndex.provided)) {
    throw new Error("batch_item_index must be a non-negative safe integer when known");
  }
  return {
    reservation_id: reservationID,
    operation_id: operationID,
    owner_key_id: ownerKeyID,
    nullifier_lookup_key: nullifierLookupKeyValue,
    nullifier_lookup_key_id: String(input.nullifier_lookup_key_id || input.nullifierLookupKeyID || input.nullifierLookupKeyId || ""),
    status,
    lease_owner: String(input.lease_owner || input.leaseOwner || ""),
    lease_token: String(input.lease_token || input.leaseToken || ""),
    lease_until: String(input.lease_until || input.leaseUntil || ""),
    last_heartbeat_at: String(input.last_heartbeat_at || input.lastHeartbeatAt || ""),
    kind: String(input.kind || input.operation_kind || input.operationKind || ""),
    note_id: String(input.note_id || input.noteID || input.noteId || ""),
    amount: String(input.amount || ""),
    tx_hash: String(input.tx_hash || input.txHash || "").toUpperCase(),
    height: normalizedUint64Value(input.height ?? 0, "reservation height"),
    sequence: normalizedUint64Value(input.sequence ?? 0, "reservation sequence"),
    payload_hash: String(input.payload_hash || input.payloadHash || ""),
    expected_output_commitment: String(input.expected_output_commitment || input.expectedOutputCommitment || ""),
    expected_disclosure_digest: String(input.expected_disclosure_digest || input.expectedDisclosureDigest || ""),
    expected_recipient_hash: String(input.expected_recipient_hash || input.expectedRecipientHash || ""),
    expected_amount: String(firstDefined(input.expected_amount, input.expectedAmount, "")),
    expected_amount_hash: String(input.expected_amount_hash || input.expectedAmountHash || ""),
    expected_denom: String(input.expected_denom || input.expectedDenom || ""),
    batch_item_index: batchItemIndex.value,
    batch_item_index_known: batchItemIndexKnown,
    sign_doc_hash: String(input.sign_doc_hash || input.signDocHash || ""),
    tx_bytes_hash: String(input.tx_bytes_hash || input.txBytesHash || ""),
    submitted_tx_hash: String(input.submitted_tx_hash || input.submittedTxHash || input.txHashSubmitted || ""),
    broadcast_attempt_count: broadcastAttemptCount,
    broadcast_in_flight: broadcastInFlight,
    last_broadcast_error: String(input.last_broadcast_error || input.lastBroadcastError || ""),
    created_at: createdAt,
    updated_at: updatedAt,
    metadata: normalizeReservationMetadata(input.metadata)
  };
}

const initialLifecycleMetadataFields = new Set([
  "relay_handed_off",
  "relayHandedOff",
  "relay_handed_off_at",
  "relayHandedOffAt",
  "broadcast_attempt_started_at",
  "broadcastAttemptStartedAt",
  "broadcast_attempt_reason",
  "broadcastAttemptReason",
  "no_broadcast_attempt",
  "noBroadcastAttempt",
  "proof_discarded",
  "proofDiscarded",
  "operator_approved",
  "operatorApproved",
  "operator_id",
  "operatorId",
  "operator_approval_reference",
  "operatorApprovalReference",
  "operation_status",
  "operationStatus",
  "operation_success_evidence_matches",
  "operationSuccessEvidenceMatches",
  "operation_success_evidence_errors",
  "operationSuccessEvidenceErrors",
  "operation_success_evidence_required",
  "operationSuccessEvidenceRequired",
  "manual_review_resolution_reason",
  "manualReviewResolutionReason",
  "wallet_rejected_before_broadcast",
  "walletRejectedBeforeBroadcast",
  "provider_rejection_code",
  "providerRejectionCode"
]);

function assertInitialReservationRecord(reservation, { allowManagedClaimTokenHash = false } = {}) {
  if (reservation.status !== reservationStatuses.Reserved) {
    throw new Error("new reservations must start as Reserved");
  }
  if (
    reservation.lease_owner ||
    reservation.lease_token ||
    reservation.lease_until ||
    reservation.last_heartbeat_at ||
    reservation.payload_hash ||
    reservation.expected_output_commitment ||
    reservation.expected_disclosure_digest ||
    reservation.expected_recipient_hash ||
    reservation.expected_amount ||
    reservation.expected_amount_hash ||
    reservation.expected_denom ||
    reservation.batch_item_index_known ||
    reservation.batch_item_index !== 0 ||
    reservation.sign_doc_hash ||
    reservation.tx_bytes_hash ||
    reservation.submitted_tx_hash ||
    reservation.broadcast_attempt_count ||
    reservation.broadcast_in_flight ||
    reservation.last_broadcast_error
  ) {
    throw new Error("new reservations cannot include lifecycle, broadcast, or relay evidence");
  }
  const metadata = reservation.metadata || {};
  if (
    !allowManagedClaimTokenHash &&
    Object.prototype.hasOwnProperty.call(metadata, reservationClaimTokenHashField)
  ) {
    throw new Error("new reservations cannot include manager claim-token metadata");
  }
  if (Object.keys(metadata).some(key => initialLifecycleMetadataFields.has(key))) {
    throw new Error("new reservations cannot include lifecycle evidence metadata");
  }
}

function activeKey(reservation) {
  return `${reservation.owner_key_id}\x00${reservation.nullifier_lookup_key}`;
}

function normalizeState(state = {}) {
  if (!state || typeof state !== "object" || Array.isArray(state)) {
    throw new Error("reservation state must be an object");
  }
  const version = state.version ?? 1;
  if (version !== 1) {
    throw new Error(`unsupported reservation state version: ${version}`);
  }
  if (state.reservations !== undefined && !Array.isArray(state.reservations)) {
    throw new Error("reservation state reservations must be an array");
  }
  const reservations = (state.reservations || []).map(normalizeReservation);
  const reservationIDs = new Set();
  const activeKeys = new Set();
  const confirmedSpentKeys = new Set();
  for (const reservation of reservations) {
    if (reservationIDs.has(reservation.reservation_id)) {
      throw new Error(`duplicate reservation_id in reservation state: ${reservation.reservation_id}`);
    }
    reservationIDs.add(reservation.reservation_id);
    const key = activeKey(reservation);
    if (isActiveReservationStatus(reservation.status)) {
      if (activeKeys.has(key)) {
        throw new Error("duplicate active reservation in reservation state");
      }
      if (confirmedSpentKeys.has(key)) {
        throw new Error("confirmed spent reservation conflicts with an active reservation in reservation state");
      }
      activeKeys.add(key);
    } else if (reservation.status === reservationStatuses.ConfirmedSpent) {
      if (activeKeys.has(key)) {
        throw new Error("confirmed spent reservation conflicts with an active reservation in reservation state");
      }
      confirmedSpentKeys.add(key);
    }
  }
  return {
    version,
    reservations
  };
}

function activeConflict(reservations, candidate, excludeReservationID = "") {
  if (!isActiveReservationStatus(candidate.status)) return false;
  const key = activeKey(candidate);
  return reservations.some(reservation =>
    reservation.reservation_id !== excludeReservationID &&
    isActiveReservationStatus(reservation.status) &&
    activeKey(reservation) === key
  );
}

function confirmedSpentConflict(reservations, candidate, excludeReservationID = "") {
  if (!isActiveReservationStatus(candidate.status)) return false;
  const key = activeKey(candidate);
  return reservations.some(reservation =>
    reservation.reservation_id !== excludeReservationID &&
    reservation.status === reservationStatuses.ConfirmedSpent &&
    activeKey(reservation) === key
  );
}

function reservationBlockersByLookupKey(reservations = [], lookupKeys = new Set()) {
  const blockers = new Map();
  for (const reservation of reservations) {
    const lookupKey = reservation.nullifier_lookup_key;
    if (!lookupKeys.has(lookupKey)) continue;
    const active = isActiveReservationStatus(reservation.status);
    if (!active && reservation.status !== reservationStatuses.ConfirmedSpent) continue;
    const existing = blockers.get(lookupKey);
    if (!existing || (active && existing.status === reservationStatuses.ConfirmedSpent)) {
      blockers.set(lookupKey, reservation);
    }
  }
  return blockers;
}

function patchLeaseToken(patch = {}) {
  return String(patch.lease_token || patch.leaseToken || "");
}

function patchLeaseOwner(patch = {}) {
  return String(patch.lease_owner || patch.leaseOwner || "");
}

function leaseExpirationMs(reservation) {
  const value = Date.parse(reservation.lease_until || "");
  return Number.isFinite(value) ? value : 0;
}

function reservationClaimTokenHash(token) {
  return hexFromBytes(sha256(utf8Bytes(
    `clairveil-reservation-claim-v1\0${String(token || "")}`
  )));
}

function assertCurrentLeaseToken(current, token, owner, now) {
  if (!token) {
    throw new Error("lease token is required");
  }
  if (!current.lease_token || token !== current.lease_token) {
    throw new Error("reservation lease token mismatch");
  }
  if (!owner) {
    throw new Error("lease owner is required");
  }
  if (!current.lease_owner || owner !== current.lease_owner) {
    throw new Error("reservation lease owner mismatch");
  }
  if (leaseExpirationMs(current) <= new Date(now).getTime()) {
    throw new Error("reservation lease expired");
  }
}

function isLeaseExpiredError(error) {
  return /reservation lease expired/.test(error?.message || "");
}

function assertLeaseTransitionAllowed(current, to, patch, now) {
  if (!requiresReservationLeaseToken(current.status, to)) return;
  if (
    current.status === reservationStatuses.Reserved &&
    to === reservationStatuses.Proving &&
    !current.lease_token
  ) {
    const token = patchLeaseToken(patch);
    const owner = String(patch.lease_owner || patch.leaseOwner || "");
    const until = Date.parse(patch.lease_until || patch.leaseUntil || "");
    if (!token || !owner || !Number.isFinite(until)) {
      throw new Error("a future lease owner, token, and expiry are required to start proving");
    }
    const expectedClaimHash = String(
      current.metadata?.[reservationClaimTokenHashField] || ""
    );
    if (!expectedClaimHash) {
      throw new Error("reservation claim token is not bound; release and reserve the note again");
    }
    if (reservationClaimTokenHash(token) !== expectedClaimHash) {
      throw new Error("reservation claim token mismatch");
    }
    if (until <= new Date(now).getTime()) throw new Error("reservation lease expired");
    return;
  }
  const leaseExpiresAt = leaseExpirationMs(current);
  const recoveryAfterExpiredWorkerLease =
    canApplyExpiredLeaseRecovery(current, to, patch, now) &&
    leaseExpiresAt > 0 &&
    leaseExpiresAt <= new Date(now).getTime();
  if (recoveryAfterExpiredWorkerLease) return;
  const token = patchLeaseToken(patch);
  const owner = patchLeaseOwner(patch);
  try {
    assertCurrentLeaseToken(current, token, owner, now);
  } catch (error) {
    if (/lease token is required/.test(error?.message || "")) {
      throw new Error(`lease token is required for reservation transition: ${current.status} -> ${to}`);
    }
    throw error;
  }
}

function canApplyExpiredLeaseRecovery(current, to, patch = {}, now) {
  if (!canRecoverReservationAfterLeaseExpiry(current.status, to)) return false;
  const leaseExpiresAt = leaseExpirationMs(current);
  if (leaseExpiresAt <= 0 || leaseExpiresAt > new Date(now).getTime()) return false;
  return true;
}

function isLeaseRenewalPatch(current, to, patch = {}) {
  if (current.status !== to) return false;
  return ["lease_owner", "leaseOwner", "lease_token", "leaseToken", "lease_until", "leaseUntil", "last_heartbeat_at", "lastHeartbeatAt"]
    .some(key => Object.prototype.hasOwnProperty.call(patch, key));
}

const sameStatusLeasePatchFields = new Set([
  "lease_owner", "leaseOwner",
  "lease_token", "leaseToken",
  "lease_until", "leaseUntil",
  "last_heartbeat_at", "lastHeartbeatAt",
  "updated_at", "updatedAt"
]);

const writeOnceReservationEvidenceFields = [
  ["payload_hash", "payloadHash"],
  ["submitted_tx_hash", "submittedTxHash", "txHashSubmitted"],
  ["tx_bytes_hash", "txBytesHash"],
  ["sign_doc_hash", "signDocHash"]
];

const normalizedWriteOnceIdentityFields = new Set([
  "submitted_tx_hash",
  "tx_bytes_hash",
  "sign_doc_hash"
]);

const operationSuccessPredicateFields = [
  ["expected_output_commitment", "expectedOutputCommitment"],
  ["expected_disclosure_digest", "expectedDisclosureDigest"],
  ["expected_recipient_hash", "expectedRecipientHash"],
  ["expected_amount", "expectedAmount"],
  ["expected_amount_hash", "expectedAmountHash"],
  ["expected_denom", "expectedDenom"],
  ["batch_item_index", "batchItemIndex"],
  ["batch_item_index_known", "batchItemIndexKnown"]
];

const operationOutcomeMetadataFields = new Set([
  "operation_status",
  "operation_success_evidence_matches",
  "operation_success_evidence_errors"
]);

const protectedMetadataEvidenceFields = [
  "relay_handed_off",
  "relayHandedOff",
  "relay_handed_off_at",
  "relayHandedOffAt",
  "broadcast_attempt_started_at",
  "broadcastAttemptStartedAt",
  "broadcast_attempt_reason",
  "broadcastAttemptReason",
  "operation_status",
  "operationStatus",
  "operation_success_evidence_matches",
  "operationSuccessEvidenceMatches",
  "operation_success_evidence_errors",
  "operationSuccessEvidenceErrors",
  "operation_success_evidence_required",
  "operationSuccessEvidenceRequired",
  "operator_approved",
  "operatorApproved",
  "operator_id",
  "operatorId",
  "operator_approval_reference",
  "operatorApprovalReference",
  "manual_review_resolution_reason",
  "manualReviewResolutionReason"
];

const managedLifecycleMetadataAliases = new Map([
  ["relayHandedOff", "relay_handed_off"],
  ["relayHandedOffAt", "relay_handed_off_at"],
  ["broadcastAttemptStartedAt", "broadcast_attempt_started_at"],
  ["broadcastAttemptReason", "broadcast_attempt_reason"],
  ["noBroadcastAttempt", "no_broadcast_attempt"],
  ["proofDiscarded", "proof_discarded"],
  ["operatorApproved", "operator_approved"],
  ["operatorId", "operator_id"],
  ["operatorApprovalReference", "operator_approval_reference"],
  ["operationStatus", "operation_status"],
  ["operationSuccessEvidenceMatches", "operation_success_evidence_matches"],
  ["operationSuccessEvidenceErrors", "operation_success_evidence_errors"],
  ["operationSuccessEvidenceRequired", "operation_success_evidence_required"],
  ["manualReviewResolutionReason", "manual_review_resolution_reason"],
  ["walletRejectedBeforeBroadcast", "wallet_rejected_before_broadcast"],
  ["providerRejectionCode", "provider_rejection_code"]
]);

const managedLifecycleMetadataFields = new Set([
  reservationClaimTokenHashField,
  ...initialLifecycleMetadataFields,
  "wallet_rejected_before_broadcast",
  "provider_rejection_code"
].filter(field => !managedLifecycleMetadataAliases.has(field)));

function metadataFieldChanged(currentMetadata, nextMetadata, field) {
  if (!Object.prototype.hasOwnProperty.call(nextMetadata, field)) return false;
  return !Object.prototype.hasOwnProperty.call(currentMetadata, field) ||
    JSON.stringify(nextMetadata[field]) !== JSON.stringify(currentMetadata[field]);
}

function assertManagedLifecycleMetadataMutation(current, to, patch = {}, {
  managedRelayHandoff = false,
  managedBroadcastAttempt = false,
  managedBroadcastRejection = false,
  managedOperationReconcile = false
} = {}) {
  const metadata = patch.metadata;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return;
  const currentMetadata = current.metadata || {};
  for (const [alias, canonical] of managedLifecycleMetadataAliases) {
    if (!metadataFieldChanged(currentMetadata, metadata, alias)) continue;
    throw new Error(`${alias} lifecycle metadata alias cannot be introduced; use ${canonical}`);
  }
  const allowed = new Set();
  if (current.status === reservationStatuses.Proving && to === reservationStatuses.ProofReady) {
    allowed.add("no_broadcast_attempt");
    allowed.add("operation_success_evidence_required");
  }
  if (managedRelayHandoff) {
    allowed.add("relay_handed_off");
    allowed.add("relay_handed_off_at");
    allowed.add("no_broadcast_attempt");
  }
  if (managedBroadcastAttempt) {
    allowed.add("broadcast_attempt_started_at");
    allowed.add("broadcast_attempt_reason");
    allowed.add("no_broadcast_attempt");
  }
  if (managedBroadcastRejection) {
    allowed.add("wallet_rejected_before_broadcast");
    allowed.add("provider_rejection_code");
    allowed.add("no_broadcast_attempt");
    allowed.add("proof_discarded");
  }
  if (managedOperationReconcile) {
    for (const field of operationOutcomeMetadataFields) allowed.add(field);
  }
  if ([
    reservationStatuses.Submitted,
    reservationStatuses.Unknown,
    reservationStatuses.ReplanRequired,
    reservationStatuses.ManualReview,
    reservationStatuses.Failed
  ].includes(to)) {
    allowed.add("no_broadcast_attempt");
  }
  if ([
    reservationStatuses.ReplanRequired,
    reservationStatuses.ManualReview,
    reservationStatuses.Failed
  ].includes(to)) {
    allowed.add("proof_discarded");
  }
  if (current.status === reservationStatuses.ManualReview && [
    reservationStatuses.Released,
    reservationStatuses.ReplanRequired,
    reservationStatuses.Failed
  ].includes(to)) {
    allowed.add("operator_approved");
    allowed.add("operator_id");
    allowed.add("operator_approval_reference");
    allowed.add("manual_review_resolution_reason");
  }
  const unauthorized = [...managedLifecycleMetadataFields].find(field =>
    metadataFieldChanged(currentMetadata, metadata, field) && !allowed.has(field)
  );
  if (unauthorized) {
    throw new Error(`${unauthorized} lifecycle metadata may only be set by its managed reservation transition`);
  }
}

function patchHasAnyOwnProperty(patch = {}, keys = []) {
  return keys.some(key => Object.prototype.hasOwnProperty.call(patch, key));
}

function patchValueForAliases(patch = {}, keys = []) {
  return firstDefined(...keys.map(key => patch[key]));
}

function patchWithPreservedReservationClaimHash(current, patch = {}) {
  const claimHash = String(
    current.metadata?.[reservationClaimTokenHashField] || ""
  );
  if (!claimHash || !patch.metadata || typeof patch.metadata !== "object" || Array.isArray(patch.metadata)) {
    return patch;
  }
  return {
    ...patch,
    metadata: {
      ...patch.metadata,
      [reservationClaimTokenHashField]: claimHash
    }
  };
}

function assertReservationEvidencePatchMonotonic(current, patch = {}, {
  allowOperationOutcomeMutation = false
} = {}) {
  for (const aliases of writeOnceReservationEvidenceFields) {
    if (!patchHasAnyOwnProperty(patch, aliases)) continue;
    const field = aliases[0];
    const existing = String(current[field] || "");
    const incoming = String(patchValueForAliases(patch, aliases) || "");
    if (!incoming) {
      if (existing) {
        throw new Error(`${field} cannot be cleared through reservation mutation`);
      }
      continue;
    }
    const comparableExisting = normalizedWriteOnceIdentityFields.has(field)
      ? normalizedTxIdentity(existing)
      : existing;
    const comparableIncoming = normalizedWriteOnceIdentityFields.has(field)
      ? normalizedTxIdentity(incoming)
      : incoming;
    if (existing && comparableIncoming !== comparableExisting) {
      throw new Error(`${field} is write-once once broadcast evidence is recorded`);
    }
  }
  if (Object.prototype.hasOwnProperty.call(patch, "broadcast_attempt_count") ||
      Object.prototype.hasOwnProperty.call(patch, "broadcastAttemptCount")) {
    const nextCount = Number(patch.broadcast_attempt_count ?? patch.broadcastAttemptCount);
    const currentCount = Number(current.broadcast_attempt_count || 0);
    if (!Number.isSafeInteger(nextCount) || nextCount < currentCount) {
      throw new Error("broadcast_attempt_count cannot decrease through reservation mutation");
    }
  }
  if (!Object.prototype.hasOwnProperty.call(patch, "metadata")) return;
  const nextMetadata = patch.metadata;
  if (!nextMetadata || typeof nextMetadata !== "object" || Array.isArray(nextMetadata)) {
    throw new Error("reservation metadata evidence cannot be cleared through mutation");
  }
  if (!allowOperationOutcomeMutation) {
    const unauthorizedOutcomeField = [...operationOutcomeMetadataFields].find(field =>
      Object.prototype.hasOwnProperty.call(nextMetadata, field) &&
      JSON.stringify(nextMetadata[field]) !== JSON.stringify(current.metadata?.[field])
    );
    if (unauthorizedOutcomeField) {
      throw new Error(`${unauthorizedOutcomeField} metadata may only be set by operation reconciliation`);
    }
  }
  for (const field of protectedMetadataEvidenceFields) {
    if (allowOperationOutcomeMutation && operationOutcomeMetadataFields.has(field)) continue;
    const existing = current.metadata?.[field];
    if (existing === undefined || existing === null || existing === "") continue;
    if (!Object.prototype.hasOwnProperty.call(nextMetadata, field) ||
        JSON.stringify(nextMetadata[field]) !== JSON.stringify(existing)) {
      throw new Error(`${field} metadata evidence cannot be replaced or cleared through reservation mutation`);
    }
  }
}

function patchWithStableWriteOnceIdentityRepresentation(current, patch = {}) {
  let normalized = patch;
  for (const aliases of writeOnceReservationEvidenceFields) {
    const field = aliases[0];
    if (!normalizedWriteOnceIdentityFields.has(field) ||
        !patchHasAnyOwnProperty(patch, aliases)) {
      continue;
    }
    const existing = String(current[field] || "");
    const incoming = String(patchValueForAliases(patch, aliases) || "");
    if (!existing ||
        normalizedTxIdentity(existing) !== normalizedTxIdentity(incoming)) {
      continue;
    }
    if (normalized === patch) normalized = { ...patch };
    for (const alias of aliases) delete normalized[alias];
    normalized[field] = existing;
  }
  return normalized;
}

function comparablePredicateValue(field, value) {
  if (field === "batch_item_index") return Number(value || 0);
  if (field === "batch_item_index_known") return value === true;
  return String(value || "");
}

function assertOperationSuccessPredicateImmutable(current, to, patch = {}) {
  const initializing = current.status === reservationStatuses.Proving && to === reservationStatuses.ProofReady;
  for (const aliases of operationSuccessPredicateFields) {
    if (!patchHasAnyOwnProperty(patch, aliases)) continue;
    const field = aliases[0];
    const existing = comparablePredicateValue(field, current[field]);
    const incoming = comparablePredicateValue(field, patchValueForAliases(patch, aliases));
    if (!initializing && incoming !== existing) {
      throw new Error(`${field} is write-once after ProofReady success evidence is established`);
    }
  }
  if (!Object.prototype.hasOwnProperty.call(patch, "metadata")) return;
  const metadata = patch.metadata;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return;
  const incomingState = operationSuccessEvidenceRequiredMetadataState(metadata);
  if (!incomingState.present) return;
  const existing = operationSuccessEvidenceRequired(current);
  const incoming = incomingState.value;
  if (!initializing && incoming !== existing) {
    throw new Error("operation_success_evidence_required is write-once after ProofReady success evidence is established");
  }
}

const commonReservationPatchFields = new Set([
  "updated_at", "updatedAt", "metadata",
  "lease_owner", "leaseOwner", "lease_token", "leaseToken",
  "lease_until", "leaseUntil", "last_heartbeat_at", "lastHeartbeatAt"
]);
const broadcastReservationPatchFields = new Set([
  "submitted_tx_hash", "submittedTxHash", "txHashSubmitted",
  "tx_bytes_hash", "txBytesHash", "sign_doc_hash", "signDocHash",
  "broadcast_attempt_count", "broadcastAttemptCount",
  "broadcast_in_flight", "broadcastInFlight",
  "last_broadcast_error", "lastBroadcastError"
]);
const reconciliationReservationPatchFields = new Set([
  "nullifier_unspent_confirmed", "nullifierUnspentConfirmed",
  "checked_height", "checkedHeight",
  "tx_hash_checked", "txHashChecked",
  "tx_absent_or_failed_confirmed", "txAbsentOrFailedConfirmed",
  "proof_discarded", "proofDiscarded",
  "authoritative_expiry_confirmed", "authoritativeExpiryConfirmed"
]);

const reconciliationMetadataAliases = [
  ["nullifier_unspent_confirmed", "nullifierUnspentConfirmed", true],
  ["checked_height", "checkedHeight", false],
  ["tx_hash_checked", "txHashChecked", false],
  ["tx_absent_or_failed_confirmed", "txAbsentOrFailedConfirmed", true],
  ["proof_discarded", "proofDiscarded", true],
  ["authoritative_expiry_confirmed", "authoritativeExpiryConfirmed", true]
];

function patchWithPersistedReconciliationEvidence(patch = {}) {
  let metadata = patch.metadata;
  let changed = false;
  for (const [field, alias, isBoolean] of reconciliationMetadataAliases) {
    if (!patchHasAnyOwnProperty(patch, [field, alias])) continue;
    if (!changed) {
      metadata = {
        ...(metadata && typeof metadata === "object" && !Array.isArray(metadata)
          ? metadata
          : {})
      };
      changed = true;
    }
    const value = patchValueForAliases(patch, [field, alias]);
    metadata[field] = isBoolean ? booleanEvidence(value) : value;
  }
  return changed ? { ...patch, metadata } : patch;
}

function allowedReservationPatchFields(current, to, {
  managedRelayHandoff = false,
  managedBroadcastAttempt = false,
  managedOperationReconcile = false
} = {}) {
  const allowed = new Set(commonReservationPatchFields);
  if (to === reservationStatuses.ProofReady && current.status === reservationStatuses.Proving) {
    for (const aliases of operationSuccessPredicateFields) {
      for (const alias of aliases) allowed.add(alias);
    }
    allowed.add("payload_hash");
    allowed.add("payloadHash");
    allowed.add("sign_doc_hash");
    allowed.add("signDocHash");
    allowed.add("tx_bytes_hash");
    allowed.add("txBytesHash");
  }
  if (managedRelayHandoff) {
    allowed.add("payload_hash");
    allowed.add("payloadHash");
    allowed.add("tx_bytes_hash");
    allowed.add("txBytesHash");
    allowed.add("sign_doc_hash");
    allowed.add("signDocHash");
  }
  if (managedBroadcastAttempt) {
    for (const field of broadcastReservationPatchFields) allowed.add(field);
  }
  if ([
    reservationStatuses.Submitted,
    reservationStatuses.Unknown,
    reservationStatuses.ReplanRequired,
    reservationStatuses.Failed,
    reservationStatuses.ManualReview
  ].includes(to)) {
    for (const field of broadcastReservationPatchFields) allowed.add(field);
    for (const field of reconciliationReservationPatchFields) allowed.add(field);
  }
  if (managedOperationReconcile) {
    return new Set(["updated_at", "updatedAt", "metadata"]);
  }
  return allowed;
}

function assertReservationTransitionPatchFields(current, to, patch = {}, options = {}) {
  const allowed = allowedReservationPatchFields(current, to, options);
  const disallowed = Object.keys(patch).find(field => !allowed.has(field));
  if (disallowed) {
    throw new Error(`reservation patch field is not allowed for ${current.status} -> ${to}: ${disallowed}`);
  }
}

function assertManagedOperationReconciliation(current, to, patch = {}) {
  if (patch[managedOperationReconciliation] !== true) return false;
  if (to !== current.status && to !== reservationStatuses.ConfirmedSpent) {
    throw new Error("managed operation reconciliation may only retain status or quarantine a spent note");
  }
  const metadata = patch.metadata;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new Error("managed operation reconciliation requires operation outcome metadata");
  }
  for (const [field, value] of Object.entries(current.metadata || {})) {
    if (operationOutcomeMetadataFields.has(field)) continue;
    if (!Object.prototype.hasOwnProperty.call(metadata, field) ||
        JSON.stringify(metadata[field]) !== JSON.stringify(value)) {
      throw new Error(`${field} metadata cannot change during operation reconciliation`);
    }
  }
  const unexpected = Object.keys(metadata).find(field =>
    !operationOutcomeMetadataFields.has(field) &&
    !Object.prototype.hasOwnProperty.call(current.metadata || {}, field)
  );
  if (unexpected) {
    throw new Error(`${unexpected} metadata cannot be added during operation reconciliation`);
  }
  return true;
}

function assertSameStatusLeaseRenewalPatch(current, patch = {}, now) {
  const keys = Object.keys(patch);
  if (!keys.some(key => sameStatusLeasePatchFields.has(key)) ||
      keys.some(key => !sameStatusLeasePatchFields.has(key))) {
    throw new Error("same-status reservation mutations are limited to lease renewal fields");
  }
  const leaseUntil = Date.parse(String(patch.lease_until || patch.leaseUntil || ""));
  if (!Number.isFinite(leaseUntil) || leaseUntil <= new Date(now).getTime()) {
    throw new Error("same-status lease renewal requires a future lease_until");
  }
  const existingLeaseUntil = leaseExpirationMs(current);
  if (existingLeaseUntil > leaseUntil) {
    throw new Error("same-status lease renewal cannot shorten an existing lease");
  }
  assertCurrentLeaseToken(current, patchLeaseToken(patch), patchLeaseOwner(patch), now);
}

function isManagedRelayHandoffMutation(current, to, patch = {}) {
  return patch[managedReservationEvidenceMutation] === "relay_handoff" &&
    current.status === reservationStatuses.ProofReady &&
    to === reservationStatuses.ProofReady;
}

function isManagedBroadcastAttemptMutation(current, to, patch = {}) {
  return patch[managedReservationEvidenceMutation] === "broadcast_attempt" &&
    current.status === reservationStatuses.ProofReady &&
    to === reservationStatuses.ProofReady;
}

function assertManagedBroadcastAttemptMutation(current, to, patch, now) {
  if (!isManagedBroadcastAttemptMutation(current, to, patch)) return false;
  if (current.metadata?.relay_handed_off === true || current.metadata?.relayHandedOff === true) {
    throw new Error("relay payload was handed off");
  }
  if (current.broadcast_in_flight || Number(current.broadcast_attempt_count || 0) > 0) {
    throw new Error("broadcast attempt already started; reconcile before retry");
  }
  if (patch.broadcast_in_flight !== true) {
    throw new Error("broadcast attempt must set broadcast_in_flight");
  }
  if (Number(patch.broadcast_attempt_count) !== Number(current.broadcast_attempt_count || 0) + 1) {
    throw new Error("broadcast attempt count must increase exactly once");
  }
  if (patch.metadata?.no_broadcast_attempt !== false) {
    throw new Error("broadcast attempt must clear no_broadcast_attempt evidence");
  }
  assertCurrentLeaseToken(current, patchLeaseToken(patch), patchLeaseOwner(patch), now);
  return true;
}

function isManagedBroadcastRejectionMutation(current, to, patch = {}) {
  return patch[managedReservationEvidenceMutation] === "broadcast_rejected" &&
    current.status === reservationStatuses.ProofReady &&
    to === reservationStatuses.ReplanRequired;
}

function assertManagedBroadcastRejectionMutation(current, to, patch, now) {
  if (!isManagedBroadcastRejectionMutation(current, to, patch)) return false;
  if (current.metadata?.relay_handed_off === true || current.metadata?.relayHandedOff === true) {
    throw new Error("relay payload was handed off");
  }
  const durableBroadcastRejection = current.broadcast_in_flight &&
    Number(current.broadcast_attempt_count || 0) >= 1;
  const preparedSigningRejection = !current.broadcast_in_flight &&
    Number(current.broadcast_attempt_count || 0) === 0 &&
    Boolean(current.sign_doc_hash) &&
    !current.tx_bytes_hash &&
    !current.submitted_tx_hash;
  if (!durableBroadcastRejection && !preparedSigningRejection) {
    throw new Error("wallet rejection resolution requires a prepared sign-doc or durable in-flight broadcast attempt");
  }
  if (
    patch.metadata?.wallet_rejected_before_broadcast !== true ||
    String(patch.metadata?.provider_rejection_code || "") !== "4001" ||
    patch.metadata?.no_broadcast_attempt !== true ||
    patch.metadata?.proof_discarded !== true
  ) {
    throw new Error("wallet rejection resolution requires definitive no-broadcast and proof-discard evidence");
  }
  assertCurrentLeaseToken(current, patchLeaseToken(patch), patchLeaseOwner(patch), now);
  return true;
}

function assertManagedRelayHandoffMutation(current, to, patch, now) {
  if (!isManagedRelayHandoffMutation(current, to, patch)) return false;
  if (current.broadcast_in_flight || Number(current.broadcast_attempt_count || 0) > 0) {
    throw new Error("broadcast attempt already started; reconcile before relay handoff");
  }
  const metadata = patch.metadata;
  if (!metadata || !booleanEvidence(metadata.relay_handed_off)) {
    throw new Error("relay handoff evidence requires relay_handed_off metadata");
  }
  const payloadHash = String(patch.payload_hash || patch.payloadHash || "");
  if (!payloadHash || !current.payload_hash || payloadHash !== current.payload_hash) {
    throw new Error("relay handoff payload hash must match the ProofReady reservation");
  }
  assertCurrentLeaseToken(current, patchLeaseToken(patch), patchLeaseOwner(patch), now);
  return true;
}

function assertStoreLeaseMutationAllowed(current, to, patch, now) {
  if (requiresReservationLeaseToken(current.status, to)) {
    if (
      canApplyExpiredLeaseRecovery(current, to, patch, now)
    ) {
      return;
    }
    assertLeaseTransitionAllowed(current, to, patch, now);
    return;
  }
  if (isLeaseRenewalPatch(current, to, patch)) {
    assertCurrentLeaseToken(current, patchLeaseToken(patch), patchLeaseOwner(patch), now);
  }
}

function clearsLeaseForStatusTransition(to) {
  return ![
    reservationStatuses.Proving,
    reservationStatuses.ProofReady
  ].includes(to);
}

function patchWithClearedLease(to, patch = {}) {
  if (!clearsLeaseForStatusTransition(to)) return patch;
  return {
    ...patch,
    lease_owner: "",
    lease_token: "",
    lease_until: "",
    last_heartbeat_at: "",
    broadcast_in_flight: false
  };
}

function leaseUntilFromMetadata(metadata = {}, now, fallbackDurationMs) {
  const explicitLeaseUntil = metadata.leaseUntil || metadata.lease_until;
  const leaseUntil = explicitLeaseUntil
    ? nowIso(explicitLeaseUntil)
    : futureIso(now, Number(metadata.leaseDurationMs || metadata.lease_duration_ms || fallbackDurationMs));
  if (Date.parse(leaseUntil) <= new Date(now).getTime()) {
    throw new Error("reservation lease renewal must extend into the future");
  }
  return leaseUntil;
}

function broadcastAttemptMetadata(metadata = {}) {
  return {
    txHash: String(metadata.txHash || metadata.tx_hash || metadata.submitted_tx_hash || metadata.submittedTxHash || metadata.txHashSubmitted || ""),
    txBytesHash: String(metadata.txBytesHash || metadata.tx_bytes_hash || ""),
    signDocHash: String(metadata.signDocHash || metadata.sign_doc_hash || "")
  };
}

function hasBroadcastAttemptMetadata(metadata = {}) {
  const attempt = broadcastAttemptMetadata(metadata);
  return Boolean(attempt.txHash || attempt.txBytesHash);
}

function hasSubmittedBroadcastAttemptMetadata(metadata = {}) {
  const attempt = broadcastAttemptMetadata(metadata);
  return Boolean(attempt.txHash || attempt.txBytesHash);
}

function assertBroadcastAttemptMetadata(metadata = {}, status = "reservation transition") {
  if (!hasBroadcastAttemptMetadata(metadata)) {
    throw new Error(`${status} requires broadcast attempt metadata`);
  }
}

function assertSubmittedBroadcastAttemptMetadata(metadata = {}, status = "reservation transition") {
  if (!hasSubmittedBroadcastAttemptMetadata(metadata)) {
    throw new Error(`${status} requires submitted tx hash or tx bytes hash`);
  }
}

function assertCoreTransitionEvidence(from, to, patch = {}) {
  if (to === reservationStatuses.ConfirmedSpent) {
    if (!patch[reconciledSpentTransition]) {
      throw new Error("ConfirmedSpent transitions require reconcileSpentNotes chain spent evidence");
    }
    return;
  }
  if (from !== reservationStatuses.ProofReady) return;
  if (to === reservationStatuses.Submitted) {
    assertSubmittedBroadcastAttemptMetadata(patch, "ProofReady -> Submitted");
  } else if (to === reservationStatuses.Unknown) {
    assertBroadcastAttemptMetadata(patch, "ProofReady -> Unknown");
  }
}

function assertStoreTransitionEvidence(current, to, patch = {}) {
  if (
    current.status === reservationStatuses.ProofReady &&
    [reservationStatuses.Submitted, reservationStatuses.Unknown].includes(to) &&
    (!current.broadcast_in_flight || Number(current.broadcast_attempt_count || 0) < 1)
  ) {
    throw new Error("durable broadcast attempt is required before terminal bookkeeping");
  }
  assertCoreTransitionEvidence(current.status, to, patch);
  assertInactiveTransitionEvidence(current, to, patch);
}

function metadataEvidenceValue(input = {}, ...keys) {
  const nested = metadataObject(input);
  return firstDefined(
    ...keys.flatMap(key => [input[key], nested[key]])
  );
}

function hasStoredBroadcastEvidence(reservation = {}) {
  return Boolean(
    String(firstDefined(
      reservation.submitted_tx_hash,
      reservation.submittedTxHash,
      reservation.tx_hash,
      reservation.txHash
    ) || "").trim() ||
    Number(reservation.broadcast_attempt_count || 0) > 0 ||
    booleanEvidence(firstDefined(
      reservation.broadcast_in_flight,
      reservation.broadcastInFlight
    )) ||
    booleanEvidence(reservation.metadata?.relay_handed_off) ||
    booleanEvidence(reservation.metadata?.relayHandedOff)
  );
}

function hasProofDiscardEvidence(reservation = {}, metadata = {}) {
  return Boolean(
    booleanEvidence(consistentMetadataAliasValue(
      metadata,
      ["no_broadcast_attempt", "noBroadcastAttempt"],
      "no broadcast attempt evidence",
      { boolean: true }
    )) &&
    booleanEvidence(consistentMetadataAliasValue(
      metadata,
      ["proof_discarded", "proofDiscarded"],
      "proof discarded evidence",
      { boolean: true }
    )) &&
    !hasStoredBroadcastEvidence(reservation) &&
    !hasStoredBroadcastEvidence(metadata)
  );
}

function hasManualReviewApprovalEvidence(metadata = {}) {
  const approved = booleanEvidence(metadataEvidenceValue(
    metadata,
    "operator_approved",
    "operatorApproved",
    "manual_review_approved",
    "manualReviewApproved"
  ));
  const reference = String(metadataEvidenceValue(
    metadata,
    "operator_approval_reference",
    "operatorApprovalReference",
    "manual_review_resolution",
    "manualReviewResolution"
  ) || "").trim();
  const operatorID = String(metadataEvidenceValue(
    metadata,
    "operator_id",
    "operatorId",
    "operatorID"
  ) || "").trim();
  return approved && Boolean(operatorID) && Boolean(reference);
}

function assertInactiveTransitionEvidence(current, to, metadata = {}) {
  const from = current.status;
  if (
    (from === reservationStatuses.Submitted || from === reservationStatuses.Unknown) &&
    (to === reservationStatuses.ReplanRequired || to === reservationStatuses.Failed) &&
    !hasPostBroadcastReplanEvidence(metadata)
  ) {
    throw new Error(`${from} -> ${to} requires nullifier_unspent_confirmed and tx_absent_or_failed_confirmed reconcile evidence`);
  }
  if (from === reservationStatuses.ProofReady && to === reservationStatuses.ReplanRequired) {
    if (!hasProofDiscardEvidence(current, metadata)) {
      throw new Error("ProofReady -> ReplanRequired requires no_broadcast_attempt and proof_discarded evidence");
    }
  }
  if (
    from === reservationStatuses.ManualReview &&
    [reservationStatuses.Released, reservationStatuses.ReplanRequired, reservationStatuses.Failed].includes(to) &&
    !hasManualReviewApprovalEvidence(metadata)
  ) {
    throw new Error(`${from} -> ${to} requires operator approval evidence`);
  }
}

function reconciledSpentPatch(patch = {}, { operationReconcile = false } = {}) {
  const authorized = { ...patch };
  Object.defineProperty(authorized, reconciledSpentTransition, { value: true });
  if (operationReconcile) {
    Object.defineProperty(authorized, managedOperationReconciliation, { value: true });
  }
  return authorized;
}

function operationReconciliationOutcome(reservations, spentNotesByLookupKey) {
  const requiresEvidence = reservations.some(operationSuccessEvidenceRequired);
  if (!requiresEvidence) return { evaluated: false, matches: true, errors: [] };
  const evaluations = [];
  for (const reservation of reservations) {
    const note = spentNotesByLookupKey.get(reservation.nullifier_lookup_key);
    if (!note) {
      return {
        evaluated: true,
        matches: false,
        operationStatus: operationStatuses.ManualReview,
        errors: ["operation input evidence incomplete"]
      };
    }
    const evidence = evaluateOperationSuccessEvidence(reservation, note);
    if (!evidence.evaluated) {
      return {
        evaluated: true,
        matches: false,
        operationStatus: operationStatuses.ManualReview,
        errors: ["operation input evidence incomplete"]
      };
    }
    evaluations.push(evidence);
  }
  const errors = [...new Set(evaluations.flatMap(evidence => evidence.errors))];
  if (evaluations.some(evidence => !evidence.matches)) {
    return {
      evaluated: true,
      matches: false,
      operationStatus: operationStatuses.ConflictSpent,
      errors: errors.length ? errors : ["operation input evidence conflict"]
    };
  }
  return {
    evaluated: true,
    matches: true,
    operationStatus: operationStatuses.Succeeded,
    errors: []
  };
}

function operationReconciliationTransitions(reservations, spentNotesByLookupKey, now) {
  const outcome = operationReconciliationOutcome(reservations, spentNotesByLookupKey);
  const priorSucceeded = reservations.some(
    reservation => reservation.metadata?.operation_status === operationStatuses.Succeeded
  );
  if (priorSucceeded) {
    const allSucceeded = reservations.every(reservation =>
      reservation.status === reservationStatuses.ConfirmedSpent &&
      reservation.metadata?.operation_status === operationStatuses.Succeeded &&
      reservation.metadata?.operation_success_evidence_matches === true
    );
    if (!allSucceeded) {
      throw new Error("retry evidence conflicts with a succeeded operation reconciliation");
    }
    const explicitEvidenceKeys = [
      "operationSuccessEvidence", "operation_success_evidence", "successEvidence",
      "success_evidence", "evidence", "txResult", "tx_result", "transactionResult",
      "transaction_result", "broadcastResult", "broadcast_result", "outputCommitment",
      "output_commitment", "outputCommitmentHex", "output_commitment_hex",
      "commitmentHex", "commitment_hex", "auditDisclosureDigest",
      "audit_disclosure_digest", "auditDisclosureDigestHex",
      "audit_disclosure_digest_hex", "disclosureDigest", "disclosure_digest",
      "recipientHash", "recipient_hash", "recipientHashHex", "recipient_hash_hex",
      "amountHash", "amount_hash", "amountHashHex", "amount_hash_hex",
      "expectedOutputCommitment", "expected_output_commitment",
      "expectedDisclosureDigest", "expected_disclosure_digest",
      "expectedRecipientHash", "expected_recipient_hash", "expectedAmount",
      "expected_amount", "operationAmount", "operation_amount", "actualAmount",
      "actual_amount", "expectedAmountHash", "expected_amount_hash",
      "expectedDenom", "expected_denom", "operationDenom", "operation_denom",
      "actualDenom", "actual_denom", "batchItemIndex", "batch_item_index",
      "itemIndex", "item_index", "batchItemIndexKnown", "batch_item_index_known",
      "itemIndexKnown", "item_index_known"
    ];
    for (const reservation of reservations) {
      const note = spentNotesByLookupKey.get(reservation.nullifier_lookup_key);
      if (!note) continue;
      const hasExplicitEvidence = explicitEvidenceKeys.some(key =>
        Object.prototype.hasOwnProperty.call(note, key) && note[key] != null
      );
      if (!hasExplicitEvidence) continue;
      const evidence = evaluateOperationSuccessEvidence(reservation, note);
      if (!evidence.evaluated || !evidence.matches) {
        throw new Error("retry evidence conflicts with a succeeded operation reconciliation");
      }
    }
    return [];
  }
  const transitions = [];
  for (const reservation of reservations) {
    const spent = spentNotesByLookupKey.has(reservation.nullifier_lookup_key);
    if (spent && reservation.status === reservationStatuses.ConfirmedSpent && !outcome.evaluated) {
      continue;
    }
    const to = spent ? reservationStatuses.ConfirmedSpent : reservation.status;
    if (!spent && !outcome.evaluated) continue;
    const patch = { updated_at: now };
    if (outcome.evaluated) {
      patch.metadata = {
        ...(reservation.metadata || {}),
        operation_status: outcome.operationStatus,
        operation_success_evidence_matches: outcome.matches,
        operation_success_evidence_errors: outcome.errors
      };
    }
    transitions.push({
      reservationID: reservation.reservation_id,
      from: reservation.status,
      to,
      patch: reconciledSpentPatch(patch, { operationReconcile: outcome.evaluated })
    });
  }
  return transitions;
}

function metadataObject(metadata = {}) {
  const nested = metadata.metadata;
  return nested && typeof nested === "object" && !Array.isArray(nested) ? nested : {};
}

function firstDefined(...values) {
  return values.find(value => value !== undefined && value !== null);
}

function consistentMetadataAliasValue(metadata = {}, keys = [], label, { boolean = false } = {}) {
  const nested = metadataObject(metadata);
  const values = [];
  for (const source of [metadata, nested]) {
    for (const key of keys) {
      if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
      const value = source[key];
      if (value === undefined || value === null) continue;
      if (boolean && typeof value !== "boolean") {
        throw new Error(`${label} must be a boolean`);
      }
      values.push(value);
    }
  }
  if (!values.length) return undefined;
  const normalized = values.map(value => boolean ? value : String(value));
  if (normalized.some(value => value !== normalized[0])) {
    throw new Error(`${label} aliases conflict`);
  }
  return values[0];
}

function aliasedStringValue(input = {}, canonicalKey, aliasKey, label) {
  const canonical = input?.[canonicalKey];
  const alias = input?.[aliasKey];
  if (
    canonical !== undefined && canonical !== null &&
    alias !== undefined && alias !== null &&
    String(canonical) !== String(alias)
  ) {
    throw new Error(`${label} aliases conflict`);
  }
  return String(firstDefined(canonical, alias, ""));
}

function aliasedStringArray(input = {}, canonicalKey, aliasKey, label) {
  const canonical = input?.[canonicalKey];
  const alias = input?.[aliasKey];
  for (const value of [canonical, alias]) {
    if (value !== undefined && value !== null && !Array.isArray(value)) {
      throw new Error(`${label} must be an array`);
    }
  }
  const canonicalValues = canonical == null ? null : canonical.map(String);
  const aliasValues = alias == null ? null : alias.map(String);
  if (
    canonicalValues && aliasValues &&
    (canonicalValues.length !== aliasValues.length ||
      canonicalValues.some((value, index) => value !== aliasValues[index]))
  ) {
    throw new Error(`${label} aliases conflict`);
  }
  return canonicalValues || aliasValues || [];
}

function booleanEvidence(value) {
  return value === true;
}

function hasLiteralSpentEvidence(note = {}) {
  return ["spent", "isSpent", "is_spent"].some(field =>
    Object.prototype.hasOwnProperty.call(note || {}, field) && note[field] === true
  );
}

function operationEvidenceEnvelopesEqual(left, right, seen = new WeakMap()) {
  if (Object.is(left, right)) return true;
  if (
    left === null || right === null ||
    typeof left !== "object" || typeof right !== "object"
  ) {
    return false;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) &&
      left.length === right.length &&
      left.every((value, index) => operationEvidenceEnvelopesEqual(value, right[index], seen));
  }
  if (ArrayBuffer.isView(left) || ArrayBuffer.isView(right)) {
    if (!ArrayBuffer.isView(left) || !ArrayBuffer.isView(right)) return false;
    const leftBytes = new Uint8Array(left.buffer, left.byteOffset, left.byteLength);
    const rightBytes = new Uint8Array(right.buffer, right.byteOffset, right.byteLength);
    return leftBytes.length === rightBytes.length &&
      leftBytes.every((value, index) => value === rightBytes[index]);
  }
  const leftPrototype = Object.getPrototypeOf(left);
  const rightPrototype = Object.getPrototypeOf(right);
  if (leftPrototype !== rightPrototype || (leftPrototype !== Object.prototype && leftPrototype !== null)) {
    return false;
  }
  let rightObjects = seen.get(left);
  if (rightObjects?.has(right)) return true;
  if (!rightObjects) {
    rightObjects = new WeakSet();
    seen.set(left, rightObjects);
  }
  rightObjects.add(right);
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index] &&
      operationEvidenceEnvelopesEqual(left[key], right[key], seen));
}

function nestedOperationEvidence(input = {}) {
  const candidates = [];
  for (const key of ["operationSuccessEvidence", "operation_success_evidence", "successEvidence", "success_evidence", "evidence"]) {
    const candidate = input?.[key];
    if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
      candidates.push(candidate);
    }
  }
  if (candidates.length > 1 && candidates.slice(1).some(candidate =>
    !operationEvidenceEnvelopesEqual(candidates[0], candidate)
  )) {
    throw new Error("operation success evidence envelope aliases conflict");
  }
  return candidates[0] || null;
}

function txResultObjects(input = {}) {
  const results = [];
  for (const key of ["txResult", "tx_result", "transactionResult", "transaction_result", "broadcastResult", "broadcast_result"]) {
    const candidate = input?.[key];
    if (
      candidate &&
      typeof candidate === "object" &&
      !Array.isArray(candidate) &&
      !results.includes(candidate)
    ) {
      results.push(candidate);
    }
  }
  return results;
}

function executionResultObjects(...sources) {
  const results = [];
  for (const source of sources) {
    if (!source || typeof source !== "object" || Array.isArray(source)) continue;
    const rawEvmReceipt = [
      "txHash", "tx_hash", "txhash", "hash", "submittedTxHash",
      "submitted_tx_hash", "txHashSubmitted", "transactionHash",
      "transaction_hash", "transaction_hash_hex"
    ].some(key => Object.prototype.hasOwnProperty.call(source, key)) &&
      ["status", "receiptStatus", "receipt_status"].some(key =>
        Object.prototype.hasOwnProperty.call(source, key)
      );
    for (const nestedResult of txResultObjects(source)) {
      if (!results.includes(nestedResult)) results.push(nestedResult);
    }
    const topLevelResult = (
      Object.prototype.hasOwnProperty.call(source, "code") ||
      Object.prototype.hasOwnProperty.call(source, "receipt") ||
      rawEvmReceipt
        ? source
        : null
    );
    if (topLevelResult && !results.includes(topLevelResult)) results.push(topLevelResult);
  }
  return results;
}

const executionResultContainerKeys = [
  "broadcast",
  "tx",
  "tx_response",
  "txResponse",
  "receipt",
  "transactionReceipt",
  "transaction_receipt"
];

function executionResultContainers(result = {}) {
  if (!result || typeof result !== "object" || Array.isArray(result)) return [];
  const containers = [];
  const queue = [result];
  const seen = new Set();
  while (queue.length) {
    const candidate = queue.shift();
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) || seen.has(candidate)) {
      continue;
    }
    seen.add(candidate);
    containers.push(candidate);
    for (const key of executionResultContainerKeys) {
      const nested = candidate[key];
      if (nested && typeof nested === "object" && !Array.isArray(nested)) {
        queue.push(nested);
      }
    }
  }
  return containers;
}

function identityValuesFromResult(result = {}, keys = []) {
  return executionResultContainers(result)
    .flatMap(container => keys.map(key => container[key]))
    .filter(value => value !== undefined && value !== null && String(value).trim() !== "")
    .map(String);
}

function uniqueIdentityValues(values = []) {
  return [...new Set(values.filter(value => String(value).trim() !== "").map(String))];
}

function operationEvidenceAliasConflict(sources = [], keys = [], {
  caseInsensitive = false
} = {}) {
  const values = [];
  for (const source of sources) {
    if (!source || typeof source !== "object" || Array.isArray(source)) continue;
    for (const key of keys) {
      if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
      const value = source[key];
      if (value === undefined || value === null) continue;
      const normalized = String(value).trim();
      values.push(caseInsensitive ? normalized.toLowerCase() : normalized);
    }
  }
  return new Set(values).size > 1;
}

function operationSuccessEvidence(input = {}) {
  const nested = nestedOperationEvidence(input);
  const evidenceSource = nested || input;
  const source = evidenceSource;
  const aliasSources = [evidenceSource];
  const txResults = executionResultObjects(evidenceSource);
  const txResult = txResults[0] || null;
  const txHashKeys = [
    "txHash", "tx_hash", "txhash", "hash", "submittedTxHash",
    "submitted_tx_hash", "txHashSubmitted", "transactionHash",
    "transaction_hash", "transaction_hash_hex"
  ];
  const txBytesHashKeys = ["txBytesHash", "tx_bytes_hash", "txBytes", "tx_bytes"];
  const signDocHashKeys = ["signDocHash", "sign_doc_hash", "signDoc", "sign_doc"];
  const txHashes = uniqueIdentityValues([
    ...identityValuesFromResult(evidenceSource, txHashKeys),
    ...txResults.flatMap(result => identityValuesFromResult(result, txHashKeys))
  ]);
  const txBytesHashes = uniqueIdentityValues([
    ...identityValuesFromResult(evidenceSource, txBytesHashKeys),
    ...txResults.flatMap(result => identityValuesFromResult(result, txBytesHashKeys))
  ]);
  const signDocHashes = uniqueIdentityValues([
    ...identityValuesFromResult(evidenceSource, signDocHashKeys),
    ...txResults.flatMap(result => identityValuesFromResult(result, signDocHashKeys))
  ]);
  const batchItemIndexKeys = [
    "batchItemIndex", "batch_item_index", "itemIndex", "item_index"
  ];
  const batchItemIndexKnownKeys = [
    "batchItemIndexKnown", "batch_item_index_known", "itemIndexKnown", "item_index_known"
  ];
  const batchItemIndex = firstDefined(...batchItemIndexKeys.map(key => source[key]));
  const batchItemIndexKnown = firstDefined(...batchItemIndexKnownKeys.map(key => source[key]));
  const normalizedItemIndex = normalizedBatchItemIndex(batchItemIndex);
  const outputCommitmentKeys = [
    "expectedOutputCommitment", "expected_output_commitment",
    "outputCommitment", "output_commitment", "outputCommitmentHex",
    "output_commitment_hex", "commitmentHex", "commitment_hex"
  ];
  const disclosureDigestKeys = [
    "expectedDisclosureDigest", "expected_disclosure_digest",
    "auditDisclosureDigest", "audit_disclosure_digest",
    "auditDisclosureDigestHex", "audit_disclosure_digest_hex",
    "disclosureDigest", "disclosure_digest"
  ];
  const recipientHashKeys = [
    "expectedRecipientHash", "expected_recipient_hash",
    "recipientHash", "recipient_hash", "recipientHashHex",
    "recipient_hash_hex"
  ];
  const amountKeys = [
    "expectedAmount", "expected_amount", "operationAmount",
    "operation_amount", "actualAmount", "actual_amount",
    ...(nested ? ["amount"] : [])
  ];
  const amountHashKeys = [
    "expectedAmountHash", "expected_amount_hash", "amountHash",
    "amount_hash", "amountHashHex", "amount_hash_hex"
  ];
  const denomKeys = [
    "expectedDenom", "expected_denom", "operationDenom",
    "operation_denom", "actualDenom", "actual_denom", "denom",
    "assetDenom", "asset_denom"
  ];
  const aliasErrors = [];
  for (const [field, keys, options] of [
    ["expected_output_commitment", outputCommitmentKeys, { caseInsensitive: true }],
    ["expected_disclosure_digest", disclosureDigestKeys, { caseInsensitive: true }],
    ["expected_recipient_hash", recipientHashKeys, { caseInsensitive: true }],
    ["expected_amount", amountKeys, {}],
    ["expected_amount_hash", amountHashKeys, { caseInsensitive: true }],
    ["expected_denom", denomKeys, {}],
    ["batch_item_index", batchItemIndexKeys, {}],
    ["batch_item_index_known", batchItemIndexKnownKeys, {}]
  ]) {
    if (operationEvidenceAliasConflict(aliasSources, keys, options)) {
      aliasErrors.push(`${field} evidence aliases conflict`);
    }
  }
  const aliasValue = keys => String(firstDefined(...keys.map(key => source[key]), ""));
  return {
    txHash: txHashes[0] || "",
    txHashes,
    txBytesHash: txBytesHashes[0] || "",
    txBytesHashes,
    signDocHash: signDocHashes[0] || "",
    signDocHashes,
    txResult,
    txResults,
    outputCommitment: aliasValue(outputCommitmentKeys),
    disclosureDigest: aliasValue(disclosureDigestKeys),
    recipientHash: aliasValue(recipientHashKeys),
    amount: aliasValue(amountKeys),
    amountHash: aliasValue(amountHashKeys),
    denom: aliasValue(denomKeys),
    aliasErrors,
    batchItemIndex: normalizedItemIndex.value,
    batchItemIndexValid: normalizedItemIndex.valid,
    batchItemIndexProvided: normalizedItemIndex.provided,
    batchItemIndexKnown: batchItemIndexKnown !== undefined && batchItemIndexKnown !== null
      ? booleanEvidence(batchItemIndexKnown)
      : batchItemIndex !== undefined && batchItemIndex !== null
  };
}

function expectedOperationSuccessEvidence(reservation = {}) {
  const batchItemIndex = normalizedBatchItemIndex(reservation.batch_item_index);
  return {
    outputCommitment: String(reservation.expected_output_commitment || ""),
    disclosureDigest: String(reservation.expected_disclosure_digest || ""),
    recipientHash: String(reservation.expected_recipient_hash || ""),
    amount: String(reservation.expected_amount || ""),
    amountHash: String(reservation.expected_amount_hash || ""),
    denom: String(reservation.expected_denom || ""),
    batchItemIndex: batchItemIndex.value,
    batchItemIndexValid: batchItemIndex.valid,
    batchItemIndexProvided: batchItemIndex.provided,
    batchItemIndexKnown: booleanEvidence(reservation.batch_item_index_known)
  };
}

function operationSuccessEvidenceRequired(reservation = {}) {
  const metadata = reservation.metadata || {};
  return booleanEvidence(firstDefined(
    metadata.operation_success_evidence_required,
    metadata.operationSuccessEvidenceRequired,
    reservation.operation_success_evidence_required,
    reservation.operationSuccessEvidenceRequired,
    false
  ));
}

function operationEvidenceValuesEqual(expected, actual, { caseInsensitive = false } = {}) {
  const left = String(expected || "").trim();
  const right = String(actual || "").trim();
  if (caseInsensitive) return left.toLowerCase() === right.toLowerCase();
  return left === right;
}

function normalizedTxIdentity(value) {
  return String(value || "").trim().toLowerCase().replace(/^0x/, "");
}

function normalizedIdentityValues(values = []) {
  return [...new Set(values.map(normalizedTxIdentity).filter(Boolean))];
}

function evaluateOperationTxIdentity(reservation = {}, actual = {}) {
  const expectedTxHash = normalizedTxIdentity(reservation.submitted_tx_hash);
  const expectedTxBytesHash = normalizedTxIdentity(reservation.tx_bytes_hash);
  const actualTxHashes = normalizedIdentityValues(actual.txHashes || [actual.txHash]);
  const actualTxBytesHashes = normalizedIdentityValues(actual.txBytesHashes || [actual.txBytesHash]);
  const expectedSignDoc = normalizedTxIdentity(reservation.sign_doc_hash);
  const actualSignDocs = normalizedIdentityValues(actual.signDocHashes || [actual.signDocHash]);
  const actualIdentitySeen = Boolean(
    actualTxHashes.length ||
    actualTxBytesHashes.length ||
    actualSignDocs.length
  );
  const errors = [];
  let matched = false;

  if (!actualIdentitySeen) {
    errors.push("tx_hash_or_tx_result identity missing");
  }
  if (!expectedTxHash && !expectedTxBytesHash) {
    errors.push("persisted tx_hash_or_tx_bytes identity missing");
  }
  if (actualTxHashes.length > 1) {
    errors.push("tx_hash evidence conflict");
  }
  if (actualTxBytesHashes.length > 1) {
    errors.push("tx_bytes_hash evidence conflict");
  }
  if (actualSignDocs.length > 1) {
    errors.push("sign_doc_hash evidence conflict");
  }
  for (const actualTxHash of actualTxHashes) {
    if (!expectedTxHash || actualTxHash !== expectedTxHash) {
      errors.push("tx_hash_or_tx_bytes mismatch");
    } else {
      matched = true;
    }
  }
  for (const actualTxBytesHash of actualTxBytesHashes) {
    if (!expectedTxBytesHash || actualTxBytesHash !== expectedTxBytesHash) {
      errors.push("tx_hash_or_tx_bytes mismatch");
    } else {
      matched = true;
    }
  }
  if (expectedSignDoc) {
    for (const actualSignDoc of actualSignDocs) {
      if (actualSignDoc !== expectedSignDoc) {
        errors.push("sign_doc_hash mismatch");
      }
    }
  }
  if (!matched && !errors.length) {
    errors.push("matching persisted tx identity missing");
  }
  return { matches: errors.length === 0 && matched, errors };
}

function executionOutcomeErrors(txResult) {
  if (!txResult || typeof txResult !== "object") return [];
  const errors = [];
  const containers = executionResultContainers(txResult);
  const cosmosCodes = containers
    .filter(container => Object.prototype.hasOwnProperty.call(container, "code"))
    .map(container => container.code)
    .filter(code => code !== undefined && code !== null && String(code).trim() !== "");
  for (const cosmosCode of cosmosCodes) {
    const normalized = typeof cosmosCode === "number"
      ? Number.isSafeInteger(cosmosCode) && cosmosCode >= 0 ? cosmosCode : null
      : typeof cosmosCode === "string" && /^(0|[1-9][0-9]*)$/.test(cosmosCode)
        ? Number(cosmosCode)
        : null;
    if (!Number.isSafeInteger(normalized) || normalized !== 0) {
      errors.push("tx_result_code indicates failure");
    }
  }
  const receiptStatuses = containers
    .flatMap(container => [
      container.receiptStatus,
      container.receipt_status,
      container.status
    ])
    .filter(status => status !== undefined && status !== null && String(status).trim() !== "");
  for (const receiptStatus of receiptStatuses) {
    const normalized = String(receiptStatus).trim().toLowerCase();
    const succeeded = receiptStatus === true ||
      receiptStatus === 1 ||
      receiptStatus === 1n ||
      normalized === "1" ||
      normalized === "true" ||
      normalized === "success" ||
      /^0x0*1$/.test(normalized);
    if (!succeeded) errors.push("evm_receipt_status indicates failure");
  }
  return [...new Set(errors)];
}

function evaluateOperationSuccessEvidence(reservation = {}, actualInput = {}) {
  if (!operationSuccessEvidenceRequired(reservation)) {
    return { evaluated: false, matches: true, errors: [] };
  }
  const expected = expectedOperationSuccessEvidence(reservation);
  const actual = operationSuccessEvidence(actualInput);
  const txIdentity = evaluateOperationTxIdentity(reservation, actual);
  const errors = [...new Set([
    ...txIdentity.errors,
    ...actual.aliasErrors,
    ...actual.txResults.flatMap(executionOutcomeErrors)
  ])];
  const check = (field, expectedValue, actualValue, options = {}) => {
    if (!expectedValue) {
      errors.push(`${field} expected value missing`);
      return;
    }
    if (!actualValue) {
      errors.push(`${field} missing`);
      return;
    }
    if (!operationEvidenceValuesEqual(expectedValue, actualValue, options)) {
      errors.push(`${field} mismatch`);
    }
  };
  check("expected_output_commitment", expected.outputCommitment, actual.outputCommitment, { caseInsensitive: true });
  check("expected_disclosure_digest", expected.disclosureDigest, actual.disclosureDigest, { caseInsensitive: true });
  check("expected_recipient_hash", expected.recipientHash, actual.recipientHash, { caseInsensitive: true });
  if (expected.amount) check("expected_amount", expected.amount, actual.amount);
  check("expected_amount_hash", expected.amountHash, actual.amountHash, { caseInsensitive: true });
  check("expected_denom", expected.denom, actual.denom);
  if (expected.batchItemIndexKnown && !actual.batchItemIndexProvided) {
    errors.push("batch_item_index missing");
  } else if (expected.batchItemIndexKnown && !actual.batchItemIndexValid) {
    errors.push("batch_item_index invalid");
  } else if (expected.batchItemIndexKnown && !actual.batchItemIndexKnown) {
    errors.push("batch_item_index missing");
  } else if (expected.batchItemIndexKnown && expected.batchItemIndex !== actual.batchItemIndex) {
    errors.push("batch_item_index mismatch");
  }
  return {
    evaluated: true,
    matches: errors.length === 0,
    errors
  };
}

function postBroadcastReplanEvidence(metadata = {}) {
  return {
    nullifierUnspentConfirmed: consistentMetadataAliasValue(
      metadata,
      ["nullifierUnspentConfirmed", "nullifier_unspent_confirmed"],
      "nullifier unspent evidence",
      { boolean: true }
    ),
    checkedHeight: consistentMetadataAliasValue(
      metadata,
      ["checkedHeight", "checked_height"],
      "checked height evidence"
    ),
    txHashChecked: consistentMetadataAliasValue(
      metadata,
      ["txHashChecked", "tx_hash_checked"],
      "checked transaction hash evidence"
    ),
    txAbsentOrFailedConfirmed: consistentMetadataAliasValue(
      metadata,
      ["txAbsentOrFailedConfirmed", "tx_absent_or_failed_confirmed"],
      "transaction absent or failed evidence",
      { boolean: true }
    )
  };
}

function hasPostBroadcastReplanEvidence(metadata = {}) {
  const evidence = postBroadcastReplanEvidence(metadata);
  return Boolean(
    booleanEvidence(evidence.nullifierUnspentConfirmed) &&
    booleanEvidence(evidence.txAbsentOrFailedConfirmed)
  );
}

function proofReadyTransitionPatch(metadata = {}) {
  const evidence = operationSuccessEvidence(metadata);
  if (evidence.aliasErrors.length) {
    throw new Error(evidence.aliasErrors.join("; "));
  }
  if (!evidence.batchItemIndexValid ||
      (evidence.batchItemIndexKnown && !evidence.batchItemIndexProvided)) {
    throw new Error("batch item index must be a non-negative safe integer");
  }
  const operationEvidenceRequiredState = operationSuccessEvidenceRequiredInputState(metadata);
  const operationEvidenceRequired = operationEvidenceRequiredState.present
    ? operationEvidenceRequiredState.value
    : false;
  return {
    lease_token: metadata.leaseToken || metadata.lease_token || "",
    payload_hash: metadata.payloadHash || metadata.payload_hash || "",
    sign_doc_hash: metadata.signDocHash || metadata.sign_doc_hash || "",
    tx_bytes_hash: metadata.txBytesHash || metadata.tx_bytes_hash || "",
    expected_output_commitment: evidence.outputCommitment,
    expected_disclosure_digest: evidence.disclosureDigest,
    expected_recipient_hash: evidence.recipientHash,
    expected_amount: evidence.amount,
    expected_amount_hash: evidence.amountHash,
    expected_denom: evidence.denom,
    batch_item_index: evidence.batchItemIndex,
    batch_item_index_known: evidence.batchItemIndexKnown,
    metadata: {
      ...(metadata.metadata || {}),
      no_broadcast_attempt: true,
      ...(operationEvidenceRequired ? { operation_success_evidence_required: true } : {})
    }
  };
}

function assertReplanTransitionEvidence(from, to, metadata = {}) {
  if (to !== reservationStatuses.ReplanRequired) return;
  if (from === reservationStatuses.ConfirmedSpent) return;
  if (from !== reservationStatuses.Submitted && from !== reservationStatuses.Unknown) return;
  if (!hasPostBroadcastReplanEvidence(metadata)) {
    throw new Error(`${from} -> ReplanRequired requires nullifier_unspent_confirmed and tx_absent_or_failed_confirmed reconcile evidence`);
  }
}

function patchIfPresent(patch, key, value) {
  if (value !== undefined && value !== null && value !== "") {
    patch[key] = value;
  }
}

const immutableReservationPatchFields = [
  "reservation_id", "reservationID", "reservationId",
  "operation_id", "operationID", "operationId",
  "owner_key_id", "ownerKeyId", "owner_keyID", "ownerKeyID",
  "nullifier_lookup_key", "nullifierLookupKey",
  "nullifier_lookup_key_id", "nullifierLookupKeyId", "nullifierLookupKeyID",
  "note_id", "noteId", "noteID",
  "kind", "operation_kind", "operationKind",
  "amount", "tx_hash", "txHash", "height", "sequence",
  "created_at", "createdAt"
];

function assertPatchKeepsReservationIdentity(patch = {}) {
  const changed = immutableReservationPatchFields.find(key =>
    Object.prototype.hasOwnProperty.call(patch, key)
  );
  if (changed) {
    throw new Error(`reservation identity field cannot be changed through mutation: ${changed}`);
  }
}

function assertReservationIdentityUnchanged(current, next) {
  const immutableFields = [
    "reservation_id", "operation_id", "owner_key_id", "nullifier_lookup_key",
    "nullifier_lookup_key_id", "note_id", "kind", "amount", "tx_hash",
    "height", "sequence", "created_at"
  ];
  const changed = immutableFields.find(field => current[field] !== next[field]);
  if (changed) {
    throw new Error(`reservation identity field cannot be changed through mutation: ${changed}`);
  }
}

const exactOperationLifecycleStatuses = new Set([
  reservationStatuses.Reserved,
  reservationStatuses.Proving,
  reservationStatuses.ProofReady,
  reservationStatuses.Submitted,
  reservationStatuses.Unknown,
  reservationStatuses.ManualReview,
  reservationStatuses.ReplanRequired,
  reservationStatuses.Released,
  reservationStatuses.Failed
]);

function operationReservationGroupKey(reservation) {
  return `${reservation.owner_key_id}\x00${reservation.operation_id}`;
}

function assertExactOperationLifecycleTransitionSets(reservations, transitions, currentByReservationID) {
  const selectedByOperation = new Map();
  const targetByOperation = new Map();
  for (const transition of transitions) {
    const current = currentByReservationID.get(transition.reservationID);
    if (current?.status === reservationStatuses.ConfirmedSpent) continue;
    if (!current?.operation_id || (
      !exactOperationLifecycleStatuses.has(transition.to) &&
      transition.patch?.[managedOperationReconciliation] !== true
    )) continue;
    const key = operationReservationGroupKey(current);
    if (!selectedByOperation.has(key)) selectedByOperation.set(key, new Set());
    selectedByOperation.get(key).add(current.reservation_id);
    if (transition.patch?.[managedOperationReconciliation] !== true) {
      const target = targetByOperation.get(key);
      if (target && target !== transition.to) {
        throw new Error("operation lifecycle transition requires one target status for the linked reservation set");
      }
      targetByOperation.set(key, transition.to);
    }
  }
  for (const [key, selected] of selectedByOperation) {
    const linked = reservations.filter(candidate =>
      operationReservationGroupKey(candidate) === key &&
      candidate.status !== reservationStatuses.ConfirmedSpent
    );
    if (linked.length !== selected.size || linked.some(candidate => !selected.has(candidate.reservation_id))) {
      throw new Error("operation lifecycle transition requires the exact linked reservation set");
    }
  }
}

export class MemoryReservationStore {
  constructor({ state, now } = {}) {
    this.state = normalizeState(state);
    this.now = now || (() => new Date());
  }

  async load() {
    return cloneJSON(this.state);
  }

  // Test/migration escape hatch. Application code must use the CAS methods below.
  async unsafeReplaceState(state) {
    this.state = normalizeState(state);
    return this.load();
  }

  async listReservations(filter = {}) {
    const statuses = new Set((filter.statuses || []).map(String));
    const ownerKeyId = String(filter.ownerKeyId || filter.owner_key_id || "");
    const reservations = this.state.reservations
      .filter(reservation => !statuses.size || statuses.has(reservation.status))
      .filter(reservation => !ownerKeyId || reservation.owner_key_id === ownerKeyId)
      .sort((left, right) => left.created_at.localeCompare(right.created_at));
    return cloneJSON(filter.limit > 0 ? reservations.slice(0, filter.limit) : reservations);
  }

  async getReservation(reservationID) {
    const reservation = this.state.reservations.find(candidate => candidate.reservation_id === reservationID);
    if (!reservation) throw new Error(`reservation not found: ${reservationID}`);
    return cloneJSON(reservation);
  }

  async createReservationBatch(reservations = [], options = {}) {
    const normalized = reservations.map(normalizeReservation);
    const allowManagedClaimTokenHash = options?.[managedReservationCreation] === true;
    const existingIDs = new Set(this.state.reservations.map(reservation => reservation.reservation_id));
    const usedOperationIDs = new Set(this.state.reservations
      .filter(reservation => reservation.operation_id)
      .map(operationReservationGroupKey));
    const pendingIDs = new Set();
    const combined = [...this.state.reservations];
    for (const reservation of normalized) {
      assertInitialReservationRecord(reservation, { allowManagedClaimTokenHash });
      if (reservation.operation_id && usedOperationIDs.has(operationReservationGroupKey(reservation))) {
        throw new Error(`operation_id has already been used: ${reservation.operation_id}`);
      }
      if (existingIDs.has(reservation.reservation_id) || pendingIDs.has(reservation.reservation_id)) {
        throw new Error(`active reservation already exists: ${reservation.reservation_id}`);
      }
      pendingIDs.add(reservation.reservation_id);
      if (activeConflict(combined, reservation)) {
        throw new Error("active reservation already exists");
      }
      if (confirmedSpentConflict(combined, reservation)) {
        throw new Error("confirmed spent reservation prevents note reuse");
      }
      combined.push(reservation);
    }
    this.state.reservations = combined;
    return cloneJSON(normalized);
  }

  // Test/migration escape hatch. This deliberately bypasses manager ownership and lease checks.
  async unsafeReplaceReservation(reservation) {
    const normalized = normalizeReservation(reservation);
    const index = this.state.reservations.findIndex(candidate => candidate.reservation_id === normalized.reservation_id);
    if (index < 0) throw new Error(`reservation not found: ${normalized.reservation_id}`);
    assertReservationIdentityUnchanged(this.state.reservations[index], normalized);
    if (this.state.reservations[index].status !== normalized.status) {
      throw new Error("reservation status changes require compareAndSetReservationStatus");
    }
    if (
      activeConflict(this.state.reservations, normalized, normalized.reservation_id) ||
      confirmedSpentConflict(this.state.reservations, normalized, normalized.reservation_id)
    ) {
      throw new Error("active reservation already exists");
    }
    this.state.reservations[index] = normalized;
    return cloneJSON(normalized);
  }

  async compareAndSetReservationStatus(reservationID, from, to, patch = {}) {
    const [updated] = await this.compareAndSetReservationStatusBatch([{
      reservationID,
      from,
      to,
      patch
    }]);
    return updated;
  }

  async compareAndSetReservationStatusBatch(transitions = []) {
    const normalizedTransitions = transitions.map(transition => ({
      reservationID: aliasedStringValue(
        transition,
        "reservationID",
        "reservation_id",
        "reservationID"
      ),
      from: String(transition.from || ""),
      to: String(transition.to || ""),
      patch: transition.patch || {}
    }));
    const seen = new Set();
    const indexes = [];
    const updated = [];
    const currentByReservationID = new Map();
    const nextReservations = [...this.state.reservations];
    const now = this.now();
    for (const transition of normalizedTransitions) {
      if (!transition.reservationID) throw new Error("reservationID is required");
      if (seen.has(transition.reservationID)) {
        throw new Error(`duplicate reservation transition: ${transition.reservationID}`);
      }
      seen.add(transition.reservationID);
      const index = this.state.reservations.findIndex(candidate =>
        candidate.reservation_id === transition.reservationID
      );
      if (index < 0) throw new Error(`reservation not found: ${transition.reservationID}`);
      const current = this.state.reservations[index];
      currentByReservationID.set(transition.reservationID, current);
      if (current.status !== transition.from) {
        throw new Error(`reservation compare-and-set failed: expected ${transition.from}, got ${current.status}`);
      }
      const managedRelayHandoff = assertManagedRelayHandoffMutation(current, transition.to, transition.patch, now);
      const managedBroadcastAttempt = assertManagedBroadcastAttemptMutation(current, transition.to, transition.patch, now);
      const managedBroadcastRejection = assertManagedBroadcastRejectionMutation(current, transition.to, transition.patch, now);
      const managedOperationReconcile = assertManagedOperationReconciliation(
        current,
        transition.to,
        transition.patch
      );
      const quarantineSpent = transition.to === reservationStatuses.ConfirmedSpent &&
        transition.patch[reconciledSpentTransition] === true;
      if (transition.from === transition.to && !managedRelayHandoff && !managedBroadcastAttempt && !managedOperationReconcile) {
        assertSameStatusLeaseRenewalPatch(current, transition.patch, now);
      }
      if (transition.from !== transition.to && !quarantineSpent && !canTransitionReservation(transition.from, transition.to)) {
        throw new Error(`invalid reservation transition: ${transition.from} -> ${transition.to}`);
      }
      assertPatchKeepsReservationIdentity(transition.patch);
      assertReservationTransitionPatchFields(current, transition.to, transition.patch, {
        managedRelayHandoff,
        managedBroadcastAttempt,
        managedOperationReconcile
      });
      if (!managedBroadcastRejection) {
        assertStoreTransitionEvidence(current, transition.to, transition.patch);
      }
      assertOperationSuccessPredicateImmutable(current, transition.to, transition.patch);
      assertReservationEvidencePatchMonotonic(current, transition.patch, {
        allowOperationOutcomeMutation: managedOperationReconcile
      });
      assertManagedLifecycleMetadataMutation(current, transition.to, transition.patch, {
        managedRelayHandoff,
        managedBroadcastAttempt,
        managedBroadcastRejection,
        managedOperationReconcile
      });
      assertStoreLeaseMutationAllowed(current, transition.to, transition.patch, now);
      const stablePatch = patchWithStableWriteOnceIdentityRepresentation(
        current,
        transition.patch
      );
      const patch = patchWithClearedLease(
        transition.to,
        patchWithPersistedReconciliationEvidence(
          patchWithPreservedReservationClaimHash(current, stablePatch)
        )
      );
      const next = normalizeReservation({
        ...current,
        ...patch,
        status: transition.to,
        updated_at: nowIso(now)
      });
      indexes.push(index);
      updated.push(next);
    }

    assertExactOperationLifecycleTransitionSets(
      this.state.reservations,
      normalizedTransitions,
      currentByReservationID,
    );

    for (let i = 0; i < updated.length; i += 1) {
      nextReservations[indexes[i]] = updated[i];
    }
    for (const reservation of updated) {
      if (
        activeConflict(nextReservations, reservation, reservation.reservation_id) ||
        confirmedSpentConflict(nextReservations, reservation, reservation.reservation_id)
      ) {
        throw new Error("active reservation already exists");
      }
    }
    this.state.reservations = nextReservations;
    return cloneJSON(updated);
  }

  async releaseReservationBatch({
    reservationIDs = [],
    ownerKeyId = "",
    leaseOwner = "",
    leaseToken = ""
  } = {}) {
    const ids = [...new Set((reservationIDs || []).map(String).filter(Boolean))];
    if (!ids.length) return [];
    if (!ownerKeyId) throw new Error("reservation owner key id is required");
    const now = this.now();
    const updated = [];
    const indexes = [];
    const currentByReservationID = new Map();
    const transitions = [];
    for (const reservationID of ids) {
      const index = this.state.reservations.findIndex(candidate =>
        candidate.reservation_id === reservationID
      );
      if (index < 0) throw new Error(`reservation not found: ${reservationID}`);
      const current = this.state.reservations[index];
      if (current.owner_key_id !== ownerKeyId) {
        throw new Error("reservation owner mismatch");
      }
      if (
        current.status !== reservationStatuses.Reserved &&
        current.status !== reservationStatuses.Proving
      ) {
        throw new Error(`reservation release requires Reserved or Proving status: ${current.status}`);
      }
      if (current.status === reservationStatuses.Proving || current.lease_token) {
        assertCurrentLeaseToken(current, leaseToken, leaseOwner, now);
      }
      indexes.push(index);
      updated.push(normalizeReservation({
        ...current,
        status: reservationStatuses.Released,
        lease_owner: "",
        lease_token: "",
        lease_until: "",
        last_heartbeat_at: "",
        updated_at: nowIso(now)
      }));
      currentByReservationID.set(reservationID, current);
      transitions.push({
        reservationID,
        from: current.status,
        to: reservationStatuses.Released,
        patch: {}
      });
    }
    assertExactOperationLifecycleTransitionSets(
      this.state.reservations,
      transitions,
      currentByReservationID
    );
    for (let index = 0; index < updated.length; index += 1) {
      this.state.reservations[indexes[index]] = updated[index];
    }
    return cloneJSON(updated);
  }

  async findActiveReservationByLookupKey(ownerKeyId, lookupKey) {
    const reservation = this.state.reservations.find(candidate =>
      candidate.owner_key_id === ownerKeyId &&
      candidate.nullifier_lookup_key === lookupKey &&
      isActiveReservationStatus(candidate.status)
    );
    return reservation ? cloneJSON(reservation) : null;
  }

  async findReservationsByLookupKey(ownerKeyId, lookupKey) {
    return cloneJSON(this.state.reservations.filter(candidate =>
      candidate.owner_key_id === ownerKeyId &&
      candidate.nullifier_lookup_key === lookupKey
    ));
  }

  async reconcileSpentByLookupKey(ownerKeyId, lookupKey, note, { now = nowIso(this.now()) } = {}) {
    return this.reconcileSpentByLookupKeys(ownerKeyId, [{ lookupKey, note }], { now });
  }

  async reconcileSpentByLookupKeys(ownerKeyId, spentNotes = [], { now = nowIso(this.now()) } = {}) {
    for (const { note } of spentNotes) {
      if (!hasLiteralSpentEvidence(note)) {
        throw new Error("spent reconciliation requires literal spent evidence");
      }
    }
    const spentNotesByLookupKey = new Map(spentNotes.map(({ lookupKey, note }) => [lookupKey, note]));
    const transitions = [];
    const affectedGroups = new Map();
    for (const { lookupKey } of spentNotes) {
      for (const reservation of this.state.reservations) {
        if (reservation.owner_key_id !== ownerKeyId || reservation.nullifier_lookup_key !== lookupKey) continue;
        const key = reservation.operation_id
          ? operationReservationGroupKey(reservation)
          : `${reservation.owner_key_id}\x00reservation:${reservation.reservation_id}`;
        affectedGroups.set(key, reservation.operation_id
          ? this.state.reservations.filter(candidate =>
              candidate.owner_key_id === ownerKeyId &&
              candidate.operation_id === reservation.operation_id
            )
          : [reservation]);
      }
    }
    for (const reservations of affectedGroups.values()) {
      transitions.push(...operationReconciliationTransitions(reservations, spentNotesByLookupKey, now));
    }
    if (!transitions.length) return [];
    // This starts the CAS before yielding, so one snapshot covers every
    // matching lookup key and quarantine is all-or-nothing for the scan page.
    return this.compareAndSetReservationStatusBatch(transitions);
  }
}

function requestToPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("IndexedDB request failed"));
  });
}

function txDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error || new Error("IndexedDB transaction failed"));
    transaction.onabort = () => reject(transaction.error || new Error("IndexedDB transaction aborted"));
  });
}

export class IndexedDbReservationStore extends MemoryReservationStore {
  constructor(options = {}) {
    const {
      dbName = "clairveil-reservations",
      namespace = "default",
      indexedDB: indexedDBImpl,
      locks = globalThis.navigator?.locks,
      requireLocks = true,
      require_locks,
      encodeState,
      encode_state,
      decodeState,
      decode_state,
      now
    } = options;
    super({ now });
    this.dbName = dbName;
    this.namespace = namespace;
    this.indexedDB = indexedDBImpl || globalThis.indexedDB;
    if (!this.indexedDB) {
      throw new Error("IndexedDB is unavailable");
    }
    this.locks = locks || null;
    this.requireLocks = Boolean(require_locks ?? requireLocks);
    this.encodeState = encodeState || encode_state || null;
    this.decodeState = decodeState || decode_state || null;
    this.unsafeAllowPlaintext = normalizedBooleanAlias(
      options,
      "unsafeAllowPlaintext",
      "unsafe_allow_plaintext"
    );
    this.lockName = `clairveil-reservations:${this.dbName}:${this.namespace}`;
    if (this.requireLocks && typeof this.locks?.request !== "function") {
      throw new Error("Web Locks API is required for cross-tab atomic browser note reservation storage");
    }
    if (Boolean(this.encodeState) !== Boolean(this.decodeState)) {
      throw new Error("IndexedDB reservation state requires both encodeState and decodeState callbacks");
    }
    if (!this.encodeState && !this.unsafeAllowPlaintext) {
      throw new Error("IndexedDB reservation store requires at-rest state encryption callbacks; pass unsafeAllowPlaintext: true only for demos/tests");
    }
    this.dbPromise = null;
  }

  async db() {
    if (this.dbPromise) return this.dbPromise;
    this.dbPromise = new Promise((resolve, reject) => {
      const request = this.indexedDB.open(this.dbName, 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore("states");
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("IndexedDB open failed"));
    });
    return this.dbPromise;
  }

  async load() {
    const db = await this.db();
    const tx = db.transaction("states", "readonly");
    const value = await requestToPromise(tx.objectStore("states").get(this.namespace));
    await txDone(tx);
    if (value === undefined) return normalizeState({});
    const decoded = this.decodeState
      ? await this.decodeState(value)
      : value;
    if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
      throw new Error("IndexedDB reservation state decoder returned an invalid state");
    }
    return normalizeState(decoded);
  }

  async #writeState(state) {
    const normalized = normalizeState(state);
    const encoded = this.encodeState
      ? await this.encodeState(cloneJSON(normalized))
      : normalized;
    if (encoded === undefined || encoded === null) {
      throw new Error("IndexedDB reservation state encoder returned an invalid value");
    }
    const db = await this.db();
    const tx = db.transaction("states", "readwrite");
    tx.objectStore("states").put(encoded, this.namespace);
    await txDone(tx);
    return cloneJSON(normalized);
  }

  async mutate(mutator) {
    return this.withMutationLock(async () => {
      const state = await this.load();
      const result = await mutator(state);
      await this.#writeState(state);
      return result;
    });
  }

  async withMutationLock(callback) {
    return withInProcessMutationLock(this.lockName, () => {
      if (typeof this.locks?.request !== "function") {
        return callback();
      }
      return this.locks.request(this.lockName, { mode: "exclusive" }, callback);
    });
  }

  async listReservations(filter = {}) {
    const state = await this.load();
    return new MemoryReservationStore({ state, now: this.now }).listReservations(filter);
  }

  async getReservation(reservationID) {
    const state = await this.load();
    return new MemoryReservationStore({ state, now: this.now }).getReservation(reservationID);
  }

  async createReservationBatch(reservations = [], options = {}) {
    return this.mutate(async state => {
      const memory = new MemoryReservationStore({ state, now: this.now });
      const created = await memory.createReservationBatch(reservations, options);
      Object.assign(state, await memory.load());
      return created;
    });
  }

  async unsafeReplaceState(state) {
    return this.withMutationLock(() => this.#writeState(state));
  }

  async unsafeReplaceReservation(reservation) {
    return this.mutate(async state => {
      const memory = new MemoryReservationStore({ state, now: this.now });
      const updated = await memory.unsafeReplaceReservation(reservation);
      Object.assign(state, await memory.load());
      return updated;
    });
  }

  async compareAndSetReservationStatus(reservationID, from, to, patch = {}) {
    return this.mutate(async state => {
      const memory = new MemoryReservationStore({ state, now: this.now });
      const updated = await memory.compareAndSetReservationStatus(reservationID, from, to, patch);
      Object.assign(state, await memory.load());
      return updated;
    });
  }

  async compareAndSetReservationStatusBatch(transitions = []) {
    return this.mutate(async state => {
      const memory = new MemoryReservationStore({ state, now: this.now });
      const updated = await memory.compareAndSetReservationStatusBatch(transitions);
      Object.assign(state, await memory.load());
      return updated;
    });
  }

  async releaseReservationBatch(options = {}) {
    return this.mutate(async state => {
      const memory = new MemoryReservationStore({ state, now: this.now });
      const updated = await memory.releaseReservationBatch(options);
      Object.assign(state, await memory.load());
      return updated;
    });
  }

  async findActiveReservationByLookupKey(ownerKeyId, lookupKey) {
    const state = await this.load();
    return new MemoryReservationStore({ state, now: this.now }).findActiveReservationByLookupKey(ownerKeyId, lookupKey);
  }

  async findReservationsByLookupKey(ownerKeyId, lookupKey) {
    const state = await this.load();
    return new MemoryReservationStore({ state, now: this.now }).findReservationsByLookupKey(ownerKeyId, lookupKey);
  }

  async reconcileSpentByLookupKey(ownerKeyId, lookupKey, note, options = {}) {
    return this.reconcileSpentByLookupKeys(ownerKeyId, [{ lookupKey, note }], options);
  }

  async reconcileSpentByLookupKeys(ownerKeyId, spentNotes, options = {}) {
    return this.mutate(async state => {
      const memory = new MemoryReservationStore({ state, now: this.now });
      const updated = await memory.reconcileSpentByLookupKeys(ownerKeyId, spentNotes, options);
      Object.assign(state, await memory.load());
      return updated;
    });
  }
}

export function createBrowserReservationStore(options = {}) {
  const unsafeAllowMemoryFallback = normalizedBooleanAlias(
    options,
    "unsafeAllowMemoryFallback",
    "unsafe_allow_memory_fallback"
  );
  if (options.indexedDB !== null && (options.indexedDB || globalThis.indexedDB)) {
    return new IndexedDbReservationStore(options);
  }
  if (unsafeAllowMemoryFallback) {
    return new MemoryReservationStore(options);
  }
  throw new Error("IndexedDB is unavailable for browser note reservations; use unsafeAllowMemoryFallback only for demos/tests");
}

export class NoteReservationManager {
  constructor(options = {}) {
    const {
      store,
      ownerKeyId,
      owner_key_id,
      indexKey,
      index_key,
      nullifierLookupKeyId,
      nullifier_lookup_key_id,
      leaseOwner,
      lease_owner,
      leaseDurationMs,
      lease_duration_ms,
      now
    } = options;
    if (!store) {
      throw new Error("reservation store is required; pass MemoryReservationStore explicitly only for demos/tests");
    }
    this.store = store;
    this.ownerKeyId = String(ownerKeyId || owner_key_id || "");
    if (!this.ownerKeyId) {
      throw new Error("ownerKeyId is required");
    }
    const explicitIndexKey = indexKey ?? index_key;
    const unsafePublicIndexKey = normalizedBooleanAlias(
      options,
      "unsafeAllowPublicIndexKey",
      "unsafe_allow_public_index_key"
    );
    if (explicitIndexKey === undefined || explicitIndexKey === null || explicitIndexKey === "") {
      if (!unsafePublicIndexKey) {
        throw new Error("indexKey is required for note reservations; pass unsafeAllowPublicIndexKey only for single-user demos");
      }
      this.indexKey = utf8Bytes(this.ownerKeyId);
    } else {
      const indexKeyBytes = bytes(explicitIndexKey);
      if (!indexKeyBytes.length) {
        throw new Error("indexKey is required for note reservations");
      }
      this.indexKey = indexKeyBytes;
    }
    this.nullifierLookupKeyId = String(nullifierLookupKeyId || nullifier_lookup_key_id || "default");
    this.leaseOwner = String(leaseOwner || lease_owner || `reservation-worker:${randomHex(16)}`);
    this.leaseDurationMs = Number(leaseDurationMs || lease_duration_ms || defaultLeaseDurationMs);
    this.now = now || (() => new Date());
  }

  timestamp() {
    return nowIso(this.now());
  }

  async lookupKeyForNote(noteLike) {
    return nullifierLookupKeyFromHex(this.indexKey, noteNullifierHex(noteLike));
  }

  async listActiveReservations() {
    return this.store.listReservations({
      ownerKeyId: this.ownerKeyId,
      statuses: activeReservationStatuses
    });
  }

  async getReservation(reservationID) {
    return this.getOwnedReservation(reservationID);
  }

  assertReservationOwner(reservation) {
    if (reservation.owner_key_id !== this.ownerKeyId) {
      throw new Error("reservation owner mismatch");
    }
  }

  async getOwnedReservation(reservationID) {
    const reservation = await this.store.getReservation(reservationID);
    this.assertReservationOwner(reservation);
    return reservation;
  }

  async _ownedReservationsByID(reservationIDs = []) {
    const ids = [...new Set(reservationIDs || [])];
    if (!ids.length) return new Map();
    const reservations = await this.store.listReservations();
    const byID = new Map(
      reservations.map(reservation => [reservation.reservation_id, reservation])
    );
    const owned = new Map();
    for (const reservationID of ids) {
      const reservation = byID.get(reservationID);
      if (!reservation) throw new Error(`reservation not found: ${reservationID}`);
      this.assertReservationOwner(reservation);
      owned.set(reservationID, reservation);
    }
    return owned;
  }

  async reservationForNote(noteLike) {
    const lookupKey = await this.lookupKeyForNote(noteLike);
    const reservations = await this.store.findReservationsByLookupKey(this.ownerKeyId, lookupKey);
    return reservations.find(reservation => isActiveReservationStatus(reservation.status)) ||
      reservations.find(reservation => reservation.status === reservationStatuses.ConfirmedSpent) ||
      null;
  }

  async reservationStatusByNote(notes = []) {
    const keyedNotes = [];
    for (const note of notes || []) {
      const nullifierHex = noteNullifierHex(note);
      if (!nullifierHex) continue;
      keyedNotes.push([nullifierHex, await this.lookupKeyForNote(note)]);
    }
    const lookupKeys = new Set(keyedNotes.map(([, lookupKey]) => lookupKey));
    const reservations = lookupKeys.size
      ? await this.store.listReservations({ ownerKeyId: this.ownerKeyId })
      : [];
    const blockers = reservationBlockersByLookupKey(reservations, lookupKeys);
    return new Map(keyedNotes.map(([nullifierHex, lookupKey]) => [
      nullifierHex,
      blockers.get(lookupKey) || null
    ]));
  }

  async filterAvailableNotes(notes = []) {
    const keyedNotes = [];
    for (const note of notes || []) {
      keyedNotes.push([note, await this.lookupKeyForNote(note)]);
    }
    const lookupKeys = new Set(keyedNotes.map(([, lookupKey]) => lookupKey));
    const reservations = lookupKeys.size
      ? await this.store.listReservations({ ownerKeyId: this.ownerKeyId })
      : [];
    const blockers = reservationBlockersByLookupKey(reservations, lookupKeys);
    return keyedNotes
      .filter(([, lookupKey]) => !blockers.has(lookupKey))
      .map(([note]) => note);
  }

  async reserveNotes({
    notes = [],
    operationId,
    operation_id,
    kind = "transfer",
    metadata = {}
  } = {}) {
    const selected = [...notes];
    if (!selected.length) {
      return {
        operation_id: String(operationId || operation_id || ""),
        lease_owner: this.leaseOwner,
        lease_token: "",
        lease_until: "",
        reservation_ids: [],
        reservations: []
      };
    }
    const operationID = String(operationId || operation_id || `${kind}:${randomHex(12)}`);
    const now = this.timestamp();
    const leaseToken = randomHex(16);
    const leaseUntil = futureIso(now, this.leaseDurationMs);
    const reservations = [];
    for (const note of selected) {
      const identity = noteReservationIdentity(note);
      const lookupKey = await this.lookupKeyForNote(note);
      reservations.push(normalizeReservation({
        reservation_id: `${operationID}:note:${lookupKey.slice(0, 20)}`,
        operation_id: operationID,
        owner_key_id: this.ownerKeyId,
        nullifier_lookup_key: lookupKey,
        nullifier_lookup_key_id: this.nullifierLookupKeyId,
        status: reservationStatuses.Reserved,
        lease_owner: "",
        lease_token: "",
        lease_until: "",
        last_heartbeat_at: "",
        kind,
        note_id: identity.noteId,
        amount: identity.amount,
        tx_hash: identity.txHash,
        height: identity.height,
        sequence: identity.sequence,
        created_at: now,
        updated_at: now,
        metadata: {
          ...metadata,
          [reservationClaimTokenHashField]: reservationClaimTokenHash(leaseToken)
        }
      }));
    }
    const created = await this.store.createReservationBatch(reservations, {
      [managedReservationCreation]: true
    });
    return {
      operation_id: operationID,
      lease_owner: this.leaseOwner,
      lease_token: leaseToken,
      lease_until: leaseUntil,
      reservation_ids: created.map(reservation => reservation.reservation_id),
      reservations: created
    };
  }

  async reservePlan({
    plan,
    kind = "transfer",
    operationId,
    operation_id,
    metadata = {}
  } = {}) {
    return this.reserveNotes({
      notes: selectedReservationNotesFromPlan(plan),
      operationId,
      operation_id,
      kind,
      metadata
    });
  }

  async transitionBatch(reservationIDs = [], from, to, patch = {}) {
    return this._transitionBatchEntries([{
      reservationIDs,
      from,
      to,
      patch
    }]);
  }

  async _transitionBatchEntries(entries = []) {
    const now = this.timestamp();
    const transitions = [];
    const currentByID = await this._ownedReservationsByID(
      (entries || []).flatMap(entry => entry?.reservationIDs || [])
    );
    for (const entry of entries || []) {
      const {
        reservationIDs = [],
        from,
        to,
        patch = {}
      } = entry || {};
      assertPatchKeepsReservationIdentity(patch);
      assertCoreTransitionEvidence(from, to, patch);
      const transitionPatch = {
        ...patch,
        updated_at: now
      };
      const patchCarriesLeaseCredentials = [
        "lease_owner", "leaseOwner", "lease_token", "leaseToken",
        "lease_until", "leaseUntil", "last_heartbeat_at", "lastHeartbeatAt"
      ].some(key => Object.prototype.hasOwnProperty.call(patch, key));
      if (requiresReservationLeaseToken(from, to)) {
        transitionPatch.lease_owner = this.leaseOwner;
        transitionPatch.last_heartbeat_at = now;
        transitionPatch.lease_until = patch.lease_until || patch.leaseUntil || futureIso(now, this.leaseDurationMs);
      } else if (from === to && patchCarriesLeaseCredentials) {
        transitionPatch.lease_owner = this.leaseOwner;
      }
      for (const reservationID of reservationIDs || []) {
        const current = currentByID.get(reservationID);
        assertLeaseTransitionAllowed(current, to, transitionPatch, now);
        assertReplanTransitionEvidence(current.status, to, patch);
        assertInactiveTransitionEvidence(current, to, patch);
        if (current.status !== from) {
          throw new Error(`reservation compare-and-set failed: expected ${from}, got ${current.status}`);
        }
        if (from !== to && !canTransitionReservation(from, to)) {
          throw new Error(`invalid reservation transition: ${from} -> ${to}`);
        }
        const reservationPatch = patch.metadata && typeof patch.metadata === "object" && !Array.isArray(patch.metadata)
          ? {
              ...transitionPatch,
              metadata: {
                ...(current.metadata || {}),
                ...patch.metadata
              }
            }
          : transitionPatch;
        transitions.push({
          reservationID,
          from,
          to,
          patch: reservationPatch
        });
      }
    }
    if (!transitions.length) return [];
    if (typeof this.store.compareAndSetReservationStatusBatch !== "function") {
      throw new Error("reservation store atomic batch compare-and-set is required");
    }
    return this.store.compareAndSetReservationStatusBatch(transitions);
  }

  async renewLease(reservationIDs = [], metadata = {}) {
    const now = this.timestamp();
    const leaseToken = metadata.leaseToken || metadata.lease_token || "";
    const requestedLeaseUntil = leaseUntilFromMetadata(metadata, now, this.leaseDurationMs);
    const transitions = [];
    const currentByID = await this._ownedReservationsByID(reservationIDs);
    for (const reservationID of reservationIDs || []) {
      const current = currentByID.get(reservationID);
      if (!isActiveReservationStatus(current.status)) {
        throw new Error(`reservation lease cannot be renewed for inactive status: ${current.status}`);
      }
      assertCurrentLeaseToken(current, leaseToken, this.leaseOwner, now);
      const currentLeaseUntil = Date.parse(current.lease_until || "");
      const requestedLeaseUntilMs = Date.parse(requestedLeaseUntil);
      const leaseUntil = Number.isFinite(currentLeaseUntil) && currentLeaseUntil > requestedLeaseUntilMs
        ? current.lease_until
        : requestedLeaseUntil;
      transitions.push({
        reservationID,
        from: current.status,
        to: current.status,
        patch: {
          lease_owner: this.leaseOwner,
          lease_token: leaseToken,
          lease_until: leaseUntil,
          last_heartbeat_at: now,
          updated_at: now
        }
      });
    }
    if (!transitions.length) return [];
    if (typeof this.store.compareAndSetReservationStatusBatch !== "function") {
      throw new Error("reservation store atomic batch compare-and-set is required");
    }
    return this.store.compareAndSetReservationStatusBatch(transitions);
  }

  async recordRelayHandoff(reservationIDs = [], metadata = {}) {
    const now = this.timestamp();
    const leaseToken = metadata.leaseToken || metadata.lease_token || "";
    const payloadHash = String(metadata.payloadHash || metadata.payload_hash || "").trim();
    const txBytesHash = String(metadata.txBytesHash || metadata.tx_bytes_hash || "").trim();
    const signDocHash = String(metadata.signDocHash || metadata.sign_doc_hash || "").trim();
    if (!payloadHash) {
      throw new Error("relay handoff requires the prepared payload hash");
    }
    const transitions = [];
    const currentByID = await this._ownedReservationsByID(reservationIDs);
    for (const reservationID of reservationIDs || []) {
      const current = currentByID.get(reservationID);
      if (current.status !== reservationStatuses.ProofReady) {
        throw new Error(`relay handoff requires ProofReady reservation: ${current.status}`);
      }
      if (current.broadcast_in_flight || Number(current.broadcast_attempt_count || 0) > 0) {
        throw new Error("broadcast attempt already started; reconcile before relay handoff");
      }
      assertCurrentLeaseToken(current, leaseToken, this.leaseOwner, now);
      if (!current.payload_hash || current.payload_hash !== payloadHash) {
        throw new Error("relay handoff payload hash does not match the ProofReady reservation");
      }
      if (current.tx_bytes_hash && txBytesHash && current.tx_bytes_hash !== txBytesHash) {
        throw new Error("relay handoff transaction hash does not match the ProofReady reservation");
      }
      if (current.sign_doc_hash && signDocHash && current.sign_doc_hash !== signDocHash) {
        throw new Error("relay handoff sign-doc hash does not match the ProofReady reservation");
      }
      const patch = {
        lease_owner: this.leaseOwner,
        lease_token: leaseToken,
        lease_until: current.lease_until,
        last_heartbeat_at: now,
        updated_at: now,
        payload_hash: payloadHash,
        ...(txBytesHash ? { tx_bytes_hash: txBytesHash } : {}),
        ...(signDocHash ? { sign_doc_hash: signDocHash } : {}),
        metadata: {
          ...(current.metadata || {}),
          ...(metadata.metadata || {}),
          relay_handed_off: true,
          relay_handed_off_at: String(
            current.metadata?.relay_handed_off_at ||
            current.metadata?.relayHandedOffAt ||
            metadata.handedOffAt ||
            metadata.handed_off_at ||
            now
          ),
          no_broadcast_attempt: false
        }
      };
      Object.defineProperty(patch, managedReservationEvidenceMutation, {
        value: "relay_handoff",
        enumerable: true
      });
      transitions.push({
        reservationID,
        from: reservationStatuses.ProofReady,
        to: reservationStatuses.ProofReady,
        patch
      });
    }
    if (!transitions.length) return [];
    if (typeof this.store.compareAndSetReservationStatusBatch !== "function") {
      throw new Error("reservation store atomic batch compare-and-set is required");
    }
    return this.store.compareAndSetReservationStatusBatch(transitions);
  }

  async heartbeatLease(reservationIDs = [], metadata = {}) {
    return this.renewLease(reservationIDs, metadata);
  }

  async markProving(reservationIDs = [], metadata = {}) {
    return this.transitionBatch(reservationIDs, reservationStatuses.Reserved, reservationStatuses.Proving, {
      lease_token: metadata.leaseToken || metadata.lease_token || ""
    });
  }

  async markProofReady(reservationIDs = [], metadata = {}) {
    return this.transitionBatch(
      reservationIDs,
      reservationStatuses.Proving,
      reservationStatuses.ProofReady,
      proofReadyTransitionPatch(metadata),
    );
  }

  async markProofReadyBatch(entries = []) {
    return this._transitionBatchEntries((entries || []).map(entry => ({
      reservationIDs: aliasedStringArray(
        entry,
        "reservationIDs",
        "reservation_ids",
        "reservationIDs"
      ),
      from: reservationStatuses.Proving,
      to: reservationStatuses.ProofReady,
      patch: proofReadyTransitionPatch(entry?.metadata || {})
    })));
  }

  async markBroadcastAttempting(reservationIDs = [], metadata = {}) {
    const now = this.timestamp();
    const leaseToken = metadata.leaseToken || metadata.lease_token || "";
    const attempt = broadcastAttemptMetadata(metadata);
    const transitions = [];
    const currentByID = await this._ownedReservationsByID(reservationIDs);
    for (const reservationID of reservationIDs || []) {
      const current = currentByID.get(reservationID);
      if (current.status !== reservationStatuses.ProofReady) {
        throw new Error(`broadcast attempt requires ProofReady reservation: ${current.status}`);
      }
      assertCurrentLeaseToken(current, leaseToken, this.leaseOwner, now);
      const patch = {
        lease_owner: this.leaseOwner,
        lease_token: leaseToken,
        lease_until: current.lease_until,
        last_heartbeat_at: now,
        updated_at: now,
        broadcast_in_flight: true,
        broadcast_attempt_count: Number(current.broadcast_attempt_count || 0) + 1,
        metadata: {
          ...(current.metadata || {}),
          ...(metadata.metadata || {}),
          broadcast_attempt_started_at: now,
          broadcast_attempt_reason: String(metadata.reason || "external_broadcast_boundary_crossed"),
          no_broadcast_attempt: false
        }
      };
      patchIfPresent(patch, "submitted_tx_hash", attempt.txHash);
      patchIfPresent(patch, "tx_bytes_hash", attempt.txBytesHash);
      patchIfPresent(patch, "sign_doc_hash", attempt.signDocHash);
      Object.defineProperty(patch, managedReservationEvidenceMutation, {
        value: "broadcast_attempt",
        enumerable: true
      });
      transitions.push({
        reservationID,
        from: reservationStatuses.ProofReady,
        to: reservationStatuses.ProofReady,
        patch
      });
    }
    if (!transitions.length) return [];
    if (typeof this.store.compareAndSetReservationStatusBatch !== "function") {
      throw new Error("reservation store atomic batch compare-and-set is required");
    }
    return this.store.compareAndSetReservationStatusBatch(transitions);
  }

  async markBroadcastRejected(reservationIDs = [], metadata = {}) {
    const now = this.timestamp();
    const leaseToken = metadata.leaseToken || metadata.lease_token || "";
    const transitions = [];
    const currentByID = await this._ownedReservationsByID(reservationIDs);
    for (const reservationID of reservationIDs || []) {
      const current = currentByID.get(reservationID);
      if (current.status !== reservationStatuses.ProofReady) {
        throw new Error(`wallet rejection resolution requires ProofReady reservation: ${current.status}`);
      }
      assertCurrentLeaseToken(current, leaseToken, this.leaseOwner, now);
      const patch = {
        lease_owner: this.leaseOwner,
        lease_token: leaseToken,
        broadcast_in_flight: false,
        broadcast_attempt_count: Number(current.broadcast_attempt_count || 0),
        last_broadcast_error: String(metadata.error || metadata.lastBroadcastError || metadata.last_broadcast_error || "wallet request rejected"),
        updated_at: now,
        metadata: {
          ...(current.metadata || {}),
          ...(metadata.metadata || {}),
          wallet_rejected_before_broadcast: true,
          provider_rejection_code: String(metadata.providerCode || metadata.provider_code || "4001"),
          no_broadcast_attempt: true,
          proof_discarded: true,
          reconcile_reason: "wallet_rejected_before_broadcast"
        }
      };
      Object.defineProperty(patch, managedReservationEvidenceMutation, {
        value: "broadcast_rejected",
        enumerable: true
      });
      transitions.push({
        reservationID,
        from: reservationStatuses.ProofReady,
        to: reservationStatuses.ReplanRequired,
        patch
      });
    }
    if (!transitions.length) return [];
    if (typeof this.store.compareAndSetReservationStatusBatch !== "function") {
      throw new Error("reservation store atomic batch compare-and-set is required");
    }
    return this.store.compareAndSetReservationStatusBatch(transitions);
  }

  async markSubmitted(reservationIDs = [], metadata = {}) {
    assertSubmittedBroadcastAttemptMetadata(metadata, "markSubmitted");
    const attempt = broadcastAttemptMetadata(metadata);
    const patch = {
      lease_token: metadata.leaseToken || metadata.lease_token || "",
      broadcast_in_flight: false,
      metadata: {
        ...(metadata.metadata || {}),
        no_broadcast_attempt: false
      }
    };
    patchIfPresent(patch, "submitted_tx_hash", attempt.txHash);
    patchIfPresent(patch, "tx_bytes_hash", attempt.txBytesHash);
    patchIfPresent(patch, "sign_doc_hash", attempt.signDocHash);
    return this.transitionBatch(reservationIDs, reservationStatuses.ProofReady, reservationStatuses.Submitted, patch);
  }

  async markUnknown(reservationIDs = [], metadata = {}) {
    assertBroadcastAttemptMetadata(metadata, "markUnknown");
    const attempt = broadcastAttemptMetadata(metadata);
    const from = metadata.fromStatus || metadata.from_status || reservationStatuses.ProofReady;
    if (![reservationStatuses.ProofReady, reservationStatuses.Submitted].includes(from)) {
      throw new Error(`markUnknown requires ProofReady or Submitted status, got ${from}`);
    }
    const patch = {
      lease_token: metadata.leaseToken || metadata.lease_token || "",
      last_broadcast_error: metadata.error || metadata.lastBroadcastError || metadata.last_broadcast_error || "",
      broadcast_in_flight: false,
      metadata: {
        ...(metadata.metadata || {}),
        no_broadcast_attempt: false
      }
    };
    patchIfPresent(patch, "submitted_tx_hash", attempt.txHash);
    patchIfPresent(patch, "tx_bytes_hash", attempt.txBytesHash);
    patchIfPresent(patch, "sign_doc_hash", attempt.signDocHash);
    return this.transitionBatch(reservationIDs, from, reservationStatuses.Unknown, patch);
  }

  async markReplanRequired(reservationIDs = [], metadata = {}) {
    const from = metadata.fromStatus || metadata.from_status || reservationStatuses.Submitted;
    const patch = {};
    const evidence = postBroadcastReplanEvidence(metadata);
    const proofDiscarded = consistentMetadataAliasValue(
      metadata,
      ["proofDiscarded", "proof_discarded"],
      "proof discarded evidence",
      { boolean: true }
    );
    const authoritativeExpiryConfirmed = consistentMetadataAliasValue(
      metadata,
      ["authoritativeExpiryConfirmed", "authoritative_expiry_confirmed"],
      "authoritative expiry evidence",
      { boolean: true }
    );
    patchIfPresent(patch, "lease_token", metadata.leaseToken ?? metadata.lease_token);
    patch.lease_owner = this.leaseOwner;
    patchIfPresent(patch, "submitted_tx_hash", metadata.txHash ?? metadata.tx_hash);
    patchIfPresent(patch, "tx_bytes_hash", metadata.txBytesHash ?? metadata.tx_bytes_hash);
    patchIfPresent(patch, "sign_doc_hash", metadata.signDocHash ?? metadata.sign_doc_hash);
    patchIfPresent(patch, "last_broadcast_error", metadata.error ?? metadata.lastBroadcastError ?? metadata.last_broadcast_error);
    const nestedMetadata = metadataObject(metadata);
    if (
      Object.keys(nestedMetadata).length ||
      evidence.nullifierUnspentConfirmed !== undefined ||
      evidence.checkedHeight !== undefined ||
      evidence.txHashChecked !== undefined ||
      evidence.txAbsentOrFailedConfirmed !== undefined ||
      proofDiscarded !== undefined ||
      authoritativeExpiryConfirmed !== undefined
    ) {
      patch.metadata = { ...nestedMetadata };
      if (booleanEvidence(evidence.nullifierUnspentConfirmed)) {
        patch.metadata.nullifier_unspent_confirmed = true;
      }
      if (booleanEvidence(evidence.txAbsentOrFailedConfirmed)) {
        patch.metadata.tx_absent_or_failed_confirmed = true;
      }
      if (booleanEvidence(proofDiscarded)) {
        patch.metadata.proof_discarded = true;
      }
      if (booleanEvidence(authoritativeExpiryConfirmed)) {
        patch.metadata.authoritative_expiry_confirmed = true;
      }
      patchIfPresent(patch.metadata, "checked_height", evidence.checkedHeight);
      patchIfPresent(patch.metadata, "tx_hash_checked", evidence.txHashChecked);
    }
    if (metadata.fromStatus || metadata.from_status) {
      return this.transitionBatch(reservationIDs, from, reservationStatuses.ReplanRequired, patch);
    }
    assertPatchKeepsReservationIdentity(patch);
    const now = this.timestamp();
    const transitionPatch = {
      ...patch,
      updated_at: now
    };
    const transitions = [];
    const currentByID = await this._ownedReservationsByID(reservationIDs);
    for (const reservationID of reservationIDs || []) {
      const current = currentByID.get(reservationID);
      assertLeaseTransitionAllowed(current, reservationStatuses.ReplanRequired, transitionPatch, now);
      assertReplanTransitionEvidence(current.status, reservationStatuses.ReplanRequired, patch);
      assertInactiveTransitionEvidence(current, reservationStatuses.ReplanRequired, patch);
      if (!canTransitionReservation(current.status, reservationStatuses.ReplanRequired)) {
        throw new Error(`invalid reservation transition: ${current.status} -> ${reservationStatuses.ReplanRequired}`);
      }
      transitions.push({
        reservationID,
        from: current.status,
        to: reservationStatuses.ReplanRequired,
        patch: patch.metadata && typeof patch.metadata === "object" && !Array.isArray(patch.metadata)
          ? {
              ...transitionPatch,
              metadata: {
                ...(current.metadata || {}),
                ...patch.metadata
              }
            }
          : transitionPatch
      });
    }
    if (!transitions.length) return [];
    if (typeof this.store.compareAndSetReservationStatusBatch !== "function") {
      throw new Error("reservation store atomic batch compare-and-set is required");
    }
    return this.store.compareAndSetReservationStatusBatch(transitions);
  }

  async releaseReservedOrProving(reservationIDs = [], metadata = {}) {
    const leaseToken = metadata.leaseToken || metadata.lease_token || "";
    const currentByID = await this._ownedReservationsByID(reservationIDs);
    for (const reservationID of reservationIDs || []) {
      const current = currentByID.get(reservationID);
      if (current.status === reservationStatuses.Proving) {
        assertCurrentLeaseToken(current, leaseToken, this.leaseOwner, this.timestamp());
      } else if (current.status !== reservationStatuses.Reserved) {
        throw new Error(`reservation rollback requires Reserved or Proving status: ${current.status}`);
      }
    }
    if (typeof this.store.releaseReservationBatch !== "function") {
      throw new Error("reservation store atomic release batch is required");
    }
    return this.store.releaseReservationBatch({
      reservationIDs,
      ownerKeyId: this.ownerKeyId,
      leaseOwner: this.leaseOwner,
      leaseToken
    });
  }

  async markManualReview(reservationIDs = [], metadata = {}) {
    assertPatchKeepsReservationIdentity(metadata);
    const now = this.timestamp();
    const patch = {
      lease_token: metadata.leaseToken || metadata.lease_token || "",
      lease_owner: this.leaseOwner,
      last_broadcast_error: metadata.error || metadata.lastBroadcastError || metadata.last_broadcast_error || "",
      updated_at: now,
      metadata: {
        ...(metadata.metadata || {})
      }
    };
    const transitions = [];
    const currentByID = await this._ownedReservationsByID(reservationIDs);
    for (const reservationID of reservationIDs || []) {
      const current = currentByID.get(reservationID);
      if (!canTransitionReservation(current.status, reservationStatuses.ManualReview)) {
        throw new Error(`invalid reservation transition: ${current.status} -> ${reservationStatuses.ManualReview}`);
      }
      transitions.push({
        reservationID,
        from: current.status,
        to: reservationStatuses.ManualReview,
        patch: {
          ...patch,
          metadata: {
            ...(current.metadata || {}),
            ...patch.metadata
          }
        }
      });
    }
    if (typeof this.store.compareAndSetReservationStatusBatch !== "function") {
      throw new Error("reservation store atomic batch compare-and-set is required");
    }
    return this.store.compareAndSetReservationStatusBatch(transitions);
  }

  async resolveManualReview(reservationIDs = [], resolution = {}) {
    const target = String(resolution.target || resolution.toStatus || resolution.to_status || "");
    if (![reservationStatuses.Released, reservationStatuses.ReplanRequired, reservationStatuses.Failed].includes(target)) {
      throw new Error("ManualReview resolution target must be Released, ReplanRequired, or Failed");
    }
    const operatorId = String(resolution.operatorId || resolution.operator_id || "").trim();
    const approvalReference = String(resolution.approvalReference || resolution.approval_reference || "").trim();
    if (!operatorId || !approvalReference) {
      throw new Error("ManualReview resolution requires operatorId and approvalReference");
    }
    return this.transitionBatch(reservationIDs, reservationStatuses.ManualReview, target, {
      metadata: {
        ...(resolution.metadata || {}),
        operator_approved: true,
        operator_id: operatorId,
        operator_approval_reference: approvalReference,
        manual_review_resolution_reason: String(resolution.reason || "")
      }
    });
  }

  async reconcileSpentNotes(notes = []) {
    const seenLookupKeys = new Set();
    const spentNotes = [];
    for (const note of notes || []) {
      if (!hasLiteralSpentEvidence(note)) continue;
      const lookupKey = await this.lookupKeyForNote(note);
      if (seenLookupKeys.has(lookupKey)) continue;
      seenLookupKeys.add(lookupKey);
      spentNotes.push({ lookupKey, note });
    }
    if (!spentNotes.length) return [];
    if (typeof this.store.reconcileSpentByLookupKeys !== "function") {
      throw new Error("reservation store atomic spent reconciliation is required");
    }
    return this.store.reconcileSpentByLookupKeys(
      this.ownerKeyId,
      spentNotes,
      { now: this.timestamp() }
    );
  }
}

export function createNoteReservationManager(options = {}) {
  return new NoteReservationManager(options);
}

export async function preparePlanReservation(reservationManager, {
  plan,
  kind = "transfer",
  metadata = {}
} = {}) {
  if (!reservationManager) return null;
  const batch = await reservationManager.reservePlan({ plan, kind, metadata });
  if (!batch.reservation_ids.length) return null;
  try {
    const reservations = await reservationManager.markProving(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      leaseUntil: batch.lease_until
    });
    return {
      ...batch,
      lease_owner: reservations[0]?.lease_owner || batch.lease_owner,
      lease_token: reservations[0]?.lease_token || batch.lease_token,
      lease_until: reservations[0]?.lease_until || batch.lease_until,
      reservations
    };
  } catch (error) {
    await rollbackPlanReservationPreservingError(reservationManager, batch, error);
    throw error;
  }
}

export async function rollbackPlanReservation(reservationManager, batch) {
  if (!reservationManager || !batch?.reservation_ids?.length) return;
  try {
    await reservationManager.releaseReservedOrProving(batch.reservation_ids, {
      leaseToken: batch.lease_token || batch.leaseToken || batch.reservations?.[0]?.lease_token || ""
    });
  } catch (error) {
    if (!isLeaseExpiredError(error)) {
      throw error;
    }
    await reservationManager.markManualReview(batch.reservation_ids, {
      error: error?.message || "rollback failed because reservation lease expired",
      metadata: {
        reconcile_reason: "rollback_lease_expired",
        rollback_error: error?.message || "reservation lease expired"
      }
    });
  }
}

export async function rollbackPlanReservationPreservingError(reservationManager, batch, error) {
  try {
    await rollbackPlanReservation(reservationManager, batch);
  } catch (cleanupError) {
    if (error && typeof error === "object") {
      const existing = Array.isArray(error.reservationCleanupErrors)
        ? error.reservationCleanupErrors
        : [];
      try {
        error.reservationCleanupErrors = [...existing, cleanupError];
      } catch {
        // Cleanup annotations are best-effort and must never replace the original error.
      }
    }
  }
}
