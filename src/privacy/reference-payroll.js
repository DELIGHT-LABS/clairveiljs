import { fromBech32, toBech32 } from "@cosmjs/encoding";
import { Secp256k1, Secp256k1Signature } from "@cosmjs/crypto";
import { base64FromBytes, bytesFromBase64, hash160, hexFromBytes, randomBytes, sha256, sha256Hex, utf8Bytes } from "../core/browser-crypto.js";
import { FIELD_MODULUS, bytesFromHex, bytesToBigIntBE, decodeShieldedAddress, unpackPoint } from "../core/crypto.js";
import { ClairveilErrorCode, OperationStateMixedError } from "../core/errors.js";
import { PubKey as Secp256k1PubKey } from "cosmjs-types/cosmos/crypto/secp256k1/keys";
import { SignMode } from "cosmjs-types/cosmos/tx/signing/v1beta1/signing";
import { AuthInfo, SignDoc, TxBody, TxRaw } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import { MsgBatchTransfer as GeneratedMsgBatchTransfer } from "../generated/clairveil/privacy/v1/tx.js";
import {
  buildPreparedBatchTransferPayload,
  buildMsgBatchTransferFromPrepared,
  normalizePreparedBatchTransferProof,
  preparedBatchTransferEffectHex,
  validatePreparedBatchTransferPayloadEnvelope
} from "./batch-transfer.js";
import {
  normalizeAssetRegistryEntryV1,
  normalizeAssetRegistryQueryResponseV1
} from "./asset-registry.js";
import { validateCircuitConfigV1 } from "./circuit-config.js";
import { privacyPolicyValue, userDisclosureModeValue } from "./payload.js";
import { computeNoteNullifierV1, fieldHexV1, validateNoteV1 } from "./protocol-v1.js";
import { hashAmount, hashRecipient, reservationHeartbeatIntervalMs } from "./reservation.js";

/** Reference Payroll contracts. The one-proof executor is intentionally separate from legacy transfer-batch. */
export const payrollDisclosureScopes = Object.freeze([
  "employee", "company", "auditor", "external"
]);

export const payrollPlanStatuses = Object.freeze({
  Draft: "Draft",
  Confirmed: "Confirmed",
  Cancelled: "Cancelled"
});

export const payrollItemStatuses = Object.freeze({
  Planned: "Planned",
  Reserved: "Reserved",
  Proving: "Proving",
  ProofReady: "ProofReady",
  Submitted: "Submitted",
  Confirmed: "Confirmed",
  Failed: "Failed",
  ReplanRequired: "ReplanRequired",
  ManualReview: "ManualReview"
});

export const notePreparationRecommendationKinds = Object.freeze({
  AddFunds: "add-funds",
  MakeDummy: "make-dummy",
  SplitMerge: "split-merge",
  ResolveReservationLock: "resolve-reservation-lock"
});

export const oneProofPayrollCircuitSetId = "privacy-note-v1";
export const oneProofPayrollMaxInputs = 16;
export const oneProofPayrollMaxOutputs = 32;
export const oneProofPayrollOperationEvidenceVersion = "payroll-one-proof-operation-evidence-v1";
export const oneProofPayrollExecutionVersion = "payroll-one-proof-execution-v1";
/** Versioned, private-at-rest checkpoint for a resumable one-proof payroll operation. */
export const oneProofPayrollArtifactVersion = "payroll-one-proof-artifact-v1";

const oneProofPayrollRetryDecisionVersion = "payroll-one-proof-retry-decision-v1";
/** Maximum age of tx/nullifier observations authorizing an exact retransmit. */
export const oneProofPayrollRetryDecisionTTLSeconds = 30;
// Retry evidence is deliberately an in-process, one-use capability. Persisting
// or reconstructing this object would turn an old chain observation into fresh
// authorization to cross the broadcast boundary.
const oneProofPayrollRetryDecisionBindings = new WeakMap();

const disclosureScopeSet = new Set(payrollDisclosureScopes);
const disclosureModeName = new Map([
  ["none", 0],
  ["USER_DISCLOSURE_MODE_NONE", 0],
  ["public", 1],
  ["USER_DISCLOSURE_MODE_PUBLIC", 1],
  ["recipient-encrypted", 2],
  ["USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED", 2]
]);
const maxUint64 = (1n << 64n) - 1n;
const maxBatchPlanSearch = 20000;
const maxInputCandidateSearch = 4096;
const maxInputCandidates = 64;

function oneProofOutputMode(options = {}) {
  const mode = text(options.output_mode ?? options.outputMode ?? "compact").toLowerCase();
  if (mode === "compact") return mode;
  // The CLI/reference docs spell this mode `exact32`; retain the older
  // hyphenated SDK spelling as a compatible alias while storing one canonical
  // value in every prepared operation.
  if (mode === "exact32" || mode === "exact-32") return "exact-32";
  throw new Error("one-proof payroll output mode must be compact, exact32, or exact-32");
}

function text(value) {
  return String(value ?? "").trim();
}

function canonicalUint64(value, label, { positive = false } = {}) {
  if (value === undefined || value === null || value === "") throw new Error(`${label} is required`);
  if (!["bigint", "number", "string"].includes(typeof value)) throw new Error(`${label} must be a canonical uint64`);
  if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error(`${label} must be a canonical uint64`);
  const encoded = typeof value === "string" ? value : String(value);
  if (!/^(0|[1-9][0-9]*)$/.test(encoded)) throw new Error(`${label} must be a canonical uint64`);
  const parsed = BigInt(encoded);
  if (parsed > maxUint64 || (positive && parsed === 0n)) throw new Error(`${label} must be${positive ? " a positive" : ""} uint64`);
  return parsed;
}

function canonicalDigest(value, label) {
  const normalized = text(value).toLowerCase();
  if (!normalized) return "";
  if (!/^[0-9a-f]{64}$/.test(normalized)) throw new Error(`${label} must be canonical 32-byte hex`);
  return normalized;
}

function canonicalDisclosurePubKey(value, label) {
  const normalized = text(value).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) throw new Error(`${label} must be 32-byte compressed pubkey hex`);
  try {
    const point = unpackPoint(bytesFromHex(normalized, label));
    if (point.x === 0n && point.y === 1n) throw new Error("point identity is not allowed");
  } catch (error) {
    throw new Error(`${label} must be a canonical non-identity prime-subgroup point: ${error.message}`);
  }
  return normalized;
}

function normalizePolicyValue(value) {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0 || value > 7) throw new Error("unsupported payroll user privacy policy");
    return value;
  }
  if (typeof value === "bigint") return normalizePolicyValue(Number(value));
  const normalized = text(value || "all-private");
  if (/^[0-7]$/.test(normalized)) return Number(normalized);
  if (Object.hasOwn(privacyPolicyValue, normalized)) return privacyPolicyValue[normalized];
  throw new Error(`unsupported payroll user privacy policy ${JSON.stringify(value)}`);
}

function normalizeModeValue(value) {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0 || value > 2) throw new Error("unsupported payroll user disclosure mode");
    return value;
  }
  if (typeof value === "bigint") return normalizeModeValue(Number(value));
  const normalized = text(value);
  if (/^[0-2]$/.test(normalized)) return Number(normalized);
  if (disclosureModeName.has(normalized)) return disclosureModeName.get(normalized);
  if (Object.hasOwn(userDisclosureModeValue, normalized)) return userDisclosureModeValue[normalized];
  throw new Error(`unsupported payroll user disclosure mode ${JSON.stringify(value)}`);
}

function policyInput(policy = {}) {
  if (!policy || typeof policy !== "object") throw new Error("payroll disclosure policy must be an object");
  return {
    user_privacy_policy: policy.user_privacy_policy ?? policy.userPrivacyPolicy ?? "all-private",
    user_disclosure_mode: policy.user_disclosure_mode ?? policy.userDisclosureMode ?? 0,
    user_disclosure_target_pubkey_hex: policy.user_disclosure_target_pubkey_hex ?? policy.userDisclosureTargetPubKeyHex ?? "",
    user_disclosure_target_key_id: policy.user_disclosure_target_key_id ?? policy.userDisclosureTargetKeyID ?? "",
    expected_user_disclosure_digest: policy.expected_user_disclosure_digest ?? policy.expectedUserDisclosureDigest ?? "",
    expected_audit_disclosure_digest: policy.expected_audit_disclosure_digest ?? policy.expectedAuditDisclosureDigest ?? "",
    expected_self_view_disclosure_digest: policy.expected_self_view_disclosure_digest ?? policy.expectedSelfViewDisclosureDigest ?? ""
  };
}

/** Normalize and validate the Go PayrollDisclosurePolicy contract. */
export function normalizePayrollDisclosurePolicy(policy = {}) {
  const input = policyInput(policy);
  const userPrivacyPolicy = normalizePolicyValue(input.user_privacy_policy);
  const userDisclosureMode = normalizeModeValue(input.user_disclosure_mode);
  const targetPubKey = text(input.user_disclosure_target_pubkey_hex).toLowerCase();
  const targetKeyID = text(input.user_disclosure_target_key_id);
  const normalized = {
    user_privacy_policy: userPrivacyPolicy,
    user_disclosure_mode: userDisclosureMode,
    user_disclosure_target_pubkey_hex: targetPubKey,
    user_disclosure_target_key_id: targetKeyID,
    expected_user_disclosure_digest: canonicalDigest(input.expected_user_disclosure_digest, "expected_user_disclosure_digest"),
    expected_audit_disclosure_digest: canonicalDigest(input.expected_audit_disclosure_digest, "expected_audit_disclosure_digest"),
    expected_self_view_disclosure_digest: canonicalDigest(input.expected_self_view_disclosure_digest, "expected_self_view_disclosure_digest")
  };
  if (userPrivacyPolicy === 0) {
    if (userDisclosureMode !== 0) throw new Error("all-private disclosure policy must use mode none");
    if (targetPubKey || targetKeyID) throw new Error("all-private disclosure policy must not include a user disclosure target key");
    if (normalized.expected_user_disclosure_digest) throw new Error("all-private disclosure policy must not include expected_user_disclosure_digest");
  } else if (userDisclosureMode === 1) {
    if (targetPubKey) throw new Error("public user disclosure must not include a target pubkey");
  } else if (userDisclosureMode === 2) {
    normalized.user_disclosure_target_pubkey_hex = canonicalDisclosurePubKey(targetPubKey, "user disclosure target pubkey");
  } else {
    throw new Error("non-private user disclosure requires public or recipient-encrypted mode");
  }
  return Object.freeze(normalized);
}

export function validatePayrollDisclosurePolicy(policy = {}) {
  normalizePayrollDisclosurePolicy(policy);
  return true;
}

/** Validate a product/backend disclosure-key record before it reaches payroll planning. */
export function normalizeDisclosureKeyEntry(entry = {}) {
  if (!entry || typeof entry !== "object") throw new Error("disclosure key entry must be an object");
  const normalized = {
    key_id: text(entry.key_id ?? entry.keyID ?? entry.keyId),
    scope: text(entry.scope),
    subject_id: text(entry.subject_id ?? entry.subjectID ?? entry.subjectId),
    public_key_hex: text(entry.public_key_hex ?? entry.publicKeyHex).toLowerCase(),
    version: text(entry.version),
    active: entry.active === true
  };
  if (!normalized.key_id) throw new Error("disclosure key_id is required");
  if (!disclosureScopeSet.has(normalized.scope)) throw new Error(`unsupported disclosure key scope ${JSON.stringify(normalized.scope)}`);
  if (!normalized.subject_id) throw new Error("disclosure key subject_id is required");
  normalized.public_key_hex = canonicalDisclosurePubKey(normalized.public_key_hex, "disclosure key public_key_hex");
  return Object.freeze(normalized);
}

export function validateDisclosureKeyEntry(entry = {}) {
  normalizeDisclosureKeyEntry(entry);
  return true;
}

/** In-memory helper for product tests and local clients. It never serializes raw private keys. */
export class MemoryDisclosureKeyRegistry {
  #entries = new Map();

  constructor(entries = []) {
    if (!Array.isArray(entries)) throw new Error("disclosure key registry entries must be an array");
    entries.forEach(entry => this.add(entry));
  }

  add(entry) {
    const normalized = normalizeDisclosureKeyEntry(entry);
    this.#entries.set(`${normalized.scope}\x00${normalized.subject_id}`, normalized);
    return normalized;
  }

  lookupDisclosureKey(scope, subjectID) {
    const key = `${text(scope)}\x00${text(subjectID)}`;
    const found = this.#entries.get(key);
    if (!found || !found.active) throw new Error(`active disclosure key ${text(scope)}/${text(subjectID)} was not found`);
    return { ...found };
  }
}

export function createDisclosureKeyRegistry(entries = []) {
  return new MemoryDisclosureKeyRegistry(entries);
}

function effectiveDisclosurePolicy(defaultPolicy, item) {
  const supplied = item.disclosure_policy ?? item.disclosurePolicy;
  const policySet = item.disclosure_policy_set ?? item.disclosurePolicySet;
  if (supplied === undefined || supplied === null || policySet === false) return defaultPolicy;
  return normalizePayrollDisclosurePolicy(supplied);
}

function normalizePayrollItem(item, defaultPolicy, index, options) {
  if (!item || typeof item !== "object") throw new Error(`payroll item ${index} must be an object`);
  const normalized = {
    item_id: text(item.item_id ?? item.itemID ?? item.itemId),
    employee_id: text(item.employee_id ?? item.employeeID ?? item.employeeId),
    recipient_address: text(item.recipient_address ?? item.recipientAddress),
    amount: canonicalUint64(item.amount, `payroll item ${index} amount`, { positive: true }),
    denom: text(item.denom),
    disclosure_policy: effectiveDisclosurePolicy(defaultPolicy, item),
    expected_output_commitment: canonicalDigest(item.expected_output_commitment ?? item.expectedOutputCommitment, `payroll item ${index} expected_output_commitment`),
    expected_disclosure_digest: canonicalDigest(item.expected_disclosure_digest ?? item.expectedDisclosureDigest, `payroll item ${index} expected_disclosure_digest`)
  };
  if (!normalized.item_id) throw new Error(`payroll item ${index} item_id is required`);
  if (!normalized.recipient_address) throw new Error(`payroll item ${normalized.item_id} recipient_address is required`);
  // This also rejects invalid or non-canonical shielded addresses before we use them as evidence.
  hashRecipient(normalized.recipient_address, options);
  return normalized;
}

/** Normalize and validate PayrollInput. Values returned by this function are safe to use for planning. */
export function normalizePayrollInput(input = {}, options = {}) {
  if (!input || typeof input !== "object") throw new Error("payroll input must be an object");
  const normalized = {
    company_id: text(input.company_id ?? input.companyID ?? input.companyId),
    payroll_id: text(input.payroll_id ?? input.payrollID ?? input.payrollId),
    batch_id: text(input.batch_id ?? input.batchID ?? input.batchId),
    denom: text(input.denom),
    attempt: Number(input.attempt ?? 0),
    default_disclosure_policy: normalizePayrollDisclosurePolicy(input.default_disclosure_policy ?? input.defaultDisclosurePolicy ?? {}),
    created_at: input.created_at ?? input.createdAt ?? null,
    items: []
  };
  if (!normalized.company_id) throw new Error("payroll company_id is required");
  if (!normalized.payroll_id) throw new Error("payroll payroll_id is required");
  if (!normalized.batch_id) throw new Error("payroll batch_id is required");
  if (!normalized.denom) throw new Error("payroll denom is required");
  hashAmount(normalized.denom, 0n);
  if (!Number.isSafeInteger(normalized.attempt) || normalized.attempt < 0) throw new Error("payroll attempt must be a non-negative safe integer");
  const items = input.items;
  if (!Array.isArray(items) || items.length === 0) throw new Error("at least one payroll item is required");
  const itemIDs = new Set();
  const employeeIDs = new Set();
  normalized.items = items.map((item, index) => {
    const current = normalizePayrollItem(item, normalized.default_disclosure_policy, index, options);
    if (current.denom && current.denom !== normalized.denom) throw new Error(`payroll item ${current.item_id} denom does not match payroll denom`);
    current.denom = normalized.denom;
    if (itemIDs.has(current.item_id)) throw new Error(`duplicate payroll item_id ${current.item_id}`);
    itemIDs.add(current.item_id);
    if (current.employee_id) {
      if (employeeIDs.has(current.employee_id)) throw new Error(`duplicate payroll employee_id ${current.employee_id}`);
      employeeIDs.add(current.employee_id);
    }
    return Object.freeze(current);
  });
  return Object.freeze(normalized);
}

export function validatePayrollInput(input = {}, options = {}) {
  normalizePayrollInput(input, options);
  return true;
}

function normalizeTreasuryNote(note, index) {
  if (!note || typeof note !== "object") throw new Error(`treasury note ${index} must be an object`);
  return {
    ...note,
    note_id: text(note.note_id ?? note.noteID ?? note.noteId),
    owner_key_id: text(note.owner_key_id ?? note.ownerKeyID ?? note.ownerKeyId),
    nullifier_lookup_key: text(note.nullifier_lookup_key ?? note.nullifierLookupKey),
    nullifier_lookup_key_id: text(note.nullifier_lookup_key_id ?? note.nullifierLookupKeyID ?? note.nullifierLookupKeyId),
    denom: text(note.denom),
    amount: canonicalUint64(note.amount, `treasury note ${index} amount`),
    is_spent: note.is_spent === true || note.isSpent === true,
    reservation_id: text(note.reservation_id ?? note.reservationID ?? note.reservationId)
  };
}

function availableNotes(denom, notes) {
  return notes
    .filter(note => !note.is_spent && !note.reservation_id && note.denom === denom)
    .sort((left, right) => left.amount === right.amount
      ? left.note_id.localeCompare(right.note_id)
      : left.amount < right.amount ? -1 : 1);
}

function withinLegacyOutputBound(total, target) {
  return total >= target && total - target <= maxUint64;
}

function selectLegacyInputs(available, target) {
  const zero = available.find(note => note.amount === 0n);
  const positive = available.find(note => note.amount > 0n && withinLegacyOutputBound(note.amount, target));
  if (zero && positive) return [positive, zero];
  let best = null;
  for (let left = 0; left < available.length; left += 1) {
    if (available[left].amount <= 0n) continue;
    for (let right = left + 1; right < available.length; right += 1) {
      if (available[right].amount <= 0n) continue;
      const total = available[left].amount + available[right].amount;
      if (!withinLegacyOutputBound(total, target)) continue;
      if (!best || total < best.total || (total === best.total && `${available[left].note_id}\x00${available[right].note_id}` < best.key)) {
        best = { total, key: `${available[left].note_id}\x00${available[right].note_id}`, notes: [available[left], available[right]] };
      }
    }
  }
  return best?.notes ?? null;
}

function idsForPreparation(available, target, limit = 6) {
  const candidate = [];
  for (const note of available) if (note.amount === 0n) candidate.push(note);
  for (const note of available) if (note.amount >= target) candidate.push(note);
  for (let left = 0; left < available.length; left += 1) {
    for (let right = left + 1; right < available.length; right += 1) {
      if (withinLegacyOutputBound(available[left].amount + available[right].amount, target)) candidate.push(available[left], available[right]);
    }
  }
  return [...new Set(candidate.map(note => note.note_id).filter(Boolean))].slice(0, limit);
}

function preparationRecommendation(item, available, zeroAvailable, denom) {
  const single = available.filter(note => note.amount >= item.amount && withinLegacyOutputBound(note.amount, item.amount));
  if (single.length && zeroAvailable === 0) {
    return {
      kind: notePreparationRecommendationKinds.MakeDummy,
      item_id: item.item_id,
      message: "a sufficient single note exists, but a zero-value dummy note is required by the legacy 2-input transfer circuit",
      required_count: 1,
      target_amount: 0n,
      denom,
      candidate_note_ids: single.slice(0, 3).map(note => note.note_id)
    };
  }
  return {
    kind: notePreparationRecommendationKinds.SplitMerge,
    item_id: item.item_id,
    message: "prepare exact or pairable notes before the legacy 2-input payroll item can execute",
    required_count: 1,
    target_amount: item.amount,
    denom,
    candidate_note_ids: idsForPreparation(available, item.amount)
  };
}

/**
 * Go-compatible legacy 2x2 preparation analysis. It is an advisory UI gate;
 * execute payroll with planOneProofPayroll, not transfer-batch.
 */
export function analyzeNotePreparation(input, treasuryNotes = [], policy = {}) {
  const payroll = normalizePayrollInput(input, policy);
  if (!Array.isArray(treasuryNotes)) throw new Error("treasury notes must be an array");
  const notes = treasuryNotes.map(normalizeTreasuryNote);
  const spendable = availableNotes(payroll.denom, notes);
  const reservedNoteCount = notes.filter(note => !note.is_spent && note.reservation_id).length;
  const spentNoteCount = notes.filter(note => note.is_spent).length;
  const zeroDummyAvailable = spendable.filter(note => note.amount === 0n).length;
  const report = {
    company_id: payroll.company_id,
    payroll_id: payroll.payroll_id,
    batch_id: payroll.batch_id,
    denom: payroll.denom,
    total_items: payroll.items.length,
    ready_items: 0,
    blocked_items: 0,
    spendable_note_count: spendable.length,
    reserved_note_count: reservedNoteCount,
    spent_note_count: spentNoteCount,
    zero_dummy_available: zeroDummyAvailable,
    zero_dummy_required: 0,
    total_payroll_amount: payroll.items.reduce((sum, item) => sum + item.amount, 0n),
    total_spendable_amount: spendable.reduce((sum, note) => sum + note.amount, 0n),
    estimated_message_chunks: 0,
    items: [],
    recommendations: [],
    operation_hints: []
  };
  const remaining = [...spendable];
  for (const item of payroll.items) {
    const selected = selectLegacyInputs(remaining, item.amount);
    if (selected) {
      const selectedIDs = new Set(selected.map(note => note.note_id));
      for (let index = remaining.length - 1; index >= 0; index -= 1) if (selectedIDs.has(remaining[index].note_id)) remaining.splice(index, 1);
      report.ready_items += 1;
      report.items.push({ item_id: item.item_id, employee_id: item.employee_id, amount: item.amount, ready: true, reason: "", selected_note_ids: selected.map(note => note.note_id) });
    } else {
      report.blocked_items += 1;
      report.items.push({ item_id: item.item_id, employee_id: item.employee_id, amount: item.amount, ready: false, reason: "insufficient compatible unreserved notes", selected_note_ids: [] });
      report.recommendations.push(preparationRecommendation(item, spendable, zeroDummyAvailable, payroll.denom));
    }
  }
  if (report.total_spendable_amount < report.total_payroll_amount) {
    report.recommendations.push({
      kind: notePreparationRecommendationKinds.AddFunds,
      item_id: "",
      message: `spendable total ${report.total_spendable_amount} is below payroll total ${report.total_payroll_amount}`,
      required_count: 1,
      target_amount: report.total_payroll_amount - report.total_spendable_amount,
      denom: payroll.denom,
      candidate_note_ids: []
    });
  }
  if (reservedNoteCount) report.recommendations.push({
    kind: notePreparationRecommendationKinds.ResolveReservationLock,
    item_id: "",
    message: `${reservedNoteCount} treasury notes are already reserved and excluded from preparation`,
    required_count: reservedNoteCount,
    target_amount: null,
    denom: "",
    candidate_note_ids: []
  });
  const singleNoteRequirements = payroll.items.filter(item => spendable.some(note => note.amount >= item.amount && withinLegacyOutputBound(note.amount, item.amount))).length;
  report.zero_dummy_required = Math.max(0, singleNoteRequirements - zeroDummyAvailable);
  if (report.zero_dummy_required > 0) report.recommendations.push({
    kind: notePreparationRecommendationKinds.MakeDummy,
    item_id: "",
    message: `prepare at least ${report.zero_dummy_required} additional zero-value dummy notes`,
    required_count: report.zero_dummy_required,
    target_amount: 0n,
    denom: payroll.denom,
    candidate_note_ids: []
  });
  report.operation_hints = report.recommendations.map(recommendation => ({ ...recommendation }));
  const maxMessagesPerTx = Number(policy.max_messages_per_tx ?? policy.maxMessagesPerTx ?? 1);
  const chunkSize = Number.isSafeInteger(maxMessagesPerTx) && maxMessagesPerTx > 0 ? maxMessagesPerTx : 1;
  report.estimated_message_chunks = report.ready_items ? Math.ceil(report.ready_items / chunkSize) : 0;
  return report;
}

function idComponent(value) {
  return base64FromBytes(utf8Bytes(value || "_")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function payrollBatchOperationID(input, operationIndex) {
  if (!Number.isSafeInteger(operationIndex) || operationIndex < 0) throw new Error("payroll operation index must be a non-negative safe integer");
  const attempt = input.attempt > 0 ? `:attempt:${String(input.attempt).padStart(3, "0")}` : "";
  return `company:${idComponent(input.company_id)}:batch:${idComponent(input.batch_id)}:payroll:${idComponent(input.payroll_id)}:item:${idComponent(`batch-${String(operationIndex).padStart(6, "0")}`)}${attempt}:one-proof-16x32`;
}

function selectOneProofCandidates(available, target) {
  const byOwner = new Map();
  for (const note of available) {
    if (note.amount <= 0n || !note.owner_key_id) continue;
    const list = byOwner.get(note.owner_key_id) || [];
    list.push(note);
    byOwner.set(note.owner_key_id, list);
  }
  const candidateLists = [];
  const ownerIDs = [...byOwner.keys()].sort();
  const perOwnerLimit = Math.max(1, Math.ceil(maxInputCandidates / ownerIDs.length));
  // This limit applies to the whole payroll-planning attempt, not once per
  // owner.  Per-owner slices retain deterministic fairness while preventing a
  // large cache of owner keys from multiplying the bounded DFS work.
  const perOwnerVisitLimit = Math.max(1, Math.floor(maxInputCandidateSearch / ownerIDs.length));
  let remainingVisits = maxInputCandidateSearch;
  for (const ownerID of ownerIDs) {
    if (remainingVisits <= 0) break;
    const notes = [...byOwner.get(ownerID)].sort((left, right) => left.amount === right.amount ? left.note_id.localeCompare(right.note_id) : left.amount > right.amount ? -1 : 1);
    const ownerCandidates = [];
    const selected = [];
    let visited = 0;
    const visit = (index, total) => {
      if (total >= target) {
        if (ownerCandidates.length >= perOwnerLimit) return;
        const copy = [...selected].sort((left, right) => left.note_id.localeCompare(right.note_id));
        ownerCandidates.push({ notes: copy, total });
        return;
      }
      if (remainingVisits <= 0 || visited >= perOwnerVisitLimit || ownerCandidates.length >= perOwnerLimit) return;
      visited += 1;
      remainingVisits -= 1;
      if (index >= notes.length || selected.length >= oneProofPayrollMaxInputs) return;
      let maxReachable = total;
      for (let cursor = index; cursor < notes.length && cursor < index + (oneProofPayrollMaxInputs - selected.length); cursor += 1) maxReachable += notes[cursor].amount;
      if (maxReachable < target) return;
      selected.push(notes[index]);
      visit(index + 1, total + notes[index].amount);
      selected.pop();
      visit(index + 1, total);
    };
    visit(0, 0n);
    candidateLists.push(ownerCandidates);
  }
  const unique = new Map();
  for (const ownerCandidates of candidateLists) {
    for (const candidate of ownerCandidates) unique.set(candidate.notes.map(note => note.note_id).join("\x00"), candidate);
  }
  return [...unique.values()].sort((left, right) => {
    const leftWaste = left.total - target;
    const rightWaste = right.total - target;
    if (leftWaste !== rightWaste) return leftWaste < rightWaste ? -1 : 1;
    if (left.notes.length !== right.notes.length) return left.notes.length - right.notes.length;
    return left.notes.map(note => note.note_id).join("\x00").localeCompare(right.notes.map(note => note.note_id).join("\x00"));
  }).slice(0, maxInputCandidates);
}

function planOneProofSearch(input, available, itemOffset, operationIndex, state, options) {
  if (itemOffset === input.items.length) return [];
  state.farthest = Math.max(state.farthest, itemOffset);
  if (state.remaining-- <= 0) return null;
  const maxPayments = Math.min(oneProofPayrollMaxOutputs, input.items.length - itemOffset);
  const outputMode = oneProofOutputMode(options);
  for (let paymentCount = maxPayments; paymentCount >= 1; paymentCount -= 1) {
    const items = input.items.slice(itemOffset, itemOffset + paymentCount);
    const paymentTotal = items.reduce((sum, item) => sum + item.amount, 0n);
    for (const selection of selectOneProofCandidates(available, paymentTotal)) {
      const change = selection.total - paymentTotal;
      if (change > maxUint64 || (paymentCount === oneProofPayrollMaxOutputs && change !== 0n)) continue;
      const compactOutputCount = paymentCount + (change > 0n ? 1 : 0);
      if (compactOutputCount > oneProofPayrollMaxOutputs) continue;
      const operation = buildOneProofOperationPlan(input, items, selection, paymentTotal, change, operationIndex, options);
      const selectedIDs = new Set(selection.notes.map(note => note.note_id));
      const remainder = planOneProofSearch(input, available.filter(note => !selectedIDs.has(note.note_id)), itemOffset + paymentCount, operationIndex + 1, state, options);
      if (remainder) return [operation, ...remainder];
    }
  }
  return null;
}

function preferredExpectedDigest(item) {
  return item.expected_disclosure_digest || item.disclosure_policy.expected_audit_disclosure_digest || "";
}

function buildOneProofOperationPlan(input, items, selection, paymentTotal, change, operationIndex, options = {}) {
  const operationID = payrollBatchOperationID(input, operationIndex);
  const plannedItems = items.map((item, itemIndex) => ({
    company_id: input.company_id,
    payroll_id: input.payroll_id,
    batch_id: input.batch_id,
    attempt: input.attempt,
    chunk_id: `company:${idComponent(input.company_id)}:batch:${idComponent(input.batch_id)}:payroll:${idComponent(input.payroll_id)}${input.attempt > 0 ? `:attempt:${String(input.attempt).padStart(3, "0")}` : ""}:chunk:${String(operationIndex).padStart(6, "0")}`,
    item_id: item.item_id,
    employee_id: item.employee_id,
    operation_id: operationID,
    recipient_address: item.recipient_address,
    expected_recipient_hash: hashRecipient(item.recipient_address, options),
    amount: item.amount,
    expected_amount_hash: hashAmount(input.denom, item.amount),
    denom: input.denom,
    disclosure_policy: item.disclosure_policy,
    expected_output_commitment: item.expected_output_commitment,
    expected_disclosure_digest: preferredExpectedDigest(item),
    input_notes: selection.notes.map(note => ({ ...note })),
    status: payrollItemStatuses.Planned,
    failure_reason: "",
    retry_count: 0,
    batch_item_index: itemIndex
  }));
  const outputMode = oneProofOutputMode(options);
  const compactOutputCount = items.length + (change > 0n ? 1 : 0);
  const paddingCount = outputMode === "exact-32" ? oneProofPayrollMaxOutputs - compactOutputCount : 0;
  return {
    operation_id: operationID,
    circuit_set_id: oneProofPayrollCircuitSetId,
    items: plannedItems,
    input_notes: selection.notes.map(note => ({ ...note })),
    input_total: selection.total,
    payment_total: paymentTotal,
    change,
    output_count: compactOutputCount + paddingCount,
    has_change: change > 0n,
    output_mode: outputMode,
    padding_count: paddingCount
  };
}

/** Plan current 1..16-input / 1..32-output payroll operations. It never creates an implicit merge. */
export function planOneProofPayroll(input, treasuryNotes = [], options = {}) {
  const payroll = normalizePayrollInput(input, options);
  if (!Array.isArray(treasuryNotes)) throw new Error("treasury notes must be an array");
  const notes = treasuryNotes.map(normalizeTreasuryNote);
  const state = { remaining: Number(options.search_limit ?? options.searchLimit ?? maxBatchPlanSearch), farthest: 0 };
  const operations = planOneProofSearch(payroll, availableNotes(payroll.denom, notes), 0, 0, state, options);
  if (!operations) {
    const item = payroll.items[Math.min(state.farthest, payroll.items.length - 1)];
    throw new Error(`one-proof payroll preparation is required: item ${item.item_id} cannot be funded by 1..16 current notes`);
  }
  return {
    company_id: payroll.company_id,
    payroll_id: payroll.payroll_id,
    batch_id: payroll.batch_id,
    denom: payroll.denom,
    attempt: payroll.attempt,
    status: payrollPlanStatuses.Draft,
    circuit_set_id: oneProofPayrollCircuitSetId,
    operations,
    created_at: payroll.created_at,
    updated_at: null
  };
}

/** Validate the authoritative AssetRegistryV1 entry before constructing a payroll witness. */
export function normalizePayrollAssetRegistryEntry(entry, denom) {
  return normalizeAssetRegistryEntryV1(entry, { canonical_denom: denom });
}

async function resolvePayrollAssetRegistry(assetRegistry, denom) {
  if (!assetRegistry) throw new Error("an authoritative AssetRegistryV1 resolver is required for one-proof payroll");
  let response;
  if (typeof assetRegistry === "function") response = await assetRegistry(denom);
  else if (typeof assetRegistry.queryAssetByDenom === "function") response = await assetRegistry.queryAssetByDenom(denom);
  else if (typeof assetRegistry.resolveAsset === "function") response = await assetRegistry.resolveAsset(denom);
  else if (typeof assetRegistry.fetchAssetByDenom === "function") {
    return normalizeAssetRegistryQueryResponseV1(await assetRegistry.fetchAssetByDenom(denom), { canonical_denom: denom }).asset;
  }
  else response = assetRegistry;
  return normalizePayrollAssetRegistryEntry(response, denom);
}

/** Resolve the live consensus CircuitConfig before creating a payroll witness. */
async function resolvePayrollCircuitConfig(circuitConfig) {
  if (!circuitConfig) throw new Error("an authoritative CircuitConfig resolver is required for one-proof payroll");
  let response;
  if (typeof circuitConfig === "function") response = await circuitConfig();
  else if (typeof circuitConfig.assertCircuitConfig === "function") response = await circuitConfig.assertCircuitConfig();
  else if (typeof circuitConfig.fetchCircuitConfig === "function") response = await circuitConfig.fetchCircuitConfig();
  else throw new Error("an authoritative CircuitConfig resolver is required for one-proof payroll");
  return validateCircuitConfigV1(response);
}

/**
 * Bind the active consensus circuit identity and denom mapping before output
 * secrets are generated or the one-proof intent reaches the owner signer.
 */
async function resolvePayrollProtocolPreflight(input, denom) {
  const assetRegistry = input.asset_registry ?? input.assetRegistry;
  const preflight = input.protocol_preflight ?? input.protocolPreflight ?? input.cosmos_client ?? input.cosmosClient
    ?? (typeof assetRegistry?.assertProtocolPreflight === "function" ? assetRegistry : null);
  if (preflight && typeof preflight.assertProtocolPreflight === "function") {
    const response = await preflight.assertProtocolPreflight(denom);
    if (!response || typeof response !== "object") throw new Error("one-proof payroll protocol preflight response is required");
    return Object.freeze({
      circuit_config: validateCircuitConfigV1(response.circuit_config ?? response.circuitConfig),
      asset: normalizePayrollAssetRegistryEntry(response.asset, denom)
    });
  }
  const circuitConfig = input.circuit_config ?? input.circuitConfig ?? input.cosmos_client ?? input.cosmosClient;
  const [validatedCircuitConfig, asset] = await Promise.all([
    resolvePayrollCircuitConfig(circuitConfig),
    resolvePayrollAssetRegistry(assetRegistry, denom)
  ]);
  return Object.freeze({ circuit_config: validatedCircuitConfig, asset });
}

function canonicalFieldSecret(value, label, { nonZero = true } = {}) {
  if (value === undefined || value === null || value === "") {
    while (true) {
      const candidate = bytesToBigIntBE(randomBytes(32));
      if (candidate < FIELD_MODULUS && (!nonZero || candidate !== 0n)) return candidate;
    }
  }
  const encoded = String(value).trim();
  if (!/^(0|[1-9][0-9]*)$/.test(encoded)) throw new Error(`${label} must be a canonical BN254 field element`);
  const parsed = BigInt(encoded);
  if (parsed >= FIELD_MODULUS || (nonZero && parsed === 0n)) throw new Error(`${label} must be a${nonZero ? " non-zero" : ""} canonical BN254 field element`);
  return parsed;
}

function secretForOutput(secrets, key, policy) {
  const source = secrets?.[key] ?? {};
  if (!source || typeof source !== "object") throw new Error(`payroll output secret ${key} must be an object`);
  return {
    randomness: canonicalFieldSecret(source.randomness, `payroll output ${key} randomness`),
    userDisclosureBlinding: policy === 0 ? 0n : canonicalFieldSecret(source.user_disclosure_blinding ?? source.userDisclosureBlinding, `payroll output ${key} user disclosure blinding`),
    fullDisclosureBlinding: canonicalFieldSecret(source.full_disclosure_blinding ?? source.fullDisclosureBlinding, `payroll output ${key} full disclosure blinding`),
    memo: String(source.memo ?? "")
  };
}

function preparedInputFromTreasuryNote(note, index, assetID) {
  const noteValue = validateNoteV1(note.note ?? note);
  if (noteValue.assetID !== assetID) throw new Error(`payroll input ${index} asset does not match AssetRegistryV1`);
  if (noteValue.amount !== note.amount) throw new Error(`payroll input ${index} amount does not match treasury inventory`);
  const merklePath = note.merkle_path ?? note.merklePath;
  const merklePathHelper = note.merkle_path_helper ?? note.merklePathHelper;
  if (!Array.isArray(merklePath) || !Array.isArray(merklePathHelper)) throw new Error(`payroll input ${index} requires a same-root Merkle path snapshot`);
  return { note: noteValue, merklePath, merklePathHelper };
}

function paymentNote(item, assetID, secret, options) {
  let recipient;
  try {
    recipient = decodeShieldedAddress(item.recipient_address, options);
  } catch (error) {
    throw new Error(`payroll item ${item.item_id} recipient must be a valid shielded address: ${error.message}`);
  }
  return {
    receiverSpendPubKeyX: recipient.spendPubKey.x,
    receiverSpendPubKeyY: recipient.spendPubKey.y,
    receiverViewPubKeyX: recipient.viewPubKey.x,
    receiverViewPubKeyY: recipient.viewPubKey.y,
    amount: item.amount,
    assetID,
    randomness: secret.randomness,
    memo: secret.memo
  };
}

function changeNote(inputNote, amount, assetID, secret) {
  return {
    receiverSpendPubKeyX: inputNote.receiverSpendPubKeyX,
    receiverSpendPubKeyY: inputNote.receiverSpendPubKeyY,
    receiverViewPubKeyX: inputNote.receiverViewPubKeyX,
    receiverViewPubKeyY: inputNote.receiverViewPubKeyY,
    amount,
    assetID,
    randomness: secret.randomness,
    memo: secret.memo
  };
}

function expectedDigest(value, label) {
  if (!value) return "";
  return hexFromBytes(bytesFromBase64(value, label));
}

function assertExpectedValue(expected, actual, label) {
  if (expected && expected !== actual) throw new Error(`${label} does not match the final prepared payroll payload`);
}

/**
 * Derive per-payment success evidence from a final, signed prepared payload.
 * Full disclosure is a single commitment shared by audit and self-view envelopes.
 */
export function buildExpectedPayrollEvidence(operation, payload, options = {}) {
  if (!operation || typeof operation !== "object") throw new Error("one-proof payroll operation is required");
  validatePreparedBatchTransferPayloadEnvelope(payload, options.now_unix == null && options.nowUnix == null ? {} : { nowUnix: options.now_unix ?? options.nowUnix });
  const items = operation.items;
  if (!Array.isArray(items) || items.length === 0 || !Array.isArray(payload.outputs) || !Array.isArray(payload.message_outputs)) throw new Error("payroll operation and prepared payload outputs are required");
  const expectedOutputCount = items.length + (operation.has_change ? 1 : 0) + Number(operation.padding_count ?? 0);
  if (payload.outputs.length !== expectedOutputCount || payload.message_outputs.length !== expectedOutputCount) throw new Error("prepared payload output shape does not match one-proof payroll operation");
  const assetIDHex = (() => {
    const decimal = String(payload.asset_id ?? "");
    if (!/^(0|[1-9][0-9]*)$/.test(decimal)) throw new Error("prepared payload asset_id is invalid");
    const field = BigInt(decimal);
    if (field === 0n || field >= FIELD_MODULUS) throw new Error("prepared payload asset_id is invalid");
    return field.toString(16).padStart(64, "0");
  })();
  return items.map((item, index) => {
    const output = payload.outputs[index];
    const wire = payload.message_outputs[index];
    if (output?.kind !== "payment" || String(output?.note?.am ?? "") !== item.amount.toString()) throw new Error(`prepared payment output ${index} does not match payroll item ${item.item_id}`);
    if (Number(output.privacy_policy) !== item.disclosure_policy.user_privacy_policy || Number(output.disclosure_mode) !== item.disclosure_policy.user_disclosure_mode) throw new Error(`prepared payment output ${index} disclosure policy does not match payroll item ${item.item_id}`);
    const commitment = expectedDigest(wire?.commitment, `payroll output ${index} commitment`);
    const userDigest = expectedDigest(wire?.user_disclosure_digest, `payroll output ${index} user disclosure digest`);
    const fullDigest = expectedDigest(wire?.full_disclosure_digest, `payroll output ${index} full disclosure digest`);
    const recipientHash = hashRecipient(item.recipient_address, options);
    const amountHash = hashAmount(item.denom, item.amount);
    assertExpectedValue(item.expected_output_commitment, commitment, `payroll item ${item.item_id} expected output commitment`);
    assertExpectedValue(item.expected_disclosure_digest, fullDigest, `payroll item ${item.item_id} expected disclosure digest`);
    assertExpectedValue(item.disclosure_policy.expected_user_disclosure_digest, userDigest, `payroll item ${item.item_id} expected user disclosure digest`);
    assertExpectedValue(item.disclosure_policy.expected_audit_disclosure_digest, fullDigest, `payroll item ${item.item_id} expected audit disclosure digest`);
    assertExpectedValue(item.disclosure_policy.expected_self_view_disclosure_digest, fullDigest, `payroll item ${item.item_id} expected self-view disclosure digest`);
    return Object.freeze({
      operation_id: operation.operation_id,
      item_id: item.item_id,
      employee_id: item.employee_id,
      batch_item_index: index,
      role: "payment",
      expected_output_commitment: commitment,
      expected_user_disclosure_digest: userDigest,
      expected_audit_disclosure_digest: fullDigest,
      expected_self_view_disclosure_digest: fullDigest,
      expected_recipient_hash: recipientHash,
      expected_amount_hash: amountHash,
      expected_denom: item.denom,
      asset_id_hex: assetIDHex,
      user_privacy_policy: item.disclosure_policy.user_privacy_policy,
      user_disclosure_mode: item.disclosure_policy.user_disclosure_mode,
      audit_key_id: payload.audit_key_id,
      audit_key_epoch: payload.audit_key_epoch
    });
  });
}

/**
 * Build the single canonical `privacy-note-v1` prepared payload for one
 * payroll operation. It accepts only fixed-v1 notes, same-root Merkle paths,
 * and an authoritative AssetRegistryV1 lookup.
 */
export async function prepareOneProofPayrollOperation(input = {}) {
  if (!input || typeof input !== "object") throw new Error("one-proof payroll preparation input is required");
  const operation = input.operation;
  if (!operation || typeof operation !== "object" || !Array.isArray(operation.items) || !Array.isArray(operation.input_notes)) throw new Error("one-proof payroll operation plan is required");
  if (operation.circuit_set_id && operation.circuit_set_id !== oneProofPayrollCircuitSetId) throw new Error("one-proof payroll operation must use privacy-note-v1");
  if (operation.items.length < 1 || operation.items.length > oneProofPayrollMaxOutputs || operation.input_notes.length < 1 || operation.input_notes.length > oneProofPayrollMaxInputs) throw new Error("one-proof payroll operation exceeds 16x32 capacity");
  const denom = text(operation.items[0]?.denom);
  if (!denom || operation.items.some(item => text(item.denom) !== denom)) throw new Error("one-proof payroll operation requires one canonical denom");
  // This must happen before any witness secret is generated or signed.
  const preflight = await resolvePayrollProtocolPreflight(input, denom);
  const asset = preflight.asset;
  const preparedInputs = operation.input_notes.map((note, index) => preparedInputFromTreasuryNote(note, index, asset.asset_id_field));
  const inputTotal = preparedInputs.reduce((sum, entry) => sum + entry.note.amount, 0n);
  const paymentTotal = operation.items.reduce((sum, item) => sum + canonicalUint64(item.amount, `payroll item ${item.item_id} amount`, { positive: true }), 0n);
  const change = inputTotal - paymentTotal;
  const plannedChange = canonicalUint64(operation.change, "one-proof payroll operation change");
  const plannedOutputCount = Number(operation.output_count);
  const outputMode = oneProofOutputMode(operation);
  const paddingCount = Number(operation.padding_count ?? operation.paddingCount ?? 0);
  if (!Number.isSafeInteger(plannedOutputCount) || plannedOutputCount < 1 || plannedOutputCount > oneProofPayrollMaxOutputs) throw new Error("one-proof payroll operation output count is invalid");
  if (!Number.isSafeInteger(paddingCount) || paddingCount < 0) throw new Error("one-proof payroll operation output mode is invalid");
  if (change < 0n || change !== plannedChange || Boolean(change > 0n) !== Boolean(operation.has_change)) throw new Error("one-proof payroll operation totals are inconsistent");
  const compactOutputCount = operation.items.length + (change > 0n ? 1 : 0);
  if (plannedOutputCount !== compactOutputCount + paddingCount || (outputMode === "compact" && paddingCount !== 0) || (outputMode === "exact-32" && plannedOutputCount !== oneProofPayrollMaxOutputs)) {
    throw new Error("one-proof payroll operation output shape is inconsistent");
  }
  const secrets = input.output_secrets ?? input.outputSecrets ?? {};
  const outputs = operation.items.map(item => {
    const secret = secretForOutput(secrets, item.item_id, item.disclosure_policy.user_privacy_policy);
    return {
      kind: "payment",
      note: paymentNote(item, asset.asset_id_field, secret, input),
      privacyPolicy: item.disclosure_policy.user_privacy_policy,
      disclosureMode: item.disclosure_policy.user_disclosure_mode,
      ...(item.disclosure_policy.user_disclosure_target_pubkey_hex ? { disclosureTargetPubKey: item.disclosure_policy.user_disclosure_target_pubkey_hex } : {}),
      userDisclosureBlinding: secret.userDisclosureBlinding,
      fullDisclosureBlinding: secret.fullDisclosureBlinding
    };
  });
  if (change > 0n) {
    const secret = secretForOutput(secrets, "change", 0);
    outputs.push({
      kind: "change",
      note: changeNote(preparedInputs[0].note, change, asset.asset_id_field, secret),
      privacyPolicy: 0,
      disclosureMode: 0,
      userDisclosureBlinding: 0n,
      fullDisclosureBlinding: secret.fullDisclosureBlinding
    });
  }
  for (let index = 0; index < paddingCount; index += 1) {
    const secret = secretForOutput(secrets, `padding:${index}`, 0);
    outputs.push({
      kind: "padding",
      note: changeNote(preparedInputs[0].note, 0n, asset.asset_id_field, secret),
      privacyPolicy: 0,
      disclosureMode: 0,
      userDisclosureBlinding: 0n,
      fullDisclosureBlinding: secret.fullDisclosureBlinding
    });
  }
  if (outputs.length !== plannedOutputCount) throw new Error("one-proof payroll operation output count is inconsistent");
  const payload = await buildPreparedBatchTransferPayload({
    creator: input.creator,
    chainId: input.chain_id ?? input.chainId,
    expiresAtUnix: input.expires_at_unix ?? input.expiresAtUnix,
    root: input.root,
    inputs: preparedInputs,
    outputs,
    auditKeyId: input.audit_key_id ?? input.auditKeyId,
    auditKeyEpoch: input.audit_key_epoch ?? input.auditKeyEpoch,
    auditDisclosureTargetPubKey: input.audit_disclosure_target_pubkey ?? input.auditDisclosureTargetPubKey,
    selfViewDisclosureTargetPubKey: input.self_view_disclosure_target_pubkey ?? input.selfViewDisclosureTargetPubKey,
    disableSelfViewDisclosure: input.disable_self_view_disclosure ?? input.disableSelfViewDisclosure,
    signer: input.signer,
    allowLegacyNoteHashSigner: true
  });
  const expectedEvidence = buildExpectedPayrollEvidence(operation, payload, input);
  const effects = preparedBatchTransferEffectHex(payload);
  return Object.freeze({
    operation,
    circuit_config: preflight.circuit_config,
    asset_registry_entry: asset,
    payload,
    expected_evidence: expectedEvidence,
    input_nullifier_hexes: effects.nullifier_hexes
  });
}

/** Recheck every input nullifier immediately before a one-proof broadcast. */
export async function assertOneProofPayrollNullifiersUnspent(payload, checkNullifiers) {
  if (typeof checkNullifiers !== "function") throw new Error("a batch nullifier status reader is required");
  validatePreparedBatchTransferPayloadEnvelope(payload);
  const nullifiers = preparedBatchTransferEffectHex(payload).nullifier_hexes;
  const statuses = await checkNullifiers(nullifiers);
  const statusFor = nullifier => statuses instanceof Map
    ? statuses.get(nullifier) ?? statuses.get(`0x${nullifier}`)
    : statuses?.[nullifier] ?? statuses?.[`0x${nullifier}`];
  for (const [index, nullifier] of nullifiers.entries()) {
    const value = statusFor(nullifier);
    if (value !== false) throw new Error(`one-proof payroll input nullifier at index ${index} is spent, missing, or has an invalid status`);
  }
  return nullifiers;
}

/**
 * Adapt one planned payroll operation to the existing CAS/lease reservation
 * manager. This deliberately reserves all batch inputs under one operation ID.
 */
export function reservationPlanForOneProofPayrollOperation(operation) {
  if (!operation || typeof operation !== "object" || !text(operation.operation_id) || !Array.isArray(operation.input_notes) || !operation.input_notes.length) {
    throw new Error("one-proof payroll operation with input notes is required for reservation");
  }
  const inputs = operation.input_notes.map((treasuryNote, index) => {
    const note = validateNoteV1(treasuryNote.note ?? treasuryNote);
    return {
      note,
      nullifier: fieldHexV1(computeNoteNullifierV1(note)),
      note_id: text(treasuryNote.note_id) || `${operation.operation_id}:input:${index}`,
      tx_hash: text(treasuryNote.tx_hash ?? treasuryNote.txHash),
      height: treasuryNote.height ?? 0,
      sequence: treasuryNote.sequence ?? 0,
      nullifier_status: "unspent"
    };
  });
  return Object.freeze({ selection: { inputs } });
}

/** Confirm all one-proof input reservations before requesting a signature or proof. */
export async function reserveOneProofPayrollOperation(reservationManager, operation, { metadata = {} } = {}) {
  if (!reservationManager || typeof reservationManager.reservePlan !== "function") throw new Error("a NoteReservationManager is required for one-proof payroll reservation");
  if (!operation || typeof operation !== "object") throw new Error("one-proof payroll operation is required");
  const ownerKeyID = text(operation.input_notes?.[0]?.owner_key_id ?? operation.input_notes?.[0]?.ownerKeyID);
  if (!ownerKeyID || operation.input_notes.some(note => text(note.owner_key_id ?? note.ownerKeyID) !== ownerKeyID)) throw new Error("one-proof payroll inputs must have one owner_key_id for reservation");
  if (text(reservationManager.ownerKeyId) !== ownerKeyID) throw new Error("one-proof payroll reservation manager owner_key_id does not match operation inputs");
  return reservationManager.reservePlan({
    plan: reservationPlanForOneProofPayrollOperation(operation),
    operationId: operation.operation_id,
    kind: "payroll-one-proof-16x32",
    metadata: { ...metadata, payroll_operation_id: operation.operation_id, circuit_set_id: oneProofPayrollCircuitSetId }
  });
}

function frozenReservationBatch(batch, reservations) {
  return Object.freeze({
    ...batch,
    reservation_ids: Object.freeze([...(batch.reservation_ids || [])]),
    reservations: Object.freeze([...(reservations || [])])
  });
}

async function payrollReservationSet(reservationManager, prepared, reservationBatch) {
  if (!reservationManager || typeof reservationManager.getReservations !== "function" || typeof reservationManager.lookupKeyForNote !== "function") {
    throw new Error("a NoteReservationManager with atomic reservation-set lookup support is required");
  }
  const normalized = expectedPayrollEvidenceForPreparedOperation(prepared);
  const reservationIDs = [...(reservationBatch?.reservation_ids || [])].map(value => text(value));
  if (!reservationIDs.length || reservationIDs.some(id => !id) || new Set(reservationIDs).size !== reservationIDs.length) {
    throw new Error("one-proof payroll reservation batch requires unique reservation IDs");
  }
  if (text(reservationBatch?.operation_id) !== normalized.operation.operation_id) {
    throw new Error("one-proof payroll reservation batch operation ID does not match the prepared operation");
  }
  if (reservationIDs.length !== normalized.operation.input_notes.length) {
    throw new Error("one-proof payroll reservation batch input count does not match the prepared operation");
  }
  const loadedReservations = await reservationManager.getReservations(reservationIDs);
  const reservationsByID = new Map(loadedReservations.map(reservation => [text(reservation.reservation_id), reservation]));
  if (loadedReservations.length !== reservationIDs.length || reservationsByID.size !== reservationIDs.length) {
    throw new Error("one-proof payroll reservation batch lookup did not return the exact reservation set");
  }
  const reservations = reservationIDs.map(id => reservationsByID.get(id));
  if (reservations.some(reservation => !reservation)) {
    throw new Error("one-proof payroll reservation batch lookup did not return the exact reservation set");
  }
  if (reservations.some(reservation => text(reservation.operation_id) !== normalized.operation.operation_id)) {
    throw new Error("one-proof payroll reservation does not belong to the prepared operation");
  }
  // Derive lookup keys through the same adapter used at reservation time. The
  // adapter pins the canonical nullifier alongside the note; using the raw
  // treasury note here can select a different nullifier identity.
  const reservationPlan = reservationPlanForOneProofPayrollOperation(normalized.operation);
  const expectedLookupKeys = await Promise.all(reservationPlan.selection.inputs.map(input =>
    reservationManager.lookupKeyForNote(input)
  ));
  const actualLookupKeys = reservations.map(reservation => text(reservation.nullifier_lookup_key));
  if (new Set(expectedLookupKeys).size !== expectedLookupKeys.length ||
      new Set(actualLookupKeys).size !== actualLookupKeys.length ||
      expectedLookupKeys.some(key => !actualLookupKeys.includes(key))) {
    throw new Error("one-proof payroll reservation inputs do not match the prepared operation");
  }
  return { normalized, reservationIDs, reservations };
}

function reservationStatusesAre(reservations, ...statuses) {
  return reservations.length > 0 && reservations.every(reservation => statuses.includes(String(reservation.status)));
}

function throwIfPayrollReservationStateMixed(reservations, message = "one-proof payroll reservations have mixed states") {
  if (new Set(reservations.map(reservation => String(reservation.status))).size <= 1) return;
  const states = reservations.map(reservation => ({
    reservation_id: text(reservation.reservation_id),
    status: text(reservation.status),
    ...(reservation.metadata?.operation_status
      ? { operation_status: text(reservation.metadata.operation_status) }
      : {})
  }));
  const operationIDs = [...new Set(reservations.map(reservation => text(reservation.operation_id)).filter(Boolean))];
  throw new OperationStateMixedError({
    operation_id: operationIDs.length === 1 ? operationIDs[0] : "",
    reservations: states
  }, `${message}: ${states.map(state => `${state.reservation_id}=${state.status}`).join(", ")}`);
}

function payrollReservationMetadata(operationEvidence, metadata = {}) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new Error("one-proof payroll reservation metadata must be an object");
  }
  return {
    ...metadata,
    payroll_operation_id: operationEvidence.operation_id,
    payroll_circuit_set_id: operationEvidence.circuit_set_id,
    payroll_payload_hash: operationEvidence.payload_hash,
    ...(operationEvidence.proof_hash ? { payroll_proof_hash: operationEvidence.proof_hash } : {})
  };
}

function consistentPayrollBroadcastIdentity(label, values) {
  const normalized = values
    .filter(value => value !== undefined && value !== null)
    .map(value => text(value));
  if (new Set(normalized).size > 1) {
    throw new Error(`one-proof payroll ${label} aliases must match`);
  }
  return normalized[0] || "";
}

function payrollBroadcastIdentity({
  tx_hash,
  txHash,
  tx_bytes_hash,
  txBytesHash,
  sign_doc_hash,
  signDocHash
} = {}) {
  return {
    txHash: consistentPayrollBroadcastIdentity("transaction hash", [tx_hash, txHash]),
    txBytesHash: consistentPayrollBroadcastIdentity("transaction bytes hash", [tx_bytes_hash, txBytesHash]),
    signDocHash: consistentPayrollBroadcastIdentity("sign-doc hash", [sign_doc_hash, signDocHash])
  };
}

function requiredPayrollCosmosBroadcastIdentity(input = {}, label = "broadcast attempt", {
  requireSignedBindings = false
} = {}) {
  const normalizedAlias = (aliasLabel, values) => {
    const normalized = values
      .filter(value => value !== undefined && value !== null)
      .map(value => canonicalDigest(value, `one-proof payroll ${label} ${aliasLabel}`));
    if (new Set(normalized).size > 1) {
      throw new Error(`one-proof payroll ${label} ${aliasLabel} aliases must match`);
    }
    return normalized[0] || "";
  };
  const txHash = normalizedAlias("transaction hash", [input.tx_hash, input.txHash]).toUpperCase();
  if (!txHash) {
    throw new Error(`one-proof payroll ${label} requires the exact Cosmos transaction hash`);
  }
  const txBytesHash = normalizedAlias(
    "transaction bytes hash",
    [input.tx_bytes_hash, input.txBytesHash]
  );
  if (requireSignedBindings && !txBytesHash) {
    throw new Error(`one-proof payroll ${label} requires the exact signed transaction bytes hash`);
  }
  if (txBytesHash && txBytesHash.toUpperCase() !== txHash) {
    throw new Error(`one-proof payroll ${label} transaction hash does not match its signed transaction bytes hash`);
  }
  const signDocHash = normalizedAlias(
    "sign-doc hash",
    [input.sign_doc_hash, input.signDocHash]
  );
  if (requireSignedBindings && !signDocHash) {
    throw new Error(`one-proof payroll ${label} requires the exact sign-doc hash`);
  }
  return {
    txHash,
    txBytesHash,
    signDocHash
  };
}

function assertPayrollBroadcastIdentityMatches(reservations, identity, { requireComplete = false } = {}) {
  const storedTxHashes = [...new Set(reservations.map(reservation => text(reservation.submitted_tx_hash)).filter(Boolean))];
  const storedTxBytesHashes = [...new Set(reservations.map(reservation => text(reservation.tx_bytes_hash)).filter(Boolean))];
  if (storedTxHashes.length === 1 && storedTxBytesHashes.length === 1 &&
      storedTxHashes[0].toLowerCase() !== storedTxBytesHashes[0].toLowerCase()) {
    throw new Error("one-proof payroll durable transaction hash does not match its transaction bytes hash");
  }
  const fields = [
    ["txHash", "submitted_tx_hash"],
    ["txBytesHash", "tx_bytes_hash"],
    ["signDocHash", "sign_doc_hash"]
  ];
  for (const [identityField, reservationField] of fields) {
    const stored = [...new Set(reservations.map(reservation => text(reservation[reservationField])).filter(Boolean))];
    if (stored.length > 1) {
      throw new Error(`one-proof payroll reservations have conflicting ${reservationField}`);
    }
    if (identity[identityField] && stored.length && identity[identityField] !== stored[0]) {
      throw new Error(`one-proof payroll ${identityField} does not match the durable broadcast attempt`);
    }
    if (requireComplete && (!identity[identityField] || reservations.some(reservation =>
      text(reservation[reservationField]) !== identity[identityField]
    ))) {
      throw new Error(`one-proof payroll durable broadcast attempt is missing or mismatches exact ${reservationField}`);
    }
  }
}

/** Reserve and immediately lease-claim an exact one-proof payroll input set before proving. */
export async function prepareOneProofPayrollReservation(reservationManager, prepared, { metadata = {} } = {}) {
  const normalized = expectedPayrollEvidenceForPreparedOperation(prepared);
  const operationEvidence = buildOneProofPayrollOperationEvidence(prepared);
  const batch = await reserveOneProofPayrollOperation(reservationManager, normalized.operation, {
    metadata: payrollReservationMetadata(operationEvidence, metadata)
  });
  try {
    const reservations = await reservationManager.markProving(batch.reservation_ids, {
      leaseToken: batch.lease_token
    });
    return frozenReservationBatch(batch, reservations);
  } catch (error) {
    try {
      await reservationManager.releaseReservedOrProving(batch.reservation_ids, {
        leaseToken: batch.lease_token
      });
    } catch {
      try {
        await reservationManager.markManualReview(batch.reservation_ids, {
          error: "payroll_reservation_claim_failed",
          metadata: { reconcile_reason: "payroll_reservation_claim_failed" }
        });
      } catch {
        // Preserve the original claim failure; manual recovery remains available from the reservation store.
      }
    }
    throw error;
  }
}

function preparedFromPayrollExecution(execution) {
  if (!execution || typeof execution !== "object" || execution.version !== oneProofPayrollExecutionVersion) {
    throw new Error("proven one-proof payroll execution is required");
  }
  const prepared = {
    operation: execution.operation,
    circuit_config: execution.circuit_config,
    payload: execution.payload,
    expected_evidence: execution.operation_evidence?.expected_evidence,
    input_nullifier_hexes: execution.input_nullifier_hexes
  };
  validateOneProofPayrollOperationEvidence(execution.operation_evidence, prepared);
  const proof = normalizePreparedBatchTransferProof(execution.payload, execution.proof);
  if (execution.operation_evidence.proof_payload_hash !== proof.request_payload_hash ||
      execution.operation_evidence.proof_hash !== sha256Hex(proof.proof_bytes)) {
    throw new Error("one-proof payroll execution proof does not match its operation evidence");
  }
  return { prepared, proof };
}

/** Bind a proven one-proof payroll execution to its claimed reservations before broadcast. */
export async function markOneProofPayrollReservationProofReady(reservationManager, reservationBatch, execution, {
  signDocHash,
  sign_doc_hash,
  metadata = {}
} = {}) {
  const { prepared } = preparedFromPayrollExecution(execution);
  const reservationSet = await payrollReservationSet(reservationManager, prepared, reservationBatch);
  const evidence = execution.operation_evidence;
  const operationEvidenceHash = oneProofPayrollOperationEvidenceHash(evidence);
  const resolvedSignDocHash = consistentPayrollBroadcastIdentity(
    "sign-doc hash",
    [signDocHash, sign_doc_hash]
  );
  if (reservationStatusesAre(reservationSet.reservations, "ProofReady")) {
    if (reservationSet.reservations.some(reservation =>
      text(reservation.payload_hash) !== evidence.payload_hash ||
      text(reservation.metadata?.payroll_proof_hash) !== text(evidence.proof_hash) ||
      text(reservation.expected_operation_evidence_hash) !== operationEvidenceHash ||
      (resolvedSignDocHash && text(reservation.sign_doc_hash) !== resolvedSignDocHash) ||
      reservation.metadata?.operation_success_evidence_required !== true
    )) {
      throw new Error("one-proof payroll ProofReady reservation evidence does not match the execution");
    }
    return Object.freeze([...reservationSet.reservations]);
  }
  if (!reservationStatusesAre(reservationSet.reservations, "Proving")) {
    throwIfPayrollReservationStateMixed(reservationSet.reservations);
    throw new Error("one-proof payroll reservations must all be Proving before they become ProofReady");
  }
  return Object.freeze(await reservationManager.markProofReady(reservationSet.reservationIDs, {
    leaseToken: reservationBatch.lease_token,
    payloadHash: evidence.payload_hash,
    ...(resolvedSignDocHash ? { signDocHash: resolvedSignDocHash } : {}),
    expectedOperationEvidenceHash: operationEvidenceHash,
    operationSuccessEvidenceRequired: true,
    metadata: payrollReservationMetadata(evidence, metadata)
  }));
}

function payrollArtifactReservationIDs(reservationBatch) {
  const values = [...(reservationBatch?.reservation_ids || [])].map(value => text(value));
  if (!values.length || values.some(value => !value) || new Set(values).size !== values.length) {
    throw new Error("one-proof payroll broadcast artifact requires distinct reservation IDs");
  }
  return values;
}

function verifiedPayrollArtifactBroadcastIdentity(artifactInput, reservationBatch, execution) {
  if (!artifactInput || typeof artifactInput !== "object" || Array.isArray(artifactInput) || !text(artifactInput.artifact_hash)) {
    throw new Error("one-proof payroll broadcast attempt requires a verified signed artifact");
  }
  const artifact = normalizeOneProofPayrollArtifact(artifactInput);
  if (!artifact.execution || !artifact.reservation_batch || !artifact.sign_doc || !artifact.signed_tx_bytes) {
    throw new Error("one-proof payroll broadcast artifact must contain execution, reservation, sign-doc, and signed TxRaw checkpoints");
  }
  const expected = preparedFromPayrollExecution(execution);
  const artifactExecution = preparedFromPayrollExecution(artifact.execution);
  if (artifactExecution.prepared.operation.operation_id !== expected.prepared.operation.operation_id ||
      artifactExecution.prepared.payload.payload_hash !== expected.prepared.payload.payload_hash ||
      oneProofPayrollOperationEvidenceHash(artifact.execution.operation_evidence) !==
        oneProofPayrollOperationEvidenceHash(execution.operation_evidence)) {
    throw new Error("one-proof payroll broadcast artifact does not match the proven execution");
  }
  const expectedReservationIDs = payrollArtifactReservationIDs(reservationBatch);
  const artifactReservationIDs = payrollArtifactReservationIDs(artifact.reservation_batch);
  if (text(artifact.reservation_batch.operation_id) !== text(reservationBatch?.operation_id) ||
      text(artifact.reservation_batch.lease_token) !== text(reservationBatch?.lease_token) ||
      expectedReservationIDs.length !== artifactReservationIDs.length ||
      expectedReservationIDs.some(id => !artifactReservationIDs.includes(id))) {
    throw new Error("one-proof payroll broadcast artifact does not match the reservation batch");
  }
  return requiredPayrollCosmosBroadcastIdentity({
    txHash: artifact.tx_hash,
    txBytesHash: artifact.tx_bytes_hash,
    signDocHash: artifact.sign_doc_hash
  }, "broadcast artifact", { requireSignedBindings: true });
}

/**
 * Durably record crossing the external broadcast boundary before sending a
 * payroll transaction. The transaction identity is derived only from a
 * validated, exact-TxRaw artifact bound to this execution and reservation set.
 * An idempotent return for an already Submitted/Unknown operation validates
 * identity only; use retransmitOneProofPayrollArtifact to authorize a retry.
 */
export async function markOneProofPayrollReservationBroadcastAttempting(reservationManager, reservationBatch, execution, {
  artifact,
  reason,
  metadata = {}
} = {}) {
  if (!reservationManager || typeof reservationManager.markBroadcastAttempting !== "function") {
    throw new Error("a NoteReservationManager with broadcast-attempt support is required");
  }
  const broadcastIdentity = verifiedPayrollArtifactBroadcastIdentity(artifact, reservationBatch, execution);
  const { prepared } = preparedFromPayrollExecution(execution);
  const reservationSet = await payrollReservationSet(reservationManager, prepared, reservationBatch);
  const evidence = execution.operation_evidence;
  if (reservationSet.reservations.some(reservation => text(reservation.payload_hash) !== evidence.payload_hash)) {
    throw new Error("one-proof payroll reservations must be payload-bound before broadcast");
  }
  throwIfPayrollReservationStateMixed(reservationSet.reservations);
  assertPayrollBroadcastIdentityMatches(reservationSet.reservations, broadcastIdentity);
  const hasAttempt = reservationStatusesAre(reservationSet.reservations, "ProofReady") && reservationSet.reservations.every(reservation =>
    reservation.broadcast_in_flight === true && Number(reservation.broadcast_attempt_count || 0) >= 1
  );
  if (hasAttempt) {
    assertPayrollBroadcastIdentityMatches(reservationSet.reservations, broadcastIdentity, { requireComplete: true });
    if (typeof reservationManager.renewLease !== "function") {
      throw new Error("reservationManager.renewLease is required to validate an existing one-proof payroll broadcast attempt");
    }
    const renewed = await reservationManager.renewLease(reservationSet.reservationIDs, {
      leaseToken: reservationBatch.lease_token
    });
    assertPayrollBroadcastIdentityMatches(renewed, broadcastIdentity, { requireComplete: true });
    return Object.freeze(renewed);
  }
  if (reservationStatusesAre(reservationSet.reservations, "Submitted") ||
      reservationStatusesAre(reservationSet.reservations, "Unknown")) {
    if (reservationSet.reservations.some(reservation => Number(reservation.broadcast_attempt_count || 0) < 1)) {
      throw new Error("one-proof payroll terminal broadcast state is missing its durable attempt count");
    }
    assertPayrollBroadcastIdentityMatches(reservationSet.reservations, broadcastIdentity, { requireComplete: true });
    return Object.freeze([...reservationSet.reservations]);
  }
  if (!reservationStatusesAre(reservationSet.reservations, "ProofReady") ||
      reservationSet.reservations.some(reservation => reservation.broadcast_in_flight || Number(reservation.broadcast_attempt_count || 0) !== 0)) {
    throw new Error("one-proof payroll reservations require one clean ProofReady state before a broadcast attempt");
  }
  const attempted = await reservationManager.markBroadcastAttempting(reservationSet.reservationIDs, {
    leaseToken: reservationBatch.lease_token,
    ...broadcastIdentity,
    reason,
    metadata: payrollReservationMetadata(evidence, metadata)
  });
  assertPayrollBroadcastIdentityMatches(attempted, broadcastIdentity, { requireComplete: true });
  return Object.freeze(attempted);
}

/** Persist Submitted only when all three exact artifact marker fields match. */
export async function markOneProofPayrollReservationSubmitted(reservationManager, reservationBatch, execution, {
  tx_hash,
  txHash,
  tx_bytes_hash,
  txBytesHash,
  sign_doc_hash,
  signDocHash
} = {}) {
  if (!reservationManager || typeof reservationManager.markSubmitted !== "function") {
    throw new Error("a NoteReservationManager with submitted-state support is required");
  }
  const broadcastIdentity = requiredPayrollCosmosBroadcastIdentity(
    { tx_hash, txHash, tx_bytes_hash, txBytesHash, sign_doc_hash, signDocHash },
    "submission",
    { requireSignedBindings: true }
  );
  const { prepared } = preparedFromPayrollExecution(execution);
  const reservationSet = await payrollReservationSet(reservationManager, prepared, reservationBatch);
  const evidence = execution.operation_evidence;
  assertPayrollBroadcastIdentityMatches(reservationSet.reservations, broadcastIdentity, { requireComplete: true });
  if (reservationStatusesAre(reservationSet.reservations, "Submitted")) {
    if (reservationSet.reservations.some(reservation => Number(reservation.broadcast_attempt_count || 0) < 1)) {
      throw new Error("one-proof payroll Submitted state is missing its durable broadcast attempt");
    }
    return Object.freeze([...reservationSet.reservations]);
  }
  if (!reservationStatusesAre(reservationSet.reservations, "ProofReady") ||
      reservationSet.reservations.some(reservation =>
        text(reservation.payload_hash) !== evidence.payload_hash ||
        reservation.broadcast_in_flight !== true ||
        Number(reservation.broadcast_attempt_count || 0) < 1
      )) {
    throwIfPayrollReservationStateMixed(reservationSet.reservations);
    throw new Error("one-proof payroll reservations need a durable payload-bound broadcast attempt before submission");
  }
  const submitted = await reservationManager.markSubmitted(reservationSet.reservationIDs, {
    leaseToken: reservationBatch.lease_token,
    ...broadcastIdentity
  });
  assertPayrollBroadcastIdentityMatches(submitted, broadcastIdentity, { requireComplete: true });
  return Object.freeze(submitted);
}

/** Invoke exactly one explicitly selected one-proof prover; no automatic prover failover is performed. */
export async function proveOneProofPayrollOperation(payload, prover, { nowUnix } = {}) {
  if (!prover || typeof prover.proveBatchTransfer !== "function") throw new Error("one explicit proveBatchTransfer adapter is required");
  validatePreparedBatchTransferPayloadEnvelope(payload, nowUnix == null ? {} : { nowUnix });
  const response = await prover.proveBatchTransfer(payload);
  const proof = response?.proof && typeof response.proof === "object" ? response.proof : response;
  return normalizePreparedBatchTransferProof(payload, proof, nowUnix == null ? {} : { nowUnix });
}

function sameEvidence(expected, actual) {
  const fields = [
    "operation_id", "item_id", "employee_id", "batch_item_index", "role",
    "expected_output_commitment", "expected_user_disclosure_digest",
    "expected_audit_disclosure_digest", "expected_self_view_disclosure_digest",
    "expected_recipient_hash", "expected_amount_hash", "expected_denom",
    "asset_id_hex", "user_privacy_policy", "user_disclosure_mode",
    "audit_key_id", "audit_key_epoch"
  ];
  return fields.every(field => String(expected?.[field] ?? "") === String(actual?.[field] ?? ""));
}

function expectedPayrollEvidenceForPreparedOperation(prepared, { nowUnix } = {}) {
  if (!prepared || typeof prepared !== "object") throw new Error("prepared one-proof payroll operation is required");
  const operation = prepared.operation;
  const payload = prepared.payload;
  if (!operation || !payload) throw new Error("prepared one-proof payroll operation requires operation and payload");
  const circuitConfig = validateCircuitConfigV1(prepared.circuit_config);
  validatePreparedBatchTransferPayloadEnvelope(payload, nowUnix == null ? {} : { nowUnix });
  if (operation.circuit_set_id !== oneProofPayrollCircuitSetId || payload.circuit_set_id !== oneProofPayrollCircuitSetId) {
    throw new Error("prepared one-proof payroll operation circuit identity is invalid");
  }
  if (!text(operation.operation_id)) throw new Error("prepared one-proof payroll operation ID is required");
  const expected = buildExpectedPayrollEvidence(operation, payload, nowUnix == null ? {} : { now_unix: nowUnix });
  if (!Array.isArray(prepared.expected_evidence) || prepared.expected_evidence.length !== expected.length ||
      expected.some((entry, index) => !sameEvidence(entry, prepared.expected_evidence[index]))) {
    throw new Error("prepared one-proof payroll expected evidence does not match the final payload");
  }
  const effects = preparedBatchTransferEffectHex(payload);
  if (prepared.input_nullifier_hexes !== undefined && (
    !Array.isArray(prepared.input_nullifier_hexes) ||
    prepared.input_nullifier_hexes.length !== effects.nullifier_hexes.length ||
    prepared.input_nullifier_hexes.some((value, index) => canonicalDigest(value, "prepared input nullifier") !== effects.nullifier_hexes[index])
  )) {
    throw new Error("prepared one-proof payroll input nullifiers do not match the final payload");
  }
  return { operation, payload, expected, effects, circuitConfig };
}

/**
 * Materialize the non-secret evidence that binds one payroll operation to its
 * signed batch payload. This is safe to persist only with the product's normal
 * handling for employee IDs and recipient/amount hashes; it never contains a
 * prover witness or an unencrypted note secret.
 */
export function buildOneProofPayrollOperationEvidence(prepared, { proof, nowUnix } = {}) {
  const normalized = expectedPayrollEvidenceForPreparedOperation(prepared, { nowUnix });
  let normalizedProof = null;
  if (proof !== undefined && proof !== null) {
    normalizedProof = normalizePreparedBatchTransferProof(normalized.payload, proof, nowUnix == null ? {} : { nowUnix });
  }
  const evidence = {
    version: oneProofPayrollOperationEvidenceVersion,
    operation_id: normalized.operation.operation_id,
    circuit_set_id: oneProofPayrollCircuitSetId,
    payload_hash: normalized.payload.payload_hash,
    input_nullifier_hexes: Object.freeze([...normalized.effects.nullifier_hexes]),
    expected_evidence: Object.freeze(normalized.expected.map(item => Object.freeze({ ...item }))),
    ...(normalizedProof ? {
      proof_payload_hash: normalizedProof.request_payload_hash,
      proof_hash: sha256Hex(normalizedProof.proof_bytes)
    } : {})
  };
  return Object.freeze(evidence);
}

/**
 * Stable digest for the complete one-proof payroll success predicate. It pins
 * every expected payment output to the exact signed payload so all input-note
 * reservations can share one operation-level reconciliation predicate.
 */
export function oneProofPayrollOperationEvidenceHash(evidence) {
  if (!evidence || typeof evidence !== "object" || evidence.version !== oneProofPayrollOperationEvidenceVersion) {
    throw new Error("one-proof payroll operation evidence is required for its reconciliation hash");
  }
  const operationID = text(evidence.operation_id);
  if (!operationID || evidence.circuit_set_id !== oneProofPayrollCircuitSetId) {
    throw new Error("one-proof payroll operation evidence identity is invalid for its reconciliation hash");
  }
  const inputNullifiers = evidence.input_nullifier_hexes;
  const expected = evidence.expected_evidence;
  if (!Array.isArray(inputNullifiers) || !inputNullifiers.length || !Array.isArray(expected) || !expected.length) {
    throw new Error("one-proof payroll operation evidence inputs and outputs are required for its reconciliation hash");
  }
  if ((evidence.proof_payload_hash === undefined) !== (evidence.proof_hash === undefined)) {
    throw new Error("one-proof payroll operation evidence proof hash pair is incomplete");
  }
  const canonical = {
    version: oneProofPayrollOperationEvidenceVersion,
    operation_id: operationID,
    circuit_set_id: oneProofPayrollCircuitSetId,
    payload_hash: canonicalDigest(evidence.payload_hash, "one-proof payroll evidence payload hash"),
    input_nullifier_hexes: inputNullifiers.map(value => canonicalDigest(value, "one-proof payroll evidence nullifier")),
    expected_evidence: expected.map((item, index) => {
      if (!item || typeof item !== "object") throw new Error(`one-proof payroll expected evidence ${index} is invalid`);
      const batchItemIndex = Number(item.batch_item_index);
      if (!Number.isSafeInteger(batchItemIndex) || batchItemIndex < 0) {
        throw new Error(`one-proof payroll expected evidence ${index} batch item index is invalid`);
      }
      return {
        operation_id: text(item.operation_id),
        item_id: text(item.item_id),
        employee_id: text(item.employee_id),
        batch_item_index: batchItemIndex,
        role: text(item.role),
        expected_output_commitment: canonicalDigest(item.expected_output_commitment, `one-proof payroll expected evidence ${index} commitment`),
        expected_user_disclosure_digest: canonicalDigest(item.expected_user_disclosure_digest, `one-proof payroll expected evidence ${index} user disclosure digest`),
        expected_audit_disclosure_digest: canonicalDigest(item.expected_audit_disclosure_digest, `one-proof payroll expected evidence ${index} audit disclosure digest`),
        expected_self_view_disclosure_digest: canonicalDigest(item.expected_self_view_disclosure_digest, `one-proof payroll expected evidence ${index} self-view disclosure digest`),
        expected_recipient_hash: canonicalDigest(item.expected_recipient_hash, `one-proof payroll expected evidence ${index} recipient hash`),
        expected_amount_hash: canonicalDigest(item.expected_amount_hash, `one-proof payroll expected evidence ${index} amount hash`),
        expected_denom: text(item.expected_denom),
        asset_id_hex: canonicalDigest(item.asset_id_hex, `one-proof payroll expected evidence ${index} asset ID`),
        user_privacy_policy: Number(item.user_privacy_policy),
        user_disclosure_mode: Number(item.user_disclosure_mode),
        audit_key_id: text(item.audit_key_id),
        audit_key_epoch: canonicalUint64(item.audit_key_epoch, `one-proof payroll expected evidence ${index} audit key epoch`, { positive: true }).toString()
      };
    }),
    ...(evidence.proof_payload_hash === undefined ? {} : {
      proof_payload_hash: canonicalDigest(evidence.proof_payload_hash, "one-proof payroll evidence proof payload hash"),
      proof_hash: canonicalDigest(evidence.proof_hash, "one-proof payroll evidence proof hash")
    })
  };
  const expectedIndexes = new Set(canonical.expected_evidence.map(item => item.batch_item_index));
  if (!canonical.payload_hash || expectedIndexes.size !== canonical.expected_evidence.length || canonical.expected_evidence.some(item =>
    item.operation_id !== operationID || !item.item_id || item.role !== "payment" ||
    !item.expected_output_commitment || !item.expected_audit_disclosure_digest ||
    !item.expected_recipient_hash || !item.expected_amount_hash || !item.expected_denom ||
    !item.asset_id_hex || !Number.isSafeInteger(item.user_privacy_policy) ||
    !Number.isSafeInteger(item.user_disclosure_mode) || !item.audit_key_id ||
    !/^[1-9][0-9]*$/.test(item.audit_key_epoch)
  )) {
    throw new Error("one-proof payroll operation evidence is incomplete for its reconciliation hash");
  }
  return sha256Hex(utf8Bytes(JSON.stringify(canonical)));
}

function artifactJSONValue(value, ancestors = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("one-proof payroll artifact cannot contain a non-finite number");
    return value;
  }
  if (typeof value === "bigint") return { $clairveil_artifact_type: "bigint", decimal: value.toString() };
  if (value instanceof Uint8Array) return { $clairveil_artifact_type: "bytes", base64: base64FromBytes(value) };
  if (ArrayBuffer.isView(value)) {
    return { $clairveil_artifact_type: "bytes", base64: base64FromBytes(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)) };
  }
  if (value instanceof ArrayBuffer) return { $clairveil_artifact_type: "bytes", base64: base64FromBytes(new Uint8Array(value)) };
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new Error("one-proof payroll artifact cannot contain a cycle");
    ancestors.add(value);
    const result = value.map(item => artifactJSONValue(item, ancestors));
    ancestors.delete(value);
    return result;
  }
  if (!value || typeof value !== "object") throw new Error("one-proof payroll artifact contains an unsupported value");
  if (ancestors.has(value)) throw new Error("one-proof payroll artifact cannot contain a cycle");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new Error("one-proof payroll artifact contains a non-plain object");
  ancestors.add(value);
  const result = {};
  for (const key of Object.keys(value).sort()) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") {
      throw new Error("one-proof payroll artifact contains a forbidden object key");
    }
    if (value[key] !== undefined) result[key] = artifactJSONValue(value[key], ancestors);
  }
  ancestors.delete(value);
  return result;
}

function artifactValueFromJSON(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") return value;
  if (Array.isArray(value)) return value.map(artifactValueFromJSON);
  if (!value || typeof value !== "object") throw new Error("one-proof payroll artifact JSON contains an unsupported value");
  const type = value.$clairveil_artifact_type;
  if (type !== undefined) {
    if (type === "bigint" && Object.keys(value).length === 2 && /^(0|[1-9][0-9]*)$/.test(String(value.decimal ?? ""))) {
      return BigInt(value.decimal);
    }
    if (type === "bytes" && Object.keys(value).length === 2 && typeof value.base64 === "string") {
      const bytes = bytesFromBase64(value.base64, "one-proof payroll artifact bytes");
      if (base64FromBytes(bytes) === value.base64) return bytes;
    }
    throw new Error("one-proof payroll artifact JSON contains an invalid typed value");
  }
  const result = {};
  for (const key of Object.keys(value)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") {
      throw new Error("one-proof payroll artifact JSON contains a forbidden object key");
    }
    result[key] = artifactValueFromJSON(value[key]);
  }
  return result;
}

function canonicalArtifactJSON(value) {
  return JSON.stringify(artifactJSONValue(value));
}

function cloneArtifactValue(value) {
  return artifactValueFromJSON(JSON.parse(canonicalArtifactJSON(value)));
}

function canonicalArtifactDigest(value, label) {
  return canonicalDigest(value, label);
}

function artifactContentHash(contents) {
  return sha256Hex(utf8Bytes(canonicalArtifactJSON(contents)));
}

function artifactOptionalText(value, label) {
  const normalized = text(value);
  if (normalized && typeof value !== "string") throw new Error(`one-proof payroll artifact ${label} must be a string`);
  return normalized;
}

function artifactDigestInputAlias(input, snakeKey, camelKey, label) {
  const values = [input?.[snakeKey], input?.[camelKey]]
    .filter(value => value !== undefined && value !== null);
  const normalized = values.map(value => {
    if (typeof value !== "string") {
      throw new Error(`one-proof payroll artifact ${label} must be a string`);
    }
    return canonicalArtifactDigest(value, `one-proof payroll artifact ${label}`);
  });
  if (new Set(normalized).size > 1) {
    throw new Error(`one-proof payroll artifact ${label} aliases must match`);
  }
  return normalized[0] || "";
}

function artifactSignedTransactionBytes(value) {
  if (value === undefined || value === null) return null;
  if (value instanceof Uint8Array) return Uint8Array.from(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
  if (value instanceof ArrayBuffer) return new Uint8Array(value).slice();
  throw new Error("one-proof payroll artifact signed transaction must be bytes");
}

function artifactBytesEqual(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array) || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function artifactSignDocBytes(signDoc, field, label) {
  if (!signDoc || typeof signDoc !== "object" || Array.isArray(signDoc)) {
    throw new Error("one-proof payroll artifact sign-doc must be a Cosmos direct sign-doc");
  }
  const encoded = signDoc[field];
  if (typeof encoded !== "string" || !encoded) {
    throw new Error(`one-proof payroll artifact sign-doc ${label} is required`);
  }
  const decoded = bytesFromBase64(encoded, `one-proof payroll artifact sign-doc ${label}`);
  if (!decoded.length || base64FromBytes(decoded) !== encoded) {
    throw new Error(`one-proof payroll artifact sign-doc ${label} must be canonical non-empty base64`);
  }
  return decoded;
}

function payrollDirectSignerPublicKey(authInfo, creator) {
  const signerInfo = authInfo?.signerInfos?.[0];
  if (signerInfo?.modeInfo?.single?.mode !== SignMode.SIGN_MODE_DIRECT) {
    throw new Error("one-proof payroll artifact signer must use Cosmos SIGN_MODE_DIRECT");
  }
  const encodedPublicKey = signerInfo.publicKey;
  if (!encodedPublicKey || encodedPublicKey.typeUrl !== Secp256k1PubKey.typeUrl || !encodedPublicKey.value?.length) {
    throw new Error("one-proof payroll artifact signer must contain one Cosmos secp256k1 public key");
  }
  let publicKey;
  try {
    const decoded = Secp256k1PubKey.decode(encodedPublicKey.value);
    if (!artifactBytesEqual(Secp256k1PubKey.encode(decoded).finish(), encodedPublicKey.value)) {
      throw new Error("public key protobuf is not canonical");
    }
    publicKey = Secp256k1.compressPubkey(decoded.key);
    if (!artifactBytesEqual(publicKey, decoded.key)) {
      throw new Error("public key must use compressed encoding");
    }
  } catch (error) {
    throw new Error(`one-proof payroll artifact signer public key is invalid: ${error.message}`);
  }
  try {
    const decodedCreator = fromBech32(creator);
    if (toBech32(decodedCreator.prefix, decodedCreator.data) !== creator) {
      throw new Error("creator address is not canonical");
    }
    if (toBech32(decodedCreator.prefix, hash160(publicKey)) !== creator) {
      throw new Error("public key does not identify the message creator");
    }
  } catch (error) {
    throw new Error(`one-proof payroll artifact signer does not match its message creator: ${error.message}`);
  }
  return publicKey;
}

function validatePayrollCosmosSignDoc(signDoc, execution) {
  const bodyBytes = artifactSignDocBytes(signDoc, "bodyBytes", "bodyBytes");
  const authInfoBytes = artifactSignDocBytes(signDoc, "authInfoBytes", "authInfoBytes");
  if (typeof signDoc.chainId !== "string" || !signDoc.chainId || signDoc.chainId !== signDoc.chainId.trim()) {
    throw new Error("one-proof payroll artifact sign-doc chainId must be a canonical non-empty string");
  }
  const executionChainID = execution?.payload?.chain_id;
  if (typeof executionChainID !== "string" || !executionChainID || executionChainID !== executionChainID.trim()) {
    throw new Error("one-proof payroll artifact execution chain_id must be a canonical non-empty string");
  }
  if (signDoc.chainId !== executionChainID) {
    throw new Error("one-proof payroll artifact sign-doc chainId does not match its proven execution");
  }
  const accountNumber = canonicalUint64(signDoc.accountNumber, "one-proof payroll artifact sign-doc accountNumber");

  let body;
  let authInfo;
  try {
    body = TxBody.decode(bodyBytes);
    authInfo = AuthInfo.decode(authInfoBytes);
  } catch (error) {
    throw new Error(`one-proof payroll artifact sign-doc contains invalid Cosmos protobuf: ${error.message}`);
  }
  if (!artifactBytesEqual(TxBody.encode(body).finish(), bodyBytes) ||
      !artifactBytesEqual(AuthInfo.encode(authInfo).finish(), authInfoBytes)) {
    throw new Error("one-proof payroll artifact sign-doc must use canonical Cosmos protobuf bytes");
  }
  if (body.messages.length !== 1 || body.messages[0].typeUrl !== GeneratedMsgBatchTransfer.typeUrl) {
    throw new Error("one-proof payroll artifact sign-doc must contain exactly one MsgBatchTransfer");
  }
  if (authInfo.signerInfos.length !== 1) {
    throw new Error("one-proof payroll artifact sign-doc must contain exactly one Cosmos signer");
  }

  const creator = text(execution?.message?.creator);
  if (!creator) throw new Error("one-proof payroll artifact execution message creator is required");
  const signerPublicKey = payrollDirectSignerPublicKey(authInfo, creator);
  let expectedMessageBytes;
  let executionMessageBytes;
  try {
    const expectedMessage = buildMsgBatchTransferFromPrepared(execution.payload, execution.proof, {
      creator,
      // Artifact recovery still has to validate an expired checkpoint. The
      // payload's signed expiry remains part of the reconstructed message.
      nowUnix: 0
    });
    expectedMessageBytes = GeneratedMsgBatchTransfer.encode(
      GeneratedMsgBatchTransfer.fromPartial(expectedMessage)
    ).finish();
    executionMessageBytes = GeneratedMsgBatchTransfer.encode(
      GeneratedMsgBatchTransfer.fromPartial(execution.message)
    ).finish();
  } catch (error) {
    throw new Error(`one-proof payroll artifact execution cannot reconstruct MsgBatchTransfer: ${error.message}`);
  }
  if (!artifactBytesEqual(executionMessageBytes, expectedMessageBytes)) {
    throw new Error("one-proof payroll artifact execution message does not match its payload and proof");
  }
  if (!artifactBytesEqual(body.messages[0].value, expectedMessageBytes)) {
    throw new Error("one-proof payroll artifact sign-doc does not match its proven execution");
  }

  const unsignedTxRaw = TxRaw.fromPartial({ bodyBytes, authInfoBytes, signatures: [] });
  return {
    bodyBytes,
    authInfoBytes,
    chainId: signDoc.chainId,
    accountNumber,
    signerPublicKey,
    signDocHash: sha256Hex(TxRaw.encode(unsignedTxRaw).finish())
  };
}

function validatePayrollSignedTxRaw(signedTxBytes, signDocBinding) {
  if (!(signedTxBytes instanceof Uint8Array) || !signedTxBytes.length) {
    throw new Error("one-proof payroll artifact signed transaction must be a non-empty Cosmos TxRaw");
  }
  let txRaw;
  try {
    txRaw = TxRaw.decode(signedTxBytes);
  } catch (error) {
    throw new Error(`one-proof payroll artifact signed transaction is not a valid Cosmos TxRaw: ${error.message}`);
  }
  if (!artifactBytesEqual(TxRaw.encode(txRaw).finish(), signedTxBytes)) {
    throw new Error("one-proof payroll artifact signed transaction must use canonical Cosmos TxRaw bytes");
  }
  if (!txRaw.bodyBytes.length || !txRaw.authInfoBytes.length ||
      txRaw.signatures.length !== 1 || txRaw.signatures[0].length !== 64) {
    throw new Error("one-proof payroll artifact signed transaction must contain one 64-byte Cosmos secp256k1 signature");
  }
  if (!artifactBytesEqual(txRaw.bodyBytes, signDocBinding.bodyBytes) ||
      !artifactBytesEqual(txRaw.authInfoBytes, signDocBinding.authInfoBytes)) {
    throw new Error("one-proof payroll artifact signed TxRaw does not match its sign-doc bodyBytes/authInfoBytes");
  }
  try {
    const signature = Secp256k1Signature.fromFixedLength(txRaw.signatures[0]);
    const signBytes = SignDoc.encode(SignDoc.fromPartial({
      bodyBytes: signDocBinding.bodyBytes,
      authInfoBytes: signDocBinding.authInfoBytes,
      chainId: signDocBinding.chainId,
      accountNumber: signDocBinding.accountNumber
    })).finish();
    if (!Secp256k1.verifySignature(signature, sha256(signBytes), signDocBinding.signerPublicKey)) {
      throw new Error("signature verification failed");
    }
  } catch (error) {
    throw new Error(`one-proof payroll artifact signed transaction signature is invalid: ${error.message}`);
  }
  return txRaw;
}

function normalizeOneProofPayrollArtifact(artifact, { nowUnix, allowExpired = false } = {}) {
  if (!artifact || typeof artifact !== "object" || Array.isArray(artifact)) throw new Error("one-proof payroll artifact is required");
  if (artifact.version !== oneProofPayrollArtifactVersion) {
    throw new Error(`unsupported one-proof payroll artifact version ${JSON.stringify(artifact.version)}`);
  }
  const prepared = cloneArtifactValue(artifact.prepared);
  const validationOptions = allowExpired ? { nowUnix: 0 } : nowUnix == null ? {} : { nowUnix };
  const preparedNormalized = expectedPayrollEvidenceForPreparedOperation(prepared, validationOptions);
  const execution = artifact.execution == null ? null : cloneArtifactValue(artifact.execution);
  if (execution) {
    const executionPrepared = preparedFromPayrollExecution(execution).prepared;
    validateOneProofPayrollOperationEvidence(execution.operation_evidence, prepared, validationOptions);
    if (executionPrepared.payload.payload_hash !== preparedNormalized.payload.payload_hash ||
        executionPrepared.operation.operation_id !== preparedNormalized.operation.operation_id ||
        !text(execution.message?.creator)) {
      throw new Error("one-proof payroll artifact execution does not match its prepared operation");
    }
  }
  const reservationBatch = artifact.reservation_batch == null ? null : cloneArtifactValue(artifact.reservation_batch);
  const signDoc = artifact.sign_doc == null ? null : cloneArtifactValue(artifact.sign_doc);
  const signedTxBytes = artifact.signed_tx_bytes == null ? null : artifactSignedTransactionBytes(artifact.signed_tx_bytes);
  const suppliedTxHash = artifactOptionalText(artifact.tx_hash, "transaction hash");
  const suppliedTxBytesHash = artifactOptionalText(artifact.tx_bytes_hash, "transaction bytes hash");
  const suppliedSignDocHash = artifactOptionalText(artifact.sign_doc_hash, "sign-doc hash");
  if (suppliedTxBytesHash) canonicalArtifactDigest(suppliedTxBytesHash, "one-proof payroll artifact transaction bytes hash");
  if (suppliedSignDocHash) canonicalArtifactDigest(suppliedSignDocHash, "one-proof payroll artifact sign-doc hash");
  if (signDoc && !execution) throw new Error("one-proof payroll artifact sign-doc requires a proven execution");
  if (signedTxBytes && (!execution || !signDoc)) {
    throw new Error("one-proof payroll artifact signed transaction requires a proven execution and sign-doc");
  }
  if (suppliedTxHash && !signedTxBytes) throw new Error("one-proof payroll artifact transaction hash requires exact signed transaction bytes");
  if (suppliedTxBytesHash && !signedTxBytes) {
    throw new Error("one-proof payroll artifact transaction bytes hash requires exact signed transaction bytes");
  }
  if (suppliedSignDocHash && !signDoc) throw new Error("one-proof payroll artifact sign-doc hash requires a sign-doc");
  const signDocBinding = signDoc ? validatePayrollCosmosSignDoc(signDoc, execution) : null;
  if (signedTxBytes) validatePayrollSignedTxRaw(signedTxBytes, signDocBinding);
  const txBytesHash = signedTxBytes ? sha256Hex(signedTxBytes) : suppliedTxBytesHash.toLowerCase();
  const txHash = signedTxBytes ? txBytesHash.toUpperCase() : "";
  if (suppliedTxHash) {
    const normalizedSuppliedTxHash = canonicalArtifactDigest(
      suppliedTxHash,
      "one-proof payroll artifact transaction hash"
    ).toUpperCase();
    if (normalizedSuppliedTxHash !== txHash) {
      throw new Error("one-proof payroll artifact signed transaction bytes do not match tx_hash");
    }
  }
  if (signedTxBytes && suppliedTxBytesHash && suppliedTxBytesHash.toLowerCase() !== txBytesHash) {
    throw new Error("one-proof payroll artifact signed transaction bytes do not match tx_bytes_hash");
  }
  const signDocHash = signDocBinding?.signDocHash || "";
  if (signDoc && suppliedSignDocHash && suppliedSignDocHash.toLowerCase() !== signDocHash) {
    throw new Error("one-proof payroll artifact sign-doc does not match sign_doc_hash");
  }
  const contents = {
    version: oneProofPayrollArtifactVersion,
    prepared,
    execution,
    reservation_batch: reservationBatch,
    sign_doc: signDoc,
    signed_tx_bytes: signedTxBytes,
    tx_hash: txHash,
    tx_bytes_hash: txBytesHash,
    sign_doc_hash: signDocHash.toLowerCase(),
    tx_result: artifact.tx_result == null ? null : cloneArtifactValue(artifact.tx_result)
  };
  const artifactHash = artifactOptionalText(artifact.artifact_hash, "integrity hash").toLowerCase();
  if (artifactHash && canonicalArtifactDigest(artifactHash, "one-proof payroll artifact integrity hash") !== artifactContentHash(contents)) {
    throw new Error("one-proof payroll artifact integrity hash does not match its contents");
  }
  return Object.freeze({ ...contents, artifact_hash: artifactContentHash(contents) });
}

/**
 * Create a private-at-rest checkpoint for a prepared/proven one-proof payroll
 * operation. Persist the result through an encrypted private store (0600 when
 * using a local file); it includes notes, reservation lease material, and
 * optionally the exact already-signed transaction bytes.
 */
export function createOneProofPayrollArtifact(input = {}) {
  if (!input || typeof input !== "object") throw new Error("one-proof payroll artifact input is required");
  const txHash = artifactDigestInputAlias(input, "tx_hash", "txHash", "transaction hash");
  const txBytesHash = artifactDigestInputAlias(input, "tx_bytes_hash", "txBytesHash", "transaction bytes hash");
  const signDocHash = artifactDigestInputAlias(input, "sign_doc_hash", "signDocHash", "sign-doc hash");
  const provisional = {
    version: oneProofPayrollArtifactVersion,
    prepared: input.prepared,
    execution: input.execution ?? null,
    reservation_batch: input.reservation_batch ?? input.reservationBatch ?? null,
    sign_doc: input.sign_doc ?? input.signDoc ?? null,
    signed_tx_bytes: input.signed_tx_bytes ?? input.signedTxBytes ?? null,
    tx_hash: txHash,
    tx_bytes_hash: txBytesHash,
    sign_doc_hash: signDocHash,
    tx_result: input.tx_result ?? input.txResult ?? null
  };
  return normalizeOneProofPayrollArtifact(provisional);
}

/** Serialize a verified artifact to deterministic typed JSON for private durable storage. */
export function serializeOneProofPayrollArtifact(artifact) {
  return canonicalArtifactJSON(normalizeOneProofPayrollArtifact(artifact, { allowExpired: true }));
}

/** Parse and validate a versioned private artifact restored from durable storage. */
export function parseOneProofPayrollArtifact(serialized, { nowUnix } = {}) {
  if (typeof serialized !== "string" || !serialized.trim()) throw new Error("serialized one-proof payroll artifact is required");
  let decoded;
  try {
    decoded = artifactValueFromJSON(JSON.parse(serialized));
  } catch (error) {
    throw new Error(`serialized one-proof payroll artifact is invalid: ${error.message}`);
  }
  if (!decoded || typeof decoded !== "object" || typeof decoded.artifact_hash !== "string" || !decoded.artifact_hash.trim()) {
    throw new Error("serialized one-proof payroll artifact is missing its integrity hash");
  }
  return normalizeOneProofPayrollArtifact(decoded, { nowUnix, allowExpired: true });
}

/**
 * Recover the next safe action after a process restart. Supply the latest
 * chain time when a retry must reject an expired prepared payload.
 */
export function resumeOneProofPayrollArtifact(value, { nowUnix } = {}) {
  if (typeof value !== "string" && (!value || typeof value !== "object" || typeof value.artifact_hash !== "string" || !value.artifact_hash.trim())) {
    throw new Error("one-proof payroll artifact is missing its integrity hash");
  }
  const artifact = typeof value === "string"
    ? parseOneProofPayrollArtifact(value, { nowUnix })
    : normalizeOneProofPayrollArtifact(value, { nowUnix, allowExpired: true });
  const resolvedNowUnix = nowUnix ?? Math.floor(Date.now() / 1000);
  const isExpired = Number(artifact.prepared.payload.expires_at_unix) <= resolvedNowUnix;
  const nextAction = isExpired ? "manual-review"
    : artifact.signed_tx_bytes ? "retransmit-signed-transaction"
    : artifact.execution ? (artifact.sign_doc ? "sign-transaction" : "create-sign-doc")
      : "prove";
  return Object.freeze({
    artifact,
    prepared: artifact.prepared,
    ...(artifact.execution ? { execution: artifact.execution } : {}),
    ...(artifact.reservation_batch ? { reservation_batch: artifact.reservation_batch } : {}),
    ...(artifact.sign_doc ? { sign_doc: artifact.sign_doc } : {}),
    ...(artifact.signed_tx_bytes ? { signed_tx_bytes: Uint8Array.from(artifact.signed_tx_bytes) } : {}),
    next_action: nextAction
  });
}

function normalizedPayrollRetryTransactionState(value) {
  const candidate = typeof value === "string" ? value : value?.state ?? value?.status;
  const state = text(candidate).toLowerCase().replaceAll("_", "-");
  if (state === "succeeded" || state === "success") return "succeeded";
  if (state === "failed" || state === "failure") return "failed";
  if (state === "not-found" || state === "notfound" || state === "absent") return "not-found";
  throw new Error("one-proof payroll transaction query must return succeeded, failed, or not-found");
}

/**
 * Query transaction identity before input nullifiers, then decide whether an
 * exact signed transaction is safe to retransmit. A timeout is not evidence
 * that a broadcast failed: spent or incomplete nullifier evidence always
 * remains a manual-review outcome.
 */
export async function inspectOneProofPayrollArtifactRetry(value, {
  queryTransaction,
  checkNullifiers,
  nowUnix
} = {}) {
  if (typeof checkNullifiers !== "function") {
    throw new Error("a batch nullifier status reader is required before one-proof payroll retry");
  }
  const resolvedNowUnix = nowUnix ?? Math.floor(Date.now() / 1000);
  const resumed = resumeOneProofPayrollArtifact(value, { nowUnix: resolvedNowUnix });
  const artifact = resumed.artifact;
  const prepared = expectedPayrollEvidenceForPreparedOperation(artifact.prepared, { nowUnix: 0 });
  const isExpired = Number(prepared.payload.expires_at_unix) <= resolvedNowUnix;
  let transactionState = "not-checked";
  if (artifact.tx_hash) {
    if (typeof queryTransaction !== "function") {
      throw new Error("a transaction query callback is required when a one-proof payroll artifact has a transaction hash");
    }
    transactionState = normalizedPayrollRetryTransactionState(await queryTransaction(artifact.tx_hash, {
      artifact,
      tx_bytes_hash: artifact.tx_bytes_hash,
      sign_doc_hash: artifact.sign_doc_hash
    }));
  }
  const inputNullifiers = normalizedNullifierStatuses(
    prepared.effects.nullifier_hexes,
    await checkNullifiers([...prepared.effects.nullifier_hexes])
  );
  const anySpent = inputNullifiers.some(entry => entry.spent);
  const allSpent = inputNullifiers.every(entry => entry.spent);
  let nextAction;
  let reason;
  if (transactionState === "succeeded") {
    if (!allSpent) {
      nextAction = "manual-review";
      reason = "successful transaction has incomplete input nullifier evidence";
    } else {
      nextAction = "reconcile-succeeded";
      reason = "transaction is confirmed and every input nullifier is spent";
    }
  } else if (transactionState === "failed") {
    nextAction = "manual-review";
    reason = anySpent
      ? "failed transaction has spent input nullifier evidence"
      : "failed transaction cannot be retried with its exact signed bytes";
  } else if (anySpent) {
    nextAction = "manual-review";
    reason = "input nullifier is spent without a confirmed successful transaction";
  } else if (isExpired) {
    nextAction = "manual-review";
    reason = "prepared payload expired before an unobserved transaction could be retransmitted";
  } else if (resumed.signed_tx_bytes) {
    nextAction = "retransmit-signed-transaction";
    reason = "transaction is absent and every input nullifier is explicitly unspent";
  } else {
    nextAction = resumed.next_action;
    reason = "every input nullifier is explicitly unspent";
  }
  const result = {
    artifact,
    transaction_state: transactionState,
    input_nullifiers: Object.freeze(inputNullifiers),
    next_action: nextAction,
    reason
  };
  if (nextAction === "retransmit-signed-transaction") {
    const issuedAtWallClockMs = Date.now();
    const expiresAtUnix = Math.min(
      Number(prepared.payload.expires_at_unix),
      resolvedNowUnix + oneProofPayrollRetryDecisionTTLSeconds
    );
    const retryDecision = Object.freeze({
      version: oneProofPayrollRetryDecisionVersion,
      artifact_hash: artifact.artifact_hash,
      tx_hash: artifact.tx_hash,
      tx_bytes_hash: artifact.tx_bytes_hash,
      issued_at_unix: resolvedNowUnix,
      expires_at_unix: expiresAtUnix
    });
    oneProofPayrollRetryDecisionBindings.set(retryDecision, Object.freeze({
      artifactHash: artifact.artifact_hash,
      txHash: artifact.tx_hash,
      txBytesHash: artifact.tx_bytes_hash,
      issuedAtUnix: resolvedNowUnix,
      expiresAtUnix,
      issuedAtWallClockMs,
      expiresAtWallClockMs: issuedAtWallClockMs + Math.max(0, expiresAtUnix - resolvedNowUnix) * 1000
    }));
    result.retry_decision = retryDecision;
  }
  return Object.freeze(result);
}

function oneProofPayrollRetryDecisionInput(input = {}) {
  const camel = input.retryDecision;
  const snake = input.retry_decision;
  if (camel !== undefined && snake !== undefined && camel !== snake) {
    throw new Error("one-proof payroll retry decision aliases must identify the same decision");
  }
  return camel ?? snake;
}

function payrollBroadcastError(error, identity, {
  bookkeepingError,
  message = "one-proof payroll signed transaction outcome requires reconciliation"
} = {}) {
  const original = error && typeof error === "object" ? error : new Error(String(error || message));
  let target = original;
  try {
    target.txHash = identity.txHash;
    target.txBytesHash = identity.txBytesHash;
    target.signDocHash = identity.signDocHash;
    target.reservationReconciliationRequired = true;
    if (bookkeepingError) target.reservationBookkeepingError = bookkeepingError;
  } catch {
    target = new Error(String(original?.message || message), { cause: original });
    target.txHash = identity.txHash;
    target.txBytesHash = identity.txBytesHash;
    target.signDocHash = identity.signDocHash;
    target.reservationReconciliationRequired = true;
    if (bookkeepingError) target.reservationBookkeepingError = bookkeepingError;
  }
  return target;
}

function payrollBroadcastStatus(reservations) {
  throwIfPayrollReservationStateMixed(reservations);
  return text(reservations[0]?.status);
}

async function authoritativePayrollBroadcastSet(reservationManager, artifact, identity, {
  requireCompleteIdentity = true
} = {}) {
  const reservationSet = await payrollReservationSet(
    reservationManager,
    artifact.prepared,
    artifact.reservation_batch
  );
  assertPayrollBroadcastIdentityMatches(reservationSet.reservations, identity, {
    requireComplete: requireCompleteIdentity
  });
  return reservationSet;
}

async function recordPayrollBroadcastUnknown(reservationManager, artifact, identity, error) {
  const reservationSet = await authoritativePayrollBroadcastSet(reservationManager, artifact, identity);
  const status = payrollBroadcastStatus(reservationSet.reservations);
  if (status === "Unknown" || status === "ConfirmedSpent") {
    return Object.freeze([...reservationSet.reservations]);
  }
  if (status !== "ProofReady" && status !== "Submitted") {
    throw new Error(`one-proof payroll broadcast outcome cannot become Unknown from ${status}`);
  }
  if (status === "ProofReady" && reservationSet.reservations.some(reservation =>
    reservation.broadcast_in_flight !== true || Number(reservation.broadcast_attempt_count || 0) < 1
  )) {
    throw new Error("one-proof payroll Unknown outcome requires a durable broadcast attempt");
  }
  const unknown = await reservationManager.markUnknown(reservationSet.reservationIDs, {
    fromStatus: status,
    leaseToken: artifact.reservation_batch.lease_token,
    ...identity,
    error: "one_proof_payroll_broadcast_result_unknown",
    metadata: payrollReservationMetadata(artifact.execution.operation_evidence, {
      reconcile_reason: "one_proof_payroll_broadcast_result_unknown"
    })
  });
  assertPayrollBroadcastIdentityMatches(unknown, identity, { requireComplete: true });
  return Object.freeze(unknown);
}

async function recordPayrollBroadcastResolved(reservationManager, artifact, identity) {
  const reservationSet = await authoritativePayrollBroadcastSet(reservationManager, artifact, identity);
  const status = payrollBroadcastStatus(reservationSet.reservations);
  if (status === "Submitted" || status === "Unknown" || status === "ConfirmedSpent") {
    return Object.freeze([...reservationSet.reservations]);
  }
  if (status !== "ProofReady") {
    throw new Error(`one-proof payroll resolved broadcast cannot be recorded from ${status}`);
  }
  return markOneProofPayrollReservationSubmitted(
    reservationManager,
    artifact.reservation_batch,
    artifact.execution,
    identity
  );
}

function startPayrollBroadcastHeartbeat(reservationManager, artifact, reservations) {
  const intervalMs = reservationHeartbeatIntervalMs({
    leaseDurationMs: reservationManager.leaseDurationMs,
    leaseUntil: reservations[0]?.lease_until
  });
  let heartbeatError = null;
  let inFlight = null;
  const heartbeat = async () => {
    if (heartbeatError || inFlight) return inFlight;
    inFlight = reservationManager.renewLease(artifact.reservation_batch.reservation_ids, {
      leaseToken: artifact.reservation_batch.lease_token
    }).catch(error => {
      heartbeatError = error;
    }).finally(() => {
      inFlight = null;
    });
    return inFlight;
  };
  const timer = typeof globalThis.setInterval === "function"
    ? globalThis.setInterval(() => { void heartbeat(); }, intervalMs)
    : null;
  return {
    assertHealthy() {
      if (!heartbeatError) return;
      const error = new Error("one-proof payroll reservation lease heartbeat failed during signed transaction broadcast");
      error.name = "ReservationHeartbeatError";
      error.cause = heartbeatError;
      throw error;
    },
    async stop() {
      if (timer && typeof globalThis.clearInterval === "function") globalThis.clearInterval(timer);
      if (inFlight) await inFlight;
      return heartbeatError;
    }
  };
}

/**
 * Retransmit exact signed bytes with a fresh one-use decision. This owns the
 * durable marker, ProofReady heartbeat, and Submitted/Unknown outcome write.
 */
export async function retransmitOneProofPayrollArtifact(value, {
  broadcastSignedTx,
  reservationManager,
  retryDecision,
  retry_decision,
  nowUnix
} = {}) {
  if (typeof broadcastSignedTx !== "function") throw new Error("a broadcastSignedTx callback is required to retransmit a one-proof payroll artifact");
  if (!reservationManager || typeof reservationManager.markBroadcastAttempting !== "function" ||
      typeof reservationManager.markSubmitted !== "function" || typeof reservationManager.markUnknown !== "function") {
    throw new Error("a NoteReservationManager with broadcast lifecycle support is required to retransmit a one-proof payroll artifact");
  }
  const decision = oneProofPayrollRetryDecisionInput({ retryDecision, retry_decision });
  const decisionBinding = decision && typeof decision === "object"
    ? oneProofPayrollRetryDecisionBindings.get(decision)
    : null;
  if (!decisionBinding) {
    throw new Error("a fresh inspect-issued one-proof payroll retry-safe decision is required");
  }
  const resolvedNowUnix = nowUnix ?? Math.floor(Date.now() / 1000);
  const resumed = resumeOneProofPayrollArtifact(value, { nowUnix: resolvedNowUnix });
  if (!resumed.signed_tx_bytes) throw new Error("one-proof payroll artifact does not contain exact signed transaction bytes");
  if (
    decisionBinding.artifactHash !== resumed.artifact.artifact_hash ||
    decisionBinding.txHash !== resumed.artifact.tx_hash ||
    decisionBinding.txBytesHash !== resumed.artifact.tx_bytes_hash
  ) {
    throw new Error("one-proof payroll retry-safe decision does not match the signed artifact identity");
  }
  const wallClockNowMs = Date.now();
  if (
    resolvedNowUnix < decisionBinding.issuedAtUnix ||
    resolvedNowUnix >= decisionBinding.expiresAtUnix ||
    wallClockNowMs < decisionBinding.issuedAtWallClockMs ||
    wallClockNowMs >= decisionBinding.expiresAtWallClockMs
  ) {
    oneProofPayrollRetryDecisionBindings.delete(decision);
    throw new Error("one-proof payroll retry-safe decision is stale");
  }
  expectedPayrollEvidenceForPreparedOperation(resumed.artifact.prepared, { nowUnix: resolvedNowUnix });
  // Consume before invoking caller code so concurrent/re-entrant callers cannot
  // use one chain observation to cross the external boundary twice.
  oneProofPayrollRetryDecisionBindings.delete(decision);
  const artifact = resumed.artifact;
  if (!artifact.execution || !artifact.reservation_batch) {
    throw new Error("one-proof payroll signed artifact requires execution and reservation checkpoints before retransmit");
  }
  const identity = requiredPayrollCosmosBroadcastIdentity({
    txHash: artifact.tx_hash,
    txBytesHash: artifact.tx_bytes_hash,
    signDocHash: artifact.sign_doc_hash
  }, "retry artifact", { requireSignedBindings: true });
  const beforeMarker = await payrollReservationSet(reservationManager, artifact.prepared, artifact.reservation_batch);
  const beforeMarkerStatus = payrollBroadcastStatus(beforeMarker.reservations);
  const existingAttempt = beforeMarker.reservations.some(reservation =>
    reservation.broadcast_in_flight === true || Number(reservation.broadcast_attempt_count || 0) > 0
  );
  if (existingAttempt) {
    try {
      const partialAttempt = beforeMarkerStatus === "ProofReady"
        ? beforeMarker.reservations.some(reservation =>
            reservation.broadcast_in_flight !== true || Number(reservation.broadcast_attempt_count || 0) < 1
          )
        : beforeMarker.reservations.some(reservation => Number(reservation.broadcast_attempt_count || 0) < 1);
      if (partialAttempt) {
        throw new Error("one-proof payroll reservations have a partial durable broadcast attempt");
      }
      assertPayrollBroadcastIdentityMatches(beforeMarker.reservations, identity, { requireComplete: true });
    } catch (error) {
      throw payrollBroadcastError(error, identity);
    }
  }
  if (beforeMarkerStatus === "ProofReady") {
    if (typeof reservationManager.renewLease !== "function") {
      const error = new Error("reservationManager.renewLease is required to keep the one-proof payroll lease alive through broadcast");
      if (existingAttempt) throw payrollBroadcastError(error, identity);
      throw error;
    }
    try {
      await reservationManager.renewLease(beforeMarker.reservationIDs, {
        leaseToken: artifact.reservation_batch.lease_token
      });
    } catch (error) {
      if (existingAttempt) throw payrollBroadcastError(error, identity);
      throw error;
    }
  }
  let markerReservations;
  try {
    markerReservations = await markOneProofPayrollReservationBroadcastAttempting(
      reservationManager,
      artifact.reservation_batch,
      artifact.execution,
      {
        artifact,
        reason: "one_proof_payroll_exact_txraw_retransmit"
      }
    );
  } catch (error) {
    // A custom durable store may have committed its marker before losing the
    // acknowledgement. Do not call the RPC, and tell the caller to reconcile
    // the exact identity before issuing another decision.
    throw payrollBroadcastError(error, identity);
  }
  const markerStatus = payrollBroadcastStatus(markerReservations);
  const heartbeat = markerStatus === "ProofReady"
    ? startPayrollBroadcastHeartbeat(reservationManager, artifact, markerReservations)
    : null;
  const context = {
    artifact,
    tx_hash: artifact.tx_hash,
    tx_bytes_hash: artifact.tx_bytes_hash,
    sign_doc_hash: artifact.sign_doc_hash
  };
  let result;
  try {
    const boundaryNowMs = Date.now();
    if (boundaryNowMs >= decisionBinding.expiresAtWallClockMs) {
      throw new Error("one-proof payroll retry-safe decision became stale before the broadcast boundary");
    }
    heartbeat?.assertHealthy();
    result = await broadcastSignedTx(Uint8Array.from(resumed.signed_tx_bytes), context);
    heartbeat?.assertHealthy();
    try {
      await recordPayrollBroadcastResolved(reservationManager, artifact, identity);
    } catch (bookkeepingError) {
      try {
        await recordPayrollBroadcastUnknown(reservationManager, artifact, identity, bookkeepingError);
      } catch (unknownBookkeepingError) {
        throw payrollBroadcastError(bookkeepingError, identity, {
          bookkeepingError: unknownBookkeepingError
        });
      }
      throw payrollBroadcastError(bookkeepingError, identity);
    }
    return result;
  } catch (error) {
    try {
      await recordPayrollBroadcastUnknown(reservationManager, artifact, identity, error);
    } catch (bookkeepingError) {
      throw payrollBroadcastError(error, identity, { bookkeepingError });
    }
    throw payrollBroadcastError(error, identity);
  } finally {
    const heartbeatError = await heartbeat?.stop();
    if (heartbeatError) {
      // A terminal CAS can race the final timer. Exact Submitted/Unknown state
      // is authoritative; otherwise the durable in-flight marker remains and
      // the caller receives the primary reconciliation error above.
      try {
        const latest = await authoritativePayrollBroadcastSet(reservationManager, artifact, identity);
        const latestStatus = payrollBroadcastStatus(latest.reservations);
        if (!["Submitted", "Unknown", "ConfirmedSpent"].includes(latestStatus)) throw heartbeatError;
      } catch {
        // The primary result/error already carries exact durable identity. A
        // later reconciliation will observe the still-active marker.
      }
    }
  }
}

/** Validate an operation evidence artifact against the exact prepared payload. */
export function validateOneProofPayrollOperationEvidence(evidence, prepared, { nowUnix } = {}) {
  if (!evidence || typeof evidence !== "object") throw new Error("one-proof payroll operation evidence is required");
  if (evidence.version !== oneProofPayrollOperationEvidenceVersion) {
    throw new Error(`unsupported one-proof payroll operation evidence version ${JSON.stringify(evidence.version)}`);
  }
  const normalized = expectedPayrollEvidenceForPreparedOperation(prepared, { nowUnix });
  if (text(evidence.operation_id) !== normalized.operation.operation_id || evidence.circuit_set_id !== oneProofPayrollCircuitSetId) {
    throw new Error("one-proof payroll operation evidence identity does not match the prepared operation");
  }
  if (canonicalDigest(evidence.payload_hash, "one-proof payroll payload hash") !== normalized.payload.payload_hash) {
    throw new Error("one-proof payroll operation evidence payload hash does not match the prepared payload");
  }
  if (!Array.isArray(evidence.input_nullifier_hexes) || evidence.input_nullifier_hexes.length !== normalized.effects.nullifier_hexes.length ||
      evidence.input_nullifier_hexes.some((value, index) => canonicalDigest(value, "one-proof payroll evidence nullifier") !== normalized.effects.nullifier_hexes[index])) {
    throw new Error("one-proof payroll operation evidence nullifiers do not match the prepared payload");
  }
  if (!Array.isArray(evidence.expected_evidence) || evidence.expected_evidence.length !== normalized.expected.length ||
      normalized.expected.some((entry, index) => !sameEvidence(entry, evidence.expected_evidence[index]))) {
    throw new Error("one-proof payroll operation evidence outputs do not match the prepared payload");
  }
  const proofPayloadHash = evidence.proof_payload_hash;
  const proofHash = evidence.proof_hash;
  if ((proofPayloadHash === undefined) !== (proofHash === undefined)) {
    throw new Error("one-proof payroll proof evidence must include both proof payload hash and proof hash");
  }
  if (proofPayloadHash !== undefined) {
    if (canonicalDigest(proofPayloadHash, "one-proof payroll proof payload hash") !== normalized.payload.payload_hash ||
        !canonicalDigest(proofHash, "one-proof payroll proof hash")) {
      throw new Error("one-proof payroll proof evidence is invalid");
    }
  }
  return true;
}

/**
 * Prove one fully prepared payroll operation with exactly one selected batch
 * prover. Input nullifiers are checked immediately before and after proving,
 * so the result is safe to hand to the signing/broadcast boundary only if the
 * same inputs remain unspent.
 */
export async function provePreparedOneProofPayrollOperation(prepared, prover, {
  creator,
  checkNullifiers,
  nowUnix
} = {}) {
  if (typeof checkNullifiers !== "function") {
    throw new Error("a batch nullifier status reader is required before one-proof payroll proving");
  }
  const resolvedNowUnix = nowUnix ?? Math.floor(Date.now() / 1000);
  const normalized = expectedPayrollEvidenceForPreparedOperation(prepared, { nowUnix: resolvedNowUnix });
  await assertOneProofPayrollNullifiersUnspent(normalized.payload, checkNullifiers);
  const proof = await proveOneProofPayrollOperation(normalized.payload, prover, { nowUnix: resolvedNowUnix });
  await assertOneProofPayrollNullifiersUnspent(normalized.payload, checkNullifiers);
  const preparedCreator = text(normalized.payload.creator);
  const sender = text(creator ?? preparedCreator);
  if (!preparedCreator || !sender) throw new Error("one-proof payroll batch transfer creator is required");
  // `creator` is a Cosmos envelope signer, not a batch-proof public input.
  // The payload creator remains pinned for auditability while a fresh relayer
  // may replace the message creator after proof generation.
  const message = buildMsgBatchTransferFromPrepared(normalized.payload, proof, { creator: sender, nowUnix: resolvedNowUnix });
  const operationEvidence = buildOneProofPayrollOperationEvidence(prepared, { proof, nowUnix: resolvedNowUnix });
  return Object.freeze({
    version: oneProofPayrollExecutionVersion,
    operation: normalized.operation,
    circuit_config: normalized.circuitConfig,
    payload: normalized.payload,
    proof,
    message,
    operation_evidence: operationEvidence,
    input_nullifier_hexes: Object.freeze([...normalized.effects.nullifier_hexes])
  });
}

/** Build a Cosmos direct sign-doc from a proven one-proof payroll operation. */
export async function createOneProofPayrollBatchSignDoc(execution, {
  cosmosClient,
  signer,
  pubKeyHex,
  gasLimit,
  gas_limit,
  feeAmount,
  fee_amount,
  memo,
  nowUnix
} = {}) {
  if (!execution || typeof execution !== "object" || execution.version !== oneProofPayrollExecutionVersion) {
    throw new Error("proven one-proof payroll execution is required");
  }
  if (!cosmosClient || typeof cosmosClient.createBatchTransferSignDoc !== "function") {
    throw new Error("a Cosmos client with createBatchTransferSignDoc is required");
  }
  const resolvedNowUnix = nowUnix ?? Math.floor(Date.now() / 1000);
  validateOneProofPayrollOperationEvidence(execution.operation_evidence, {
    operation: execution.operation,
    circuit_config: execution.circuit_config,
    payload: execution.payload,
    expected_evidence: execution.operation_evidence.expected_evidence,
    input_nullifier_hexes: execution.input_nullifier_hexes
  }, { nowUnix: resolvedNowUnix });
  const proof = normalizePreparedBatchTransferProof(execution.payload, execution.proof, { nowUnix: resolvedNowUnix });
  if (execution.operation_evidence.proof_payload_hash !== proof.request_payload_hash ||
      execution.operation_evidence.proof_hash !== sha256Hex(proof.proof_bytes)) {
    throw new Error("one-proof payroll execution proof does not match its operation evidence");
  }
  const preparedCreator = text(execution.payload.creator);
  const messageCreator = text(execution.message?.creator);
  if (!preparedCreator || !messageCreator) throw new Error("one-proof payroll execution creator is required");
  if (signer !== undefined && text(signer) !== messageCreator) {
    throw new Error("one-proof payroll sign-doc signer must match the proven message creator");
  }
  const message = buildMsgBatchTransferFromPrepared(execution.payload, execution.proof, {
    creator: messageCreator,
    nowUnix: resolvedNowUnix
  });
  const circuitConfig = validateCircuitConfigV1(execution.circuit_config);
  const signDoc = await cosmosClient.createBatchTransferSignDoc({
    signer,
    pubKeyHex,
    gasLimit,
    gas_limit,
    feeAmount,
    fee_amount,
    message,
    chainNowUnix: resolvedNowUnix,
    expectedCircuitIdentity: circuitConfig.circuit_set_identity,
    ...(memo === undefined ? {} : { memo })
  });
  return Object.freeze({
    operation_evidence: execution.operation_evidence,
    message,
    sign_doc: signDoc
  });
}

function normalizedNullifierStatuses(nullifiers, statuses) {
  const values = new Map();
  const add = (raw, used) => {
    const nullifier = canonicalDigest(raw, "one-proof payroll nullifier status key");
    if (typeof used !== "boolean") throw new Error("one-proof payroll nullifier has an invalid status");
    if (values.has(nullifier) && values.get(nullifier) !== used) {
      throw new Error("one-proof payroll nullifier has conflicting statuses");
    }
    values.set(nullifier, used);
  };
  if (statuses instanceof Map) {
    for (const [nullifier, used] of statuses) add(nullifier, used);
  } else if (statuses && typeof statuses === "object" && !Array.isArray(statuses)) {
    for (const [nullifier, used] of Object.entries(statuses)) add(nullifier, used);
  } else {
    throw new Error("one-proof payroll nullifier status response must be a Map or object");
  }
  return nullifiers.map((nullifier, index) => {
    if (!values.has(nullifier)) throw new Error(`one-proof payroll nullifier status is missing at index ${index}`);
    return Object.freeze({ nullifier, spent: values.get(nullifier) });
  });
}

/**
 * Reconcile a prepared one-proof operation with explicit chain outcome,
 * complete input-nullifier state, and typed per-output evidence. No branch
 * can mark an item successful from a spent nullifier alone.
 */
export async function reconcileOneProofPayrollOperationEvidence({
  prepared,
  operation_evidence,
  checkNullifiers,
  tx_succeeded,
  txSucceeded,
  tx_failed,
  txFailed,
  observed_outputs,
  observedOutputs
} = {}) {
  if (typeof checkNullifiers !== "function") throw new Error("a batch nullifier status reader is required for one-proof payroll reconciliation");
  validateOneProofPayrollOperationEvidence(operation_evidence, prepared);
  const succeeded = tx_succeeded ?? txSucceeded;
  const failed = tx_failed ?? txFailed;
  if (succeeded !== undefined && typeof succeeded !== "boolean") throw new Error("one-proof payroll tx_succeeded must be a boolean");
  if (failed !== undefined && typeof failed !== "boolean") throw new Error("one-proof payroll tx_failed must be a boolean");
  if (succeeded === true && failed === true) throw new Error("one-proof payroll transaction cannot be both succeeded and failed");
  const nullifiers = operation_evidence.input_nullifier_hexes;
  const inputNullifiers = normalizedNullifierStatuses(nullifiers, await checkNullifiers(nullifiers));
  const anySpent = inputNullifiers.some(entry => entry.spent);
  const allSpent = inputNullifiers.every(entry => entry.spent);
  let items;
  let status;
  if (succeeded !== true && failed !== true) {
    status = anySpent ? "ManualReview" : "Pending";
    items = operation_evidence.expected_evidence.map(item => ({
      item_id: item.item_id,
      batch_item_index: item.batch_item_index,
      status,
      reason: anySpent
        ? "input nullifier is spent without a confirmed one-proof payroll transaction"
        : "chain transaction outcome is not yet confirmed"
    }));
  } else if (failed === true && !anySpent) {
    status = "Failed";
    items = reconcileOneProofPayrollEvidence({ expected_evidence: operation_evidence.expected_evidence, tx_failed: true });
  } else if (failed === true || !allSpent) {
    status = "ManualReview";
    const reason = failed === true
      ? "failed one-proof payroll transaction has spent input evidence"
      : "confirmed one-proof payroll transaction has unspent input evidence";
    items = operation_evidence.expected_evidence.map(item => ({
      item_id: item.item_id,
      batch_item_index: item.batch_item_index,
      status,
      reason
    }));
  } else {
    items = reconcileOneProofPayrollEvidence({
      expected_evidence: operation_evidence.expected_evidence,
      observed_outputs: observed_outputs ?? observedOutputs ?? [],
      tx_succeeded: true
    });
    status = items.every(item => item.status === "Succeeded") ? "Succeeded" : "ManualReview";
  }
  return Object.freeze({
    operation_id: operation_evidence.operation_id,
    status,
    input_nullifiers: inputNullifiers,
    items
  });
}

async function markPayrollReservationsManualReview(reservationManager, reservationSet, reservationBatch, operationEvidence, reconciliation) {
  if (reservationStatusesAre(reservationSet.reservations, "ManualReview")) {
    return { action: "ManualReview", reservations: reservationSet.reservations };
  }
  if (reservationSet.reservations.some(reservation => String(reservation.status) === "ConfirmedSpent")) {
    return { action: "ManualReviewRequired", reservations: reservationSet.reservations };
  }
  const reservations = await reservationManager.markManualReview(reservationSet.reservationIDs, {
    leaseToken: reservationBatch.lease_token,
    error: "payroll_operation_evidence_manual_review",
    metadata: payrollReservationMetadata(operationEvidence, {
      reconcile_reason: "payroll_operation_evidence_manual_review",
      payroll_reconciliation_status: reconciliation.status
    })
  });
  return { action: "ManualReview", reservations };
}

function payrollReconciliationSuccessEvidence(operationEvidence, {
  tx_hash,
  txHash,
  tx_bytes_hash,
  txBytesHash,
  sign_doc_hash,
  signDocHash,
  tx_result,
  txResult,
  checked_height,
  checkedHeight,
  tx_hash_checked,
  txHashChecked
} = {}) {
  if (tx_result !== undefined && txResult !== undefined && JSON.stringify(tx_result) !== JSON.stringify(txResult)) {
    throw new Error("one-proof payroll reconciliation tx result aliases must match");
  }
  const identity = payrollBroadcastIdentity({ tx_hash, txHash, tx_bytes_hash, txBytesHash, sign_doc_hash, signDocHash });
  return {
    ...identity,
    ...(tx_result ?? txResult ? { txResult: tx_result ?? txResult } : {}),
    operationEvidenceHash: oneProofPayrollOperationEvidenceHash(operationEvidence)
  };
}

function manualReviewFromPersistedPayrollConflict(reconciliation, reservations) {
  const errors = [...new Set(reservations.flatMap(reservation =>
    Array.isArray(reservation.metadata?.operation_success_evidence_errors)
      ? reservation.metadata.operation_success_evidence_errors
      : []
  ))];
  const conflictsByKey = new Map();
  for (const conflict of reservations.flatMap(reservation =>
    Array.isArray(reservation.metadata?.operation_success_evidence_conflicts)
      ? reservation.metadata.operation_success_evidence_conflicts
      : []
  )) {
    if (!conflict || typeof conflict !== "object" || Array.isArray(conflict)) continue;
    const key = JSON.stringify([
      text(conflict.reservation_id),
      text(conflict.field),
      text(conflict.source_field),
      text(conflict.reason),
      Object.prototype.hasOwnProperty.call(conflict, "expected") ? text(conflict.expected) : null,
      Object.prototype.hasOwnProperty.call(conflict, "actual") ? text(conflict.actual) : null
    ]);
    if (!conflictsByKey.has(key)) conflictsByKey.set(key, conflict);
  }
  const conflicts = [...conflictsByKey.values()];
  const reason = errors.length
    ? `persisted payroll operation evidence conflict: ${errors.join(", ")}`
    : "persisted payroll operation evidence did not confirm the one-proof payroll operation";
  return Object.freeze({
    ...reconciliation,
    status: "ManualReview",
    error_code: ClairveilErrorCode.OPERATION_EVIDENCE_CONFLICT,
    error_details: Object.freeze({
      operation_id: text(reservations[0]?.operation_id || reconciliation.operation_id),
      conflicts: Object.freeze(conflicts.map(conflict => Object.freeze({ ...conflict })))
    }),
    items: reconciliation.items.map(item => ({ ...item, status: "ManualReview", reason }))
  });
}

/**
 * Reconcile chain evidence and transition the exact payroll reservation set.
 * Successful inputs are confirmed spent only after typed output evidence matches;
 * any ambiguous or conflicting result keeps the reservation unavailable for review.
 */
export async function reconcileOneProofPayrollReservation({
  reservation_manager,
  reservationManager,
  reservation_batch,
  reservationBatch,
  prepared,
  operation_evidence,
  operationEvidence,
  check_nullifiers,
  checkNullifiers,
  tx_succeeded,
  txSucceeded,
  tx_failed,
  txFailed,
  observed_outputs,
  observedOutputs,
  tx_hash,
  txHash,
  tx_bytes_hash,
  txBytesHash,
  sign_doc_hash,
  signDocHash,
  tx_result,
  txResult,
  checked_height,
  checkedHeight,
  tx_hash_checked,
  txHashChecked
} = {}) {
  const manager = reservation_manager ?? reservationManager;
  const batch = reservation_batch ?? reservationBatch;
  const evidence = operation_evidence ?? operationEvidence;
  if (!manager || typeof manager.reconcileSpentNotes !== "function" || typeof manager.markBroadcastFailed !== "function" || typeof manager.markManualReview !== "function") {
    throw new Error("a NoteReservationManager with reconciliation support is required");
  }
  const resolvedCheckedHeight = consistentPayrollBroadcastIdentity(
    "checked height",
    [checked_height, checkedHeight]
  );
  const resolvedTxHashChecked = consistentPayrollBroadcastIdentity(
    "checked transaction hash",
    [tx_hash_checked, txHashChecked]
  );
  const reservationSet = await payrollReservationSet(manager, prepared, batch);
  throwIfPayrollReservationStateMixed(reservationSet.reservations);
  const reconciliation = await reconcileOneProofPayrollOperationEvidence({
    prepared,
    operation_evidence: evidence,
    checkNullifiers: check_nullifiers ?? checkNullifiers,
    tx_succeeded,
    txSucceeded,
    tx_failed,
    txFailed,
    observed_outputs,
    observedOutputs
  });
  if (reconciliation.status === "Pending") {
    return Object.freeze({
      reconciliation,
      reservation_action: "None",
      reservations: Object.freeze([...reservationSet.reservations])
    });
  }
  if (reconciliation.status === "Succeeded") {
    if (!reservationStatusesAre(reservationSet.reservations, "Submitted", "Unknown", "ConfirmedSpent")) {
      const manual = await markPayrollReservationsManualReview(manager, reservationSet, batch, evidence, reconciliation);
      return Object.freeze({ reconciliation, reservation_action: manual.action, reservations: Object.freeze([...manual.reservations]) });
    }
    const operationSuccessEvidence = payrollReconciliationSuccessEvidence(evidence, {
      tx_hash, txHash, tx_bytes_hash, txBytesHash, sign_doc_hash, signDocHash, tx_result, txResult
    });
    const spentInputs = reservationPlanForOneProofPayrollOperation(reservationSet.normalized.operation)
      .selection.inputs.map(input => ({ ...input, spent: true, operationSuccessEvidence }));
    const reconciled = await manager.reconcileSpentNotes(spentInputs);
    const confirmed = await payrollReservationSet(manager, prepared, batch);
    if (reservationStatusesAre(confirmed.reservations, "ConfirmedSpent") && confirmed.reservations.every(reservation =>
      reservation.metadata?.operation_status === "Succeeded" &&
      reservation.metadata?.operation_success_evidence_matches === true
    )) {
      return Object.freeze({
        reconciliation,
        reservation_action: "ConfirmedSpent",
        reservations: Object.freeze(reconciled.length ? [...reconciled] : [...confirmed.reservations])
      });
    }
    return Object.freeze({
      reconciliation: manualReviewFromPersistedPayrollConflict(reconciliation, confirmed.reservations),
      reservation_action: "ManualReviewRequired",
      reservations: Object.freeze([...confirmed.reservations])
    });
  }
  if (reconciliation.status === "Failed" && reservationStatusesAre(reservationSet.reservations, "ReplanRequired")) {
    return Object.freeze({
      reconciliation,
      reservation_action: "ReplanRequired",
      reservations: Object.freeze([...reservationSet.reservations])
    });
  }
  const failedFromStatus = reservationStatusesAre(reservationSet.reservations, "Submitted")
    ? "Submitted"
    : reservationStatusesAre(reservationSet.reservations, "Unknown")
      ? "Unknown"
      : "";
  if (reconciliation.status === "Failed" && failedFromStatus) {
    const reservations = await manager.markBroadcastFailed(reservationSet.reservationIDs, {
      checkedHeight: resolvedCheckedHeight,
      txHashChecked: resolvedTxHashChecked,
      nullifierUnspentConfirmed: true,
      txAbsentOrFailedConfirmed: true,
      error: "payroll_transaction_failed_unspent",
      metadata: payrollReservationMetadata(evidence, {
        reconcile_reason: "payroll_transaction_failed_unspent",
        payroll_reconciliation_status: reconciliation.status
      })
    });
    return Object.freeze({ reconciliation, reservation_action: "ReplanRequired", reservations: Object.freeze([...reservations]) });
  }
  const manual = await markPayrollReservationsManualReview(manager, reservationSet, batch, evidence, reconciliation);
  return Object.freeze({ reconciliation, reservation_action: manual.action, reservations: Object.freeze([...manual.reservations]) });
}

function consistentObservedEvidenceAlias(value, names, label, normalize) {
  const aliases = names
    .map(name => value[name])
    .filter(alias => alias !== undefined && alias !== null);
  if (!aliases.length) return normalize(undefined);
  const normalized = aliases.map(alias => normalize(alias));
  if (normalized.some(alias => alias !== normalized[0])) {
    throw new Error(`${label} aliases conflict`);
  }
  return normalized[0];
}

function observedEvidenceByIndex(observedOutputs) {
  if (!Array.isArray(observedOutputs)) throw new Error("observed one-proof payroll outputs must be an array");
  const observed = new Map();
  for (const value of observedOutputs) {
    if (!value || typeof value !== "object") throw new Error("observed one-proof payroll output must be an object");
    const index = consistentObservedEvidenceAlias(
      value,
      ["batch_item_index", "batchItemIndex", "output_index", "outputIndex"],
      "observed one-proof payroll output index",
      Number
    );
    if (!Number.isSafeInteger(index) || index < 0 || observed.has(index)) throw new Error("observed one-proof payroll outputs require unique non-negative output indexes");
    const digest = (names, label) => consistentObservedEvidenceAlias(
      value,
      names,
      `observed output ${index} ${label}`,
      alias => canonicalDigest(alias, `observed output ${index} ${label}`)
    );
    observed.set(index, {
      commitment: digest(["commitment", "expected_output_commitment", "expectedOutputCommitment"], "commitment"),
      user: digest(["user_disclosure_digest", "userDisclosureDigest"], "user disclosure digest"),
      full: digest(["full_disclosure_digest", "fullDisclosureDigest", "audit_disclosure_digest", "auditDisclosureDigest"], "full disclosure digest"),
      recipient: digest(["recipient_hash", "recipientHash"], "recipient hash"),
      amount: digest(["amount_hash", "amountHash"], "amount hash"),
      denom: consistentObservedEvidenceAlias(
        value,
        ["denom", "expected_denom", "expectedDenom"],
        `observed output ${index} denom`,
        text
      ),
      auditKeyID: consistentObservedEvidenceAlias(
        value,
        ["audit_key_id", "auditKeyId"],
        `observed output ${index} audit key ID`,
        text
      ),
      auditKeyEpoch: consistentObservedEvidenceAlias(
        value,
        ["audit_key_epoch", "auditKeyEpoch"],
        `observed output ${index} audit key epoch`,
        alias => text(alias) === ""
          ? ""
          : canonicalUint64(alias, `observed output ${index} audit key epoch`, { positive: true }).toString()
      )
    });
  }
  return observed;
}

/**
 * Reconcile typed output evidence independently from input nullifier state.
 * A spent input alone can never produce a Succeeded payroll item here.
 */
export function reconcileOneProofPayrollEvidence({ expected_evidence, expectedEvidence, observed_outputs, observedOutputs, tx_succeeded, txSucceeded, tx_failed, txFailed } = {}) {
  const expected = expected_evidence ?? expectedEvidence;
  if (!Array.isArray(expected) || !expected.length) throw new Error("expected one-proof payroll evidence is required");
  const succeeded = tx_succeeded ?? txSucceeded;
  const failed = tx_failed ?? txFailed;
  if (succeeded === true && failed === true) throw new Error("one-proof payroll transaction cannot be both succeeded and failed");
  if (succeeded !== true && failed !== true) return expected.map(item => ({ item_id: item.item_id, batch_item_index: item.batch_item_index, status: "Pending", reason: "chain transaction outcome is not yet confirmed" }));
  if (failed === true) return expected.map(item => ({ item_id: item.item_id, batch_item_index: item.batch_item_index, status: "Failed", reason: "one-proof payroll transaction failed on chain" }));
  const observed = observedEvidenceByIndex(observed_outputs ?? observedOutputs ?? []);
  return expected.map(item => {
    const value = observed.get(item.batch_item_index);
    if (!value) return { item_id: item.item_id, batch_item_index: item.batch_item_index, status: "ManualReview", reason: "confirmed transaction is missing typed output evidence" };
    const mismatch = [
      [item.expected_output_commitment, value.commitment, "commitment"],
      [item.expected_user_disclosure_digest, value.user, "user disclosure digest"],
      [item.expected_audit_disclosure_digest, value.full, "full disclosure digest"],
      [item.expected_recipient_hash, value.recipient, "recipient hash"],
      [item.expected_amount_hash, value.amount, "amount hash"],
      [item.expected_denom, value.denom, "denom"],
      [item.audit_key_id, value.auditKeyID, "audit key ID"],
      [String(item.audit_key_epoch), value.auditKeyEpoch, "audit key epoch"]
    ].find(([needed, actual]) => needed !== actual);
    return mismatch
      ? { item_id: item.item_id, batch_item_index: item.batch_item_index, status: "ManualReview", reason: `typed output evidence ${mismatch[2]} does not match` }
      : { item_id: item.item_id, batch_item_index: item.batch_item_index, status: "Succeeded", reason: "" };
  });
}
