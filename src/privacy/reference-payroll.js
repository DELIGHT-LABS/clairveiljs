import { base64FromBytes, bytesFromBase64, hexFromBytes, randomBytes, sha256Hex, utf8Bytes } from "../core/browser-crypto.js";
import { FIELD_MODULUS, bytesToBigIntBE, decodeShieldedAddress } from "../core/crypto.js";
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
import { privacyPolicyValue, userDisclosureModeValue } from "./payload.js";
import { computeNoteNullifierV1, fieldHexV1, validateNoteV1 } from "./protocol-v1.js";
import { hashAmount, hashRecipient } from "./reservation.js";

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
  const candidates = [];
  for (const ownerID of [...byOwner.keys()].sort()) {
    const notes = [...byOwner.get(ownerID)].sort((left, right) => left.amount === right.amount ? left.note_id.localeCompare(right.note_id) : left.amount > right.amount ? -1 : 1);
    const selected = [];
    let visited = 0;
    const visit = (index, total) => {
      if (visited >= maxInputCandidateSearch || candidates.length >= maxInputCandidates) return;
      visited += 1;
      if (total >= target) {
        const copy = [...selected].sort((left, right) => left.note_id.localeCompare(right.note_id));
        candidates.push({ notes: copy, total });
        return;
      }
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
  }
  const unique = new Map();
  for (const candidate of candidates) unique.set(candidate.notes.map(note => note.note_id).join("\x00"), candidate);
  return [...unique.values()].sort((left, right) => {
    const leftWaste = left.total - target;
    const rightWaste = right.total - target;
    if (leftWaste !== rightWaste) return leftWaste < rightWaste ? -1 : 1;
    if (left.notes.length !== right.notes.length) return left.notes.length - right.notes.length;
    return left.notes.map(note => note.note_id).join("\x00").localeCompare(right.notes.map(note => note.note_id).join("\x00"));
  });
}

function planOneProofSearch(input, available, itemOffset, operationIndex, state, options) {
  if (itemOffset === input.items.length) return [];
  state.farthest = Math.max(state.farthest, itemOffset);
  if (state.remaining-- <= 0) return null;
  const maxPayments = Math.min(oneProofPayrollMaxOutputs, input.items.length - itemOffset);
  for (let paymentCount = maxPayments; paymentCount >= 1; paymentCount -= 1) {
    const items = input.items.slice(itemOffset, itemOffset + paymentCount);
    const paymentTotal = items.reduce((sum, item) => sum + item.amount, 0n);
    for (const selection of selectOneProofCandidates(available, paymentTotal)) {
      const change = selection.total - paymentTotal;
      if (change > maxUint64 || (paymentCount === oneProofPayrollMaxOutputs && change !== 0n)) continue;
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
  return {
    operation_id: operationID,
    circuit_set_id: oneProofPayrollCircuitSetId,
    items: plannedItems,
    input_notes: selection.notes.map(note => ({ ...note })),
    input_total: selection.total,
    payment_total: paymentTotal,
    change,
    output_count: items.length + (change > 0n ? 1 : 0),
    has_change: change > 0n
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
  const expectedOutputCount = items.length + (operation.has_change ? 1 : 0);
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
  const asset = await resolvePayrollAssetRegistry(input.asset_registry ?? input.assetRegistry, denom);
  const preparedInputs = operation.input_notes.map((note, index) => preparedInputFromTreasuryNote(note, index, asset.asset_id_field));
  const inputTotal = preparedInputs.reduce((sum, entry) => sum + entry.note.amount, 0n);
  const paymentTotal = operation.items.reduce((sum, item) => sum + canonicalUint64(item.amount, `payroll item ${item.item_id} amount`, { positive: true }), 0n);
  const change = inputTotal - paymentTotal;
  const plannedChange = canonicalUint64(operation.change, "one-proof payroll operation change");
  const plannedOutputCount = Number(operation.output_count);
  if (!Number.isSafeInteger(plannedOutputCount) || plannedOutputCount < 1 || plannedOutputCount > oneProofPayrollMaxOutputs) throw new Error("one-proof payroll operation output count is invalid");
  if (change < 0n || change !== plannedChange || Boolean(change > 0n) !== Boolean(operation.has_change)) throw new Error("one-proof payroll operation totals are inconsistent");
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
    signer: input.signer
  });
  const expectedEvidence = buildExpectedPayrollEvidence(operation, payload, input);
  const effects = preparedBatchTransferEffectHex(payload);
  return Object.freeze({ operation, asset_registry_entry: asset, payload, expected_evidence: expectedEvidence, input_nullifier_hexes: effects.nullifier_hexes });
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
  for (const nullifier of nullifiers) {
    const value = statusFor(nullifier);
    if (value !== false) throw new Error(`one-proof payroll input nullifier ${nullifier} is spent, missing, or has an invalid status`);
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
  return { operation, payload, expected, effects };
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
  if (!preparedCreator || !sender) throw new Error("one-proof payroll batch transfer creator must be fixed during payload preparation");
  if (sender !== preparedCreator) throw new Error("one-proof payroll batch transfer creator does not match the prepared payload");
  const message = buildMsgBatchTransferFromPrepared(normalized.payload, proof, { creator: sender, nowUnix: resolvedNowUnix });
  const operationEvidence = buildOneProofPayrollOperationEvidence(prepared, { proof, nowUnix: resolvedNowUnix });
  return Object.freeze({
    version: oneProofPayrollExecutionVersion,
    operation: normalized.operation,
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
  if (!preparedCreator || text(execution.message?.creator) !== preparedCreator) {
    throw new Error("one-proof payroll execution creator does not match the prepared payload");
  }
  const message = buildMsgBatchTransferFromPrepared(execution.payload, execution.proof, {
    creator: preparedCreator,
    nowUnix: resolvedNowUnix
  });
  const signDoc = await cosmosClient.createBatchTransferSignDoc({
    signer,
    pubKeyHex,
    gasLimit,
    message,
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
    if (typeof used !== "boolean") throw new Error(`one-proof payroll nullifier ${nullifier} has an invalid status`);
    if (values.has(nullifier) && values.get(nullifier) !== used) {
      throw new Error(`one-proof payroll nullifier ${nullifier} has conflicting statuses`);
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
  return nullifiers.map(nullifier => {
    if (!values.has(nullifier)) throw new Error(`one-proof payroll nullifier status is missing ${nullifier}`);
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

function observedEvidenceByIndex(observedOutputs) {
  if (!Array.isArray(observedOutputs)) throw new Error("observed one-proof payroll outputs must be an array");
  const observed = new Map();
  for (const value of observedOutputs) {
    if (!value || typeof value !== "object") throw new Error("observed one-proof payroll output must be an object");
    const index = Number(value.batch_item_index ?? value.batchItemIndex ?? value.output_index ?? value.outputIndex);
    if (!Number.isSafeInteger(index) || index < 0 || observed.has(index)) throw new Error("observed one-proof payroll outputs require unique non-negative output indexes");
    observed.set(index, {
      commitment: canonicalDigest(value.commitment ?? value.expected_output_commitment ?? value.expectedOutputCommitment, `observed output ${index} commitment`),
      user: canonicalDigest(value.user_disclosure_digest ?? value.userDisclosureDigest, `observed output ${index} user disclosure digest`),
      full: canonicalDigest(value.full_disclosure_digest ?? value.fullDisclosureDigest ?? value.audit_disclosure_digest ?? value.auditDisclosureDigest, `observed output ${index} full disclosure digest`),
      recipient: canonicalDigest(value.recipient_hash ?? value.recipientHash, `observed output ${index} recipient hash`),
      amount: canonicalDigest(value.amount_hash ?? value.amountHash, `observed output ${index} amount hash`),
      denom: text(value.denom ?? value.expected_denom ?? value.expectedDenom)
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
      [item.expected_denom, value.denom, "denom"]
    ].find(([needed, actual]) => needed !== actual);
    return mismatch
      ? { item_id: item.item_id, batch_item_index: item.batch_item_index, status: "ManualReview", reason: `typed output evidence ${mismatch[2]} does not match` }
      : { item_id: item.item_id, batch_item_index: item.batch_item_index, status: "Succeeded", reason: "" };
  });
}
