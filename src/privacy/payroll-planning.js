// Pure payroll normalization and bounded selection. Execution/proving lives in its caller.
import { base64FromBytes, utf8Bytes } from "../core/browser-crypto.js";
import { bytesFromHex, unpackPoint } from "../core/crypto.js";
import { sumAmountTotals } from "../core/amount.js";
import { canonicalAssetDenomV1 } from "./asset-denom.js";
import { privacyPolicyValue } from "./disclosure-policy.js";
import { hashRecipient } from "./operation-hash.js";

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

export const oneProofPayrollMaxInputs = 16;
export const oneProofPayrollMaxOutputs = 32;
const disclosureScopeSet = new Set(payrollDisclosureScopes);
const disclosureModeName = new Map([
  ["none", 0],
  ["USER_DISCLOSURE_MODE_NONE", 0],
  ["public", 1],
  ["USER_DISCLOSURE_MODE_PUBLIC", 1],
  ["recipient-encrypted", 2],
  ["USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED", 2]
]);
const maxBatchPlanSearch = 20000;
const maxInputCandidateSearch = 4096;
const maxInputCandidates = 64;

export function oneProofOutputMode(options = {}) {
  const mode = text(options.output_mode ?? options.outputMode ?? "compact").toLowerCase();
  if (mode === "compact") return mode;
  // The CLI/reference docs spell this mode `exact32`; retain the older
  // hyphenated SDK spelling as a compatible alias while storing one canonical
  // value in every prepared operation.
  if (mode === "exact32" || mode === "exact-32") return "exact-32";
  throw new Error("one-proof payroll output mode must be compact, exact32, or exact-32");
}

export function text(value) {
  return String(value ?? "").trim();
}

export function canonicalDigest(value, label) {
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

function normalizePayrollItem(item, defaultPolicy, index, options, amountPolicy) {
  if (!item || typeof item !== "object") throw new Error(`payroll item ${index} must be an object`);
  const normalized = {
    item_id: text(item.item_id ?? item.itemID ?? item.itemId),
    employee_id: text(item.employee_id ?? item.employeeID ?? item.employeeId),
    recipient_address: text(item.recipient_address ?? item.recipientAddress),
    amount: amountPolicy.parse(item.amount, `payroll item ${index} amount`, { positive: true }),
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
export function normalizePayrollInputWithPolicy(input = {}, options = {}, amountPolicy) {
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
  canonicalAssetDenomV1(normalized.denom);
  if (!Number.isSafeInteger(normalized.attempt) || normalized.attempt < 0) throw new Error("payroll attempt must be a non-negative safe integer");
  const items = input.items;
  if (!Array.isArray(items) || items.length === 0) throw new Error("at least one payroll item is required");
  const itemIDs = new Set();
  const employeeIDs = new Set();
  normalized.items = items.map((item, index) => {
    const current = normalizePayrollItem(item, normalized.default_disclosure_policy, index, options, amountPolicy);
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

export function normalizeTreasuryNote(note, index, amountPolicy) {
  if (!note || typeof note !== "object") throw new Error(`treasury note ${index} must be an object`);
  return {
    ...note,
    note_id: text(note.note_id ?? note.noteID ?? note.noteId),
    owner_key_id: text(note.owner_key_id ?? note.ownerKeyID ?? note.ownerKeyId),
    nullifier_lookup_key: text(note.nullifier_lookup_key ?? note.nullifierLookupKey),
    nullifier_lookup_key_id: text(note.nullifier_lookup_key_id ?? note.nullifierLookupKeyID ?? note.nullifierLookupKeyId),
    denom: text(note.denom),
    amount: amountPolicy.parse(note.amount, `treasury note ${index} amount`),
    is_spent: note.is_spent === true || note.isSpent === true,
    reservation_id: text(note.reservation_id ?? note.reservationID ?? note.reservationId)
  };
}

export function availableNotes(denom, notes) {
  return notes
    .filter(note => !note.is_spent && !note.reservation_id && note.denom === denom)
    .sort((left, right) => left.amount === right.amount
      ? left.note_id.localeCompare(right.note_id)
      : left.amount < right.amount ? -1 : 1);
}

function idComponent(value) {
  return base64FromBytes(utf8Bytes(value || "_")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function payrollBatchOperationID(input, operationIndex) {
  if (!Number.isSafeInteger(operationIndex) || operationIndex < 0) throw new Error("payroll operation index must be a non-negative safe integer");
  const attempt = input.attempt > 0 ? `:attempt:${String(input.attempt).padStart(3, "0")}` : "";
  return `company:${idComponent(input.company_id)}:batch:${idComponent(input.batch_id)}:payroll:${idComponent(input.payroll_id)}:item:${idComponent(`batch-${String(operationIndex).padStart(6, "0")}`)}${attempt}:one-proof-16x32`;
}

function selectOneProofCandidates(available, target, amountPolicy) {
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
      if (amountPolicy.transactionMaximum !== null && total > amountPolicy.transactionMaximum) return;
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

function planOneProofSearch(input, available, itemOffset, operationIndex, state, options, amountPolicy) {
  if (itemOffset === input.items.length) return [];
  state.farthest = Math.max(state.farthest, itemOffset);
  if (state.remaining-- <= 0) return null;
  const maxPayments = Math.min(oneProofPayrollMaxOutputs, input.items.length - itemOffset);
  const outputMode = oneProofOutputMode(options);
  for (let paymentCount = maxPayments; paymentCount >= 1; paymentCount -= 1) {
    const items = input.items.slice(itemOffset, itemOffset + paymentCount);
    const paymentTotal = items.reduce((sum, item) => sum + item.amount, 0n);
    if (amountPolicy.transactionMaximum !== null && paymentTotal > amountPolicy.transactionMaximum) continue;
    for (const selection of selectOneProofCandidates(available, paymentTotal, amountPolicy)) {
      const change = selection.total - paymentTotal;
      if (change > amountPolicy.maximum || (paymentCount === oneProofPayrollMaxOutputs && change !== 0n)) continue;
      const compactOutputCount = paymentCount + (change > 0n ? 1 : 0);
      if (compactOutputCount > oneProofPayrollMaxOutputs) continue;
      const operation = buildOneProofOperationPlan(input, items, selection, paymentTotal, change, operationIndex, options, amountPolicy);
      const selectedIDs = new Set(selection.notes.map(note => note.note_id));
      const remainder = planOneProofSearch(input, available.filter(note => !selectedIDs.has(note.note_id)), itemOffset + paymentCount, operationIndex + 1, state, options, amountPolicy);
      if (remainder) return [operation, ...remainder];
    }
  }
  return null;
}

function preferredExpectedDigest(item) {
  return item.expected_disclosure_digest || item.disclosure_policy.expected_audit_disclosure_digest || "";
}

function buildOneProofOperationPlan(input, items, selection, paymentTotal, change, operationIndex, options, amountPolicy) {
  const operationID = payrollBatchOperationID(input, operationIndex) + (amountPolicy.amountModel === "uint128" ? ":uint128" : "");
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
    expected_amount_hash: amountPolicy.hash(input.denom, item.amount),
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
    ...(amountPolicy.amountModel === "uint128" ? { amount_model: "uint128" } : { circuit_set_id: amountPolicy.circuitSetId }),
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
export function planOneProofPayrollWithPolicy(input, treasuryNotes = [], options = {}, amountPolicy) {
  const payroll = normalizePayrollInputWithPolicy(input, options, amountPolicy);
  if (!Array.isArray(treasuryNotes)) throw new Error("treasury notes must be an array");
  const notes = treasuryNotes.map((note, index) => normalizeTreasuryNote(note, index, amountPolicy));
  if (amountPolicy.amountModel === "uint128") {
    const ids = new Set();
    for (const note of notes) {
      if (!note.note_id || ids.has(note.note_id)) throw new Error("missing or duplicate treasury note identity");
      ids.add(note.note_id);
    }
    const limit = options.search_limit ?? options.searchLimit ?? maxBatchPlanSearch;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > maxBatchPlanSearch) throw new Error("V2 payroll search limit must be an integer in 1..20000");
  }
  const state = { remaining: Number(options.search_limit ?? options.searchLimit ?? maxBatchPlanSearch), farthest: 0 };
  const operations = planOneProofSearch(payroll, availableNotes(payroll.denom, notes), 0, 0, state, options, amountPolicy);
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
    ...(amountPolicy.amountModel === "uint128" ? {
      amount_model: "uint128",
      total_payroll_amount: sumAmountTotals(payroll.items.map(item => item.amount)),
      total_spendable_amount: sumAmountTotals(availableNotes(payroll.denom, notes).map(note => note.amount))
    } : { circuit_set_id: amountPolicy.circuitSetId }),
    operations,
    created_at: payroll.created_at,
    updated_at: null
  };
}
