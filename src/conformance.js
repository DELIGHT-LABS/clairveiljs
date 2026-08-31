import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  hashAmount,
  hashRecipient,
  nullifierLookupKey
} from "./privacy/reservation.js";

export const conformanceFixtureRelativePath = "x/privacy/client/sdk/conformance/testdata";
// The directory is versioned with ClairveilJS. The core contract itself is an
// exact commit snapshot, not the unrelated immutable Clairveil v0.3.1 tag.
export const clairveilConformanceBundleVersion = "v0.3.1";
/** @deprecated Use clairveilConformanceBundleVersion for the SDK bundle identity. */
export const supportedClairveilRelease = clairveilConformanceBundleVersion;
export const supportedClairveilSourceKind = "commit_snapshot";
export const supportedClairveilCommit = "0ff92839872de26b787a60d8e4d5822cc459855b";
export const defaultConformanceFixtureDir = `fixtures/clairveil-${clairveilConformanceBundleVersion}/${conformanceFixtureRelativePath}`;

export const batchTransferConformanceFixtureName = "privacy_batch_transfer_v1_contract.json";
export const noteReservationConformanceFixtureName = "privacy_note_reservation_contract.json";
export const noteReservationContractVersionV3 = 3;

const expectedActiveReservationStatusesV3 = Object.freeze([
  "Reserved",
  "Proving",
  "ProofReady",
  "Submitted",
  "Unknown",
  "ManualReview"
]);

const expectedAllowedReservationTransitionsV3 = Object.freeze([
  ["Discovered", "Available"],
  ["Discovered", "Failed"],
  ["Available", "Reserved"],
  ["Reserved", "Proving"],
  ["Reserved", "Released"],
  ["Reserved", "ReplanRequired"],
  ["Reserved", "ManualReview"],
  ["Proving", "ProofReady"],
  ["Proving", "Reserved"],
  ["Proving", "ReplanRequired"],
  ["Proving", "ManualReview"],
  ["ProofReady", "Submitted"],
  ["ProofReady", "Unknown"],
  ["ProofReady", "ConfirmedSpent"],
  ["ProofReady", "ReplanRequired"],
  ["ProofReady", "ManualReview"],
  ["Submitted", "ConfirmedSpent"],
  ["Submitted", "Failed"],
  ["Submitted", "Unknown"],
  ["Submitted", "ReplanRequired"],
  ["Submitted", "ManualReview"],
  ["Unknown", "ConfirmedSpent"],
  ["Unknown", "Failed"],
  ["Unknown", "ReplanRequired"],
  ["Unknown", "ManualReview"],
  ["ManualReview", "ConfirmedSpent"],
  ["ManualReview", "Failed"],
  ["ManualReview", "Released"],
  ["ManualReview", "ReplanRequired"],
  ["Failed", "ReplanRequired"],
  ["Released", "Available"],
  ["ReplanRequired", "Reserved"],
  ["ReplanRequired", "Failed"],
  ["ReplanRequired", "ManualReview"]
]);

const expectedRejectedReservationTransitionsV3 = Object.freeze([
  ["Submitted", "Available"],
  ["Proving", "Released"],
  ["ProofReady", "Available"],
  ["ProofReady", "Released"],
  ["Unknown", "Available"],
  ["Unknown", "Submitted"],
  ["ManualReview", "Available"]
]);

const expectedLeaseRequiredTransitionsV3 = Object.freeze([
  ["Reserved", "Proving"],
  ["Proving", "ProofReady"],
  ["Proving", "Reserved"],
  ["Proving", "ReplanRequired"],
  ["Proving", "ManualReview"],
  ["ProofReady", "Submitted"],
  ["ProofReady", "Unknown"],
  ["ProofReady", "ReplanRequired"],
  ["ProofReady", "ManualReview"]
]);

const expectedExpiredLeaseRecoveryTransitionsV3 = Object.freeze([
  ["Proving", "ReplanRequired"],
  ["Proving", "ManualReview"],
  ["ProofReady", "ManualReview"]
]);

const expectedSuccessEvidenceV3 = Object.freeze([
  "matching_persisted_tx_identity",
  "expected_output_commitment",
  "expected_disclosure_digest",
  "expected_recipient_hash",
  "expected_amount_hash",
  "expected_denom",
  "batch_item_index",
  "batch_item_index_known"
]);

const expectedWriteOnceEvidenceV3 = Object.freeze([
  "payload_hash",
  "submitted_tx_hash",
  "tx_bytes_hash",
  "sign_doc_hash",
  "expected_output_commitment",
  "expected_disclosure_digest",
  "expected_recipient_hash",
  "expected_amount",
  "expected_amount_hash",
  "expected_denom",
  "batch_item_index",
  "batch_item_index_known",
  "operation_success_evidence_required"
]);

const requiredNoteReservationContractV3Fields = Object.freeze([
  "version",
  "fixture_migration",
  "active_reservation_statuses",
  "allowed_transitions",
  "rejected_transitions",
  "active_unique_key",
  "batch_reserve",
  "nullifier_lookup_key",
  "operation_hash_test_vectors",
  "operation_hash_rejection_vectors",
  "lease_transition_preconditions",
  "transition_evidence_preconditions",
  "manual_review_resolution",
  "relay_handoff",
  "initial_state_preconditions",
  "fail_closed_runtime_policy",
  "evidence_immutability",
  "spent_sibling_quarantine",
  "success_evidence_required",
  "batch_item_index_policy",
  "operation_identity_evidence",
  "operation_success_examples"
]);

function conformanceContractError(label, detail) {
  throw new Error(`note reservation contract v3 ${label}: ${detail}`);
}

function assertContractCondition(condition, label, detail) {
  if (!condition) conformanceContractError(label, detail);
}

function assertContractEqual(actual, expected, label) {
  assertContractCondition(
    actual === expected,
    label,
    `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`
  );
}

function contractRecord(value, label, { required = [], allowed = required } = {}) {
  assertContractCondition(
    Boolean(value) && typeof value === "object" && !Array.isArray(value),
    label,
    "expected an object"
  );
  for (const field of required) {
    assertContractCondition(
      Object.prototype.hasOwnProperty.call(value, field),
      label,
      `missing required field ${field}`
    );
  }
  if (allowed) {
    const allowedFields = new Set(allowed);
    const unexpected = Object.keys(value).filter(field => !allowedFields.has(field));
    assertContractCondition(
      unexpected.length === 0,
      label,
      `unexpected field ${JSON.stringify(unexpected[0])}`
    );
  }
  return value;
}

function contractArray(value, label, { nonEmpty = false } = {}) {
  assertContractCondition(Array.isArray(value), label, "expected an array");
  if (nonEmpty) assertContractCondition(value.length > 0, label, "expected at least one item");
  return value;
}

function contractString(value, label, { nonEmpty = false } = {}) {
  assertContractCondition(typeof value === "string", label, "expected a string");
  if (nonEmpty) assertContractCondition(value.trim().length > 0, label, "expected a non-empty string");
  return value;
}

function assertContractStringArray(actual, expected, label, { set = false } = {}) {
  const values = contractArray(actual, label).map((value, index) =>
    contractString(value, `${label}[${index}]`)
  );
  const normalizedActual = set ? [...values].sort() : values;
  const normalizedExpected = set ? [...expected].sort() : [...expected];
  assertContractEqual(normalizedActual.length, normalizedExpected.length, `${label} length`);
  for (const [index, expectedValue] of normalizedExpected.entries()) {
    assertContractEqual(normalizedActual[index], expectedValue, `${label}[${index}]`);
  }
}

function reservationTransitionKey(value, label) {
  const transition = contractArray(value, label);
  assertContractEqual(transition.length, 2, `${label} length`);
  return `${contractString(transition[0], `${label}[0]`)}\x00${contractString(transition[1], `${label}[1]`)}`;
}

function assertReservationTransitionSet(actual, expected, label) {
  const actualKeys = contractArray(actual, label).map((transition, index) =>
    reservationTransitionKey(transition, `${label}[${index}]`)
  ).sort();
  const expectedKeys = expected.map((transition, index) =>
    reservationTransitionKey(transition, `${label} expected[${index}]`)
  ).sort();
  assertContractStringArray(actualKeys, expectedKeys, label);
}

function assertContractVectorRejected(callback, label) {
  let rejected = false;
  try {
    callback();
  } catch {
    rejected = true;
  }
  assertContractCondition(rejected, label, "expected the rejection vector to be rejected");
}

function normalizedContractTxIdentity(value, label) {
  if (value === undefined) return "";
  const identity = contractString(value, label, { nonEmpty: true });
  return identity.trim().toLowerCase().replace(/^0x/u, "");
}

/**
 * Validate the complete language-neutral note-reservation v3 handoff contract.
 * This deliberately rejects v1/v2 and validates every normative set and vector
 * before the fixture is exposed to a conformance runner.
 */
export function validateNoteReservationContractV3(value) {
  const contract = contractRecord(value, "root", {
    required: requiredNoteReservationContractV3Fields,
    allowed: requiredNoteReservationContractV3Fields
  });
  assertContractEqual(contract.version, noteReservationContractVersionV3, "version");

  const migration = contractRecord(contract.fixture_migration, "fixture_migration", {
    required: ["from_version", "to_version", "downstream_action"]
  });
  assertContractEqual(migration.from_version, 1, "fixture_migration.from_version");
  assertContractEqual(migration.to_version, 3, "fixture_migration.to_version");
  contractString(migration.downstream_action, "fixture_migration.downstream_action", { nonEmpty: true });

  assertContractStringArray(
    contract.active_reservation_statuses,
    expectedActiveReservationStatusesV3,
    "active_reservation_statuses"
  );
  assertReservationTransitionSet(
    contract.allowed_transitions,
    expectedAllowedReservationTransitionsV3,
    "allowed_transitions"
  );
  assertReservationTransitionSet(
    contract.rejected_transitions,
    expectedRejectedReservationTransitionsV3,
    "rejected_transitions"
  );
  assertContractStringArray(
    contract.active_unique_key,
    ["owner_key_id", "nullifier_lookup_key"],
    "active_unique_key"
  );

  const batchReserve = contractRecord(contract.batch_reserve, "batch_reserve", {
    required: ["atomic", "error_policy", "lock_requirement"]
  });
  assertContractEqual(batchReserve.atomic, true, "batch_reserve.atomic");
  contractString(batchReserve.error_policy, "batch_reserve.error_policy", { nonEmpty: true });
  contractString(batchReserve.lock_requirement, "batch_reserve.lock_requirement", { nonEmpty: true });

  const lookup = contractRecord(contract.nullifier_lookup_key, "nullifier_lookup_key", {
    required: ["algorithm", "encoding", "key_version_field", "test_vectors"]
  });
  assertContractEqual(lookup.algorithm, "HMAC-SHA256", "nullifier_lookup_key.algorithm");
  assertContractEqual(lookup.encoding, "hex", "nullifier_lookup_key.encoding");
  assertContractEqual(lookup.key_version_field, "nullifier_lookup_key_id", "nullifier_lookup_key.key_version_field");
  for (const [index, rawVector] of contractArray(
    lookup.test_vectors,
    "nullifier_lookup_key.test_vectors",
    { nonEmpty: true }
  ).entries()) {
    const label = `nullifier_lookup_key.test_vectors[${index}]`;
    const vector = contractRecord(rawVector, label, {
      required: ["index_key_utf8", "nullifier_utf8", "lookup_key_hex"]
    });
    const indexKey = contractString(vector.index_key_utf8, `${label}.index_key_utf8`, { nonEmpty: true });
    const nullifier = contractString(vector.nullifier_utf8, `${label}.nullifier_utf8`, { nonEmpty: true });
    assertContractEqual(
      vector.lookup_key_hex,
      nullifierLookupKey(indexKey, nullifier),
      `${label}.lookup_key_hex`
    );
  }

  for (const [index, rawVector] of contractArray(
    contract.operation_hash_test_vectors,
    "operation_hash_test_vectors",
    { nonEmpty: true }
  ).entries()) {
    const label = `operation_hash_test_vectors[${index}]`;
    const vector = contractRecord(rawVector, label, {
      required: ["recipient", "recipient_hash", "denom", "amount", "amount_hash"]
    });
    assertContractEqual(hashRecipient(vector.recipient), vector.recipient_hash, `${label}.recipient_hash`);
    assertContractEqual(hashAmount(vector.denom, vector.amount), vector.amount_hash, `${label}.amount_hash`);
  }

  for (const [index, rawVector] of contractArray(
    contract.operation_hash_rejection_vectors,
    "operation_hash_rejection_vectors",
    { nonEmpty: true }
  ).entries()) {
    const label = `operation_hash_rejection_vectors[${index}]`;
    const vector = contractRecord(rawVector, label, {
      required: ["name", "recipient", "denom", "amount", "reject_hash"]
    });
    contractString(vector.name, `${label}.name`, { nonEmpty: true });
    contractString(vector.recipient, `${label}.recipient`);
    contractString(vector.denom, `${label}.denom`);
    contractString(vector.amount, `${label}.amount`);
    assertContractCondition(
      vector.reject_hash === "recipient" || vector.reject_hash === "amount",
      `${label}.reject_hash`,
      "expected recipient or amount"
    );
    assertContractVectorRejected(
      () => vector.reject_hash === "recipient"
        ? hashRecipient(vector.recipient)
        : hashAmount(vector.denom, vector.amount),
      label
    );
  }

  const lease = contractRecord(contract.lease_transition_preconditions, "lease_transition_preconditions", {
    required: ["token_required_for", "recovery_without_token_after_expiry_for", "fields", "policy"]
  });
  assertReservationTransitionSet(
    lease.token_required_for,
    expectedLeaseRequiredTransitionsV3,
    "lease_transition_preconditions.token_required_for"
  );
  assertReservationTransitionSet(
    lease.recovery_without_token_after_expiry_for,
    expectedExpiredLeaseRecoveryTransitionsV3,
    "lease_transition_preconditions.recovery_without_token_after_expiry_for"
  );
  assertContractStringArray(
    lease.fields,
    ["lease_owner", "lease_token", "lease_until", "last_heartbeat_at"],
    "lease_transition_preconditions.fields"
  );
  contractString(lease.policy, "lease_transition_preconditions.policy", { nonEmpty: true });

  const expectedTransitionEvidence = [
    {
      name: "proof discard before replan",
      transition: ["ProofReady", "ReplanRequired"],
      required: ["no_broadcast_attempt", "proof_discarded"],
      positive: { no_broadcast_attempt: true, proof_discarded: true },
      negative: { no_broadcast_attempt: true, proof_discarded: false }
    },
    {
      name: "post-broadcast replan or failure",
      transition: ["Submitted", "ReplanRequired"],
      required: ["nullifier_unspent_confirmed", "tx_absent_or_failed_confirmed"],
      positive: { nullifier_unspent_confirmed: true, tx_absent_or_failed_confirmed: true },
      negative: { nullifier_unspent_confirmed: true, tx_absent_or_failed_confirmed: false }
    }
  ];
  const transitionEvidence = contractArray(
    contract.transition_evidence_preconditions,
    "transition_evidence_preconditions"
  );
  assertContractEqual(transitionEvidence.length, expectedTransitionEvidence.length, "transition_evidence_preconditions length");
  for (const [index, expected] of expectedTransitionEvidence.entries()) {
    const label = `transition_evidence_preconditions[${index}]`;
    const vector = contractRecord(transitionEvidence[index], label, {
      required: ["name", "transition", "required_evidence", "positive", "negative"]
    });
    assertContractEqual(vector.name, expected.name, `${label}.name`);
    assertContractEqual(
      reservationTransitionKey(vector.transition, `${label}.transition`),
      reservationTransitionKey(expected.transition, `${label}.expected_transition`),
      `${label}.transition`
    );
    assertContractStringArray(vector.required_evidence, expected.required, `${label}.required_evidence`);
    for (const polarity of ["positive", "negative"]) {
      const evidence = contractRecord(vector[polarity], `${label}.${polarity}`, {
        required: expected.required
      });
      for (const field of expected.required) {
        assertContractEqual(evidence[field], expected[polarity][field], `${label}.${polarity}.${field}`);
      }
    }
  }

  const manualReview = contractRecord(contract.manual_review_resolution, "manual_review_resolution", {
    required: ["required_evidence", "positive", "negative"]
  });
  const manualReviewFields = ["operator_approved", "operator_id", "operator_approval_reference"];
  assertContractStringArray(manualReview.required_evidence, manualReviewFields, "manual_review_resolution.required_evidence");
  const manualPositive = contractRecord(manualReview.positive, "manual_review_resolution.positive", {
    required: manualReviewFields
  });
  const manualNegative = contractRecord(manualReview.negative, "manual_review_resolution.negative", {
    required: manualReviewFields
  });
  assertContractEqual(manualPositive.operator_approved, true, "manual_review_resolution.positive.operator_approved");
  contractString(manualPositive.operator_id, "manual_review_resolution.positive.operator_id", { nonEmpty: true });
  contractString(manualPositive.operator_approval_reference, "manual_review_resolution.positive.operator_approval_reference", { nonEmpty: true });
  assertContractEqual(manualNegative.operator_approved, true, "manual_review_resolution.negative.operator_approved");
  assertContractEqual(manualNegative.operator_id, "", "manual_review_resolution.negative.operator_id");
  contractString(manualNegative.operator_approval_reference, "manual_review_resolution.negative.operator_approval_reference");

  const relay = contractRecord(contract.relay_handoff, "relay_handoff", {
    required: ["status", "lease_must_remain", "record_requires", "proof_discard_after_handoff", "write_once_evidence", "positive", "negative", "negative_vectors"]
  });
  assertContractEqual(relay.status, "ProofReady", "relay_handoff.status");
  assertContractEqual(relay.lease_must_remain, true, "relay_handoff.lease_must_remain");
  assertContractStringArray(relay.record_requires, ["ProofReady", "lease_owner", "lease_token", "payload_hash_matches"], "relay_handoff.record_requires");
  assertContractEqual(relay.proof_discard_after_handoff, "reject", "relay_handoff.proof_discard_after_handoff");
  assertContractStringArray(relay.write_once_evidence, ["payload_hash", "relay_handed_off", "relay_handed_off_at"], "relay_handoff.write_once_evidence");
  const relayEvidenceFields = ["relay_handed_off", "lease_owner_present", "lease_token_present", "payload_hash_matches"];
  const relayPositive = contractRecord(relay.positive, "relay_handoff.positive", { required: relayEvidenceFields });
  const relayNegative = contractRecord(relay.negative, "relay_handoff.negative", { required: relayEvidenceFields });
  for (const field of relayEvidenceFields) {
    assertContractEqual(relayPositive[field], true, `relay_handoff.positive.${field}`);
  }
  assertContractEqual(relayNegative.relay_handed_off, true, "relay_handoff.negative.relay_handed_off");
  for (const field of ["lease_owner_present", "lease_token_present", "payload_hash_matches"]) {
    assertContractEqual(relayNegative[field], false, `relay_handoff.negative.${field}`);
  }
  const expectedRelayNegativeVectors = [
    ["payload_hash_mismatch", false, true, true],
    ["mixed_reservation_status", true, false, true],
    ["partial_operation_reservation_set", true, true, false]
  ];
  const relayNegativeVectors = contractArray(relay.negative_vectors, "relay_handoff.negative_vectors");
  assertContractEqual(relayNegativeVectors.length, 3, "relay_handoff.negative_vectors length");
  for (const [index, expected] of expectedRelayNegativeVectors.entries()) {
    const label = `relay_handoff.negative_vectors[${index}]`;
    const vector = contractRecord(relayNegativeVectors[index], label, {
      required: ["name", "payload_hash_matches", "all_reservations_proof_ready", "operation_reservation_set_exact"]
    });
    assertContractEqual(vector.name, expected[0], `${label}.name`);
    assertContractEqual(vector.payload_hash_matches, expected[1], `${label}.payload_hash_matches`);
    assertContractEqual(vector.all_reservations_proof_ready, expected[2], `${label}.all_reservations_proof_ready`);
    assertContractEqual(vector.operation_reservation_set_exact, expected[3], `${label}.operation_reservation_set_exact`);
  }

  const initial = contractRecord(contract.initial_state_preconditions, "initial_state_preconditions", {
    required: ["reservation_status", "operation_status", "forbidden_reservation_evidence", "forbidden_operation_evidence", "positive", "negative"]
  });
  assertContractEqual(initial.reservation_status, "Reserved", "initial_state_preconditions.reservation_status");
  assertContractEqual(initial.operation_status, "Planned", "initial_state_preconditions.operation_status");
  assertContractStringArray(initial.forbidden_reservation_evidence, ["lease", "payload_hash", "broadcast", "relay_handoff", "manual_review"], "initial_state_preconditions.forbidden_reservation_evidence");
  assertContractStringArray(initial.forbidden_operation_evidence, ["payload_hash", "tx_identity"], "initial_state_preconditions.forbidden_operation_evidence");
  const initialFields = ["reservation_clean", "operation_clean"];
  const initialPositive = contractRecord(initial.positive, "initial_state_preconditions.positive", { required: initialFields });
  const initialNegative = contractRecord(initial.negative, "initial_state_preconditions.negative", { required: initialFields });
  for (const field of initialFields) {
    assertContractEqual(initialPositive[field], true, `initial_state_preconditions.positive.${field}`);
    assertContractEqual(initialNegative[field], false, `initial_state_preconditions.negative.${field}`);
  }

  const runtime = contractRecord(contract.fail_closed_runtime_policy, "fail_closed_runtime_policy", {
    required: ["nullifier_spent_evidence", "relay_submission", "heartbeat", "broadcast_boundary"]
  });
  const nullifierEvidence = contractRecord(runtime.nullifier_spent_evidence, "fail_closed_runtime_policy.nullifier_spent_evidence", {
    required: ["spent_value", "unspent_value", "other_values"]
  });
  assertContractEqual(nullifierEvidence.spent_value, true, "fail_closed_runtime_policy.nullifier_spent_evidence.spent_value");
  assertContractEqual(nullifierEvidence.unspent_value, false, "fail_closed_runtime_policy.nullifier_spent_evidence.unspent_value");
  assertContractEqual(nullifierEvidence.other_values, "unknown_excluded_from_spending", "fail_closed_runtime_policy.nullifier_spent_evidence.other_values");
  const relaySubmission = contractRecord(runtime.relay_submission, "fail_closed_runtime_policy.relay_submission", {
    required: ["chain_time_source", "chain_time_required", "recheck_immediately_before_broadcast", "on_unavailable"]
  });
  assertContractEqual(relaySubmission.chain_time_source, "latest_chain_block_time", "fail_closed_runtime_policy.relay_submission.chain_time_source");
  assertContractEqual(relaySubmission.chain_time_required, true, "fail_closed_runtime_policy.relay_submission.chain_time_required");
  assertContractEqual(relaySubmission.recheck_immediately_before_broadcast, true, "fail_closed_runtime_policy.relay_submission.recheck_immediately_before_broadcast");
  assertContractEqual(relaySubmission.on_unavailable, "reject_submit", "fail_closed_runtime_policy.relay_submission.on_unavailable");
  const heartbeat = contractRecord(runtime.heartbeat, "fail_closed_runtime_policy.heartbeat", {
    required: ["coverage", "await_in_flight_before_stop"]
  });
  assertContractStringArray(heartbeat.coverage, ["proof_generation", "transaction_or_sign_doc_build", "proof_ready_transition"], "fail_closed_runtime_policy.heartbeat.coverage");
  assertContractEqual(heartbeat.await_in_flight_before_stop, true, "fail_closed_runtime_policy.heartbeat.await_in_flight_before_stop");
  const broadcastBoundary = contractRecord(runtime.broadcast_boundary, "fail_closed_runtime_policy.broadcast_boundary", {
    required: ["durable_attempt_before_external_call", "retry_blocked_until_reconciled"]
  });
  assertContractEqual(broadcastBoundary.durable_attempt_before_external_call, true, "fail_closed_runtime_policy.broadcast_boundary.durable_attempt_before_external_call");
  assertContractEqual(broadcastBoundary.retry_blocked_until_reconciled, true, "fail_closed_runtime_policy.broadcast_boundary.retry_blocked_until_reconciled");

  const immutability = contractRecord(contract.evidence_immutability, "evidence_immutability", {
    required: ["write_once_fields", "monotonic_fields", "negative", "mutation_rejection_vectors"]
  });
  assertContractStringArray(immutability.write_once_fields, expectedWriteOnceEvidenceV3, "evidence_immutability.write_once_fields");
  assertContractStringArray(immutability.monotonic_fields, ["broadcast_attempt_count"], "evidence_immutability.monotonic_fields");
  const immutableNegative = contractRecord(immutability.negative, "evidence_immutability.negative", {
    required: ["submitted_tx_hash"]
  });
  assertContractEqual(immutableNegative.submitted_tx_hash, "", "evidence_immutability.negative.submitted_tx_hash");
  const mutationVectors = contractArray(immutability.mutation_rejection_vectors, "evidence_immutability.mutation_rejection_vectors");
  assertContractStringArray(mutationVectors.map(vector => vector?.field), expectedWriteOnceEvidenceV3, "evidence_immutability.mutation_rejection_vectors fields");
  for (const [index, rawVector] of mutationVectors.entries()) {
    const label = `evidence_immutability.mutation_rejection_vectors[${index}]`;
    const vector = contractRecord(rawVector, label, {
      required: ["field", "original", "mutation"]
    });
    assertContractCondition(
      JSON.stringify(vector.original) !== JSON.stringify(vector.mutation),
      label,
      "original and mutation must differ"
    );
  }

  const sibling = contractRecord(contract.spent_sibling_quarantine, "spent_sibling_quarantine", {
    required: ["match_fields", "target_status", "positive", "negative"]
  });
  assertContractStringArray(sibling.match_fields, ["owner_key_id", "nullifier_lookup_key"], "spent_sibling_quarantine.match_fields");
  assertContractEqual(sibling.target_status, "ConfirmedSpent", "spent_sibling_quarantine.target_status");
  const siblingFields = ["matching_siblings", "confirmed_spent"];
  const siblingPositive = contractRecord(sibling.positive, "spent_sibling_quarantine.positive", { required: siblingFields });
  const siblingNegative = contractRecord(sibling.negative, "spent_sibling_quarantine.negative", { required: siblingFields });
  for (const [label, evidence] of [["positive", siblingPositive], ["negative", siblingNegative]]) {
    for (const field of siblingFields) {
      assertContractCondition(
        Number.isSafeInteger(evidence[field]) && evidence[field] >= (label === "positive" || field === "matching_siblings" ? 1 : 0),
        `spent_sibling_quarantine.${label}.${field}`,
        "expected a safe integer within the schema minimum"
      );
    }
  }
  assertContractEqual(siblingPositive.confirmed_spent, siblingPositive.matching_siblings, "spent_sibling_quarantine positive quarantine");
  assertContractCondition(siblingNegative.confirmed_spent < siblingNegative.matching_siblings, "spent_sibling_quarantine negative quarantine", "expected incomplete sibling quarantine");

  assertContractStringArray(contract.success_evidence_required, expectedSuccessEvidenceV3, "success_evidence_required");
  contractString(contract.batch_item_index_policy, "batch_item_index_policy", { nonEmpty: true });

  const identityEvidence = contractRecord(contract.operation_identity_evidence, "operation_identity_evidence", {
    required: ["required", "vectors"]
  });
  assertContractEqual(identityEvidence.required, "matching_persisted_tx_identity", "operation_identity_evidence.required");
  const expectedIdentityVectorNames = [
    "bare successful result is insufficient",
    "mismatched identity is conflict",
    "matching identity succeeds",
    "case and prefix normalized identity succeeds",
    "matching tx bytes identity succeeds",
    "unexpected tx hash conflicts with stored tx bytes identity",
    "tx hash does not match tx bytes field",
    "sign doc alone is not chain identity",
    "sign doc mismatch conflicts with matching tx identity"
  ];
  const identityVectors = contractArray(identityEvidence.vectors, "operation_identity_evidence.vectors");
  assertContractStringArray(identityVectors.map(vector => vector?.name), expectedIdentityVectorNames, "operation_identity_evidence vector names", { set: true });
  for (const [index, rawVector] of identityVectors.entries()) {
    const label = `operation_identity_evidence.vectors[${index}]`;
    const vector = contractRecord(rawVector, label, {
      required: ["name", "tx_result", "operation_status"],
      allowed: ["name", "stored_tx_hash", "stored_tx_bytes_hash", "stored_sign_doc_hash", "tx_result", "operation_status"]
    });
    contractString(vector.name, `${label}.name`, { nonEmpty: true });
    const txResult = contractRecord(vector.tx_result, `${label}.tx_result`, {
      required: ["code"],
      allowed: ["code", "txhash", "tx_bytes_hash", "sign_doc_hash"]
    });
    assertContractCondition(
      Number.isSafeInteger(txResult.code) && txResult.code >= 0,
      `${label}.tx_result.code`,
      "expected a non-negative safe integer"
    );
    const storedTxHash = normalizedContractTxIdentity(vector.stored_tx_hash, `${label}.stored_tx_hash`);
    const storedTxBytesHash = normalizedContractTxIdentity(vector.stored_tx_bytes_hash, `${label}.stored_tx_bytes_hash`);
    const storedSignDocHash = normalizedContractTxIdentity(vector.stored_sign_doc_hash, `${label}.stored_sign_doc_hash`);
    const actualTxHash = normalizedContractTxIdentity(txResult.txhash, `${label}.tx_result.txhash`);
    const actualTxBytesHash = normalizedContractTxIdentity(txResult.tx_bytes_hash, `${label}.tx_result.tx_bytes_hash`);
    const actualSignDocHash = normalizedContractTxIdentity(txResult.sign_doc_hash, `${label}.tx_result.sign_doc_hash`);
    assertContractCondition(Boolean(storedTxHash || storedTxBytesHash), label, "stored_tx_hash or stored_tx_bytes_hash is required");
    const sameFieldMismatch =
      (Boolean(actualTxHash) && actualTxHash !== storedTxHash) ||
      (Boolean(actualTxBytesHash) && actualTxBytesHash !== storedTxBytesHash) ||
      (Boolean(storedSignDocHash) && Boolean(actualSignDocHash) && actualSignDocHash !== storedSignDocHash);
    const matched = txResult.code === 0 && !sameFieldMismatch && (
      (Boolean(actualTxHash) && actualTxHash === storedTxHash) ||
      (Boolean(storedTxBytesHash) && actualTxBytesHash === storedTxBytesHash)
    );
    assertContractEqual(vector.operation_status, matched ? "Succeeded" : "ConflictSpent", `${label}.operation_status`);
  }

  const successExamples = contractArray(contract.operation_success_examples, "operation_success_examples");
  assertContractEqual(successExamples.length, 2, "operation_success_examples length");
  let matchingExample = null;
  let conflictExample = null;
  for (const [index, rawExample] of successExamples.entries()) {
    const label = `operation_success_examples[${index}]`;
    const example = contractRecord(rawExample, label, {
      required: ["name", "nullifier_spent", "evidence_matches_expected_values", "note_status", "operation_status"]
    });
    contractString(example.name, `${label}.name`, { nonEmpty: true });
    assertContractEqual(example.nullifier_spent, true, `${label}.nullifier_spent`);
    assertContractCondition(typeof example.evidence_matches_expected_values === "boolean", `${label}.evidence_matches_expected_values`, "expected a boolean");
    if (example.evidence_matches_expected_values) matchingExample = example;
    else conflictExample = example;
  }
  assertContractCondition(Boolean(matchingExample), "operation_success_examples", "missing matching-evidence example");
  assertContractCondition(Boolean(conflictExample), "operation_success_examples", "missing conflicting-evidence example");
  assertContractEqual(matchingExample.note_status, "ConfirmedSpent", "operation_success_examples matching note_status");
  assertContractEqual(matchingExample.operation_status, "Succeeded", "operation_success_examples matching operation_status");
  assertContractEqual(conflictExample.note_status, "ConfirmedSpent", "operation_success_examples conflict note_status");
  assertContractEqual(conflictExample.operation_status, "ConflictSpent", "operation_success_examples conflict operation_status");

  return contract;
}

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));

export const defaultConformanceFixtureNames = Object.freeze([
  "privacy_wallet_golden_vectors.json",
  "privacy_browser_signer_provider_contract.json",
  "privacy_wallet_readonly_reference_bundle.json",
  "privacy_prover_example_bundle.json",
  "privacy_prover_http_api_contract.json",
  "privacy_send_capable_reference_flow.json",
  "privacy_batch_joinsplit_v1_contract.json",
  "privacy_note_v1_contract.json",
  "privacy_disclosure_blinding_v1_contract.json",
  batchTransferConformanceFixtureName,
  noteReservationConformanceFixtureName,
  "privacy_relay_withdraw_contract.json"
]);

function resolveConformanceFixturePath(fixtureDir, name) {
  return join(fixtureDir, name);
}

export function suggestClairveilConformanceFixtureDirs({ cwd = process.cwd() } = {}) {
  return [
    resolve(packageRoot, defaultConformanceFixtureDir),
    resolve(cwd, defaultConformanceFixtureDir),
    resolve(cwd, conformanceFixtureRelativePath)
  ];
}

export function resolveClairveilConformanceFixtureDir({ fixtureDir } = {}) {
  if (fixtureDir) return fixtureDir;
  if (process.env.CLAIRVEIL_CONFORMANCE_FIXTURE_DIR) {
    return process.env.CLAIRVEIL_CONFORMANCE_FIXTURE_DIR;
  }
  const candidates = suggestClairveilConformanceFixtureDirs();
  return candidates.find(candidate => existsSync(candidate)) || candidates[0];
}

export function clairveilConformanceFixturesAvailable(options = {}) {
  return existsSync(resolveClairveilConformanceFixtureDir(options));
}

export function clairveilConformanceFixtureSkipReason(options = {}) {
  const fixtureDir = resolveClairveilConformanceFixtureDir(options);
  if (existsSync(fixtureDir)) return "";
  return `Bundled Clairveil commit snapshot ${supportedClairveilCommit} conformance fixtures not found at ${fixtureDir}. Set CLAIRVEIL_CONFORMANCE_FIXTURE_DIR only when intentionally testing another fixture directory.`;
}

export function readClairveilConformanceFixture(name, options = {}) {
  const fixtureDir = resolveClairveilConformanceFixtureDir(options);
  if (!existsSync(fixtureDir)) {
    throw new Error(clairveilConformanceFixtureSkipReason({ ...options, fixtureDir }));
  }
  const fixture = JSON.parse(
    readFileSync(resolveConformanceFixturePath(fixtureDir, name), "utf8")
  );
  return name === noteReservationConformanceFixtureName
    ? validateNoteReservationContractV3(fixture)
    : fixture;
}

export function loadClairveilConformanceFixtures(options = {}) {
  const fixtureNames = options.fixtureNames || options.fixtures || defaultConformanceFixtureNames;
  const loaded = {};
  for (const name of fixtureNames) {
    loaded[name] = readClairveilConformanceFixture(name, options);
  }
  return loaded;
}

export async function runClairveilConformanceFixtures(options = {}, runner) {
  const required = Boolean(options.required ?? process.env.CLAIRVEIL_CONFORMANCE_REQUIRED === "1");
  const fixtureDir = resolveClairveilConformanceFixtureDir(options);
  const reason = clairveilConformanceFixtureSkipReason({ ...options, fixtureDir });
  if (reason) {
    if (required) throw new Error(reason);
    return {
      skipped: true,
      reason,
      fixtureDir,
      fixtures: {}
    };
  }

  const fixtures = loadClairveilConformanceFixtures({ ...options, fixtureDir });
  const callback = runner || options.runner || options.test;
  const result = typeof callback === "function"
    ? await callback(fixtures, { fixtureDir })
    : undefined;
  return {
    skipped: false,
    reason: "",
    fixtureDir,
    fixtures,
    result
  };
}
