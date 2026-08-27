export const conformanceFixtureRelativePath: string;
export const defaultConformanceFixtureDir: string;
export const clairveilConformanceBundleVersion: "v0.3.1";
export const supportedClairveilSourceKind: "commit_snapshot";
export const supportedClairveilCommit: "621c24a3ef1118b6ab2b8b780ab00da6fbc00e1b";
export const defaultConformanceFixtureNames: readonly string[];
export const batchTransferConformanceFixtureName: string;
export const noteReservationConformanceFixtureName: "privacy_note_reservation_contract.json";
export const noteReservationContractVersionV3: 3;

export type NoteReservationStatusV3 =
  | "Discovered"
  | "Available"
  | "Reserved"
  | "Proving"
  | "ProofReady"
  | "Submitted"
  | "Unknown"
  | "ManualReview"
  | "ConfirmedSpent"
  | "Failed"
  | "Released"
  | "ReplanRequired";

export type NoteReservationTransitionV3 = [NoteReservationStatusV3, NoteReservationStatusV3];

export interface NoteReservationOperationIdentityVectorV3 {
  name: string;
  stored_tx_hash?: string;
  stored_tx_bytes_hash?: string;
  stored_sign_doc_hash?: string;
  tx_result: {
    code: number;
    txhash?: string;
    tx_bytes_hash?: string;
    sign_doc_hash?: string;
  };
  operation_status: "Succeeded" | "ConflictSpent";
}

export interface NoteReservationContractV3 {
  version: 3;
  fixture_migration: {
    from_version: 1;
    to_version: 3;
    downstream_action: string;
  };
  active_reservation_statuses: NoteReservationStatusV3[];
  allowed_transitions: NoteReservationTransitionV3[];
  rejected_transitions: NoteReservationTransitionV3[];
  active_unique_key: string[];
  batch_reserve: {
    atomic: true;
    error_policy: string;
    lock_requirement: string;
  };
  nullifier_lookup_key: {
    algorithm: "HMAC-SHA256";
    encoding: "hex";
    key_version_field: "nullifier_lookup_key_id";
    test_vectors: Array<{
      index_key_utf8: string;
      nullifier_utf8: string;
      lookup_key_hex: string;
    }>;
  };
  operation_hash_test_vectors: Array<{
    recipient: string;
    recipient_hash: string;
    denom: string;
    amount: string;
    amount_hash: string;
  }>;
  operation_hash_rejection_vectors: Array<{
    name: string;
    recipient: string;
    denom: string;
    amount: string;
    reject_hash: "recipient" | "amount";
  }>;
  lease_transition_preconditions: {
    token_required_for: NoteReservationTransitionV3[];
    recovery_without_token_after_expiry_for: NoteReservationTransitionV3[];
    fields: string[];
    policy: string;
  };
  transition_evidence_preconditions: Array<{
    name: string;
    transition: NoteReservationTransitionV3;
    required_evidence: string[];
    positive: Record<string, boolean>;
    negative: Record<string, boolean>;
  }>;
  manual_review_resolution: {
    required_evidence: string[];
    positive: {
      operator_approved: true;
      operator_id: string;
      operator_approval_reference: string;
    };
    negative: {
      operator_approved: true;
      operator_id: string;
      operator_approval_reference: string;
    };
  };
  relay_handoff: {
    status: "ProofReady";
    lease_must_remain: true;
    record_requires: string[];
    proof_discard_after_handoff: "reject";
    write_once_evidence: string[];
    positive: {
      relay_handed_off: true;
      lease_owner_present: true;
      lease_token_present: true;
      payload_hash_matches: true;
    };
    negative: {
      relay_handed_off: true;
      lease_owner_present: false;
      lease_token_present: false;
      payload_hash_matches: false;
    };
    negative_vectors: Array<{
      name: string;
      payload_hash_matches: boolean;
      all_reservations_proof_ready: boolean;
      operation_reservation_set_exact: boolean;
    }>;
  };
  initial_state_preconditions: {
    reservation_status: "Reserved";
    operation_status: "Planned";
    forbidden_reservation_evidence: string[];
    forbidden_operation_evidence: string[];
    positive: { reservation_clean: true; operation_clean: true };
    negative: { reservation_clean: false; operation_clean: false };
  };
  fail_closed_runtime_policy: {
    nullifier_spent_evidence: {
      spent_value: true;
      unspent_value: false;
      other_values: "unknown_excluded_from_spending";
    };
    relay_submission: {
      chain_time_source: "latest_chain_block_time";
      chain_time_required: true;
      recheck_immediately_before_broadcast: true;
      on_unavailable: "reject_submit";
    };
    heartbeat: {
      coverage: string[];
      await_in_flight_before_stop: true;
    };
    broadcast_boundary: {
      durable_attempt_before_external_call: true;
      retry_blocked_until_reconciled: true;
    };
  };
  evidence_immutability: {
    write_once_fields: string[];
    monotonic_fields: string[];
    negative: { submitted_tx_hash: "" };
    mutation_rejection_vectors: Array<{
      field: string;
      original: unknown;
      mutation: unknown;
    }>;
  };
  spent_sibling_quarantine: {
    match_fields: string[];
    target_status: "ConfirmedSpent";
    positive: { matching_siblings: number; confirmed_spent: number };
    negative: { matching_siblings: number; confirmed_spent: number };
  };
  success_evidence_required: string[];
  batch_item_index_policy: string;
  operation_identity_evidence: {
    required: "matching_persisted_tx_identity";
    vectors: NoteReservationOperationIdentityVectorV3[];
  };
  operation_success_examples: Array<{
    name: string;
    nullifier_spent: true;
    evidence_matches_expected_values: boolean;
    note_status: "ConfirmedSpent";
    operation_status: "Succeeded" | "ConflictSpent";
  }>;
}

export interface ClairveilConformanceFixtureOptions {
  fixtureDir?: string;
  fixtureNames?: string[];
  fixtures?: string[];
  required?: boolean;
  runner?: ClairveilConformanceFixtureRunner;
  test?: ClairveilConformanceFixtureRunner;
}

export type ClairveilConformanceFixtureMap = Record<string, object>;

export type ClairveilConformanceFixtureRunner = (
  fixtures: ClairveilConformanceFixtureMap,
  context: { fixtureDir: string }
) => unknown | Promise<unknown>;

export interface ClairveilConformanceRunResult {
  skipped: boolean;
  reason: string;
  fixtureDir: string;
  fixtures: ClairveilConformanceFixtureMap;
  result?: unknown;
}

export function validateNoteReservationContractV3(value: unknown): NoteReservationContractV3;
export function resolveClairveilConformanceFixtureDir(options?: ClairveilConformanceFixtureOptions): string;
export function suggestClairveilConformanceFixtureDirs(options?: { cwd?: string }): string[];
export function clairveilConformanceFixturesAvailable(options?: ClairveilConformanceFixtureOptions): boolean;
export function clairveilConformanceFixtureSkipReason(options?: ClairveilConformanceFixtureOptions): string;
export function readClairveilConformanceFixture(
  name: typeof noteReservationConformanceFixtureName,
  options?: ClairveilConformanceFixtureOptions
): NoteReservationContractV3;
export function readClairveilConformanceFixture(name: string, options?: ClairveilConformanceFixtureOptions): object;
export function loadClairveilConformanceFixtures(options?: ClairveilConformanceFixtureOptions): ClairveilConformanceFixtureMap;
export function runClairveilConformanceFixtures(
  options?: ClairveilConformanceFixtureOptions,
  runner?: ClairveilConformanceFixtureRunner
): Promise<ClairveilConformanceRunResult>;
