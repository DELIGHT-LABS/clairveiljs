import type { BytesLike, Hex } from "../core/crypto.js";
import type { FoundNote } from "../core/note.js";
import type { TransferBatchPlan, TransferPlan, WithdrawPlan } from "./planner.js";

export declare const reservationStatuses: Readonly<{
  Discovered: "Discovered";
  Available: "Available";
  Reserved: "Reserved";
  Proving: "Proving";
  ProofReady: "ProofReady";
  Submitted: "Submitted";
  ConfirmedSpent: "ConfirmedSpent";
  Failed: "Failed";
  ReplanRequired: "ReplanRequired";
  Released: "Released";
  Unknown: "Unknown";
  ManualReview: "ManualReview";
}>;

export declare const operationStatuses: Readonly<{
  Planned: "Planned";
  Proving: "Proving";
  ProofReady: "ProofReady";
  Submitted: "Submitted";
  Succeeded: "Succeeded";
  Failed: "Failed";
  ReplanRequired: "ReplanRequired";
  Unknown: "Unknown";
  ManualReview: "ManualReview";
  ConflictSpent: "ConflictSpent";
}>;

export type ReservationStatus = typeof reservationStatuses[keyof typeof reservationStatuses];
export type OperationStatus = typeof operationStatuses[keyof typeof operationStatuses];
export type ReservationMetadataValue =
  | string
  | number
  | boolean
  | null
  | readonly ReservationMetadataValue[]
  | { readonly [key: string]: ReservationMetadataValue };
export type ReservationMetadata = Record<string, ReservationMetadataValue>;

export declare const activeReservationStatuses: readonly ReservationStatus[];

export interface NoteReservationRecord {
  reservation_id: string;
  operation_id: string;
  owner_key_id: string;
  nullifier_lookup_key: string;
  nullifier_lookup_key_id: string;
  status: ReservationStatus | string;
  lease_owner: string;
  lease_token: string;
  lease_until: string;
  last_heartbeat_at: string;
  kind: string;
  note_id: string;
  amount: string;
  tx_hash: string;
  height: number | string;
  sequence: number | string;
  payload_hash: string;
  expected_output_commitment: string;
  expected_disclosure_digest: string;
  expected_recipient_hash: string;
  expected_amount: string;
  expected_amount_hash: string;
  expected_denom: string;
  batch_item_index: number;
  batch_item_index_known: boolean;
  sign_doc_hash: string;
  tx_bytes_hash: string;
  submitted_tx_hash: string;
  broadcast_attempt_count: number;
  broadcast_in_flight: boolean;
  last_broadcast_error: string;
  created_at: string;
  updated_at: string;
  metadata: ReservationMetadata;
}

type InitialReservationID =
  | { reservation_id: string; reservationID?: string; reservationId?: string }
  | { reservation_id?: string; reservationID: string; reservationId?: string }
  | { reservation_id?: string; reservationID?: string; reservationId: string };

type InitialReservationOwnerKeyID =
  | { owner_key_id: string; ownerKeyID?: string; ownerKeyId?: string }
  | { owner_key_id?: string; ownerKeyID: string; ownerKeyId?: string }
  | { owner_key_id?: string; ownerKeyID?: string; ownerKeyId: string };

type InitialReservationLookupKey =
  | { nullifier_lookup_key: string; nullifierLookupKey?: string }
  | { nullifier_lookup_key?: string; nullifierLookupKey: string };

/** Normal creation accepts only a clean Reserved record with its runtime-required identity; import fixtures through unsafe APIs. */
export type InitialNoteReservationRecord = Omit<Partial<NoteReservationRecord>,
  | "reservation_id"
  | "owner_key_id"
  | "nullifier_lookup_key"
  | "status"
  | "lease_owner"
  | "lease_token"
  | "lease_until"
  | "last_heartbeat_at"
  | "payload_hash"
  | "expected_output_commitment"
  | "expected_disclosure_digest"
  | "expected_recipient_hash"
  | "expected_amount"
  | "expected_amount_hash"
  | "expected_denom"
  | "batch_item_index"
  | "batch_item_index_known"
  | "sign_doc_hash"
  | "tx_bytes_hash"
  | "submitted_tx_hash"
  | "broadcast_attempt_count"
  | "broadcast_in_flight"
  | "last_broadcast_error"
> & InitialReservationID & InitialReservationOwnerKeyID & InitialReservationLookupKey & {
  status?: "Reserved";
  lease_owner?: never;
  lease_token?: never;
  lease_until?: never;
  last_heartbeat_at?: never;
  payload_hash?: never;
  payloadHash?: never;
  expected_output_commitment?: never;
  expectedOutputCommitment?: never;
  expected_disclosure_digest?: never;
  expectedDisclosureDigest?: never;
  expected_recipient_hash?: never;
  expectedRecipientHash?: never;
  expected_amount?: never;
  expectedAmount?: never;
  expected_amount_hash?: never;
  expectedAmountHash?: never;
  expected_denom?: never;
  expectedDenom?: never;
  batch_item_index?: never;
  batchItemIndex?: never;
  batch_item_index_known?: never;
  batchItemIndexKnown?: never;
  operation_success_evidence_required?: never;
  operationSuccessEvidenceRequired?: never;
  sign_doc_hash?: never;
  signDocHash?: never;
  tx_bytes_hash?: never;
  txBytesHash?: never;
  submitted_tx_hash?: never;
  submittedTxHash?: never;
  broadcast_attempt_count?: never;
  broadcastAttemptCount?: never;
  broadcast_in_flight?: never;
  broadcastInFlight?: never;
  last_broadcast_error?: never;
  lastBroadcastError?: never;
};

export type SpentNoteEvidence = (object | FoundNote) & (
  { spent: true } |
  { isSpent: true } |
  { is_spent: true }
);

export interface ReservationStore {
  load?: () => Promise<{ version: number; reservations: NoteReservationRecord[] }>;
  listReservations(filter?: { statuses?: readonly string[]; ownerKeyId?: string; owner_key_id?: string; limit?: number }): Promise<NoteReservationRecord[]>;
  getReservation(reservationID: string): Promise<NoteReservationRecord>;
  createReservationBatch(reservations: readonly InitialNoteReservationRecord[]): Promise<NoteReservationRecord[]>;
  compareAndSetReservationStatus(reservationID: string, from: string, to: string, patch?: Partial<NoteReservationRecord>): Promise<NoteReservationRecord>;
  compareAndSetReservationStatusBatch(transitions: readonly {
    /** If both aliases are supplied, their string values must match. */
    reservationID?: string;
    reservation_id?: string;
    from: string;
    to: string;
    patch?: Partial<NoteReservationRecord>;
  }[]): Promise<NoteReservationRecord[]>;
  releaseReservationBatch(options: {
    reservationIDs: readonly string[];
    ownerKeyId: string;
    leaseOwner?: string;
    leaseToken?: string;
  }): Promise<NoteReservationRecord[]>;
  findActiveReservationByLookupKey(ownerKeyId: string, lookupKey: string): Promise<NoteReservationRecord | null>;
  findReservationsByLookupKey(ownerKeyId: string, lookupKey: string): Promise<NoteReservationRecord[]>;
  reconcileSpentByLookupKey(ownerKeyId: string, lookupKey: string, note: SpentNoteEvidence, options?: { now?: string | Date }): Promise<NoteReservationRecord[]>;
  reconcileSpentByLookupKeys(ownerKeyId: string, spentNotes: Array<{ lookupKey: string; note: SpentNoteEvidence }>, options?: { now?: string | Date }): Promise<NoteReservationRecord[]>;
}

export interface ReservationLockManager {
  request<T>(
    name: string,
    options: { mode?: "exclusive" | "shared" },
    callback: () => T | Promise<T>
  ): Promise<T>;
}

export declare function isActiveReservationStatus(status: string): boolean;
export declare function canTransitionReservation(from: string, to: string): boolean;
export declare function requiresReservationLeaseToken(from: string, to: string): boolean;
/** True only for worker-owned cleanup transitions that may run after the stored lease has expired. */
export declare function canRecoverReservationAfterLeaseExpiry(from: string, to: string): boolean;
export declare function reservationHeartbeatIntervalMs(input?: {
  leaseDurationMs?: number;
  lease_duration_ms?: number;
  leaseUntil?: string | Date;
  lease_until?: string | Date;
  minIntervalMs?: number;
  maxIntervalMs?: number;
  now?: string | Date;
}): number;
/** Computes a lookup key from raw nullifier bytes or a non-hex string label. For 32-byte nullifier hex strings, use nullifierLookupKeyFromHex. */
export declare function nullifierLookupKey(indexKey: BytesLike | string, nullifier: BytesLike | string): Hex;
/** Computes a lookup key from a 32-byte nullifier hex string. */
export declare function nullifierLookupKeyFromHex(indexKey: BytesLike | string, nullifierHex: Hex | string): Hex;
/** Go-compatible SHA-256 hash of a canonical shielded recipient for operation success evidence. */
export declare function hashRecipient(recipient: string, options?: string | {
  shieldedPrefix?: string;
  prefix?: string;
}): Hex;
/** Go-compatible SHA-256 hash of canonical non-empty denom and uint64 `denom:amount` operation evidence. */
export declare function hashAmount(denom: string, amount: bigint | number | string): Hex;
export declare function noteNullifierHex(noteLike: object | FoundNote): Hex;
export declare function noteReservationIdentity(noteLike: object | FoundNote): {
  nullifierHex: Hex;
  noteId: string;
  amount: string;
  height: number | string;
  sequence: number | string;
  txHash: string;
};
export declare function selectedReservationNotesFromPlan(plan?: TransferPlan | TransferBatchPlan | WithdrawPlan | object | null): FoundNote[];

export declare class MemoryReservationStore implements ReservationStore {
  constructor(input?: {
    state?: { version?: number; reservations?: Partial<NoteReservationRecord>[] };
    /** Store-local clock used when validating lease state inside atomic mutations. */
    now?: () => Date;
  });
  load(): Promise<{ version: number; reservations: NoteReservationRecord[] }>;
  /** Unsafe test/migration API. Application code must use CAS transitions. */
  unsafeReplaceState(state: { version?: number; reservations?: Partial<NoteReservationRecord>[] }): Promise<{ version: number; reservations: NoteReservationRecord[] }>;
  listReservations(filter?: { statuses?: readonly string[]; ownerKeyId?: string; owner_key_id?: string; limit?: number }): Promise<NoteReservationRecord[]>;
  getReservation(reservationID: string): Promise<NoteReservationRecord>;
  createReservationBatch(reservations?: readonly InitialNoteReservationRecord[]): Promise<NoteReservationRecord[]>;
  /** Unsafe test/migration API. Application code must use manager transitions. */
  unsafeReplaceReservation(reservation: NoteReservationRecord): Promise<NoteReservationRecord>;
  compareAndSetReservationStatus(reservationID: string, from: string, to: string, patch?: Partial<NoteReservationRecord>): Promise<NoteReservationRecord>;
  compareAndSetReservationStatusBatch(transitions?: readonly {
    /** If both aliases are supplied, their string values must match. */
    reservationID?: string;
    reservation_id?: string;
    from: string;
    to: string;
    patch?: Partial<NoteReservationRecord>;
  }[]): Promise<NoteReservationRecord[]>;
  releaseReservationBatch(options: {
    reservationIDs: readonly string[];
    ownerKeyId: string;
    leaseOwner?: string;
    leaseToken?: string;
  }): Promise<NoteReservationRecord[]>;
  findActiveReservationByLookupKey(ownerKeyId: string, lookupKey: string): Promise<NoteReservationRecord | null>;
  findReservationsByLookupKey(ownerKeyId: string, lookupKey: string): Promise<NoteReservationRecord[]>;
  reconcileSpentByLookupKey(ownerKeyId: string, lookupKey: string, note: SpentNoteEvidence, options?: { now?: string | Date }): Promise<NoteReservationRecord[]>;
  reconcileSpentByLookupKeys(ownerKeyId: string, spentNotes: Array<{ lookupKey: string; note: SpentNoteEvidence }>, options?: { now?: string | Date }): Promise<NoteReservationRecord[]>;
}

export declare class IndexedDbReservationStore extends MemoryReservationStore {
  constructor(input?: {
    dbName?: string;
    namespace?: string;
    indexedDB?: IDBFactory;
    locks?: ReservationLockManager | null;
    requireLocks?: boolean;
    require_locks?: boolean;
    /** Encodes the full reservation state before writing it to IndexedDB. Provide with decodeState in production. */
    encodeState?: (state: { version: number; reservations: NoteReservationRecord[] }) => object | string | number | boolean | bigint | Promise<object | string | number | boolean | bigint>;
    encode_state?: (state: { version: number; reservations: NoteReservationRecord[] }) => object | string | number | boolean | bigint | Promise<object | string | number | boolean | bigint>;
    /** Decodes the value read from IndexedDB. Provide with encodeState in production. */
    decodeState?: (value: unknown) => { version?: number; reservations?: Partial<NoteReservationRecord>[] } | Promise<{ version?: number; reservations?: Partial<NoteReservationRecord>[] }>;
    decode_state?: (value: unknown) => { version?: number; reservations?: Partial<NoteReservationRecord>[] } | Promise<{ version?: number; reservations?: Partial<NoteReservationRecord>[] }>;
    /** Explicit demo/test-only opt-in for plaintext IndexedDB state. */
    unsafeAllowPlaintext?: boolean;
    unsafe_allow_plaintext?: boolean;
    /** Store-local clock used when validating lease state inside atomic mutations. */
    now?: () => Date;
  });
}

export declare function createBrowserReservationStore(options?: {
  dbName?: string;
  namespace?: string;
  indexedDB?: IDBFactory | null;
  locks?: ReservationLockManager | null;
  requireLocks?: boolean;
  require_locks?: boolean;
  encodeState?: (state: { version: number; reservations: NoteReservationRecord[] }) => object | string | number | boolean | bigint | Promise<object | string | number | boolean | bigint>;
  encode_state?: (state: { version: number; reservations: NoteReservationRecord[] }) => object | string | number | boolean | bigint | Promise<object | string | number | boolean | bigint>;
  decodeState?: (value: unknown) => { version?: number; reservations?: Partial<NoteReservationRecord>[] } | Promise<{ version?: number; reservations?: Partial<NoteReservationRecord>[] }>;
  decode_state?: (value: unknown) => { version?: number; reservations?: Partial<NoteReservationRecord>[] } | Promise<{ version?: number; reservations?: Partial<NoteReservationRecord>[] }>;
  unsafeAllowPlaintext?: boolean;
  unsafe_allow_plaintext?: boolean;
  /** Explicit demo/test-only opt-in when IndexedDB is unavailable. */
  unsafeAllowMemoryFallback?: boolean;
  unsafe_allow_memory_fallback?: boolean;
  now?: () => Date;
  state?: { version?: number; reservations?: Partial<NoteReservationRecord>[] };
}): ReservationStore;

type NoteReservationOwnerInput =
  | { ownerKeyId: string; owner_key_id?: string }
  | { ownerKeyId?: string; owner_key_id: string };

type NoteReservationManagerBaseInput = {
  store: ReservationStore;
  nullifierLookupKeyId?: string;
  nullifier_lookup_key_id?: string;
  leaseOwner?: string;
  lease_owner?: string;
  leaseDurationMs?: number;
  lease_duration_ms?: number;
  now?: () => Date;
} & NoteReservationOwnerInput;

export type NoteReservationManagerInput = NoteReservationManagerBaseInput & (
  | { indexKey: BytesLike | string; index_key?: BytesLike | string; unsafeAllowPublicIndexKey?: false; unsafe_allow_public_index_key?: false }
  | { index_key: BytesLike | string; indexKey?: BytesLike | string; unsafeAllowPublicIndexKey?: false; unsafe_allow_public_index_key?: false }
  | { indexKey?: BytesLike | string; index_key?: BytesLike | string; unsafeAllowPublicIndexKey: true; unsafe_allow_public_index_key?: boolean }
  | { indexKey?: BytesLike | string; index_key?: BytesLike | string; unsafeAllowPublicIndexKey?: boolean; unsafe_allow_public_index_key: true }
);

export interface ReservationBatch {
  operation_id: string;
  lease_owner: string;
  lease_token: string;
  lease_until: string;
  reservation_ids: string[];
  reservations: NoteReservationRecord[];
}

export interface ReservationLeaseMetadata {
  leaseToken?: string;
  lease_token?: string;
  leaseOwner?: string;
  lease_owner?: string;
  leaseUntil?: string | Date;
  lease_until?: string | Date;
  leaseDurationMs?: number;
  lease_duration_ms?: number;
}

/** `markProving` claims a manager-owned lease; only the generated batch token is accepted. */
export interface ReservationProvingMetadata {
  leaseToken?: string;
  lease_token?: string;
}

export interface ReservationOperationSuccessEvidenceMetadata {
  operationSuccessEvidenceRequired?: boolean;
  operation_success_evidence_required?: boolean;
  txHash?: string;
  tx_hash?: string;
  txhash?: string;
  submittedTxHash?: string;
  submitted_tx_hash?: string;
  txHashSubmitted?: string;
  transactionHash?: string;
  transaction_hash?: string;
  transaction_hash_hex?: string;
  txBytesHash?: string;
  tx_bytes_hash?: string;
  txBytes?: string;
  tx_bytes?: string;
  signDocHash?: string;
  sign_doc_hash?: string;
  signDoc?: string;
  sign_doc?: string;
  txResult?: object;
  tx_result?: object;
  transactionResult?: object;
  transaction_result?: object;
  expectedOutputCommitment?: string;
  expected_output_commitment?: string;
  outputCommitment?: string;
  output_commitment?: string;
  outputCommitmentHex?: string;
  output_commitment_hex?: string;
  expectedDisclosureDigest?: string;
  expected_disclosure_digest?: string;
  auditDisclosureDigest?: string;
  audit_disclosure_digest?: string;
  auditDisclosureDigestHex?: string;
  audit_disclosure_digest_hex?: string;
  expectedRecipientHash?: string;
  expected_recipient_hash?: string;
  recipientHash?: string;
  recipient_hash?: string;
  expectedAmount?: string;
  expected_amount?: string;
  expectedAmountHash?: string;
  expected_amount_hash?: string;
  amountHash?: string;
  amount_hash?: string;
  expectedDenom?: string;
  expected_denom?: string;
  denom?: string;
  assetDenom?: string;
  asset_denom?: string;
  batchItemIndex?: number | string;
  batch_item_index?: number | string;
  itemIndex?: number | string;
  item_index?: number | string;
  batchItemIndexKnown?: boolean;
  batch_item_index_known?: boolean;
}

export type ReservationProofReadyMetadata = ReservationLeaseMetadata & ReservationOperationSuccessEvidenceMetadata & {
  payloadHash?: string;
  payload_hash?: string;
  signDocHash?: string;
  sign_doc_hash?: string;
  txBytesHash?: string;
  tx_bytes_hash?: string;
  metadata?: ReservationMetadata;
};

export type ReservationProofReadyBatchEntry = {
  /** If both aliases are supplied, they must contain the same IDs in the same order. */
  reservationIDs?: readonly string[];
  reservation_ids?: readonly string[];
  metadata?: ReservationProofReadyMetadata;
};

type ReservationBroadcastMetadataFields = {
  broadcastAttemptCount?: number;
  broadcast_attempt_count?: number;
  metadata?: ReservationMetadata;
};

type ReservationBroadcastAttemptFields = {
  txHash?: string;
  tx_hash?: string;
  submittedTxHash?: string;
  submitted_tx_hash?: string;
  txHashSubmitted?: string;
  txBytesHash?: string;
  tx_bytes_hash?: string;
  signDocHash?: string;
  sign_doc_hash?: string;
};

type ReservationSubmittedBroadcastAttempt = ReservationBroadcastAttemptFields & (
  | { txHash: string }
  | { tx_hash: string }
  | { submittedTxHash: string }
  | { submitted_tx_hash: string }
  | { txHashSubmitted: string }
  | { txBytesHash: string }
  | { tx_bytes_hash: string }
);

export type ReservationSubmittedMetadata = ReservationLeaseMetadata & ReservationBroadcastMetadataFields & ReservationSubmittedBroadcastAttempt;

export type ReservationUnknownMetadata = ReservationLeaseMetadata & ReservationBroadcastMetadataFields & ReservationSubmittedBroadcastAttempt & {
  fromStatus?: "ProofReady" | "Submitted";
  from_status?: "ProofReady" | "Submitted";
  error?: string;
  lastBroadcastError?: string;
  last_broadcast_error?: string;
};

export interface ReservationReplanMetadata extends ReservationLeaseMetadata {
  fromStatus?: string;
  from_status?: string;
  txHash?: string;
  tx_hash?: string;
  txBytesHash?: string;
  tx_bytes_hash?: string;
  signDocHash?: string;
  sign_doc_hash?: string;
  error?: string;
  lastBroadcastError?: string;
  last_broadcast_error?: string;
  /** Required when replanning a Submitted or Unknown reservation so callers prove the nullifier was checked unspent. */
  nullifierUnspentConfirmed?: boolean;
  nullifier_unspent_confirmed?: boolean;
  /** Required with nullifierUnspentConfirmed for Submitted or Unknown: the recorded tx was confirmed absent or failed. */
  txAbsentOrFailedConfirmed?: boolean;
  tx_absent_or_failed_confirmed?: boolean;
  checkedHeight?: number | string;
  checked_height?: number | string;
  txHashChecked?: string | boolean;
  tx_hash_checked?: string | boolean;
  /** Required when discarding a local ProofReady proof before any broadcast attempt. */
  proofDiscarded?: boolean;
  proof_discarded?: boolean;
  /** Required with relay_payload_expired when an authoritative chain block time established expiry. */
  authoritativeExpiryConfirmed?: boolean;
  authoritative_expiry_confirmed?: boolean;
  metadata?: ReservationMetadata;
}

/** Operator approval required to make a ManualReview note available again. */
export interface ReservationManualReviewResolution {
  target: "Released" | "ReplanRequired" | "Failed";
  operatorId: string;
  approvalReference: string;
  reason?: string;
  metadata?: ReservationMetadata;
}

export declare class NoteReservationManager {
  store: ReservationStore;
  ownerKeyId: string;
  nullifierLookupKeyId: string;
  leaseOwner: string;
  leaseDurationMs: number;
  constructor(input: NoteReservationManagerInput);
  lookupKeyForNote(noteLike: object | FoundNote): Promise<Hex>;
  listActiveReservations(): Promise<NoteReservationRecord[]>;
  getReservation(reservationID: string): Promise<NoteReservationRecord>;
  reservationForNote(noteLike: object | FoundNote): Promise<NoteReservationRecord | null>;
  reservationStatusByNote(notes?: readonly (object | FoundNote)[]): Promise<Map<string, NoteReservationRecord | null>>;
  filterAvailableNotes<T extends object | FoundNote>(notes?: readonly T[]): Promise<T[]>;
  reserveNotes(input?: { notes?: readonly (object | FoundNote)[]; operationId?: string; operation_id?: string; kind?: string; metadata?: ReservationMetadata }): Promise<ReservationBatch>;
  reservePlan(input?: { plan?: TransferPlan | TransferBatchPlan | WithdrawPlan | object | null; kind?: string; operationId?: string; operation_id?: string; metadata?: ReservationMetadata }): Promise<ReservationBatch>;
  transitionBatch(reservationIDs: readonly string[], from: string, to: string, patch?: Partial<NoteReservationRecord>): Promise<NoteReservationRecord[]>;
  renewLease(reservationIDs?: readonly string[], metadata?: ReservationLeaseMetadata): Promise<NoteReservationRecord[]>;
  heartbeatLease(reservationIDs?: readonly string[], metadata?: ReservationLeaseMetadata): Promise<NoteReservationRecord[]>;
  markProving(reservationIDs?: readonly string[], metadata?: ReservationProvingMetadata): Promise<NoteReservationRecord[]>;
  markProofReady(reservationIDs?: readonly string[], metadata?: ReservationProofReadyMetadata): Promise<NoteReservationRecord[]>;
  markProofReadyBatch(entries?: readonly ReservationProofReadyBatchEntry[]): Promise<NoteReservationRecord[]>;
  markBroadcastAttempting(reservationIDs: readonly string[], metadata: ReservationLeaseMetadata & ReservationBroadcastAttemptFields & { reason?: string; metadata?: ReservationMetadata }): Promise<NoteReservationRecord[]>;
  markBroadcastRejected(reservationIDs: readonly string[], metadata: ReservationLeaseMetadata & { providerCode?: string | number; provider_code?: string | number; error?: string; metadata?: ReservationMetadata }): Promise<NoteReservationRecord[]>;
  markSubmitted(reservationIDs: readonly string[], metadata: ReservationSubmittedMetadata): Promise<NoteReservationRecord[]>;
  markUnknown(reservationIDs: readonly string[], metadata: ReservationUnknownMetadata): Promise<NoteReservationRecord[]>;
  /** Records a copied relay payload without exposing a generic same-status metadata patch. */
  recordRelayHandoff(reservationIDs: readonly string[], metadata: ReservationLeaseMetadata & (
    | { payloadHash: string; payload_hash?: string }
    | { payload_hash: string; payloadHash?: string }
  ) & {
    txBytesHash?: string;
    tx_bytes_hash?: string;
    signDocHash?: string;
    sign_doc_hash?: string;
    handedOffAt?: string;
    handed_off_at?: string;
    metadata?: ReservationMetadata;
  }): Promise<NoteReservationRecord[]>;
  markReplanRequired(reservationIDs?: readonly string[], metadata?: ReservationReplanMetadata): Promise<NoteReservationRecord[]>;
  markManualReview(reservationIDs?: readonly string[], metadata?: ReservationLeaseMetadata & {
    error?: string;
    lastBroadcastError?: string;
    last_broadcast_error?: string;
    metadata?: ReservationMetadata;
  }): Promise<NoteReservationRecord[]>;
  resolveManualReview(reservationIDs: readonly string[], resolution: ReservationManualReviewResolution): Promise<NoteReservationRecord[]>;
  releaseReservedOrProving(reservationIDs?: readonly string[], metadata?: ReservationLeaseMetadata): Promise<NoteReservationRecord[]>;
  reconcileSpentNotes(notes?: readonly (object | FoundNote)[]): Promise<NoteReservationRecord[]>;
}

export declare function createNoteReservationManager(options: NoteReservationManagerInput): NoteReservationManager;
export declare function preparePlanReservation(reservationManager: NoteReservationManager | null | undefined, input?: { plan?: TransferPlan | TransferBatchPlan | WithdrawPlan | object | null; kind?: string; metadata?: ReservationMetadata }): Promise<ReservationBatch | null>;
export declare function rollbackPlanReservation(reservationManager: NoteReservationManager | null | undefined, batch: ReservationBatch | null | undefined): Promise<void>;
/** Attempts rollback without replacing the original prepare/prover error. */
export declare function rollbackPlanReservationPreservingError(reservationManager: NoteReservationManager | null | undefined, batch: ReservationBatch | null | undefined, error: unknown): Promise<void>;
