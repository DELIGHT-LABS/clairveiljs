import type { Hex } from "../core/crypto.js";
import type { PreparedBatchTransferPayload } from "./batch-transfer.js";
import type { PreparedBatchTransferProof } from "./batch-transfer.js";
import type { NoteReservationManager, ReservationBatch, ReservationMetadata } from "./reservation.js";
import type { NoteReservationRecord } from "./reservation.js";
import type { CircuitConfigV1, ValidatedCircuitConfigV1 } from "./circuit-config.js";

export type PayrollAmount = bigint | number | string;
export type PayrollDisclosureScope = "employee" | "company" | "auditor" | "external";
export type PayrollDisclosureMode = 0 | 1 | 2 | "none" | "public" | "recipient-encrypted" | "USER_DISCLOSURE_MODE_NONE" | "USER_DISCLOSURE_MODE_PUBLIC" | "USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED";

export const payrollDisclosureScopes: readonly PayrollDisclosureScope[];
export const payrollPlanStatuses: Readonly<{ Draft: "Draft"; Confirmed: "Confirmed"; Cancelled: "Cancelled" }>;
export const payrollItemStatuses: Readonly<{
  Planned: "Planned"; Reserved: "Reserved"; Proving: "Proving"; ProofReady: "ProofReady"; Submitted: "Submitted";
  Confirmed: "Confirmed"; Failed: "Failed"; ReplanRequired: "ReplanRequired"; ManualReview: "ManualReview";
}>;
export const notePreparationRecommendationKinds: Readonly<{ AddFunds: "add-funds"; MakeDummy: "make-dummy"; SplitMerge: "split-merge"; ResolveReservationLock: "resolve-reservation-lock" }>;
export const oneProofPayrollCircuitSetId: "privacy-note-v1";
export const oneProofPayrollMaxInputs: 16;
export const oneProofPayrollMaxOutputs: 32;
export const oneProofPayrollOperationEvidenceVersion: "payroll-one-proof-operation-evidence-v1";
export const oneProofPayrollExecutionVersion: "payroll-one-proof-execution-v1";

export interface PayrollDisclosurePolicy {
  user_privacy_policy?: number | string;
  user_disclosure_mode?: PayrollDisclosureMode | number;
  user_disclosure_target_pubkey_hex?: string;
  user_disclosure_target_key_id?: string;
  expected_user_disclosure_digest?: string;
  expected_audit_disclosure_digest?: string;
  expected_self_view_disclosure_digest?: string;
  userPrivacyPolicy?: number | string;
  userDisclosureMode?: PayrollDisclosureMode | number;
  userDisclosureTargetPubKeyHex?: string;
  userDisclosureTargetKeyID?: string;
  expectedUserDisclosureDigest?: string;
  expectedAuditDisclosureDigest?: string;
  expectedSelfViewDisclosureDigest?: string;
}

export interface NormalizedPayrollDisclosurePolicy {
  user_privacy_policy: number;
  user_disclosure_mode: 0 | 1 | 2;
  user_disclosure_target_pubkey_hex: string;
  user_disclosure_target_key_id: string;
  expected_user_disclosure_digest: string;
  expected_audit_disclosure_digest: string;
  expected_self_view_disclosure_digest: string;
}

export interface PayrollItemInput {
  item_id?: string;
  employee_id?: string;
  recipient_address?: string;
  amount: PayrollAmount;
  denom?: string;
  disclosure_policy?: PayrollDisclosurePolicy;
  disclosure_policy_set?: boolean;
  expected_output_commitment?: string;
  expected_disclosure_digest?: string;
  itemID?: string;
  itemId?: string;
  employeeID?: string;
  employeeId?: string;
  recipientAddress?: string;
  disclosurePolicy?: PayrollDisclosurePolicy;
  disclosurePolicySet?: boolean;
  expectedOutputCommitment?: string;
  expectedDisclosureDigest?: string;
}

export interface PayrollInput {
  company_id?: string;
  payroll_id?: string;
  batch_id: string;
  denom: string;
  attempt?: number;
  default_disclosure_policy?: PayrollDisclosurePolicy;
  created_at?: string | Date | null;
  items: PayrollItemInput[];
  companyID?: string;
  companyId?: string;
  payrollID?: string;
  payrollId?: string;
  batchID?: string;
  batchId?: string;
  defaultDisclosurePolicy?: PayrollDisclosurePolicy;
  createdAt?: string | Date | null;
}

export interface NormalizedPayrollItemInput {
  item_id: string;
  employee_id: string;
  recipient_address: string;
  amount: bigint;
  denom: string;
  disclosure_policy: NormalizedPayrollDisclosurePolicy;
  expected_output_commitment: string;
  expected_disclosure_digest: string;
}

export interface NormalizedPayrollInput {
  company_id: string;
  payroll_id: string;
  batch_id: string;
  denom: string;
  attempt: number;
  default_disclosure_policy: NormalizedPayrollDisclosurePolicy;
  created_at: string | Date | null;
  items: readonly NormalizedPayrollItemInput[];
}

export interface TreasuryNote {
  note_id?: string;
  owner_key_id?: string;
  nullifier_lookup_key?: string;
  nullifier_lookup_key_id?: string;
  denom: string;
  amount: PayrollAmount;
  is_spent?: boolean;
  reservation_id?: string;
  note?: object;
  merkle_path?: string[];
  merkle_path_helper?: number[];
  noteID?: string;
  noteId?: string;
  ownerKeyID?: string;
  ownerKeyId?: string;
  nullifierLookupKey?: string;
  nullifierLookupKeyID?: string;
  nullifierLookupKeyId?: string;
  isSpent?: boolean;
  reservationID?: string;
  reservationId?: string;
  [key: string]: unknown;
}

export interface DisclosureKeyEntry {
  key_id?: string;
  scope: PayrollDisclosureScope;
  subject_id?: string;
  public_key_hex?: string;
  version?: string;
  active: boolean;
  keyID?: string;
  keyId?: string;
  subjectID?: string;
  subjectId?: string;
  publicKeyHex?: string;
}

export interface NormalizedDisclosureKeyEntry {
  key_id: string;
  scope: PayrollDisclosureScope;
  subject_id: string;
  public_key_hex: string;
  version: string;
  active: boolean;
}

export interface NotePreparationRecommendation {
  kind: "add-funds" | "make-dummy" | "split-merge" | "resolve-reservation-lock";
  item_id: string;
  message: string;
  required_count: number;
  target_amount: bigint | null;
  denom: string;
  candidate_note_ids: string[];
}

export type NotePreparationOperationHint = NotePreparationRecommendation;

export interface NotePreparationItemReport {
  item_id: string;
  employee_id: string;
  amount: bigint;
  ready: boolean;
  reason: string;
  selected_note_ids: string[];
}

export interface NotePreparationReport {
  company_id: string;
  payroll_id: string;
  batch_id: string;
  denom: string;
  total_items: number;
  ready_items: number;
  blocked_items: number;
  spendable_note_count: number;
  reserved_note_count: number;
  spent_note_count: number;
  zero_dummy_available: number;
  zero_dummy_required: number;
  total_payroll_amount: bigint;
  total_spendable_amount: bigint;
  estimated_message_chunks: number;
  items: NotePreparationItemReport[];
  recommendations: NotePreparationRecommendation[];
  operation_hints: NotePreparationOperationHint[];
}

export interface PayrollPlanItem {
  company_id: string;
  payroll_id: string;
  batch_id: string;
  attempt: number;
  chunk_id: string;
  item_id: string;
  employee_id: string;
  operation_id: string;
  recipient_address: string;
  expected_recipient_hash: Hex;
  amount: bigint;
  expected_amount_hash: Hex;
  denom: string;
  disclosure_policy: NormalizedPayrollDisclosurePolicy;
  expected_output_commitment: string;
  expected_disclosure_digest: string;
  input_notes: TreasuryNote[];
  status: keyof typeof payrollItemStatuses | string;
  failure_reason: string;
  retry_count: number;
  batch_item_index: number;
}

export interface OneProofPayrollOperationPlan {
  operation_id: string;
  circuit_set_id: typeof oneProofPayrollCircuitSetId;
  items: PayrollPlanItem[];
  input_notes: TreasuryNote[];
  input_total: bigint;
  payment_total: bigint;
  change: bigint;
  output_count: number;
  has_change: boolean;
  /** compact emits only payments/change; exact-32 fills remaining output slots with zero-value padding notes. */
  output_mode?: "compact" | "exact-32" | "exact32";
  padding_count?: number;
}

export interface PayrollPlan {
  company_id: string;
  payroll_id: string;
  batch_id: string;
  denom: string;
  attempt: number;
  status: "Draft" | "Confirmed" | "Cancelled";
  circuit_set_id: typeof oneProofPayrollCircuitSetId;
  operations: OneProofPayrollOperationPlan[];
  created_at: string | Date | null;
  updated_at: string | Date | null;
}

export interface PayrollAssetRegistryEntryV1 {
  canonical_denom?: string;
  canonicalDenom?: string;
  asset_id?: Uint8Array | string;
  assetId?: Uint8Array | string;
}

export interface NormalizedPayrollAssetRegistryEntryV1 {
  canonical_denom: string;
  asset_id: Uint8Array;
  asset_id_hex: Hex;
  asset_id_field: bigint;
}

export interface ExpectedPayrollOutputEvidence {
  operation_id: string;
  item_id: string;
  employee_id: string;
  batch_item_index: number;
  role: "payment";
  expected_output_commitment: Hex;
  expected_user_disclosure_digest: Hex | "";
  expected_audit_disclosure_digest: Hex;
  expected_self_view_disclosure_digest: Hex;
  expected_recipient_hash: Hex;
  expected_amount_hash: Hex;
  expected_denom: string;
  asset_id_hex: Hex;
  user_privacy_policy: number;
  user_disclosure_mode: 0 | 1 | 2;
  audit_key_id: string;
  audit_key_epoch: number;
}

export interface OneProofPayrollOutputSecret {
  randomness?: bigint | number | string;
  user_disclosure_blinding?: bigint | number | string;
  userDisclosureBlinding?: bigint | number | string;
  full_disclosure_blinding?: bigint | number | string;
  fullDisclosureBlinding?: bigint | number | string;
  memo?: string;
}

export interface PrepareOneProofPayrollOperationInput {
  operation: OneProofPayrollOperationPlan;
  asset_registry?: PayrollAssetRegistryEntryV1 | { asset?: PayrollAssetRegistryEntryV1 } | ((denom: string) => PayrollAssetRegistryEntryV1 | { asset?: PayrollAssetRegistryEntryV1 } | Promise<PayrollAssetRegistryEntryV1 | { asset?: PayrollAssetRegistryEntryV1 }>) | {
    queryAssetByDenom?(denom: string): PayrollAssetRegistryEntryV1 | { asset?: PayrollAssetRegistryEntryV1 } | Promise<PayrollAssetRegistryEntryV1 | { asset?: PayrollAssetRegistryEntryV1 }>;
    resolveAsset?(denom: string): PayrollAssetRegistryEntryV1 | { asset?: PayrollAssetRegistryEntryV1 } | Promise<PayrollAssetRegistryEntryV1 | { asset?: PayrollAssetRegistryEntryV1 }>;
    fetchAssetByDenom?(denom: string): PayrollAssetRegistryEntryV1 | { asset?: PayrollAssetRegistryEntryV1 } | Promise<PayrollAssetRegistryEntryV1 | { asset?: PayrollAssetRegistryEntryV1 }>;
  };
  assetRegistry?: PrepareOneProofPayrollOperationInput["asset_registry"];
  /** Preferred source: a Cosmos client that atomically pins circuit and asset consensus state. */
  protocol_preflight?: {
    assertProtocolPreflight(denom: string): Promise<{
      circuit_config?: CircuitConfigV1 | object;
      circuitConfig?: CircuitConfigV1 | object;
      asset: PayrollAssetRegistryEntryV1 | { asset?: PayrollAssetRegistryEntryV1 };
    }>;
  };
  protocolPreflight?: PrepareOneProofPayrollOperationInput["protocol_preflight"];
  /** Required when protocol_preflight/cosmosClient is not supplied; raw cached configs are not accepted. */
  circuit_config?: (() => CircuitConfigV1 | object | Promise<CircuitConfigV1 | object>) | {
    assertCircuitConfig?(): CircuitConfigV1 | object | Promise<CircuitConfigV1 | object>;
    fetchCircuitConfig?(): CircuitConfigV1 | object | Promise<CircuitConfigV1 | object>;
  };
  circuitConfig?: PrepareOneProofPayrollOperationInput["circuit_config"];
  cosmos_client?: PrepareOneProofPayrollOperationInput["protocol_preflight"] & PrepareOneProofPayrollOperationInput["circuit_config"];
  cosmosClient?: PrepareOneProofPayrollOperationInput["cosmos_client"];
  creator?: string;
  chain_id?: string;
  chainId?: string;
  expires_at_unix?: number;
  expiresAtUnix?: number;
  root?: Uint8Array | string | bigint | number;
  audit_key_id?: string;
  auditKeyId?: string;
  audit_key_epoch?: number;
  auditKeyEpoch?: number;
  audit_disclosure_target_pubkey?: Uint8Array | string | object;
  auditDisclosureTargetPubKey?: Uint8Array | string | object;
  self_view_disclosure_target_pubkey?: Uint8Array | string | object;
  selfViewDisclosureTargetPubKey?: Uint8Array | string | object;
  disable_self_view_disclosure?: boolean;
  disableSelfViewDisclosure?: boolean;
  output_secrets?: Record<string, OneProofPayrollOutputSecret>;
  outputSecrets?: Record<string, OneProofPayrollOutputSecret>;
  signer: {
    signBatchTransfer?(request: object): Promise<Uint8Array> | Uint8Array;
    signSpendNoteHash?(intent: bigint): Promise<Uint8Array> | Uint8Array;
    signNoteHash?(intent: bigint): Promise<Uint8Array> | Uint8Array;
  };
  shieldedPrefix?: string;
  prefix?: string;
}

export interface PreparedOneProofPayrollOperation {
  operation: OneProofPayrollOperationPlan;
  circuit_config: ValidatedCircuitConfigV1;
  asset_registry_entry: NormalizedPayrollAssetRegistryEntryV1;
  payload: PreparedBatchTransferPayload;
  expected_evidence: readonly ExpectedPayrollOutputEvidence[];
  input_nullifier_hexes: string[];
}

export interface OneProofPayrollOperationEvidence {
  version: typeof oneProofPayrollOperationEvidenceVersion;
  operation_id: string;
  circuit_set_id: typeof oneProofPayrollCircuitSetId;
  payload_hash: Hex;
  input_nullifier_hexes: readonly Hex[];
  expected_evidence: readonly ExpectedPayrollOutputEvidence[];
  proof_payload_hash?: Hex;
  proof_hash?: Hex;
}

/** SHA-256 binding for the full persisted payroll success predicate. */
export type OneProofPayrollOperationEvidenceHash = Hex;

export interface ProvenOneProofPayrollOperation {
  version: typeof oneProofPayrollExecutionVersion;
  operation: OneProofPayrollOperationPlan;
  payload: PreparedBatchTransferPayload;
  proof: PreparedBatchTransferProof & { proof_bytes: Uint8Array };
  message: object;
  operation_evidence: OneProofPayrollOperationEvidence;
  input_nullifier_hexes: readonly Hex[];
}

/** Private-at-rest, restart-safe checkpoint for a one-proof payroll operation. */
export interface OneProofPayrollArtifact {
  version: typeof oneProofPayrollArtifactVersion;
  prepared: PreparedOneProofPayrollOperation;
  execution: ProvenOneProofPayrollOperation | null;
  reservation_batch: OneProofPayrollReservationBatch | null;
  sign_doc: object | null;
  signed_tx_bytes: Uint8Array | null;
  tx_hash: string;
  tx_bytes_hash: Hex | "";
  /** Deterministic SHA-256 of the checkpointed sign_doc. */
  sign_doc_hash: Hex | "";
  tx_result: object | null;
  artifact_hash: Hex;
}

export interface OneProofPayrollArtifactInput {
  prepared: PreparedOneProofPayrollOperation;
  execution?: ProvenOneProofPayrollOperation | null;
  reservation_batch?: OneProofPayrollReservationBatch | null;
  reservationBatch?: OneProofPayrollReservationBatch | null;
  sign_doc?: object | null;
  signDoc?: object | null;
  signed_tx_bytes?: Uint8Array | null;
  signedTxBytes?: Uint8Array | null;
  tx_hash?: string;
  txHash?: string;
  tx_bytes_hash?: Hex;
  txBytesHash?: Hex;
  /** Optional assertion; when sign_doc is present it must equal its SHA-256. */
  sign_doc_hash?: Hex;
  signDocHash?: Hex;
  tx_result?: object | null;
  txResult?: object | null;
}

export interface ResumedOneProofPayrollArtifact {
  artifact: OneProofPayrollArtifact;
  prepared: PreparedOneProofPayrollOperation;
  execution?: ProvenOneProofPayrollOperation;
  reservation_batch?: OneProofPayrollReservationBatch;
  sign_doc?: object;
  signed_tx_bytes?: Uint8Array;
  next_action: "prove" | "create-sign-doc" | "sign-transaction" | "retransmit-signed-transaction";
}

export interface ReconciledOneProofPayrollOperationEvidence {
  operation_id: string;
  status: "Pending" | "Succeeded" | "Failed" | "ManualReview";
  input_nullifiers: readonly { nullifier: Hex; spent: boolean }[];
  items: ReconciledPayrollItemEvidence[];
}

export type OneProofPayrollReservationAction = "None" | "ConfirmedSpent" | "ReplanRequired" | "ManualReview" | "ManualReviewRequired";

export interface OneProofPayrollReservationBatch extends ReservationBatch {
  operation_id: string;
  reservation_ids: string[];
  reservations: NoteReservationRecord[];
}

export interface ReconciledOneProofPayrollReservation {
  reconciliation: ReconciledOneProofPayrollOperationEvidence;
  reservation_action: OneProofPayrollReservationAction;
  reservations: readonly NoteReservationRecord[];
}

export interface OneProofPayrollBroadcastIdentity {
  tx_hash?: string;
  txHash?: string;
  tx_bytes_hash?: string;
  txBytesHash?: string;
  sign_doc_hash?: string;
  signDocHash?: string;
}

export type OneProofPayrollBroadcastAttempt = OneProofPayrollBroadcastIdentity & {
  reason?: string;
  metadata?: ReservationMetadata;
} & (
  | { tx_hash: string }
  | { txHash: string }
  | { tx_bytes_hash: string }
  | { txBytesHash: string }
);

export type OneProofPayrollSubmittedBroadcast = OneProofPayrollBroadcastIdentity & (
  | { tx_hash: string }
  | { txHash: string }
  | { tx_bytes_hash: string }
  | { txBytesHash: string }
);

export interface OneProofPayrollReservationPlan {
  selection: { inputs: Array<{ note: object; nullifier: Hex; note_id: string; tx_hash: string; height: number | string; sequence: number | string; nullifier_status: "unspent" }> };
}

export interface ObservedPayrollOutputEvidence {
  batch_item_index?: number;
  batchItemIndex?: number;
  output_index?: number;
  outputIndex?: number;
  commitment?: string;
  user_disclosure_digest?: string;
  userDisclosureDigest?: string;
  full_disclosure_digest?: string;
  fullDisclosureDigest?: string;
  audit_disclosure_digest?: string;
  auditDisclosureDigest?: string;
  recipient_hash?: string;
  recipientHash?: string;
  amount_hash?: string;
  amountHash?: string;
  denom?: string;
}

export interface OneProofPayrollReconciliationTxEvidence {
  tx_hash?: string;
  txHash?: string;
  tx_bytes_hash?: string;
  txBytesHash?: string;
  sign_doc_hash?: string;
  signDocHash?: string;
  tx_result?: object;
  txResult?: object;
}

export interface ReconciledPayrollItemEvidence {
  item_id: string;
  batch_item_index: number;
  status: "Pending" | "Succeeded" | "Failed" | "ManualReview";
  reason: string;
}

/** Existing reservation record, used unchanged by the Reference Payroll surface. */
export type NoteReservation = NoteReservationRecord;
/** The one-proof operation plan is the JS payroll-operation binding. */
export type PayrollOperation = OneProofPayrollOperationPlan;

export function normalizePayrollDisclosurePolicy(policy?: PayrollDisclosurePolicy): NormalizedPayrollDisclosurePolicy;
export function validatePayrollDisclosurePolicy(policy?: PayrollDisclosurePolicy): true;
export function normalizeDisclosureKeyEntry(entry?: DisclosureKeyEntry): NormalizedDisclosureKeyEntry;
export function validateDisclosureKeyEntry(entry?: DisclosureKeyEntry): true;
export class MemoryDisclosureKeyRegistry {
  constructor(entries?: DisclosureKeyEntry[]);
  add(entry: DisclosureKeyEntry): NormalizedDisclosureKeyEntry;
  lookupDisclosureKey(scope: PayrollDisclosureScope, subjectID: string): NormalizedDisclosureKeyEntry;
}
export function createDisclosureKeyRegistry(entries?: DisclosureKeyEntry[]): MemoryDisclosureKeyRegistry;
export function normalizePayrollInput(input?: PayrollInput, options?: { shieldedPrefix?: string; prefix?: string }): NormalizedPayrollInput;
export function validatePayrollInput(input?: PayrollInput, options?: { shieldedPrefix?: string; prefix?: string }): true;
export function analyzeNotePreparation(input: PayrollInput, treasuryNotes?: TreasuryNote[], policy?: { max_messages_per_tx?: number; maxMessagesPerTx?: number; shieldedPrefix?: string; prefix?: string }): NotePreparationReport;
export function payrollBatchOperationID(input: Pick<NormalizedPayrollInput, "company_id" | "payroll_id" | "batch_id" | "attempt">, operationIndex: number): string;
export function planOneProofPayroll(input: PayrollInput, treasuryNotes?: TreasuryNote[], options?: { search_limit?: number; searchLimit?: number; output_mode?: "compact" | "exact-32" | "exact32"; outputMode?: "compact" | "exact-32" | "exact32"; shieldedPrefix?: string; prefix?: string }): PayrollPlan;
export function normalizePayrollAssetRegistryEntry(entry: PayrollAssetRegistryEntryV1 | { asset?: PayrollAssetRegistryEntryV1 }, denom: string): NormalizedPayrollAssetRegistryEntryV1;
export function buildExpectedPayrollEvidence(operation: OneProofPayrollOperationPlan, payload: PreparedBatchTransferPayload, options?: { now_unix?: number; nowUnix?: number; shieldedPrefix?: string; prefix?: string }): readonly ExpectedPayrollOutputEvidence[];
export function prepareOneProofPayrollOperation(input: PrepareOneProofPayrollOperationInput): Promise<PreparedOneProofPayrollOperation>;
export function assertOneProofPayrollNullifiersUnspent(payload: PreparedBatchTransferPayload, checkNullifiers: (nullifiers: string[]) => Promise<Map<string, boolean> | Record<string, boolean>>): Promise<string[]>;
export function reservationPlanForOneProofPayrollOperation(operation: OneProofPayrollOperationPlan): OneProofPayrollReservationPlan;
export function reserveOneProofPayrollOperation(reservationManager: NoteReservationManager, operation: OneProofPayrollOperationPlan, options?: { metadata?: ReservationMetadata }): Promise<ReservationBatch>;
export function prepareOneProofPayrollReservation(reservationManager: NoteReservationManager, prepared: PreparedOneProofPayrollOperation, options?: { metadata?: ReservationMetadata }): Promise<OneProofPayrollReservationBatch>;
export function proveOneProofPayrollOperation(payload: PreparedBatchTransferPayload, prover: { proveBatchTransfer(payload: PreparedBatchTransferPayload): Promise<PreparedBatchTransferProof | { proof: PreparedBatchTransferProof }> }, options?: { nowUnix?: number }): Promise<PreparedBatchTransferProof & { proof_bytes: Uint8Array }>;
export function buildOneProofPayrollOperationEvidence(prepared: PreparedOneProofPayrollOperation, options?: { proof?: PreparedBatchTransferProof; nowUnix?: number }): OneProofPayrollOperationEvidence;
export function oneProofPayrollOperationEvidenceHash(evidence: OneProofPayrollOperationEvidence): OneProofPayrollOperationEvidenceHash;
export const oneProofPayrollArtifactVersion: "payroll-one-proof-artifact-v1";
export function createOneProofPayrollArtifact(input: OneProofPayrollArtifactInput): OneProofPayrollArtifact;
export function serializeOneProofPayrollArtifact(artifact: OneProofPayrollArtifact): string;
export function parseOneProofPayrollArtifact(serialized: string, options?: { nowUnix?: number }): OneProofPayrollArtifact;
export function resumeOneProofPayrollArtifact(value: OneProofPayrollArtifact | string, options?: { nowUnix?: number }): ResumedOneProofPayrollArtifact;
export function retransmitOneProofPayrollArtifact(value: OneProofPayrollArtifact | string, input: {
  /** Receives the exact checkpointed TxRaw bytes. This callback performs the external broadcast. */
  broadcastSignedTx(signedTxBytes: Uint8Array, context: { artifact: OneProofPayrollArtifact; tx_bytes_hash: Hex | "" }): Promise<unknown> | unknown;
  /** Latest chain time; defaults to the local current time and rejects expired artifacts. */
  nowUnix?: number;
}): Promise<unknown>;
export function validateOneProofPayrollOperationEvidence(evidence: OneProofPayrollOperationEvidence, prepared: PreparedOneProofPayrollOperation, options?: { nowUnix?: number }): true;
export function provePreparedOneProofPayrollOperation(prepared: PreparedOneProofPayrollOperation, prover: { proveBatchTransfer(payload: PreparedBatchTransferPayload): Promise<PreparedBatchTransferProof | { proof: PreparedBatchTransferProof }> }, options: {
  /** Optional Cosmos relayer/signer. It may differ from the creator pinned in the prepared payload. */
  creator?: string;
  checkNullifiers: (nullifiers: string[]) => Promise<Map<string, boolean> | Record<string, boolean>>;
  nowUnix?: number;
}): Promise<ProvenOneProofPayrollOperation>;
export function createOneProofPayrollBatchSignDoc(execution: ProvenOneProofPayrollOperation, input: {
  cosmosClient: { createBatchTransferSignDoc(input: { signer?: string; pubKeyHex?: string; gasLimit?: number; message: object; memo?: string }): Promise<object> };
  signer?: string;
  pubKeyHex?: string;
  gasLimit?: number;
  memo?: string;
  nowUnix?: number;
}): Promise<{ operation_evidence: OneProofPayrollOperationEvidence; message: object; sign_doc: object }>;
export function markOneProofPayrollReservationProofReady(reservationManager: NoteReservationManager, reservationBatch: OneProofPayrollReservationBatch, execution: ProvenOneProofPayrollOperation, options?: { metadata?: ReservationMetadata }): Promise<readonly NoteReservationRecord[]>;
export function markOneProofPayrollReservationBroadcastAttempting(reservationManager: NoteReservationManager, reservationBatch: OneProofPayrollReservationBatch, execution: ProvenOneProofPayrollOperation, input?: OneProofPayrollBroadcastAttempt): Promise<readonly NoteReservationRecord[]>;
export function markOneProofPayrollReservationSubmitted(reservationManager: NoteReservationManager, reservationBatch: OneProofPayrollReservationBatch, execution: ProvenOneProofPayrollOperation, input: OneProofPayrollSubmittedBroadcast): Promise<readonly NoteReservationRecord[]>;
export function reconcileOneProofPayrollOperationEvidence(input: {
  prepared: PreparedOneProofPayrollOperation;
  operation_evidence: OneProofPayrollOperationEvidence;
  checkNullifiers: (nullifiers: string[]) => Promise<Map<string, boolean> | Record<string, boolean>>;
  tx_succeeded?: boolean;
  txSucceeded?: boolean;
  tx_failed?: boolean;
  txFailed?: boolean;
  observed_outputs?: readonly ObservedPayrollOutputEvidence[];
  observedOutputs?: readonly ObservedPayrollOutputEvidence[];
}): Promise<ReconciledOneProofPayrollOperationEvidence>;
export function reconcileOneProofPayrollReservation(input: OneProofPayrollReconciliationTxEvidence & {
  reservation_manager?: NoteReservationManager;
  reservationManager?: NoteReservationManager;
  reservation_batch?: OneProofPayrollReservationBatch;
  reservationBatch?: OneProofPayrollReservationBatch;
  prepared: PreparedOneProofPayrollOperation;
  operation_evidence?: OneProofPayrollOperationEvidence;
  operationEvidence?: OneProofPayrollOperationEvidence;
  check_nullifiers?: (nullifiers: string[]) => Promise<Map<string, boolean> | Record<string, boolean>>;
  checkNullifiers?: (nullifiers: string[]) => Promise<Map<string, boolean> | Record<string, boolean>>;
  tx_succeeded?: boolean;
  txSucceeded?: boolean;
  tx_failed?: boolean;
  txFailed?: boolean;
  observed_outputs?: readonly ObservedPayrollOutputEvidence[];
  observedOutputs?: readonly ObservedPayrollOutputEvidence[];
}): Promise<ReconciledOneProofPayrollReservation>;
export function reconcileOneProofPayrollEvidence(input?: {
  expected_evidence?: readonly ExpectedPayrollOutputEvidence[];
  expectedEvidence?: readonly ExpectedPayrollOutputEvidence[];
  observed_outputs?: readonly ObservedPayrollOutputEvidence[];
  observedOutputs?: readonly ObservedPayrollOutputEvidence[];
  tx_succeeded?: boolean;
  txSucceeded?: boolean;
  tx_failed?: boolean;
  txFailed?: boolean;
}): ReconciledPayrollItemEvidence[];
