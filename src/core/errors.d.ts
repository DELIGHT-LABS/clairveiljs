export const ClairveilErrorCode: Readonly<{
  INVALID_ARGUMENT: "INVALID_ARGUMENT";
  INVALID_AMOUNT: "INVALID_AMOUNT";
  WALLET_UNAVAILABLE: "WALLET_UNAVAILABLE";
  ROOT_SIGNATURE_REQUIRED: "ROOT_SIGNATURE_REQUIRED";
  SIGNER_MISMATCH: "SIGNER_MISMATCH";
  INSUFFICIENT_BALANCE: "INSUFFICIENT_BALANCE";
  SELF_MERGE_REQUIRED: "SELF_MERGE_REQUIRED";
  ZERO_DUMMY_REQUIRED: "ZERO_DUMMY_REQUIRED";
  EXACT_NOTE_REQUIRED: "EXACT_NOTE_REQUIRED";
  PROVER_UNAVAILABLE: "PROVER_UNAVAILABLE";
  PROVER_TIMEOUT: "PROVER_TIMEOUT";
  PROVER_CANCELLED: "PROVER_CANCELLED";
  PROVER_REJECTED: "PROVER_REJECTED";
  DISCLOSURE_UNAVAILABLE: "DISCLOSURE_UNAVAILABLE";
  TX_BROADCAST_FAILED: "TX_BROADCAST_FAILED";
  OPERATION_STATE_MIXED: "OPERATION_STATE_MIXED";
  OPERATION_EVIDENCE_CONFLICT: "OPERATION_EVIDENCE_CONFLICT";
}>;

export type ClairveilErrorCodeValue = typeof ClairveilErrorCode[keyof typeof ClairveilErrorCode];

export class ClairveilError extends Error {
  code: ClairveilErrorCodeValue | string;
  details: object;
  status?: number;
  proverCode?: string;
  retryable?: boolean;
  constructor(code: ClairveilErrorCodeValue | string, message: string, details?: object);
}

export interface OperationReservationStateDetail {
  reservation_id: string;
  status: string;
  operation_status?: string;
}

export interface OperationStateMixedDetails {
  operation_id: string;
  reservations: readonly OperationReservationStateDetail[];
}

export type OperationEvidenceConflictField =
  | "tx_hash"
  | "commitment"
  | "digest"
  | "amount"
  | "recipient_hash"
  | "denom"
  | "batch_item_index"
  | "transaction_outcome"
  | "operation_input";

export interface OperationEvidenceConflictDetail {
  reservation_id: string;
  field: OperationEvidenceConflictField | string;
  source_field: string;
  reason: "mismatch" | "missing" | "expected_missing" | "alias_conflict" | "conflict" | "failure" | string;
  expected?: string | number | boolean | readonly string[];
  actual?: string | number | boolean | readonly string[];
}

export interface OperationEvidenceConflictDetails {
  operation_id: string;
  conflicts: readonly OperationEvidenceConflictDetail[];
}

export class OperationStateMixedError extends ClairveilError {
  code: "OPERATION_STATE_MIXED";
  details: OperationStateMixedDetails;
  constructor(details: OperationStateMixedDetails, message?: string);
}

export class OperationEvidenceConflictError extends ClairveilError {
  code: "OPERATION_EVIDENCE_CONFLICT";
  details: OperationEvidenceConflictDetails;
  constructor(details: OperationEvidenceConflictDetails, message?: string);
}

export function clairveilError(code: ClairveilErrorCodeValue | string, message: string, details?: object): ClairveilError;
export function isClairveilError(error: unknown, code?: ClairveilErrorCodeValue | string): boolean;
export function plannerStatusToErrorCode(status: string): ClairveilErrorCodeValue;
export function wrapProverError(error: unknown): ClairveilError;
