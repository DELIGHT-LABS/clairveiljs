export const ClairveilErrorCode: Readonly<{
  INVALID_ARGUMENT: "INVALID_ARGUMENT";
  WALLET_UNAVAILABLE: "WALLET_UNAVAILABLE";
  ROOT_SIGNATURE_REQUIRED: "ROOT_SIGNATURE_REQUIRED";
  SIGNER_MISMATCH: "SIGNER_MISMATCH";
  INSUFFICIENT_BALANCE: "INSUFFICIENT_BALANCE";
  SELF_MERGE_REQUIRED: "SELF_MERGE_REQUIRED";
  ZERO_DUMMY_REQUIRED: "ZERO_DUMMY_REQUIRED";
  EXACT_NOTE_REQUIRED: "EXACT_NOTE_REQUIRED";
  PROVER_UNAVAILABLE: "PROVER_UNAVAILABLE";
  PROVER_TIMEOUT: "PROVER_TIMEOUT";
  PROVER_REJECTED: "PROVER_REJECTED";
  DISCLOSURE_UNAVAILABLE: "DISCLOSURE_UNAVAILABLE";
  TX_BROADCAST_FAILED: "TX_BROADCAST_FAILED";
}>;

export type ClairveilErrorCodeValue = typeof ClairveilErrorCode[keyof typeof ClairveilErrorCode];

export class ClairveilError extends Error {
  code: ClairveilErrorCodeValue | string;
  details: object;
  constructor(code: ClairveilErrorCodeValue | string, message: string, details?: object);
}

export function clairveilError(code: ClairveilErrorCodeValue | string, message: string, details?: object): ClairveilError;
export function isClairveilError(error: unknown, code?: ClairveilErrorCodeValue | string): boolean;
export function plannerStatusToErrorCode(status: string): ClairveilErrorCodeValue;
export function wrapProverError(error: unknown): ClairveilError;
