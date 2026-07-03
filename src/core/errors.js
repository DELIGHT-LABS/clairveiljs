export const ClairveilErrorCode = Object.freeze({
  INVALID_ARGUMENT: "INVALID_ARGUMENT",
  INVALID_AMOUNT: "INVALID_AMOUNT",
  WALLET_UNAVAILABLE: "WALLET_UNAVAILABLE",
  ROOT_SIGNATURE_REQUIRED: "ROOT_SIGNATURE_REQUIRED",
  SIGNER_MISMATCH: "SIGNER_MISMATCH",
  INSUFFICIENT_BALANCE: "INSUFFICIENT_BALANCE",
  SELF_MERGE_REQUIRED: "SELF_MERGE_REQUIRED",
  ZERO_DUMMY_REQUIRED: "ZERO_DUMMY_REQUIRED",
  EXACT_NOTE_REQUIRED: "EXACT_NOTE_REQUIRED",
  PROVER_UNAVAILABLE: "PROVER_UNAVAILABLE",
  PROVER_TIMEOUT: "PROVER_TIMEOUT",
  PROVER_REJECTED: "PROVER_REJECTED",
  DISCLOSURE_UNAVAILABLE: "DISCLOSURE_UNAVAILABLE",
  TX_BROADCAST_FAILED: "TX_BROADCAST_FAILED"
});

export class ClairveilError extends Error {
  constructor(code, message, details = {}) {
    super(message || code);
    this.name = "ClairveilError";
    this.code = code;
    this.details = details;
  }
}

export function clairveilError(code, message, details) {
  return new ClairveilError(code, message, details);
}

export function isClairveilError(error, code) {
  if (!(error instanceof ClairveilError)) return false;
  return code ? error.code === code : true;
}

export function plannerStatusToErrorCode(status) {
  switch (status) {
    case "invalid_amount":
      return ClairveilErrorCode.INVALID_AMOUNT;
    case "insufficient_balance":
      return ClairveilErrorCode.INSUFFICIENT_BALANCE;
    case "self_merge_required":
      return ClairveilErrorCode.SELF_MERGE_REQUIRED;
    case "zero_dummy_required":
      return ClairveilErrorCode.ZERO_DUMMY_REQUIRED;
    case "exact_note_required":
      return ClairveilErrorCode.EXACT_NOTE_REQUIRED;
    default:
      return ClairveilErrorCode.INVALID_ARGUMENT;
  }
}

export function wrapProverError(error) {
  const message = error?.message || String(error);
  if (/timed out|abort/i.test(message)) {
    return new ClairveilError(ClairveilErrorCode.PROVER_TIMEOUT, message, { cause: error });
  }
  if (/status\s+5\d\d|unavailable|ECONNREFUSED|fetch failed/i.test(message)) {
    return new ClairveilError(ClairveilErrorCode.PROVER_UNAVAILABLE, message, { cause: error });
  }
  return new ClairveilError(ClairveilErrorCode.PROVER_REJECTED, message, { cause: error });
}
