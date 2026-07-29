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
  PROVER_CANCELLED: "PROVER_CANCELLED",
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
  const details = { cause: error };
  if (Number.isInteger(error?.status)) details.status = error.status;
  if (typeof error?.proverCode === "string" && error.proverCode) details.proverCode = error.proverCode;
  if (typeof error?.retryable === "boolean") details.retryable = error.retryable;
  const wrapped = code => {
    const result = new ClairveilError(code, message, details);
    if (details.status !== undefined) result.status = details.status;
    if (details.proverCode !== undefined) result.proverCode = details.proverCode;
    if (details.retryable !== undefined) result.retryable = details.retryable;
    return result;
  };
  if (error?.code === ClairveilErrorCode.PROVER_CANCELLED) {
    return wrapped(ClairveilErrorCode.PROVER_CANCELLED);
  }
  if (/timed out|abort/i.test(message)) {
    return wrapped(ClairveilErrorCode.PROVER_TIMEOUT);
  }
  if (error?.retryable === true || /status\s+(?:429|5\d\d)|unavailable|ECONNREFUSED|fetch failed/i.test(message)) {
    return wrapped(ClairveilErrorCode.PROVER_UNAVAILABLE);
  }
  return wrapped(ClairveilErrorCode.PROVER_REJECTED);
}
