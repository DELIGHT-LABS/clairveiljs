import { normalizeFoundNote, parseCoin } from "../core/note.js";
import { selectBatchTransferInputs, selectTransferInputs, summarizeSpendableNotesByDenom } from "./payload.js";
import { ClairveilError, plannerStatusToErrorCode } from "../core/errors.js";
import { createNotePlanner } from "./note-planner.js";

export const { planTransferNotes, planTransferBatchNotes, planWithdrawNotes } = createNotePlanner({
  maxShieldedAmount: (1n << 64n) - 1n, normalizeFoundNote, parseCoin,
  selectTransferInputs, selectBatchTransferInputs, summarizeSpendableNotesByDenom
});

export class ClairveilPlannerError extends ClairveilError {
  constructor(plan) {
    super(
      plannerStatusToErrorCode(plan?.status),
      plan?.message || "Clairveil planner could not build the requested transaction",
      { plan }
    );
    this.name = "ClairveilPlannerError";
    this.plan = plan;
  }
}

export function assertPlanCanBuildTx(plan) {
  if (!plan?.canBuildTx) {
    throw new ClairveilPlannerError(plan);
  }
  return plan;
}
