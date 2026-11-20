import { maxShieldedAmountV2, parseAmount128 } from "../core/amount.js";
import { normalizeFoundNote128 } from "../core/note128.js";
import { defaultAssetDenom, parseCoin } from "../core/coin.js";
import { createNoteSelection } from "./note-selection.js";
import { createNotePlanner } from "./note-planner.js";

const selection = createNoteSelection({
  maxShieldedAmount: maxShieldedAmountV2,
  maxTransactionAmount: maxShieldedAmountV2,
  normalizeInventoryNote: normalizeFoundNote128,
  parseTargetAmount: parseAmount128
});

function parsePlanningCoin(value, denom = defaultAssetDenom) {
  if (typeof value !== "string" && typeof value !== "bigint") {
    throw new Error("planning amount must be a canonical coin string or bigint");
  }
  if (typeof value === "string" && value !== value.trim()) throw new Error("planning amount must be canonical");
  // Parsing is unbounded so the planner can report an invalid_amount status.
  return parseCoin(typeof value === "bigint" ? value.toString() : value, denom);
}

const planner = createNotePlanner({
  maxShieldedAmount: maxShieldedAmountV2,
  maxTransactionAmount: maxShieldedAmountV2,
  normalizeFoundNote: normalizeFoundNote128,
  parseCoin: parsePlanningCoin,
  ...selection
});

export const summarizeSpendableNotesByDenomV2 = selection.summarizeSpendableNotesByDenom;
export const selectTransferInputsV2 = selection.selectTransferInputs;
export const selectBatchTransferInputsV2 = selection.selectBatchTransferInputs;
// Amount eligibility only: signing/proving/codec compatibility is checked by
// the separately versioned workflow, never inferred from canBuildTx.
export const planTransferNotesV2 = input => ({ ...planner.planTransferNotes(input), amountModel: "uint128" });
export const planTransferBatchNotesV2 = input => ({ ...planner.planTransferBatchNotes(input), amountModel: "uint128" });
export const planWithdrawNotesV2 = input => ({ ...planner.planWithdrawNotes(input), amountModel: "uint128" });
