import type { CoinString, FoundNote } from "../core/note.js";
import { ClairveilError } from "../core/errors.js";

export interface PlannerFacts {
  requestedAmount: CoinString;
  requestedAmountValue: string;
  denom: string;
  spendableTotal: CoinString;
  spendableTotalValue: string;
  spendableCount: number;
  currentMaxNote: CoinString;
  currentMaxNoteValue: string;
  selectedInputTotal: CoinString;
  selectedInputTotalValue: string;
}

export interface TransferSelection {
  inputs: FoundNote[];
  total: bigint;
  isFinal: boolean;
  needsZeroDummy: boolean;
}

export interface TransferPlan {
  status: "final_transfer_ready" | "self_merge_required" | "zero_dummy_required" | "insufficient_balance" | "invalid_amount";
  canBuildTx: boolean;
  action: string;
  message: string;
  nextAmount?: CoinString;
  facts: PlannerFacts;
  selection: TransferSelection;
}

export interface WithdrawPlan {
  status: "withdraw_ready" | "exact_note_required" | "insufficient_balance" | "invalid_amount";
  canBuildTx: boolean;
  action: string;
  message: string;
  facts: PlannerFacts;
  selectedNote: FoundNote | null;
}

export function planTransferNotes(input?: { notes?: FoundNote[]; amount?: CoinString; denom?: string }): TransferPlan;
export function planWithdrawNotes(input?: { notes?: FoundNote[]; amount?: CoinString; denom?: string }): WithdrawPlan;

export class ClairveilPlannerError extends ClairveilError {
  plan: TransferPlan | WithdrawPlan;
  constructor(plan: TransferPlan | WithdrawPlan);
}

export function assertPlanCanBuildTx<T extends TransferPlan | WithdrawPlan>(plan: T): T;
