export interface PlannerFacts {
  requestedAmount: string;
  requestedAmountValue: string;
  denom: string;
  spendableTotal: string;
  spendableTotalValue: string;
  spendableCount: number;
  currentMaxNote: string;
  currentMaxNoteValue: string;
  selectedInputTotal: string;
  selectedInputTotalValue: string;
}

export interface TransferSelection<T> {
  inputs: T[];
  total: bigint;
  isFinal: boolean;
  needsZeroDummy: boolean;
}

export interface TransferPlan<T> {
  status: "final_transfer_ready" | "self_merge_required" | "zero_dummy_required" | "insufficient_balance" | "invalid_amount";
  canBuildTx: boolean;
  action: string;
  message: string;
  nextAmount?: string;
  facts: PlannerFacts;
  selection: TransferSelection<T>;
}

export interface TransferBatchPlan<T> {
  status: "batch_transfer_ready" | "batch_note_preparation_required" | "batch_capacity_exceeded" | "mixed_denom_unsupported" | "insufficient_balance" | "invalid_amount" | "invalid_batch";
  canBuildTx: boolean;
  action: string;
  message: string;
  facts: PlannerFacts;
  selection?: TransferSelection<T>;
  selections: TransferSelection<T>[];
}

export interface WithdrawPlan<T> {
  status: "withdraw_ready" | "exact_note_required" | "insufficient_balance" | "invalid_amount";
  canBuildTx: boolean;
  action: string;
  message: string;
  facts: PlannerFacts;
  selectedNote: T | null;
}
