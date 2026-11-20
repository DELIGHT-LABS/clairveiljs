import type { CoinString, FoundNote } from "../core/note.js";
import { ClairveilError } from "../core/errors.js";

import type * as Plans from "./planning-types.js";
export type PlannerFacts = Plans.PlannerFacts;
export type TransferSelection = Plans.TransferSelection<FoundNote>;
export type TransferPlan = Plans.TransferPlan<FoundNote>;
export type TransferBatchPlan = Plans.TransferBatchPlan<FoundNote>;
export type WithdrawPlan = Plans.WithdrawPlan<FoundNote>;

export function planTransferNotes(input?: { notes?: FoundNote[]; amount?: CoinString; denom?: string }): TransferPlan;
export function planTransferBatchNotes(input?: { notes?: FoundNote[]; amounts?: CoinString[]; denom?: string }): TransferBatchPlan;
export function planWithdrawNotes(input?: { notes?: FoundNote[]; amount?: CoinString; denom?: string }): WithdrawPlan;

export class ClairveilPlannerError extends ClairveilError {
  plan: TransferPlan | TransferBatchPlan | WithdrawPlan;
  constructor(plan: TransferPlan | TransferBatchPlan | WithdrawPlan);
}

export function assertPlanCanBuildTx<T extends TransferPlan | TransferBatchPlan | WithdrawPlan>(plan: T): T;
