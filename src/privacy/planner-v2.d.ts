import type { Amount128Input } from "../core/amount.js";
import type { FoundNote128Input, NormalizedFoundNote128 } from "../core/note128.js";
import type { TransferPlan, TransferBatchPlan, WithdrawPlan, TransferSelection } from "./planning-types.js";

export interface TransferPlanV2 extends Omit<TransferPlan<NormalizedFoundNote128>, "status"> {
  amountModel: "uint128";
  status: TransferPlan<NormalizedFoundNote128>["status"] | "note_preparation_required";
}
export interface TransferBatchPlanV2 extends TransferBatchPlan<NormalizedFoundNote128> { amountModel: "uint128"; }
export interface WithdrawPlanV2 extends WithdrawPlan<NormalizedFoundNote128> { amountModel: "uint128"; }
/** Inventory must already have validated V2 nullifiers and unspent evidence. */
export function summarizeSpendableNotesByDenomV2(notes: FoundNote128Input[], denom?: string): { notes: NormalizedFoundNote128[]; total: bigint };
export function selectTransferInputsV2(notes: FoundNote128Input[], denom: string, targetAmount: Amount128Input): TransferSelection<NormalizedFoundNote128>;
export function selectBatchTransferInputsV2(notes: FoundNote128Input[], denom: string, targetAmount: Amount128Input): TransferSelection<NormalizedFoundNote128>;
export function planTransferNotesV2(input?: { notes?: FoundNote128Input[]; amount?: string | bigint; denom?: string }): TransferPlanV2;
export function planTransferBatchNotesV2(input?: { notes?: FoundNote128Input[]; amounts?: (string | bigint)[]; denom?: string }): TransferBatchPlanV2;
export function planWithdrawNotesV2(input?: { notes?: FoundNote128Input[]; amount?: string | bigint; denom?: string }): WithdrawPlanV2;
