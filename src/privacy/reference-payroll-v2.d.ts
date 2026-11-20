import type { Amount128Input } from "../core/amount.js";
import type {
  PayrollInput, TreasuryNote, NormalizedPayrollInput,
  PayrollPlanFields, PayrollOperationPlanFields
} from "./payroll-types.js";

export interface PayrollInputV2 extends PayrollInput<Amount128Input> {}
export interface TreasuryNoteV2 extends TreasuryNote<Amount128Input> {}
export interface NormalizedTreasuryNoteV2 extends TreasuryNote<bigint> {
  note_id: string;
  owner_key_id: string;
  nullifier_lookup_key: string;
  nullifier_lookup_key_id: string;
  is_spent: boolean;
  reservation_id: string;
}
export interface OneProofPayrollOperationPlanV2 extends PayrollOperationPlanFields<NormalizedTreasuryNoteV2> {
  amount_model: "uint128";
  circuit_set_id?: never;
}
export interface PayrollPlanV2 extends PayrollPlanFields<OneProofPayrollOperationPlanV2> {
  amount_model: "uint128";
  circuit_set_id?: never;
  operations: OneProofPayrollOperationPlanV2[];
  total_payroll_amount: bigint;
  total_spendable_amount: bigint;
}
export interface PayrollPlanningOptionsV2 {
  shieldedPrefix?: string;
  output_mode?: "compact" | "exact32" | "exact-32";
  outputMode?: "compact" | "exact32" | "exact-32";
  search_limit?: number;
  searchLimit?: number;
}
export function normalizePayrollInputV2(input: PayrollInputV2, options?: PayrollPlanningOptionsV2): NormalizedPayrollInput;
/** Bounded amount eligibility, not a proof-ready or executable transaction. */
export function planOneProofPayrollV2(input: PayrollInputV2, notes?: TreasuryNoteV2[], options?: PayrollPlanningOptionsV2): PayrollPlanV2;
