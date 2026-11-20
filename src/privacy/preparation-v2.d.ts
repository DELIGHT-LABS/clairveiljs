import type { Amount128Input } from "../core/amount.js";
import type { FoundNote128Input } from "../core/note128.js";
import type { OutputEffect } from "../generated/clairveil/privacy/v2/tx.js";
export interface DepositMaterialV2 {
  amount: string; output: OutputEffect; plaintext: Uint8Array; auditPlaintext: Uint8Array[];
  clear(): void; toJSON(): never;
}
export interface SpendInputsV2 {
  amount: string; total: bigint; change: bigint; plaintexts: Uint8Array[];
  commitments: Uint8Array[]; nullifiers: Uint8Array[]; clear(): void; toJSON(): never;
}
export function prepareDepositMaterialV2(input: { rootSeed: Uint8Array; amount: Amount128Input; denom: string; memo?: string }): DepositMaterialV2;
export function prepareSpendInputsV2(input: { kind: "transfer" | "withdraw"; rootSeed: Uint8Array; notes: FoundNote128Input[]; amount: Amount128Input; denom: string }): SpendInputsV2;
