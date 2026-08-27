import type { Hex } from "../core/crypto.js";

export type EvmFinalityMode = "receipt" | "confirmations" | "safe" | "finalized" | "custom";
export type EvmJsonRpcQuery = (method: string, params?: readonly unknown[]) => Promise<unknown>;

export interface EvmReceiptFinalityPolicy {
  mode: "receipt";
}

export interface EvmConfirmationFinalityPolicy {
  mode: "confirmations";
  confirmations: number;
}

export interface EvmBlockTagFinalityPolicy {
  mode: "safe" | "finalized";
}

export interface EvmCustomFinalityContext {
  readonly txHash: Hex | string;
  readonly receipt: object;
  readonly rpc: EvmJsonRpcQuery;
  readonly attempts: number;
  readonly intervalMs: number;
}

export interface EvmFinalityEvidence {
  readonly verified: boolean;
  readonly mode: EvmFinalityMode;
  readonly txHash: Hex | string;
  readonly blockNumber?: Hex | string;
  readonly blockHash?: Hex | string;
  readonly finalityBlockNumber?: Hex | string;
  readonly confirmations?: number;
  readonly blockTag?: "safe" | "finalized";
  readonly error?: string;
  readonly [key: string]: unknown;
}

export interface EvmCustomFinalityPolicy {
  mode: "custom";
  waitForFinality(context: EvmCustomFinalityContext): EvmFinalityEvidence | Promise<EvmFinalityEvidence>;
}

export type EvmFinalityPolicy =
  | EvmReceiptFinalityPolicy
  | EvmConfirmationFinalityPolicy
  | EvmBlockTagFinalityPolicy
  | EvmCustomFinalityPolicy;

export const evmFinalityModes: readonly EvmFinalityMode[];
export function createEvmFinalityPolicy(
  input: EvmFinalityMode | EvmFinalityPolicy
): Readonly<EvmFinalityPolicy>;
export function waitForEvmFinality(input: {
  txHash: Hex | string;
  receipt: object;
  rpc: EvmJsonRpcQuery;
  policy: EvmFinalityMode | EvmFinalityPolicy;
  attempts?: number;
  intervalMs?: number;
}): Promise<Readonly<EvmFinalityEvidence>>;
