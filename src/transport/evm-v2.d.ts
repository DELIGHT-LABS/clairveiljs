import type { AbiParameter } from "./evm-abi.js";
import type { AuditAuthorization, OutputEffect } from "../generated/clairveil/privacy/v2/tx.js";
export type DirectPrivacyOperationV2 = "deposit" | "transfer" | "withdraw";
export interface EvmDepositRequestV2 { output: OutputEffect; proof: Uint8Array; expiresAtUnix: bigint; audit: AuditAuthorization }
export interface EvmTransferRequestV2 { proof: Uint8Array; root: Uint8Array; nullifiers: Uint8Array[]; outputs: OutputEffect[]; expiresAtUnix: bigint; audit: AuditAuthorization }
export interface EvmWithdrawRequestV2 { proof: Uint8Array; root: Uint8Array; nullifier: Uint8Array; amount: string; recipient: string; expiresAtUnix: bigint; audit: AuditAuthorization }
export const evmPrivacyV2Abi: readonly { readonly type: "function"; readonly name: DirectPrivacyOperationV2; readonly inputs: readonly AbiParameter[]; readonly outputs: readonly AbiParameter[]; readonly stateMutability: "payable" | "nonpayable" }[];
/** Wire encoding only; not proof, chain, actor or payable value verification. */
export function encodeEvmPrivacyRequestV2(kind: "deposit", request: EvmDepositRequestV2): string;
export function encodeEvmPrivacyRequestV2(kind: "transfer", request: EvmTransferRequestV2): string;
export function encodeEvmPrivacyRequestV2(kind: "withdraw", request: EvmWithdrawRequestV2): string;
export function encodeEvmPrivacyRequestV2(kind: DirectPrivacyOperationV2, request: EvmDepositRequestV2 | EvmTransferRequestV2 | EvmWithdrawRequestV2): string;
export function decodeEvmPrivacyRequestV2(kind: DirectPrivacyOperationV2, calldata: string): EvmDepositRequestV2 | EvmTransferRequestV2 | EvmWithdrawRequestV2;
export function verifyEvmEffectV2(input:{kind:DirectPrivacyOperationV2;request:EvmDepositRequestV2|EvmTransferRequestV2|EvmWithdrawRequestV2;creator:string;accountPrefix:string;amount?:string;transaction:Record<string,string>;rpcTransaction:Record<string,unknown>;receipt?:Record<string,unknown>;txHash:string}):true;
