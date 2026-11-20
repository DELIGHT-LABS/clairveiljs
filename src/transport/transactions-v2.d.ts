import type { AuditSnapshotV2 } from "../privacy/audit-config-v2.js";
import type { MsgDeposit, MsgTransfer, MsgWithdraw } from "../generated/clairveil/privacy/v2/tx.js";
import type { EvmDepositRequestV2, EvmTransferRequestV2, EvmWithdrawRequestV2 } from "./evm-v2.js";
export type DirectAuditMessageV2 = MsgDeposit | MsgTransfer | MsgWithdraw;
export interface DirectAuditTransactionInputV2 { kind:"deposit"|"transfer"|"withdraw"; message:DirectAuditMessageV2; snapshot:AuditSnapshotV2 }
export function validateDirectAuditMessageV2(input:DirectAuditTransactionInputV2):DirectAuditMessageV2;
export function buildCosmosTransactionV2(input:DirectAuditTransactionInputV2 & {
  actor:{namespace:"cosmos";chainId:string;address:string;pubKeyHex:string}; accountNumber:string|bigint; sequence:string|bigint;
  gasLimit:number;feeAmount?:{denom:string;amount:string}[];memo?:string;
}):{message:DirectAuditMessageV2;signDoc:{bodyBytes:string;authInfoBytes:string;chainId:string;accountNumber:string}};
export function evmRequestFromMessageV2(kind:DirectAuditTransactionInputV2["kind"],message:DirectAuditMessageV2,accountPrefix:string):EvmDepositRequestV2|EvmTransferRequestV2|EvmWithdrawRequestV2;
export function buildEvmTransactionV2(input:DirectAuditTransactionInputV2 & {
  actor:{namespace:"eip155";chainId:string;address:string};nativeDenom:string;contractAddress:string;
  transactionOptions:{from:string;to:string;chainId:string;gas:string;nonce:string;maxFeePerGas:string;maxPriorityFeePerGas:string};
}):{message:DirectAuditMessageV2;transaction:Record<string,string>};
