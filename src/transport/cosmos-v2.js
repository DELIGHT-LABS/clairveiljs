import { Registry } from "@cosmjs/proto-signing";
import { defaultRegistryTypes } from "@cosmjs/stargate";
import {
  MsgDeposit,
  MsgWithdraw,
  MsgTransfer,
  MsgBatchTransfer,
  MsgScheduleAuditKeyEpoch,
  MsgCancelPendingAuditEpoch,
  MsgSetPrivacyHalt
} from "../generated/clairveil/privacy/v2/tx.js";

// Wire bindings only. These exports neither prepare audit authorization nor
// change the legacy wallet/kernel transaction or prover flows.
export {
  AuditAuthorization as AuditAuthorizationV2,
  OutputEffect as OutputEffectV2,
  MsgDeposit as MsgDepositV2,
  MsgDepositResponse as MsgDepositResponseV2,
  MsgWithdraw as MsgWithdrawV2,
  MsgWithdrawResponse as MsgWithdrawResponseV2,
  MsgTransfer as MsgTransferV2,
  MsgTransferResponse as MsgTransferResponseV2,
  MsgBatchTransfer as MsgBatchTransferV2,
  MsgBatchTransferResponse as MsgBatchTransferResponseV2,
  MsgScheduleAuditKeyEpoch as MsgScheduleAuditKeyEpochV2,
  MsgScheduleAuditKeyEpochResponse as MsgScheduleAuditKeyEpochResponseV2,
  MsgCancelPendingAuditEpoch as MsgCancelPendingAuditEpochV2,
  MsgCancelPendingAuditEpochResponse as MsgCancelPendingAuditEpochResponseV2,
  MsgSetPrivacyHalt as MsgSetPrivacyHaltV2,
  MsgSetPrivacyHaltResponse as MsgSetPrivacyHaltResponseV2
} from "../generated/clairveil/privacy/v2/tx.js";
export {
  QueryAuditKeyRequest as QueryAuditKeyRequestV2,
  QueryAuditRecordResponse as QueryAuditRecordResponseV2,
  QueryAuditKeyScheduleRequest as QueryAuditKeyScheduleRequestV2,
  QueryAuditKeyScheduleResponse as QueryAuditKeyScheduleResponseV2,
  QueryAuditConfigurationRequest as QueryAuditConfigurationRequestV2,
  QueryAuditConfigurationResponse as QueryAuditConfigurationResponseV2
} from "../generated/clairveil/privacy/v2/query.js";

export const msgDepositV2TypeUrl = MsgDeposit.typeUrl;
export const msgWithdrawV2TypeUrl = MsgWithdraw.typeUrl;
export const msgTransferV2TypeUrl = MsgTransfer.typeUrl;
export const msgBatchTransferV2TypeUrl = MsgBatchTransfer.typeUrl;
export const msgScheduleAuditKeyEpochV2TypeUrl = MsgScheduleAuditKeyEpoch.typeUrl;
export const msgCancelPendingAuditEpochV2TypeUrl = MsgCancelPendingAuditEpoch.typeUrl;
export const msgSetPrivacyHaltV2TypeUrl = MsgSetPrivacyHalt.typeUrl;

/** Explicit V2 message registration; the existing V1 registry stays unchanged. */
export function createClairveilV2Registry(extraTypes = []) {
  return new Registry([
    ...defaultRegistryTypes,
    ...[
      MsgDeposit, MsgWithdraw, MsgTransfer, MsgBatchTransfer,
      MsgScheduleAuditKeyEpoch, MsgCancelPendingAuditEpoch, MsgSetPrivacyHalt
    ].map(codec => [codec.typeUrl, codec]),
    ...extraTypes
  ]);
}
