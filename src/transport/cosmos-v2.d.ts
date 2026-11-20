import type { ClairveilRegistry, ClairveilRegistryGeneratedType } from "./cosmos-registry.js";

/** Core v0.6.1 wire bindings. No V2 preparation, proving, or wallet workflow is implied. */
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

export const msgDepositV2TypeUrl: "/clairveil.privacy.v2.MsgDeposit";
export const msgWithdrawV2TypeUrl: "/clairveil.privacy.v2.MsgWithdraw";
export const msgTransferV2TypeUrl: "/clairveil.privacy.v2.MsgTransfer";
export const msgBatchTransferV2TypeUrl: "/clairveil.privacy.v2.MsgBatchTransfer";
export const msgScheduleAuditKeyEpochV2TypeUrl: "/clairveil.privacy.v2.MsgScheduleAuditKeyEpoch";
export const msgCancelPendingAuditEpochV2TypeUrl: "/clairveil.privacy.v2.MsgCancelPendingAuditEpoch";
export const msgSetPrivacyHaltV2TypeUrl: "/clairveil.privacy.v2.MsgSetPrivacyHalt";
export function createClairveilV2Registry(
  extraTypes?: ReadonlyArray<readonly [string, ClairveilRegistryGeneratedType]>
): ClairveilRegistry;
