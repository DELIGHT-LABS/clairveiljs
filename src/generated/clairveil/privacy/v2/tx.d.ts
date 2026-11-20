import { BinaryReader, BinaryWriter } from "../../../binary.js";
import { DeepPartial } from "../../../helpers.js";
/**
 * @name AuditAuthorization
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.AuditAuthorization
 */
export interface AuditAuthorization {
    keyId: Uint8Array;
    epoch: bigint;
    envelope: Uint8Array;
}
/**
 * @name OutputEffect
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.OutputEffect
 */
export interface OutputEffect {
    commitment: Uint8Array;
    ciphertext: Uint8Array;
    viewTag: Uint8Array;
    userPrivacyPolicy: number;
    userDisclosureMode: number;
    userDisclosureDigest: Uint8Array;
    userDisclosureTargetPubkey: Uint8Array;
    userDisclosurePayload: Uint8Array;
    selfFullDisclosureDigest: Uint8Array;
    selfViewDisclosurePayload: Uint8Array;
}
/**
 * @name MsgDeposit
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgDeposit
 */
export interface MsgDeposit {
    creator: string;
    amount: string;
    output?: OutputEffect;
    proof: Uint8Array;
    expiresAtUnix: bigint;
    audit?: AuditAuthorization;
}
/**
 * @name MsgWithdraw
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgWithdraw
 */
export interface MsgWithdraw {
    creator: string;
    amount: string;
    recipient: string;
    root: Uint8Array;
    nullifier: Uint8Array;
    proof: Uint8Array;
    expiresAtUnix: bigint;
    audit?: AuditAuthorization;
}
/**
 * @name MsgTransfer
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgTransfer
 */
export interface MsgTransfer {
    creator: string;
    root: Uint8Array;
    nullifiers: Uint8Array[];
    outputs: OutputEffect[];
    proof: Uint8Array;
    expiresAtUnix: bigint;
    audit?: AuditAuthorization;
}
/**
 * @name MsgBatchTransfer
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgBatchTransfer
 */
export interface MsgBatchTransfer {
    creator: string;
    root: Uint8Array;
    nullifiers: Uint8Array[];
    outputs: OutputEffect[];
    proof: Uint8Array;
    expiresAtUnix: bigint;
    audit?: AuditAuthorization;
}
/**
 * @name MsgScheduleAuditKeyEpoch
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgScheduleAuditKeyEpoch
 */
export interface MsgScheduleAuditKeyEpoch {
    authority: string;
    epoch: bigint;
    activationHeight: bigint;
    publicKey: Uint8Array;
    suite: number;
    possessionProof: Uint8Array;
}
/**
 * @name MsgCancelPendingAuditEpoch
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgCancelPendingAuditEpoch
 */
export interface MsgCancelPendingAuditEpoch {
    authority: string;
    epoch: bigint;
}
/**
 * @name MsgSetPrivacyHalt
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgSetPrivacyHalt
 */
export interface MsgSetPrivacyHalt {
    authority: string;
    halted: boolean;
}
/**
 * Field 1 remains permanently reserved after removal of the transition cursor.
 * @name MsgDepositResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgDepositResponse
 */
export interface MsgDepositResponse {
}
/**
 * @name MsgWithdrawResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgWithdrawResponse
 */
export interface MsgWithdrawResponse {
}
/**
 * @name MsgTransferResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgTransferResponse
 */
export interface MsgTransferResponse {
}
/**
 * @name MsgBatchTransferResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgBatchTransferResponse
 */
export interface MsgBatchTransferResponse {
}
/**
 * @name MsgScheduleAuditKeyEpochResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgScheduleAuditKeyEpochResponse
 */
export interface MsgScheduleAuditKeyEpochResponse {
}
/**
 * @name MsgCancelPendingAuditEpochResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgCancelPendingAuditEpochResponse
 */
export interface MsgCancelPendingAuditEpochResponse {
}
/**
 * @name MsgSetPrivacyHaltResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgSetPrivacyHaltResponse
 */
export interface MsgSetPrivacyHaltResponse {
}
/**
 * @name AuditAuthorization
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.AuditAuthorization
 */
export declare const AuditAuthorization: {
    typeUrl: string;
    encode(message: AuditAuthorization, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): AuditAuthorization;
    fromPartial(object: DeepPartial<AuditAuthorization>): AuditAuthorization;
};
/**
 * @name OutputEffect
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.OutputEffect
 */
export declare const OutputEffect: {
    typeUrl: string;
    encode(message: OutputEffect, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): OutputEffect;
    fromPartial(object: DeepPartial<OutputEffect>): OutputEffect;
};
/**
 * @name MsgDeposit
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgDeposit
 */
export declare const MsgDeposit: {
    typeUrl: string;
    encode(message: MsgDeposit, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgDeposit;
    fromPartial(object: DeepPartial<MsgDeposit>): MsgDeposit;
};
/**
 * @name MsgWithdraw
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgWithdraw
 */
export declare const MsgWithdraw: {
    typeUrl: string;
    encode(message: MsgWithdraw, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgWithdraw;
    fromPartial(object: DeepPartial<MsgWithdraw>): MsgWithdraw;
};
/**
 * @name MsgTransfer
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgTransfer
 */
export declare const MsgTransfer: {
    typeUrl: string;
    encode(message: MsgTransfer, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgTransfer;
    fromPartial(object: DeepPartial<MsgTransfer>): MsgTransfer;
};
/**
 * @name MsgBatchTransfer
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgBatchTransfer
 */
export declare const MsgBatchTransfer: {
    typeUrl: string;
    encode(message: MsgBatchTransfer, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgBatchTransfer;
    fromPartial(object: DeepPartial<MsgBatchTransfer>): MsgBatchTransfer;
};
/**
 * @name MsgScheduleAuditKeyEpoch
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgScheduleAuditKeyEpoch
 */
export declare const MsgScheduleAuditKeyEpoch: {
    typeUrl: string;
    encode(message: MsgScheduleAuditKeyEpoch, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgScheduleAuditKeyEpoch;
    fromPartial(object: DeepPartial<MsgScheduleAuditKeyEpoch>): MsgScheduleAuditKeyEpoch;
};
/**
 * @name MsgCancelPendingAuditEpoch
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgCancelPendingAuditEpoch
 */
export declare const MsgCancelPendingAuditEpoch: {
    typeUrl: string;
    encode(message: MsgCancelPendingAuditEpoch, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgCancelPendingAuditEpoch;
    fromPartial(object: DeepPartial<MsgCancelPendingAuditEpoch>): MsgCancelPendingAuditEpoch;
};
/**
 * @name MsgSetPrivacyHalt
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgSetPrivacyHalt
 */
export declare const MsgSetPrivacyHalt: {
    typeUrl: string;
    encode(message: MsgSetPrivacyHalt, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgSetPrivacyHalt;
    fromPartial(object: DeepPartial<MsgSetPrivacyHalt>): MsgSetPrivacyHalt;
};
/**
 * Field 1 remains permanently reserved after removal of the transition cursor.
 * @name MsgDepositResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgDepositResponse
 */
export declare const MsgDepositResponse: {
    typeUrl: string;
    encode(_: MsgDepositResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgDepositResponse;
    fromPartial(_: DeepPartial<MsgDepositResponse>): MsgDepositResponse;
};
/**
 * @name MsgWithdrawResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgWithdrawResponse
 */
export declare const MsgWithdrawResponse: {
    typeUrl: string;
    encode(_: MsgWithdrawResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgWithdrawResponse;
    fromPartial(_: DeepPartial<MsgWithdrawResponse>): MsgWithdrawResponse;
};
/**
 * @name MsgTransferResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgTransferResponse
 */
export declare const MsgTransferResponse: {
    typeUrl: string;
    encode(_: MsgTransferResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgTransferResponse;
    fromPartial(_: DeepPartial<MsgTransferResponse>): MsgTransferResponse;
};
/**
 * @name MsgBatchTransferResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgBatchTransferResponse
 */
export declare const MsgBatchTransferResponse: {
    typeUrl: string;
    encode(_: MsgBatchTransferResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgBatchTransferResponse;
    fromPartial(_: DeepPartial<MsgBatchTransferResponse>): MsgBatchTransferResponse;
};
/**
 * @name MsgScheduleAuditKeyEpochResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgScheduleAuditKeyEpochResponse
 */
export declare const MsgScheduleAuditKeyEpochResponse: {
    typeUrl: string;
    encode(_: MsgScheduleAuditKeyEpochResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgScheduleAuditKeyEpochResponse;
    fromPartial(_: DeepPartial<MsgScheduleAuditKeyEpochResponse>): MsgScheduleAuditKeyEpochResponse;
};
/**
 * @name MsgCancelPendingAuditEpochResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgCancelPendingAuditEpochResponse
 */
export declare const MsgCancelPendingAuditEpochResponse: {
    typeUrl: string;
    encode(_: MsgCancelPendingAuditEpochResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgCancelPendingAuditEpochResponse;
    fromPartial(_: DeepPartial<MsgCancelPendingAuditEpochResponse>): MsgCancelPendingAuditEpochResponse;
};
/**
 * @name MsgSetPrivacyHaltResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgSetPrivacyHaltResponse
 */
export declare const MsgSetPrivacyHaltResponse: {
    typeUrl: string;
    encode(_: MsgSetPrivacyHaltResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgSetPrivacyHaltResponse;
    fromPartial(_: DeepPartial<MsgSetPrivacyHaltResponse>): MsgSetPrivacyHaltResponse;
};
