import { UserDisclosureMode } from "./tx.js";
import { BinaryReader, BinaryWriter } from "../../../binary.js";
import { DeepPartial } from "../../../helpers.js";
/**
 * These messages freeze and measure the BatchJoinSplit16x32 maximum wire shape. They are
 * not registered with the Msg service and do not authorize a state transition.
 * @name BatchTransferWirePrototypeV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.BatchTransferWirePrototypeV1
 */
export interface BatchTransferWirePrototypeV1 {
    creator: string;
    proof: Uint8Array;
    root: Uint8Array;
    nullifiers: Uint8Array[];
    outputs: BatchTransferOutputWirePrototypeV1[];
    /**
     * Canonical lowercase ASCII [a-z0-9][a-z0-9._-]*, 1..64 bytes.
     */
    auditKeyId: string;
    auditKeyEpoch: bigint;
    auditDisclosureTargetPubkey: Uint8Array;
    expiresAtUnix: bigint;
}
/**
 * @name BatchTransferOutputWirePrototypeV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.BatchTransferOutputWirePrototypeV1
 */
export interface BatchTransferOutputWirePrototypeV1 {
    commitment: Uint8Array;
    ciphertext: Uint8Array;
    viewTag: Uint8Array;
    userPrivacyPolicy: number;
    userDisclosureMode: UserDisclosureMode;
    userDisclosureDigest: Uint8Array;
    userDisclosureTargetPubkey: Uint8Array;
    userDisclosurePayload: Uint8Array;
    fullDisclosureDigest: Uint8Array;
    auditDisclosurePayload: Uint8Array;
    selfViewDisclosurePayload: Uint8Array;
}
/**
 * BatchMinimalEventWirePrototypeV1 measures the binary form of the summary
 * attributes. No ciphertext, disclosure payload, or full value list appears.
 * @name BatchMinimalEventWirePrototypeV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.BatchMinimalEventWirePrototypeV1
 */
export interface BatchMinimalEventWirePrototypeV1 {
    effectId: Uint8Array;
    relayer: string;
    inputCount: number;
    outputCount: number;
    nullifierRoot: Uint8Array;
    commitmentRoot: Uint8Array;
    userDisclosureRoot: Uint8Array;
    fullDisclosureRoot: Uint8Array;
    expiresAtUnix: bigint;
}
/**
 * These messages freeze and measure the BatchJoinSplit16x32 maximum wire shape. They are
 * not registered with the Msg service and do not authorize a state transition.
 * @name BatchTransferWirePrototypeV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.BatchTransferWirePrototypeV1
 */
export declare const BatchTransferWirePrototypeV1: {
    typeUrl: string;
    encode(message: BatchTransferWirePrototypeV1, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): BatchTransferWirePrototypeV1;
    fromPartial(object: DeepPartial<BatchTransferWirePrototypeV1>): BatchTransferWirePrototypeV1;
};
/**
 * @name BatchTransferOutputWirePrototypeV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.BatchTransferOutputWirePrototypeV1
 */
export declare const BatchTransferOutputWirePrototypeV1: {
    typeUrl: string;
    encode(message: BatchTransferOutputWirePrototypeV1, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): BatchTransferOutputWirePrototypeV1;
    fromPartial(object: DeepPartial<BatchTransferOutputWirePrototypeV1>): BatchTransferOutputWirePrototypeV1;
};
/**
 * BatchMinimalEventWirePrototypeV1 measures the binary form of the summary
 * attributes. No ciphertext, disclosure payload, or full value list appears.
 * @name BatchMinimalEventWirePrototypeV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.BatchMinimalEventWirePrototypeV1
 */
export declare const BatchMinimalEventWirePrototypeV1: {
    typeUrl: string;
    encode(message: BatchMinimalEventWirePrototypeV1, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): BatchMinimalEventWirePrototypeV1;
    fromPartial(object: DeepPartial<BatchMinimalEventWirePrototypeV1>): BatchMinimalEventWirePrototypeV1;
};
