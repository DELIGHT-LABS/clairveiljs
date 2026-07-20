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
function createBaseBatchTransferWirePrototypeV1(): BatchTransferWirePrototypeV1 {
  return {
    creator: "",
    proof: new Uint8Array(),
    root: new Uint8Array(),
    nullifiers: [],
    outputs: [],
    auditKeyId: "",
    auditKeyEpoch: BigInt(0),
    auditDisclosureTargetPubkey: new Uint8Array(),
    expiresAtUnix: BigInt(0)
  };
}
/**
 * These messages freeze and measure the BatchJoinSplit16x32 maximum wire shape. They are
 * not registered with the Msg service and do not authorize a state transition.
 * @name BatchTransferWirePrototypeV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.BatchTransferWirePrototypeV1
 */
export const BatchTransferWirePrototypeV1 = {
  typeUrl: "/clairveil.privacy.v1.BatchTransferWirePrototypeV1",
  encode(message: BatchTransferWirePrototypeV1, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.creator !== "") {
      writer.uint32(10).string(message.creator);
    }
    if (message.proof.length !== 0) {
      writer.uint32(18).bytes(message.proof);
    }
    if (message.root.length !== 0) {
      writer.uint32(26).bytes(message.root);
    }
    for (const v of message.nullifiers) {
      writer.uint32(34).bytes(v!);
    }
    for (const v of message.outputs) {
      BatchTransferOutputWirePrototypeV1.encode(v!, writer.uint32(42).fork()).ldelim();
    }
    if (message.auditKeyId !== "") {
      writer.uint32(50).string(message.auditKeyId);
    }
    if (message.auditKeyEpoch !== BigInt(0)) {
      writer.uint32(56).uint64(message.auditKeyEpoch);
    }
    if (message.auditDisclosureTargetPubkey.length !== 0) {
      writer.uint32(66).bytes(message.auditDisclosureTargetPubkey);
    }
    if (message.expiresAtUnix !== BigInt(0)) {
      writer.uint32(72).int64(message.expiresAtUnix);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): BatchTransferWirePrototypeV1 {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseBatchTransferWirePrototypeV1();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.creator = reader.string();
          break;
        case 2:
          message.proof = reader.bytes();
          break;
        case 3:
          message.root = reader.bytes();
          break;
        case 4:
          message.nullifiers.push(reader.bytes());
          break;
        case 5:
          message.outputs.push(BatchTransferOutputWirePrototypeV1.decode(reader, reader.uint32()));
          break;
        case 6:
          message.auditKeyId = reader.string();
          break;
        case 7:
          message.auditKeyEpoch = reader.uint64();
          break;
        case 8:
          message.auditDisclosureTargetPubkey = reader.bytes();
          break;
        case 9:
          message.expiresAtUnix = reader.int64();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<BatchTransferWirePrototypeV1>): BatchTransferWirePrototypeV1 {
    const message = createBaseBatchTransferWirePrototypeV1();
    message.creator = object.creator ?? "";
    message.proof = object.proof ?? new Uint8Array();
    message.root = object.root ?? new Uint8Array();
    message.nullifiers = object.nullifiers?.map(e => e) || [];
    message.outputs = object.outputs?.map(e => BatchTransferOutputWirePrototypeV1.fromPartial(e)) || [];
    message.auditKeyId = object.auditKeyId ?? "";
    message.auditKeyEpoch = object.auditKeyEpoch !== undefined && object.auditKeyEpoch !== null ? BigInt(object.auditKeyEpoch.toString()) : BigInt(0);
    message.auditDisclosureTargetPubkey = object.auditDisclosureTargetPubkey ?? new Uint8Array();
    message.expiresAtUnix = object.expiresAtUnix !== undefined && object.expiresAtUnix !== null ? BigInt(object.expiresAtUnix.toString()) : BigInt(0);
    return message;
  }
};
function createBaseBatchTransferOutputWirePrototypeV1(): BatchTransferOutputWirePrototypeV1 {
  return {
    commitment: new Uint8Array(),
    ciphertext: new Uint8Array(),
    viewTag: new Uint8Array(),
    userPrivacyPolicy: 0,
    userDisclosureMode: 0,
    userDisclosureDigest: new Uint8Array(),
    userDisclosureTargetPubkey: new Uint8Array(),
    userDisclosurePayload: new Uint8Array(),
    fullDisclosureDigest: new Uint8Array(),
    auditDisclosurePayload: new Uint8Array(),
    selfViewDisclosurePayload: new Uint8Array()
  };
}
/**
 * @name BatchTransferOutputWirePrototypeV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.BatchTransferOutputWirePrototypeV1
 */
export const BatchTransferOutputWirePrototypeV1 = {
  typeUrl: "/clairveil.privacy.v1.BatchTransferOutputWirePrototypeV1",
  encode(message: BatchTransferOutputWirePrototypeV1, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.commitment.length !== 0) {
      writer.uint32(10).bytes(message.commitment);
    }
    if (message.ciphertext.length !== 0) {
      writer.uint32(18).bytes(message.ciphertext);
    }
    if (message.viewTag.length !== 0) {
      writer.uint32(26).bytes(message.viewTag);
    }
    if (message.userPrivacyPolicy !== 0) {
      writer.uint32(32).uint32(message.userPrivacyPolicy);
    }
    if (message.userDisclosureMode !== 0) {
      writer.uint32(40).int32(message.userDisclosureMode);
    }
    if (message.userDisclosureDigest.length !== 0) {
      writer.uint32(50).bytes(message.userDisclosureDigest);
    }
    if (message.userDisclosureTargetPubkey.length !== 0) {
      writer.uint32(58).bytes(message.userDisclosureTargetPubkey);
    }
    if (message.userDisclosurePayload.length !== 0) {
      writer.uint32(66).bytes(message.userDisclosurePayload);
    }
    if (message.fullDisclosureDigest.length !== 0) {
      writer.uint32(74).bytes(message.fullDisclosureDigest);
    }
    if (message.auditDisclosurePayload.length !== 0) {
      writer.uint32(82).bytes(message.auditDisclosurePayload);
    }
    if (message.selfViewDisclosurePayload.length !== 0) {
      writer.uint32(90).bytes(message.selfViewDisclosurePayload);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): BatchTransferOutputWirePrototypeV1 {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseBatchTransferOutputWirePrototypeV1();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.commitment = reader.bytes();
          break;
        case 2:
          message.ciphertext = reader.bytes();
          break;
        case 3:
          message.viewTag = reader.bytes();
          break;
        case 4:
          message.userPrivacyPolicy = reader.uint32();
          break;
        case 5:
          message.userDisclosureMode = reader.int32() as any;
          break;
        case 6:
          message.userDisclosureDigest = reader.bytes();
          break;
        case 7:
          message.userDisclosureTargetPubkey = reader.bytes();
          break;
        case 8:
          message.userDisclosurePayload = reader.bytes();
          break;
        case 9:
          message.fullDisclosureDigest = reader.bytes();
          break;
        case 10:
          message.auditDisclosurePayload = reader.bytes();
          break;
        case 11:
          message.selfViewDisclosurePayload = reader.bytes();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<BatchTransferOutputWirePrototypeV1>): BatchTransferOutputWirePrototypeV1 {
    const message = createBaseBatchTransferOutputWirePrototypeV1();
    message.commitment = object.commitment ?? new Uint8Array();
    message.ciphertext = object.ciphertext ?? new Uint8Array();
    message.viewTag = object.viewTag ?? new Uint8Array();
    message.userPrivacyPolicy = object.userPrivacyPolicy ?? 0;
    message.userDisclosureMode = object.userDisclosureMode ?? 0;
    message.userDisclosureDigest = object.userDisclosureDigest ?? new Uint8Array();
    message.userDisclosureTargetPubkey = object.userDisclosureTargetPubkey ?? new Uint8Array();
    message.userDisclosurePayload = object.userDisclosurePayload ?? new Uint8Array();
    message.fullDisclosureDigest = object.fullDisclosureDigest ?? new Uint8Array();
    message.auditDisclosurePayload = object.auditDisclosurePayload ?? new Uint8Array();
    message.selfViewDisclosurePayload = object.selfViewDisclosurePayload ?? new Uint8Array();
    return message;
  }
};
function createBaseBatchMinimalEventWirePrototypeV1(): BatchMinimalEventWirePrototypeV1 {
  return {
    effectId: new Uint8Array(),
    relayer: "",
    inputCount: 0,
    outputCount: 0,
    nullifierRoot: new Uint8Array(),
    commitmentRoot: new Uint8Array(),
    userDisclosureRoot: new Uint8Array(),
    fullDisclosureRoot: new Uint8Array(),
    expiresAtUnix: BigInt(0)
  };
}
/**
 * BatchMinimalEventWirePrototypeV1 measures the binary form of the summary
 * attributes. No ciphertext, disclosure payload, or full value list appears.
 * @name BatchMinimalEventWirePrototypeV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.BatchMinimalEventWirePrototypeV1
 */
export const BatchMinimalEventWirePrototypeV1 = {
  typeUrl: "/clairveil.privacy.v1.BatchMinimalEventWirePrototypeV1",
  encode(message: BatchMinimalEventWirePrototypeV1, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.effectId.length !== 0) {
      writer.uint32(10).bytes(message.effectId);
    }
    if (message.relayer !== "") {
      writer.uint32(18).string(message.relayer);
    }
    if (message.inputCount !== 0) {
      writer.uint32(24).uint32(message.inputCount);
    }
    if (message.outputCount !== 0) {
      writer.uint32(32).uint32(message.outputCount);
    }
    if (message.nullifierRoot.length !== 0) {
      writer.uint32(42).bytes(message.nullifierRoot);
    }
    if (message.commitmentRoot.length !== 0) {
      writer.uint32(50).bytes(message.commitmentRoot);
    }
    if (message.userDisclosureRoot.length !== 0) {
      writer.uint32(58).bytes(message.userDisclosureRoot);
    }
    if (message.fullDisclosureRoot.length !== 0) {
      writer.uint32(66).bytes(message.fullDisclosureRoot);
    }
    if (message.expiresAtUnix !== BigInt(0)) {
      writer.uint32(72).int64(message.expiresAtUnix);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): BatchMinimalEventWirePrototypeV1 {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseBatchMinimalEventWirePrototypeV1();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.effectId = reader.bytes();
          break;
        case 2:
          message.relayer = reader.string();
          break;
        case 3:
          message.inputCount = reader.uint32();
          break;
        case 4:
          message.outputCount = reader.uint32();
          break;
        case 5:
          message.nullifierRoot = reader.bytes();
          break;
        case 6:
          message.commitmentRoot = reader.bytes();
          break;
        case 7:
          message.userDisclosureRoot = reader.bytes();
          break;
        case 8:
          message.fullDisclosureRoot = reader.bytes();
          break;
        case 9:
          message.expiresAtUnix = reader.int64();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<BatchMinimalEventWirePrototypeV1>): BatchMinimalEventWirePrototypeV1 {
    const message = createBaseBatchMinimalEventWirePrototypeV1();
    message.effectId = object.effectId ?? new Uint8Array();
    message.relayer = object.relayer ?? "";
    message.inputCount = object.inputCount ?? 0;
    message.outputCount = object.outputCount ?? 0;
    message.nullifierRoot = object.nullifierRoot ?? new Uint8Array();
    message.commitmentRoot = object.commitmentRoot ?? new Uint8Array();
    message.userDisclosureRoot = object.userDisclosureRoot ?? new Uint8Array();
    message.fullDisclosureRoot = object.fullDisclosureRoot ?? new Uint8Array();
    message.expiresAtUnix = object.expiresAtUnix !== undefined && object.expiresAtUnix !== null ? BigInt(object.expiresAtUnix.toString()) : BigInt(0);
    return message;
  }
};