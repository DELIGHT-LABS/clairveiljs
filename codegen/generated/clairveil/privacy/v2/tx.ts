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
export interface MsgDepositResponse {}
/**
 * @name MsgWithdrawResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgWithdrawResponse
 */
export interface MsgWithdrawResponse {}
/**
 * @name MsgTransferResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgTransferResponse
 */
export interface MsgTransferResponse {}
/**
 * @name MsgBatchTransferResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgBatchTransferResponse
 */
export interface MsgBatchTransferResponse {}
/**
 * @name MsgScheduleAuditKeyEpochResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgScheduleAuditKeyEpochResponse
 */
export interface MsgScheduleAuditKeyEpochResponse {}
/**
 * @name MsgCancelPendingAuditEpochResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgCancelPendingAuditEpochResponse
 */
export interface MsgCancelPendingAuditEpochResponse {}
/**
 * @name MsgSetPrivacyHaltResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgSetPrivacyHaltResponse
 */
export interface MsgSetPrivacyHaltResponse {}
function createBaseAuditAuthorization(): AuditAuthorization {
  return {
    keyId: new Uint8Array(),
    epoch: BigInt(0),
    envelope: new Uint8Array()
  };
}
/**
 * @name AuditAuthorization
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.AuditAuthorization
 */
export const AuditAuthorization = {
  typeUrl: "/clairveil.privacy.v2.AuditAuthorization",
  encode(message: AuditAuthorization, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.keyId.length !== 0) {
      writer.uint32(10).bytes(message.keyId);
    }
    if (message.epoch !== BigInt(0)) {
      writer.uint32(16).uint64(message.epoch);
    }
    if (message.envelope.length !== 0) {
      writer.uint32(26).bytes(message.envelope);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): AuditAuthorization {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseAuditAuthorization();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.keyId = reader.bytes();
          break;
        case 2:
          message.epoch = reader.uint64();
          break;
        case 3:
          message.envelope = reader.bytes();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<AuditAuthorization>): AuditAuthorization {
    const message = createBaseAuditAuthorization();
    message.keyId = object.keyId ?? new Uint8Array();
    message.epoch = object.epoch !== undefined && object.epoch !== null ? BigInt(object.epoch.toString()) : BigInt(0);
    message.envelope = object.envelope ?? new Uint8Array();
    return message;
  }
};
function createBaseOutputEffect(): OutputEffect {
  return {
    commitment: new Uint8Array(),
    ciphertext: new Uint8Array(),
    viewTag: new Uint8Array(),
    userPrivacyPolicy: 0,
    userDisclosureMode: 0,
    userDisclosureDigest: new Uint8Array(),
    userDisclosureTargetPubkey: new Uint8Array(),
    userDisclosurePayload: new Uint8Array(),
    selfFullDisclosureDigest: new Uint8Array(),
    selfViewDisclosurePayload: new Uint8Array()
  };
}
/**
 * @name OutputEffect
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.OutputEffect
 */
export const OutputEffect = {
  typeUrl: "/clairveil.privacy.v2.OutputEffect",
  encode(message: OutputEffect, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
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
      writer.uint32(40).uint32(message.userDisclosureMode);
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
    if (message.selfFullDisclosureDigest.length !== 0) {
      writer.uint32(74).bytes(message.selfFullDisclosureDigest);
    }
    if (message.selfViewDisclosurePayload.length !== 0) {
      writer.uint32(82).bytes(message.selfViewDisclosurePayload);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): OutputEffect {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseOutputEffect();
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
          message.userDisclosureMode = reader.uint32();
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
          message.selfFullDisclosureDigest = reader.bytes();
          break;
        case 10:
          message.selfViewDisclosurePayload = reader.bytes();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<OutputEffect>): OutputEffect {
    const message = createBaseOutputEffect();
    message.commitment = object.commitment ?? new Uint8Array();
    message.ciphertext = object.ciphertext ?? new Uint8Array();
    message.viewTag = object.viewTag ?? new Uint8Array();
    message.userPrivacyPolicy = object.userPrivacyPolicy ?? 0;
    message.userDisclosureMode = object.userDisclosureMode ?? 0;
    message.userDisclosureDigest = object.userDisclosureDigest ?? new Uint8Array();
    message.userDisclosureTargetPubkey = object.userDisclosureTargetPubkey ?? new Uint8Array();
    message.userDisclosurePayload = object.userDisclosurePayload ?? new Uint8Array();
    message.selfFullDisclosureDigest = object.selfFullDisclosureDigest ?? new Uint8Array();
    message.selfViewDisclosurePayload = object.selfViewDisclosurePayload ?? new Uint8Array();
    return message;
  }
};
function createBaseMsgDeposit(): MsgDeposit {
  return {
    creator: "",
    amount: "",
    output: undefined,
    proof: new Uint8Array(),
    expiresAtUnix: BigInt(0),
    audit: undefined
  };
}
/**
 * @name MsgDeposit
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgDeposit
 */
export const MsgDeposit = {
  typeUrl: "/clairveil.privacy.v2.MsgDeposit",
  encode(message: MsgDeposit, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.creator !== "") {
      writer.uint32(10).string(message.creator);
    }
    if (message.amount !== "") {
      writer.uint32(18).string(message.amount);
    }
    if (message.output !== undefined) {
      OutputEffect.encode(message.output, writer.uint32(26).fork()).ldelim();
    }
    if (message.proof.length !== 0) {
      writer.uint32(34).bytes(message.proof);
    }
    if (message.expiresAtUnix !== BigInt(0)) {
      writer.uint32(40).int64(message.expiresAtUnix);
    }
    if (message.audit !== undefined) {
      AuditAuthorization.encode(message.audit, writer.uint32(50).fork()).ldelim();
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgDeposit {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgDeposit();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.creator = reader.string();
          break;
        case 2:
          message.amount = reader.string();
          break;
        case 3:
          message.output = OutputEffect.decode(reader, reader.uint32());
          break;
        case 4:
          message.proof = reader.bytes();
          break;
        case 5:
          message.expiresAtUnix = reader.int64();
          break;
        case 6:
          message.audit = AuditAuthorization.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<MsgDeposit>): MsgDeposit {
    const message = createBaseMsgDeposit();
    message.creator = object.creator ?? "";
    message.amount = object.amount ?? "";
    message.output = object.output !== undefined && object.output !== null ? OutputEffect.fromPartial(object.output) : undefined;
    message.proof = object.proof ?? new Uint8Array();
    message.expiresAtUnix = object.expiresAtUnix !== undefined && object.expiresAtUnix !== null ? BigInt(object.expiresAtUnix.toString()) : BigInt(0);
    message.audit = object.audit !== undefined && object.audit !== null ? AuditAuthorization.fromPartial(object.audit) : undefined;
    return message;
  }
};
function createBaseMsgWithdraw(): MsgWithdraw {
  return {
    creator: "",
    amount: "",
    recipient: "",
    root: new Uint8Array(),
    nullifier: new Uint8Array(),
    proof: new Uint8Array(),
    expiresAtUnix: BigInt(0),
    audit: undefined
  };
}
/**
 * @name MsgWithdraw
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgWithdraw
 */
export const MsgWithdraw = {
  typeUrl: "/clairveil.privacy.v2.MsgWithdraw",
  encode(message: MsgWithdraw, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.creator !== "") {
      writer.uint32(10).string(message.creator);
    }
    if (message.amount !== "") {
      writer.uint32(18).string(message.amount);
    }
    if (message.recipient !== "") {
      writer.uint32(26).string(message.recipient);
    }
    if (message.root.length !== 0) {
      writer.uint32(34).bytes(message.root);
    }
    if (message.nullifier.length !== 0) {
      writer.uint32(42).bytes(message.nullifier);
    }
    if (message.proof.length !== 0) {
      writer.uint32(50).bytes(message.proof);
    }
    if (message.expiresAtUnix !== BigInt(0)) {
      writer.uint32(56).int64(message.expiresAtUnix);
    }
    if (message.audit !== undefined) {
      AuditAuthorization.encode(message.audit, writer.uint32(66).fork()).ldelim();
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgWithdraw {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgWithdraw();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.creator = reader.string();
          break;
        case 2:
          message.amount = reader.string();
          break;
        case 3:
          message.recipient = reader.string();
          break;
        case 4:
          message.root = reader.bytes();
          break;
        case 5:
          message.nullifier = reader.bytes();
          break;
        case 6:
          message.proof = reader.bytes();
          break;
        case 7:
          message.expiresAtUnix = reader.int64();
          break;
        case 8:
          message.audit = AuditAuthorization.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<MsgWithdraw>): MsgWithdraw {
    const message = createBaseMsgWithdraw();
    message.creator = object.creator ?? "";
    message.amount = object.amount ?? "";
    message.recipient = object.recipient ?? "";
    message.root = object.root ?? new Uint8Array();
    message.nullifier = object.nullifier ?? new Uint8Array();
    message.proof = object.proof ?? new Uint8Array();
    message.expiresAtUnix = object.expiresAtUnix !== undefined && object.expiresAtUnix !== null ? BigInt(object.expiresAtUnix.toString()) : BigInt(0);
    message.audit = object.audit !== undefined && object.audit !== null ? AuditAuthorization.fromPartial(object.audit) : undefined;
    return message;
  }
};
function createBaseMsgTransfer(): MsgTransfer {
  return {
    creator: "",
    root: new Uint8Array(),
    nullifiers: [],
    outputs: [],
    proof: new Uint8Array(),
    expiresAtUnix: BigInt(0),
    audit: undefined
  };
}
/**
 * @name MsgTransfer
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgTransfer
 */
export const MsgTransfer = {
  typeUrl: "/clairveil.privacy.v2.MsgTransfer",
  encode(message: MsgTransfer, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.creator !== "") {
      writer.uint32(10).string(message.creator);
    }
    if (message.root.length !== 0) {
      writer.uint32(18).bytes(message.root);
    }
    for (const v of message.nullifiers) {
      writer.uint32(26).bytes(v!);
    }
    for (const v of message.outputs) {
      OutputEffect.encode(v!, writer.uint32(34).fork()).ldelim();
    }
    if (message.proof.length !== 0) {
      writer.uint32(42).bytes(message.proof);
    }
    if (message.expiresAtUnix !== BigInt(0)) {
      writer.uint32(48).int64(message.expiresAtUnix);
    }
    if (message.audit !== undefined) {
      AuditAuthorization.encode(message.audit, writer.uint32(58).fork()).ldelim();
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgTransfer {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgTransfer();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.creator = reader.string();
          break;
        case 2:
          message.root = reader.bytes();
          break;
        case 3:
          message.nullifiers.push(reader.bytes());
          break;
        case 4:
          message.outputs.push(OutputEffect.decode(reader, reader.uint32()));
          break;
        case 5:
          message.proof = reader.bytes();
          break;
        case 6:
          message.expiresAtUnix = reader.int64();
          break;
        case 7:
          message.audit = AuditAuthorization.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<MsgTransfer>): MsgTransfer {
    const message = createBaseMsgTransfer();
    message.creator = object.creator ?? "";
    message.root = object.root ?? new Uint8Array();
    message.nullifiers = object.nullifiers?.map(e => e) || [];
    message.outputs = object.outputs?.map(e => OutputEffect.fromPartial(e)) || [];
    message.proof = object.proof ?? new Uint8Array();
    message.expiresAtUnix = object.expiresAtUnix !== undefined && object.expiresAtUnix !== null ? BigInt(object.expiresAtUnix.toString()) : BigInt(0);
    message.audit = object.audit !== undefined && object.audit !== null ? AuditAuthorization.fromPartial(object.audit) : undefined;
    return message;
  }
};
function createBaseMsgBatchTransfer(): MsgBatchTransfer {
  return {
    creator: "",
    root: new Uint8Array(),
    nullifiers: [],
    outputs: [],
    proof: new Uint8Array(),
    expiresAtUnix: BigInt(0),
    audit: undefined
  };
}
/**
 * @name MsgBatchTransfer
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgBatchTransfer
 */
export const MsgBatchTransfer = {
  typeUrl: "/clairveil.privacy.v2.MsgBatchTransfer",
  encode(message: MsgBatchTransfer, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.creator !== "") {
      writer.uint32(10).string(message.creator);
    }
    if (message.root.length !== 0) {
      writer.uint32(18).bytes(message.root);
    }
    for (const v of message.nullifiers) {
      writer.uint32(26).bytes(v!);
    }
    for (const v of message.outputs) {
      OutputEffect.encode(v!, writer.uint32(34).fork()).ldelim();
    }
    if (message.proof.length !== 0) {
      writer.uint32(42).bytes(message.proof);
    }
    if (message.expiresAtUnix !== BigInt(0)) {
      writer.uint32(48).int64(message.expiresAtUnix);
    }
    if (message.audit !== undefined) {
      AuditAuthorization.encode(message.audit, writer.uint32(58).fork()).ldelim();
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgBatchTransfer {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgBatchTransfer();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.creator = reader.string();
          break;
        case 2:
          message.root = reader.bytes();
          break;
        case 3:
          message.nullifiers.push(reader.bytes());
          break;
        case 4:
          message.outputs.push(OutputEffect.decode(reader, reader.uint32()));
          break;
        case 5:
          message.proof = reader.bytes();
          break;
        case 6:
          message.expiresAtUnix = reader.int64();
          break;
        case 7:
          message.audit = AuditAuthorization.decode(reader, reader.uint32());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<MsgBatchTransfer>): MsgBatchTransfer {
    const message = createBaseMsgBatchTransfer();
    message.creator = object.creator ?? "";
    message.root = object.root ?? new Uint8Array();
    message.nullifiers = object.nullifiers?.map(e => e) || [];
    message.outputs = object.outputs?.map(e => OutputEffect.fromPartial(e)) || [];
    message.proof = object.proof ?? new Uint8Array();
    message.expiresAtUnix = object.expiresAtUnix !== undefined && object.expiresAtUnix !== null ? BigInt(object.expiresAtUnix.toString()) : BigInt(0);
    message.audit = object.audit !== undefined && object.audit !== null ? AuditAuthorization.fromPartial(object.audit) : undefined;
    return message;
  }
};
function createBaseMsgScheduleAuditKeyEpoch(): MsgScheduleAuditKeyEpoch {
  return {
    authority: "",
    epoch: BigInt(0),
    activationHeight: BigInt(0),
    publicKey: new Uint8Array(),
    suite: 0,
    possessionProof: new Uint8Array()
  };
}
/**
 * @name MsgScheduleAuditKeyEpoch
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgScheduleAuditKeyEpoch
 */
export const MsgScheduleAuditKeyEpoch = {
  typeUrl: "/clairveil.privacy.v2.MsgScheduleAuditKeyEpoch",
  encode(message: MsgScheduleAuditKeyEpoch, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.authority !== "") {
      writer.uint32(10).string(message.authority);
    }
    if (message.epoch !== BigInt(0)) {
      writer.uint32(16).uint64(message.epoch);
    }
    if (message.activationHeight !== BigInt(0)) {
      writer.uint32(24).uint64(message.activationHeight);
    }
    if (message.publicKey.length !== 0) {
      writer.uint32(34).bytes(message.publicKey);
    }
    if (message.suite !== 0) {
      writer.uint32(40).uint32(message.suite);
    }
    if (message.possessionProof.length !== 0) {
      writer.uint32(50).bytes(message.possessionProof);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgScheduleAuditKeyEpoch {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgScheduleAuditKeyEpoch();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.authority = reader.string();
          break;
        case 2:
          message.epoch = reader.uint64();
          break;
        case 3:
          message.activationHeight = reader.uint64();
          break;
        case 4:
          message.publicKey = reader.bytes();
          break;
        case 5:
          message.suite = reader.uint32();
          break;
        case 6:
          message.possessionProof = reader.bytes();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<MsgScheduleAuditKeyEpoch>): MsgScheduleAuditKeyEpoch {
    const message = createBaseMsgScheduleAuditKeyEpoch();
    message.authority = object.authority ?? "";
    message.epoch = object.epoch !== undefined && object.epoch !== null ? BigInt(object.epoch.toString()) : BigInt(0);
    message.activationHeight = object.activationHeight !== undefined && object.activationHeight !== null ? BigInt(object.activationHeight.toString()) : BigInt(0);
    message.publicKey = object.publicKey ?? new Uint8Array();
    message.suite = object.suite ?? 0;
    message.possessionProof = object.possessionProof ?? new Uint8Array();
    return message;
  }
};
function createBaseMsgCancelPendingAuditEpoch(): MsgCancelPendingAuditEpoch {
  return {
    authority: "",
    epoch: BigInt(0)
  };
}
/**
 * @name MsgCancelPendingAuditEpoch
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgCancelPendingAuditEpoch
 */
export const MsgCancelPendingAuditEpoch = {
  typeUrl: "/clairveil.privacy.v2.MsgCancelPendingAuditEpoch",
  encode(message: MsgCancelPendingAuditEpoch, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.authority !== "") {
      writer.uint32(10).string(message.authority);
    }
    if (message.epoch !== BigInt(0)) {
      writer.uint32(16).uint64(message.epoch);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgCancelPendingAuditEpoch {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgCancelPendingAuditEpoch();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.authority = reader.string();
          break;
        case 2:
          message.epoch = reader.uint64();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<MsgCancelPendingAuditEpoch>): MsgCancelPendingAuditEpoch {
    const message = createBaseMsgCancelPendingAuditEpoch();
    message.authority = object.authority ?? "";
    message.epoch = object.epoch !== undefined && object.epoch !== null ? BigInt(object.epoch.toString()) : BigInt(0);
    return message;
  }
};
function createBaseMsgSetPrivacyHalt(): MsgSetPrivacyHalt {
  return {
    authority: "",
    halted: false
  };
}
/**
 * @name MsgSetPrivacyHalt
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgSetPrivacyHalt
 */
export const MsgSetPrivacyHalt = {
  typeUrl: "/clairveil.privacy.v2.MsgSetPrivacyHalt",
  encode(message: MsgSetPrivacyHalt, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.authority !== "") {
      writer.uint32(10).string(message.authority);
    }
    if (message.halted === true) {
      writer.uint32(16).bool(message.halted);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgSetPrivacyHalt {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgSetPrivacyHalt();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.authority = reader.string();
          break;
        case 2:
          message.halted = reader.bool();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<MsgSetPrivacyHalt>): MsgSetPrivacyHalt {
    const message = createBaseMsgSetPrivacyHalt();
    message.authority = object.authority ?? "";
    message.halted = object.halted ?? false;
    return message;
  }
};
function createBaseMsgDepositResponse(): MsgDepositResponse {
  return {};
}
/**
 * Field 1 remains permanently reserved after removal of the transition cursor.
 * @name MsgDepositResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgDepositResponse
 */
export const MsgDepositResponse = {
  typeUrl: "/clairveil.privacy.v2.MsgDepositResponse",
  encode(_: MsgDepositResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgDepositResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgDepositResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(_: DeepPartial<MsgDepositResponse>): MsgDepositResponse {
    const message = createBaseMsgDepositResponse();
    return message;
  }
};
function createBaseMsgWithdrawResponse(): MsgWithdrawResponse {
  return {};
}
/**
 * @name MsgWithdrawResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgWithdrawResponse
 */
export const MsgWithdrawResponse = {
  typeUrl: "/clairveil.privacy.v2.MsgWithdrawResponse",
  encode(_: MsgWithdrawResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgWithdrawResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgWithdrawResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(_: DeepPartial<MsgWithdrawResponse>): MsgWithdrawResponse {
    const message = createBaseMsgWithdrawResponse();
    return message;
  }
};
function createBaseMsgTransferResponse(): MsgTransferResponse {
  return {};
}
/**
 * @name MsgTransferResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgTransferResponse
 */
export const MsgTransferResponse = {
  typeUrl: "/clairveil.privacy.v2.MsgTransferResponse",
  encode(_: MsgTransferResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgTransferResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgTransferResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(_: DeepPartial<MsgTransferResponse>): MsgTransferResponse {
    const message = createBaseMsgTransferResponse();
    return message;
  }
};
function createBaseMsgBatchTransferResponse(): MsgBatchTransferResponse {
  return {};
}
/**
 * @name MsgBatchTransferResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgBatchTransferResponse
 */
export const MsgBatchTransferResponse = {
  typeUrl: "/clairveil.privacy.v2.MsgBatchTransferResponse",
  encode(_: MsgBatchTransferResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgBatchTransferResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgBatchTransferResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(_: DeepPartial<MsgBatchTransferResponse>): MsgBatchTransferResponse {
    const message = createBaseMsgBatchTransferResponse();
    return message;
  }
};
function createBaseMsgScheduleAuditKeyEpochResponse(): MsgScheduleAuditKeyEpochResponse {
  return {};
}
/**
 * @name MsgScheduleAuditKeyEpochResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgScheduleAuditKeyEpochResponse
 */
export const MsgScheduleAuditKeyEpochResponse = {
  typeUrl: "/clairveil.privacy.v2.MsgScheduleAuditKeyEpochResponse",
  encode(_: MsgScheduleAuditKeyEpochResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgScheduleAuditKeyEpochResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgScheduleAuditKeyEpochResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(_: DeepPartial<MsgScheduleAuditKeyEpochResponse>): MsgScheduleAuditKeyEpochResponse {
    const message = createBaseMsgScheduleAuditKeyEpochResponse();
    return message;
  }
};
function createBaseMsgCancelPendingAuditEpochResponse(): MsgCancelPendingAuditEpochResponse {
  return {};
}
/**
 * @name MsgCancelPendingAuditEpochResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgCancelPendingAuditEpochResponse
 */
export const MsgCancelPendingAuditEpochResponse = {
  typeUrl: "/clairveil.privacy.v2.MsgCancelPendingAuditEpochResponse",
  encode(_: MsgCancelPendingAuditEpochResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgCancelPendingAuditEpochResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgCancelPendingAuditEpochResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(_: DeepPartial<MsgCancelPendingAuditEpochResponse>): MsgCancelPendingAuditEpochResponse {
    const message = createBaseMsgCancelPendingAuditEpochResponse();
    return message;
  }
};
function createBaseMsgSetPrivacyHaltResponse(): MsgSetPrivacyHaltResponse {
  return {};
}
/**
 * @name MsgSetPrivacyHaltResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.MsgSetPrivacyHaltResponse
 */
export const MsgSetPrivacyHaltResponse = {
  typeUrl: "/clairveil.privacy.v2.MsgSetPrivacyHaltResponse",
  encode(_: MsgSetPrivacyHaltResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): MsgSetPrivacyHaltResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseMsgSetPrivacyHaltResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(_: DeepPartial<MsgSetPrivacyHaltResponse>): MsgSetPrivacyHaltResponse {
    const message = createBaseMsgSetPrivacyHaltResponse();
    return message;
  }
};