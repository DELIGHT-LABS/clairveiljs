import { BinaryReader, BinaryWriter } from "../../../binary.js";
import { DeepPartial } from "../../../helpers.js";
export enum UserDisclosureMode {
  USER_DISCLOSURE_MODE_NONE = 0,
  USER_DISCLOSURE_MODE_PUBLIC = 1,
  USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED = 2,
  UNRECOGNIZED = -1,
}
export function userDisclosureModeFromJSON(object: any): UserDisclosureMode {
  switch (object) {
    case 0:
    case "USER_DISCLOSURE_MODE_NONE":
      return UserDisclosureMode.USER_DISCLOSURE_MODE_NONE;
    case 1:
    case "USER_DISCLOSURE_MODE_PUBLIC":
      return UserDisclosureMode.USER_DISCLOSURE_MODE_PUBLIC;
    case 2:
    case "USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED":
      return UserDisclosureMode.USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED;
    case -1:
    case "UNRECOGNIZED":
    default:
      return UserDisclosureMode.UNRECOGNIZED;
  }
}
export function userDisclosureModeToJSON(object: UserDisclosureMode): string {
  switch (object) {
    case UserDisclosureMode.USER_DISCLOSURE_MODE_NONE:
      return "USER_DISCLOSURE_MODE_NONE";
    case UserDisclosureMode.USER_DISCLOSURE_MODE_PUBLIC:
      return "USER_DISCLOSURE_MODE_PUBLIC";
    case UserDisclosureMode.USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED:
      return "USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED";
    case UserDisclosureMode.UNRECOGNIZED:
    default:
      return "UNRECOGNIZED";
  }
}
/**
 * MsgDeposit: 투명 자산 -> 익명 자산 변환
 * @name MsgDeposit
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgDeposit
 */
export interface MsgDeposit {
  /**
   * 입금자
   */
  creator: string;
  /**
   * 금액 (예: 100uclair)
   */
  amount: string;
  /**
   * 머클 트리에 들어갈 해시
   */
  noteCommitment: Uint8Array;
  /**
   * 복구용 암호화 데이터
   */
  encryptedNote: Uint8Array;
  /**
   * commitment가 amount/asset에 묶였다는 ZK proof
   */
  proof: Uint8Array;
}
/**
 * MsgWithdraw: 익명 자산 -> 투명 자산 변환
 * @name MsgWithdraw
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgWithdraw
 */
export interface MsgWithdraw {
  creator: string;
  /**
   * ZK Proof
   */
  proof: Uint8Array;
  /**
   * 참조한 머클 루트
   */
  root: Uint8Array;
  /**
   * 이중 지불 방지 태그
   */
  nullifier: Uint8Array;
  /**
   * 출금 금액 (예: 100uclair)
   */
  amount: string;
  /**
   * 출금 주소
   */
  recipient: string;
  chainId: string;
  expiresAtUnix: bigint;
}
/**
 * MsgTransfer: 내부 전송
 * @name MsgTransfer
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgTransfer
 */
export interface MsgTransfer {
  creator: string;
  /**
   * ZK Proof Data
   */
  proof: Uint8Array;
  /**
   * Merkle Root
   */
  root: Uint8Array;
  /**
   * Spent Note's Nullifier
   */
  nullifiers: Uint8Array[];
  /**
   * Output Commitments (Recipient, Change)
   */
  newCommitments: Uint8Array[];
  /**
   * On-chain Encryption (ECDH Encrypted Data)
   * 수신자가 복호화해서 Note 정보를 알 수 있게 함
   */
  cipherTexts: Uint8Array[];
  /**
   * Optional user selective disclosure.
   * 0x00: all-private
   * 0x01: disclose amount (+ asset id)
   * 0x02: disclose recipient full shielded address
   * 0x04: disclose sender full shielded address
   */
  userPrivacyPolicy: number;
  userDisclosureDigest: Uint8Array;
  userDisclosureMode: UserDisclosureMode;
  userDisclosureTargetPubkey: Uint8Array;
  userDisclosurePayload: Uint8Array;
  /**
   * Mandatory master-auditor disclosure.
   */
  auditDisclosureDigest: Uint8Array;
  auditDisclosureTargetPubkey: Uint8Array;
  auditDisclosurePayload: Uint8Array;
  /**
   * Optional sender self-view disclosure.
   * The payload is encrypted to the sender's own disclosure key. The target
   * public key is intentionally omitted to avoid sender clustering.
   */
  selfViewDisclosureDigest: Uint8Array;
  selfViewDisclosurePayload: Uint8Array;
  /**
   * Per-output scan performance tags. The exact tag bytes are bound to the
   * owner-authorized payload digest and proof, but the circuit does not
   * constrain their derivation from encrypted-output key material. Wallets
   * must treat ownership semantics as untrusted hints. Safe default scans must
   * full-decrypt on tag mismatch; explicit fast modes may skip well-formed
   * mismatches only when recovery/rescan policy is in place.
   */
  viewTags: Uint8Array[];
  /**
   * Absolute authorization expiry. The owner signature and proof bind this
   * value; the transaction is expired when block_time >= expires_at_unix.
   */
  expiresAtUnix: bigint;
}
/**
 * MsgBatchTransfer performs one atomic 1..16 input / 1..32 output shielded
 * JoinSplit. Field numbers and meanings form the version-1 batch-transfer wire
 * contract. Counts are derived exclusively from the repeated field lengths.
 * @name MsgBatchTransfer
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgBatchTransfer
 */
export interface MsgBatchTransfer {
  creator: string;
  proof: Uint8Array;
  root: Uint8Array;
  nullifiers: Uint8Array[];
  outputs: BatchTransferOutput[];
  /**
   * Canonical lowercase ASCII [a-z0-9][a-z0-9._-]*, 1..64 bytes.
   */
  auditKeyId: string;
  auditKeyEpoch: bigint;
  auditDisclosureTargetPubkey: Uint8Array;
  expiresAtUnix: bigint;
}
/**
 * BatchTransferOutput carries exactly one ordered output effect. The full
 * disclosure digest is shared by mandatory audit and optional self-view
 * disclosure payloads; a separate self-view target or digest is not exposed.
 * @name BatchTransferOutput
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.BatchTransferOutput
 */
export interface BatchTransferOutput {
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
 * MsgDepositResponse
 * @name MsgDepositResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgDepositResponse
 */
export interface MsgDepositResponse {}
/**
 * MsgWithdrawResponse
 * @name MsgWithdrawResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgWithdrawResponse
 */
export interface MsgWithdrawResponse {}
/**
 * MsgTransferResponse
 * @name MsgTransferResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgTransferResponse
 */
export interface MsgTransferResponse {}
/**
 * MsgBatchTransferResponse is empty because all scan/output data is stored in
 * typed state and queried separately.
 * @name MsgBatchTransferResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgBatchTransferResponse
 */
export interface MsgBatchTransferResponse {}
function createBaseMsgDeposit(): MsgDeposit {
  return {
    creator: "",
    amount: "",
    noteCommitment: new Uint8Array(),
    encryptedNote: new Uint8Array(),
    proof: new Uint8Array()
  };
}
/**
 * MsgDeposit: 투명 자산 -> 익명 자산 변환
 * @name MsgDeposit
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgDeposit
 */
export const MsgDeposit = {
  typeUrl: "/clairveil.privacy.v1.MsgDeposit",
  encode(message: MsgDeposit, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.creator !== "") {
      writer.uint32(10).string(message.creator);
    }
    if (message.amount !== "") {
      writer.uint32(18).string(message.amount);
    }
    if (message.noteCommitment.length !== 0) {
      writer.uint32(26).bytes(message.noteCommitment);
    }
    if (message.encryptedNote.length !== 0) {
      writer.uint32(34).bytes(message.encryptedNote);
    }
    if (message.proof.length !== 0) {
      writer.uint32(42).bytes(message.proof);
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
          message.noteCommitment = reader.bytes();
          break;
        case 4:
          message.encryptedNote = reader.bytes();
          break;
        case 5:
          message.proof = reader.bytes();
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
    message.noteCommitment = object.noteCommitment ?? new Uint8Array();
    message.encryptedNote = object.encryptedNote ?? new Uint8Array();
    message.proof = object.proof ?? new Uint8Array();
    return message;
  }
};
function createBaseMsgWithdraw(): MsgWithdraw {
  return {
    creator: "",
    proof: new Uint8Array(),
    root: new Uint8Array(),
    nullifier: new Uint8Array(),
    amount: "",
    recipient: "",
    chainId: "",
    expiresAtUnix: BigInt(0)
  };
}
/**
 * MsgWithdraw: 익명 자산 -> 투명 자산 변환
 * @name MsgWithdraw
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgWithdraw
 */
export const MsgWithdraw = {
  typeUrl: "/clairveil.privacy.v1.MsgWithdraw",
  encode(message: MsgWithdraw, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.creator !== "") {
      writer.uint32(10).string(message.creator);
    }
    if (message.proof.length !== 0) {
      writer.uint32(18).bytes(message.proof);
    }
    if (message.root.length !== 0) {
      writer.uint32(26).bytes(message.root);
    }
    if (message.nullifier.length !== 0) {
      writer.uint32(34).bytes(message.nullifier);
    }
    if (message.amount !== "") {
      writer.uint32(58).string(message.amount);
    }
    if (message.recipient !== "") {
      writer.uint32(66).string(message.recipient);
    }
    if (message.chainId !== "") {
      writer.uint32(74).string(message.chainId);
    }
    if (message.expiresAtUnix !== BigInt(0)) {
      writer.uint32(80).int64(message.expiresAtUnix);
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
          message.proof = reader.bytes();
          break;
        case 3:
          message.root = reader.bytes();
          break;
        case 4:
          message.nullifier = reader.bytes();
          break;
        case 7:
          message.amount = reader.string();
          break;
        case 8:
          message.recipient = reader.string();
          break;
        case 9:
          message.chainId = reader.string();
          break;
        case 10:
          message.expiresAtUnix = reader.int64();
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
    message.proof = object.proof ?? new Uint8Array();
    message.root = object.root ?? new Uint8Array();
    message.nullifier = object.nullifier ?? new Uint8Array();
    message.amount = object.amount ?? "";
    message.recipient = object.recipient ?? "";
    message.chainId = object.chainId ?? "";
    message.expiresAtUnix = object.expiresAtUnix !== undefined && object.expiresAtUnix !== null ? BigInt(object.expiresAtUnix.toString()) : BigInt(0);
    return message;
  }
};
function createBaseMsgTransfer(): MsgTransfer {
  return {
    creator: "",
    proof: new Uint8Array(),
    root: new Uint8Array(),
    nullifiers: [],
    newCommitments: [],
    cipherTexts: [],
    userPrivacyPolicy: 0,
    userDisclosureDigest: new Uint8Array(),
    userDisclosureMode: 0,
    userDisclosureTargetPubkey: new Uint8Array(),
    userDisclosurePayload: new Uint8Array(),
    auditDisclosureDigest: new Uint8Array(),
    auditDisclosureTargetPubkey: new Uint8Array(),
    auditDisclosurePayload: new Uint8Array(),
    selfViewDisclosureDigest: new Uint8Array(),
    selfViewDisclosurePayload: new Uint8Array(),
    viewTags: [],
    expiresAtUnix: BigInt(0)
  };
}
/**
 * MsgTransfer: 내부 전송
 * @name MsgTransfer
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgTransfer
 */
export const MsgTransfer = {
  typeUrl: "/clairveil.privacy.v1.MsgTransfer",
  encode(message: MsgTransfer, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
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
    for (const v of message.newCommitments) {
      writer.uint32(42).bytes(v!);
    }
    for (const v of message.cipherTexts) {
      writer.uint32(50).bytes(v!);
    }
    if (message.userPrivacyPolicy !== 0) {
      writer.uint32(56).uint32(message.userPrivacyPolicy);
    }
    if (message.userDisclosureDigest.length !== 0) {
      writer.uint32(66).bytes(message.userDisclosureDigest);
    }
    if (message.userDisclosureMode !== 0) {
      writer.uint32(72).int32(message.userDisclosureMode);
    }
    if (message.userDisclosureTargetPubkey.length !== 0) {
      writer.uint32(82).bytes(message.userDisclosureTargetPubkey);
    }
    if (message.userDisclosurePayload.length !== 0) {
      writer.uint32(90).bytes(message.userDisclosurePayload);
    }
    if (message.auditDisclosureDigest.length !== 0) {
      writer.uint32(98).bytes(message.auditDisclosureDigest);
    }
    if (message.auditDisclosureTargetPubkey.length !== 0) {
      writer.uint32(106).bytes(message.auditDisclosureTargetPubkey);
    }
    if (message.auditDisclosurePayload.length !== 0) {
      writer.uint32(114).bytes(message.auditDisclosurePayload);
    }
    if (message.selfViewDisclosureDigest.length !== 0) {
      writer.uint32(122).bytes(message.selfViewDisclosureDigest);
    }
    if (message.selfViewDisclosurePayload.length !== 0) {
      writer.uint32(130).bytes(message.selfViewDisclosurePayload);
    }
    for (const v of message.viewTags) {
      writer.uint32(138).bytes(v!);
    }
    if (message.expiresAtUnix !== BigInt(0)) {
      writer.uint32(144).int64(message.expiresAtUnix);
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
          message.proof = reader.bytes();
          break;
        case 3:
          message.root = reader.bytes();
          break;
        case 4:
          message.nullifiers.push(reader.bytes());
          break;
        case 5:
          message.newCommitments.push(reader.bytes());
          break;
        case 6:
          message.cipherTexts.push(reader.bytes());
          break;
        case 7:
          message.userPrivacyPolicy = reader.uint32();
          break;
        case 8:
          message.userDisclosureDigest = reader.bytes();
          break;
        case 9:
          message.userDisclosureMode = reader.int32() as any;
          break;
        case 10:
          message.userDisclosureTargetPubkey = reader.bytes();
          break;
        case 11:
          message.userDisclosurePayload = reader.bytes();
          break;
        case 12:
          message.auditDisclosureDigest = reader.bytes();
          break;
        case 13:
          message.auditDisclosureTargetPubkey = reader.bytes();
          break;
        case 14:
          message.auditDisclosurePayload = reader.bytes();
          break;
        case 15:
          message.selfViewDisclosureDigest = reader.bytes();
          break;
        case 16:
          message.selfViewDisclosurePayload = reader.bytes();
          break;
        case 17:
          message.viewTags.push(reader.bytes());
          break;
        case 18:
          message.expiresAtUnix = reader.int64();
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
    message.proof = object.proof ?? new Uint8Array();
    message.root = object.root ?? new Uint8Array();
    message.nullifiers = object.nullifiers?.map(e => e) || [];
    message.newCommitments = object.newCommitments?.map(e => e) || [];
    message.cipherTexts = object.cipherTexts?.map(e => e) || [];
    message.userPrivacyPolicy = object.userPrivacyPolicy ?? 0;
    message.userDisclosureDigest = object.userDisclosureDigest ?? new Uint8Array();
    message.userDisclosureMode = object.userDisclosureMode ?? 0;
    message.userDisclosureTargetPubkey = object.userDisclosureTargetPubkey ?? new Uint8Array();
    message.userDisclosurePayload = object.userDisclosurePayload ?? new Uint8Array();
    message.auditDisclosureDigest = object.auditDisclosureDigest ?? new Uint8Array();
    message.auditDisclosureTargetPubkey = object.auditDisclosureTargetPubkey ?? new Uint8Array();
    message.auditDisclosurePayload = object.auditDisclosurePayload ?? new Uint8Array();
    message.selfViewDisclosureDigest = object.selfViewDisclosureDigest ?? new Uint8Array();
    message.selfViewDisclosurePayload = object.selfViewDisclosurePayload ?? new Uint8Array();
    message.viewTags = object.viewTags?.map(e => e) || [];
    message.expiresAtUnix = object.expiresAtUnix !== undefined && object.expiresAtUnix !== null ? BigInt(object.expiresAtUnix.toString()) : BigInt(0);
    return message;
  }
};
function createBaseMsgBatchTransfer(): MsgBatchTransfer {
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
 * MsgBatchTransfer performs one atomic 1..16 input / 1..32 output shielded
 * JoinSplit. Field numbers and meanings form the version-1 batch-transfer wire
 * contract. Counts are derived exclusively from the repeated field lengths.
 * @name MsgBatchTransfer
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgBatchTransfer
 */
export const MsgBatchTransfer = {
  typeUrl: "/clairveil.privacy.v1.MsgBatchTransfer",
  encode(message: MsgBatchTransfer, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
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
      BatchTransferOutput.encode(v!, writer.uint32(42).fork()).ldelim();
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
          message.proof = reader.bytes();
          break;
        case 3:
          message.root = reader.bytes();
          break;
        case 4:
          message.nullifiers.push(reader.bytes());
          break;
        case 5:
          message.outputs.push(BatchTransferOutput.decode(reader, reader.uint32()));
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
  fromPartial(object: DeepPartial<MsgBatchTransfer>): MsgBatchTransfer {
    const message = createBaseMsgBatchTransfer();
    message.creator = object.creator ?? "";
    message.proof = object.proof ?? new Uint8Array();
    message.root = object.root ?? new Uint8Array();
    message.nullifiers = object.nullifiers?.map(e => e) || [];
    message.outputs = object.outputs?.map(e => BatchTransferOutput.fromPartial(e)) || [];
    message.auditKeyId = object.auditKeyId ?? "";
    message.auditKeyEpoch = object.auditKeyEpoch !== undefined && object.auditKeyEpoch !== null ? BigInt(object.auditKeyEpoch.toString()) : BigInt(0);
    message.auditDisclosureTargetPubkey = object.auditDisclosureTargetPubkey ?? new Uint8Array();
    message.expiresAtUnix = object.expiresAtUnix !== undefined && object.expiresAtUnix !== null ? BigInt(object.expiresAtUnix.toString()) : BigInt(0);
    return message;
  }
};
function createBaseBatchTransferOutput(): BatchTransferOutput {
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
 * BatchTransferOutput carries exactly one ordered output effect. The full
 * disclosure digest is shared by mandatory audit and optional self-view
 * disclosure payloads; a separate self-view target or digest is not exposed.
 * @name BatchTransferOutput
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.BatchTransferOutput
 */
export const BatchTransferOutput = {
  typeUrl: "/clairveil.privacy.v1.BatchTransferOutput",
  encode(message: BatchTransferOutput, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
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
  decode(input: BinaryReader | Uint8Array, length?: number): BatchTransferOutput {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseBatchTransferOutput();
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
  fromPartial(object: DeepPartial<BatchTransferOutput>): BatchTransferOutput {
    const message = createBaseBatchTransferOutput();
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
function createBaseMsgDepositResponse(): MsgDepositResponse {
  return {};
}
/**
 * MsgDepositResponse
 * @name MsgDepositResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgDepositResponse
 */
export const MsgDepositResponse = {
  typeUrl: "/clairveil.privacy.v1.MsgDepositResponse",
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
 * MsgWithdrawResponse
 * @name MsgWithdrawResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgWithdrawResponse
 */
export const MsgWithdrawResponse = {
  typeUrl: "/clairveil.privacy.v1.MsgWithdrawResponse",
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
 * MsgTransferResponse
 * @name MsgTransferResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgTransferResponse
 */
export const MsgTransferResponse = {
  typeUrl: "/clairveil.privacy.v1.MsgTransferResponse",
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
 * MsgBatchTransferResponse is empty because all scan/output data is stored in
 * typed state and queried separately.
 * @name MsgBatchTransferResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgBatchTransferResponse
 */
export const MsgBatchTransferResponse = {
  typeUrl: "/clairveil.privacy.v1.MsgBatchTransferResponse",
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