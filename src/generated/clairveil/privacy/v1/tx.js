import { BinaryReader, BinaryWriter } from "../../../binary.js";
export var UserDisclosureMode;
(function (UserDisclosureMode) {
    UserDisclosureMode[UserDisclosureMode["USER_DISCLOSURE_MODE_NONE"] = 0] = "USER_DISCLOSURE_MODE_NONE";
    UserDisclosureMode[UserDisclosureMode["USER_DISCLOSURE_MODE_PUBLIC"] = 1] = "USER_DISCLOSURE_MODE_PUBLIC";
    UserDisclosureMode[UserDisclosureMode["USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED"] = 2] = "USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED";
    UserDisclosureMode[UserDisclosureMode["UNRECOGNIZED"] = -1] = "UNRECOGNIZED";
})(UserDisclosureMode || (UserDisclosureMode = {}));
export function userDisclosureModeFromJSON(object) {
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
export function userDisclosureModeToJSON(object) {
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
function createBaseMsgDeposit() {
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
    encode(message, writer = BinaryWriter.create()) {
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
    decode(input, length) {
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
    fromPartial(object) {
        const message = createBaseMsgDeposit();
        message.creator = object.creator ?? "";
        message.amount = object.amount ?? "";
        message.noteCommitment = object.noteCommitment ?? new Uint8Array();
        message.encryptedNote = object.encryptedNote ?? new Uint8Array();
        message.proof = object.proof ?? new Uint8Array();
        return message;
    }
};
function createBaseMsgWithdraw() {
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
    encode(message, writer = BinaryWriter.create()) {
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
    decode(input, length) {
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
    fromPartial(object) {
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
function createBaseMsgTransfer() {
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
        viewTags: []
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
    encode(message, writer = BinaryWriter.create()) {
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
            writer.uint32(34).bytes(v);
        }
        for (const v of message.newCommitments) {
            writer.uint32(42).bytes(v);
        }
        for (const v of message.cipherTexts) {
            writer.uint32(50).bytes(v);
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
            writer.uint32(138).bytes(v);
        }
        return writer;
    },
    decode(input, length) {
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
                    message.userDisclosureMode = reader.int32();
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
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
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
        return message;
    }
};
function createBaseMsgDepositResponse() {
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
    encode(_, writer = BinaryWriter.create()) {
        return writer;
    },
    decode(input, length) {
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
    fromPartial(_) {
        const message = createBaseMsgDepositResponse();
        return message;
    }
};
function createBaseMsgWithdrawResponse() {
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
    encode(_, writer = BinaryWriter.create()) {
        return writer;
    },
    decode(input, length) {
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
    fromPartial(_) {
        const message = createBaseMsgWithdrawResponse();
        return message;
    }
};
function createBaseMsgTransferResponse() {
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
    encode(_, writer = BinaryWriter.create()) {
        return writer;
    },
    decode(input, length) {
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
    fromPartial(_) {
        const message = createBaseMsgTransferResponse();
        return message;
    }
};
