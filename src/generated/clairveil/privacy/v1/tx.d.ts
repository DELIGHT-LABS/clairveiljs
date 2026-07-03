import { BinaryReader, BinaryWriter } from "../../../binary.js";
import { DeepPartial } from "../../../helpers.js";
export declare enum UserDisclosureMode {
    USER_DISCLOSURE_MODE_NONE = 0,
    USER_DISCLOSURE_MODE_PUBLIC = 1,
    USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED = 2,
    UNRECOGNIZED = -1
}
export declare function userDisclosureModeFromJSON(object: any): UserDisclosureMode;
export declare function userDisclosureModeToJSON(object: UserDisclosureMode): string;
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
}
/**
 * MsgDepositResponse
 * @name MsgDepositResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgDepositResponse
 */
export interface MsgDepositResponse {
}
/**
 * MsgWithdrawResponse
 * @name MsgWithdrawResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgWithdrawResponse
 */
export interface MsgWithdrawResponse {
}
/**
 * MsgTransferResponse
 * @name MsgTransferResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgTransferResponse
 */
export interface MsgTransferResponse {
}
/**
 * MsgDeposit: 투명 자산 -> 익명 자산 변환
 * @name MsgDeposit
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgDeposit
 */
export declare const MsgDeposit: {
    typeUrl: string;
    encode(message: MsgDeposit, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgDeposit;
    fromPartial(object: DeepPartial<MsgDeposit>): MsgDeposit;
};
/**
 * MsgWithdraw: 익명 자산 -> 투명 자산 변환
 * @name MsgWithdraw
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgWithdraw
 */
export declare const MsgWithdraw: {
    typeUrl: string;
    encode(message: MsgWithdraw, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgWithdraw;
    fromPartial(object: DeepPartial<MsgWithdraw>): MsgWithdraw;
};
/**
 * MsgTransfer: 내부 전송
 * @name MsgTransfer
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgTransfer
 */
export declare const MsgTransfer: {
    typeUrl: string;
    encode(message: MsgTransfer, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgTransfer;
    fromPartial(object: DeepPartial<MsgTransfer>): MsgTransfer;
};
/**
 * MsgDepositResponse
 * @name MsgDepositResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgDepositResponse
 */
export declare const MsgDepositResponse: {
    typeUrl: string;
    encode(_: MsgDepositResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgDepositResponse;
    fromPartial(_: DeepPartial<MsgDepositResponse>): MsgDepositResponse;
};
/**
 * MsgWithdrawResponse
 * @name MsgWithdrawResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgWithdrawResponse
 */
export declare const MsgWithdrawResponse: {
    typeUrl: string;
    encode(_: MsgWithdrawResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgWithdrawResponse;
    fromPartial(_: DeepPartial<MsgWithdrawResponse>): MsgWithdrawResponse;
};
/**
 * MsgTransferResponse
 * @name MsgTransferResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MsgTransferResponse
 */
export declare const MsgTransferResponse: {
    typeUrl: string;
    encode(_: MsgTransferResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MsgTransferResponse;
    fromPartial(_: DeepPartial<MsgTransferResponse>): MsgTransferResponse;
};
