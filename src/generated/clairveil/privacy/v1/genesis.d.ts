import { BinaryReader, BinaryWriter } from "../../../binary.js";
import { DeepPartial } from "../../../helpers.js";
/**
 * GenesisState defines the bank module's genesis state.
 * @name GenesisState
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.GenesisState
 */
export interface GenesisState {
    commitments: Uint8Array[];
    historicalRoots: Uint8Array[];
    nullifiers: Uint8Array[];
    auditMasterPubkey: Uint8Array;
    circuitSetIdentity?: CircuitSetIdentity;
    assetRegistry: AssetRegistryEntryV1[];
    privacyGlobalSequence: bigint;
    privacyEvents: PrivacyEventRecordV1[];
    privacyScanSummaries: PrivacyScanSummaryV2[];
    privacyScanOutputs: PrivacyScanOutputV2[];
    merkleRootSnapshots: MerkleRootSnapshotV1[];
    reserveBalances: ReserveBalanceV1[];
    stateVersion: number;
    auditKeyId: string;
    auditKeyEpoch: bigint;
}
/**
 * AssetRegistryEntryV1 is the consensus 1:1 mapping between a canonical
 * Cosmos denom and its canonical 32-byte NoteV1 asset ID.
 * @name AssetRegistryEntryV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.AssetRegistryEntryV1
 */
export interface AssetRegistryEntryV1 {
    canonicalDenom: string;
    assetId: Uint8Array;
}
/**
 * PrivacyScanCursorV1 is ordered lexicographically by
 * (height, global_sequence, output_index). It is shared by Deposit,
 * JoinSplit2x2, and BatchJoinSplit16x32 operations.
 * @name PrivacyScanCursorV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyScanCursorV1
 */
export interface PrivacyScanCursorV1 {
    height: bigint;
    globalSequence: bigint;
    outputIndex: number;
}
/**
 * @name PrivacyEventAttributeV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyEventAttributeV1
 */
export interface PrivacyEventAttributeV1 {
    key: string;
    value: string;
}
/**
 * PrivacyEventRecordV1 preserves the legacy indexed event feed across genesis
 * export/import. New batch payload bytes must not be copied into attributes.
 * @name PrivacyEventRecordV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyEventRecordV1
 */
export interface PrivacyEventRecordV1 {
    globalSequence: bigint;
    height: bigint;
    txHash: Uint8Array;
    eventType: string;
    attributes: PrivacyEventAttributeV1[];
}
/**
 * PrivacyScanSummaryV2 is stored once for a logical privacy operation.
 * @name PrivacyScanSummaryV2
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyScanSummaryV2
 */
export interface PrivacyScanSummaryV2 {
    globalSequence: bigint;
    height: bigint;
    txHash: Uint8Array;
    eventType: string;
    nullifiers: Uint8Array[];
    outputCount: number;
    circuitSetId: string;
    payloadVersion: string;
    scanSchemaVersion: string;
    auditKeyId: string;
    auditKeyEpoch: bigint;
    auditTargetPubkey: Uint8Array;
    effectId: Uint8Array;
}
/**
 * PrivacyScanOutputV2 stores raw bytes exactly once per output. Its key and
 * body both carry the shared cursor so corrupt/mis-keyed records fail closed.
 * @name PrivacyScanOutputV2
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyScanOutputV2
 */
export interface PrivacyScanOutputV2 {
    globalSequence: bigint;
    height: bigint;
    outputIndex: number;
    effectId: Uint8Array;
    commitment: Uint8Array;
    ciphertext: Uint8Array;
    encryptedNote: Uint8Array;
    viewTag: Uint8Array;
    leafIndex: bigint;
    leafIndexFound: boolean;
    userPrivacyPolicy: number;
    userDisclosureMode: string;
    userDisclosureDigest: Uint8Array;
    userDisclosureTargetPubkey: Uint8Array;
    userDisclosurePayload: Uint8Array;
    fullDisclosureDigest: Uint8Array;
    auditDisclosurePayload: Uint8Array;
    selfViewDisclosurePayload: Uint8Array;
    circuitSetId: string;
    payloadVersion: string;
    scanSchemaVersion: string;
    auditKeyId: string;
    auditKeyEpoch: bigint;
    auditTargetPubkey: Uint8Array;
    txHash: Uint8Array;
    eventType: string;
}
/**
 * MerkleRootSnapshotV1 binds a historical root to the exact commitment prefix
 * and block height needed to build all requested paths from one snapshot.
 * @name MerkleRootSnapshotV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MerkleRootSnapshotV1
 */
export interface MerkleRootSnapshotV1 {
    root: Uint8Array;
    leafCount: bigint;
    height: bigint;
}
/**
 * @name ReserveBalanceV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.ReserveBalanceV1
 */
export interface ReserveBalanceV1 {
    canonicalDenom: string;
    totalDeposited: string;
    totalWithdrawn: string;
}
/**
 * @name CircuitIdentity
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.CircuitIdentity
 */
export interface CircuitIdentity {
    circuitId: string;
    verifyingKeySha256: string;
    publicInputSchemaSha256: string;
}
/**
 * @name CircuitSetIdentity
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.CircuitSetIdentity
 */
export interface CircuitSetIdentity {
    schemaVersion: string;
    circuitSetId: string;
    curve: string;
    circuits: CircuitIdentity[];
}
/**
 * GenesisState defines the bank module's genesis state.
 * @name GenesisState
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.GenesisState
 */
export declare const GenesisState: {
    typeUrl: string;
    encode(message: GenesisState, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): GenesisState;
    fromPartial(object: DeepPartial<GenesisState>): GenesisState;
};
/**
 * AssetRegistryEntryV1 is the consensus 1:1 mapping between a canonical
 * Cosmos denom and its canonical 32-byte NoteV1 asset ID.
 * @name AssetRegistryEntryV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.AssetRegistryEntryV1
 */
export declare const AssetRegistryEntryV1: {
    typeUrl: string;
    encode(message: AssetRegistryEntryV1, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): AssetRegistryEntryV1;
    fromPartial(object: DeepPartial<AssetRegistryEntryV1>): AssetRegistryEntryV1;
};
/**
 * PrivacyScanCursorV1 is ordered lexicographically by
 * (height, global_sequence, output_index). It is shared by Deposit,
 * JoinSplit2x2, and BatchJoinSplit16x32 operations.
 * @name PrivacyScanCursorV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyScanCursorV1
 */
export declare const PrivacyScanCursorV1: {
    typeUrl: string;
    encode(message: PrivacyScanCursorV1, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): PrivacyScanCursorV1;
    fromPartial(object: DeepPartial<PrivacyScanCursorV1>): PrivacyScanCursorV1;
};
/**
 * @name PrivacyEventAttributeV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyEventAttributeV1
 */
export declare const PrivacyEventAttributeV1: {
    typeUrl: string;
    encode(message: PrivacyEventAttributeV1, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): PrivacyEventAttributeV1;
    fromPartial(object: DeepPartial<PrivacyEventAttributeV1>): PrivacyEventAttributeV1;
};
/**
 * PrivacyEventRecordV1 preserves the legacy indexed event feed across genesis
 * export/import. New batch payload bytes must not be copied into attributes.
 * @name PrivacyEventRecordV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyEventRecordV1
 */
export declare const PrivacyEventRecordV1: {
    typeUrl: string;
    encode(message: PrivacyEventRecordV1, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): PrivacyEventRecordV1;
    fromPartial(object: DeepPartial<PrivacyEventRecordV1>): PrivacyEventRecordV1;
};
/**
 * PrivacyScanSummaryV2 is stored once for a logical privacy operation.
 * @name PrivacyScanSummaryV2
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyScanSummaryV2
 */
export declare const PrivacyScanSummaryV2: {
    typeUrl: string;
    encode(message: PrivacyScanSummaryV2, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): PrivacyScanSummaryV2;
    fromPartial(object: DeepPartial<PrivacyScanSummaryV2>): PrivacyScanSummaryV2;
};
/**
 * PrivacyScanOutputV2 stores raw bytes exactly once per output. Its key and
 * body both carry the shared cursor so corrupt/mis-keyed records fail closed.
 * @name PrivacyScanOutputV2
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyScanOutputV2
 */
export declare const PrivacyScanOutputV2: {
    typeUrl: string;
    encode(message: PrivacyScanOutputV2, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): PrivacyScanOutputV2;
    fromPartial(object: DeepPartial<PrivacyScanOutputV2>): PrivacyScanOutputV2;
};
/**
 * MerkleRootSnapshotV1 binds a historical root to the exact commitment prefix
 * and block height needed to build all requested paths from one snapshot.
 * @name MerkleRootSnapshotV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MerkleRootSnapshotV1
 */
export declare const MerkleRootSnapshotV1: {
    typeUrl: string;
    encode(message: MerkleRootSnapshotV1, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): MerkleRootSnapshotV1;
    fromPartial(object: DeepPartial<MerkleRootSnapshotV1>): MerkleRootSnapshotV1;
};
/**
 * @name ReserveBalanceV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.ReserveBalanceV1
 */
export declare const ReserveBalanceV1: {
    typeUrl: string;
    encode(message: ReserveBalanceV1, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): ReserveBalanceV1;
    fromPartial(object: DeepPartial<ReserveBalanceV1>): ReserveBalanceV1;
};
/**
 * @name CircuitIdentity
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.CircuitIdentity
 */
export declare const CircuitIdentity: {
    typeUrl: string;
    encode(message: CircuitIdentity, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): CircuitIdentity;
    fromPartial(object: DeepPartial<CircuitIdentity>): CircuitIdentity;
};
/**
 * @name CircuitSetIdentity
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.CircuitSetIdentity
 */
export declare const CircuitSetIdentity: {
    typeUrl: string;
    encode(message: CircuitSetIdentity, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): CircuitSetIdentity;
    fromPartial(object: DeepPartial<CircuitSetIdentity>): CircuitSetIdentity;
};
