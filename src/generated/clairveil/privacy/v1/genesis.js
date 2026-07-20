import { BinaryReader, BinaryWriter } from "../../../binary.js";
function createBaseGenesisState() {
    return {
        commitments: [],
        historicalRoots: [],
        nullifiers: [],
        auditMasterPubkey: new Uint8Array(),
        circuitSetIdentity: undefined,
        assetRegistry: [],
        privacyGlobalSequence: BigInt(0),
        privacyEvents: [],
        privacyScanSummaries: [],
        privacyScanOutputs: [],
        merkleRootSnapshots: [],
        reserveBalances: [],
        stateVersion: 0,
        auditKeyId: "",
        auditKeyEpoch: BigInt(0)
    };
}
/**
 * GenesisState defines the bank module's genesis state.
 * @name GenesisState
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.GenesisState
 */
export const GenesisState = {
    typeUrl: "/clairveil.privacy.v1.GenesisState",
    encode(message, writer = BinaryWriter.create()) {
        for (const v of message.commitments) {
            writer.uint32(10).bytes(v);
        }
        for (const v of message.historicalRoots) {
            writer.uint32(18).bytes(v);
        }
        for (const v of message.nullifiers) {
            writer.uint32(26).bytes(v);
        }
        if (message.auditMasterPubkey.length !== 0) {
            writer.uint32(34).bytes(message.auditMasterPubkey);
        }
        if (message.circuitSetIdentity !== undefined) {
            CircuitSetIdentity.encode(message.circuitSetIdentity, writer.uint32(42).fork()).ldelim();
        }
        for (const v of message.assetRegistry) {
            AssetRegistryEntryV1.encode(v, writer.uint32(50).fork()).ldelim();
        }
        if (message.privacyGlobalSequence !== BigInt(0)) {
            writer.uint32(56).uint64(message.privacyGlobalSequence);
        }
        for (const v of message.privacyEvents) {
            PrivacyEventRecordV1.encode(v, writer.uint32(66).fork()).ldelim();
        }
        for (const v of message.privacyScanSummaries) {
            PrivacyScanSummaryV2.encode(v, writer.uint32(74).fork()).ldelim();
        }
        for (const v of message.privacyScanOutputs) {
            PrivacyScanOutputV2.encode(v, writer.uint32(82).fork()).ldelim();
        }
        for (const v of message.merkleRootSnapshots) {
            MerkleRootSnapshotV1.encode(v, writer.uint32(90).fork()).ldelim();
        }
        for (const v of message.reserveBalances) {
            ReserveBalanceV1.encode(v, writer.uint32(98).fork()).ldelim();
        }
        if (message.stateVersion !== 0) {
            writer.uint32(104).uint32(message.stateVersion);
        }
        if (message.auditKeyId !== "") {
            writer.uint32(114).string(message.auditKeyId);
        }
        if (message.auditKeyEpoch !== BigInt(0)) {
            writer.uint32(120).uint64(message.auditKeyEpoch);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseGenesisState();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.commitments.push(reader.bytes());
                    break;
                case 2:
                    message.historicalRoots.push(reader.bytes());
                    break;
                case 3:
                    message.nullifiers.push(reader.bytes());
                    break;
                case 4:
                    message.auditMasterPubkey = reader.bytes();
                    break;
                case 5:
                    message.circuitSetIdentity = CircuitSetIdentity.decode(reader, reader.uint32());
                    break;
                case 6:
                    message.assetRegistry.push(AssetRegistryEntryV1.decode(reader, reader.uint32()));
                    break;
                case 7:
                    message.privacyGlobalSequence = reader.uint64();
                    break;
                case 8:
                    message.privacyEvents.push(PrivacyEventRecordV1.decode(reader, reader.uint32()));
                    break;
                case 9:
                    message.privacyScanSummaries.push(PrivacyScanSummaryV2.decode(reader, reader.uint32()));
                    break;
                case 10:
                    message.privacyScanOutputs.push(PrivacyScanOutputV2.decode(reader, reader.uint32()));
                    break;
                case 11:
                    message.merkleRootSnapshots.push(MerkleRootSnapshotV1.decode(reader, reader.uint32()));
                    break;
                case 12:
                    message.reserveBalances.push(ReserveBalanceV1.decode(reader, reader.uint32()));
                    break;
                case 13:
                    message.stateVersion = reader.uint32();
                    break;
                case 14:
                    message.auditKeyId = reader.string();
                    break;
                case 15:
                    message.auditKeyEpoch = reader.uint64();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseGenesisState();
        message.commitments = object.commitments?.map(e => e) || [];
        message.historicalRoots = object.historicalRoots?.map(e => e) || [];
        message.nullifiers = object.nullifiers?.map(e => e) || [];
        message.auditMasterPubkey = object.auditMasterPubkey ?? new Uint8Array();
        message.circuitSetIdentity = object.circuitSetIdentity !== undefined && object.circuitSetIdentity !== null ? CircuitSetIdentity.fromPartial(object.circuitSetIdentity) : undefined;
        message.assetRegistry = object.assetRegistry?.map(e => AssetRegistryEntryV1.fromPartial(e)) || [];
        message.privacyGlobalSequence = object.privacyGlobalSequence !== undefined && object.privacyGlobalSequence !== null ? BigInt(object.privacyGlobalSequence.toString()) : BigInt(0);
        message.privacyEvents = object.privacyEvents?.map(e => PrivacyEventRecordV1.fromPartial(e)) || [];
        message.privacyScanSummaries = object.privacyScanSummaries?.map(e => PrivacyScanSummaryV2.fromPartial(e)) || [];
        message.privacyScanOutputs = object.privacyScanOutputs?.map(e => PrivacyScanOutputV2.fromPartial(e)) || [];
        message.merkleRootSnapshots = object.merkleRootSnapshots?.map(e => MerkleRootSnapshotV1.fromPartial(e)) || [];
        message.reserveBalances = object.reserveBalances?.map(e => ReserveBalanceV1.fromPartial(e)) || [];
        message.stateVersion = object.stateVersion ?? 0;
        message.auditKeyId = object.auditKeyId ?? "";
        message.auditKeyEpoch = object.auditKeyEpoch !== undefined && object.auditKeyEpoch !== null ? BigInt(object.auditKeyEpoch.toString()) : BigInt(0);
        return message;
    }
};
function createBaseAssetRegistryEntryV1() {
    return {
        canonicalDenom: "",
        assetId: new Uint8Array()
    };
}
/**
 * AssetRegistryEntryV1 is the consensus 1:1 mapping between a canonical
 * Cosmos denom and its canonical 32-byte NoteV1 asset ID.
 * @name AssetRegistryEntryV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.AssetRegistryEntryV1
 */
export const AssetRegistryEntryV1 = {
    typeUrl: "/clairveil.privacy.v1.AssetRegistryEntryV1",
    encode(message, writer = BinaryWriter.create()) {
        if (message.canonicalDenom !== "") {
            writer.uint32(10).string(message.canonicalDenom);
        }
        if (message.assetId.length !== 0) {
            writer.uint32(18).bytes(message.assetId);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseAssetRegistryEntryV1();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.canonicalDenom = reader.string();
                    break;
                case 2:
                    message.assetId = reader.bytes();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseAssetRegistryEntryV1();
        message.canonicalDenom = object.canonicalDenom ?? "";
        message.assetId = object.assetId ?? new Uint8Array();
        return message;
    }
};
function createBasePrivacyScanCursorV1() {
    return {
        height: BigInt(0),
        globalSequence: BigInt(0),
        outputIndex: 0
    };
}
/**
 * PrivacyScanCursorV1 is ordered lexicographically by
 * (height, global_sequence, output_index). It is shared by Deposit,
 * JoinSplit2x2, and BatchJoinSplit16x32 operations.
 * @name PrivacyScanCursorV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyScanCursorV1
 */
export const PrivacyScanCursorV1 = {
    typeUrl: "/clairveil.privacy.v1.PrivacyScanCursorV1",
    encode(message, writer = BinaryWriter.create()) {
        if (message.height !== BigInt(0)) {
            writer.uint32(8).int64(message.height);
        }
        if (message.globalSequence !== BigInt(0)) {
            writer.uint32(16).uint64(message.globalSequence);
        }
        if (message.outputIndex !== 0) {
            writer.uint32(24).uint32(message.outputIndex);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBasePrivacyScanCursorV1();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.height = reader.int64();
                    break;
                case 2:
                    message.globalSequence = reader.uint64();
                    break;
                case 3:
                    message.outputIndex = reader.uint32();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBasePrivacyScanCursorV1();
        message.height = object.height !== undefined && object.height !== null ? BigInt(object.height.toString()) : BigInt(0);
        message.globalSequence = object.globalSequence !== undefined && object.globalSequence !== null ? BigInt(object.globalSequence.toString()) : BigInt(0);
        message.outputIndex = object.outputIndex ?? 0;
        return message;
    }
};
function createBasePrivacyEventAttributeV1() {
    return {
        key: "",
        value: ""
    };
}
/**
 * @name PrivacyEventAttributeV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyEventAttributeV1
 */
export const PrivacyEventAttributeV1 = {
    typeUrl: "/clairveil.privacy.v1.PrivacyEventAttributeV1",
    encode(message, writer = BinaryWriter.create()) {
        if (message.key !== "") {
            writer.uint32(10).string(message.key);
        }
        if (message.value !== "") {
            writer.uint32(18).string(message.value);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBasePrivacyEventAttributeV1();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.key = reader.string();
                    break;
                case 2:
                    message.value = reader.string();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBasePrivacyEventAttributeV1();
        message.key = object.key ?? "";
        message.value = object.value ?? "";
        return message;
    }
};
function createBasePrivacyEventRecordV1() {
    return {
        globalSequence: BigInt(0),
        height: BigInt(0),
        txHash: new Uint8Array(),
        eventType: "",
        attributes: []
    };
}
/**
 * PrivacyEventRecordV1 preserves the legacy indexed event feed across genesis
 * export/import. New batch payload bytes must not be copied into attributes.
 * @name PrivacyEventRecordV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyEventRecordV1
 */
export const PrivacyEventRecordV1 = {
    typeUrl: "/clairveil.privacy.v1.PrivacyEventRecordV1",
    encode(message, writer = BinaryWriter.create()) {
        if (message.globalSequence !== BigInt(0)) {
            writer.uint32(8).uint64(message.globalSequence);
        }
        if (message.height !== BigInt(0)) {
            writer.uint32(16).int64(message.height);
        }
        if (message.txHash.length !== 0) {
            writer.uint32(26).bytes(message.txHash);
        }
        if (message.eventType !== "") {
            writer.uint32(34).string(message.eventType);
        }
        for (const v of message.attributes) {
            PrivacyEventAttributeV1.encode(v, writer.uint32(42).fork()).ldelim();
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBasePrivacyEventRecordV1();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.globalSequence = reader.uint64();
                    break;
                case 2:
                    message.height = reader.int64();
                    break;
                case 3:
                    message.txHash = reader.bytes();
                    break;
                case 4:
                    message.eventType = reader.string();
                    break;
                case 5:
                    message.attributes.push(PrivacyEventAttributeV1.decode(reader, reader.uint32()));
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBasePrivacyEventRecordV1();
        message.globalSequence = object.globalSequence !== undefined && object.globalSequence !== null ? BigInt(object.globalSequence.toString()) : BigInt(0);
        message.height = object.height !== undefined && object.height !== null ? BigInt(object.height.toString()) : BigInt(0);
        message.txHash = object.txHash ?? new Uint8Array();
        message.eventType = object.eventType ?? "";
        message.attributes = object.attributes?.map(e => PrivacyEventAttributeV1.fromPartial(e)) || [];
        return message;
    }
};
function createBasePrivacyScanSummaryV2() {
    return {
        globalSequence: BigInt(0),
        height: BigInt(0),
        txHash: new Uint8Array(),
        eventType: "",
        nullifiers: [],
        outputCount: 0,
        circuitSetId: "",
        payloadVersion: "",
        scanSchemaVersion: "",
        auditKeyId: "",
        auditKeyEpoch: BigInt(0),
        auditTargetPubkey: new Uint8Array(),
        effectId: new Uint8Array()
    };
}
/**
 * PrivacyScanSummaryV2 is stored once for a logical privacy operation.
 * @name PrivacyScanSummaryV2
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyScanSummaryV2
 */
export const PrivacyScanSummaryV2 = {
    typeUrl: "/clairveil.privacy.v1.PrivacyScanSummaryV2",
    encode(message, writer = BinaryWriter.create()) {
        if (message.globalSequence !== BigInt(0)) {
            writer.uint32(8).uint64(message.globalSequence);
        }
        if (message.height !== BigInt(0)) {
            writer.uint32(16).int64(message.height);
        }
        if (message.txHash.length !== 0) {
            writer.uint32(26).bytes(message.txHash);
        }
        if (message.eventType !== "") {
            writer.uint32(34).string(message.eventType);
        }
        for (const v of message.nullifiers) {
            writer.uint32(42).bytes(v);
        }
        if (message.outputCount !== 0) {
            writer.uint32(48).uint32(message.outputCount);
        }
        if (message.circuitSetId !== "") {
            writer.uint32(58).string(message.circuitSetId);
        }
        if (message.payloadVersion !== "") {
            writer.uint32(66).string(message.payloadVersion);
        }
        if (message.scanSchemaVersion !== "") {
            writer.uint32(74).string(message.scanSchemaVersion);
        }
        if (message.auditKeyId !== "") {
            writer.uint32(82).string(message.auditKeyId);
        }
        if (message.auditKeyEpoch !== BigInt(0)) {
            writer.uint32(88).uint64(message.auditKeyEpoch);
        }
        if (message.auditTargetPubkey.length !== 0) {
            writer.uint32(98).bytes(message.auditTargetPubkey);
        }
        if (message.effectId.length !== 0) {
            writer.uint32(106).bytes(message.effectId);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBasePrivacyScanSummaryV2();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.globalSequence = reader.uint64();
                    break;
                case 2:
                    message.height = reader.int64();
                    break;
                case 3:
                    message.txHash = reader.bytes();
                    break;
                case 4:
                    message.eventType = reader.string();
                    break;
                case 5:
                    message.nullifiers.push(reader.bytes());
                    break;
                case 6:
                    message.outputCount = reader.uint32();
                    break;
                case 7:
                    message.circuitSetId = reader.string();
                    break;
                case 8:
                    message.payloadVersion = reader.string();
                    break;
                case 9:
                    message.scanSchemaVersion = reader.string();
                    break;
                case 10:
                    message.auditKeyId = reader.string();
                    break;
                case 11:
                    message.auditKeyEpoch = reader.uint64();
                    break;
                case 12:
                    message.auditTargetPubkey = reader.bytes();
                    break;
                case 13:
                    message.effectId = reader.bytes();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBasePrivacyScanSummaryV2();
        message.globalSequence = object.globalSequence !== undefined && object.globalSequence !== null ? BigInt(object.globalSequence.toString()) : BigInt(0);
        message.height = object.height !== undefined && object.height !== null ? BigInt(object.height.toString()) : BigInt(0);
        message.txHash = object.txHash ?? new Uint8Array();
        message.eventType = object.eventType ?? "";
        message.nullifiers = object.nullifiers?.map(e => e) || [];
        message.outputCount = object.outputCount ?? 0;
        message.circuitSetId = object.circuitSetId ?? "";
        message.payloadVersion = object.payloadVersion ?? "";
        message.scanSchemaVersion = object.scanSchemaVersion ?? "";
        message.auditKeyId = object.auditKeyId ?? "";
        message.auditKeyEpoch = object.auditKeyEpoch !== undefined && object.auditKeyEpoch !== null ? BigInt(object.auditKeyEpoch.toString()) : BigInt(0);
        message.auditTargetPubkey = object.auditTargetPubkey ?? new Uint8Array();
        message.effectId = object.effectId ?? new Uint8Array();
        return message;
    }
};
function createBasePrivacyScanOutputV2() {
    return {
        globalSequence: BigInt(0),
        height: BigInt(0),
        outputIndex: 0,
        effectId: new Uint8Array(),
        commitment: new Uint8Array(),
        ciphertext: new Uint8Array(),
        encryptedNote: new Uint8Array(),
        viewTag: new Uint8Array(),
        leafIndex: BigInt(0),
        leafIndexFound: false,
        userPrivacyPolicy: 0,
        userDisclosureMode: "",
        userDisclosureDigest: new Uint8Array(),
        userDisclosureTargetPubkey: new Uint8Array(),
        userDisclosurePayload: new Uint8Array(),
        fullDisclosureDigest: new Uint8Array(),
        auditDisclosurePayload: new Uint8Array(),
        selfViewDisclosurePayload: new Uint8Array(),
        circuitSetId: "",
        payloadVersion: "",
        scanSchemaVersion: "",
        auditKeyId: "",
        auditKeyEpoch: BigInt(0),
        auditTargetPubkey: new Uint8Array(),
        txHash: new Uint8Array(),
        eventType: ""
    };
}
/**
 * PrivacyScanOutputV2 stores raw bytes exactly once per output. Its key and
 * body both carry the shared cursor so corrupt/mis-keyed records fail closed.
 * @name PrivacyScanOutputV2
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.PrivacyScanOutputV2
 */
export const PrivacyScanOutputV2 = {
    typeUrl: "/clairveil.privacy.v1.PrivacyScanOutputV2",
    encode(message, writer = BinaryWriter.create()) {
        if (message.globalSequence !== BigInt(0)) {
            writer.uint32(8).uint64(message.globalSequence);
        }
        if (message.height !== BigInt(0)) {
            writer.uint32(16).int64(message.height);
        }
        if (message.outputIndex !== 0) {
            writer.uint32(24).uint32(message.outputIndex);
        }
        if (message.effectId.length !== 0) {
            writer.uint32(34).bytes(message.effectId);
        }
        if (message.commitment.length !== 0) {
            writer.uint32(42).bytes(message.commitment);
        }
        if (message.ciphertext.length !== 0) {
            writer.uint32(50).bytes(message.ciphertext);
        }
        if (message.encryptedNote.length !== 0) {
            writer.uint32(58).bytes(message.encryptedNote);
        }
        if (message.viewTag.length !== 0) {
            writer.uint32(66).bytes(message.viewTag);
        }
        if (message.leafIndex !== BigInt(0)) {
            writer.uint32(72).uint64(message.leafIndex);
        }
        if (message.leafIndexFound === true) {
            writer.uint32(80).bool(message.leafIndexFound);
        }
        if (message.userPrivacyPolicy !== 0) {
            writer.uint32(88).uint32(message.userPrivacyPolicy);
        }
        if (message.userDisclosureMode !== "") {
            writer.uint32(98).string(message.userDisclosureMode);
        }
        if (message.userDisclosureDigest.length !== 0) {
            writer.uint32(106).bytes(message.userDisclosureDigest);
        }
        if (message.userDisclosureTargetPubkey.length !== 0) {
            writer.uint32(114).bytes(message.userDisclosureTargetPubkey);
        }
        if (message.userDisclosurePayload.length !== 0) {
            writer.uint32(122).bytes(message.userDisclosurePayload);
        }
        if (message.fullDisclosureDigest.length !== 0) {
            writer.uint32(130).bytes(message.fullDisclosureDigest);
        }
        if (message.auditDisclosurePayload.length !== 0) {
            writer.uint32(138).bytes(message.auditDisclosurePayload);
        }
        if (message.selfViewDisclosurePayload.length !== 0) {
            writer.uint32(146).bytes(message.selfViewDisclosurePayload);
        }
        if (message.circuitSetId !== "") {
            writer.uint32(154).string(message.circuitSetId);
        }
        if (message.payloadVersion !== "") {
            writer.uint32(162).string(message.payloadVersion);
        }
        if (message.scanSchemaVersion !== "") {
            writer.uint32(170).string(message.scanSchemaVersion);
        }
        if (message.auditKeyId !== "") {
            writer.uint32(178).string(message.auditKeyId);
        }
        if (message.auditKeyEpoch !== BigInt(0)) {
            writer.uint32(184).uint64(message.auditKeyEpoch);
        }
        if (message.auditTargetPubkey.length !== 0) {
            writer.uint32(194).bytes(message.auditTargetPubkey);
        }
        if (message.txHash.length !== 0) {
            writer.uint32(202).bytes(message.txHash);
        }
        if (message.eventType !== "") {
            writer.uint32(210).string(message.eventType);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBasePrivacyScanOutputV2();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.globalSequence = reader.uint64();
                    break;
                case 2:
                    message.height = reader.int64();
                    break;
                case 3:
                    message.outputIndex = reader.uint32();
                    break;
                case 4:
                    message.effectId = reader.bytes();
                    break;
                case 5:
                    message.commitment = reader.bytes();
                    break;
                case 6:
                    message.ciphertext = reader.bytes();
                    break;
                case 7:
                    message.encryptedNote = reader.bytes();
                    break;
                case 8:
                    message.viewTag = reader.bytes();
                    break;
                case 9:
                    message.leafIndex = reader.uint64();
                    break;
                case 10:
                    message.leafIndexFound = reader.bool();
                    break;
                case 11:
                    message.userPrivacyPolicy = reader.uint32();
                    break;
                case 12:
                    message.userDisclosureMode = reader.string();
                    break;
                case 13:
                    message.userDisclosureDigest = reader.bytes();
                    break;
                case 14:
                    message.userDisclosureTargetPubkey = reader.bytes();
                    break;
                case 15:
                    message.userDisclosurePayload = reader.bytes();
                    break;
                case 16:
                    message.fullDisclosureDigest = reader.bytes();
                    break;
                case 17:
                    message.auditDisclosurePayload = reader.bytes();
                    break;
                case 18:
                    message.selfViewDisclosurePayload = reader.bytes();
                    break;
                case 19:
                    message.circuitSetId = reader.string();
                    break;
                case 20:
                    message.payloadVersion = reader.string();
                    break;
                case 21:
                    message.scanSchemaVersion = reader.string();
                    break;
                case 22:
                    message.auditKeyId = reader.string();
                    break;
                case 23:
                    message.auditKeyEpoch = reader.uint64();
                    break;
                case 24:
                    message.auditTargetPubkey = reader.bytes();
                    break;
                case 25:
                    message.txHash = reader.bytes();
                    break;
                case 26:
                    message.eventType = reader.string();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBasePrivacyScanOutputV2();
        message.globalSequence = object.globalSequence !== undefined && object.globalSequence !== null ? BigInt(object.globalSequence.toString()) : BigInt(0);
        message.height = object.height !== undefined && object.height !== null ? BigInt(object.height.toString()) : BigInt(0);
        message.outputIndex = object.outputIndex ?? 0;
        message.effectId = object.effectId ?? new Uint8Array();
        message.commitment = object.commitment ?? new Uint8Array();
        message.ciphertext = object.ciphertext ?? new Uint8Array();
        message.encryptedNote = object.encryptedNote ?? new Uint8Array();
        message.viewTag = object.viewTag ?? new Uint8Array();
        message.leafIndex = object.leafIndex !== undefined && object.leafIndex !== null ? BigInt(object.leafIndex.toString()) : BigInt(0);
        message.leafIndexFound = object.leafIndexFound ?? false;
        message.userPrivacyPolicy = object.userPrivacyPolicy ?? 0;
        message.userDisclosureMode = object.userDisclosureMode ?? "";
        message.userDisclosureDigest = object.userDisclosureDigest ?? new Uint8Array();
        message.userDisclosureTargetPubkey = object.userDisclosureTargetPubkey ?? new Uint8Array();
        message.userDisclosurePayload = object.userDisclosurePayload ?? new Uint8Array();
        message.fullDisclosureDigest = object.fullDisclosureDigest ?? new Uint8Array();
        message.auditDisclosurePayload = object.auditDisclosurePayload ?? new Uint8Array();
        message.selfViewDisclosurePayload = object.selfViewDisclosurePayload ?? new Uint8Array();
        message.circuitSetId = object.circuitSetId ?? "";
        message.payloadVersion = object.payloadVersion ?? "";
        message.scanSchemaVersion = object.scanSchemaVersion ?? "";
        message.auditKeyId = object.auditKeyId ?? "";
        message.auditKeyEpoch = object.auditKeyEpoch !== undefined && object.auditKeyEpoch !== null ? BigInt(object.auditKeyEpoch.toString()) : BigInt(0);
        message.auditTargetPubkey = object.auditTargetPubkey ?? new Uint8Array();
        message.txHash = object.txHash ?? new Uint8Array();
        message.eventType = object.eventType ?? "";
        return message;
    }
};
function createBaseMerkleRootSnapshotV1() {
    return {
        root: new Uint8Array(),
        leafCount: BigInt(0),
        height: BigInt(0)
    };
}
/**
 * MerkleRootSnapshotV1 binds a historical root to the exact commitment prefix
 * and block height needed to build all requested paths from one snapshot.
 * @name MerkleRootSnapshotV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.MerkleRootSnapshotV1
 */
export const MerkleRootSnapshotV1 = {
    typeUrl: "/clairveil.privacy.v1.MerkleRootSnapshotV1",
    encode(message, writer = BinaryWriter.create()) {
        if (message.root.length !== 0) {
            writer.uint32(10).bytes(message.root);
        }
        if (message.leafCount !== BigInt(0)) {
            writer.uint32(16).uint64(message.leafCount);
        }
        if (message.height !== BigInt(0)) {
            writer.uint32(24).int64(message.height);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseMerkleRootSnapshotV1();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.root = reader.bytes();
                    break;
                case 2:
                    message.leafCount = reader.uint64();
                    break;
                case 3:
                    message.height = reader.int64();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseMerkleRootSnapshotV1();
        message.root = object.root ?? new Uint8Array();
        message.leafCount = object.leafCount !== undefined && object.leafCount !== null ? BigInt(object.leafCount.toString()) : BigInt(0);
        message.height = object.height !== undefined && object.height !== null ? BigInt(object.height.toString()) : BigInt(0);
        return message;
    }
};
function createBaseReserveBalanceV1() {
    return {
        canonicalDenom: "",
        totalDeposited: "",
        totalWithdrawn: ""
    };
}
/**
 * @name ReserveBalanceV1
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.ReserveBalanceV1
 */
export const ReserveBalanceV1 = {
    typeUrl: "/clairveil.privacy.v1.ReserveBalanceV1",
    encode(message, writer = BinaryWriter.create()) {
        if (message.canonicalDenom !== "") {
            writer.uint32(10).string(message.canonicalDenom);
        }
        if (message.totalDeposited !== "") {
            writer.uint32(18).string(message.totalDeposited);
        }
        if (message.totalWithdrawn !== "") {
            writer.uint32(26).string(message.totalWithdrawn);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseReserveBalanceV1();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.canonicalDenom = reader.string();
                    break;
                case 2:
                    message.totalDeposited = reader.string();
                    break;
                case 3:
                    message.totalWithdrawn = reader.string();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseReserveBalanceV1();
        message.canonicalDenom = object.canonicalDenom ?? "";
        message.totalDeposited = object.totalDeposited ?? "";
        message.totalWithdrawn = object.totalWithdrawn ?? "";
        return message;
    }
};
function createBaseCircuitIdentity() {
    return {
        circuitId: "",
        verifyingKeySha256: "",
        publicInputSchemaSha256: ""
    };
}
/**
 * @name CircuitIdentity
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.CircuitIdentity
 */
export const CircuitIdentity = {
    typeUrl: "/clairveil.privacy.v1.CircuitIdentity",
    encode(message, writer = BinaryWriter.create()) {
        if (message.circuitId !== "") {
            writer.uint32(10).string(message.circuitId);
        }
        if (message.verifyingKeySha256 !== "") {
            writer.uint32(18).string(message.verifyingKeySha256);
        }
        if (message.publicInputSchemaSha256 !== "") {
            writer.uint32(26).string(message.publicInputSchemaSha256);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseCircuitIdentity();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.circuitId = reader.string();
                    break;
                case 2:
                    message.verifyingKeySha256 = reader.string();
                    break;
                case 3:
                    message.publicInputSchemaSha256 = reader.string();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseCircuitIdentity();
        message.circuitId = object.circuitId ?? "";
        message.verifyingKeySha256 = object.verifyingKeySha256 ?? "";
        message.publicInputSchemaSha256 = object.publicInputSchemaSha256 ?? "";
        return message;
    }
};
function createBaseCircuitSetIdentity() {
    return {
        schemaVersion: "",
        circuitSetId: "",
        curve: "",
        circuits: []
    };
}
/**
 * @name CircuitSetIdentity
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.CircuitSetIdentity
 */
export const CircuitSetIdentity = {
    typeUrl: "/clairveil.privacy.v1.CircuitSetIdentity",
    encode(message, writer = BinaryWriter.create()) {
        if (message.schemaVersion !== "") {
            writer.uint32(10).string(message.schemaVersion);
        }
        if (message.circuitSetId !== "") {
            writer.uint32(18).string(message.circuitSetId);
        }
        if (message.curve !== "") {
            writer.uint32(26).string(message.curve);
        }
        for (const v of message.circuits) {
            CircuitIdentity.encode(v, writer.uint32(34).fork()).ldelim();
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseCircuitSetIdentity();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.schemaVersion = reader.string();
                    break;
                case 2:
                    message.circuitSetId = reader.string();
                    break;
                case 3:
                    message.curve = reader.string();
                    break;
                case 4:
                    message.circuits.push(CircuitIdentity.decode(reader, reader.uint32()));
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseCircuitSetIdentity();
        message.schemaVersion = object.schemaVersion ?? "";
        message.circuitSetId = object.circuitSetId ?? "";
        message.curve = object.curve ?? "";
        message.circuits = object.circuits?.map(e => CircuitIdentity.fromPartial(e)) || [];
        return message;
    }
};
