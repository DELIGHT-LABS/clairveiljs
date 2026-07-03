import { BinaryReader, BinaryWriter } from "../../../binary.js";
function createBaseQueryCheckNullifierRequest() {
    return {
        nullifier: ""
    };
}
/**
 * QueryCheckNullifierRequest
 * @name QueryCheckNullifierRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCheckNullifierRequest
 */
export const QueryCheckNullifierRequest = {
    typeUrl: "/clairveil.privacy.v1.QueryCheckNullifierRequest",
    encode(message, writer = BinaryWriter.create()) {
        if (message.nullifier !== "") {
            writer.uint32(10).string(message.nullifier);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryCheckNullifierRequest();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.nullifier = reader.string();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryCheckNullifierRequest();
        message.nullifier = object.nullifier ?? "";
        return message;
    }
};
function createBaseQueryCheckNullifierResponse() {
    return {
        used: false
    };
}
/**
 * QueryCheckNullifierResponse
 * @name QueryCheckNullifierResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCheckNullifierResponse
 */
export const QueryCheckNullifierResponse = {
    typeUrl: "/clairveil.privacy.v1.QueryCheckNullifierResponse",
    encode(message, writer = BinaryWriter.create()) {
        if (message.used === true) {
            writer.uint32(8).bool(message.used);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryCheckNullifierResponse();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.used = reader.bool();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryCheckNullifierResponse();
        message.used = object.used ?? false;
        return message;
    }
};
function createBaseQueryTreeStateRequest() {
    return {};
}
/**
 * @name QueryTreeStateRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryTreeStateRequest
 */
export const QueryTreeStateRequest = {
    typeUrl: "/clairveil.privacy.v1.QueryTreeStateRequest",
    encode(_, writer = BinaryWriter.create()) {
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryTreeStateRequest();
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
        const message = createBaseQueryTreeStateRequest();
        return message;
    }
};
function createBaseQueryTreeStateResponse() {
    return {
        root: "",
        leafCount: BigInt(0),
        depth: 0,
        initialized: false,
        maxLeaves: BigInt(0),
        remainingLeaves: BigInt(0)
    };
}
/**
 * @name QueryTreeStateResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryTreeStateResponse
 */
export const QueryTreeStateResponse = {
    typeUrl: "/clairveil.privacy.v1.QueryTreeStateResponse",
    encode(message, writer = BinaryWriter.create()) {
        if (message.root !== "") {
            writer.uint32(10).string(message.root);
        }
        if (message.leafCount !== BigInt(0)) {
            writer.uint32(16).uint64(message.leafCount);
        }
        if (message.depth !== 0) {
            writer.uint32(24).uint32(message.depth);
        }
        if (message.initialized === true) {
            writer.uint32(32).bool(message.initialized);
        }
        if (message.maxLeaves !== BigInt(0)) {
            writer.uint32(40).uint64(message.maxLeaves);
        }
        if (message.remainingLeaves !== BigInt(0)) {
            writer.uint32(48).uint64(message.remainingLeaves);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryTreeStateResponse();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.root = reader.string();
                    break;
                case 2:
                    message.leafCount = reader.uint64();
                    break;
                case 3:
                    message.depth = reader.uint32();
                    break;
                case 4:
                    message.initialized = reader.bool();
                    break;
                case 5:
                    message.maxLeaves = reader.uint64();
                    break;
                case 6:
                    message.remainingLeaves = reader.uint64();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryTreeStateResponse();
        message.root = object.root ?? "";
        message.leafCount = object.leafCount !== undefined && object.leafCount !== null ? BigInt(object.leafCount.toString()) : BigInt(0);
        message.depth = object.depth ?? 0;
        message.initialized = object.initialized ?? false;
        message.maxLeaves = object.maxLeaves !== undefined && object.maxLeaves !== null ? BigInt(object.maxLeaves.toString()) : BigInt(0);
        message.remainingLeaves = object.remainingLeaves !== undefined && object.remainingLeaves !== null ? BigInt(object.remainingLeaves.toString()) : BigInt(0);
        return message;
    }
};
function createBaseQueryCommitmentInfoRequest() {
    return {
        commitmentHex: ""
    };
}
/**
 * @name QueryCommitmentInfoRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCommitmentInfoRequest
 */
export const QueryCommitmentInfoRequest = {
    typeUrl: "/clairveil.privacy.v1.QueryCommitmentInfoRequest",
    encode(message, writer = BinaryWriter.create()) {
        if (message.commitmentHex !== "") {
            writer.uint32(10).string(message.commitmentHex);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryCommitmentInfoRequest();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.commitmentHex = reader.string();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryCommitmentInfoRequest();
        message.commitmentHex = object.commitmentHex ?? "";
        return message;
    }
};
function createBaseQueryCommitmentInfoResponse() {
    return {
        found: false,
        leafIndex: BigInt(0)
    };
}
/**
 * @name QueryCommitmentInfoResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCommitmentInfoResponse
 */
export const QueryCommitmentInfoResponse = {
    typeUrl: "/clairveil.privacy.v1.QueryCommitmentInfoResponse",
    encode(message, writer = BinaryWriter.create()) {
        if (message.found === true) {
            writer.uint32(8).bool(message.found);
        }
        if (message.leafIndex !== BigInt(0)) {
            writer.uint32(16).uint64(message.leafIndex);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryCommitmentInfoResponse();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.found = reader.bool();
                    break;
                case 2:
                    message.leafIndex = reader.uint64();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryCommitmentInfoResponse();
        message.found = object.found ?? false;
        message.leafIndex = object.leafIndex !== undefined && object.leafIndex !== null ? BigInt(object.leafIndex.toString()) : BigInt(0);
        return message;
    }
};
function createBaseQueryPrivacyEventsRequest() {
    return {
        afterHeight: BigInt(0),
        page: BigInt(0),
        limit: BigInt(0),
        eventTypes: []
    };
}
/**
 * @name QueryPrivacyEventsRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyEventsRequest
 */
export const QueryPrivacyEventsRequest = {
    typeUrl: "/clairveil.privacy.v1.QueryPrivacyEventsRequest",
    encode(message, writer = BinaryWriter.create()) {
        if (message.afterHeight !== BigInt(0)) {
            writer.uint32(8).int64(message.afterHeight);
        }
        if (message.page !== BigInt(0)) {
            writer.uint32(16).uint64(message.page);
        }
        if (message.limit !== BigInt(0)) {
            writer.uint32(24).uint64(message.limit);
        }
        for (const v of message.eventTypes) {
            writer.uint32(34).string(v);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryPrivacyEventsRequest();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.afterHeight = reader.int64();
                    break;
                case 2:
                    message.page = reader.uint64();
                    break;
                case 3:
                    message.limit = reader.uint64();
                    break;
                case 4:
                    message.eventTypes.push(reader.string());
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryPrivacyEventsRequest();
        message.afterHeight = object.afterHeight !== undefined && object.afterHeight !== null ? BigInt(object.afterHeight.toString()) : BigInt(0);
        message.page = object.page !== undefined && object.page !== null ? BigInt(object.page.toString()) : BigInt(0);
        message.limit = object.limit !== undefined && object.limit !== null ? BigInt(object.limit.toString()) : BigInt(0);
        message.eventTypes = object.eventTypes?.map(e => e) || [];
        return message;
    }
};
function createBaseQueryPrivacyEventAttribute() {
    return {
        key: "",
        value: ""
    };
}
/**
 * @name QueryPrivacyEventAttribute
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyEventAttribute
 */
export const QueryPrivacyEventAttribute = {
    typeUrl: "/clairveil.privacy.v1.QueryPrivacyEventAttribute",
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
        const message = createBaseQueryPrivacyEventAttribute();
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
        const message = createBaseQueryPrivacyEventAttribute();
        message.key = object.key ?? "";
        message.value = object.value ?? "";
        return message;
    }
};
function createBaseQueryPrivacyEvent() {
    return {
        sequence: BigInt(0),
        height: BigInt(0),
        txHashHex: "",
        eventType: "",
        attributes: []
    };
}
/**
 * @name QueryPrivacyEvent
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyEvent
 */
export const QueryPrivacyEvent = {
    typeUrl: "/clairveil.privacy.v1.QueryPrivacyEvent",
    encode(message, writer = BinaryWriter.create()) {
        if (message.sequence !== BigInt(0)) {
            writer.uint32(8).uint64(message.sequence);
        }
        if (message.height !== BigInt(0)) {
            writer.uint32(16).int64(message.height);
        }
        if (message.txHashHex !== "") {
            writer.uint32(26).string(message.txHashHex);
        }
        if (message.eventType !== "") {
            writer.uint32(34).string(message.eventType);
        }
        for (const v of message.attributes) {
            QueryPrivacyEventAttribute.encode(v, writer.uint32(42).fork()).ldelim();
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryPrivacyEvent();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.sequence = reader.uint64();
                    break;
                case 2:
                    message.height = reader.int64();
                    break;
                case 3:
                    message.txHashHex = reader.string();
                    break;
                case 4:
                    message.eventType = reader.string();
                    break;
                case 5:
                    message.attributes.push(QueryPrivacyEventAttribute.decode(reader, reader.uint32()));
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryPrivacyEvent();
        message.sequence = object.sequence !== undefined && object.sequence !== null ? BigInt(object.sequence.toString()) : BigInt(0);
        message.height = object.height !== undefined && object.height !== null ? BigInt(object.height.toString()) : BigInt(0);
        message.txHashHex = object.txHashHex ?? "";
        message.eventType = object.eventType ?? "";
        message.attributes = object.attributes?.map(e => QueryPrivacyEventAttribute.fromPartial(e)) || [];
        return message;
    }
};
function createBaseQueryPrivacyEventsResponse() {
    return {
        events: [],
        page: BigInt(0),
        limit: BigInt(0),
        hasMore: false
    };
}
/**
 * @name QueryPrivacyEventsResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyEventsResponse
 */
export const QueryPrivacyEventsResponse = {
    typeUrl: "/clairveil.privacy.v1.QueryPrivacyEventsResponse",
    encode(message, writer = BinaryWriter.create()) {
        for (const v of message.events) {
            QueryPrivacyEvent.encode(v, writer.uint32(10).fork()).ldelim();
        }
        if (message.page !== BigInt(0)) {
            writer.uint32(16).uint64(message.page);
        }
        if (message.limit !== BigInt(0)) {
            writer.uint32(24).uint64(message.limit);
        }
        if (message.hasMore === true) {
            writer.uint32(32).bool(message.hasMore);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryPrivacyEventsResponse();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.events.push(QueryPrivacyEvent.decode(reader, reader.uint32()));
                    break;
                case 2:
                    message.page = reader.uint64();
                    break;
                case 3:
                    message.limit = reader.uint64();
                    break;
                case 4:
                    message.hasMore = reader.bool();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryPrivacyEventsResponse();
        message.events = object.events?.map(e => QueryPrivacyEvent.fromPartial(e)) || [];
        message.page = object.page !== undefined && object.page !== null ? BigInt(object.page.toString()) : BigInt(0);
        message.limit = object.limit !== undefined && object.limit !== null ? BigInt(object.limit.toString()) : BigInt(0);
        message.hasMore = object.hasMore ?? false;
        return message;
    }
};
function createBaseQueryMerklePathRequest() {
    return {
        commitmentHex: ""
    };
}
/**
 * QueryMerklePathRequest
 * @name QueryMerklePathRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryMerklePathRequest
 */
export const QueryMerklePathRequest = {
    typeUrl: "/clairveil.privacy.v1.QueryMerklePathRequest",
    encode(message, writer = BinaryWriter.create()) {
        if (message.commitmentHex !== "") {
            writer.uint32(10).string(message.commitmentHex);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryMerklePathRequest();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.commitmentHex = reader.string();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryMerklePathRequest();
        message.commitmentHex = object.commitmentHex ?? "";
        return message;
    }
};
function createBaseQueryMerklePathResponse() {
    return {
        path: [],
        pathHelper: [],
        root: ""
    };
}
/**
 * QueryMerklePathResponse
 * @name QueryMerklePathResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryMerklePathResponse
 */
export const QueryMerklePathResponse = {
    typeUrl: "/clairveil.privacy.v1.QueryMerklePathResponse",
    encode(message, writer = BinaryWriter.create()) {
        for (const v of message.path) {
            writer.uint32(10).string(v);
        }
        writer.uint32(18).fork();
        for (const v of message.pathHelper) {
            writer.uint32(v);
        }
        writer.ldelim();
        if (message.root !== "") {
            writer.uint32(26).string(message.root);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryMerklePathResponse();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.path.push(reader.string());
                    break;
                case 2:
                    if ((tag & 7) === 2) {
                        const end2 = reader.uint32() + reader.pos;
                        while (reader.pos < end2) {
                            message.pathHelper.push(reader.uint32());
                        }
                    }
                    else {
                        message.pathHelper.push(reader.uint32());
                    }
                    break;
                case 3:
                    message.root = reader.string();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryMerklePathResponse();
        message.path = object.path?.map(e => e) || [];
        message.pathHelper = object.pathHelper?.map(e => e) || [];
        message.root = object.root ?? "";
        return message;
    }
};
function createBaseQueryAuditConfigRequest() {
    return {};
}
/**
 * @name QueryAuditConfigRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAuditConfigRequest
 */
export const QueryAuditConfigRequest = {
    typeUrl: "/clairveil.privacy.v1.QueryAuditConfigRequest",
    encode(_, writer = BinaryWriter.create()) {
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryAuditConfigRequest();
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
        const message = createBaseQueryAuditConfigRequest();
        return message;
    }
};
function createBaseQueryAuditConfigResponse() {
    return {
        auditMasterPubkeyHex: ""
    };
}
/**
 * @name QueryAuditConfigResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAuditConfigResponse
 */
export const QueryAuditConfigResponse = {
    typeUrl: "/clairveil.privacy.v1.QueryAuditConfigResponse",
    encode(message, writer = BinaryWriter.create()) {
        if (message.auditMasterPubkeyHex !== "") {
            writer.uint32(10).string(message.auditMasterPubkeyHex);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryAuditConfigResponse();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.auditMasterPubkeyHex = reader.string();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryAuditConfigResponse();
        message.auditMasterPubkeyHex = object.auditMasterPubkeyHex ?? "";
        return message;
    }
};
function createBaseQueryDisclosureConfigRequest() {
    return {};
}
/**
 * @name QueryDisclosureConfigRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryDisclosureConfigRequest
 */
export const QueryDisclosureConfigRequest = {
    typeUrl: "/clairveil.privacy.v1.QueryDisclosureConfigRequest",
    encode(_, writer = BinaryWriter.create()) {
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryDisclosureConfigRequest();
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
        const message = createBaseQueryDisclosureConfigRequest();
        return message;
    }
};
function createBaseQueryDisclosureConfigResponse() {
    return {
        payloadVersion: "",
        auditDisclosureRequired: false,
        supportedUserPolicies: [],
        supportedUserModes: []
    };
}
/**
 * @name QueryDisclosureConfigResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryDisclosureConfigResponse
 */
export const QueryDisclosureConfigResponse = {
    typeUrl: "/clairveil.privacy.v1.QueryDisclosureConfigResponse",
    encode(message, writer = BinaryWriter.create()) {
        if (message.payloadVersion !== "") {
            writer.uint32(10).string(message.payloadVersion);
        }
        if (message.auditDisclosureRequired === true) {
            writer.uint32(16).bool(message.auditDisclosureRequired);
        }
        for (const v of message.supportedUserPolicies) {
            writer.uint32(26).string(v);
        }
        for (const v of message.supportedUserModes) {
            writer.uint32(34).string(v);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryDisclosureConfigResponse();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.payloadVersion = reader.string();
                    break;
                case 2:
                    message.auditDisclosureRequired = reader.bool();
                    break;
                case 3:
                    message.supportedUserPolicies.push(reader.string());
                    break;
                case 4:
                    message.supportedUserModes.push(reader.string());
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryDisclosureConfigResponse();
        message.payloadVersion = object.payloadVersion ?? "";
        message.auditDisclosureRequired = object.auditDisclosureRequired ?? false;
        message.supportedUserPolicies = object.supportedUserPolicies?.map(e => e) || [];
        message.supportedUserModes = object.supportedUserModes?.map(e => e) || [];
        return message;
    }
};
function createBaseQueryCircuitConfigRequest() {
    return {};
}
/**
 * @name QueryCircuitConfigRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCircuitConfigRequest
 */
export const QueryCircuitConfigRequest = {
    typeUrl: "/clairveil.privacy.v1.QueryCircuitConfigRequest",
    encode(_, writer = BinaryWriter.create()) {
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryCircuitConfigRequest();
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
        const message = createBaseQueryCircuitConfigRequest();
        return message;
    }
};
function createBaseQueryCircuitArtifact() {
    return {
        circuitId: "",
        artifactType: "",
        filename: "",
        checksumEnv: "",
        sha256: ""
    };
}
/**
 * @name QueryCircuitArtifact
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCircuitArtifact
 */
export const QueryCircuitArtifact = {
    typeUrl: "/clairveil.privacy.v1.QueryCircuitArtifact",
    encode(message, writer = BinaryWriter.create()) {
        if (message.circuitId !== "") {
            writer.uint32(10).string(message.circuitId);
        }
        if (message.artifactType !== "") {
            writer.uint32(18).string(message.artifactType);
        }
        if (message.filename !== "") {
            writer.uint32(26).string(message.filename);
        }
        if (message.checksumEnv !== "") {
            writer.uint32(34).string(message.checksumEnv);
        }
        if (message.sha256 !== "") {
            writer.uint32(42).string(message.sha256);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryCircuitArtifact();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.circuitId = reader.string();
                    break;
                case 2:
                    message.artifactType = reader.string();
                    break;
                case 3:
                    message.filename = reader.string();
                    break;
                case 4:
                    message.checksumEnv = reader.string();
                    break;
                case 5:
                    message.sha256 = reader.string();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryCircuitArtifact();
        message.circuitId = object.circuitId ?? "";
        message.artifactType = object.artifactType ?? "";
        message.filename = object.filename ?? "";
        message.checksumEnv = object.checksumEnv ?? "";
        message.sha256 = object.sha256 ?? "";
        return message;
    }
};
function createBaseQueryCircuitConfigResponse() {
    return {
        schemaVersion: "",
        activeSetId: "",
        curve: "",
        manifestFile: "",
        manifestAvailable: false,
        checksumSource: "",
        generatedAt: "",
        artifacts: []
    };
}
/**
 * @name QueryCircuitConfigResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCircuitConfigResponse
 */
export const QueryCircuitConfigResponse = {
    typeUrl: "/clairveil.privacy.v1.QueryCircuitConfigResponse",
    encode(message, writer = BinaryWriter.create()) {
        if (message.schemaVersion !== "") {
            writer.uint32(10).string(message.schemaVersion);
        }
        if (message.activeSetId !== "") {
            writer.uint32(18).string(message.activeSetId);
        }
        if (message.curve !== "") {
            writer.uint32(26).string(message.curve);
        }
        if (message.manifestFile !== "") {
            writer.uint32(34).string(message.manifestFile);
        }
        if (message.manifestAvailable === true) {
            writer.uint32(40).bool(message.manifestAvailable);
        }
        if (message.checksumSource !== "") {
            writer.uint32(50).string(message.checksumSource);
        }
        if (message.generatedAt !== "") {
            writer.uint32(58).string(message.generatedAt);
        }
        for (const v of message.artifacts) {
            QueryCircuitArtifact.encode(v, writer.uint32(66).fork()).ldelim();
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryCircuitConfigResponse();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.schemaVersion = reader.string();
                    break;
                case 2:
                    message.activeSetId = reader.string();
                    break;
                case 3:
                    message.curve = reader.string();
                    break;
                case 4:
                    message.manifestFile = reader.string();
                    break;
                case 5:
                    message.manifestAvailable = reader.bool();
                    break;
                case 6:
                    message.checksumSource = reader.string();
                    break;
                case 7:
                    message.generatedAt = reader.string();
                    break;
                case 8:
                    message.artifacts.push(QueryCircuitArtifact.decode(reader, reader.uint32()));
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryCircuitConfigResponse();
        message.schemaVersion = object.schemaVersion ?? "";
        message.activeSetId = object.activeSetId ?? "";
        message.curve = object.curve ?? "";
        message.manifestFile = object.manifestFile ?? "";
        message.manifestAvailable = object.manifestAvailable ?? false;
        message.checksumSource = object.checksumSource ?? "";
        message.generatedAt = object.generatedAt ?? "";
        message.artifacts = object.artifacts?.map(e => QueryCircuitArtifact.fromPartial(e)) || [];
        return message;
    }
};
function createBaseQueryReserveRequest() {
    return {
        denom: ""
    };
}
/**
 * @name QueryReserveRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryReserveRequest
 */
export const QueryReserveRequest = {
    typeUrl: "/clairveil.privacy.v1.QueryReserveRequest",
    encode(message, writer = BinaryWriter.create()) {
        if (message.denom !== "") {
            writer.uint32(10).string(message.denom);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryReserveRequest();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.denom = reader.string();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryReserveRequest();
        message.denom = object.denom ?? "";
        return message;
    }
};
function createBaseQueryReserveResponse() {
    return {
        denom: "",
        moduleBalance: "",
        totalDeposited: "",
        totalWithdrawn: "",
        expectedModuleBalance: "",
        invariantHolds: false
    };
}
/**
 * @name QueryReserveResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryReserveResponse
 */
export const QueryReserveResponse = {
    typeUrl: "/clairveil.privacy.v1.QueryReserveResponse",
    encode(message, writer = BinaryWriter.create()) {
        if (message.denom !== "") {
            writer.uint32(10).string(message.denom);
        }
        if (message.moduleBalance !== "") {
            writer.uint32(18).string(message.moduleBalance);
        }
        if (message.totalDeposited !== "") {
            writer.uint32(26).string(message.totalDeposited);
        }
        if (message.totalWithdrawn !== "") {
            writer.uint32(34).string(message.totalWithdrawn);
        }
        if (message.expectedModuleBalance !== "") {
            writer.uint32(42).string(message.expectedModuleBalance);
        }
        if (message.invariantHolds === true) {
            writer.uint32(48).bool(message.invariantHolds);
        }
        return writer;
    },
    decode(input, length) {
        const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
        let end = length === undefined ? reader.len : reader.pos + length;
        const message = createBaseQueryReserveResponse();
        while (reader.pos < end) {
            const tag = reader.uint32();
            switch (tag >>> 3) {
                case 1:
                    message.denom = reader.string();
                    break;
                case 2:
                    message.moduleBalance = reader.string();
                    break;
                case 3:
                    message.totalDeposited = reader.string();
                    break;
                case 4:
                    message.totalWithdrawn = reader.string();
                    break;
                case 5:
                    message.expectedModuleBalance = reader.string();
                    break;
                case 6:
                    message.invariantHolds = reader.bool();
                    break;
                default:
                    reader.skipType(tag & 7);
                    break;
            }
        }
        return message;
    },
    fromPartial(object) {
        const message = createBaseQueryReserveResponse();
        message.denom = object.denom ?? "";
        message.moduleBalance = object.moduleBalance ?? "";
        message.totalDeposited = object.totalDeposited ?? "";
        message.totalWithdrawn = object.totalWithdrawn ?? "";
        message.expectedModuleBalance = object.expectedModuleBalance ?? "";
        message.invariantHolds = object.invariantHolds ?? false;
        return message;
    }
};
