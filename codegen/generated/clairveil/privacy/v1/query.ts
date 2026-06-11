import { BinaryReader, BinaryWriter } from "../../../binary.js";
import { DeepPartial } from "../../../helpers.js";
/**
 * QueryCheckNullifierRequest
 * @name QueryCheckNullifierRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCheckNullifierRequest
 */
export interface QueryCheckNullifierRequest {
  /**
   * Hex string
   */
  nullifier: string;
}
/**
 * QueryCheckNullifierResponse
 * @name QueryCheckNullifierResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCheckNullifierResponse
 */
export interface QueryCheckNullifierResponse {
  used: boolean;
}
/**
 * @name QueryTreeStateRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryTreeStateRequest
 */
export interface QueryTreeStateRequest {}
/**
 * @name QueryTreeStateResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryTreeStateResponse
 */
export interface QueryTreeStateResponse {
  /**
   * canonical 32-byte hex
   */
  root: string;
  /**
   * current leaf count
   */
  leafCount: bigint;
  /**
   * merkle depth
   */
  depth: number;
  /**
   * true when at least one commitment exists
   */
  initialized: boolean;
  /**
   * maximum leaves for the active tree
   */
  maxLeaves: bigint;
  /**
   * leaves that can still be appended
   */
  remainingLeaves: bigint;
}
/**
 * @name QueryCommitmentInfoRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCommitmentInfoRequest
 */
export interface QueryCommitmentInfoRequest {
  commitmentHex: string;
}
/**
 * @name QueryCommitmentInfoResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCommitmentInfoResponse
 */
export interface QueryCommitmentInfoResponse {
  found: boolean;
  leafIndex: bigint;
}
/**
 * @name QueryPrivacyEventsRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyEventsRequest
 */
export interface QueryPrivacyEventsRequest {
  afterHeight: bigint;
  page: bigint;
  limit: bigint;
  eventTypes: string[];
}
/**
 * @name QueryPrivacyEventAttribute
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyEventAttribute
 */
export interface QueryPrivacyEventAttribute {
  key: string;
  value: string;
}
/**
 * @name QueryPrivacyEvent
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyEvent
 */
export interface QueryPrivacyEvent {
  sequence: bigint;
  height: bigint;
  txHashHex: string;
  eventType: string;
  attributes: QueryPrivacyEventAttribute[];
}
/**
 * @name QueryPrivacyEventsResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyEventsResponse
 */
export interface QueryPrivacyEventsResponse {
  events: QueryPrivacyEvent[];
  page: bigint;
  limit: bigint;
  hasMore: boolean;
}
/**
 * QueryMerklePathRequest
 * @name QueryMerklePathRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryMerklePathRequest
 */
export interface QueryMerklePathRequest {
  commitmentHex: string;
}
/**
 * QueryMerklePathResponse
 * @name QueryMerklePathResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryMerklePathResponse
 */
export interface QueryMerklePathResponse {
  /**
   * Hex strings
   */
  path: string[];
  /**
   * 0 or 1 (Index bits)
   */
  pathHelper: number[];
  /**
   * Hex string
   */
  root: string;
}
/**
 * @name QueryAuditConfigRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAuditConfigRequest
 */
export interface QueryAuditConfigRequest {}
/**
 * @name QueryAuditConfigResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAuditConfigResponse
 */
export interface QueryAuditConfigResponse {
  auditMasterPubkeyHex: string;
}
/**
 * @name QueryDisclosureConfigRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryDisclosureConfigRequest
 */
export interface QueryDisclosureConfigRequest {}
/**
 * @name QueryDisclosureConfigResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryDisclosureConfigResponse
 */
export interface QueryDisclosureConfigResponse {
  payloadVersion: string;
  auditDisclosureRequired: boolean;
  supportedUserPolicies: string[];
  supportedUserModes: string[];
}
/**
 * @name QueryCircuitConfigRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCircuitConfigRequest
 */
export interface QueryCircuitConfigRequest {}
/**
 * @name QueryCircuitArtifact
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCircuitArtifact
 */
export interface QueryCircuitArtifact {
  circuitId: string;
  artifactType: string;
  filename: string;
  checksumEnv: string;
  sha256: string;
}
/**
 * @name QueryCircuitConfigResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCircuitConfigResponse
 */
export interface QueryCircuitConfigResponse {
  schemaVersion: string;
  activeSetId: string;
  curve: string;
  manifestFile: string;
  manifestAvailable: boolean;
  checksumSource: string;
  generatedAt: string;
  artifacts: QueryCircuitArtifact[];
}
function createBaseQueryCheckNullifierRequest(): QueryCheckNullifierRequest {
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
  encode(message: QueryCheckNullifierRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.nullifier !== "") {
      writer.uint32(10).string(message.nullifier);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryCheckNullifierRequest {
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
  fromPartial(object: DeepPartial<QueryCheckNullifierRequest>): QueryCheckNullifierRequest {
    const message = createBaseQueryCheckNullifierRequest();
    message.nullifier = object.nullifier ?? "";
    return message;
  }
};
function createBaseQueryCheckNullifierResponse(): QueryCheckNullifierResponse {
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
  encode(message: QueryCheckNullifierResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.used === true) {
      writer.uint32(8).bool(message.used);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryCheckNullifierResponse {
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
  fromPartial(object: DeepPartial<QueryCheckNullifierResponse>): QueryCheckNullifierResponse {
    const message = createBaseQueryCheckNullifierResponse();
    message.used = object.used ?? false;
    return message;
  }
};
function createBaseQueryTreeStateRequest(): QueryTreeStateRequest {
  return {};
}
/**
 * @name QueryTreeStateRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryTreeStateRequest
 */
export const QueryTreeStateRequest = {
  typeUrl: "/clairveil.privacy.v1.QueryTreeStateRequest",
  encode(_: QueryTreeStateRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryTreeStateRequest {
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
  fromPartial(_: DeepPartial<QueryTreeStateRequest>): QueryTreeStateRequest {
    const message = createBaseQueryTreeStateRequest();
    return message;
  }
};
function createBaseQueryTreeStateResponse(): QueryTreeStateResponse {
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
  encode(message: QueryTreeStateResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
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
  decode(input: BinaryReader | Uint8Array, length?: number): QueryTreeStateResponse {
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
  fromPartial(object: DeepPartial<QueryTreeStateResponse>): QueryTreeStateResponse {
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
function createBaseQueryCommitmentInfoRequest(): QueryCommitmentInfoRequest {
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
  encode(message: QueryCommitmentInfoRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.commitmentHex !== "") {
      writer.uint32(10).string(message.commitmentHex);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryCommitmentInfoRequest {
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
  fromPartial(object: DeepPartial<QueryCommitmentInfoRequest>): QueryCommitmentInfoRequest {
    const message = createBaseQueryCommitmentInfoRequest();
    message.commitmentHex = object.commitmentHex ?? "";
    return message;
  }
};
function createBaseQueryCommitmentInfoResponse(): QueryCommitmentInfoResponse {
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
  encode(message: QueryCommitmentInfoResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.found === true) {
      writer.uint32(8).bool(message.found);
    }
    if (message.leafIndex !== BigInt(0)) {
      writer.uint32(16).uint64(message.leafIndex);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryCommitmentInfoResponse {
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
  fromPartial(object: DeepPartial<QueryCommitmentInfoResponse>): QueryCommitmentInfoResponse {
    const message = createBaseQueryCommitmentInfoResponse();
    message.found = object.found ?? false;
    message.leafIndex = object.leafIndex !== undefined && object.leafIndex !== null ? BigInt(object.leafIndex.toString()) : BigInt(0);
    return message;
  }
};
function createBaseQueryPrivacyEventsRequest(): QueryPrivacyEventsRequest {
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
  encode(message: QueryPrivacyEventsRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
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
      writer.uint32(34).string(v!);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryPrivacyEventsRequest {
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
  fromPartial(object: DeepPartial<QueryPrivacyEventsRequest>): QueryPrivacyEventsRequest {
    const message = createBaseQueryPrivacyEventsRequest();
    message.afterHeight = object.afterHeight !== undefined && object.afterHeight !== null ? BigInt(object.afterHeight.toString()) : BigInt(0);
    message.page = object.page !== undefined && object.page !== null ? BigInt(object.page.toString()) : BigInt(0);
    message.limit = object.limit !== undefined && object.limit !== null ? BigInt(object.limit.toString()) : BigInt(0);
    message.eventTypes = object.eventTypes?.map(e => e) || [];
    return message;
  }
};
function createBaseQueryPrivacyEventAttribute(): QueryPrivacyEventAttribute {
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
  encode(message: QueryPrivacyEventAttribute, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.key !== "") {
      writer.uint32(10).string(message.key);
    }
    if (message.value !== "") {
      writer.uint32(18).string(message.value);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryPrivacyEventAttribute {
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
  fromPartial(object: DeepPartial<QueryPrivacyEventAttribute>): QueryPrivacyEventAttribute {
    const message = createBaseQueryPrivacyEventAttribute();
    message.key = object.key ?? "";
    message.value = object.value ?? "";
    return message;
  }
};
function createBaseQueryPrivacyEvent(): QueryPrivacyEvent {
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
  encode(message: QueryPrivacyEvent, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
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
      QueryPrivacyEventAttribute.encode(v!, writer.uint32(42).fork()).ldelim();
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryPrivacyEvent {
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
  fromPartial(object: DeepPartial<QueryPrivacyEvent>): QueryPrivacyEvent {
    const message = createBaseQueryPrivacyEvent();
    message.sequence = object.sequence !== undefined && object.sequence !== null ? BigInt(object.sequence.toString()) : BigInt(0);
    message.height = object.height !== undefined && object.height !== null ? BigInt(object.height.toString()) : BigInt(0);
    message.txHashHex = object.txHashHex ?? "";
    message.eventType = object.eventType ?? "";
    message.attributes = object.attributes?.map(e => QueryPrivacyEventAttribute.fromPartial(e)) || [];
    return message;
  }
};
function createBaseQueryPrivacyEventsResponse(): QueryPrivacyEventsResponse {
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
  encode(message: QueryPrivacyEventsResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    for (const v of message.events) {
      QueryPrivacyEvent.encode(v!, writer.uint32(10).fork()).ldelim();
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
  decode(input: BinaryReader | Uint8Array, length?: number): QueryPrivacyEventsResponse {
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
  fromPartial(object: DeepPartial<QueryPrivacyEventsResponse>): QueryPrivacyEventsResponse {
    const message = createBaseQueryPrivacyEventsResponse();
    message.events = object.events?.map(e => QueryPrivacyEvent.fromPartial(e)) || [];
    message.page = object.page !== undefined && object.page !== null ? BigInt(object.page.toString()) : BigInt(0);
    message.limit = object.limit !== undefined && object.limit !== null ? BigInt(object.limit.toString()) : BigInt(0);
    message.hasMore = object.hasMore ?? false;
    return message;
  }
};
function createBaseQueryMerklePathRequest(): QueryMerklePathRequest {
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
  encode(message: QueryMerklePathRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.commitmentHex !== "") {
      writer.uint32(10).string(message.commitmentHex);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryMerklePathRequest {
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
  fromPartial(object: DeepPartial<QueryMerklePathRequest>): QueryMerklePathRequest {
    const message = createBaseQueryMerklePathRequest();
    message.commitmentHex = object.commitmentHex ?? "";
    return message;
  }
};
function createBaseQueryMerklePathResponse(): QueryMerklePathResponse {
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
  encode(message: QueryMerklePathResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    for (const v of message.path) {
      writer.uint32(10).string(v!);
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
  decode(input: BinaryReader | Uint8Array, length?: number): QueryMerklePathResponse {
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
          } else {
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
  fromPartial(object: DeepPartial<QueryMerklePathResponse>): QueryMerklePathResponse {
    const message = createBaseQueryMerklePathResponse();
    message.path = object.path?.map(e => e) || [];
    message.pathHelper = object.pathHelper?.map(e => e) || [];
    message.root = object.root ?? "";
    return message;
  }
};
function createBaseQueryAuditConfigRequest(): QueryAuditConfigRequest {
  return {};
}
/**
 * @name QueryAuditConfigRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAuditConfigRequest
 */
export const QueryAuditConfigRequest = {
  typeUrl: "/clairveil.privacy.v1.QueryAuditConfigRequest",
  encode(_: QueryAuditConfigRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditConfigRequest {
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
  fromPartial(_: DeepPartial<QueryAuditConfigRequest>): QueryAuditConfigRequest {
    const message = createBaseQueryAuditConfigRequest();
    return message;
  }
};
function createBaseQueryAuditConfigResponse(): QueryAuditConfigResponse {
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
  encode(message: QueryAuditConfigResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.auditMasterPubkeyHex !== "") {
      writer.uint32(10).string(message.auditMasterPubkeyHex);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditConfigResponse {
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
  fromPartial(object: DeepPartial<QueryAuditConfigResponse>): QueryAuditConfigResponse {
    const message = createBaseQueryAuditConfigResponse();
    message.auditMasterPubkeyHex = object.auditMasterPubkeyHex ?? "";
    return message;
  }
};
function createBaseQueryDisclosureConfigRequest(): QueryDisclosureConfigRequest {
  return {};
}
/**
 * @name QueryDisclosureConfigRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryDisclosureConfigRequest
 */
export const QueryDisclosureConfigRequest = {
  typeUrl: "/clairveil.privacy.v1.QueryDisclosureConfigRequest",
  encode(_: QueryDisclosureConfigRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryDisclosureConfigRequest {
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
  fromPartial(_: DeepPartial<QueryDisclosureConfigRequest>): QueryDisclosureConfigRequest {
    const message = createBaseQueryDisclosureConfigRequest();
    return message;
  }
};
function createBaseQueryDisclosureConfigResponse(): QueryDisclosureConfigResponse {
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
  encode(message: QueryDisclosureConfigResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.payloadVersion !== "") {
      writer.uint32(10).string(message.payloadVersion);
    }
    if (message.auditDisclosureRequired === true) {
      writer.uint32(16).bool(message.auditDisclosureRequired);
    }
    for (const v of message.supportedUserPolicies) {
      writer.uint32(26).string(v!);
    }
    for (const v of message.supportedUserModes) {
      writer.uint32(34).string(v!);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryDisclosureConfigResponse {
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
  fromPartial(object: DeepPartial<QueryDisclosureConfigResponse>): QueryDisclosureConfigResponse {
    const message = createBaseQueryDisclosureConfigResponse();
    message.payloadVersion = object.payloadVersion ?? "";
    message.auditDisclosureRequired = object.auditDisclosureRequired ?? false;
    message.supportedUserPolicies = object.supportedUserPolicies?.map(e => e) || [];
    message.supportedUserModes = object.supportedUserModes?.map(e => e) || [];
    return message;
  }
};
function createBaseQueryCircuitConfigRequest(): QueryCircuitConfigRequest {
  return {};
}
/**
 * @name QueryCircuitConfigRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCircuitConfigRequest
 */
export const QueryCircuitConfigRequest = {
  typeUrl: "/clairveil.privacy.v1.QueryCircuitConfigRequest",
  encode(_: QueryCircuitConfigRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryCircuitConfigRequest {
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
  fromPartial(_: DeepPartial<QueryCircuitConfigRequest>): QueryCircuitConfigRequest {
    const message = createBaseQueryCircuitConfigRequest();
    return message;
  }
};
function createBaseQueryCircuitArtifact(): QueryCircuitArtifact {
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
  encode(message: QueryCircuitArtifact, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
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
  decode(input: BinaryReader | Uint8Array, length?: number): QueryCircuitArtifact {
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
  fromPartial(object: DeepPartial<QueryCircuitArtifact>): QueryCircuitArtifact {
    const message = createBaseQueryCircuitArtifact();
    message.circuitId = object.circuitId ?? "";
    message.artifactType = object.artifactType ?? "";
    message.filename = object.filename ?? "";
    message.checksumEnv = object.checksumEnv ?? "";
    message.sha256 = object.sha256 ?? "";
    return message;
  }
};
function createBaseQueryCircuitConfigResponse(): QueryCircuitConfigResponse {
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
  encode(message: QueryCircuitConfigResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
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
      QueryCircuitArtifact.encode(v!, writer.uint32(66).fork()).ldelim();
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryCircuitConfigResponse {
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
  fromPartial(object: DeepPartial<QueryCircuitConfigResponse>): QueryCircuitConfigResponse {
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