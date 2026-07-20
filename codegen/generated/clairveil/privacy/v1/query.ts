import { PrivacyScanCursorV1, CircuitSetIdentity, AssetRegistryEntryV1, PrivacyScanSummaryV2, PrivacyScanOutputV2 } from "./genesis.js";
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
 * @name QueryCheckNullifiersRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCheckNullifiersRequest
 */
export interface QueryCheckNullifiersRequest {
  nullifiers: string[];
}
/**
 * @name QueryNullifierStatus
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryNullifierStatus
 */
export interface QueryNullifierStatus {
  nullifier: string;
  used: boolean;
}
/**
 * @name QueryCheckNullifiersResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCheckNullifiersResponse
 */
export interface QueryCheckNullifiersResponse {
  statuses: QueryNullifierStatus[];
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
 * @name QueryScanEventsRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryScanEventsRequest
 */
export interface QueryScanEventsRequest {
  afterHeight: bigint;
  afterSequence: bigint;
  limit: bigint;
  eventTypes: string[];
}
/**
 * @name QueryScanOutput
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryScanOutput
 */
export interface QueryScanOutput {
  outputIndex: number;
  commitmentHex: string;
  encryptedNoteHex: string;
  cipherTextHex: string;
  viewTagHex: string;
  leafIndexFound: boolean;
  leafIndex: bigint;
}
/**
 * @name QueryScanEvent
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryScanEvent
 */
export interface QueryScanEvent {
  sequence: bigint;
  height: bigint;
  txHashHex: string;
  eventType: string;
  outputs: QueryScanOutput[];
  nullifierHexes: string[];
}
/**
 * @name QueryScanEventsResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryScanEventsResponse
 */
export interface QueryScanEventsResponse {
  events: QueryScanEvent[];
  nextHeight: bigint;
  nextSequence: bigint;
  limit: bigint;
  hasMore: boolean;
  scanFormatVersion: number;
  viewTagVersion: number;
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
  auditKeyId: string;
  auditKeyEpoch: bigint;
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
  circuitSetIdentity?: CircuitSetIdentity;
}
/**
 * @name QueryReserveRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryReserveRequest
 */
export interface QueryReserveRequest {
  denom: string;
}
/**
 * @name QueryReserveResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryReserveResponse
 */
export interface QueryReserveResponse {
  denom: string;
  moduleBalance: string;
  totalDeposited: string;
  totalWithdrawn: string;
  expectedModuleBalance: string;
  invariantHolds: boolean;
}
/**
 * @name QueryAssetByDenomRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAssetByDenomRequest
 */
export interface QueryAssetByDenomRequest {
  canonicalDenom: string;
}
/**
 * @name QueryAssetByDenomResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAssetByDenomResponse
 */
export interface QueryAssetByDenomResponse {
  asset?: AssetRegistryEntryV1;
  mappingVersion: string;
}
/**
 * @name QueryAssetByIDRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAssetByIDRequest
 */
export interface QueryAssetByIDRequest {
  assetIdHex: string;
}
/**
 * @name QueryAssetByIDResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAssetByIDResponse
 */
export interface QueryAssetByIDResponse {
  asset?: AssetRegistryEntryV1;
  mappingVersion: string;
}
/**
 * @name QueryPrivacyScanRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyScanRequest
 */
export interface QueryPrivacyScanRequest {
  after?: PrivacyScanCursorV1;
  outputLimit: number;
  eventLimit: number;
  maxEncodedBytes: bigint;
  eventTypes: string[];
}
/**
 * @name QueryPrivacyScanResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyScanResponse
 */
export interface QueryPrivacyScanResponse {
  /**
   * Summaries are the event boundary and include zero-output events such as
   * withdrawals. A summary may be repeated on the next page when its outputs
   * span pages. Consumers MUST collect output_count outputs and observe
   * has_more=false for that event before marking a multi-output item complete.
   */
  summaries: PrivacyScanSummaryV2[];
  outputs: PrivacyScanOutputV2[];
  nextCursor?: PrivacyScanCursorV1;
  hasMore: boolean;
  outputLimit: number;
  eventLimit: number;
  maxEncodedBytes: bigint;
  scannedEventCount: number;
  encodedBytes: bigint;
  scanSchemaVersion: string;
}
/**
 * @name QueryCommitmentPathsAtRootRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCommitmentPathsAtRootRequest
 */
export interface QueryCommitmentPathsAtRootRequest {
  commitmentHexes: string[];
  rootHex: string;
  snapshotHeight: bigint;
}
/**
 * @name QueryCommitmentPathAtRoot
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCommitmentPathAtRoot
 */
export interface QueryCommitmentPathAtRoot {
  commitmentHex: string;
  leafIndex: bigint;
  path: string[];
  pathHelper: number[];
}
/**
 * @name QueryCommitmentPathsAtRootResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCommitmentPathsAtRootResponse
 */
export interface QueryCommitmentPathsAtRootResponse {
  rootHex: string;
  snapshotHeight: bigint;
  leafCount: bigint;
  paths: QueryCommitmentPathAtRoot[];
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
function createBaseQueryCheckNullifiersRequest(): QueryCheckNullifiersRequest {
  return {
    nullifiers: []
  };
}
/**
 * @name QueryCheckNullifiersRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCheckNullifiersRequest
 */
export const QueryCheckNullifiersRequest = {
  typeUrl: "/clairveil.privacy.v1.QueryCheckNullifiersRequest",
  encode(message: QueryCheckNullifiersRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    for (const v of message.nullifiers) {
      writer.uint32(10).string(v!);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryCheckNullifiersRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryCheckNullifiersRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.nullifiers.push(reader.string());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryCheckNullifiersRequest>): QueryCheckNullifiersRequest {
    const message = createBaseQueryCheckNullifiersRequest();
    message.nullifiers = object.nullifiers?.map(e => e) || [];
    return message;
  }
};
function createBaseQueryNullifierStatus(): QueryNullifierStatus {
  return {
    nullifier: "",
    used: false
  };
}
/**
 * @name QueryNullifierStatus
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryNullifierStatus
 */
export const QueryNullifierStatus = {
  typeUrl: "/clairveil.privacy.v1.QueryNullifierStatus",
  encode(message: QueryNullifierStatus, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.nullifier !== "") {
      writer.uint32(10).string(message.nullifier);
    }
    if (message.used === true) {
      writer.uint32(16).bool(message.used);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryNullifierStatus {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryNullifierStatus();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.nullifier = reader.string();
          break;
        case 2:
          message.used = reader.bool();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryNullifierStatus>): QueryNullifierStatus {
    const message = createBaseQueryNullifierStatus();
    message.nullifier = object.nullifier ?? "";
    message.used = object.used ?? false;
    return message;
  }
};
function createBaseQueryCheckNullifiersResponse(): QueryCheckNullifiersResponse {
  return {
    statuses: []
  };
}
/**
 * @name QueryCheckNullifiersResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCheckNullifiersResponse
 */
export const QueryCheckNullifiersResponse = {
  typeUrl: "/clairveil.privacy.v1.QueryCheckNullifiersResponse",
  encode(message: QueryCheckNullifiersResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    for (const v of message.statuses) {
      QueryNullifierStatus.encode(v!, writer.uint32(10).fork()).ldelim();
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryCheckNullifiersResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryCheckNullifiersResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.statuses.push(QueryNullifierStatus.decode(reader, reader.uint32()));
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryCheckNullifiersResponse>): QueryCheckNullifiersResponse {
    const message = createBaseQueryCheckNullifiersResponse();
    message.statuses = object.statuses?.map(e => QueryNullifierStatus.fromPartial(e)) || [];
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
function createBaseQueryScanEventsRequest(): QueryScanEventsRequest {
  return {
    afterHeight: BigInt(0),
    afterSequence: BigInt(0),
    limit: BigInt(0),
    eventTypes: []
  };
}
/**
 * @name QueryScanEventsRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryScanEventsRequest
 */
export const QueryScanEventsRequest = {
  typeUrl: "/clairveil.privacy.v1.QueryScanEventsRequest",
  encode(message: QueryScanEventsRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.afterHeight !== BigInt(0)) {
      writer.uint32(8).int64(message.afterHeight);
    }
    if (message.afterSequence !== BigInt(0)) {
      writer.uint32(16).uint64(message.afterSequence);
    }
    if (message.limit !== BigInt(0)) {
      writer.uint32(24).uint64(message.limit);
    }
    for (const v of message.eventTypes) {
      writer.uint32(34).string(v!);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryScanEventsRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryScanEventsRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.afterHeight = reader.int64();
          break;
        case 2:
          message.afterSequence = reader.uint64();
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
  fromPartial(object: DeepPartial<QueryScanEventsRequest>): QueryScanEventsRequest {
    const message = createBaseQueryScanEventsRequest();
    message.afterHeight = object.afterHeight !== undefined && object.afterHeight !== null ? BigInt(object.afterHeight.toString()) : BigInt(0);
    message.afterSequence = object.afterSequence !== undefined && object.afterSequence !== null ? BigInt(object.afterSequence.toString()) : BigInt(0);
    message.limit = object.limit !== undefined && object.limit !== null ? BigInt(object.limit.toString()) : BigInt(0);
    message.eventTypes = object.eventTypes?.map(e => e) || [];
    return message;
  }
};
function createBaseQueryScanOutput(): QueryScanOutput {
  return {
    outputIndex: 0,
    commitmentHex: "",
    encryptedNoteHex: "",
    cipherTextHex: "",
    viewTagHex: "",
    leafIndexFound: false,
    leafIndex: BigInt(0)
  };
}
/**
 * @name QueryScanOutput
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryScanOutput
 */
export const QueryScanOutput = {
  typeUrl: "/clairveil.privacy.v1.QueryScanOutput",
  encode(message: QueryScanOutput, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.outputIndex !== 0) {
      writer.uint32(8).uint32(message.outputIndex);
    }
    if (message.commitmentHex !== "") {
      writer.uint32(18).string(message.commitmentHex);
    }
    if (message.encryptedNoteHex !== "") {
      writer.uint32(26).string(message.encryptedNoteHex);
    }
    if (message.cipherTextHex !== "") {
      writer.uint32(34).string(message.cipherTextHex);
    }
    if (message.viewTagHex !== "") {
      writer.uint32(42).string(message.viewTagHex);
    }
    if (message.leafIndexFound === true) {
      writer.uint32(48).bool(message.leafIndexFound);
    }
    if (message.leafIndex !== BigInt(0)) {
      writer.uint32(56).uint64(message.leafIndex);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryScanOutput {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryScanOutput();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.outputIndex = reader.uint32();
          break;
        case 2:
          message.commitmentHex = reader.string();
          break;
        case 3:
          message.encryptedNoteHex = reader.string();
          break;
        case 4:
          message.cipherTextHex = reader.string();
          break;
        case 5:
          message.viewTagHex = reader.string();
          break;
        case 6:
          message.leafIndexFound = reader.bool();
          break;
        case 7:
          message.leafIndex = reader.uint64();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryScanOutput>): QueryScanOutput {
    const message = createBaseQueryScanOutput();
    message.outputIndex = object.outputIndex ?? 0;
    message.commitmentHex = object.commitmentHex ?? "";
    message.encryptedNoteHex = object.encryptedNoteHex ?? "";
    message.cipherTextHex = object.cipherTextHex ?? "";
    message.viewTagHex = object.viewTagHex ?? "";
    message.leafIndexFound = object.leafIndexFound ?? false;
    message.leafIndex = object.leafIndex !== undefined && object.leafIndex !== null ? BigInt(object.leafIndex.toString()) : BigInt(0);
    return message;
  }
};
function createBaseQueryScanEvent(): QueryScanEvent {
  return {
    sequence: BigInt(0),
    height: BigInt(0),
    txHashHex: "",
    eventType: "",
    outputs: [],
    nullifierHexes: []
  };
}
/**
 * @name QueryScanEvent
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryScanEvent
 */
export const QueryScanEvent = {
  typeUrl: "/clairveil.privacy.v1.QueryScanEvent",
  encode(message: QueryScanEvent, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
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
    for (const v of message.outputs) {
      QueryScanOutput.encode(v!, writer.uint32(42).fork()).ldelim();
    }
    for (const v of message.nullifierHexes) {
      writer.uint32(50).string(v!);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryScanEvent {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryScanEvent();
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
          message.outputs.push(QueryScanOutput.decode(reader, reader.uint32()));
          break;
        case 6:
          message.nullifierHexes.push(reader.string());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryScanEvent>): QueryScanEvent {
    const message = createBaseQueryScanEvent();
    message.sequence = object.sequence !== undefined && object.sequence !== null ? BigInt(object.sequence.toString()) : BigInt(0);
    message.height = object.height !== undefined && object.height !== null ? BigInt(object.height.toString()) : BigInt(0);
    message.txHashHex = object.txHashHex ?? "";
    message.eventType = object.eventType ?? "";
    message.outputs = object.outputs?.map(e => QueryScanOutput.fromPartial(e)) || [];
    message.nullifierHexes = object.nullifierHexes?.map(e => e) || [];
    return message;
  }
};
function createBaseQueryScanEventsResponse(): QueryScanEventsResponse {
  return {
    events: [],
    nextHeight: BigInt(0),
    nextSequence: BigInt(0),
    limit: BigInt(0),
    hasMore: false,
    scanFormatVersion: 0,
    viewTagVersion: 0
  };
}
/**
 * @name QueryScanEventsResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryScanEventsResponse
 */
export const QueryScanEventsResponse = {
  typeUrl: "/clairveil.privacy.v1.QueryScanEventsResponse",
  encode(message: QueryScanEventsResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    for (const v of message.events) {
      QueryScanEvent.encode(v!, writer.uint32(10).fork()).ldelim();
    }
    if (message.nextHeight !== BigInt(0)) {
      writer.uint32(16).int64(message.nextHeight);
    }
    if (message.nextSequence !== BigInt(0)) {
      writer.uint32(24).uint64(message.nextSequence);
    }
    if (message.limit !== BigInt(0)) {
      writer.uint32(32).uint64(message.limit);
    }
    if (message.hasMore === true) {
      writer.uint32(40).bool(message.hasMore);
    }
    if (message.scanFormatVersion !== 0) {
      writer.uint32(48).uint32(message.scanFormatVersion);
    }
    if (message.viewTagVersion !== 0) {
      writer.uint32(56).uint32(message.viewTagVersion);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryScanEventsResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryScanEventsResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.events.push(QueryScanEvent.decode(reader, reader.uint32()));
          break;
        case 2:
          message.nextHeight = reader.int64();
          break;
        case 3:
          message.nextSequence = reader.uint64();
          break;
        case 4:
          message.limit = reader.uint64();
          break;
        case 5:
          message.hasMore = reader.bool();
          break;
        case 6:
          message.scanFormatVersion = reader.uint32();
          break;
        case 7:
          message.viewTagVersion = reader.uint32();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryScanEventsResponse>): QueryScanEventsResponse {
    const message = createBaseQueryScanEventsResponse();
    message.events = object.events?.map(e => QueryScanEvent.fromPartial(e)) || [];
    message.nextHeight = object.nextHeight !== undefined && object.nextHeight !== null ? BigInt(object.nextHeight.toString()) : BigInt(0);
    message.nextSequence = object.nextSequence !== undefined && object.nextSequence !== null ? BigInt(object.nextSequence.toString()) : BigInt(0);
    message.limit = object.limit !== undefined && object.limit !== null ? BigInt(object.limit.toString()) : BigInt(0);
    message.hasMore = object.hasMore ?? false;
    message.scanFormatVersion = object.scanFormatVersion ?? 0;
    message.viewTagVersion = object.viewTagVersion ?? 0;
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
    auditMasterPubkeyHex: "",
    auditKeyId: "",
    auditKeyEpoch: BigInt(0)
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
    if (message.auditKeyId !== "") {
      writer.uint32(18).string(message.auditKeyId);
    }
    if (message.auditKeyEpoch !== BigInt(0)) {
      writer.uint32(24).uint64(message.auditKeyEpoch);
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
        case 2:
          message.auditKeyId = reader.string();
          break;
        case 3:
          message.auditKeyEpoch = reader.uint64();
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
    message.auditKeyId = object.auditKeyId ?? "";
    message.auditKeyEpoch = object.auditKeyEpoch !== undefined && object.auditKeyEpoch !== null ? BigInt(object.auditKeyEpoch.toString()) : BigInt(0);
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
    artifacts: [],
    circuitSetIdentity: undefined
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
    if (message.circuitSetIdentity !== undefined) {
      CircuitSetIdentity.encode(message.circuitSetIdentity, writer.uint32(74).fork()).ldelim();
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
        case 9:
          message.circuitSetIdentity = CircuitSetIdentity.decode(reader, reader.uint32());
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
    message.circuitSetIdentity = object.circuitSetIdentity !== undefined && object.circuitSetIdentity !== null ? CircuitSetIdentity.fromPartial(object.circuitSetIdentity) : undefined;
    return message;
  }
};
function createBaseQueryReserveRequest(): QueryReserveRequest {
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
  encode(message: QueryReserveRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.denom !== "") {
      writer.uint32(10).string(message.denom);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryReserveRequest {
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
  fromPartial(object: DeepPartial<QueryReserveRequest>): QueryReserveRequest {
    const message = createBaseQueryReserveRequest();
    message.denom = object.denom ?? "";
    return message;
  }
};
function createBaseQueryReserveResponse(): QueryReserveResponse {
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
  encode(message: QueryReserveResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
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
  decode(input: BinaryReader | Uint8Array, length?: number): QueryReserveResponse {
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
  fromPartial(object: DeepPartial<QueryReserveResponse>): QueryReserveResponse {
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
function createBaseQueryAssetByDenomRequest(): QueryAssetByDenomRequest {
  return {
    canonicalDenom: ""
  };
}
/**
 * @name QueryAssetByDenomRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAssetByDenomRequest
 */
export const QueryAssetByDenomRequest = {
  typeUrl: "/clairveil.privacy.v1.QueryAssetByDenomRequest",
  encode(message: QueryAssetByDenomRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.canonicalDenom !== "") {
      writer.uint32(10).string(message.canonicalDenom);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryAssetByDenomRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryAssetByDenomRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.canonicalDenom = reader.string();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryAssetByDenomRequest>): QueryAssetByDenomRequest {
    const message = createBaseQueryAssetByDenomRequest();
    message.canonicalDenom = object.canonicalDenom ?? "";
    return message;
  }
};
function createBaseQueryAssetByDenomResponse(): QueryAssetByDenomResponse {
  return {
    asset: undefined,
    mappingVersion: ""
  };
}
/**
 * @name QueryAssetByDenomResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAssetByDenomResponse
 */
export const QueryAssetByDenomResponse = {
  typeUrl: "/clairveil.privacy.v1.QueryAssetByDenomResponse",
  encode(message: QueryAssetByDenomResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.asset !== undefined) {
      AssetRegistryEntryV1.encode(message.asset, writer.uint32(10).fork()).ldelim();
    }
    if (message.mappingVersion !== "") {
      writer.uint32(18).string(message.mappingVersion);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryAssetByDenomResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryAssetByDenomResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.asset = AssetRegistryEntryV1.decode(reader, reader.uint32());
          break;
        case 2:
          message.mappingVersion = reader.string();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryAssetByDenomResponse>): QueryAssetByDenomResponse {
    const message = createBaseQueryAssetByDenomResponse();
    message.asset = object.asset !== undefined && object.asset !== null ? AssetRegistryEntryV1.fromPartial(object.asset) : undefined;
    message.mappingVersion = object.mappingVersion ?? "";
    return message;
  }
};
function createBaseQueryAssetByIDRequest(): QueryAssetByIDRequest {
  return {
    assetIdHex: ""
  };
}
/**
 * @name QueryAssetByIDRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAssetByIDRequest
 */
export const QueryAssetByIDRequest = {
  typeUrl: "/clairveil.privacy.v1.QueryAssetByIDRequest",
  encode(message: QueryAssetByIDRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.assetIdHex !== "") {
      writer.uint32(10).string(message.assetIdHex);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryAssetByIDRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryAssetByIDRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.assetIdHex = reader.string();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryAssetByIDRequest>): QueryAssetByIDRequest {
    const message = createBaseQueryAssetByIDRequest();
    message.assetIdHex = object.assetIdHex ?? "";
    return message;
  }
};
function createBaseQueryAssetByIDResponse(): QueryAssetByIDResponse {
  return {
    asset: undefined,
    mappingVersion: ""
  };
}
/**
 * @name QueryAssetByIDResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAssetByIDResponse
 */
export const QueryAssetByIDResponse = {
  typeUrl: "/clairveil.privacy.v1.QueryAssetByIDResponse",
  encode(message: QueryAssetByIDResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.asset !== undefined) {
      AssetRegistryEntryV1.encode(message.asset, writer.uint32(10).fork()).ldelim();
    }
    if (message.mappingVersion !== "") {
      writer.uint32(18).string(message.mappingVersion);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryAssetByIDResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryAssetByIDResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.asset = AssetRegistryEntryV1.decode(reader, reader.uint32());
          break;
        case 2:
          message.mappingVersion = reader.string();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryAssetByIDResponse>): QueryAssetByIDResponse {
    const message = createBaseQueryAssetByIDResponse();
    message.asset = object.asset !== undefined && object.asset !== null ? AssetRegistryEntryV1.fromPartial(object.asset) : undefined;
    message.mappingVersion = object.mappingVersion ?? "";
    return message;
  }
};
function createBaseQueryPrivacyScanRequest(): QueryPrivacyScanRequest {
  return {
    after: undefined,
    outputLimit: 0,
    eventLimit: 0,
    maxEncodedBytes: BigInt(0),
    eventTypes: []
  };
}
/**
 * @name QueryPrivacyScanRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyScanRequest
 */
export const QueryPrivacyScanRequest = {
  typeUrl: "/clairveil.privacy.v1.QueryPrivacyScanRequest",
  encode(message: QueryPrivacyScanRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.after !== undefined) {
      PrivacyScanCursorV1.encode(message.after, writer.uint32(10).fork()).ldelim();
    }
    if (message.outputLimit !== 0) {
      writer.uint32(16).uint32(message.outputLimit);
    }
    if (message.eventLimit !== 0) {
      writer.uint32(24).uint32(message.eventLimit);
    }
    if (message.maxEncodedBytes !== BigInt(0)) {
      writer.uint32(32).uint64(message.maxEncodedBytes);
    }
    for (const v of message.eventTypes) {
      writer.uint32(42).string(v!);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryPrivacyScanRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryPrivacyScanRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.after = PrivacyScanCursorV1.decode(reader, reader.uint32());
          break;
        case 2:
          message.outputLimit = reader.uint32();
          break;
        case 3:
          message.eventLimit = reader.uint32();
          break;
        case 4:
          message.maxEncodedBytes = reader.uint64();
          break;
        case 5:
          message.eventTypes.push(reader.string());
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryPrivacyScanRequest>): QueryPrivacyScanRequest {
    const message = createBaseQueryPrivacyScanRequest();
    message.after = object.after !== undefined && object.after !== null ? PrivacyScanCursorV1.fromPartial(object.after) : undefined;
    message.outputLimit = object.outputLimit ?? 0;
    message.eventLimit = object.eventLimit ?? 0;
    message.maxEncodedBytes = object.maxEncodedBytes !== undefined && object.maxEncodedBytes !== null ? BigInt(object.maxEncodedBytes.toString()) : BigInt(0);
    message.eventTypes = object.eventTypes?.map(e => e) || [];
    return message;
  }
};
function createBaseQueryPrivacyScanResponse(): QueryPrivacyScanResponse {
  return {
    summaries: [],
    outputs: [],
    nextCursor: undefined,
    hasMore: false,
    outputLimit: 0,
    eventLimit: 0,
    maxEncodedBytes: BigInt(0),
    scannedEventCount: 0,
    encodedBytes: BigInt(0),
    scanSchemaVersion: ""
  };
}
/**
 * @name QueryPrivacyScanResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyScanResponse
 */
export const QueryPrivacyScanResponse = {
  typeUrl: "/clairveil.privacy.v1.QueryPrivacyScanResponse",
  encode(message: QueryPrivacyScanResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    for (const v of message.summaries) {
      PrivacyScanSummaryV2.encode(v!, writer.uint32(10).fork()).ldelim();
    }
    for (const v of message.outputs) {
      PrivacyScanOutputV2.encode(v!, writer.uint32(18).fork()).ldelim();
    }
    if (message.nextCursor !== undefined) {
      PrivacyScanCursorV1.encode(message.nextCursor, writer.uint32(26).fork()).ldelim();
    }
    if (message.hasMore === true) {
      writer.uint32(32).bool(message.hasMore);
    }
    if (message.outputLimit !== 0) {
      writer.uint32(40).uint32(message.outputLimit);
    }
    if (message.eventLimit !== 0) {
      writer.uint32(48).uint32(message.eventLimit);
    }
    if (message.maxEncodedBytes !== BigInt(0)) {
      writer.uint32(56).uint64(message.maxEncodedBytes);
    }
    if (message.scannedEventCount !== 0) {
      writer.uint32(64).uint32(message.scannedEventCount);
    }
    if (message.encodedBytes !== BigInt(0)) {
      writer.uint32(72).uint64(message.encodedBytes);
    }
    if (message.scanSchemaVersion !== "") {
      writer.uint32(82).string(message.scanSchemaVersion);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryPrivacyScanResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryPrivacyScanResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.summaries.push(PrivacyScanSummaryV2.decode(reader, reader.uint32()));
          break;
        case 2:
          message.outputs.push(PrivacyScanOutputV2.decode(reader, reader.uint32()));
          break;
        case 3:
          message.nextCursor = PrivacyScanCursorV1.decode(reader, reader.uint32());
          break;
        case 4:
          message.hasMore = reader.bool();
          break;
        case 5:
          message.outputLimit = reader.uint32();
          break;
        case 6:
          message.eventLimit = reader.uint32();
          break;
        case 7:
          message.maxEncodedBytes = reader.uint64();
          break;
        case 8:
          message.scannedEventCount = reader.uint32();
          break;
        case 9:
          message.encodedBytes = reader.uint64();
          break;
        case 10:
          message.scanSchemaVersion = reader.string();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryPrivacyScanResponse>): QueryPrivacyScanResponse {
    const message = createBaseQueryPrivacyScanResponse();
    message.summaries = object.summaries?.map(e => PrivacyScanSummaryV2.fromPartial(e)) || [];
    message.outputs = object.outputs?.map(e => PrivacyScanOutputV2.fromPartial(e)) || [];
    message.nextCursor = object.nextCursor !== undefined && object.nextCursor !== null ? PrivacyScanCursorV1.fromPartial(object.nextCursor) : undefined;
    message.hasMore = object.hasMore ?? false;
    message.outputLimit = object.outputLimit ?? 0;
    message.eventLimit = object.eventLimit ?? 0;
    message.maxEncodedBytes = object.maxEncodedBytes !== undefined && object.maxEncodedBytes !== null ? BigInt(object.maxEncodedBytes.toString()) : BigInt(0);
    message.scannedEventCount = object.scannedEventCount ?? 0;
    message.encodedBytes = object.encodedBytes !== undefined && object.encodedBytes !== null ? BigInt(object.encodedBytes.toString()) : BigInt(0);
    message.scanSchemaVersion = object.scanSchemaVersion ?? "";
    return message;
  }
};
function createBaseQueryCommitmentPathsAtRootRequest(): QueryCommitmentPathsAtRootRequest {
  return {
    commitmentHexes: [],
    rootHex: "",
    snapshotHeight: BigInt(0)
  };
}
/**
 * @name QueryCommitmentPathsAtRootRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCommitmentPathsAtRootRequest
 */
export const QueryCommitmentPathsAtRootRequest = {
  typeUrl: "/clairveil.privacy.v1.QueryCommitmentPathsAtRootRequest",
  encode(message: QueryCommitmentPathsAtRootRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    for (const v of message.commitmentHexes) {
      writer.uint32(10).string(v!);
    }
    if (message.rootHex !== "") {
      writer.uint32(18).string(message.rootHex);
    }
    if (message.snapshotHeight !== BigInt(0)) {
      writer.uint32(24).int64(message.snapshotHeight);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryCommitmentPathsAtRootRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryCommitmentPathsAtRootRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.commitmentHexes.push(reader.string());
          break;
        case 2:
          message.rootHex = reader.string();
          break;
        case 3:
          message.snapshotHeight = reader.int64();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryCommitmentPathsAtRootRequest>): QueryCommitmentPathsAtRootRequest {
    const message = createBaseQueryCommitmentPathsAtRootRequest();
    message.commitmentHexes = object.commitmentHexes?.map(e => e) || [];
    message.rootHex = object.rootHex ?? "";
    message.snapshotHeight = object.snapshotHeight !== undefined && object.snapshotHeight !== null ? BigInt(object.snapshotHeight.toString()) : BigInt(0);
    return message;
  }
};
function createBaseQueryCommitmentPathAtRoot(): QueryCommitmentPathAtRoot {
  return {
    commitmentHex: "",
    leafIndex: BigInt(0),
    path: [],
    pathHelper: []
  };
}
/**
 * @name QueryCommitmentPathAtRoot
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCommitmentPathAtRoot
 */
export const QueryCommitmentPathAtRoot = {
  typeUrl: "/clairveil.privacy.v1.QueryCommitmentPathAtRoot",
  encode(message: QueryCommitmentPathAtRoot, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.commitmentHex !== "") {
      writer.uint32(10).string(message.commitmentHex);
    }
    if (message.leafIndex !== BigInt(0)) {
      writer.uint32(16).uint64(message.leafIndex);
    }
    for (const v of message.path) {
      writer.uint32(26).string(v!);
    }
    writer.uint32(34).fork();
    for (const v of message.pathHelper) {
      writer.uint32(v);
    }
    writer.ldelim();
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryCommitmentPathAtRoot {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryCommitmentPathAtRoot();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.commitmentHex = reader.string();
          break;
        case 2:
          message.leafIndex = reader.uint64();
          break;
        case 3:
          message.path.push(reader.string());
          break;
        case 4:
          if ((tag & 7) === 2) {
            const end2 = reader.uint32() + reader.pos;
            while (reader.pos < end2) {
              message.pathHelper.push(reader.uint32());
            }
          } else {
            message.pathHelper.push(reader.uint32());
          }
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryCommitmentPathAtRoot>): QueryCommitmentPathAtRoot {
    const message = createBaseQueryCommitmentPathAtRoot();
    message.commitmentHex = object.commitmentHex ?? "";
    message.leafIndex = object.leafIndex !== undefined && object.leafIndex !== null ? BigInt(object.leafIndex.toString()) : BigInt(0);
    message.path = object.path?.map(e => e) || [];
    message.pathHelper = object.pathHelper?.map(e => e) || [];
    return message;
  }
};
function createBaseQueryCommitmentPathsAtRootResponse(): QueryCommitmentPathsAtRootResponse {
  return {
    rootHex: "",
    snapshotHeight: BigInt(0),
    leafCount: BigInt(0),
    paths: []
  };
}
/**
 * @name QueryCommitmentPathsAtRootResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCommitmentPathsAtRootResponse
 */
export const QueryCommitmentPathsAtRootResponse = {
  typeUrl: "/clairveil.privacy.v1.QueryCommitmentPathsAtRootResponse",
  encode(message: QueryCommitmentPathsAtRootResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.rootHex !== "") {
      writer.uint32(10).string(message.rootHex);
    }
    if (message.snapshotHeight !== BigInt(0)) {
      writer.uint32(16).int64(message.snapshotHeight);
    }
    if (message.leafCount !== BigInt(0)) {
      writer.uint32(24).uint64(message.leafCount);
    }
    for (const v of message.paths) {
      QueryCommitmentPathAtRoot.encode(v!, writer.uint32(34).fork()).ldelim();
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryCommitmentPathsAtRootResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryCommitmentPathsAtRootResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.rootHex = reader.string();
          break;
        case 2:
          message.snapshotHeight = reader.int64();
          break;
        case 3:
          message.leafCount = reader.uint64();
          break;
        case 4:
          message.paths.push(QueryCommitmentPathAtRoot.decode(reader, reader.uint32()));
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryCommitmentPathsAtRootResponse>): QueryCommitmentPathsAtRootResponse {
    const message = createBaseQueryCommitmentPathsAtRootResponse();
    message.rootHex = object.rootHex ?? "";
    message.snapshotHeight = object.snapshotHeight !== undefined && object.snapshotHeight !== null ? BigInt(object.snapshotHeight.toString()) : BigInt(0);
    message.leafCount = object.leafCount !== undefined && object.leafCount !== null ? BigInt(object.leafCount.toString()) : BigInt(0);
    message.paths = object.paths?.map(e => QueryCommitmentPathAtRoot.fromPartial(e)) || [];
    return message;
  }
};