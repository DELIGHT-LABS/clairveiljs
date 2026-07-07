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
export interface QueryTreeStateRequest {
}
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
export interface QueryAuditConfigRequest {
}
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
export interface QueryDisclosureConfigRequest {
}
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
export interface QueryCircuitConfigRequest {
}
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
 * QueryCheckNullifierRequest
 * @name QueryCheckNullifierRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCheckNullifierRequest
 */
export declare const QueryCheckNullifierRequest: {
    typeUrl: string;
    encode(message: QueryCheckNullifierRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryCheckNullifierRequest;
    fromPartial(object: DeepPartial<QueryCheckNullifierRequest>): QueryCheckNullifierRequest;
};
/**
 * QueryCheckNullifierResponse
 * @name QueryCheckNullifierResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCheckNullifierResponse
 */
export declare const QueryCheckNullifierResponse: {
    typeUrl: string;
    encode(message: QueryCheckNullifierResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryCheckNullifierResponse;
    fromPartial(object: DeepPartial<QueryCheckNullifierResponse>): QueryCheckNullifierResponse;
};
/**
 * @name QueryCheckNullifiersRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCheckNullifiersRequest
 */
export declare const QueryCheckNullifiersRequest: {
    typeUrl: string;
    encode(message: QueryCheckNullifiersRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryCheckNullifiersRequest;
    fromPartial(object: DeepPartial<QueryCheckNullifiersRequest>): QueryCheckNullifiersRequest;
};
/**
 * @name QueryNullifierStatus
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryNullifierStatus
 */
export declare const QueryNullifierStatus: {
    typeUrl: string;
    encode(message: QueryNullifierStatus, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryNullifierStatus;
    fromPartial(object: DeepPartial<QueryNullifierStatus>): QueryNullifierStatus;
};
/**
 * @name QueryCheckNullifiersResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCheckNullifiersResponse
 */
export declare const QueryCheckNullifiersResponse: {
    typeUrl: string;
    encode(message: QueryCheckNullifiersResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryCheckNullifiersResponse;
    fromPartial(object: DeepPartial<QueryCheckNullifiersResponse>): QueryCheckNullifiersResponse;
};
/**
 * @name QueryTreeStateRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryTreeStateRequest
 */
export declare const QueryTreeStateRequest: {
    typeUrl: string;
    encode(_: QueryTreeStateRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryTreeStateRequest;
    fromPartial(_: DeepPartial<QueryTreeStateRequest>): QueryTreeStateRequest;
};
/**
 * @name QueryTreeStateResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryTreeStateResponse
 */
export declare const QueryTreeStateResponse: {
    typeUrl: string;
    encode(message: QueryTreeStateResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryTreeStateResponse;
    fromPartial(object: DeepPartial<QueryTreeStateResponse>): QueryTreeStateResponse;
};
/**
 * @name QueryCommitmentInfoRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCommitmentInfoRequest
 */
export declare const QueryCommitmentInfoRequest: {
    typeUrl: string;
    encode(message: QueryCommitmentInfoRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryCommitmentInfoRequest;
    fromPartial(object: DeepPartial<QueryCommitmentInfoRequest>): QueryCommitmentInfoRequest;
};
/**
 * @name QueryCommitmentInfoResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCommitmentInfoResponse
 */
export declare const QueryCommitmentInfoResponse: {
    typeUrl: string;
    encode(message: QueryCommitmentInfoResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryCommitmentInfoResponse;
    fromPartial(object: DeepPartial<QueryCommitmentInfoResponse>): QueryCommitmentInfoResponse;
};
/**
 * @name QueryPrivacyEventsRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyEventsRequest
 */
export declare const QueryPrivacyEventsRequest: {
    typeUrl: string;
    encode(message: QueryPrivacyEventsRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryPrivacyEventsRequest;
    fromPartial(object: DeepPartial<QueryPrivacyEventsRequest>): QueryPrivacyEventsRequest;
};
/**
 * @name QueryPrivacyEventAttribute
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyEventAttribute
 */
export declare const QueryPrivacyEventAttribute: {
    typeUrl: string;
    encode(message: QueryPrivacyEventAttribute, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryPrivacyEventAttribute;
    fromPartial(object: DeepPartial<QueryPrivacyEventAttribute>): QueryPrivacyEventAttribute;
};
/**
 * @name QueryPrivacyEvent
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyEvent
 */
export declare const QueryPrivacyEvent: {
    typeUrl: string;
    encode(message: QueryPrivacyEvent, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryPrivacyEvent;
    fromPartial(object: DeepPartial<QueryPrivacyEvent>): QueryPrivacyEvent;
};
/**
 * @name QueryPrivacyEventsResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryPrivacyEventsResponse
 */
export declare const QueryPrivacyEventsResponse: {
    typeUrl: string;
    encode(message: QueryPrivacyEventsResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryPrivacyEventsResponse;
    fromPartial(object: DeepPartial<QueryPrivacyEventsResponse>): QueryPrivacyEventsResponse;
};
/**
 * @name QueryScanEventsRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryScanEventsRequest
 */
export declare const QueryScanEventsRequest: {
    typeUrl: string;
    encode(message: QueryScanEventsRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryScanEventsRequest;
    fromPartial(object: DeepPartial<QueryScanEventsRequest>): QueryScanEventsRequest;
};
/**
 * @name QueryScanOutput
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryScanOutput
 */
export declare const QueryScanOutput: {
    typeUrl: string;
    encode(message: QueryScanOutput, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryScanOutput;
    fromPartial(object: DeepPartial<QueryScanOutput>): QueryScanOutput;
};
/**
 * @name QueryScanEvent
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryScanEvent
 */
export declare const QueryScanEvent: {
    typeUrl: string;
    encode(message: QueryScanEvent, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryScanEvent;
    fromPartial(object: DeepPartial<QueryScanEvent>): QueryScanEvent;
};
/**
 * @name QueryScanEventsResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryScanEventsResponse
 */
export declare const QueryScanEventsResponse: {
    typeUrl: string;
    encode(message: QueryScanEventsResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryScanEventsResponse;
    fromPartial(object: DeepPartial<QueryScanEventsResponse>): QueryScanEventsResponse;
};
/**
 * QueryMerklePathRequest
 * @name QueryMerklePathRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryMerklePathRequest
 */
export declare const QueryMerklePathRequest: {
    typeUrl: string;
    encode(message: QueryMerklePathRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryMerklePathRequest;
    fromPartial(object: DeepPartial<QueryMerklePathRequest>): QueryMerklePathRequest;
};
/**
 * QueryMerklePathResponse
 * @name QueryMerklePathResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryMerklePathResponse
 */
export declare const QueryMerklePathResponse: {
    typeUrl: string;
    encode(message: QueryMerklePathResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryMerklePathResponse;
    fromPartial(object: DeepPartial<QueryMerklePathResponse>): QueryMerklePathResponse;
};
/**
 * @name QueryAuditConfigRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAuditConfigRequest
 */
export declare const QueryAuditConfigRequest: {
    typeUrl: string;
    encode(_: QueryAuditConfigRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditConfigRequest;
    fromPartial(_: DeepPartial<QueryAuditConfigRequest>): QueryAuditConfigRequest;
};
/**
 * @name QueryAuditConfigResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryAuditConfigResponse
 */
export declare const QueryAuditConfigResponse: {
    typeUrl: string;
    encode(message: QueryAuditConfigResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditConfigResponse;
    fromPartial(object: DeepPartial<QueryAuditConfigResponse>): QueryAuditConfigResponse;
};
/**
 * @name QueryDisclosureConfigRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryDisclosureConfigRequest
 */
export declare const QueryDisclosureConfigRequest: {
    typeUrl: string;
    encode(_: QueryDisclosureConfigRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryDisclosureConfigRequest;
    fromPartial(_: DeepPartial<QueryDisclosureConfigRequest>): QueryDisclosureConfigRequest;
};
/**
 * @name QueryDisclosureConfigResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryDisclosureConfigResponse
 */
export declare const QueryDisclosureConfigResponse: {
    typeUrl: string;
    encode(message: QueryDisclosureConfigResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryDisclosureConfigResponse;
    fromPartial(object: DeepPartial<QueryDisclosureConfigResponse>): QueryDisclosureConfigResponse;
};
/**
 * @name QueryCircuitConfigRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCircuitConfigRequest
 */
export declare const QueryCircuitConfigRequest: {
    typeUrl: string;
    encode(_: QueryCircuitConfigRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryCircuitConfigRequest;
    fromPartial(_: DeepPartial<QueryCircuitConfigRequest>): QueryCircuitConfigRequest;
};
/**
 * @name QueryCircuitArtifact
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCircuitArtifact
 */
export declare const QueryCircuitArtifact: {
    typeUrl: string;
    encode(message: QueryCircuitArtifact, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryCircuitArtifact;
    fromPartial(object: DeepPartial<QueryCircuitArtifact>): QueryCircuitArtifact;
};
/**
 * @name QueryCircuitConfigResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryCircuitConfigResponse
 */
export declare const QueryCircuitConfigResponse: {
    typeUrl: string;
    encode(message: QueryCircuitConfigResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryCircuitConfigResponse;
    fromPartial(object: DeepPartial<QueryCircuitConfigResponse>): QueryCircuitConfigResponse;
};
/**
 * @name QueryReserveRequest
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryReserveRequest
 */
export declare const QueryReserveRequest: {
    typeUrl: string;
    encode(message: QueryReserveRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryReserveRequest;
    fromPartial(object: DeepPartial<QueryReserveRequest>): QueryReserveRequest;
};
/**
 * @name QueryReserveResponse
 * @package clairveil.privacy.v1
 * @see proto type: clairveil.privacy.v1.QueryReserveResponse
 */
export declare const QueryReserveResponse: {
    typeUrl: string;
    encode(message: QueryReserveResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryReserveResponse;
    fromPartial(object: DeepPartial<QueryReserveResponse>): QueryReserveResponse;
};
