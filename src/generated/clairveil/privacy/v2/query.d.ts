import { BinaryReader, BinaryWriter } from "../../../binary.js";
import { DeepPartial } from "../../../helpers.js";
/**
 * @name QueryAuditKeyRequest
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditKeyRequest
 */
export interface QueryAuditKeyRequest {
    epoch: bigint;
}
/**
 * @name QueryAuditRecordResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditRecordResponse
 */
export interface QueryAuditRecordResponse {
    record: Uint8Array;
    storeKey: Uint8Array;
    stateHeight: bigint;
}
/**
 * @name QueryAuditKeyScheduleRequest
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditKeyScheduleRequest
 */
export interface QueryAuditKeyScheduleRequest {
}
/**
 * @name QueryAuditKeyScheduleResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditKeyScheduleResponse
 */
export interface QueryAuditKeyScheduleResponse {
    activeEpoch: bigint;
    nextActivationHeight: bigint;
    nextEpoch: bigint;
    halted: boolean;
    stateHeight: bigint;
}
/**
 * @name QueryAuditConfigurationRequest
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditConfigurationRequest
 */
export interface QueryAuditConfigurationRequest {
}
/**
 * @name QueryAuditConfigurationResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditConfigurationResponse
 */
export interface QueryAuditConfigurationResponse {
    networkNonce: Uint8Array;
    initialHeight: bigint;
    circuitIdentity: Uint8Array;
    stateHeight: bigint;
}
/**
 * @name QueryAuditKeyRequest
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditKeyRequest
 */
export declare const QueryAuditKeyRequest: {
    typeUrl: string;
    encode(message: QueryAuditKeyRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditKeyRequest;
    fromPartial(object: DeepPartial<QueryAuditKeyRequest>): QueryAuditKeyRequest;
};
/**
 * @name QueryAuditRecordResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditRecordResponse
 */
export declare const QueryAuditRecordResponse: {
    typeUrl: string;
    encode(message: QueryAuditRecordResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditRecordResponse;
    fromPartial(object: DeepPartial<QueryAuditRecordResponse>): QueryAuditRecordResponse;
};
/**
 * @name QueryAuditKeyScheduleRequest
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditKeyScheduleRequest
 */
export declare const QueryAuditKeyScheduleRequest: {
    typeUrl: string;
    encode(_: QueryAuditKeyScheduleRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditKeyScheduleRequest;
    fromPartial(_: DeepPartial<QueryAuditKeyScheduleRequest>): QueryAuditKeyScheduleRequest;
};
/**
 * @name QueryAuditKeyScheduleResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditKeyScheduleResponse
 */
export declare const QueryAuditKeyScheduleResponse: {
    typeUrl: string;
    encode(message: QueryAuditKeyScheduleResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditKeyScheduleResponse;
    fromPartial(object: DeepPartial<QueryAuditKeyScheduleResponse>): QueryAuditKeyScheduleResponse;
};
/**
 * @name QueryAuditConfigurationRequest
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditConfigurationRequest
 */
export declare const QueryAuditConfigurationRequest: {
    typeUrl: string;
    encode(_: QueryAuditConfigurationRequest, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditConfigurationRequest;
    fromPartial(_: DeepPartial<QueryAuditConfigurationRequest>): QueryAuditConfigurationRequest;
};
/**
 * @name QueryAuditConfigurationResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditConfigurationResponse
 */
export declare const QueryAuditConfigurationResponse: {
    typeUrl: string;
    encode(message: QueryAuditConfigurationResponse, writer?: BinaryWriter): BinaryWriter;
    decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditConfigurationResponse;
    fromPartial(object: DeepPartial<QueryAuditConfigurationResponse>): QueryAuditConfigurationResponse;
};
