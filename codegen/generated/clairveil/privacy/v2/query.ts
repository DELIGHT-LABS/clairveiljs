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
export interface QueryAuditKeyScheduleRequest {}
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
export interface QueryAuditConfigurationRequest {}
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
function createBaseQueryAuditKeyRequest(): QueryAuditKeyRequest {
  return {
    epoch: BigInt(0)
  };
}
/**
 * @name QueryAuditKeyRequest
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditKeyRequest
 */
export const QueryAuditKeyRequest = {
  typeUrl: "/clairveil.privacy.v2.QueryAuditKeyRequest",
  encode(message: QueryAuditKeyRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.epoch !== BigInt(0)) {
      writer.uint32(8).uint64(message.epoch);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditKeyRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryAuditKeyRequest();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.epoch = reader.uint64();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryAuditKeyRequest>): QueryAuditKeyRequest {
    const message = createBaseQueryAuditKeyRequest();
    message.epoch = object.epoch !== undefined && object.epoch !== null ? BigInt(object.epoch.toString()) : BigInt(0);
    return message;
  }
};
function createBaseQueryAuditRecordResponse(): QueryAuditRecordResponse {
  return {
    record: new Uint8Array(),
    storeKey: new Uint8Array(),
    stateHeight: BigInt(0)
  };
}
/**
 * @name QueryAuditRecordResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditRecordResponse
 */
export const QueryAuditRecordResponse = {
  typeUrl: "/clairveil.privacy.v2.QueryAuditRecordResponse",
  encode(message: QueryAuditRecordResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.record.length !== 0) {
      writer.uint32(10).bytes(message.record);
    }
    if (message.storeKey.length !== 0) {
      writer.uint32(18).bytes(message.storeKey);
    }
    if (message.stateHeight !== BigInt(0)) {
      writer.uint32(24).int64(message.stateHeight);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditRecordResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryAuditRecordResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.record = reader.bytes();
          break;
        case 2:
          message.storeKey = reader.bytes();
          break;
        case 3:
          message.stateHeight = reader.int64();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryAuditRecordResponse>): QueryAuditRecordResponse {
    const message = createBaseQueryAuditRecordResponse();
    message.record = object.record ?? new Uint8Array();
    message.storeKey = object.storeKey ?? new Uint8Array();
    message.stateHeight = object.stateHeight !== undefined && object.stateHeight !== null ? BigInt(object.stateHeight.toString()) : BigInt(0);
    return message;
  }
};
function createBaseQueryAuditKeyScheduleRequest(): QueryAuditKeyScheduleRequest {
  return {};
}
/**
 * @name QueryAuditKeyScheduleRequest
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditKeyScheduleRequest
 */
export const QueryAuditKeyScheduleRequest = {
  typeUrl: "/clairveil.privacy.v2.QueryAuditKeyScheduleRequest",
  encode(_: QueryAuditKeyScheduleRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditKeyScheduleRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryAuditKeyScheduleRequest();
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
  fromPartial(_: DeepPartial<QueryAuditKeyScheduleRequest>): QueryAuditKeyScheduleRequest {
    const message = createBaseQueryAuditKeyScheduleRequest();
    return message;
  }
};
function createBaseQueryAuditKeyScheduleResponse(): QueryAuditKeyScheduleResponse {
  return {
    activeEpoch: BigInt(0),
    nextActivationHeight: BigInt(0),
    nextEpoch: BigInt(0),
    halted: false,
    stateHeight: BigInt(0)
  };
}
/**
 * @name QueryAuditKeyScheduleResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditKeyScheduleResponse
 */
export const QueryAuditKeyScheduleResponse = {
  typeUrl: "/clairveil.privacy.v2.QueryAuditKeyScheduleResponse",
  encode(message: QueryAuditKeyScheduleResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.activeEpoch !== BigInt(0)) {
      writer.uint32(8).uint64(message.activeEpoch);
    }
    if (message.nextActivationHeight !== BigInt(0)) {
      writer.uint32(16).uint64(message.nextActivationHeight);
    }
    if (message.nextEpoch !== BigInt(0)) {
      writer.uint32(24).uint64(message.nextEpoch);
    }
    if (message.halted === true) {
      writer.uint32(32).bool(message.halted);
    }
    if (message.stateHeight !== BigInt(0)) {
      writer.uint32(40).int64(message.stateHeight);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditKeyScheduleResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryAuditKeyScheduleResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.activeEpoch = reader.uint64();
          break;
        case 2:
          message.nextActivationHeight = reader.uint64();
          break;
        case 3:
          message.nextEpoch = reader.uint64();
          break;
        case 4:
          message.halted = reader.bool();
          break;
        case 5:
          message.stateHeight = reader.int64();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryAuditKeyScheduleResponse>): QueryAuditKeyScheduleResponse {
    const message = createBaseQueryAuditKeyScheduleResponse();
    message.activeEpoch = object.activeEpoch !== undefined && object.activeEpoch !== null ? BigInt(object.activeEpoch.toString()) : BigInt(0);
    message.nextActivationHeight = object.nextActivationHeight !== undefined && object.nextActivationHeight !== null ? BigInt(object.nextActivationHeight.toString()) : BigInt(0);
    message.nextEpoch = object.nextEpoch !== undefined && object.nextEpoch !== null ? BigInt(object.nextEpoch.toString()) : BigInt(0);
    message.halted = object.halted ?? false;
    message.stateHeight = object.stateHeight !== undefined && object.stateHeight !== null ? BigInt(object.stateHeight.toString()) : BigInt(0);
    return message;
  }
};
function createBaseQueryAuditConfigurationRequest(): QueryAuditConfigurationRequest {
  return {};
}
/**
 * @name QueryAuditConfigurationRequest
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditConfigurationRequest
 */
export const QueryAuditConfigurationRequest = {
  typeUrl: "/clairveil.privacy.v2.QueryAuditConfigurationRequest",
  encode(_: QueryAuditConfigurationRequest, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditConfigurationRequest {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryAuditConfigurationRequest();
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
  fromPartial(_: DeepPartial<QueryAuditConfigurationRequest>): QueryAuditConfigurationRequest {
    const message = createBaseQueryAuditConfigurationRequest();
    return message;
  }
};
function createBaseQueryAuditConfigurationResponse(): QueryAuditConfigurationResponse {
  return {
    networkNonce: new Uint8Array(),
    initialHeight: BigInt(0),
    circuitIdentity: new Uint8Array(),
    stateHeight: BigInt(0)
  };
}
/**
 * @name QueryAuditConfigurationResponse
 * @package clairveil.privacy.v2
 * @see proto type: clairveil.privacy.v2.QueryAuditConfigurationResponse
 */
export const QueryAuditConfigurationResponse = {
  typeUrl: "/clairveil.privacy.v2.QueryAuditConfigurationResponse",
  encode(message: QueryAuditConfigurationResponse, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    if (message.networkNonce.length !== 0) {
      writer.uint32(10).bytes(message.networkNonce);
    }
    if (message.initialHeight !== BigInt(0)) {
      writer.uint32(16).uint64(message.initialHeight);
    }
    if (message.circuitIdentity.length !== 0) {
      writer.uint32(26).bytes(message.circuitIdentity);
    }
    if (message.stateHeight !== BigInt(0)) {
      writer.uint32(32).int64(message.stateHeight);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): QueryAuditConfigurationResponse {
    const reader = input instanceof BinaryReader ? input : new BinaryReader(input);
    let end = length === undefined ? reader.len : reader.pos + length;
    const message = createBaseQueryAuditConfigurationResponse();
    while (reader.pos < end) {
      const tag = reader.uint32();
      switch (tag >>> 3) {
        case 1:
          message.networkNonce = reader.bytes();
          break;
        case 2:
          message.initialHeight = reader.uint64();
          break;
        case 3:
          message.circuitIdentity = reader.bytes();
          break;
        case 4:
          message.stateHeight = reader.int64();
          break;
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<QueryAuditConfigurationResponse>): QueryAuditConfigurationResponse {
    const message = createBaseQueryAuditConfigurationResponse();
    message.networkNonce = object.networkNonce ?? new Uint8Array();
    message.initialHeight = object.initialHeight !== undefined && object.initialHeight !== null ? BigInt(object.initialHeight.toString()) : BigInt(0);
    message.circuitIdentity = object.circuitIdentity ?? new Uint8Array();
    message.stateHeight = object.stateHeight !== undefined && object.stateHeight !== null ? BigInt(object.stateHeight.toString()) : BigInt(0);
    return message;
  }
};