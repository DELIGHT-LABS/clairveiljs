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
}
function createBaseGenesisState(): GenesisState {
  return {
    commitments: [],
    historicalRoots: [],
    nullifiers: [],
    auditMasterPubkey: new Uint8Array()
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
  encode(message: GenesisState, writer: BinaryWriter = BinaryWriter.create()): BinaryWriter {
    for (const v of message.commitments) {
      writer.uint32(10).bytes(v!);
    }
    for (const v of message.historicalRoots) {
      writer.uint32(18).bytes(v!);
    }
    for (const v of message.nullifiers) {
      writer.uint32(26).bytes(v!);
    }
    if (message.auditMasterPubkey.length !== 0) {
      writer.uint32(34).bytes(message.auditMasterPubkey);
    }
    return writer;
  },
  decode(input: BinaryReader | Uint8Array, length?: number): GenesisState {
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
        default:
          reader.skipType(tag & 7);
          break;
      }
    }
    return message;
  },
  fromPartial(object: DeepPartial<GenesisState>): GenesisState {
    const message = createBaseGenesisState();
    message.commitments = object.commitments?.map(e => e) || [];
    message.historicalRoots = object.historicalRoots?.map(e => e) || [];
    message.nullifiers = object.nullifiers?.map(e => e) || [];
    message.auditMasterPubkey = object.auditMasterPubkey ?? new Uint8Array();
    return message;
  }
};