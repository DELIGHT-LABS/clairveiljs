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
