import type { Hex } from "../core/crypto.js";
import type { MsgTransfer } from "../generated/clairveil/privacy/v1/tx.js";

export const preparedTransferV5PayloadVersion: "v5";
export const preparedTransferV5ProofVersion: "v2";
export const transferV5ProofRequestVersion: "v2";
export const transferV5ProofResponseVersion: "v2";

export interface PreparedTransferV5Input {
  amount: string;
  randomness_hex: Hex;
  spend_pubkey_hex: Hex;
  view_pubkey_hex: Hex;
  merkle_path: string[];
  merkle_path_helper: number[];
  nullifier_hex: Hex;
}

export interface PreparedTransferV5Output {
  amount: string;
  randomness_hex: Hex;
  spend_pubkey_hex: Hex;
  view_pubkey_hex: Hex;
  commitment_hex: Hex;
}

export interface PreparedTransferV5Payload {
  version: typeof preparedTransferV5PayloadVersion;
  creator: string;
  chain_id: string;
  expires_at_unix: number;
  root_hex: Hex;
  asset_id_hex: Hex;
  inputs: [PreparedTransferV5Input, PreparedTransferV5Input];
  outputs: [PreparedTransferV5Output, PreparedTransferV5Output];
  cipher_text_hexes: [Hex, Hex];
  view_tag_hexes: [Hex, Hex];
  user_privacy_policy: number;
  user_disclosure_mode: number;
  user_disclosure_digest_hex: Hex | "";
  user_disclosure_target_pubkey_hex: Hex | "";
  user_disclosure_payload_hex: Hex | "";
  audit_disclosure_digest_hex: Hex;
  audit_disclosure_target_pubkey_hex: Hex;
  audit_disclosure_payload_hex: Hex;
  self_view_disclosure_digest_hex: Hex | "";
  self_view_disclosure_payload_hex: Hex | "";
  user_disclosure_blinding_hex: Hex | "";
  full_disclosure_blinding_hex: Hex;
  owner_signature_hex: Hex;
  payload_hash: Hex;
}

export interface PreparedTransferV5Proof {
  version: typeof preparedTransferV5ProofVersion;
  payload_hash: Hex;
  proof_hex: Hex;
}

export function buildPreparedTransferV5Payload(input: object): Promise<PreparedTransferV5Payload>;
export function computePreparedTransferV5PayloadHash(payload: Partial<PreparedTransferV5Payload>): Hex;
export function validatePreparedTransferV5PayloadMetadata(payload: PreparedTransferV5Payload): true;
export function validatePreparedTransferV5PayloadAt(payload: PreparedTransferV5Payload, nowUnix?: number): true;
export function validatePreparedTransferV5Proof(payload: PreparedTransferV5Payload, proof: PreparedTransferV5Proof, options?: { nowUnix?: number }): true;
export function buildTransferV5MsgFromPayloadAndProof(payload: PreparedTransferV5Payload, proof: PreparedTransferV5Proof, options?: { nowUnix?: number }): MsgTransfer;
