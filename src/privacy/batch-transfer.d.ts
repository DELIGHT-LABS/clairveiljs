import type { MsgBatchTransfer } from "../generated/clairveil/privacy/v1/tx.js";

export const preparedBatchTransferPayloadVersion: "batch-transfer-payload-v1";
export const preparedBatchTransferProofVersion: "batch-transfer-proof-v1";
export const batchTransferCircuitSetId: "privacy-note-v1";
export const batchTransferProofRequestVersion: "v1";
export const batchTransferProofResponseVersion: "v1";
export const batchTransferProofPath: "/v1/proofs/batch-transfer";
export const batchTransferProofSize: 164;

export interface PreparedBatchTransferPayload {
  version: typeof preparedBatchTransferPayloadVersion;
  circuit_set_id: typeof batchTransferCircuitSetId;
  creator?: string;
  chain_id: string;
  expires_at_unix: number;
  root: string;
  inputs: Array<{ nullifier: string }>;
  outputs: unknown[];
  message_outputs: Array<Record<string, unknown>>;
  audit_key_id: string;
  audit_key_epoch: number;
  audit_disclosure_target_pubkey: string;
  payload_hash: string;
}

export interface PreparedBatchTransferProof {
  version: typeof preparedBatchTransferProofVersion;
  request_payload_hash: string;
  proof: string;
  circuit_set_id?: string;
  artifact_checksum?: string;
  proof_bytes?: Uint8Array;
}

export function validatePreparedBatchTransferPayloadEnvelope(payload: PreparedBatchTransferPayload, options?: { nowUnix?: number }): true;
export function normalizePreparedBatchTransferProof(payload: PreparedBatchTransferPayload, proof: PreparedBatchTransferProof, options?: { nowUnix?: number }): PreparedBatchTransferProof & { proof_bytes: Uint8Array };
export function buildMsgBatchTransferFromPrepared(payload: PreparedBatchTransferPayload, proof: PreparedBatchTransferProof, options?: { creator?: string; nowUnix?: number }): MsgBatchTransfer;
export function preparedBatchTransferEffectHex(payload: PreparedBatchTransferPayload): { root_hex: string; nullifier_hexes: string[]; output_commitment_hexes: string[] };
