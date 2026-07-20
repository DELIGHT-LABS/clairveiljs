import type { MsgBatchTransfer } from "../generated/clairveil/privacy/v1/tx.js";
import type { Point } from "../core/crypto.js";
import type { NoteV1 } from "./protocol-v1.js";

export const preparedBatchTransferPayloadVersion: "batch-transfer-payload-v1";
export const preparedBatchTransferProofVersion: "batch-transfer-proof-v1";
export const batchTransferCircuitSetId: "privacy-note-v1";
export const batchTransferProofRequestVersion: "v1";
export const batchTransferProofResponseVersion: "v1";
export const batchTransferProofPath: "/v1/proofs/batch-transfer";
export const batchTransferProofSize: 164;

export type BatchField = bigint | number | string;

export interface PreparedBatchTransferInput {
  note: { rsx: string; rsy: string; rvx: string; rvy: string; am: string; as: string; rn: string; mm: string };
  merkle_path: string[];
  merkle_path_helper: number[];
  nullifier: string;
}

export interface PreparedBatchTransferOutput {
  kind: "payment" | "change" | "padding";
  note: { rsx: string; rsy: string; rvx: string; rvy: string; am: string; as: string; rn: string; mm: string };
  privacy_policy: number;
  disclosure_mode: number;
  disclosure_target_pubkey?: string;
  user_disclosure_blinding: string;
  full_disclosure_blinding: string;
}

export interface PreparedBatchTransferPayload {
  version: typeof preparedBatchTransferPayloadVersion;
  circuit_set_id: typeof batchTransferCircuitSetId;
  creator?: string;
  chain_id: string;
  expires_at_unix: number;
  root: string;
  asset_id: string;
  inputs: PreparedBatchTransferInput[];
  outputs: PreparedBatchTransferOutput[];
  message_outputs: Array<Record<string, unknown>>;
  audit_key_id: string;
  audit_key_epoch: number;
  audit_disclosure_target_pubkey: string;
  nullifier_root: string;
  commitment_root: string;
  user_disclosure_root: string;
  full_disclosure_root: string;
  payload_digest_hi: string;
  payload_digest_lo: string;
  expected_intent: string;
  owner_signature: string;
  payload_hash: string;
}

export interface BuildPreparedBatchTransferInput {
  creator?: string;
  chainId?: string;
  chain_id?: string;
  expiresAtUnix?: number;
  expires_at_unix?: number;
  root?: Uint8Array | string | BatchField;
  inputs: Array<{ note: NoteV1; merklePath?: string[]; merkle_path?: string[]; merklePathHelper?: number[]; merkle_path_helper?: number[] }>;
  outputs: Array<{
    kind: "payment" | "change" | "padding";
    note: NoteV1;
    privacyPolicy?: number;
    privacy_policy?: number;
    disclosureMode?: 0 | 1 | 2;
    disclosure_mode?: 0 | 1 | 2;
    disclosureTargetPubKey?: Point | Uint8Array | string;
    disclosure_target_pubkey?: Point | Uint8Array | string;
    userDisclosureBlinding?: BatchField;
    user_disclosure_blinding?: BatchField;
    fullDisclosureBlinding?: BatchField;
    full_disclosure_blinding?: BatchField;
  }>;
  auditKeyId?: string;
  audit_key_id?: string;
  auditKeyEpoch?: number;
  audit_key_epoch?: number;
  auditDisclosureTargetPubKey?: Point | Uint8Array | string;
  audit_disclosure_target_pubkey?: Point | Uint8Array | string;
  selfViewDisclosureTargetPubKey?: Point | Uint8Array | string;
  self_view_disclosure_target_pubkey?: Point | Uint8Array | string;
  disableSelfViewDisclosure?: boolean;
  signer: {
    signBatchTransfer?(request: { version: string; circuitSetId: string; chainId: string; expiresAtUnix: number; canonicalPayload: Uint8Array; expectedIntent: bigint; message: object }): Promise<Uint8Array> | Uint8Array;
    signSpendNoteHash?(intent: bigint): Promise<Uint8Array> | Uint8Array;
    signNoteHash?(intent: bigint): Promise<Uint8Array> | Uint8Array;
  };
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
export function computePreparedBatchTransferPayloadHash(payload: PreparedBatchTransferPayload): string;
export function serializePreparedBatchTransferPayload(payload: PreparedBatchTransferPayload): string;
export function serializeBatchTransferProofRequest(payload: PreparedBatchTransferPayload): string;
export function buildPreparedBatchTransferPayload(input: BuildPreparedBatchTransferInput): Promise<PreparedBatchTransferPayload>;
export function normalizePreparedBatchTransferProof(payload: PreparedBatchTransferPayload, proof: PreparedBatchTransferProof, options?: { nowUnix?: number }): PreparedBatchTransferProof & { proof_bytes: Uint8Array };
export function buildMsgBatchTransferFromPrepared(payload: PreparedBatchTransferPayload, proof: PreparedBatchTransferProof, options?: { creator?: string; nowUnix?: number }): MsgBatchTransfer;
export function preparedBatchTransferEffectHex(payload: PreparedBatchTransferPayload): { root_hex: string; nullifier_hexes: string[]; output_commitment_hexes: string[] };
