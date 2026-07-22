import type { Hex } from "../core/crypto.js";
import type { PreparedWithdrawProof } from "./payload.js";
import type { PreparedTransferV5Payload, PreparedTransferV5Proof } from "./transfer-v5.js";
import type {
  PreparedBatchTransferPayload,
  PreparedBatchTransferProof
} from "./batch-transfer.js";

export interface ProverAdapter {
  proveTransfer(request: { version?: "v2"; payload?: PreparedTransferV5Payload } | PreparedTransferV5Payload): Promise<{ version: typeof transferProofResponseVersion; proof: PreparedTransferV5Proof }>;
  proveWithdraw(request: object): Promise<{ version: typeof withdrawProofResponseVersion; proof: PreparedWithdrawProof }>;
}

export interface BatchTransferProverAdapter {
  proveBatchTransfer(request: { version?: "v1"; payload?: PreparedBatchTransferPayload } | PreparedBatchTransferPayload): Promise<{ version: "v1"; proof: PreparedBatchTransferProof & { proof_bytes: Uint8Array } }>;
}

export const transferProofRequestVersion: "v2";
export const transferProofResponseVersion: "v2";
export const withdrawProofRequestVersion: "v2";
export const withdrawProofResponseVersion: "v2";
export const defaultProverResponseMaxBytes: number;

export function createHttpProverAdapter(input?: {
  baseURL: string;
  bearerToken?: string;
  timeoutMs?: number;
  /** Maximum decoded HTTP response size. Defaults to 1 MiB. */
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
}): ProverAdapter & BatchTransferProverAdapter;

export function createAsyncJobProverAdapter(input: {
  submitTransferJob: (request: object) => Promise<object>;
  submitWithdrawJob: (request: object) => Promise<object>;
  getJob: (jobId: string) => Promise<object>;
  intervalMs?: number;
  timeoutMs?: number;
  now?: () => number;
  sleepImpl?: (ms: number) => Promise<void>;
}): ProverAdapter;

export function createStaticProverAdapter(input?: { transferProofHex?: Hex; withdrawProofHex?: Hex }): ProverAdapter;
