import type { Hex } from "../core/crypto.js";
import type {
  PreparedTransferProof,
  PreparedWithdrawProof
} from "./payload.js";

export interface ProverAdapter {
  proveTransfer(request: object): Promise<{ version: typeof transferProofResponseVersion; proof: PreparedTransferProof }>;
  proveWithdraw(request: object): Promise<{ version: typeof withdrawProofResponseVersion; proof: PreparedWithdrawProof }>;
}

export const transferProofRequestVersion: "v1";
export const transferProofResponseVersion: "v1";
export const withdrawProofRequestVersion: "v1";
export const withdrawProofResponseVersion: "v1";

export function createHttpProverAdapter(input?: {
  baseURL: string;
  bearerToken?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}): ProverAdapter;

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
