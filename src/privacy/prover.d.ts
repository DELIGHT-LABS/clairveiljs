import type { Hex } from "../core/crypto.js";
import type { PreparedWithdrawProof } from "./payload.js";
import type { PreparedTransferV5Payload, PreparedTransferV5Proof } from "./transfer-v5.js";
import type {
  PreparedBatchTransferPayload,
  PreparedBatchTransferProof
} from "./batch-transfer.js";

export interface ProverAdapter {
  proveTransfer(request: { version?: "v2"; payload?: PreparedTransferV5Payload } | PreparedTransferV5Payload, options?: ProverRequestOptions): Promise<{ version: typeof transferProofResponseVersion; proof: PreparedTransferV5Proof }>;
  proveWithdraw(request: object, options?: ProverRequestOptions): Promise<{ version: typeof withdrawProofResponseVersion; proof: PreparedWithdrawProof }>;
}

export interface BatchTransferProverAdapter {
  proveBatchTransfer(request: { version?: "v1"; payload?: PreparedBatchTransferPayload } | PreparedBatchTransferPayload, options?: ProverRequestOptions): Promise<{ version: "v1"; proof: PreparedBatchTransferProof & { proof_bytes: Uint8Array } }>;
}

export interface ProverRequestOptions {
  /** Cancels waiting for the prover request/job. In-process proving may continue remotely. */
  signal?: AbortSignal;
  /** Authoritative chain time used to validate an expiry-bound transfer proof. */
  nowUnix?: number;
}

/** Input passed to a local/WASM or pinned remote DepositCircuit proof provider. */
export interface DepositProofProviderInput extends ProverRequestOptions {
  material?: object;
  amount?: string;
  note?: object;
  noteJson?: string;
  note_json?: string;
  noteCommitmentHex?: Hex;
  note_commitment_hex?: Hex;
}

/** Exact, versioned response returned by the pinned DepositCircuit endpoint. */
export interface DepositProofProviderResponse {
  version: "v1";
  proof_hex: Hex;
  note_commitment_hex: Hex;
}

export type DepositProofProvider = (
  input: DepositProofProviderInput
) => Promise<DepositProofProviderResponse | object> | DepositProofProviderResponse | object;

export type AsyncJobSubmitter = (request: object, options?: ProverRequestOptions) => Promise<object>;

interface AsyncJobProverAdapterOptions {
  submitTransferJob?: AsyncJobSubmitter;
  submitWithdrawJob?: AsyncJobSubmitter;
  submitBatchTransferJob?: AsyncJobSubmitter;
  getJob: (jobId: string, options?: ProverRequestOptions) => Promise<object>;
  intervalMs?: number;
  timeoutMs?: number;
  now?: () => number;
  sleepImpl?: (ms: number) => Promise<void>;
}

export type AsyncJobProverAdapterInput = AsyncJobProverAdapterOptions & (
  { submitTransferJob: AsyncJobSubmitter } |
  { submitWithdrawJob: AsyncJobSubmitter } |
  { submitBatchTransferJob: AsyncJobSubmitter }
);

export type AsyncJobProverAdapterFor<T extends AsyncJobProverAdapterInput> =
  (T["submitTransferJob"] extends AsyncJobSubmitter ? Pick<ProverAdapter, "proveTransfer"> : {}) &
  (T["submitWithdrawJob"] extends AsyncJobSubmitter ? Pick<ProverAdapter, "proveWithdraw"> : {}) &
  (T["submitBatchTransferJob"] extends AsyncJobSubmitter ? BatchTransferProverAdapter : {});

export const transferProofRequestVersion: "v2";
export const transferProofResponseVersion: "v2";
export const withdrawProofRequestVersion: "v2";
export const withdrawProofResponseVersion: "v2";
export const depositProofResponseVersion: "v1";
export const defaultProverResponseMaxBytes: number;
export const defaultDepositProofTimeoutMs: number;

export function createHttpProverAdapter(input?: {
  baseURL: string;
  bearerToken?: string;
  timeoutMs?: number;
  /** Maximum decoded HTTP response size. Defaults to 1 MiB. */
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
}): ProverAdapter & BatchTransferProverAdapter;

/**
 * Creates the strict, exact-endpoint DepositCircuit provider used by an active
 * browser profile's `depositProofUrl`.
 */
export function createHttpDepositProofProvider(input?: {
  url: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
}): DepositProofProvider;

export function createAsyncJobProverAdapter<T extends AsyncJobProverAdapterInput>(input: T): AsyncJobProverAdapterFor<T>;

export function createStaticProverAdapter(input?: { transferProofHex?: Hex; withdrawProofHex?: Hex }): ProverAdapter;
