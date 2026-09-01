import type { BytesLike, Hex } from "../core/crypto.js";
import type { DepositMaterial, Note } from "../core/note.js";
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

export interface DepositProverPayloadV1 {
  version: "v1";
  receiver_spend_pubkey_hex: Hex;
  receiver_view_pubkey_hex: Hex;
  amount: string;
  asset_id_hex: Hex;
  randomness_hex: Hex;
  note_commitment_hex: Hex;
}

export interface DepositProofRequestV1 {
  version: "v1";
  payload: DepositProverPayloadV1;
}

export interface DepositProofV1 {
  version: "v1";
  note_commitment_hex: Hex;
  proof_hex: Hex;
}

export interface DepositProofResponseV1 {
  version: "v1";
  proof: DepositProofV1;
}

export interface ProverRequestOptions {
  /** Cancels waiting for the prover request/job. In-process proving may continue remotely. */
  signal?: AbortSignal;
  /** Authoritative chain time used before and after proving expiry-bound operations. */
  nowUnix?: number;
}

/** Material input accepted by request builders and HTTP adapter conveniences. */
export interface DepositProofMaterialInput extends ProverRequestOptions {
  request?: DepositProofRequestV1;
  material?: DepositMaterial | object;
  amount?: string;
  note?: Note | object;
  /** @deprecated Local-provider compatibility only; canonical HTTP never sends note JSON. */
  noteJson?: string;
  /** @deprecated Local-provider compatibility only; canonical HTTP never sends note JSON. */
  note_json?: string;
  noteCommitmentHex?: Hex;
  note_commitment_hex?: Hex;
}

/**
 * Hybrid input passed to an injected browser/local/WASM provider. Canonical
 * Cosmos calls expose `payload`; legacy browser calls expose `material`.
 */
export interface DepositProofProviderInput extends DepositProofMaterialInput {
  version?: "v1";
  payload?: DepositProverPayloadV1;
}

export type DepositProofRequestInput = DepositProofRequestV1 | DepositProofMaterialInput;

export interface DepositProverAdapter {
  proveDeposit(input: DepositProofRequestInput, options?: ProverRequestOptions): Promise<DepositProofResponseV1>;
}

/** Legacy local/WASM result shape. It is never accepted as an HTTP response wire. */
export interface LegacyDepositProofProviderResponse {
  version?: "v1";
  proof_hex: Hex;
  note_commitment_hex: Hex;
}

export type DepositProofProviderResult = DepositProofResponseV1 | LegacyDepositProofProviderResponse | object;

export type DepositProofProvider = (
  input: DepositProofProviderInput,
  options?: ProverRequestOptions
) => Promise<DepositProofProviderResult> | DepositProofProviderResult;

/** Flat response returned by the legacy product-owned/EVM endpoint. */
export interface DepositProofProviderResponse {
  version: "v1";
  proof_hex: Hex;
  note_commitment_hex: Hex;
}

export type HttpDepositProofProvider = (
  input: DepositProofProviderInput,
  options?: ProverRequestOptions
) => Promise<DepositProofProviderResponse>;

/** Canonical v1 response plus non-enumerable legacy browser accessors. */
export interface DepositProofProviderResponseV1 extends DepositProofResponseV1 {
  readonly proof_hex: Hex;
  readonly note_commitment_hex: Hex;
}

export type HttpDepositProofProviderV1 = (
  input: DepositProofRequestInput,
  options?: ProverRequestOptions
) => Promise<DepositProofProviderResponseV1>;

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
export const depositProofPath: "/v1/prover/deposit";
export const depositProofRequestVersion: "v1";
export const depositProofPayloadVersion: "v1";
export const depositProofResponseVersion: "v1";
export const depositProofVersion: "v1";
export const depositProofByteLength: 164;
export const defaultProverResponseMaxBytes: number;
export const defaultDepositProofTimeoutMs: number;

export function createHttpProverAdapter(input: {
  baseURL: string;
  bearerToken?: string;
  timeoutMs?: number;
  /** Maximum decoded HTTP response size. Defaults to 1 MiB. */
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
}): ProverAdapter & BatchTransferProverAdapter & DepositProverAdapter;

export function buildDepositProofRequestV1(input: DepositProofRequestInput): DepositProofRequestV1;
export function validateDepositProofRequestV1(request: DepositProofRequestV1 | object): DepositProofRequestV1;
export function validateDepositProofBytesV1(proof: BytesLike | Hex, label?: string): Uint8Array;
export function validateDepositProofResponseV1(request: DepositProofRequestV1, response: DepositProofResponseV1 | object): DepositProofResponseV1;
export function normalizeDepositProofProviderResultV1(request: DepositProofRequestV1, result: DepositProofProviderResult): DepositProofResponseV1;

/**
 * Creates the legacy exact-endpoint DepositCircuit provider used by EVM and
 * product-owned integrations. It preserves the flat request/response wire.
 */
export function createHttpDepositProofProvider(input?: {
  url: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
}): HttpDepositProofProvider;

/** Creates the strict exact-endpoint provider for Core v0.4 Cosmos deposits. */
export function createHttpDepositProofProviderV1(input: {
  url: string;
  bearerToken?: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
}): HttpDepositProofProviderV1;

export function createAsyncJobProverAdapter<T extends AsyncJobProverAdapterInput>(input: T): AsyncJobProverAdapterFor<T>;

export function createStaticProverAdapter(input?: { transferProofHex?: Hex; withdrawProofHex?: Hex }): ProverAdapter;
