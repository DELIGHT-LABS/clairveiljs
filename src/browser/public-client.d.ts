export type Uint64CursorInput = number | bigint | string;
import type {
  NormalizedAssetRegistryEntryV1,
  NormalizedAssetRegistryQueryResponseV1
} from "../privacy/asset-registry.js";
import type { VerifiedCommitmentPathSnapshot } from "../privacy/merkle-path.js";
import type {
  ValidatedAuditConfigV1,
  ValidatedDisclosureConfigV1,
  ValidatedReserveResponseV1
} from "../privacy/network-config.js";
import type { ValidatedCircuitConfigV1 } from "../privacy/circuit-config.js";
import type { PrivacyStateAdapter } from "../transport/privacy-state.js";
import type {
  PrivacyScanValidationStateV2,
  ValidatedPrivacyScanPageV2
} from "../privacy/scan.js";

export interface PrivacyEventsQuery {
  afterHeight?: Uint64CursorInput;
  after_height?: Uint64CursorInput;
  afterSequence?: Uint64CursorInput;
  after_sequence?: Uint64CursorInput;
  page?: number;
  limit?: number;
  eventTypes?: string[];
  event_types?: string[];
}

export interface PrivacyScanCursorInput {
  height?: Uint64CursorInput;
  globalSequence?: Uint64CursorInput;
  global_sequence?: Uint64CursorInput;
  outputIndex?: number;
  output_index?: number;
}

export interface TypedPrivacyScanQuery {
  after?: PrivacyScanCursorInput;
  outputLimit?: number;
  output_limit?: number;
  eventLimit?: number;
  event_limit?: number;
  maxEncodedBytes?: Uint64CursorInput;
  max_encoded_bytes?: Uint64CursorInput;
  eventTypes?: string[];
  event_types?: string[];
  /** Retain the same mutable state while fetching consecutive cursor pages. */
  validationState?: PrivacyScanValidationStateV2;
  validation_state?: PrivacyScanValidationStateV2;
}

export interface CommitmentPathsAtRootQuery {
  commitmentHexes?: readonly string[];
  commitment_hexes?: readonly string[];
  rootHex?: string;
  root_hex?: string;
  snapshotHeight?: Uint64CursorInput;
  snapshot_height?: Uint64CursorInput;
}

export interface ClairveilPublicClientOptions {
  rest?: string;
  restEndpoints?: string[];
  queryTimeoutMs?: number;
  fetchTimeoutMs?: number;
  queryRetry?: QueryRetryOptions | false;
  nullifierFailover?: boolean;
  /** Allow Merkle witness and exact-snapshot queries to fail over across REST endpoints. */
  merklePathFailover?: boolean;
  /** Contract-getter, indexer, or REST replacement for privacy-state reads. */
  privacyStateAdapter?: PrivacyStateAdapter;
}

export interface QueryRetryOptions {
  retries?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  jitter?: boolean;
  retryStatuses?: number[];
}

export interface ReserveResponse {
  denom: string;
  module_balance: string;
  total_deposited: string;
  total_withdrawn: string;
  expected_module_balance: string;
  invariant_holds: boolean;
}

export function eventAttribute(event: object, key: string): string;
export function isAuditableTransfer(event: object): boolean;

export class ClairveilPublicClient {
  constructor(options: ClairveilPublicClientOptions);
  rest: string;
  restEndpoints: string[];
  activeRestEndpoint: string;
  privacyStateAdapter: Readonly<PrivacyStateAdapter> | null;
  restUrl(path: string, endpoint?: string): string;
  fetchJson<T = object>(pathOrUrl: string, options?: {
    method?: string;
    body?: BodyInit | null;
    headers?: Record<string, string>;
    failover?: boolean;
    endpoint?: string;
    updateActiveEndpoint?: boolean;
  }): Promise<T>;
  fetchNullifierJson<T = object>(path: string, options?: {
    method?: string;
    body?: BodyInit | null;
    headers?: Record<string, string>;
  }): Promise<T>;
  fetchMerklePathJson<T = object>(path: string, options?: {
    method?: string;
    body?: BodyInit | null;
    headers?: Record<string, string>;
  }): Promise<T>;
  fetchPrivacyEvents(options?: PrivacyEventsQuery): Promise<object & { events?: object[] }>;
  fetchScanEvents(options?: PrivacyEventsQuery): Promise<object & { events?: object[] }>;
  fetchPrivacyScan(options?: TypedPrivacyScanQuery): Promise<object>;
  queryPrivacyScan(options?: TypedPrivacyScanQuery): Promise<ValidatedPrivacyScanPageV2>;
  fetchTreeState(): Promise<object>;
  fetchCommitmentInfo(commitmentHex: string): Promise<object>;
  lookupMerklePath(commitmentHex: string): Promise<object>;
  checkNullifier(nullifierHex: string): Promise<{ nullifier: string; used: boolean }>;
  checkNullifiers(nullifierHexes: readonly string[]): Promise<Map<string, boolean>>;
  fetchAuditableTransfers(options?: PrivacyEventsQuery): Promise<object & { events: object[] }>;
  fetchAuditableBatchTransfers(options?: TypedPrivacyScanQuery): Promise<ValidatedPrivacyScanPageV2>;
  fetchAuditConfig(): Promise<object>;
  fetchDisclosureConfig(): Promise<object>;
  queryAuditConfig(): Promise<ValidatedAuditConfigV1>;
  queryDisclosureConfig(): Promise<ValidatedDisclosureConfigV1>;
  fetchCircuitConfig(options?: { expectedCircuitIdentity?: ValidatedCircuitConfigV1["circuit_set_identity"] }): Promise<ValidatedCircuitConfigV1>;
  assertCircuitConfig(options?: { expectedCircuitIdentity?: ValidatedCircuitConfigV1["circuit_set_identity"] }): Promise<ValidatedCircuitConfigV1>;
  fetchReserve(denom: string): Promise<ReserveResponse>;
  queryReserve(denom: string): Promise<ValidatedReserveResponseV1>;
  fetchAssetByDenom(denom: string): Promise<object>;
  fetchAssetByID(assetIdHex: string): Promise<object>;
  queryAssetByDenom(denom: string): Promise<NormalizedAssetRegistryQueryResponseV1>;
  queryAssetByID(assetIdHex: string): Promise<NormalizedAssetRegistryQueryResponseV1>;
  resolveAsset(denom: string): Promise<NormalizedAssetRegistryEntryV1>;
  resolveAssetByDenom(denom: string): Promise<NormalizedAssetRegistryEntryV1>;
  resolveAssetByID(assetIdHex: string): Promise<NormalizedAssetRegistryEntryV1>;
  fetchCommitmentPathsAtRoot(options: CommitmentPathsAtRootQuery): Promise<object>;
  queryCommitmentPathsAtRoot(options: CommitmentPathsAtRootQuery): Promise<VerifiedCommitmentPathSnapshot>;
  createCommitmentPathSnapshotProvider(options: CommitmentPathsAtRootQuery): Promise<{
    lookupMerklePath(commitmentHex: string): Promise<object>;
  }>;
}

export function createClairveilPublicClient(options: ClairveilPublicClientOptions): ClairveilPublicClient;
