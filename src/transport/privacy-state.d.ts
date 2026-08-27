import type { Hex } from "../core/crypto.js";
import type { PrivacyScanValidationStateV2 } from "../privacy/scan.js";

export type PrivacyStateUint64CursorInput = number | bigint | string;
export interface PrivacyStateScanCursorInput {
  height?: PrivacyStateUint64CursorInput;
  globalSequence?: PrivacyStateUint64CursorInput;
  global_sequence?: PrivacyStateUint64CursorInput;
  outputIndex?: number;
  output_index?: number;
}
export interface PrivacyStateScanQuery {
  after?: PrivacyStateScanCursorInput;
  outputLimit?: number;
  output_limit?: number;
  eventLimit?: number;
  event_limit?: number;
  maxEncodedBytes?: PrivacyStateUint64CursorInput;
  max_encoded_bytes?: PrivacyStateUint64CursorInput;
  eventTypes?: string[];
  event_types?: string[];
  validationState?: PrivacyScanValidationStateV2;
  validation_state?: PrivacyScanValidationStateV2;
}

export type PrivacyStateAdapterResult<T = object> = T | Promise<T>;
export type PrivacyNullifierStatuses =
  | ReadonlyMap<string, boolean | object>
  | Record<string, boolean | object>
  | { statuses?: readonly object[]; Statuses?: readonly object[] };

/**
 * Transport-neutral source of untrusted Clairveil privacy state.
 *
 * Implementations may use REST, EVM contract getters, or an indexer. Return
 * raw values here: ClairveilJS applies the canonical v0.3.1 validators after
 * crossing this boundary.
 */
export interface PrivacyStateAdapter {
  fetchPrivacyScan(options?: PrivacyStateScanQuery): PrivacyStateAdapterResult<object>;
  fetchTreeState(): PrivacyStateAdapterResult<object>;
  fetchCommitmentInfo(commitmentHex: Hex | string): PrivacyStateAdapterResult<object>;
  lookupMerklePath(commitmentHex: Hex | string): PrivacyStateAdapterResult<object>;
  fetchAuditConfig(): PrivacyStateAdapterResult<object>;
  fetchDisclosureConfig(): PrivacyStateAdapterResult<object>;
  fetchCircuitConfig(options?: object): PrivacyStateAdapterResult<object>;
  fetchReserve(denom: string): PrivacyStateAdapterResult<object>;
  fetchAssetByDenom(denom: string): PrivacyStateAdapterResult<object>;
  fetchAssetByID(assetIdHex: Hex | string): PrivacyStateAdapterResult<object>;
  fetchCommitmentPathsAtRoot(options?: object): PrivacyStateAdapterResult<object>;
  checkNullifiers(nullifierHexes: readonly (Hex | string)[]): PrivacyStateAdapterResult<PrivacyNullifierStatuses>;
  /** Diagnostic raw-event API; wallet state must use fetchPrivacyScan. */
  fetchPrivacyEvents?(options?: object): PrivacyStateAdapterResult<object>;
  /** Diagnostic raw-event API; wallet state must use fetchPrivacyScan. */
  fetchScanEvents?(options?: object): PrivacyStateAdapterResult<object>;
  checkNullifier?(nullifierHex: Hex | string): PrivacyStateAdapterResult<object | boolean>;
}

export interface PrivacyStateAdapterInvocationOptions {
  timeoutMs: number;
  retry?: {
    retries?: number;
    baseDelayMs?: number;
    maxDelayMs?: number;
    jitter?: boolean;
    retryStatuses?: ReadonlySet<number> | readonly number[];
  };
}

export const privacyStateAdapterRequiredMethods: readonly (keyof PrivacyStateAdapter)[];
export const privacyStateAdapterOptionalMethods: readonly (keyof PrivacyStateAdapter)[];
export const privacyStateAdapterMethods: readonly (keyof PrivacyStateAdapter)[];
export function createPrivacyStateAdapter(adapter: PrivacyStateAdapter): Readonly<PrivacyStateAdapter>;
export function invokePrivacyStateAdapter<T = object>(
  adapter: Readonly<PrivacyStateAdapter>,
  method: keyof PrivacyStateAdapter,
  args: readonly unknown[] | undefined,
  options: PrivacyStateAdapterInvocationOptions
): Promise<T>;
export function normalizePrivacyNullifierStatuses(
  response: PrivacyNullifierStatuses,
  requestedNullifiers: readonly (Hex | string)[]
): Map<string, boolean>;
export const privacyNullifierBatchLimit: 1000;
export function checkPrivacyStateAdapterNullifiers(
  adapter: Readonly<PrivacyStateAdapter>,
  nullifierHexes: readonly (Hex | string)[],
  options: PrivacyStateAdapterInvocationOptions
): Promise<Map<string, boolean>>;
