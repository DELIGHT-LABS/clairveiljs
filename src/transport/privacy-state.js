/**
 * Transport-neutral privacy-state query contract.
 *
 * Adapters return the same untrusted response shapes as Clairveil REST. The
 * SDK deliberately keeps schema, circuit, asset, Merkle, scan, and reserve
 * validation above this boundary so a contract getter or indexer cannot
 * bypass the fail-closed checks used by the built-in REST transport.
 */

import { parseNullifierUsage } from "../privacy/scan.js";

function privacyStateAdapterTimeoutMs(value) {
  const timeoutMs = Number(value);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("PrivacyStateAdapter timeoutMs must be positive");
  }
  return timeoutMs;
}

function privacyStateAdapterRetry(value = {}) {
  const retry = value || {};
  const retries = Number(retry.retries ?? 0);
  const baseDelayMs = Number(retry.baseDelayMs ?? 0);
  const maxDelayMs = Number(retry.maxDelayMs ?? baseDelayMs);
  if (!Number.isSafeInteger(retries) || retries < 0) {
    throw new Error("PrivacyStateAdapter retries must be a non-negative integer");
  }
  if (!Number.isFinite(baseDelayMs) || baseDelayMs < 0 ||
      !Number.isFinite(maxDelayMs) || maxDelayMs < 0) {
    throw new Error("PrivacyStateAdapter retry delays must be non-negative");
  }
  return {
    retries,
    baseDelayMs,
    maxDelayMs,
    jitter: retry.jitter === true,
    retryStatuses: retry.retryStatuses instanceof Set
      ? retry.retryStatuses
      : new Set(retry.retryStatuses || [])
  };
}

function privacyStateAdapterRetryDelayMs(attemptNumber, retry) {
  const base = retry.baseDelayMs * (attemptNumber <= 1 ? 1 : 3 ** (attemptNumber - 1));
  const capped = Math.min(retry.maxDelayMs, base);
  if (!retry.jitter || capped <= 0) return capped;
  return Math.round(capped + (Math.random() * capped * 0.2));
}

function privacyStateAdapterErrorIsRetryable(error, retry) {
  if (error?.code === "PRIVACY_STATE_ADAPTER_TIMEOUT") return true;
  if (error?.status != null) {
    return retry.retryStatuses.has(Number(error.status));
  }
  return true;
}

function sleep(ms) {
  return ms > 0 ? new Promise(resolve => setTimeout(resolve, ms)) : Promise.resolve();
}

function clonePrivacyStateAdapterValue(value, seen = new Map()) {
  if (value == null || typeof value !== "object") return value;
  if (seen.has(value)) return seen.get(value);
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (value instanceof ArrayBuffer) return value.slice(0);
  if (ArrayBuffer.isView(value)) {
    return new value.constructor(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  if (value instanceof Date) return new Date(value.getTime());
  if (value instanceof Map) {
    const cloned = new Map();
    seen.set(value, cloned);
    for (const [key, item] of value) {
      cloned.set(
        clonePrivacyStateAdapterValue(key, seen),
        clonePrivacyStateAdapterValue(item, seen)
      );
    }
    return cloned;
  }
  if (value instanceof Set) {
    const cloned = new Set();
    seen.set(value, cloned);
    for (const item of value) cloned.add(clonePrivacyStateAdapterValue(item, seen));
    return cloned;
  }
  if (Array.isArray(value)) {
    const cloned = [];
    seen.set(value, cloned);
    for (const item of value) cloned.push(clonePrivacyStateAdapterValue(item, seen));
    return cloned;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return value;
  const cloned = {};
  seen.set(value, cloned);
  for (const [key, item] of Object.entries(value)) {
    cloned[key] = clonePrivacyStateAdapterValue(item, seen);
  }
  return cloned;
}

function clonePrivacyStateAdapterArguments(args) {
  return (args || []).map(value => clonePrivacyStateAdapterValue(value));
}

function invokeWithTimeout(method, invoke, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      const error = new Error(`PrivacyStateAdapter.${method} timed out after ${timeoutMs}ms`);
      error.code = "PRIVACY_STATE_ADAPTER_TIMEOUT";
      reject(error);
    }, timeoutMs);
    Promise.resolve()
      .then(invoke)
      .then(
        value => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          resolve(value);
        },
        error => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          reject(error);
        }
      );
  });
}

export const privacyStateAdapterRequiredMethods = Object.freeze([
  "fetchPrivacyScan",
  "fetchTreeState",
  "fetchCommitmentInfo",
  "lookupMerklePath",
  "fetchAuditConfig",
  "fetchDisclosureConfig",
  "fetchCircuitConfig",
  "fetchReserve",
  "fetchAssetByDenom",
  "fetchAssetByID",
  "fetchCommitmentPathsAtRoot",
  "checkNullifiers"
]);

export const privacyStateAdapterOptionalMethods = Object.freeze([
  "fetchPrivacyEvents",
  "fetchScanEvents",
  "checkNullifier"
]);

export const privacyStateAdapterMethods = Object.freeze([
  ...privacyStateAdapterRequiredMethods,
  ...privacyStateAdapterOptionalMethods
]);

/**
 * Validate and bind a complete PrivacyStateAdapter implementation.
 *
 * Methods are bound to the original adapter instance so class-based chain
 * adapters can safely keep their own RPC/indexer clients as instance state.
 */
export function createPrivacyStateAdapter(adapter) {
  if (!adapter || (typeof adapter !== "object" && typeof adapter !== "function")) {
    throw new TypeError("privacyStateAdapter must be an object");
  }
  const missing = privacyStateAdapterRequiredMethods.filter(
    method => typeof adapter[method] !== "function"
  );
  if (missing.length) {
    throw new TypeError(`privacyStateAdapter is missing required methods: ${missing.join(", ")}`);
  }
  const normalized = {};
  for (const method of privacyStateAdapterMethods) {
    if (adapter[method] == null) continue;
    if (typeof adapter[method] !== "function") {
      throw new TypeError(`privacyStateAdapter.${method} must be a function`);
    }
    normalized[method] = adapter[method].bind(adapter);
  }
  return Object.freeze(normalized);
}

/**
 * Invoke one read-only adapter method with the same bounded timeout and retry
 * policy used by the built-in REST query transport. Retries stay on the same
 * adapter instance and never introduce cross-provider privacy failover.
 */
export async function invokePrivacyStateAdapter(adapter, method, args = [], {
  timeoutMs,
  retry
} = {}) {
  const adapterMethod = adapter?.[method];
  if (typeof adapterMethod !== "function") {
    throw new TypeError(`PrivacyStateAdapter.${method} must be a function`);
  }
  const resolvedTimeoutMs = privacyStateAdapterTimeoutMs(timeoutMs);
  const resolvedRetry = privacyStateAdapterRetry(retry);
  let lastError = null;
  for (let attempt = 0; attempt <= resolvedRetry.retries; attempt += 1) {
    try {
      return await invokeWithTimeout(
        method,
        // Adapter implementations are transport code, not owners of the SDK's
        // cursor, validation state, or expected-nullifier collections. Give
        // every attempt an isolated snapshot so response validation cannot be
        // weakened by argument mutation and retries cannot share mutations.
        () => adapterMethod(...clonePrivacyStateAdapterArguments(args)),
        resolvedTimeoutMs
      );
    } catch (error) {
      lastError = error;
      const canRetry = attempt < resolvedRetry.retries &&
        privacyStateAdapterErrorIsRetryable(error, resolvedRetry);
      if (!canRetry) throw error;
      await sleep(privacyStateAdapterRetryDelayMs(attempt + 1, resolvedRetry));
    }
  }
  throw lastError;
}

/** Normalize a transport-specific batch response into one complete status map. */
export function normalizePrivacyNullifierStatuses(response, requestedNullifiers) {
  const normalizedRequested = [...new Set((requestedNullifiers || [])
    .map(value => String(value || "").trim().toLowerCase())
    .filter(Boolean))];
  if (normalizedRequested.length === 0) return new Map();
  const requested = new Set(normalizedRequested);
  const statuses = new Map();
  const invalid = new Set();
  const addStatus = (nullifier, value) => {
    const key = String(nullifier || "").trim().toLowerCase();
    if (!requested.has(key) || invalid.has(key)) return;
    const used = parseNullifierUsage(value);
    if (used === null || (statuses.has(key) && statuses.get(key) !== used)) {
      statuses.delete(key);
      invalid.add(key);
      return;
    }
    statuses.set(key, used);
  };

  if (response instanceof Map) {
    for (const [nullifier, value] of response) addStatus(nullifier, value);
  } else if (response && typeof response === "object" &&
      (Array.isArray(response.statuses) || Array.isArray(response.Statuses))) {
    for (const status of [
      ...(Array.isArray(response.statuses) ? response.statuses : []),
      ...(Array.isArray(response.Statuses) ? response.Statuses : [])
    ]) {
      const canonical = status?.nullifier;
      const alias = status?.Nullifier;
      if (canonical != null && alias != null &&
          String(canonical).trim().toLowerCase() !== String(alias).trim().toLowerCase()) {
        addStatus(canonical, null);
        addStatus(alias, null);
      } else {
        addStatus(canonical ?? alias, status);
      }
    }
  } else if (response && typeof response === "object" && !Array.isArray(response)) {
    for (const [nullifier, value] of Object.entries(response)) addStatus(nullifier, value);
  } else {
    throw new Error("privacyStateAdapter.checkNullifiers returned an unsupported status shape");
  }

  const unresolved = normalizedRequested.filter(
    nullifier => invalid.has(nullifier) || !statuses.has(nullifier)
  );
  if (unresolved.length) {
    throw new Error(`privacyStateAdapter.checkNullifiers did not return one unambiguous status for: ${unresolved.join(", ")}`);
  }
  return new Map(normalizedRequested.map(nullifier => [nullifier, statuses.get(nullifier)]));
}

export const privacyNullifierBatchLimit = 1000;

/**
 * Query adapter-backed nullifier state in the same bounded batches as the
 * canonical REST transport, validating every batch before combining it.
 */
export async function checkPrivacyStateAdapterNullifiers(adapter, nullifierHexes, options) {
  const normalized = [...new Set((nullifierHexes || [])
    .map(value => String(value || "").trim().toLowerCase())
    .filter(Boolean))];
  if (normalized.length === 0) return new Map();
  const statuses = new Map();
  for (let start = 0; start < normalized.length; start += privacyNullifierBatchLimit) {
    const chunk = normalized.slice(start, start + privacyNullifierBatchLimit);
    const response = await invokePrivacyStateAdapter(
      adapter,
      "checkNullifiers",
      [chunk],
      options
    );
    for (const [nullifier, used] of normalizePrivacyNullifierStatuses(response, chunk)) {
      statuses.set(nullifier, used);
    }
  }
  return new Map(normalized.map(nullifier => [nullifier, statuses.get(nullifier)]));
}
