import {
  parseNullifierUsage,
  validatePrivacyScanPageV2
} from "../privacy/scan.js";
import {
  createCommitmentPathSnapshotProvider,
  normalizeCommitmentPathsAtRootRequest,
  normalizeCommitmentPathsAtRootResponse
} from "../privacy/merkle-path.js";
import {
  canonicalAssetDenomV1,
  canonicalAssetIDHexV1,
  normalizeAssetRegistryQueryResponseV1
} from "../privacy/asset-registry.js";
import {
  normalizeAuditConfigV1,
  normalizeDisclosureConfigV1,
  normalizeReserveResponseV1
} from "../privacy/network-config.js";
import { validateCircuitConfigV1 } from "../privacy/circuit-config.js";
import {
  checkPrivacyStateAdapterNullifiers,
  createPrivacyStateAdapter,
  invokePrivacyStateAdapter,
  normalizePrivacyNullifierStatuses
} from "../transport/privacy-state.js";

function trimTrailingSlash(value) {
  return String(value || "").replace(/\/$/, "");
}

const defaultFetchTimeoutMs = 30000;
const defaultRetryStatuses = Object.freeze([408, 429, 502, 503, 504]);
const defaultQueryRetry = Object.freeze({
  retries: 2,
  baseDelayMs: 250,
  maxDelayMs: 1500,
  jitter: true,
  retryStatuses: defaultRetryStatuses
});

function normalizeTimeoutMs(value, label = "timeoutMs") {
  const timeoutMs = Number(value);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error(`${label} must be positive`);
  }
  return timeoutMs;
}

function normalizeRestEndpoints(primary, restEndpoints = [], { allowEmpty = false } = {}) {
  const endpoints = [];
  for (const endpoint of [primary, ...(Array.isArray(restEndpoints) ? restEndpoints : [])]) {
    const normalized = trimTrailingSlash(endpoint);
    if (normalized && !endpoints.includes(normalized)) {
      endpoints.push(normalized);
    }
  }
  if (!endpoints.length && !allowEmpty) {
    throw new Error("rest endpoint is required");
  }
  return endpoints;
}

function normalizeQueryRetry(value = {}) {
  if (value === false) {
    return {
      retries: 0,
      baseDelayMs: defaultQueryRetry.baseDelayMs,
      maxDelayMs: defaultQueryRetry.maxDelayMs,
      jitter: false,
      retryStatuses: new Set(defaultRetryStatuses)
    };
  }
  const retry = value || {};
  const retries = Number(retry.retries ?? defaultQueryRetry.retries);
  const baseDelayMs = Number(retry.baseDelayMs ?? defaultQueryRetry.baseDelayMs);
  const maxDelayMs = Number(retry.maxDelayMs ?? defaultQueryRetry.maxDelayMs);
  if (!Number.isSafeInteger(retries) || retries < 0) throw new Error("queryRetry.retries must be a non-negative integer");
  if (!Number.isFinite(baseDelayMs) || baseDelayMs < 0) throw new Error("queryRetry.baseDelayMs must be non-negative");
  if (!Number.isFinite(maxDelayMs) || maxDelayMs < 0) throw new Error("queryRetry.maxDelayMs must be non-negative");
  return {
    retries,
    baseDelayMs,
    maxDelayMs,
    jitter: retry.jitter ?? defaultQueryRetry.jitter,
    retryStatuses: new Set(retry.retryStatuses ?? defaultRetryStatuses)
  };
}

function retryDelayMs(attemptNumber, retry) {
  const base = retry.baseDelayMs * (attemptNumber <= 1 ? 1 : 3 ** (attemptNumber - 1));
  const capped = Math.min(retry.maxDelayMs, base);
  if (!retry.jitter || capped <= 0) return capped;
  return Math.round(capped + (Math.random() * capped * 0.2));
}

function sleep(ms) {
  return ms > 0 ? new Promise(resolve => setTimeout(resolve, ms)) : Promise.resolve();
}

function isRetryableFetchError(error, retry) {
  if (error?.name === "AbortError" || error?.code === "FETCH_TIMEOUT") return true;
  if (error?.status != null) return retry.retryStatuses.has(Number(error.status));
  return true;
}

async function fetchJson(url, { timeoutMs = defaultFetchTimeoutMs, method = "GET", body, headers } = {}) {
  const resolvedTimeoutMs = normalizeTimeoutMs(timeoutMs, "fetch timeoutMs");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), resolvedTimeoutMs);
  try {
    const response = await fetch(url, {
      method,
      headers: {
        accept: "application/json",
        ...(body != null ? { "content-type": "application/json" } : {}),
        ...(headers || {})
      },
      body,
      signal: controller.signal
    });
    if (!response.ok) {
      const error = new Error(`${response.status} ${response.statusText}`);
      error.status = response.status;
      error.statusText = response.statusText;
      throw error;
    }
    return response.json();
  } catch (error) {
    if (error?.name === "AbortError") {
      const timeoutError = new Error(`fetch request timed out after ${resolvedTimeoutMs}ms`);
      timeoutError.code = "FETCH_TIMEOUT";
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchJsonWithRetry(urlForEndpoint, endpoints, {
  timeoutMs,
  retry,
  method,
  body,
  headers,
  failoverStatuses = []
} = {}) {
  const normalizedRetry = normalizeQueryRetry(retry);
  const normalizedFailoverStatuses = new Set(failoverStatuses || []);
  let lastError = null;
  let lastNonCapabilityError = null;
  for (let endpointIndex = 0; endpointIndex < endpoints.length; endpointIndex += 1) {
    const endpoint = endpoints[endpointIndex];
    for (let attempt = 0; attempt <= normalizedRetry.retries; attempt += 1) {
      try {
        return {
          data: await fetchJson(urlForEndpoint(endpoint), { timeoutMs, method, body, headers }),
          endpoint
        };
      } catch (error) {
        lastError = error;
        if (normalizedFailoverStatuses.has(Number(error?.status))) {
          if (endpointIndex < endpoints.length - 1) break;
          throw lastNonCapabilityError || error;
        }
        const retryable = isRetryableFetchError(error, normalizedRetry);
        if (!retryable) {
          throw error;
        }
        lastNonCapabilityError = error;
        const canRetry = attempt < normalizedRetry.retries && retryable;
        if (!canRetry) break;
        await sleep(retryDelayMs(attempt + 1, normalizedRetry));
      }
    }
  }
  throw lastNonCapabilityError || lastError;
}

function privacyEventsQuery({
  afterHeight,
  after_height,
  page,
  limit,
  eventTypes,
  event_types
} = {}) {
  const params = new URLSearchParams();
  const resolvedAfterHeight = afterHeight ?? after_height;
  if (resolvedAfterHeight != null) {
    params.set("after_height", String(resolvedAfterHeight));
  }
  if (page != null) {
    params.set("page", String(page));
  }
  if (limit != null) {
    params.set("limit", String(limit));
  }
  const resolvedEventTypes = eventTypes ?? event_types;
  if (Array.isArray(resolvedEventTypes)) {
    for (const eventType of resolvedEventTypes) {
      if (String(eventType || "").trim()) {
        params.append("event_types", String(eventType).trim());
      }
    }
  } else if (resolvedEventTypes != null && String(resolvedEventTypes).trim()) {
    params.set("event_types", String(resolvedEventTypes).trim());
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

function scanEventsQuery({
  afterHeight,
  after_height,
  afterSequence,
  after_sequence,
  limit,
  eventTypes,
  event_types
} = {}) {
  const params = new URLSearchParams();
  const resolvedAfterHeight = afterHeight ?? after_height;
  if (resolvedAfterHeight != null) {
    params.set("after_height", String(resolvedAfterHeight));
  }
  const resolvedAfterSequence = afterSequence ?? after_sequence;
  if (resolvedAfterSequence != null) {
    params.set("after_sequence", String(resolvedAfterSequence));
  }
  if (limit != null) {
    params.set("limit", String(limit));
  }
  const resolvedEventTypes = eventTypes ?? event_types;
  if (Array.isArray(resolvedEventTypes)) {
    for (const eventType of resolvedEventTypes) {
      if (String(eventType || "").trim()) {
        params.append("event_types", String(eventType).trim());
      }
    }
  } else if (resolvedEventTypes != null && String(resolvedEventTypes).trim()) {
    params.set("event_types", String(resolvedEventTypes).trim());
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

function jsonRequestBody(value) {
  return JSON.stringify(value, (_key, item) => typeof item === "bigint" ? item.toString() : item);
}

function privacyScanRequestBody(options = {}) {
  const after = options.after;
  const cursor = after && typeof after === "object"
    ? {
      height: after.height ?? 0,
      globalSequence: after.globalSequence ?? after.global_sequence ?? 0,
      outputIndex: after.outputIndex ?? after.output_index ?? 0
    }
    : undefined;
  const outputLimit = options.outputLimit ?? options.output_limit;
  const eventLimit = options.eventLimit ?? options.event_limit;
  const maxEncodedBytes = options.maxEncodedBytes ?? options.max_encoded_bytes;
  const eventTypes = options.eventTypes ?? options.event_types;
  return {
    ...(cursor ? { after: cursor } : {}),
    ...(outputLimit != null ? { outputLimit } : {}),
    ...(eventLimit != null ? { eventLimit } : {}),
    ...(maxEncodedBytes != null ? { maxEncodedBytes } : {}),
    ...(eventTypes != null ? { eventTypes } : {})
  };
}

function commitmentPathsAtRootRequestBody(options = {}) {
  const commitments = options.commitmentHexes ?? options.commitment_hexes;
  if (!Array.isArray(commitments) || commitments.length === 0 || commitments.length > 16) {
    throw new Error("commitmentHexes must contain 1..16 commitments");
  }
  const rootHex = String(options.rootHex ?? options.root_hex ?? "").trim();
  if (!rootHex) throw new Error("rootHex is required");
  const snapshotHeight = options.snapshotHeight ?? options.snapshot_height;
  return {
    commitmentHexes: commitments.map(value => String(value || "").trim()),
    rootHex,
    ...(snapshotHeight == null || String(snapshotHeight).trim() === "" ? {} : { snapshotHeight })
  };
}

export function eventAttribute(event, key) {
  return (event?.attributes || []).find(attribute => attribute.key === key)?.value || "";
}

export function isAuditableTransfer(event) {
  return event?.event_type === "shielded_transfer" && Boolean(eventAttribute(event, "audit_disclosure_payload"));
}

export class ClairveilPublicClient {
  constructor({ rest, restEndpoints, queryTimeoutMs = defaultFetchTimeoutMs, fetchTimeoutMs, queryRetry, nullifierFailover = false, merklePathFailover = false, privacyStateAdapter } = {}) {
    this.privacyStateAdapter = privacyStateAdapter == null
      ? null
      : createPrivacyStateAdapter(privacyStateAdapter);
    this.restEndpoints = normalizeRestEndpoints(rest, restEndpoints, {
      allowEmpty: Boolean(this.privacyStateAdapter)
    });
    this.rest = this.restEndpoints[0] || "";
    this.activeRestEndpoint = this.rest;
    this.queryTimeoutMs = normalizeTimeoutMs(fetchTimeoutMs ?? queryTimeoutMs, "queryTimeoutMs");
    this.queryRetry = normalizeQueryRetry(queryRetry);
    this.nullifierFailover = Boolean(nullifierFailover);
    this.merklePathFailover = Boolean(merklePathFailover);
  }

  restUrl(path, endpoint = this.activeRestEndpoint) {
    if (!endpoint) {
      throw new Error("rest endpoint is required for this query; implement the corresponding PrivacyStateAdapter method");
    }
    return `${endpoint}${path.startsWith("/") ? path : `/${path}`}`;
  }

  async queryPrivacyStateAdapter(method, args, restQuery) {
    const adapterMethod = this.privacyStateAdapter?.[method];
    if (typeof adapterMethod === "function") {
      return invokePrivacyStateAdapter(this.privacyStateAdapter, method, args, {
        timeoutMs: this.queryTimeoutMs,
        retry: this.queryRetry
      });
    }
    if (!this.restEndpoints.length) {
      throw new Error(`PrivacyStateAdapter.${method} is required because no REST endpoint is configured`);
    }
    return restQuery();
  }

  async fetchJson(pathOrUrl, {
    method,
    body,
    headers,
    failover = true,
    endpoint,
    updateActiveEndpoint = endpoint == null,
    failoverStatuses
  } = {}) {
    const text = String(pathOrUrl || "");
    const isAbsolute = /^https?:\/\//i.test(text);
    if (isAbsolute) {
      const result = await fetchJsonWithRetry(
        url => url,
        [text],
        {
          timeoutMs: this.queryTimeoutMs,
          retry: this.queryRetry,
          method,
          body,
          headers,
          failoverStatuses
        }
      );
      return result.data;
    }
    const path = text;
    const initialEndpoint = endpoint || this.activeRestEndpoint;
    if (!initialEndpoint) throw new Error("rest endpoint is required for this query");
    const endpoints = failover
      ? [initialEndpoint, ...this.restEndpoints.filter(candidate => candidate !== initialEndpoint)]
      : [initialEndpoint];
    const result = await fetchJsonWithRetry(
      endpoint => this.restUrl(path, endpoint),
      endpoints,
      {
        timeoutMs: this.queryTimeoutMs,
        retry: this.queryRetry,
        method,
        body,
        headers,
        failoverStatuses
      }
    );
    if (updateActiveEndpoint) this.activeRestEndpoint = result.endpoint;
    return result.data;
  }

  async fetchNullifierJson(path, options = {}) {
    return this.fetchJson(path, {
      ...options,
      failover: this.nullifierFailover,
      // Normal queries may fail over. Sensitive nullifier queries stay on the
      // configured endpoint unless the caller explicitly opted into failover.
      ...(this.nullifierFailover ? {} : {
        endpoint: this.rest,
        updateActiveEndpoint: false
      })
    });
  }

  async fetchMerklePathJson(path, options = {}) {
    return this.fetchJson(path, {
      ...options,
      failover: this.merklePathFailover,
      // Merkle witnesses reveal the commitments a wallet is attempting to
      // spend. Keep those requests on the configured endpoint unless the
      // application explicitly accepts cross-endpoint disclosure.
      ...(this.merklePathFailover ? {} : {
        endpoint: this.rest,
        updateActiveEndpoint: false
      })
    });
  }

  async fetchPrivacyEvents(options = {}) {
    return this.queryPrivacyStateAdapter(
      "fetchPrivacyEvents",
      [options],
      () => this.fetchJson(`/clairveil/privacy/v1/events${privacyEventsQuery(options)}`)
    );
  }

  async fetchScanEvents(options = {}) {
    return this.queryPrivacyStateAdapter(
      "fetchScanEvents",
      [options],
      () => this.fetchJson(`/clairveil/privacy/v1/scan_events${scanEventsQuery(options)}`)
    );
  }

  async fetchPrivacyScan(options = {}) {
    return this.queryPrivacyStateAdapter(
      "fetchPrivacyScan",
      [options],
      () => this.fetchJson("/clairveil/privacy/v1/privacy_scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: jsonRequestBody(privacyScanRequestBody(options)),
        failoverStatuses: [404, 405, 501]
      })
    );
  }

  /** Fetch a typed privacy-scan-v2 page and fail closed before it is consumed. */
  async queryPrivacyScan(options = {}) {
    const {
      validationState,
      validation_state,
      ...request
    } = options || {};
    return validatePrivacyScanPageV2(
      await this.fetchPrivacyScan(request),
      {
        ...request,
        ...(validationState ?? validation_state
          ? { validationState: validationState ?? validation_state }
          : {})
      }
    );
  }

  async fetchTreeState() {
    return this.queryPrivacyStateAdapter(
      "fetchTreeState",
      [],
      () => this.fetchJson("/clairveil/privacy/v1/tree_state")
    );
  }

  async fetchCommitmentInfo(commitmentHex) {
    const normalized = String(commitmentHex || "").trim();
    if (!normalized) throw new Error("commitment is required");
    return this.queryPrivacyStateAdapter(
      "fetchCommitmentInfo",
      [normalized],
      () => this.fetchJson(`/clairveil/privacy/v1/commitment/${encodeURIComponent(normalized)}`)
    );
  }

  async lookupMerklePath(commitmentHex) {
    const normalized = String(commitmentHex || "").trim();
    if (!normalized) throw new Error("commitment is required");
    return this.queryPrivacyStateAdapter(
      "lookupMerklePath",
      [normalized],
      () => this.fetchMerklePathJson(`/clairveil/privacy/v1/merkle_path/${encodeURIComponent(normalized)}`)
    );
  }

  async checkNullifier(nullifierHex) {
    const normalized = String(nullifierHex || "").trim().toLowerCase();
    if (this.privacyStateAdapter) {
      if (typeof this.privacyStateAdapter.checkNullifier === "function") {
        const result = await invokePrivacyStateAdapter(
          this.privacyStateAdapter,
          "checkNullifier",
          [normalized],
          { timeoutMs: this.queryTimeoutMs, retry: this.queryRetry }
        );
        const used = parseNullifierUsage(result);
        if (used === null) {
          throw new Error("privacyStateAdapter.checkNullifier returned an ambiguous status");
        }
        return { nullifier: normalized, used };
      }
      const statuses = normalizePrivacyNullifierStatuses(
        await invokePrivacyStateAdapter(
          this.privacyStateAdapter,
          "checkNullifiers",
          [[normalized]],
          { timeoutMs: this.queryTimeoutMs, retry: this.queryRetry }
        ),
        [normalized]
      );
      return { nullifier: normalized, used: statuses.get(normalized) };
    }
    const result = await this.fetchNullifierJson(
      `/clairveil/privacy/v1/nullifier/${encodeURIComponent(normalized)}`
    );
    const used = parseNullifierUsage(result);
    if (used === null) {
      throw new Error("nullifier response returned an ambiguous status");
    }
    return { nullifier: normalized, used };
  }

  async checkNullifiers(nullifierHexes = []) {
    const normalized = [...new Set((nullifierHexes || []).map(value => String(value || "").trim().toLowerCase()).filter(Boolean))];
    if (normalized.length === 0) return new Map();
    if (this.privacyStateAdapter) {
      return checkPrivacyStateAdapterNullifiers(
        this.privacyStateAdapter,
        normalized,
        { timeoutMs: this.queryTimeoutMs, retry: this.queryRetry }
      );
    }
    const usedByNullifier = new Map();
    const invalidNullifiers = new Set();
    const addStatus = (nullifier, value) => {
      const key = String(nullifier || "").trim().toLowerCase();
      if (!key || invalidNullifiers.has(key)) return;
      const used = parseNullifierUsage(value);
      if (used === null || (usedByNullifier.has(key) && usedByNullifier.get(key) !== used)) {
        usedByNullifier.delete(key);
        invalidNullifiers.add(key);
        return;
      }
      usedByNullifier.set(key, used);
    };
    for (let start = 0; start < normalized.length; start += 1000) {
      const response = await this.fetchNullifierJson("/clairveil/privacy/v1/nullifiers", {
        method: "POST",
        body: JSON.stringify({ nullifiers: normalized.slice(start, start + 1000) })
      });
      for (const status of [
        ...(Array.isArray(response?.statuses) ? response.statuses : []),
        ...(Array.isArray(response?.Statuses) ? response.Statuses : [])
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
    }
    return usedByNullifier;
  }

  async fetchAuditableTransfers(options = {}) {
    const data = await this.fetchPrivacyEvents(options);
    return {
      ...data,
      events: (data.events || []).filter(isAuditableTransfer)
    };
  }

  async fetchAuditableBatchTransfers(options = {}) {
    const requestedTypes = options.eventTypes ?? options.event_types;
    if (requestedTypes != null && (
      !Array.isArray(requestedTypes) ||
      requestedTypes.some(value => String(value || "").trim() !== "batch_transfer")
    )) {
      throw new Error("auditable batch transfer query only accepts the batch_transfer event type");
    }
    const {
      validationState,
      validation_state,
      ...transportOptions
    } = options || {};
    const request = { ...transportOptions, eventTypes: ["batch_transfer"] };
    delete request.event_types;
    const page = validatePrivacyScanPageV2(
      await this.fetchPrivacyScan(request),
      {
        ...request,
        ...(validationState ?? validation_state
          ? { validationState: validationState ?? validation_state }
          : {})
      }
    );
    if (page.summaries.some(summary => summary.event_type !== "batch_transfer") ||
        page.outputs.some(output => output.event_type !== "batch_transfer")) {
      throw new Error("auditable batch transfer response contains a non-batch event");
    }
    return page;
  }

  async fetchReserve(denom) {
    const normalizedDenom = String(denom || "").trim();
    if (!normalizedDenom) {
      throw new Error("reserve denom is required");
    }
    return this.queryPrivacyStateAdapter(
      "fetchReserve",
      [normalizedDenom],
      () => this.fetchJson(`/clairveil/privacy/v1/reserve/${encodeURIComponent(normalizedDenom)}`)
    );
  }

  async fetchAuditConfig() {
    return this.queryPrivacyStateAdapter("fetchAuditConfig", [], () => this.fetchJson("/clairveil/privacy/v1/audit_config"));
  }

  async fetchDisclosureConfig() {
    return this.queryPrivacyStateAdapter("fetchDisclosureConfig", [], () => this.fetchJson("/clairveil/privacy/v1/disclosure_config"));
  }

  async queryAuditConfig() {
    return normalizeAuditConfigV1(await this.fetchAuditConfig());
  }

  async queryDisclosureConfig() {
    return normalizeDisclosureConfigV1(await this.fetchDisclosureConfig());
  }

  async fetchCircuitConfig(options = {}) {
    return validateCircuitConfigV1(
      await this.queryPrivacyStateAdapter(
        "fetchCircuitConfig",
        [],
        () => this.fetchJson("/clairveil/privacy/v1/circuit_config")
      ),
      options
    );
  }

  async assertCircuitConfig(options = {}) {
    return this.fetchCircuitConfig(options);
  }

  async queryReserve(denom) {
    const canonicalDenom = canonicalAssetDenomV1(denom);
    return normalizeReserveResponseV1(await this.fetchReserve(canonicalDenom), canonicalDenom);
  }

  async fetchAssetByDenom(denom) {
    const canonicalDenom = String(denom || "").trim();
    if (!canonicalDenom) throw new Error("asset denom is required");
    return this.queryPrivacyStateAdapter(
      "fetchAssetByDenom",
      [canonicalDenom],
      () => this.fetchJson(`/clairveil/privacy/v1/assets/by_denom/${encodeURIComponent(canonicalDenom)}`)
    );
  }

  async fetchAssetByID(assetIdHex) {
    const canonicalAssetID = String(assetIdHex || "").trim();
    if (!canonicalAssetID) throw new Error("asset ID is required");
    return this.queryPrivacyStateAdapter(
      "fetchAssetByID",
      [canonicalAssetID],
      () => this.fetchJson(`/clairveil/privacy/v1/assets/by_id/${encodeURIComponent(canonicalAssetID)}`)
    );
  }

  /** Fetch and fail-closed validate an AssetRegistryV1 denom lookup. */
  async queryAssetByDenom(denom) {
    const canonicalDenom = canonicalAssetDenomV1(denom);
    return normalizeAssetRegistryQueryResponseV1(
      await this.fetchAssetByDenom(canonicalDenom),
      { canonical_denom: canonicalDenom }
    );
  }

  /** Fetch and fail-closed validate an AssetRegistryV1 reverse lookup. */
  async queryAssetByID(assetIdHex) {
    const canonicalAssetID = canonicalAssetIDHexV1(assetIdHex);
    return normalizeAssetRegistryQueryResponseV1(
      await this.fetchAssetByID(canonicalAssetID),
      { asset_id_hex: canonicalAssetID }
    );
  }

  /** Resolver shape consumed by one-proof payroll preparation. */
  async resolveAsset(denom) {
    return (await this.queryAssetByDenom(denom)).asset;
  }

  async resolveAssetByDenom(denom) {
    return this.resolveAsset(denom);
  }

  async resolveAssetByID(assetIdHex) {
    return (await this.queryAssetByID(assetIdHex)).asset;
  }

  async fetchCommitmentPathsAtRoot(options = {}) {
    return this.queryPrivacyStateAdapter(
      "fetchCommitmentPathsAtRoot",
      [options],
      () => this.fetchMerklePathJson("/clairveil/privacy/v1/commitment_paths_at_root", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: jsonRequestBody(commitmentPathsAtRootRequestBody(options))
      })
    );
  }

  async queryCommitmentPathsAtRoot(options = {}) {
    const request = normalizeCommitmentPathsAtRootRequest(options);
    const response = await this.fetchCommitmentPathsAtRoot(request);
    return normalizeCommitmentPathsAtRootResponse(response, request);
  }

  async createCommitmentPathSnapshotProvider(options = {}) {
    return createCommitmentPathSnapshotProvider(await this.queryCommitmentPathsAtRoot(options));
  }
}

export function createClairveilPublicClient(options) {
  return new ClairveilPublicClient(options);
}
