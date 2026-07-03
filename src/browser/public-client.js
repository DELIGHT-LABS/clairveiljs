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

function normalizeRestEndpoints(primary, restEndpoints = []) {
  const endpoints = [];
  for (const endpoint of [primary, ...(Array.isArray(restEndpoints) ? restEndpoints : [])]) {
    const normalized = trimTrailingSlash(endpoint);
    if (normalized && !endpoints.includes(normalized)) {
      endpoints.push(normalized);
    }
  }
  if (!endpoints.length) {
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

async function fetchJson(url, { timeoutMs = defaultFetchTimeoutMs } = {}) {
  const resolvedTimeoutMs = normalizeTimeoutMs(timeoutMs, "fetch timeoutMs");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), resolvedTimeoutMs);
  try {
    const response = await fetch(url, {
      headers: { accept: "application/json" },
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
      const timeoutError = new Error(`fetch request timed out after ${resolvedTimeoutMs}ms: ${url}`);
      timeoutError.code = "FETCH_TIMEOUT";
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchJsonWithRetry(urlForEndpoint, endpoints, { timeoutMs, retry } = {}) {
  const normalizedRetry = normalizeQueryRetry(retry);
  let lastError = null;
  for (const endpoint of endpoints) {
    for (let attempt = 0; attempt <= normalizedRetry.retries; attempt += 1) {
      try {
        return {
          data: await fetchJson(urlForEndpoint(endpoint), { timeoutMs }),
          endpoint
        };
      } catch (error) {
        lastError = error;
        const retryable = isRetryableFetchError(error, normalizedRetry);
        if (!retryable) {
          throw error;
        }
        const canRetry = attempt < normalizedRetry.retries && retryable;
        if (!canRetry) break;
        await sleep(retryDelayMs(attempt + 1, normalizedRetry));
      }
    }
  }
  throw lastError;
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

export function eventAttribute(event, key) {
  return (event?.attributes || []).find(attribute => attribute.key === key)?.value || "";
}

export function isAuditableTransfer(event) {
  return event?.event_type === "shielded_transfer" && Boolean(eventAttribute(event, "audit_disclosure_payload"));
}

export class ClairveilPublicClient {
  constructor({ rest, restEndpoints, queryTimeoutMs = defaultFetchTimeoutMs, fetchTimeoutMs, queryRetry } = {}) {
    this.restEndpoints = normalizeRestEndpoints(rest, restEndpoints);
    this.rest = this.restEndpoints[0];
    this.activeRestEndpoint = this.rest;
    this.queryTimeoutMs = normalizeTimeoutMs(fetchTimeoutMs ?? queryTimeoutMs, "queryTimeoutMs");
    this.queryRetry = normalizeQueryRetry(queryRetry);
  }

  restUrl(path, endpoint = this.activeRestEndpoint) {
    return `${endpoint}${path.startsWith("/") ? path : `/${path}`}`;
  }

  async fetchJson(pathOrUrl) {
    const text = String(pathOrUrl || "");
    const isAbsolute = /^https?:\/\//i.test(text);
    if (isAbsolute) {
      const result = await fetchJsonWithRetry(
        url => url,
        [text],
        {
          timeoutMs: this.queryTimeoutMs,
          retry: this.queryRetry
        }
      );
      return result.data;
    }
    const path = text;
    const endpoints = [this.activeRestEndpoint, ...this.restEndpoints.filter(endpoint => endpoint !== this.activeRestEndpoint)];
    const result = await fetchJsonWithRetry(
      endpoint => this.restUrl(path, endpoint),
      endpoints,
      {
        timeoutMs: this.queryTimeoutMs,
        retry: this.queryRetry
      }
    );
    this.activeRestEndpoint = result.endpoint;
    return result.data;
  }

  async fetchPrivacyEvents(options = {}) {
    return this.fetchJson(`/clairveil/privacy/v1/events${privacyEventsQuery(options)}`);
  }

  async fetchAuditableTransfers(options = {}) {
    const data = await this.fetchPrivacyEvents(options);
    return {
      ...data,
      events: (data.events || []).filter(isAuditableTransfer)
    };
  }

  async fetchReserve(denom) {
    const normalizedDenom = String(denom || "").trim();
    if (!normalizedDenom) {
      throw new Error("reserve denom is required");
    }
    return this.fetchJson(`/clairveil/privacy/v1/reserve/${encodeURIComponent(normalizedDenom)}`);
  }
}

export function createClairveilPublicClient(options) {
  return new ClairveilPublicClient(options);
}
