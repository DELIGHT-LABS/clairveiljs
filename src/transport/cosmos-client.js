import { toBech32 } from "@cosmjs/encoding";
import { Registry, encodePubkey, makeAuthInfoBytes, makeSignDoc } from "@cosmjs/proto-signing";
import { defaultRegistryTypes, StargateClient } from "@cosmjs/stargate";
import { TxBody, TxRaw } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import {
  MsgDeposit as GeneratedMsgDeposit,
  MsgTransfer as GeneratedMsgTransfer,
  MsgWithdraw as GeneratedMsgWithdraw,
  UserDisclosureMode
} from "../generated/clairveil/privacy/v1/tx.js";
import {
  bytesFromHex,
  defaultAccountPrefix,
  derivePrivacyMaterial,
  normalizeBech32Prefix
} from "../core/crypto.js";
import {
  decodeAuditDisclosureFromEvent,
  decodeSelfViewDisclosureFromEvent,
  decodeUserDisclosureFromEvent,
  disclosureScalarFromHex
} from "../core/disclosure.js";
import {
  buildDepositMaterial as buildDepositMaterialCore,
  defaultAssetDenom,
  parseCoin
} from "../core/note.js";
import {
  buildPreparedTransferPayload as buildPreparedTransferPayloadCore,
  buildTransferMessage as buildTransferMessageCore,
  buildPreparedWithdrawProverPayload as buildPreparedWithdrawProverPayloadCore,
  buildRelayWithdrawMsgFromPayload as buildRelayWithdrawMsgFromPayloadCore,
  buildRelayWithdrawPayload as buildRelayWithdrawPayloadCore,
  buildWithdrawMessage as buildWithdrawMessageCore,
  validateRelayWithdrawPayload
} from "../privacy/payload.js";
import {
  assertPlanCanBuildTx,
  planTransferBatchNotes,
  planTransferNotes,
  planWithdrawNotes
} from "../privacy/planner.js";
import {
  preparePlanReservation,
  reservationHeartbeatIntervalMs,
  reservationStatuses,
  rollbackPlanReservation,
  rollbackPlanReservationPreservingError
} from "../privacy/reservation.js";
import { parseNullifierUsage, scanNotes as scanNotesCore } from "../privacy/scan.js";
import {
  createWalletAdapter,
  derivePrivacyMaterialFromWallet
} from "../wallet/adapter.js";
import {
  base64FromBytes,
  bytesFromBase64,
  bytesFromHex as rawBytesFromHex,
  hash160,
  hexFromBytes,
  sha256Hex
} from "../core/browser-crypto.js";

export * from "../core/crypto.js";
export * from "../core/disclosure.js";
export * from "../core/errors.js";
export * from "../core/note.js";
export * from "../privacy/payload.js";
export * from "../privacy/planner.js";
export * from "../privacy/prover.js";

function appendReservationCleanupErrors(error, cleanupErrors = []) {
  if (!cleanupErrors.length || !error || typeof error !== "object") return;
  try {
    const existing = Array.isArray(error.reservationCleanupErrors)
      ? error.reservationCleanupErrors
      : [];
    error.reservationCleanupErrors = [...existing, ...cleanupErrors];
  } catch {
    // Cleanup annotations are best-effort and must never replace the original error.
  }
}
export * from "../privacy/reservation.js";
export * from "../privacy/scan.js";
export * from "../privacy/note-store.js";
export * from "../core/schemas.js";
export * from "../wallet/adapter.js";
export {
  userDisclosureModeFromJSON,
  userDisclosureModeToJSON
} from "../generated/clairveil/privacy/v1/tx.js";

export const msgDepositTypeUrl = GeneratedMsgDeposit.typeUrl;
export const msgTransferTypeUrl = GeneratedMsgTransfer.typeUrl;
export const msgWithdrawTypeUrl = GeneratedMsgWithdraw.typeUrl;
const defaultPrepareScanMaxPages = 1000;
const cosmosSignDocMetadataField = "__clairveilCosmosSignDoc";
const cosmosReservationRequiredMemoMarker = "[clairveil-reservation-required:v1]";
const defaultFetchTimeoutMs = 30000;
const maxUint64 = (1n << 64n) - 1n;
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

function normalizeNonNegativeInteger(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return number;
}

function uint64CursorBigInt(value, label) {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative safe integer, bigint, or canonical uint64 string`);
    }
    return BigInt(value);
  }
  if (typeof value === "bigint") {
    if (value < 0n || value > maxUint64) {
      throw new Error(`${label} must be within uint64 range`);
    }
    return value;
  }
  const text = String(value ?? "").trim();
  if (!/^(0|[1-9][0-9]*)$/.test(text)) {
    throw new Error(`${label} must be a canonical uint64 decimal string`);
  }
  const parsed = BigInt(text);
  if (parsed > maxUint64) {
    throw new Error(`${label} must be within uint64 range`);
  }
  return parsed;
}

function uint64CursorValue(value, label) {
  const parsed = uint64CursorBigInt(value, label);
  return parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : parsed.toString();
}

function compareUint64Cursor(left, right, label) {
  const leftValue = uint64CursorBigInt(left, `${label} left value`);
  const rightValue = uint64CursorBigInt(right, `${label} right value`);
  return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
}

function maxUint64Cursor(values, label) {
  let maximum = 0n;
  for (const value of values) {
    const parsed = uint64CursorBigInt(value ?? 0, label);
    if (parsed > maximum) maximum = parsed;
  }
  return maximum <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(maximum) : maximum.toString();
}

function decrementUint64Cursor(value, label) {
  const parsed = uint64CursorBigInt(value ?? 0, label);
  const decremented = parsed > 0n ? parsed - 1n : 0n;
  return decremented <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(decremented) : decremented.toString();
}

function normalizeDelayMs(value, label) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) {
    throw new Error(`${label} must be non-negative`);
  }
  return number;
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
  return {
    retries: normalizeNonNegativeInteger(retry.retries ?? defaultQueryRetry.retries, "queryRetry.retries"),
    baseDelayMs: normalizeDelayMs(retry.baseDelayMs ?? defaultQueryRetry.baseDelayMs, "queryRetry.baseDelayMs"),
    maxDelayMs: normalizeDelayMs(retry.maxDelayMs ?? defaultQueryRetry.maxDelayMs, "queryRetry.maxDelayMs"),
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

function normalizeRestEndpoints(primary, restEndpoints = []) {
  const endpoints = [];
  for (const endpoint of [primary, ...(Array.isArray(restEndpoints) ? restEndpoints : [])]) {
    const normalized = normalizeRestEndpoint(String(endpoint || ""));
    if (normalized && !endpoints.includes(normalized)) {
      endpoints.push(normalized);
    }
  }
  if (!endpoints.length) {
    throw new Error("rest endpoint is required");
  }
  return endpoints;
}

function requiredDepositProof(input = {}) {
  if (input?.proof != null) {
    const proof = typeof input.proof === "string"
      ? bytesFromHex(input.proof, "deposit proof")
      : Uint8Array.from(input.proof);
    if (proof.length) return proof;
  }
  const proofHex = input?.proofHex ?? input?.proof_hex;
  if (proofHex != null && String(proofHex).trim()) {
    const proof = bytesFromHex(proofHex, "deposit proof");
    if (proof.length) return proof;
  }
  throw new Error("deposit proof is required; provide proof or proofHex");
}

export const MsgDeposit = GeneratedMsgDeposit;
export const MsgTransfer = GeneratedMsgTransfer;
export const MsgWithdraw = GeneratedMsgWithdraw;
export { UserDisclosureMode };

export function createClairveilRegistry(extraTypes = []) {
  return new Registry([
    ...defaultRegistryTypes,
    [msgDepositTypeUrl, MsgDeposit],
    [msgTransferTypeUrl, MsgTransfer],
    [msgWithdrawTypeUrl, MsgWithdraw],
    ...extraTypes
  ]);
}

export function normalizeRpcEndpoint(rpc) {
  return rpc.replace(/^tcp:\/\//, "http://").replace(/\/$/, "");
}

export function normalizeRestEndpoint(rest) {
  return rest.replace(/\/$/, "");
}

export function buildRootSigningMessage(address, pubKeyHex) {
  return [
    "clairveil-root-v1",
    `address:${address}`,
    `pubkey:${pubKeyHex}`
  ].join("\n");
}

export function cosmosAddressFromPubKey(pubKeyHex, prefix = "clair") {
  return toBech32(prefix, hash160(rawBytesFromHex(pubKeyHex, "pubKeyHex")));
}

export function verifySignerPubKey(address, pubKeyHex, prefix = defaultAccountPrefix) {
  const expectedAddress = cosmosAddressFromPubKey(pubKeyHex, prefix);
  return {
    address,
    expectedAddress,
    matches: address === expectedAddress
  };
}

export function assertSignerPubKey(address, pubKeyHex, prefix = defaultAccountPrefix) {
  const signerCheck = verifySignerPubKey(address, pubKeyHex, prefix);
  if (!signerCheck.matches) {
    throw new Error(`signer address/pubKey mismatch. ${address} maps to ${signerCheck.expectedAddress}`);
  }
  return signerCheck;
}

export function eventAttribute(event, key) {
  return (event?.attributes || []).find(attribute => attribute.key === key)?.value || "";
}

export function isAuditableTransfer(event) {
  return event?.event_type === "shielded_transfer" && Boolean(eventAttribute(event, "audit_disclosure_payload"));
}

function toBase64(bytes) {
  return base64FromBytes(bytes);
}

function fromBase64(value, label = "base64") {
  return bytesFromBase64(value, label);
}

function attachBroadcastEvidence(error, { txHash = "", txBytesHash = "" } = {}) {
  const original = error && typeof error === "object"
    ? error
    : new Error(String(error || "broadcast failed"));
  try {
    if (txHash && !original.txHash && !original.txhash) {
      original.txHash = txHash;
    }
    if (txBytesHash && !original.txBytesHash && !original.tx_bytes_hash) {
      original.txBytesHash = txBytesHash;
    }
    return original;
  } catch {
    const wrapped = new Error(
      String(original?.message || error || "broadcast failed"),
      { cause: original }
    );
    if (typeof original?.name === "string" && original.name) {
      wrapped.name = original.name;
    }
    if (txHash) wrapped.txHash = txHash;
    if (txBytesHash) wrapped.txBytesHash = txBytesHash;
    return wrapped;
  }
}

function directSignDocFromBase64(signDoc) {
  return {
    bodyBytes: fromBase64(signDoc.bodyBytes, "bodyBytes"),
    authInfoBytes: fromBase64(signDoc.authInfoBytes, "authInfoBytes"),
    chainId: signDoc.chainId,
    accountNumber: BigInt(signDoc.accountNumber)
  };
}

function markCosmosSignDocReservationRequired(
  signDoc,
  reservationBatch
) {
  if (
    !signDoc ||
    typeof signDoc !== "object" ||
    !reservationBatch?.reservation_ids?.length
  ) {
    return signDoc;
  }
  const current = signDoc[cosmosSignDocMetadataField] || {};
  const bindingHash = cosmosSignDocBindingHash(signDoc);
  Object.defineProperty(signDoc, cosmosSignDocMetadataField, {
    value: Object.freeze({
      ...current,
      reservationRequired: true,
      bindingHash
    }),
    enumerable: true,
    configurable: true
  });
  return signDoc;
}

function cosmosSignDocMetadata(signDoc) {
  return signDoc?.[cosmosSignDocMetadataField] || {};
}

function reservationRequiredCosmosMemo(memo = "") {
  return [String(memo || "").trim(), cosmosReservationRequiredMemoMarker]
    .filter(Boolean)
    .join("\n");
}

function cosmosTxBodyRequiresReservation(signDoc) {
  try {
    const body = TxBody.decode(fromBase64(signDoc?.bodyBytes, "bodyBytes"));
    return String(body.memo || "")
      .split("\n")
      .some(line => line.trim() === cosmosReservationRequiredMemoMarker);
  } catch {
    return false;
  }
}

function externalCosmosSignDoc(signDoc) {
  if (!signDoc || typeof signDoc !== "object") return signDoc;
  const external = { ...signDoc };
  delete external[cosmosSignDocMetadataField];
  return external;
}

function fromHex(value, label = "hex") {
  return rawBytesFromHex(value, label);
}

async function fetchJson(url, {
  timeoutMs = defaultFetchTimeoutMs,
  fetchImpl = globalThis.fetch,
  method = "GET",
  body,
  headers
} = {}) {
  const resolvedTimeoutMs = normalizeTimeoutMs(timeoutMs, "fetch timeoutMs");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), resolvedTimeoutMs);
  const requestHeaders = {
    accept: "application/json",
    ...(body != null ? { "content-type": "application/json" } : {}),
    ...(headers || {})
  };
  try {
    const response = await fetchImpl(url, {
      method,
      headers: requestHeaders,
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
      const timeoutError = new Error(`fetch request timed out after ${resolvedTimeoutMs}ms: ${url}`);
      timeoutError.code = "FETCH_TIMEOUT";
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchJsonWithRetry(urlForEndpoint, endpoints, { timeoutMs, retry, fetchImpl, method, body, headers } = {}) {
  const normalizedRetry = normalizeQueryRetry(retry);
  let lastError = null;
  for (const endpoint of endpoints) {
    for (let attempt = 0; attempt <= normalizedRetry.retries; attempt += 1) {
      try {
        return {
          data: await fetchJson(urlForEndpoint(endpoint), { timeoutMs, fetchImpl, method, body, headers }),
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

function privacyEventsCursor(data, request = {}) {
  const events = data?.events || [];
  let latestHeight = 0;
  let latestTxHash = "";
  for (const event of events) {
    const height = uint64CursorValue(event?.height ?? 0, "privacy event height");
    if (compareUint64Cursor(height, latestHeight, "privacy event height") >= 0) {
      latestHeight = height;
      latestTxHash = String(event?.tx_hash_hex || "").toUpperCase();
    }
  }
  return {
    source: "privacy_events",
    after_height: uint64CursorValue(request.afterHeight ?? request.after_height ?? 0, "privacy events after height"),
    page: Number(data?.page ?? request.page ?? 1),
    limit: Number(data?.limit ?? request.limit ?? events.length),
    event_types: request.eventTypes ?? request.event_types ?? [],
    has_more: Boolean(data?.has_more),
    latest_height: latestHeight,
    latest_tx_hash: latestTxHash
  };
}

function scanEventsCursor(data, request = {}) {
  const events = data?.events || [];
  let latestHeight = 0;
  let latestSequence = 0;
  let latestTxHash = "";
  for (const event of events) {
    const height = uint64CursorValue(event?.height ?? 0, "scan event height");
    const sequence = uint64CursorValue(event?.sequence ?? 0, "scan event sequence");
    const heightComparison = compareUint64Cursor(height, latestHeight, "scan event height");
    if (heightComparison > 0 || (
      heightComparison === 0 &&
      compareUint64Cursor(sequence, latestSequence, "scan event sequence") >= 0
    )) {
      latestHeight = height;
      latestSequence = sequence;
      latestTxHash = String(event?.tx_hash_hex ?? event?.txHashHex ?? "").toUpperCase();
    }
  }
  return {
    source: "scan_events",
    after_height: uint64CursorValue(request.afterHeight ?? request.after_height ?? 0, "scan events after height"),
    after_sequence: uint64CursorValue(request.afterSequence ?? request.after_sequence ?? 0, "scan events after sequence"),
    limit: Number(data?.limit ?? request.limit ?? events.length),
    event_types: request.eventTypes ?? request.event_types ?? [],
    has_more: Boolean(data?.has_more),
    next_height: uint64CursorValue(data?.next_height ?? data?.nextHeight ?? request.afterHeight ?? request.after_height ?? 0, "scan events next height"),
    next_sequence: uint64CursorValue(data?.next_sequence ?? data?.nextSequence ?? request.afterSequence ?? request.after_sequence ?? 0, "scan events next sequence"),
    latest_height: latestHeight,
    latest_sequence: latestSequence,
    latest_tx_hash: latestTxHash,
    scan_format_version: Number(data?.scan_format_version ?? data?.scanFormatVersion ?? 0),
    view_tag_version: Number(data?.view_tag_version ?? data?.viewTagVersion ?? 0)
  };
}

function assertScanEventsVersions(data) {
  const scanFormatVersion = Number(data?.scan_format_version ?? data?.scanFormatVersion ?? 0);
  const viewTagVersion = Number(data?.view_tag_version ?? data?.viewTagVersion ?? 0);
  if (scanFormatVersion !== 1) {
    const error = new Error(`unsupported scan_format_version ${scanFormatVersion}; expected 1`);
    error.code = "UNSUPPORTED_SCAN_EVENTS_VERSION";
    throw error;
  }
  if (viewTagVersion !== 1) {
    const error = new Error(`unsupported view_tag_version ${viewTagVersion}; expected 1`);
    error.code = "UNSUPPORTED_SCAN_EVENTS_VERSION";
    throw error;
  }
}

export function nextPrivacyScanOptions(scanOrCursor = {}, defaults = {}) {
  const cursor = scanOrCursor?.scanCursor || scanOrCursor || {};
  if (cursor.source === "scan_events" || cursor.next_sequence != null || cursor.nextSequence != null) {
    const hasMore = Boolean(cursor.has_more ?? cursor.hasMore);
    const next = {
      afterHeight: uint64CursorValue(
        hasMore
          ? cursor.next_height ?? cursor.nextHeight ?? cursor.after_height ?? cursor.afterHeight ?? 0
          : cursor.next_height ?? cursor.nextHeight ?? cursor.latest_height ?? cursor.latestHeight ?? cursor.after_height ?? cursor.afterHeight ?? 0,
        "scan resume height"
      ),
      afterSequence: uint64CursorValue(
        hasMore
          ? cursor.next_sequence ?? cursor.nextSequence ?? cursor.after_sequence ?? cursor.afterSequence ?? 0
          : cursor.next_sequence ?? cursor.nextSequence ?? cursor.latest_sequence ?? cursor.latestSequence ?? cursor.after_sequence ?? cursor.afterSequence ?? 0,
        "scan resume sequence"
      ),
      limit: Number(cursor.limit ?? defaults.limit ?? 200),
      eventTypes: cursor.event_types ?? cursor.eventTypes ?? defaults.eventTypes ?? defaults.event_types ?? [],
      hasMore,
      completed: !hasMore
    };
    next.scanSource = "scan_events";
    const maxPages = defaults.maxPages ?? defaults.max_pages;
    if (maxPages != null) next.maxPages = maxPages;
    const includeFoundNotes = defaults.includeFoundNotes ?? defaults.include_found_notes;
    if (includeFoundNotes != null) next.includeFoundNotes = Boolean(includeFoundNotes);
    return next;
  }
  const afterHeight = uint64CursorValue(cursor.after_height ?? cursor.afterHeight ?? defaults.afterHeight ?? defaults.after_height ?? 0, "privacy events after height");
  const latestHeight = uint64CursorValue(cursor.latest_height ?? cursor.latestHeight ?? 0, "privacy events latest height");
  const hasMore = Boolean(cursor.has_more ?? cursor.hasMore);
  const nextPage = hasMore
    ? Number(cursor.next_page ?? cursor.nextPage ?? (Number(cursor.page || 1) + 1))
    : 1;
  const nextAfterHeight = hasMore
    ? afterHeight
    : maxUint64Cursor([afterHeight, latestHeight], "privacy events resume height");
  const next = {
    afterHeight: nextAfterHeight,
    page: nextPage,
    limit: Number(cursor.limit ?? defaults.limit ?? 200),
    eventTypes: cursor.event_types ?? cursor.eventTypes ?? defaults.eventTypes ?? defaults.event_types ?? [],
    scanSource: cursor.source === "privacy_events" ? "privacy_events" : defaults.scanSource ?? defaults.scan_source ?? "privacy_events"
  };
  const maxPages = defaults.maxPages ?? defaults.max_pages;
  if (maxPages != null) next.maxPages = maxPages;
  const includeFoundNotes = defaults.includeFoundNotes ?? defaults.include_found_notes;
  if (includeFoundNotes != null) next.includeFoundNotes = Boolean(includeFoundNotes);
  next.hasMore = hasMore;
  next.completed = !hasMore;
  return next;
}

function resolveScanOptions({
  scan,
  afterHeight,
  after_height,
  afterSequence,
  after_sequence,
  page,
  limit,
  maxPages,
  max_pages,
  eventTypes,
  event_types,
  scanSource,
  scan_source
} = {}) {
  return {
    afterHeight: scan?.afterHeight ?? scan?.after_height ?? afterHeight ?? after_height,
    afterSequence: scan?.afterSequence ?? scan?.after_sequence ?? afterSequence ?? after_sequence,
    page: scan?.page ?? page,
    limit: scan?.limit ?? limit,
    maxPages: scan?.maxPages ?? scan?.max_pages ?? maxPages ?? max_pages,
    eventTypes: scan?.eventTypes ?? scan?.event_types ?? eventTypes ?? event_types,
    scanSource: scan?.scanSource ?? scan?.scan_source ?? scanSource ?? scan_source
  };
}

function indexedTxToRestish(tx) {
  if (!tx) return null;
  return {
    height: String(tx.height),
    txhash: tx.hash,
    code: tx.code,
    raw_log: tx.rawLog,
    events: tx.events || [],
    tx: tx.tx
  };
}

function publicPrivacyAccount(material) {
  return {
    address: material.address,
    pubKeyHex: material.pubKeyHex,
    signing_message: material.signingMessage,
    shielded_address: material.shieldedAddress,
    disclosure_pubkey_hex: material.disclosurePubKeyHex,
    root_signature_hash: material.rootSignatureHash
  };
}

async function reservationAvailableNotes(reservationManager, notes) {
  if (!reservationManager) return notes;
  if (typeof reservationManager.filterAvailableNotes !== "function") {
    throw new Error("reservationManager.filterAvailableNotes is required");
  }
  return reservationManager.filterAvailableNotes(notes);
}

function reservationBatchSummary(batch) {
  if (!batch) return null;
  return {
    operation_id: batch.operation_id,
    lease_owner: batch.lease_owner || batch.reservations?.[0]?.lease_owner || "",
    lease_token: batch.lease_token || batch.reservations?.[0]?.lease_token || "",
    lease_until: batch.lease_until || batch.reservations?.[0]?.lease_until || "",
    reservation_ids: [...(batch.reservation_ids || [])],
    reservations: [...(batch.reservations || [])]
  };
}

function broadcastReservationContext(options = {}) {
  const reservationManager = options.reservationManager ?? options.reservation_manager ?? null;
  const reservation = options.reservation ?? options.reservationBatch ?? options.reservation_batch ?? null;
  const reservationIDs = [...(reservation?.reservation_ids || [])].filter(Boolean).map(String);
  if (!reservationManager && !reservation) return null;
  if (!reservationIDs.length) {
    throw new Error("reserved-note broadcast requires reservation ids");
  }
  if (!reservationManager || typeof reservationManager.markBroadcastAttempting !== "function") {
    throw new Error("reservationManager.markBroadcastAttempting is required for reserved-note broadcast");
  }
  const leaseToken = String(
    reservation?.lease_token || reservation?.reservations?.[0]?.lease_token || ""
  );
  if (!leaseToken) {
    throw new Error("reserved-note broadcast requires the current lease token");
  }
  return { reservationManager, reservationIDs, leaseToken };
}

function signedWithdrawMessage(signedTx) {
  const body = TxBody.decode(fromBase64(signedTx?.bodyBytes, "bodyBytes"));
  const withdrawals = body.messages.filter(message => message.typeUrl === msgWithdrawTypeUrl);
  if (!withdrawals.length) return null;
  if (body.messages.length !== 1 || withdrawals.length !== 1) {
    throw new Error("withdraw broadcast must contain exactly one MsgWithdraw");
  }
  return GeneratedMsgWithdraw.decode(withdrawals[0].value);
}

export function cosmosSignDocBindingHash({ bodyBytes, authInfoBytes } = {}) {
  const txRaw = TxRaw.fromPartial({
    bodyBytes: fromBase64(bodyBytes, "bodyBytes"),
    authInfoBytes: fromBase64(authInfoBytes, "authInfoBytes"),
    signatures: []
  });
  return sha256Hex(TxRaw.encode(txRaw).finish());
}

async function authoritativeReservationRecords(context) {
  if (!context) return [];
  if (typeof context.reservationManager.getReservation !== "function") {
    throw new Error("reservationManager.getReservation is required for reserved-note broadcast validation");
  }
  return Promise.all(context.reservationIDs.map(id => context.reservationManager.getReservation(id)));
}

function assertReservationPayloadMatches(records, payload) {
  if (!records.length) return;
  const payloadHash = String(payload?.payload_hash || "").trim();
  const storedHashes = records.map(record => String(record?.payload_hash ?? record?.payloadHash ?? "").trim());
  if (!payloadHash || storedHashes.some(hash => !hash || hash !== payloadHash)) {
    throw new Error("relay payload does not match the reserved payload hash");
  }
}

function assertReservationSignDocMatches(records, signDocHash, { allowPayloadBinding = false } = {}) {
  if (!records.length) return;
  const mismatched = records.some(record => {
    const storedHash = String(record?.sign_doc_hash ?? record?.signDocHash ?? "").trim();
    if (storedHash) return storedHash !== signDocHash;
    return !(allowPayloadBinding && String(record?.payload_hash ?? record?.payloadHash ?? "").trim());
  });
  if (!signDocHash || mismatched) {
    throw new Error("Cosmos sign doc does not match the reservation ProofReady artifact");
  }
}

function assertSignedWithdrawMatchesPayload(message, payload) {
  const normalizedPayloadHex = value => String(value || "").trim().replace(/^0x/i, "").toLowerCase();
  const matches =
    hexFromBytes(message.proof) === normalizedPayloadHex(payload.proof_hex) &&
    hexFromBytes(message.root) === normalizedPayloadHex(payload.root_hex) &&
    hexFromBytes(message.nullifier) === normalizedPayloadHex(payload.nullifier_hex) &&
    String(message.amount) === String(payload.amount) &&
    String(message.recipient) === String(payload.recipient) &&
    String(message.chainId) === String(payload.chain_id) &&
    BigInt(message.expiresAtUnix) === BigInt(payload.expires_at_unix);
  if (!matches) {
    throw new Error("relay payload does not match the Cosmos signed transaction being broadcast");
  }
}

async function validateRelayBroadcastContext(options, {
  expectedChainId,
  accountPrefix,
  signedTx,
  reservationContext,
  signDocHash
} = {}) {
  const payload = options?.relayPayload ?? options?.relay_payload ?? null;
  const reservationRecords = await authoritativeReservationRecords(reservationContext);
  assertReservationSignDocMatches(reservationRecords, signDocHash, { allowPayloadBinding: Boolean(payload) });
  const chainTimeProvider = options?.getChainNowUnix ?? options?.get_chain_now_unix;
  const withdrawMessage = signedWithdrawMessage(signedTx);
  if (!payload) {
    if (withdrawMessage) {
      throw new Error("withdraw broadcast requires relayPayload and authoritative chain time");
    }
    if (
      options?.chainNowUnix != null ||
      options?.chain_now_unix != null ||
      chainTimeProvider != null
    ) {
      throw new Error("relayPayload is required when relay broadcast chain time is provided");
    }
    return;
  }
  if (chainTimeProvider != null && typeof chainTimeProvider !== "function") {
    throw new Error("getChainNowUnix must be a function");
  }
  const chainNowUnix = chainTimeProvider
    ? await chainTimeProvider()
    : options.chainNowUnix ?? options.chain_now_unix;
  validateRelayWithdrawPayload(payload, {
    chainNowUnix,
    expectedChainId: options.expectedChainId ?? options.expected_chain_id ?? expectedChainId,
    expectedRecipient: options.expectedRecipient ?? options.expected_recipient,
    accountPrefix: options.accountPrefix ?? options.account_prefix ?? accountPrefix
  });
  assertReservationPayloadMatches(reservationRecords, payload);
  if (!withdrawMessage) {
    throw new Error("relayPayload does not match a Cosmos MsgWithdraw transaction");
  }
  assertSignedWithdrawMatchesPayload(withdrawMessage, payload);
}

function attachReservationBookkeepingError(error, bookkeepingError) {
  const original = error && typeof error === "object"
    ? error
    : new Error(String(error || "broadcast failed"));
  try {
    original.reservationBookkeepingError = bookkeepingError;
    original.reservationReconciliationRequired = true;
    return original;
  } catch {
    const wrapped = new Error(
      String(original?.message || error || "broadcast failed"),
      { cause: original }
    );
    if (typeof original?.name === "string" && original.name) {
      wrapped.name = original.name;
    }
    wrapped.reservationBookkeepingError = bookkeepingError;
    wrapped.reservationReconciliationRequired = true;
    return wrapped;
  }
}

async function beginBroadcastReservation(context, reason, evidence = {}) {
  if (!context) return;
  await context.reservationManager.markBroadcastAttempting(context.reservationIDs, {
    leaseToken: context.leaseToken,
    reason,
    txHash: evidence.txHash || "",
    txBytesHash: evidence.txBytesHash || "",
    signDocHash: evidence.signDocHash || ""
  });
}

async function markBroadcastReservationUnknown(context, error, evidence = {}) {
  if (!context) return;
  try {
    await context.reservationManager.markUnknown(context.reservationIDs, {
      leaseToken: context.leaseToken,
      txHash: evidence.txHash || "",
      txBytesHash: evidence.txBytesHash || "",
      signDocHash: evidence.signDocHash || "",
      error: String(error?.message || error || "broadcast result is unknown"),
      metadata: { reconcile_reason: "sdk_broadcast_result_unknown" }
    });
  } catch (bookkeepingError) {
    throw attachReservationBookkeepingError(error, bookkeepingError);
  }
}

async function markBroadcastReservationSubmitted(context, evidence = {}) {
  if (!context) return;
  try {
    await context.reservationManager.markSubmitted(context.reservationIDs, {
      leaseToken: context.leaseToken,
      txHash: evidence.txHash || "",
      txBytesHash: evidence.txBytesHash || "",
      signDocHash: evidence.signDocHash || ""
    });
  } catch (bookkeepingError) {
    const error = new Error("transaction was broadcast but reservation submission could not be recorded");
    error.txHash = evidence.txHash || "";
    error.txBytesHash = evidence.txBytesHash || "";
    throw attachReservationBookkeepingError(error, bookkeepingError);
  }
}

function isExplicitWalletRejection(error) {
  return String(error?.code ?? error?.data?.code ?? "") === "4001";
}

async function markSigningReservationRejected(context, error) {
  if (!context) return;
  try {
    if (typeof context.reservationManager.markBroadcastRejected !== "function") {
      throw new Error("reservationManager.markBroadcastRejected is required for pre-broadcast wallet rejection");
    }
    await context.reservationManager.markBroadcastRejected(context.reservationIDs, {
      leaseToken: context.leaseToken,
      error: String(error?.message || error || "wallet request rejected"),
      providerCode: "4001",
      metadata: {
        wallet_rejected_before_broadcast: true,
        provider_rejection_code: "4001",
        reconcile_reason: "wallet_rejected_before_broadcast"
      }
    });
  } catch (bookkeepingError) {
    throw attachReservationBookkeepingError(error, bookkeepingError);
  }
}

function transferProofReadyMetadata(built, context = {}) {
  const output = built?.payload?.outputs?.[0] || {};
  const coin = context.amount ? parseCoin(context.amount, context.denom || "") : null;
  const batchItemIndex = context.batchItemIndex ?? context.batch_item_index;
  const batchItemIndexKnown = context.batchItemIndexKnown ?? context.batch_item_index_known;
  const expectedOutputCommitment = built?.payload?.outputs?.[0]?.commitment_hex || "";
  const expectedDisclosureDigest = built?.payload?.audit_disclosure_digest_hex || "";
  const expectedRecipientHash = context.expectedRecipientHash ?? context.expected_recipient_hash ?? "";
  const expectedAmount = output.amount || coin?.amount || "";
  const expectedAmountHash = context.expectedAmountHash ?? context.expected_amount_hash ?? "";
  const expectedDenom = context.expectedDenom ?? context.expected_denom ?? coin?.denom ?? context.denom ?? "";
  const operationSuccessEvidenceRequired = Boolean(
    expectedOutputCommitment &&
    expectedDisclosureDigest &&
    expectedRecipientHash &&
    expectedAmount &&
    expectedAmountHash &&
    expectedDenom
  );
  return {
    payloadHash: built?.payload?.payload_hash || "",
    signDocHash: context.signDocHash ?? context.sign_doc_hash ?? "",
    expectedOutputCommitment,
    expectedDisclosureDigest,
    expectedRecipientHash,
    expectedAmount,
    expectedAmountHash,
    expectedDenom,
    batchItemIndex: batchItemIndex ?? 0,
    batchItemIndexKnown: batchItemIndexKnown ?? (operationSuccessEvidenceRequired || (batchItemIndex !== undefined && batchItemIndex !== null)),
    operationSuccessEvidenceRequired
  };
}

function resolveDirectOperationEvidenceHashes({
  expectedRecipientHash,
  expected_recipient_hash,
  expectedAmountHash,
  expected_amount_hash
} = {}) {
  const recipientProvided = operationEvidenceAliasProvided(
    expectedRecipientHash,
    expected_recipient_hash
  );
  const amountProvided = operationEvidenceAliasProvided(
    expectedAmountHash,
    expected_amount_hash
  );
  const recipientHash = resolveOperationEvidenceAlias(
    expectedRecipientHash,
    expected_recipient_hash,
    "expectedRecipientHash"
  );
  const amountHash = resolveOperationEvidenceAlias(
    expectedAmountHash,
    expected_amount_hash,
    "expectedAmountHash"
  );
  if (recipientProvided !== amountProvided) {
    throw new Error("expected recipient hash and expected amount hash must be provided together");
  }
  if (recipientProvided && !recipientHash.trim()) {
    throw new Error("expectedRecipientHash must not be empty");
  }
  if (amountProvided && !amountHash.trim()) {
    throw new Error("expectedAmountHash must not be empty");
  }
  return {
    provided: recipientProvided,
    expectedRecipientHash: recipientHash,
    expectedAmountHash: amountHash
  };
}

function operationEvidenceAliasProvided(camelValue, snakeValue) {
  return (camelValue !== undefined && camelValue !== null) ||
    (snakeValue !== undefined && snakeValue !== null);
}

function resolveOperationEvidenceAlias(camelValue, snakeValue, name) {
  const camelProvided = camelValue !== undefined && camelValue !== null;
  const snakeProvided = snakeValue !== undefined && snakeValue !== null;
  if (camelProvided && snakeProvided && String(camelValue) !== String(snakeValue)) {
    throw new Error(`${name} aliases conflict`);
  }
  return String(camelProvided ? camelValue : snakeProvided ? snakeValue : "");
}

function resolveOperationEvidenceArrayAlias(camelValue, snakeValue, name) {
  const camelProvided = camelValue !== undefined && camelValue !== null;
  const snakeProvided = snakeValue !== undefined && snakeValue !== null;
  if (camelProvided && !Array.isArray(camelValue)) {
    throw new Error(`${name} must be an array`);
  }
  if (snakeProvided && !Array.isArray(snakeValue)) {
    throw new Error(`${name} must be an array`);
  }
  if (camelProvided && snakeProvided) {
    const camelItems = camelValue.map(String);
    const snakeItems = snakeValue.map(String);
    if (camelItems.length !== snakeItems.length ||
        camelItems.some((value, index) => value !== snakeItems[index])) {
      throw new Error(`${name} aliases conflict`);
    }
  }
  return camelProvided ? camelValue : snakeProvided ? snakeValue : [];
}

function resolveBatchOperationEvidence({
  amounts = [],
  expectedRecipientHash,
  expected_recipient_hash,
  expectedRecipientHashes,
  expected_recipient_hashes,
  expectedAmountHashes,
  expected_amount_hashes
} = {}) {
  const recipientHashScalarProvided = operationEvidenceAliasProvided(
    expectedRecipientHash,
    expected_recipient_hash
  );
  const recipientHashArrayProvided = operationEvidenceAliasProvided(
    expectedRecipientHashes,
    expected_recipient_hashes
  );
  const amountHashArrayProvided = operationEvidenceAliasProvided(
    expectedAmountHashes,
    expected_amount_hashes
  );
  const recipientHashScalar = resolveOperationEvidenceAlias(
    expectedRecipientHash,
    expected_recipient_hash,
    "expectedRecipientHash"
  );
  const recipientHashArray = resolveOperationEvidenceArrayAlias(
    expectedRecipientHashes,
    expected_recipient_hashes,
    "expectedRecipientHashes"
  );
  const amountHashArray = resolveOperationEvidenceArrayAlias(
    expectedAmountHashes,
    expected_amount_hashes,
    "expectedAmountHashes"
  );
  const evidenceProvided = recipientHashScalarProvided ||
    recipientHashArrayProvided || amountHashArrayProvided;
  if (!evidenceProvided) {
    return {
      enabled: false,
      recipientHashes: [],
      amountHashes: []
    };
  }
  if (recipientHashArrayProvided && recipientHashArray.length !== amounts.length) {
    throw new Error("expectedRecipientHashes length must match batch amounts length");
  }
  if (amountHashArray.length !== amounts.length) {
    throw new Error("expectedAmountHashes length must match batch amounts length when batch operation evidence is provided");
  }
  const recipientHashes = amounts.map((_, index) =>
    String(recipientHashArray[index] || recipientHashScalar || "").trim()
  );
  const amountHashes = amounts.map((_, index) => String(amountHashArray[index] || "").trim());
  const missingRecipientIndex = recipientHashes.findIndex(value => !value);
  if (missingRecipientIndex >= 0) {
    throw new Error(`expected recipient hash is required for batch item ${missingRecipientIndex}`);
  }
  const missingAmountIndex = amountHashes.findIndex(value => !value);
  if (missingAmountIndex >= 0) {
    throw new Error(`expected amount hash is required for batch item ${missingAmountIndex}`);
  }
  return {
    enabled: true,
    recipientHashes,
    amountHashes
  };
}

function withdrawProofReadyMetadata(built, context = {}) {
  const expiresAtUnix = String(
    built?.payload?.expires_at_unix ||
    built?.payload?.expiresAtUnix ||
    built?.proverPayload?.expires_at_unix ||
    built?.proverPayload?.expiresAtUnix ||
    ""
  );
  return {
    payloadHash: built?.payload?.payload_hash || built?.proverPayload?.payload_hash || "",
    signDocHash: context.signDocHash ?? context.sign_doc_hash ?? "",
    expectedOutputCommitment: "",
    expectedDisclosureDigest: "",
    metadata: expiresAtUnix ? { payload_expires_at_unix: expiresAtUnix } : {}
  };
}

async function markReservationProofReady(reservationManager, batch, metadata) {
  if (!reservationManager || !batch?.reservation_ids?.length) return [];
  if (typeof reservationManager.markProofReady !== "function") {
    throw new Error("reservationManager.markProofReady is required");
  }
  const reservations = await reservationManager.markProofReady(batch.reservation_ids, {
    ...metadata,
    leaseToken: batch.lease_token || batch.reservations?.[0]?.lease_token || ""
  });
  batch.reservations = reservations;
  batch.lease_until = reservations[0]?.lease_until || batch.lease_until;
  return reservations;
}

async function reservationIDsForNotes(reservationManager, batch, notes) {
  if (!reservationManager || !batch?.reservation_ids?.length) return [];
  if (typeof reservationManager.lookupKeyForNote !== "function") {
    throw new Error("reservationManager.lookupKeyForNote is required");
  }
  const lookupKeys = new Set();
  for (const note of notes || []) {
    lookupKeys.add(await reservationManager.lookupKeyForNote(note));
  }
  const reservationIDs = (batch.reservations || [])
    .filter(reservation => lookupKeys.has(reservation.nullifier_lookup_key))
    .map(reservation => reservation.reservation_id);
  return reservationIDs;
}

function mergeBatchReservations(batch, updated) {
  const updatedByID = new Map(updated.map(reservation => [reservation.reservation_id, reservation]));
  batch.reservations = (batch.reservations || []).map(reservation =>
    updatedByID.get(reservation.reservation_id) || reservation
  );
  batch.lease_until = updated[0]?.lease_until || batch.lease_until;
}

async function markReservationProofReadyForNotes(reservationManager, batch, notes, metadata) {
  const reservationIDs = await reservationIDsForNotes(reservationManager, batch, notes);
  if (!reservationIDs.length) return [];
  const updated = await reservationManager.markProofReady(reservationIDs, {
    ...metadata,
    leaseToken: batch.lease_token || batch.reservations?.[0]?.lease_token || ""
  });
  mergeBatchReservations(batch, updated);
  return updated;
}

async function markReservationProofReadyForBatchItems(reservationManager, batch, items) {
  if (!reservationManager || !batch?.reservation_ids?.length) return [];
  if (typeof reservationManager.markProofReadyBatch !== "function") {
    throw new Error("reservationManager.markProofReadyBatch is required for atomic batch transfer preparation");
  }
  const entries = [];
  for (const item of items || []) {
    const reservationIDs = await reservationIDsForNotes(reservationManager, batch, item?.notes);
    if (!reservationIDs.length) continue;
    entries.push({
      reservationIDs,
      metadata: {
        ...(item?.metadata || {}),
        leaseToken: batch.lease_token || batch.reservations?.[0]?.lease_token || ""
      }
    });
  }
  if (!entries.length) return [];
  const updated = await reservationManager.markProofReadyBatch(entries);
  mergeBatchReservations(batch, updated);
  return updated;
}

async function replanProofReadyReservations(reservationManager, batch, error, reason) {
  if (!reservationManager || !batch?.reservation_ids?.length) return [];
  if (typeof reservationManager.getReservation !== "function" || typeof reservationManager.markReplanRequired !== "function") {
    return [];
  }
  const proofReadyIDs = [];
  for (const reservationID of batch.reservation_ids || []) {
    try {
      const reservation = await reservationManager.getReservation(reservationID);
      if (reservation.status === reservationStatuses.ProofReady) {
        proofReadyIDs.push(reservationID);
      }
    } catch (_) {
      // Best-effort cleanup should not hide the original prepare failure.
    }
  }
  if (!proofReadyIDs.length) return [];
  return reservationManager.markReplanRequired(proofReadyIDs, {
    leaseToken: batch.lease_token || batch.reservations?.[0]?.lease_token || "",
    error: error?.message || String(error || "reservation replan required"),
    metadata: {
      reconcile_reason: reason,
      no_broadcast_attempt: true,
      proof_discarded: true
    }
  });
}

async function renewReservationLease(reservationManager, batch) {
  if (!reservationManager || !batch?.reservation_ids?.length) return [];
  if (typeof reservationManager.renewLease !== "function") return [];
  const reservations = await reservationManager.renewLease(batch.reservation_ids, {
    leaseToken: batch.lease_token || batch.reservations?.[0]?.lease_token || ""
  });
  batch.reservations = reservations;
  batch.lease_until = reservations[0]?.lease_until || batch.lease_until;
  return reservations;
}

async function withReservationHeartbeat(reservationManager, batch, task) {
  if (!reservationManager || !batch?.reservation_ids?.length || typeof reservationManager.renewLease !== "function") {
    return task({
      assertHeartbeatHealthy() {},
      async heartbeatNow() {}
    });
  }
  await renewReservationLease(reservationManager, batch);
  const heartbeatIntervalMs = reservationHeartbeatIntervalMs({
    leaseDurationMs: reservationManager.leaseDurationMs,
    leaseUntil: batch.lease_until || batch.reservations?.[0]?.lease_until
  });
  let heartbeatError = null;
  let inFlightHeartbeat = null;
  const heartbeat = async () => {
    if (heartbeatError) return;
    try {
      await renewReservationLease(reservationManager, batch);
    } catch (error) {
      heartbeatError = error;
    }
  };
  const heartbeatNow = async () => {
    if (!inFlightHeartbeat) {
      inFlightHeartbeat = heartbeat().finally(() => {
        inFlightHeartbeat = null;
      });
    }
    await inFlightHeartbeat;
    assertHeartbeatHealthy();
  };
  const assertHeartbeatHealthy = () => {
    if (!heartbeatError) return;
    const error = new Error("note reservation lease heartbeat failed during proof generation");
    error.name = "ReservationHeartbeatError";
    error.cause = heartbeatError;
    throw error;
  };
  const timer = typeof globalThis.setInterval === "function"
    ? globalThis.setInterval(() => { void heartbeatNow().catch(() => {}); }, heartbeatIntervalMs)
    : null;
  let taskCompleted = false;
  let result;
  try {
    result = await task({ assertHeartbeatHealthy, heartbeatNow });
    taskCompleted = true;
  } finally {
    if (timer && typeof globalThis.clearInterval === "function") {
      globalThis.clearInterval(timer);
    }
    if (inFlightHeartbeat) await inFlightHeartbeat;
  }
  if (taskCompleted && heartbeatError) {
    return {
      ...result,
      reservationReconciliationRequired: true,
      reservationReconciliationWarning: {
        code: "reservation_heartbeat_failed_after_proof_ready",
        message: "The prepared artifact is durable, but reservation reconciliation is required before broadcast.",
        cause: heartbeatError?.message || String(heartbeatError)
      }
    };
  }
  return result;
}

function reservationReconciliationFields(result = {}) {
  return result.reservationReconciliationRequired === true
    ? {
        reservationReconciliationRequired: true,
        reservationReconciliationWarning: result.reservationReconciliationWarning
      }
    : {};
}

export class ClairveilJS {
  constructor({
    rpc,
    rest,
    restEndpoints,
    chainId,
    accountPrefix,
    bech32Prefix,
    shieldedPrefix,
    defaultDenom = defaultAssetDenom,
    assetDenom,
    registry = createClairveilRegistry(),
    queryTimeoutMs = defaultFetchTimeoutMs,
    fetchTimeoutMs,
    queryRetry,
    nullifierFailover = false
  } = {}) {
    this.rpc = normalizeRpcEndpoint(rpc);
    this.restEndpoints = normalizeRestEndpoints(rest, restEndpoints);
    this.rest = this.restEndpoints[0];
    this.activeRestEndpoint = this.rest;
    this.chainId = chainId;
    this.accountPrefix = normalizeBech32Prefix(accountPrefix ?? bech32Prefix ?? defaultAccountPrefix, "accountPrefix");
    this.bech32Prefix = this.accountPrefix;
    this.shieldedPrefix = normalizeBech32Prefix(shieldedPrefix ?? `${this.accountPrefix}s`, "shieldedPrefix");
    this.defaultDenom = String(assetDenom ?? defaultDenom ?? defaultAssetDenom);
    this.registry = registry;
    this.queryTimeoutMs = normalizeTimeoutMs(fetchTimeoutMs ?? queryTimeoutMs, "queryTimeoutMs");
    this.queryRetry = normalizeQueryRetry(queryRetry);
    this.nullifierFailover = Boolean(nullifierFailover);
    this.clientPromise = null;
  }

  async connect() {
    if (!this.clientPromise) {
      this.clientPromise = StargateClient.connect(this.rpc);
    }
    return this.clientPromise;
  }

  async disconnect() {
    if (!this.clientPromise) return;
    const client = await this.clientPromise;
    client.disconnect();
    this.clientPromise = null;
  }

  restUrl(path, endpoint = this.activeRestEndpoint) {
    return `${endpoint}${path}`;
  }

  async fetchJson(pathOrUrl, {
    failover = false,
    retry = this.queryRetry,
    method,
    body,
    headers,
    endpoint,
    updateActiveEndpoint = endpoint == null
  } = {}) {
    const text = String(pathOrUrl || "");
    const isAbsolute = /^https?:\/\//i.test(text);
    if (isAbsolute) {
      const result = await fetchJsonWithRetry(
        url => url,
        [text],
        {
          timeoutMs: this.queryTimeoutMs,
          retry,
          method,
          body,
          headers
        }
      );
      return result.data;
    }
    const path = text;
    const initialEndpoint = endpoint || this.activeRestEndpoint;
    const endpoints = failover
      ? [initialEndpoint, ...this.restEndpoints.filter(candidate => candidate !== initialEndpoint)]
      : [initialEndpoint];
    const result = await fetchJsonWithRetry(
      endpoint => this.restUrl(path, endpoint),
      endpoints,
      {
        timeoutMs: this.queryTimeoutMs,
        retry,
        method,
        body,
        headers
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

  async getAccountInfo(address) {
    const data = await this.fetchJson(`/cosmos/auth/v1beta1/account_info/${address}`, { failover: true });
    const info = data.info;
    if (!info?.account_number || info.sequence == null) {
      throw new Error("account not found on-chain; fund it first");
    }
    return {
      accountNumber: BigInt(info.account_number),
      sequence: BigInt(info.sequence)
    };
  }

  async getBalances(address) {
    const client = await this.connect();
    const balances = await client.getAllBalances(address);
    return {
      balances: balances.map(balance => ({ denom: balance.denom, amount: balance.amount })),
      pagination: null
    };
  }

  async getTx(txHash) {
    const client = await this.connect();
    return indexedTxToRestish(await client.getTx(txHash));
  }

  async waitForTx(txHash, { attempts = 20, intervalMs = 1500 } = {}) {
    for (let i = 0; i < attempts; i += 1) {
      const tx = await this.getTx(txHash);
      if (tx) return tx;
      await new Promise(resolve => setTimeout(resolve, intervalMs));
    }
    return null;
  }

  async fetchPrivacyEvents(options = {}) {
    return this.fetchJson(`/clairveil/privacy/v1/events${privacyEventsQuery(options)}`, { failover: true });
  }

  async fetchScanEvents(options = {}) {
    const data = await this.fetchJson(`/clairveil/privacy/v1/scan_events${scanEventsQuery(options)}`, { failover: true });
    assertScanEventsVersions(data);
    return data;
  }

  async fetchTreeState() {
    return this.fetchJson("/clairveil/privacy/v1/tree_state", { failover: true });
  }

  async fetchCommitmentInfo(commitmentHex) {
    return this.fetchJson(`/clairveil/privacy/v1/commitment/${commitmentHex}`, { failover: true });
  }

  async lookupMerklePath(commitmentHex) {
    return this.fetchJson(`/clairveil/privacy/v1/merkle_path/${commitmentHex}`, { failover: true });
  }

  async fetchAuditConfig() {
    return this.fetchJson("/clairveil/privacy/v1/audit_config", { failover: true });
  }

  async fetchDisclosureConfig() {
    return this.fetchJson("/clairveil/privacy/v1/disclosure_config", { failover: true });
  }

  async fetchCircuitConfig() {
    return this.fetchJson("/clairveil/privacy/v1/circuit_config", { failover: true });
  }

  async fetchReserve(denom) {
    const normalizedDenom = String(denom || "").trim();
    if (!normalizedDenom) {
      throw new Error("reserve denom is required");
    }
    return this.fetchJson(`/clairveil/privacy/v1/reserve/${encodeURIComponent(normalizedDenom)}`, { failover: true });
  }

  async checkNullifier(nullifierHex) {
    return this.fetchNullifierJson(`/clairveil/privacy/v1/nullifier/${nullifierHex}`);
  }

  async checkNullifiers(nullifierHexes = []) {
    const normalized = [...new Set((nullifierHexes || []).map(value => String(value || "").trim().toLowerCase()).filter(Boolean))];
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
    const chunkSize = 1000;
    for (let start = 0; start < normalized.length; start += chunkSize) {
      const chunk = normalized.slice(start, start + chunkSize);
      const response = await this.fetchNullifierJson("/clairveil/privacy/v1/nullifiers", {
        method: "POST",
        body: JSON.stringify({ nullifiers: chunk })
      });
      for (const status of response?.statuses || response?.Statuses || []) {
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

  async deriveWalletPrivacyMaterial(wallet) {
    return derivePrivacyMaterialFromWallet(wallet, {
      shieldedPrefix: this.shieldedPrefix
    });
  }

  async scanNotes({
    rootSeed,
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page = 1,
    limit = 200,
    maxPages = 1,
    eventTypes = ["deposit", "shielded_transfer"],
    event_types,
    includeFoundNotes = false,
    scanSource = "scan_events",
    scan_source
  } = {}) {
    const resolvedEventTypes = event_types ?? eventTypes;
    const pageLimit = Math.max(1, Number(limit || 200));
    const pageBudget = Math.max(1, Number(maxPages || 1));
    const source = scan_source ?? scanSource;

    let legacyAfterHeight = afterHeight;
    let legacyAfterHeightAlias = after_height;
    let legacyPage = page;
    if (source !== "privacy_events") {
      const startAfterHeight = uint64CursorValue(afterHeight ?? after_height ?? 0, "scan after height");
      const startAfterSequence = uint64CursorValue(afterSequence ?? after_sequence ?? 0, "scan after sequence");
      const events = [];
      let currentAfterHeight = startAfterHeight;
      let currentAfterSequence = startAfterSequence;
      let pagesScanned = 0;
      let hasMore = false;
      let lastData = null;
      try {
        for (; pagesScanned < pageBudget;) {
          const request = {
            afterHeight: currentAfterHeight,
            afterSequence: currentAfterSequence,
            limit: pageLimit,
            eventTypes: resolvedEventTypes
          };
          const data = await this.fetchScanEvents(request);
          lastData = data;
          events.push(...(data.events || []));
          pagesScanned += 1;
          hasMore = Boolean(data.has_more ?? data.hasMore);
          const nextHeight = uint64CursorValue(data.next_height ?? data.nextHeight ?? currentAfterHeight, "scan next height");
          const nextSequence = uint64CursorValue(data.next_sequence ?? data.nextSequence ?? currentAfterSequence, "scan next sequence");
          if (
            hasMore &&
            compareUint64Cursor(nextHeight, currentAfterHeight, "scan height") === 0 &&
            compareUint64Cursor(nextSequence, currentAfterSequence, "scan sequence") === 0
          ) {
            throw new Error("scan events cursor did not advance");
          }
          currentAfterHeight = nextHeight;
          currentAfterSequence = nextSequence;
          if (!hasMore) break;
        }

        const result = await scanNotesCore({
          rootSeed,
          events,
          checkNullifiers: nullifiers => this.checkNullifiers(nullifiers),
          checkNullifier: nullifierHex => this.checkNullifier(nullifierHex),
          includeFoundNotes
        });
        const cursor = scanEventsCursor(lastData || {
          events,
          limit: pageLimit,
          has_more: hasMore,
          next_height: currentAfterHeight,
          next_sequence: currentAfterSequence,
          scan_format_version: 1,
          view_tag_version: 1
        }, {
          afterHeight: startAfterHeight,
          afterSequence: startAfterSequence,
          limit: pageLimit,
          eventTypes: resolvedEventTypes
        });
        return {
          ...result,
          diagnostics: {
            ...result.diagnostics,
            pages_scanned: pagesScanned,
            max_pages: pageBudget
          },
          scanCursor: {
            ...cursor,
            pages_scanned: pagesScanned,
            completed: !hasMore
          },
          nextScanOptions: nextPrivacyScanOptions({
            ...cursor,
            pages_scanned: pagesScanned,
            completed: !hasMore
          }, {
            maxPages: pageBudget,
            includeFoundNotes,
            eventTypes: resolvedEventTypes
          })
        };
      } catch (error) {
        const canFallback = error?.status === 404 || error?.status === 501 || error?.status === 503 || error?.code === "UNSUPPORTED_SCAN_EVENTS_VERSION";
        if (!canFallback) throw error;
        // The legacy endpoint begins at after_height + 1 and has no sequence
        // cursor. Rewind one block so a mid-block scan_events cursor cannot
        // skip the remaining events at that height.
        const rewindHeight = decrementUint64Cursor(startAfterHeight, "scan fallback height");
        legacyAfterHeight = rewindHeight;
        legacyAfterHeightAlias = rewindHeight;
        legacyPage = 1;
      }
    }

    const startPage = Math.max(1, Number(legacyPage || 1));
    const baseRequest = {
      afterHeight: legacyAfterHeight,
      after_height: legacyAfterHeightAlias,
      limit: pageLimit,
      eventTypes: resolvedEventTypes
    };
    const events = [];
    let currentPage = startPage;
    let pagesScanned = 0;
    let hasMore = false;
    let lastData = null;

    for (; pagesScanned < pageBudget;) {
      const request = { ...baseRequest, page: currentPage };
      const data = await this.fetchPrivacyEvents(request);
      lastData = data;
      events.push(...(data.events || []));
      pagesScanned += 1;
      hasMore = Boolean(data.has_more);
      if (!hasMore) break;
      currentPage = Number(data.page || currentPage) + 1;
    }

    const result = await scanNotesCore({
      rootSeed,
      events,
      checkNullifiers: nullifiers => this.checkNullifiers(nullifiers),
      checkNullifier: nullifierHex => this.checkNullifier(nullifierHex),
      includeFoundNotes
    });
    const cursor = privacyEventsCursor({
      ...(lastData || {}),
      events,
      has_more: hasMore
    }, { ...baseRequest, page: lastData?.page ?? currentPage });
    return {
      ...result,
      diagnostics: {
        ...result.diagnostics,
        pages_scanned: pagesScanned,
        max_pages: pageBudget
      },
      scanCursor: {
        ...cursor,
        pages_scanned: pagesScanned,
        next_page: hasMore ? currentPage : 1,
        completed: !hasMore
      },
      nextScanOptions: nextPrivacyScanOptions({
        ...cursor,
        pages_scanned: pagesScanned,
        next_page: hasMore ? currentPage : 1,
        completed: !hasMore
      }, {
        maxPages: pageBudget,
        includeFoundNotes,
        eventTypes: resolvedEventTypes
      })
    };
  }

  async fetchAuditableTransfers(options = {}) {
    const data = await this.fetchPrivacyEvents(options);
    return {
      ...data,
      events: (data.events || []).filter(isAuditableTransfer)
    };
  }

  async findPrivacyEventByTxHash(txHash, {
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page = 1,
    limit = 200,
    maxPages = defaultPrepareScanMaxPages,
    max_pages,
    eventTypes = ["shielded_transfer"],
    event_types,
    scanSource,
    scan_source
  } = {}) {
    const normalizedTxHash = String(txHash || "").trim().toUpperCase();
    if (!normalizedTxHash) {
      throw new Error("txHash is required");
    }
    const pageBudget = Math.max(1, Number(max_pages ?? maxPages ?? defaultPrepareScanMaxPages));
    const pageLimit = Math.max(1, Number(limit || 200));
    const resolvedEventTypes = event_types ?? eventTypes;
    const source = scan_source ?? scanSource ?? "privacy_events";
    if (source !== "privacy_events") {
      let currentAfterHeight = uint64CursorValue(afterHeight ?? after_height ?? 0, "event lookup after height");
      let currentAfterSequence = uint64CursorValue(afterSequence ?? after_sequence ?? 0, "event lookup after sequence");
      for (let pagesScanned = 0; pagesScanned < pageBudget; pagesScanned += 1) {
        const data = await this.fetchScanEvents({
          afterHeight: currentAfterHeight,
          afterSequence: currentAfterSequence,
          limit: pageLimit,
          eventTypes: resolvedEventTypes
        });
        const event = (data.events || []).find(item =>
          String(item.tx_hash_hex || "").toUpperCase() === normalizedTxHash
        );
        if (event) return event;
        if (!Boolean(data.has_more ?? data.hasMore)) break;
        const nextHeight = uint64CursorValue(data.next_height ?? data.nextHeight ?? currentAfterHeight, "event lookup next height");
        const nextSequence = uint64CursorValue(data.next_sequence ?? data.nextSequence ?? currentAfterSequence, "event lookup next sequence");
        if (
          compareUint64Cursor(nextHeight, currentAfterHeight, "event lookup height") === 0 &&
          compareUint64Cursor(nextSequence, currentAfterSequence, "event lookup sequence") === 0
        ) {
          throw new Error("scan events cursor did not advance");
        }
        currentAfterHeight = nextHeight;
        currentAfterSequence = nextSequence;
      }
      throw new Error(`transfer event not found for tx ${normalizedTxHash}`);
    }
    let currentPage = Math.max(1, Number(page || 1));

    for (let pagesScanned = 0; pagesScanned < pageBudget; pagesScanned += 1) {
      const data = await this.fetchPrivacyEvents({
        afterHeight,
        after_height,
        page: currentPage,
        limit: pageLimit,
        eventTypes: resolvedEventTypes
      });
      const event = (data.events || []).find(item => String(item.tx_hash_hex || "").toUpperCase() === normalizedTxHash);
      if (event) {
        return event;
      }
      if (!data.has_more) break;
      currentPage = Number(data.page || currentPage) + 1;
    }
    throw new Error(`transfer event not found for tx ${normalizedTxHash}`);
  }

  derivePrivacyAccount({ address, pubKeyHex, pub_key_hex, signatureBase64, signature_base64 }) {
    const material = derivePrivacyMaterial({
      address,
      pubKeyHex: pubKeyHex ?? pub_key_hex,
      signatureBase64: signatureBase64 ?? signature_base64,
      shieldedPrefix: this.shieldedPrefix
    });
    return {
      signing_message: material.signingMessage,
      shielded_address: material.shieldedAddress,
      disclosure_pubkey_hex: material.disclosurePubKeyHex,
      root_signature_hash: material.rootSignatureHash
    };
  }

  buildDepositMaterial(input) {
    return buildDepositMaterialCore({
      shieldedPrefix: this.shieldedPrefix,
      assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
      ...input
    });
  }

  buildDepositMessage(input) {
    const material = input?.depositMaterial ?? input?.deposit_material ?? (
      input?.material?.note_commitment && input?.material?.encrypted_note
        ? input.material
        : buildDepositMaterialCore({
          shieldedPrefix: this.shieldedPrefix,
          assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
          ...input
        })
    );
    const expectedCreator = String(input?.creator || "").trim();
    if (expectedCreator && String(material.creator || "").trim() !== expectedCreator) {
      throw new Error(`deposit material creator mismatch: expected ${expectedCreator}, got ${material.creator || ""}`);
    }
    const expectedAmount = input?.amount == null
      ? ""
      : parseCoin(input.amount, input?.assetDenom ?? input?.denom ?? this.defaultDenom).raw;
    if (expectedAmount && String(material.amount || "").trim() !== expectedAmount) {
      throw new Error(`deposit material amount mismatch: expected ${expectedAmount}, got ${material.amount || ""}`);
    }
    const proof = requiredDepositProof(input);
    return {
      material,
      message: {
        creator: material.creator,
        amount: material.amount,
        noteCommitment: material.note_commitment,
        encryptedNote: material.encrypted_note,
        proof
      }
    };
  }

  async scanWalletNotes({
    wallet,
    material,
    limit = 200,
    maxPages = 1,
    max_pages,
    noteStore,
    includeFoundNotes = false,
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page,
    eventTypes,
    event_types,
    scanSource,
    scan_source
  } = {}) {
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    let resolvedAfterHeight = afterHeight ?? after_height;
    let resolvedAfterSequence = afterSequence ?? after_sequence;
    let resolvedPage = page;
    let resolvedScanSource = scan_source ?? scanSource;
    if (resolvedAfterHeight == null && noteStore) {
      const cached = await noteStore.load();
      const cachedCursor = cached.scanCursor || {};
      if (cachedCursor.source === "scan_events" || cachedCursor.source === "privacy_events") {
        const next = nextPrivacyScanOptions(cachedCursor, { limit, maxPages });
        const requestedSource = resolvedScanSource;
        const sourceChanged = Boolean(requestedSource && requestedSource !== cachedCursor.source);
        if (sourceChanged) {
          // ScanEvents resumes after an exact (height, sequence), while the legacy
          // endpoint starts at after_height + 1. Rewind one height when translating
          // either cursor so a source switch may duplicate events but cannot skip one.
          resolvedAfterHeight = decrementUint64Cursor(next.afterHeight ?? 0, "scan source switch height");
          resolvedAfterSequence = 0;
          resolvedPage = 1;
        } else {
          resolvedAfterHeight = next.afterHeight;
          resolvedAfterSequence = next.afterSequence ?? 0;
          resolvedPage = resolvedPage ?? next.page;
          resolvedScanSource = next.scanSource ?? cachedCursor.source;
        }
      } else if (cachedCursor.has_more && (cachedCursor.next_sequence != null || cachedCursor.nextSequence != null)) {
        resolvedAfterHeight = cachedCursor.next_height ?? cachedCursor.nextHeight ?? cached.lastScannedHeight ?? 0;
        resolvedAfterSequence = cachedCursor.next_sequence ?? cachedCursor.nextSequence ?? cached.lastScannedSequence ?? 0;
      } else if (cachedCursor.has_more && (cachedCursor.next_page || cachedCursor.nextPage)) {
        resolvedAfterHeight = cachedCursor.after_height ?? cachedCursor.afterHeight ?? cached.lastScannedHeight ?? 0;
        resolvedAfterSequence = cachedCursor.after_sequence ?? cachedCursor.afterSequence ?? cached.lastScannedSequence ?? 0;
        resolvedPage = resolvedPage ?? cachedCursor.next_page ?? cachedCursor.nextPage;
      } else {
        resolvedAfterHeight = cached.lastScannedHeight || 0;
        resolvedAfterSequence = cached.lastScannedSequence || 0;
      }
    }
    const scan = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      limit,
      maxPages: max_pages ?? maxPages,
      afterHeight: resolvedAfterHeight,
      afterSequence: resolvedAfterSequence,
      page: resolvedPage,
      scanSource: resolvedScanSource,
      eventTypes: event_types ?? eventTypes,
      includeFoundNotes: true
    });
    if (noteStore) {
      await noteStore.mergeScanResult(scan, { owner: privacy.address });
      await this.refreshNoteStoreSpentStatuses(noteStore);
    }
    if (includeFoundNotes) {
      return {
        ...scan,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    const { foundNotes: _foundNotes, ...safeScan } = scan;
    return {
      ...safeScan,
      privacyAccount: publicPrivacyAccount(privacy)
    };
  }

  async refreshNoteStoreSpentStatuses(noteStore) {
    if (!noteStore) return null;
    let current = await noteStore.load();
    const nullifiers = [];
    for (const note of current.notes || []) {
      const nullifier = String(note?.nullifier || "").trim().toLowerCase();
      if (!nullifier) continue;
      nullifiers.push(nullifier);
    }
    if (!nullifiers.length) return current;
    const nullifierStatuses = new Map();
    try {
      const statuses = await this.checkNullifiers(nullifiers);
      for (const nullifier of nullifiers) {
        if (statuses.has(nullifier)) {
          const used = parseNullifierUsage(statuses.get(nullifier));
          if (used !== null) {
            nullifierStatuses.set(nullifier, used ? "spent" : "unspent");
          }
        }
      }
      const missing = nullifiers.filter(nullifier => !nullifierStatuses.has(nullifier));
      if (!missing.length) {
        return typeof noteStore.setNullifierStatuses === "function"
          ? noteStore.setNullifierStatuses(nullifierStatuses)
          : current;
      }
      nullifiers.length = 0;
      nullifiers.push(...missing);
    } catch {
      // Check every note individually before marking a cached nullifier as unknown.
    }
    for (const nullifier of nullifiers) {
      try {
        const result = await this.checkNullifier(nullifier);
        const used = parseNullifierUsage(result);
        nullifierStatuses.set(nullifier, used === null ? "unknown" : used ? "spent" : "unspent");
      } catch {
        nullifierStatuses.set(nullifier, "unknown");
      }
    }
    return typeof noteStore.setNullifierStatuses === "function"
      ? noteStore.setNullifierStatuses(nullifierStatuses)
      : current;
  }

  async planWalletTransfer({ wallet, material, amount, denom, limit = 200, maxPages = defaultPrepareScanMaxPages, scan: scanOptions, scanSource, scan_source } = {}) {
    const resolvedScanOptions = resolveScanOptions({ scan: scanOptions, limit, maxPages, scanSource, scan_source });
    const scan = await this.scanWalletNotes({
      wallet,
      material,
      ...resolvedScanOptions,
      limit: resolvedScanOptions.limit ?? 200,
      maxPages: resolvedScanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    return {
      plan: planTransferNotes({
        notes: scan.foundNotes,
        amount,
        denom: denom ?? this.defaultDenom
      }),
      scan
    };
  }

  async planWalletWithdraw({ wallet, material, amount, denom, limit = 200, maxPages = defaultPrepareScanMaxPages, scan: scanOptions, scanSource, scan_source } = {}) {
    const resolvedScanOptions = resolveScanOptions({ scan: scanOptions, limit, maxPages, scanSource, scan_source });
    const scan = await this.scanWalletNotes({
      wallet,
      material,
      ...resolvedScanOptions,
      limit: resolvedScanOptions.limit ?? 200,
      maxPages: resolvedScanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    return {
      plan: planWithdrawNotes({
        notes: scan.foundNotes,
        amount,
        denom: denom ?? this.defaultDenom
      }),
      scan
    };
  }

  async prepareDeposit({ wallet, material, depositMaterial, deposit_material, amount, memo = "Clairveil deposit", gasLimit = 2500000, denom, assetDenom, proof, proofHex, proof_hex } = {}) {
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const prepared = this.buildDepositMessage({
      depositMaterial: depositMaterial ?? deposit_material,
      creator: privacy.address,
      rootSeed: privacy.rootSeed,
      amount,
      assetDenom: assetDenom ?? denom ?? this.defaultDenom,
      memo,
      proof,
      proofHex: proofHex ?? proof_hex
    });
    const signDoc = await this.buildDirectSignDoc({
      signer: privacy.address,
      pubKeyHex: privacy.pubKeyHex,
      gasLimit,
      messages: [
        {
          typeUrl: msgDepositTypeUrl,
          value: prepared.message
        }
      ],
      memo
    });

    return {
      status: "ready",
      signDoc,
      message: prepared.message,
      material: prepared.material,
      privacyAccount: publicPrivacyAccount(privacy)
    };
  }

  async prepareTransfer({
    wallet,
    material,
    amount,
    recipient,
    proverAdapter,
    userPrivacyPolicy = "all-private",
    userDisclosureMode,
    userDisclosureTargetPubKeyHex = "",
    auditDisclosureTargetPubKeyHex,
    expectedRecipientHash,
    expected_recipient_hash,
    expectedAmountHash,
    expected_amount_hash,
    denom,
    allowPlanStep = false,
    scan,
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page,
    limit = 200,
    maxPages = defaultPrepareScanMaxPages,
    max_pages,
    eventTypes,
    event_types,
    scanSource,
    scan_source,
    gasLimit = 8000000,
    reservationManager,
    reservation_manager
  } = {}) {
    const resolvedReservationManager = reservationManager ?? reservation_manager ?? null;
    const operationEvidence = resolveDirectOperationEvidenceHashes({
      expectedRecipientHash,
      expected_recipient_hash,
      expectedAmountHash,
      expected_amount_hash
    });
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const scanOptions = resolveScanOptions({
      scan,
      afterHeight,
      after_height,
      afterSequence,
      after_sequence,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types,
      scanSource,
      scan_source
    });
    const scanResult = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    const availableFoundNotes = await reservationAvailableNotes(resolvedReservationManager, scanResult.foundNotes);
    const plan = planTransferNotes({
      notes: availableFoundNotes,
      amount,
      denom: denom ?? this.defaultDenom
    });
    if (plan.status === "self_merge_required" && !allowPlanStep) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    if (!plan.canBuildTx) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    assertPlanCanBuildTx(plan);

    const auditPubKeyHex = auditDisclosureTargetPubKeyHex
      || (await this.fetchAuditConfig()).audit_master_pubkey_hex;
    const isFinal = plan.status === "final_transfer_ready";
    const stepRecipient = isFinal ? recipient : privacy.shieldedAddress;
    const stepAmount = isFinal ? amount : plan.nextAmount;
    let reservationBatch = null;
    try {
      reservationBatch = await preparePlanReservation(resolvedReservationManager, {
        plan,
        kind: isFinal ? "transfer" : "self_merge",
        metadata: {
          amount: stepAmount,
          recipient: stepRecipient,
          finalAmount: amount,
          finalRecipient: recipient
        }
      });
      const heartbeatResult = await withReservationHeartbeat(resolvedReservationManager, reservationBatch, async ({ assertHeartbeatHealthy, heartbeatNow }) => {
        const built = await this.buildTransferMessage({
          proverAdapter,
          creator: privacy.address,
          inputs: plan.selection.inputs,
          recipient: stepRecipient,
          amount: stepAmount,
          transferDenom: denom ?? this.defaultDenom,
          rootSeed: privacy.rootSeed,
          shieldedPrefix: this.shieldedPrefix,
          userPrivacyPolicy: isFinal ? userPrivacyPolicy : "all-private",
          userDisclosureMode: isFinal ? userDisclosureMode : "none",
          userDisclosureTargetPubKeyHex: isFinal ? userDisclosureTargetPubKeyHex : "",
          auditDisclosureTargetPubKeyHex: auditPubKeyHex
        });
        assertHeartbeatHealthy();
        const signDoc = await this.buildDirectSignDoc({
          signer: privacy.address,
          pubKeyHex: privacy.pubKeyHex,
          gasLimit,
          messages: [
            {
              typeUrl: msgTransferTypeUrl,
              value: built.message
            }
          ],
          memo: reservationBatch
            ? reservationRequiredCosmosMemo("Clairveil veiled transfer")
            : "Clairveil veiled transfer"
        });
        const signDocHash = cosmosSignDocBindingHash(signDoc);
        await heartbeatNow();
        await markReservationProofReady(resolvedReservationManager, reservationBatch, transferProofReadyMetadata(built, {
          amount: stepAmount,
          denom: denom ?? this.defaultDenom,
          expectedRecipientHash: isFinal ? operationEvidence.expectedRecipientHash : "",
          expectedAmountHash: isFinal ? operationEvidence.expectedAmountHash : "",
          signDocHash
        }));
        return {
          built,
          signDoc: markCosmosSignDocReservationRequired(
            signDoc,
            reservationBatch
          )
        };
      });
      const { built, signDoc } = heartbeatResult;

      return {
        ...reservationReconciliationFields(heartbeatResult),
        status: "ready",
        plan,
        scan: scanResult,
        signDoc,
        payload: built.payload,
        proof: built.proof,
        message: built.message,
        reservation: reservationBatchSummary(reservationBatch),
        prepared: {
          planAction: isFinal ? "final_transfer" : "self_merge",
          isFinal,
          amount: stepAmount,
          recipient: stepRecipient,
          finalAmount: amount,
          finalRecipient: recipient,
          selectedInputTotal: plan.selection.total.toString(),
          reservation: reservationBatchSummary(reservationBatch)
        },
        privacyAccount: publicPrivacyAccount(privacy)
      };
    } catch (error) {
      await rollbackPlanReservationPreservingError(resolvedReservationManager, reservationBatch, error);
      throw error;
    }
  }

  async prepareTransferBatch({
    wallet,
    material,
    amounts,
    recipient,
    proverAdapter,
    userPrivacyPolicy = "all-private",
    userDisclosureMode = "none",
    userDisclosureTargetPubKeyHex = "",
    auditDisclosureTargetPubKeyHex,
    expectedRecipientHash,
    expected_recipient_hash,
    expectedRecipientHashes,
    expected_recipient_hashes,
    expectedAmountHashes,
    expected_amount_hashes,
    denom,
    scan,
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page,
    limit = 200,
    maxPages = defaultPrepareScanMaxPages,
    max_pages,
    eventTypes,
    event_types,
    scanSource,
    scan_source,
    gasLimit = 25000000,
    reservationManager,
    reservation_manager
  } = {}) {
    const resolvedReservationManager = reservationManager ?? reservation_manager ?? null;
    const operationEvidence = resolveBatchOperationEvidence({
      amounts,
      expectedRecipientHash,
      expected_recipient_hash,
      expectedRecipientHashes,
      expected_recipient_hashes,
      expectedAmountHashes,
      expected_amount_hashes
    });
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const scanOptions = resolveScanOptions({
      scan,
      afterHeight,
      after_height,
      afterSequence,
      after_sequence,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types,
      scanSource,
      scan_source
    });
    const scanResult = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    const availableFoundNotes = await reservationAvailableNotes(resolvedReservationManager, scanResult.foundNotes);
    const plan = planTransferBatchNotes({
      notes: availableFoundNotes,
      amounts,
      denom: denom ?? this.defaultDenom
    });
    if (!plan.canBuildTx) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    assertPlanCanBuildTx(plan);

    const auditPubKeyHex = auditDisclosureTargetPubKeyHex
      || (await this.fetchAuditConfig()).audit_master_pubkey_hex;
    let reservationBatch = null;
    try {
      reservationBatch = await preparePlanReservation(resolvedReservationManager, {
        plan,
        kind: "batch_transfer",
        metadata: {
          amounts: [...amounts],
          recipient
        }
      });
      const heartbeatResult = await withReservationHeartbeat(resolvedReservationManager, reservationBatch, async ({ assertHeartbeatHealthy, heartbeatNow }) => {
        const items = [];
        for (let i = 0; i < amounts.length; i += 1) {
          const built = await this.buildTransferMessage({
            proverAdapter,
            creator: privacy.address,
            inputs: plan.selections[i].inputs,
            recipient,
            amount: amounts[i],
            transferDenom: denom ?? this.defaultDenom,
            rootSeed: privacy.rootSeed,
            shieldedPrefix: this.shieldedPrefix,
            userPrivacyPolicy,
            userDisclosureMode,
            userDisclosureTargetPubKeyHex,
            auditDisclosureTargetPubKeyHex: auditPubKeyHex
          });
          items.push(built);
          assertHeartbeatHealthy();
        }
        const signDoc = await this.buildDirectSignDoc({
          signer: privacy.address,
          pubKeyHex: privacy.pubKeyHex,
          gasLimit,
          messages: items.map(built => ({
            typeUrl: msgTransferTypeUrl,
            value: built.message
          })),
          memo: reservationBatch
            ? reservationRequiredCosmosMemo("Clairveil batch veiled transfer")
            : "Clairveil batch veiled transfer"
        });
        const signDocHash = cosmosSignDocBindingHash(signDoc);
        await heartbeatNow();
        await markReservationProofReadyForBatchItems(
          resolvedReservationManager,
          reservationBatch,
          items.map((built, i) => ({
            notes: plan.selections[i].inputs,
            metadata: transferProofReadyMetadata(built, {
              amount: amounts[i],
              denom: denom ?? this.defaultDenom,
              expectedRecipientHash: operationEvidence.recipientHashes[i] || "",
              expectedAmountHash: operationEvidence.amountHashes[i] || "",
              batchItemIndex: i,
              batchItemIndexKnown: true,
              signDocHash
            })
          })),
        );
        return {
          builtItems: items,
          signDoc: markCosmosSignDocReservationRequired(
            signDoc,
            reservationBatch
          )
        };
      });
      const { builtItems, signDoc } = heartbeatResult;

      return {
        ...reservationReconciliationFields(heartbeatResult),
        status: "ready",
        plan,
        scan: scanResult,
        signDoc,
        payloads: builtItems.map(built => built.payload),
        proofs: builtItems.map(built => built.proof),
        messages: builtItems.map(built => built.message),
        reservation: reservationBatchSummary(reservationBatch),
        prepared: {
          planAction: "batch_transfer",
          amounts: [...amounts],
          recipient,
          selectedInputTotals: plan.selections.map(selection => selection.total.toString()),
          reservation: reservationBatchSummary(reservationBatch)
        },
        privacyAccount: publicPrivacyAccount(privacy)
      };
    } catch (error) {
      const cleanupErrors = [];
      try {
        await replanProofReadyReservations(resolvedReservationManager, reservationBatch, error, "batch_prepare_failed_after_partial_proof_ready");
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
      try {
        await rollbackPlanReservation(resolvedReservationManager, reservationBatch);
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
      appendReservationCleanupErrors(error, cleanupErrors);
      throw error;
    }
  }

  async prepareWithdraw({
    wallet,
    material,
    amount,
    recipient,
    proverAdapter,
    denom,
    assetDenom,
    scan,
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page,
    limit = 200,
    maxPages = defaultPrepareScanMaxPages,
    max_pages,
    eventTypes,
    event_types,
    scanSource,
    scan_source,
    expiresAtUnix,
    chainNowUnix,
    chain_now_unix,
    gasLimit = 5000000,
    reservationManager,
    reservation_manager
  } = {}) {
    const resolvedReservationManager = reservationManager ?? reservation_manager ?? null;
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const scanOptions = resolveScanOptions({
      scan,
      afterHeight,
      after_height,
      afterSequence,
      after_sequence,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types,
      scanSource,
      scan_source
    });
    const scanResult = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    const availableFoundNotes = await reservationAvailableNotes(resolvedReservationManager, scanResult.foundNotes);
    const plan = planWithdrawNotes({
      notes: availableFoundNotes,
      amount,
      denom: assetDenom ?? denom ?? this.defaultDenom
    });
    if (!plan.canBuildTx) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    assertPlanCanBuildTx(plan);

    let reservationBatch = null;
    try {
      reservationBatch = await preparePlanReservation(resolvedReservationManager, {
        plan,
        kind: "withdraw",
        metadata: {
          amount,
          recipient
        }
      });
      const heartbeatResult = await withReservationHeartbeat(resolvedReservationManager, reservationBatch, async ({ assertHeartbeatHealthy, heartbeatNow }) => {
        const built = await this.buildWithdrawMessage({
          proverAdapter,
          creator: privacy.address,
          notes: [plan.selectedNote],
          amount,
          assetDenom: assetDenom ?? denom ?? this.defaultDenom,
          recipient,
          rootSeed: privacy.rootSeed,
          chainId: this.chainId,
          expiresAtUnix,
          chainNowUnix: chainNowUnix ?? chain_now_unix
        });
        assertHeartbeatHealthy();
        const signDoc = await this.buildDirectSignDoc({
          signer: privacy.address,
          pubKeyHex: privacy.pubKeyHex,
          gasLimit,
          messages: [
            {
              typeUrl: msgWithdrawTypeUrl,
              value: built.message
            }
          ],
          memo: reservationBatch
            ? reservationRequiredCosmosMemo("Clairveil veiled withdraw")
            : "Clairveil veiled withdraw"
        });
        const signDocHash = cosmosSignDocBindingHash(signDoc);
        await heartbeatNow();
        await markReservationProofReady(
          resolvedReservationManager,
          reservationBatch,
          withdrawProofReadyMetadata(built, { signDocHash })
        );
        return {
          built,
          signDoc: markCosmosSignDocReservationRequired(
            signDoc,
            reservationBatch
          )
        };
      });
      const { built, signDoc } = heartbeatResult;

      return {
        ...reservationReconciliationFields(heartbeatResult),
        status: "ready",
        plan,
        scan: scanResult,
        signDoc,
        proverPayload: built.proverPayload,
        proof: built.proof,
        payload: built.payload,
        message: built.message,
        selectedNote: built.selectedNote,
        reservation: reservationBatchSummary(reservationBatch),
        privacyAccount: publicPrivacyAccount(privacy)
      };
    } catch (error) {
      await rollbackPlanReservationPreservingError(resolvedReservationManager, reservationBatch, error);
      throw error;
    }
  }

  async prepareRelayWithdraw({
    wallet,
    material,
    amount,
    recipient,
    proverAdapter,
    denom,
    assetDenom,
    scan,
    afterHeight,
    after_height,
    afterSequence,
    after_sequence,
    page,
    limit = 200,
    maxPages = defaultPrepareScanMaxPages,
    max_pages,
    eventTypes,
    event_types,
    scanSource,
    scan_source,
    expiresAtUnix,
    chainNowUnix,
    chain_now_unix,
    reservationManager,
    reservation_manager
  } = {}) {
    const resolvedReservationManager = reservationManager ?? reservation_manager ?? null;
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const scanOptions = resolveScanOptions({
      scan,
      afterHeight,
      after_height,
      afterSequence,
      after_sequence,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types,
      scanSource,
      scan_source
    });
    const scanResult = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    const availableFoundNotes = await reservationAvailableNotes(resolvedReservationManager, scanResult.foundNotes);
    const plan = planWithdrawNotes({
      notes: availableFoundNotes,
      amount,
      denom: assetDenom ?? denom ?? this.defaultDenom
    });
    if (!plan.canBuildTx) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    assertPlanCanBuildTx(plan);

    let reservationBatch = null;
    try {
      reservationBatch = await preparePlanReservation(resolvedReservationManager, {
        plan,
        kind: "relay_withdraw"
      });
      const heartbeatResult = await withReservationHeartbeat(resolvedReservationManager, reservationBatch, async ({ assertHeartbeatHealthy, heartbeatNow }) => {
        const built = await this.buildRelayWithdrawPayload({
          proverAdapter,
          notes: [plan.selectedNote],
          amount,
          assetDenom: assetDenom ?? denom ?? this.defaultDenom,
          recipient,
          rootSeed: privacy.rootSeed,
          chainId: this.chainId,
          expiresAtUnix,
          chainNowUnix: chainNowUnix ?? chain_now_unix
        });
        assertHeartbeatHealthy();
        await heartbeatNow();
        await markReservationProofReady(resolvedReservationManager, reservationBatch, withdrawProofReadyMetadata(built));
        return { built };
      });
      const { built } = heartbeatResult;

      return {
        ...reservationReconciliationFields(heartbeatResult),
        status: "ready",
        plan,
        scan: scanResult,
        proverPayload: built.proverPayload,
        proof: built.proof,
        payload: built.payload,
        selectedNote: built.selectedNote,
        reservation: reservationBatchSummary(reservationBatch),
        privacyAccount: publicPrivacyAccount(privacy)
      };
    } catch (error) {
      await rollbackPlanReservationPreservingError(resolvedReservationManager, reservationBatch, error);
      throw error;
    }
  }

  async createDepositSignDoc(input) {
    return this.prepareDeposit(input);
  }

  async createTransferSignDoc(input) {
    const result = await this.prepareTransfer(input);
    if (result.status !== "ready") {
      throw new Error(result.plan?.message || `transfer is not ready: ${result.status}`);
    }
    return result;
  }

  async createTransferBatchSignDoc(input) {
    const result = await this.prepareTransferBatch(input);
    if (result.status !== "ready") {
      throw new Error(result.plan?.message || `transfer batch is not ready: ${result.status}`);
    }
    return result;
  }

  async createWithdrawSignDoc(input) {
    const result = await this.prepareWithdraw(input);
    if (result.status !== "ready") {
      throw new Error(result.plan?.message || `withdraw is not ready: ${result.status}`);
    }
    return result;
  }

  async createRelayWithdrawPayload(input) {
    const result = await this.prepareRelayWithdraw(input);
    if (result.status !== "ready") {
      throw new Error(result.plan?.message || `relay withdraw is not ready: ${result.status}`);
    }
    return result;
  }

  async buildPreparedTransferPayload(input) {
    return buildPreparedTransferPayloadCore({
      merklePathProvider: this,
      shieldedPrefix: this.shieldedPrefix,
      transferDenom: input?.transferDenom ?? input?.denom ?? this.defaultDenom,
      ...input
    });
  }

  async buildTransferMessage(input) {
    return buildTransferMessageCore({
      merklePathProvider: this,
      shieldedPrefix: this.shieldedPrefix,
      transferDenom: input?.transferDenom ?? input?.denom ?? this.defaultDenom,
      ...input,
      checkNullifiers: input?.checkNullifiers ?? (nullifiers => this.checkNullifiers(nullifiers))
    });
  }

  async buildPreparedWithdrawProverPayload(input) {
    return buildPreparedWithdrawProverPayloadCore({
      merklePathProvider: this,
      accountPrefix: this.accountPrefix,
      assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
      ...input,
      chainId: input?.chainId ?? this.chainId
    });
  }

  async buildRelayWithdrawPayload(input) {
    return buildRelayWithdrawPayloadCore({
      merklePathProvider: this,
      accountPrefix: this.accountPrefix,
      assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
      ...input,
      chainId: input?.chainId ?? this.chainId,
      checkNullifiers: input?.checkNullifiers ?? (nullifiers => this.checkNullifiers(nullifiers))
    });
  }

  async buildWithdrawMessage(input) {
    return buildWithdrawMessageCore({
      merklePathProvider: this,
      accountPrefix: this.accountPrefix,
      assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
      ...input,
      chainId: input?.chainId ?? this.chainId,
      checkNullifiers: input?.checkNullifiers ?? (nullifiers => this.checkNullifiers(nullifiers))
    });
  }

  buildRelayWithdrawMessageFromPayload({
    payload,
    relayer,
    creator,
    chainNowUnix,
    nowUnix,
    expectedChainId,
    expectedRecipient,
    accountPrefix
  } = {}) {
    if (!payload) {
      throw new Error("payload is required for relay withdraw");
    }
    return buildRelayWithdrawMsgFromPayloadCore(payload, relayer ?? creator, {
      chainNowUnix: chainNowUnix ?? nowUnix,
      expectedChainId: expectedChainId ?? this.chainId,
      expectedRecipient,
      accountPrefix: accountPrefix ?? this.accountPrefix
    });
  }

  async createRelayWithdrawSignDoc({
    payload,
    relayer,
    creator,
    pubKeyHex,
    pub_key_hex,
    gasLimit = 5000000,
    feeAmount = [],
    memo = "Clairveil relay withdraw",
    chainNowUnix,
    nowUnix,
    expectedChainId,
    expectedRecipient,
    accountPrefix
  } = {}) {
    const signer = relayer ?? creator;
    const message = this.buildRelayWithdrawMessageFromPayload({
      payload,
      relayer: signer,
      chainNowUnix: chainNowUnix ?? nowUnix,
      expectedChainId,
      expectedRecipient,
      accountPrefix
    });
    const signDoc = await this.buildDirectSignDoc({
      signer: String(signer || ""),
      pubKeyHex: pubKeyHex ?? pub_key_hex,
      gasLimit,
      feeAmount,
      messages: [
        {
          typeUrl: msgWithdrawTypeUrl,
          value: message
        }
      ],
      memo
    });
    return {
      status: "ready",
      relayer: message.creator,
      payload,
      message,
      signDoc
    };
  }

  async decodeUserDisclosure({
    txHash,
    tx_hash,
    address,
    pubKeyHex,
    pub_key_hex,
    signatureBase64,
    signature_base64,
    skipSignerPubKeyCheck,
    skip_signer_pubkey_check,
    ...eventQuery
  }) {
    const normalizedTxHash = String(txHash ?? tx_hash ?? "").trim().toUpperCase();
    const event = await this.findPrivacyEventByTxHash(normalizedTxHash, eventQuery);
    if (eventAttribute(event, "user_disclosure_mode") === "USER_DISCLOSURE_MODE_PUBLIC") {
      return decodeUserDisclosureFromEvent(
        event,
        1n,
        "",
        normalizedTxHash,
        { shieldedPrefix: this.shieldedPrefix }
      );
    }
    const signerPubKeyHex = pubKeyHex ?? pub_key_hex;
    const skipSignerCheck = Boolean(skipSignerPubKeyCheck ?? skip_signer_pubkey_check);
    if (!skipSignerCheck) {
      assertSignerPubKey(address, signerPubKeyHex, this.bech32Prefix);
    }
    const material = derivePrivacyMaterial({
      address,
      pubKeyHex: signerPubKeyHex,
      signatureBase64: signatureBase64 ?? signature_base64,
      shieldedPrefix: this.shieldedPrefix
    });
    return decodeUserDisclosureFromEvent(
      event,
      material.disclosureScalar,
      material.disclosurePubKeyHex,
      normalizedTxHash,
      { shieldedPrefix: this.shieldedPrefix }
    );
  }

  async decodeSelfViewDisclosure({
    txHash,
    tx_hash,
    address,
    pubKeyHex,
    pub_key_hex,
    signatureBase64,
    signature_base64,
    skipSignerPubKeyCheck,
    skip_signer_pubkey_check,
    disclosureScalar,
    disclosure_scalar,
    disclosureScalarHex,
    disclosure_scalar_hex,
    ...eventQuery
  }) {
    const normalizedTxHash = String(txHash ?? tx_hash ?? "").trim().toUpperCase();
    const event = await this.findPrivacyEventByTxHash(normalizedTxHash, eventQuery);
    const directScalar = disclosureScalar ?? disclosure_scalar;
    const directScalarHex = disclosureScalarHex ?? disclosure_scalar_hex;
    if (directScalar != null || directScalarHex != null) {
      return decodeSelfViewDisclosureFromEvent(
        event,
        directScalar != null ? directScalar : disclosureScalarFromHex(directScalarHex),
        normalizedTxHash,
        { shieldedPrefix: this.shieldedPrefix }
      );
    }
    const signerPubKeyHex = pubKeyHex ?? pub_key_hex;
    const skipSignerCheck = Boolean(skipSignerPubKeyCheck ?? skip_signer_pubkey_check);
    if (!skipSignerCheck) {
      assertSignerPubKey(address, signerPubKeyHex, this.bech32Prefix);
    }
    const material = derivePrivacyMaterial({
      address,
      pubKeyHex: signerPubKeyHex,
      signatureBase64: signatureBase64 ?? signature_base64,
      shieldedPrefix: this.shieldedPrefix
    });
    return decodeSelfViewDisclosureFromEvent(
      event,
      material.disclosureScalar,
      normalizedTxHash,
      { shieldedPrefix: this.shieldedPrefix }
    );
  }

  async decodeAuditDisclosure({ txHash, tx_hash, disclosurePrivKeyHex, disclosure_privkey_hex, ...eventQuery }) {
    const normalizedTxHash = String(txHash ?? tx_hash ?? "").trim().toUpperCase();
    const event = await this.findPrivacyEventByTxHash(normalizedTxHash, eventQuery);
    return decodeAuditDisclosureFromEvent(
      event,
      disclosureScalarFromHex(disclosurePrivKeyHex ?? disclosure_privkey_hex),
      normalizedTxHash,
      { shieldedPrefix: this.shieldedPrefix }
    );
  }

  async buildDirectSignDoc({ signer, pubKeyHex, messages, memo = "", gasLimit = 200000, feeAmount = [] }) {
    assertSignerPubKey(signer, pubKeyHex, this.bech32Prefix);
    const account = await this.getAccountInfo(signer);
    const pubkey = encodePubkey({
      type: "tendermint/PubKeySecp256k1",
      value: toBase64(fromHex(pubKeyHex, "pubKeyHex"))
    });
    const bodyBytes = this.registry.encodeTxBody({
      messages,
      memo
    });
    const authInfoBytes = makeAuthInfoBytes(
      [{ pubkey, sequence: account.sequence }],
      feeAmount,
      gasLimit,
      undefined,
      undefined
    );
    const signDoc = makeSignDoc(bodyBytes, authInfoBytes, this.chainId, account.accountNumber);
    return {
      bodyBytes: toBase64(signDoc.bodyBytes),
      authInfoBytes: toBase64(signDoc.authInfoBytes),
      chainId: signDoc.chainId,
      accountNumber: signDoc.accountNumber.toString()
    };
  }

  buildTxRawBytes({ bodyBytes, authInfoBytes, signature }) {
    const txRaw = TxRaw.fromPartial({
      bodyBytes: fromBase64(bodyBytes, "bodyBytes"),
      authInfoBytes: fromBase64(authInfoBytes, "authInfoBytes"),
      signatures: [fromBase64(signature, "signature")]
    });
    return TxRaw.encode(txRaw).finish();
  }

  async broadcastSignedTx(signedTx, waitOptions) {
    const reservationContext = broadcastReservationContext(waitOptions || signedTx || {});
    const signDocHash = cosmosSignDocBindingHash(signedTx);
    const reservationRequired = cosmosSignDocMetadata(signedTx).reservationRequired ||
      cosmosTxBodyRequiresReservation(signedTx);
    if (reservationRequired && !reservationContext) {
      throw new Error("prepared reserved Cosmos signed transaction requires reservationManager and reservation");
    }
    const txBytes = this.buildTxRawBytes(signedTx);
    const txBytesHash = sha256Hex(txBytes);
    await validateRelayBroadcastContext(waitOptions || signedTx || {}, {
      expectedChainId: this.chainId,
      accountPrefix: this.accountPrefix,
      signedTx,
      reservationContext,
      signDocHash
    });
    const client = await this.connect();
    await beginBroadcastReservation(
      reservationContext,
      "cosmos_broadcast_tx_sync",
      { txBytesHash, signDocHash }
    );
    let txhash = "";
    let tx;
    try {
      txhash = await client.broadcastTxSync(txBytes);
      tx = await this.waitForTx(txhash, waitOptions);
    } catch (error) {
      const wrapped = attachBroadcastEvidence(error, { txHash: txhash, txBytesHash });
      await markBroadcastReservationUnknown(reservationContext, wrapped, { txHash: txhash, txBytesHash });
      throw wrapped;
    }
    const rawTxCode = tx?.code;
    const txCode = typeof rawTxCode === "number"
      ? Number.isSafeInteger(rawTxCode) && rawTxCode >= 0 ? rawTxCode : null
      : typeof rawTxCode === "string" && /^(0|[1-9][0-9]*)$/.test(rawTxCode)
        ? Number(rawTxCode)
        : null;
    const rawLog = String(tx?.raw_log || "");
    const broadcast = {
      txhash,
      code: txCode,
      raw_log: tx ? rawLog : `transaction was broadcast but not found yet: ${txhash}`
    };
    if (tx && txCode !== 0) {
      const detail = txCode == null
        ? "missing or malformed code"
        : `code ${txCode}: ${rawLog || "no raw log"}`;
      const error = new Error(`broadcasted transaction did not include an explicit successful result (${detail})`);
      error.txhash = txhash;
      error.txHash = txhash;
      error.txBytesHash = txBytesHash;
      error.broadcast = broadcast;
      error.tx = tx;
      await markBroadcastReservationUnknown(reservationContext, error, { txHash: txhash, txBytesHash });
      throw error;
    }
    const result = {
      ok: Boolean(tx && txCode === 0),
      broadcast,
      tx,
      txBytesHash,
      error: tx ? "" : broadcast.raw_log
    };
    if (result.ok) {
      await markBroadcastReservationSubmitted(reservationContext, { txHash: txhash, txBytesHash });
    } else {
      await markBroadcastReservationUnknown(
        reservationContext,
        new Error(result.error),
        { txHash: txhash, txBytesHash }
      );
    }
    return result;
  }

  async signDirectAndBroadcast(input = {}) {
    const {
      wallet,
      signDoc,
      waitOptions,
      attempts,
      intervalMs,
      reservationManager,
      reservation_manager,
      reservation,
      reservationBatch,
      reservation_batch
    } = input;
    if (attempts !== undefined && waitOptions?.attempts !== undefined && attempts !== waitOptions.attempts) {
      throw new Error("attempts conflicts with waitOptions.attempts");
    }
    if (intervalMs !== undefined && waitOptions?.intervalMs !== undefined && intervalMs !== waitOptions.intervalMs) {
      throw new Error("intervalMs conflicts with waitOptions.intervalMs");
    }
    const resolvedWaitOptions = {
      ...(waitOptions || {}),
      ...(attempts !== undefined ? { attempts } : {}),
      ...(intervalMs !== undefined ? { intervalMs } : {})
    };
    const resolvedReservation = reservation ?? reservationBatch ?? reservation_batch;
    const reservationContext = broadcastReservationContext({
      ...resolvedWaitOptions,
      reservationManager: reservationManager ?? reservation_manager ?? null,
      reservation: resolvedReservation
    });
    const signDocHash = cosmosSignDocBindingHash(signDoc);
    const reservationRequired = cosmosSignDocMetadata(signDoc).reservationRequired ||
      cosmosTxBodyRequiresReservation(signDoc);
    if (reservationRequired && !reservationContext) {
      throw new Error("prepared reserved Cosmos sign doc requires reservationManager and reservation");
    }
    const walletSignDoc = externalCosmosSignDoc(signDoc);
    const broadcastOptions = {
      ...resolvedWaitOptions,
      reservationManager: reservationManager ?? reservation_manager ?? null,
      reservation: resolvedReservation,
      relayPayload: input.relayPayload ?? input.relay_payload,
      getChainNowUnix: input.getChainNowUnix ?? input.get_chain_now_unix,
      chainNowUnix: input.chainNowUnix ?? input.chain_now_unix,
      expectedChainId: input.expectedChainId ?? input.expected_chain_id,
      expectedRecipient: input.expectedRecipient ?? input.expected_recipient,
      accountPrefix: input.accountPrefix ?? input.account_prefix
    };
    await validateRelayBroadcastContext(broadcastOptions, {
      expectedChainId: this.chainId,
      accountPrefix: this.accountPrefix,
      signedTx: walletSignDoc,
      reservationContext,
      signDocHash
    });
    const adapter = createWalletAdapter(wallet);
    let signed;
    try {
      signed = await adapter.signDirect(directSignDocFromBase64(walletSignDoc), {
        signDoc: walletSignDoc
      });
    } catch (error) {
      if (isExplicitWalletRejection(error)) {
        await markSigningReservationRejected(reservationContext, error);
      }
      throw error;
    }
    const signedDoc = signed.signed || {};
    const signature = signed.signature?.signature || signed.signature;
    return this.broadcastSignedTx({
      bodyBytes: toBase64(signedDoc.bodyBytes || fromBase64(walletSignDoc.bodyBytes, "bodyBytes")),
      authInfoBytes: toBase64(signedDoc.authInfoBytes || fromBase64(walletSignDoc.authInfoBytes, "authInfoBytes")),
      signature
    }, broadcastOptions);
  }
}

export function createClairveilClient(options) {
  return new ClairveilJS(options);
}
