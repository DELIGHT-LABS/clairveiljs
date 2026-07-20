import {
  assertSignerPubKey,
  buildRootSigningMessage,
  createClairveilClient,
  verifySignerPubKey
} from "../transport/cosmos-client.js";
import {
  createClairveilEvmClient,
  evmTransactionBindingHash,
  evmAddressToBech32,
  isEvmAddress,
  markEvmTransactionReservationRequired,
  normalizeEvmAddress
} from "../transport/evm.js";
import {
  derivePrivacyMaterial,
  hexFromBytes
} from "../core/crypto.js";
import {
  ClairveilError,
  ClairveilErrorCode,
  plannerStatusToErrorCode
} from "../core/errors.js";
import {
  parseCoin
} from "../core/note.js";
import {
  assertPlanCanBuildTx,
  planTransferNotes,
  planWithdrawNotes
} from "../privacy/planner.js";
import {
  preparePlanReservation,
  reservationHeartbeatIntervalMs,
  rollbackPlanReservation,
  rollbackPlanReservationPreservingError
} from "../privacy/reservation.js";
import {
  createHttpProverAdapter
} from "../privacy/prover.js";

const defaultPrepareScanMaxPages = 1000;
const defaultFetchTimeoutMs = 30000;

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

function trimTrailingSlash(value) {
  return String(value || "").replace(/\/$/, "");
}

function normalizeRpcEndpoint(value) {
  return trimTrailingSlash(String(value || "").replace(/^tcp:\/\//, "http://"));
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

function browserJsonReplacer(_key, value) {
  return typeof value === "bigint" ? value.toString() : value;
}

function normalizeTimeoutMs(value, label = "timeoutMs") {
  const timeoutMs = Number(value);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error(`${label} must be positive`);
  }
  return timeoutMs;
}

async function fetchJson(url, options = {}) {
  const { timeoutMs = defaultFetchTimeoutMs, ...fetchOptions } = options;
  const resolvedTimeoutMs = normalizeTimeoutMs(timeoutMs, "fetch timeoutMs");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), resolvedTimeoutMs);
  if (fetchOptions.signal) {
    if (fetchOptions.signal.aborted) {
      controller.abort();
    } else {
      fetchOptions.signal.addEventListener("abort", () => controller.abort(), { once: true });
    }
  }
  try {
    const response = await fetch(url, {
      ...fetchOptions,
      headers: {
        accept: "application/json",
        ...(fetchOptions.body ? { "content-type": "application/json" } : {}),
        ...(fetchOptions.headers || {})
      },
      signal: controller.signal
    });
    const text = await response.text();
    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = { error: text };
      }
    }
    if (!response.ok || data?.error) {
      const message = data?.error?.message || data?.error || response.statusText;
      throw new Error(message);
    }
    return data;
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error(`fetch request timed out after ${resolvedTimeoutMs}ms: ${url}`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function privacyEventsQuery({
  afterHeight,
  after_height,
  afterSequence,
  after_sequence,
  page,
  limit,
  eventTypes,
  event_types
} = {}) {
  const params = new URLSearchParams();
  const resolvedAfterHeight = afterHeight ?? after_height;
  if (resolvedAfterHeight != null) params.set("after_height", String(resolvedAfterHeight));
  const resolvedAfterSequence = afterSequence ?? after_sequence;
  if (resolvedAfterSequence != null) params.set("after_sequence", String(resolvedAfterSequence));
  if (page != null) params.set("page", String(page));
  if (limit != null) params.set("limit", String(limit));
  const resolvedEventTypes = eventTypes ?? event_types;
  if (Array.isArray(resolvedEventTypes)) {
    for (const eventType of resolvedEventTypes) {
      if (String(eventType || "").trim()) params.append("event_types", String(eventType).trim());
    }
  } else if (resolvedEventTypes != null && String(resolvedEventTypes).trim()) {
    params.set("event_types", String(resolvedEventTypes).trim());
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

function walletTypeFromBody(body = {}, fallback = "cosmos") {
  const walletType = body.walletType ?? body.wallet_type ?? fallback;
  if (walletType === "cosmos" || walletType === "evm") return walletType;
  throw new ClairveilError(
    ClairveilErrorCode.INVALID_ARGUMENT,
    `unsupported wallet type: ${String(walletType)}`
  );
}

function addIfPresent(target, key, value) {
  if (value != null) {
    target[key] = value;
  }
}

function evmReceiptStatusKind(status) {
  if (typeof status === "number") {
    if (status === 1) return "success";
    if (status === 0) return "failure";
    return "unknown";
  }
  if (typeof status === "bigint") {
    if (status === 1n) return "success";
    if (status === 0n) return "failure";
    return "unknown";
  }
  if (typeof status !== "string") return "unknown";
  const normalized = status.trim().toLowerCase();
  if (/^0x0*1$/.test(normalized)) return "success";
  if (/^0x0+$/.test(normalized)) return "failure";
  return "unknown";
}

function scanOptionsFromBody(body = {}) {
  const scan = body.scan || {};
  return {
    afterHeight: scan.afterHeight ?? scan.after_height ?? body.scanAfterHeight ?? body.scan_after_height ?? body.afterHeight ?? body.after_height,
    afterSequence: scan.afterSequence ?? scan.after_sequence ?? body.scanAfterSequence ?? body.scan_after_sequence ?? body.afterSequence ?? body.after_sequence,
    page: scan.page ?? body.scanPage ?? body.scan_page ?? body.page,
    limit: scan.limit ?? body.scanLimit ?? body.scan_limit ?? body.limit,
    maxPages: scan.maxPages ?? scan.max_pages ?? body.scanMaxPages ?? body.scan_max_pages ?? body.maxPages ?? body.max_pages,
    eventTypes: scan.eventTypes ?? scan.event_types ?? body.eventTypes ?? body.event_types,
    scanSource: scan.scanSource ?? scan.scan_source ?? body.scanSource ?? body.scan_source
  };
}

function relayChainNowUnixFromBody(body = {}) {
  return body.chainNowUnix
    ?? body.chain_now_unix
    ?? body.nowUnix
    ?? body.now_unix;
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
    txBytesHash: context.txBytesHash ?? context.tx_bytes_hash ?? "",
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
    txBytesHash: context.txBytesHash ?? context.tx_bytes_hash ?? "",
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

async function markReservationReplanRequired(reservationManager, reservation, error, reason) {
  if (!reservationManager || !reservation?.reservation_ids?.length) return [];
  if (typeof reservationManager.markReplanRequired !== "function") {
    throw new Error("reservationManager.markReplanRequired is required");
  }
  return reservationManager.markReplanRequired(reservation.reservation_ids, {
    leaseToken: reservation.lease_token || reservation.reservations?.[0]?.lease_token || "",
    error: error?.message || String(error || "reservation replan required"),
    metadata: {
      reconcile_reason: reason,
      no_broadcast_attempt: true,
      proof_discarded: true
    }
  });
}

async function replanProofReadyReservationPreservingError(reservationManager, reservation, error, reason) {
  try {
    await markReservationReplanRequired(reservationManager, reservation, error, reason);
  } catch (cleanupError) {
    appendReservationCleanupErrors(error, [cleanupError]);
  }
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

function positiveCoinForDenom(amount, denom, label) {
  const coin = parseCoin(amount, denom);
  if (coin.denom !== denom) {
    throw new Error(`${label} denom must be ${denom}, got ${coin.denom}`);
  }
  if (BigInt(coin.amount) <= 0n) {
    throw new Error(`${label} amount must be greater than 0.`);
  }
  return coin;
}

function txEventAttribute(event, key) {
  return (event?.attributes || []).find(attribute => attribute.key === key)?.value || "";
}

function txEventsOfType(tx, type) {
  return (tx?.tx_result?.events || tx?.events || []).filter(event => event.type === type);
}

function firstTxEventOfType(tx, type) {
  return txEventsOfType(tx, type)[0] || null;
}

function txMessageAction(tx) {
  return txEventsOfType(tx, "message")
    .map(event => txEventAttribute(event, "action"))
    .find(Boolean) || "";
}

function evmFailureFromTx(tx) {
  return txEventsOfType(tx, "ethereum_tx")
    .map(event => txEventAttribute(event, "ethereumTxFailed"))
    .find(Boolean) || "";
}

function blockEventType(tx) {
  const action = txMessageAction(tx);
  const evmFailure = evmFailureFromTx(tx);
  if (action === "/cosmos.bank.v1beta1.MsgSend") return "bank send";
  if (action === "/clairveil.privacy.v1.MsgDeposit") return "privacy deposit";
  if (action === "/clairveil.privacy.v1.MsgTransfer") return "privacy transfer";
  if (action === "/clairveil.privacy.v1.MsgWithdraw") return "privacy withdraw";
  if (action === "/cosmos.evm.vm.v1.MsgEthereumTx" && evmFailure) return "ethereumtx failed";
  return action ? action.split(".").pop()?.replace(/^Msg/, "").toLowerCase() || "tx" : "tx";
}

function blockEventSummary(tx) {
  const transfer = firstTxEventOfType(tx, "transfer");
  const spent = firstTxEventOfType(tx, "coin_spent");
  const received = firstTxEventOfType(tx, "coin_received");
  const shieldedTransfer = firstTxEventOfType(tx, "shielded_transfer");
  const deposit = firstTxEventOfType(tx, "shielded_deposit") || firstTxEventOfType(tx, "deposit");
  const withdraw = firstTxEventOfType(tx, "shielded_withdraw") || firstTxEventOfType(tx, "withdraw");
  const messageSender = txEventsOfType(tx, "message")
    .map(event => txEventAttribute(event, "sender"))
    .find(Boolean);

  return {
    action: txMessageAction(tx),
    amount: txEventAttribute(transfer, "amount") || txEventAttribute(spent, "amount") || txEventAttribute(received, "amount"),
    from: txEventAttribute(transfer, "sender") || txEventAttribute(spent, "spender") || txEventAttribute(shieldedTransfer, "relayer") || messageSender,
    to: txEventAttribute(transfer, "recipient") || txEventAttribute(received, "receiver") || txEventAttribute(withdraw, "recipient"),
    commitment: txEventAttribute(deposit, "commitment") || txEventAttribute(shieldedTransfer, "commitment_1") || txEventAttribute(withdraw, "commitment"),
    disclosureTarget: txEventAttribute(shieldedTransfer, "user_disclosure_target_pubkey") || txEventAttribute(shieldedTransfer, "audit_disclosure_target_pubkey"),
    evmFailure: evmFailureFromTx(tx)
  };
}

function plannerError(result) {
  const error = new ClairveilError(
    plannerStatusToErrorCode(result?.status),
    result?.plan?.message || `privacy transaction is not ready: ${result?.status || "unknown"}`,
    {
      status: result?.status || "",
      plan: result?.plan || null,
      prepared: result?.prepared || null
    }
  );
  error.status = error.details.status;
  error.plan = error.details.plan;
  error.prepared = error.details.prepared;
  return error;
}

function asBytesBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.slice(i, i + 0x8000));
  }
  return btoa(binary);
}

export class ClairveilBrowserClient {
  constructor({
    profile,
    rpc,
    rest,
    restEndpoints,
    chainId,
    accountPrefix,
    shieldedPrefix,
    denom,
    proverUrl,
    proverTimeoutMs = 120000,
    queryTimeoutMs = defaultFetchTimeoutMs,
    fetchTimeoutMs,
    queryRetry,
    nullifierFailover,
    evmRpc,
    evmChainId,
    evmPrivacyPrecompileAddress,
    evmGasLimit = "0x989680",
    evmSendGasLimit = "0x5208"
  } = {}) {
    const resolved = profile || {};
    this.profile = resolved;
    this.defaultWalletType = walletTypeFromBody({}, resolved.transport ?? "cosmos");
    this.rpc = normalizeRpcEndpoint(resolved.rpc || rpc);
    this.restEndpoints = normalizeRestEndpoints(
      resolved.rest || rest,
      resolved.restEndpoints || restEndpoints
    );
    this.rest = this.restEndpoints[0];
    this.chainId = resolved.chainId || chainId;
    this.accountPrefix = resolved.accountPrefix || accountPrefix || "clair";
    this.shieldedPrefix = resolved.shieldedPrefix || shieldedPrefix || `${this.accountPrefix}s`;
    this.denom = resolved.denom || denom || "uclair";
    this.proverUrl = trimTrailingSlash(resolved.proverUrl || proverUrl || "");
    this.proverTimeoutMs = proverTimeoutMs;
    this.queryTimeoutMs = normalizeTimeoutMs(fetchTimeoutMs ?? queryTimeoutMs, "queryTimeoutMs");
    this.evmRpc = resolved.evmRpc || evmRpc || "";
    this.evmChainId = resolved.evmChainId || evmChainId || "";
    this.evmGasLimit = resolved.evmGasLimit || evmGasLimit;
    this.evmSendGasLimit = resolved.evmSendGasLimit || evmSendGasLimit;
    this.cosmos = createClairveilClient({
      rpc: this.rpc,
      rest: this.rest,
      chainId: this.chainId,
      accountPrefix: this.accountPrefix,
      shieldedPrefix: this.shieldedPrefix,
      defaultDenom: this.denom,
      restEndpoints: this.restEndpoints,
      queryTimeoutMs: this.queryTimeoutMs,
      queryRetry,
      nullifierFailover
    });
    this.evm = createClairveilEvmClient({
      contractAddress: resolved.evmPrivacyPrecompileAddress || evmPrivacyPrecompileAddress,
      chainId: this.chainId,
      accountPrefix: this.accountPrefix,
      shieldedPrefix: this.shieldedPrefix,
      defaultDenom: this.denom
    });
  }

  restUrl(path) {
    return `${this.rest}${path.startsWith("/") ? path : `/${path}`}`;
  }

  rpcUrl(path) {
    return `${this.rpc}${path.startsWith("/") ? path : `/${path}`}`;
  }

  fetchJson(url, options = {}) {
    return fetchJson(url, { timeoutMs: this.queryTimeoutMs, ...options });
  }

  proverAdapter() {
    if (!this.proverUrl) {
      throw new ClairveilError(
        ClairveilErrorCode.PROVER_UNAVAILABLE,
        "proverUrl is required for transfer and withdraw proof generation"
      );
    }
    return createHttpProverAdapter({
      baseURL: this.proverUrl,
      timeoutMs: this.proverTimeoutMs
    });
  }

  async health() {
    const [status, tree, audit] = await Promise.allSettled([
      this.fetchJson(this.rpcUrl("/status")),
      this.cosmos.fetchTreeState(),
      this.cosmos.fetchAuditConfig()
    ]);
    return {
      status: status.status === "fulfilled" ? status.value.result : null,
      tree: tree.status === "fulfilled" ? tree.value : null,
      audit: audit.status === "fulfilled" ? audit.value : null,
      errors: [status, tree, audit]
        .filter(result => result.status === "rejected")
        .map(result => result.reason.message)
    };
  }

  async fetchBlockEvents(rawLimit = 30) {
    const limit = Math.min(Math.max(Number.parseInt(rawLimit, 10) || 30, 1), 50);
    const url = new URL(this.rpcUrl("/tx_search"));
    url.searchParams.set("query", "\"tx.height>=1\"");
    url.searchParams.set("prove", "false");
    url.searchParams.set("page", "1");
    url.searchParams.set("per_page", String(limit));
    url.searchParams.set("order_by", "\"desc\"");

    const data = await this.fetchJson(url);
    return {
      events: (data.result?.txs || []).map(tx => ({
        type: blockEventType(tx),
        height: tx.height,
        tx_hash_hex: tx.hash,
        code: Number(tx.tx_result?.code ?? tx.code ?? 0),
        gas_used: tx.tx_result?.gas_used || "",
        gas_wanted: tx.tx_result?.gas_wanted || "",
        summary: blockEventSummary(tx)
      }))
    };
  }

  async fetchPrivacyEvents(options = {}) {
    return this.cosmos.fetchPrivacyEvents(options);
  }

  async fetchScanEvents(options = {}) {
    return this.cosmos.fetchScanEvents(options);
  }

  async fetchAuditableTransfers(options = {}) {
    return this.cosmos.fetchAuditableTransfers(options);
  }

  async fetchReserve(denom) {
    return this.cosmos.fetchReserve(denom);
  }

  buildRootSigningMessage(address, pubKeyHex) {
    return buildRootSigningMessage(address, pubKeyHex);
  }

  verifySignerPubKey(address, pubKeyHex) {
    return verifySignerPubKey(address, pubKeyHex, this.accountPrefix);
  }

  evmAccountIdentity(value) {
    const evmAddress = normalizeEvmAddress(value, "EVM account");
    return {
      evmAddress,
      address: evmAddressToBech32(evmAddress, this.accountPrefix),
      pubKeyHex: evmAddress.slice(2)
    };
  }

  derivePrivacyAccount(input) {
    return this.cosmos.derivePrivacyAccount(input);
  }

  walletTypeFromBody(body = {}) {
    return walletTypeFromBody(body, this.defaultWalletType);
  }

  privacyMaterial(body, walletType = this.walletTypeFromBody(body)) {
    const material = derivePrivacyMaterial({
      address: body.address,
      pubKeyHex: body.pubKeyHex ?? body.pub_key_hex,
      signatureBase64: body.signatureBase64 ?? body.signature_base64,
      shieldedPrefix: this.shieldedPrefix
    });
    if (walletType !== "evm") {
      assertSignerPubKey(material.address, material.pubKeyHex, this.accountPrefix);
    }
    return material;
  }

  async getBalances(address) {
    return this.cosmos.fetchJson(`/cosmos/bank/v1beta1/balances/${address}`, { failover: true });
  }

  async waitForTx(txHash, options) {
    return this.cosmos.waitForTx(txHash, options);
  }

  async waitForEvmReceipt(txHash, { attempts = 30, intervalMs = 1000 } = {}) {
    const hash = `0x${String(txHash || "").replace(/^0x/i, "").toLowerCase()}`;
    for (let i = 0; i < attempts; i += 1) {
      const receipt = await this.evmJsonRpc("eth_getTransactionReceipt", [hash]);
      if (receipt) return receipt;
      await new Promise(resolve => setTimeout(resolve, intervalMs));
    }
    return null;
  }

  async evmJsonRpc(method, params = []) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.queryTimeoutMs);
    let response;
    try {
      response = await fetch(this.evmRpc, {
        method: "POST",
        headers: { "content-type": "application/json" },
        signal: controller.signal,
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: Date.now(),
          method,
          params
        })
      });
    } catch (error) {
      if (error?.name === "AbortError") {
        throw new Error(`EVM RPC ${method} timed out after ${this.queryTimeoutMs}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
    const data = await response.json();
    if (data.error) {
      throw new Error(data.error.message || `EVM RPC ${method} failed`);
    }
    return data.result;
  }

  async waitForEvmTransaction(txHash) {
    const receipt = await this.waitForEvmReceipt(txHash);
    const receiptStatus = evmReceiptStatusKind(receipt?.status);
    const receiptSucceeded = receiptStatus === "success";
    return {
      txHash: String(txHash || "").replace(/^0x/i, "").toUpperCase(),
      evmTxHash: `0x${String(txHash || "").replace(/^0x/i, "").toLowerCase()}`,
      receipt,
      tx: null,
      ok: Boolean(receipt && receiptSucceeded),
      error: receipt
        ? receiptSucceeded
          ? ""
          : receiptStatus === "failure"
            ? `EVM tx failed with receipt status ${String(receipt.status)}`
            : `EVM tx did not include an explicit successful receipt status: ${String(receipt.status ?? "missing")}`
        : "",
      errors: receipt ? [] : [`EVM tx was broadcast but receipt was not found yet: ${txHash}`]
    };
  }

  evmNativeSendTransaction({ to, amount }) {
    const coin = positiveCoinForDenom(amount, this.denom, "send");
    return {
      to: normalizeEvmAddress(to, "send recipient"),
      chainId: this.evmChainId,
      value: `0x${BigInt(coin.amount).toString(16)}`,
      gas: this.evmSendGasLimit
    };
  }

  async buildBankSendSignDoc({ from, pubKeyHex, to, amount }) {
    const coin = positiveCoinForDenom(amount, this.denom, "send");
    return this.cosmos.buildDirectSignDoc({
      signer: from,
      pubKeyHex,
      messages: [
        {
          typeUrl: "/cosmos.bank.v1beta1.MsgSend",
          value: {
            fromAddress: from,
            toAddress: to,
            amount: [{
              denom: coin.denom,
              amount: coin.amount
            }]
          }
        }
      ],
      memo: "Clairveil DApp signed send"
    });
  }

  async broadcastSignedTx(input, waitOptions) {
    return this.cosmos.broadcastSignedTx(input, waitOptions);
  }

  async signDirectAndBroadcast(input) {
    return this.cosmos.signDirectAndBroadcast(input);
  }

  async prepareDeposit(body) {
    const walletType = this.walletTypeFromBody(body);
    const material = this.privacyMaterial(body, walletType);
    const amount = body.amount;
    let depositMaterial = body.depositMaterial ?? body.deposit_material ?? null;
    if (walletType === "evm") {
      const built = this.evm.buildDepositTransaction({
        material: depositMaterial,
        creator: material.address,
        rootSeed: material.rootSeed,
        amount,
        assetDenom: this.denom
      });
      return {
        transaction: {
          chainId: this.evmChainId,
          gas: this.evmGasLimit,
          ...built.transaction
        },
        prepared: {
          shieldedAddress: built.material.shieldedAddress || material.shieldedAddress,
          noteCommitmentHex: built.material.note_commitment_hex,
          amount: built.material.amount
        }
      };
    }
    let depositProof = body.proof ?? null;
    let depositProofHex = body.proofHex ?? body.proof_hex ?? "";
    if (!depositProof && !depositProofHex && typeof body.depositProofProvider === "function") {
      depositMaterial = depositMaterial ?? this.cosmos.buildDepositMaterial({
        creator: material.address,
        rootSeed: material.rootSeed,
        amount,
        assetDenom: this.denom
      });
      const proof = await body.depositProofProvider({
        material: depositMaterial,
        amount: depositMaterial.amount,
        note: depositMaterial.note,
        noteJson: depositMaterial.note_json,
        note_json: depositMaterial.note_json,
        noteCommitmentHex: depositMaterial.note_commitment_hex,
        note_commitment_hex: depositMaterial.note_commitment_hex
      });
      depositProof = proof?.proof ?? proof?.depositProof ?? proof?.deposit_proof ?? null;
      depositProofHex = proof?.proofHex ?? proof?.proof_hex ?? proof?.depositProofHex ?? proof?.deposit_proof_hex ?? "";
    }
    if (!depositProof && !depositProofHex) {
      throw new Error("deposit proof is required; provide proof/proofHex or depositProofProvider");
    }
    const prepared = await this.cosmos.prepareDeposit({
      material,
      depositMaterial,
      amount,
      gasLimit: 2500000,
      proof: depositProof,
      proofHex: depositProofHex
    });
    return {
      signDoc: prepared.signDoc,
      prepared: {
        shieldedAddress: prepared.privacyAccount.shielded_address,
        noteCommitmentHex: prepared.material.note_commitment_hex,
        amount: prepared.material.amount
      }
    };
  }

  async prepareTransfer(body) {
    const walletType = this.walletTypeFromBody(body);
    const material = this.privacyMaterial(body, walletType);
    const amount = body.amount;
    const recipient = body.recipient;
    const userPrivacyPolicy = body.privacyPolicy ?? body.privacy_policy ?? "all-private";
    const userDisclosureMode = body.disclosureMode ?? body.disclosure_mode ?? "none";
    const userDisclosureTargetPubKeyHex = body.disclosurePubKeyHex ?? body.disclosure_pubkey_hex ?? "";
    const operationEvidence = resolveDirectOperationEvidenceHashes({
      expectedRecipientHash: body.expectedRecipientHash,
      expected_recipient_hash: body.expected_recipient_hash,
      expectedAmountHash: body.expectedAmountHash,
      expected_amount_hash: body.expected_amount_hash
    });
    const allowPlanStep = Boolean(body.allowPlanStep ?? body.allow_plan_step);
    const scanOptions = scanOptionsFromBody(body);
    const reservationManager = body.reservationManager ?? body.reservation_manager ?? null;

    if (walletType !== "evm") {
      const prepared = await this.cosmos.prepareTransfer({
        proverAdapter: this.proverAdapter(),
        material,
        recipient,
        amount,
        userPrivacyPolicy,
        userDisclosureMode,
        userDisclosureTargetPubKeyHex,
        ...(operationEvidence.provided ? {
          expectedRecipientHash: operationEvidence.expectedRecipientHash,
          expectedAmountHash: operationEvidence.expectedAmountHash
        } : {}),
        allowPlanStep,
        scan: scanOptions,
        gasLimit: 8000000,
        reservationManager
      });
      if (prepared.status !== "ready") throw plannerError(prepared);
      return {
        ...reservationReconciliationFields(prepared),
        signDoc: prepared.signDoc,
        reservation: prepared.reservation || null,
        prepared: {
          ...prepared.prepared,
          shieldedAddress: prepared.privacyAccount.shielded_address,
          finalAmount: amount,
          finalRecipient: recipient,
          privacyPolicy: userPrivacyPolicy,
          disclosureMode: userDisclosureMode,
          planStatus: prepared.plan?.status || "",
          planAction: prepared.prepared?.planAction || prepared.plan?.action || ""
        },
        plan: prepared.plan
      };
    }

    const scan = await this.cosmos.scanNotes({
      rootSeed: material.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    const availableFoundNotes = await reservationAvailableNotes(reservationManager, scan.foundNotes);
    const plan = planTransferNotes({ notes: availableFoundNotes, amount, denom: this.denom });
    if (plan.status === "self_merge_required" && !allowPlanStep) throw plannerError({ status: plan.status, plan, scan });
    if (!plan.canBuildTx) throw plannerError({ status: plan.status, plan, scan });
    assertPlanCanBuildTx(plan);

    const audit = await this.cosmos.fetchAuditConfig();
    const auditPubKeyHex = audit.audit_master_pubkey_hex || "";
    const isFinal = plan.status === "final_transfer_ready";
    const stepRecipient = isFinal ? recipient : material.shieldedAddress;
    const stepAmount = isFinal ? amount : plan.nextAmount;
    let reservationBatch = null;
    try {
      reservationBatch = await preparePlanReservation(reservationManager, {
        plan,
        kind: isFinal ? "transfer" : "self_merge",
        metadata: {
          amount: stepAmount,
          recipient: stepRecipient,
          finalAmount: amount,
          finalRecipient: recipient
        }
      });
      const heartbeatResult = await withReservationHeartbeat(reservationManager, reservationBatch, async ({ assertHeartbeatHealthy, heartbeatNow }) => {
        const built = await this.cosmos.buildTransferMessage({
          proverAdapter: this.proverAdapter(),
          creator: material.address,
          inputs: plan.selection.inputs,
          recipient: stepRecipient,
          amount: stepAmount,
          transferDenom: this.denom,
          rootSeed: material.rootSeed,
          shieldedPrefix: this.shieldedPrefix,
          userPrivacyPolicy: isFinal ? userPrivacyPolicy : "all-private",
          userDisclosureMode: isFinal ? userDisclosureMode : "none",
          userDisclosureTargetPubKeyHex: isFinal ? userDisclosureTargetPubKeyHex : "",
          auditDisclosureTargetPubKeyHex: auditPubKeyHex,
          disableSelfViewDisclosure: true
        });
        assertHeartbeatHealthy();
        let transaction = {
          chainId: this.evmChainId,
          gas: this.evmGasLimit,
          ...this.evm.contract.buildTransferTransaction(built.message)
        };
        if (reservationBatch) transaction = markEvmTransactionReservationRequired(transaction);
        const txBytesHash = reservationBatch ? evmTransactionBindingHash(transaction) : "";
        await heartbeatNow();
        await markReservationProofReady(reservationManager, reservationBatch, transferProofReadyMetadata(built, {
          amount: stepAmount,
          denom: this.denom,
          expectedRecipientHash: isFinal ? operationEvidence.expectedRecipientHash : "",
          expectedAmountHash: isFinal ? operationEvidence.expectedAmountHash : "",
          txBytesHash
        }));
        return { built, transaction };
      });
      const { built, transaction } = heartbeatResult;
      return {
        ...reservationReconciliationFields(heartbeatResult),
        transaction,
        reservation: reservationBatchSummary(reservationBatch),
        prepared: {
          ...built,
          planAction: isFinal ? "final_transfer" : "self_merge",
          isFinal,
          amount: stepAmount,
          recipient: stepRecipient,
          finalAmount: amount,
          finalRecipient: recipient,
          selectedInputTotal: plan.selection.total.toString(),
          shieldedAddress: material.shieldedAddress,
          privacyPolicy: userPrivacyPolicy,
          disclosureMode: userDisclosureMode,
          planStatus: plan.status,
          reservation: reservationBatchSummary(reservationBatch)
        },
        plan
      };
    } catch (error) {
      await rollbackPlanReservationPreservingError(reservationManager, reservationBatch, error);
      throw error;
    }
  }

  async prepareTransferBatch(body) {
    const walletType = this.walletTypeFromBody(body);
    if (walletType === "evm") {
      throw new Error("batch transfer is currently supported for Cosmos wallet profiles only");
    }
    const material = this.privacyMaterial(body, walletType);
    const amounts = body.amounts || [];
    const recipient = body.recipient;
    const userPrivacyPolicy = body.privacyPolicy ?? body.privacy_policy ?? "all-private";
    const userDisclosureMode = body.disclosureMode ?? body.disclosure_mode ?? "none";
    const userDisclosureTargetPubKeyHex = body.disclosurePubKeyHex ?? body.disclosure_pubkey_hex ?? "";
    const scanOptions = scanOptionsFromBody(body);
    const reservationManager = body.reservationManager ?? body.reservation_manager ?? null;

    const prepared = await this.cosmos.prepareTransferBatch({
      proverAdapter: this.proverAdapter(),
      material,
      recipient,
      amounts,
      userPrivacyPolicy,
      userDisclosureMode,
      userDisclosureTargetPubKeyHex,
      expectedRecipientHash: body.expectedRecipientHash,
      expected_recipient_hash: body.expected_recipient_hash,
      expectedRecipientHashes: body.expectedRecipientHashes,
      expected_recipient_hashes: body.expected_recipient_hashes,
      expectedAmountHashes: body.expectedAmountHashes,
      expected_amount_hashes: body.expected_amount_hashes,
      scan: scanOptions,
      gasLimit: body.gasLimit ?? body.gas_limit ?? 25000000,
      reservationManager
    });
    if (prepared.status !== "ready") throw plannerError(prepared);
    return {
      ...reservationReconciliationFields(prepared),
      signDoc: prepared.signDoc,
      reservation: prepared.reservation || null,
      prepared: {
        ...prepared.prepared,
        shieldedAddress: prepared.privacyAccount.shielded_address,
        privacyPolicy: userPrivacyPolicy,
        disclosureMode: userDisclosureMode,
        planStatus: prepared.plan?.status || "",
        planAction: prepared.prepared?.planAction || prepared.plan?.action || "",
        payloads: prepared.payloads,
        proofs: prepared.proofs,
        messages: prepared.messages
      },
      plan: prepared.plan
    };
  }

  async prepareWithdraw(body) {
    const walletType = this.walletTypeFromBody(body);
    const material = this.privacyMaterial(body, walletType);
    const amount = body.amount;
    const rawRecipient = body.recipient;
    const evmRecipient = isEvmAddress(rawRecipient) ? normalizeEvmAddress(rawRecipient, "withdraw recipient") : "";
    const recipient = evmRecipient ? evmAddressToBech32(evmRecipient, this.accountPrefix) : rawRecipient;
    const reservationManager = body.reservationManager ?? body.reservation_manager ?? null;

    if (walletType !== "evm") {
      const prepared = await this.cosmos.prepareWithdraw({
        proverAdapter: this.proverAdapter(),
        material,
        amount,
        recipient,
        scan: scanOptionsFromBody(body),
        expiresAtUnix: body.expiresAtUnix ?? body.expires_at_unix,
        chainNowUnix: body.chainNowUnix ?? body.chain_now_unix,
        gasLimit: 5000000,
        reservationManager
      });
      if (prepared.status !== "ready") throw plannerError(prepared);
      return {
        ...reservationReconciliationFields(prepared),
        signDoc: prepared.signDoc,
        payload: prepared.payload,
        proof: prepared.proof,
        message: prepared.message,
        reservation: prepared.reservation || null,
        prepared: {
          shieldedAddress: prepared.privacyAccount.shielded_address,
          amount: prepared.payload.amount,
          recipient: prepared.payload.recipient,
          selectedNoteNullifier: prepared.selectedNote?.nullifier || prepared.payload.nullifier_hex,
          expiresAtUnix: prepared.payload.expires_at_unix,
          payload: prepared.payload,
          proof: prepared.proof,
          message: prepared.message,
          reservation: prepared.reservation || null
        },
        plan: prepared.plan
      };
    }

    const scanOptions = scanOptionsFromBody(body);
    const scan = await this.cosmos.scanNotes({
      rootSeed: material.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    const availableFoundNotes = await reservationAvailableNotes(reservationManager, scan.foundNotes);
    const plan = planWithdrawNotes({ notes: availableFoundNotes, amount, denom: this.denom });
    if (!plan.canBuildTx) throw plannerError({ status: plan.status, plan, scan });
    assertPlanCanBuildTx(plan);
    let reservationBatch = null;
    try {
      reservationBatch = await preparePlanReservation(reservationManager, {
        plan,
        kind: "withdraw",
        metadata: {
          amount,
          recipient
        }
      });
      const heartbeatResult = await withReservationHeartbeat(reservationManager, reservationBatch, async ({ assertHeartbeatHealthy, heartbeatNow }) => {
        const built = await this.cosmos.buildWithdrawMessage({
          proverAdapter: this.proverAdapter(),
          creator: material.address,
          notes: [plan.selectedNote],
          amount,
          assetDenom: this.denom,
          recipient,
          rootSeed: material.rootSeed,
          chainId: this.chainId,
          expiresAtUnix: body.expiresAtUnix ?? body.expires_at_unix,
          chainNowUnix: body.chainNowUnix ?? body.chain_now_unix
        });
        assertHeartbeatHealthy();
        const message = evmRecipient ? { ...built.message, evmRecipient } : built.message;
        const evmBuilt = await this.evm.buildWithdrawTransaction({
          message,
          payload: built.payload,
          proof: built.proof
        });
        let transaction = {
          chainId: this.evmChainId,
          gas: this.evmGasLimit,
          ...evmBuilt.transaction
        };
        if (reservationBatch) transaction = markEvmTransactionReservationRequired(transaction);
        const txBytesHash = reservationBatch ? evmTransactionBindingHash(transaction) : "";
        await heartbeatNow();
        await markReservationProofReady(reservationManager, reservationBatch, withdrawProofReadyMetadata(built, { txBytesHash }));
        return { built, transaction, message };
      });
      const { built, transaction, message } = heartbeatResult;
      return {
        ...reservationReconciliationFields(heartbeatResult),
        transaction,
        payload: built.payload,
        proof: built.proof,
        message,
        reservation: reservationBatchSummary(reservationBatch),
        prepared: {
          shieldedAddress: material.shieldedAddress,
          amount: built.payload.amount,
          recipient: built.payload.recipient,
          evmRecipient,
          selectedNoteNullifier: built.selectedNote?.nullifier || built.payload.nullifier_hex,
          expiresAtUnix: built.payload.expires_at_unix,
          payload: built.payload,
          proof: built.proof,
          message,
          reservation: reservationBatchSummary(reservationBatch)
        },
        plan
      };
    } catch (error) {
      await rollbackPlanReservationPreservingError(reservationManager, reservationBatch, error);
      throw error;
    }
  }

  async prepareRelayWithdraw(body) {
    const walletType = this.walletTypeFromBody(body);
    const material = this.privacyMaterial(body, walletType);
    const amount = body.amount;
    const rawRecipient = body.recipient;
    const evmRecipient = isEvmAddress(rawRecipient) ? normalizeEvmAddress(rawRecipient, "withdraw recipient") : "";
    const recipient = evmRecipient ? evmAddressToBech32(evmRecipient, this.accountPrefix) : rawRecipient;
    const reservationManager = body.reservationManager ?? body.reservation_manager ?? null;
    const prepared = await this.cosmos.prepareRelayWithdraw({
      proverAdapter: this.proverAdapter(),
      material,
      amount,
      recipient,
      scan: scanOptionsFromBody(body),
      expiresAtUnix: body.expiresAtUnix ?? body.expires_at_unix,
      chainNowUnix: relayChainNowUnixFromBody(body),
      reservationManager
    });
    if (prepared.status !== "ready") throw plannerError(prepared);
    if (walletType === "evm") {
      let built;
      try {
        built = await this.evm.buildWithdrawTransaction({
          payload: prepared.payload,
          proof: prepared.proof,
          proverPayload: prepared.proverPayload,
          selectedNote: prepared.selectedNote,
          evmRecipient: evmRecipient || undefined,
          chainNowUnix: relayChainNowUnixFromBody(body),
          transactionOptions: body.transactionOptions ?? body.transaction_options
        });
      } catch (error) {
        await replanProofReadyReservationPreservingError(
          reservationManager,
          prepared.reservation,
          error,
          "evm_relay_transaction_build_failed_before_handoff"
        );
        throw error;
      }
      let transaction = { chainId: this.evmChainId, gas: this.evmGasLimit, ...built.transaction };
      if (prepared.reservation) {
        transaction = markEvmTransactionReservationRequired(transaction);
      }
      return {
        ...reservationReconciliationFields(prepared),
        payload: prepared.payload,
        transaction,
        reservation: prepared.reservation || null,
        prepared: {
          shieldedAddress: prepared.privacyAccount.shielded_address,
          amount: prepared.payload.amount,
          recipient: prepared.payload.recipient,
          evmRecipient,
          selectedNoteNullifier: prepared.selectedNote?.nullifier || prepared.payload.nullifier_hex,
          expiresAtUnix: prepared.payload.expires_at_unix,
          payload: prepared.payload,
          proof: prepared.proof,
          message: built.message,
          reservation: prepared.reservation || null
        },
        plan: prepared.plan
      };
    }
    return {
      ...reservationReconciliationFields(prepared),
      payload: prepared.payload,
      reservation: prepared.reservation || null,
      prepared: {
        shieldedAddress: prepared.privacyAccount.shielded_address,
        amount: prepared.payload.amount,
        recipient: prepared.payload.recipient,
        evmRecipient,
        selectedNoteNullifier: prepared.selectedNote?.nullifier || prepared.payload.nullifier_hex,
        expiresAtUnix: prepared.payload.expires_at_unix,
        payload: prepared.payload,
        proof: prepared.proof,
        reservation: prepared.reservation || null
      },
      plan: prepared.plan
    };
  }

  buildRelayWithdrawMessageFromPayload(body = {}) {
    return this.cosmos.buildRelayWithdrawMessageFromPayload({
      payload: body.payload,
      relayer: body.relayer ?? body.creator ?? body.address,
      chainNowUnix: relayChainNowUnixFromBody(body),
      expectedChainId: body.expectedChainId ?? body.expected_chain_id,
      expectedRecipient: body.expectedRecipient ?? body.expected_recipient,
      accountPrefix: body.accountPrefix ?? body.account_prefix
    });
  }

  async createRelayWithdrawSignDoc(body = {}) {
    const result = await this.cosmos.createRelayWithdrawSignDoc({
      payload: body.payload,
      relayer: body.relayer ?? body.creator ?? body.address,
      pubKeyHex: body.pubKeyHex ?? body.pub_key_hex,
      gasLimit: body.gasLimit ?? body.gas_limit,
      feeAmount: body.feeAmount ?? body.fee_amount ?? [],
      memo: body.memo,
      chainNowUnix: relayChainNowUnixFromBody(body),
      expectedChainId: body.expectedChainId ?? body.expected_chain_id,
      expectedRecipient: body.expectedRecipient ?? body.expected_recipient,
      accountPrefix: body.accountPrefix ?? body.account_prefix
    });
    return {
      signDoc: result.signDoc,
      message: result.message,
      payload: result.payload,
      relayer: result.relayer
    };
  }

  async scanWalletNotes(body) {
    const material = this.privacyMaterial(body);
    const {
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
      scan_source,
      noteStore,
      note_store,
      includeFoundNotes = false
    } = body || {};
    return this.cosmos.scanWalletNotes({
      material,
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
      scan_source,
      noteStore: noteStore ?? note_store,
      includeFoundNotes
    });
  }

  async checkNullifier(nullifierHex) {
    return this.cosmos.checkNullifier(nullifierHex);
  }

  async checkNullifiers(nullifierHexes) {
    return this.cosmos.checkNullifiers(nullifierHexes);
  }

  async decodeUserDisclosure(body) {
    const request = { txHash: body.txHash ?? body.tx_hash };
    addIfPresent(request, "afterHeight", body.afterHeight ?? body.after_height);
    addIfPresent(request, "afterSequence", body.afterSequence ?? body.after_sequence);
    addIfPresent(request, "page", body.page);
    addIfPresent(request, "limit", body.limit);
    addIfPresent(request, "maxPages", body.maxPages ?? body.max_pages);
    addIfPresent(request, "eventTypes", body.eventTypes ?? body.event_types);
    addIfPresent(request, "scanSource", body.scanSource ?? body.scan_source);
    if (body.address && (body.pubKeyHex || body.pub_key_hex) && (body.signatureBase64 || body.signature_base64)) {
      const walletType = this.walletTypeFromBody(body);
      Object.assign(request, walletType === "evm"
        ? { ...body, skipSignerPubKeyCheck: true }
        : body);
    }
    return this.cosmos.decodeUserDisclosure(request);
  }

  async decodeSelfViewDisclosure(body) {
    const request = { txHash: body.txHash ?? body.tx_hash };
    addIfPresent(request, "afterHeight", body.afterHeight ?? body.after_height);
    addIfPresent(request, "afterSequence", body.afterSequence ?? body.after_sequence);
    addIfPresent(request, "page", body.page);
    addIfPresent(request, "limit", body.limit);
    addIfPresent(request, "maxPages", body.maxPages ?? body.max_pages);
    addIfPresent(request, "eventTypes", body.eventTypes ?? body.event_types);
    addIfPresent(request, "scanSource", body.scanSource ?? body.scan_source);
    addIfPresent(request, "disclosureScalar", body.disclosureScalar ?? body.disclosure_scalar);
    addIfPresent(request, "disclosureScalarHex", body.disclosureScalarHex ?? body.disclosure_scalar_hex);
    if (body.address && (body.pubKeyHex || body.pub_key_hex) && (body.signatureBase64 || body.signature_base64)) {
      const walletType = this.walletTypeFromBody(body);
      Object.assign(request, walletType === "evm"
        ? { ...body, skipSignerPubKeyCheck: true }
        : body);
    }
    return this.cosmos.decodeSelfViewDisclosure(request);
  }

  async decodeAuditDisclosure(body = {}) {
    const request = {
      txHash: body.txHash ?? body.tx_hash,
      disclosurePrivKeyHex: body.disclosurePrivKeyHex ?? body.disclosure_privkey_hex
    };
    addIfPresent(request, "afterHeight", body.afterHeight ?? body.after_height);
    addIfPresent(request, "afterSequence", body.afterSequence ?? body.after_sequence);
    addIfPresent(request, "page", body.page);
    addIfPresent(request, "limit", body.limit);
    addIfPresent(request, "maxPages", body.maxPages ?? body.max_pages);
    addIfPresent(request, "eventTypes", body.eventTypes ?? body.event_types);
    addIfPresent(request, "scanSource", body.scanSource ?? body.scan_source);
    return this.cosmos.decodeAuditDisclosure(request);
  }

  txRawBytesBase64({ bodyBytes, authInfoBytes, signature }) {
    return asBytesBase64(this.cosmos.buildTxRawBytes({ bodyBytes, authInfoBytes, signature }));
  }
}

export function createClairveilBrowserClient(options) {
  return new ClairveilBrowserClient(options);
}

export const ClairveilBrowserDappClient = ClairveilBrowserClient;

export function createClairveilBrowserDappClient(options) {
  return createClairveilBrowserClient(options);
}

export {
  buildRootSigningMessage,
  evmAddressToBech32,
  verifySignerPubKey
};
