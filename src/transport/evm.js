import { fromBech32, toBech32 } from "@cosmjs/encoding";
import sha3 from "js-sha3";
import {
  buildDepositMaterial,
  parseCoin
} from "../core/note.js";
import {
  buildPreparedTransferPayload,
  buildTransferMessage,
  buildTransferMsgFromPayloadAndProof,
  buildPreparedWithdrawProverPayload,
  buildWithdrawMsgFromPayload,
  buildWithdrawMessage,
  validateRelayWithdrawPayload
} from "../privacy/payload.js";
import {
  defaultShieldedPrefix,
  bytesFromHex,
  hexFromBytes,
  normalizeBech32Prefix,
  normalizeHex
} from "../core/crypto.js";
import { sha256Hex } from "../core/browser-crypto.js";
import {
  getBroadcastReservationRecords,
  recheckReservedInputNullifiers
} from "../privacy/reservation.js";

export * from "./evm-finality.js";

/**
 * @deprecated Resolve the privacy contract address from the active chain
 * configuration. This compatibility export is never used as an implicit
 * client default.
 */
export const evmPrivacyPrecompileAddress = "0x100000000000000000000000000000000000000b";
/** @deprecated Use an explicit chain-configured contractAddress. */
export const defaultEvmPrivacyPrecompileAddress = evmPrivacyPrecompileAddress;

const { keccak_256: keccak256 } = sha3;
const zeroWord = "0".repeat(64);
const emptyBytes = new Uint8Array();
const evmPrivacyDepositSignature = "deposit((bytes,bytes,bytes))";
const evmPrivacyTransferSignature = "transfer((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes,bytes,bytes,uint64))";
const evmPrivacyWithdrawSignature = "withdraw((bytes,bytes,bytes,string,address,string,uint64))";
const evmPrivacyTransferWithAuthorizationSignature = "transferWithAuthorization((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes,bytes,bytes,uint64),(address,address,uint256,uint64,uint8,bytes))";
const evmPrivacyWithdrawWithAuthorizationSignature = "withdrawWithAuthorization((bytes,bytes,bytes,string,address,string,uint64),(address,address,uint256,uint64,uint8,bytes))";
const evmPrivacyBatchTransferSignature = "batchTransfer(bytes32,(bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes,bytes,bytes,uint64)[])";
const evmPrivacyBatchTransferWithAuthorizationSignature = "batchTransferWithAuthorization(bytes32,((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes,bytes,bytes,uint64),(address,address,uint256,uint64,uint8,bytes))[])";
const evmPrivacySingleProofBatchTransferSignature = "singleProofBatchTransfer((bytes,bytes,bytes[],(bytes,bytes,bytes,uint32,uint8,bytes,bytes,bytes,bytes,bytes,bytes)[],string,uint64,bytes,uint64))";
const evmPrivacySingleProofBatchTransferWithAuthorizationSignature = "singleProofBatchTransferWithAuthorization((bytes,bytes,bytes[],(bytes,bytes,bytes,uint32,uint8,bytes,bytes,bytes,bytes,bytes,bytes)[],string,uint64,bytes,uint64),(address,address,uint256,uint64,uint8,bytes))";
const evmTransactionMarker = Symbol("clairveil.evm-transaction");
const evmTransactionMetadataField = "__clairveilEvmTransaction";
const evmAuthorizationProfileMetadata = Symbol("clairveil.evm-authorization-profile-metadata");

export const evmDepositModeNonpayable = "nonpayable";
export const evmDepositModePayableExactValue = "payable-exact-value";
/** The canonical Clairveil EVM precompile binds payable deposits to exact msg.value. */
export const defaultEvmDepositMode = evmDepositModePayableExactValue;
export const evmDepositModes = Object.freeze([
  evmDepositModeNonpayable,
  evmDepositModePayableExactValue
]);

function normalizedEvmQuantity(value, label) {
  if (value == null || String(value).trim() === "") return "";
  let quantity;
  try {
    quantity = BigInt(value);
  } catch {
    throw new Error(`${label} must be an EVM quantity`);
  }
  if (quantity < 0n) throw new Error(`${label} must be non-negative`);
  return `0x${quantity.toString(16)}`;
}

export function normalizeEvmDepositMode(value = defaultEvmDepositMode) {
  const mode = String(value ?? defaultEvmDepositMode).trim();
  if (!evmDepositModes.includes(mode)) {
    throw new Error(`unsupported EVM deposit mode ${JSON.stringify(mode)}`);
  }
  return mode;
}

function normalizeEvmNativeDenom(value, fallback = "uclair") {
  const denom = String(value ?? fallback).trim();
  if (!denom) throw new Error("EVM native denom is required");
  try {
    return parseCoin(`0${denom}`, denom).denom;
  } catch {
    throw new Error(`invalid EVM native denom ${JSON.stringify(denom)}`);
  }
}

export function evmDepositValueForAmount(amount, nativeDenom = "uclair") {
  const expectedDenom = normalizeEvmNativeDenom(nativeDenom);
  const coin = parseCoin(amount, expectedDenom);
  if (coin.denom !== expectedDenom) {
    throw new Error(
      `payable EVM deposit denom ${coin.denom} does not match native denom ${expectedDenom}`
    );
  }
  if (BigInt(coin.amount) > 0xffffffffffffffffn) {
    throw new Error("payable EVM deposit amount must fit the Clairveil uint64 amount range");
  }
  return normalizedEvmQuantity(coin.amount, "payable EVM deposit amount");
}

function boundDepositTransactionValue(message, options, depositMode, nativeDenom) {
  const mode = normalizeEvmDepositMode(depositMode);
  const expectedValue = mode === evmDepositModePayableExactValue
    ? evmDepositValueForAmount(message?.amount, nativeDenom)
    : "0x0";
  if (Object.prototype.hasOwnProperty.call(options, "value") && options.value != null) {
    const suppliedValue = normalizedEvmQuantity(options.value, "deposit transaction value");
    if (suppliedValue !== expectedValue) {
      throw new Error(
        `deposit transaction value ${suppliedValue} does not match required value ${expectedValue}`
      );
    }
  }
  return expectedValue;
}

function zeroTransactionValue(options, operation) {
  const value = normalizedEvmQuantity(options?.value ?? "0x0", `${operation} transaction value`);
  if (value !== "0x0") {
    throw new Error(`${operation} transaction value must be zero`);
  }
  return "0x0";
}

async function assertWalletEvmChainId(wallet, expectedEvmChainId) {
  if (!expectedEvmChainId) return;
  if (!wallet || typeof wallet.getChainId !== "function") {
    throw new Error("EVM wallet must expose getChainId() before transaction submission");
  }
  const actualEvmChainId = normalizedEvmQuantity(
    await wallet.getChainId(),
    "EVM wallet chain ID"
  );
  if (actualEvmChainId !== expectedEvmChainId) {
    throw new Error(
      `EVM wallet chain ID ${actualEvmChainId} does not match configured evmChainId ${expectedEvmChainId}`
    );
  }
}

function markedEvmTransaction(transaction, metadata = {}) {
  if (!transaction || typeof transaction !== "object") return transaction;
  const current = {
    ...(transaction[evmTransactionMetadataField] || {}),
    ...(transaction[evmTransactionMarker] || {})
  };
  const next = Object.freeze({ ...current, ...metadata });
  const marked = { ...transaction };
  Object.defineProperty(marked, evmTransactionMetadataField, {
    value: next,
    enumerable: true,
    configurable: true
  });
  Object.defineProperty(marked, evmTransactionMarker, {
    value: next,
    enumerable: true,
    configurable: true
  });
  return marked;
}

function evmTransactionMetadata(transaction) {
  return {
    ...(transaction?.[evmTransactionMetadataField] || {}),
    ...(transaction?.[evmTransactionMarker] || {})
  };
}

function privacyTransactionBindingMetadata(transaction, operation, metadata = {}) {
  return {
    operation,
    expectedTo: normalizeEvmAddress(transaction?.to, `${operation} transaction target`),
    expectedData: String(transaction?.data || "").trim().toLowerCase(),
    expectedValue: normalizedEvmQuantity(
      transaction?.value ?? "0x0",
      `${operation} transaction value`
    ),
    ...metadata
  };
}

function canonicalExternalEvmTransaction(transaction) {
  if (!transaction || typeof transaction !== "object") return transaction;
  const canonical = {};
  for (const key of ["from", "to", "data"]) {
    if (!Object.prototype.hasOwnProperty.call(transaction, key) || transaction[key] == null) continue;
    canonical[key] = String(transaction[key]).trim().toLowerCase();
  }
  for (const [key, label] of [
    ["value", "transaction value"],
    ["gas", "transaction gas"],
    ["gasPrice", "transaction gasPrice"],
    ["maxFeePerGas", "transaction maxFeePerGas"],
    ["maxPriorityFeePerGas", "transaction maxPriorityFeePerGas"],
    ["nonce", "transaction nonce"],
    ["chainId", "transaction chainId"]
  ]) {
    if (!Object.prototype.hasOwnProperty.call(transaction, key)) continue;
    const normalized = normalizedEvmQuantity(transaction[key], label);
    if (normalized) canonical[key] = normalized;
  }
  return canonical;
}

function externalEvmTransaction(transaction) {
  return canonicalExternalEvmTransaction(transaction);
}

export function markEvmTransactionReservationRequired(transaction) {
  return markedEvmTransaction(transaction, { reservationRequired: true });
}

export function evmTransactionBindingHash(transaction = {}) {
  const external = canonicalExternalEvmTransaction(transaction);
  const canonical = {
    from: external.from || "",
    to: external.to || "",
    data: external.data || "",
    value: external.value || "0x0",
    gas: external.gas || "",
    gasPrice: external.gasPrice || "",
    maxFeePerGas: external.maxFeePerGas || "",
    maxPriorityFeePerGas: external.maxPriorityFeePerGas || "",
    nonce: external.nonce || "",
    chainId: external.chainId || ""
  };
  return sha256Hex(JSON.stringify(canonical));
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

function isKnownWithdrawTransaction(transaction) {
  if (["withdraw", "withdrawWithAuthorization"].includes(evmTransactionMetadata(transaction).operation)) return true;
  const data = String(transaction?.data || "").trim().replace(/^0x/i, "").toLowerCase();
  return [evmPrivacyWithdrawSignature, evmPrivacyWithdrawWithAuthorizationSignature]
    .some(signature => data.startsWith(functionSelector(signature).toLowerCase()));
}

function knownPrivacyTransactionOperation(transaction) {
  const data = String(transaction?.data || "").trim().replace(/^0x/i, "").toLowerCase();
  for (const [operation, signature] of [
    ["deposit", evmPrivacyDepositSignature],
    ["transfer", evmPrivacyTransferSignature],
    ["withdraw", evmPrivacyWithdrawSignature],
    ["transferWithAuthorization", evmPrivacyTransferWithAuthorizationSignature],
    ["withdrawWithAuthorization", evmPrivacyWithdrawWithAuthorizationSignature],
    ["batchTransfer", evmPrivacyBatchTransferSignature],
    ["batchTransferWithAuthorization", evmPrivacyBatchTransferWithAuthorizationSignature],
    ["singleProofBatchTransfer", evmPrivacySingleProofBatchTransferSignature],
    ["singleProofBatchTransferWithAuthorization", evmPrivacySingleProofBatchTransferWithAuthorizationSignature]
  ]) {
    if (data.startsWith(functionSelector(signature).toLowerCase())) return operation;
  }
  const operation = evmTransactionMetadata(transaction).operation;
  if ([
    "deposit",
    "transfer",
    "withdraw",
    "transferWithAuthorization",
    "withdrawWithAuthorization",
    "batchTransfer",
    "batchTransferWithAuthorization",
    "singleProofBatchTransfer",
    "singleProofBatchTransferWithAuthorization"
  ].includes(operation)) return operation;
  return "";
}

function assertPrivacyTransactionBinding(transaction, depositMode, contractAddress) {
  const operation = knownPrivacyTransactionOperation(transaction);
  if (!operation) return;
  const metadata = evmTransactionMetadata(transaction);
  const actualTo = normalizeEvmAddress(transaction?.to, `${operation} transaction target`);
  const configuredTarget = String(contractAddress ?? "").trim();
  if (configuredTarget &&
      actualTo !== normalizeEvmAddress(configuredTarget, "configured privacy contract target")) {
    throw new Error(`${operation} transaction target does not match the configured privacy contract`);
  }
  if (!configuredTarget && !metadata.expectedTo) {
    throw new Error(`${operation} transaction requires a configured or prepared privacy contract target`);
  }
  const actualValue = normalizedEvmQuantity(
    transaction?.value ?? "0x0",
    `${operation} transaction value`
  );
  const actualData = String(transaction?.data || "").trim().toLowerCase();
  const hasPreparedBinding = [
    metadata.expectedTo,
    metadata.expectedData,
    metadata.expectedValue
  ].some(value => value != null && String(value) !== "");
  if (hasPreparedBinding) {
    if (!metadata.expectedTo || !metadata.expectedData || !metadata.expectedValue) {
      throw new Error(`${operation} transaction binding metadata is incomplete`);
    }
    if (actualTo !== metadata.expectedTo ||
        actualData !== metadata.expectedData ||
        actualValue !== metadata.expectedValue) {
      throw new Error(`${operation} transaction binding was modified after preparation`);
    }
  }
  if (operation !== "deposit") {
    if (actualValue !== "0x0") {
      throw new Error(`${operation} transaction value must be zero`);
    }
    return;
  }
  const mode = normalizeEvmDepositMode(depositMode);
  if (mode === evmDepositModeNonpayable) {
    if (actualValue !== "0x0") {
      throw new Error("nonpayable EVM deposit transaction value must be zero");
    }
    return;
  }
  if (metadata.operation !== "deposit" ||
      metadata.depositMode !== evmDepositModePayableExactValue ||
      !metadata.expectedTo ||
      !metadata.expectedData ||
      !metadata.expectedValue) {
    throw new Error(
      "payable EVM deposit transaction must be built by the configured Clairveil client"
    );
  }
  if (actualTo !== metadata.expectedTo ||
      actualData !== metadata.expectedData ||
      actualValue !== metadata.expectedValue) {
    throw new Error("payable EVM deposit transaction binding was modified after preparation");
  }
}

function assertReservationPayloadMatches(records, payload) {
  if (!records.length) return;
  const payloadHash = String(payload?.payload_hash || "").trim();
  const storedHashes = records.map(record => String(record?.payload_hash ?? record?.payloadHash ?? "").trim());
  if (!payloadHash || storedHashes.some(hash => !hash || hash !== payloadHash)) {
    throw new Error("relay payload does not match the reserved payload hash");
  }
}

function assertReservationTransactionMatches(records, transactionHash, { allowPayloadBinding = false } = {}) {
  if (!records.length) return;
  const mismatched = records.some(record => {
    const storedHash = String(record?.tx_bytes_hash ?? record?.txBytesHash ?? "").trim();
    if (storedHash) return storedHash !== transactionHash;
    return !(allowPayloadBinding && String(record?.payload_hash ?? record?.payloadHash ?? "").trim());
  });
  if (!transactionHash || mismatched) {
    throw new Error("EVM transaction does not match the reservation ProofReady artifact");
  }
}

async function validateRelayBroadcastContext(options, {
  expectedChainId,
  accountPrefix,
  transaction,
  contract,
  reservationContext,
  transactionHash
} = {}) {
  const payload = options?.relayPayload ?? options?.relay_payload ?? null;
  const reservationRecords = await getBroadcastReservationRecords(reservationContext);
  assertReservationTransactionMatches(reservationRecords, transactionHash, { allowPayloadBinding: Boolean(payload) });
  const reservationHasTransactionBinding = reservationRecords.some(record =>
    Boolean(String(record?.tx_bytes_hash ?? record?.txBytesHash ?? "").trim())
  );
  const chainTimeProvider = options?.getChainNowUnix ?? options?.get_chain_now_unix;
  if (!payload) {
    if (isKnownWithdrawTransaction(transaction)) {
      throw new Error("withdraw broadcast requires relayPayload and authoritative chain time");
    }
    if (
      options?.chainNowUnix != null ||
      options?.chain_now_unix != null ||
      chainTimeProvider != null
    ) {
      throw new Error("relayPayload is required when relay broadcast chain time is provided");
    }
    return transaction;
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
  if (!contract || typeof contract.buildWithdrawTransaction !== "function") {
    throw new Error("withdraw broadcast requires a contract adapter for payload binding");
  }
  const message = buildWithdrawMsgFromPayload(payload, "", chainNowUnix);
  const expectedTransaction = contract.buildWithdrawTransaction(
    message,
    options.relayTransactionOptions ?? options.relay_transaction_options ?? {}
  );
  const actualTo = String(transaction?.to || "").trim().toLowerCase();
  const expectedTo = String(expectedTransaction?.to || "").trim().toLowerCase();
  const actualData = String(transaction?.data || "").trim().toLowerCase();
  const expectedData = String(expectedTransaction?.data || "").trim().toLowerCase();
  const actualValue = normalizedEvmQuantity(transaction?.value ?? "0x0", "transaction value");
  const expectedValue = normalizedEvmQuantity(expectedTransaction?.value ?? "0x0", "expected transaction value");
  if (!actualTo || actualTo !== expectedTo || !actualData || actualData !== expectedData || actualValue !== expectedValue) {
    throw new Error("relay payload does not match the EVM transaction being broadcast");
  }
  const actualEvmChainId = normalizedEvmQuantity(transaction?.chainId, "transaction chainId");
  const expectedEvmChainId = normalizedEvmQuantity(
    options?.expectedEvmChainId ?? options?.expected_evm_chain_id,
    "expectedEvmChainId"
  );
  if (actualEvmChainId && !expectedEvmChainId) {
    throw new Error("expectedEvmChainId is required when the relay transaction includes chainId");
  }
  if (actualEvmChainId !== expectedEvmChainId) {
    throw new Error("relay transaction chainId does not match expectedEvmChainId");
  }
  return {
    ...(reservationHasTransactionBinding ? transaction : {}),
    ...expectedTransaction,
    ...(expectedEvmChainId ? { chainId: expectedEvmChainId } : {})
  };
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

async function beginBroadcastReservation(context, txBytesHash) {
  if (!context) return;
  await context.reservationManager.markBroadcastAttempting(context.reservationIDs, {
    leaseToken: context.leaseToken,
    reason: "evm_eth_send_transaction",
    txBytesHash
  });
}

async function markBroadcastReservationManualReview(context, error) {
  if (!context) return;
  try {
    await context.reservationManager.markManualReview(context.reservationIDs, {
      leaseToken: context.leaseToken,
      error: "sdk_evm_broadcast_result_unknown",
      metadata: {
        opaque_broadcast_error: true,
        no_broadcast_attempt: false,
        reconcile_reason: "sdk_evm_broadcast_result_unknown"
      }
    });
  } catch (bookkeepingError) {
    throw attachReservationBookkeepingError(error, bookkeepingError);
  }
}

function isExplicitWalletRejection(error) {
  return String(error?.code ?? error?.data?.code ?? "") === "4001";
}

async function markBroadcastReservationRejected(context, error) {
  if (!context) return;
  try {
    await context.reservationManager.markBroadcastRejected(context.reservationIDs, {
      leaseToken: context.leaseToken,
      error: "wallet_rejected_before_broadcast",
      providerCode: "4001"
    });
  } catch (bookkeepingError) {
    throw attachReservationBookkeepingError(error, bookkeepingError);
  }
}

async function markBroadcastReservationSubmitted(context, txHash) {
  if (!context) return;
  try {
    await context.reservationManager.markSubmitted(context.reservationIDs, {
      leaseToken: context.leaseToken,
      txHash
    });
  } catch (bookkeepingError) {
    const error = new Error("EVM transaction was submitted but reservation submission could not be recorded");
    error.txHash = txHash;
    throw attachReservationBookkeepingError(error, bookkeepingError);
  }
}

const evmPrivacyDepositTuple = {
  name: "request",
  type: "tuple",
  components: [
    { name: "noteCommitment", type: "bytes" },
    { name: "encryptedNote", type: "bytes" },
    { name: "proof", type: "bytes" }
  ]
};
const evmPrivacyTransferTuple = {
  name: "request",
  type: "tuple",
  components: [
    { name: "proof", type: "bytes" },
    { name: "root", type: "bytes" },
    { name: "nullifiers", type: "bytes[]" },
    { name: "newCommitments", type: "bytes[]" },
    { name: "cipherTexts", type: "bytes[]" },
    { name: "viewTags", type: "bytes[]" },
    { name: "userPrivacyPolicy", type: "uint32" },
    { name: "userDisclosureDigest", type: "bytes" },
    { name: "userDisclosureMode", type: "uint8" },
    { name: "userDisclosureTargetPubkey", type: "bytes" },
    { name: "userDisclosurePayload", type: "bytes" },
    { name: "auditDisclosureDigest", type: "bytes" },
    { name: "auditDisclosureTargetPubkey", type: "bytes" },
    { name: "auditDisclosurePayload", type: "bytes" },
    { name: "selfViewDisclosureDigest", type: "bytes" },
    { name: "selfViewDisclosurePayload", type: "bytes" },
    { name: "expiresAtUnix", type: "uint64" }
  ]
};
const evmPrivacyWithdrawTuple = {
  name: "request",
  type: "tuple",
  components: [
    { name: "proof", type: "bytes" },
    { name: "root", type: "bytes" },
    { name: "nullifier", type: "bytes" },
    { name: "amount", type: "string" },
    { name: "recipient", type: "address" },
    { name: "chainId", type: "string" },
    { name: "expiresAtUnix", type: "uint64" }
  ]
};
const evmPrivacyAuthorizationTuple = {
  name: "authorization",
  type: "tuple",
  components: [
    { name: "effectiveSender", type: "address" },
    { name: "executor", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint64" },
    { name: "authorizationKind", type: "uint8" },
    { name: "signature", type: "bytes" }
  ]
};
const evmPrivacySingleProofBatchOutputTuple = {
  name: "output",
  type: "tuple",
  components: [
    { name: "commitment", type: "bytes" },
    { name: "ciphertext", type: "bytes" },
    { name: "viewTag", type: "bytes" },
    { name: "userPrivacyPolicy", type: "uint32" },
    { name: "userDisclosureMode", type: "uint8" },
    { name: "userDisclosureDigest", type: "bytes" },
    { name: "userDisclosureTargetPubkey", type: "bytes" },
    { name: "userDisclosurePayload", type: "bytes" },
    { name: "fullDisclosureDigest", type: "bytes" },
    { name: "auditDisclosurePayload", type: "bytes" },
    { name: "selfViewDisclosurePayload", type: "bytes" }
  ]
};
const evmPrivacySingleProofBatchTuple = {
  name: "request",
  type: "tuple",
  components: [
    { name: "proof", type: "bytes" },
    { name: "root", type: "bytes" },
    { name: "nullifiers", type: "bytes[]" },
    { name: "outputs", type: "tuple[]", components: evmPrivacySingleProofBatchOutputTuple.components },
    { name: "auditKeyId", type: "string" },
    { name: "auditKeyEpoch", type: "uint64" },
    { name: "auditDisclosureTargetPubkey", type: "bytes" },
    { name: "expiresAtUnix", type: "uint64" }
  ]
};
const evmPrivacyAuthorizedTransferItemTuple = {
  name: "item",
  type: "tuple",
  components: [evmPrivacyTransferTuple, evmPrivacyAuthorizationTuple]
};

function evmPrivacyFunction(name, inputs, stateMutability = "nonpayable") {
  return {
    type: "function",
    name,
    stateMutability,
    inputs,
    outputs: [{ name: "success", type: "bool" }]
  };
}

function evmPrivacyEvent(name, inputs) {
  return { type: "event", name, inputs, anonymous: false };
}

/** Default ClairveilJS adapter ABI for compatible EVM privacy precompiles. */
export const evmPrivacyPrecompileAbi = Object.freeze([
  evmPrivacyFunction("deposit", [evmPrivacyDepositTuple], "payable"),
  evmPrivacyFunction("transfer", [evmPrivacyTransferTuple]),
  evmPrivacyFunction("withdraw", [evmPrivacyWithdrawTuple]),
  evmPrivacyFunction("transferWithAuthorization", [evmPrivacyTransferTuple, evmPrivacyAuthorizationTuple]),
  evmPrivacyFunction("withdrawWithAuthorization", [evmPrivacyWithdrawTuple, evmPrivacyAuthorizationTuple]),
  evmPrivacyFunction("singleProofBatchTransfer", [evmPrivacySingleProofBatchTuple]),
  evmPrivacyFunction("singleProofBatchTransferWithAuthorization", [evmPrivacySingleProofBatchTuple, evmPrivacyAuthorizationTuple]),
  evmPrivacyFunction("batchTransfer", [
    { name: "batchId", type: "bytes32" },
    { name: "requests", type: "tuple[]", components: evmPrivacyTransferTuple.components }
  ]),
  evmPrivacyFunction("batchTransferWithAuthorization", [
    { name: "batchId", type: "bytes32" },
    { name: "items", type: "tuple[]", components: evmPrivacyAuthorizedTransferItemTuple.components }
  ]),
  evmPrivacyEvent("PrivacyDeposit", [
    { name: "effectiveSender", type: "address", indexed: true },
    { name: "operator", type: "address", indexed: true },
    { name: "amount", type: "string", indexed: false },
    { name: "noteCommitment", type: "bytes", indexed: false }
  ]),
  evmPrivacyEvent("PrivacyTransfer", [
    { name: "effectiveSender", type: "address", indexed: true },
    { name: "operator", type: "address", indexed: true },
    { name: "root", type: "bytes", indexed: false }
  ]),
  evmPrivacyEvent("PrivacyWithdraw", [
    { name: "effectiveSender", type: "address", indexed: true },
    { name: "operator", type: "address", indexed: true },
    { name: "recipient", type: "address", indexed: true },
    { name: "amount", type: "string", indexed: false }
  ]),
  evmPrivacyEvent("PrivacyBatchTransferItem", [
    { name: "effectiveSender", type: "address", indexed: true },
    { name: "operator", type: "address", indexed: true },
    { name: "batchId", type: "bytes32", indexed: true },
    { name: "itemIndex", type: "uint64", indexed: false },
    { name: "requestHash", type: "bytes32", indexed: false },
    { name: "root", type: "bytes", indexed: false }
  ]),
  evmPrivacyEvent("PrivacySingleProofBatchTransfer", [
    { name: "effectiveSender", type: "address", indexed: true },
    { name: "operator", type: "address", indexed: true },
    { name: "requestHash", type: "bytes32", indexed: true },
    { name: "root", type: "bytes", indexed: false },
    { name: "inputCount", type: "uint8", indexed: false },
    { name: "outputCount", type: "uint8", indexed: false }
  ])
]);
/** Retained as a compatibility export; deposit is already payable in the canonical ABI. */
export const evmPrivacyPrecompilePayableDepositAbi = evmPrivacyPrecompileAbi;

function strip0x(value) {
  return String(value || "").trim().replace(/^0x/i, "");
}

function with0x(hex) {
  return `0x${strip0x(hex).toLowerCase()}`;
}

function bytesLikeToHex(value, label = "bytes") {
  if (value == null) return "";
  if (typeof value === "string") {
    return normalizeHex(value, label);
  }
  return hexFromBytes(Uint8Array.from(value));
}

function padRightWord(hex) {
  const clean = strip0x(hex);
  const remainder = clean.length % 64;
  return remainder === 0 ? clean : clean.padEnd(clean.length + (64 - remainder), "0");
}

function uintWord(value, bits = 256) {
  const n = BigInt(value);
  if (n < 0n) throw new Error("uint value must be non-negative");
  if (bits < 256 && n >= (1n << BigInt(bits))) {
    throw new Error(`uint${bits} value overflow`);
  }
  const hex = n.toString(16);
  if (hex.length > 64) throw new Error("uint value does not fit in 32 bytes");
  return hex.padStart(64, "0");
}

function addressWord(value) {
  const hex = strip0x(value).toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(hex)) {
    throw new Error("EVM address must be 20-byte hex");
  }
  return hex.padStart(64, "0");
}

function bytes32Word(value, label = "bytes32") {
  const hex = bytesLikeToHex(value, label);
  if (hex.length !== 64) {
    throw new Error(`${label} must be 32 bytes`);
  }
  return hex;
}

function utf8Hex(value) {
  return hexFromBytes(new TextEncoder().encode(String(value)));
}

function abiTypeName(type) {
  return typeof type === "string" ? type : type?.type;
}

function abiComponents(type) {
  return type?.components || [];
}

function isDynamicAbiType(type) {
  const name = abiTypeName(type);
  if (name === "tuple") {
    return abiComponents(type).some(component => isDynamicAbiType(component));
  }
  return name === "bytes" || name === "string" || name.endsWith("[]");
}

function encodeStaticAbi(type, value) {
  const name = abiTypeName(type);
  if (name === "tuple") return encodeTupleAbi(type, value);
  if (/^uint(8|16|32|64|128|256)?$/.test(name)) {
    const bits = Number(name.slice(4) || "256");
    return uintWord(value, bits);
  }
  if (name === "bool") {
    if (typeof value !== "boolean") {
      throw new Error("bool ABI value must be a boolean");
    }
    return uintWord(value ? 1 : 0, 8);
  }
  if (name === "address") return addressWord(value);
  if (name === "bytes32") return bytes32Word(value);
  throw new Error(`unsupported static ABI type ${name}`);
}

function encodeBytes(hex) {
  const clean = strip0x(hex);
  return `${uintWord(clean.length / 2)}${padRightWord(clean)}`;
}

function arrayElementAbiType(type) {
  const name = abiTypeName(type);
  if (!name.endsWith("[]")) throw new Error(`ABI type ${name} is not an array`);
  const elementName = name.slice(0, -2);
  return elementName === "tuple"
    ? { type: "tuple", components: abiComponents(type) }
    : elementName;
}

function encodeDynamicArray(type, value) {
  if (!Array.isArray(value)) {
    throw new Error(`${abiTypeName(type)} value must be an array`);
  }
  const elementType = arrayElementAbiType(type);
  const encodedItems = value.map(item => isDynamicAbiType(elementType)
    ? encodeDynamicAbi(elementType, item)
    : encodeStaticAbi(elementType, item));
  if (!isDynamicAbiType(elementType)) {
    return `${uintWord(value.length)}${encodedItems.join("")}`;
  }
  const heads = [];
  let offset = 32 * value.length;
  for (const encoded of encodedItems) {
    heads.push(uintWord(offset));
    offset += encoded.length / 2;
  }
  return `${uintWord(value.length)}${heads.join("")}${encodedItems.join("")}`;
}

function encodeDynamicAbi(type, value) {
  const name = abiTypeName(type);
  if (name === "tuple") return encodeTupleAbi(type, value);
  if (name === "bytes") return encodeBytes(bytesLikeToHex(value));
  if (name === "string") return encodeBytes(utf8Hex(value));
  if (name.endsWith("[]")) return encodeDynamicArray(type, value);
  throw new Error(`unsupported dynamic ABI type ${name}`);
}

function tupleComponentValue(component, value, index) {
  if (Array.isArray(value)) return value[index];
  if (value && typeof value === "object" && component.name) return value[component.name];
  throw new Error(`tuple component ${component.name || index} is missing`);
}

function encodeTupleAbi(type, value) {
  const components = abiComponents(type);
  return encodeAbiParameters(
    components,
    components.map((component, index) => tupleComponentValue(component, value, index))
  );
}

export function functionSelector(signature) {
  return keccak256(String(signature)).slice(0, 8);
}

export function encodeAbiParameters(types, values) {
  if (types.length !== values.length) {
    throw new Error(`ABI parameter count mismatch: ${types.length} types, ${values.length} values`);
  }
  const heads = [];
  const tails = [];
  let tailOffset = types.length * 32;
  for (let i = 0; i < types.length; i += 1) {
    const type = types[i];
    const value = values[i];
    if (isDynamicAbiType(type)) {
      const encoded = encodeDynamicAbi(type, value);
      heads.push(uintWord(tailOffset));
      tails.push(encoded);
      tailOffset += encoded.length / 2;
    } else {
      heads.push(encodeStaticAbi(type, value));
    }
  }
  return `${heads.join("")}${tails.join("")}`;
}

export function encodeFunctionData(signature, types, values) {
  return with0x(`${functionSelector(signature)}${encodeAbiParameters(types, values)}`);
}

export function normalizeEvmAddress(value, label = "EVM address") {
  const hex = strip0x(value).toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(hex)) {
    throw new Error(`${label} must be 20-byte hex`);
  }
  return `0x${hex}`;
}

export function isEvmAddress(value) {
  return typeof value === "string" && /^[0-9a-f]{40}$/i.test(strip0x(value));
}

export function evmAddressToBech32(address, prefix) {
  const normalizedPrefix = normalizeBech32Prefix(prefix, "accountPrefix");
  return toBech32(normalizedPrefix, bytesFromHex(strip0x(normalizeEvmAddress(address)), "EVM address"));
}

export function bech32AddressToEvm(address, expectedPrefix) {
  const decoded = fromBech32(String(address || "").trim());
  if (expectedPrefix) {
    const normalizedPrefix = normalizeBech32Prefix(expectedPrefix, "accountPrefix");
    if (decoded.prefix !== normalizedPrefix) {
      throw new Error(`bech32 address prefix mismatch: expected ${normalizedPrefix}, got ${decoded.prefix}`);
    }
  }
  const bytes = Uint8Array.from(decoded.data);
  if (bytes.length !== 20) {
    throw new Error(`bech32 address must decode to 20 bytes for EVM precompile calls, got ${bytes.length}`);
  }
  return `0x${hexFromBytes(bytes)}`;
}

function valueFrom(object, names, fallback) {
  for (const name of names) {
    if (object?.[name] != null) return object[name];
  }
  return fallback;
}

function requiredBytes(value, label, byteLength) {
  const hex = bytesLikeToHex(value, label);
  if (!hex) throw new Error(`${label} is required`);
  if (byteLength != null && hex.length !== byteLength * 2) {
    throw new Error(`${label} must be ${byteLength} bytes`);
  }
  return value;
}

function optionalBytes(value) {
  // Solidity JSON values commonly spell an omitted `bytes` value as "0x".
  // Preserve its meaning as an empty byte array instead of routing it through
  // the general hex normalizer, which correctly rejects an empty hex body for
  // required byte fields.
  if (value == null) return emptyBytes;
  if (typeof value === "string" && value.trim().toLowerCase() === "0x") {
    return emptyBytes;
  }
  return value;
}

function requiredUint(value, label, bits = 256) {
  if (value == null || String(value).trim() === "") {
    throw new Error(`${label} is required`);
  }
  let parsed;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(`${label} must be a uint${bits}`);
  }
  if (parsed < 0n || parsed >= (1n << BigInt(bits))) {
    throw new Error(`${label} must be a uint${bits}`);
  }
  return parsed;
}

function requiredUint64(value, label) {
  return requiredUint(value, label, 64);
}

function strictTransferUnix(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function aliasedEvmTransferUnix(input, camelName, snakeName, label, { required = false } = {}) {
  const camelProvided = input?.[camelName] !== undefined && input?.[camelName] !== null;
  const snakeProvided = input?.[snakeName] !== undefined && input?.[snakeName] !== null;
  const camel = camelProvided ? strictTransferUnix(input[camelName], label) : undefined;
  const snake = snakeProvided ? strictTransferUnix(input[snakeName], label) : undefined;
  if (camelProvided && snakeProvided && camel !== snake) {
    throw new Error(`${label} aliases conflict`);
  }
  if (required && !camelProvided && !snakeProvided) {
    throw new Error(`${label} is required from authoritative chain time`);
  }
  return camelProvided ? camel : snake;
}

function transferMessageExpiry(message) {
  const camelProvided = message?.expiresAtUnix !== undefined && message?.expiresAtUnix !== null;
  const snakeProvided = message?.expires_at_unix !== undefined && message?.expires_at_unix !== null;
  if (!camelProvided && !snakeProvided) {
    throw new Error("transfer message expiresAtUnix is required");
  }
  const camel = camelProvided
    ? requiredUint64(message.expiresAtUnix, "transfer message expiresAtUnix")
    : undefined;
  const snake = snakeProvided
    ? requiredUint64(message.expires_at_unix, "transfer message expires_at_unix")
    : undefined;
  if (camelProvided && snakeProvided && camel !== snake) {
    throw new Error("transfer message expiresAtUnix aliases conflict");
  }
  return camelProvided ? camel : snake;
}

function assertEvmTransferExecutionBinding(input, built) {
  const chainNowUnix = aliasedEvmTransferUnix(
    input,
    "chainNowUnix",
    "chain_now_unix",
    "transfer chainNowUnix",
    { required: true }
  );
  const requestedExpiry = aliasedEvmTransferUnix(
    input,
    "expiresAtUnix",
    "expires_at_unix",
    "transfer expiresAtUnix"
  );
  const messageExpiry = transferMessageExpiry(built.message);
  if (requestedExpiry !== undefined && BigInt(requestedExpiry) !== messageExpiry) {
    throw new Error("transfer message expiry does not match the requested expiresAtUnix");
  }
  if (BigInt(chainNowUnix) >= messageExpiry) {
    throw new Error("transfer message expired before EVM transaction construction");
  }

  const hasPayload = built.payload !== undefined && built.payload !== null;
  const hasProof = built.proof !== undefined && built.proof !== null;
  if (hasPayload !== hasProof) {
    throw new Error("EVM transfer payload and proof must be supplied together");
  }
  if (hasPayload) {
    const expectedMessage = buildTransferMsgFromPayloadAndProof(
      built.payload,
      built.proof,
      { nowUnix: chainNowUnix }
    );
    if (encodeEvmPrivacyTransfer(expectedMessage) !== encodeEvmPrivacyTransfer(built.message)) {
      throw new Error("EVM transfer message does not match the supplied payload and proof");
    }
  }
}

function bytesArray(value, label, byteLength) {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value.map((item, index) => requiredBytes(item, `${label}[${index}]`, byteLength));
}

function explicitWithdrawEvmRecipient(message) {
  const recipient = valueFrom(message, ["evmRecipient", "evm_recipient", "recipientAddress", "recipient_address"], null);
  return recipient ? normalizeEvmAddress(recipient, "withdraw recipient") : "";
}

function assertWithdrawEvmRecipientMatchesMessage(evmRecipient, messageRecipient, accountPrefix) {
  if (!evmRecipient || messageRecipient == null) return;
  const recipient = String(messageRecipient).trim();
  if (!recipient) return;
  if (isEvmAddress(recipient)) {
    const normalizedRecipient = normalizeEvmAddress(recipient, "withdraw recipient");
    if (normalizedRecipient.toLowerCase() !== evmRecipient.toLowerCase()) {
      throw new Error(`withdraw evmRecipient does not match message recipient: ${evmRecipient} does not match ${normalizedRecipient}`);
    }
    return;
  }
  const decodedRecipient = bech32AddressToEvm(recipient, accountPrefix);
  if (decodedRecipient.toLowerCase() !== evmRecipient.toLowerCase()) {
    throw new Error(`withdraw evmRecipient does not match message recipient: ${evmRecipient} does not match ${decodedRecipient}`);
  }
}

function withdrawRecipientToEvmAddress(message, options = {}) {
  const recipient = explicitWithdrawEvmRecipient(message);
  if (recipient) {
    assertWithdrawEvmRecipientMatchesMessage(recipient, valueFrom(message, ["recipient"], null), options.accountPrefix);
    return recipient;
  }
  const fallback = valueFrom(message, ["recipient"], null);
  if (isEvmAddress(fallback)) return normalizeEvmAddress(fallback, "withdraw recipient");
  return bech32AddressToEvm(fallback, options.accountPrefix);
}

function evmPrivacyDepositRequest(message) {
  return {
    noteCommitment: requiredBytes(valueFrom(message, ["noteCommitment", "note_commitment"], null), "note commitment", 32),
    encryptedNote: requiredBytes(valueFrom(message, ["encryptedNote", "encrypted_note"], null), "encrypted note"),
    proof: requiredBytes(valueFrom(message, ["proof", "depositProof", "deposit_proof"], null), "deposit proof")
  };
}

function evmPrivacyTransferRequest(message) {
  return {
    proof: requiredBytes(valueFrom(message, ["proof"], null), "transfer proof"),
    root: requiredBytes(valueFrom(message, ["root"], null), "transfer root", 32),
    nullifiers: bytesArray(valueFrom(message, ["nullifiers"], null), "transfer nullifiers", 32),
    newCommitments: bytesArray(valueFrom(message, ["newCommitments", "new_commitments"], null), "transfer new commitments", 32),
    cipherTexts: bytesArray(valueFrom(message, ["cipherTexts", "cipher_texts"], null), "transfer cipher texts"),
    viewTags: bytesArray(valueFrom(message, ["viewTags", "view_tags"], null), "transfer view tags", 2),
    userPrivacyPolicy: requiredUint(
      valueFrom(message, ["userPrivacyPolicy", "user_privacy_policy"], 0),
      "transfer user privacy policy",
      32
    ),
    userDisclosureDigest: optionalBytes(valueFrom(message, ["userDisclosureDigest", "user_disclosure_digest"], null)),
    userDisclosureMode: requiredUint(
      valueFrom(message, ["userDisclosureMode", "user_disclosure_mode"], 0),
      "transfer user disclosure mode",
      8
    ),
    userDisclosureTargetPubkey: optionalBytes(valueFrom(message, ["userDisclosureTargetPubkey", "user_disclosure_target_pubkey"], null)),
    userDisclosurePayload: optionalBytes(valueFrom(message, ["userDisclosurePayload", "user_disclosure_payload"], null)),
    auditDisclosureDigest: optionalBytes(valueFrom(message, ["auditDisclosureDigest", "audit_disclosure_digest"], null)),
    auditDisclosureTargetPubkey: optionalBytes(valueFrom(message, ["auditDisclosureTargetPubkey", "audit_disclosure_target_pubkey"], null)),
    auditDisclosurePayload: optionalBytes(valueFrom(message, ["auditDisclosurePayload", "audit_disclosure_payload"], null)),
    selfViewDisclosureDigest: optionalBytes(valueFrom(message, ["selfViewDisclosureDigest", "self_view_disclosure_digest"], null)),
    selfViewDisclosurePayload: optionalBytes(valueFrom(message, ["selfViewDisclosurePayload", "self_view_disclosure_payload"], null)),
    expiresAtUnix: requiredUint64(
      valueFrom(message, ["expiresAtUnix", "expires_at_unix"], null),
      "transfer expiresAtUnix"
    )
  };
}

function evmPrivacyWithdrawRequest(message, options = {}) {
  return {
    proof: requiredBytes(message.proof, "withdraw proof"),
    root: requiredBytes(message.root, "withdraw root", 32),
    nullifier: requiredBytes(message.nullifier, "withdraw nullifier", 32),
    amount: String(message.amount || ""),
    recipient: withdrawRecipientToEvmAddress(message, options),
    chainId: String(message.chainId ?? message.chain_id ?? options.chainId ?? ""),
    expiresAtUnix: requiredUint64(
      message.expiresAtUnix ?? message.expires_at_unix,
      "withdraw expiresAtUnix"
    )
  };
}

function evmPrivacyAuthorization(authorization, { requireSignature = true } = {}) {
  if (!authorization || typeof authorization !== "object") {
    throw new Error("privacy authorization is required");
  }
  const effectiveSender = normalizeEvmAddress(
    valueFrom(authorization, ["effectiveSender", "effective_sender"], null),
    "authorization effectiveSender"
  );
  const executor = normalizeEvmAddress(
    valueFrom(authorization, ["executor"], null),
    "authorization executor"
  );
  const deadline = requiredUint64(valueFrom(authorization, ["deadline"], null), "authorization deadline");
  const authorizationKind = requiredUint(
    valueFrom(authorization, ["authorizationKind", "authorization_kind"], null),
    "authorization kind",
    8
  );
  if (effectiveSender === `0x${"0".repeat(40)}` || executor === `0x${"0".repeat(40)}`) {
    throw new Error("authorization effectiveSender and executor must not be zero");
  }
  if (deadline === 0n) throw new Error("authorization deadline must be positive");
  const signature = valueFrom(authorization, ["signature"], null);
  if (requireSignature && signature == null) {
    throw new Error("authorization signature is required");
  }
  return {
    effectiveSender,
    executor,
    nonce: requiredUint(valueFrom(authorization, ["nonce"], null), "authorization nonce"),
    deadline,
    authorizationKind,
    signature: requireSignature
      ? requiredBytes(signature, "authorization signature")
      : optionalBytes(signature)
  };
}

function evmPrivacySingleProofBatchRequest(message) {
  const outputs = valueFrom(message, ["outputs"], null);
  if (!Array.isArray(outputs) || outputs.length < 1 || outputs.length > 32) {
    throw new Error("single-proof batch outputs must contain 1..32 items");
  }
  const nullifiers = bytesArray(valueFrom(message, ["nullifiers"], null), "single-proof batch nullifiers", 32);
  if (nullifiers.length < 1 || nullifiers.length > 16) {
    throw new Error("single-proof batch nullifiers must contain 1..16 items");
  }
  return {
    proof: requiredBytes(valueFrom(message, ["proof"], null), "single-proof batch proof"),
    root: requiredBytes(valueFrom(message, ["root"], null), "single-proof batch root", 32),
    nullifiers,
    outputs: outputs.map((output, index) => ({
      commitment: requiredBytes(valueFrom(output, ["commitment"], null), `single-proof batch output ${index} commitment`, 32),
      ciphertext: requiredBytes(valueFrom(output, ["ciphertext"], null), `single-proof batch output ${index} ciphertext`, 430),
      viewTag: requiredBytes(valueFrom(output, ["viewTag", "view_tag"], null), `single-proof batch output ${index} view tag`, 2),
      userPrivacyPolicy: requiredUint(valueFrom(output, ["userPrivacyPolicy", "user_privacy_policy"], 0), `single-proof batch output ${index} user privacy policy`, 32),
      userDisclosureMode: requiredUint(valueFrom(output, ["userDisclosureMode", "user_disclosure_mode"], 0), `single-proof batch output ${index} user disclosure mode`, 8),
      userDisclosureDigest: optionalBytes(valueFrom(output, ["userDisclosureDigest", "user_disclosure_digest"], null)),
      userDisclosureTargetPubkey: optionalBytes(valueFrom(output, ["userDisclosureTargetPubkey", "user_disclosure_target_pubkey"], null)),
      userDisclosurePayload: optionalBytes(valueFrom(output, ["userDisclosurePayload", "user_disclosure_payload"], null)),
      fullDisclosureDigest: requiredBytes(valueFrom(output, ["fullDisclosureDigest", "full_disclosure_digest"], null), `single-proof batch output ${index} full disclosure digest`, 32),
      auditDisclosurePayload: requiredBytes(valueFrom(output, ["auditDisclosurePayload", "audit_disclosure_payload"], null), `single-proof batch output ${index} audit disclosure payload`, 472),
      selfViewDisclosurePayload: optionalBytes(valueFrom(output, ["selfViewDisclosurePayload", "self_view_disclosure_payload"], null))
    })),
    auditKeyId: String(valueFrom(message, ["auditKeyId", "audit_key_id"], "")).trim(),
    auditKeyEpoch: requiredUint64(valueFrom(message, ["auditKeyEpoch", "audit_key_epoch"], null), "single-proof batch audit key epoch"),
    auditDisclosureTargetPubkey: requiredBytes(valueFrom(message, ["auditDisclosureTargetPubkey", "audit_disclosure_target_pubkey"], null), "single-proof batch audit disclosure target pubkey"),
    expiresAtUnix: requiredUint64(valueFrom(message, ["expiresAtUnix", "expires_at_unix"], null), "single-proof batch expiresAtUnix")
  };
}

function evmPrivacyBatchId(batchId) {
  const normalized = bytes32Word(batchId, "batchId");
  if (normalized === zeroWord) throw new Error("batchId must not be zero");
  return with0x(normalized);
}

export function encodeEvmPrivacyDeposit(message, options = {}) {
  const request = evmPrivacyDepositRequest(message);
  return encodeFunctionData(
    options.signature || evmPrivacyDepositSignature,
    [evmPrivacyDepositTuple],
    [request]
  );
}

export function encodeEvmPrivacyTransfer(message, options = {}) {
  const request = evmPrivacyTransferRequest(message);
  return encodeFunctionData(
    options.signature || evmPrivacyTransferSignature,
    [evmPrivacyTransferTuple],
    [request]
  );
}

export function encodeEvmPrivacyWithdraw(message, options = {}) {
  const request = evmPrivacyWithdrawRequest(message, options);
  return encodeFunctionData(
    options.signature || evmPrivacyWithdrawSignature,
    [evmPrivacyWithdrawTuple],
    [request]
  );
}

export function encodeEvmPrivacyTransferWithAuthorization(message, authorization, options = {}) {
  return encodeFunctionData(
    options.signature || evmPrivacyTransferWithAuthorizationSignature,
    [evmPrivacyTransferTuple, evmPrivacyAuthorizationTuple],
    [evmPrivacyTransferRequest(message), evmPrivacyAuthorization(authorization)]
  );
}

export function encodeEvmPrivacyWithdrawWithAuthorization(message, authorization, options = {}) {
  return encodeFunctionData(
    options.signature || evmPrivacyWithdrawWithAuthorizationSignature,
    [evmPrivacyWithdrawTuple, evmPrivacyAuthorizationTuple],
    [evmPrivacyWithdrawRequest(message, options), evmPrivacyAuthorization(authorization)]
  );
}

export function encodeEvmPrivacyBatchTransfer(batchId, requests, options = {}) {
  if (!Array.isArray(requests) || requests.length < 1 || requests.length > 20) {
    throw new Error("batch transfer requests must contain 1..20 items");
  }
  return encodeFunctionData(
    options.signature || evmPrivacyBatchTransferSignature,
    [
      { name: "batchId", type: "bytes32" },
      { name: "requests", type: "tuple[]", components: evmPrivacyTransferTuple.components }
    ],
    [evmPrivacyBatchId(batchId), requests.map(evmPrivacyTransferRequest)]
  );
}

export function encodeEvmPrivacyBatchTransferWithAuthorization(batchId, items, options = {}) {
  if (!Array.isArray(items) || items.length < 1 || items.length > 20) {
    throw new Error("authorized batch transfer items must contain 1..20 items");
  }
  return encodeFunctionData(
    options.signature || evmPrivacyBatchTransferWithAuthorizationSignature,
    [
      { name: "batchId", type: "bytes32" },
      { name: "items", type: "tuple[]", components: evmPrivacyAuthorizedTransferItemTuple.components }
    ],
    [evmPrivacyBatchId(batchId), items.map((item, index) => ({
      request: evmPrivacyTransferRequest(item?.request ?? item?.message ?? item),
      authorization: evmPrivacyAuthorization(item?.authorization ?? item?.auth ?? item?.privacyAuthorization)
    }))]
  );
}

export function encodeEvmPrivacySingleProofBatchTransfer(message, options = {}) {
  return encodeFunctionData(
    options.signature || evmPrivacySingleProofBatchTransferSignature,
    [evmPrivacySingleProofBatchTuple],
    [evmPrivacySingleProofBatchRequest(message)]
  );
}

export function encodeEvmPrivacySingleProofBatchTransferWithAuthorization(message, authorization, options = {}) {
  return encodeFunctionData(
    options.signature || evmPrivacySingleProofBatchTransferWithAuthorizationSignature,
    [evmPrivacySingleProofBatchTuple, evmPrivacyAuthorizationTuple],
    [evmPrivacySingleProofBatchRequest(message), evmPrivacyAuthorization(authorization)]
  );
}

export function defaultEncodeEvmDeposit(message, options = {}) {
  return encodeEvmPrivacyDeposit(message, options);
}

export function defaultEncodeEvmTransfer(message, options = {}) {
  return encodeEvmPrivacyTransfer(message, options);
}

export function defaultEncodeEvmWithdraw(message, options = {}) {
  return encodeEvmPrivacyWithdraw(message, options);
}

function keccakHex(value, label = "EVM bytes") {
  const clean = strip0x(bytesLikeToHex(value, label));
  return `0x${keccak256.create().update(bytesFromHex(clean, label)).hex()}`;
}

function receiptHex(value, label) {
  return with0x(bytesLikeToHex(value, label));
}

function receiptAddressTopic(address) {
  return `0x${strip0x(normalizeEvmAddress(address)).padStart(64, "0")}`;
}

function receiptBytes32Topic(value, label) {
  return `0x${bytes32Word(value, label)}`;
}

function requestHashForTransferRequest(request) {
  return keccakHex(encodeAbiParameters([evmPrivacyTransferTuple], [request]), "transfer request encoding");
}

function requestHashForSingleProofBatchRequest(request) {
  return keccakHex(
    `${functionSelector(evmPrivacySingleProofBatchTransferSignature)}${encodeAbiParameters([evmPrivacySingleProofBatchTuple], [request])}`,
    "single-proof batch request encoding"
  );
}

const evmPrivacyAuthorizationTypedDataTypes = Object.freeze({
  EIP712Domain: Object.freeze([
    Object.freeze({ name: "name", type: "string" }),
    Object.freeze({ name: "version", type: "string" }),
    Object.freeze({ name: "chainId", type: "uint256" }),
    Object.freeze({ name: "verifyingContract", type: "address" })
  ]),
  PrivacyActionAuthorization: Object.freeze([
    Object.freeze({ name: "authorizationEnvelopeSelector", type: "bytes4" }),
    Object.freeze({ name: "authorizationActionSelector", type: "bytes4" }),
    Object.freeze({ name: "effectiveSender", type: "address" }),
    Object.freeze({ name: "executor", type: "address" }),
    Object.freeze({ name: "nonce", type: "uint256" }),
    Object.freeze({ name: "deadline", type: "uint64" }),
    Object.freeze({ name: "cosmosChainIdHash", type: "bytes32" }),
    Object.freeze({ name: "requestHash", type: "bytes32" }),
    Object.freeze({ name: "batchId", type: "bytes32" }),
    Object.freeze({ name: "batchItemIndex", type: "uint64" }),
    Object.freeze({ name: "authorizationKind", type: "uint8" })
  ])
});

function normalizeEvmPrivacyAuthorizationDomain(domain) {
  if (!domain || typeof domain !== "object" || Array.isArray(domain)) {
    throw new Error("EVM privacy authorization domain is required");
  }
  const name = String(domain.name ?? "").trim();
  const version = String(domain.version ?? "1").trim();
  if (!name) throw new Error("EVM privacy authorization domain name is required");
  if (!version) throw new Error("EVM privacy authorization domain version is required");
  return Object.freeze({ name, version });
}

function normalizeEvmAuthorizationKindSet(kinds) {
  if (kinds == null) return null;
  if (!Array.isArray(kinds)) {
    throw new Error("supportedAuthorizationKinds must be an array of uint8 values");
  }
  const normalized = kinds.map((kind, index) => requiredUint(
    kind,
    `supportedAuthorizationKinds[${index}]`,
    8
  ));
  if (new Set(normalized).size !== normalized.length) {
    throw new Error("supportedAuthorizationKinds must not contain duplicates");
  }
  return new Set(normalized);
}

function normalizeEvmAuthorizationProfile(profile) {
  if (profile == null) return null;
  if (typeof profile !== "object" || Array.isArray(profile)) {
    throw new Error("EVM authorization profile must be an object");
  }
  if (profile.validate != null && typeof profile.validate !== "function") {
    throw new Error("EVM authorization profile validate must be a function");
  }
  if (profile.buildTypedData != null && typeof profile.buildTypedData !== "function") {
    throw new Error("EVM authorization profile buildTypedData must be a function");
  }
  if (typeof profile.validate !== "function" && typeof profile.buildTypedData !== "function") {
    throw new Error("EVM authorization profile must provide validate or buildTypedData");
  }
  return profile;
}

function validateEvmPrivacyAuthorization(authorization, profile, options = {}) {
  const normalized = evmPrivacyAuthorization(authorization, options);
  profile?.validate?.(normalized);
  return normalized;
}

/**
 * Creates a policy for an EVM privacy authorization envelope.  The target
 * chain chooses its accepted authorization kinds and EIP-712 domain; neither
 * is imposed by the transport itself.
 */
export function createEvmAuthorizationProfile({
  supportedAuthorizationKinds,
  typedDataDomain,
  validate
} = {}) {
  const supportedKinds = normalizeEvmAuthorizationKindSet(supportedAuthorizationKinds);
  const domain = typedDataDomain == null
    ? null
    : normalizeEvmPrivacyAuthorizationDomain(typedDataDomain);
  if (validate != null && typeof validate !== "function") {
    throw new Error("authorization profile validate must be a function");
  }
  const applyPolicy = authorization => {
    if (supportedKinds && !supportedKinds.has(authorization.authorizationKind)) {
      throw new Error(`unsupported EVM privacy authorization kind ${authorization.authorizationKind}`);
    }
    if (validate) validate(authorization);
    return authorization;
  };
  const profile = {
    validate(authorization) {
      applyPolicy(authorization);
    },
    ...(domain ? {
      buildTypedData(input = {}) {
        const authorization = applyPolicy(
          evmPrivacyAuthorization(input.authorization, { requireSignature: false })
        );
        return buildEvmPrivacyAuthorizationTypedData({
          ...input,
          authorization,
          domain
        });
      }
    } : {})
  };
  Object.defineProperty(profile, evmAuthorizationProfileMetadata, {
    value: Object.freeze({
      supportedAuthorizationKinds: supportedKinds
        ? Object.freeze([...supportedKinds].sort((left, right) => left < right ? -1 : left > right ? 1 : 0))
        : null,
      typedDataDomain: domain,
      validate: validate ?? null
    })
  });
  return Object.freeze(profile);
}

function authorizationProfilesCompatible(left, right) {
  if (left === right) return true;
  const leftMetadata = left?.[evmAuthorizationProfileMetadata];
  const rightMetadata = right?.[evmAuthorizationProfileMetadata];
  if (!leftMetadata || !rightMetadata) return false;
  return operationIndependentValuesEqual(
    leftMetadata.supportedAuthorizationKinds,
    rightMetadata.supportedAuthorizationKinds
  ) && operationIndependentValuesEqual(
    leftMetadata.typedDataDomain,
    rightMetadata.typedDataDomain
  ) && leftMetadata.validate === rightMetadata.validate;
}

function operationIndependentValuesEqual(left, right) {
  if (left === right) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) &&
      left.length === right.length &&
      left.every((value, index) => operationIndependentValuesEqual(value, right[index]));
  }
  if (!left || !right || typeof left !== "object" || typeof right !== "object") {
    return false;
  }
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return leftKeys.length === rightKeys.length && leftKeys.every((key, index) =>
    key === rightKeys[index] && operationIndependentValuesEqual(left[key], right[key])
  );
}

/** Build a canonical Clairveil EVM PrivacyActionAuthorization EIP-712 payload. */
export function buildEvmPrivacyAuthorizationTypedData({
  action,
  request,
  authorization,
  cosmosChainId,
  evmChainId,
  contractAddress,
  batchId = `0x${zeroWord}`,
  batchItemIndex = 0,
  domain
} = {}) {
  const normalizedAuthorization = evmPrivacyAuthorization(authorization, { requireSignature: false });
  const normalizedDomain = normalizeEvmPrivacyAuthorizationDomain(domain);
  const canonicalAction = String(action || "").trim();
  const actionConfig = {
    transfer: {
      envelope: evmPrivacyTransferWithAuthorizationSignature,
      action: evmPrivacyTransferSignature,
      request: () => evmPrivacyTransferRequest(request),
      requestHash: requestHashForTransferRequest,
      batch: false
    },
    withdraw: {
      envelope: evmPrivacyWithdrawWithAuthorizationSignature,
      action: evmPrivacyWithdrawSignature,
      request: () => evmPrivacyWithdrawRequest(request, { chainId: cosmosChainId }),
      requestHash: value => keccakHex(encodeAbiParameters([evmPrivacyWithdrawTuple], [value]), "withdraw request encoding"),
      batch: false
    },
    batchTransfer: {
      envelope: evmPrivacyBatchTransferWithAuthorizationSignature,
      action: evmPrivacyTransferSignature,
      request: () => evmPrivacyTransferRequest(request),
      requestHash: requestHashForTransferRequest,
      batch: true
    },
    singleProofBatchTransfer: {
      envelope: evmPrivacySingleProofBatchTransferWithAuthorizationSignature,
      action: evmPrivacySingleProofBatchTransferSignature,
      request: () => evmPrivacySingleProofBatchRequest(request),
      requestHash: requestHashForSingleProofBatchRequest,
      batch: false
    }
  }[canonicalAction];
  if (!actionConfig) {
    throw new Error("privacy authorization action must be transfer, withdraw, batchTransfer, or singleProofBatchTransfer");
  }
  const normalizedCosmosChainId = String(cosmosChainId || "").trim();
  if (!normalizedCosmosChainId) throw new Error("cosmosChainId is required for privacy authorization");
  const normalizedEvmChainId = requiredUint(evmChainId, "evmChainId");
  if (contractAddress == null || String(contractAddress).trim() === "") {
    throw new Error("privacy authorization contractAddress is required");
  }
  const verifyingContract = normalizeEvmAddress(contractAddress, "privacy authorization verifying contract");
  const normalizedBatchId = actionConfig.batch ? evmPrivacyBatchId(batchId) : `0x${zeroWord}`;
  const normalizedBatchItemIndex = actionConfig.batch
    ? requiredUint64(batchItemIndex, "batchItemIndex")
    : 0n;
  const normalizedRequest = actionConfig.request();
  const requestHash = actionConfig.requestHash(normalizedRequest);
  return Object.freeze({
    types: evmPrivacyAuthorizationTypedDataTypes,
    primaryType: "PrivacyActionAuthorization",
    domain: Object.freeze({
      name: normalizedDomain.name,
      version: normalizedDomain.version,
      chainId: normalizedEvmChainId.toString(),
      verifyingContract
    }),
    message: Object.freeze({
      authorizationEnvelopeSelector: `0x${functionSelector(actionConfig.envelope)}`,
      authorizationActionSelector: `0x${functionSelector(actionConfig.action)}`,
      effectiveSender: normalizedAuthorization.effectiveSender,
      executor: normalizedAuthorization.executor,
      nonce: normalizedAuthorization.nonce.toString(),
      deadline: normalizedAuthorization.deadline.toString(),
      cosmosChainIdHash: `0x${keccak256(normalizedCosmosChainId)}`,
      requestHash,
      batchId: normalizedBatchId,
      batchItemIndex: normalizedBatchItemIndex.toString(),
      authorizationKind: normalizedAuthorization.authorizationKind.toString()
    })
  });
}

function receiptExpectationForDeposit(message, nativeDenom) {
  const request = evmPrivacyDepositRequest(message);
  const amount = parseCoin(message?.amount, nativeDenom).raw;
  return {
    event: "PrivacyDeposit",
    effectiveSender: "operator",
    amount,
    noteCommitment: receiptHex(request.noteCommitment, "note commitment")
  };
}

function receiptExpectationForTransfer(message, authorization = null) {
  const request = evmPrivacyTransferRequest(message);
  return {
    event: "PrivacyTransfer",
    effectiveSender: authorization
      ? normalizeEvmAddress(evmPrivacyAuthorization(authorization).effectiveSender)
      : "operator",
    root: receiptHex(request.root, "transfer root")
  };
}

function receiptExpectationForWithdraw(message, options, authorization = null) {
  const request = evmPrivacyWithdrawRequest(message, options);
  return {
    event: "PrivacyWithdraw",
    effectiveSender: authorization
      ? normalizeEvmAddress(evmPrivacyAuthorization(authorization).effectiveSender)
      : "operator",
    recipient: request.recipient,
    amount: request.amount
  };
}

function receiptExpectationForBatch(batchId, requests, items = null) {
  const normalizedBatchId = evmPrivacyBatchId(batchId);
  const entries = (items || requests).map((item, index) => {
    const request = evmPrivacyTransferRequest(items ? (item?.request ?? item?.message ?? item) : item);
    const authorization = items
      ? evmPrivacyAuthorization(item?.authorization ?? item?.auth ?? item?.privacyAuthorization)
      : null;
    return {
      itemIndex: BigInt(index),
      effectiveSender: authorization ? authorization.effectiveSender : "operator",
      requestHash: requestHashForTransferRequest(request),
      root: receiptHex(request.root, `batch request ${index} root`)
    };
  });
  return { event: "PrivacyBatchTransferItem", batchId: normalizedBatchId, entries };
}

function receiptExpectationForSingleProofBatch(message, authorization = null) {
  const request = evmPrivacySingleProofBatchRequest(message);
  return {
    event: "PrivacySingleProofBatchTransfer",
    effectiveSender: authorization
      ? normalizeEvmAddress(evmPrivacyAuthorization(authorization).effectiveSender)
      : "operator",
    requestHash: requestHashForSingleProofBatchRequest(request),
    root: receiptHex(request.root, "single-proof batch root"),
    inputCount: BigInt(request.nullifiers.length),
    outputCount: BigInt(request.outputs.length)
  };
}

function receiptExpectationForCanonicalTransaction(transaction, buildCanonicalData, buildExpectation) {
  const data = strip0x(transaction?.data).toLowerCase();
  let canonicalData;
  try {
    canonicalData = typeof buildCanonicalData === "function"
      ? buildCanonicalData()
      : buildCanonicalData;
  } catch {
    // A public custom adapter can intentionally support a legacy or otherwise
    // non-canonical request shape. It remains usable as a transaction adapter,
    // but it cannot receive the SDK's strong event-evidence guarantee.
    return null;
  }
  const expected = strip0x(canonicalData).toLowerCase();
  // Receipt events for transfers bind only part of the request. Attach a
  // strict expectation only when the adapter returned the exact canonical
  // EVM calldata that the SDK validated, never merely a matching selector.
  return data && expected && data === expected ? buildExpectation() : null;
}

function receiptData(value, label) {
  const clean = strip0x(value);
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(clean)) {
    throw new Error(`${label} must be even-length hex`);
  }
  return clean.toLowerCase();
}

function receiptWord(data, index, label) {
  const start = index * 64;
  const word = data.slice(start, start + 64);
  if (word.length !== 64) throw new Error(`${label} is truncated`);
  return word;
}

function receiptUint(data, index, label) {
  return BigInt(`0x${receiptWord(data, index, label)}`);
}

function receiptDynamicBytes(data, index, label) {
  const offset = receiptUint(data, index, `${label} offset`);
  if (offset > BigInt(Number.MAX_SAFE_INTEGER) || offset % 32n !== 0n) {
    throw new Error(`${label} has an invalid offset`);
  }
  const offsetIndex = Number(offset / 32n);
  const length = receiptUint(data, offsetIndex, `${label} length`);
  if (length > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${label} is too large`);
  const start = (offsetIndex + 1) * 64;
  const end = start + Number(length) * 2;
  const payload = data.slice(start, end);
  if (payload.length !== Number(length) * 2) throw new Error(`${label} is truncated`);
  return `0x${payload}`;
}

function receiptString(data, index, label) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytesFromHex(strip0x(receiptDynamicBytes(data, index, label)), label));
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
}

function receiptSucceeded(status) {
  try {
    return BigInt(status) === 1n;
  } catch {
    return false;
  }
}

function receiptLogTopics(log, label) {
  if (!Array.isArray(log?.topics)) throw new Error(`${label}.topics is required`);
  return log.topics.map((topic, index) => receiptBytes32Topic(topic, `${label}.topics[${index}]`));
}

function expectedPrivacyLogs(receipt, contractAddress, eventName) {
  if (!receiptSucceeded(receipt?.status)) {
    throw new Error("privacy receipt does not have an explicit successful status");
  }
  if (!Array.isArray(receipt?.logs)) throw new Error("privacy receipt logs are required");
  const signature = {
    PrivacyDeposit: "PrivacyDeposit(address,address,string,bytes)",
    PrivacyTransfer: "PrivacyTransfer(address,address,bytes)",
    PrivacyWithdraw: "PrivacyWithdraw(address,address,address,string)",
    PrivacyBatchTransferItem: "PrivacyBatchTransferItem(address,address,bytes32,uint64,bytes32,bytes)",
    PrivacySingleProofBatchTransfer: "PrivacySingleProofBatchTransfer(address,address,bytes32,bytes,uint8,uint8)"
  }[eventName];
  if (!signature) throw new Error(`unsupported privacy receipt event ${eventName}`);
  const topic = `0x${keccak256(signature)}`;
  const target = normalizeEvmAddress(contractAddress, "privacy contract address");
  return receipt.logs.filter((log, index) => {
    if (normalizeEvmAddress(log?.address, `receipt.logs[${index}].address`) !== target) return false;
    const topics = receiptLogTopics(log, `receipt.logs[${index}]`);
    return topics[0] === topic;
  });
}

function assertReceiptSenderTopics(log, expectation, operator, label) {
  const topics = receiptLogTopics(log, label);
  const effectiveSender = expectation.effectiveSender === "operator"
    ? operator
    : normalizeEvmAddress(expectation.effectiveSender, `${label} effective sender`);
  if (topics[1] !== receiptAddressTopic(effectiveSender) || topics[2] !== receiptAddressTopic(operator)) {
    throw new Error(`${label} effectiveSender/operator does not match the prepared privacy call`);
  }
  return topics;
}

function normalizedEvmTransactionHash(value, label) {
  const clean = String(value ?? "").trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error(`${label} must be a 32-byte EVM transaction hash`);
  }
  return `0x${clean}`;
}

/**
 * Bind an RPC transaction to the exact SDK-prepared privacy request and the
 * configured EVM network. This deliberately verifies only fields that remain
 * stable across wallet fee/nonce filling: hash, sender, target, calldata,
 * value, and chain ID.
 */
export function verifyEvmTransactionIdentity({
  transaction,
  rpcTransaction,
  txHash,
  sender,
  expectedChainId,
  actualChainId
} = {}) {
  if (!rpcTransaction || typeof rpcTransaction !== "object" || Array.isArray(rpcTransaction)) {
    throw new Error("EVM transaction identity verification requires eth_getTransactionByHash output");
  }
  const metadata = evmTransactionMetadata(transaction);
  if (!metadata.operation ||
      !metadata.expectedTo || !metadata.expectedData || !metadata.expectedValue) {
    throw new Error("EVM transaction identity verification requires an SDK-prepared privacy transaction");
  }

  const preparedTo = normalizeEvmAddress(transaction?.to, "prepared privacy transaction target");
  const preparedData = String(transaction?.data ?? "").trim().toLowerCase();
  const preparedValue = normalizedEvmQuantity(
    transaction?.value ?? "0x0",
    "prepared privacy transaction value"
  );
  if (preparedTo !== metadata.expectedTo ||
      preparedData !== metadata.expectedData ||
      preparedValue !== metadata.expectedValue) {
    throw new Error("prepared privacy transaction binding was modified before confirmation");
  }

  const requestedHash = normalizedEvmTransactionHash(txHash, "requested transaction hash");
  const rpcHash = normalizedEvmTransactionHash(
    rpcTransaction.hash ?? rpcTransaction.transactionHash,
    "RPC transaction hash"
  );
  if (rpcHash !== requestedHash) {
    throw new Error("RPC transaction hash does not match the requested transaction");
  }

  const expectedSender = normalizeEvmAddress(sender, "privacy transaction sender");
  const rpcSender = normalizeEvmAddress(rpcTransaction.from, "RPC transaction sender");
  if (rpcSender !== expectedSender) {
    throw new Error("RPC transaction sender does not match the submitted privacy transaction sender");
  }
  if (transaction?.from != null &&
      normalizeEvmAddress(transaction.from, "prepared privacy transaction sender") !== expectedSender) {
    throw new Error("prepared privacy transaction sender does not match the submitted sender");
  }

  const rpcTo = normalizeEvmAddress(rpcTransaction.to, "RPC transaction target");
  if (rpcTo !== preparedTo) {
    throw new Error("RPC transaction target does not match the prepared privacy transaction");
  }
  const rpcInput = rpcTransaction.input;
  const rpcData = rpcTransaction.data;
  if (rpcInput != null && rpcData != null &&
      String(rpcInput).trim().toLowerCase() !== String(rpcData).trim().toLowerCase()) {
    throw new Error("RPC transaction input/data aliases conflict");
  }
  const actualData = String(rpcInput ?? rpcData ?? "").trim().toLowerCase();
  if (!actualData || actualData !== preparedData) {
    throw new Error("RPC transaction calldata does not match the prepared privacy transaction");
  }
  if (rpcTransaction.value == null) {
    throw new Error("RPC transaction value is required for privacy transaction verification");
  }
  const actualValue = normalizedEvmQuantity(rpcTransaction.value, "RPC transaction value");
  if (actualValue !== preparedValue) {
    throw new Error("RPC transaction value does not match the prepared privacy transaction");
  }

  const configuredChainId = expectedChainId == null || String(expectedChainId).trim() === ""
    ? ""
    : normalizedEvmQuantity(expectedChainId, "expected EVM chain ID");
  const preparedChainId = transaction?.chainId == null || String(transaction.chainId).trim() === ""
    ? ""
    : normalizedEvmQuantity(transaction.chainId, "prepared EVM chain ID");
  const expectedNetwork = configuredChainId || preparedChainId;
  if (!expectedNetwork) {
    throw new Error("expected EVM chain ID is required for transaction identity verification");
  }
  if (configuredChainId && preparedChainId && configuredChainId !== preparedChainId) {
    throw new Error("prepared EVM transaction chain ID does not match the configured network");
  }
  const rpcNetwork = normalizedEvmQuantity(actualChainId, "EVM RPC chain ID");
  if (!rpcNetwork || rpcNetwork !== expectedNetwork) {
    throw new Error("EVM RPC chain ID does not match the prepared privacy transaction");
  }
  if (rpcTransaction.chainId != null && String(rpcTransaction.chainId).trim() !== "" &&
      normalizedEvmQuantity(rpcTransaction.chainId, "RPC transaction chain ID") !== expectedNetwork) {
    throw new Error("RPC transaction chain ID does not match the prepared privacy transaction");
  }

  return Object.freeze({
    verified: true,
    operation: metadata.operation,
    txHash: requestedHash,
    sender: expectedSender,
    to: preparedTo,
    data: preparedData,
    value: preparedValue,
    chainId: expectedNetwork,
    txBytesHash: evmTransactionBindingHash(transaction)
  });
}

/**
 * Verify an EVM privacy contract's action-specific event after a successful receipt.
 * Receipt status alone is intentionally insufficient because a proxy/caught
 * revert or unrelated call can otherwise look successful to the wallet.
 */
export function verifyEvmPrivacyReceipt({ transaction, receipt, sender, contractAddress } = {}) {
  const expectation = evmTransactionMetadata(transaction).receiptExpectation;
  if (!expectation || typeof expectation !== "object") {
    throw new Error("privacy receipt verification requires an SDK-prepared transaction");
  }
  const operator = normalizeEvmAddress(sender, "privacy transaction sender");
  const logs = expectedPrivacyLogs(
    receipt,
    contractAddress ?? transaction?.to,
    expectation.event
  );
  if (expectation.event !== "PrivacyBatchTransferItem" && logs.length !== 1) {
    throw new Error(`${expectation.event} receipt event count must be exactly one`);
  }

  if (expectation.event === "PrivacyDeposit") {
    const log = logs[0];
    assertReceiptSenderTopics(log, expectation, operator, "PrivacyDeposit");
    const data = receiptData(log.data, "PrivacyDeposit data");
    if (receiptString(data, 0, "PrivacyDeposit amount") !== expectation.amount ||
        receiptDynamicBytes(data, 1, "PrivacyDeposit note commitment") !== expectation.noteCommitment) {
      throw new Error("PrivacyDeposit amount or note commitment does not match the prepared privacy call");
    }
  } else if (expectation.event === "PrivacyTransfer") {
    const log = logs[0];
    assertReceiptSenderTopics(log, expectation, operator, "PrivacyTransfer");
    if (receiptDynamicBytes(receiptData(log.data, "PrivacyTransfer data"), 0, "PrivacyTransfer root") !== expectation.root) {
      throw new Error("PrivacyTransfer root does not match the prepared privacy call");
    }
  } else if (expectation.event === "PrivacyWithdraw") {
    const log = logs[0];
    const topics = assertReceiptSenderTopics(log, expectation, operator, "PrivacyWithdraw");
    if (topics[3] !== receiptAddressTopic(expectation.recipient) ||
        receiptString(receiptData(log.data, "PrivacyWithdraw data"), 0, "PrivacyWithdraw amount") !== expectation.amount) {
      throw new Error("PrivacyWithdraw recipient or amount does not match the prepared privacy call");
    }
  } else if (expectation.event === "PrivacyBatchTransferItem") {
    if (logs.length !== expectation.entries.length) {
      throw new Error(`PrivacyBatchTransferItem receipt emitted ${logs.length} items; expected ${expectation.entries.length}`);
    }
    const seen = new Set();
    for (const [index, log] of logs.entries()) {
      const data = receiptData(log.data, `PrivacyBatchTransferItem[${index}] data`);
      const itemIndex = receiptUint(data, 0, `PrivacyBatchTransferItem[${index}] item index`);
      if (itemIndex >= BigInt(expectation.entries.length) || seen.has(itemIndex.toString())) {
        throw new Error("PrivacyBatchTransferItem has an invalid or duplicate item index");
      }
      seen.add(itemIndex.toString());
      const expected = expectation.entries[Number(itemIndex)];
      const topics = assertReceiptSenderTopics(log, expected, operator, `PrivacyBatchTransferItem[${index}]`);
      const batchIDMatches = topics[3] === receiptBytes32Topic(expectation.batchId, "batchId");
      const observedRequestHash = `0x${receiptWord(data, 1, `PrivacyBatchTransferItem[${index}] request hash`)}`;
      const requestHashMatches = observedRequestHash === expected.requestHash;
      const rootMatches = receiptDynamicBytes(data, 2, `PrivacyBatchTransferItem[${index}] root`) === expected.root;
      if (!batchIDMatches || !requestHashMatches || !rootMatches) {
        const mismatches = [
          !batchIDMatches && "batchId",
          !requestHashMatches && "requestHash",
          !rootMatches && "root"
        ].filter(Boolean).join(", ");
        throw new Error(`PrivacyBatchTransferItem ${itemIndex} does not match the prepared privacy call: ${mismatches}`);
      }
    }
  } else if (expectation.event === "PrivacySingleProofBatchTransfer") {
    const log = logs[0];
    const topics = assertReceiptSenderTopics(log, expectation, operator, "PrivacySingleProofBatchTransfer");
    const data = receiptData(log.data, "PrivacySingleProofBatchTransfer data");
    if (topics[3] !== receiptBytes32Topic(expectation.requestHash, "single-proof batch request hash") ||
        receiptDynamicBytes(data, 0, "PrivacySingleProofBatchTransfer root") !== expectation.root ||
        receiptUint(data, 1, "PrivacySingleProofBatchTransfer input count") !== expectation.inputCount ||
        receiptUint(data, 2, "PrivacySingleProofBatchTransfer output count") !== expectation.outputCount) {
      throw new Error("PrivacySingleProofBatchTransfer does not match the prepared privacy call");
    }
  }

  return Object.freeze({ verified: true, event: expectation.event, operation: evmTransactionMetadata(transaction).operation });
}

export function createEip1193WalletAdapter({ provider, account } = {}) {
  if (!provider?.request) {
    throw new Error("EIP-1193 provider with request({ method, params }) is required");
  }
  async function accounts() {
    const resolved = account
      ? [account]
      : await provider.request({ method: "eth_requestAccounts", params: [] });
    if (!Array.isArray(resolved) || !resolved[0]) {
      throw new Error("EVM wallet returned no accounts");
    }
    return resolved.map(item => normalizeEvmAddress(item));
  }
  return {
    async getAddress() {
      return (await accounts())[0];
    },
    async getChainId() {
      return provider.request({ method: "eth_chainId", params: [] });
    },
    async signPrivacyRoot(messageBytes) {
      const address = await this.getAddress();
      const messageHex = with0x(hexFromBytes(messageBytes));
      const signature = await provider.request({
        method: "personal_sign",
        params: [messageHex, address]
      });
      if (typeof signature !== "string" || !/^0x[0-9a-fA-F]+$/.test(signature)) {
        throw new Error("EVM wallet personal_sign must return a 0x-prefixed hex signature");
      }
      return signature;
    },
    async signTypedData(typedData) {
      const address = await this.getAddress();
      const signature = await provider.request({
        method: "eth_signTypedData_v4",
        params: [address, JSON.stringify(typedData)]
      });
      if (typeof signature !== "string" || !/^0x[0-9a-fA-F]+$/.test(signature)) {
        throw new Error("EVM wallet eth_signTypedData_v4 must return a 0x-prefixed hex signature");
      }
      return signature;
    },
    async sendTransaction(transaction) {
      const externalTransaction = externalEvmTransaction(transaction);
      const from = externalTransaction.from
        ? normalizeEvmAddress(externalTransaction.from, "transaction from")
        : await this.getAddress();
      return provider.request({
        method: "eth_sendTransaction",
        params: [{ ...externalTransaction, from }]
      });
    },
    async call(transaction, blockTag = "latest") {
      return provider.request({
        method: "eth_call",
        params: [externalEvmTransaction(transaction), blockTag]
      });
    },
    async getLogs(filter) {
      return provider.request({
        method: "eth_getLogs",
        params: [filter]
      });
    }
  };
}

export function createEvmContractAdapter({
  contractAddress,
  encodeDeposit = defaultEncodeEvmDeposit,
  encodeTransfer = defaultEncodeEvmTransfer,
  encodeWithdraw = defaultEncodeEvmWithdraw,
  encodeTransferWithAuthorization = encodeEvmPrivacyTransferWithAuthorization,
  encodeWithdrawWithAuthorization = encodeEvmPrivacyWithdrawWithAuthorization,
  encodeBatchTransfer = encodeEvmPrivacyBatchTransfer,
  encodeBatchTransferWithAuthorization = encodeEvmPrivacyBatchTransferWithAuthorization,
  encodeSingleProofBatchTransfer = encodeEvmPrivacySingleProofBatchTransfer,
  encodeSingleProofBatchTransferWithAuthorization = encodeEvmPrivacySingleProofBatchTransferWithAuthorization,
  accountPrefix,
  chainId,
  depositMode = defaultEvmDepositMode,
  nativeDenom = "uclair",
  authorizationProfile = null,
  verifyPrivacyReceipt: verifyPrivacyReceiptHook
} = {}) {
  if (contractAddress == null || String(contractAddress).trim() === "") {
    throw new Error("EVM contract adapter requires contractAddress");
  }
  const to = normalizeEvmAddress(contractAddress, "contractAddress");
  const resolvedDepositMode = normalizeEvmDepositMode(depositMode);
  const resolvedNativeDenom = normalizeEvmNativeDenom(nativeDenom);
  const resolvedAuthorizationProfile = normalizeEvmAuthorizationProfile(authorizationProfile);
  if (verifyPrivacyReceiptHook != null && typeof verifyPrivacyReceiptHook !== "function") {
    throw new Error("EVM contract adapter verifyPrivacyReceipt must be a function");
  }
  const validateAuthorization = (authorization, options = {}) => validateEvmPrivacyAuthorization(
    authorization,
    resolvedAuthorizationProfile,
    options
  );
  return {
    contractAddress: to,
    ...(resolvedAuthorizationProfile ? { authorizationProfile: resolvedAuthorizationProfile } : {}),
    ...(verifyPrivacyReceiptHook ? { verifyPrivacyReceipt: verifyPrivacyReceiptHook } : {}),
    abi: resolvedDepositMode === evmDepositModePayableExactValue
      ? evmPrivacyPrecompilePayableDepositAbi
      : evmPrivacyPrecompileAbi,
    buildDepositTransaction(message, options = {}) {
      const data = encodeDeposit(message, { accountPrefix, chainId, ...options });
      const value = boundDepositTransactionValue(
        message,
        options,
        resolvedDepositMode,
        resolvedNativeDenom
      );
      const transaction = {
        to,
        data,
        value
      };
      return markedEvmTransaction(transaction, privacyTransactionBindingMetadata(
        transaction,
        "deposit",
        {
          depositMode: resolvedDepositMode,
          nativeDenom: resolvedNativeDenom
        }
      ));
    },
    buildTransferTransaction(message, options = {}) {
      const value = zeroTransactionValue(options, "transfer");
      return {
        to,
        data: encodeTransfer(message, { accountPrefix, chainId, ...options }),
        value
      };
    },
    buildWithdrawTransaction(message, options = {}) {
      const value = zeroTransactionValue(options, "withdraw");
      return {
        to,
        data: encodeWithdraw(message, { accountPrefix, chainId, ...options }),
        value
      };
    },
    buildTransferWithAuthorizationTransaction(message, authorization, options = {}) {
      const value = zeroTransactionValue(options, "transferWithAuthorization");
      return {
        to,
        data: encodeTransferWithAuthorization(
          message,
          validateAuthorization(authorization),
          { accountPrefix, chainId, ...options }
        ),
        value
      };
    },
    buildWithdrawWithAuthorizationTransaction(message, authorization, options = {}) {
      const value = zeroTransactionValue(options, "withdrawWithAuthorization");
      return {
        to,
        data: encodeWithdrawWithAuthorization(
          message,
          validateAuthorization(authorization),
          { accountPrefix, chainId, ...options }
        ),
        value
      };
    },
    buildBatchTransferTransaction(batchId, requests, options = {}) {
      const value = zeroTransactionValue(options, "batchTransfer");
      return { to, data: encodeBatchTransfer(batchId, requests, { accountPrefix, chainId, ...options }), value };
    },
    buildBatchTransferWithAuthorizationTransaction(batchId, items, options = {}) {
      const value = zeroTransactionValue(options, "batchTransferWithAuthorization");
      if (!Array.isArray(items)) throw new Error("authorized batch items must be an array");
      const normalizedItems = items.map((item, index) => ({
        ...item,
        authorization: validateAuthorization(
          item?.authorization ?? item?.auth ?? item?.privacyAuthorization,
          { requireSignature: true, index }
        )
      }));
      return {
        to,
        data: encodeBatchTransferWithAuthorization(batchId, normalizedItems, { accountPrefix, chainId, ...options }),
        value
      };
    },
    buildSingleProofBatchTransferTransaction(message, options = {}) {
      const value = zeroTransactionValue(options, "singleProofBatchTransfer");
      return { to, data: encodeSingleProofBatchTransfer(message, { accountPrefix, chainId, ...options }), value };
    },
    buildSingleProofBatchTransferWithAuthorizationTransaction(message, authorization, options = {}) {
      const value = zeroTransactionValue(options, "singleProofBatchTransferWithAuthorization");
      return {
        to,
        data: encodeSingleProofBatchTransferWithAuthorization(
          message,
          validateAuthorization(authorization),
          { accountPrefix, chainId, ...options }
        ),
        value
      };
    },
    buildAuthorizationTypedData(input = {}) {
      if (!resolvedAuthorizationProfile?.buildTypedData) {
        throw new Error("configured EVM authorization profile does not provide buildTypedData()");
      }
      return resolvedAuthorizationProfile.buildTypedData({
        ...input,
        authorization: validateAuthorization(input.authorization, { requireSignature: false }),
        contractAddress: input.contractAddress ?? to
      });
    }
  };
}

export function createEvmPrivacyPrecompileAdapter(options = {}) {
  return createEvmContractAdapter({
    contractAddress: options.contractAddress,
    accountPrefix: options.accountPrefix,
    chainId: options.chainId,
    depositMode: options.depositMode,
    nativeDenom: options.nativeDenom,
    authorizationProfile: options.authorizationProfile,
    verifyPrivacyReceipt: options.verifyPrivacyReceipt,
    encodeDeposit: options.encodeDeposit ?? encodeEvmPrivacyDeposit,
    encodeTransfer: options.encodeTransfer ?? encodeEvmPrivacyTransfer,
    encodeWithdraw: options.encodeWithdraw ?? encodeEvmPrivacyWithdraw,
    encodeTransferWithAuthorization: options.encodeTransferWithAuthorization ?? encodeEvmPrivacyTransferWithAuthorization,
    encodeWithdrawWithAuthorization: options.encodeWithdrawWithAuthorization ?? encodeEvmPrivacyWithdrawWithAuthorization,
    encodeBatchTransfer: options.encodeBatchTransfer ?? encodeEvmPrivacyBatchTransfer,
    encodeBatchTransferWithAuthorization: options.encodeBatchTransferWithAuthorization ?? encodeEvmPrivacyBatchTransferWithAuthorization,
    encodeSingleProofBatchTransfer: options.encodeSingleProofBatchTransfer ?? encodeEvmPrivacySingleProofBatchTransfer,
    encodeSingleProofBatchTransferWithAuthorization: options.encodeSingleProofBatchTransferWithAuthorization ?? encodeEvmPrivacySingleProofBatchTransferWithAuthorization
  });
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

export class ClairveilEvmClient {
  constructor({
    provider,
    contractAddress,
    chainId,
    evmChainId,
    accountPrefix,
    bech32Prefix,
    shieldedPrefix = defaultShieldedPrefix,
    defaultDenom = "uclair",
    depositMode = defaultEvmDepositMode,
    nativeDenom = defaultDenom,
    contractAdapter,
    authorizationProfile = null
  } = {}) {
    this.provider = provider;
    this.chainId = chainId;
    this.evmChainId = evmChainId == null || String(evmChainId).trim() === ""
      ? ""
      : normalizedEvmQuantity(evmChainId, "evmChainId");
    this.accountPrefix = normalizeBech32Prefix(accountPrefix ?? bech32Prefix ?? "clair", "accountPrefix");
    this.bech32Prefix = this.accountPrefix;
    this.shieldedPrefix = normalizeBech32Prefix(shieldedPrefix, "shieldedPrefix");
    this.defaultDenom = String(defaultDenom || "uclair");
    this.depositMode = normalizeEvmDepositMode(depositMode);
    this.nativeDenom = normalizeEvmNativeDenom(nativeDenom, this.defaultDenom);
    const adapterContractAddress = contractAdapter?.contractAddress;
    if (contractAdapter && (adapterContractAddress == null || String(adapterContractAddress).trim() === "")) {
      throw new Error("EVM contractAdapter.contractAddress is required");
    }
    const resolvedContractAddress = contractAddress ?? adapterContractAddress;
    if (resolvedContractAddress == null || String(resolvedContractAddress).trim() === "") {
      throw new Error("Clairveil EVM client requires contractAddress or contractAdapter.contractAddress");
    }
    if (contractAdapter && contractAddress != null &&
        normalizeEvmAddress(adapterContractAddress, "contractAdapter.contractAddress") !==
          normalizeEvmAddress(contractAddress, "contractAddress")) {
      throw new Error("contractAddress conflicts with contractAdapter.contractAddress");
    }
    const adapterAuthorizationProfile = contractAdapter?.authorizationProfile ?? null;
    if (authorizationProfile != null && adapterAuthorizationProfile != null &&
        !authorizationProfilesCompatible(authorizationProfile, adapterAuthorizationProfile)) {
      throw new Error("authorizationProfile conflicts with contractAdapter.authorizationProfile");
    }
    this.authorizationProfile = normalizeEvmAuthorizationProfile(
      authorizationProfile ?? adapterAuthorizationProfile
    );
    this.contract = contractAdapter || createEvmPrivacyPrecompileAdapter({
      contractAddress: resolvedContractAddress,
      accountPrefix: this.accountPrefix,
      chainId,
      depositMode: this.depositMode,
      nativeDenom: this.nativeDenom,
      authorizationProfile: this.authorizationProfile
    });
  }

  validateAuthorization(authorization, options = {}) {
    return validateEvmPrivacyAuthorization(authorization, this.authorizationProfile, options);
  }

  buildAuthorizationTypedData(input = {}) {
    if (!this.authorizationProfile?.buildTypedData) {
      throw new Error("configured EVM authorization profile does not provide buildTypedData()");
    }
    return this.authorizationProfile.buildTypedData({
      ...input,
      authorization: this.validateAuthorization(input.authorization, { requireSignature: false }),
      contractAddress: input.contractAddress ?? this.contract.contractAddress
    });
  }

  buildDepositMaterial(input) {
    return buildDepositMaterial({
      assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
      shieldedPrefix: this.shieldedPrefix,
      ...input
    });
  }

  buildDepositTransaction(input = {}) {
    if (input.message) {
      const transactionOptions = {
        ...(input.transactionOptions || {}),
        value: boundDepositTransactionValue(
          input.message,
          input.transactionOptions || {},
          this.depositMode,
          this.nativeDenom
        )
      };
      const transaction = this.contract.buildDepositTransaction(
        input.message,
        transactionOptions
      );
      const expectedData = String(transaction?.data || "").trim().toLowerCase();
      const expectedValue = transactionOptions.value;
      const actualValue = normalizedEvmQuantity(
        transaction?.value ?? "0x0",
        "deposit transaction value"
      );
      if (actualValue !== expectedValue) {
        throw new Error("EVM contract adapter returned a mismatched deposit transaction value");
      }
      return {
        status: "ready",
        message: input.message,
        transaction: markedEvmTransaction(transaction, privacyTransactionBindingMetadata(
          transaction,
          "deposit",
          {
            depositMode: this.depositMode,
            nativeDenom: this.nativeDenom,
            expectedData,
            expectedValue,
            receiptExpectation: receiptExpectationForCanonicalTransaction(
              transaction,
              () => encodeEvmPrivacyDeposit(input.message),
              () => receiptExpectationForDeposit(input.message, this.nativeDenom)
            )
          }
        ))
      };
    }
    const material = input.material || input.depositMaterial || input.deposit_material || this.buildDepositMaterial(input);
    const expectedCreator = String(input.creator || "").trim();
    if (expectedCreator && String(material.creator || "").trim() !== expectedCreator) {
      throw new Error(`deposit material creator mismatch: expected ${expectedCreator}, got ${material.creator || ""}`);
    }
    const expectedAmount = input.amount == null
      ? ""
      : parseCoin(input.amount, input.assetDenom ?? input.denom ?? this.defaultDenom).raw;
    if (expectedAmount && String(material.amount || "").trim() !== expectedAmount) {
      throw new Error(`deposit material amount mismatch: expected ${expectedAmount}, got ${material.amount || ""}`);
    }
    const message = input.message || {
      amount: material.amount,
      noteCommitment: material.note_commitment,
      encryptedNote: material.encrypted_note,
      proof: input.proof ?? input.proofHex ?? input.proof_hex ?? input.depositProof ?? input.deposit_proof
    };
    const transactionOptions = {
      ...(input.transactionOptions || {}),
      value: boundDepositTransactionValue(
        message,
        input.transactionOptions || {},
        this.depositMode,
        this.nativeDenom
      )
    };
    const transaction = this.contract.buildDepositTransaction(message, transactionOptions);
    const expectedData = String(transaction?.data || "").trim().toLowerCase();
    const expectedValue = transactionOptions.value;
    const actualValue = normalizedEvmQuantity(
      transaction?.value ?? "0x0",
      "deposit transaction value"
    );
    if (actualValue !== expectedValue) {
      throw new Error("EVM contract adapter returned a mismatched deposit transaction value");
    }
    return {
      status: "ready",
      material,
      message,
      transaction: markedEvmTransaction(transaction, privacyTransactionBindingMetadata(
        transaction,
        "deposit",
          {
            depositMode: this.depositMode,
            nativeDenom: this.nativeDenom,
            expectedData,
            expectedValue,
            receiptExpectation: receiptExpectationForCanonicalTransaction(
              transaction,
              () => encodeEvmPrivacyDeposit(message),
              () => receiptExpectationForDeposit(message, this.nativeDenom)
            )
        }
      ))
    };
  }

  async buildTransferTransaction(input = {}) {
    const built = input.message
      ? { message: input.message, payload: input.payload, proof: input.proof }
      : await buildTransferMessage({
        shieldedPrefix: this.shieldedPrefix,
        transferDenom: input.transferDenom ?? input.denom ?? this.defaultDenom,
        ...input,
        chainId: input.chainId ?? this.chainId,
        checkNullifiers: input.checkNullifiers
      });
    assertEvmTransferExecutionBinding(input, built);
    const transaction = this.contract.buildTransferTransaction(
      built.message,
      input.transactionOptions
    );
    return {
      status: "ready",
      ...built,
      transaction: markedEvmTransaction(
        transaction,
        privacyTransactionBindingMetadata(transaction, "transfer", {
          receiptExpectation: receiptExpectationForCanonicalTransaction(
            transaction,
            () => encodeEvmPrivacyTransfer(built.message),
            () => receiptExpectationForTransfer(built.message)
          )
        })
      )
    };
  }

  async buildPreparedTransferPayload(input = {}) {
    return buildPreparedTransferPayload({
      shieldedPrefix: this.shieldedPrefix,
      transferDenom: input.transferDenom ?? input.denom ?? this.defaultDenom,
      ...input,
      chainId: input.chainId ?? this.chainId
    });
  }

  async buildPreparedWithdrawProverPayload(input = {}) {
    const recipient = isEvmAddress(input.recipient)
      ? evmAddressToBech32(input.recipient, input.accountPrefix ?? this.accountPrefix)
      : input.recipient;
    return buildPreparedWithdrawProverPayload({
      assetDenom: input.assetDenom ?? input.denom ?? this.defaultDenom,
      ...input,
      recipient,
      accountPrefix: input.accountPrefix ?? this.accountPrefix,
      chainId: input.chainId ?? this.chainId
    });
  }

  async buildWithdrawTransaction(input = {}) {
    const accountPrefix = input.accountPrefix ?? this.accountPrefix;
    const evmRecipient = input.evmRecipient
      ?? input.evm_recipient
      ?? (isEvmAddress(input.recipient) ? normalizeEvmAddress(input.recipient, "withdraw recipient") : undefined);
    const recipient = evmRecipient
      ? evmAddressToBech32(evmRecipient, accountPrefix)
      : input.recipient;
    let built;
    if (input.message) {
      built = {
        message: input.message,
        payload: input.payload,
        proof: input.proof,
        proverPayload: input.proverPayload,
        selectedNote: input.selectedNote
      };
    } else if (input.payload) {
      const expectedRecipientInput = input.expectedRecipient
        ?? input.expected_recipient
        ?? (input.recipient == null ? undefined : recipient);
      const expectedRecipient = isEvmAddress(expectedRecipientInput)
        ? evmAddressToBech32(expectedRecipientInput, accountPrefix)
        : expectedRecipientInput;
      const expectedChainId = input.expectedChainId
        ?? input.expected_chain_id
        ?? input.chainId
        ?? input.chain_id
        ?? this.chainId;
      if (!String(expectedChainId ?? "").trim()) {
        throw new Error("expectedChainId is required for relay withdraw payload validation");
      }
      const chainNowUnix = input.chainNowUnix
        ?? input.chain_now_unix
        ?? input.nowUnix
        ?? input.now_unix;
      validateRelayWithdrawPayload(input.payload, {
        chainNowUnix,
        expectedChainId,
        expectedRecipient,
        accountPrefix
      });
      built = {
        message: buildWithdrawMsgFromPayload(
          input.payload,
          input.relayer ?? input.creator ?? input.address ?? "",
          chainNowUnix
        ),
        payload: input.payload,
        proof: input.proof,
        proverPayload: input.proverPayload,
        selectedNote: input.selectedNote
      };
    } else {
      built = await buildWithdrawMessage({
        assetDenom: input.assetDenom ?? input.denom ?? this.defaultDenom,
        ...input,
        chainNowUnix: input.chainNowUnix ?? input.chain_now_unix ?? input.nowUnix ?? input.now_unix,
        checkNullifiers: input.checkNullifiers,
        recipient,
        accountPrefix,
        chainId: input.chainId ?? this.chainId
      });
    }
    const candidateMessage = evmRecipient
      ? { ...built.message, evmRecipient }
      : built.message;
    const messageEvmRecipient = explicitWithdrawEvmRecipient(candidateMessage);
    assertWithdrawEvmRecipientMatchesMessage(messageEvmRecipient, candidateMessage?.recipient, accountPrefix);
    const message = messageEvmRecipient
      ? { ...candidateMessage, evmRecipient: messageEvmRecipient }
      : candidateMessage;
    const transaction = this.contract.buildWithdrawTransaction(
      message,
      input.transactionOptions
    );
    return {
      status: "ready",
      ...built,
      message,
      transaction: markedEvmTransaction(
        transaction,
        privacyTransactionBindingMetadata(transaction, "withdraw", {
          receiptExpectation: receiptExpectationForCanonicalTransaction(
            transaction,
            () => encodeEvmPrivacyWithdraw(message, { accountPrefix, chainId: this.chainId }),
            () => receiptExpectationForWithdraw(message, { accountPrefix, chainId: this.chainId })
          )
        })
      )
    };
  }

  buildTransferWithAuthorizationTransaction({ message, authorization, transactionOptions } = {}) {
    if (!message) throw new Error("transfer message is required");
    if (typeof this.contract.buildTransferWithAuthorizationTransaction !== "function") {
      throw new Error("configured EVM contract adapter does not support transferWithAuthorization");
    }
    const normalizedAuthorization = this.validateAuthorization(authorization);
    const transaction = this.contract.buildTransferWithAuthorizationTransaction(
      message,
      normalizedAuthorization,
      transactionOptions
    );
    return {
      status: "ready",
      message,
      authorization: normalizedAuthorization,
      transaction: markedEvmTransaction(
        transaction,
        privacyTransactionBindingMetadata(transaction, "transferWithAuthorization", {
          receiptExpectation: receiptExpectationForCanonicalTransaction(
            transaction,
            () => encodeEvmPrivacyTransferWithAuthorization(message, normalizedAuthorization),
            () => receiptExpectationForTransfer(message, normalizedAuthorization)
          )
        })
      )
    };
  }

  buildWithdrawWithAuthorizationTransaction({ message, authorization, transactionOptions } = {}) {
    if (!message) throw new Error("withdraw message is required");
    if (typeof this.contract.buildWithdrawWithAuthorizationTransaction !== "function") {
      throw new Error("configured EVM contract adapter does not support withdrawWithAuthorization");
    }
    const normalizedAuthorization = this.validateAuthorization(authorization);
    const transaction = this.contract.buildWithdrawWithAuthorizationTransaction(
      message,
      normalizedAuthorization,
      transactionOptions
    );
    return {
      status: "ready",
      message,
      authorization: normalizedAuthorization,
      transaction: markedEvmTransaction(
        transaction,
        privacyTransactionBindingMetadata(transaction, "withdrawWithAuthorization", {
          receiptExpectation: receiptExpectationForCanonicalTransaction(
            transaction,
            () => encodeEvmPrivacyWithdrawWithAuthorization(
              message,
              normalizedAuthorization,
              { accountPrefix: this.accountPrefix, chainId: this.chainId }
            ),
            () => receiptExpectationForWithdraw(message, { accountPrefix: this.accountPrefix, chainId: this.chainId }, normalizedAuthorization)
          )
        })
      )
    };
  }

  buildBatchTransferTransaction({ batchId, requests, transactionOptions } = {}) {
    if (typeof this.contract.buildBatchTransferTransaction !== "function") {
      throw new Error("configured EVM contract adapter does not support batchTransfer");
    }
    const transaction = this.contract.buildBatchTransferTransaction(batchId, requests, transactionOptions);
    return {
      status: "ready",
      batchId,
      requests,
      transaction: markedEvmTransaction(
        transaction,
        privacyTransactionBindingMetadata(transaction, "batchTransfer", {
          receiptExpectation: receiptExpectationForCanonicalTransaction(
            transaction,
            () => encodeEvmPrivacyBatchTransfer(batchId, requests),
            () => receiptExpectationForBatch(batchId, requests)
          )
        })
      )
    };
  }

  buildBatchTransferWithAuthorizationTransaction({ batchId, items, transactionOptions } = {}) {
    if (typeof this.contract.buildBatchTransferWithAuthorizationTransaction !== "function") {
      throw new Error("configured EVM contract adapter does not support batchTransferWithAuthorization");
    }
    if (!Array.isArray(items)) throw new Error("authorized batch items must be an array");
    const normalizedItems = items.map(item => ({
      ...item,
      authorization: this.validateAuthorization(
        item?.authorization ?? item?.auth ?? item?.privacyAuthorization
      )
    }));
    const transaction = this.contract.buildBatchTransferWithAuthorizationTransaction(
      batchId,
      normalizedItems,
      transactionOptions
    );
    return {
      status: "ready",
      batchId,
      items: normalizedItems,
      transaction: markedEvmTransaction(
        transaction,
        privacyTransactionBindingMetadata(transaction, "batchTransferWithAuthorization", {
          receiptExpectation: receiptExpectationForCanonicalTransaction(
            transaction,
            () => encodeEvmPrivacyBatchTransferWithAuthorization(batchId, normalizedItems),
            () => receiptExpectationForBatch(batchId, null, normalizedItems)
          )
        })
      )
    };
  }

  buildSingleProofBatchTransferTransaction({ message, transactionOptions } = {}) {
    if (!message) throw new Error("single-proof batch transfer message is required");
    if (typeof this.contract.buildSingleProofBatchTransferTransaction !== "function") {
      throw new Error("configured EVM contract adapter does not support singleProofBatchTransfer");
    }
    const transaction = this.contract.buildSingleProofBatchTransferTransaction(message, transactionOptions);
    return {
      status: "ready",
      message,
      transaction: markedEvmTransaction(
        transaction,
        privacyTransactionBindingMetadata(transaction, "singleProofBatchTransfer", {
          receiptExpectation: receiptExpectationForCanonicalTransaction(
            transaction,
            () => encodeEvmPrivacySingleProofBatchTransfer(message),
            () => receiptExpectationForSingleProofBatch(message)
          )
        })
      )
    };
  }

  buildSingleProofBatchTransferWithAuthorizationTransaction({ message, authorization, transactionOptions } = {}) {
    if (!message) throw new Error("single-proof batch transfer message is required");
    if (typeof this.contract.buildSingleProofBatchTransferWithAuthorizationTransaction !== "function") {
      throw new Error("configured EVM contract adapter does not support singleProofBatchTransferWithAuthorization");
    }
    const normalizedAuthorization = this.validateAuthorization(authorization);
    const transaction = this.contract.buildSingleProofBatchTransferWithAuthorizationTransaction(
      message,
      normalizedAuthorization,
      transactionOptions
    );
    return {
      status: "ready",
      message,
      authorization: normalizedAuthorization,
      transaction: markedEvmTransaction(
        transaction,
        privacyTransactionBindingMetadata(transaction, "singleProofBatchTransferWithAuthorization", {
          receiptExpectation: receiptExpectationForCanonicalTransaction(
            transaction,
            () => encodeEvmPrivacySingleProofBatchTransferWithAuthorization(message, normalizedAuthorization),
            () => receiptExpectationForSingleProofBatch(message, normalizedAuthorization)
          )
        })
      )
    };
  }

  async sendTransaction(wallet, transaction, reservationOptions = {}) {
    assertPrivacyTransactionBinding(
      transaction,
      this.depositMode,
      this.contract.contractAddress
    );
    const reservationContext = broadcastReservationContext(reservationOptions);
    const checkNullifiers = reservationOptions.checkNullifiers ?? reservationOptions.check_nullifiers;
    if (reservationOptions.checkNullifiers != null && reservationOptions.check_nullifiers != null &&
        reservationOptions.checkNullifiers !== reservationOptions.check_nullifiers) {
      throw new Error("checkNullifiers aliases conflict");
    }
    if (evmTransactionMetadata(transaction).reservationRequired && !reservationContext) {
      throw new Error("prepared reserved EVM transaction requires reservationManager and reservation");
    }
    const transactionHash = evmTransactionBindingHash(transaction);
    const broadcastTransaction = await validateRelayBroadcastContext(reservationOptions, {
      expectedChainId: this.chainId,
      accountPrefix: this.accountPrefix,
      transaction,
      contract: this.contract,
      reservationContext,
      transactionHash
    });
    const submittedTransaction = externalEvmTransaction(broadcastTransaction);
    const broadcastTransactionHash = evmTransactionBindingHash(submittedTransaction);
    const submissionWallet = wallet?.sendTransaction
      ? wallet
      : createEip1193WalletAdapter({ provider: this.provider });
    await assertWalletEvmChainId(submissionWallet, this.evmChainId);
    const relayPayload = reservationOptions.relayPayload ?? reservationOptions.relay_payload;
    await recheckReservedInputNullifiers(
      reservationContext,
      checkNullifiers,
      relayPayload?.nullifier_hex ? [relayPayload.nullifier_hex] : []
    );
    await beginBroadcastReservation(reservationContext, broadcastTransactionHash);
    let txHash;
    try {
      txHash = await submissionWallet.sendTransaction(submittedTransaction);
    } catch (error) {
      if (reservationContext && isExplicitWalletRejection(error)) {
        await markBroadcastReservationRejected(reservationContext, error);
      } else {
        await markBroadcastReservationManualReview(reservationContext, error);
      }
      throw error;
    }
    const normalizedTxHash = String(txHash || "").trim();
    if (!/^0x[0-9a-fA-F]{64}$/.test(normalizedTxHash)) {
      const error = new Error("EVM wallet returned an invalid transaction hash");
      await markBroadcastReservationManualReview(reservationContext, error);
      throw error;
    }
    await markBroadcastReservationSubmitted(reservationContext, normalizedTxHash);
    return normalizedTxHash;
  }

  verifyPrivacyReceipt({ transaction, receipt, sender } = {}) {
    if (!receiptSucceeded(receipt?.status)) {
      throw new Error("privacy receipt does not have an explicit successful status");
    }
    const metadata = evmTransactionMetadata(transaction);
    if (typeof this.contract.verifyPrivacyReceipt === "function") {
      const result = this.contract.verifyPrivacyReceipt(Object.freeze({
        transaction,
        receipt,
        sender,
        contractAddress: this.contract.contractAddress,
        operation: metadata.operation
      }));
      if (!result || typeof result !== "object" || Array.isArray(result) ||
          result.verified !== true) {
        throw new Error("custom EVM privacy receipt verifier must return { verified: true, operation, event }");
      }
      const operation = String(result.operation ?? "").trim();
      const event = String(result.event ?? "").trim();
      if (!metadata.operation || !operation || operation !== metadata.operation) {
        throw new Error("custom EVM privacy receipt verifier operation does not match the prepared transaction");
      }
      if (!event) {
        throw new Error("custom EVM privacy receipt verifier must identify the verified event");
      }
      return Object.freeze({ verified: true, operation, event });
    }
    return verifyEvmPrivacyReceipt({
      transaction,
      receipt,
      sender,
      contractAddress: this.contract.contractAddress
    });
  }

  verifyTransactionIdentity(input = {}) {
    return verifyEvmTransactionIdentity({
      ...input,
      expectedChainId: input.expectedChainId ?? this.evmChainId
    });
  }

  privacyAccount(material) {
    return publicPrivacyAccount(material);
  }
}

export function createClairveilEvmClient(options) {
  return new ClairveilEvmClient(options);
}
