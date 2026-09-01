import {
  bytesFromHex,
  canonicalFieldHex,
  hexFromBytes,
  normalizeHex,
  packPointHex,
  unpackPointHex
} from "../core/crypto.js";
import {
  computeNoteCommitmentHex,
  normalizeNote,
  noteSpendPubKeyHex,
  noteViewPubKeyHex
} from "../core/note.js";
import {
  preparedWithdrawProofVersion,
  validatePreparedWithdrawProof,
  validatePreparedWithdrawProverPayloadMetadata
} from "./payload.js";
import {
  preparedTransferV5ProofVersion,
  preparedTransferV5PayloadVersion,
  validateCanonicalGroth16ProofBytes,
  validatePreparedTransferV5PayloadAt,
  validatePreparedTransferV5Proof
} from "./transfer-v5.js";
import {
  batchTransferCircuitSetId,
  batchTransferProofPath,
  batchTransferProofRequestVersion,
  batchTransferProofResponseVersion,
  normalizePreparedBatchTransferProof,
  preparedBatchTransferPayloadVersion,
  serializePreparedBatchTransferPayload,
  validatePreparedBatchTransferPayloadEnvelope
} from "./batch-transfer.js";
import {
  wrapProverError
} from "../core/errors.js";

export const transferProofRequestVersion = "v2";
export const transferProofResponseVersion = "v2";
export const withdrawProofRequestVersion = "v2";
export const withdrawProofResponseVersion = "v2";
export const depositProofPath = "/v1/prover/deposit";
export const depositProofRequestVersion = "v1";
export const depositProofPayloadVersion = "v1";
export const depositProofResponseVersion = "v1";
export const depositProofVersion = "v1";
export const depositProofByteLength = 164;
/** Match the bounded Go prover transport response policy. */
export const defaultProverResponseMaxBytes = 1 << 20;
/** Browser-DApp deposit proof requests have the same 120s bound as the reference integration. */
export const defaultDepositProofTimeoutMs = 120000;
const proverErrorResponseVersion = "v1";
const proverErrorCodes = new Set([
  "invalid_request",
  "method_not_allowed",
  "not_found",
  "unauthorized",
  "unavailable",
  "proof_failed",
  "busy"
]);
const proverErrorStatusCodes = Object.freeze({
  invalid_request: new Set([400, 413, 415]),
  method_not_allowed: new Set([405]),
  not_found: new Set([404]),
  unauthorized: new Set([401]),
  unavailable: new Set([503]),
  proof_failed: new Set([500]),
  busy: new Set([429])
});

function normalizeBaseURL(baseURL) {
  const url = new URL(String(baseURL || ""));
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`unsupported prover URL protocol ${url.protocol}`);
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("prover URL must not contain credentials, query parameters, or a fragment");
  }
  if (url.protocol === "http:" && !isLoopbackProverHost(url.hostname)) {
    throw new Error(`prover transport requires HTTPS for non-loopback endpoint ${JSON.stringify(url.host)}`);
  }
  return url;
}

/** Normalize the pinned deposit endpoint under the common prover URL policy. */
function normalizeDepositProofURL(urlValue) {
  return normalizeBaseURL(urlValue);
}

function proverRequestURL(baseURL, path) {
  const url = new URL(baseURL);
  const prefix = url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`;
  url.pathname = `${prefix}${String(path || "").replace(/^\/+/, "")}`;
  url.search = "";
  url.hash = "";
  return url;
}

function isLoopbackProverHost(hostname) {
  const normalized = String(hostname || "").replace(/^\[|\]$/g, "").toLowerCase();
  if (normalized === "localhost" || normalized === "::1") return true;
  const octets = normalized.split(".");
  return octets.length === 4 && octets[0] === "127" && octets.every(octet =>
    /^(?:0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255
  );
}

/**
 * JSON.parse silently overwrites duplicate object keys. The Go prover
 * transport rejects those keys, unknown fields, and trailing JSON values, so
 * responses need a small strict parser before their semantic validation.
 */
function parseStrictJSON(source) {
  const text = String(source);
  let index = 0;
  const error = message => {
    throw new Error(`${message} at byte ${index}`);
  };
  const whitespace = () => {
    while (index < text.length && " \n\r\t".includes(text[index])) index += 1;
  };
  const string = () => {
    const start = index;
    if (text[index] !== "\"") error("expected JSON string");
    index += 1;
    while (index < text.length) {
      const character = text[index];
      if (character === "\"") {
        index += 1;
        try {
          return JSON.parse(text.slice(start, index));
        } catch {
          error("invalid JSON string");
        }
      }
      if (character === "\\") {
        index += 1;
        const escape = text[index];
        if (!'"\\/bfnrtu'.includes(escape || "")) error("invalid JSON string escape");
        if (escape === "u") {
          const hex = text.slice(index + 1, index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) error("invalid JSON unicode escape");
          index += 4;
        }
      } else if (character.codePointAt(0) <= 0x1f) {
        error("invalid JSON control character");
      }
      index += 1;
    }
    error("unterminated JSON string");
  };
  const value = () => {
    whitespace();
    const character = text[index];
    if (character === "{") {
      index += 1;
      whitespace();
      const object = Object.create(null);
      const keys = new Set();
      if (text[index] === "}") {
        index += 1;
        return object;
      }
      while (true) {
        whitespace();
        const key = string();
        if (keys.has(key)) error("duplicate JSON object key");
        keys.add(key);
        whitespace();
        if (text[index] !== ":") error("expected JSON object colon");
        index += 1;
        object[key] = value();
        whitespace();
        if (text[index] === "}") {
          index += 1;
          return object;
        }
        if (text[index] !== ",") error("expected JSON object comma");
        index += 1;
      }
    }
    if (character === "[") {
      index += 1;
      whitespace();
      const array = [];
      if (text[index] === "]") {
        index += 1;
        return array;
      }
      while (true) {
        array.push(value());
        whitespace();
        if (text[index] === "]") {
          index += 1;
          return array;
        }
        if (text[index] !== ",") error("expected JSON array comma");
        index += 1;
      }
    }
    if (character === "\"") return string();
    for (const [literal, result] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(literal, index)) {
        index += literal.length;
        return result;
      }
    }
    const number = text.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!number) error("expected JSON value");
    index += number[0].length;
    return Number(number[0]);
  };
  const parsed = value();
  whitespace();
  if (index !== text.length) error("multiple JSON values are not allowed");
  return parsed;
}

function responseContentLength(response) {
  const raw = response?.headers?.get?.("content-length");
  if (!raw || !/^(0|[1-9][0-9]*)$/.test(raw.trim())) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}

function assertJSONResponseContentType(response, label = "prover response") {
  const contentType = String(response?.headers?.get?.("content-type") || "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (contentType !== "application/json") {
    throw new Error(`${label} must return Content-Type: application/json`);
  }
}

async function readBoundedResponseText(response, maxResponseBytes) {
  const declaredLength = responseContentLength(response);
  if (declaredLength !== null && declaredLength > maxResponseBytes) {
    throw new Error(`prover response exceeds ${maxResponseBytes} byte limit`);
  }
  if (!response?.body || typeof response.body.getReader !== "function") {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maxResponseBytes) {
      throw new Error(`prover response exceeds ${maxResponseBytes} byte limit`);
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      total += chunk.byteLength;
      if (total > maxResponseBytes) {
        try {
          await reader.cancel();
        } catch {
          // The response was already rejected; cancellation is best effort.
        }
        throw new Error(`prover response exceeds ${maxResponseBytes} byte limit`);
      }
      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

function proverCancelledError() {
  const error = new Error("prover request cancelled");
  error.name = "AbortError";
  error.code = "PROVER_CANCELLED";
  return error;
}

function linkAbortSignal(signal, controller, onExternalAbort) {
  if (!signal) return () => {};
  if (signal.aborted) {
    onExternalAbort();
    controller.abort();
    return () => {};
  }
  const abort = () => {
    onExternalAbort();
    controller.abort();
  };
  signal.addEventListener("abort", abort, { once: true });
  return () => signal.removeEventListener("abort", abort);
}

async function postJSON({ baseURL, path, body, serializedBody, bearerToken, timeoutMs, maxResponseBytes, fetchImpl, signal }) {
  const controller = new AbortController();
  let timedOut = false;
  let cancelled = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const unlinkAbortSignal = linkAbortSignal(signal, controller, () => {
    cancelled = true;
  });
  if (signal?.aborted) {
    clearTimeout(timeout);
    unlinkAbortSignal();
    throw proverCancelledError();
  }
  const headers = new Headers();
  headers.set("Accept", "application/json");
  headers.set("Content-Type", "application/json");
  if (bearerToken && String(bearerToken).trim()) {
    headers.set("Authorization", `Bearer ${String(bearerToken).trim()}`);
  }

  try {
    const response = await fetchImpl(proverRequestURL(baseURL, path), {
      method: "POST",
      headers,
      body: serializedBody ?? JSON.stringify(body),
      cache: "no-store",
      redirect: "error",
      signal: controller.signal
    });
    // The common Core prover contract fixes JSON response media type for both
    // successes and errors. Reject an ambiguous body before parsing it or
    // classifying any untrusted error envelope.
    assertJSONResponseContentType(response);
    const text = await readBoundedResponseText(response, maxResponseBytes);
    if (response.status !== 200) {
      throw proverRequestError(response.status, text);
    }
    try {
      return parseStrictJSON(text);
    } catch {
      throw new Error("prover response was not valid canonical JSON");
    }
  } catch (error) {
    if (error?.name === "AbortError") {
      if (cancelled || signal?.aborted) throw proverCancelledError();
      if (timedOut) throw new Error(`prover request timed out after ${timeoutMs}ms`);
    }
    if (cancelled || signal?.aborted) {
      throw proverCancelledError();
    }
    throw error;
  } finally {
    clearTimeout(timeout);
    unlinkAbortSignal();
  }
}

function assertDirectDepositProofResponse(response, endpoint) {
  if (response?.redirected === true) {
    throw new Error("deposit proof response must not redirect");
  }
  const finalURL = String(response?.url || "");
  if (finalURL && new URL(finalURL).href !== endpoint.href) {
    throw new Error("deposit proof response must be served directly from its configured endpoint");
  }
  assertJSONResponseContentType(response, "deposit proof response");
}

async function postDepositProofJSON({
  endpoint,
  body,
  bearerToken,
  timeoutMs,
  maxResponseBytes,
  fetchImpl,
  signal,
  exactSuccessStatus,
  noStore = false
}) {
  const controller = new AbortController();
  let timedOut = false;
  let cancelled = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const unlinkAbortSignal = linkAbortSignal(signal, controller, () => {
    cancelled = true;
  });
  if (signal?.aborted) {
    clearTimeout(timeout);
    unlinkAbortSignal();
    throw proverCancelledError();
  }

  try {
    const usesCanonicalHeaders = bearerToken !== undefined;
    const headers = !usesCanonicalHeaders
      ? { Accept: "application/json", "Content-Type": "application/json" }
      : new Headers({ Accept: "application/json", "Content-Type": "application/json" });
    if (usesCanonicalHeaders && bearerToken && String(bearerToken).trim()) {
      headers.set("Authorization", `Bearer ${String(bearerToken).trim()}`);
    }
    const requestInit = {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      redirect: "error",
      signal: controller.signal
    };
    if (noStore) requestInit.cache = "no-store";
    const response = await fetchImpl(endpoint, requestInit);
    assertDirectDepositProofResponse(response, endpoint);
    const text = await readBoundedResponseText(response, maxResponseBytes);
    const succeeded = exactSuccessStatus === undefined
      ? response.ok
      : response.status === exactSuccessStatus;
    if (!succeeded) throw proverRequestError(response.status, text);
    try {
      return parseStrictJSON(text);
    } catch {
      throw new Error("deposit proof response was not valid canonical JSON");
    }
  } catch (error) {
    if (error?.name === "AbortError") {
      if (cancelled || signal?.aborted) throw proverCancelledError();
      if (timedOut) throw new Error(`deposit proof request timed out after ${timeoutMs}ms`);
    }
    if (cancelled || signal?.aborted) throw proverCancelledError();
    throw error;
  } finally {
    clearTimeout(timeout);
    unlinkAbortSignal();
  }
}

function assertResponseObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value;
}

function assertOnlyResponseFields(value, label, fields) {
  assertResponseObject(value, label);
  const allowed = new Set(fields);
  const unknown = Object.keys(value).filter(key => !allowed.has(key));
  if (unknown.length) throw new Error(`${label} contains an unknown JSON field`);
  return value;
}

const maxUint64 = (1n << 64n) - 1n;

function exactLowerHex(value, length, label) {
  if (typeof value !== "string" || value.length !== length || !/^[0-9a-f]+$/.test(value)) {
    throw new Error(`${label} must be exactly ${length} lowercase hex characters`);
  }
  return value;
}

function canonicalDepositFieldHex(value, label, { nonZero = false } = {}) {
  const encoded = exactLowerHex(value, 64, label);
  const parsed = BigInt(`0x${encoded}`);
  // Deposit fields live in the scalar field used by NoteV1, not the BN254
  // curve base field used by the Groth16 proof points below.
  if (canonicalFieldHex(parsed) !== encoded) {
    throw new Error(`${label} must be a canonical BN254 scalar-field encoding`);
  }
  if (nonZero && parsed === 0n) throw new Error(`${label} must be non-zero`);
  return encoded;
}

function canonicalDepositAmount(value, label) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical uint64 decimal string`);
  }
  if (BigInt(value) > maxUint64) throw new Error(`${label} exceeds uint64`);
  return value;
}

function canonicalDepositPublicKey(value, label) {
  const encoded = exactLowerHex(value, 64, label);
  let point;
  try {
    point = unpackPointHex(encoded);
  } catch (error) {
    throw new Error(`${label} must be a canonical compressed BN254 twisted-Edwards point: ${error.message}`);
  }
  if (point.x === 0n && point.y === 1n) throw new Error(`${label} must not be the identity point`);
  if (packPointHex(point) !== encoded) throw new Error(`${label} is not canonically encoded`);
  return point;
}

/** Validate the exact gnark BN254 Groth16 frame and return a defensive byte copy. */
export function validateDepositProofBytesV1(value, label = "deposit proof") {
  if (typeof value === "string") exactLowerHex(value, depositProofByteLength * 2, label);
  return validateCanonicalGroth16ProofBytes(value, label);
}

export function validateDepositProofRequestV1(request) {
  const label = "deposit proof request";
  assertOnlyResponseFields(request, label, ["version", "payload"]);
  if (request.version !== depositProofRequestVersion) {
    throw new Error(`${label}.version must be ${depositProofRequestVersion}`);
  }
  const payloadLabel = `${label}.payload`;
  const payload = assertOnlyResponseFields(request.payload, payloadLabel, [
    "version",
    "receiver_spend_pubkey_hex",
    "receiver_view_pubkey_hex",
    "amount",
    "asset_id_hex",
    "randomness_hex",
    "note_commitment_hex"
  ]);
  if (payload.version !== depositProofPayloadVersion) {
    throw new Error(`${payloadLabel}.version must be ${depositProofPayloadVersion}`);
  }
  const spendPoint = canonicalDepositPublicKey(payload.receiver_spend_pubkey_hex, `${payloadLabel}.receiver_spend_pubkey_hex`);
  const viewPoint = canonicalDepositPublicKey(payload.receiver_view_pubkey_hex, `${payloadLabel}.receiver_view_pubkey_hex`);
  const amount = canonicalDepositAmount(payload.amount, `${payloadLabel}.amount`);
  const assetIDHex = canonicalDepositFieldHex(payload.asset_id_hex, `${payloadLabel}.asset_id_hex`);
  const randomnessHex = canonicalDepositFieldHex(payload.randomness_hex, `${payloadLabel}.randomness_hex`);
  const commitmentHex = canonicalDepositFieldHex(
    payload.note_commitment_hex,
    `${payloadLabel}.note_commitment_hex`,
    { nonZero: true }
  );
  const note = {
    receiverSpendPubKeyX: spendPoint.x,
    receiverSpendPubKeyY: spendPoint.y,
    receiverViewPubKeyX: viewPoint.x,
    receiverViewPubKeyY: viewPoint.y,
    amount: BigInt(amount),
    assetID: BigInt(`0x${assetIDHex}`),
    randomness: BigInt(`0x${randomnessHex}`),
    memo: ""
  };
  if (computeNoteCommitmentHex(note) !== commitmentHex) {
    throw new Error("deposit prover payload note commitment mismatch");
  }
  return Object.freeze({
    version: depositProofRequestVersion,
    payload: Object.freeze({
      version: depositProofPayloadVersion,
      receiver_spend_pubkey_hex: payload.receiver_spend_pubkey_hex,
      receiver_view_pubkey_hex: payload.receiver_view_pubkey_hex,
      amount,
      asset_id_hex: assetIDHex,
      randomness_hex: randomnessHex,
      note_commitment_hex: commitmentHex
    })
  });
}

export function buildDepositProofRequestV1(input = {}) {
  const candidate = input?.request ?? input;
  if (candidate && typeof candidate === "object" && Object.prototype.hasOwnProperty.call(candidate, "payload")) {
    return validateDepositProofRequestV1(candidate);
  }
  const material = input?.material && typeof input.material === "object" ? input.material : {};
  const noteLike = input?.note ?? material.note;
  if (!noteLike) throw new Error("deposit proof NoteV1 is required");
  const note = normalizeNote(noteLike);
  const recomputedCommitmentHex = computeNoteCommitmentHex(note);
  const suppliedCommitment = input?.note_commitment_hex ?? input?.noteCommitmentHex ?? material.note_commitment_hex;
  if (suppliedCommitment != null && suppliedCommitment !== "") {
    const normalizedCommitment = normalizeHex(String(suppliedCommitment), "deposit proof note commitment");
    if (normalizedCommitment.length !== 64 || normalizedCommitment !== recomputedCommitmentHex) {
      throw new Error("deposit proof note commitment does not match the local NoteV1");
    }
  }
  return validateDepositProofRequestV1({
    version: depositProofRequestVersion,
    payload: {
      version: depositProofPayloadVersion,
      receiver_spend_pubkey_hex: noteSpendPubKeyHex(note),
      receiver_view_pubkey_hex: noteViewPubKeyHex(note),
      amount: note.amount.toString(),
      asset_id_hex: canonicalFieldHex(note.assetID),
      randomness_hex: canonicalFieldHex(note.randomness),
      note_commitment_hex: recomputedCommitmentHex
    }
  });
}

export function validateDepositProofResponseV1(request, response) {
  const normalizedRequest = validateDepositProofRequestV1(request);
  const label = "deposit proof response";
  assertOnlyResponseFields(response, label, ["version", "proof"]);
  if (response.version !== depositProofResponseVersion) {
    throw new Error(`${label}.version must be ${depositProofResponseVersion}`);
  }
  const proofLabel = `${label}.proof`;
  const proof = assertOnlyResponseFields(response.proof, proofLabel, [
    "version", "note_commitment_hex", "proof_hex"
  ]);
  if (proof.version !== depositProofVersion) {
    throw new Error(`${proofLabel}.version must be ${depositProofVersion}`);
  }
  const commitmentHex = canonicalDepositFieldHex(
    proof.note_commitment_hex,
    `${proofLabel}.note_commitment_hex`,
    { nonZero: true }
  );
  if (commitmentHex !== normalizedRequest.payload.note_commitment_hex) {
    throw new Error("deposit proof response note commitment mismatch");
  }
  const proofBytes = validateDepositProofBytesV1(proof.proof_hex, `${proofLabel}.proof_hex`);
  return Object.freeze({
    version: depositProofResponseVersion,
    proof: Object.freeze({
      version: depositProofVersion,
      note_commitment_hex: commitmentHex,
      proof_hex: hexFromBytes(proofBytes)
    })
  });
}

/** Normalize legacy local/WASM provider output without permitting a legacy HTTP wire. */
export function normalizeDepositProofProviderResultV1(request, result) {
  if (result?.proof && typeof result.proof === "object" &&
      !ArrayBuffer.isView(result.proof) && !Array.isArray(result.proof) &&
      !(result.proof instanceof ArrayBuffer)) {
    return validateDepositProofResponseV1(request, result);
  }
  const proofValue = result?.proof_hex ?? result?.proofHex ??
    result?.deposit_proof_hex ?? result?.depositProofHex ??
    result?.proof_bytes ?? result?.proofBytes ?? result?.proof ??
    result?.depositProof ?? result?.deposit_proof;
  const proofHex = proofValue == null
    ? undefined
    : hexFromBytes(validateDepositProofBytesV1(proofValue, "deposit proof provider result"));
  return validateDepositProofResponseV1(request, {
    version: result?.version ?? depositProofResponseVersion,
    proof: {
      version: result?.proof_version ?? result?.proofVersion ?? depositProofVersion,
      note_commitment_hex: result?.note_commitment_hex ?? result?.noteCommitmentHex ?? request?.payload?.note_commitment_hex,
      proof_hex: proofHex
    }
  });
}

function proverRequestError(status, responseText) {
  let code = "";
  let retryable = false;
  try {
    const response = assertOnlyResponseFields(
      parseStrictJSON(responseText),
      "prover error response",
      ["version", "code", "message", "retryable"]
    );
    if (response.version !== proverErrorResponseVersion) {
      throw new Error("unsupported prover error response version");
    }
    code = String(response.code || "");
    if (!proverErrorCodes.has(code)) throw new Error("unsupported prover error response code");
    if (!proverErrorStatusCodes[code]?.has(status)) {
      throw new Error("prover error response code does not match HTTP status");
    }
    if (typeof response.message !== "string" || !response.message.trim()) {
      throw new Error("prover error response message is required");
    }
    const expectedRetryable = code === "busy";
    const hasRetryable = Object.prototype.hasOwnProperty.call(response, "retryable");
    if ((expectedRetryable && (!hasRetryable || response.retryable !== true)) ||
        (!expectedRetryable && hasRetryable && response.retryable !== false)) {
      throw new Error("invalid prover error retryability");
    }
    retryable = expectedRetryable;
  } catch {
    code = "";
    retryable = false;
  }
  const error = new Error(
    `prover request failed with status ${status}${code ? ` (${code})` : ""}`
  );
  error.status = status;
  error.proverCode = code;
  error.retryable = retryable;
  return error;
}

function normalizeProofShape(proof, kind, expectedVersion) {
  const label = `${kind} proof response.proof`;
  assertOnlyResponseFields(proof, label, ["version", "payload_hash", "proof_hex"]);
  if (proof.version !== expectedVersion) {
    throw new Error(`${label}.version must be ${expectedVersion}`);
  }
  const payloadHash = normalizeHex(proof.payload_hash, `${label}.payload_hash`);
  if (payloadHash.length !== 64) {
    throw new Error(`${label}.payload_hash must be a 32-byte hex string`);
  }
  return {
    ...proof,
    payload_hash: payloadHash,
    proof_hex: normalizeHex(proof.proof_hex, `${label}.proof_hex`)
  };
}

function normalizeProofResponseShape(response, kind, expectedResponseVersion, expectedProofVersion) {
  const label = `${kind} proof response`;
  assertOnlyResponseFields(response, label, ["version", "proof"]);
  if (response.version !== expectedResponseVersion) {
    throw new Error(`${label}.version must be ${expectedResponseVersion}`);
  }
  return {
    ...response,
    proof: normalizeProofShape(response.proof, kind, expectedProofVersion)
  };
}

function proofRequestEnvelope(request, expectedVersion) {
  const isEnvelope = Boolean(
    request && typeof request === "object" && Object.prototype.hasOwnProperty.call(request, "payload")
  );
  return {
    // Bare payloads are the only legacy convenience shape. Once callers use
    // an envelope, its version must be explicit and exact: defaulting a
    // missing/falsy version would silently upgrade an unsupported wire.
    version: isEnvelope ? request.version : expectedVersion,
    payload: isEnvelope ? request.payload : request
  };
}

function knownFields(value, fields) {
  return Object.fromEntries(fields.map(field => [field, value[field]]));
}

function canonicalBatchNote(note) {
  return {
    rsx: String(note.rsx ?? note.receiverSpendPubKeyX),
    rsy: String(note.rsy ?? note.receiverSpendPubKeyY),
    rvx: String(note.rvx ?? note.receiverViewPubKeyX),
    rvy: String(note.rvy ?? note.receiverViewPubKeyY),
    am: String(note.am ?? note.amount),
    as: String(note.as ?? note.assetID ?? note.asset_id),
    rn: String(note.rn ?? note.randomness),
    mm: String(note.mm ?? note.memo ?? "")
  };
}

function canonicalBatchPayload(payload) {
  return {
    version: preparedBatchTransferPayloadVersion,
    circuit_set_id: batchTransferCircuitSetId,
    ...(String(payload.creator ?? "") ? { creator: String(payload.creator) } : {}),
    chain_id: String(payload.chain_id),
    expires_at_unix: Number(payload.expires_at_unix),
    root: String(payload.root),
    asset_id: String(payload.asset_id),
    inputs: payload.inputs.map(input => ({
      note: canonicalBatchNote(input.note),
      merkle_path: input.merkle_path.map(String),
      merkle_path_helper: input.merkle_path_helper.map(Number),
      nullifier: String(input.nullifier)
    })),
    outputs: payload.outputs.map(output => ({
      kind: String(output.kind),
      note: canonicalBatchNote(output.note),
      privacy_policy: Number(output.privacy_policy),
      disclosure_mode: Number(output.disclosure_mode),
      ...(String(output.disclosure_target_pubkey ?? "")
        ? { disclosure_target_pubkey: String(output.disclosure_target_pubkey) }
        : {}),
      user_disclosure_blinding: String(output.user_disclosure_blinding),
      full_disclosure_blinding: String(output.full_disclosure_blinding)
    })),
    message_outputs: payload.message_outputs.map(output => ({
      commitment: String(output.commitment),
      ciphertext: String(output.ciphertext),
      view_tag: String(output.view_tag),
      user_privacy_policy: Number(output.user_privacy_policy),
      user_disclosure_mode: Number(output.user_disclosure_mode),
      user_disclosure_digest: String(output.user_disclosure_digest ?? ""),
      user_disclosure_target_pubkey: String(output.user_disclosure_target_pubkey ?? ""),
      user_disclosure_payload: String(output.user_disclosure_payload ?? ""),
      full_disclosure_digest: String(output.full_disclosure_digest),
      audit_disclosure_payload: String(output.audit_disclosure_payload),
      self_view_disclosure_payload: String(output.self_view_disclosure_payload ?? "")
    })),
    audit_key_id: String(payload.audit_key_id),
    audit_key_epoch: String(payload.audit_key_epoch),
    audit_disclosure_target_pubkey: String(payload.audit_disclosure_target_pubkey),
    nullifier_root: String(payload.nullifier_root),
    commitment_root: String(payload.commitment_root),
    user_disclosure_root: String(payload.user_disclosure_root),
    full_disclosure_root: String(payload.full_disclosure_root),
    payload_digest_hi: String(payload.payload_digest_hi),
    payload_digest_lo: String(payload.payload_digest_lo),
    expected_intent: String(payload.expected_intent),
    owner_signature: String(payload.owner_signature),
    payload_hash: String(payload.payload_hash)
  };
}

function canonicalTransferProofRequest(request, { nowUnix } = {}) {
  const candidate = proofRequestEnvelope(request, transferProofRequestVersion);
  if (candidate.version !== transferProofRequestVersion) {
    throw new Error(`unsupported transfer proof request version ${JSON.stringify(candidate.version)}`);
  }
  if (candidate.payload?.version !== preparedTransferV5PayloadVersion) {
    throw new Error(`unsupported transfer payload version ${JSON.stringify(candidate.payload?.version)} (expected ${preparedTransferV5PayloadVersion})`);
  }
  validatePreparedTransferV5PayloadAt(candidate.payload, nowUnix);
  const payload = knownFields(candidate.payload, [
    "version",
    "creator",
    "chain_id",
    "expires_at_unix",
    "root_hex",
    "asset_id_hex",
    "inputs",
    "outputs",
    "cipher_text_hexes",
    "view_tag_hexes",
    "user_privacy_policy",
    "user_disclosure_mode",
    "user_disclosure_digest_hex",
    "user_disclosure_target_pubkey_hex",
    "user_disclosure_payload_hex",
    "audit_disclosure_digest_hex",
    "audit_disclosure_target_pubkey_hex",
    "audit_disclosure_payload_hex",
    "self_view_disclosure_digest_hex",
    "self_view_disclosure_payload_hex",
    "user_disclosure_blinding_hex",
    "full_disclosure_blinding_hex",
    "owner_signature_hex",
    "payload_hash"
  ]);
  payload.inputs = candidate.payload.inputs.map(input => ({
    ...knownFields(input, [
      "amount",
      "randomness_hex",
      "spend_pubkey_hex",
      "view_pubkey_hex",
      "merkle_path",
      "merkle_path_helper",
      "nullifier_hex"
    ]),
    merkle_path: [...input.merkle_path],
    merkle_path_helper: [...input.merkle_path_helper]
  }));
  payload.outputs = candidate.payload.outputs.map(output => knownFields(output, [
    "amount",
    "randomness_hex",
    "spend_pubkey_hex",
    "view_pubkey_hex",
    "commitment_hex"
  ]));
  payload.cipher_text_hexes = [...candidate.payload.cipher_text_hexes];
  payload.view_tag_hexes = [...candidate.payload.view_tag_hexes];
  return { version: transferProofRequestVersion, payload };
}

function canonicalWithdrawProofRequest(request, { nowUnix } = {}) {
  const candidate = proofRequestEnvelope(request, withdrawProofRequestVersion);
  if (candidate.version !== withdrawProofRequestVersion) {
    throw new Error(`unsupported withdraw proof request version ${JSON.stringify(candidate.version)}`);
  }
  validatePreparedWithdrawProverPayloadMetadata(candidate.payload, nowUnix);
  const payload = knownFields(candidate.payload, [
    "version",
    "root_hex",
    "nullifier_hex",
    "amount",
    "asset_denom",
    "asset_id_hex",
    "recipient",
    "recipient_bytes_hex",
    "chain_id",
    "expires_at_unix",
    "note_randomness_hex",
    "spend_pubkey_hex",
    "view_pubkey_hex",
    "merkle_path",
    "merkle_path_helper",
    "spend_intent_signature_hex",
    "payload_hash"
  ]);
  payload.merkle_path = [...candidate.payload.merkle_path];
  payload.merkle_path_helper = [...candidate.payload.merkle_path_helper];
  return { version: withdrawProofRequestVersion, payload };
}

function canonicalBatchTransferProofRequest(request, { nowUnix } = {}) {
  const candidate = proofRequestEnvelope(request, batchTransferProofRequestVersion);
  if (candidate.version !== batchTransferProofRequestVersion) {
    throw new Error(`unsupported batch transfer proof request version ${JSON.stringify(candidate.version)}`);
  }
  validatePreparedBatchTransferPayloadEnvelope(candidate.payload, { nowUnix });
  const payload = canonicalBatchPayload(candidate.payload);
  const serializedPayload = serializePreparedBatchTransferPayload(payload);
  // Build the callback-facing request from the same canonical wire used by
  // HTTP. Keeping the caller's object here would let ignored unknown/private
  // fields cross an async prover boundary even though they are not hashed.
  const serializedBody = `{"version":${JSON.stringify(batchTransferProofRequestVersion)},"payload":${serializedPayload}}`;
  return {
    request: { version: batchTransferProofRequestVersion, payload },
    serializedBody
  };
}

function unwrapTransferProof(request, response, { nowUnix } = {}) {
  const normalized = normalizeProofResponseShape(
    response,
    "transfer",
    transferProofResponseVersion,
    preparedTransferV5ProofVersion
  );
  const proof = normalized.proof;
  validatePreparedTransferV5Proof(request.payload, proof, { nowUnix });
  return {
    version: normalized.version,
    proof
  };
}

function unwrapWithdrawProof(request, response, { nowUnix } = {}) {
  const normalized = normalizeProofResponseShape(
    response,
    "withdraw",
    withdrawProofResponseVersion,
    preparedWithdrawProofVersion
  );
  const proof = normalized.proof;
  validatePreparedWithdrawProof(request.payload, proof, nowUnix);
  return {
    version: normalized.version,
    proof
  };
}

function unwrapBatchTransferProof(request, response, { nowUnix } = {}) {
  const label = "batch transfer proof response";
  assertOnlyResponseFields(response, label, ["version", "proof"]);
  if (response.version !== batchTransferProofResponseVersion) {
    throw new Error(`${label}.version must be ${batchTransferProofResponseVersion}`);
  }
  assertOnlyResponseFields(response.proof, `${label}.proof`, [
    "version", "request_payload_hash", "proof", "circuit_set_id", "artifact_checksum"
  ]);
  return {
    ...response,
    proof: normalizePreparedBatchTransferProof(request.payload, response.proof, {
      nowUnix
    })
  };
}

export function createHttpProverAdapter({
  baseURL,
  bearerToken = "",
  timeoutMs = 120000,
  maxResponseBytes = defaultProverResponseMaxBytes,
  fetchImpl = fetch
} = {}) {
  if (!fetchImpl) {
    throw new Error("fetch implementation is required");
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("timeoutMs must be positive");
  }
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes <= 0) {
    throw new Error("maxResponseBytes must be a positive safe integer");
  }
  const normalizedBaseURL = normalizeBaseURL(baseURL);

  return {
    async proveTransfer(request, { signal, nowUnix } = {}) {
      try {
        const normalizedRequest = canonicalTransferProofRequest(request, { nowUnix });
        const response = await postJSON({
          baseURL: normalizedBaseURL,
          path: "/v1/prover/transfer",
          body: normalizedRequest,
          bearerToken,
          timeoutMs,
          maxResponseBytes,
          fetchImpl,
          signal
        });
        return unwrapTransferProof(normalizedRequest, response, { nowUnix });
      } catch (error) {
        throw wrapProverError(error);
      }
    },

    async proveWithdraw(request, { signal, nowUnix } = {}) {
      try {
        const normalizedRequest = canonicalWithdrawProofRequest(request, { nowUnix });
        const response = await postJSON({
          baseURL: normalizedBaseURL,
          path: "/v1/prover/withdraw",
          body: normalizedRequest,
          bearerToken,
          timeoutMs,
          maxResponseBytes,
          fetchImpl,
          signal
        });
        return unwrapWithdrawProof(normalizedRequest, response, { nowUnix });
      } catch (error) {
        throw wrapProverError(error);
      }
    },

    async proveDeposit(input, { signal } = {}) {
      try {
        const request = buildDepositProofRequestV1(input);
        const response = await postDepositProofJSON({
          endpoint: proverRequestURL(normalizedBaseURL, depositProofPath),
          body: request,
          bearerToken,
          timeoutMs,
          maxResponseBytes,
          fetchImpl,
          signal: signal ?? input?.signal,
          exactSuccessStatus: 200,
          noStore: true
        });
        return validateDepositProofResponseV1(request, response);
      } catch (error) {
        throw wrapProverError(error);
      }
    },

    async proveBatchTransfer(request, { signal, nowUnix } = {}) {
      try {
        const canonical = canonicalBatchTransferProofRequest(request, { nowUnix });
        const response = await postJSON({
          baseURL: normalizedBaseURL,
          path: batchTransferProofPath,
          body: canonical.request,
          serializedBody: canonical.serializedBody,
          bearerToken,
          timeoutMs,
          maxResponseBytes,
          fetchImpl,
          signal
        });
        return unwrapBatchTransferProof(canonical.request, response, { nowUnix });
      } catch (error) {
        throw wrapProverError(error);
      }
    }
  };
}

function depositProviderResponseWithLegacyAccessors(response) {
  const compatible = {
    version: response.version,
    proof: response.proof
  };
  // Older browser facades read these properties directly. Keep non-enumerable
  // accessors so they do not alter the canonical v1 response object or JSON.
  Object.defineProperties(compatible, {
    proof_hex: { value: response.proof.proof_hex, enumerable: false },
    note_commitment_hex: { value: response.proof.note_commitment_hex, enumerable: false }
  });
  return Object.freeze(compatible);
}

/**
 * Build the legacy exact-endpoint provider retained for EVM and product-owned
 * integrations. Its flat wire is intentionally separate from Core v0.4's
 * canonical Cosmos deposit contract.
 */
export function createHttpDepositProofProvider({
  url,
  timeoutMs = defaultDepositProofTimeoutMs,
  maxResponseBytes = defaultProverResponseMaxBytes,
  fetchImpl = fetch
} = {}) {
  if (!fetchImpl) throw new Error("fetch implementation is required");
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("deposit proof timeoutMs must be positive");
  }
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes <= 0) {
    throw new Error("deposit proof maxResponseBytes must be a positive safe integer");
  }
  const endpoint = normalizeDepositProofURL(url);

  return async function proveDeposit(input = {}, { signal } = {}) {
    try {
      const noteJSON = String(input.note_json ?? input.noteJson ?? input.material?.note_json ?? "");
      const noteCommitmentHex = normalizeHex(
        String(input.note_commitment_hex ?? input.noteCommitmentHex ?? input.material?.note_commitment_hex ?? ""),
        "deposit proof note_commitment_hex"
      );
      if (noteCommitmentHex.length !== 64) {
        throw new Error("deposit proof note_commitment_hex must be a 32-byte hex string");
      }
      if (!noteJSON) throw new Error("deposit proof note_json is required");
      const response = assertOnlyResponseFields(
        await postDepositProofJSON({
          endpoint,
          body: {
            note_json: noteJSON,
            note_commitment_hex: noteCommitmentHex
          },
          timeoutMs,
          maxResponseBytes,
          fetchImpl,
          signal: signal ?? input?.signal
        }),
        "deposit proof response",
        ["version", "proof_hex", "note_commitment_hex"]
      );
      if (response.version !== depositProofResponseVersion) {
        throw new Error(`deposit proof response.version must be ${depositProofResponseVersion}`);
      }
      const responseCommitmentHex = normalizeHex(
        response.note_commitment_hex,
        "deposit proof response.note_commitment_hex"
      );
      if (responseCommitmentHex !== noteCommitmentHex) {
        throw new Error("deposit proof response note_commitment_hex does not match the request");
      }
      return Object.freeze({
        version: depositProofResponseVersion,
        proof_hex: normalizeHex(response.proof_hex, "deposit proof response.proof_hex"),
        note_commitment_hex: responseCommitmentHex
      });
    } catch (error) {
      throw wrapProverError(error);
    }
  };
}

/** Build an exact-endpoint convenience provider using the canonical Core v0.4 wire. */
export function createHttpDepositProofProviderV1({
  url,
  bearerToken = "",
  timeoutMs = defaultDepositProofTimeoutMs,
  maxResponseBytes = defaultProverResponseMaxBytes,
  fetchImpl = fetch
} = {}) {
  if (!fetchImpl) throw new Error("fetch implementation is required");
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("deposit proof timeoutMs must be positive");
  }
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes <= 0) {
    throw new Error("deposit proof maxResponseBytes must be a positive safe integer");
  }
  const endpoint = normalizeDepositProofURL(url);

  return async function proveDeposit(input = {}, { signal } = {}) {
    try {
      const request = buildDepositProofRequestV1(input);
      const response = await postDepositProofJSON({
        endpoint,
        body: request,
        bearerToken,
        timeoutMs,
        maxResponseBytes,
        fetchImpl,
        signal: signal ?? input?.signal,
        exactSuccessStatus: 200,
        noStore: true
      });
      return depositProviderResponseWithLegacyAccessors(
        validateDepositProofResponseV1(request, response)
      );
    } catch (error) {
      throw wrapProverError(error);
    }
  };
}

async function sleep(ms) {
  await new Promise(resolve => setTimeout(resolve, ms));
}

async function abortable(value, signal) {
  if (!signal) return value;
  if (signal.aborted) throw proverCancelledError();
  let abort;
  const cancellation = new Promise((_, reject) => {
    abort = () => reject(proverCancelledError());
    signal.addEventListener("abort", abort, { once: true });
  });
  try {
    return await Promise.race([value, cancellation]);
  } finally {
    signal.removeEventListener("abort", abort);
  }
}

function normalizeJobResult(job) {
  const status = String(job?.status || "").toLowerCase();
  if (["done", "complete", "completed", "succeeded", "success"].includes(status)) return "completed";
  if (["failed", "error", "rejected"].includes(status)) return "failed";
  if (["queued", "pending", "running", "processing", "submitted"].includes(status)) return "pending";
  return status || "pending";
}

export function createAsyncJobProverAdapter({
  submitTransferJob,
  submitWithdrawJob,
  submitBatchTransferJob,
  getJob,
  intervalMs = 1000,
  timeoutMs = 300000,
  now = () => Date.now(),
  sleepImpl = sleep
} = {}) {
  if (![submitTransferJob, submitWithdrawJob, submitBatchTransferJob].some(submit => typeof submit === "function")) {
    throw new Error("at least one prover job submit function is required");
  }
  if (typeof getJob !== "function") {
    throw new Error("getJob(jobId) is required");
  }

  async function waitForProof({ request, submit, unwrap, unwrapOptions, signal }) {
    try {
      if (signal?.aborted) throw proverCancelledError();
      const submitted = await abortable(submit(request, { signal }), signal);
      const jobId = submitted?.jobId ?? submitted?.job_id ?? submitted?.id;
      if (!jobId) {
        throw new Error("prover job submit response must include jobId");
      }

      const deadline = now() + timeoutMs;
      while (now() <= deadline) {
        if (signal?.aborted) throw proverCancelledError();
        const job = await abortable(getJob(jobId, { signal }), signal);
        const status = normalizeJobResult(job);
        if (status === "completed") {
          const response = job.response ?? job.result ?? job;
          return unwrap(request, response, unwrapOptions);
        }
        if (status === "failed") {
          throw wrapProverError(new Error(`prover job ${jobId} failed`));
        }
        await abortable(sleepImpl(intervalMs), signal);
      }
      throw wrapProverError(new Error(`prover job ${jobId} timed out after ${timeoutMs}ms`));
    } catch (error) {
      if (error?.code === "PROVER_CANCELLED") throw wrapProverError(error);
      throw error;
    }
  }

  const adapter = {};

  if (typeof submitTransferJob === "function") {
    adapter.proveTransfer = async (request, { signal, nowUnix } = {}) => {
      const normalizedRequest = canonicalTransferProofRequest(request, { nowUnix });
      return waitForProof({
        request: normalizedRequest,
        submit: submitTransferJob,
        unwrap: unwrapTransferProof,
        unwrapOptions: { nowUnix },
        signal
      });
    };
  }

  if (typeof submitWithdrawJob === "function") {
    adapter.proveWithdraw = async (request, { signal, nowUnix } = {}) => {
      const normalizedRequest = canonicalWithdrawProofRequest(request, { nowUnix });
      return waitForProof({
        request: normalizedRequest,
        submit: submitWithdrawJob,
        unwrap: unwrapWithdrawProof,
        unwrapOptions: { nowUnix },
        signal
      });
    };
  }

  if (typeof submitBatchTransferJob === "function") {
    adapter.proveBatchTransfer = async (request, { signal, nowUnix } = {}) => {
      const canonical = canonicalBatchTransferProofRequest(request, { nowUnix });
      return waitForProof({
        request: canonical.request,
        submit: submitBatchTransferJob,
        unwrap: unwrapBatchTransferProof,
        unwrapOptions: { nowUnix },
        signal
      });
    };
  }

  return adapter;
}

export function createStaticProverAdapter({ transferProofHex = "", withdrawProofHex = "" } = {}) {
  return {
    async proveTransfer(request, { nowUnix } = {}) {
      const normalizedRequest = canonicalTransferProofRequest(request, { nowUnix });
      const payload = normalizedRequest.payload;
      const proof = {
        version: preparedTransferV5ProofVersion,
        payload_hash: payload.payload_hash,
        proof_hex: transferProofHex
      };
      validatePreparedTransferV5Proof(payload, proof, { nowUnix });
      return { version: transferProofResponseVersion, proof };
    },

    async proveWithdraw(request, { nowUnix } = {}) {
      const normalizedRequest = canonicalWithdrawProofRequest(request, { nowUnix });
      const payload = normalizedRequest.payload;
      const proof = {
        version: preparedWithdrawProofVersion,
        payload_hash: payload.payload_hash,
        proof_hex: withdrawProofHex
      };
      validatePreparedWithdrawProof(payload, proof, nowUnix);
      return { version: withdrawProofResponseVersion, proof };
    }
  };
}
