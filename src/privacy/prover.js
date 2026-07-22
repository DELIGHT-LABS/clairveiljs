import {
  normalizeHex
} from "../core/crypto.js";
import {
  preparedWithdrawProofVersion,
  validatePreparedWithdrawProof
} from "./payload.js";
import {
  preparedTransferV5ProofVersion,
  preparedTransferV5PayloadVersion,
  validatePreparedTransferV5Proof
} from "./transfer-v5.js";
import {
  batchTransferProofPath,
  batchTransferProofRequestVersion,
  batchTransferProofResponseVersion,
  normalizePreparedBatchTransferProof,
  serializeBatchTransferProofRequest,
  validatePreparedBatchTransferPayloadEnvelope
} from "./batch-transfer.js";
import {
  wrapProverError
} from "../core/errors.js";

export const transferProofRequestVersion = "v2";
export const transferProofResponseVersion = "v2";
export const withdrawProofRequestVersion = "v2";
export const withdrawProofResponseVersion = "v2";
/** Match the bounded Go prover transport response policy. */
export const defaultProverResponseMaxBytes = 1 << 20;

function normalizeBaseURL(baseURL) {
  const url = new URL(String(baseURL || ""));
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`unsupported prover URL protocol ${url.protocol}`);
  }
  if (url.protocol === "http:" && !isLoopbackProverHost(url.hostname)) {
    throw new Error(`prover transport requires HTTPS for non-loopback endpoint ${JSON.stringify(url.host)}`);
  }
  return url;
}

function isLoopbackProverHost(hostname) {
  const normalized = String(hostname || "").replace(/^\[|\]$/g, "").toLowerCase();
  return normalized === "localhost" || normalized === "::1" || normalized === "127.0.0.1";
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
        if (keys.has(key)) error(`duplicate JSON object key ${JSON.stringify(key)}`);
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

async function postJSON({ baseURL, path, body, serializedBody, bearerToken, timeoutMs, maxResponseBytes, fetchImpl }) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const headers = new Headers();
  headers.set("Content-Type", "application/json");
  if (bearerToken && String(bearerToken).trim()) {
    headers.set("Authorization", `Bearer ${String(bearerToken).trim()}`);
  }

  try {
    const response = await fetchImpl(new URL(path, baseURL), {
      method: "POST",
      headers,
      body: serializedBody ?? JSON.stringify(body),
      redirect: "error",
      signal: controller.signal
    });
    const text = await readBoundedResponseText(response, maxResponseBytes);
    if (!response.ok) {
      throw new Error(`prover request failed with status ${response.status}: ${text}`);
    }
    try {
      return parseStrictJSON(text);
    } catch (error) {
      throw new Error(`prover response was not JSON: ${error.message}`);
    }
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error(`prover request timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
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
  if (unknown.length) throw new Error(`${label} contains unknown JSON field ${JSON.stringify(unknown[0])}`);
  return value;
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

function unwrapTransferProof(request, response) {
  const normalized = normalizeProofResponseShape(
    response,
    "transfer",
    transferProofResponseVersion,
    preparedTransferV5ProofVersion
  );
  const proof = normalized.proof;
  validatePreparedTransferV5Proof(request.payload, proof);
  return {
    version: normalized.version,
    proof
  };
}

function unwrapWithdrawProof(request, response) {
  const normalized = normalizeProofResponseShape(
    response,
    "withdraw",
    withdrawProofResponseVersion,
    preparedWithdrawProofVersion
  );
  const proof = normalized.proof;
  validatePreparedWithdrawProof(request.payload, proof);
  return {
    version: normalized.version,
    proof
  };
}

function unwrapBatchTransferProof(request, response) {
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
      nowUnix: Math.floor(Date.now() / 1000)
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
    async proveTransfer(request) {
      const normalizedRequest = {
        version: request?.version || transferProofRequestVersion,
        payload: request?.payload || request
      };
      if (normalizedRequest.version !== transferProofRequestVersion) {
        throw new Error(`unsupported transfer proof request version ${JSON.stringify(normalizedRequest.version)}`);
      }
      if (normalizedRequest.payload?.version !== preparedTransferV5PayloadVersion) {
        throw new Error(`unsupported transfer payload version ${JSON.stringify(normalizedRequest.payload?.version)} (expected ${preparedTransferV5PayloadVersion})`);
      }
      try {
        const response = await postJSON({
          baseURL: normalizedBaseURL,
          path: "/v1/prover/transfer",
          body: normalizedRequest,
          bearerToken,
          timeoutMs,
          maxResponseBytes,
          fetchImpl
        });
        return unwrapTransferProof(normalizedRequest, response);
      } catch (error) {
        throw wrapProverError(error);
      }
    },

    async proveWithdraw(request) {
      const normalizedRequest = {
        version: request?.version || withdrawProofRequestVersion,
        payload: request?.payload || request
      };
      if (normalizedRequest.version !== withdrawProofRequestVersion) {
        throw new Error(`unsupported withdraw proof request version ${JSON.stringify(normalizedRequest.version)}`);
      }
      try {
        const response = await postJSON({
          baseURL: normalizedBaseURL,
          path: "/v1/prover/withdraw",
          body: normalizedRequest,
          bearerToken,
          timeoutMs,
          maxResponseBytes,
          fetchImpl
        });
        return unwrapWithdrawProof(normalizedRequest, response);
      } catch (error) {
        throw wrapProverError(error);
      }
    },

    async proveBatchTransfer(request) {
      const isEnvelope = Boolean(request && typeof request === "object" && Object.prototype.hasOwnProperty.call(request, "payload"));
      const normalizedRequest = {
        version: isEnvelope ? (request.version || batchTransferProofRequestVersion) : batchTransferProofRequestVersion,
        payload: isEnvelope ? request.payload : request
      };
      if (normalizedRequest.version !== batchTransferProofRequestVersion) {
        throw new Error(`unsupported batch transfer proof request version ${JSON.stringify(normalizedRequest.version)}`);
      }
      try {
        validatePreparedBatchTransferPayloadEnvelope(normalizedRequest.payload, {
          nowUnix: Math.floor(Date.now() / 1000)
        });
        const response = await postJSON({
          baseURL: normalizedBaseURL,
          path: batchTransferProofPath,
          body: normalizedRequest,
          serializedBody: serializeBatchTransferProofRequest(normalizedRequest.payload),
          bearerToken,
          timeoutMs,
          maxResponseBytes,
          fetchImpl
        });
        return unwrapBatchTransferProof(normalizedRequest, response);
      } catch (error) {
        throw wrapProverError(error);
      }
    }
  };
}

async function sleep(ms) {
  await new Promise(resolve => setTimeout(resolve, ms));
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

  async function waitForProof({ request, submit, unwrap }) {
    const submitted = await submit(request);
    const jobId = submitted?.jobId ?? submitted?.job_id ?? submitted?.id;
    if (!jobId) {
      throw new Error("prover job submit response must include jobId");
    }

    const deadline = now() + timeoutMs;
    while (now() <= deadline) {
      const job = await getJob(jobId);
      const status = normalizeJobResult(job);
      if (status === "completed") {
        const response = job.response ?? job.result ?? job;
        return unwrap(request, response);
      }
      if (status === "failed") {
        throw wrapProverError(new Error(job.error || job.message || `prover job ${jobId} failed`));
      }
      await sleepImpl(intervalMs);
    }
    throw wrapProverError(new Error(`prover job ${jobId} timed out after ${timeoutMs}ms`));
  }

  const adapter = {};

  if (typeof submitTransferJob === "function") {
    adapter.proveTransfer = async request => {
      const normalizedRequest = {
        version: request?.version || transferProofRequestVersion,
        payload: request?.payload || request
      };
      if (normalizedRequest.version !== transferProofRequestVersion) {
        throw new Error(`unsupported transfer proof request version ${JSON.stringify(normalizedRequest.version)}`);
      }
      if (normalizedRequest.payload?.version !== preparedTransferV5PayloadVersion) {
        throw new Error(`unsupported transfer payload version ${JSON.stringify(normalizedRequest.payload?.version)} (expected ${preparedTransferV5PayloadVersion})`);
      }
      return waitForProof({
        request: normalizedRequest,
        submit: submitTransferJob,
        unwrap: unwrapTransferProof
      });
    };
  }

  if (typeof submitWithdrawJob === "function") {
    adapter.proveWithdraw = async request => {
      const normalizedRequest = {
        version: request?.version || withdrawProofRequestVersion,
        payload: request?.payload || request
      };
      if (normalizedRequest.version !== withdrawProofRequestVersion) {
        throw new Error(`unsupported withdraw proof request version ${JSON.stringify(normalizedRequest.version)}`);
      }
      return waitForProof({
        request: normalizedRequest,
        submit: submitWithdrawJob,
        unwrap: unwrapWithdrawProof
      });
    };
  }

  if (typeof submitBatchTransferJob === "function") {
    adapter.proveBatchTransfer = async request => {
      const isEnvelope = Boolean(
        request && typeof request === "object" && Object.prototype.hasOwnProperty.call(request, "payload")
      );
      const normalizedRequest = {
        version: isEnvelope ? (request.version || batchTransferProofRequestVersion) : batchTransferProofRequestVersion,
        payload: isEnvelope ? request.payload : request
      };
      if (normalizedRequest.version !== batchTransferProofRequestVersion) {
        throw new Error(`unsupported batch transfer proof request version: ${normalizedRequest.version}`);
      }
      validatePreparedBatchTransferPayloadEnvelope(normalizedRequest.payload, {
        nowUnix: Math.floor(Date.now() / 1000)
      });
      return waitForProof({
        request: normalizedRequest,
        submit: submitBatchTransferJob,
        unwrap: unwrapBatchTransferProof
      });
    };
  }

  return adapter;
}

export function createStaticProverAdapter({ transferProofHex = "", withdrawProofHex = "" } = {}) {
  return {
    async proveTransfer(request) {
      const payload = request?.payload || request;
      const proof = {
        version: preparedTransferV5ProofVersion,
        payload_hash: payload.payload_hash,
        proof_hex: transferProofHex
      };
      validatePreparedTransferProof(payload, proof);
      return { version: transferProofResponseVersion, proof };
    },

    async proveWithdraw(request) {
      const payload = request?.payload || request;
      const proof = {
        version: preparedWithdrawProofVersion,
        payload_hash: payload.payload_hash,
        proof_hex: withdrawProofHex
      };
      validatePreparedWithdrawProof(payload, proof);
      return { version: withdrawProofResponseVersion, proof };
    }
  };
}
