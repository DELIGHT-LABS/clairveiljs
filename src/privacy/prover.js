import {
  normalizeHex
} from "../core/crypto.js";
import {
  preparedTransferProofVersion,
  preparedWithdrawProofVersion,
  validatePreparedTransferProof,
  validatePreparedWithdrawProof
} from "./payload.js";
import {
  wrapProverError
} from "../core/errors.js";

export const transferProofRequestVersion = "v1";
export const transferProofResponseVersion = "v1";
export const withdrawProofRequestVersion = "v1";
export const withdrawProofResponseVersion = "v1";

function normalizeBaseURL(baseURL) {
  const url = new URL(String(baseURL || ""));
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`unsupported prover URL protocol ${url.protocol}`);
  }
  return url;
}

async function postJSON({ baseURL, path, body, bearerToken, timeoutMs, fetchImpl }) {
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
      body: JSON.stringify(body),
      signal: controller.signal
    });
    const text = await response.text();
    if (!response.ok) {
      throw new Error(`prover request failed with status ${response.status}: ${text}`);
    }
    try {
      return JSON.parse(text);
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

function normalizeProofShape(proof, kind, expectedVersion) {
  const label = `${kind} proof response.proof`;
  assertResponseObject(proof, label);
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
  assertResponseObject(response, label);
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
    preparedTransferProofVersion
  );
  const proof = normalized.proof;
  validatePreparedTransferProof(request.payload, proof);
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

export function createHttpProverAdapter({
  baseURL,
  bearerToken = "",
  timeoutMs = 120000,
  fetchImpl = fetch
} = {}) {
  if (!fetchImpl) {
    throw new Error("fetch implementation is required");
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("timeoutMs must be positive");
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
      try {
        const response = await postJSON({
          baseURL: normalizedBaseURL,
          path: "/v1/prover/transfer",
          body: normalizedRequest,
          bearerToken,
          timeoutMs,
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
          fetchImpl
        });
        return unwrapWithdrawProof(normalizedRequest, response);
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
  getJob,
  intervalMs = 1000,
  timeoutMs = 300000,
  now = () => Date.now(),
  sleepImpl = sleep
} = {}) {
  if (typeof submitTransferJob !== "function") {
    throw new Error("submitTransferJob(request) is required");
  }
  if (typeof submitWithdrawJob !== "function") {
    throw new Error("submitWithdrawJob(request) is required");
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

  return {
    async proveTransfer(request) {
      const normalizedRequest = {
        version: request?.version || transferProofRequestVersion,
        payload: request?.payload || request
      };
      if (normalizedRequest.version !== transferProofRequestVersion) {
        throw new Error(`unsupported transfer proof request version ${JSON.stringify(normalizedRequest.version)}`);
      }
      return waitForProof({
        request: normalizedRequest,
        submit: submitTransferJob,
        unwrap: unwrapTransferProof
      });
    },

    async proveWithdraw(request) {
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
    }
  };
}

export function createStaticProverAdapter({ transferProofHex = "", withdrawProofHex = "" } = {}) {
  return {
    async proveTransfer(request) {
      const payload = request?.payload || request;
      const proof = {
        version: preparedTransferProofVersion,
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
