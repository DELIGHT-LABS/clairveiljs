import { consumeAuditPreparation } from "./audit-prepared-state.js";
import {
  auditProofRequest,
  auditProofResponse,
  maxAuditWitnessBytes,
  maxAuditResponseBytes,
} from "./audit-prover-wire.js";

const messages = {
  request: "invalid full audit witness or preparation",
  snapshot: "audit snapshot changed or preparation expired",
  transport: "audit prover transport failed",
  response: "invalid audit prover response",
  verification: "local audit proof verification failed",
  aborted: "audit proving aborted",
  timeout: "audit proving timed out",
};
export class AuditProverErrorV2 extends Error {
  constructor(code) {
    super(messages[code]);
    this.name = "AuditProverErrorV2";
    this.code = code;
  }
}
function endpoint(baseUrl) {
  const url = new URL(baseUrl);
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/" ||
    !(
      url.protocol === "https:" ||
      (url.protocol === "http:" &&
        ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname))
    )
  )
    throw new Error(
      "prover requires an explicit HTTPS origin or HTTP loopback origin",
    );
  return url.origin + "/v2/prover/audit-field";
}
function check(signal) {
  if (signal.aborted) throw new Error("aborted");
}
function bounded(promise, signal) {
  return new Promise((resolve, reject) => {
    const clean = () => signal.removeEventListener("abort", abort);
    const abort = () => {
      clean();
      reject(new Error("aborted"));
    };
    signal.addEventListener("abort", abort, { once: true });
    Promise.resolve(promise).then(
      (value) => {
        clean();
        resolve(value);
      },
      (error) => {
        clean();
        reject(error);
      },
    );
    if (signal.aborted) abort();
  });
}
async function readResponse(response, signal, target) {
  if (
    response.status !== 200 ||
    response.redirected ||
    (response.url && response.url !== target) ||
    !/^application\/json(?:\s*;|$)/i.test(
      response.headers.get("content-type") ?? "",
    )
  ) {
    void response.body?.cancel().catch(() => {});
    throw new Error("invalid response metadata");
  }
  const size = response.headers.get("content-length");
  if (
    size !== null &&
    (!/^\d+$/.test(size) || Number(size) > maxAuditResponseBytes)
  ) {
    void response.body?.cancel().catch(() => {});
    throw new Error("response size bound");
  }
  if (!response.body?.getReader) throw new Error("streaming response required");
  const reader = response.body.getReader(),
    chunks = [];
  let total = 0,
    done = false;
  try {
    while (true) {
      const next = await bounded(reader.read(), signal);
      check(signal);
      if (next.done) {
        done = true;
        break;
      }
      if (
        !(next.value instanceof Uint8Array) ||
        (total += next.value.length) > maxAuditResponseBytes
      )
        throw new Error("response size bound");
      chunks.push(next.value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return bytes;
  } finally {
    if (!done) void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
/** Wallet-local coordinator. The explicitly selected prover receives the complete private witness. */
export function createAuditProverV2({
  baseUrl,
  verifier,
  fetch: fetchImpl = globalThis.fetch,
  timeoutMs = 120000,
  bearerToken,
} = {}) {
  const target = endpoint(baseUrl);
  if (typeof verifier?.verify !== "function")
    throw new Error("trusted local proof verifier required");
  const verify = verifier.verify.bind(verifier);
  if (typeof fetchImpl !== "function")
    throw new Error("fetch implementation required");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 3600000)
    throw new Error("finite prover timeout required (1..3600000 ms)");
  if (
    bearerToken !== undefined &&
    (typeof bearerToken !== "string" ||
      !/^[\x21-\x7e]+$/.test(bearerToken) ||
      bearerToken.length > 4096)
  )
    throw new Error("invalid bearer token");
  const headers = {
    "content-type": "application/json",
    accept: "application/json",
  };
  if (bearerToken) headers.authorization = `Bearer ${bearerToken}`;
  return Object.freeze({
    async prove({ prepared, witness, signal }) {
      const { kind, snapshot } = consumeAuditPreparation(prepared);
      const controller = new AbortController();
      let timedOut = false,
        phase = "request",
        owned,
        request,
        body;
      const abort = () => controller.abort();
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
      const deadline = setTimeout(() => {
        timedOut = true;
        abort();
      }, timeoutMs);
      try {
        if (
          !(witness instanceof Uint8Array) ||
          witness.length > maxAuditWitnessBytes
        )
          throw new Error("witness bound");
        owned = Uint8Array.from(witness);
        witness.fill(0);
        check(controller.signal);
        const publicInputs = prepared.publicInputs(),
          message = prepared.messageData();
        request = auditProofRequest(kind, snapshot, publicInputs, owned);
        owned.fill(0);
        body = JSON.stringify(request);
        request.witness = "";
        phase = "snapshot";
        await bounded(prepared.assertCurrent(), controller.signal);
        // Synchronous dispatch fence after the last asynchronous freshness check.
        check(controller.signal);
        prepared.assertMessageBinding(message);
        phase = "transport";
        const response = await bounded(
          fetchImpl(target, {
            method: "POST",
            headers: { ...headers },
            body,
            signal: controller.signal,
            redirect: "error",
            credentials: "omit",
            cache: "no-store",
            referrerPolicy: "no-referrer",
          }),
          controller.signal,
        );
        body = undefined;
        check(controller.signal);
        phase = "response";
        const proof = auditProofResponse(
          await readResponse(response, controller.signal, target),
          request,
        );
        phase = "snapshot";
        await bounded(prepared.assertCurrent(), controller.signal);
        check(controller.signal);
        phase = "verification";
        const verified = await bounded(
          verify({
            kind,
            circuitIdentity: snapshot.circuitIdentity,
            artifactHash: snapshot.artifactHash,
            publicInputs: Object.freeze(publicInputs.slice()),
            proof: proof.slice(),
            signal: controller.signal,
          }),
          controller.signal,
        );
        check(controller.signal);
        if (verified !== true) throw new Error("proof verification failed");
        phase = "snapshot";
        await bounded(prepared.assertCurrent(), controller.signal);
        check(controller.signal);
        prepared.assertMessageBinding(message);
        return { ...message, proof };
      } catch {
        throw new AuditProverErrorV2(
          timedOut ? "timeout" : controller.signal.aborted ? "aborted" : phase,
        );
      } finally {
        clearTimeout(deadline);
        signal?.removeEventListener("abort", abort);
        controller.abort();
        owned?.fill(0);
        if (witness instanceof Uint8Array) witness.fill(0);
        if (request) request.witness = "";
        body = undefined;
        prepared.clear();
      }
    },
  });
}
