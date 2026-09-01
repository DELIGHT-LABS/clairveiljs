import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import {
  buildDepositProofRequestV1,
  createAsyncJobProverAdapter,
  createHttpDepositProofProvider,
  createHttpDepositProofProviderV1,
  createHttpProverAdapter,
  createStaticProverAdapter,
  normalizeDepositProofProviderResultV1,
  validateDepositProofBytesV1,
  validateDepositProofResponseV1
} from "clairveiljs/prover";
import { ClairveilErrorCode, wrapProverError } from "clairveiljs/errors";
import { unpackPointHex } from "clairveiljs/crypto";
import {
  depositProverConformanceFixtureName,
  readClairveilProverConformanceFixture
} from "clairveiljs/conformance";
import {
  fixtureTestOptions,
  readFixture
} from "./helpers.js";

function jsonResponse(body, status = 200, contentType = "application/json", extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "cache-control": "no-store",
      ...(status === 405 ? { allow: "POST" } : {}),
      ...(contentType == null ? {} : { "content-type": contentType }),
      ...extraHeaders
    }
  });
}

function hangingJSONBodyResponse() {
  return {
    status: 200,
    ok: true,
    redirected: false,
    url: "",
    headers: new Headers({
      "cache-control": "no-store",
      "content-type": "application/json"
    }),
    body: {
      getReader() {
        return {
          read: () => new Promise(() => {}),
          releaseLock() {}
        };
      }
    }
  };
}

function canonicalEmptyGroth16ProofHex() {
  return [
    `40${"00".repeat(31)}`,
    `40${"00".repeat(63)}`,
    `40${"00".repeat(31)}`,
    "00000000",
    `40${"00".repeat(31)}`
  ].join("");
}

// gnark-compatible frame using the BN254 G1/G2 generators. Core v0.4.0's
// ValidateCanonicalProofBN254 accepts this decode -> encode round trip.
const canonicalGeneratorGroth16ProofHex =
  "8000000000000000000000000000000000000000000000000000000000000001" +
  "998e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c" +
  "21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed" +
  "8000000000000000000000000000000000000000000000000000000000000001" +
  "00000000" +
  "8000000000000000000000000000000000000000000000000000000000000001";

function depositRequestFromContract() {
  return readClairveilProverConformanceFixture(
    depositProverConformanceFixtureName
  ).canonical_positive_request;
}

test("static prover adapter validates and returns a transfer v5 proof", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const adapter = createStaticProverAdapter({
    transferProofHex: examples.transfer.response.proof.proof_hex
  });

  const response = await adapter.proveTransfer(examples.transfer.request);

  assert.equal(response.version, "v2");
  assert.deepEqual(response.proof, examples.transfer.response.proof);
});

test("prover adapters reject missing or falsy versions on explicit envelopes", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  let httpCalls = 0;
  let submissions = 0;
  const adapters = [
    createStaticProverAdapter({
      transferProofHex: examples.transfer.response.proof.proof_hex,
      withdrawProofHex: examples.withdraw.response.proof.proof_hex
    }),
    createHttpProverAdapter({
      baseURL: "http://127.0.0.1",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => {
        httpCalls += 1;
        throw new Error("invalid envelope must not reach the prover");
      }
    }),
    createAsyncJobProverAdapter({
      submitTransferJob: async () => {
        submissions += 1;
        throw new Error("invalid envelope must not reach the prover");
      },
      submitWithdrawJob: async () => {
        submissions += 1;
        throw new Error("invalid envelope must not reach the prover");
      },
      getJob: async () => ({ status: "pending" })
    })
  ];

  for (const adapter of adapters) {
    for (const invalidVersion of [undefined, "", null, 0]) {
      const transferEnvelope = invalidVersion === undefined
        ? { payload: examples.transfer.request.payload }
        : { version: invalidVersion, payload: examples.transfer.request.payload };
      const withdrawEnvelope = invalidVersion === undefined
        ? { payload: examples.withdraw.request.payload }
        : { version: invalidVersion, payload: examples.withdraw.request.payload };
      await assert.rejects(
        () => adapter.proveTransfer(transferEnvelope),
        /unsupported transfer proof request version/
      );
      await assert.rejects(
        () => adapter.proveWithdraw(withdrawEnvelope),
        /unsupported withdraw proof request version/
      );
    }
  }
  assert.equal(httpCalls, 0);
  assert.equal(submissions, 0);
});

test("transfer prover adapters validate proofs against authoritative chain time", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const expiry = examples.transfer.request.payload.expires_at_unix;
  const adapters = [
    createStaticProverAdapter({
      transferProofHex: examples.transfer.response.proof.proof_hex
    }),
    createHttpProverAdapter({
      baseURL: "http://127.0.0.1",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => jsonResponse(examples.transfer.response)
    }),
    createAsyncJobProverAdapter({
      submitTransferJob: async () => ({ job_id: "authoritative-time" }),
      getJob: async () => ({
        status: "completed",
        response: examples.transfer.response
      }),
      intervalMs: 0
    })
  ];

  for (const adapter of adapters) {
    const response = await adapter.proveTransfer(examples.transfer.request, {
      nowUnix: expiry - 1
    });
    assert.deepEqual(response.proof, examples.transfer.response.proof);
    await assert.rejects(
      () => adapter.proveTransfer(examples.transfer.request, { nowUnix: expiry }),
      /transfer v5 payload expired/
    );
  }
});

test("withdraw prover adapters validate proofs against authoritative chain time", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const expiry = examples.withdraw.request.payload.expires_at_unix;
  const adapters = [
    createStaticProverAdapter({
      withdrawProofHex: examples.withdraw.response.proof.proof_hex
    }),
    createHttpProverAdapter({
      baseURL: "http://127.0.0.1",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => jsonResponse(examples.withdraw.response)
    }),
    createAsyncJobProverAdapter({
      submitWithdrawJob: async () => ({ job_id: "withdraw-authoritative-time" }),
      getJob: async () => ({
        status: "completed",
        response: examples.withdraw.response
      }),
      intervalMs: 0
    })
  ];

  for (const adapter of adapters) {
    const response = await adapter.proveWithdraw(examples.withdraw.request, {
      nowUnix: expiry - 1
    });
    assert.deepEqual(response.proof, examples.withdraw.response.proof);
    await assert.rejects(
      () => adapter.proveWithdraw(examples.withdraw.request, { nowUnix: expiry }),
      /withdraw prover payload expired/
    );
  }
});

test("transfer and withdraw requests are validated and reduced to canonical fields before handoff", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const marker = "private-marker-must-not-cross-prover-boundary";
  const transferRequest = structuredClone(examples.transfer.request);
  transferRequest.private_marker = marker;
  transferRequest.payload.private_marker = marker;
  transferRequest.payload.inputs[0].private_marker = marker;
  const withdrawRequest = structuredClone(examples.withdraw.request);
  withdrawRequest.private_marker = marker;
  withdrawRequest.payload.private_marker = marker;

  const httpCalls = [];
  const httpAdapter = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (url, init) => {
      httpCalls.push(JSON.parse(init.body));
      return url.pathname.endsWith("/transfer")
        ? jsonResponse(examples.transfer.response)
        : jsonResponse(examples.withdraw.response);
    }
  });
  await httpAdapter.proveTransfer(transferRequest, {
    nowUnix: transferRequest.payload.expires_at_unix - 1
  });
  await httpAdapter.proveWithdraw(withdrawRequest, {
    nowUnix: withdrawRequest.payload.expires_at_unix - 1
  });
  assert.equal(JSON.stringify(httpCalls).includes(marker), false);

  const submitted = [];
  const asyncAdapter = createAsyncJobProverAdapter({
    submitTransferJob: async request => {
      submitted.push(request);
      return { job_id: "canonical-transfer" };
    },
    submitWithdrawJob: async request => {
      submitted.push(request);
      return { job_id: "canonical-withdraw" };
    },
    getJob: async jobId => ({
      status: "completed",
      response: jobId === "canonical-transfer"
        ? examples.transfer.response
        : examples.withdraw.response
    }),
    intervalMs: 0
  });
  await asyncAdapter.proveTransfer(transferRequest, {
    nowUnix: transferRequest.payload.expires_at_unix - 1
  });
  await asyncAdapter.proveWithdraw(withdrawRequest, {
    nowUnix: withdrawRequest.payload.expires_at_unix - 1
  });
  assert.equal(JSON.stringify(submitted).includes(marker), false);

  const httpCallsBeforeExpiryChecks = httpCalls.length;
  const submissionsBeforeExpiryChecks = submitted.length;
  for (const [adapter, requestsBefore] of [
    [httpAdapter, httpCallsBeforeExpiryChecks],
    [asyncAdapter, submissionsBeforeExpiryChecks]
  ]) {
    await assert.rejects(
      () => adapter.proveTransfer(transferRequest, {
        nowUnix: transferRequest.payload.expires_at_unix
      }),
      /transfer v5 payload expired/
    );
    await assert.rejects(
      () => adapter.proveWithdraw(withdrawRequest, {
        nowUnix: withdrawRequest.payload.expires_at_unix
      }),
      /withdraw prover payload expired/
    );
    assert.equal(
      adapter === httpAdapter ? httpCalls.length : submitted.length,
      requestsBefore
    );
  }
});

test("transfer and withdraw proofs require a fully canonical BN254 Groth16 frame", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const malformedInfinity = Uint8Array.from(Buffer.from(canonicalEmptyGroth16ProofHex(), "hex"));
  malformedInfinity[1] = 1;
  const proofHex = Buffer.from(malformedInfinity).toString("hex");
  const adapter = createStaticProverAdapter({
    transferProofHex: proofHex,
    withdrawProofHex: proofHex
  });

  await assert.rejects(
    () => adapter.proveTransfer(examples.transfer.request, { nowUnix: 0 }),
    /non-canonical infinity encoding/
  );
  await assert.rejects(
    () => adapter.proveWithdraw(examples.withdraw.request, { nowUnix: 0 }),
    /non-canonical infinity encoding/
  );
});

test("common transfer and withdraw routes require exact HTTP 200 success", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  for (const kind of ["transfer", "withdraw"]) {
    const adapter = createHttpProverAdapter({
      baseURL: "http://127.0.0.1",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => jsonResponse(examples[kind].response, 201)
    });
    await assert.rejects(
      () => adapter[kind === "transfer" ? "proveTransfer" : "proveWithdraw"](
        examples[kind].request,
        { nowUnix: examples[kind].request.payload.expires_at_unix - 1 }
      ),
      error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
        error?.status === 201 &&
        /status 201/.test(error.message)
    );
  }
});

test("common transfer and withdraw routes require exact JSON Content-Type on success and error", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const errorBody = {
    version: "v1",
    code: "proof_failed",
    message: "must not be parsed without the declared JSON media type",
    retryable: false
  };

  for (const kind of ["transfer", "withdraw"]) {
    const prove = adapter => adapter[kind === "transfer" ? "proveTransfer" : "proveWithdraw"](
      examples[kind].request,
      { nowUnix: examples[kind].request.payload.expires_at_unix - 1 }
    );
    for (const [status, body] of [
      [200, examples[kind].response],
      [500, errorBody]
    ]) {
      for (const contentType of [
        null,
        "text/plain",
        "application/json; charset=utf-8",
        "application/json; private=unknown"
      ]) {
        const adapter = createHttpProverAdapter({
          baseURL: "http://127.0.0.1",
          proverTransportRedirectsDisabled: true,
          fetchImpl: async () => jsonResponse(body, status, contentType)
        });
        await assert.rejects(
          () => prove(adapter),
          error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
            /Content-Type: application\/json/.test(error.message)
        );
      }
    }
  }
});

test("common prover routes require no-store responses and exact 405 Allow", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const proveTransfer = adapter => adapter.proveTransfer(examples.transfer.request, {
    nowUnix: examples.transfer.request.payload.expires_at_unix - 1
  });
  const proofFailed = {
    version: "v1",
    code: "proof_failed",
    message: "must not be trusted before response headers are validated",
    retryable: false
  };

  for (const [status, body] of [
    [200, examples.transfer.response],
    [500, proofFailed]
  ]) {
    for (const fetchImpl of [
      async () => new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" }
      }),
      async () => jsonResponse(body, status, "application/json", {
        "cache-control": "public, max-age=3600"
      })
    ]) {
      const adapter = createHttpProverAdapter({
        baseURL: "http://127.0.0.1",
        proverTransportRedirectsDisabled: true,
        fetchImpl
      });
      await assert.rejects(
        () => proveTransfer(adapter),
        error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
          error?.proverCode === undefined &&
          /Cache-Control: no-store/.test(error.message)
      );
    }
  }

  const methodNotAllowed = {
    version: "v1",
    code: "method_not_allowed",
    message: "POST is required",
    retryable: false
  };
  for (const fetchImpl of [
    async () => new Response(JSON.stringify(methodNotAllowed), {
      status: 405,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store"
      }
    }),
    async () => jsonResponse(methodNotAllowed, 405, "application/json", { allow: "GET" })
  ]) {
    const adapter = createHttpProverAdapter({
      baseURL: "http://127.0.0.1",
      proverTransportRedirectsDisabled: true,
      fetchImpl
    });
    await assert.rejects(
      () => proveTransfer(adapter),
      error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
        error?.proverCode === undefined &&
        /Allow: POST/.test(error.message)
    );
  }

  const canonical405 = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async () => jsonResponse(methodNotAllowed, 405)
  });
  await assert.rejects(
    () => proveTransfer(canonical405),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
      error?.status === 405 &&
      error?.proverCode === "method_not_allowed"
  );
});

test("HTTP prover adapter follows the Go route and version contract", fixtureTestOptions, async () => {
  const contract = readFixture("privacy_prover_http_api_contract.json");
  const examples = readFixture("privacy_prover_example_bundle.json");
  const calls = [];
  const adapter = createHttpProverAdapter({
    baseURL: "https://prover.example/base/",
    bearerToken: " test-token ",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (url, init) => {
      const body = JSON.parse(init.body);
      calls.push({
        url: String(url),
        method: init.method,
        contentType: init.headers.get("Content-Type"),
        authorization: init.headers.get("Authorization"),
        body
      });
      if (url.pathname === `/base${contract.transfer_route.path}`) {
        return jsonResponse(examples.transfer.response);
      }
      if (url.pathname === `/base${contract.withdraw_route.path}`) {
        return jsonResponse(examples.withdraw.response);
      }
      return jsonResponse({ version: "v1", code: "not_found" }, 404);
    }
  });

  const transfer = await adapter.proveTransfer(examples.transfer.request);
  const withdraw = await adapter.proveWithdraw(examples.withdraw.request);

  assert.equal(calls[0].url, `https://prover.example/base${contract.transfer_route.path}`);
  assert.equal(calls[0].method, contract.transfer_route.method);
  assert.equal(calls[0].contentType, contract.content_type);
  assert.equal(calls[0].authorization, "Bearer test-token");
  assert.equal(calls[0].body.version, contract.transfer_route.request_version);
  assert.equal(transfer.version, contract.transfer_route.response_version);

  assert.equal(calls[1].url, `https://prover.example/base${contract.withdraw_route.path}`);
  assert.equal(calls[1].method, contract.withdraw_route.method);
  assert.equal(calls[1].body.version, contract.withdraw_route.request_version);
  assert.equal(withdraw.version, contract.withdraw_route.response_version);
});

test("HTTP prover adapter preserves a base URL path prefix with or without a trailing slash", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  for (const baseURL of ["https://prover.example/tenant-a", "https://prover.example/tenant-a/"]) {
    const paths = [];
    const adapter = createHttpProverAdapter({
      baseURL,
      proverTransportRedirectsDisabled: true,
      fetchImpl: async url => {
        paths.push(url.pathname);
        return url.pathname.endsWith("/transfer")
          ? jsonResponse(examples.transfer.response)
          : jsonResponse(examples.withdraw.response);
      }
    });
    await adapter.proveTransfer(examples.transfer.request);
    await adapter.proveWithdraw(examples.withdraw.request);
    assert.deepEqual(paths, [
      "/tenant-a/v1/prover/transfer",
      "/tenant-a/v1/prover/withdraw"
    ]);
  }
});

test("HTTP prover adapter rejects proof payload hash mismatch", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const adapter = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async url => {
      if (url.pathname.endsWith("/withdraw")) {
        return jsonResponse({
          ...examples.withdraw.response,
          proof: {
            ...examples.withdraw.response.proof,
            payload_hash: "00".repeat(32)
          }
        });
      }
      return jsonResponse({
        ...examples.transfer.response,
        proof: {
          ...examples.transfer.response.proof,
          payload_hash: "00".repeat(32)
        }
      });
    }
  });

  await assert.rejects(
    () => adapter.proveTransfer(examples.transfer.request),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED && /transfer v5 proof payload hash mismatch/.test(error.message)
  );
  await assert.rejects(
    () => adapter.proveWithdraw(examples.withdraw.request),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED && /withdraw proof payload hash mismatch/.test(error.message)
  );
});

test("HTTP prover adapter rejects malformed proof response shapes", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");

  for (const [body, pattern] of [
    [{}, /transfer proof response\.version must be v2/],
    [{ version: "v2" }, /transfer proof response\.proof must be a JSON object/],
    [
      {
        ...examples.transfer.response,
        proof: {
          ...examples.transfer.response.proof,
          payload_hash: "aa"
        }
      },
      /payload_hash must be a 32-byte hex string/
    ],
    [
      {
        ...examples.transfer.response,
        proof: {
          ...examples.transfer.response.proof,
          proof_hex: "not-hex"
        }
      },
      /proof_hex must be valid hex/
    ]
  ]) {
    const adapter = createHttpProverAdapter({
      baseURL: "http://127.0.0.1",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => jsonResponse(body)
    });
    await assert.rejects(
      () => adapter.proveTransfer(examples.transfer.request),
      error => error?.code === ClairveilErrorCode.PROVER_REJECTED && pattern.test(error.message)
    );
  }
});

test("HTTP prover adapter aborts on timeout", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  let sawAbort = false;
  const adapter = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    timeoutMs: 5,
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => {
        sawAbort = true;
        reject(new DOMException("aborted", "AbortError"));
      });
    })
  });

  await assert.rejects(
    () => adapter.proveTransfer(examples.transfer.request),
    error => error?.code === ClairveilErrorCode.PROVER_TIMEOUT && /timed out/.test(error.message)
  );
  assert.equal(sawAbort, true);
});

test("HTTP prover adapter supports caller cancellation separately from timeout", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const controller = new AbortController();
  let sawAbort = false;
  const adapter = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    timeoutMs: 1000,
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => {
        sawAbort = true;
        reject(new DOMException("aborted", "AbortError"));
      });
    })
  });

  const pending = adapter.proveTransfer(examples.transfer.request, { signal: controller.signal });
  controller.abort();
  await assert.rejects(
    () => pending,
    error => error?.code === ClairveilErrorCode.PROVER_CANCELLED && /cancelled/.test(error.message)
  );
  assert.equal(sawAbort, true);
});

test("HTTP prover adapter bounds fetch implementations that ignore abort", {
  ...fixtureTestOptions,
  timeout: 1000
}, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  let timeoutSignal = null;
  let rejectLateFetch;
  const timedOut = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    timeoutMs: 5,
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (_url, init) => {
      timeoutSignal = init.signal;
      return new Promise((_resolve, reject) => {
        rejectLateFetch = reject;
      });
    }
  });

  await assert.rejects(
    () => timedOut.proveTransfer(examples.transfer.request),
    error => error?.code === ClairveilErrorCode.PROVER_TIMEOUT && /timed out/.test(error.message)
  );
  assert.equal(timeoutSignal.aborted, true);
  rejectLateFetch(new Error("late ignored fetch failure"));
  await new Promise(resolve => setImmediate(resolve));

  const controller = new AbortController();
  let cancellationSignal = null;
  const cancelled = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    timeoutMs: 1000,
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (_url, init) => {
      cancellationSignal = init.signal;
      return new Promise(() => {});
    }
  });
  const pending = cancelled.proveTransfer(examples.transfer.request, {
    signal: controller.signal
  });
  controller.abort();
  await assert.rejects(
    () => pending,
    error => error?.code === ClairveilErrorCode.PROVER_CANCELLED && /cancelled/.test(error.message)
  );
  assert.equal(cancellationSignal.aborted, true);
});

test("canonical deposit provider bounds body reads that ignore abort", {
  timeout: 1000
}, async () => {
  const request = depositRequestFromContract();
  let timeoutSignal = null;
  const timedOut = createHttpDepositProofProviderV1({
    url: "http://127.0.0.1:8080/deposit-proof",
    timeoutMs: 5,
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (_url, init) => {
      timeoutSignal = init.signal;
      return hangingJSONBodyResponse();
    }
  });
  await assert.rejects(
    () => timedOut(request),
    error => error?.code === ClairveilErrorCode.PROVER_TIMEOUT && /timed out/.test(error.message)
  );
  assert.equal(timeoutSignal.aborted, true);

  const controller = new AbortController();
  let cancellationSignal = null;
  const cancelled = createHttpDepositProofProviderV1({
    url: "http://127.0.0.1:8080/deposit-proof",
    timeoutMs: 1000,
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (_url, init) => {
      cancellationSignal = init.signal;
      return hangingJSONBodyResponse();
    }
  });
  const pending = cancelled(request, { signal: controller.signal });
  controller.abort();
  await assert.rejects(
    () => pending,
    error => error?.code === ClairveilErrorCode.PROVER_CANCELLED && /cancelled/.test(error.message)
  );
  assert.equal(cancellationSignal.aborted, true);
});

test("HTTP prover adapter clears timeout and caller-abort hooks after success", {
  ...fixtureTestOptions,
  timeout: 1000
}, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const controller = new AbortController();
  let internalSignal = null;
  const adapter = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    timeoutMs: 20,
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (_url, init) => {
      internalSignal = init.signal;
      return jsonResponse(examples.transfer.response);
    }
  });

  await adapter.proveTransfer(examples.transfer.request, { signal: controller.signal });
  controller.abort();
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(internalSignal.aborted, false);
});

test("deposit request builder emits the canonical v0.4 memo-free payload", () => {
  const expected = depositRequestFromContract();
  const spend = unpackPointHex(expected.payload.receiver_spend_pubkey_hex);
  const view = unpackPointHex(expected.payload.receiver_view_pubkey_hex);
  const request = buildDepositProofRequestV1({
    note: {
      receiverSpendPubKeyX: spend.x,
      receiverSpendPubKeyY: spend.y,
      receiverViewPubKeyX: view.x,
      receiverViewPubKeyY: view.y,
      amount: BigInt(expected.payload.amount),
      assetID: BigInt(`0x${expected.payload.asset_id_hex}`),
      randomness: BigInt(`0x${expected.payload.randomness_hex}`),
      memo: "must stay local"
    },
    note_commitment_hex: expected.payload.note_commitment_hex,
    note_json: "must never be serialized"
  });

  assert.deepEqual(request, expected);
  assert.equal(JSON.stringify(request).includes("memo"), false);
  assert.equal(JSON.stringify(request).includes("note_json"), false);
  assert.throws(
    () => buildDepositProofRequestV1({ ...expected, unexpected: true }),
    /unknown JSON field/
  );
  assert.throws(
    () => buildDepositProofRequestV1({
      note_json: "{}",
      note_commitment_hex: expected.payload.note_commitment_hex
    }),
    /NoteV1 is required/
  );
  assert.throws(
    () => buildDepositProofRequestV1({
      ...expected,
      signal: new AbortController().signal
    }),
    /unknown JSON field/
  );
});

test("HTTP prover adapter supports the canonical v0.4 deposit route", async () => {
  const request = depositRequestFromContract();
  const proofHex = canonicalEmptyGroth16ProofHex();
  const calls = [];
  const adapter = createHttpProverAdapter({
    baseURL: "https://deposit.example/base",
    bearerToken: " deposit-token ",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (url, init) => {
      calls.push({
        url: String(url),
        method: init.method,
        redirect: init.redirect,
        cache: init.cache,
        accept: init.headers.get("Accept"),
        contentType: init.headers.get("Content-Type"),
        authorization: init.headers.get("Authorization"),
        body: JSON.parse(init.body)
      });
      return jsonResponse({
        version: "v1",
        proof: {
          version: "v1",
          note_commitment_hex: request.payload.note_commitment_hex,
          proof_hex: proofHex
        }
      });
    }
  });

  const result = await adapter.proveDeposit(request);

  assert.deepEqual(calls, [{
    url: "https://deposit.example/base/v1/prover/deposit",
    method: "POST",
    redirect: "error",
    cache: "no-store",
    accept: "application/json",
    contentType: "application/json",
    authorization: "Bearer deposit-token",
    body: request
  }]);
  assert.deepEqual(result, {
    version: "v1",
    proof: {
      version: "v1",
      note_commitment_hex: request.payload.note_commitment_hex,
      proof_hex: proofHex
    }
  });
});

test("async prover job adapter supports a deposit-only canonical v0.4 prover", async () => {
  const input = structuredClone(depositRequestFromContract());
  const signal = new AbortController().signal;
  const proofHex = canonicalEmptyGroth16ProofHex();
  const response = {
    version: "v1",
    proof: {
      version: "v1",
      note_commitment_hex: input.payload.note_commitment_hex,
      proof_hex: proofHex
    }
  };
  let submitted;
  let submitOptions;
  let getOptions;
  const adapter = createAsyncJobProverAdapter({
    submitDepositJob: async (request, options) => {
      submitted = request;
      submitOptions = options;
      return { job_id: "deposit-job-1" };
    },
    getJob: async (jobId, options) => {
      assert.equal(jobId, "deposit-job-1");
      getOptions = options;
      return { status: "completed", response };
    },
    intervalMs: 0
  });

  const result = await adapter.proveDeposit(input, { signal });

  assert.notEqual(submitted, input);
  assert.deepEqual(submitted, input);
  assert.equal(Object.isFrozen(submitted), true);
  assert.equal(Object.isFrozen(submitted.payload), true);
  assert.deepEqual(submitOptions, { signal });
  assert.deepEqual(getOptions, { signal });
  assert.deepEqual(result, response);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.proof), true);
  assert.equal(typeof adapter.proveTransfer, "undefined");
  assert.equal(typeof adapter.proveWithdraw, "undefined");
  assert.equal(typeof adapter.proveBatchTransfer, "undefined");
});

test("async deposit jobs validate requests and completed proof bindings", async () => {
  const request = depositRequestFromContract();
  const proofHex = canonicalEmptyGroth16ProofHex();
  let submissions = 0;
  let response = {
    version: "v1",
    proof: {
      version: "v1",
      note_commitment_hex: request.payload.note_commitment_hex,
      proof_hex: proofHex
    }
  };
  const adapter = createAsyncJobProverAdapter({
    submitDepositJob: async () => {
      submissions += 1;
      return { job_id: "deposit-validation" };
    },
    getJob: async () => ({ status: "completed", result: response }),
    intervalMs: 0
  });

  await assert.rejects(
    () => adapter.proveDeposit({ ...request, version: "v2" }),
    /deposit proof request\.version must be v1/
  );
  assert.equal(submissions, 0);

  for (const [mutate, pattern] of [
    [value => ({ ...value, version: "v2" }), /deposit proof response\.version must be v1/],
    [value => ({
      ...value,
      proof: { ...value.proof, note_commitment_hex: `${"00".repeat(31)}01` }
    }), /note commitment mismatch/],
    [value => ({
      ...value,
      proof: { ...value.proof, proof_hex: value.proof.proof_hex.slice(0, -2) }
    }), /exactly 328 lowercase hex characters/]
  ]) {
    response = mutate({
      version: "v1",
      proof: {
        version: "v1",
        note_commitment_hex: request.payload.note_commitment_hex,
        proof_hex: proofHex
      }
    });
    await assert.rejects(() => adapter.proveDeposit(request), pattern);
  }
  assert.equal(submissions, 3);
});

test("async deposit jobs share cancellation, timeout, and failed-job semantics", async () => {
  const request = depositRequestFromContract();
  const controller = new AbortController();
  const cancelled = createAsyncJobProverAdapter({
    submitDepositJob: async () => ({ job_id: "deposit-cancelled" }),
    getJob: async () => new Promise(() => {}),
    intervalMs: 0
  });
  const pending = cancelled.proveDeposit(request, { signal: controller.signal });
  controller.abort();
  await assert.rejects(
    () => pending,
    error => error?.code === ClairveilErrorCode.PROVER_CANCELLED
  );

  let clock = 0;
  const timedOut = createAsyncJobProverAdapter({
    submitDepositJob: async () => ({ job_id: "deposit-timeout" }),
    getJob: async () => ({ status: "pending" }),
    timeoutMs: 1,
    intervalMs: 0,
    now: () => clock++,
    sleepImpl: async () => {}
  });
  await assert.rejects(
    () => timedOut.proveDeposit(request),
    error => error?.code === ClairveilErrorCode.PROVER_TIMEOUT && /timed out/.test(error.message)
  );

  const failed = createAsyncJobProverAdapter({
    submitDepositJob: async () => ({ job_id: "deposit-failed" }),
    getJob: async () => ({ status: "failed", error: "private solver details" }),
    intervalMs: 0
  });
  await assert.rejects(
    () => failed.proveDeposit(request),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
      /prover job deposit-failed failed/.test(error.message) &&
      !error.message.includes("private solver")
  );
});

test("async deposit job timeout bounds hanging submit, poll, and sleep phases", {
  timeout: 1000
}, async () => {
  const request = depositRequestFromContract();
  let sleepSignal = null;
  const cases = [
    ["submit", createAsyncJobProverAdapter({
      submitDepositJob: async () => new Promise(() => {}),
      getJob: async () => ({ status: "pending" }),
      timeoutMs: 5
    })],
    ["poll", createAsyncJobProverAdapter({
      submitDepositJob: async () => ({ job_id: "hung-poll" }),
      getJob: async () => new Promise(() => {}),
      timeoutMs: 5
    })],
    ["sleep", createAsyncJobProverAdapter({
      submitDepositJob: async () => ({ job_id: "hung-sleep" }),
      getJob: async () => ({ status: "pending" }),
      sleepImpl: async (_ms, options) => {
        sleepSignal = options.signal;
        return new Promise(() => {});
      },
      intervalMs: 1000,
      timeoutMs: 5
    })]
  ];

  for (const [phase, adapter] of cases) {
    await assert.rejects(
      () => adapter.proveDeposit(request),
      error => error?.code === ClairveilErrorCode.PROVER_TIMEOUT &&
        /timed out/.test(error.message),
      `${phase} must observe the end-to-end timeout`
    );
  }
  assert.equal(sleepSignal.aborted, true);
});

test("async job deadline is checked after submit before polling", async () => {
  const request = depositRequestFromContract();
  let clock = 0;
  let pollCalls = 0;
  const adapter = createAsyncJobProverAdapter({
    submitDepositJob: async () => {
      clock = 5;
      return { job_id: "expired-after-submit" };
    },
    getJob: async () => {
      pollCalls += 1;
      return { status: "pending" };
    },
    timeoutMs: 5,
    now: () => clock
  });

  await assert.rejects(
    () => adapter.proveDeposit(request),
    error => error?.code === ClairveilErrorCode.PROVER_TIMEOUT &&
      /expired-after-submit/.test(error.message)
  );
  assert.equal(pollCalls, 0);
});

test("async job caller cancellation wins while submit is uncooperative", {
  timeout: 1000
}, async () => {
  const request = depositRequestFromContract();
  const controller = new AbortController();
  let submittedSignal = null;
  const adapter = createAsyncJobProverAdapter({
    submitDepositJob: async (_request, options) => {
      submittedSignal = options.signal;
      return new Promise(() => {});
    },
    getJob: async () => ({ status: "pending" }),
    timeoutMs: 1000
  });

  const pending = adapter.proveDeposit(request, { signal: controller.signal });
  controller.abort();
  await assert.rejects(
    () => pending,
    error => error?.code === ClairveilErrorCode.PROVER_CANCELLED
  );
  assert.equal(submittedSignal, controller.signal);
});

test("async job success clears its deadline timer and wait signal", {
  timeout: 1000
}, async () => {
  const request = depositRequestFromContract();
  const proofHex = canonicalEmptyGroth16ProofHex();
  let polls = 0;
  let waitSignal = null;
  const adapter = createAsyncJobProverAdapter({
    submitDepositJob: async () => ({ job_id: "quick-success" }),
    getJob: async () => {
      polls += 1;
      if (polls === 1) return { status: "pending" };
      return {
        status: "completed",
        response: {
          version: "v1",
          proof: {
            version: "v1",
            note_commitment_hex: request.payload.note_commitment_hex,
            proof_hex: proofHex
          }
        }
      };
    },
    sleepImpl: async (_ms, options) => {
      waitSignal = options.signal;
    },
    intervalMs: 0,
    timeoutMs: 250
  });

  await adapter.proveDeposit(request);
  await new Promise(resolve => setTimeout(resolve, 300));
  assert.equal(waitSignal.aborted, false);
});

test("async job timing configuration fails closed", () => {
  const base = {
    submitDepositJob: async () => ({ job_id: "invalid-config" }),
    getJob: async () => ({ status: "pending" })
  };
  for (const options of [
    { intervalMs: -1 },
    { intervalMs: Number.NaN },
    { timeoutMs: 0 },
    { timeoutMs: Number.POSITIVE_INFINITY },
    { timeoutMs: 2_147_483_648 },
    { now: null },
    { sleepImpl: null }
  ]) {
    assert.throws(() => createAsyncJobProverAdapter({ ...base, ...options }));
  }
});

test("HTTP prover timing configuration enforces the native timer bound", () => {
  const maximumTimeoutMs = 2_147_483_647;
  const factories = [
    timeoutMs => createHttpProverAdapter({
      baseURL: "https://prover.example",
      timeoutMs
    }),
    timeoutMs => createHttpDepositProofProvider({
      url: "https://prover.example/v1/deposit-proof",
      timeoutMs
    }),
    timeoutMs => createHttpDepositProofProviderV1({
      url: "https://prover.example/v1/prover/deposit",
      timeoutMs
    })
  ];

  for (const createProvider of factories) {
    assert.doesNotThrow(() => createProvider(maximumTimeoutMs));
    assert.throws(
      () => createProvider(maximumTimeoutMs + 1),
      /must be a positive finite number no greater than 2147483647/
    );
  }
});

test("generic deposit prover enforces the exact endpoint response policy", async () => {
  const request = depositRequestFromContract();
  const proofHex = canonicalEmptyGroth16ProofHex();
  const responseBody = {
    version: "v1",
    proof: {
      version: "v1",
      note_commitment_hex: request.payload.note_commitment_hex,
      proof_hex: proofHex
    }
  };
  const missingContentType = createHttpProverAdapter({
    baseURL: "https://deposit.example/base",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async () => new Response(JSON.stringify(responseBody), { status: 200 })
  });
  await assert.rejects(
    () => missingContentType.proveDeposit(request),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED && /Content-Type/.test(error.message)
  );

  const redirected = createHttpProverAdapter({
    baseURL: "https://deposit.example/base",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async () => {
      const response = jsonResponse(responseBody);
      Object.defineProperties(response, {
        redirected: { value: true },
        url: { value: "https://other.example/v1/prover/deposit" }
      });
      return response;
    }
  });
  await assert.rejects(
    () => redirected.proveDeposit(request),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED && /must not redirect/.test(error.message)
  );

  for (const status of [201, 202, 206]) {
    const adapter = createHttpProverAdapter({
      baseURL: "https://deposit.example/base",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => jsonResponse(responseBody, status)
    });
    const pinned = createHttpDepositProofProviderV1({
      url: "https://deposit.example/v1/prover/deposit",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => jsonResponse(responseBody, status)
    });
    for (const prove of [
      () => adapter.proveDeposit(request),
      () => pinned(request)
    ]) {
      await assert.rejects(
        prove,
        error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
          error?.status === status &&
          new RegExp(`status ${status}`).test(error.message)
      );
    }
  }
});

test("canonical prover routes reject unattested custom fetch before sending private inputs", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const depositRequest = depositRequestFromContract();
  let fetchCalls = 0;
  const unsafeFetch = async () => {
    fetchCalls += 1;
    throw new Error("unattested fetch must not be called");
  };
  const routes = [
    adapter => adapter.proveDeposit(depositRequest),
    adapter => adapter.proveTransfer(examples.transfer.request, {
      nowUnix: examples.transfer.request.payload.expires_at_unix - 1
    }),
    adapter => adapter.proveWithdraw(examples.withdraw.request, {
      nowUnix: examples.withdraw.request.payload.expires_at_unix - 1
    })
  ];

  for (const invoke of routes) {
    await assert.rejects(
      async () => invoke(createHttpProverAdapter({
        baseURL: "https://prover.example",
        fetchImpl: unsafeFetch
      })),
      /custom prover fetch implementation must set proverTransportRedirectsDisabled to true/
    );
  }
  await assert.rejects(
    async () => createHttpDepositProofProviderV1({
      url: "https://prover.example/v1/prover/deposit",
      fetchImpl: unsafeFetch
    })(depositRequest),
    /custom prover fetch implementation must set proverTransportRedirectsDisabled to true/
  );
  assert.equal(fetchCalls, 0);
});

test("canonical prover routes reject redirected or cross-endpoint custom-fetch responses", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const depositRequest = depositRequestFromContract();
  const depositResponse = {
    version: "v1",
    proof: {
      version: "v1",
      note_commitment_hex: depositRequest.payload.note_commitment_hex,
      proof_hex: canonicalEmptyGroth16ProofHex()
    }
  };
  const routes = [
    {
      response: depositResponse,
      invoke: adapter => adapter.proveDeposit(depositRequest)
    },
    {
      response: examples.transfer.response,
      invoke: adapter => adapter.proveTransfer(examples.transfer.request, {
        nowUnix: examples.transfer.request.payload.expires_at_unix - 1
      })
    },
    {
      response: examples.withdraw.response,
      invoke: adapter => adapter.proveWithdraw(examples.withdraw.request, {
        nowUnix: examples.withdraw.request.payload.expires_at_unix - 1
      })
    }
  ];

  for (const route of routes) {
    for (const responseIdentity of [
      { redirected: true, url: "https://other.example/proof" },
      { redirected: false, url: "https://other.example/proof" }
    ]) {
      const adapter = createHttpProverAdapter({
        baseURL: "https://prover.example",
        proverTransportRedirectsDisabled: true,
        fetchImpl: async () => {
          const response = jsonResponse(route.response);
          Object.defineProperties(response, {
            redirected: { value: responseIdentity.redirected },
            url: { value: responseIdentity.url }
          });
          return response;
        }
      });
      await assert.rejects(
        () => route.invoke(adapter),
        error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
          /must not redirect|configured endpoint/.test(error.message)
      );
    }
  }
});

test("native prover fetch refuses redirects without disclosing route payloads", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const depositRequest = depositRequestFromContract();
  let originHits = 0;
  let targetHits = 0;
  const target = createServer((request, response) => {
    targetHits += 1;
    request.resume();
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  await new Promise((resolve, reject) => {
    target.once("error", reject);
    target.listen(0, "127.0.0.1", resolve);
  });
  const targetURL = `http://127.0.0.1:${target.address().port}`;
  const origin = createServer((request, response) => {
    originHits += 1;
    request.resume();
    response.writeHead(307, { location: `${targetURL}${request.url}` });
    response.end();
  });
  await new Promise((resolve, reject) => {
    origin.once("error", reject);
    origin.listen(0, "127.0.0.1", resolve);
  });

  try {
    const adapter = createHttpProverAdapter({
      baseURL: `http://127.0.0.1:${origin.address().port}`
    });
    for (const invoke of [
      () => adapter.proveDeposit(depositRequest),
      () => adapter.proveTransfer(examples.transfer.request, {
        nowUnix: examples.transfer.request.payload.expires_at_unix - 1
      }),
      () => adapter.proveWithdraw(examples.withdraw.request, {
        nowUnix: examples.withdraw.request.payload.expires_at_unix - 1
      })
    ]) {
      await assert.rejects(
        invoke,
        error => error?.code === ClairveilErrorCode.PROVER_REJECTED
      );
    }
    assert.equal(originHits, 3);
    assert.equal(targetHits, 0);
  } finally {
    await Promise.all([
      new Promise(resolve => origin.close(resolve)),
      new Promise(resolve => target.close(resolve))
    ]);
  }
});

test("canonical deposit adapters enforce exact response Content-Type and no-store", async () => {
  const request = depositRequestFromContract();
  const responseBody = {
    version: "v1",
    proof: {
      version: "v1",
      note_commitment_hex: request.payload.note_commitment_hex,
      proof_hex: canonicalEmptyGroth16ProofHex()
    }
  };

  for (const fetchImpl of [
    async () => new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: { "content-type": "application/json" }
    }),
    async () => jsonResponse(responseBody, 200, "application/json", {
      "cache-control": "public"
    })
  ]) {
    const providers = [
      createHttpProverAdapter({
        baseURL: "https://deposit.example",
        proverTransportRedirectsDisabled: true,
        fetchImpl
      }).proveDeposit,
      createHttpDepositProofProviderV1({
        url: "https://deposit.example/v1/prover/deposit",
        proverTransportRedirectsDisabled: true,
        fetchImpl
      })
    ];
    for (const prove of providers) {
      await assert.rejects(
        () => prove(request),
        error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
          error?.proverCode === undefined &&
          /Cache-Control: no-store/.test(error.message)
      );
    }
  }

  for (const contentType of [
    "application/json; charset=utf-8",
    "application/json; private=unknown"
  ]) {
    const adapter = createHttpProverAdapter({
      baseURL: "https://deposit.example",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => jsonResponse(responseBody, 200, contentType)
    });
    await assert.rejects(
      () => adapter.proveDeposit(request),
      error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
        /Content-Type: application\/json/.test(error.message)
    );
  }
});

test("pinned v1 deposit provider uses an exact endpoint with the canonical nested wire", async () => {
  const request = depositRequestFromContract();
  const proofHex = canonicalEmptyGroth16ProofHex();
  const calls = [];
  const provider = createHttpDepositProofProviderV1({
    url: "https://deposit.example/prove",
    bearerToken: " deposit-token ",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (url, init) => {
      calls.push({
        url: String(url),
        method: init.method,
        redirect: init.redirect,
        cache: init.cache,
        accept: init.headers.get("Accept"),
        contentType: init.headers.get("Content-Type"),
        authorization: init.headers.get("Authorization"),
        body: JSON.parse(init.body)
      });
      return jsonResponse({
        version: "v1",
        proof: {
          version: "v1",
          note_commitment_hex: request.payload.note_commitment_hex,
          proof_hex: proofHex
        }
      });
    }
  });

  const result = await provider(request);

  assert.deepEqual(calls, [{
    url: "https://deposit.example/prove",
    method: "POST",
    redirect: "error",
    cache: "no-store",
    accept: "application/json",
    contentType: "application/json",
    authorization: "Bearer deposit-token",
    body: request
  }]);
  assert.deepEqual(result, {
    version: "v1",
    proof: {
      version: "v1",
      note_commitment_hex: request.payload.note_commitment_hex,
      proof_hex: proofHex
    }
  });
  assert.equal(result.proof_hex, proofHex);
  assert.equal(result.note_commitment_hex, request.payload.note_commitment_hex);

  const mismatchedCommitment = createHttpDepositProofProviderV1({
    url: "https://deposit.example/prove",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async () => jsonResponse({
      version: "v1",
      proof: {
        version: "v1",
        proof_hex: proofHex,
        note_commitment_hex: "22".repeat(32)
      }
    })
  });
  await assert.rejects(
    () => mismatchedCommitment(request),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED && /commitment mismatch/.test(error.message)
  );
});

test("legacy pinned deposit provider preserves the flat EVM request and response wire", async () => {
  const calls = [];
  const provider = createHttpDepositProofProvider({
    url: "https://deposit.example/legacy-prove",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (url, init) => {
      calls.push({
        url: String(url),
        method: init.method,
        redirect: init.redirect,
        cache: init.cache,
        accept: init.headers.Accept,
        contentType: init.headers["Content-Type"],
        body: JSON.parse(init.body)
      });
      return new Response(JSON.stringify({
        version: "v1",
        proof_hex: "ab",
        note_commitment_hex: "11".repeat(32)
      }), {
        status: 201,
        headers: { "content-type": "application/json; charset=utf-8" }
      });
    }
  });

  const result = await provider({
    note_json: '{"amount":"1uclair"}',
    note_commitment_hex: "11".repeat(32)
  });

  assert.deepEqual(calls, [{
    url: "https://deposit.example/legacy-prove",
    method: "POST",
    redirect: "error",
    cache: undefined,
    accept: "application/json",
    contentType: "application/json",
    body: {
      note_json: '{"amount":"1uclair"}',
      note_commitment_hex: "11".repeat(32)
    }
  }]);
  assert.deepEqual(result, {
    version: "v1",
    proof_hex: "ab",
    note_commitment_hex: "11".repeat(32)
  });
});

test("deposit proof validation enforces full canonical gnark framing", () => {
  const request = depositRequestFromContract();
  const proofHex = canonicalEmptyGroth16ProofHex();
  const response = {
    version: "v1",
    proof: {
      version: "v1",
      note_commitment_hex: request.payload.note_commitment_hex,
      proof_hex: proofHex
    }
  };
  assert.equal(validateDepositProofBytesV1(proofHex).length, 164);
  assert.equal(validateDepositProofBytesV1(canonicalGeneratorGroth16ProofHex).length, 164);
  assert.deepEqual(validateDepositProofResponseV1(request, response), response);
  assert.deepEqual(normalizeDepositProofProviderResultV1(request, {
    version: "v1",
    note_commitment_hex: request.payload.note_commitment_hex,
    proof_hex: proofHex
  }), response);
  for (const [field, value] of [
    ["proof", proofHex],
    ["depositProof", Uint8Array.from(Buffer.from(proofHex, "hex"))],
    ["deposit_proof", proofHex],
    ["proofHex", proofHex],
    ["proof_hex", proofHex]
  ]) {
    assert.deepEqual(
      normalizeDepositProofProviderResultV1(request, { [field]: value }),
      response,
      `local provider alias ${field}`
    );
  }

  const badInfinity = Uint8Array.from(Buffer.from(proofHex, "hex"));
  badInfinity[1] = 1;
  assert.throws(
    () => validateDepositProofBytesV1(badInfinity),
    /non-canonical infinity encoding/
  );
  const commitments = Uint8Array.from(Buffer.from(proofHex, "hex"));
  commitments[131] = 1;
  assert.throws(
    () => validateDepositProofBytesV1(commitments),
    /commitments are not supported/
  );
  const invalidByteArray = [...badInfinity];
  invalidByteArray[0] = 256;
  assert.throws(
    () => validateDepositProofBytesV1(invalidByteArray),
    /only integers from 0 through 255/
  );
});

test("pinned v1 DepositCircuit provider forwards caller cancellation", async () => {
  const controller = new AbortController();
  let sawAbort = false;
  const provider = createHttpDepositProofProviderV1({
    url: "http://127.0.0.1:8080/deposit-proof",
    timeoutMs: 1000,
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => {
        sawAbort = true;
        reject(new DOMException("aborted", "AbortError"));
      }, { once: true });
    })
  });

  const pending = provider(depositRequestFromContract(), { signal: controller.signal });
  controller.abort();
  await assert.rejects(
    () => pending,
    error => error?.code === ClairveilErrorCode.PROVER_CANCELLED && /cancelled/.test(error.message)
  );
  assert.equal(sawAbort, true);
});

test("prover base and exact URLs reject credentials, queries, and fragments", () => {
  for (const url of [
    "https://user:secret@prover.example/base",
    "https://prover.example/base?tenant=other",
    "https://prover.example/base#alternate"
  ]) {
    assert.throws(
      () => createHttpProverAdapter({ baseURL: url }),
      /must not contain credentials, query parameters, or a fragment/
    );
    assert.throws(
      () => createHttpDepositProofProvider({ url }),
      /must not contain credentials, query parameters, or a fragment/
    );
    assert.throws(
      () => createHttpDepositProofProviderV1({ url }),
      /must not contain credentials, query parameters, or a fragment/
    );
  }
});

test("async prover job adapter stops waiting when the caller cancels", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const controller = new AbortController();
  let sawSignal = false;
  const adapter = createAsyncJobProverAdapter({
    submitTransferJob: async (_request, options) => {
      sawSignal = options.signal === controller.signal;
      return { job_id: "job-cancelled" };
    },
    getJob: async () => new Promise(() => {}),
    intervalMs: 0
  });

  const pending = adapter.proveTransfer(examples.transfer.request, { signal: controller.signal });
  controller.abort();
  await assert.rejects(
    () => pending,
    error => error?.code === ClairveilErrorCode.PROVER_CANCELLED && /cancelled/.test(error.message)
  );
  assert.equal(sawSignal, true);
});

test("HTTP prover adapter reports non-JSON and error status responses", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");

  const nonJson = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async () => new Response("not-json", {
      status: 200,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store"
      }
    })
  });
  await assert.rejects(
    () => nonJson.proveTransfer(examples.transfer.request),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED && /not valid canonical JSON/.test(error.message)
  );

  const malformedUnavailable = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async () => new Response("down", {
      status: 503,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store"
      }
    })
  });
  await assert.rejects(
    () => malformedUnavailable.proveWithdraw(examples.withdraw.request),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
      /status 503/.test(error.message) &&
      error?.status === 503 &&
      error?.proverCode === undefined &&
      error?.retryable === false &&
      !error.message.includes("down")
  );
});

test("malformed prover error envelopes are rejected before 5xx availability classification", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const malformedBodies = [
    { unexpected: true },
    {
      version: "v2",
      code: "proof_failed",
      message: "unsupported envelope version",
      retryable: false
    },
    {
      version: "v1",
      code: "future_code",
      message: "unsupported envelope code",
      retryable: false
    },
    {
      version: "v1",
      code: "unavailable",
      message: "status-code mismatch",
      retryable: false
    }
  ];

  for (const body of malformedBodies) {
    const adapter = createHttpProverAdapter({
      baseURL: "http://127.0.0.1",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => jsonResponse(body, 500)
    });
    await assert.rejects(
      () => adapter.proveTransfer(examples.transfer.request),
      error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
        error?.status === 500 &&
        error?.proverCode === undefined &&
        error?.retryable === false &&
        !error.message.includes("unsupported") &&
        !error.message.includes("status-code")
    );
  }

  const depositRequest = depositRequestFromContract();
  const canonicalDepositProviders = [
    createHttpProverAdapter({
      baseURL: "http://127.0.0.1",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => jsonResponse({ unexpected: true }, 500)
    }).proveDeposit,
    createHttpDepositProofProviderV1({
      url: "http://127.0.0.1/v1/prover/deposit",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => jsonResponse({ unexpected: true }, 500)
    })
  ];
  for (const proveDeposit of canonicalDepositProviders) {
    await assert.rejects(
      () => proveDeposit(depositRequest),
      error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
        error?.status === 500 &&
        error?.proverCode === undefined &&
        error?.retryable === false &&
        !error.message.includes("unexpected")
    );
  }
});

test("prover errors preserve structured identity before inspecting message text", () => {
  for (const error of [
    Object.assign(new Error("socket aborted"), { code: "ECONNRESET" }),
    new Error("request aborted", {
      cause: Object.assign(new Error("socket closed"), { code: "UND_ERR_SOCKET" })
    })
  ]) {
    assert.equal(wrapProverError(error).code, ClairveilErrorCode.PROVER_UNAVAILABLE);
  }

  for (const code of [
    ClairveilErrorCode.PROVER_CANCELLED,
    ClairveilErrorCode.PROVER_TIMEOUT,
    ClairveilErrorCode.PROVER_UNAVAILABLE,
    ClairveilErrorCode.PROVER_REJECTED
  ]) {
    assert.equal(
      wrapProverError(Object.assign(new Error("ambiguous abort wording"), { code })).code,
      code
    );
  }

  assert.equal(
    wrapProverError(new TypeError("fetch failed", {
      cause: new Error("unexpected redirect")
    })).code,
    ClairveilErrorCode.PROVER_REJECTED
  );
  assert.equal(
    wrapProverError(new TypeError("fetch failed")).code,
    ClairveilErrorCode.PROVER_UNAVAILABLE
  );
  assert.equal(
    wrapProverError(new Error("prover request timed out")).code,
    ClairveilErrorCode.PROVER_TIMEOUT
  );
});

test("HTTP prover adapter classifies exact browser fetch failures as unavailable", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  for (const message of [
    "fetch failed",
    "Failed to fetch",
    "NetworkError when attempting to fetch resource.",
    "Load failed"
  ]) {
    const adapter = createHttpProverAdapter({
      baseURL: "https://prover.example",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => {
        throw new TypeError(message);
      }
    });
    await assert.rejects(
      () => adapter.proveTransfer(examples.transfer.request),
      error => error?.code === ClairveilErrorCode.PROVER_UNAVAILABLE && error.message === message
    );
  }

  for (const message of [
    "Failed to fetch witness schema",
    "proof unavailable because its payload is invalid",
    "Load failed after validating the response"
  ]) {
    const adapter = createHttpProverAdapter({
      baseURL: "https://prover.example",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => {
        throw new TypeError(message);
      }
    });
    await assert.rejects(
      () => adapter.proveTransfer(examples.transfer.request),
      error => error?.code === ClairveilErrorCode.PROVER_REJECTED
    );
  }
});

test("HTTP prover adapter classifies a truncated response stream as unavailable", fixtureTestOptions, async t => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const partialBody = '{"version":"v2","proof":';
  const server = createServer((request, response) => {
    request.resume();
    response.writeHead(200, {
      "cache-control": "no-store",
      "content-length": String(Buffer.byteLength(partialBody) + 1024),
      "content-type": "application/json"
    });
    response.write(partialBody, () => response.socket?.destroy());
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    server.closeAllConnections?.();
    await new Promise(resolve => server.close(resolve));
  });
  const address = server.address();
  assert.equal(typeof address, "object");
  const adapter = createHttpProverAdapter({
    baseURL: `http://127.0.0.1:${address.port}`
  });

  await assert.rejects(
    () => adapter.proveTransfer(examples.transfer.request),
    error => error?.code === ClairveilErrorCode.PROVER_UNAVAILABLE &&
      error.message === "terminated" &&
      error?.details?.cause?.cause?.code === "UND_ERR_SOCKET"
  );
});

test("prover failures preserve only safe error metadata and never echo server or solver text", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const busy = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async () => jsonResponse({
      version: "v1",
      code: "busy",
      message: "private witness solver details",
      retryable: true
    }, 429)
  });
  await assert.rejects(
    () => busy.proveTransfer(examples.transfer.request),
    error => error?.code === ClairveilErrorCode.PROVER_UNAVAILABLE &&
      error?.status === 429 &&
      error?.proverCode === "busy" &&
      error?.retryable === true &&
      error?.details?.retryable === true &&
      !error.message.includes("private witness")
  );

  const incompleteBusy = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async () => jsonResponse({
      version: "v1",
      code: "busy",
      message: "private witness solver details"
    }, 429)
  });
  await assert.rejects(
    () => incompleteBusy.proveDeposit(depositRequestFromContract()),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
      error?.status === 429 &&
      error?.proverCode === undefined &&
      error?.retryable === false
  );

  const proofFailed = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async () => jsonResponse({
      version: "v1",
      code: "proof_failed",
      message: "private witness solver details",
      retryable: false
    }, 500)
  });
  await assert.rejects(
    () => proofFailed.proveDeposit(depositRequestFromContract()),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
      error?.status === 500 &&
      error?.proverCode === "proof_failed" &&
      error?.retryable === false &&
      !error.message.includes("private witness")
  );

  const unavailable = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async () => jsonResponse({
      version: "v1",
      code: "unavailable",
      message: "operator diagnostics"
    }, 503)
  });
  await assert.rejects(
    () => unavailable.proveDeposit(depositRequestFromContract()),
    error => error?.code === ClairveilErrorCode.PROVER_UNAVAILABLE &&
      error?.status === 503 &&
      error?.proverCode === "unavailable" &&
      error?.retryable === false
  );

  const job = createAsyncJobProverAdapter({
    submitTransferJob: async () => ({ job_id: "job-1" }),
    getJob: async () => ({
      status: "failed",
      error: "sensitive gnark solver output"
    }),
    intervalMs: 0
  });
  await assert.rejects(
    () => job.proveTransfer(examples.transfer.request),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
      /prover job job-1 failed/.test(error.message) &&
      !error.message.includes("sensitive gnark")
  );
});

test("HTTP prover adapter requires HTTPS remotely, denies redirects, and strict-parses responses", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  assert.throws(
    () => createHttpProverAdapter({ baseURL: "http://prover.example" }),
    /requires HTTPS for non-loopback/
  );
  const fetchOptions = [];
  const adapter = createHttpProverAdapter({
    baseURL: "https://prover.example",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (_url, init) => {
      fetchOptions.push(init.redirect);
      return jsonResponse(examples.transfer.response);
    }
  });
  await adapter.proveTransfer(examples.transfer.request);
  assert.deepEqual(fetchOptions, ["error"]);

  for (const [body, secret, pattern] of [
    [
      `{"version":"v2","proof":${JSON.stringify(examples.transfer.response.proof)},"private_witness_field":true}`,
      "private_witness_field",
      /contains an unknown JSON field/
    ],
    [
      `{"version":"v2","private_duplicate_key":"first","private_duplicate_key":"second","proof":${JSON.stringify(examples.transfer.response.proof)}}`,
      "private_duplicate_key",
      /not valid canonical JSON/
    ],
    [
      `${JSON.stringify(examples.transfer.response)} "sensitive-trailing-text"`,
      "sensitive-trailing-text",
      /not valid canonical JSON/
    ]
  ]) {
    const strictAdapter = createHttpProverAdapter({
      baseURL: "http://127.0.0.1",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => new Response(body, {
        status: 200,
        headers: {
          "content-type": "application/json",
          "cache-control": "no-store"
        }
      })
    });
    await assert.rejects(
      () => strictAdapter.proveTransfer(examples.transfer.request),
      error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
        pattern.test(error.message) &&
        !error.message.includes(secret)
    );
  }
});

test("HTTP prover URL policy accepts the full IPv4 loopback range and rejects spoof hosts", () => {
  for (const baseURL of [
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://127.0.0.2:8080",
    "http://127.255.255.254:8080",
    "http://[::1]:8080"
  ]) {
    assert.doesNotThrow(() => createHttpProverAdapter({ baseURL }));
    assert.doesNotThrow(() => createHttpDepositProofProviderV1({
      url: `${baseURL}/v1/prover/deposit`
    }));
  }

  for (const baseURL of [
    "http://localhost.example:8080",
    "http://127.0.0.1.example:8080",
    "http://127.example:8080",
    "http://128.0.0.1:8080"
  ]) {
    assert.throws(
      () => createHttpProverAdapter({ baseURL }),
      /requires HTTPS for non-loopback/
    );
    assert.throws(
      () => createHttpDepositProofProviderV1({ url: `${baseURL}/v1/prover/deposit` }),
      /requires HTTPS for non-loopback/
    );
  }
});

test("HTTP prover adapter bounds response bytes before parsing", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  assert.throws(
    () => createHttpProverAdapter({ baseURL: "http://127.0.0.1", maxResponseBytes: 0 }),
    /maxResponseBytes must be a positive safe integer/
  );
  const adapter = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    maxResponseBytes: 16,
    proverTransportRedirectsDisabled: true,
    fetchImpl: async () => new Response("x".repeat(17), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store"
      }
    })
  });
  await assert.rejects(
    () => adapter.proveTransfer(examples.transfer.request),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED && /response exceeds 16 byte limit/.test(error.message)
  );

  const declaredOversize = createHttpProverAdapter({
    baseURL: "http://127.0.0.1",
    maxResponseBytes: 16,
    proverTransportRedirectsDisabled: true,
    fetchImpl: async () => new Response("{}", {
      status: 200,
      headers: {
        "content-length": "17",
        "content-type": "application/json",
        "cache-control": "no-store"
      }
    })
  });
  await assert.rejects(
    () => declaredOversize.proveTransfer(examples.transfer.request),
    /response exceeds 16 byte limit/
  );
});
