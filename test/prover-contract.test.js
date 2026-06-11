import test from "node:test";
import assert from "node:assert/strict";
import {
  createHttpProverAdapter
} from "clairveiljs/prover";
import { ClairveilErrorCode } from "clairveiljs/errors";
import {
  fixtureTestOptions,
  readFixture
} from "./helpers.js";

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" }
  });
}

test("HTTP prover adapter follows the Go route and version contract", fixtureTestOptions, async () => {
  const contract = readFixture("privacy_prover_http_api_contract.json");
  const examples = readFixture("privacy_prover_example_bundle.json");
  const calls = [];
  const adapter = createHttpProverAdapter({
    baseURL: "https://prover.example/base/",
    bearerToken: " test-token ",
    fetchImpl: async (url, init) => {
      const body = JSON.parse(init.body);
      calls.push({
        url: String(url),
        method: init.method,
        contentType: init.headers.get("Content-Type"),
        authorization: init.headers.get("Authorization"),
        body
      });
      if (url.pathname === contract.transfer_route.path) {
        return jsonResponse(examples.transfer.response);
      }
      if (url.pathname === contract.withdraw_route.path) {
        return jsonResponse(examples.withdraw.response);
      }
      return jsonResponse({ version: "v1", code: "not_found" }, 404);
    }
  });

  const transfer = await adapter.proveTransfer(examples.transfer.request);
  const withdraw = await adapter.proveWithdraw(examples.withdraw.request);

  assert.equal(calls[0].url, `https://prover.example${contract.transfer_route.path}`);
  assert.equal(calls[0].method, contract.transfer_route.method);
  assert.equal(calls[0].contentType, contract.content_type);
  assert.equal(calls[0].authorization, "Bearer test-token");
  assert.equal(calls[0].body.version, contract.transfer_route.request_version);
  assert.equal(transfer.version, contract.transfer_route.response_version);

  assert.equal(calls[1].url, `https://prover.example${contract.withdraw_route.path}`);
  assert.equal(calls[1].method, contract.withdraw_route.method);
  assert.equal(calls[1].body.version, contract.withdraw_route.request_version);
  assert.equal(withdraw.version, contract.withdraw_route.response_version);
});

test("HTTP prover adapter rejects proof payload hash mismatch", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const adapter = createHttpProverAdapter({
    baseURL: "http://prover.example",
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
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED && /transfer proof payload hash mismatch/.test(error.message)
  );
  await assert.rejects(
    () => adapter.proveWithdraw(examples.withdraw.request),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED && /withdraw proof payload hash mismatch/.test(error.message)
  );
});

test("HTTP prover adapter rejects malformed proof response shapes", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");

  for (const [body, pattern] of [
    [{}, /transfer proof response\.version must be v1/],
    [{ version: "v1" }, /transfer proof response\.proof must be a JSON object/],
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
      baseURL: "http://prover.example",
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
    baseURL: "http://prover.example",
    timeoutMs: 5,
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

test("HTTP prover adapter reports non-JSON and error status responses", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");

  const nonJson = createHttpProverAdapter({
    baseURL: "http://prover.example",
    fetchImpl: async () => new Response("not-json", { status: 200 })
  });
  await assert.rejects(
    () => nonJson.proveTransfer(examples.transfer.request),
    error => error?.code === ClairveilErrorCode.PROVER_REJECTED && /not JSON/.test(error.message)
  );

  const unavailable = createHttpProverAdapter({
    baseURL: "http://prover.example",
    fetchImpl: async () => new Response("down", { status: 503 })
  });
  await assert.rejects(
    () => unavailable.proveWithdraw(examples.withdraw.request),
    error => error?.code === ClairveilErrorCode.PROVER_UNAVAILABLE && /status 503/.test(error.message)
  );
});
