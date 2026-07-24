import test from "node:test";
import assert from "node:assert/strict";
import { ClairveilBrowserClient } from "clairveiljs/browser-dapp";

function browserClient(options = {}) {
  return new ClairveilBrowserClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair",
    ...options
  });
}

test("waitForEvmTransaction treats padded success status as successful", async () => {
  const client = browserClient();
  client.waitForEvmReceipt = async () => ({ status: "0x01" });

  const result = await client.waitForEvmTransaction("0xabc");

  assert.equal(result.ok, true);
  assert.equal(result.error, "");
});

test("waitForEvmTransaction keeps missing receipt status ambiguous", async () => {
  const client = browserClient();
  client.waitForEvmReceipt = async () => ({});

  const result = await client.waitForEvmTransaction("0xabc");

  assert.equal(result.ok, false);
  assert.match(result.error, /explicit successful receipt status/);
  assert.doesNotMatch(result.error, /failed with receipt status/);
});

test("evmJsonRpc forwards only allowlisted read-only methods", async () => {
  const client = browserClient();
  client.evmRpc = "http://evm.local";
  const originalFetch = globalThis.fetch;
  const methods = [];
  globalThis.fetch = async (_url, options) => {
    methods.push(JSON.parse(options.body).method);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x1" }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };

  try {
    assert.equal(await client.evmJsonRpc("eth_blockNumber"), "0x1");
    await assert.rejects(
      () => client.evmJsonRpc("eth_sendRawTransaction", ["0xdeadbeef"]),
      /not permitted for read-only queries/
    );
    assert.deepEqual(methods, ["eth_blockNumber"]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("evmJsonRpc rejects a missing EVM RPC endpoint before fetch", async () => {
  const client = browserClient();
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error("fetch must not be called");
  };

  try {
    await assert.rejects(
      () => client.evmJsonRpc("eth_blockNumber"),
      /evmRpc is required for EVM JSON-RPC queries/
    );
    assert.equal(fetchCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("evmJsonRpc rejects HTTP failures and times out while reading the response body", async () => {
  const client = browserClient({ evmRpc: "http://evm.local", queryTimeoutMs: 5 });
  const originalFetch = globalThis.fetch;

  try {
    globalThis.fetch = async () => new Response(JSON.stringify({ message: "unavailable" }), {
      status: 503,
      headers: { "content-type": "application/json" }
    });
    await assert.rejects(
      () => client.evmJsonRpc("eth_blockNumber"),
      /EVM RPC eth_blockNumber failed: unavailable/
    );

    globalThis.fetch = async (_url, options) => ({
      ok: true,
      async json() {
        return new Promise((_resolve, reject) => {
          options.signal.addEventListener("abort", () => {
            const error = new Error("aborted");
            error.name = "AbortError";
            reject(error);
          }, { once: true });
        });
      }
    });
    await assert.rejects(
      () => client.evmJsonRpc("eth_blockNumber"),
      /EVM RPC eth_blockNumber timed out after 5ms/
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("browser preparation rejects conflicting operation-evidence aliases", async () => {
  const client = browserClient();
  client.privacyMaterial = () => ({});
  client.proverAdapter = () => ({});

  await assert.rejects(
    () => client.prepareTransfer({
      amount: "1uclair",
      recipient: "clairs1recipient",
      expectedRecipientHash: "recipient-a",
      expected_recipient_hash: "recipient-b",
      expectedAmountHash: "amount-a",
      expected_amount_hash: "amount-a"
    }),
    /expectedRecipientHash aliases conflict/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      amounts: ["1uclair"],
      recipient: "clairs1recipient",
      expectedRecipientHashes: ["recipient-a"],
      expected_recipient_hashes: ["recipient-b"],
      expectedAmountHashes: ["amount-a"],
      expected_amount_hashes: ["amount-a"]
    }),
    /expectedRecipientHashes aliases conflict/
  );
  await assert.rejects(
    () => client.prepareTransfer({
      amount: "1uclair",
      recipient: "clairs1recipient",
      expectedRecipientHash: "",
      expectedAmountHash: ""
    }),
    /expectedRecipientHash must not be empty/
  );
});

test("browser client delegates signDirectAndBroadcast to the Cosmos client", async () => {
  const client = browserClient();
  const input = { wallet: {}, signDoc: {} };
  client.cosmos.signDirectAndBroadcast = async received => {
    assert.equal(received, input);
    return { ok: true };
  };

  assert.deepEqual(await client.signDirectAndBroadcast(input), { ok: true });
});

test("browser disclosure wrappers forward an explicit asset denom", async () => {
  const client = browserClient();
  const received = [];
  client.cosmos.decodeUserDisclosure = async input => received.push(input) && input;
  client.cosmos.decodeSelfViewDisclosure = async input => received.push(input) && input;
  client.cosmos.decodeAuditDisclosure = async input => received.push(input) && input;

  await client.decodeUserDisclosure({ txHash: "user", assetDenom: "uatom" });
  await client.decodeSelfViewDisclosure({ tx_hash: "self", asset_denom: "uatom", disclosureScalar: 3n });
  await client.decodeAuditDisclosure({ txHash: "audit", assetDenom: "uatom", asset_denom: "uatom", disclosurePrivKeyHex: "01".repeat(32) });

  assert.deepEqual(received.map(input => input.assetDenom), ["uatom", undefined, "uatom"]);
  assert.deepEqual(received.map(input => input.asset_denom), [undefined, "uatom", "uatom"]);
});

test("browser disclosure wrappers preserve conflicting denom aliases for transport validation", async () => {
  const client = browserClient();
  client.cosmos.decodeAuditDisclosure = async input => {
    if (input.assetDenom !== input.asset_denom) throw new Error("assetDenom aliases conflict");
    return input;
  };

  await assert.rejects(
    () => client.decodeAuditDisclosure({
      txHash: "audit",
      assetDenom: "uatom",
      asset_denom: "uosmo",
      disclosurePrivKeyHex: "01".repeat(32)
    }),
    /aliases conflict/
  );
});

test("browser relay cleanup preserves a frozen transaction build error", async () => {
  const client = browserClient();
  client.privacyMaterial = () => ({});
  client.proverAdapter = () => ({});
  const reservation = {
    reservation_ids: ["reservation-1"],
    lease_token: "lease-token"
  };
  client.cosmos.prepareRelayWithdraw = async () => ({
    status: "ready",
    payload: {},
    proof: {},
    proverPayload: {},
    selectedNote: {},
    reservation,
    privacyAccount: { shielded_address: "clairs1sender" }
  });
  const original = Object.freeze(new Error("frozen EVM transaction build failure"));
  client.evm.buildWithdrawTransaction = async () => {
    throw original;
  };
  const reservationManager = {
    async markReplanRequired() {
      throw new Error("reservation cleanup failed");
    }
  };

  await assert.rejects(
    () => client.prepareRelayWithdraw({
      walletType: "evm",
      amount: "1uclair",
      recipient: "clair1recipient",
      chainNowUnix: 4102444800,
      reservationManager
    }),
    error => error === original
  );
});

test("browser relay helpers preserve legacy chain-time aliases", async () => {
  const client = browserClient();
  client.privacyMaterial = () => ({});
  client.proverAdapter = () => ({});

  let preparedInput = null;
  client.cosmos.prepareRelayWithdraw = async input => {
    preparedInput = input;
    return { status: "insufficient_funds", plan: { message: "not ready" } };
  };
  await assert.rejects(
    () => client.prepareRelayWithdraw({
      amount: "1uclair",
      recipient: "clair1recipient",
      nowUnix: 4102444800
    }),
    /not ready/
  );
  assert.equal(preparedInput.chainNowUnix, 4102444800);

  client.cosmos.buildRelayWithdrawMessageFromPayload = input => input;
  const messageInput = client.buildRelayWithdrawMessageFromPayload({
    payload: {},
    address: "clair1relayer",
    now_unix: 4102444801
  });
  assert.equal(messageInput.chainNowUnix, 4102444801);

  let signDocInput = null;
  client.cosmos.createRelayWithdrawSignDoc = async input => {
    signDocInput = input;
    return { signDoc: {}, message: {}, payload: input.payload, relayer: input.relayer };
  };
  await client.createRelayWithdrawSignDoc({
    payload: {},
    address: "clair1relayer",
    pubKeyHex: "02".padEnd(66, "0"),
    nowUnix: 4102444802
  });
  assert.equal(signDocInput.chainNowUnix, 4102444802);
});
