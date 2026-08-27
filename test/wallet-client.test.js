import test from "node:test";
import assert from "node:assert/strict";
import {
  ClairveilBrowserClient,
  resolveActiveClairveilWebClientProfile,
  validateClairveilWebClientConfig
} from "clairveiljs/browser-dapp";
import { CURVE_BASE, encodeShieldedAddress } from "clairveiljs/core";
import { createEvmContractAdapter } from "clairveiljs/evm";
import { fixtureTestOptions, readFixture } from "./helpers.js";

const validClairsRecipient = encodeShieldedAddress(CURVE_BASE, CURVE_BASE, {
  shieldedPrefix: "clairs"
});

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

function webCosmosProfile(overrides = {}) {
  return {
    id: "clairveil-cosmos-test",
    label: "Clairveil Cosmos Test",
    chainName: "Clairveil Cosmos Test",
    transport: "cosmos",
    wallet: "keplr",
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair",
    displayDenom: "CLAIR",
    coinDecimals: 6,
    proverUrl: "http://127.0.0.1:8080",
    keplrCoinType: 118,
    gasPriceStep: { low: 0.01, average: 0.025, high: 0.04 },
    keplrChainInfo: {
      chainId: "clairveil-local-3",
      chainName: "Clairveil Cosmos Test",
      rpc: "http://127.0.0.1:26657",
      rest: "http://127.0.0.1:1317",
      bip44: { coinType: 118 },
      bech32Config: {
        bech32PrefixAccAddr: "clair",
        bech32PrefixAccPub: "clairpub",
        bech32PrefixValAddr: "clairvaloper",
        bech32PrefixValPub: "clairvaloperpub",
        bech32PrefixConsAddr: "clairvalcons",
        bech32PrefixConsPub: "clairvalconspub"
      },
      currencies: [{ coinDenom: "CLAIR", coinMinimalDenom: "uclair", coinDecimals: 6 }],
      feeCurrencies: [{
        coinDenom: "CLAIR",
        coinMinimalDenom: "uclair",
        coinDecimals: 6,
        gasPriceStep: { low: 0.01, average: 0.025, high: 0.04 }
      }],
      stakeCurrency: { coinDenom: "CLAIR", coinMinimalDenom: "uclair", coinDecimals: 6 },
      features: []
    },
    ...overrides
  };
}

function webEvmProfile(overrides = {}) {
  return {
    id: "clairveil-evm-test",
    label: "Clairveil EVM Test",
    chainName: "Clairveil EVM Test",
    transport: "evm",
    wallet: "metamask",
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair",
    displayDenom: "CLAIR",
    coinDecimals: 6,
    proverUrl: "http://127.0.0.1:8080",
    evmRpc: "http://127.0.0.1:8545",
    evmChainId: "0x539",
    evmChainName: "Clairveil EVM Test",
    evmPrivacyPrecompileAddress: "0x0000000000000000000000000000000000000900",
    evmDepositMode: "payable-exact-value",
    evmNativeDenom: "uclair",
    evmGasLimit: "0x989680",
    evmSendGasLimit: "0x5208",
    ...overrides
  };
}

function completePrivacyStateAdapter() {
  const empty = async () => ({});
  return {
    fetchPrivacyScan: empty,
    fetchTreeState: empty,
    fetchCommitmentInfo: empty,
    lookupMerklePath: empty,
    fetchAuditConfig: empty,
    fetchDisclosureConfig: empty,
    fetchCircuitConfig: empty,
    fetchReserve: empty,
    fetchAssetByDenom: empty,
    fetchAssetByID: empty,
    fetchCommitmentPathsAtRoot: empty,
    checkNullifiers: async () => ({})
  };
}

test("profiled browser clients retain the caller's explicit batch opt-in", () => {
  const client = browserClient({
    profile: webCosmosProfile(),
    enableExperimentalBatchTransfer: true
  });

  assert.equal(client.cosmos.enableExperimentalBatchTransfer, true);
  assert.equal(client.profile.enableExperimentalBatchTransfer, undefined);
});

test("browser Web config validation resolves one complete active profile and rejects unsafe compatibility state", () => {
  const profile = webCosmosProfile();
  const config = {
    schemaVersion: "clairveil-web-client-config-v1",
    activeChainProfileId: profile.id,
    chainProfiles: [profile],
    serverBacked: true,
    serverFeatures: { batchTransfer: true },
    chainId: profile.chainId,
    rpc: profile.rpc,
    rest: profile.rest,
    proverUrl: profile.proverUrl,
    transport: profile.transport,
    denom: profile.denom,
    displayDenom: profile.displayDenom,
    coinDecimals: profile.coinDecimals,
    accountPrefix: profile.accountPrefix,
    shieldedPrefix: profile.shieldedPrefix,
    keplrChainInfo: profile.keplrChainInfo
  };

  const validated = validateClairveilWebClientConfig(config);
  assert.equal(validated.activeProfile, validated.chainProfiles[0]);
  assert.equal(resolveActiveClairveilWebClientProfile(config).id, profile.id);

  assert.throws(
    () => validateClairveilWebClientConfig({ ...config, chainProfiles: [profile, profile] }),
    /duplicate profile IDs/
  );
  assert.throws(
    () => validateClairveilWebClientConfig({ ...config, rpc: "http://127.0.0.1:9999" }),
    /config\.rpc must match the active chain profile/
  );
  assert.throws(
    () => validateClairveilWebClientConfig({
      schemaVersion: "clairveil-web-client-config-v1",
      activeChainProfileId: "evm",
      chainProfiles: [webEvmProfile({ id: "evm" })],
      keplrChainInfo: profile.keplrChainInfo
    }),
    /config\.keplrChainInfo must match the active chain profile|not permitted for an active EVM profile/
  );
});

test("EVM browser profile may omit Cosmos REST and RPC only with a complete privacy state adapter", () => {
  const profile = webEvmProfile();
  delete profile.rpc;
  delete profile.rest;

  assert.throws(
    () => new ClairveilBrowserClient({ profile }),
    /profile\.rpc must be a string/
  );
  assert.throws(
    () => validateClairveilWebClientConfig({
      schemaVersion: "clairveil-web-client-config-v1",
      activeChainProfileId: profile.id,
      chainProfiles: [profile]
    }),
    /config\.chainProfiles\[0\].*profile\.rpc must be a string/
  );
  const client = new ClairveilBrowserClient({
    profile,
    privacyStateAdapter: completePrivacyStateAdapter()
  });
  assert.equal(client.rpc, "");
  assert.equal(client.rest, "");
  assert.ok(client.privacyStateAdapter);
});

test("waitForEvmTransaction requires RPC identity and privacy-event verification", async () => {
  const client = browserClient({ profile: webEvmProfile() });
  const txHash = `0x${"ab".repeat(32)}`;
  const sender = "0x1111111111111111111111111111111111111111";
  const privacyTransaction = {
    to: "0x0000000000000000000000000000000000000900",
    data: "0x1234",
    value: "0x0",
    chainId: "0x539"
  };
  const rpcTransaction = {
    hash: txHash,
    from: sender,
    to: privacyTransaction.to,
    input: privacyTransaction.data,
    value: privacyTransaction.value,
    chainId: privacyTransaction.chainId
  };
  client.waitForEvmReceipt = async () => ({
    transactionHash: txHash,
    status: "0x01",
    blockNumber: "0xa",
    blockHash: `0x${"12".repeat(32)}`,
    logs: []
  });
  client.evmJsonRpc = async method => method === "eth_chainId" ? "0x539" : rpcTransaction;
  client.evm.verifyTransactionIdentity = () => ({ verified: true, txHash });
  client.evm.verifyPrivacyReceipt = () => ({ verified: true, event: "PrivacyTransfer", operation: "transfer" });

  const result = await client.waitForEvmTransaction(txHash, {
    privacyTransaction,
    sender,
    finalityPolicy: "receipt"
  });

  assert.equal(result.ok, true);
  assert.equal(result.error, "");
  assert.equal(result.tx, rpcTransaction);
  assert.equal(result.evmTransactionVerified, true);
  assert.equal(result.evmPrivacyReceiptVerified, true);
  assert.equal(result.evmFinalityVerified, true);
  assert.equal(result.finality.mode, "receipt");
});

test("waitForEvmTransaction fails closed when no EVM finality policy is configured", async () => {
  const client = browserClient({ profile: webEvmProfile() });
  const txHash = `0x${"ad".repeat(32)}`;
  const sender = "0x1111111111111111111111111111111111111111";
  const privacyTransaction = {
    to: "0x0000000000000000000000000000000000000900",
    data: "0x1234",
    value: "0x0",
    chainId: "0x539"
  };
  client.waitForEvmReceipt = async () => ({
    transactionHash: txHash,
    status: "0x1",
    blockNumber: "0xa",
    blockHash: `0x${"13".repeat(32)}`,
    logs: []
  });
  client.evmJsonRpc = async method => method === "eth_chainId" ? "0x539" : ({
    hash: txHash,
    from: sender,
    to: privacyTransaction.to,
    input: privacyTransaction.data,
    value: privacyTransaction.value,
    chainId: privacyTransaction.chainId
  });
  client.evm.verifyTransactionIdentity = () => ({ verified: true, txHash });
  client.evm.verifyPrivacyReceipt = () => ({
    verified: true,
    event: "PrivacyTransfer",
    operation: "transfer"
  });

  const result = await client.waitForEvmTransaction(txHash, { privacyTransaction, sender });

  assert.equal(result.ok, false);
  assert.equal(result.finality, null);
  assert.equal(result.evmFinalityVerified, false);
  assert.match(result.error, /finality policy is required/);
});

test("waitForEvmTransaction accepts custom calldata only through its adapter receipt verifier", async () => {
  const profile = webEvmProfile();
  const sender = "0x1111111111111111111111111111111111111111";
  const txHash = `0x${"ac".repeat(32)}`;
  const adapter = createEvmContractAdapter({
    contractAddress: profile.evmPrivacyPrecompileAddress,
    encodeTransfer: () => "0xdeadbeef",
    verifyPrivacyReceipt({ receipt, operation }) {
      assert.equal(receipt.logs[0].data, "0xcafe");
      return { verified: true, operation, event: "CustomPrivacyTransfer" };
    }
  });
  const client = browserClient({ profile, evmContractAdapter: adapter });
  const prepared = await client.evm.buildTransferTransaction({
    message: { expiresAtUnix: 4_102_448_400n },
    chainNowUnix: 4_102_444_800
  });
  const rpcTransaction = {
    hash: txHash,
    from: sender,
    to: prepared.transaction.to,
    input: prepared.transaction.data,
    value: prepared.transaction.value,
    chainId: profile.evmChainId
  };
  client.waitForEvmReceipt = async () => ({
    transactionHash: txHash,
    status: "0x1",
    blockNumber: "0xa",
    blockHash: `0x${"14".repeat(32)}`,
    logs: [{ address: prepared.transaction.to, topics: [], data: "0xcafe" }]
  });
  client.evmJsonRpc = async method => method === "eth_chainId"
    ? profile.evmChainId
    : rpcTransaction;

  const result = await client.waitForEvmTransaction(txHash, {
    privacyTransaction: prepared.transaction,
    sender,
    finalityPolicy: "receipt"
  });

  assert.equal(result.ok, true);
  assert.equal(result.transactionVerification.operation, "transfer");
  assert.equal(result.privacyReceipt.event, "CustomPrivacyTransfer");
  assert.equal(result.evmFinalityVerified, true);
  assert.throws(
    () => browserClient({
      profile,
      evmContractAdapter: createEvmContractAdapter({
        contractAddress: "0x0000000000000000000000000000000000000999"
      })
    }),
    /contractAddress conflicts/
  );
});

test("waitForEvmTransaction keeps missing receipt status ambiguous", async () => {
  const client = browserClient({ profile: webEvmProfile() });
  const txHash = `0x${"bc".repeat(32)}`;
  const sender = "0x1111111111111111111111111111111111111111";
  const privacyTransaction = {
    to: "0x0000000000000000000000000000000000000900",
    data: "0x1234",
    value: "0x0",
    chainId: "0x539"
  };
  client.waitForEvmReceipt = async () => ({ transactionHash: txHash, logs: [] });
  client.evmJsonRpc = async method => method === "eth_chainId" ? "0x539" : ({
    hash: txHash,
    from: sender,
    to: privacyTransaction.to,
    input: privacyTransaction.data,
    value: privacyTransaction.value,
    chainId: privacyTransaction.chainId
  });
  client.evm.verifyTransactionIdentity = () => ({ verified: true, txHash });

  const result = await client.waitForEvmTransaction(txHash, { privacyTransaction, sender });

  assert.equal(result.ok, false);
  assert.match(result.error, /explicit successful receipt status/);
  assert.doesNotMatch(result.error, /failed with receipt status/);
  assert.equal(result.evmPrivacyReceiptVerified, false);
  assert.equal(result.evmFinalityVerified, false);
});

test("waitForEvmTransaction rejects receipt-status-only confirmation", async () => {
  const client = browserClient({ profile: webEvmProfile() });
  await assert.rejects(
    () => client.waitForEvmTransaction(`0x${"cd".repeat(32)}`),
    /original SDK-prepared privacyTransaction/
  );
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
  const client = browserClient({ enableExperimentalBatchTransfer: true });
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
    () => client.prepareTransferBatch({
      amounts: ["1uclair"],
      recipient: "clairs1recipient",
      reservationManager: {},
      reservation_manager: {},
      onPreparedPayload() {},
      onPreparedProof() {}
    }),
    /reservationManager aliases conflict/
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

test("browser transfer preparation rejects conflicting self-view aliases", async () => {
  const client = browserClient();
  client.privacyMaterial = () => ({});

  await assert.rejects(
    () => client.prepareTransfer({
      amount: "1uclair",
      recipient: "clairs1recipient",
      disableSelfViewDisclosure: true,
      disable_self_view_disclosure: false
    }),
    /disableSelfViewDisclosure aliases conflict/
  );
  await assert.rejects(
    () => client.prepareTransfer({
      amount: "1uclair",
      recipient: "clairs1recipient",
      selfViewDisclosureTargetPubKeyHex: "01",
      self_view_disclosure_target_pubkey: "02"
    }),
    /selfViewDisclosureTargetPubKeyHex aliases conflict/
  );
  await assert.rejects(
    () => client.prepareTransfer({
      amount: "1uclair",
      recipient: "clairs1recipient",
      chainNowUnix: 10,
      chain_now_unix: 11
    }),
    /chainNowUnix aliases conflict/
  );
  await assert.rejects(
    () => client.prepareTransfer({
      amount: "1uclair",
      recipient: "clairs1recipient",
      expiresAtUnix: 20,
      expires_at_unix: 21,
      chainNowUnix: 10
    }),
    /expiresAtUnix aliases conflict/
  );
});

test("browser batch preparation rejects conflicting snapshot and disclosure aliases", async () => {
  const client = browserClient({ enableExperimentalBatchTransfer: true });

  await assert.rejects(
    () => client.prepareTransferBatch({
      amounts: ["1uclair"],
      recipient: "clairs1recipient",
      rootHex: "11".repeat(32),
      root_hex: "22".repeat(32),
      snapshotHeight: 10,
      snapshot_height: 10
    }),
    /rootHex aliases conflict/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      amounts: ["1uclair"],
      recipient: "clairs1recipient",
      disableSelfViewDisclosure: true,
      disable_self_view_disclosure: false
    }),
    /disableSelfViewDisclosure aliases conflict/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      amounts: ["1uclair"],
      recipient: "clairs1recipient",
      privacyPolicy: "all-private",
      privacy_policy: "amount"
    }),
    /privacyPolicy aliases conflict/
  );
  await assert.rejects(
    () => client.provePreparedBatchTransfer({
      chainNowUnix: 10,
      chain_now_unix: 11
    }),
    /chainNowUnix aliases conflict/
  );
  await assert.rejects(
    () => client.finalizePreparedBatchTransfer({
      pubKeyHex: "02".repeat(33),
      pub_key_hex: "03".repeat(33)
    }),
    /pubKeyHex aliases conflict/
  );
  await assert.rejects(
    () => client.prepareWithdraw({
      amount: "1uclair",
      recipient: "clair1recipient",
      expiresAtUnix: 10,
      expires_at_unix: 11
    }),
    /expiresAtUnix aliases conflict/
  );
  await assert.rejects(
    () => client.prepareWithdraw({
      amount: "1uclair",
      recipient: "clair1recipient",
      chainNowUnix: 10,
      chain_now_unix: 11
    }),
    /chainNowUnix aliases conflict/
  );
  await assert.rejects(
    () => client.prepareRelayWithdraw({
      amount: "1uclair",
      recipient: "clair1recipient",
      expiresAtUnix: 10,
      expires_at_unix: 11,
      chainNowUnix: 9
    }),
    /expiresAtUnix aliases conflict/
  );
  await assert.rejects(
    () => client.prepareRelayWithdraw({
      amount: "1uclair",
      recipient: "clair1recipient",
      chainNowUnix: 10,
      now_unix: 11
    }),
    /chainNowUnix aliases conflict/
  );
});

test("browser batch preparation forwards profile fees to the Cosmos sign-doc path", async () => {
  const client = browserClient({ enableExperimentalBatchTransfer: true });
  client.privacyMaterial = () => ({ shieldedAddress: "clairs1sender" });
  let received = null;
  client.cosmos.prepareTransferBatch = async input => {
    received = input;
    return {
      status: "ready",
      signDoc: {},
      reservation: null,
      prepared: {
        payments: [{ privacyPolicy: "all-private", disclosureMode: "none" }]
      },
      privacyAccount: { shielded_address: "clairs1sender" },
      plan: {}
    };
  };
  const fees = [{ denom: "uclair", amount: "41" }];
  await client.prepareTransferBatch({
    amounts: ["1uclair"],
    recipient: "clairs1recipient",
    proverAdapter: {},
    reservationManager: {},
    onPreparedPayload() {},
    onPreparedProof() {},
    gas_limit: 26000000,
    fee_amount: fees
  });

  assert.equal(received.gasLimit, 26000000);
  assert.equal(received.fee_amount, fees);
});

test("browser Cosmos transfer preserves caller gas and fee aliases at the SDK facade", async () => {
  const client = browserClient();
  client.privacyMaterial = () => ({ shieldedAddress: "clairs1sender" });
  let received = null;
  client.cosmos.prepareTransfer = async input => {
    received = input;
    return {
      status: "ready",
      signDoc: {},
      reservation: null,
      privacyAccount: { shielded_address: "clairs1sender" },
      prepared: { planAction: "final_transfer" },
      plan: { status: "final_transfer_ready" },
      payload: {},
      proof: {},
      message: {}
    };
  };

  await client.prepareTransfer({
    amount: "1uclair",
    recipient: "clairs1recipient",
    proverAdapter: {},
    chainNowUnix: 10,
    gas_limit: 8123456,
    fee_amount: [{ denom: "uclair", amount: "47" }]
  });

  assert.equal(received.gasLimit, 8123456);
  assert.deepEqual(received.feeAmount, [{ denom: "uclair", amount: "47" }]);
  assert.equal(received.fee_amount, undefined);
  await assert.rejects(() => client.prepareTransfer({
    amount: "1uclair",
    recipient: "clairs1recipient",
    chainNowUnix: 10,
    gasLimit: 8,
    gas_limit: 9
  }), /gasLimit aliases conflict/);
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

test("browser Cosmos deposit preserves exact encrypted output for confirmation", async () => {
  const client = browserClient();
  client.privacyMaterial = () => ({ address: "clair1sender", rootSeed: new Uint8Array(32) });
  let received = null;
  client.cosmos.prepareDeposit = async input => {
    received = input;
    return ({
    signDoc: { chainId: "clairveil-local-3" },
    material: {
      note_commitment_hex: "11".repeat(32),
      encrypted_note_hex: "22".repeat(48),
      amount: "1uclair",
    },
    privacyAccount: { shielded_address: "clairs1sender" },
    });
  };

  const prepared = await client.prepareDeposit({
    amount: "1uclair",
    proofHex: "ab",
    gas_limit: 3123456,
    fee_amount: [{ denom: "uclair", amount: "17" }]
  });

  assert.equal(prepared.prepared.noteCommitmentHex, "11".repeat(32));
  assert.equal(prepared.prepared.encryptedNoteHex, "22".repeat(48));
  assert.equal(received.gas_limit, 3123456);
  assert.deepEqual(received.fee_amount, [{ denom: "uclair", amount: "17" }]);
});

test("browser profile uses only its pinned DepositCircuit endpoint", async () => {
  const client = browserClient({
    profile: webCosmosProfile({ depositProofUrl: "https://deposit.example/prove" }),
    depositProofUrl: "https://ignored.example/prove"
  });
  client.privacyMaterial = () => ({
    address: "clair1sender",
    rootSeed: new Uint8Array(32)
  });
  client.cosmos.buildDepositMaterial = () => ({
    amount: "1uclair",
    note: { amount: "1" },
    note_json: '{"amount":"1"}',
    note_commitment_hex: "11".repeat(32)
  });
  let preparedInput = null;
  client.cosmos.prepareDeposit = async input => {
    preparedInput = input;
    return {
      signDoc: { chainId: "clairveil-local-3" },
      material: {
        note_commitment_hex: "11".repeat(32),
        encrypted_note_hex: "22".repeat(48),
        amount: "1uclair"
      },
      privacyAccount: { shielded_address: "clairs1sender" }
    };
  };
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({
      url: String(url),
      method: init.method,
      redirect: init.redirect,
      body: JSON.parse(init.body),
      signal: init.signal
    });
    return new Response(JSON.stringify({
      version: "v1",
      proof_hex: "ab",
      note_commitment_hex: "11".repeat(32)
    }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };

  try {
    await client.prepareDeposit({ amount: "1uclair" });
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.deepEqual(calls.map(({ signal, ...call }) => call), [{
    url: "https://deposit.example/prove",
    method: "POST",
    redirect: "error",
    body: {
      note_json: '{"amount":"1"}',
      note_commitment_hex: "11".repeat(32)
    }
  }]);
  assert.equal(calls[0].signal.aborted, false);
  assert.equal(preparedInput.proofHex, "ab");
});

test("EVM profile prepare checks the connected wallet network before building an artifact", async () => {
  const client = browserClient({
    profile: webEvmProfile()
  });
  client.evmJsonRpc = async () => "0x539";
  let protocolPreflightCalls = 0;
  client.cosmos.assertProtocolPreflight = async () => {
    protocolPreflightCalls += 1;
    return {};
  };
  let materialBuilt = false;
  client.privacyMaterial = () => {
    materialBuilt = true;
    return {
      address: "clair1sender",
      rootSeed: new Uint8Array(32),
      shieldedAddress: "clairs1sender"
    };
  };

  await assert.rejects(
    () => client.prepareDeposit({
      address: "0x1111111111111111111111111111111111111111",
      pubKeyHex: "02".padEnd(66, "0"),
      signatureBase64: "AQID",
      amount: "1uclair",
      evmWallet: { getChainId: async () => "0x1" }
    }),
    /EVM wallet chain ID 0x1 does not match configured evmChainId 0x539/
  );
  assert.equal(materialBuilt, false);
  assert.equal(protocolPreflightCalls, 0);
});

test("payable EVM deposit profiles require an exact native-denom binding", async () => {
  const profile = webEvmProfile({
    evmDepositMode: "payable-exact-value",
    evmNativeDenom: "uclair"
  });
  const client = browserClient({ profile });
  assert.equal(client.evmDepositMode, "payable-exact-value");
  assert.equal(client.evmNativeDenom, "uclair");

  assert.throws(
    () => browserClient({
      profile: webEvmProfile({
        evmDepositMode: "payable-exact-value",
        evmNativeDenom: undefined
      })
    }),
    /profile\.evmNativeDenom/
  );
  assert.throws(
    () => browserClient({
      profile: webEvmProfile({
        evmDepositMode: "payable-exact-value",
        evmNativeDenom: "uother"
      })
    }),
    /must match profile\.denom/
  );
  assert.throws(
    () => browserClient({
      profile: webEvmProfile({ evmDepositMode: "caller-selected" })
    }),
    /unsupported EVM deposit mode/
  );

  client.evmJsonRpc = async () => "0x539";
  let protocolPreflightCalled = false;
  client.cosmos.assertProtocolPreflight = async () => {
    protocolPreflightCalled = true;
    return {};
  };
  await assert.rejects(
    () => client.prepareDeposit({
      amount: "1uother",
      evmWallet: { getChainId: async () => "0x539" },
      depositProofProvider: async () => {
        throw new Error("deposit proof provider must not be called");
      }
    }),
    /does not match native denom/
  );
  assert.equal(protocolPreflightCalled, false);

  let depositProofProviderCalled = false;
  await assert.rejects(
    () => client.prepareDeposit({
      amount: "1uclair",
      depositMaterial: { amount: "2uclair" },
      evmWallet: { getChainId: async () => "0x539" },
      depositProofProvider: async () => {
        depositProofProviderCalled = true;
        return {};
      }
    }),
    /deposit material amount mismatch/
  );
  assert.equal(depositProofProviderCalled, false);
  assert.equal(protocolPreflightCalled, false);
});

test("EVM deposit runs the consensus protocol preflight before building a transaction", async () => {
  const client = browserClient({ profile: webEvmProfile() });
  client.evmJsonRpc = async () => "0x539";
  client.cosmos.assertProtocolPreflight = async denom => {
    assert.equal(denom, "uclair");
    throw new Error("active circuit configuration is unavailable");
  };
  let materialBuilt = false;
  client.privacyMaterial = () => {
    materialBuilt = true;
    return {};
  };

  await assert.rejects(
    () => client.prepareDeposit({
      amount: "1uclair",
      evmWallet: { getChainId: async () => "0x539" }
    }),
    /active circuit configuration is unavailable/
  );
  assert.equal(materialBuilt, false);
});

test("EVM prepareDeposit forwards its required proof into the canonical precompile build", async () => {
  const client = browserClient({ profile: webEvmProfile() });
  client.evmJsonRpc = async () => "0x539";
  client.cosmos.assertProtocolPreflight = async () => ({});
  client.privacyMaterial = () => ({
    address: "clair1sender",
    rootSeed: new Uint8Array(32),
    shieldedAddress: "clairs1sender"
  });
  client.cosmos.buildDepositMaterial = () => ({
    amount: "1uclair",
    shieldedAddress: "clairs1sender",
    note_commitment_hex: "11".repeat(32)
  });
  let captured = null;
  client.evm.buildDepositTransaction = input => {
    captured = input;
    return {
      material: {
        shieldedAddress: "clairs1sender",
        note_commitment_hex: "11".repeat(32),
        encrypted_note_hex: "22".repeat(48),
        amount: "1uclair"
      },
      transaction: { to: webEvmProfile().evmPrivacyPrecompileAddress, data: "0x1234" }
    };
  };

  const prepared = await client.prepareDeposit({
    amount: "1uclair",
    proofHex: "ab",
    evmWallet: { getChainId: async () => "0x539" }
  });

  assert.equal(captured.proof, "ab");
  assert.equal(prepared.transaction.data, "0x1234");
  assert.equal(prepared.prepared.encryptedNoteHex, "22".repeat(48));
});

test("browser DApp profiles reject schema-incomplete or transport-incompatible configuration", () => {
  assert.throws(
    () => browserClient({ profile: { ...webEvmProfile(), evmGasLimit: undefined } }),
    /profile\.evmGasLimit/
  );
  assert.throws(
    () => browserClient({ profile: { ...webEvmProfile(), wallet: "keplr" } }),
    /profile\.wallet must be metamask/
  );
  assert.throws(
    () => browserClient({ profile: { ...webCosmosProfile(), unknown: true } }),
    /not supported by the Clairveil Web profile schema/
  );
});

test("browser EVM submission rechecks the profile network and delegates reservation-aware broadcast", async () => {
  const client = browserClient({ profile: webEvmProfile() });
  client.evmJsonRpc = async () => "0x539";
  const transaction = {
    to: "0x0000000000000000000000000000000000000900",
    data: "0x1234",
    gas: "0x5208",
    chainId: "0x539"
  };
  let captured = null;
  client.evm.sendTransaction = async (wallet, submitted, options) => {
    captured = { wallet, submitted, options };
    return `0x${"ab".repeat(32)}`;
  };
  const wallet = {
    getChainId: async () => "0x539",
    sendTransaction: async () => `0x${"cd".repeat(32)}`
  };
  const transactionHash = await client.sendEvmTransaction({ wallet, transaction });

  assert.equal(transactionHash, `0x${"ab".repeat(32)}`);
  assert.equal(captured.wallet, wallet);
  assert.equal(captured.submitted, transaction);
  assert.deepEqual(captured.options, {});

  await client.sendEvmTransaction({
    wallet,
    transaction,
    relayPayload: { payload_hash: "payload" },
    chainNowUnix: 4102444800
  });
  assert.equal(captured.options.expectedChainId, "clairveil-local-3");
  assert.equal(captured.options.accountPrefix, "clair");
  assert.equal(captured.options.expectedEvmChainId, "0x539");
  await assert.rejects(
    () => client.sendEvmTransaction({
      wallet,
      transaction,
      relayPayload: { payload_hash: "payload" },
      chainNowUnix: 4102444800,
      expectedEvmChainId: "0x1"
    }),
    /must match the active profile evmChainId/
  );
});

test("browser Cosmos transfer preserves the prepared effect for DApp confirmation", async () => {
  const client = browserClient();
  client.privacyMaterial = () => ({});
  client.proverAdapter = () => ({});
  const payload = { payload_hash: "payload-hash" };
  const proof = { payload_hash: "payload-hash", proof_hex: "proof" };
  const message = { creator: "clair1sender" };
  let received;
  client.cosmos.prepareTransfer = async input => {
    received = input;
    return ({
    status: "ready",
    signDoc: { chainId: "clairveil-local-3" },
    reservation: null,
    prepared: {
      planAction: "final_transfer",
      isFinal: true,
      amount: "1uclair",
      recipient: "clairs1recipient",
    },
    payload,
    proof,
    message,
    plan: { status: "final_transfer_ready" },
    privacyAccount: { shielded_address: "clairs1sender" },
  });
  };

  const prepared = await client.prepareTransfer({
    amount: "1uclair",
    recipient: "clairs1recipient",
    chainNowUnix: 4102444800,
    chain_now_unix: 4102444800,
    expiresAtUnix: 4102448400,
    expires_at_unix: 4102448400
  });

  assert.equal(prepared.prepared.payload, payload);
  assert.equal(prepared.prepared.proof, proof);
  assert.equal(prepared.prepared.message, message);
  assert.equal(received.chainNowUnix, 4102444800);
  assert.equal(received.expiresAtUnix, 4102448400);
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

test("browser batch disclosure, audit-query, and staged-proof wrappers delegate without dropping fields", async () => {
  const client = browserClient({ enableExperimentalBatchTransfer: true });
  const received = [];
  client.cosmos.decodeBatchUserDisclosure = async input => received.push(["user", input]) && input;
  client.cosmos.decodeBatchSelfViewDisclosure = async input => received.push(["self", input]) && input;
  client.cosmos.decodeBatchAuditDisclosure = async input => received.push(["audit", input]) && input;
  client.cosmos.fetchAuditableBatchTransfers = async input => received.push(["query", input]) && input;
  client.cosmos.provePreparedBatchTransfer = async input => received.push(["prove", input]) && input;

  const output = { output_index: 2 };
  await client.decodeBatchUserDisclosure({ output, assetDenom: "uatom", disclosureScalar: 3n });
  await client.decodeBatchSelfViewDisclosure({ output, asset_denom: "uatom", disclosure_scalar: 4n });
  await client.decodeBatchAuditDisclosure({ output, assetDenom: "uatom", disclosureScalar: 5n });
  await client.fetchAuditableBatchTransfers({
    after: { height: 7, globalSequence: 8, outputIndex: 9 }
  });
  const customProver = { proveBatchTransfer: async () => ({}) };
  const signal = new AbortController().signal;
  await client.provePreparedBatchTransfer({
    payload: { creator: "clair1sender" },
    proverAdapter: customProver,
    operationId: "batch-operation-1",
    reservation: { reservation_ids: ["reservation-1"] },
    chainNowUnix: 10,
    signal,
    onPreparedProof() {}
  });

  assert.deepEqual(received.slice(0, 3).map(([, input]) => input.output), [output, output, output]);
  assert.equal(received[0][1].assetDenom, "uatom");
  assert.equal(received[1][1].asset_denom, "uatom");
  assert.equal(received[2][1].disclosureScalar, 5n);
  assert.deepEqual(received[3][1].after, { height: 7, globalSequence: 8, outputIndex: 9 });
  assert.equal(received[4][1].proverAdapter, customProver);
  assert.equal(received[4][1].creator, "clair1sender");
  assert.equal(received[4][1].operationId, "batch-operation-1");
  assert.deepEqual(received[4][1].reservation, { reservation_ids: ["reservation-1"] });
  assert.equal(received[4][1].chainNowUnix, 10);
  assert.equal(received[4][1].signal, signal);
  assert.equal(typeof received[4][1].onPreparedProof, "function");
});

test("browser staged batch finalizer forwards the original recovery context", async () => {
  const client = browserClient({ enableExperimentalBatchTransfer: true });
  let received = null;
  client.cosmos.finalizePreparedBatchTransfer = async input => {
    received = input;
    return { signDoc: {}, reservation: {} };
  };
  const reservationManager = {};
  const reservation = { reservation_ids: ["reservation-1"] };
  const payload = { creator: "clair1sender" };
  const proof = { request_payload_hash: "payload-hash" };

  await client.finalizePreparedBatchTransfer({
    payload,
    proof,
    address: "clair1sender",
    pub_key_hex: "02".repeat(33),
    gas_limit: 123,
    fee_amount: [{ denom: "uclair", amount: "43" }],
    amounts: ["1uclair"],
    recipient: "clairs1recipient",
    operation_id: "batch-operation-1",
    reservation_manager: reservationManager,
    reservation_batch: reservation,
    chain_now_unix: 10
  });

  assert.equal(received.payload, payload);
  assert.equal(received.proof, proof);
  assert.equal(received.signer, "clair1sender");
  assert.equal(received.pubKeyHex, "02".repeat(33));
  assert.equal(received.gasLimit, 123);
  assert.deepEqual(received.fee_amount, [{ denom: "uclair", amount: "43" }]);
  assert.equal(received.userPrivacyPolicy, "all-private");
  assert.equal(received.userDisclosureMode, "none");
  assert.equal(received.operation_id, "batch-operation-1");
  assert.equal(received.reservation_manager, reservationManager);
  assert.equal(received.reservation_batch, reservation);
  assert.equal(received.chainNowUnix, 10);
});

test("browser client uses an injected prover adapter and bearer auth for the HTTP fallback", fixtureTestOptions, async () => {
  const injected = {
    proveTransfer: async () => ({}),
    proveWithdraw: async () => ({}),
    proveBatchTransfer: async () => ({})
  };
  const client = browserClient({
    proverAdapter: injected,
    proverBearerToken: "bearer-test"
  });

  assert.equal(client.proverAdapter(), injected);

  const examples = readFixture("privacy_prover_example_bundle.json");
  const originalFetch = globalThis.fetch;
  let authorization = "";
  globalThis.fetch = async (_url, init) => {
    authorization = init.headers.get("Authorization");
    return new Response(JSON.stringify(examples.transfer.response), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };

  try {
    const fallback = browserClient({
      proverUrl: "https://prover.example.invalid",
      proverBearerToken: "bearer-test"
    }).proverAdapter();
    assert.equal(typeof fallback.proveTransfer, "function");
    assert.equal(typeof fallback.proveWithdraw, "function");
    assert.equal(typeof fallback.proveBatchTransfer, "function");
    await fallback.proveTransfer(examples.transfer.request);
    assert.equal(authorization, "Bearer bearer-test");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("browser relay execution builder preserves a frozen transaction build error", async () => {
  const client = browserClient({
    evmPrivacyPrecompileAddress: "0x0000000000000000000000000000000000000900"
  });
  client.privacyMaterial = () => ({});
  client.proverAdapter = () => ({});
  const original = Object.freeze(new Error("frozen EVM transaction build failure"));
  client.evm.buildWithdrawTransaction = async () => {
    throw original;
  };
  client.cosmos.prepareRelayWithdraw = async input => input.executionBuilder({
    payload: {},
    proof: {},
    proverPayload: {},
    selectedNote: {},
    plan: {},
    reservation: null
  });

  await assert.rejects(
    () => client.prepareRelayWithdraw({
      walletType: "evm",
      amount: "1uclair",
      recipient: "clair1recipient",
      chainNowUnix: 4102444800
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

  assert.throws(
    () => client.buildRelayWithdrawMessageFromPayload({
      payload: {},
      address: "clair1relayer",
      chainNowUnix: 4102444800,
      nowUnix: 4102444801
    }),
    /chainNowUnix aliases conflict/
  );
  await assert.rejects(
    () => client.createRelayWithdrawSignDoc({
      payload: {},
      address: "clair1relayer",
      pubKeyHex: "02".padEnd(66, "0"),
      chain_now_unix: 4102444800,
      now_unix: 4102444801
    }),
    /chainNowUnix aliases conflict/
  );
});

test("browser health fails closed when a required chain query fails", async () => {
  const client = browserClient();
  client.fetchJson = async () => ({ result: { node_info: { network: "clairveil-local-3" } } });
  client.cosmos.fetchTreeState = async () => {
    throw new Error("tree endpoint unavailable");
  };
  client.cosmos.queryAuditConfig = async () => ({ audit_key_id: "audit-key-1" });

  await assert.rejects(
    () => client.health(),
    /browser health check failed: tree endpoint unavailable/
  );
});

test("endpoint-less default Cosmos browser health fails closed instead of reporting EVM", async () => {
  const client = new ClairveilBrowserClient({
    chainId: "clairveil-local-3",
    privacyStateAdapter: completePrivacyStateAdapter()
  });
  client.cosmos.fetchTreeState = async () => ({
    root: "00".repeat(32),
    leaf_count: "0",
    depth: 32,
    initialized: true,
    max_leaves: "4294967296",
    remaining_leaves: "4294967296"
  });
  client.cosmos.queryAuditConfig = async () => ({ audit_key_id: "audit-key-1" });

  await assert.rejects(
    () => client.health(),
    /browser health check failed: Cosmos RPC endpoint is required/
  );
});

test("browser health rejects a malformed tree state instead of reporting a healthy result", async () => {
  const client = browserClient();
  client.fetchJson = async () => ({ result: { node_info: { network: "clairveil-local-3" } } });
  client.cosmos.fetchTreeState = async () => ({
    root: "00".repeat(31) + "01",
    leaf_count: "1",
    depth: 32,
    initialized: true,
    max_leaves: "4294967296",
    remaining_leaves: "4294967294"
  });
  client.cosmos.queryAuditConfig = async () => ({ audit_key_id: "audit-key-1" });

  await assert.rejects(
    () => client.health(),
    /browser health check failed: tree state leaf counts are inconsistent/
  );
});

test("browser health permits only an empty uninitialized tree when explicitly requested", async () => {
  const client = browserClient();
  client.fetchJson = async () => ({ result: { node_info: { network: "clairveil-local-3" } } });
  client.cosmos.fetchTreeState = async () => ({
    root: "00".repeat(32),
    leaf_count: "0",
    depth: 32,
    initialized: false,
    max_leaves: "4294967296",
    remaining_leaves: "4294967296"
  });
  client.cosmos.queryAuditConfig = async () => ({ audit_key_id: "audit-key-1" });

  await assert.rejects(
    () => client.health(),
    /browser health check failed: tree state is not initialized/
  );
  const health = await client.health({ allowUninitializedTree: true });
  assert.equal(health.tree.initialized, false);

  client.cosmos.fetchTreeState = async () => ({
    root: "00".repeat(32),
    leaf_count: "1",
    depth: 32,
    initialized: false,
    max_leaves: "4294967296",
    remaining_leaves: "4294967295"
  });
  await assert.rejects(
    () => client.health({ allowUninitializedTree: true }),
    /browser health check failed: an uninitialized tree state must have zero leaves/
  );
});

test("browser EVM prepareTransfer preflights audit and disclosure config before scanning notes", async () => {
  const client = browserClient({
    evmChainId: "0x7a69",
    evmPrivacyPrecompileAddress: "0x0000000000000000000000000000000000000900"
  });
  client.privacyMaterial = () => ({
    rootSeed: new Uint8Array(32),
    address: "clair1sender",
    pubKeyHex: "02".padEnd(66, "0"),
    shieldedAddress: "clairs1sender"
  });
  client.cosmos.assertTransferProtocolConfig = async () => {
    throw new Error("active audit config is invalid");
  };
  client.cosmos.scanNotes = async () => {
    throw new Error("scan must not run before protocol preflight");
  };

  await assert.rejects(
    () => client.prepareTransfer({
      walletType: "evm",
      amount: "1uclair",
      recipient: validClairsRecipient
    }),
    /active audit config is invalid/
  );
});
