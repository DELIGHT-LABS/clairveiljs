import test from "node:test";
import assert from "node:assert/strict";
import {
  createClairveilClient,
  createPrivacyStateAdapter
} from "clairveiljs/cosmos-client";
import { ClairveilBrowserClient } from "clairveiljs/browser-dapp";
import { createClairveilPublicClient } from "clairveiljs/browser-public";

function completeAdapter(overrides = {}) {
  return {
    fetchPrivacyScan: async () => ({ scanSchemaVersion: "unsupported" }),
    fetchTreeState: async () => ({ root: "11".repeat(32) }),
    fetchCommitmentInfo: async commitment => ({ commitment }),
    lookupMerklePath: async commitment => ({ commitment, siblings: [] }),
    fetchAuditConfig: async () => ({}),
    fetchDisclosureConfig: async () => ({}),
    fetchCircuitConfig: async () => ({}),
    fetchReserve: async denom => ({ denom }),
    fetchAssetByDenom: async denom => ({ denom }),
    fetchAssetByID: async assetId => ({ assetId }),
    fetchCommitmentPathsAtRoot: async request => ({ request }),
    checkNullifiers: async nullifiers => new Map(nullifiers.map(value => [value, false])),
    ...overrides
  };
}

test("PrivacyStateAdapter supports a privacy-only client without Cosmos RPC or REST", async () => {
  const calls = [];
  const adapter = completeAdapter({
    async fetchTreeState() {
      calls.push(this.marker);
      return { root: "22".repeat(32) };
    },
    marker: "bound-adapter"
  });
  const client = createClairveilClient({
    chainId: "evm-only-1",
    privacyStateAdapter: adapter
  });

  assert.equal(client.rpc, "");
  assert.deepEqual(client.restEndpoints, []);
  assert.deepEqual(await client.fetchTreeState(), { root: "22".repeat(32) });
  assert.deepEqual(calls, ["bound-adapter"]);

  const nullifier = "ab".repeat(32);
  assert.deepEqual(await client.checkNullifiers([nullifier]), new Map([[nullifier, false]]));
  await assert.rejects(() => client.connect(), /rpc endpoint is required for Cosmos/);
});

test("browser wallet and public facades use PrivacyStateAdapter without Clairveil REST", async () => {
  const adapter = completeAdapter({
    fetchTreeState: async () => ({ root: "33".repeat(32) })
  });
  const walletClient = new ClairveilBrowserClient({
    transport: "evm",
    chainId: "evm-only-1",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair",
    evmRpc: "http://127.0.0.1:8545",
    evmChainId: "0x1",
    evmPrivacyPrecompileAddress: "0x0000000000000000000000000000000000000900",
    privacyStateAdapter: adapter
  });
  const publicClient = createClairveilPublicClient({ privacyStateAdapter: adapter });

  assert.equal(walletClient.profileTransport, "evm");
  assert.deepEqual(await walletClient.fetchTreeState(), { root: "33".repeat(32) });
  assert.deepEqual(await publicClient.fetchTreeState(), { root: "33".repeat(32) });
  assert.deepEqual(publicClient.restEndpoints, []);
});

test("an EVM runtime profile may omit Cosmos endpoints only with PrivacyStateAdapter", async () => {
  const profile = {
    id: "evm-adapter-only",
    label: "EVM adapter only",
    chainName: "EVM adapter only",
    chainId: "evm-only-1",
    transport: "evm",
    wallet: "metamask",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair",
    displayDenom: "CLAIR",
    coinDecimals: 6,
    proverUrl: "https://prover.example",
    evmRpc: "https://evm.example",
    evmChainId: "0x539",
    evmChainName: "EVM adapter only",
    evmPrivacyPrecompileAddress: "0x0000000000000000000000000000000000000900",
    evmNativeDenom: "uclair",
    evmGasLimit: "0x989680",
    evmSendGasLimit: "0x5208"
  };
  const client = new ClairveilBrowserClient({
    profile,
    privacyStateAdapter: completeAdapter({
      fetchTreeState: async () => ({ root: "44".repeat(32) })
    })
  });

  assert.equal(client.profileTransport, "evm");
  assert.equal(client.rpc, "");
  assert.deepEqual(client.restEndpoints, []);
  assert.deepEqual(await client.fetchTreeState(), { root: "44".repeat(32) });
  assert.throws(
    () => new ClairveilBrowserClient({ profile }),
    /profile\.rpc must be a string/
  );
});

test("PrivacyStateAdapter responses still pass through typed fail-closed validation", async () => {
  const client = createClairveilClient({
    chainId: "evm-only-1",
    privacyStateAdapter: completeAdapter()
  });

  await assert.rejects(
    () => client.queryPrivacyScan({ outputLimit: 1 }),
    /privacy-scan-v2|scan schema/i
  );
});

test("PrivacyStateAdapter requires the complete canonical state capability set", () => {
  assert.throws(
    () => createPrivacyStateAdapter({ fetchPrivacyScan() {} }),
    /missing required methods:.*fetchTreeState.*checkNullifiers/
  );
});

test("PrivacyStateAdapter nullifier responses fail closed when a status is missing or conflicting", async () => {
  const first = "01".repeat(32);
  const second = "02".repeat(32);
  const missing = createClairveilClient({
    chainId: "evm-only-1",
    privacyStateAdapter: completeAdapter({
      checkNullifiers: async () => new Map([[first, false]])
    })
  });
  await assert.rejects(
    () => missing.checkNullifiers([first, second]),
    new RegExp(second)
  );

  const conflicting = createClairveilClient({
    chainId: "evm-only-1",
    privacyStateAdapter: completeAdapter({
      checkNullifiers: async () => ({
        statuses: [
          { nullifier: first, used: false },
          { nullifier: first, used: true }
        ]
      })
    })
  });
  await assert.rejects(
    () => conflicting.checkNullifiers([first]),
    /unambiguous status/
  );

  const conflictingListAliases = createClairveilClient({
    chainId: "evm-only-1",
    privacyStateAdapter: completeAdapter({
      checkNullifiers: async () => ({
        statuses: [{ nullifier: first, used: false }],
        Statuses: [{ Nullifier: first.toUpperCase(), Used: true }]
      })
    })
  });
  await assert.rejects(
    () => conflictingListAliases.checkNullifiers([first]),
    /unambiguous status/
  );

  let emptyCalls = 0;
  const empty = createClairveilClient({
    chainId: "evm-only-1",
    privacyStateAdapter: completeAdapter({
      checkNullifiers: async () => {
        emptyCalls += 1;
        throw new Error("empty nullifier queries must not cross the adapter boundary");
      }
    })
  });
  assert.deepEqual(await empty.checkNullifiers([]), new Map());
  assert.equal(emptyCalls, 0);
});

test("PrivacyStateAdapter nullifier reads preserve the canonical 1000-item batch limit", async () => {
  const nullifiers = Array.from({ length: 1001 }, (_, index) =>
    (index + 1).toString(16).padStart(64, "0")
  );
  for (const createClient of [
    adapter => createClairveilClient({ chainId: "evm-only-1", privacyStateAdapter: adapter }),
    adapter => createClairveilPublicClient({ privacyStateAdapter: adapter })
  ]) {
    const calls = [];
    const client = createClient(completeAdapter({
      async checkNullifiers(chunk) {
        calls.push([...chunk]);
        return new Map(chunk.map(nullifier => [nullifier, false]));
      }
    }));
    const statuses = await client.checkNullifiers(nullifiers);
    assert.deepEqual(calls.map(chunk => chunk.length), [1000, 1]);
    assert.equal(statuses.size, 1001);
    assert.equal(statuses.get(nullifiers[1000]), false);
  }
});

test("PrivacyStateAdapter cannot mutate the SDK nullifier expectation or caller scan cursor", async () => {
  const first = "05".repeat(32);
  const second = "06".repeat(32);
  const scanRequest = {
    after: { height: 9, globalSequence: 3, outputIndex: 1 },
    outputLimit: 1
  };
  const client = createClairveilClient({
    chainId: "evm-only-1",
    privacyStateAdapter: completeAdapter({
      async checkNullifiers(nullifiers) {
        nullifiers.pop();
        return new Map([[first, false]]);
      },
      async fetchPrivacyScan(request) {
        request.after.height = 0;
        return { scanSchemaVersion: "unsupported" };
      }
    })
  });

  await assert.rejects(
    () => client.checkNullifiers([first, second]),
    new RegExp(second)
  );
  await assert.rejects(
    () => client.queryPrivacyScan(scanRequest),
    /privacy-scan-v2|scan schema/i
  );
  assert.deepEqual(scanRequest.after, { height: 9, globalSequence: 3, outputIndex: 1 });
});

test("PrivacyStateAdapter single-nullifier booleans normalize to the public result shape", async () => {
  const nullifier = "07".repeat(32);
  const client = createClairveilClient({
    chainId: "evm-only-1",
    privacyStateAdapter: completeAdapter({
      checkNullifier: async () => false
    })
  });

  assert.deepEqual(await client.checkNullifier(nullifier), {
    nullifier,
    used: false
  });
});

test("PrivacyStateAdapter reads use bounded same-adapter retry", async () => {
  let treeAttempts = 0;
  const publicClient = createClairveilPublicClient({
    queryTimeoutMs: 50,
    queryRetry: { retries: 1, baseDelayMs: 0, maxDelayMs: 0, jitter: false },
    privacyStateAdapter: completeAdapter({
      async fetchTreeState() {
        treeAttempts += 1;
        if (treeAttempts === 1) throw new Error("transient indexer error");
        return { root: "55".repeat(32) };
      }
    })
  });
  assert.deepEqual(await publicClient.fetchTreeState(), { root: "55".repeat(32) });
  assert.equal(treeAttempts, 2);

  const nullifier = "03".repeat(32);
  let nullifierAttempts = 0;
  const walletClient = createClairveilClient({
    chainId: "evm-only-1",
    queryTimeoutMs: 50,
    queryRetry: { retries: 1, baseDelayMs: 0, maxDelayMs: 0, jitter: false },
    privacyStateAdapter: completeAdapter({
      async checkNullifiers(nullifiers) {
        nullifierAttempts += 1;
        if (nullifierAttempts === 1) throw new Error("transient contract read error");
        return new Map(nullifiers.map(value => [value, false]));
      }
    })
  });
  assert.deepEqual(await walletClient.checkNullifiers([nullifier]), new Map([[nullifier, false]]));
  assert.equal(nullifierAttempts, 2);
});

test("PrivacyStateAdapter reads time out instead of hanging wallet or public clients", async () => {
  const adapter = completeAdapter({
    fetchTreeState: async () => new Promise(() => {}),
    checkNullifiers: async () => new Promise(() => {})
  });
  const walletClient = createClairveilClient({
    chainId: "evm-only-1",
    queryTimeoutMs: 5,
    queryRetry: false,
    privacyStateAdapter: adapter
  });
  const publicClient = createClairveilPublicClient({
    queryTimeoutMs: 5,
    queryRetry: false,
    privacyStateAdapter: adapter
  });

  await assert.rejects(
    () => walletClient.checkNullifiers(["04".repeat(32)]),
    /PrivacyStateAdapter\.checkNullifiers timed out after 5ms/
  );
  await assert.rejects(
    () => publicClient.fetchTreeState(),
    /PrivacyStateAdapter\.fetchTreeState timed out after 5ms/
  );
});
