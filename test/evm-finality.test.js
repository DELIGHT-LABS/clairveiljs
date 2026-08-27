import test from "node:test";
import assert from "node:assert/strict";
import {
  createEvmFinalityPolicy,
  waitForEvmFinality
} from "clairveiljs/evm-finality";

const txHash = `0x${"ab".repeat(32)}`;
const blockHash = `0x${"cd".repeat(32)}`;
const otherBlockHash = `0x${"ef".repeat(32)}`;

function receipt(overrides = {}) {
  return {
    transactionHash: txHash,
    status: "0x1",
    blockNumber: "0xa",
    blockHash,
    ...overrides
  };
}

test("receipt finality policy preserves the explicit low-finality compatibility mode", async () => {
  const evidence = await waitForEvmFinality({
    txHash,
    receipt: receipt(),
    rpc: async () => { throw new Error("receipt policy must not query another block"); },
    policy: "receipt"
  });

  assert.equal(evidence.verified, true);
  assert.equal(evidence.mode, "receipt");
  assert.equal(evidence.blockHash, blockHash);
});

test("EVM finality has no implicit policy and receipt mode requires mined block identity", async () => {
  assert.throws(
    () => createEvmFinalityPolicy(),
    /evmFinalityPolicy must be a policy object or mode string/
  );
  await assert.rejects(
    () => waitForEvmFinality({
      txHash,
      receipt: receipt(),
      rpc: async () => null
    }),
    /evmFinalityPolicy must be a policy object or mode string/
  );
  const evidence = await waitForEvmFinality({
    txHash,
    receipt: receipt({ blockHash: undefined }),
    rpc: async () => null,
    policy: "receipt"
  });
  assert.equal(evidence.verified, false);
  assert.match(evidence.error, /blockHash/);
});

test("confirmation-depth finality waits for depth and rechecks canonical receipt identity", async () => {
  let headReads = 0;
  const calls = [];
  const rpc = async (method, params) => {
    calls.push([method, params]);
    if (method === "eth_blockNumber") return headReads++ === 0 ? "0xa" : "0xb";
    if (method === "eth_getTransactionReceipt") return receipt();
    if (method === "eth_getBlockByNumber") return { number: "0xa", hash: blockHash };
    throw new Error(`unexpected method ${method}`);
  };

  const evidence = await waitForEvmFinality({
    txHash,
    receipt: receipt(),
    rpc,
    policy: { mode: "confirmations", confirmations: 2 },
    attempts: 2,
    intervalMs: 0
  });

  assert.equal(evidence.verified, true);
  assert.equal(evidence.confirmations, 2);
  assert.equal(evidence.finalityBlockNumber, "0xb");
  assert.equal(calls.filter(([method]) => method === "eth_blockNumber").length, 2);
  assert.ok(calls.some(([method, params]) => method === "eth_getBlockByNumber" && params[0] === "0xa"));
});

test("built-in finality retries transient RPC failures within the configured bound", async () => {
  let headReads = 0;
  const rpc = async (method, params) => {
    if (method === "eth_blockNumber") {
      headReads += 1;
      if (headReads === 1) throw new Error("temporary RPC outage");
      return "0xb";
    }
    if (method === "eth_getTransactionReceipt") return receipt();
    if (method === "eth_getBlockByNumber" && params[0] === "0xa") {
      return { number: "0xa", hash: blockHash };
    }
    throw new Error(`unexpected method ${method}`);
  };

  const evidence = await waitForEvmFinality({
    txHash,
    receipt: receipt(),
    rpc,
    policy: { mode: "confirmations", confirmations: 2 },
    attempts: 2,
    intervalMs: 0
  });

  assert.equal(evidence.verified, true);
  assert.equal(headReads, 2);
});

test("safe/finalized policies reject a receipt whose inclusion block was reorganized", async () => {
  const evidence = await waitForEvmFinality({
    txHash,
    receipt: receipt(),
    rpc: async (method, params) => {
      if (method === "eth_getBlockByNumber" && params[0] === "safe") {
        return { number: "0xb", hash: otherBlockHash };
      }
      if (method === "eth_getBlockByNumber") return { number: "0xa", hash: otherBlockHash };
      if (method === "eth_getTransactionReceipt") return receipt();
      throw new Error(`unexpected method ${method}`);
    },
    policy: { mode: "safe" },
    attempts: 1,
    intervalMs: 0
  });

  assert.equal(evidence.verified, false);
  assert.match(evidence.error, /no longer canonical|reorg/i);
});

test("custom finality evidence is bound to the submitted transaction and receipt block", async () => {
  const policy = createEvmFinalityPolicy({
    mode: "custom",
    waitForFinality: async () => ({
      verified: true,
      mode: "custom",
      txHash: `0x${"12".repeat(32)}`,
      blockHash
    })
  });
  const evidence = await waitForEvmFinality({
    txHash,
    receipt: receipt(),
    rpc: async () => null,
    policy
  });

  assert.equal(evidence.verified, false);
  assert.match(evidence.error, /different transaction/);

  const wrongBlockEvidence = await waitForEvmFinality({
    txHash,
    receipt: receipt(),
    rpc: async () => null,
    policy: {
      mode: "custom",
      waitForFinality: async () => ({
        verified: true,
        mode: "custom",
        txHash,
        blockHash: otherBlockHash
      })
    }
  });
  assert.equal(wrongBlockEvidence.verified, false);
  assert.match(wrongBlockEvidence.error, /different inclusion block/);
});
