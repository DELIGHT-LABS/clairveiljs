const transactionHashPattern = /^0x[0-9a-fA-F]{64}$/;
const blockHashPattern = /^0x[0-9a-fA-F]{64}$/;
const quantityPattern = /^0x[0-9a-fA-F]+$/;
const terminalCanonicalConflict = Symbol("clairveil.evm-finality-terminal-canonical-conflict");

export const evmFinalityModes = Object.freeze([
  "receipt",
  "confirmations",
  "safe",
  "finalized",
  "custom"
]);

function transactionHash(value, label = "EVM transaction hash") {
  const normalized = String(value || "").trim().toLowerCase();
  if (!transactionHashPattern.test(normalized)) {
    throw new Error(`${label} must be a 32-byte 0x-prefixed hash`);
  }
  return normalized;
}

function blockHash(value, label = "EVM block hash") {
  const normalized = String(value || "").trim().toLowerCase();
  if (!blockHashPattern.test(normalized)) {
    throw new Error(`${label} must be a 32-byte 0x-prefixed hash`);
  }
  return normalized;
}

function quantity(value, label) {
  const normalized = String(value ?? "").trim();
  if (!quantityPattern.test(normalized)) {
    throw new Error(`${label} must be an EVM quantity`);
  }
  return BigInt(normalized);
}

function canonicalQuantity(value) {
  return `0x${value.toString(16)}`;
}

function positiveInteger(value, label) {
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 1) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return normalized;
}

function receiptSucceeded(status) {
  try {
    return quantity(status, "EVM receipt status") === 1n;
  } catch {
    return false;
  }
}

function sleep(ms) {
  return ms > 0 ? new Promise(resolve => setTimeout(resolve, ms)) : Promise.resolve();
}

function canonicalConflict(message) {
  const error = new Error(message);
  Object.defineProperty(error, terminalCanonicalConflict, { value: true });
  return error;
}

/** Normalize a built-in or downstream custom EVM finality policy. */
export function createEvmFinalityPolicy(input) {
  const policy = typeof input === "string" ? { mode: input } : input;
  if (!policy || typeof policy !== "object") {
    throw new TypeError("evmFinalityPolicy must be a policy object or mode string");
  }
  const customWait = policy.waitForFinality ?? policy.wait_for_finality;
  const mode = String(policy.mode ?? (typeof customWait === "function" ? "custom" : "")).trim();
  if (!mode) {
    throw new TypeError("evmFinalityPolicy.mode is required");
  }
  if (!evmFinalityModes.includes(mode)) {
    throw new Error(`unsupported EVM finality mode ${JSON.stringify(mode)}`);
  }
  if (mode === "custom") {
    if (typeof customWait !== "function") {
      throw new TypeError("custom EVM finality policy requires waitForFinality");
    }
    return Object.freeze({ mode, waitForFinality: customWait.bind(policy) });
  }
  if (customWait != null) {
    throw new TypeError("waitForFinality is only permitted for custom EVM finality policies");
  }
  if (mode === "confirmations") {
    return Object.freeze({
      mode,
      confirmations: positiveInteger(policy.confirmations, "evmFinalityPolicy.confirmations")
    });
  }
  if (policy.confirmations != null) {
    throw new TypeError("confirmations is only permitted for confirmations finality mode");
  }
  return Object.freeze({ mode });
}

function failure(policy, txHashValue, error, fields = {}) {
  return Object.freeze({
    verified: false,
    mode: policy.mode,
    txHash: txHashValue,
    ...fields,
    error: String(error?.message || error || "EVM finality verification failed")
  });
}

function receiptBlockIdentity(receipt) {
  return {
    blockNumber: quantity(receipt?.blockNumber, "EVM receipt blockNumber"),
    blockHash: blockHash(receipt?.blockHash, "EVM receipt blockHash")
  };
}

async function verifyCanonicalInclusion({ rpc, txHash: txHashValue, receipt, expectedBlock }) {
  const [currentReceipt, canonicalBlock] = await Promise.all([
    rpc("eth_getTransactionReceipt", [txHashValue]),
    rpc("eth_getBlockByNumber", [canonicalQuantity(expectedBlock.blockNumber), false])
  ]);
  if (!currentReceipt) throw new Error("EVM receipt disappeared before finality");
  if (transactionHash(currentReceipt.transactionHash, "refetched EVM receipt transactionHash") !== txHashValue) {
    throw canonicalConflict("refetched EVM receipt transaction hash changed before finality");
  }
  if (!receiptSucceeded(currentReceipt.status)) {
    throw canonicalConflict("refetched EVM receipt is not successful");
  }
  const currentBlock = receiptBlockIdentity(currentReceipt);
  if (currentBlock.blockNumber !== expectedBlock.blockNumber || currentBlock.blockHash !== expectedBlock.blockHash) {
    throw canonicalConflict("EVM receipt block identity changed before finality (possible reorg)");
  }
  if (!canonicalBlock) throw new Error("canonical EVM inclusion block is unavailable");
  if (blockHash(canonicalBlock.hash, "canonical EVM block hash") !== expectedBlock.blockHash) {
    throw canonicalConflict("EVM receipt block is no longer canonical (reorg detected)");
  }
  if (quantity(canonicalBlock.number, "canonical EVM block number") !== expectedBlock.blockNumber) {
    throw canonicalConflict("canonical EVM block number does not match the receipt");
  }
  const originalBlock = receiptBlockIdentity(receipt);
  if (originalBlock.blockNumber !== currentBlock.blockNumber || originalBlock.blockHash !== currentBlock.blockHash) {
    throw canonicalConflict("original EVM receipt block identity changed before finality");
  }
  return currentReceipt;
}

/**
 * Wait for the selected finality policy and re-check canonical block identity.
 * Built-in safe/finalized/depth modes fail closed on a receipt move or reorg.
 */
export async function waitForEvmFinality({
  txHash: txHashInput,
  receipt,
  rpc,
  policy,
  attempts = 30,
  intervalMs = 1000
} = {}) {
  const normalizedPolicy = createEvmFinalityPolicy(policy);
  const txHashValue = transactionHash(txHashInput);
  if (typeof rpc !== "function") throw new TypeError("EVM finality requires an RPC query function");
  if (!receipt || typeof receipt !== "object") {
    return failure(normalizedPolicy, txHashValue, "EVM receipt is required for finality verification");
  }
  try {
    if (transactionHash(receipt.transactionHash, "EVM receipt transactionHash") !== txHashValue) {
      throw new Error("EVM receipt transaction hash does not match the requested transaction");
    }
    if (!receiptSucceeded(receipt.status)) {
      throw new Error("EVM receipt must contain an explicit successful status before finality");
    }
  } catch (error) {
    return failure(normalizedPolicy, txHashValue, error);
  }

  if (normalizedPolicy.mode === "receipt") {
    let identity;
    try {
      identity = receiptBlockIdentity(receipt);
    } catch (error) {
      return failure(normalizedPolicy, txHashValue, error);
    }
    return Object.freeze({
      verified: true,
      mode: normalizedPolicy.mode,
      txHash: txHashValue,
      blockNumber: canonicalQuantity(identity.blockNumber),
      blockHash: identity.blockHash
    });
  }

  if (normalizedPolicy.mode === "custom") {
    try {
      const result = await normalizedPolicy.waitForFinality(Object.freeze({
        txHash: txHashValue,
        receipt,
        rpc,
        attempts,
        intervalMs
      }));
      if (!result || typeof result !== "object" || result.verified !== true) {
        throw new Error(result?.error || "custom EVM finality policy did not verify the transaction");
      }
      if (result.txHash != null && transactionHash(result.txHash, "custom finality txHash") !== txHashValue) {
        throw new Error("custom EVM finality evidence references a different transaction");
      }
      if (result.blockHash != null && receipt.blockHash != null &&
          blockHash(result.blockHash, "custom finality blockHash") !== blockHash(receipt.blockHash, "EVM receipt blockHash")) {
        throw new Error("custom EVM finality evidence references a different inclusion block");
      }
      return Object.freeze({ ...result, verified: true, mode: "custom", txHash: txHashValue });
    } catch (error) {
      return failure(normalizedPolicy, txHashValue, error);
    }
  }

  let expectedBlock;
  try {
    expectedBlock = receiptBlockIdentity(receipt);
  } catch (error) {
    return failure(normalizedPolicy, txHashValue, error);
  }
  const maxAttempts = positiveInteger(attempts, "finality attempts");
  const delay = Number(intervalMs);
  if (!Number.isFinite(delay) || delay < 0) {
    throw new Error("finality intervalMs must be a non-negative finite number");
  }

  let lastError = null;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      let finalityBlock;
      if (normalizedPolicy.mode === "confirmations") {
        const head = quantity(await rpc("eth_blockNumber", []), "EVM latest block number");
        const requiredHead = expectedBlock.blockNumber + BigInt(normalizedPolicy.confirmations - 1);
        if (head >= requiredHead) finalityBlock = head;
      } else {
        const taggedBlock = await rpc("eth_getBlockByNumber", [normalizedPolicy.mode, false]);
        if (taggedBlock) {
          const taggedNumber = quantity(taggedBlock.number, `${normalizedPolicy.mode} EVM block number`);
          if (taggedNumber >= expectedBlock.blockNumber) finalityBlock = taggedNumber;
        }
      }

      if (finalityBlock != null) {
        await verifyCanonicalInclusion({
          rpc,
          txHash: txHashValue,
          receipt,
          expectedBlock
        });
        return Object.freeze({
          verified: true,
          mode: normalizedPolicy.mode,
          txHash: txHashValue,
          blockNumber: canonicalQuantity(expectedBlock.blockNumber),
          blockHash: expectedBlock.blockHash,
          finalityBlockNumber: canonicalQuantity(finalityBlock),
          ...(normalizedPolicy.mode === "confirmations"
            ? { confirmations: normalizedPolicy.confirmations }
            : { blockTag: normalizedPolicy.mode })
        });
      }
    } catch (error) {
      lastError = error;
      if (error?.[terminalCanonicalConflict]) {
        return failure(normalizedPolicy, txHashValue, error, {
          blockNumber: canonicalQuantity(expectedBlock.blockNumber),
          blockHash: expectedBlock.blockHash
        });
      }
    }
    if (attempt + 1 < maxAttempts) await sleep(delay);
  }
  return failure(
    normalizedPolicy,
    txHashValue,
    lastError
      ? `EVM ${normalizedPolicy.mode} finality verification failed after ${maxAttempts} attempts: ${lastError.message}`
      : `EVM transaction did not reach ${normalizedPolicy.mode} finality within ${maxAttempts} attempts`,
    {
      blockNumber: canonicalQuantity(expectedBlock.blockNumber),
      blockHash: expectedBlock.blockHash
    }
  );
}
