import { parseCoin } from "../core/note.js";

const provided = value => value !== undefined && value !== null;

export const aliasedValueProvided = (camelValue, snakeValue) =>
  provided(camelValue) || provided(snakeValue);

export function resolveAliasedString(camelValue, snakeValue, name) {
  const hasCamel = provided(camelValue);
  const hasSnake = provided(snakeValue);
  if (hasCamel && hasSnake && String(camelValue) !== String(snakeValue)) {
    throw new Error(`${name} aliases conflict`);
  }
  return String(hasCamel ? camelValue : hasSnake ? snakeValue : "");
}

export function resolveDirectOperationEvidenceHashes({
  expectedRecipientHash,
  expected_recipient_hash,
  expectedAmountHash,
  expected_amount_hash
} = {}) {
  const recipientProvided = aliasedValueProvided(expectedRecipientHash, expected_recipient_hash);
  const amountProvided = aliasedValueProvided(expectedAmountHash, expected_amount_hash);
  const recipientHash = resolveAliasedString(
    expectedRecipientHash,
    expected_recipient_hash,
    "expectedRecipientHash"
  );
  const amountHash = resolveAliasedString(
    expectedAmountHash,
    expected_amount_hash,
    "expectedAmountHash"
  );
  if (recipientProvided !== amountProvided) {
    throw new Error("expected recipient hash and expected amount hash must be provided together");
  }
  if (recipientProvided && !recipientHash.trim()) {
    throw new Error("expectedRecipientHash must not be empty");
  }
  if (amountProvided && !amountHash.trim()) {
    throw new Error("expectedAmountHash must not be empty");
  }
  return {
    provided: recipientProvided,
    expectedRecipientHash: recipientHash,
    expectedAmountHash: amountHash
  };
}

export function normalizeCosmosFeeCoins(value, label = "feeAmount") {
  if (value == null) return Object.freeze([]);
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  const coins = value.map((coin, index) => {
    if (!coin || typeof coin !== "object" || Array.isArray(coin)) {
      throw new Error(`${label}[${index}] must be a Cosmos coin`);
    }
    const denom = String(coin.denom ?? "").trim();
    const amount = String(coin.amount ?? "").trim();
    if (!/^[A-Za-z][A-Za-z0-9/:._-]{2,127}$/.test(denom)) {
      throw new Error(`${label}[${index}].denom must be a valid Cosmos SDK denomination`);
    }
    if (!/^(0|[1-9][0-9]*)$/.test(amount)) {
      throw new Error(`${label}[${index}].amount must be a canonical non-negative integer string`);
    }
    return Object.freeze({ denom, amount });
  }).sort((left, right) => left.denom < right.denom ? -1 : left.denom > right.denom ? 1 : 0);
  if (coins.some((coin, index) => index > 0 && coin.denom === coins[index - 1].denom)) {
    throw new Error(`${label} must not contain duplicate denominations`);
  }
  return Object.freeze(coins);
}

export function resolveCosmosFeeAmount(feeAmount, fee_amount) {
  const camel = provided(feeAmount) ? normalizeCosmosFeeCoins(feeAmount, "feeAmount") : null;
  const snake = provided(fee_amount) ? normalizeCosmosFeeCoins(fee_amount, "fee_amount") : null;
  if (camel && snake && JSON.stringify(camel) !== JSON.stringify(snake)) {
    throw new Error("feeAmount aliases conflict");
  }
  return camel || snake || Object.freeze([]);
}

function normalizeCosmosGasLimit(value, label) {
  const normalized = typeof value === "bigint"
    ? value > 0n && value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : NaN
    : value;
  if (typeof normalized !== "number" || !Number.isSafeInteger(normalized) || normalized <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return normalized;
}

export function resolveCosmosGasLimit(gasLimit, gas_limit, fallback) {
  const camel = provided(gasLimit) ? normalizeCosmosGasLimit(gasLimit, "gasLimit") : null;
  const snake = provided(gas_limit) ? normalizeCosmosGasLimit(gas_limit, "gas_limit") : null;
  if (camel !== null && snake !== null && camel !== snake) {
    throw new Error("gasLimit aliases conflict");
  }
  return camel ?? snake ?? normalizeCosmosGasLimit(fallback, "default gasLimit");
}

export function transferProofReadyMetadata(built, context = {}, bindingField) {
  const output = built?.payload?.outputs?.[0] || {};
  const coin = context.amount ? parseCoin(context.amount, context.denom || "") : null;
  const itemIndex = context.batchItemIndex ?? context.batch_item_index;
  const itemIndexKnown = context.batchItemIndexKnown ?? context.batch_item_index_known;
  const expectedOutputCommitment = output.commitment_hex || "";
  const expectedDisclosureDigest = built?.payload?.audit_disclosure_digest_hex || "";
  const expectedRecipientHash = context.expectedRecipientHash ?? context.expected_recipient_hash ?? "";
  const expectedAmount = output.amount || coin?.amount || "";
  const expectedAmountHash = context.expectedAmountHash ?? context.expected_amount_hash ?? "";
  const expectedDenom = context.expectedDenom ?? context.expected_denom ?? coin?.denom ?? context.denom ?? "";
  const operationSuccessEvidenceRequired = Boolean(
    expectedOutputCommitment && expectedDisclosureDigest && expectedRecipientHash &&
    expectedAmount && expectedAmountHash && expectedDenom
  );
  const snakeBindingField = bindingField === "signDocHash" ? "sign_doc_hash" : "tx_bytes_hash";
  return {
    payloadHash: built?.payload?.payload_hash || "",
    [bindingField]: context[bindingField] ?? context[snakeBindingField] ?? "",
    expectedOutputCommitment,
    expectedDisclosureDigest,
    expectedRecipientHash,
    expectedAmount,
    expectedAmountHash,
    expectedDenom,
    batchItemIndex: itemIndex ?? 0,
    batchItemIndexKnown: itemIndexKnown ?? (
      operationSuccessEvidenceRequired || (itemIndex !== undefined && itemIndex !== null)
    ),
    operationSuccessEvidenceRequired
  };
}
