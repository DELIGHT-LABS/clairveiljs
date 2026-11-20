/** Core v0.6.1 shielded note and single-operation amount boundary. */
export const maxShieldedAmountV2 = (1n << 128n) - 1n;
export const shieldedAmountBitLengthV2 = 128;

function canonicalAmount(value, label) {
  if (typeof value === "bigint" && value >= 0n) return value;
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical non-negative decimal string or bigint`);
  }
  return BigInt(value);
}

export function parseAmount128(value, label = "amount", { positive = false } = {}) {
  const amount = canonicalAmount(value, label);
  if (amount > maxShieldedAmountV2) throw new Error(`${label} exceeds the uint128 shielded amount limit`);
  if (positive && amount === 0n) throw new Error(`${label} must be positive`);
  return amount;
}

/** Bound each note and the aggregate for ONE transaction, including change. */
export function sumAmounts128(values, label = "transaction amount total") {
  if (!Array.isArray(values)) throw new Error("transaction amounts must be an array");
  let total = 0n;
  for (const value of values) total = parseAmount128(total + parseAmount128(value, label), label);
  return total;
}

/** Wallet/payroll/cumulative totals have no uint128 cap. Validate notes separately. */
export function sumAmountTotals(values) {
  if (!Array.isArray(values)) throw new Error("aggregate amounts must be an array");
  let total = 0n;
  for (const value of values) total += canonicalAmount(value, "aggregate amount");
  return total;
}

export function amount128ToJSON(value) {
  return JSON.stringify(parseAmount128(value).toString());
}

export function amount128FromJSON(json) {
  if (typeof json !== "string") throw new Error("amount JSON must be a string");
  const value = JSON.parse(json);
  if (typeof value !== "string") throw new Error("amount JSON must contain a decimal string, never a number");
  return parseAmount128(value);
}
