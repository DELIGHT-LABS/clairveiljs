import { maxShieldedAmountV2, parseAmount128 } from "../core/amount.js";
import { sha256Hex, utf8Bytes } from "../core/browser-crypto.js";
import { canonicalAssetDenomV1 } from "./asset-denom.js";
import { normalizePayrollInputWithPolicy, planOneProofPayrollWithPolicy } from "./payroll-planning.js";

const amountPolicy = Object.freeze({
  amountModel: "uint128", parse: parseAmount128,
  maximum: maxShieldedAmountV2, transactionMaximum: maxShieldedAmountV2,
  hash(denom, amount) {
    return sha256Hex(utf8Bytes(`${canonicalAssetDenomV1(denom)}:${parseAmount128(amount)}`));
  }
});

export function normalizePayrollInputV2(input = {}, options = {}) {
  return normalizePayrollInputWithPolicy(input, options, amountPolicy);
}

/** Amount eligibility only; proof preparation must supply its validated circuit identity. */
export function planOneProofPayrollV2(input, treasuryNotes = [], options = {}) {
  return planOneProofPayrollWithPolicy(input, treasuryNotes, options, amountPolicy);
}
