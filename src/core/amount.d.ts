/** Amounts cross JSON boundaries as canonical decimal strings; no JS numbers. */
export type Amount128Input = bigint | string;
export const maxShieldedAmountV2: bigint;
export const shieldedAmountBitLengthV2: 128;
export function parseAmount128(value: Amount128Input, label?: string, options?: { positive?: boolean }): bigint;
export function sumAmounts128(values: readonly Amount128Input[], label?: string): bigint;
/** Arbitrary-precision aggregate totals; does not validate individual note limits. */
export function sumAmountTotals(values: readonly (bigint | string)[]): bigint;
export function amount128ToJSON(value: Amount128Input): string;
export function amount128FromJSON(json: string): bigint;
