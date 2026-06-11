import type { ClairAddress, Hex, ShieldedAddress } from "./crypto.js";

export interface AddressPrefixOptions {
  accountPrefix?: string;
  bech32Prefix?: string;
  shieldedPrefix?: string;
}

export function assertObject(value: unknown, label?: string): object;
export function assertString(value: unknown, label?: string): string;
export function assertDecimalString(value: unknown, label?: string): string;
export function assertHex(value: unknown, byteLength?: number, label?: string): Hex;
export function assertClairAddress(value: unknown, label?: string | AddressPrefixOptions, options?: AddressPrefixOptions): ClairAddress;
export function assertShieldedAddress(value: unknown, label?: string | AddressPrefixOptions, options?: AddressPrefixOptions): ShieldedAddress;
export function assertDisclosurePubKeyHex(value: unknown, label?: string): Hex;
export function assertFoundNoteShape(value: unknown, label?: string): object;
export function assertPreparedTransferPayloadShape(value: unknown, label?: string, options?: AddressPrefixOptions): object;
export function assertPreparedWithdrawProverPayloadShape(value: unknown, label?: string, options?: AddressPrefixOptions): object;
