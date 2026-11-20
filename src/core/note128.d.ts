import type { Amount128Input } from "./amount.js";
import type { Point } from "./crypto.js";
import type { NoteFields } from "../privacy/protocol-fields.js";

export interface Note128 extends NoteFields {}
export type Note128Input = { [K in Exclude<keyof Note128, "memo">]: string | bigint } & { memo?: string };
export type NullifierStatus128 = "spent" | "unspent" | "unknown" | "unverified";
export interface FoundNote128Input {
  note: Note128Input;
  nullifier: string;
  nullifierStatus?: NullifierStatus128;
  isSpent?: boolean;
  txHash?: string;
  height?: number | string | bigint;
  sequence?: number | string | bigint;
}
export interface NormalizedFoundNote128 {
  note: Note128;
  nullifier: string;
  nullifierStatus: NullifierStatus128;
  isSpent: boolean;
  txHash: string;
  height: string;
  sequence: string;
}
/** Validates the uint128 amount/field model, not fixed-v2 cryptographic validity. */
export function createNote128(input: {
  spendPubKey: Point; viewPubKey: Point; amount: Amount128Input;
  assetDenom?: string; assetId?: string | bigint; randomness?: string | bigint; memo?: string;
}): Note128;
export function normalizeNote128(note: Note128Input): Note128;
/** Canonical fields only. Missing status remains unverified; heights use decimal strings. */
export function normalizeFoundNote128(found: FoundNote128Input): NormalizedFoundNote128;
