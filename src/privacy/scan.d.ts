import type { BytesLike, Hex } from "../core/crypto.js";
import type { FoundNote, NormalizedFoundNote } from "../core/note.js";

export interface ScanResult {
  notes: Array<{
    index: number;
    status: "spendable" | "spent" | "unverified";
    nullifier_status: "spent" | "unspent" | "unknown" | "unverified";
    amount: string;
    nullifier: Hex;
    tx_hash: Hex;
    height: number | string;
    sequence: number | string;
  }>;
  summary: {
    total_spendable: string;
    spendable_count: number;
    spent_count: number;
    total_count: number;
  };
  diagnostics: {
    scanned_events: number;
    new_notes_found: number;
    pages_scanned?: number;
    max_pages?: number;
    unverified_nullifier_count?: number;
  };
  foundNotes?: NormalizedFoundNote[];
}

export function parseNoteBytes(bytes: BytesLike): object;
export function parseNullifierUsage(value: unknown): boolean | null;
export function processPrivacyEvent(event: object, input: { rootSeed?: BytesLike; spendScalar?: bigint; viewScalar?: bigint }): NormalizedFoundNote[];
export function normalizeFoundNotes(notes: Array<object | FoundNote>): NormalizedFoundNote[];
export type ScanNullifierUsage =
  | boolean
  | { used: boolean; Used?: never }
  | { used?: never; Used: boolean };
export type ScanNullifierStatusEntry =
  ({ nullifier: Hex; Nullifier?: never } | { nullifier?: never; Nullifier: Hex }) &
  Exclude<ScanNullifierUsage, boolean>;
export type ScanNullifierStatusResult =
  Map<Hex, ScanNullifierUsage> |
  Record<Hex, ScanNullifierUsage> |
  { statuses: readonly ScanNullifierStatusEntry[] };
export function scanNotes(input: {
  rootSeed?: BytesLike;
  events?: object[];
  checkNullifier?: (nullifier: Hex) => Promise<ScanNullifierUsage> | ScanNullifierUsage;
  checkNullifiers?: (nullifiers: Hex[]) => ScanNullifierStatusResult | Promise<ScanNullifierStatusResult>;
  includeFoundNotes?: boolean;
}): Promise<ScanResult>;
