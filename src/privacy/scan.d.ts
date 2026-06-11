import type { BytesLike, Hex } from "../core/crypto.js";
import type { FoundNote } from "../core/note.js";

export interface ScanResult {
  notes: Array<{
    index: number;
    status: "spendable" | "spent";
    amount: string;
    nullifier: Hex;
    tx_hash: Hex;
    height: number;
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
  };
  foundNotes?: FoundNote[];
}

export function parseNoteBytes(bytes: BytesLike): object;
export function processPrivacyEvent(event: object, input: { rootSeed?: BytesLike; spendScalar?: bigint; viewScalar?: bigint }): FoundNote[];
export function normalizeFoundNotes(notes: Array<object | FoundNote>): FoundNote[];
export function scanNotes(input: {
  rootSeed?: BytesLike;
  events?: object[];
  checkNullifier?: (nullifier: Hex) => Promise<object | boolean> | object | boolean;
  includeFoundNotes?: boolean;
}): Promise<ScanResult>;
