import type { Hex } from "../core/crypto.js";
import type { FoundNote, NormalizedFoundNote } from "../core/note.js";
import type { ScanResult } from "./scan.js";

export interface StoredFoundNote extends NormalizedFoundNote {
  commitment_hex: Hex;
  nullifier_hex: Hex;
  amount: string;
  asset_denom: string;
  asset_id_hex: Hex;
  randomness_hex: Hex;
  spend_pubkey_hex: Hex;
  view_pubkey_hex: Hex;
  tx_hash: Hex;
  sequence: number | string;
  spent: boolean;
}

export interface NoteStoreScanCursor {
  after_height?: number | string;
  after_sequence?: number | string;
  page?: number;
  limit?: number;
  event_types?: string[];
  has_more?: boolean;
  latest_height?: number | string;
  latest_sequence?: number | string;
  next_height?: number | string;
  next_sequence?: number | string;
  latest_tx_hash?: Hex;
  [key: string]: unknown;
}

export interface NoteStoreState {
  owner?: string;
  notes: StoredFoundNote[];
  lastScannedHeight?: number | string;
  lastScannedSequence?: number | string;
  lastScannedTxHash?: Hex | "";
  rollbackHeight?: number | string;
  scanCursor?: NoteStoreScanCursor | null;
  [key: string]: unknown;
}

export function serializeFoundNote(foundLike: FoundNote | object): object;
export function deserializeFoundNote(serialized: object): StoredFoundNote;

export class MemoryNoteStore {
  constructor(options?: { owner?: string; state?: Partial<NoteStoreState> });
  load(): Promise<NoteStoreState>;
  save(state: Partial<NoteStoreState>): Promise<NoteStoreState>;
  clear(): Promise<NoteStoreState>;
  mergeScanResult(scanResult: ScanResult & { scanCursor?: NoteStoreScanCursor }, options?: {
    owner?: string;
    rollbackToHeight?: number | string;
    rollback_to_height?: number | string;
  }): Promise<NoteStoreState>;
  rollbackToHeight(height: number | string): Promise<NoteStoreState>;
  markSpent(nullifiers: Hex[] | Hex): Promise<NoteStoreState>;
  setNullifierStatuses(statuses: Map<Hex, "spent" | "unspent" | "unknown" | "unverified"> | Record<Hex, "spent" | "unspent" | "unknown" | "unverified">): Promise<NoteStoreState>;
}

export class LocalStorageNoteStore extends MemoryNoteStore {
  constructor(options?: { storage?: Storage; key?: string; owner?: string; allowPlaintext?: boolean });
}
