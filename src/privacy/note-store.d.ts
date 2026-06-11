import type { Hex } from "../core/crypto.js";
import type { FoundNote } from "../core/note.js";
import type { ScanResult } from "./scan.js";

export interface StoredFoundNote extends FoundNote {
  commitment_hex: Hex;
  nullifier_hex: Hex;
  amount: string;
  asset_denom: string;
  asset_id_hex: Hex;
  randomness_hex: Hex;
  spend_pubkey_hex: Hex;
  view_pubkey_hex: Hex;
  tx_hash: Hex;
  spent: boolean;
}

export interface NoteStoreScanCursor {
  after_height?: number;
  page?: number;
  limit?: number;
  event_types?: string[];
  has_more?: boolean;
  latest_height?: number;
  latest_tx_hash?: Hex;
  [key: string]: unknown;
}

export interface NoteStoreState {
  owner?: string;
  notes: StoredFoundNote[];
  lastScannedHeight?: number;
  lastScannedTxHash?: Hex | "";
  rollbackHeight?: number;
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
    rollbackToHeight?: number;
    rollback_to_height?: number;
  }): Promise<NoteStoreState>;
  rollbackToHeight(height: number): Promise<NoteStoreState>;
  markSpent(nullifiers: Hex[] | Hex): Promise<NoteStoreState>;
}

export class LocalStorageNoteStore extends MemoryNoteStore {
  constructor(options?: { storage?: Storage; key?: string; owner?: string; allowPlaintext?: boolean });
}
