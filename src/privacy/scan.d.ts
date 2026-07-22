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

export const privacyScanSchemaVersionV2: "privacy-scan-v2";
export const privacyScanEventTypeV2: Readonly<{
  deposit: "deposit";
  shieldedTransfer: "shielded_transfer";
  batchTransfer: "batch_transfer";
  withdraw: "withdraw";
}>;
export const privacyScanValidationStateVersionV2: "privacy-scan-validation-v2";

/** Mutable state supplied to validatePrivacyScanPageV2 across cursor pages. */
export interface PrivacyScanValidationStateV2 {
  version: "privacy-scan-validation-v2";
  batch_self_view_by_event: Map<string, boolean>;
}

export interface PrivacyScanCursorV2 {
  height: number | string;
  global_sequence: number | string;
  output_index: number;
}

export interface ValidatedPrivacyScanSummaryV2 {
  height: number | string;
  global_sequence: number | string;
  tx_hash: Uint8Array;
  event_type: "deposit" | "shielded_transfer" | "batch_transfer" | "withdraw";
  nullifiers: readonly Uint8Array[];
  output_count: number;
  circuit_set_id: "privacy-note-v1";
  payload_version: "privacy-fixed-v1";
  scan_schema_version: "privacy-scan-v2";
  audit_key_id: string;
  audit_key_epoch: number | string;
  audit_target_pubkey: Uint8Array;
  effect_id: Uint8Array;
}

export interface ValidatedPrivacyScanOutputV2 {
  height: number | string;
  global_sequence: number | string;
  output_index: number;
  effect_id: Uint8Array;
  commitment: Uint8Array;
  ciphertext: Uint8Array;
  encrypted_note: Uint8Array;
  view_tag: Uint8Array;
  leaf_index: number | string;
  leaf_index_found: true;
  user_privacy_policy: number;
  user_disclosure_mode: string;
  user_disclosure_digest: Uint8Array;
  user_disclosure_target_pubkey: Uint8Array;
  user_disclosure_payload: Uint8Array;
  full_disclosure_digest: Uint8Array;
  audit_disclosure_payload: Uint8Array;
  self_view_disclosure_payload: Uint8Array;
  circuit_set_id: "privacy-note-v1";
  payload_version: "privacy-fixed-v1";
  scan_schema_version: "privacy-scan-v2";
  audit_key_id: string;
  audit_key_epoch: number | string;
  audit_target_pubkey: Uint8Array;
  tx_hash: Uint8Array;
  event_type: ValidatedPrivacyScanSummaryV2["event_type"];
}

export interface ValidatedPrivacyScanPageV2 {
  scan_schema_version: "privacy-scan-v2";
  summaries: readonly ValidatedPrivacyScanSummaryV2[];
  outputs: readonly ValidatedPrivacyScanOutputV2[];
  next_cursor: PrivacyScanCursorV2;
  has_more: boolean;
  scanned_event_count: number;
  encoded_bytes: number | string;
}

export function parseNoteBytes(bytes: BytesLike): object;
export function parseNullifierUsage(value: unknown): boolean | null;
export function processPrivacyEvent(event: object, input: { rootSeed?: BytesLike; spendScalar?: bigint; viewScalar?: bigint }): NormalizedFoundNote[];
export function normalizeFoundNotes(notes: Array<object | FoundNote>): NormalizedFoundNote[];
export function createPrivacyScanValidationStateV2(): PrivacyScanValidationStateV2;
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
  /** Internal adapter input for a prevalidated typed privacy-scan-v2 page. */
  preprocessedFoundNotes?: Array<object | FoundNote>;
  checkNullifier?: (nullifier: Hex) => Promise<ScanNullifierUsage> | ScanNullifierUsage;
  checkNullifiers?: (nullifiers: Hex[]) => ScanNullifierStatusResult | Promise<ScanNullifierStatusResult>;
  includeFoundNotes?: boolean;
}): Promise<ScanResult>;
export function validatePrivacyScanPageV2(response: object, request?: {
  after?: Partial<PrivacyScanCursorV2> & { globalSequence?: number | bigint | string; outputIndex?: number };
  outputLimit?: number;
  output_limit?: number;
  eventLimit?: number;
  event_limit?: number;
  maxEncodedBytes?: number | bigint | string;
  max_encoded_bytes?: number | bigint | string;
  eventTypes?: string[];
  event_types?: string[];
  /** Retain this object while validating consecutive pages to bind batch self-view all-or-none. */
  validationState?: PrivacyScanValidationStateV2;
  validation_state?: PrivacyScanValidationStateV2;
}): ValidatedPrivacyScanPageV2;
export function processPrivacyScanOutputV2(output: ValidatedPrivacyScanOutputV2, input: {
  rootSeed: BytesLike;
  spendScalar?: bigint;
  viewScalar?: bigint;
}): NormalizedFoundNote | null;
export function processPrivacyScanPageV2(page: ValidatedPrivacyScanPageV2, input: {
  rootSeed: BytesLike;
  spendScalar?: bigint;
  viewScalar?: bigint;
}): NormalizedFoundNote[];
