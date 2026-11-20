import type { FoundNote128Input,NormalizedFoundNote128 } from "../core/note128.js";
export const privacyNoteCacheStateVersionV2: "privacy-audit-note-cache-v2";
/** Sensitive plaintext representation; encrypt before persisting. */
export interface StoredNoteV2 {
  version: typeof privacyNoteCacheStateVersionV2; plaintext: string; commitment: string; nullifier: string;
  nullifierStatus: "spent" | "unspent" | "unknown" | "unverified"; isSpent: boolean; txHash: string; height: string; sequence: string;
}
export function serializeFoundNoteV2(input: FoundNote128Input): StoredNoteV2;
export function deserializeFoundNoteV2(input: object): NormalizedFoundNote128;
export function isVerifiedUnspentFoundNoteV2(input: FoundNote128Input): boolean;
