import type { AuditSnapshotV2 } from "./audit-config-v2.js";
import type { PreparedAuditAuthorizationV2 } from "./audit-authorization-v2.js";
import type { FoundNote128Input } from "../core/note128.js";
import type { Amount128Input } from "../core/amount.js";
export interface AuditWitnessBackendV2 { prepare(input: {request: Uint8Array; signal?: AbortSignal}): Promise<Uint8Array>; }
export interface AuditWitnessPathV2 { commitment: string; root: Uint8Array; path: string[]; helper: number[]; }
export interface AuditWitnessInputV2 {
  kind: "deposit" | "transfer" | "withdraw"; rootSeed: Uint8Array; snapshot: AuditSnapshotV2;
  creator: string; chainId: string; amount: Amount128Input; denom: string; expiresAtUnix: string | bigint;
  backend: AuditWitnessBackendV2; getCurrentSnapshot(): Promise<AuditSnapshotV2>;
  checkpoint(input: {kind: "deposit" | "transfer" | "withdraw"; commitments: string[]; nullifiers: string[]}): Promise<void>;
  signal?: AbortSignal; memo?: string; notes?: FoundNote128Input[]; paths?: AuditWitnessPathV2[];
  recipient?: string; shieldedPrefix?: string; disclosure?: { policy: number; mode: number; target?: Uint8Array }; disableSelfView?: boolean;
}
/** Private, nonserializable owner authorization and full witness. No chain submission. */
export function prepareAuditWitnessV2(input: AuditWitnessInputV2): Promise<{
  prepared: PreparedAuditAuthorizationV2; witness: Uint8Array; clear(): void; toJSON(): never;
}>;
