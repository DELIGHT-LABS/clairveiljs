import type { AuditSnapshotV2 } from "./audit-config-v2.js";
import type {
  OutputEffect,
  AuditAuthorization,
  MsgDeposit,
  MsgWithdraw,
  MsgTransfer,
  MsgBatchTransfer,
} from "../generated/clairveil/privacy/v2/tx.js";
export type AuditKindV2 = 1 | 2 | 3 | 4;
export type AuditMessageV2 =
  MsgDeposit | MsgWithdraw | MsgTransfer | MsgBatchTransfer;
export type AuditMessageDataV2 =
  | Omit<MsgDeposit, "proof" | "audit">
  | Omit<MsgWithdraw, "proof" | "audit">
  | Omit<MsgTransfer, "proof" | "audit">
  | Omit<MsgBatchTransfer, "proof" | "audit">;
export type AuthorizedAuditDataV2 = AuditMessageDataV2 & {
  audit: AuditAuthorization;
};
export interface AuditBindingInputV2 {
  kind: AuditKindV2;
  snapshot: AuditSnapshotV2;
  message: AuditMessageDataV2 | AuthorizedAuditDataV2 | AuditMessageV2;
}
/** Trusted wallet-local implementation. Never pass these inputs across the DApp boundary or to an HTTP service. */
export interface AuditEncryptionBackendV2 {
  /** PI21 is 672 BE bytes; plaintext is 6/2/13/177 canonical BE32 fields. Caller clears owned plaintext and returned witness after copying. */
  encrypt(request: {
    kind: AuditKindV2;
    publicInputs: Uint8Array;
    plaintext: Uint8Array;
    signal?: AbortSignal;
  }): Promise<{ envelope: Uint8Array; witness: Uint8Array }>;
}
export interface PreparedAuditAuthorizationV2 {
  /** Detached public data; no proof and not broadcast ready. */
  messageData(): AuthorizedAuditDataV2;
  publicInputs(): bigint[];
  /** Empty for deposit. */
  ownerIntent(): Uint8Array;
  /** Explicit private export for the trusted prover coordinator; caller must clear the copy. */
  exportEncryptionWitness(): Uint8Array;
  assertMessageBinding(message: AuthorizedAuditDataV2 | AuditMessageV2): true;
  assertCurrent(): Promise<true>;
  clear(): void;
  toJSON(): never;
}
/** Constructs a detached generated OutputEffect from fixed-v2 recovery/disclosure bytes and validates its position. */
export function createAuditOutputEffectV2(
  kind: AuditKindV2,
  outputIndex: number,
  effect: Pick<OutputEffect, "commitment" | "ciphertext"> &
    Partial<OutputEffect>,
): OutputEffect;
export function encodeAuditAuxV2(
  kind: AuditKindV2,
  outputs: ReadonlyArray<OutputEffect>,
): Uint8Array;
/** PI21 without authorization; PI23 with authorization. Public validation is not proof verification. */
export function buildAuditPublicInputsV2(input: AuditBindingInputV2): bigint[];
export function verifyAuditMessageBindingV2(
  input: AuditBindingInputV2 & { publicInputs: readonly bigint[] },
): true;
export function parseAuditEnvelopeV2(
  kind: AuditKindV2,
  inputs: number,
  outputs: number,
  value: Uint8Array,
): {
  kind: AuditKindV2;
  inputCount: number;
  outputCount: number;
  nonce: Uint8Array;
  ephemeral: { x: bigint; y: bigint };
  ciphertext: bigint[];
  tag: bigint;
};
export function computeAuditCipherRootV2(
  kind: AuditKindV2,
  publicInputs: readonly bigint[],
  envelope: Uint8Array,
): [bigint, bigint];
export function computeAuditContextHashV2(
  kind: AuditKindV2,
  publicInputs: readonly bigint[],
  envelope: Uint8Array,
): Uint8Array;
export function computeAuditOwnerIntentV2(
  kind: AuditKindV2,
  publicInputs: readonly bigint[],
  envelope: Uint8Array,
): Uint8Array;
/** Plaintext is private, fixed-layout Core data. Its relation to notes/witness is enforced by the circuit in the subsequent proving step, not this public binding layer. */
export function prepareAuditAuthorizationV2(
  input: AuditBindingInputV2 & {
    plaintext: ReadonlyArray<Uint8Array>;
    backend: AuditEncryptionBackendV2;
    getCurrentSnapshot: () => Promise<AuditSnapshotV2>;
    signal?: AbortSignal;
    now?: () => bigint;
  },
): Promise<PreparedAuditAuthorizationV2>;
