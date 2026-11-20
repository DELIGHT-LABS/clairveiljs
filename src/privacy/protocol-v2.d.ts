import type { Hex, Point } from "../core/crypto.js";
import type { Amount128Input } from "../core/amount.js";
import type { NoteFields, DisclosureFields } from "./protocol-fields.js";

export const privacyFixedV2: "privacy-fixed-v2";
export const fixedBinaryVersionV2: 2;
export const notePlaintextV2Size: 358;
export const disclosurePlaintextV2Size: 400;
export const encryptedEnvelopeV2HeaderSize: 20;
export const noteMemoCapacityV2: 128;
export const encryptedEnvelopeKindV2: Readonly<{ depositNote: 1; transferNote: 2; userDisclosure: 3; auditDisclosure: 4; selfViewDisclosure: 5 }>;
export type EncryptedEnvelopeKindV2 = 1 | 2 | 3 | 4 | 5;
export type DisclosureEnvelopeKindV2 = 3 | 4 | 5;
export type DisclosureDigestSchemeV2 = "transfer" | "batch";
/** Same field shape; explicit V2 functions enforce uint128 and fixed-v2 framing. */
export interface NoteV2 extends NoteFields {}
export type NoteV2Input = { [K in Exclude<keyof NoteV2, "memo">]: Amount128Input } & { memo?: string };
export interface DisclosurePlaintextV2 extends DisclosureFields {}
export type DisclosurePlaintextV2Input = Omit<DisclosurePlaintextV2, "amount"> & { amount: Amount128Input };
export interface TransferNoteBindingV2 { outputCommitment: Uint8Array | Hex; outputIndex: number; viewTag: Uint8Array | Hex; }

export function validateNoteV2(note: NoteV2Input): NoteV2;
export function computeNoteCommitmentV2(note: NoteV2Input): bigint;
export function computeNoteNullifierV2(note: NoteV2Input): bigint;
export function marshalNotePlaintextV2(note: NoteV2Input): Uint8Array;
export function unmarshalNotePlaintextV2(value: Uint8Array | Hex): NoteV2;
export function validateDisclosurePlaintextV2(payload: DisclosurePlaintextV2Input): DisclosurePlaintextV2;
export function marshalDisclosurePlaintextV2(payload: DisclosurePlaintextV2Input): Uint8Array;
export function unmarshalDisclosurePlaintextV2(value: Uint8Array | Hex): DisclosurePlaintextV2;
/** Explicit scheme selection; framing alone does not identify the circuit digest. */
export function computeDisclosureDigestV2(payload: DisclosurePlaintextV2Input, scheme: DisclosureDigestSchemeV2): bigint;
export function verifyDisclosureDigestV2(payload: DisclosurePlaintextV2Input, expectedDigest: Uint8Array | Hex, scheme: DisclosureDigestSchemeV2): true;
export function encryptedEnvelopeV2Size(kind: EncryptedEnvelopeKindV2): number;
export function wrapEncryptedEnvelopeV2(kind: EncryptedEnvelopeKindV2, ciphertext: Uint8Array | Hex): Uint8Array;
export function decodeEncryptedEnvelopeV2(value: Uint8Array | Hex): { kind: EncryptedEnvelopeKindV2; ciphertext: Uint8Array };
export function unwrapEncryptedEnvelopeV2(value: Uint8Array | Hex, expectedKind: EncryptedEnvelopeKindV2): Uint8Array;
export function encryptDepositNoteV2(note: NoteV2Input, rootSeed: Uint8Array): Uint8Array;
export function decryptDepositNoteV2(ciphertext: Uint8Array | Hex, rootSeed: Uint8Array): NoteV2;
/** The supplied commitment must match the note. */
export function encryptNoteForTransferV2(note: NoteV2Input, outputCommitment: Uint8Array | Hex, outputIndex: number): { ciphertext: Uint8Array; viewTag: Uint8Array };
/** Optional binding verifies the view tag and the decrypted note commitment. */
export function decryptTransferNoteV2(ciphertext: Uint8Array | Hex, scalar: bigint, binding?: TransferNoteBindingV2): NoteV2;
export function encryptDisclosureV2(disclosure: DisclosurePlaintextV2Input, target: Point, kind: DisclosureEnvelopeKindV2): Uint8Array;
/** Authenticated decryption and plane validation; verify the external digest separately. */
export function decryptDisclosureV2(ciphertext: Uint8Array | Hex, scalar: bigint, expectedKind: DisclosureEnvelopeKindV2): DisclosurePlaintextV2;
