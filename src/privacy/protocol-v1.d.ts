import type { Hex, Point } from "../core/crypto.js";

export const privacyFixedV1: "privacy-fixed-v1";
export const activeCircuitSetIdV1: "privacy-note-v1";
export const notePlaintextV1Size: 350;
export const disclosurePlaintextV1Size: 392;
export const encryptedEnvelopeV1HeaderSize: 20;
export const noteMemoCapacityV1: 128;
export const batchTransferPayloadDomainV1: "clairveil.batch-transfer-payload.v1";
export const transferPayloadDomainV1: "clairveil.transfer-payload.v1";
export const batchVectorKindV1: Readonly<{ nullifier: "nullifier"; commitment: "commitment"; userDisclosure: "user_disclosure"; fullDisclosure: "full_disclosure" }>;
export const encryptedEnvelopeKindV1: Readonly<{ depositNote: 1; transferNote: 2; userDisclosure: 3; auditDisclosure: 4; selfViewDisclosure: 5 }>;

export interface NoteV1 {
  receiverSpendPubKeyX: bigint;
  receiverSpendPubKeyY: bigint;
  receiverViewPubKeyX: bigint;
  receiverViewPubKeyY: bigint;
  amount: bigint;
  assetID: bigint;
  randomness: bigint;
  memo: string;
}

export interface DigestLimbsV1 { bytes: Uint8Array; hex: Hex; hi: bigint; lo: bigint; }

export interface DisclosurePlaintextV1 {
  plane: 1 | 2;
  outputIndex: number;
  policy: number;
  disclosedFieldBitmap: number;
  commitment: bigint;
  amount: bigint;
  assetID: bigint;
  senderSpendKeyX: bigint;
  senderSpendKeyY: bigint;
  senderViewKeyX: bigint;
  senderViewKeyY: bigint;
  recipientSpendKeyX: bigint;
  recipientSpendKeyY: bigint;
  recipientViewKeyX: bigint;
  recipientViewKeyY: bigint;
  disclosureBlinding: bigint;
}

export function domainFieldV1(label: string): bigint;
export function computeAssetIdV1(denom: string): bigint;
export function computeNoteCommitmentV1(note: NoteV1): bigint;
export function computeNoteNullifierV1(note: NoteV1): bigint;
export function computeNoteTreeNodeV1(level: number | bigint, left: bigint, right: bigint): bigint;
export function emptyNoteTreeRootsV1(depth: number | bigint): bigint[];
export function validateNoteV1(note: object): NoteV1;
export function marshalNotePlaintextV1(note: NoteV1): Uint8Array;
export function unmarshalNotePlaintextV1(value: Uint8Array | Hex): NoteV1;
export function marshalDisclosurePlaintextV1(payload: DisclosurePlaintextV1): Uint8Array;
export function unmarshalDisclosurePlaintextV1(value: Uint8Array | Hex): DisclosurePlaintextV1;
export function computeTransferUserDisclosureDigestV2(input: object): bigint;
export function computeTransferFullDisclosureDigestV2(input: object): bigint;
export function validateBatchJoinSplitCountsV1(inputCount: number | bigint, outputCount: number | bigint): true;
export function computeBatchVectorRootV1(kind: "nullifier" | "commitment" | "user_disclosure" | "full_disclosure", count: number | bigint, values: bigint[]): bigint;
export function computeBatchUserDisclosureVectorRootV1(count: number | bigint, policies: number[], rawDigests: bigint[]): bigint;
export function computeBatchUserDisclosureDigestV1(input: object): bigint;
export function computeBatchFullDisclosureDigestV1(input: object): bigint;
export function computeBatchTransferIntentV1(input: object): bigint;
export function wrapEncryptedEnvelopeV1(kind: number, ciphertext: Uint8Array | Hex): Uint8Array;
export function unwrapEncryptedEnvelopeV1(value: Uint8Array | Hex, expectedKind?: number): Uint8Array;
export function encryptNoteForTransferV1(note: NoteV1, outputCommitment: Uint8Array | Hex, outputIndex: number): { ciphertext: Uint8Array; viewTag: Uint8Array };
export function decryptTransferNoteV1(ciphertext: Uint8Array | Hex, scalar: bigint): NoteV1;
export function encryptDisclosureV1(disclosure: DisclosurePlaintextV1, target: Point, kind: 3 | 4 | 5): Uint8Array;
export function decryptDisclosureV1(ciphertext: Uint8Array | Hex, scalar: bigint, expectedKind: 3 | 4 | 5): DisclosurePlaintextV1;
export function encryptDepositNoteV1(note: NoteV1, rootSeed: Uint8Array): Uint8Array;
export function decryptDepositNoteV1(ciphertext: Uint8Array | Hex, rootSeed: Uint8Array): NoteV1;
export function validateBatchTransferEffectsV1(message: object): object;
export function canonicalBatchTransferPayloadBytesV1(message: object): Uint8Array;
export function computeBatchTransferPayloadDigestV1(message: object): DigestLimbsV1;
export function canonicalTransferPayloadBytesV1(message: object): Uint8Array;
export function computeTransferPayloadDigestV1(message: object): DigestLimbsV1;
export function computeChainDomainV1(chainId: string, circuitSetId?: string): DigestLimbsV1;
export function computeTransferIntentV2(input: object): bigint;
export function computeWithdrawRecipientDigestV1(recipientBytes: Uint8Array | Hex): DigestLimbsV1;
export function computeSpendIntentV2(input: object): bigint;
export function fieldHexV1(value: bigint): Hex;
