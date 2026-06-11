import type { Base64, BytesLike, ClairAddress, Hex, Point, ShieldedAddress } from "./crypto.js";

export type CoinString = string;

export interface ParsedCoin {
  amount: string;
  denom: string;
  raw: CoinString;
}

export interface Note {
  receiverSpendPubKeyX: bigint;
  receiverSpendPubKeyY: bigint;
  receiverViewPubKeyX: bigint;
  receiverViewPubKeyY: bigint;
  amount: bigint;
  assetID: bigint;
  randomness: bigint;
  memo: string;
}

export interface FoundNote {
  note: Note;
  nullifier: Hex;
  isSpent: boolean;
  txHash: Hex;
  height: number;
}

export interface NoteHashSigner {
  spendScalar?: bigint;
  spendPubKey?: Point;
  signNoteHash?: (messageHash: bigint) => Promise<Uint8Array> | Uint8Array;
  signSpendNoteHash?: (messageHash: bigint) => Promise<Uint8Array> | Uint8Array;
}

export interface DepositMaterial {
  creator: ClairAddress | string;
  amount: CoinString;
  note: Note;
  note_json: string;
  note_commitment: Uint8Array;
  note_commitment_hex: Hex;
  note_commitment_base64: Base64;
  encrypted_note: Uint8Array;
  encrypted_note_hex: Hex;
  encrypted_note_base64: Base64;
}

export const defaultAssetDenom: "uclair";

export function parseCoin(value: string | number | bigint, defaultDenom?: string): ParsedCoin;
export function noteFromShieldedAddress(input: { shieldedAddress: ShieldedAddress; amount: string | number | bigint; assetDenom?: string; randomness?: bigint | string | number; memo?: string; shieldedPrefix?: string }): Note;
export function noteFromRootSeed(input: { rootSeed: BytesLike; amount: string | number | bigint; assetDenom?: string; randomness?: bigint | string | number; memo?: string }): Note;
export function createNote(input: { spendPubKey: Point; viewPubKey: Point; amount: string | number | bigint; assetDenom?: string; assetId?: string | number | bigint; randomness?: bigint | string | number; memo?: string }): Note;
export function normalizeNote(note: object): Note;
export function noteToGoJSON(noteLike: object): string;
export function noteToGoJSONBytes(noteLike: object): Uint8Array;
export function computeNoteCommitment(noteLike: object): bigint;
export function computeNoteCommitmentHex(noteLike: object): Hex;
export function computeNoteCommitmentBytes(noteLike: object): Uint8Array;
export function computeNoteNullifier(noteLike: object): bigint;
export function computeNoteNullifierHex(noteLike: object): Hex;
export function noteSpendPubKey(noteLike: object): Point;
export function noteViewPubKey(noteLike: object): Point;
export function noteSpendPubKeyHex(noteLike: object): Hex;
export function noteViewPubKeyHex(noteLike: object): Hex;
export function encryptWithRootSeed(plaintext: BytesLike, rootSeed: BytesLike): Uint8Array;
export function decryptWithRootSeed(ciphertextBytes: BytesLike, rootSeed: BytesLike): Uint8Array;
export function encryptNoteWithRootSeed(noteLike: object, rootSeed: BytesLike): Uint8Array;
export function asymEncrypt(plaintext: BytesLike, receiverPubKey: Point): Uint8Array;
export function asymEncryptHex(plaintext: BytesLike, receiverPubKeyHex: Hex): Hex;
export function encryptNoteForReceiver(noteLike: object): Uint8Array;
export function computeTransferNoteHash(noteLike: object): bigint;
export function computeWithdrawNoteHash(noteLike: object, recipientBytes: BytesLike): bigint;
export function signNoteHash(messageHash: bigint, input: { spendScalar: bigint; spendPubKey?: Point }): Uint8Array;
export function createSpendNoteHashSigner(rootSeed: BytesLike): NoteHashSigner;
export function resolveTransferSignature(signer: NoteHashSigner, messageHash: bigint): Promise<Uint8Array>;
export function resolveWithdrawSignature(signer: NoteHashSigner, messageHash: bigint): Promise<Uint8Array>;
export function buildDepositMaterial(input?: { creator?: ClairAddress | string; rootSeed?: BytesLike; shieldedAddress?: ShieldedAddress; amount?: CoinString; memo?: string; assetDenom?: string; shieldedPrefix?: string }): DepositMaterial;
export function normalizeFoundNote(foundNote: object): FoundNote;
export function pointFromHex(value: Hex, label?: string): Point;
export function bytesFromOptionalHex(value: string | undefined | null, label?: string): Uint8Array;
