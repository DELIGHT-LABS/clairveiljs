export type Hex = string;
export type Base64 = string;
export type ClairAddress = string;
export type ShieldedAddress = string;
export type BytesLike = Uint8Array | ArrayBuffer | ArrayBufferView | number[] | string;

export interface PrefixOptions {
  accountPrefix?: string;
  bech32Prefix?: string;
  shieldedPrefix?: string;
  prefix?: string;
}

export interface Point {
  x: bigint;
  y: bigint;
}

export interface KeyPair {
  seed: Uint8Array;
  scalar: bigint;
  scalarHex: Hex;
  pubKey: Point;
  pubKeyHex: Hex;
}

export interface PrivacyMaterial {
  address?: ClairAddress;
  pubKeyHex?: Hex;
  signatureBase64?: Base64;
  signingMessage: string;
  rootSeed: Uint8Array;
  rootSeedHex: Hex;
  rootSignatureHash: Hex;
  shieldedAddress: ShieldedAddress;
  disclosureScalar: bigint;
  disclosureScalarHex: Hex;
  disclosurePubKey: Point;
  disclosurePubKeyHex: Hex;
}

export const FIELD_MODULUS: bigint;
export const CURVE_ORDER: bigint;
export const CURVE_D: bigint;
export const CURVE_A: bigint;
export const CURVE_BASE: Point;
export const CURVE_IDENTITY: Point;
export const rootSigningDomain: "clairveil-root-v1";
export const spendDomain: "privacy-spend";
export const viewDomain: "privacy-view";
export const disclosureDomain: "privacy-disclosure";
export const defaultAccountPrefix: "clair";
export const defaultShieldedPrefix: "clairs";

export function normalizeHex(value: string, label?: string): Hex;
export function normalizeBech32Prefix(value: string, label?: string): string;
export function bytesFromHex(value: string, label?: string): Uint8Array;
export function hexFromBytes(bytes: BytesLike): Hex;
export function bytesToBigIntBE(bytes: BytesLike): bigint;
export function bytesToBigIntLE(bytes: BytesLike): bigint;
export function bigIntToBytesBE(value: bigint | number | string, size?: number): Uint8Array;
export function bigIntToBytesLE(value: bigint | number | string, size?: number): Uint8Array;
export function toField(value: bigint | number | string | BytesLike | null | undefined): bigint;
export function canonicalFieldBytes(value: bigint | number | string | BytesLike): Uint8Array;
export function canonicalFieldHex(value: bigint | number | string | BytesLike): Hex;
export function decodeCanonicalFieldHex(value: string, label?: string): Uint8Array;
export function packPoint(point: Point): Uint8Array;
export function packPointHex(point: Point): Hex;
export function unpackPoint(bytesLike: BytesLike): Point;
export function unpackPointHex(hex: Hex): Point;
export function pointAdd(p: Point, q: Point): Point;
export function scalarMultiply(point: Point, scalar: bigint | number | string): Point;
export function deriveScalarFromSeed(seed: BytesLike): bigint;
export function scalarToFixedHex(scalar: bigint | number | string): Hex;
export function derivePubKeyFromScalar(scalar: bigint | number | string): Point;
export function buildRootSigningMessage(address: ClairAddress, pubKeyHex: Hex): string;
export function computeRootSeed(address: ClairAddress, pubKeyBytes: BytesLike, signatureBytes: BytesLike): Uint8Array;
export function deriveDomainSeed(rootSeed: BytesLike, domain: string): Uint8Array;
export function deriveKeyPair(rootSeed: BytesLike, domain: string): KeyPair;
export function deriveSpendKeys(rootSeed: BytesLike): KeyPair;
export function deriveViewKeys(rootSeed: BytesLike): KeyPair;
export function deriveDisclosureKeys(rootSeed: BytesLike): KeyPair;
export function encodeShieldedAddress(spendPubKey: Point, viewPubKey: Point, options?: string | PrefixOptions): ShieldedAddress;
export function canonicalizeShieldedAddressForOperationHash(address: string, options?: string | PrefixOptions): ShieldedAddress;
export function decodeShieldedAddress(address: ShieldedAddress, options?: string | PrefixOptions): { spendPubKey: Point; viewPubKey: Point };
export function deriveShieldedAddress(rootSeed: BytesLike, options?: PrefixOptions): ShieldedAddress;
export function derivePrivacyMaterial(input: { address: ClairAddress; pubKeyHex: Hex; signatureBase64: Base64; shieldedPrefix?: string }): PrivacyMaterial;
export function mimcHash(...data: Array<bigint | number | string | BytesLike>): bigint;
export function hashStringToField(value: string): bigint;
export function asymDecrypt(ciphertextBytes: BytesLike, scalar: bigint | number | string): Uint8Array;
export function asymDecryptHex(ciphertextHex: Hex, scalar: bigint | number | string): Uint8Array;
