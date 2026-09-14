import type { KeyPair } from "../core/crypto.js";

/** Internal public-key projection, not a custody RPC account DTO or permission grant. */
export interface PublicPrivacyIdentity {
  readonly shieldedAddress: string;
  readonly spendPubKeyHex: string;
  readonly viewPubKeyHex: string;
  readonly disclosurePubKeyHex: string;
}

/** Contains secrets. Keep this object inside the trusted wallet runtime. */
export interface WalletPrivacyIdentity {
  readonly rootSeed: Uint8Array;
  readonly spend: KeyPair;
  readonly view: KeyPair;
  readonly disclosure: KeyPair;
  readonly publicIdentity: PublicPrivacyIdentity;
}

export interface PrivacyIdentityInput {
  rootSeed: Uint8Array;
  shieldedPrefix?: string;
}

/** Copies exactly 32 seed bytes and reuses the existing protocol key derivation. */
export function createPrivacyIdentity(input: PrivacyIdentityInput): WalletPrivacyIdentity;
