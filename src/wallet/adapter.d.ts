import type { Base64, ClairAddress, Hex, PrivacyMaterial } from "../core/crypto.js";

export interface WalletAdapterLike {
  address?: ClairAddress;
  pubKeyHex?: Hex;
  pubKeyBytes?: Uint8Array;
  shieldedPrefix?: string;
  getAddress?: () => Promise<ClairAddress> | ClairAddress;
  getPubKeyHex?: () => Promise<Hex | Uint8Array> | Hex | Uint8Array;
  signPrivacyRoot?: (
    messageBytes: Uint8Array,
    context?: object
  ) => Promise<Uint8Array | Base64 | { signature: Base64 }> | Uint8Array | Base64 | { signature: Base64 };
  signPrivacyRootBase64?: (messageBytes: Uint8Array, context?: object) => Promise<Base64> | Base64;
  signDirect?: (signDoc: object, context?: object) => Promise<object> | object;
  broadcastSignedTx?: (signedTx: object, context?: object) => Promise<object> | object;
}

export interface WalletAdapter {
  getAddress(): Promise<ClairAddress>;
  getPubKeyHex(): Promise<Hex>;
  signPrivacyRoot(messageBytes: Uint8Array, context?: object): Promise<Uint8Array>;
  signPrivacyRootBase64(messageBytes: Uint8Array, context?: object): Promise<Base64>;
  signDirect(signDoc: object, context?: object): Promise<object>;
  broadcastSignedTx(signedTx: object, context?: object): Promise<object>;
}

export function buildPrivacyRootSigningMessage(input: { address: ClairAddress; transparentPubKeyHex?: Hex; pubKeyHex?: Hex }): string;
export function createWalletAdapter(input?: WalletAdapterLike): WalletAdapter;
export function derivePrivacyMaterialFromWallet(walletLike: WalletAdapterLike, options?: { shieldedPrefix?: string }): Promise<PrivacyMaterial>;
export function createKeplrWalletAdapter(input: { keplr: object; chainId: string; address?: ClairAddress; accountPrefix?: string; bech32Prefix?: string }): WalletAdapter;
export function createOfflineSignerWalletAdapter(input: {
  signer: object;
  address?: ClairAddress;
  accountPrefix?: string;
  bech32Prefix?: string;
  signPrivacyRoot?: WalletAdapterLike["signPrivacyRoot"];
  signPrivacyRootBase64?: WalletAdapterLike["signPrivacyRootBase64"];
}): WalletAdapter;
