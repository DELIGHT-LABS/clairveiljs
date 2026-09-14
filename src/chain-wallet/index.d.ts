export interface CosmosChainActor {
  readonly namespace: "cosmos";
  readonly chainId: string;
  readonly address: string;
  readonly pubKeyHex: string;
}

export interface EvmChainActor {
  readonly namespace: "eip155";
  readonly chainId: string;
  readonly address: string;
}

/** Public ordinary-wallet data, not a custody grant or an authenticated privacy-account link. */
export type ChainActor = CosmosChainActor | EvmChainActor;

export interface CosmosSignDoc {
  bodyBytes: Uint8Array;
  authInfoBytes: Uint8Array;
  chainId: string;
  accountNumber: bigint;
}

export interface CosmosDirectSignResponse {
  signed: CosmosSignDoc;
  signature: { pub_key: { type: string; value: string }; signature: string };
}

export interface CosmosChainWalletAdapter {
  connect(): Promise<CosmosChainActor>;
  getActor(): Promise<CosmosChainActor>;
  signDirect(signDoc: CosmosSignDoc, actor: CosmosChainActor): Promise<CosmosDirectSignResponse>;
}

export interface EvmChainTransaction {
  to: string;
  from?: string;
  chainId?: string;
  data?: string;
  value?: string;
  gas?: string;
  gasPrice?: string;
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
  nonce?: string;
}

export interface EvmChainWalletAdapter {
  connect(): Promise<EvmChainActor>;
  getActor(): Promise<EvmChainActor>;
  sendTransaction(transaction: EvmChainTransaction, actor: EvmChainActor): Promise<string>;
}

export interface KeplrChainProvider {
  enable(chainId: string): Promise<void>;
  getKey(chainId: string): Promise<{ bech32Address: string; pubKey: Uint8Array }>;
  signDirect(chainId: string, signer: string, signDoc: CosmosSignDoc,
    options: { preferNoSetFee: boolean; preferNoSetMemo: boolean }): Promise<CosmosDirectSignResponse>;
}

export interface OfflineChainSigner {
  getAccounts(): Promise<readonly { address: string; pubkey: Uint8Array }[]>;
  signDirect(signer: string, signDoc: CosmosSignDoc): Promise<CosmosDirectSignResponse>;
}

export interface Eip1193ChainProvider {
  request(input: { method: string; params?: unknown[] }): Promise<unknown>;
}

export function createKeplrChainWalletAdapter(input: {
  keplr: KeplrChainProvider; chainId: string; address?: string; accountPrefix?: string;
}): CosmosChainWalletAdapter;
export function createOfflineSignerChainWalletAdapter(input: {
  signer: OfflineChainSigner; chainId: string; address?: string; accountPrefix?: string;
}): CosmosChainWalletAdapter;
export function createEip1193ChainWalletAdapter(input: {
  provider: Eip1193ChainProvider; chainId: string; account?: string;
}): EvmChainWalletAdapter;
