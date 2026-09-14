import type { WalletMethodMap, ClairveilOperation } from '../wallet-api/index.js';
import type { CustodyProvider } from '../custody-provider/index.js';
import type { ChainActor, CosmosChainWalletAdapter, EvmChainWalletAdapter } from '../chain-wallet/index.js';
type LogicalName<M extends string> = M extends `clairveil_${infer Name}` ? Name : never;
export type PublicWalletMethods = { [M in keyof WalletMethodMap as LogicalName<M>]: (params: WalletMethodMap[M]['params']) => Promise<WalletMethodMap[M]['result']> };
export interface SubmissionInput { operation: ClairveilOperation; actor: ChainActor; context: { sessionHandle: string; accountHandle: string; networkHandle: string }; idempotencyKey: string; networkProfileDigest: string; chainActorAccountId: string; }
export type ArtifactVerifier = (context: { operation: ClairveilOperation; artifact: object; actor: ChainActor; networkProfileDigest: string }) => boolean | Promise<boolean>;
export function createClairveilDappClient(input: { custodyProvider: CustodyProvider }): Readonly<PublicWalletMethods>;
export function createClairveilDappClient(input: { custodyProvider: CustodyProvider; chainWallet: CosmosChainWalletAdapter | EvmChainWalletAdapter; validateArtifact: ArtifactVerifier; broadcastCosmos?: (bytes: Uint8Array, actor: ChainActor) => Promise<string> }): Readonly<PublicWalletMethods & { submit(input: SubmissionInput): Promise<{ attempt: object; invoked: boolean; result?: object }> }>;
export function computeArtifactBinding(input: { operationId: string; networkProfileDigest: string; chainActorAccountId: string; artifact: object }): Promise<string>;
export function createArtifactVerifier(profile: { profileDigest: string; chainId: string; assetDenom: string; protocolChainId?: string; contractAddress?: string }): ArtifactVerifier;
