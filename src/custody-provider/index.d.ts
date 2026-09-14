import type { WalletMethod, WalletMethodMap } from '../wallet-api/index.js';
export interface CustodyTransport { request(input: { method: WalletMethod; params: unknown }): Promise<unknown>; }
export interface CustodyProvider {
 readonly generation: number;
 request<M extends WalletMethod>(input: { method: M; params: WalletMethodMap[M]['params'] }): Promise<WalletMethodMap[M]['result']>;
 invalidate(): void;
 onInvalidation(listener: () => void): () => void;
 dispose(): void;
}
export function createCustodyProvider(input: { transport: CustodyTransport; subscribeInvalidation?: (listener: () => void) => (() => void); timeoutMs?: number; clock?: () => number }): CustodyProvider;
export function createDirectBridgeTransport(input: { exchange: (request: unknown) => Promise<unknown> }): CustodyTransport;
