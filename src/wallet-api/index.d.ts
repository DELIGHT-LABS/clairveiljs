export * from './generated/types.js';
import type { WalletMethod, WalletMethodMap } from './generated/types.js';
export const schemaDigest: string;
export const methodRegistry: Readonly<Record<WalletMethod, Readonly<{ params: string; result: string; error: string; request: string; response: string; requiresMethods: readonly WalletMethod[] }>>>;
export const contractRegistry: Readonly<Record<string, unknown>>;
export class WalletRpcError extends Error { readonly code: number; readonly rpcError: Readonly<{ code: number; message: string; data?: object }>; constructor(error: { code: number; message: string; data?: object }); }
export function snapshotJson<T>(value: T, options?: { response?: boolean }): T;
export function parseWalletJson(text: string | Uint8Array, options?: { response?: boolean }): unknown;
export function validateWalletValue(definition: string, value: unknown, options?: { response?: boolean }): unknown;
export function validateWalletParams<M extends WalletMethod>(method: M, params: unknown): WalletMethodMap[M]['params'];
export function validateWalletResult<M extends WalletMethod>(method: M, result: unknown, params?: WalletMethodMap[M]['params']): WalletMethodMap[M]['result'];
export function mapWalletError(method: WalletMethod, error: unknown): WalletRpcError;
export function invalidWalletData(response?: boolean): WalletRpcError;
