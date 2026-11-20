export function strip0x(value: unknown): string;
export function with0x(value: string): string;
export function bytesLikeToHex(value: unknown, label?: string): string;
export function bytes32Word(value: unknown, label?: string): string;
export interface AbiParameter { readonly name?: string; readonly type: string; readonly components?: readonly AbiParameter[] }
export function functionSelector(signature: string): string;
export function encodeAbiParameters(types: readonly (string | AbiParameter)[], values: readonly unknown[]): string;
export function encodeFunctionData(signature: string, types: readonly (string | AbiParameter)[], values: readonly unknown[]): string;
