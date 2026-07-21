export const assetRegistryVersionV1: "privacy-asset-registry-v1";

export interface AssetRegistryEntryV1Input {
  canonical_denom?: string;
  canonicalDenom?: string;
  denom?: string;
  asset_id?: Uint8Array | ArrayBuffer | ArrayBufferView | string;
  assetId?: Uint8Array | ArrayBuffer | ArrayBufferView | string;
}

export interface NormalizedAssetRegistryEntryV1 {
  canonical_denom: string;
  asset_id: Uint8Array;
  asset_id_hex: string;
  asset_id_field: bigint;
}

export interface AssetRegistryQueryResponseV1Input {
  mapping_version?: string;
  mappingVersion?: string;
  asset?: AssetRegistryEntryV1Input;
}

export interface NormalizedAssetRegistryQueryResponseV1 {
  mapping_version: "privacy-asset-registry-v1";
  asset: NormalizedAssetRegistryEntryV1;
}

export interface AssetRegistryQueryClientV1 {
  fetchAssetByDenom(denom: string): Promise<AssetRegistryQueryResponseV1Input | object> | AssetRegistryQueryResponseV1Input | object;
  fetchAssetByID(assetIdHex: string): Promise<AssetRegistryQueryResponseV1Input | object> | AssetRegistryQueryResponseV1Input | object;
}

export function canonicalAssetDenomV1(denom: string): string;
export function canonicalAssetIDHexV1(assetID: string): string;
export function assetIDBytesV1(value: Uint8Array | ArrayBuffer | ArrayBufferView | string, label?: string): Uint8Array;
export function normalizeAssetRegistryEntryV1(entry: AssetRegistryEntryV1Input | { asset?: AssetRegistryEntryV1Input; entry?: AssetRegistryEntryV1Input }, expected?: {
  canonical_denom?: string;
  canonicalDenom?: string;
  denom?: string;
  asset_id_hex?: string;
  assetIdHex?: string;
  assetIDHex?: string;
}): NormalizedAssetRegistryEntryV1;
export function normalizeAssetRegistryQueryResponseV1(response: AssetRegistryQueryResponseV1Input, expected?: {
  canonical_denom?: string;
  canonicalDenom?: string;
  denom?: string;
  asset_id_hex?: string;
  assetIdHex?: string;
  assetIDHex?: string;
}): NormalizedAssetRegistryQueryResponseV1;

export class AssetRegistryResolverV1 {
  constructor(queryClient: AssetRegistryQueryClientV1, options?: { cache?: boolean });
  clear(): void;
  queryAssetByDenom(denom: string): Promise<NormalizedAssetRegistryQueryResponseV1>;
  queryAssetByID(assetIDHex: string): Promise<NormalizedAssetRegistryQueryResponseV1>;
  resolveAsset(denom: string): Promise<NormalizedAssetRegistryEntryV1>;
  resolveAssetByDenom(denom: string): Promise<NormalizedAssetRegistryEntryV1>;
  resolveAssetByID(assetIDHex: string): Promise<NormalizedAssetRegistryEntryV1>;
}

export function createAssetRegistryResolverV1(queryClient: AssetRegistryQueryClientV1, options?: { cache?: boolean }): AssetRegistryResolverV1;
