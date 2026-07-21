import { bytesFromBase64, bytesFromHex, hexFromBytes } from "../core/browser-crypto.js";
import { FIELD_MODULUS, bytesToBigIntBE } from "../core/crypto.js";
import { computeAssetIdV1 } from "./protocol-v1.js";

/** The only AssetRegistryV1 response version accepted by the privacy-note-v1 SDK. */
export const assetRegistryVersionV1 = "privacy-asset-registry-v1";

function text(value) {
  return String(value ?? "").trim();
}

function bytesEqual(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function aliasValue(source, aliases, label, normalize = value => value) {
  const values = aliases
    .filter(key => source?.[key] !== undefined && source?.[key] !== null)
    .map(key => ({ key, value: normalize(source[key]) }));
  if (!values.length) return undefined;
  const first = values[0].value;
  if (values.some(entry => entry.value !== first)) {
    throw new Error(`${label} aliases disagree`);
  }
  return first;
}

function entryAssetIDValue(source, label) {
  const values = ["asset_id", "assetId"]
    .filter(key => source?.[key] !== undefined && source?.[key] !== null)
    .map(key => ({ key, value: assetIDBytes(source[key], label) }));
  if (!values.length) throw new Error(`${label} is required`);
  const first = values[0].value;
  if (values.some(entry => !bytesEqual(entry.value, first))) {
    throw new Error(`${label} aliases disagree`);
  }
  return first;
}

/** Canonical Cosmos denom accepted by AssetRegistryV1 queries. */
export function canonicalAssetDenomV1(denom) {
  if (typeof denom !== "string") throw new Error("canonical asset denom must be a string");
  if (denom !== denom.trim()) throw new Error("canonical asset denom must not include surrounding whitespace");
  if (!/^[a-zA-Z][a-zA-Z0-9/:._-]{2,127}$/.test(denom)) {
    throw new Error("canonical asset denom is invalid");
  }
  return denom;
}

/** Canonical 32-byte lowercase asset-ID hex used by the reverse registry query. */
export function canonicalAssetIDHexV1(assetID) {
  if (typeof assetID !== "string") throw new Error("asset ID must be canonical 32-byte hex");
  if (assetID !== assetID.trim() || !/^[0-9a-fA-F]{64}$/.test(assetID)) {
    throw new Error("asset ID must be canonical 32-byte hex");
  }
  const bytes = bytesFromHex(assetID, "asset ID");
  const field = bytesToBigIntBE(bytes);
  if (field === 0n || field >= FIELD_MODULUS) {
    throw new Error("asset ID must be a non-zero canonical BN254 field element");
  }
  return hexFromBytes(bytes);
}

/** Decode a wire AssetRegistryV1 asset ID (protobuf JSON base64 or canonical hex). */
export function assetIDBytesV1(value, label = "AssetRegistryV1 asset_id") {
  return assetIDBytes(value, label);
}

function assetIDBytes(value, label) {
  let bytes;
  if (value instanceof Uint8Array) bytes = Uint8Array.from(value);
  else if (ArrayBuffer.isView(value)) bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
  else if (value instanceof ArrayBuffer) bytes = new Uint8Array(value).slice();
  else {
    if (typeof value !== "string" || value !== value.trim() || !value) {
      throw new Error(`${label} must be 32-byte base64 or hex`);
    }
    if (/^[0-9a-fA-F]{64}$/.test(value)) bytes = bytesFromHex(value, label);
    else {
      try {
        bytes = bytesFromBase64(value, label);
      } catch {
        throw new Error(`${label} must be 32-byte base64 or hex`);
      }
    }
  }
  if (bytes.length !== 32) throw new Error(`${label} must be exactly 32 bytes`);
  return bytes;
}

function normalizedAsset(entry) {
  return {
    canonical_denom: entry.canonical_denom,
    asset_id: Uint8Array.from(entry.asset_id),
    asset_id_hex: entry.asset_id_hex,
    asset_id_field: entry.asset_id_field
  };
}

function normalizedResponse(response) {
  return Object.freeze({
    mapping_version: response.mapping_version,
    asset: Object.freeze(normalizedAsset(response.asset))
  });
}

/**
 * Validate a consensus AssetRegistryV1 entry. It is deliberately not a
 * denom-display helper: callers must obtain an entry from the chain query.
 */
export function normalizeAssetRegistryEntryV1(entry, expected = {}) {
  const raw = entry?.asset ?? entry?.entry ?? entry;
  if (!raw || typeof raw !== "object") throw new Error("authoritative AssetRegistryV1 entry is required");
  const canonicalDenom = aliasValue(
    raw,
    ["canonical_denom", "canonicalDenom", "denom"],
    "AssetRegistryV1 canonical denom",
    value => String(value)
  );
  if (canonicalDenom === undefined) throw new Error("AssetRegistryV1 canonical denom is required");
  const denom = canonicalAssetDenomV1(canonicalDenom);
  const assetBytes = entryAssetIDValue(raw, "AssetRegistryV1 asset_id");
  if (assetBytes.length !== 32) throw new Error("AssetRegistryV1 asset_id must be exactly 32 bytes");
  const assetID = bytesToBigIntBE(assetBytes);
  if (assetID === 0n || assetID >= FIELD_MODULUS) {
    throw new Error("AssetRegistryV1 asset_id must be a non-zero canonical BN254 field element");
  }
  if (assetID !== computeAssetIdV1(denom)) {
    throw new Error("AssetRegistryV1 asset_id does not match canonical denom");
  }
  const expectedDenom = expected.canonical_denom ?? expected.canonicalDenom ?? expected.denom;
  if (expectedDenom !== undefined && denom !== canonicalAssetDenomV1(expectedDenom)) {
    throw new Error("AssetRegistryV1 denom does not match the requested denom");
  }
  const expectedID = expected.asset_id_hex ?? expected.assetIdHex ?? expected.assetIDHex;
  if (expectedID !== undefined && hexFromBytes(assetBytes) !== canonicalAssetIDHexV1(expectedID)) {
    throw new Error("AssetRegistryV1 asset_id does not match the requested asset ID");
  }
  return Object.freeze({
    canonical_denom: denom,
    asset_id: Uint8Array.from(assetBytes),
    asset_id_hex: hexFromBytes(assetBytes),
    asset_id_field: assetID
  });
}

/** Validate a complete AssetByDenom/AssetByID gateway response and its version. */
export function normalizeAssetRegistryQueryResponseV1(response, expected = {}) {
  if (!response || typeof response !== "object") throw new Error("AssetRegistryV1 query response is required");
  const mappingVersion = aliasValue(
    response,
    ["mapping_version", "mappingVersion"],
    "AssetRegistryV1 mapping version",
    value => text(value)
  );
  if (mappingVersion !== assetRegistryVersionV1) {
    throw new Error(`unsupported AssetRegistryV1 mapping version ${JSON.stringify(mappingVersion ?? "")}`);
  }
  if (!response.asset || typeof response.asset !== "object") {
    throw new Error("AssetRegistryV1 query response asset is required");
  }
  return normalizedResponse({
    mapping_version: mappingVersion,
    asset: normalizeAssetRegistryEntryV1(response.asset, expected)
  });
}

/**
 * A reusable verified registry resolver. Successful mappings can be cached:
 * registry entries are consensus one-to-one and immutable, while callers get
 * copies so mutation cannot poison the resolver cache.
 */
export class AssetRegistryResolverV1 {
  #queryClient;
  #cache;
  #byDenom = new Map();
  #byID = new Map();

  constructor(queryClient, { cache = true } = {}) {
    if (!queryClient || typeof queryClient.fetchAssetByDenom !== "function" || typeof queryClient.fetchAssetByID !== "function") {
      throw new Error("AssetRegistryResolverV1 requires fetchAssetByDenom and fetchAssetByID query methods");
    }
    this.#queryClient = queryClient;
    this.#cache = cache !== false;
  }

  clear() {
    this.#byDenom.clear();
    this.#byID.clear();
  }

  async queryAssetByDenom(denom) {
    const canonicalDenom = canonicalAssetDenomV1(denom);
    const cached = this.#byDenom.get(canonicalDenom);
    if (cached) return normalizedResponse(await cached);
    const result = normalizeAssetRegistryQueryResponseV1(
      await this.#queryClient.fetchAssetByDenom(canonicalDenom),
      { canonical_denom: canonicalDenom }
    );
    this.#remember(result);
    return normalizedResponse(result);
  }

  async queryAssetByID(assetIDHex) {
    const canonicalID = canonicalAssetIDHexV1(assetIDHex);
    const cached = this.#byID.get(canonicalID);
    if (cached) return normalizedResponse(await cached);
    const result = normalizeAssetRegistryQueryResponseV1(
      await this.#queryClient.fetchAssetByID(canonicalID),
      { asset_id_hex: canonicalID }
    );
    this.#remember(result);
    return normalizedResponse(result);
  }

  async resolveAsset(denom) {
    return (await this.queryAssetByDenom(denom)).asset;
  }

  async resolveAssetByDenom(denom) {
    return this.resolveAsset(denom);
  }

  async resolveAssetByID(assetIDHex) {
    return (await this.queryAssetByID(assetIDHex)).asset;
  }

  #remember(result) {
    if (!this.#cache) return;
    const stored = Promise.resolve(normalizedResponse(result));
    this.#byDenom.set(result.asset.canonical_denom, stored);
    this.#byID.set(result.asset.asset_id_hex, stored);
  }
}

export function createAssetRegistryResolverV1(queryClient, options) {
  return new AssetRegistryResolverV1(queryClient, options);
}
