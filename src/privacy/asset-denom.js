/** Canonical Cosmos denom used by privacy-note-v1 asset-ID hashing and registry queries. */
export function canonicalAssetDenomV1(denom) {
  if (typeof denom !== "string") throw new Error("canonical asset denom must be a string");
  if (denom !== denom.trim()) throw new Error("canonical asset denom must not include surrounding whitespace");
  if (!/^[a-zA-Z][a-zA-Z0-9/:._-]{2,127}$/.test(denom)) {
    throw new Error("canonical asset denom is invalid");
  }
  return denom;
}
