import test from "node:test";
import assert from "node:assert/strict";
import {
  assetRegistryVersionV1,
  canonicalAssetDenomV1,
  canonicalAssetIDHexV1,
  createAssetRegistryResolverV1,
  normalizeAssetRegistryEntryV1,
  normalizeAssetRegistryQueryResponseV1
} from "clairveiljs/asset-registry";
import { canonicalFieldBytes } from "clairveiljs/core";
import { base64FromBytes } from "clairveiljs/browser-crypto";
import { computeAssetIdV1 } from "clairveiljs/protocol-v1";
import { createClairveilPublicClient } from "clairveiljs/browser-public";
import { createClairveilClient } from "clairveiljs/cosmos";

const denom = "factory/clair1module/uclair";
const assetID = computeAssetIdV1(denom);
const assetIDHex = assetID.toString(16).padStart(64, "0");

function response(overrides = {}) {
  return {
    mapping_version: assetRegistryVersionV1,
    asset: {
      canonical_denom: denom,
      asset_id: base64FromBytes(canonicalFieldBytes(assetID))
    },
    ...overrides
  };
}

test("AssetRegistryV1 validates version, canonical asset field, and both query directions", () => {
  const byDenom = normalizeAssetRegistryQueryResponseV1(response(), { canonical_denom: denom });
  const byID = normalizeAssetRegistryQueryResponseV1(response(), { asset_id_hex: assetIDHex });
  assert.equal(byDenom.mapping_version, assetRegistryVersionV1);
  assert.equal(byDenom.asset.asset_id_hex, assetIDHex);
  assert.equal(byID.asset.canonical_denom, denom);
  assert.equal(canonicalAssetDenomV1(denom), denom);
  assert.equal(canonicalAssetIDHexV1(assetIDHex.toUpperCase()), assetIDHex);

  assert.throws(
    () => normalizeAssetRegistryQueryResponseV1(response({ mapping_version: "legacy" }), { canonical_denom: denom }),
    /mapping version/
  );
  assert.throws(
    () => normalizeAssetRegistryQueryResponseV1(response({ asset: { canonical_denom: denom, asset_id: "00".repeat(32) } }), { canonical_denom: denom }),
    /non-zero canonical BN254 field/
  );
  assert.throws(
    () => normalizeAssetRegistryEntryV1({ canonical_denom: denom, asset_id: assetIDHex }, { asset_id_hex: "11".repeat(32) }),
    /requested asset ID/
  );
  assert.throws(() => canonicalAssetDenomV1(` ${denom}`), /surrounding whitespace/);
  assert.throws(() => canonicalAssetIDHexV1("00".repeat(32)), /non-zero canonical BN254 field/);
});

test("AssetRegistryV1 resolver caches verified bidirectional mappings without leaking mutable cache state", async () => {
  const calls = [];
  const resolver = createAssetRegistryResolverV1({
    async fetchAssetByDenom(requestedDenom) {
      calls.push(["denom", requestedDenom]);
      return response();
    },
    async fetchAssetByID(requestedAssetID) {
      calls.push(["id", requestedAssetID]);
      return response();
    }
  });

  const first = await resolver.resolveAsset(denom);
  first.asset_id.fill(0);
  const second = await resolver.resolveAssetByID(assetIDHex);
  assert.equal(second.asset_id_hex, assetIDHex);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], ["denom", denom]);

  resolver.clear();
  await resolver.queryAssetByID(assetIDHex);
  assert.deepEqual(calls[1], ["id", assetIDHex]);
});

test("public and Cosmos query clients expose verified AssetRegistryV1 resolver methods", async () => {
  const publicClient = createClairveilPublicClient({ rest: "http://127.0.0.1:1317" });
  const cosmosClient = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  const publicCalls = [];
  const cosmosCalls = [];
  publicClient.fetchAssetByDenom = async requestedDenom => {
    publicCalls.push(requestedDenom);
    return response();
  };
  cosmosClient.fetchAssetByID = async requestedAssetID => {
    cosmosCalls.push(requestedAssetID);
    return response();
  };

  assert.equal((await publicClient.resolveAsset(denom)).asset_id_hex, assetIDHex);
  assert.equal((await cosmosClient.resolveAssetByID(assetIDHex)).canonical_denom, denom);
  assert.deepEqual(publicCalls, [denom]);
  assert.deepEqual(cosmosCalls, [assetIDHex]);
});
