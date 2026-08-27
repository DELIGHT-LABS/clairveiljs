import test from "node:test";
import assert from "node:assert/strict";
import {
  privacyNoteV1CircuitOrder,
  privacyNoteV1PublicInputSchemaSHA256,
  validateCircuitConfigV1,
  validateExpectedCircuitIdentityV1
} from "clairveiljs/circuit-config";
import { createClairveilClient } from "clairveiljs/cosmos-client";
import { derivePubKeyFromScalar, packPointHex } from "clairveiljs/core";
import { computeAssetIdV1 } from "clairveiljs/protocol-v1";

function circuitConfig() {
  const keyHashes = ["a", "b", "c", "d"].map(letter => letter.repeat(64));
  const circuits = privacyNoteV1CircuitOrder.map((circuitId, index) => ({
    circuit_id: circuitId,
    verifying_key_sha256: keyHashes[index],
    public_input_schema_sha256: privacyNoteV1PublicInputSchemaSHA256[circuitId]
  }));
  return {
    schema_version: "v1",
    active_set_id: "privacy-note-v1",
    curve: "BN254",
    checksum_source: "consensus",
    circuit_set_identity: {
      schema_version: "v1",
      circuit_set_id: "privacy-note-v1",
      curve: "BN254",
      circuits
    },
    artifacts: circuits.map(circuit => ({
      circuit_id: circuit.circuit_id,
      artifact_type: "verifying_key",
      sha256: circuit.verifying_key_sha256
    }))
  };
}

test("CircuitConfig pins privacy-note-v1 order, schemas, and consensus VK artifacts", () => {
  const response = circuitConfig();
  const validated = validateCircuitConfigV1(response, {
    expectedCircuitIdentity: response.circuit_set_identity
  });
  assert.equal(validated.active_set_id, "privacy-note-v1");
  assert.deepEqual(
    validated.circuit_set_identity.circuits.map(circuit => circuit.circuit_id),
    privacyNoteV1CircuitOrder
  );
  assert.equal(validated.artifacts[3].sha256, response.circuit_set_identity.circuits[3].verifying_key_sha256);
});

test("CircuitConfig rejects a reordered schema, artifact disagreement, or deployment pin mismatch", () => {
  const response = circuitConfig();
  const reordered = structuredClone(response);
  [reordered.circuit_set_identity.circuits[0], reordered.circuit_set_identity.circuits[1]] = [reordered.circuit_set_identity.circuits[1], reordered.circuit_set_identity.circuits[0]];
  assert.throws(() => validateCircuitConfigV1(reordered), /circuit_id must be deposit/);

  const inconsistentArtifact = structuredClone(response);
  inconsistentArtifact.artifacts[2].sha256 = "f".repeat(64);
  assert.throws(() => validateCircuitConfigV1(inconsistentArtifact), /does not match the consensus verifying key/);

  const expected = structuredClone(response.circuit_set_identity);
  expected.circuits[0].verifying_key_sha256 = "e".repeat(64);
  assert.throws(() => validateCircuitConfigV1(response, { expectedCircuitIdentity: expected }), /does not match expectedCircuitIdentity/);
  assert.throws(() => validateExpectedCircuitIdentityV1({ ...expected, circuits: expected.circuits.slice(1) }), /exactly 4 entries/);
});

test("Cosmos CircuitConfig query returns only validated consensus identity", async () => {
  const response = circuitConfig();
  const client = createClairveilClient({
    rpc: "http://rpc.example",
    rest: "http://rest.example",
    chainId: "clairveil-test-1",
    expectedCircuitIdentity: response.circuit_set_identity
  });
  client.fetchJson = async path => {
    assert.equal(path, "/clairveil/privacy/v1/circuit_config");
    return response;
  };
  const validated = await client.assertCircuitConfig();
  assert.equal(validated.checksum_source, "consensus");
});

test("protocol preflight binds the consensus circuit identity and authoritative AssetRegistry entry", async () => {
  const response = circuitConfig();
  const assetID = computeAssetIdV1("uclair").toString(16).padStart(64, "0");
  const client = createClairveilClient({
    rpc: "http://rpc.example",
    rest: "http://rest.example",
    chainId: "clairveil-test-1"
  });
  client.fetchJson = async path => {
    if (path === "/clairveil/privacy/v1/circuit_config") return response;
    if (path === "/clairveil/privacy/v1/assets/by_denom/uclair") return {
      mapping_version: "privacy-asset-registry-v1",
      asset: { canonical_denom: "uclair", asset_id: assetID }
    };
    if (path === `/clairveil/privacy/v1/assets/by_id/${assetID}`) return {
      mapping_version: "privacy-asset-registry-v1",
      asset: { canonical_denom: "uclair", asset_id: assetID }
    };
    if (path === "/clairveil/privacy/v1/audit_config") return {
      audit_master_pubkey_hex: packPointHex(derivePubKeyFromScalar(101n)),
      audit_key_id: "master",
      audit_key_epoch: "1"
    };
    if (path === "/clairveil/privacy/v1/disclosure_config") return {
      payload_version: "privacy-fixed-v1",
      audit_disclosure_required: true,
      supported_user_policies: ["all-private"],
      supported_user_modes: ["none"]
    };
    throw new Error(`unexpected path ${path}`);
  };
  const preflight = await client.assertProtocolPreflight("uclair");
  assert.equal(preflight.circuit_config.circuit_set_identity.circuits.length, 4);
  assert.equal(preflight.asset.asset_id_hex, assetID);
  const transfer = await client.assertTransferProtocolConfig("uclair");
  assert.equal(transfer.audit_config.audit_key_id, "master");
  assert.deepEqual(transfer.disclosure_config.supported_user_modes, ["none"]);
});

test("protocol preflight fails closed when the AssetRegistry reverse mapping disagrees", async () => {
  const response = circuitConfig();
  const assetID = computeAssetIdV1("uclair").toString(16).padStart(64, "0");
  const otherAssetID = computeAssetIdV1("uother").toString(16).padStart(64, "0");
  const client = createClairveilClient({
    rpc: "http://rpc.example",
    rest: "http://rest.example",
    chainId: "clairveil-test-1"
  });
  let reverseQueries = 0;
  client.fetchJson = async path => {
    if (path === "/clairveil/privacy/v1/circuit_config") return response;
    if (path === "/clairveil/privacy/v1/assets/by_denom/uclair") return {
      mapping_version: "privacy-asset-registry-v1",
      asset: { canonical_denom: "uclair", asset_id: assetID }
    };
    if (path === `/clairveil/privacy/v1/assets/by_id/${assetID}`) {
      reverseQueries += 1;
      return {
        mapping_version: "privacy-asset-registry-v1",
        asset: { canonical_denom: "uother", asset_id: otherAssetID }
      };
    }
    throw new Error(`unexpected path ${path}`);
  };

  await assert.rejects(
    () => client.assertProtocolPreflight("uclair"),
    /asset_id does not match the requested asset ID/
  );
  assert.equal(reverseQueries, 1);
});

test("low-level proof builders cannot bypass consensus protocol preflight", async () => {
  const client = createClairveilClient({
    rpc: "http://rpc.example",
    rest: "http://rest.example",
    chainId: "clairveil-test-1",
    defaultDenom: "uclair"
  });
  const denoms = [];
  client.assertProtocolPreflight = async denom => {
    denoms.push(denom);
    throw new Error(`preflight blocked ${denom}`);
  };

  for (const [method, input, expectedDenom] of [
    ["buildPreparedTransferPayload", { denom: "uasset" }, "uasset"],
    ["buildTransferMessage", { transferDenom: "uasset" }, "uasset"],
    ["buildPreparedWithdrawProverPayload", { denom: "uasset" }, "uasset"],
    ["buildRelayWithdrawPayload", { assetDenom: "uasset" }, "uasset"],
    ["buildWithdrawMessage", { denom: "uasset" }, "uasset"]
  ]) {
    await assert.rejects(
      () => client[method](input),
      /preflight blocked uasset/
    );
    assert.equal(denoms.at(-1), expectedDenom, method);
  }
});

test("raw 2x2 transfer builders bind audit and disclosure settings to active chain config", async () => {
  const activeAuditKey = packPointHex(derivePubKeyFromScalar(101n));
  const client = createClairveilClient({
    rpc: "http://rpc.example",
    rest: "http://rest.example",
    chainId: "clairveil-test-1",
    defaultDenom: "uclair"
  });
  client.assertTransferProtocolConfig = async () => ({
    audit_config: { audit_master_pubkey_hex: activeAuditKey },
    disclosure_config: {
      supported_user_policies: ["all-private"],
      supported_user_modes: ["none"]
    }
  });

  for (const method of ["buildPreparedTransferPayload", "buildTransferMessage"]) {
    await assert.rejects(
      () => client[method]({
        transferDenom: "uclair",
        auditDisclosureTargetPubKeyHex: "aa".repeat(32)
      }),
      /transfer audit disclosure target must exactly match the active chain audit config/
    );
    await assert.rejects(
      () => client[method]({
        transferDenom: "uclair",
        userPrivacyPolicy: "amount",
        userDisclosureMode: "public"
      }),
      /does not support transfer privacy policy amount/
    );
  }
});
