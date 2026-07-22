import test from "node:test";
import assert from "node:assert/strict";
import {
  privacyNoteV1CircuitOrder,
  privacyNoteV1PublicInputSchemaSHA256,
  validateCircuitConfigV1,
  validateExpectedCircuitIdentityV1
} from "clairveiljs/circuit-config";
import { createClairveilClient } from "clairveiljs/cosmos-client";
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
    assert.equal(path, "/clairveil/privacy/v1/assets/by_denom/uclair");
    return {
      mapping_version: "privacy-asset-registry-v1",
      asset: { canonical_denom: "uclair", asset_id: assetID }
    };
  };
  const preflight = await client.assertProtocolPreflight("uclair");
  assert.equal(preflight.circuit_config.circuit_set_identity.circuits.length, 4);
  assert.equal(preflight.asset.asset_id_hex, assetID);
});
