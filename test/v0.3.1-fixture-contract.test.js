import test from "node:test";
import assert from "node:assert/strict";
import { derivePubKeyFromScalar } from "clairveiljs/core";
import {
  computeAssetIdV1,
  computeBatchEffectIdV1,
  computeBatchUserDisclosureVectorRootV1,
  computeBatchVectorRootV1,
  computeNoteCommitmentV1,
  computeNoteNullifierV1,
  emptyNoteTreeRootsV1,
  encryptedEnvelopeV1HeaderSize,
  fieldHexV1,
  notePlaintextV1Size,
  disclosurePlaintextV1Size,
  privacyFixedV1,
  validateBatchJoinSplitCountsV1
} from "clairveiljs/protocol-v1";
import { privacyNoteV1PublicInputSchemaSHA256 } from "clairveiljs/circuit-config";
import { validateDisclosureBlindingSeparationV1 } from "clairveiljs/transfer-v5";
import { fixtureTestOptions, readFixture } from "./helpers.js";

const padField = value => fieldHexV1(value);

test("Clairveil v0.3.1 NoteV1 fixture is derived by the public note primitives", fixtureTestOptions, () => {
  const contract = readFixture("privacy_note_v1_contract.json");
  const vector = contract.vector;
  const spend = derivePubKeyFromScalar(BigInt(vector.spend_scalar));
  const view = derivePubKeyFromScalar(BigInt(vector.view_scalar));
  const note = {
    receiverSpendPubKeyX: spend.x,
    receiverSpendPubKeyY: spend.y,
    receiverViewPubKeyX: view.x,
    receiverViewPubKeyY: view.y,
    amount: BigInt(vector.amount),
    assetID: computeAssetIdV1(vector.denom),
    randomness: BigInt(vector.randomness),
    memo: "fixture"
  };

  assert.equal(contract.schema_version, "v1");
  assert.equal(padField(note.assetID), vector.asset_id_hex);
  assert.equal(padField(computeNoteCommitmentV1(note)), vector.commitment_hex);
  assert.equal(padField(computeNoteNullifierV1(note)), vector.nullifier_hex);
  const roots = emptyNoteTreeRootsV1(32);
  assert.equal(padField(roots[1]), vector.empty_root_1_hex);
  assert.equal(padField(roots[2]), vector.empty_root_2_hex);
  assert.equal(padField(roots[32]), vector.empty_root_32_hex);
  assert.deepEqual(contract.encoding, {
    version: privacyFixedV1,
    note_plaintext_bytes: notePlaintextV1Size,
    disclosure_plaintext_bytes: disclosurePlaintextV1Size,
    envelope_header_bytes: encryptedEnvelopeV1HeaderSize
  });
});

test("Clairveil v0.3.1 batch JoinSplit fixture is bound to aggregate roots and effect evidence", fixtureTestOptions, () => {
  const contract = readFixture("privacy_batch_joinsplit_v1_contract.json");
  const vector = contract.vector;
  const disclosure = contract.user_disclosure;
  assert.equal(contract.schema_version, "v1");
  assert.equal(contract.circuit_id, "batch-joinsplit-16x32-v1");
  assert.equal(contract.public_input_schema_sha256, privacyNoteV1PublicInputSchemaSHA256[contract.circuit_id]);
  assert.equal(validateBatchJoinSplitCountsV1(contract.max_inputs, contract.max_outputs), true);
  assert.throws(() => validateBatchJoinSplitCountsV1(0, 1), /1\.\.16/);
  assert.throws(() => validateBatchJoinSplitCountsV1(17, 1), /1\.\.16/);
  assert.throws(() => validateBatchJoinSplitCountsV1(1, 33), /1\.\.32/);

  const vectorValues = Array(vector.capacity).fill(0n);
  vector.active_values.forEach((value, index) => { vectorValues[index] = BigInt(value); });
  assert.equal(padField(computeBatchVectorRootV1(vector.kind, vector.count, vectorValues)), vector.root_hex);

  const policies = Array(32).fill(0);
  const rawDigests = Array(32).fill(0n);
  disclosure.policies.forEach((value, index) => { policies[index] = value; });
  disclosure.raw_digests.forEach((value, index) => { rawDigests[index] = BigInt(value); });
  assert.equal(padField(computeBatchUserDisclosureVectorRootV1(disclosure.count, policies, rawDigests)), disclosure.root_hex);

  const effect = contract.effect;
  assert.equal(computeBatchEffectIdV1({
    chainDomainHi: BigInt(effect.chain_domain_hi),
    chainDomainLo: BigInt(effect.chain_domain_lo),
    merkleRoot: BigInt(effect.merkle_root),
    inputCount: effect.input_count,
    outputCount: effect.output_count,
    nullifierRoot: BigInt(effect.nullifier_root),
    commitmentRoot: BigInt(effect.commitment_root),
    userDisclosureRoot: BigInt(effect.user_disclosure_root),
    fullDisclosureRoot: BigInt(effect.full_disclosure_root),
    payloadDigestHi: BigInt(effect.payload_digest_hi),
    payloadDigestLo: BigInt(effect.payload_digest_lo),
    expiresAtUnix: effect.expires_at_unix
  }), effect.id_hex);
});

test("Clairveil v0.3.1 disclosure-blinding fixture retains exact rejection codes", fixtureTestOptions, () => {
  const contract = readFixture("privacy_disclosure_blinding_v1_contract.json");
  assert.equal(contract.schema_version, "v1");
  for (const vector of contract.vectors) {
    const input = {
      enabled: vector.enabled,
      privacy_policy: vector.privacy_policy,
      output_randomness: vector.output_randomness,
      user_disclosure_blinding: vector.user_disclosure_blinding,
      full_disclosure_blinding: vector.full_disclosure_blinding
    };
    if (vector.valid) {
      assert.equal(validateDisclosureBlindingSeparationV1(input), true, vector.name);
      continue;
    }
    assert.throws(
      () => validateDisclosureBlindingSeparationV1(input),
      error => error?.code === vector.error_code && error?.field === vector.error_field,
      vector.name
    );
  }
});
