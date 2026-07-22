import test from "node:test";
import assert from "node:assert/strict";
import { derivePubKeyFromScalar, signNoteHash } from "clairveiljs/core";
import { base64FromBytes, bytesFromBase64 } from "clairveiljs/browser-crypto";
import {
  buildPreparedBatchTransferPayload,
  buildMsgBatchTransferFromPrepared,
  preparedBatchTransferProofVersion,
  serializeBatchTransferProofRequest,
  validatePreparedBatchTransferPayloadEnvelope
} from "clairveiljs/batch-transfer";
import { computeAssetIdV1, emptyNoteTreeRootsV1, unmarshalDisclosurePlaintextV1 } from "clairveiljs/protocol-v1";
import { createHttpProverAdapter } from "clairveiljs/prover";
import { fixtureTestOptions, readFixture } from "./helpers.js";

async function batchPayload({ privacyPolicy = 0, disclosureMode = 0 } = {}) {
  const ownerSpend = derivePubKeyFromScalar(17n);
  const ownerView = derivePubKeyFromScalar(19n);
  const recipientSpend = derivePubKeyFromScalar(23n);
  const recipientView = derivePubKeyFromScalar(29n);
  const assetID = computeAssetIdV1("uclair");
  const inputNote = {
    receiverSpendPubKeyX: ownerSpend.x, receiverSpendPubKeyY: ownerSpend.y,
    receiverViewPubKeyX: ownerView.x, receiverViewPubKeyY: ownerView.y,
    amount: 7n, assetID, randomness: 11n, memo: "input"
  };
  const outputNote = {
    receiverSpendPubKeyX: recipientSpend.x, receiverSpendPubKeyY: recipientSpend.y,
    receiverViewPubKeyX: recipientView.x, receiverViewPubKeyY: recipientView.y,
    amount: 7n, assetID, randomness: 13n, memo: "payment"
  };
  return buildPreparedBatchTransferPayload({
    creator: "clair1creator",
    chainId: "clairveil-test-1",
    expiresAtUnix: 4_102_448_400,
    inputs: [{
      note: inputNote,
      merklePath: emptyNoteTreeRootsV1(32).slice(0, 32).map(value => value.toString(16).padStart(64, "0")),
      merklePathHelper: Array(32).fill(0)
    }],
    outputs: [{
      kind: "payment", note: outputNote, privacyPolicy, disclosureMode,
      userDisclosureBlinding: privacyPolicy ? 21n : 0n, fullDisclosureBlinding: 15n
    }],
    auditKeyId: "audit-key-1",
    auditKeyEpoch: 1,
    auditDisclosureTargetPubKey: derivePubKeyFromScalar(31n),
    selfViewDisclosureTargetPubKey: derivePubKeyFromScalar(47n),
    signer: {
      signNoteHash: intent => signNoteHash(intent, { spendScalar: 17n, spendPubKey: ownerSpend })
    }
  });
}

test("one-proof batch prover uses the Clairveil main route and binds the response hash", async () => {
  const payload = await batchPayload();
  const proof = new Uint8Array(164).fill(7);
  let call;
  const adapter = createHttpProverAdapter({
    baseURL: "https://prover.example",
    fetchImpl: async (url, init) => {
      call = { url: String(url), body: JSON.parse(init.body) };
      return new Response(JSON.stringify({
        version: "v1",
        proof: {
          version: preparedBatchTransferProofVersion,
          request_payload_hash: payload.payload_hash,
          proof: base64FromBytes(proof),
          circuit_set_id: "privacy-note-v1"
        }
      }), { status: 200 });
    }
  });
  const response = await adapter.proveBatchTransfer(payload);
  assert.equal(call.url, "https://prover.example/v1/proofs/batch-transfer");
  assert.deepEqual(call.body, JSON.parse(serializeBatchTransferProofRequest(payload)));
  assert.deepEqual(response.proof.proof_bytes, proof);

  const message = buildMsgBatchTransferFromPrepared(payload, response.proof, { nowUnix: 1_700_000_000 });
  assert.equal(message.proof.length, 164);
  assert.equal(message.nullifiers.length, 1);
  assert.equal(message.outputs.length, 1);
  assert.equal(message.creator, "clair1creator");
});

test("one-proof batch prover rejects a proof bound to another prepared operation", async () => {
  const payload = await batchPayload();
  const adapter = createHttpProverAdapter({
    baseURL: "https://prover.example",
    fetchImpl: async () => new Response(JSON.stringify({
      version: "v1",
      proof: {
        version: preparedBatchTransferProofVersion,
        request_payload_hash: "0000000000000000000000000000000000000000000000000000000000000006",
        proof: base64FromBytes(new Uint8Array(164))
      }
    }), { status: 200 })
  });
  await assert.rejects(() => adapter.proveBatchTransfer(payload), /payload hash mismatch/);
});

test("one-proof batch preparation binds public disclosure and rejects post-signature mutation", async () => {
  const payload = await batchPayload({ privacyPolicy: 7, disclosureMode: 1 });
  const output = payload.message_outputs[0];
  const disclosure = unmarshalDisclosurePlaintextV1(bytesFromBase64(output.user_disclosure_payload));
  assert.equal(disclosure.plane, 1);
  assert.equal(disclosure.policy, 7);
  assert.equal(disclosure.disclosedFieldBitmap, 7);
  assert.notEqual(output.user_disclosure_digest, "");
  assert.throws(
    () => validatePreparedBatchTransferPayloadEnvelope({ ...payload, audit_key_id: "another-audit-key" }),
    /payload hash mismatch/
  );
});

test("Session 3B fixture defines the one-proof batch boundary and representative E2E", fixtureTestOptions, async () => {
  const contract = readFixture("privacy_batch_transfer_session3b_contract.json");
  assert.equal(contract.schema_version, "clairveil.batch-transfer.session3b.v1");
  assert.equal(contract.payload_version, "batch-transfer-payload-v1");
  assert.equal(contract.proof_version, "batch-transfer-proof-v1");
  assert.equal(contract.circuit_set_id, "privacy-note-v1");
  assert.equal(contract.circuit_id, "batch-joinsplit-16x32-v1");
  assert.equal(contract.prover_route, "/v1/proofs/batch-transfer");
  assert.equal(contract.request_version, "v1");
  assert.equal(contract.response_version, "v1");
  assert.equal(contract.max_inputs, 16);
  assert.equal(contract.max_outputs, 32);
  assert.deepEqual(contract.payroll, {
    operation_to_proof_job: "one-to-one",
    operation_to_input_reservations: "one-to-many",
    operation_to_item_outputs: "one-to-many",
    batch_and_item_status_separate: true,
    required_output_evidence: ["output_index", "commitment", "recipient_hash", "amount", "denom_or_asset_id", "user_digest", "full_digest", "audit_key_id", "audit_key_epoch"]
  });
  assert.deepEqual(contract.scan, {
    cursor_order: ["height", "global_sequence", "output_index"],
    typed_query_required: true,
    abci_fallback_after_typed_failure: false,
    safe_mode_decrypts_view_tag_mismatch: true,
    commitment_recomputation_required: true
  });
  assert.equal(contract.restart_retry.automatic_multi_prover_failover, false);
  assert.equal(contract.restart_retry.item_success_requires_output_evidence, true);

  for (const vector of contract.cases) {
    const inputTotal = vector.input_amounts.reduce((sum, amount) => sum + BigInt(amount), 0n);
    const paymentTotal = vector.payment_amounts.reduce((sum, amount) => sum + BigInt(amount), 0n);
    assert.ok(vector.input_amounts.length >= 1 && vector.input_amounts.length <= contract.max_inputs, vector.id);
    assert.ok(vector.expected_output_roles.length >= 1 && vector.expected_output_roles.length <= contract.max_outputs, vector.id);
    assert.equal(vector.expected_output_roles.length, vector.disclosure_modes.length, vector.id);
    assert.ok(paymentTotal <= inputTotal, vector.id);
    assert.deepEqual(
      vector.expected_output_roles.filter(role => role === "payment"),
      Array(vector.payment_amounts.length).fill("payment"),
      vector.id
    );
    assert.ok(vector.expected_output_roles.every((role, index) =>
      role === "payment" || (role === "change" && index === vector.payment_amounts.length) ||
      (role === "padding" && index >= vector.payment_amounts.length)
    ), vector.id);
    assert.ok(vector.disclosure_modes.every(mode => ["none", "public", "recipient-encrypted"].includes(mode)), vector.id);
  }

  const first = contract.cases.find(vector => vector.id === "one-input-one-payment");
  const payload = await batchPayload();
  const proof = {
    version: preparedBatchTransferProofVersion,
    request_payload_hash: payload.payload_hash,
    proof: base64FromBytes(new Uint8Array(164).fill(7)),
    circuit_set_id: contract.circuit_set_id
  };
  const message = buildMsgBatchTransferFromPrepared(payload, proof, { nowUnix: 1_700_000_000 });
  assert.equal(message.nullifiers.length, first.input_amounts.length);
  assert.equal(message.outputs.length, first.expected_output_roles.length);
  assert.equal(message.outputs[0].selfViewDisclosurePayload.length, 472);
  assert.deepEqual(JSON.parse(serializeBatchTransferProofRequest(payload)).version, contract.request_version);
});
