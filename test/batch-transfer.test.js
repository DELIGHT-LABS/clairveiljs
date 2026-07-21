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
    disableSelfViewDisclosure: true,
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

test("one-proof batch contract fixture keeps the payroll operation/evidence boundary", fixtureTestOptions, () => {
  const contract = readFixture("privacy_batch_transfer_v1_contract.json");
  assert.equal(contract.schema_version, "clairveil.batch-transfer.contract.v1");
  assert.equal(contract.circuit_set_id, "privacy-note-v1");
  assert.equal(contract.prover_route, "/v1/proofs/batch-transfer");
  assert.equal(contract.max_inputs, 16);
  assert.equal(contract.max_outputs, 32);
  assert.deepEqual(contract.payroll, {
    operation_to_proof_job: "one-to-one",
    operation_to_input_reservations: "one-to-many",
    operation_to_item_outputs: "one-to-many",
    batch_and_item_status_separate: true,
    required_output_evidence: ["output_index", "commitment", "recipient_hash", "amount", "denom_or_asset_id", "user_digest", "full_digest", "audit_key_id", "audit_key_epoch"]
  });
  assert.equal(contract.restart_retry.automatic_multi_prover_failover, false);
  assert.equal(contract.restart_retry.item_success_requires_output_evidence, true);
});
