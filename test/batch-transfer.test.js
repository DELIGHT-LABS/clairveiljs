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
