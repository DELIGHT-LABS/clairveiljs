import test from "node:test";
import assert from "node:assert/strict";
import { derivePubKeyFromScalar, packPoint } from "clairveiljs/core";
import { base64FromBytes } from "clairveiljs/browser-crypto";
import {
  buildMsgBatchTransferFromPrepared,
  preparedBatchTransferPayloadVersion,
  preparedBatchTransferProofVersion
} from "clairveiljs/batch-transfer";
import { encryptedEnvelopeKindV1, wrapEncryptedEnvelopeV1 } from "clairveiljs/protocol-v1";
import { createHttpProverAdapter } from "clairveiljs/prover";

function field(value) {
  const output = new Uint8Array(32);
  output[31] = value;
  return output;
}

function batchPayload() {
  const audit = derivePubKeyFromScalar(31n);
  const transferCiphertext = wrapEncryptedEnvelopeV1(encryptedEnvelopeKindV1.transferNote, new Uint8Array(410));
  const auditPayload = wrapEncryptedEnvelopeV1(encryptedEnvelopeKindV1.auditDisclosure, new Uint8Array(452));
  return {
    version: preparedBatchTransferPayloadVersion,
    circuit_set_id: "privacy-note-v1",
    creator: "clair1creator",
    chain_id: "clairveil-test-1",
    expires_at_unix: 4_102_448_400,
    root: base64FromBytes(field(1)),
    inputs: [{ nullifier: base64FromBytes(field(2)) }],
    outputs: [{}],
    message_outputs: [{
      commitment: base64FromBytes(field(3)),
      ciphertext: base64FromBytes(transferCiphertext),
      view_tag: base64FromBytes(Uint8Array.of(1, 2)),
      user_privacy_policy: 0,
      user_disclosure_mode: 0,
      user_disclosure_digest: "",
      user_disclosure_target_pubkey: "",
      user_disclosure_payload: "",
      full_disclosure_digest: base64FromBytes(field(4)),
      audit_disclosure_payload: base64FromBytes(auditPayload),
      self_view_disclosure_payload: ""
    }],
    audit_key_id: "audit-key-1",
    audit_key_epoch: 1,
    audit_disclosure_target_pubkey: base64FromBytes(packPoint(audit)),
    payload_hash: "0000000000000000000000000000000000000000000000000000000000000005"
  };
}

test("one-proof batch prover uses the Clairveil main route and binds the response hash", async () => {
  const payload = batchPayload();
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
  assert.deepEqual(call.body, { version: "v1", payload });
  assert.deepEqual(response.proof.proof_bytes, proof);

  const message = buildMsgBatchTransferFromPrepared(payload, response.proof, { nowUnix: 1_700_000_000 });
  assert.equal(message.proof.length, 164);
  assert.equal(message.nullifiers.length, 1);
  assert.equal(message.outputs.length, 1);
  assert.equal(message.creator, "clair1creator");
});

test("one-proof batch prover rejects a proof bound to another prepared operation", async () => {
  const payload = batchPayload();
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
