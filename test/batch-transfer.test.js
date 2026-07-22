import test from "node:test";
import assert from "node:assert/strict";
import { derivePubKeyFromScalar, packPoint, signNoteHash } from "clairveiljs/core";
import { base64FromBytes, bytesFromBase64, hexFromBytes } from "clairveiljs/browser-crypto";
import {
  buildPreparedBatchTransferPayload,
  buildMsgBatchTransferFromPrepared,
  preparedBatchTransferProofVersion,
  signValidatedBatchTransferIntentV1,
  serializeBatchTransferProofRequest,
  validateBatchTransferSigningRequestV1,
  validatePreparedBatchTransferPayloadEnvelope
} from "clairveiljs/batch-transfer";
import {
  computeAssetIdV1,
  computeNoteCommitmentV1,
  computeNoteTreeNodeV1,
  emptyNoteTreeRootsV1,
  fieldHexV1,
  unmarshalDisclosurePlaintextV1
} from "clairveiljs/protocol-v1";
import { createHttpProverAdapter } from "clairveiljs/prover";
import { createClairveilClient } from "clairveiljs/cosmos";
import {
  decodeBatchAuditDisclosureFromScanOutput,
  decodeBatchSelfViewDisclosureFromScanOutput,
  decodeBatchUserDisclosureFromScanOutput
} from "clairveiljs/disclosure";
import { batchTransferConformanceFixtureName } from "clairveiljs/conformance";
import { fixtureTestOptions, readFixture } from "./helpers.js";

function batchMerklePaths(notes) {
  const emptyRoots = emptyNoteTreeRootsV1(32);
  const paths = notes.map(() => []);
  const helpers = notes.map(() => []);
  let layer = notes.map(computeNoteCommitmentV1);
  for (let level = 0; level < 32; level += 1) {
    for (let inputIndex = 0; inputIndex < notes.length; inputIndex += 1) {
      const nodeIndex = inputIndex >> level;
      const siblingIndex = nodeIndex ^ 1;
      paths[inputIndex].push(fieldHexV1(layer[siblingIndex] ?? emptyRoots[level]));
      helpers[inputIndex].push(nodeIndex & 1);
    }
    const next = [];
    for (let index = 0; index < layer.length; index += 2) {
      next.push(computeNoteTreeNodeV1(level, layer[index], layer[index + 1] ?? emptyRoots[level]));
    }
    layer = next;
  }
  return { paths, helpers, root: fieldHexV1(layer[0]) };
}

function disclosurePolicyForMode(mode, fallbackPolicy, fallbackMode) {
  if (!mode) return { privacyPolicy: fallbackPolicy, disclosureMode: fallbackMode };
  if (mode === "none") return { privacyPolicy: 0, disclosureMode: 0 };
  if (mode === "public") return { privacyPolicy: 1, disclosureMode: 1 };
  if (mode === "recipient-encrypted") return { privacyPolicy: 1, disclosureMode: 2 };
  throw new Error(`unsupported fixture disclosure mode ${mode}`);
}

async function batchPayload({
  privacyPolicy = 0,
  disclosureMode = 0,
  inputAmounts = [7],
  paymentAmounts = [7],
  disclosureModes = [],
  outputRoles = [],
  selfViewEnabled = true
} = {}) {
  const ownerSpend = derivePubKeyFromScalar(17n);
  const ownerView = derivePubKeyFromScalar(19n);
  const assetID = computeAssetIdV1("uclair");
  const inputs = inputAmounts.map((amount, index) => ({
    receiverSpendPubKeyX: ownerSpend.x, receiverSpendPubKeyY: ownerSpend.y,
    receiverViewPubKeyX: ownerView.x, receiverViewPubKeyY: ownerView.y,
    amount: BigInt(amount), assetID, randomness: BigInt(11 + index), memo: `input-${index}`
  }));
  const merkle = batchMerklePaths(inputs);
  const inputTotal = inputs.reduce((sum, note) => sum + note.amount, 0n);
  const paymentTotal = paymentAmounts.reduce((sum, amount) => sum + BigInt(amount), 0n);
  if (paymentTotal > inputTotal) throw new Error("fixture batch payments exceed inputs");
  const outputs = paymentAmounts.map((amount, index) => {
    const recipientSpend = derivePubKeyFromScalar(BigInt(23 + index * 2));
    const recipientView = derivePubKeyFromScalar(BigInt(29 + index * 2));
    const { privacyPolicy: outputPolicy, disclosureMode: outputMode } = disclosurePolicyForMode(
      disclosureModes[index], privacyPolicy, disclosureMode
    );
    return {
      kind: "payment",
      note: {
        receiverSpendPubKeyX: recipientSpend.x, receiverSpendPubKeyY: recipientSpend.y,
        receiverViewPubKeyX: recipientView.x, receiverViewPubKeyY: recipientView.y,
        amount: BigInt(amount), assetID, randomness: BigInt(101 + index), memo: `payment-${index}`
      },
      privacyPolicy: outputPolicy,
      disclosureMode: outputMode,
      ...(outputMode === 2 ? { disclosureTargetPubKey: derivePubKeyFromScalar(BigInt(401 + index)) } : {}),
      userDisclosureBlinding: outputPolicy ? BigInt(2001 + index) : 0n,
      fullDisclosureBlinding: BigInt(1001 + index)
    };
  });
  const change = inputTotal - paymentTotal;
  if (change > 0n) {
    const index = outputs.length;
    outputs.push({
      kind: "change",
      note: {
        receiverSpendPubKeyX: ownerSpend.x, receiverSpendPubKeyY: ownerSpend.y,
        receiverViewPubKeyX: ownerView.x, receiverViewPubKeyY: ownerView.y,
        amount: change, assetID, randomness: BigInt(101 + index), memo: "change"
      },
      privacyPolicy: 0, disclosureMode: 0, userDisclosureBlinding: 0n, fullDisclosureBlinding: BigInt(1001 + index)
    });
  }
  const paddingCount = outputRoles.filter(role => role === "padding").length;
  for (let index = 0; index < paddingCount; index += 1) {
    const outputIndex = outputs.length;
    outputs.push({
      kind: "padding",
      note: {
        receiverSpendPubKeyX: ownerSpend.x, receiverSpendPubKeyY: ownerSpend.y,
        receiverViewPubKeyX: ownerView.x, receiverViewPubKeyY: ownerView.y,
        amount: 0n, assetID, randomness: BigInt(101 + outputIndex), memo: `padding-${index}`
      },
      privacyPolicy: 0, disclosureMode: 0, userDisclosureBlinding: 0n, fullDisclosureBlinding: BigInt(1001 + outputIndex)
    });
  }
  return buildPreparedBatchTransferPayload({
    creator: "clair1creator",
    chainId: "clairveil-test-1",
    expiresAtUnix: 4_102_448_400,
    root: merkle.root,
    inputs: inputs.map((note, index) => ({ note, merklePath: merkle.paths[index], merklePathHelper: merkle.helpers[index] })),
    outputs,
    auditKeyId: "audit-key-1",
    auditKeyEpoch: 1,
    auditDisclosureTargetPubKey: derivePubKeyFromScalar(31n),
    ...(selfViewEnabled ? { selfViewDisclosureTargetPubKey: derivePubKeyFromScalar(47n) } : { disableSelfViewDisclosure: true }),
    signer: {
      signBatchTransfer: request => signNoteHash(request.expectedIntent, { spendScalar: 17n, spendPubKey: ownerSpend })
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

test("Batch V1 typed-scan disclosure decoders bind output index, commitment, policy, digest, and blinding", async () => {
  const payload = await batchPayload({
    inputAmounts: [5, 7, 9],
    paymentAmounts: [4, 5, 6],
    disclosureModes: ["none", "public", "recipient-encrypted"],
    selfViewEnabled: true
  });
  const proof = {
    version: preparedBatchTransferProofVersion,
    request_payload_hash: payload.payload_hash,
    proof: base64FromBytes(new Uint8Array(164).fill(7)),
    circuit_set_id: "privacy-note-v1"
  };
  const message = buildMsgBatchTransferFromPrepared(payload, proof, { nowUnix: 1_700_000_000 });
  const output = (index, fields = {}) => ({
    ...message.outputs[index],
    eventType: "batch_transfer",
    outputIndex: index,
    txHash: new Uint8Array(32).fill(0xab),
    ...fields
  });

  const publicUser = decodeBatchUserDisclosureFromScanOutput(output(1), {
    shieldedPrefix: "clairs",
    assetDenom: "uclair"
  });
  assert.equal(publicUser.verified, true);
  assert.equal(publicUser.plane, "user");
  assert.equal(publicUser.output_index, 1);
  assert.equal(publicUser.policy, "amount");
  assert.equal(publicUser.amount, "5");
  assert.equal(publicUser.verification.plaintext_blinding_bound, true);

  const recipientScalar = 403n;
  const recipientUser = decodeBatchUserDisclosureFromScanOutput(output(2), {
    disclosureScalar: recipientScalar,
    disclosurePubKeyHex: hexFromBytes(packPoint(derivePubKeyFromScalar(recipientScalar))),
    shieldedPrefix: "clairs",
    assetDenom: "uclair"
  });
  assert.equal(recipientUser.verified, true);
  assert.equal(recipientUser.output_index, 2);
  assert.equal(recipientUser.source, "recipient_encrypted");

  const audit = decodeBatchAuditDisclosureFromScanOutput(output(2), {
    disclosureScalar: 31n,
    shieldedPrefix: "clairs",
    assetDenom: "uclair"
  });
  assert.equal(audit.verified, true);
  assert.equal(audit.plane, "audit");
  assert.equal(audit.output_index, 2);
  assert.equal(audit.amount, "6");

  const selfView = decodeBatchSelfViewDisclosureFromScanOutput(output(2), {
    disclosureScalar: 47n,
    shieldedPrefix: "clairs",
    assetDenom: "uclair"
  });
  assert.equal(selfView.verified, true);
  assert.equal(selfView.plane, "self-view");
  assert.equal(selfView.digest_hex, audit.digest_hex);

  const client = createClairveilClient({
    rest: "http://127.0.0.1:1317",
    rpc: "http://127.0.0.1:26657",
    chainId: "clairveil-test-1",
    accountPrefix: "clair",
    shieldedPrefix: "clairs"
  });
  const wrappedPublicUser = await client.decodeBatchUserDisclosure({
    output: output(1),
    assetDenom: "uclair"
  });
  assert.equal(wrappedPublicUser.digest_hex, publicUser.digest_hex);
  const wrappedAudit = await client.decodeBatchAuditDisclosure({
    output: output(2),
    disclosureScalar: 31n,
    assetDenom: "uclair"
  });
  assert.equal(wrappedAudit.digest_hex, audit.digest_hex);

  assert.throws(
    () => decodeBatchUserDisclosureFromScanOutput(output(2, { outputIndex: 1 }), {
      disclosureScalar: recipientScalar,
      disclosurePubKeyHex: hexFromBytes(packPoint(derivePubKeyFromScalar(recipientScalar)))
    }),
    /output index mismatch/
  );
  assert.throws(
    () => decodeBatchAuditDisclosureFromScanOutput(output(2, {
      fullDisclosureDigest: Uint8Array.from(message.outputs[2].fullDisclosureDigest).fill(1)
    }), { disclosureScalar: 31n }),
    /batch audit disclosure digest mismatch/
  );
});

test("one-proof batch signer validates the complete effect and global secret freshness before callback", async () => {
  let request;
  const ownerSpend = derivePubKeyFromScalar(17n);
  const ownerView = derivePubKeyFromScalar(19n);
  const assetID = computeAssetIdV1("uclair");
  const inputNote = {
    receiverSpendPubKeyX: ownerSpend.x, receiverSpendPubKeyY: ownerSpend.y,
    receiverViewPubKeyX: ownerView.x, receiverViewPubKeyY: ownerView.y,
    amount: 7n, assetID, randomness: 11n, memo: "input"
  };
  const outputNote = {
    receiverSpendPubKeyX: derivePubKeyFromScalar(23n).x, receiverSpendPubKeyY: derivePubKeyFromScalar(23n).y,
    receiverViewPubKeyX: derivePubKeyFromScalar(29n).x, receiverViewPubKeyY: derivePubKeyFromScalar(29n).y,
    amount: 7n, assetID, randomness: 13n, memo: "payment"
  };
  await buildPreparedBatchTransferPayload({
    chainId: "clairveil-test-1", expiresAtUnix: 4_102_448_400,
    inputs: [{ note: inputNote, merklePath: emptyNoteTreeRootsV1(32).slice(0, 32).map(value => value.toString(16).padStart(64, "0")), merklePathHelper: Array(32).fill(0) }],
    outputs: [{ kind: "payment", note: outputNote, privacyPolicy: 0, disclosureMode: 0, userDisclosureBlinding: 0n, fullDisclosureBlinding: 15n }],
    auditKeyId: "audit-key-1", auditKeyEpoch: 1, auditDisclosureTargetPubKey: derivePubKeyFromScalar(31n), disableSelfViewDisclosure: true,
    signer: {
      signBatchTransfer(candidate) {
        request = candidate;
        const validated = validateBatchTransferSigningRequestV1(candidate);
        return signNoteHash(validated.expected_intent, { spendScalar: 17n, spendPubKey: ownerSpend });
      }
    }
  });
  assert.equal(request.orderedInputs.length, 1);
  assert.equal(request.orderedOutputs.length, 1);
  assert.equal(request.canonicalEffect.creator, "");

  let callbacks = 0;
  const reusedSecret = {
    ...request,
    orderedOutputs: [{
      ...request.orderedOutputs[0],
      fullDisclosureBlinding: request.orderedInputs[0].randomness
    }]
  };
  await assert.rejects(
    () => signValidatedBatchTransferIntentV1({
      signBatchTransfer() {
        callbacks += 1;
        return new Uint8Array(64);
      }
    }, reusedSecret),
    /reuses an input\/output secret/
  );
  assert.equal(callbacks, 0);
});

test("one-proof batch fixture defines the batch boundary and representative E2E", fixtureTestOptions, async () => {
  const contract = readFixture(batchTransferConformanceFixtureName);
  assert.ok([
    "clairveil.batch-transfer.contract.v1",
    "clairveil.batch-transfer.session3b.v1"
  ].includes(contract.schema_version));
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

  for (const vector of contract.cases) {
    const payload = await batchPayload({
      inputAmounts: vector.input_amounts,
      paymentAmounts: vector.payment_amounts,
      disclosureModes: vector.disclosure_modes,
      outputRoles: vector.expected_output_roles,
      selfViewEnabled: vector.self_view_disclosure === "enabled"
    });
    const proof = {
      version: preparedBatchTransferProofVersion,
      request_payload_hash: payload.payload_hash,
      proof: base64FromBytes(new Uint8Array(164).fill(7)),
      circuit_set_id: contract.circuit_set_id
    };
    const message = buildMsgBatchTransferFromPrepared(payload, proof, { nowUnix: 1_700_000_000 });
    assert.equal(message.nullifiers.length, vector.input_amounts.length, vector.id);
    assert.equal(message.outputs.length, vector.expected_output_roles.length, vector.id);
    assert.deepEqual(payload.outputs.map(output => output.kind), vector.expected_output_roles, vector.id);
    assert.equal(
      message.outputs.every(output => output.selfViewDisclosurePayload.length === (vector.self_view_disclosure === "enabled" ? 472 : 0)),
      true,
      vector.id
    );
    assert.equal(JSON.parse(serializeBatchTransferProofRequest(payload)).version, contract.request_version, vector.id);
  }
});
