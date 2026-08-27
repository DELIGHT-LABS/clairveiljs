import test from "node:test";
import assert from "node:assert/strict";
import { Secp256k1 } from "@cosmjs/crypto";
import { toBech32 } from "@cosmjs/encoding";
import { PubKey as Secp256k1PubKey } from "cosmjs-types/cosmos/crypto/secp256k1/keys";
import { SignMode } from "cosmjs-types/cosmos/tx/signing/v1beta1/signing";
import { AuthInfo, SignDoc, TxBody, TxRaw } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import {
  MemoryDisclosureKeyRegistry,
  analyzeNotePreparation,
  assertOneProofPayrollNullifiersUnspent,
  buildExpectedPayrollEvidence,
  buildOneProofPayrollOperationEvidence,
  createOneProofPayrollArtifact,
  createOneProofPayrollBatchSignDoc,
  inspectOneProofPayrollArtifactRetry,
  markOneProofPayrollReservationBroadcastAttempting,
  markOneProofPayrollReservationProofReady,
  markOneProofPayrollReservationSubmitted,
  normalizePayrollDisclosurePolicy,
  normalizePayrollInput,
  oneProofPayrollCircuitSetId,
  oneProofPayrollOperationEvidenceHash,
  oneProofPayrollRetryDecisionTTLSeconds,
  planOneProofPayroll,
  prepareOneProofPayrollReservation,
  prepareOneProofPayrollOperation,
  provePreparedOneProofPayrollOperation,
  proveOneProofPayrollOperation,
  reconcileOneProofPayrollReservation,
  reconcileOneProofPayrollOperationEvidence,
  reconcileOneProofPayrollEvidence,
  parseOneProofPayrollArtifact,
  resumeOneProofPayrollArtifact,
  retransmitOneProofPayrollArtifact,
  reserveOneProofPayrollOperation,
  serializeOneProofPayrollArtifact,
  validateOneProofPayrollOperationEvidence
} from "clairveiljs/reference-payroll";
import { canonicalFieldBytes, derivePubKeyFromScalar, packPoint, signNoteHash } from "clairveiljs/core";
import { computeAssetIdV1, emptyNoteTreeRootsV1 } from "clairveiljs/protocol-v1";
import { base64FromBytes, bytesFromBase64, hash160, sha256, sha256Hex } from "clairveiljs/browser-crypto";
import { MemoryReservationStore, createNoteReservationManager } from "clairveiljs/reservation";
import { preparedBatchTransferProofVersion } from "clairveiljs/batch-transfer";
import { privacyNoteV1CircuitOrder, privacyNoteV1PublicInputSchemaSHA256 } from "clairveiljs/circuit-config";
import { MsgBatchTransfer, cosmosSignDocBindingHash } from "clairveiljs/cosmos-client";

const recipient = "clairs19x5u4mf4l4zqcpvr7d809fh4tjy5j50p2mwgky0nj38jpqpj7svndu3hqshu5e3s8w6pea5p30xek5p9flxjf7f44xh7cnfrlsd84pc7upgh3";
const key = Buffer.from(packPoint(derivePubKeyFromScalar(7n))).toString("hex");
const payrollSigningPrivateKey = Uint8Array.from([...new Uint8Array(31), 7]);
const payrollSigningPublicKey = Secp256k1.compressPubkey(Secp256k1.makeKeypair(payrollSigningPrivateKey).pubkey);
const payrollSignerAddress = toBech32("clair", hash160(payrollSigningPublicKey));
const otherPayrollSigningPrivateKey = Uint8Array.from([...new Uint8Array(31), 11]);
const otherPayrollSigningPublicKey = Secp256k1.compressPubkey(
  Secp256k1.makeKeypair(otherPayrollSigningPrivateKey).pubkey
);

function payrollCosmosSignDoc(message, {
  chainId = "clairveil-test-1",
  accountNumber = "7",
  memo = "Clairveil batch veiled transfer",
  publicKey = payrollSigningPublicKey,
  includePublicKey = true,
  signMode = SignMode.SIGN_MODE_DIRECT
} = {}) {
  const bodyBytes = TxBody.encode(TxBody.fromPartial({
    messages: [{
      typeUrl: MsgBatchTransfer.typeUrl,
      value: MsgBatchTransfer.encode(MsgBatchTransfer.fromPartial(message)).finish()
    }],
    memo
  })).finish();
  const authInfoBytes = AuthInfo.encode(AuthInfo.fromPartial({
    signerInfos: [{
      ...(includePublicKey ? {
        publicKey: {
          typeUrl: Secp256k1PubKey.typeUrl,
          value: Secp256k1PubKey.encode(Secp256k1PubKey.fromPartial({ key: publicKey })).finish()
        }
      } : {}),
      modeInfo: { single: { mode: signMode } },
      sequence: 3n
    }],
    fee: { amount: [], gasLimit: 25_000_000n }
  })).finish();
  return {
    bodyBytes: base64FromBytes(bodyBytes),
    authInfoBytes: base64FromBytes(authInfoBytes),
    chainId,
    accountNumber
  };
}

function signedPayrollTxRaw(signDoc, {
  privateKey = payrollSigningPrivateKey,
  signingChainId = signDoc.chainId,
  signingAccountNumber = signDoc.accountNumber,
  signature
} = {}) {
  const resolvedSignature = signature || Secp256k1.trimRecoveryByte(
    Secp256k1.createSignature(
      sha256(SignDoc.encode(SignDoc.fromPartial({
        bodyBytes: bytesFromBase64(signDoc.bodyBytes),
        authInfoBytes: bytesFromBase64(signDoc.authInfoBytes),
        chainId: signingChainId,
        accountNumber: BigInt(signingAccountNumber)
      })).finish()),
      privateKey
    ).toFixedLength()
  );
  return TxRaw.encode(TxRaw.fromPartial({
    bodyBytes: bytesFromBase64(signDoc.bodyBytes),
    authInfoBytes: bytesFromBase64(signDoc.authInfoBytes),
    signatures: [resolvedSignature]
  })).finish();
}

function payrollArtifact({
  prepared,
  execution,
  reservationBatch,
  signDoc,
  signedTxBytes,
  signedTxOptions,
  ...overrides
}) {
  return createOneProofPayrollArtifact({
    prepared,
    execution,
    reservationBatch,
    signDoc,
    signedTxBytes: signedTxBytes ?? signedPayrollTxRaw(signDoc, signedTxOptions),
    ...overrides
  });
}

function nullifierStatusMap(nullifiers, spent = false) {
  return new Map(nullifiers.map((value, index) => [
    value,
    typeof spent === "function" ? spent(index, value) : spent
  ]));
}

function checkNullifiersAs(spent) {
  return async nullifiers => nullifierStatusMap(nullifiers, spent);
}

function inspectPayrollRetry(artifact, {
  nowUnix = 1_700_000_000,
  transactionState = "not-found",
  spent = false
} = {}) {
  return inspectOneProofPayrollArtifactRetry(artifact, {
    nowUnix,
    queryTransaction: async () => transactionState,
    checkNullifiers: checkNullifiersAs(spent)
  });
}

function payrollReservationManager({
  store = new MemoryReservationStore(),
  ownerKeyId = "treasury-key",
  indexKey = "private-index",
  ...options
} = {}) {
  return createNoteReservationManager({ store, ownerKeyId, indexKey, ...options });
}

function payroll(items = [{ item_id: "salary-001", employee_id: "employee-001", recipient_address: recipient, amount: "70" }]) {
  return {
    company_id: "company-a",
    payroll_id: "2026-07",
    batch_id: "run-001",
    denom: "uclair",
    default_disclosure_policy: { user_privacy_policy: "all-private", user_disclosure_mode: "none" },
    items
  };
}

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
    circuit_set_identity: { schema_version: "v1", circuit_set_id: "privacy-note-v1", curve: "BN254", circuits },
    artifacts: circuits.map(circuit => ({ circuit_id: circuit.circuit_id, artifact_type: "verifying_key", sha256: circuit.verifying_key_sha256 }))
  };
}

test("reference payroll validates disclosure policy and active disclosure registry entries", () => {
  const privatePolicy = normalizePayrollDisclosurePolicy({ user_privacy_policy: "all-private", user_disclosure_mode: "none" });
  assert.equal(privatePolicy.user_privacy_policy, 0);
  assert.equal(privatePolicy.user_disclosure_mode, 0);
  assert.throws(
    () => normalizePayrollDisclosurePolicy({ user_privacy_policy: "amount", user_disclosure_mode: "none" }),
    /public or recipient-encrypted/
  );
  assert.throws(
    () => normalizePayrollDisclosurePolicy({ user_privacy_policy: "amount", user_disclosure_mode: "public", user_disclosure_target_pubkey_hex: key }),
    /must not include a target/
  );

  const registry = new MemoryDisclosureKeyRegistry([{
    key_id: "employee-disclosure-v1",
    scope: "employee",
    subject_id: "employee-001",
    public_key_hex: key,
    version: "v1",
    active: true
  }]);
  assert.equal(registry.lookupDisclosureKey("employee", "employee-001").key_id, "employee-disclosure-v1");
  assert.throws(() => registry.lookupDisclosureKey("employee", "employee-002"), /not found/);
  assert.throws(() => new MemoryDisclosureKeyRegistry([{
    key_id: "identity-key", scope: "employee", subject_id: "employee-002",
    public_key_hex: Buffer.from(packPoint({ x: 0n, y: 1n })).toString("hex"), version: "v1", active: true
  }]), /canonical non-identity prime-subgroup point/);
  assert.throws(() => new MemoryDisclosureKeyRegistry([{
    key_id: "invalid-key", scope: "employee", subject_id: "employee-003",
    public_key_hex: "ff".repeat(32), version: "v1", active: true
  }]), /canonical non-identity prime-subgroup point/);
});

test("reference payroll blocks legacy preparation when reserved notes are the only funding source", () => {
  const report = analyzeNotePreparation(payroll(), [
    { note_id: "large", owner_key_id: "treasury", nullifier_lookup_key: "n1", denom: "uclair", amount: "100", reservation_id: "existing" },
    { note_id: "dummy", owner_key_id: "treasury", nullifier_lookup_key: "n2", denom: "uclair", amount: "0" }
  ]);
  assert.equal(report.ready_items, 0);
  assert.equal(report.blocked_items, 1);
  assert.equal(report.reserved_note_count, 1);
  assert.equal(report.operation_hints.some(hint => hint.kind === "resolve-reservation-lock"), true);
  assert.equal(report.operation_hints.some(hint => hint.kind === "add-funds"), true);
});

test("reference payroll plans current one-proof batches without using legacy transfer-batch", () => {
  const input = payroll([
    { item_id: "salary-001", employee_id: "employee-001", recipient_address: recipient, amount: "20" },
    { item_id: "salary-002", employee_id: "employee-002", recipient_address: recipient, amount: "30" }
  ]);
  const plan = planOneProofPayroll(input, [
    { note_id: "treasury-20", owner_key_id: "treasury-key", nullifier_lookup_key: "n1", denom: "uclair", amount: "20" },
    { note_id: "treasury-30", owner_key_id: "treasury-key", nullifier_lookup_key: "n2", denom: "uclair", amount: "30" },
    { note_id: "reserved-100", owner_key_id: "treasury-key", nullifier_lookup_key: "n3", denom: "uclair", amount: "100", reservation_id: "existing" }
  ]);
  assert.equal(plan.circuit_set_id, oneProofPayrollCircuitSetId);
  assert.equal(plan.operations.length, 1);
  assert.equal(plan.operations[0].input_notes.length, 2);
  assert.equal(plan.operations[0].output_count, 2);
  assert.equal(plan.operations[0].change, 0n);
  assert.equal(plan.operations[0].items[0].batch_item_index, 0);
  assert.match(plan.operations[0].operation_id, /one-proof-16x32$/);

  const paddedPlan = planOneProofPayroll(input, [
    { note_id: "treasury-20", owner_key_id: "treasury-key", nullifier_lookup_key: "n1", denom: "uclair", amount: "20" },
    { note_id: "treasury-30", owner_key_id: "treasury-key", nullifier_lookup_key: "n2", denom: "uclair", amount: "30" }
  ], { outputMode: "exact-32" });
  assert.equal(paddedPlan.operations[0].output_mode, "exact-32");
  assert.equal(paddedPlan.operations[0].padding_count, 30);
  assert.equal(paddedPlan.operations[0].output_count, 32);
  const exact32AliasPlan = planOneProofPayroll(input, [
    { note_id: "treasury-20", owner_key_id: "treasury-key", nullifier_lookup_key: "n1", denom: "uclair", amount: "20" },
    { note_id: "treasury-30", owner_key_id: "treasury-key", nullifier_lookup_key: "n2", denom: "uclair", amount: "30" }
  ], { outputMode: "exact32" });
  assert.equal(exact32AliasPlan.operations[0].output_mode, "exact-32");

  const normalized = normalizePayrollInput(input);
  assert.equal(normalized.items[0].amount, 20n);
  const missingBatchID = payroll();
  delete missingBatchID.batch_id;
  assert.throws(() => normalizePayrollInput(missingBatchID), /payroll batch_id is required/);
  assert.throws(() => normalizePayrollInput({ ...payroll(), batch_id: " " }), /payroll batch_id is required/);
  assert.throws(
    () => planOneProofPayroll(input, [{ note_id: "wrong-owner", owner_key_id: "other", nullifier_lookup_key: "n4", denom: "uclair", amount: "20" }]),
    /preparation is required/
  );
});

test("reference payroll candidate search gives every owner a bounded share before choosing a plan", () => {
  const input = payroll([
    { item_id: "salary-001", employee_id: "employee-001", recipient_address: recipient, amount: "8" },
    { item_id: "salary-002", employee_id: "employee-002", recipient_address: recipient, amount: "105" }
  ]);
  const planForOwners = (largeOwner, exactOwner) => planOneProofPayroll(input, [
    ...Array.from({ length: 16 }, (_, index) => ({
      note_id: `large-${index}`, owner_key_id: largeOwner, nullifier_lookup_key: `large-${index}`, denom: "uclair", amount: "7"
    })),
    { note_id: "exact-8", owner_key_id: exactOwner, nullifier_lookup_key: "exact-8", denom: "uclair", amount: "8" }
  ]);

  for (const [largeOwner, exactOwner] of [["owner-a", "owner-b"], ["owner-z", "owner-a"]]) {
    const plan = planForOwners(largeOwner, exactOwner);
    assert.equal(plan.operations.length, 2);
    assert.equal(plan.operations[0].items[0].amount, 8n);
    assert.deepEqual(plan.operations[0].input_notes.map(note => note.note_id), ["exact-8"]);
    assert.equal(plan.operations[1].items[0].amount, 105n);
  }

  const crowdedInput = payroll([
    { item_id: "salary-exact", employee_id: "employee-exact", recipient_address: recipient, amount: "8" },
    ...Array.from({ length: 64 }, (_, index) => ({ item_id: `salary-${index}`, employee_id: `employee-${index}`, recipient_address: recipient, amount: "105" }))
  ]);
  const crowdedNotes = [
    ...Array.from({ length: 64 }, (_, owner) => Array.from({ length: 15 }, (_, note) => ({
      note_id: `large-${String(owner).padStart(2, "0")}-${note}`,
      owner_key_id: `owner-${String(owner).padStart(2, "0")}`,
      nullifier_lookup_key: `large-${owner}-${note}`,
      denom: "uclair",
      amount: "7"
    }))).flat(),
    { note_id: "exact-8", owner_key_id: "owner-z-exact", nullifier_lookup_key: "exact-8", denom: "uclair", amount: "8" }
  ];
  const crowdedPlan = planOneProofPayroll(crowdedInput, crowdedNotes);
  assert.equal(crowdedPlan.operations.length, 65);
  assert.deepEqual(crowdedPlan.operations[0].input_notes.map(note => note.note_id), ["exact-8"]);
});

test("reference payroll candidate search retains exact funding across more owners than its DFS visit budget", () => {
  const ownerCount = 2049;
  const plan = planOneProofPayroll(payroll([{ item_id: "salary-large-treasury", employee_id: "employee-large-treasury", recipient_address: recipient, amount: "8" }]),
    Array.from({ length: ownerCount }, (_, index) => ({
      note_id: `exact-${String(index).padStart(4, "0")}`,
      owner_key_id: `owner-${String(index).padStart(4, "0")}`,
      nullifier_lookup_key: `lookup-${index}`,
      denom: "uclair",
      amount: "8"
    }))
  );
  assert.equal(plan.operations.length, 1);
  assert.deepEqual(plan.operations[0].input_notes.map(note => note.note_id), ["exact-0000"]);
});

test("reference payroll plans every representative one-proof batch shape", () => {
  const shapes = [
    { id: "one-input-one-payment", inputs: [7], payments: [7], inputCount: 1, outputCount: 1 },
    { id: "three-input-four-output", inputs: [4, 5, 7], payments: [4, 5, 6], inputCount: 3, outputCount: 4 },
    { id: "thirty-one-payments-plus-change", inputs: Array(16).fill(100), payments: Array(31).fill(50), inputCount: 16, outputCount: 32 },
    { id: "exact-thirty-two-payments", inputs: Array(16).fill(64), payments: Array(32).fill(32), inputCount: 16, outputCount: 32 },
    { id: "explicit-zero-padding", inputs: [5], payments: [5], inputCount: 1, outputCount: 32, outputMode: "exact-32", paddingCount: 31 }
  ];
  for (const shape of shapes) {
    const plan = planOneProofPayroll(payroll(shape.payments.map((amount, index) => ({
      item_id: `${shape.id}-${index}`,
      employee_id: `${shape.id}-employee-${index}`,
      recipient_address: recipient,
      amount: String(amount)
    }))), shape.inputs.map((amount, index) => ({
      note_id: `${shape.id}-note-${index}`,
      owner_key_id: "treasury-key",
      nullifier_lookup_key: `${shape.id}-lookup-${index}`,
      denom: "uclair",
      amount: String(amount)
    })), { outputMode: shape.outputMode ?? "compact" });
    assert.equal(plan.operations.length, 1, shape.id);
    assert.equal(plan.operations[0].input_notes.length, shape.inputCount, shape.id);
    assert.equal(plan.operations[0].output_count, shape.outputCount, shape.id);
    assert.equal(plan.operations[0].padding_count, shape.paddingCount ?? 0, shape.id);
  }
});

test("reference payroll prepares one signed batch payload and binds per-item evidence", async () => {
  const ownerSpend = derivePubKeyFromScalar(17n);
  const ownerView = derivePubKeyFromScalar(19n);
  const assetID = computeAssetIdV1("uclair");
  const inputNote = {
    receiverSpendPubKeyX: ownerSpend.x, receiverSpendPubKeyY: ownerSpend.y,
    receiverViewPubKeyX: ownerView.x, receiverViewPubKeyY: ownerView.y,
    amount: 7n, assetID, randomness: 11n, memo: "treasury"
  };
  const input = payroll([{ item_id: "salary-001", employee_id: "employee-001", recipient_address: recipient, amount: "7" }]);
  const plan = planOneProofPayroll(input, [{
    note_id: "treasury-7", owner_key_id: "treasury-key", nullifier_lookup_key: "lookup-7", denom: "uclair", amount: "7",
    note: inputNote,
    merkle_path: emptyNoteTreeRootsV1(32).slice(0, 32).map(value => value.toString(16).padStart(64, "0")),
    merkle_path_helper: Array(32).fill(0)
  }]);
  const registryCalls = [];
  let circuitConfigCalls = 0;
  const prepared = await prepareOneProofPayrollOperation({
    operation: plan.operations[0],
    asset_registry: {
      queryAssetByDenom: async requestedDenom => {
        registryCalls.push(requestedDenom);
        return {
          mapping_version: "privacy-asset-registry-v1",
          asset: { canonical_denom: "uclair", asset_id: canonicalFieldBytes(assetID) }
        };
      }
    },
    circuit_config: {
      assertCircuitConfig: async () => {
        circuitConfigCalls += 1;
        return circuitConfig();
      }
    },
    creator: "clair1creator",
    chain_id: "clairveil-test-1",
    expires_at_unix: 4_102_448_400,
    audit_key_id: "audit-key-1",
    audit_key_epoch: 1,
    audit_disclosure_target_pubkey: derivePubKeyFromScalar(31n),
    disable_self_view_disclosure: true,
    output_secrets: {
      "salary-001": { randomness: 13n, full_disclosure_blinding: 15n }
    },
    signer: {
      signNoteHash: intent => signNoteHash(intent, { spendScalar: 17n, spendPubKey: ownerSpend })
    }
  });
  assert.equal(prepared.payload.circuit_set_id, oneProofPayrollCircuitSetId);
  assert.equal(prepared.circuit_config.active_set_id, oneProofPayrollCircuitSetId);
  assert.equal(prepared.expected_evidence.length, 1);
  assert.deepEqual(registryCalls, ["uclair"]);
  assert.equal(circuitConfigCalls, 1);
  assert.equal(prepared.expected_evidence[0].batch_item_index, 0);
  assert.equal(prepared.expected_evidence[0].expected_denom, "uclair");
  assert.deepEqual(buildExpectedPayrollEvidence(plan.operations[0], prepared.payload), prepared.expected_evidence);
  const paddedPlan = planOneProofPayroll(input, [{
    note_id: "treasury-7", owner_key_id: "treasury-key", nullifier_lookup_key: "lookup-7", denom: "uclair", amount: "7",
    note: inputNote,
    merkle_path: emptyNoteTreeRootsV1(32).slice(0, 32).map(value => value.toString(16).padStart(64, "0")),
    merkle_path_helper: Array(32).fill(0)
  }], { outputMode: "exact-32" });
  const paddedPrepared = await prepareOneProofPayrollOperation({
    operation: paddedPlan.operations[0],
    asset_registry: { queryAssetByDenom: async () => ({ mapping_version: "privacy-asset-registry-v1", asset: { canonical_denom: "uclair", asset_id: canonicalFieldBytes(assetID) } }) },
    circuit_config: { assertCircuitConfig: async () => circuitConfig() },
    creator: "clair1creator", chain_id: "clairveil-test-1", expires_at_unix: 4_102_448_400,
    audit_key_id: "audit-key-1", audit_key_epoch: 1, audit_disclosure_target_pubkey: derivePubKeyFromScalar(31n),
    disable_self_view_disclosure: true,
    signer: { signBatchTransfer: request => signNoteHash(request.expectedIntent, { spendScalar: 17n, spendPubKey: ownerSpend }) }
  });
  assert.equal(paddedPrepared.payload.outputs.length, 32);
  assert.deepEqual(paddedPrepared.payload.outputs.map(output => output.kind), ["payment", ...Array(31).fill("padding")]);
  assert.equal(paddedPrepared.expected_evidence.length, 1);
  const reservationStore = new MemoryReservationStore();
  const reservationManager = payrollReservationManager({ store: reservationStore });
  const reservation = await prepareOneProofPayrollReservation(reservationManager, prepared);
  assert.equal(reservation.reservation_ids.length, 1);
  assert.equal(reservation.reservations[0].status, "Proving");
  await assert.rejects(() => reserveOneProofPayrollOperation(reservationManager, plan.operations[0]), /operation_id has already been used|already reserved/i);
  const proof = await proveOneProofPayrollOperation(prepared.payload, {
    proveBatchTransfer: async payload => ({
      version: preparedBatchTransferProofVersion,
      request_payload_hash: payload.payload_hash,
      proof: base64FromBytes(new Uint8Array(164).fill(7))
    })
  });
  assert.equal(proof.request_payload_hash, prepared.payload.payload_hash);
  await assert.doesNotReject(() => assertOneProofPayrollNullifiersUnspent(prepared.payload, checkNullifiersAs(false)));
  await assert.rejects(
    () => assertOneProofPayrollNullifiersUnspent(prepared.payload, checkNullifiersAs(true)),
    error => /spent, missing, or has an invalid status/.test(error.message) &&
      !error.message.includes(prepared.input_nullifier_hexes[0])
  );
  const proofCalls = [];
  const execution = await provePreparedOneProofPayrollOperation(prepared, {
    proveBatchTransfer: async payload => ({
      version: preparedBatchTransferProofVersion,
      request_payload_hash: payload.payload_hash,
      proof: base64FromBytes(new Uint8Array(164).fill(9))
    })
  }, {
    creator: payrollSignerAddress,
    nowUnix: 1_700_000_000,
    checkNullifiers: async values => {
      proofCalls.push([...values]);
      return new Map(values.map(value => [value, false]));
    }
  });
  assert.equal(proofCalls.length, 2);
  assert.equal(execution.payload.creator, "clair1creator");
  assert.equal(execution.message.creator, payrollSignerAddress);
  assert.equal(execution.operation_evidence.payload_hash, prepared.payload.payload_hash);
  assert.match(execution.operation_evidence.proof_hash, /^[0-9a-f]{64}$/);
  assert.doesNotThrow(() => validateOneProofPayrollOperationEvidence(execution.operation_evidence, prepared));
  assert.notEqual(
    oneProofPayrollOperationEvidenceHash(execution.operation_evidence),
    oneProofPayrollOperationEvidenceHash({
      ...execution.operation_evidence,
      expected_evidence: execution.operation_evidence.expected_evidence.map(item => ({
        ...item,
        expected_amount_hash: "00".repeat(32)
      }))
    })
  );
  const proofReadyReservations = await markOneProofPayrollReservationProofReady(reservationManager, reservation, execution);
  assert.equal(proofReadyReservations[0].status, "ProofReady");
  assert.equal(proofReadyReservations[0].metadata.operation_success_evidence_required, true);
  assert.equal(proofReadyReservations[0].expected_operation_evidence_hash, oneProofPayrollOperationEvidenceHash(execution.operation_evidence));
  const markerSignDoc = payrollCosmosSignDoc(execution.message);
  const markerSignedTxBytes = signedPayrollTxRaw(markerSignDoc);
  const markerArtifact = payrollArtifact({
    prepared,
    execution,
    reservationBatch: reservation,
    signDoc: markerSignDoc,
    signedTxBytes: markerSignedTxBytes
  });
  const payrollSuccessTxHash = markerArtifact.tx_hash;
  const payrollOtherSignDoc = payrollCosmosSignDoc(execution.message, { memo: "another exact payroll transaction" });
  const payrollOtherArtifact = payrollArtifact({
    prepared,
    execution,
    reservationBatch: reservation,
    signDoc: payrollOtherSignDoc
  });
  const incompleteAttemptManager = payrollReservationManager();
  const incompleteAttemptBatch = await prepareOneProofPayrollReservation(incompleteAttemptManager, prepared);
  await markOneProofPayrollReservationProofReady(incompleteAttemptManager, incompleteAttemptBatch, execution);
  const incompleteAttemptArtifact = payrollArtifact({
    prepared,
    execution,
    reservationBatch: incompleteAttemptBatch,
    signDoc: markerSignDoc,
    signedTxBytes: markerSignedTxBytes
  });
  await incompleteAttemptManager.markBroadcastAttempting(incompleteAttemptBatch.reservation_ids, {
    leaseToken: incompleteAttemptBatch.lease_token,
    txBytesHash: incompleteAttemptArtifact.tx_bytes_hash
  });
  await assert.rejects(
    () => markOneProofPayrollReservationBroadcastAttempting(
      incompleteAttemptManager,
      incompleteAttemptBatch,
      execution,
      { artifact: incompleteAttemptArtifact }
    ),
    /missing or mismatches exact submitted_tx_hash/
  );
  await assert.rejects(
    () => markOneProofPayrollReservationSubmitted(
      incompleteAttemptManager,
      incompleteAttemptBatch,
      execution,
      {
        txHash: incompleteAttemptArtifact.tx_hash,
        txBytesHash: incompleteAttemptArtifact.tx_bytes_hash,
        signDocHash: incompleteAttemptArtifact.sign_doc_hash
      }
    ),
    /missing or mismatches exact submitted_tx_hash/
  );
  await assert.rejects(
    () => markOneProofPayrollReservationSubmitted(reservationManager, reservation, execution, {
      txHash: payrollSuccessTxHash,
      txBytesHash: markerArtifact.tx_bytes_hash,
      signDocHash: markerArtifact.sign_doc_hash
    }),
    /missing or mismatches exact submitted_tx_hash/
  );
  await assert.rejects(
    () => markOneProofPayrollReservationBroadcastAttempting(reservationManager, reservation, execution),
    /requires a verified signed artifact/
  );
  await assert.rejects(
    () => markOneProofPayrollReservationBroadcastAttempting(reservationManager, reservation, execution, {
      txHash: payrollSuccessTxHash,
      txBytesHash: markerArtifact.tx_bytes_hash,
      signDocHash: markerArtifact.sign_doc_hash
    }),
    /requires a verified signed artifact/
  );
  await assert.rejects(
    () => markOneProofPayrollReservationBroadcastAttempting(reservationManager, {
      ...reservation,
      lease_token: "another-lease-token"
    }, execution, {
      artifact: markerArtifact
    }),
    /does not match the reservation batch/
  );
  const broadcastingReservations = await markOneProofPayrollReservationBroadcastAttempting(reservationManager, reservation, execution, {
    artifact: markerArtifact
  });
  assert.equal(broadcastingReservations[0].broadcast_in_flight, true);
  assert.equal(broadcastingReservations[0].submitted_tx_hash, payrollSuccessTxHash);
  assert.equal(broadcastingReservations[0].tx_bytes_hash, markerArtifact.tx_bytes_hash);
  assert.equal(broadcastingReservations[0].sign_doc_hash, markerArtifact.sign_doc_hash);
  const foreignLeaseManager = payrollReservationManager({
    store: reservationStore,
    leaseOwner: "another-payroll-worker"
  });
  await assert.rejects(
    () => markOneProofPayrollReservationBroadcastAttempting(
      foreignLeaseManager,
      reservation,
      execution,
      { artifact: markerArtifact }
    ),
    /lease owner mismatch/
  );
  const foreignRetryInspection = await inspectPayrollRetry(markerArtifact);
  let foreignRetryRPCInvoked = false;
  await assert.rejects(
    () => retransmitOneProofPayrollArtifact(markerArtifact, {
      reservationManager: foreignLeaseManager,
      nowUnix: 1_700_000_000,
      retryDecision: foreignRetryInspection.retry_decision,
      broadcastSignedTx: async () => {
        foreignRetryRPCInvoked = true;
      }
    }),
    error => /lease owner mismatch/.test(error.message) &&
      error.reservationReconciliationRequired === true &&
      error.txHash === markerArtifact.tx_hash
  );
  assert.equal(foreignRetryRPCInvoked, false);
  let expiredMarkerNow = new Date("2026-08-25T00:00:00.000Z");
  const expiredMarkerStore = new MemoryReservationStore({ now: () => expiredMarkerNow });
  const expiredMarkerManager = payrollReservationManager({
    store: expiredMarkerStore,
    leaseOwner: "expired-marker-worker",
    leaseDurationMs: 100,
    now: () => expiredMarkerNow
  });
  const expiredMarkerBatch = await prepareOneProofPayrollReservation(expiredMarkerManager, prepared);
  await markOneProofPayrollReservationProofReady(expiredMarkerManager, expiredMarkerBatch, execution);
  const expiredMarkerSignDoc = payrollCosmosSignDoc(execution.message, { memo: "expired marker lease" });
  const expiredMarkerArtifact = payrollArtifact({
    prepared,
    execution,
    reservationBatch: expiredMarkerBatch,
    signDoc: expiredMarkerSignDoc
  });
  await markOneProofPayrollReservationBroadcastAttempting(
    expiredMarkerManager,
    expiredMarkerBatch,
    execution,
    { artifact: expiredMarkerArtifact }
  );
  expiredMarkerNow = new Date(expiredMarkerNow.getTime() + 101);
  await assert.rejects(
    () => markOneProofPayrollReservationBroadcastAttempting(
      expiredMarkerManager,
      expiredMarkerBatch,
      execution,
      { artifact: expiredMarkerArtifact }
    ),
    /lease expired/
  );
  await assert.rejects(
    () => markOneProofPayrollReservationBroadcastAttempting(reservationManager, reservation, execution, {
      artifact: payrollOtherArtifact
    }),
    /does not match the durable broadcast attempt/
  );
  const submittedReservations = await markOneProofPayrollReservationSubmitted(reservationManager, reservation, execution, {
    txHash: payrollSuccessTxHash,
    txBytesHash: markerArtifact.tx_bytes_hash,
    signDocHash: markerArtifact.sign_doc_hash
  });
  assert.equal(submittedReservations[0].status, "Submitted");
  await assert.rejects(
    () => markOneProofPayrollReservationSubmitted(reservationManager, reservation, execution, {
      txHash: payrollSuccessTxHash
    }),
    /requires the exact signed transaction bytes hash/
  );
  await assert.doesNotReject(
    () => markOneProofPayrollReservationSubmitted(reservationManager, reservation, execution, {
      txHash: payrollSuccessTxHash,
      txBytesHash: markerArtifact.tx_bytes_hash,
      signDocHash: markerArtifact.sign_doc_hash
    })
  );
  assert.throws(
    () => validateOneProofPayrollOperationEvidence({ ...execution.operation_evidence, payload_hash: "00".repeat(32) }, prepared),
    /payload hash does not match/
  );
  assert.deepEqual(buildOneProofPayrollOperationEvidence(prepared).expected_evidence, prepared.expected_evidence);
  let expectedCircuitIdentity;
  let payrollSignDocInput;
  const signDoc = await createOneProofPayrollBatchSignDoc(execution, {
    cosmosClient: {
      createBatchTransferSignDoc: async input => {
        payrollSignDocInput = input;
        expectedCircuitIdentity = input.expectedCircuitIdentity;
        return payrollCosmosSignDoc(input.message);
      }
    },
    signer: payrollSignerAddress,
    pubKeyHex: "02".repeat(33),
    gas_limit: 25000000,
    fee_amount: [{ denom: "uclair", amount: "37" }]
  });
  assert.equal(signDoc.sign_doc.chainId, "clairveil-test-1");
  assert.equal(payrollSignDocInput.gas_limit, 25000000);
  assert.deepEqual(payrollSignDocInput.fee_amount, [{ denom: "uclair", amount: "37" }]);
  assert.deepEqual(expectedCircuitIdentity, prepared.circuit_config.circuit_set_identity);
  await assert.rejects(
    () => createOneProofPayrollBatchSignDoc(execution, {
      cosmosClient: { createBatchTransferSignDoc: async () => ({}) },
      signer: "clair1creator"
    }),
    /signer must match the proven message creator/
  );
  const wrongChainSignDoc = { ...signDoc.sign_doc, chainId: "another-chain-1" };
  const wrongSignerKeySignDoc = payrollCosmosSignDoc(execution.message, {
    publicKey: otherPayrollSigningPublicKey
  });
  const missingSignerKeySignDoc = payrollCosmosSignDoc(execution.message, { includePublicKey: false });
  const wrongModeSignDoc = payrollCosmosSignDoc(execution.message, {
    signMode: SignMode.SIGN_MODE_LEGACY_AMINO_JSON
  });
  const unrelatedBodyBytes = TxBody.encode(TxBody.fromPartial({
    messages: [{ typeUrl: "/cosmos.bank.v1beta1.MsgSend", value: Uint8Array.from([8, 1]) }]
  })).finish();
  const unrelatedSignDoc = {
    ...signDoc.sign_doc,
    bodyBytes: base64FromBytes(unrelatedBodyBytes)
  };
  const otherPayrollSignDoc = payrollCosmosSignDoc({
    ...execution.message,
    creator: "clair1different"
  });
  const artifactBase = { prepared, execution, reservationBatch: reservation };
  const artifactForSignDoc = (artifactSignDoc, options = {}) => payrollArtifact({
    ...artifactBase,
    signDoc: artifactSignDoc,
    ...options
  });
  const invalidSignedArtifactCases = [
    [
      "malformed Cosmos TxRaw",
      () => artifactForSignDoc(signDoc.sign_doc, { signedTxBytes: Uint8Array.from([1, 2, 3, 4]) }),
      /not a valid Cosmos TxRaw/
    ],
    ["wrong chain id", () => artifactForSignDoc(wrongChainSignDoc), /chainId does not match its proven execution/],
    [
      "signature made for another chain",
      () => artifactForSignDoc(signDoc.sign_doc, { signedTxOptions: { signingChainId: "another-chain-1" } }),
      /signature is invalid/
    ],
    [
      "signature made for another account number",
      () => artifactForSignDoc(signDoc.sign_doc, { signedTxOptions: { signingAccountNumber: "8" } }),
      /signature is invalid/
    ],
    [
      "invalid fixed signature",
      () => artifactForSignDoc(signDoc.sign_doc, { signedTxOptions: { signature: new Uint8Array(64).fill(9) } }),
      /signature is invalid/
    ],
    [
      "signature made by another private key",
      () => artifactForSignDoc(signDoc.sign_doc, { signedTxOptions: { privateKey: otherPayrollSigningPrivateKey } }),
      /signature is invalid/
    ],
    [
      "public key does not identify the message creator",
      () => artifactForSignDoc(wrongSignerKeySignDoc, {
        signedTxOptions: { privateKey: otherPayrollSigningPrivateKey }
      }),
      /public key does not identify the message creator/
    ],
    [
      "missing signer public key",
      () => artifactForSignDoc(missingSignerKeySignDoc),
      /must contain one Cosmos secp256k1 public key/
    ],
    ["non-direct sign mode", () => artifactForSignDoc(wrongModeSignDoc), /SIGN_MODE_DIRECT/],
    [
      "unrelated transaction message",
      () => artifactForSignDoc(unrelatedSignDoc),
      /must contain exactly one MsgBatchTransfer/
    ],
    [
      "sign doc does not match the proven execution",
      () => artifactForSignDoc(otherPayrollSignDoc),
      /sign-doc does not match its proven execution/
    ]
  ];
  for (const [name, create, expected] of invalidSignedArtifactCases) {
    assert.throws(create, expected, name);
  }
  const signedTxBytes = signedPayrollTxRaw(signDoc.sign_doc);
  const signedTxHash = sha256Hex(signedTxBytes).toUpperCase();
  const artifact = artifactForSignDoc(signDoc.sign_doc, { signedTxBytes });
  const signedArtifactForBatch = (batch, memo) => {
    const batchSignDoc = payrollCosmosSignDoc(execution.message, { memo });
    return payrollArtifact({
      prepared,
      execution,
      reservationBatch: batch,
      signDoc: batchSignDoc
    });
  };
  assert.equal(artifact.tx_hash, signedTxHash);
  assert.equal(artifact.tx_bytes_hash, signedTxHash.toLowerCase());
  assert.equal(artifact.sign_doc_hash, cosmosSignDocBindingHash(signDoc.sign_doc));
  assert.equal(artifactForSignDoc(signDoc.sign_doc, {
    signedTxBytes,
    txHash: signedTxHash.toLowerCase(),
    txBytesHash: signedTxHash
  }).tx_hash, signedTxHash);
  assert.throws(
    () => artifactForSignDoc(signDoc.sign_doc, {
      signedTxBytes,
      txHash: "00".repeat(32)
    }),
    /do not match tx_hash/
  );
  assert.throws(
    () => artifactForSignDoc(signDoc.sign_doc, {
      signedTxBytes,
      tx_hash: signedTxHash,
      txHash: "00".repeat(32)
    }),
    /transaction hash aliases must match/
  );
  const serializedArtifact = serializeOneProofPayrollArtifact(artifact);
  assert.match(serializedArtifact, /payroll-one-proof-artifact-v1/);
  const restoredArtifact = parseOneProofPayrollArtifact(serializedArtifact, { nowUnix: 1_700_000_000 });
  assert.equal(restoredArtifact.artifact_hash, artifact.artifact_hash);
  assert.equal(restoredArtifact.prepared.operation.input_total, prepared.operation.input_total);
  assert.deepEqual(restoredArtifact.signed_tx_bytes, signedTxBytes);
  assert.match(restoredArtifact.sign_doc_hash, /^[0-9a-f]{64}$/);
  const resumedArtifact = resumeOneProofPayrollArtifact(serializedArtifact, { nowUnix: 1_700_000_000 });
  assert.equal(resumedArtifact.next_action, "retransmit-signed-transaction");
  const retryCalls = [];
  const retryInspection = await inspectOneProofPayrollArtifactRetry(serializedArtifact, {
    nowUnix: 1_700_000_000,
    queryTransaction: async (txHash, context) => {
      retryCalls.push(["tx", txHash, context.tx_bytes_hash]);
      return "not-found";
    },
    checkNullifiers: async nullifiers => {
      retryCalls.push(["nullifiers", [...nullifiers]]);
      return new Map(nullifiers.map(value => [value, false]));
    }
  });
  assert.deepEqual(retryCalls.map(call => call[0]), ["tx", "nullifiers"]);
  assert.equal(retryCalls[0][1], signedTxHash);
  assert.equal(retryInspection.next_action, "retransmit-signed-transaction");
  assert.equal(retryInspection.transaction_state, "not-found");
  assert.equal(retryInspection.retry_decision.tx_hash, signedTxHash);
  assert.equal(oneProofPayrollRetryDecisionTTLSeconds, 30);
  assert.equal(
    retryInspection.retry_decision.expires_at_unix,
    retryInspection.retry_decision.issued_at_unix + oneProofPayrollRetryDecisionTTLSeconds
  );
  const retransmitWithOriginalReservation = (source, options = {}) =>
    retransmitOneProofPayrollArtifact(source, {
      reservationManager,
      nowUnix: 1_700_000_000,
      broadcastSignedTx: async () => ({}),
      ...options
    });
  let retransmitted;
  await assert.rejects(
    () => retransmitWithOriginalReservation(serializedArtifact),
    /fresh inspect-issued.*retry-safe decision/
  );
  const originalDateNow = Date.now;
  let localNowMs = originalDateNow();
  Date.now = () => localNowMs;
  try {
    const shortLivedInspection = await inspectPayrollRetry(serializedArtifact, {
      nowUnix: 1_700_000_100
    });
    localNowMs += oneProofPayrollRetryDecisionTTLSeconds * 1000;
    await assert.rejects(
      () => retransmitWithOriginalReservation(serializedArtifact, {
        // A caller cannot extend the capability by replaying its old chain time.
        nowUnix: 1_700_000_100,
        retryDecision: shortLivedInspection.retry_decision
      }),
      /retry-safe decision is stale/
    );
  } finally {
    Date.now = originalDateNow;
  }
  await assert.rejects(
    () => retransmitWithOriginalReservation(serializedArtifact, {
      retryDecision: { ...retryInspection.retry_decision }
    }),
    /fresh inspect-issued.*retry-safe decision/
  );
  const differentSignedSignDoc = payrollCosmosSignDoc(execution.message, { memo: "different retry identity" });
  const differentSignedArtifact = payrollArtifact({
    prepared,
    execution,
    reservationBatch: reservation,
    signDoc: differentSignedSignDoc
  });
  await assert.rejects(
    () => retransmitWithOriginalReservation(differentSignedArtifact, {
      retryDecision: retryInspection.retry_decision
    }),
    /does not match the signed artifact identity/
  );
  await retransmitWithOriginalReservation(serializedArtifact, {
    retryDecision: retryInspection.retry_decision,
    broadcastSignedTx: async (bytes, context) => {
      retransmitted = { bytes: [...bytes], hash: context.tx_bytes_hash, txHash: context.tx_hash };
      return { txhash: context.tx_hash };
    }
  });
  assert.deepEqual(retransmitted.bytes, [...signedTxBytes]);
  assert.equal(retransmitted.hash, restoredArtifact.tx_bytes_hash);
  assert.equal(retransmitted.txHash, signedTxHash);

  const cleanRetryStore = new MemoryReservationStore();
  const cleanRetryManager = payrollReservationManager({
    store: cleanRetryStore,
    leaseOwner: "clean-payroll-worker"
  });
  const cleanRetryBatch = await prepareOneProofPayrollReservation(cleanRetryManager, prepared);
  await markOneProofPayrollReservationProofReady(cleanRetryManager, cleanRetryBatch, execution);
  const cleanRetryArtifact = signedArtifactForBatch(cleanRetryBatch, "clean internal payroll retransmit");
  const cleanRetryInspection = await inspectPayrollRetry(cleanRetryArtifact);
  assert.equal(cleanRetryInspection.next_action, "retransmit-signed-transaction");
  // Keep the already-issued lease safely long while forcing a short heartbeat
  // interval for this broadcast call.
  cleanRetryManager.leaseDurationMs = 180;
  const cleanRetryEvents = [];
  const cleanRenewLease = cleanRetryManager.renewLease.bind(cleanRetryManager);
  cleanRetryManager.renewLease = async (...args) => {
    cleanRetryEvents.push("renew");
    return cleanRenewLease(...args);
  };
  const cleanMarkAttempting = cleanRetryManager.markBroadcastAttempting.bind(cleanRetryManager);
  cleanRetryManager.markBroadcastAttempting = async (...args) => {
    cleanRetryEvents.push("marker");
    return cleanMarkAttempting(...args);
  };
  const cleanMarkSubmitted = cleanRetryManager.markSubmitted.bind(cleanRetryManager);
  cleanRetryManager.markSubmitted = async (...args) => {
    cleanRetryEvents.push("submitted");
    return cleanMarkSubmitted(...args);
  };
  await retransmitOneProofPayrollArtifact(cleanRetryArtifact, {
    reservationManager: cleanRetryManager,
    nowUnix: 1_700_000_000,
    retryDecision: cleanRetryInspection.retry_decision,
    broadcastSignedTx: async (_bytes, context) => {
      cleanRetryEvents.push("rpc");
      assert.equal(context.tx_hash, cleanRetryArtifact.tx_hash);
      await new Promise(resolve => setTimeout(resolve, 240));
      return { txhash: context.tx_hash };
    }
  });
  const cleanRetryStored = await Promise.all(
    cleanRetryBatch.reservation_ids.map(id => cleanRetryManager.getReservation(id))
  );
  assert.equal(cleanRetryStored.every(record => record.status === "Submitted"), true);
  assert.equal(cleanRetryStored.every(record => record.submitted_tx_hash === cleanRetryArtifact.tx_hash), true);
  assert.equal(cleanRetryStored.every(record => record.tx_bytes_hash === cleanRetryArtifact.tx_bytes_hash), true);
  assert.equal(cleanRetryStored.every(record => record.sign_doc_hash === cleanRetryArtifact.sign_doc_hash), true);
  assert.equal(cleanRetryEvents[0], "renew");
  assert.equal(cleanRetryEvents[1], "marker");
  assert.equal(cleanRetryEvents[2], "rpc");
  assert.equal(cleanRetryEvents.filter(event => event === "renew").length >= 2, true);
  assert.equal(cleanRetryEvents.at(-1), "submitted");

  const rpcLossStore = new MemoryReservationStore();
  const rpcLossManager = payrollReservationManager({
    store: rpcLossStore,
    leaseOwner: "rpc-loss-payroll-worker"
  });
  const rpcLossBatch = await prepareOneProofPayrollReservation(rpcLossManager, prepared);
  await markOneProofPayrollReservationProofReady(rpcLossManager, rpcLossBatch, execution);
  const rpcLossArtifact = signedArtifactForBatch(rpcLossBatch, "accepted payroll with lost RPC response");
  const rpcLossInspection = await inspectPayrollRetry(rpcLossArtifact);
  await assert.rejects(
    () => retransmitOneProofPayrollArtifact(rpcLossArtifact, {
      reservationManager: rpcLossManager,
      nowUnix: 1_700_000_000,
      retryDecision: rpcLossInspection.retry_decision,
      broadcastSignedTx: async () => {
        throw new Error("RPC response lost after transaction acceptance");
      }
    }),
    error => error.message === "RPC response lost after transaction acceptance" &&
      error.reservationReconciliationRequired === true &&
      error.txHash === rpcLossArtifact.tx_hash &&
      error.txBytesHash === rpcLossArtifact.tx_bytes_hash &&
      error.signDocHash === rpcLossArtifact.sign_doc_hash
  );
  const rpcLossUnknown = await Promise.all(
    rpcLossBatch.reservation_ids.map(id => rpcLossManager.getReservation(id))
  );
  assert.equal(rpcLossUnknown.every(record => record.status === "Unknown"), true);
  assert.equal(rpcLossUnknown.every(record => record.submitted_tx_hash === rpcLossArtifact.tx_hash), true);
  assert.equal(rpcLossUnknown.every(record => record.tx_bytes_hash === rpcLossArtifact.tx_bytes_hash), true);
  assert.equal(rpcLossUnknown.every(record => record.sign_doc_hash === rpcLossArtifact.sign_doc_hash), true);
  const rpcLossRestartedManager = payrollReservationManager({
    store: rpcLossStore,
    leaseOwner: "restarted-payroll-worker"
  });
  const rpcLossRetryInspection = await inspectPayrollRetry(rpcLossArtifact);
  await retransmitOneProofPayrollArtifact(rpcLossArtifact, {
    reservationManager: rpcLossRestartedManager,
    nowUnix: 1_700_000_000,
    retryDecision: rpcLossRetryInspection.retry_decision,
    broadcastSignedTx: async (_bytes, context) => ({ txhash: context.tx_hash })
  });
  assert.equal(
    (await rpcLossRestartedManager.getReservation(rpcLossBatch.reservation_ids[0])).status,
    "Unknown"
  );
  await assert.rejects(
    () => retransmitWithOriginalReservation(serializedArtifact, {
      retryDecision: retryInspection.retry_decision
    }),
    /fresh inspect-issued.*retry-safe decision/
  );
  const expiry = Number(prepared.payload.expires_at_unix);
  const expiredArtifact = parseOneProofPayrollArtifact(serializedArtifact, { nowUnix: expiry });
  assert.equal(expiredArtifact.artifact_hash, artifact.artifact_hash);
  assert.equal(resumeOneProofPayrollArtifact(serializedArtifact, { nowUnix: expiry }).next_action, "manual-review");
  const retryOutcomeCases = [
    {
      name: "failed transaction cannot be retransmitted",
      transactionState: "failed",
      expectedAction: "manual-review",
      expectedReason: /cannot be retried/
    },
    {
      name: "succeeded transaction reconciles",
      transactionState: "succeeded",
      spent: true,
      expectedAction: "reconcile-succeeded"
    },
    {
      name: "spent input without a transaction requires review",
      spent: index => index === 0,
      expectedAction: "manual-review"
    },
    {
      name: "expired artifact still reconciles a succeeded transaction",
      nowUnix: expiry,
      transactionState: "succeeded",
      spent: true,
      expectedAction: "reconcile-succeeded"
    },
    {
      name: "expired absent transaction requires review",
      nowUnix: expiry,
      expectedAction: "manual-review"
    }
  ];
  for (const { name, expectedAction, expectedReason, ...inspectionOptions } of retryOutcomeCases) {
    const inspection = await inspectPayrollRetry(serializedArtifact, inspectionOptions);
    assert.equal(inspection.next_action, expectedAction, name);
    if (expectedReason) assert.match(inspection.reason, expectedReason, name);
  }
  const staleInspection = await inspectPayrollRetry(serializedArtifact, { nowUnix: expiry - 1 });
  await assert.rejects(
    () => retransmitWithOriginalReservation(serializedArtifact, {
      nowUnix: expiry,
      retryDecision: staleInspection.retry_decision
    }),
    /retry-safe decision is stale/
  );
  await assert.rejects(
    () => inspectOneProofPayrollArtifactRetry(serializedArtifact, {
      nowUnix: 1_700_000_000,
      checkNullifiers: checkNullifiersAs(false)
    }),
    /transaction query callback is required/
  );
  const tamperedArtifact = JSON.parse(serializedArtifact);
  tamperedArtifact.tx_hash = "00".repeat(32);
  assert.throws(
    () => parseOneProofPayrollArtifact(JSON.stringify(tamperedArtifact), { nowUnix: 1_700_000_000 }),
    /do not match tx_hash/
  );
  const missingHashArtifact = JSON.parse(serializedArtifact);
  delete missingHashArtifact.artifact_hash;
  assert.throws(
    () => parseOneProofPayrollArtifact(JSON.stringify(missingHashArtifact), { nowUnix: 1_700_000_000 }),
    /missing its integrity hash/
  );
  assert.throws(
    () => createOneProofPayrollArtifact({ prepared, signedTxBytes: Uint8Array.from([1]) }),
    /signed transaction requires a proven execution and sign-doc/
  );
  const observed = prepared.expected_evidence.map(item => ({
    output_index: item.batch_item_index,
    commitment: item.expected_output_commitment,
    user_disclosure_digest: item.expected_user_disclosure_digest,
    full_disclosure_digest: item.expected_audit_disclosure_digest,
    recipient_hash: item.expected_recipient_hash,
    amount_hash: item.expected_amount_hash,
    denom: item.expected_denom
  }));
  const operationReconciliation = await reconcileOneProofPayrollOperationEvidence({
    prepared,
    operation_evidence: execution.operation_evidence,
    tx_succeeded: true,
    observed_outputs: observed,
    checkNullifiers: checkNullifiersAs(true)
  });
  assert.equal(operationReconciliation.status, "Succeeded");
  const rpcLossReconciliation = await reconcileOneProofPayrollReservation({
    reservationManager: rpcLossRestartedManager,
    reservationBatch: rpcLossBatch,
    prepared,
    operationEvidence: execution.operation_evidence,
    txSucceeded: true,
    txHash: rpcLossArtifact.tx_hash,
    observedOutputs: observed,
    checkNullifiers: checkNullifiersAs(true)
  });
  assert.equal(rpcLossReconciliation.reservation_action, "ConfirmedSpent");
  assert.equal(rpcLossReconciliation.reconciliation.status, "Succeeded");
  assert.equal(rpcLossReconciliation.reservations.every(record => record.status === "ConfirmedSpent"), true);
  const successfulReservationReconciliationInput = {
    reservationManager,
    reservationBatch: reservation,
    prepared,
    operationEvidence: execution.operation_evidence,
    txSucceeded: true,
    txHash: payrollSuccessTxHash,
    observedOutputs: observed,
    checkNullifiers: checkNullifiersAs(true)
  };
  const reservationReconciliation = await reconcileOneProofPayrollReservation(
    successfulReservationReconciliationInput
  );
  assert.equal(reservationReconciliation.reservation_action, "ConfirmedSpent");
  assert.equal(reservationReconciliation.reservations[0].status, "ConfirmedSpent");
  assert.equal(
    (await reconcileOneProofPayrollReservation(successfulReservationReconciliationInput)).reservation_action,
    "ConfirmedSpent"
  );
  const submittedReservationFor = async identitySuffix => {
    const manager = payrollReservationManager();
    const batch = await prepareOneProofPayrollReservation(manager, prepared);
    await markOneProofPayrollReservationProofReady(manager, batch, execution);
    const broadcastSignDoc = payrollCosmosSignDoc(execution.message, {
      memo: `submitted reservation ${identitySuffix}`
    });
    const broadcastArtifact = payrollArtifact({
      prepared,
      execution,
      reservationBatch: batch,
      signDoc: broadcastSignDoc
    });
    await markOneProofPayrollReservationBroadcastAttempting(manager, batch, execution, {
      artifact: broadcastArtifact
    });
    await markOneProofPayrollReservationSubmitted(manager, batch, execution, {
      txHash: broadcastArtifact.tx_hash,
      txBytesHash: broadcastArtifact.tx_bytes_hash,
      signDocHash: broadcastArtifact.sign_doc_hash
    });
    return { manager, batch, txHash: broadcastArtifact.tx_hash };
  };
  const failedReservation = await submittedReservationFor(11);
  const failedReconciliation = await reconcileOneProofPayrollReservation({
    reservationManager: failedReservation.manager,
    reservationBatch: failedReservation.batch,
    prepared,
    operationEvidence: execution.operation_evidence,
    txFailed: true,
    checkNullifiers: checkNullifiersAs(false)
  });
  assert.equal(failedReconciliation.reservation_action, "ReplanRequired");
  assert.equal(failedReconciliation.reservations[0].status, "ReplanRequired");
  const conflictingReservation = await submittedReservationFor(12);
  const conflictingReconciliation = await reconcileOneProofPayrollReservation({
    reservationManager: conflictingReservation.manager,
    reservationBatch: conflictingReservation.batch,
    prepared,
    operationEvidence: execution.operation_evidence,
    txSucceeded: true,
    txHash: "03".repeat(32).toUpperCase(),
    observedOutputs: observed,
    checkNullifiers: checkNullifiersAs(true)
  });
  assert.equal(conflictingReconciliation.reconciliation.status, "ManualReview");
  assert.equal(conflictingReconciliation.reservation_action, "ManualReviewRequired");
  assert.equal(conflictingReconciliation.reconciliation.error_code, "OPERATION_EVIDENCE_CONFLICT");
  assert.deepEqual(
    [...new Set(conflictingReconciliation.reconciliation.error_details.conflicts.map(conflict => conflict.field))],
    ["tx_hash"]
  );
  assert.equal(conflictingReconciliation.reservations[0].status, "ConfirmedSpent");
  assert.equal(conflictingReconciliation.reservations[0].metadata.operation_status, "ConflictSpent");
  const ambiguousReservation = await submittedReservationFor(13);
  const ambiguousReconciliation = await reconcileOneProofPayrollReservation({
    reservationManager: ambiguousReservation.manager,
    reservationBatch: ambiguousReservation.batch,
    prepared,
    operationEvidence: execution.operation_evidence,
    txSucceeded: true,
    observedOutputs: [],
    checkNullifiers: checkNullifiersAs(true)
  });
  assert.equal(ambiguousReconciliation.reservation_action, "ManualReview");
  assert.equal(ambiguousReconciliation.reservations[0].status, "ManualReview");
  const inconsistentSuccess = await reconcileOneProofPayrollOperationEvidence({
    prepared,
    operation_evidence: execution.operation_evidence,
    tx_succeeded: true,
    checkNullifiers: checkNullifiersAs(false)
  });
  assert.equal(inconsistentSuccess.status, "ManualReview");
  await assert.rejects(
    () => prepareOneProofPayrollOperation({
      operation: plan.operations[0],
      asset_registry: { canonical_denom: "uclair", asset_id: new Uint8Array(32).fill(1) },
      circuit_config: { assertCircuitConfig: async () => circuitConfig() },
      chain_id: "clairveil-test-1",
      expires_at_unix: 4_102_448_400,
      audit_key_id: "audit-key-1",
      audit_key_epoch: 1,
      audit_disclosure_target_pubkey: derivePubKeyFromScalar(31n),
      disable_self_view_disclosure: true,
      signer: { signBatchTransfer: request => signNoteHash(request.expectedIntent, { spendScalar: 17n, spendPubKey: ownerSpend }) }
    }),
    /AssetRegistryV1 asset_id does not match/
  );
  await assert.rejects(
    () => prepareOneProofPayrollOperation({
      operation: plan.operations[0],
      asset_registry: { canonical_denom: "uclair", asset_id: canonicalFieldBytes(assetID) },
      chain_id: "clairveil-test-1",
      expires_at_unix: 4_102_448_400,
      audit_key_id: "audit-key-1",
      audit_key_epoch: 1,
      audit_disclosure_target_pubkey: derivePubKeyFromScalar(31n),
      disable_self_view_disclosure: true,
      signer: { signBatchTransfer: request => signNoteHash(request.expectedIntent, { spendScalar: 17n, spendPubKey: ownerSpend }) }
    }),
    /authoritative CircuitConfig resolver is required/
  );
  assert.equal(reconcileOneProofPayrollEvidence({ expected_evidence: prepared.expected_evidence, observed_outputs: observed, tx_succeeded: true })[0].status, "Succeeded");
  assert.equal(reconcileOneProofPayrollEvidence({ expected_evidence: prepared.expected_evidence, tx_succeeded: true })[0].status, "ManualReview");
  assert.equal(reconcileOneProofPayrollEvidence({ expected_evidence: prepared.expected_evidence })[0].status, "Pending");
});
