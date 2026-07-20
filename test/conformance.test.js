import test from "node:test";
import assert from "node:assert/strict";
import { fromBech32, toBech32 } from "@cosmjs/encoding";
import {
  buildRootSigningMessage,
  bytesFromHex,
  deriveDisclosureKeys,
  derivePrivacyMaterial,
  deriveSpendKeys,
  deriveViewKeys,
  encodeShieldedAddress,
  FIELD_MODULUS,
  hexFromBytes
} from "clairveiljs/core";
import {
  asymEncrypt,
  computeNoteCommitmentHex,
  computeNoteNullifierHex,
  noteSpendPubKey,
  noteViewPubKey
} from "clairveiljs/note";
import {
  parseNoteBytes,
  scanNotes
} from "clairveiljs/scan";
import {
  assertPlanCanBuildTx,
  planWithdrawNotes
} from "clairveiljs/planner";
import {
  buildPreparedWithdrawPayloadFromProof,
  buildRelayWithdrawMsgFromPayload,
  buildTransferMsgFromPayloadAndProof,
  buildWithdrawMsgFromPayload,
  computePreparedTransferPayloadHash,
  computePreparedWithdrawPayloadHash,
  computePreparedWithdrawProverPayloadHash,
  validatePreparedTransferProof,
  validateRelayWithdrawPayload,
  validatePreparedWithdrawPayload,
  validatePreparedWithdrawProof
} from "clairveiljs/payload";
import { MsgWithdraw } from "clairveiljs/cosmos";
import { derivePrivacyMaterialFromWallet } from "clairveiljs/wallet-adapter";
import {
  activeReservationStatuses,
  canRecoverReservationAfterLeaseExpiry,
  canTransitionReservation,
  createNoteReservationManager,
  hashAmount,
  hashRecipient,
  MemoryReservationStore,
  nullifierLookupKey,
  operationStatuses,
  preparePlanReservation,
  requiresReservationLeaseToken,
  reservationStatuses
} from "clairveiljs/reservation";
import { runClairveilConformanceFixtures } from "clairveiljs/conformance";
import {
  conformanceFixtureRelativePath,
  defaultConformanceFixtureDir,
  defaultConformanceFixtureNames,
  suggestClairveilConformanceFixtureDirs
} from "clairveiljs/conformance";
import {
  fixtureDir,
  fixtureTestOptions,
  hexToBase64,
  readFixture,
  utf8ToHex
} from "./helpers.js";

function goldenMaterial(rootFixture) {
  return derivePrivacyMaterial({
    address: rootFixture.address,
    pubKeyHex: rootFixture.transparent_pubkey_hex,
    signatureBase64: hexToBase64(rootFixture.signature_hex),
    shieldedPrefix: "clairs"
  });
}

function assertIdentity(material, expected) {
  const spend = deriveSpendKeys(material.rootSeed);
  const view = deriveViewKeys(material.rootSeed);
  const disclosure = deriveDisclosureKeys(material.rootSeed);

  assert.equal(spend.scalarHex, expected.spend_scalar_hex);
  assert.equal(spend.pubKeyHex, expected.spend_pubkey_hex);
  assert.equal(view.scalarHex, expected.view_scalar_hex);
  assert.equal(view.pubKeyHex, expected.view_pubkey_hex);
  assert.equal(disclosure.scalarHex, expected.disclosure_scalar_hex);
  assert.equal(disclosure.pubKeyHex, expected.disclosure_pubkey_hex);
  assert.equal(material.shieldedAddress, expected.shielded_address);
}

function foundNoteSummary(found) {
  return {
    tx_hash: found.txHash,
    height: found.height,
    nullifier: found.nullifier,
    amount: found.note.amount.toString(),
    asset_denom: "uclair",
    receiver_shielded_address: encodeShieldedAddress(
      noteSpendPubKey(found.note),
      noteViewPubKey(found.note),
      { shieldedPrefix: "clairs" }
    )
  };
}

test("Go wallet golden vectors match JS root seed, keys, and shielded addresses", fixtureTestOptions, () => {
  const vectors = readFixture("privacy_wallet_golden_vectors.json");
  assert.equal(vectors.schema_version, "v1");

  for (const [rootKey, identityKey] of [
    ["sender_root_seed", "sender"],
    ["recipient_root_seed", "recipient"]
  ]) {
    const root = vectors[rootKey];
    const message = buildRootSigningMessage(root.address, root.transparent_pubkey_hex);
    assert.equal(utf8ToHex(message), root.signing_message_hex);

    const material = goldenMaterial(root);
    assert.equal(material.signingMessage, message);
    assert.equal(material.rootSeedHex, root.root_seed_hex);
    assertIdentity(material, vectors[identityKey]);
  }
});

test("conformance helper loads selected handoff fixtures", fixtureTestOptions, async () => {
  const result = await runClairveilConformanceFixtures({
    fixtureDir,
    fixtureNames: ["privacy_wallet_golden_vectors.json"]
  });

  assert.equal(result.skipped, false);
  assert.equal(result.fixtureDir, fixtureDir);
  assert.equal(result.fixtures["privacy_wallet_golden_vectors.json"].schema_version, "v1");
});

test("conformance helper default fixtures include the reservation contract", fixtureTestOptions, async () => {
  assert.ok(defaultConformanceFixtureNames.includes("privacy_note_reservation_contract.json"));
  assert.ok(defaultConformanceFixtureNames.includes("privacy_relay_withdraw_contract.json"));
  const result = await runClairveilConformanceFixtures({ fixtureDir });
  const contract = result.fixtures["privacy_note_reservation_contract.json"];
  assert.equal(contract.version, 3);
  assert.deepEqual(contract.fixture_migration, {
    from_version: 1,
    to_version: 3,
    downstream_action: "Fail closed for malformed or unavailable nullifier/chain-time evidence, keep the lease heartbeat through ProofReady CAS, durably record leased relay handoff before external delivery, and regenerate fixture/schema validators."
  });
  assert.deepEqual(
    contract.lease_transition_preconditions.token_required_for,
    [
      ["Reserved", "Proving"],
      ["Proving", "ProofReady"],
      ["Proving", "Reserved"],
      ["Proving", "ReplanRequired"],
      ["Proving", "ManualReview"],
      ["ProofReady", "Submitted"],
      ["ProofReady", "Unknown"],
      ["ProofReady", "ReplanRequired"],
      ["ProofReady", "ManualReview"]
    ]
  );
  assert.deepEqual(
    contract.lease_transition_preconditions.recovery_without_token_after_expiry_for,
    [
    ["Proving", "ReplanRequired"],
    ["Proving", "ManualReview"],
    ["ProofReady", "ManualReview"]
    ]
  );
  assert.ok(contract.success_evidence_required.includes("matching_persisted_tx_identity"));
  assert.ok(contract.success_evidence_required.includes("expected_recipient_hash"));
  assert.ok(contract.success_evidence_required.includes("expected_amount_hash"));
  assert.deepEqual(
    contract.evidence_immutability.mutation_rejection_vectors.map(vector => vector.field),
    contract.evidence_immutability.write_once_fields
  );
  assert.deepEqual(contract.fail_closed_runtime_policy, {
    nullifier_spent_evidence: {
      spent_value: true,
      unspent_value: false,
      other_values: "unknown_excluded_from_spending"
    },
    relay_submission: {
      chain_time_source: "latest_chain_block_time",
      chain_time_required: true,
      recheck_immediately_before_broadcast: true,
      on_unavailable: "reject_submit"
    },
    heartbeat: {
      coverage: ["proof_generation", "transaction_or_sign_doc_build", "proof_ready_transition"],
      await_in_flight_before_stop: true
    },
    broadcast_boundary: {
      durable_attempt_before_external_call: true,
      retry_blocked_until_reconciled: true
    }
  });
});

test("reservation contract fixtures replay lookup, lease, and tx identity semantics", fixtureTestOptions, async () => {
  const contract = readFixture("privacy_note_reservation_contract.json");
  const vector = contract.nullifier_lookup_key.test_vectors[0];
  assert.equal(
    nullifierLookupKey(vector.index_key_utf8, vector.nullifier_utf8),
    vector.lookup_key_hex
  );
  for (const hashVector of contract.operation_hash_test_vectors || []) {
    assert.equal(hashRecipient(hashVector.recipient), hashVector.recipient_hash);
    assert.equal(
      hashAmount(hashVector.denom, hashVector.amount),
      hashVector.amount_hash
    );
  }
  for (const rejectionVector of contract.operation_hash_rejection_vectors || []) {
    if (rejectionVector.reject_hash === "recipient") {
      assert.throws(
        () => hashRecipient(rejectionVector.recipient),
        /(recipient is required|shielded address|bech32)/i
      );
    } else {
      assert.throws(
        () => hashAmount(rejectionVector.denom, rejectionVector.amount),
        /(denom is required|denom must be|amount must be)/
      );
    }
  }

  const canonicalRecipient = fromBech32(contract.operation_hash_test_vectors[0].recipient);
  const nonCanonicalRecipientBytes = Uint8Array.from(canonicalRecipient.data);
  const compressedPoint = nonCanonicalRecipientBytes.slice(0, 32);
  const sign = compressedPoint[31] & 0x80;
  compressedPoint[31] &= 0x7f;
  let y = 0n;
  for (let index = compressedPoint.length - 1; index >= 0; index -= 1) {
    y = (y << 8n) | BigInt(compressedPoint[index]);
  }
  const nonCanonicalY = y + FIELD_MODULUS;
  assert.ok(nonCanonicalY < (1n << 255n));
  let remaining = nonCanonicalY;
  for (let index = 0; index < compressedPoint.length; index += 1) {
    compressedPoint[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  compressedPoint[31] |= sign;
  nonCanonicalRecipientBytes.set(compressedPoint, 0);
  const nonCanonicalRecipient = toBech32(canonicalRecipient.prefix, nonCanonicalRecipientBytes, 200);
  assert.throws(
    () => hashRecipient(nonCanonicalRecipient),
    /valid shielded address/
  );

  const note = {
    note: {
      receiverSpendPubKeyX: 1n,
      receiverSpendPubKeyY: 2n,
      receiverViewPubKeyX: 3n,
      receiverViewPubKeyY: 4n,
      amount: 5n,
      assetID: 7n,
      randomness: 8n,
      memo: ""
    },
    nullifier: "ab".repeat(32),
    txHash: "DISCOVERY-TX",
    height: 12,
    sequence: 3
  };
  const manager = createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "clairveil:conformance",
    indexKey: vector.index_key_utf8
  });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "payment"
  });
  await assert.rejects(
    () => manager.markProofReady(batch.reservation_ids, { leaseToken: "wrong" }),
    /lease token/
  );
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    expectedOutputCommitment: "OUTPUT",
    expectedDisclosureDigest: "DISCLOSURE",
    expectedRecipientHash: "RECIPIENT",
    expectedAmountHash: "AMOUNT",
    expectedDenom: "uclair",
    // Direct integration does not make a batch item position part of its predicate.
    batchItemIndexKnown: false,
    operationSuccessEvidenceRequired: true
  });
  await manager.markBroadcastAttempting(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    txHash: contract.operation_identity_evidence.vectors[0].stored_tx_hash
  });
  await manager.markSubmitted(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    txHash: contract.operation_identity_evidence.vectors[0].stored_tx_hash
  });
  await manager.reconcileSpentNotes([{
    ...note,
    isSpent: true,
    operationSuccessEvidence: {
      txResult: contract.operation_identity_evidence.vectors[0].tx_result,
      outputCommitment: "OUTPUT",
      disclosureDigest: "DISCLOSURE",
      recipientHash: "RECIPIENT",
      amountHash: "AMOUNT",
      denom: "uclair"
    }
  }]);
  const record = await manager.getReservation(batch.reservation_ids[0]);
  assert.equal(record.status, reservationStatuses.ConfirmedSpent);
  assert.equal(
    record.metadata.operation_status,
    operationStatuses[contract.operation_identity_evidence.vectors[0].operation_status]
  );
  assert.deepEqual(record.metadata.operation_success_evidence_errors, [
    "tx_hash_or_tx_result identity missing"
  ]);
});

test("reservation contract fixture replays state, lease, and direct operation-evidence policy", fixtureTestOptions, async () => {
  const contract = readFixture("privacy_note_reservation_contract.json");
  assert.deepEqual(activeReservationStatuses, contract.active_reservation_statuses);
  for (const [from, to] of contract.allowed_transitions) {
    assert.equal(canTransitionReservation(from, to), true, `${from} -> ${to}`);
  }
  for (const [from, to] of contract.rejected_transitions) {
    assert.equal(canTransitionReservation(from, to), false, `${from} -> ${to}`);
  }
  const fixtureTransitions = new Set(
    contract.allowed_transitions.map(([from, to]) => `${from}\0${to}`)
  );
  for (const from of Object.values(reservationStatuses)) {
    for (const to of Object.values(reservationStatuses)) {
      if (canTransitionReservation(from, to)) {
        assert.equal(
          fixtureTransitions.has(`${from}\0${to}`),
          true,
          `fixture is missing allowed transition ${from} -> ${to}`
        );
      }
    }
  }
  const actualLeaseRequiredTransitions = contract.allowed_transitions.filter(([from, to]) =>
    requiresReservationLeaseToken(from, to)
  );
  assert.deepEqual(
    actualLeaseRequiredTransitions,
    contract.lease_transition_preconditions.token_required_for
  );
  const actualExpiredLeaseRecoveryTransitions = contract.allowed_transitions.filter(([from, to]) =>
    canRecoverReservationAfterLeaseExpiry(from, to)
  );
  assert.deepEqual(
    actualExpiredLeaseRecoveryTransitions,
    contract.lease_transition_preconditions.recovery_without_token_after_expiry_for
  );

  const makeManager = () => createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "clairveil:conformance-direct",
    indexKey: "conformance-direct-index-key"
  });
  const makeNote = (nullifier, sequence) => ({
    note: {
      receiverSpendPubKeyX: 1n,
      receiverSpendPubKeyY: 2n,
      receiverViewPubKeyX: 3n,
      receiverViewPubKeyY: 4n,
      amount: 5n,
      assetID: 7n,
      randomness: 8n,
      memo: ""
    },
    nullifier,
    txHash: "DISCOVERY-TX",
    height: 12,
    sequence
  });
  const prepare = async (manager, note) => {
    const batch = await preparePlanReservation(manager, {
      plan: { selectedNote: note },
      kind: "payment"
    });
    await manager.markProofReady(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      expectedOutputCommitment: "OUTPUT",
      expectedDisclosureDigest: "DISCLOSURE",
      expectedRecipientHash: "RECIPIENT",
      expectedAmountHash: "AMOUNT",
      expectedDenom: "uclair",
      // Direct integrations may omit an item position from the success predicate.
      batchItemIndexKnown: false,
      operationSuccessEvidenceRequired: true
    });
    await manager.markBroadcastAttempting(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      txHash: "EXPECTED-TX"
    });
    await manager.markSubmitted(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      txHash: "EXPECTED-TX"
    });
    return batch;
  };
  const evidence = {
    outputCommitment: "OUTPUT",
    disclosureDigest: "DISCLOSURE",
    recipientHash: "RECIPIENT",
    amountHash: "AMOUNT",
    denom: "uclair"
  };

  const immutableManager = makeManager();
  const immutableNote = makeNote("ab".repeat(32), 3);
  const immutableBatch = await preparePlanReservation(immutableManager, {
    plan: { selectedNote: immutableNote },
    kind: "payment"
  });
  await immutableManager.markProofReady(immutableBatch.reservation_ids, {
    leaseToken: immutableBatch.lease_token,
    payloadHash: "payload-a",
    expectedOutputCommitment: "output-a",
    expectedDisclosureDigest: "disclosure-a",
    expectedRecipientHash: "recipient-a",
    expectedAmount: "7",
    expectedAmountHash: "amount-a",
    expectedDenom: "uclair",
    batchItemIndex: 0,
    batchItemIndexKnown: true,
    operationSuccessEvidenceRequired: true
  });
  await immutableManager.markBroadcastAttempting(immutableBatch.reservation_ids, {
    leaseToken: immutableBatch.lease_token,
    txHash: "tx-a"
  });
  const immutableRecord = await immutableManager.getReservation(immutableBatch.reservation_ids[0]);
  const predicateFields = new Set([
    "expected_output_commitment",
    "expected_disclosure_digest",
    "expected_recipient_hash",
    "expected_amount",
    "expected_amount_hash",
    "expected_denom",
    "batch_item_index",
    "batch_item_index_known",
    "operation_success_evidence_required"
  ]);
  for (const vector of contract.evidence_immutability.mutation_rejection_vectors.filter(
    vector => predicateFields.has(vector.field)
  )) {
    const mutation = vector.field === "operation_success_evidence_required"
      ? { metadata: { ...immutableRecord.metadata, [vector.field]: vector.mutation } }
      : { [vector.field]: vector.mutation };
    await assert.rejects(
      () => immutableManager.store.compareAndSetReservationStatus(
        immutableRecord.reservation_id,
        reservationStatuses.ProofReady,
        reservationStatuses.Submitted,
        {
          lease_owner: immutableRecord.lease_owner,
          lease_token: immutableRecord.lease_token,
          submitted_tx_hash: "tx-a",
          ...mutation
        }
      ),
      /not allowed|write-once/
    );
  }

  const [bareIdentity, mismatchedIdentity, matchingIdentity] = contract.operation_identity_evidence.vectors;
  const mismatchedManager = makeManager();
  const mismatchedNote = makeNote("cd".repeat(32), 4);
  const mismatchedBatch = await prepare(mismatchedManager, mismatchedNote);
  await mismatchedManager.reconcileSpentNotes([{
    ...mismatchedNote,
    isSpent: true,
    operationSuccessEvidence: {
      txResult: mismatchedIdentity.tx_result,
      ...evidence
    }
  }]);
  const mismatched = await mismatchedManager.getReservation(
    mismatchedBatch.reservation_ids[0]
  );
  assert.equal(mismatched.metadata.operation_status, operationStatuses[mismatchedIdentity.operation_status]);
  assert.deepEqual(mismatched.metadata.operation_success_evidence_errors, [
    "tx_hash_or_tx_bytes mismatch"
  ]);

  const matchingManager = makeManager();
  const matchingNote = makeNote("ef".repeat(32), 5);
  const matchingBatch = await prepare(matchingManager, matchingNote);
  await matchingManager.reconcileSpentNotes([{
    ...matchingNote,
    isSpent: true,
    operationSuccessEvidence: {
      txResult: matchingIdentity.tx_result,
      ...evidence
    }
  }]);
  const matching = await matchingManager.getReservation(
    matchingBatch.reservation_ids[0]
  );
  assert.equal(matching.metadata.operation_status, operationStatuses[matchingIdentity.operation_status]);
  assert.deepEqual(matching.metadata.operation_success_evidence_errors, []);
});

test("conformance helper defaults use repo-relative fixture discovery", () => {
  assert.equal(conformanceFixtureRelativePath, "x/privacy/client/sdk/conformance/testdata");
  assert.equal(defaultConformanceFixtureDir, `../clairveil/${conformanceFixtureRelativePath}`);
  assert.ok(suggestClairveilConformanceFixtureDirs().some(candidate => candidate.endsWith(conformanceFixtureRelativePath)));
});

test("browser signer provider contract derives the expected privacy material", fixtureTestOptions, async () => {
  const contract = readFixture("privacy_browser_signer_provider_contract.json").root_signer;
  const expectedMessage = Buffer.from(contract.sign_request.message_hex, "hex").toString("utf8");
  let signCalled = false;

  const material = await derivePrivacyMaterialFromWallet({
    async getAddress() {
      return contract.get_account_response.transparent_address;
    },
    async getPubKeyHex() {
      return contract.get_account_response.transparent_pubkey_hex;
    },
    async signPrivacyRoot(messageBytes, context) {
      signCalled = true;
      assert.equal(contract.sign_request.method, "sign_privacy_root");
      assert.equal(hexFromBytes(messageBytes), contract.sign_request.message_hex);
      assert.equal(context.signingMessage, expectedMessage);
      assert.equal(context.address, contract.get_account_response.transparent_address);
      assert.equal(context.pubKeyHex, contract.get_account_response.transparent_pubkey_hex);
      return bytesFromHex(contract.sign_response.signature_hex, "privacy root signature");
    }
  }, { shieldedPrefix: "clairs" });

  assert.equal(signCalled, true);
  assert.equal(material.rootSeedHex, contract.expected_derived.root_seed_hex);
  assert.equal(material.shieldedAddress, contract.expected_derived.shielded_address);
  assert.equal(material.disclosurePubKeyHex, contract.expected_derived.disclosure_pubkey_hex);
});

test("readonly note scan matches the Go reference bundle", fixtureTestOptions, async () => {
  const vectors = readFixture("privacy_wallet_golden_vectors.json");
  const browserContract = readFixture("privacy_browser_signer_provider_contract.json");
  const reference = readFixture("privacy_wallet_readonly_reference_bundle.json");
  const rootSeed = bytesFromHex(vectors.sender_root_seed.root_seed_hex, "sender root seed");

  const depositScan = await scanNotes({
    rootSeed,
    events: browserContract.scan_provider.search_privacy_events_response.events,
    checkNullifier: async nullifierHex => {
      assert.equal(nullifierHex, browserContract.scan_provider.check_nullifier_request.nullifier_hex);
      return browserContract.scan_provider.check_nullifier_response;
    },
    includeFoundNotes: true
  });

  assert.equal(depositScan.summary.total_spendable, "7");
  assert.deepEqual(foundNoteSummary(depositScan.foundNotes[0]), reference.scan.deposit_found[0]);

  const noteBytes = bytesFromHex(vectors.note.note_json_hex, "golden note JSON");
  const view = deriveViewKeys(rootSeed);
  const transferEvent = {
    event_type: "shielded_transfer",
    tx_hash_hex: vectors.scan.tx_hash_hex,
    height: vectors.scan.height,
    attributes: [{
      key: "cipher_text_1",
      value: hexFromBytes(asymEncrypt(noteBytes, view.pubKey))
    }, {
      key: "commitment_1",
      value: vectors.note.commitment_hex
    }]
  };
  const transferScan = await scanNotes({
    rootSeed,
    events: [transferEvent],
    includeFoundNotes: true
  });

  assert.deepEqual(foundNoteSummary(transferScan.foundNotes[0]), reference.scan.transfer_found[0]);
});

test("raw scans reject missing or mismatched commitments", fixtureTestOptions, async () => {
  const vectors = readFixture("privacy_wallet_golden_vectors.json");
  const rootSeed = bytesFromHex(vectors.sender_root_seed.root_seed_hex, "sender root seed");
  const noteBytes = bytesFromHex(vectors.note.note_json_hex, "golden note JSON");
  const view = deriveViewKeys(rootSeed);
  const transferCiphertext = hexFromBytes(asymEncrypt(noteBytes, view.pubKey));

  const missingDepositCommitment = await scanNotes({
    rootSeed,
    events: [{
      event_type: "deposit",
      attributes: [{ key: "encrypted_note", value: vectors.note.encrypted_note_hex }]
    }],
    includeFoundNotes: true
  });
  assert.equal(missingDepositCommitment.foundNotes.length, 0);

  const missingTransferCommitment = await scanNotes({
    rootSeed,
    events: [{
      event_type: "shielded_transfer",
      attributes: [{ key: "cipher_text_1", value: transferCiphertext }]
    }],
    includeFoundNotes: true
  });
  assert.equal(missingTransferCommitment.foundNotes.length, 0);

  const mismatchedTransferCommitment = await scanNotes({
    rootSeed,
    events: [{
      event_type: "shielded_transfer",
      attributes: [
        { key: "cipher_text_1", value: transferCiphertext },
        { key: "commitment_1", value: "00".repeat(32) },
        { key: "cipher_text_2", value: transferCiphertext },
        { key: "commitment_2", value: "ff".repeat(32) }
      ]
    }],
    includeFoundNotes: true
  });
  assert.equal(mismatchedTransferCommitment.foundNotes.length, 0);
});

test("prepared transfer and withdraw payload hashes match Go fixtures", fixtureTestOptions, () => {
  const prover = readFixture("privacy_prover_example_bundle.json");
  const flow = readFixture("privacy_send_capable_reference_flow.json");

  const transferPayload = prover.transfer.request.payload;
  const transferProof = prover.transfer.response.proof;
  assert.equal(computePreparedTransferPayloadHash(transferPayload), transferPayload.payload_hash);
  assert.equal(transferPayload.payload_hash, flow.transfer.payload_hash);
  assert.equal(transferProof.payload_hash, flow.transfer.proof_payload_hash);
  assert.equal(validatePreparedTransferProof(transferPayload, transferProof), true);
  assert.equal(buildTransferMsgFromPayloadAndProof(transferPayload, transferProof).creator, flow.transfer.msg_creator);

  const withdrawProverPayload = prover.withdraw.request.payload;
  const withdrawProof = prover.withdraw.response.proof;
  assert.equal(computePreparedWithdrawProverPayloadHash(withdrawProverPayload), withdrawProverPayload.payload_hash);
  assert.equal(withdrawProverPayload.payload_hash, flow.withdraw.payload_hash);
  assert.equal(withdrawProof.payload_hash, flow.withdraw.proof_payload_hash);
  assert.equal(validatePreparedWithdrawProof(withdrawProverPayload, withdrawProof, prover.withdraw.validation_now_unix), true);

  const finalWithdrawPayload = buildPreparedWithdrawPayloadFromProof(
    withdrawProverPayload,
    withdrawProof,
    prover.withdraw.validation_now_unix
  );
  assert.equal(computePreparedWithdrawPayloadHash(finalWithdrawPayload), flow.withdraw.final_payload_hash);
  assert.equal(finalWithdrawPayload.payload_hash, flow.withdraw.final_payload_hash);
  assert.equal(finalWithdrawPayload.amount, flow.withdraw.amount);
  assert.equal(finalWithdrawPayload.recipient, flow.withdraw.recipient);
  assert.equal(finalWithdrawPayload.chain_id, flow.withdraw.chain_id);
});

test("withdraw planner and relay payload validation reject unsafe variants", fixtureTestOptions, async () => {
  const vectors = readFixture("privacy_wallet_golden_vectors.json");
  const prover = readFixture("privacy_prover_example_bundle.json");
  const rootSeed = bytesFromHex(vectors.sender_root_seed.root_seed_hex, "sender root seed");
  const note = parseNoteBytes(bytesFromHex(vectors.note.note_json_hex, "golden note JSON"));
  const found = {
    note,
    nullifier: computeNoteNullifierHex(note),
    txHash: vectors.scan.tx_hash_hex,
    height: vectors.scan.height,
    isSpent: false,
    nullifierStatus: "unspent"
  };

  const plan = planWithdrawNotes({
    notes: [found],
    amount: "3uclair",
    denom: "uclair"
  });
  assert.equal(plan.status, "exact_note_required");
  assert.throws(
    () => assertPlanCanBuildTx(plan),
    error => error?.code === "EXACT_NOTE_REQUIRED" && /exact-match note/.test(error.message)
  );
  assert.equal(computeNoteCommitmentHex(note), vectors.note.commitment_hex);
  assert.equal(deriveSpendKeys(rootSeed).pubKeyHex, vectors.sender.spend_pubkey_hex);

  const finalPayload = buildPreparedWithdrawPayloadFromProof(
    prover.withdraw.request.payload,
    prover.withdraw.response.proof,
    prover.withdraw.validation_now_unix
  );

  assert.throws(
    () => validatePreparedWithdrawPayload(finalPayload, finalPayload.expires_at_unix + 1),
    /withdraw payload expired/
  );
  assert.throws(
    () => validatePreparedWithdrawProof(
      prover.withdraw.request.payload,
      prover.withdraw.response.proof,
      prover.withdraw.request.payload.expires_at_unix + 1
    ),
    /withdraw prover payload expired/
  );

  for (const mutation of [
    { chain_id: "wrong-chain" },
    { recipient: "clair1wrongrecipient00000000000000000" },
    { payload_hash: "00".repeat(32) }
  ]) {
    assert.throws(
      () => validatePreparedWithdrawPayload({ ...finalPayload, ...mutation }, prover.withdraw.validation_now_unix),
      /withdraw payload hash mismatch/
    );
  }

  assert.throws(
    () => validatePreparedWithdrawProof(
      prover.withdraw.request.payload,
      { ...prover.withdraw.response.proof, payload_hash: "00".repeat(32) },
      prover.withdraw.validation_now_unix
    ),
    /withdraw proof payload hash mismatch/
  );
});

test("relay withdraw handoff builds the Go-compatible relay message", fixtureTestOptions, () => {
  const relay = readFixture("privacy_relay_withdraw_contract.json");
  const payload = relay.request.payload;
  const expected = relay.expected_msg;

  assert.equal(
    validateRelayWithdrawPayload(payload, {
      chainNowUnix: 4102444800,
      expectedChainId: expected.chain_id,
      expectedRecipient: expected.recipient,
      accountPrefix: "clair"
    }),
    true
  );

  const message = buildRelayWithdrawMsgFromPayload(payload, relay.relayer.address, {
    chainNowUnix: 4102444800,
    expectedChainId: expected.chain_id,
    expectedRecipient: expected.recipient,
    accountPrefix: "clair"
  });

  assert.equal(message.creator, expected.creator);
  assert.equal(hexFromBytes(message.proof), expected.proof_hex);
  assert.equal(hexFromBytes(message.root), expected.root_hex);
  assert.equal(hexFromBytes(message.nullifier), expected.nullifier_hex);
  assert.equal(message.amount, expected.amount);
  assert.equal(message.recipient, expected.recipient);
  assert.equal(message.chainId, expected.chain_id);
  assert.equal(message.expiresAtUnix.toString(), String(expected.expires_at_unix));

  assert.throws(
    () => validateRelayWithdrawPayload(payload, {
      expectedChainId: expected.chain_id,
      expectedRecipient: expected.recipient,
      accountPrefix: "clair"
    }),
    /chainNowUnix is required/
  );

  for (const chainNowUnix of [null, "", " ", false, true, Number.NaN]) {
    assert.throws(
      () => validateRelayWithdrawPayload(payload, {
        chainNowUnix,
        expectedChainId: expected.chain_id,
        expectedRecipient: expected.recipient,
        accountPrefix: "clair"
      }),
      /chainNowUnix is required/
    );
  }

  assert.throws(
    () => buildRelayWithdrawMsgFromPayload(payload, relay.relayer.address, {
      chainNowUnix: 4102444800,
      expectedChainId: "wrong-chain",
      accountPrefix: "clair"
    }),
    /withdraw payload chain_id mismatch/
  );
  assert.throws(
    () => buildRelayWithdrawMsgFromPayload(payload, relay.relayer.address, {
      chainNowUnix: 4102444800,
      expectedRecipient: "clair1pyysjzgfpyysjzgfpyysjzgfpyysjzgf0j5ga5",
      accountPrefix: "clair"
    }),
    /withdraw payload recipient mismatch/
  );
  assert.doesNotThrow(() => buildRelayWithdrawMsgFromPayload(payload, relay.relayer.address, {
    chainNowUnix: expected.expires_at_unix,
    accountPrefix: "clair"
  }));
  assert.throws(
    () => buildRelayWithdrawMsgFromPayload(payload, relay.relayer.address, {
    chainNowUnix: expected.expires_at_unix + 1,
      accountPrefix: "clair"
    }),
    /withdraw payload expired/
  );
});

test("MsgWithdraw stays free of legacy output-note fields", fixtureTestOptions, () => {
  const prover = readFixture("privacy_prover_example_bundle.json");
  const finalPayload = buildPreparedWithdrawPayloadFromProof(
    prover.withdraw.request.payload,
    prover.withdraw.response.proof,
    prover.withdraw.validation_now_unix
  );
  const message = buildWithdrawMsgFromPayload(finalPayload, "clair1creator");
  assert.equal("newNoteCommitment" in message, false);
  assert.equal("encryptedNote" in message, false);

  const partial = MsgWithdraw.fromPartial({
    ...message,
    newNoteCommitment: new Uint8Array(32).fill(4),
    encryptedNote: new Uint8Array(32).fill(5)
  });
  assert.equal("newNoteCommitment" in partial, false);
  assert.equal("encryptedNote" in partial, false);

  const decoded = MsgWithdraw.decode(MsgWithdraw.encode({
    ...message,
    newNoteCommitment: new Uint8Array(32).fill(4),
    encryptedNote: new Uint8Array(32).fill(5)
  }).finish());
  assert.equal("newNoteCommitment" in decoded, false);
  assert.equal("encryptedNote" in decoded, false);
});
