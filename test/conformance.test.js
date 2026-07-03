import test from "node:test";
import assert from "node:assert/strict";
import {
  buildRootSigningMessage,
  bytesFromHex,
  deriveDisclosureKeys,
  derivePrivacyMaterial,
  deriveSpendKeys,
  deriveViewKeys,
  encodeShieldedAddress,
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
import { runClairveilConformanceFixtures } from "clairveiljs/conformance";
import {
  conformanceFixtureRelativePath,
  defaultConformanceFixtureDir,
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
    }]
  };
  const transferScan = await scanNotes({
    rootSeed,
    events: [transferEvent],
    includeFoundNotes: true
  });

  assert.deepEqual(foundNoteSummary(transferScan.foundNotes[0]), reference.scan.transfer_found[0]);
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
    isSpent: false
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
      nowUnix: 4102444800,
      expectedChainId: expected.chain_id,
      expectedRecipient: expected.recipient,
      accountPrefix: "clair"
    }),
    true
  );

  const message = buildRelayWithdrawMsgFromPayload(payload, relay.relayer.address, {
    nowUnix: 4102444800,
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
    () => buildRelayWithdrawMsgFromPayload(payload, relay.relayer.address, {
      nowUnix: 4102444800,
      expectedChainId: "wrong-chain",
      accountPrefix: "clair"
    }),
    /withdraw payload chain_id mismatch/
  );
  assert.throws(
    () => buildRelayWithdrawMsgFromPayload(payload, relay.relayer.address, {
      nowUnix: 4102444800,
      expectedRecipient: "clair1pyysjzgfpyysjzgfpyysjzgfpyysjzgf0j5ga5",
      accountPrefix: "clair"
    }),
    /withdraw payload recipient mismatch/
  );
  assert.throws(
    () => buildRelayWithdrawMsgFromPayload(payload, relay.relayer.address, {
      nowUnix: expected.expires_at_unix,
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
