import test from "node:test";
import assert from "node:assert/strict";
import {
  decodeAuditDisclosureFromEvent,
  decodeUserDisclosureFromEvent,
  publicPayloadReport,
  userDisclosureModeRecipientEncrypted
} from "clairveiljs/disclosure";
import {
  fixtureTestOptions,
  readFixture
} from "./helpers.js";

const policyLabels = new Map([
  [0, "all-private"],
  [1, "amount"],
  [2, "to"],
  [3, "amount-to"],
  [4, "from"],
  [5, "amount-from"],
  [6, "from-to"],
  [7, "amount-from-to"]
]);

function transferDisclosureEvent(payload, txHash = "AABBCC") {
  return {
    event_type: "shielded_transfer",
    tx_hash_hex: txHash,
    attributes: [
      { key: "user_disclosure_mode", value: userDisclosureModeRecipientEncrypted },
      { key: "user_disclosure_target_pubkey", value: payload.user_disclosure_target_pubkey_hex },
      { key: "user_disclosure_digest", value: payload.user_disclosure_digest_hex },
      { key: "user_disclosure_payload", value: payload.user_disclosure_payload_hex },
      { key: "audit_disclosure_target_pubkey", value: payload.audit_disclosure_target_pubkey_hex },
      { key: "audit_disclosure_digest", value: payload.audit_disclosure_digest_hex },
      { key: "audit_disclosure_payload", value: payload.audit_disclosure_payload_hex }
    ]
  };
}

function compactReport(report) {
  return {
    plane: report.plane,
    policy: policyLabels.get(Number(report.payload.policy)) || report.policy,
    output_index: report.output_index,
    commitment_hex: report.commitment_hex,
    digest_hex: report.digest_hex,
    verified: report.verified,
    amount: report.amount,
    asset_denom: report.asset_denom,
    from: report.from,
    to: report.to
  };
}

function expectedDisclosure(summary) {
  return {
    plane: summary.plane,
    policy: summary.policy,
    output_index: summary.output_index,
    commitment_hex: summary.commitment_hex,
    digest_hex: summary.digest_hex,
    verified: summary.verified,
    amount: summary.amount,
    asset_denom: summary.asset_denom,
    from: summary.from_shielded_address,
    to: summary.to_shielded_address
  };
}

test("user public disclosure payload verifies against the golden vector", fixtureTestOptions, () => {
  const vectors = readFixture("privacy_wallet_golden_vectors.json");
  const report = publicPayloadReport(
    vectors.disclosure.payload_json_hex,
    vectors.disclosure.digest_hex,
    vectors.scan.tx_hash_hex,
    { shieldedPrefix: "clairs" }
  );
  const compact = compactReport(report);

  assert.equal(compact.plane, "user");
  assert.equal(compact.policy, vectors.disclosure.policy);
  assert.equal(compact.verified, true);
  assert.equal(compact.amount, vectors.note.amount);
  assert.equal(compact.asset_denom, vectors.note.denom);
  assert.equal(compact.from, vectors.sender.shielded_address);
  assert.equal(compact.to, vectors.recipient.shielded_address);
  assert.equal(compact.digest_hex, vectors.disclosure.digest_hex);
});

test("user recipient-encrypted disclosure decodes and verifies against the send-capable fixture", fixtureTestOptions, () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const flow = readFixture("privacy_send_capable_reference_flow.json");
  const payload = examples.transfer.request.payload;
  const report = decodeUserDisclosureFromEvent(
    transferDisclosureEvent(payload),
    79n,
    payload.user_disclosure_target_pubkey_hex,
    "AABBCC",
    { shieldedPrefix: "clairs" }
  );

  assert.deepEqual(compactReport(report), expectedDisclosure(flow.transfer.user_disclosure));
});

test("audit disclosure decodes and verifies against the send-capable fixture", fixtureTestOptions, () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const flow = readFixture("privacy_send_capable_reference_flow.json");
  const report = decodeAuditDisclosureFromEvent(
    transferDisclosureEvent(examples.transfer.request.payload),
    83n,
    "AABBCC",
    { shieldedPrefix: "clairs" }
  );

  assert.deepEqual(compactReport(report), expectedDisclosure(flow.transfer.audit_disclosure));
});
