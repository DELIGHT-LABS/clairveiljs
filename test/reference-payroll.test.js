import test from "node:test";
import assert from "node:assert/strict";
import {
  MemoryDisclosureKeyRegistry,
  analyzeNotePreparation,
  normalizePayrollDisclosurePolicy,
  normalizePayrollInput,
  oneProofPayrollCircuitSetId,
  planOneProofPayroll
} from "clairveiljs/reference-payroll";

const recipient = "clairs19x5u4mf4l4zqcpvr7d809fh4tjy5j50p2mwgky0nj38jpqpj7svndu3hqshu5e3s8w6pea5p30xek5p9flxjf7f44xh7cnfrlsd84pc7upgh3";
const key = "11".repeat(32);

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

  const normalized = normalizePayrollInput(input);
  assert.equal(normalized.items[0].amount, 20n);
  assert.throws(
    () => planOneProofPayroll(input, [{ note_id: "wrong-owner", owner_key_id: "other", nullifier_lookup_key: "n4", denom: "uclair", amount: "20" }]),
    /preparation is required/
  );
});
