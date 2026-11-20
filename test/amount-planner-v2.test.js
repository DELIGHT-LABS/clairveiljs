import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  maxShieldedAmountV2 as MAX, parseAmount128, sumAmounts128, sumAmountTotals,
  amount128ToJSON, amount128FromJSON
} from "clairveiljs/amount";
import { createNote128, normalizeNote128, normalizeFoundNote128 } from "clairveiljs/note128";
import {
  planTransferNotesV2, planTransferBatchNotesV2, planWithdrawNotesV2,
  summarizeSpendableNotesByDenomV2, selectTransferInputsV2, selectBatchTransferInputsV2
} from "clairveiljs/planner-v2";
import { planOneProofPayrollV2, normalizePayrollInputV2 } from "clairveiljs/reference-payroll-v2";
import { planOneProofPayroll, prepareOneProofPayrollOperation } from "clairveiljs/reference-payroll";
import { CURVE_BASE } from "clairveiljs/crypto";
import { validateNoteV1, marshalNotePlaintextV1 } from "clairveiljs/protocol-v1";
import { planTransferBatchNotes } from "clairveiljs/planner";

const note = (amount, id = 1, overrides = {}) => ({
  note: createNote128({ spendPubKey: CURVE_BASE, viewPubKey: CURVE_BASE, amount, randomness: BigInt(id) }),
  nullifier: id.toString(16).padStart(64, "0"), nullifierStatus: "unspent", isSpent: false,
  txHash: `synthetic-${id}`, height: id, sequence: id, ...overrides
});
const recipient = "clairs19x5u4mf4l4zqcpvr7d809fh4tjy5j50p2mwgky0nj38jpqpj7svndu3hqshu5e3s8w6pea5p30xek5p9flxjf7f44xh7cnfrlsd84pc7upgh3";
const payroll = amounts => ({ company_id: "test", payroll_id: "test", batch_id: "test", denom: "uclair",
  items: amounts.map((amount, index) => ({ item_id: `item-${index}`, recipient_address: recipient, amount })) });
const treasury = amounts => amounts.map((amount, index) => ({ note_id: `note-${index}`, owner_key_id: "owner", denom: "uclair", amount }));

test("uint128 amount parsing and JSON match independent Core Go boundary vectors", () => {
  const fixture = JSON.parse(readFileSync(new URL("../fixtures/clairveil-v0.6.1-amount/vectors.json", import.meta.url)));
  assert.equal(fixture.source.commit, "fad307abddd0daa1c880f2e423668f5c58a0e578");
  for (const row of fixture.parse) {
    if (!row.valid) assert.throws(() => parseAmount128(row.input), /canonical|128/);
    else {
      assert.equal(parseAmount128(row.input).toString(), row.decimal);
      assert.equal(amount128ToJSON(row.input), row.json);
      assert.equal(amount128FromJSON(row.json), BigInt(row.decimal));
    }
  }
  for (const row of fixture.add) {
    if (!row.valid) assert.throws(() => sumAmounts128([row.left, row.right]), /128/);
    else assert.equal(sumAmounts128([row.left, row.right]).toString(), row.total);
  }
});

test("amount inputs reject JS numbers and coercion while aggregate totals stay unbounded", () => {
  for (const value of [0, 1, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, null, undefined, true, {}, " 1", "1 ", "01", "-0", "+1", "1e2", "1.0", -1n, MAX + 1n]) {
    assert.throws(() => parseAmount128(value));
  }
  for (const value of [0n, 1n << 64n, MAX]) assert.equal(parseAmount128(value.toString()), value);
  for (const json of ["0", "1", "null", "true", "{}", '"01"']) assert.throws(() => amount128FromJSON(json));
  assert.equal(sumAmounts128([MAX, 0n]), MAX);
  assert.throws(() => sumAmounts128([MAX, 1n]), /128/);
  assert.equal(sumAmountTotals([MAX, MAX, "1"]), MAX * 2n + 1n);
  assert.equal(sumAmountTotals([1n << 300n, 1n]), (1n << 300n) + 1n);
  assert.throws(() => sumAmounts128("12"), /array/);
  assert.throws(() => sumAmountTotals("12"), /array/);
});

test("note amount normalization enforces uint128 without widening legacy binary codecs", () => {
  const found = note(MAX);
  assert.equal(normalizeNote128({ ...found.note, amount: MAX.toString() }).amount, MAX);
  assert.equal(normalizeFoundNote128(found).note.amount, MAX);
  for (const value of [-1n, MAX + 1n, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => note(value));
    assert.throws(() => normalizeNote128({ ...found.note, amount: value }));
  }
  assert.throws(() => normalizeFoundNote128({ ...found, nullifier: undefined }), /nullifier/);
  assert.throws(() => validateNoteV1(found.note), /64/);
  assert.throws(() => marshalNotePlaintextV1(found.note), /64/);
});

test("V2 planner handles 2^64 and max uint128 with exact bigint change and a zero helper", () => {
  for (const target of [1n << 64n, MAX]) {
    const notes = [note(MAX, 1), note(0n, 2)];
    const plan = planTransferNotesV2({ notes, amount: `${target}uclair` });
    assert.equal(plan.status, "final_transfer_ready");
    assert.equal(plan.selection.total, MAX);
    assert.equal(plan.facts.requestedAmountValue, target.toString());
    assert.equal(plan.amountModel, "uint128");
  }
  assert.equal(planTransferNotesV2({ notes: [note(MAX)], amount: `${MAX}uclair` }).status, "zero_dummy_required");
  assert.equal(planWithdrawNotesV2({ notes: [note(MAX)], amount: `${MAX}uclair` }).status, "withdraw_ready");
  for (const planner of [planTransferNotesV2, planWithdrawNotesV2]) {
    assert.equal(planner({ notes: [], amount: "0uclair" }).status, "invalid_amount");
    assert.equal(planner({ notes: [], amount: `${MAX + 1n}uclair` }).status, "invalid_amount");
    assert.throws(() => planner({ notes: [], amount: Number.MAX_SAFE_INTEGER + 1 }));
  }
});

test("V2 selection bounds total inputs, including merges, without capping wallet balances", () => {
  const notes = [note(MAX - 1n, 1), note(2n, 2), note(3n, 3)];
  assert.equal(summarizeSpendableNotesByDenomV2(notes).total, MAX + 4n);
  const plan = planTransferNotesV2({ notes, amount: `${MAX}uclair` });
  assert.equal(plan.status, "self_merge_required");
  assert.equal(plan.selection.total, 5n);
  assert.equal(plan.facts.spendableTotalValue, (MAX + 4n).toString());
  assert.equal(planTransferNotesV2({ notes: notes.slice(0, 2), amount: `${MAX}uclair` }).status, "note_preparation_required");
  assert.equal(planTransferNotesV2({ notes: [note(MAX, 1), note(1n, 2)], amount: "1uclair" }).status, "zero_dummy_required");
  assert.throws(() => selectTransferInputsV2(notes, "uclair", MAX + 1n), /128/);
});

test("one V2 batch bounds payment and selected-input sums, including change", () => {
  const notes = [note(MAX - 1n, 1), note(1n, 2)];
  const ready = planTransferBatchNotesV2({ notes, amounts: [`${MAX - 1n}uclair`, "1uclair"] });
  assert.equal(ready.status, "batch_transfer_ready");
  assert.equal(ready.selection.total, MAX);
  const overflow = planTransferBatchNotesV2({ notes: [note(MAX, 1), note(1n, 2)], amounts: [`${MAX}uclair`, "1uclair"] });
  assert.equal(overflow.status, "invalid_amount");
  assert.equal(overflow.canBuildTx, false);
  const blocked = planTransferBatchNotesV2({ notes: [note(MAX - 1n, 1), note(2n, 2)], amounts: [`${MAX}uclair`] });
  assert.equal(blocked.status, "batch_note_preparation_required");
  assert.equal(blocked.canBuildTx, false);
  assert.throws(() => selectBatchTransferInputsV2(notes, "uclair", MAX + 1n), /128/);
  assert.equal(planTransferBatchNotes({ notes: [], amounts: [`${1n << 64n}uclair`] }).status, "invalid_amount");
});

test("V2 inventory keeps spent/unknown/foreign assets out and rejects duplicate note identities", () => {
  const notes = [note(MAX, 1), note(MAX, 2, { isSpent: true }), note(MAX, 3, { nullifierStatus: "unknown" })];
  const other = note(MAX, 4); other.note.assetID = 1n;
  assert.equal(summarizeSpendableNotesByDenomV2([...notes, other]).total, MAX);
  assert.throws(() => summarizeSpendableNotesByDenomV2([notes[0], notes[0]]), /duplicate/);
});

test("V2 bounded subset search finds a valid exact sum beyond overflowing large candidates", () => {
  const notes = [note(MAX - 1n, 1), note(MAX - 2n, 2), note(9n, 3), note(6n, 4), note(4n, 5)];
  const selection = selectBatchTransferInputsV2(notes, "uclair", "10");
  assert.equal(selection.total, 10n);
  assert.deepEqual(selection.inputs.map(found => found.note.amount), [4n, 6n]);
  const tooMany = Array.from({ length: 17 }, (_, i) => note(1n, i + 1));
  assert.equal(planTransferBatchNotesV2({ notes: tooMany, amounts: ["17uclair"] }).status, "batch_note_preparation_required");
  assert.equal(planTransferBatchNotesV2({ notes: [note(33n)], amounts: Array(32).fill("1uclair") }).status, "batch_capacity_exceeded");
});

test("V2 payroll splits an unbounded payroll total into bounded disjoint transactions", async () => {
  const input = payroll([MAX.toString(), MAX.toString(), "1"]);
  const plan = planOneProofPayrollV2(input, treasury([MAX, MAX, 1n]));
  assert.equal(plan.amount_model, "uint128");
  assert.equal(plan.total_payroll_amount, MAX * 2n + 1n);
  assert.equal(plan.total_spendable_amount, MAX * 2n + 1n);
  assert.equal(plan.operations.length, 3);
  assert.equal(new Set(plan.operations.flatMap(op => op.input_notes.map(n => n.note_id))).size, 3);
  for (const operation of plan.operations) {
    assert(operation.input_total <= MAX);
    assert.equal(operation.input_total, operation.payment_total + operation.change);
    assert.equal(operation.amount_model, "uint128");
    assert.equal(operation.circuit_set_id, undefined);
    await assert.rejects(() => prepareOneProofPayrollOperation({ operation }), /V2.*planning/);
  }
  assert.throws(() => planOneProofPayroll(input, treasury([MAX, MAX, 1n])), /uint64/);
  assert.throws(() => normalizePayrollInputV2(payroll([1])), /canonical/);
  assert.throws(() => normalizePayrollInputV2(payroll([(MAX + 1n).toString()])), /128/);
  assert.throws(() => planOneProofPayrollV2(payroll([MAX]), treasury([MAX - 1n, 2n])), /preparation/);
});

test("V2 payroll preserves owner/reservation/capacity boundaries and never authorizes legacy preparation", async () => {
  const input = payroll(["1"]);
  const plan = planOneProofPayrollV2(input, treasury([1n]));
  await assert.rejects(() => prepareOneProofPayrollOperation({ operation: plan.operations[0] }), /V2.*planning/);
  assert.throws(() => planOneProofPayrollV2(input, treasury([1n]).map(n => ({ ...n, reservation_id: "locked" }))), /preparation/);
  assert.throws(() => planOneProofPayrollV2(payroll(["3"]), [treasury([2n])[0], { ...treasury([2n])[0], note_id: "other", owner_key_id: "other" }]), /preparation/);
  assert.throws(() => planOneProofPayrollV2(input, [treasury([1n])[0], treasury([1n])[0]]), /duplicate/);
  const legacy = planOneProofPayroll(input, treasury([1n]));
  assert.notEqual(plan.operations[0].operation_id, legacy.operations[0].operation_id);
  const withChange = planOneProofPayrollV2(input, treasury([MAX]));
  assert.equal(withChange.operations[0].change, MAX - 1n);
  assert.equal(withChange.operations[0].input_total, MAX);
  const many = planOneProofPayrollV2(payroll(Array(33).fill("1")), treasury([32n, 1n]));
  assert.equal(many.operations.length, 2);
  assert(many.operations.every(operation => operation.output_count <= 32));
  for (const search_limit of [0, -1, 20001, NaN, Infinity, "1"]) {
    assert.throws(() => planOneProofPayrollV2(input, treasury([1n]), { search_limit }), /search limit/);
  }
});
