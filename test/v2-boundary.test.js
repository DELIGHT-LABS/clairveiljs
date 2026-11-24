import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { createNote128, normalizeNote128, normalizeFoundNote128 } from "clairveiljs/note128";
import { summarizeSpendableNotesByDenomV2 } from "clairveiljs/planner-v2";
import { CURVE_BASE } from "clairveiljs/crypto";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
const entries = ["amount", "note128", "planner-v2", "reference-payroll-v2", "protocol-v2", "audit-config-v2", "audit-authorization-v2", "audit-prover-v2", "cosmos-v2", "evm-v2", "preparation-v2", "audit-witness-v2", "reserve-v2", "scan-v2", "note-store-v2", "transactions-v2"];
const retiredDependencies = new Set([
  "src/core/note", "src/core/disclosure", "src/privacy/protocol-v1", "src/privacy/payload",
  "src/privacy/planner", "src/privacy/reference-payroll", "src/privacy/batch-transfer",
  "src/privacy/prover", "src/privacy/reservation", "src/privacy/circuit-config", "src/privacy/network-config",
  "src/generated/clairveil/privacy/v1/tx"
]);
function dependencyGraph(entry, types) {
  const seen = new Set();
  const external = new Set();
  function visit(path) {
    if (seen.has(path)) return;
    seen.add(path);
    const source = ts.createSourceFile(path, readFileSync(path, "utf8"), ts.ScriptTarget.Latest, true);
    function walk(node) {
      let target;
      if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) target = node.moduleSpecifier;
      if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument)) target = node.argument.literal;
      if (target && ts.isStringLiteral(target)) {
        if (target.text.startsWith(".")) {
          const next = resolve(dirname(path), types ? target.text.replace(/\.js$/, ".d.ts") : target.text);
          visit(next);
        } else {
          external.add(target.text);
        }
      }
      ts.forEachChild(node, walk);
    }
    walk(source);
  }
  visit(resolve(root, entry));
  return [...Array.from(seen, path => relative(root, path)), ...external];
}
for (const kind of ["import", "types"]) {
  test(`V2 ${kind} entrypoints have no dependency on retired V1 execution modules`, () => {
    for (const entry of entries) {
      const paths = dependencyGraph(manifest.exports[`./${entry}`][kind], kind === "types");
      const legacy = paths.filter(path => retiredDependencies.has(path.replace(/(?:\.d\.ts|\.js)$/, "")));
      assert.deepEqual(legacy, [], `${entry}: ${legacy.join(", ")}`);
    }
  });
}

test("audit witness preparation has no dependency on the Cosmos transaction registry", () => {
  const dependencies = dependencyGraph(manifest.exports["./audit-witness-v2"].import, false);
  const registry = dependencies.filter(name =>
    name === "src/transport/cosmos-v2.js" || /^@cosmjs\/(proto-signing|stargate)(\/|$)/.test(name));
  assert.deepEqual(registry, []);
});

const input = () => ({ spendPubKey: CURVE_BASE, viewPubKey: CURVE_BASE, amount: "1", randomness: 7n });
const found = overrides => ({ note: createNote128(input()), nullifier: "01".padStart(64,"0"), nullifierStatus: "unspent", isSpent: false, height: "1", sequence: "1", txHash: "synthetic", ...overrides });
test("an explicit note randomness value never requests fresh entropy", t => {
  t.mock.method(globalThis.crypto, "getRandomValues", () => { throw new Error("unexpected entropy request"); });
  assert.equal(createNote128(input()).randomness, 7n);
});
test("V2 note and inventory normalization reject retired V1 aliases instead of migrating them", () => {
  const note = createNote128(input());
  const compact = { rsx: note.receiverSpendPubKeyX, rsy: note.receiverSpendPubKeyY, rvx: note.receiverViewPubKeyX,
    rvy: note.receiverViewPubKeyY, am: note.amount, as: note.assetID, rn: note.randomness, mm: note.memo };
  assert.throws(() => normalizeNote128(compact), /legacy|unsupported|canonical|required/);
  assert.throws(() => normalizeNote128({ ...note, am: 2n }), /legacy|unsupported/);
  for (const alias of ["Note", "Nullifier", "NullifierStatus", "nullifier_status", "IsSpent", "spent", "Spent", "tx_hash", "TxHash", "Height", "Sequence"]) {
    assert.throws(() => normalizeFoundNote128(found({[alias]: true})), /legacy|unsupported/, alias);
  }
});
test("canonical V2 inventory stays fail-closed and sorts full-width heights numerically", () => {
  const higher = found({ height: "10000000000000000", nullifier: "02".padStart(64,"0") });
  const lower = found({ height: "9007199254740993" });
  const result = summarizeSpendableNotesByDenomV2([higher, lower]);
  assert.deepEqual(result.notes.map(note => note.height), ["9007199254740993", "10000000000000000"]);
  assert.equal(normalizeFoundNote128(found({height: 3, sequence: 4n})).height, "3");
  assert.equal(summarizeSpendableNotesByDenomV2([found({nullifierStatus: undefined})]).total, 0n);
  assert.equal(normalizeFoundNote128(found({isSpent:true})).nullifierStatus,"spent");
  assert.throws(() => normalizeFoundNote128(found({isSpent:"false"})), /boolean/);
});
