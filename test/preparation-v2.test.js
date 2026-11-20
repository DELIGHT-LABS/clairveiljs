import test from "node:test";
import assert from "node:assert/strict";
import { prepareDepositMaterialV2, prepareSpendInputsV2 } from "../src/privacy/preparation-v2.js";
import { decryptDepositNoteV2, computeNoteNullifierV2, marshalNotePlaintextV2 } from "clairveiljs/protocol-v2";
import { planTransferNotesV2, planWithdrawNotesV2 } from "clairveiljs/planner-v2";
const rootSeed = Uint8Array.from({length:32},(_,i)=>i);
const max=(1n<<128n)-1n;
function found(amount) {
  const material = prepareDepositMaterialV2({rootSeed, amount, denom:"uclair"});
  const note = decryptDepositNoteV2(material.output.ciphertext,rootSeed);
  material.clear();
  return {note, nullifier:computeNoteNullifierV2(note).toString(16).padStart(64,"0"), nullifierStatus:"unspent", isSpent:false};
}
test("V2 wallet preparation uses uint128 and fixed V2 bytes through selection and recovery",()=>{
  for (const amount of [0n,1n<<64n,max]) {
    const m=prepareDepositMaterialV2({rootSeed,amount,denom:"uclair"});
    const recovered=decryptDepositNoteV2(m.output.ciphertext,rootSeed);
    assert.equal(recovered.amount,amount);
    assert.deepEqual(m.plaintext,marshalNotePlaintextV2(recovered));
    assert.equal(m.plaintext.length,358);
    assert.throws(()=>JSON.stringify(m),/private/);
    m.clear(); assert.ok(m.plaintext.every(x=>x===0)); assert.ok(m.auditPlaintext.every(x=>x.every(b=>b===0)));
  }
  const notes=[found(max),found(0n)];
  const plan=planTransferNotesV2({notes,amount:`${1n<<64n}uclair`});
  assert.equal(plan.status,"final_transfer_ready");
  const selected=prepareSpendInputsV2({kind:"transfer",rootSeed,notes:plan.selection.inputs,amount:1n<<64n,denom:"uclair"});
  assert.equal(selected.change,max-(1n<<64n));
  assert.throws(()=>JSON.stringify(selected),/private/);
  selected.clear(); assert.ok(selected.plaintexts.every(x=>x.every(b=>b===0)));
  const w=planWithdrawNotesV2({notes,amount:`${max}uclair`});
  assert.equal(prepareSpendInputsV2({kind:"withdraw",rootSeed,notes:[w.selectedNote],amount:max,denom:"uclair"}).change,0n);
});
test("V2 preparation rejects overflow, changed owner/asset/nullifier, uncertain and duplicate notes",()=>{
  const note=found(max), zero=found(0n);
  const input={kind:"transfer",rootSeed,notes:[note,zero],amount:1n,denom:"uclair"};
  for (const amount of [max+1n,1, "01"]) assert.throws(()=>prepareDepositMaterialV2({rootSeed,amount,denom:"uclair"}));
  assert.throws(()=>prepareSpendInputsV2({...input,notes:[note,found(1n)]}),/128/);
  assert.throws(()=>prepareSpendInputsV2({...input,notes:[note,note]}),/duplicate/);
  for (const change of [{nullifierStatus:"unknown"},{isSpent:true},{nullifier:"01".repeat(32)}]) assert.throws(()=>prepareSpendInputsV2({...input,notes:[{...note,...change},zero]}),/unspent|mismatch/);
  assert.throws(()=>prepareSpendInputsV2({...input,rootSeed:new Uint8Array(32)}),/owner/);
  assert.throws(()=>prepareSpendInputsV2({...input,denom:"aother"}),/asset/);
  assert.throws(()=>prepareSpendInputsV2({...input,kind:"withdraw",notes:[note]}),/amount/);
});
