import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { prepareDepositMaterialV2 } from "clairveiljs/preparation-v2";
import { decryptDepositNoteV2,computeNoteCommitmentV2,encryptNoteForTransferV2 } from "clairveiljs/protocol-v2";
import { canonicalFieldBytes } from "clairveiljs/crypto";
import { validatePrivacyScanPageV2,processPrivacyScanPageV2,scanNotes,createPrivacyScanValidationStateV2,serializePrivacyScanValidationStateV2,restorePrivacyScanValidationStateV2 } from "clairveiljs/scan-v2";
import { serializeFoundNoteV2,deserializeFoundNoteV2 } from "../src/privacy/note-store-v2.js";
const rootSeed=Uint8Array.from({length:32},(_,i)=>i),amount=(1n<<128n)-1n;
const audit=JSON.parse(readFileSync(new URL("../fixtures/clairveil-v0.6.1-audit/vectors.json",import.meta.url))), key=audit.records[1];
function page(){
  const m=prepareDepositMaterialV2({rootSeed,amount,denom:"uclair"});m.clear();
  const identity={height:"10",globalSequence:"4",txHash:new Uint8Array(32).fill(1),eventType:"deposit",circuitSetId:"privacy-note-v1-u128-audit-field-v1",payloadVersion:"privacy-fixed-v2",scanSchemaVersion:"privacy-scan-v2",auditKeyId:key.key_id_hex,auditKeyEpoch:key.epoch,auditTargetPubkey:Buffer.from(key.public_key_hex,"hex"),effectId:new Uint8Array(32).fill(2)};
  return {scanSchemaVersion:"privacy-scan-v2",summaries:[{...identity,nullifiers:[],outputCount:1}],outputs:[{...identity,outputIndex:0,commitment:m.output.commitment,encryptedNote:m.output.ciphertext,leafIndexFound:true,leafIndex:"0"}],nextCursor:{height:"10",globalSequence:"4",outputIndex:0},hasMore:false};
}
test("audit scan recovers actual fixed V2 notes and stores full-width amounts without a legacy cache fallback",async()=>{
  const validated=validatePrivacyScanPageV2(page()),found=processPrivacyScanPageV2(validated,{rootSeed});
  assert.equal(found.length,1);assert.equal(found[0].note.amount,amount);assert.equal(found[0].nullifierStatus,"unverified");
  const result=await scanNotes({rootSeed,preprocessedFoundNotes:found,checkNullifiers:async ns=>new Map(ns.map(n=>[n,false])),includeFoundNotes:true});
  assert.equal(result.summary.total_spendable,amount.toString());
  const stored=serializeFoundNoteV2(result.foundNotes[0]);assert.deepEqual(deserializeFoundNoteV2(stored),result.foundNotes[0]);
  for(const change of [{version:"privacy-note-v1-cache-v1"},{nullifier:"01".repeat(32)},{commitment:"02".repeat(32)},{height:10},{isSpent:true}])assert.throws(()=>deserializeFoundNoteV2({...stored,...change}));
});
test("audit scan rejects legacy identity, audit key mismatch, framing changes and modified validated pages",()=>{
  for(const change of [{circuitSetId:"privacy-note-v1"},{payloadVersion:"privacy-fixed-v1"},{auditKeyEpoch:"0"},{auditKeyId:"00".repeat(32)},{effectId:new Uint8Array()}]){
    const p=page();Object.assign(p.summaries[0],change);assert.throws(()=>validatePrivacyScanPageV2(p));
  }
  const p=page();p.outputs[0].auditDisclosurePayload=Uint8Array.of(1);assert.throws(()=>validatePrivacyScanPageV2(p),/retired/);
  const v=validatePrivacyScanPageV2(page());v.outputs[0].commitment[0]^=1;assert.throws(()=>processPrivacyScanPageV2(v,{rootSeed}),/issued/);
  assert.equal(processPrivacyScanPageV2(validatePrivacyScanPageV2(page()),{rootSeed:new Uint8Array(32)}).length,0);
  const state=serializePrivacyScanValidationStateV2(createPrivacyScanValidationStateV2());assert.deepEqual(serializePrivacyScanValidationStateV2(restorePrivacyScanValidationStateV2(state)),state);
  assert.throws(()=>restorePrivacyScanValidationStateV2({...state,version:"privacy-scan-validation-v2"}));
});
test("missing or failed fresh nullifier observations cannot preserve cached spendability",async()=>{
  const found=processPrivacyScanPageV2(validatePrivacyScanPageV2(page()),{rootSeed})[0];found.nullifierStatus="unspent";
  for(const checkNullifiers of [undefined,async()=>new Map(),async()=>{throw new Error("offline");}]) {
    const result=await scanNotes({rootSeed,preprocessedFoundNotes:[found],checkNullifiers,includeFoundNotes:true});
    assert.equal(result.summary.total_spendable,"0");assert.equal(result.foundNotes[0].nullifierStatus,"unverified");
  }
});

test("partial V2 transfers resume from serialized continuation and preserve exact audit identity",()=>{
  const base=page().summaries[0];
  const summary={...base,eventType:"shielded_transfer",outputCount:2,nullifiers:[canonicalFieldBytes(3n),canonicalFieldBytes(4n)]};
  const outputs=[0,1].map(index=>{
    const material=prepareDepositMaterialV2({rootSeed,amount:index===0?1n<<65n:0n,denom:"uclair"});
    const note=decryptDepositNoteV2(material.output.ciphertext,rootSeed);material.clear();
    const commitment=canonicalFieldBytes(computeNoteCommitmentV2(note)),encrypted=encryptNoteForTransferV2(note,commitment,index);
    return {...summary,outputIndex:index,commitment,ciphertext:encrypted.ciphertext,viewTag:encrypted.viewTag,leafIndexFound:true,leafIndex:String(index),
      ...(index===0?{userDisclosureMode:"USER_DISCLOSURE_MODE_NONE",fullDisclosureDigest:canonicalFieldBytes(7n)}:{})};
  });
  const state=createPrivacyScanValidationStateV2(),first={scanSchemaVersion:"privacy-scan-v2",summaries:[summary],outputs:[outputs[0]],hasMore:true,nextCursor:{height:"10",globalSequence:"4",outputIndex:0}};
  assert.equal(processPrivacyScanPageV2(validatePrivacyScanPageV2(first,{validationState:state}),{rootSeed})[0].note.amount,1n<<65n);
  const restored=restorePrivacyScanValidationStateV2(serializePrivacyScanValidationStateV2(state));
  const second={...first,outputs:[outputs[1]],hasMore:false,nextCursor:{height:"10",globalSequence:"4",outputIndex:1}};
  const result=validatePrivacyScanPageV2(second,{after:first.nextCursor,validationState:restored});
  assert.equal(processPrivacyScanPageV2(result,{rootSeed})[0].note.amount,0n);
  assert.equal(restored.pending_summary_by_event.size,0);
  const broken=restorePrivacyScanValidationStateV2(serializePrivacyScanValidationStateV2(state));
  assert.throws(()=>validatePrivacyScanPageV2({...second,summaries:[{...summary,effectId:new Uint8Array(32).fill(3)}]},{after:first.nextCursor,validationState:broken}));
});
