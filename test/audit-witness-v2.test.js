import test from "node:test";
import assert from "node:assert/strict";
import { prepareAuditWitnessV2 } from "clairveiljs/audit-witness-v2";
import { snapshot, vectors, config } from "./helpers/audit-prover.js";
const rootSeed=Uint8Array.from({length:32},(_,i)=>i);
async function setup() {
  const current=await snapshot();let calls=0,checkpoints=0;
  const input={kind:"deposit",rootSeed,snapshot:current,creator:vectors.cases[0].creator,chainId:config.chain_id,amount:1n<<64n,denom:"uclair",expiresAtUnix:BigInt(Math.floor(Date.now()/1000)+600),
    backend:{prepare:async()=>{calls++;return new Uint8Array();}},getCurrentSnapshot:async()=>current,checkpoint:async()=>{checkpoints++;}};
  return {input,calls:()=>calls,checkpoints:()=>checkpoints};
}
test("native owner signing cannot run before a durable checkpoint and fresh snapshot",async()=>{
  const a=await setup();
  await assert.rejects(prepareAuditWitnessV2({...a.input,checkpoint:async()=>{throw new Error("durable checkpoint failed");}}),/checkpoint/);
  assert.equal(a.calls(),0);
  const b=await setup();
  await assert.rejects(prepareAuditWitnessV2({...b.input,getCurrentSnapshot:async()=>({...b.input.snapshot})}),/validated/);
  assert.equal(b.checkpoints(),1);assert.equal(b.calls(),0);
  const c=await setup(),controller=new AbortController();
  await assert.rejects(prepareAuditWitnessV2({...c.input,signal:controller.signal,checkpoint:async()=>controller.abort()}));
  assert.equal(c.calls(),0);
});
test("native preparation rejects wrong chain, overflowing amounts and malformed replies",async()=>{
  for (const changes of [{chainId:"other-chain"},{amount:1n<<128n},{creator:"invalid"},{kind:"toString"}]) {
    const s=await setup();await assert.rejects(prepareAuditWitnessV2({...s.input,...changes}));assert.equal(s.calls(),0);
  }
  const s=await setup();await assert.rejects(prepareAuditWitnessV2(s.input),/frame/);assert.equal(s.calls(),1);assert.equal(s.checkpoints(),1);
});
