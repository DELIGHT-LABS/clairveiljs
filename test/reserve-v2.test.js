import test from "node:test";
import assert from "node:assert/strict";
import { evaluateReserveV2,assertReserveCollateralizedV2,ReserveUnderCollateralizedErrorV2 } from "../src/privacy/reserve-v2.js";
const reserve=(delta=0n)=>({denom:"uclair",module_balance:(10n+delta).toString(),total_deposited:((1n<<300n)+10n).toString(),total_withdrawn:(1n<<300n).toString(),expected_module_balance:"10",liability:"10",invariant_holds:delta===0n,collateralized:delta>=0n,surplus:delta>0n?delta.toString():"0",shortfall:delta<0n?(-delta).toString():"0"});
test("reserve accepts exact and surplus collateralization with unbounded lifetime counters",()=>{
  for(const delta of [0n,1n,1n<<128n]) {
    const s=assertReserveCollateralizedV2(reserve(delta),"uclair");assert.equal(s.collateralized,true);assert.equal(s.exactMatch,delta===0n);assert.equal(s.surplus,delta.toString());
  }
});
test("reserve preserves shortfall as its own result and refuses spending admission",()=>{
  const raw=reserve(-1n),s=evaluateReserveV2(raw);assert.equal(s.shortfall,"1");assert.equal(s.collateralized,false);
  assert.throws(()=>assertReserveCollateralizedV2(raw),e=>e instanceof ReserveUnderCollateralizedErrorV2&&e.code==="under_collateralized"&&e.status.shortfall==="1");
});
test("reserve rejects stale exact-match rules, missing fields, alias conflict and bad arithmetic",()=>{
  const changes=[{liability:"9"},{total_withdrawn:"0"},{expected_module_balance:"9"},{invariant_holds:false},{collateralized:false},{surplus:"1"},{shortfall:"1"},{moduleBalance:"11"},{module_balance:(1n<<256n).toString()}];
  for(const change of changes)assert.throws(()=>evaluateReserveV2({...reserve(),...change}));
  for(const key of Object.keys(reserve())){const missing=reserve();delete missing[key];assert.throws(()=>evaluateReserveV2(missing),undefined,key);}
  for(const value of [10,10n,"01","+1"," 1","-1"])assert.throws(()=>evaluateReserveV2({...reserve(),module_balance:value}));
  assert.throws(()=>evaluateReserveV2(reserve(),"aother"),/denom/);
  assert.throws(()=>evaluateReserveV2({...reserve(1n),invariant_holds:true}),/arithmetic/);
});
