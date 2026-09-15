import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import { parseWalletJson, snapshotJson, validateWalletValue, validateWalletParams, validateWalletResult, mapWalletError, schemaDigest, methodRegistry } from 'clairveiljs/wallet-api';
const schema = JSON.parse(readFileSync(new URL('../src/wallet-api/schema/wallet-api-draft.schema.json',import.meta.url),'utf8'));
const cases = JSON.parse(readFileSync(new URL('../src/wallet-api/schema/wallet-api-draft.examples.json',import.meta.url),'utf8')).cases;
const ajv=new Ajv2020({strict:false,ownProperties:true});ajv.addSchema(schema);
test('all methods distinguish unsupported versions from malformed params without reading accessors', () => {
  const invalidParams = error => error.code === -32602;
  for (const method of Object.keys(methodRegistry)) {
    const params = cases.find(c => c.name === `${method.slice(10)}.request`).value.params;
    const fields = method === 'clairveil_getCapabilities' ? ['protocolVersion'] : ['protocolVersion', 'schemaRevision'];
    for (const field of fields) {
      const unsupported = { ...params, [field]: 'future' };
      assert.throws(() => validateWalletParams(method, unsupported), error => {
        assert.equal(error.code, 4101);
        assert.equal(error.message, 'UNSUPPORTED_VERSION');
        assert.equal(error.rpcError.data.retryable, false);
        assert.equal(mapWalletError(method, error).code, 4101);
        return true;
      });
      for (const value of [null, 1, false, [], {}]) {
        assert.throws(() => validateWalletParams(method, { ...params, [field]: value }), invalidParams);
      }
      const missing = { ...params }; delete missing[field];
      assert.throws(() => validateWalletParams(method, missing), invalidParams);
      let reads = 0;
      const accessor = { ...params };
      Object.defineProperty(accessor, field, { enumerable: true, get() { reads++; return 'future'; } });
      assert.throws(() => validateWalletParams(method, accessor), invalidParams);
      assert.equal(reads, 0);
    }
  }
  assert.throws(() => validateWalletParams('clairveil_unknown', { protocolVersion: 'future' }), error => error.code === -32601);
  assert.throws(() => validateWalletParams('clairveil_getCapabilities', { protocolVersion: '1', schemaRevision: 'future' }), invalidParams);
  assert.throws(() => validateWalletParams('clairveil_getCapabilities', { protocolVersion: 'future', oversized: 'x'.repeat(4097) }), invalidParams);
});
test('all 337 draft fixtures agree with full Draft 2020-12 and standalone validation',()=>{
 assert.equal(Object.keys(methodRegistry).length,15);
 for(const c of cases){
  assert.equal(ajv.getSchema(schema.$id+c.schema)(c.value),c.valid,c.name+' full validator');
  if(c.valid)assert.doesNotThrow(()=>validateWalletValue(c.schema,c.value,{response:true}),c.name);
  else assert.throws(()=>validateWalletValue(c.schema,c.value,{response:true}),c.name);
 }
 assert.equal(cases.find(c=>c.name==='getCapabilities.response').value.result.schemaDigest,schemaDigest);
});
test('raw parser rejects duplicate, escaped duplicate, Unicode and prototype mutations',()=>{
 for(const text of ['{"x":1,"x":2}','{"x":1,"\\u0078":2}','{"__proto__":{}}','{"a":"\\ud800"}','[1e999]','[1,]','{"a":1,}','true false']) assert.throws(()=>parseWalletJson(text),text);
 assert.throws(()=>parseWalletJson(new Uint8Array([0xff])));
 assert.deepEqual(parseWalletJson('{"a":[true,null,1.5,"é"]}'),{a:[true,null,1.5,'é']});
});
test('object inputs reject getters, non-enumerable data, cycles and classes without calling them',()=>{
 let calls=0;
 const getter={get value(){calls++;return 'private';}};
 const hidden=Object.defineProperty({},'value',{value:'private'});
 const cyclic={};cyclic.self=cyclic;
 for(const value of [getter,hidden,cyclic,new Date(),new Uint8Array(2),{value:1n},new Array(3)])assert.throws(()=>snapshotJson(value));
 assert.equal(calls,0);
});
test('request/response bounds and public projection reject oversize or hidden payloads',()=>{
 assert.throws(()=>snapshotJson({value:'x'.repeat(4097)}));
 assert.throws(()=>snapshotJson(Array(65).fill(0)));
 let shared='x'.repeat(4000);for(let i=0;i<7;i++)shared=Array(64).fill(shared);assert.throws(()=>snapshotJson(shared),/byte limit/);
 let nested={};for(let i=0;i<8;i++)nested={nested};assert.throws(()=>snapshotJson(nested));
 const valid=structuredClone(cases.find(c=>c.name==='getOperation.response').value.result);
 assert.throws(()=>validateWalletResult('clairveil_getOperation',{...valid,rootSeed:'synthetic'}));
 assert.throws(()=>validateWalletResult('clairveil_getOperation',valid,{operationId:'A'.repeat(43)}));
 const request=cases.find(c=>c.name==='getBalances.request').value.params;
 const response=structuredClone(cases.find(c=>c.name==='getBalances.response').value.result);
 if(request.protocol.assets){response.rows[0].assetDenom='uother';assert.throws(()=>validateWalletResult('clairveil_getBalances',response,request));}
});
