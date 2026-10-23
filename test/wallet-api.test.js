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
test('all draft fixtures agree with full Draft 2020-12 and standalone validation',()=>{
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

test('cancel results correlate their nested operation with the requested operation', () => {
  const params = structuredClone(cases.find(c => c.name === 'cancelOperation.request').value.params);
  const result = structuredClone(cases.find(c => c.name === 'cancelOperation.response').value.result);
  assert.deepEqual(validateWalletResult('clairveil_cancelOperation', result, params), result);
  result.operation.operationId = 'D'.repeat(42) + 'A';
  assert.throws(() => validateWalletResult('clairveil_cancelOperation', result, params), error => error.code === -32603);
});

const restoredFundingActions = {
  created: 'wait', awaiting_approval: 'approve_privacy', preparing: 'wait',
  authorization_exported: 'wait', proof_ready: 'wait', awaiting_chain_signature: 'sign_chain',
  submission_unknown: 'check_chain', submitted: 'check_chain', reconciliation_required: 'check_chain',
  confirmed: 'none', failed: 'none', cancelled: 'none', expired: 'none'
};
function restoredFundingSnapshot(state = 'awaiting_chain_signature') {
  const value = structuredClone(cases.find(c => c.name === 'getOperation.response').value.result);
  Object.assign(value, { state, runtimeState: 'recovery_required', nextAction: restoredFundingActions[state],
    summary: { assetDenom: 'usynthetic', amountBaseUnits: '1' },
    jobState: state === 'failed' ? 'failed' : ['confirmed', 'cancelled', 'expired'].includes(state) ? 'completed' : 'queued' });
  if (state === 'failed') value.failure = { code: 4113, message: 'STORAGE_UNAVAILABLE', data: { label: 'STORAGE_UNAVAILABLE', retryable: true } };
  if (state === 'awaiting_chain_signature') value.publicArtifact = {
    transport: 'cosmos', chainId: 'cosmos:synthetic-1', chainActorHandle: value.operationId,
    artifactBindingHash: '0'.repeat(64), bindingVersion: 'cv-artifact-jcs-sha256-v1',
    signDoc: { bodyBytesBase64: 'TQ==', authInfoBytesBase64: 'TQ==', chainId: 'synthetic-1', accountNumber: '0' }
  };
  return value;
}

test('restored funding permits safe policy suppression in every state', () => {
  for (const state of Object.keys(restoredFundingActions)) {
    const value = { ...restoredFundingSnapshot(state), nextAction: 'recover' };
    delete value.publicArtifact;
    assert.deepEqual(validateWalletResult('clairveil_getOperation', value), value, state);
    value.publicArtifact = restoredFundingSnapshot().publicArtifact;
    assert.throws(() => validateWalletResult('clairveil_getOperation', value), state);
  }
});

test('restored funding keeps truthful runtime state and exact normal state actions', () => {
  for (const [state, action] of Object.entries(restoredFundingActions)) {
    const value = restoredFundingSnapshot(state);
    assert.deepEqual(validateWalletResult('clairveil_getOperation', value), value, state);
    for (const nextAction of new Set([...Object.values(restoredFundingActions), 'recover'])) {
      if (nextAction === action || nextAction === 'recover' && !value.publicArtifact) continue;
      assert.throws(() => validateWalletResult('clairveil_getOperation', { ...value, nextAction }), state + ': ' + nextAction);
    }
  }
  const missingArtifact = restoredFundingSnapshot(); delete missingArtifact.publicArtifact;
  assert.throws(() => validateWalletResult('clairveil_getOperation', missingArtifact));
  const withAttempt = { ...restoredFundingSnapshot(), submissionAttempt: { attemptId: missingArtifact.operationId, state: 'unresolved' } };
  assert.throws(() => validateWalletResult('clairveil_getOperation', withAttempt));
  for (const state of ['created', 'awaiting_approval', 'preparing', 'authorization_exported', 'proof_ready', 'failed', 'cancelled', 'expired']) {
    assert.throws(() => validateWalletResult('clairveil_getOperation', { ...restoredFundingSnapshot(state), publicArtifact: restoredFundingSnapshot().publicArtifact }), state);
  }
});

test('restored funding exception never expands helpers, missing amounts or recovery-only grants', () => {
  for (const amount of ['0', '', '01', '-1', '1.0', 1, null, undefined]) {
    const value = restoredFundingSnapshot();
    if (amount === undefined) delete value.summary.amountBaseUnits;
    else value.summary.amountBaseUnits = amount;
    assert.throws(() => validateWalletResult('clairveil_getOperation', value), String(amount));
  }
  const missingSummary = restoredFundingSnapshot(); delete missingSummary.summary;
  assert.throws(() => validateWalletResult('clairveil_getOperation', missingSummary));
  for (const kind of ['zero_helper', 'self_merge', 'final_transfer', 'withdraw']) {
    assert.throws(() => validateWalletResult('clairveil_getOperation', { ...restoredFundingSnapshot(), kind, stepKind: kind }), kind);
  }
  assert.throws(() => validateWalletResult('clairveil_getOperation', { ...restoredFundingSnapshot(), stepKind: 'zero_helper' }));
  for (const state of Object.keys(restoredFundingActions)) {
    const value = { ...restoredFundingSnapshot(state), accessMode: 'recovery-only' };
    assert.throws(() => validateWalletResult('clairveil_getOperation', value), state);
    value.nextAction = 'recover'; delete value.publicArtifact;
    assert.deepEqual(validateWalletResult('clairveil_getOperation', value), value, state);
    value.publicArtifact = restoredFundingSnapshot().publicArtifact;
    assert.throws(() => validateWalletResult('clairveil_getOperation', value), state);
  }
});
