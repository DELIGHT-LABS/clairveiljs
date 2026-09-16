import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {createCustodyProvider,createDirectBridgeTransport} from 'clairveiljs/custody-provider';
import {createClairveilDappClient} from 'clairveiljs/dapp';
const cases=JSON.parse(readFileSync(new URL('../src/wallet-api/schema/wallet-api-draft.examples.json',import.meta.url))).cases;
const fixture=(name,side)=>structuredClone(cases.find(c=>c.name===name+'.'+side).value[side==='request'?'params':'result']);
function harness(){let now=0;const calls=[];let handler=async ({method})=>fixture(method.slice(10),'response');
 const provider=createCustodyProvider({transport:{request:input=>{calls.push(input);return handler(input);}},clock:()=>now,timeoutMs:1000});
 return{provider,calls,setHandler:fn=>handler=fn,advance:()=>now+=1000};}
test('provider and direct bridge reject unsupported versions before discovery or transport work', async () => {
  let calls = 0;
  const unexpected = async () => { calls++; throw new Error('unexpected transport'); };
  const provider = createCustodyProvider({ transport: { request: unexpected } });
  const bridge = createDirectBridgeTransport({ exchange: unexpected });
  for (const client of [provider, bridge]) {
    for (const request of [
      { method: 'clairveil_getCapabilities', params: { protocolVersion: '2' } },
      { method: 'clairveil_connect', params: { ...fixture('connect', 'request'), schemaRevision: 'future' } }
    ]) {
      await assert.rejects(client.request(request), error => error.code === 4101
        && error.message === 'UNSUPPORTED_VERSION' && error.rpcError.data.retryable === false);
    }
    await assert.rejects(client.request({ method: 'clairveil_getCapabilities', params: {} }), error => error.code === -32602);
  }
  assert.equal(calls, 0);
});
test('public client has all 15 typed methods with no private facade, and does not connect on construction',async()=>{
 const {provider,calls}=harness();const client=createClairveilDappClient({custodyProvider:provider});
 assert.equal(calls.length,0);assert.equal(Object.keys(client).length,15);
 for(const name of ['cosmos','privacyMaterial','derivePrivacyAccount','rootSeed'])assert.equal(client[name],undefined);
 await client.getCapabilities(fixture('getCapabilities','request'));
 const result=await client.connect(fixture('connect','request'));assert.ok(result.operationId);
 assert.equal(Object.isFrozen(result),true);
});
test('provider rejects unreviewed schemas and hostile errors without private data',async()=>{
 const h=harness();h.setHandler(async()=>({...fixture('getCapabilities','response'),schemaDigest:'00'.repeat(32)}));
 await assert.rejects(h.provider.request({method:'clairveil_getCapabilities',params:{protocolVersion:'1'}}),/Internal error/);
 h.setHandler(async()=>{throw{code:-32603,message:'private synthetic witness',cause:{rootSeed:'synthetic'}};});
 await assert.rejects(h.provider.request({method:'clairveil_getCapabilities',params:{protocolVersion:'1'}}),error=>error.message==='Internal error'&&!('cause'in error));
});
test('late replies after attachment loss and lower status revisions are rejected',async()=>{
 const h=harness();await h.provider.request({method:'clairveil_getCapabilities',params:{protocolVersion:'1'}});
 let resolve;h.setHandler(()=>new Promise(r=>resolve=r));
 const pending=h.provider.request({method:'clairveil_connect',params:fixture('connect','request')});await Promise.resolve();
 h.provider.invalidate();resolve(fixture('connect','response'));await assert.rejects(pending,/UNAUTHORIZED/);
 h.setHandler(async({method})=>fixture(method.slice(10),'response'));
 await h.provider.request({method:'clairveil_getCapabilities',params:{protocolVersion:'1'}});
 await h.provider.request({method:'clairveil_getOperation',params:fixture('getOperation','request')});h.advance();
 h.setHandler(async()=>({...fixture('getOperation','response'),statusRevision:'0'}));
 await assert.rejects(h.provider.request({method:'clairveil_getOperation',params:fixture('getOperation','request')}),/Internal error/);
});
test('direct bridge enforces response correlation and duplicate JSON members',async()=>{
 const params={protocolVersion:'1'};
 const wrong=createDirectBridgeTransport({exchange:async()=>({jsonrpc:'2.0',id:'wrong',result:fixture('getCapabilities','response')})});
 await assert.rejects(wrong.request({method:'clairveil_getCapabilities',params}));
 const duplicate=createDirectBridgeTransport({exchange:async({id})=>`{"jsonrpc":"2.0","id":"${id}","id":"${id}","result":{}}`});
 await assert.rejects(duplicate.request({method:'clairveil_getCapabilities',params}));
});

test('admission rejects hostile wrappers, throttles polling and permanently closes disposed providers',async()=>{
 const h=harness();let reads=0;
 await assert.rejects(h.provider.request({get method(){reads++;return'clairveil_connect';},params:{}}));assert.equal(reads,0);assert.equal(h.calls.length,0);
 await h.provider.request({method:'clairveil_getCapabilities',params:{protocolVersion:'1'}});
 const input={method:'clairveil_getOperation',params:fixture('getOperation','request')};
 await h.provider.request(input);await assert.rejects(h.provider.request(input),/RESOURCE_LIMIT/);
 h.provider.dispose();await assert.rejects(h.provider.request({method:'clairveil_getCapabilities',params:{protocolVersion:'1'}}),/UNAUTHORIZED/);
});

test('pending admission reserves two control slots and releases capacity after completion', async () => {
  const h = harness();
  await h.provider.request({ method: 'clairveil_getCapabilities', params: { protocolVersion: '1' } });
  const completions = [];
  h.setHandler(({ method }) => new Promise(resolve => completions.push(() => resolve(fixture(method.slice(10), 'response')))));
  const connect = { method: 'clairveil_connect', params: fixture('connect', 'request') };
  const cancel = { method: 'clairveil_cancelOperation', params: fixture('cancelOperation', 'request') };
  const pending = Array.from({ length: 16 }, () => h.provider.request(connect));
  await assert.rejects(h.provider.request(connect), /RESOURCE_LIMIT/);
  pending.push(h.provider.request(cancel), h.provider.request(cancel));
  await assert.rejects(h.provider.request(cancel), /RESOURCE_LIMIT/);
  assert.equal(completions.length, 18);
  completions.forEach(complete => complete());
  await Promise.all(pending);
  h.setHandler(async () => fixture('connect', 'response'));
  await h.provider.request(connect);
});

test('timed-out requests release every pending slot without replaying the transport', async () => {
  let stalled = true;
  let requests = 0;
  const provider = createCustodyProvider({
    timeoutMs: 10,
    transport: {
      request({ method }) {
        if (method === 'clairveil_getCapabilities') return Promise.resolve(fixture('getCapabilities', 'response'));
        requests++;
        return stalled ? new Promise(() => {}) : Promise.resolve(fixture('connect', 'response'));
      }
    }
  });
  await provider.request({ method: 'clairveil_getCapabilities', params: { protocolVersion: '1' } });
  const input = { method: 'clairveil_connect', params: fixture('connect', 'request') };
  const expired = await Promise.allSettled(Array.from({ length: 16 }, () => provider.request(input)));
  assert.ok(expired.every(result => result.status === 'rejected' && result.reason.code === 4112));
  assert.equal(requests, 16);
  stalled = false;
  await Promise.all(Array.from({ length: 16 }, () => provider.request(input)));
  assert.equal(requests, 32);
});


test('transport envelope mutation cannot change response validation or invalidate the provider', async () => {
  const h = harness();
  h.setHandler(async request => {
    request.method = 'clairveil_disconnect';
    request.params = fixture('disconnect', 'request');
    return fixture('getCapabilities', 'response');
  });
  const result = await h.provider.request({ method: 'clairveil_getCapabilities', params: { protocolVersion: '1' } });
  assert.equal(result.methods.length, 15);
  assert.equal(h.provider.generation, 0);
});

test('disabled capability is distinct from missing discovery, invalidation and unknown methods', async () => {
  const h = harness();
  const request = { method: 'clairveil_requestDisclosure', params: fixture('requestDisclosure', 'request') };
  await assert.rejects(h.provider.request(request), error => error.code === 4103);
  const capabilities = fixture('getCapabilities', 'response');
  capabilities.methods = capabilities.methods.filter(method => method !== request.method);
  capabilities.privacyTransports = ['extension-v1'];
  h.setHandler(async () => capabilities);
  await h.provider.request({ method: 'clairveil_getCapabilities', params: { protocolVersion: '1' } });
  await assert.rejects(h.provider.request(request), error => error.code === 4102
    && error.message === 'UNSUPPORTED_CAPABILITY' && error.rpcError.data.retryable === false);
  await assert.rejects(h.provider.request({ method: 'clairveil_unknown', params: {} }), error => error.code === -32601);
  assert.equal(h.calls.length, 1);
  h.setHandler(async () => fixture('connect', 'response'));
  await h.provider.request({ method: 'clairveil_connect', params: fixture('connect', 'request') });
  h.provider.invalidate();
  await assert.rejects(h.provider.request(request), error => error.code === 4103);
  assert.equal(h.calls.length, 2);
});

test('capability object order preserves attachment, polling and revision guards; value changes revoke', async () => {
  const reorder = value => Array.isArray(value) ? value.map(reorder)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.entries(value).reverse().map(([key, item]) => [key, reorder(item)])) : value;
  const h = harness();
  const discovery = { method: 'clairveil_getCapabilities', params: { protocolVersion: '1' } };
  const poll = { method: 'clairveil_getOperation', params: fixture('getOperation', 'request') };
  let invalidations = 0;
  h.provider.onInvalidation(() => invalidations++);
  const original = await h.provider.request(discovery);
  await h.provider.request(poll);
  const reordered = reorder(original);
  assert.deepEqual(reordered, original);
  h.setHandler(async () => reordered);
  await h.provider.request(discovery);
  assert.equal(h.provider.generation, 0);
  assert.equal(invalidations, 0);
  await assert.rejects(h.provider.request(poll), /RESOURCE_LIMIT/);
  h.advance();
  h.setHandler(async () => ({ ...fixture('getOperation', 'response'), statusRevision: '0' }));
  await assert.rejects(h.provider.request(poll), /Internal error/);

  for (const change of [value => { value.networks[0].profileDigest = 'ff'.repeat(32); },
    value => { value.methods = value.methods.filter(method => method !== 'clairveil_requestDisclosure'); value.privacyTransports = ['extension-v1']; },
    value => { value.methods.reverse(); }]) {
    const changed = structuredClone(reordered);
    change(changed);
    h.setHandler(async () => changed);
    const before = h.provider.generation;
    await h.provider.request(discovery);
    assert.equal(h.provider.generation, before + 1);
    assert.equal(invalidations, h.provider.generation);
  }
});

test('cancel replies must match the operation through both provider and direct bridge', async () => {
  const h = harness();
  await h.provider.request({ method: 'clairveil_getCapabilities', params: { protocolVersion: '1' } });
  const params = fixture('cancelOperation', 'request');
  const wrong = fixture('cancelOperation', 'response');
  wrong.operation.operationId = 'D'.repeat(42) + 'A';
  h.setHandler(async () => wrong);
  const bridge = createDirectBridgeTransport({ exchange: async ({ id }) => ({ jsonrpc: '2.0', id, result: wrong }) });
  for (const client of [h.provider, bridge]) {
    await assert.rejects(client.request({ method: 'clairveil_cancelOperation', params }), error => error.code === -32603);
  }
  h.provider.dispose();
});

test('a lower cancel revision cannot overwrite newer operation state', async () => {
  const h = harness();
  await h.provider.request({ method: 'clairveil_getCapabilities', params: { protocolVersion: '1' } });
  const poll = { method: 'clairveil_getOperation', params: fixture('getOperation', 'request') };
  h.setHandler(async () => ({ ...fixture('getOperation', 'response'), statusRevision: '10' }));
  await h.provider.request(poll);
  h.setHandler(async () => fixture('cancelOperation', 'response'));
  await assert.rejects(h.provider.request({ method: 'clairveil_cancelOperation', params: fixture('cancelOperation', 'request') }), error => error.code === -32603);
  h.provider.dispose();
});

test('a newer cancel revision fences an in-flight older poll and preserves the nested result', async () => {
  const h = harness();
  await h.provider.request({ method: 'clairveil_getCapabilities', params: { protocolVersion: '1' } });
  const poll = { method: 'clairveil_getOperation', params: fixture('getOperation', 'request') };
  let reply;
  const cancelled = fixture('cancelOperation', 'response');
  cancelled.operation.statusRevision = '20';
  h.setHandler(({ method }) => method === poll.method ? new Promise(resolve => { reply = resolve; }) : cancelled);
  const pending = h.provider.request(poll);
  const rejected = assert.rejects(pending, error => error.code === -32603);
  const result = await h.provider.request({ method: 'clairveil_cancelOperation', params: fixture('cancelOperation', 'request') });
  assert.deepEqual(result, cancelled);
  assert.equal(Object.isFrozen(result.operation), true);
  reply({ ...fixture('getOperation', 'response'), statusRevision: '10' });
  await rejected;
  h.provider.dispose();
});
