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
