import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { encodeEvmPrivacyRequestV2, decodeEvmPrivacyRequestV2, evmPrivacyV2Abi } from "../src/transport/evm-v2.js";
const b = (...values) => Uint8Array.from(values);
const audit = { keyId:b(1,2), epoch:(1n<<64n)-1n, envelope:b(3,4,5) };
const output = { commitment:b(6,7), ciphertext:b(8,9), viewTag:b(10,11), userPrivacyPolicy:7, userDisclosureMode:2, userDisclosureDigest:b(12), userDisclosureTargetPubkey:b(13), userDisclosurePayload:b(14), selfFullDisclosureDigest:b(15), selfViewDisclosurePayload:b(16) };
const common = { expiresAtUnix:(1n<<63n)-1n, audit };
const requests = {
  deposit:{...common, output, proof:b(17,18)},
  transfer:{...common, proof:b(25), root:b(22), nullifiers:[b(23),b(24)], outputs:[output,output]},
  withdraw:{...common, proof:b(21), root:b(19), nullifier:b(20), amount:"340282366920938463463374607431768211455uclair", recipient:"0x0123456789012345678901234567890123456789"}
};
test("V2 direct EVM encodings match independent go-ethereum/Maroo vectors", () => {
  const fixture = JSON.parse(readFileSync(new URL("../fixtures/maroo-v061-evm-vectors.json", import.meta.url)));
  assert.equal(fixture.source.commit, "823f6752e89a8d7157bd90973e7b1f9093e0ec10");
  for (const [kind, request] of Object.entries(requests)) assert.equal(encodeEvmPrivacyRequestV2(kind, request), fixture.vectors[kind].hex, kind);
  for (const [kind, request] of Object.entries(requests)) {
    const data = fixture.vectors[kind].hex;
    assert.deepEqual(decodeEvmPrivacyRequestV2(kind,data),request);
    for (const changed of [data+'00',data.slice(0,-2),data.slice(0,10)+'00'.repeat(32)+data.slice(74)]) assert.throws(()=>decodeEvmPrivacyRequestV2(kind,changed));
  }
});
test("V2 direct ABI refuses legacy, extra, missing and unsafe integer fields", () => {
  for (const kind of Object.keys(requests)) {
    const r = requests[kind];
    assert.throws(() => encodeEvmPrivacyRequestV2(kind, {...r, legacy: true}), /unsupported/);
    assert.throws(() => encodeEvmPrivacyRequestV2(kind, {...r, audit:undefined}), /required|object/);
    assert.throws(() => encodeEvmPrivacyRequestV2(kind, {...r, expiresAtUnix:Number.MAX_SAFE_INTEGER+1}), /integer/);
    assert.throws(() => encodeEvmPrivacyRequestV2(kind, {...r, expiresAtUnix:1n<<63n}), /integer|range/);
    assert.throws(() => encodeEvmPrivacyRequestV2(kind, {...r, audit:{...audit, epoch:"01"}}), /integer/);
    assert.throws(() => encodeEvmPrivacyRequestV2(kind, {...r, proof:[1,2]}), /bytes/);
  }
  assert.throws(() => encodeEvmPrivacyRequestV2("batchTransfer", requests.transfer), /unsupported/);
  assert.deepEqual(evmPrivacyV2Abi.map(x=>x.name).sort(), ["deposit","transfer","withdraw"]);
});

test('V2 receipt verification binds direct actor, calldata, value and exact event bytes', async()=>{
  const {verifyEvmEffectV2}=await import('clairveiljs/evm-v2');
  const {encodeAbiParameters}=await import('../src/transport/evm-abi.js');
  const {toBech32}=await import('@cosmjs/encoding');
  const {keccak_256}=await import('@noble/hashes/sha3.js');
  const sender='0x'+'01'.repeat(20),to='0x'+'02'.repeat(20),txHash='0x'+'ab'.repeat(32),creator=toBech32('maroo',new Uint8Array(20).fill(1));
  const topic=a=>'0x'+a.slice(2).padStart(64,'0');
  for(const kind of ['deposit','transfer','withdraw']) {
    const request=requests[kind],amount='7aokrw',tx={from:sender,to,chainId:'0x539',data:encodeEvmPrivacyRequestV2(kind,request),value:kind==='deposit'?'0x7':'0x0'};
    const rpc={...tx,hash:txHash};
    const event=kind==='deposit'?'PrivacyDeposit(address,address,string,bytes)':kind==='transfer'?'PrivacyTransfer(address,address,bytes)':'PrivacyWithdraw(address,address,address,string)';
    const data='0x'+(kind==='deposit'?encodeAbiParameters(['string','bytes'],[amount,request.output.commitment]):kind==='transfer'?encodeAbiParameters(['bytes'],[request.root]):encodeAbiParameters(['string'],[request.amount]));
    const receipt={status:'0x1',from:sender,to,transactionHash:txHash,blockHash:'0x'+'cd'.repeat(32),blockNumber:'0x3',transactionIndex:'0x0'};
    receipt.logs=[{...receipt,address:to,removed:false,topics:['0x'+Buffer.from(keccak_256(new TextEncoder().encode(event))).toString('hex'),topic(sender),topic(sender),...(kind==='withdraw'?[topic(request.recipient)]:[])],data}];
    const input={kind,request,creator,accountPrefix:'maroo',amount,transaction:tx,rpcTransaction:rpc,receipt,txHash};
    assert.equal(verifyEvmEffectV2(input),true);
    for(const change of [{status:'0x0'},{logs:[]},{logs:[{...receipt.logs[0],data:data+'00'}]},{logs:[{...receipt.logs[0],topics:[...receipt.logs[0].topics.slice(0,2),topic(to),...receipt.logs[0].topics.slice(3)]}]}])assert.throws(()=>verifyEvmEffectV2({...input,receipt:{...receipt,...change}}));
    assert.throws(()=>verifyEvmEffectV2({...input,rpcTransaction:{...rpc,input:tx.data+'00'}}));
  }
});
