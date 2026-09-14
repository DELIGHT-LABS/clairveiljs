import assert from 'node:assert/strict';
import test from 'node:test';
import {createPrivacyIdentity,createWalletKernel} from 'clairveiljs/wallet-kernel';
import {createClairveilClient,cosmosAddressFromPubKey} from 'clairveiljs/cosmos';
import {createClairveilEvmClient} from 'clairveiljs/evm';
import {secp256k1} from '@noble/curves/secp256k1.js';
const proofHex=`40${'00'.repeat(31)}40${'00'.repeat(63)}40${'00'.repeat(35)}40${'00'.repeat(31)}`;
function fixture(){
 const identity=createPrivacyIdentity({rootSeed:new Uint8Array(32).fill(7),shieldedPrefix:'clairs'});
 const pubKeyHex=Buffer.from(secp256k1.getPublicKey(new Uint8Array(32).fill(1))).toString('hex');
 const actor={namespace:'cosmos',chainId:'synthetic-1',address:cosmosAddressFromPubKey(pubKeyHex,'clair'),pubKeyHex};
 const client=createClairveilClient({rpc:'https://synthetic.invalid',rest:'https://synthetic.invalid',chainId:actor.chainId,accountPrefix:'clair',shieldedPrefix:'clairs',defaultDenom:'uclair'});
 client.deriveWalletPrivacyMaterial=async()=>{throw new Error('LEGACY_ROOT_SETUP_FORBIDDEN');};
 client.assertProtocolPreflight=async()=>({});
 client.buildDirectSignDoc=async args=>({captured:args});
 const events=[];
 const hooks={checkpoint:async()=>events.push('checkpoint'),assertAuthority:async()=>events.push('authority')};
 const kernel=createWalletKernel({identity,client,...hooks});
 return{identity,actor,client,kernel,events,hooks};
}
test('independent RootSeed builds an own Cosmos deposit through existing note/effect validators',async()=>{
 const h=fixture();const result=await h.kernel.prepareDeposit({operationId:'synthetic-deposit',actor:h.actor,amount:'7uclair',proofHex});
 assert.equal(result.message.creator,h.actor.address);
 assert.equal(result.signDoc.captured.signer,h.actor.address);
 assert.deepEqual(result.privacyAccount,h.identity.publicIdentity);
 assert.equal(result.material.note.receiverSpendPubKeyX,h.identity.spend.pubKey.x);
 assert.equal('signatureBase64' in result.privacyAccount,false);
 const changed={...h.actor,pubKeyHex:'00'.repeat(33)};
 await assert.rejects(h.kernel.prepareDeposit({operationId:'bad-key',actor:changed,amount:'7uclair',proofHex}));
});
test('scan has no ordinary-wallet dependency and persists a privacy-identity owner key',async()=>{
 const h=fixture();let root,owner;
 h.client.scanNotes=async input=>{root=input.rootSeed;return{foundNotes:[],scanCursor:{has_more:false}};};
 const noteStore={load:async()=>({notes:[]}),mergeScanResult:async(_result,input)=>{owner=input.owner;}};
 const result=await h.kernel.scan({operationId:'scan',noteStore,includeFoundNotes:true});
 assert.deepEqual(root,h.identity.rootSeed);assert.notEqual(root,h.identity.rootSeed);
 assert.equal(owner,h.identity.publicIdentity.shieldedAddress);assert.deepEqual(result.privacyAccount,h.identity.publicIdentity);
});
test('transfer and withdraw retain existing planner behavior with separate identity/actor inputs',async()=>{
 const h=fixture();const observed=[];
 h.client.scanNotes=async input=>{observed.push(input.rootSeed);return{foundNotes:[],scanCursor:{has_more:false}};};
 h.client.assertTransferProtocolConfig=async()=>({});
 for(const method of ['prepareTransfer','prepareWithdraw']){
  const result=await h.client[method]({privacyIdentity:h.identity,chainActor:h.actor,amount:'7uclair',recipient:method==='prepareTransfer'?h.identity.publicIdentity.shieldedAddress:h.actor.address});
  assert.notEqual(result.status,'ready');assert.deepEqual(result.privacyAccount,h.identity.publicIdentity);
 }
 assert.equal(observed.length,2);for(const seed of observed)assert.deepEqual(seed,h.identity.rootSeed);
 await assert.rejects(h.client.prepareDeposit({privacyIdentity:h.identity,chainActor:h.actor,material:{},amount:'7uclair',proofHex}),/cannot mix/);
});
test('kernel checkpoints a signed private request before prover invocation and fails closed on checkpoint loss',async()=>{
 const h=fixture();const calls=[];
 h.client.prepareTransfer=async input=>{assert.ok(input.privacyIdentity);assert.equal(input.material,undefined);return input.proverAdapter.proveTransfer({syntheticWitness:'private-test-only'});};
 const kernel=createWalletKernel({identity:h.identity,client:h.client,reservationManager:{},assertAuthority:async()=>{},checkpoint:async()=>calls.push('checkpoint')});
 await kernel.prepareTransfer({operationId:'transfer',actor:h.actor,amount:'1uclair',recipient:h.identity.publicIdentity.shieldedAddress,prover:{async proveTransfer(){calls.push('prover');return{};}}});
 assert.deepEqual(calls,['checkpoint','prover']);
 const failed=createWalletKernel({identity:h.identity,client:h.client,reservationManager:{},assertAuthority:async()=>{},checkpoint:async()=>{throw new Error('storage failure');}});
 await assert.rejects(failed.prepareTransfer({operationId:'failed',actor:h.actor,amount:'1uclair',recipient:h.identity.publicIdentity.shieldedAddress,prover:{async proveTransfer(){calls.push('unexpected');}}}),/storage failure/);
 assert.equal(calls.includes('unexpected'),false);
});
test('deposit proof uses the existing canonical Cosmos wire after checkpoint and validates commitment correspondence',async()=>{
 const h=fixture();const result=await h.kernel.proveDeposit({operationId:'prove-deposit',actor:h.actor,amount:'7uclair',prover:async request=>{
 assert.deepEqual(Object.keys(request),['version','payload']);assert.equal(h.events.at(-2),'checkpoint');
 return{version:'v1',proof:{version:'v1',note_commitment_hex:request.payload.note_commitment_hex,proof_hex:proofHex}};
 }});
 assert.equal(result.proofHex,proofHex);
 await h.kernel.prepareDeposit({operationId:'deposit',actor:h.actor,amount:'7uclair',...result});
});
test('same identity builds an EVM payable deposit without creating legacy signature material',async()=>{
 const h=fixture();const evmClient=createClairveilEvmClient({contractAddress:'0x'+'09'.repeat(20),chainId:'synthetic-1',nativeDenom:'uclair'});
 const actor={namespace:'eip155',chainId:'0x539',address:'0x'+'01'.repeat(20)};
 const kernel=createWalletKernel({identity:h.identity,client:h.client,evmClient,evmChainId:'0x539',...h.hooks});
 const result=await kernel.prepareDeposit({operationId:'evm-deposit',actor,amount:'7uclair',proofHex});
 assert.equal(result.execution.transaction.from,actor.address);assert.equal(result.execution.transaction.value,'0x7');assert.ok(result.execution.txBytesHash);
 assert.deepEqual(result.privacyAccount,h.identity.publicIdentity);
 kernel.dispose();await assert.rejects(kernel.scan({operationId:'disposed'}),/disposed/);
});

import {createNote} from 'clairveiljs/note';
import {computeNoteCommitmentV1,computeNoteTreeNodeV1} from 'clairveiljs/protocol-v1';
import {createNoteReservationManager,MemoryReservationStore,reservationStatuses} from 'clairveiljs/reservation';
const fieldHexV1=value=>BigInt(value).toString(16).padStart(64,'0');
function strictMerklePathProvider(notes) {
  const commitments = notes.map(note => computeNoteCommitmentV1(note));
  const capacity = 1 << Math.ceil(Math.log2(Math.max(commitments.length, 2)));
  const leaves = [...commitments];
  while (leaves.length < capacity) leaves.push(BigInt(leaves.length + 1));
  const paths = commitments.map(() => []);
  const helpers = commitments.map(() => []);
  let nodes = leaves;

  for (let level = 0; nodes.length > 1; level += 1) {
    for (let index = 0; index < commitments.length; index += 1) {
      const nodeIndex = index >> level;
      paths[index].push(fieldHexV1(nodes[nodeIndex ^ 1]));
      helpers[index].push(nodeIndex & 1);
    }
    const next = [];
    for (let index = 0; index < nodes.length; index += 2) {
      next.push(computeNoteTreeNodeV1(level, nodes[index], nodes[index + 1]));
    }
    nodes = next;
  }

  let root = nodes[0];
  for (let level = Math.log2(capacity); level < 32; level += 1) {
    const sibling = BigInt(level + 1);
    for (let index = 0; index < commitments.length; index += 1) {
      paths[index].push(fieldHexV1(sibling));
      helpers[index].push(0);
    }
    root = computeNoteTreeNodeV1(level, root, sibling);
  }

  const byCommitment = new Map(commitments.map((commitment, index) => [fieldHexV1(commitment), {
    root: fieldHexV1(root),
    path: paths[index],
    path_helper: helpers[index]
  }]));
  return {
    async lookupMerklePath(commitmentHex) {
      const result = byCommitment.get(String(commitmentHex).toLowerCase());
      if (!result) throw new Error("unexpected commitment requested from strict merkle path provider");
      return result;
    }
  };
}

for(const transport of ['cosmos','evm'])for(const kind of ['Transfer','Withdraw'])test(`independent ${transport} ${kind} runs existing private signing, proof validation, planner and reservation workflow`,async()=>{
 const h=fixture();
 const found=[0n,7n].map((amount,index)=>({note:createNote({spendPubKey:h.identity.spend.pubKey,viewPubKey:h.identity.view.pubKey,amount,assetDenom:'uclair',randomness:BigInt(index+101)}),isSpent:false,nullifierStatus:'unspent',height:index+1}));
 const paths=strictMerklePathProvider(found.map(x=>x.note));
 h.client.scanNotes=async()=>({foundNotes:found,scanCursor:{has_more:false}});
 h.client.assertTransferProtocolConfig=async()=>({audit_config:{audit_master_pubkey_hex:h.identity.publicIdentity.disclosurePubKeyHex},disclosure_config:{supported_user_policies:['all-private'],supported_user_modes:['none']}});
 h.client.createTransferMerklePathSnapshotProvider=async()=>paths;
 h.client.lookupMerklePath=paths.lookupMerklePath;
 h.client.checkNullifiers=async nullifiers=>new Map(nullifiers.map(n=>[n,false]));
 h.client.buildDirectSignDoc=async input=>({bodyBytes:Buffer.from(h.client.registry.encodeTxBody({messages:input.messages,memo:input.memo})).toString('base64'),authInfoBytes:'',chainId:h.actor.chainId,accountNumber:'0'});
 const store=new MemoryReservationStore(),reservationManager=createNoteReservationManager({store,ownerKeyId:h.identity.publicIdentity.shieldedAddress,indexKey:'synthetic-index-key'});
 const actor=transport==='cosmos'?h.actor:{namespace:'eip155',chainId:'0x539',address:'0x'+'01'.repeat(20)};
 const evmClient=transport==='evm'?createClairveilEvmClient({contractAddress:'0x'+'09'.repeat(20),chainId:h.actor.chainId,nativeDenom:'uclair'}):undefined;
 const order=[];let request;
 const kernel=createWalletKernel({identity:h.identity,client:h.client,evmClient,evmChainId:'0x539',reservationManager,assertAuthority:async()=>{},checkpoint:async record=>{order.push('checkpoint');request=record.payload;}});
 const prover={async ['prove'+kind](input){order.push('prover');assert.deepEqual(input,request);return{version:'v2',payload_hash:input.payload.payload_hash,proof_hex:proofHex};}};
 const result=await kernel['prepare'+kind]({operationId:`synthetic-${kind}`,actor,amount:'7uclair',recipient:kind==='Transfer'?h.identity.publicIdentity.shieldedAddress:actor.address,chainNowUnix:1700000000,expiresAtUnix:1700001800,prover});
 assert.equal(result.status,'ready');assert.deepEqual(order,['checkpoint','prover']);
 assert.deepEqual(result.privacyAccount,h.identity.publicIdentity);assert.ok(result.proof);assert.ok(transport==='cosmos'?result.signDoc:result.execution.transaction);
 assert.ok((await store.load()).reservations.every(r=>r.status===reservationStatuses.ProofReady));
});
