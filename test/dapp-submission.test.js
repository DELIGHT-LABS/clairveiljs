import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {createCustodyProvider} from 'clairveiljs/custody-provider';
import {createClairveilDappClient,createArtifactVerifier,computeArtifactBinding} from 'clairveiljs/dapp';
import {validateWalletValue} from 'clairveiljs/wallet-api';
import {encodeEvmPrivacyDeposit,encodeEvmPrivacyWithdraw,encodeEvmPrivacyTransfer} from 'clairveiljs/evm';
import {decodePrivacyCall} from '../src/dapp/evm-abi.js';
import {verifyCosmosSignResponse} from '../src/chain-wallet/verification.js';
import {secp256k1} from '@noble/curves/secp256k1.js';
import {sha256} from '@noble/hashes/sha2.js';
import {SignDoc} from 'cosmjs-types/cosmos/tx/v1beta1/tx';
const handle=n=>Buffer.alloc(32,n).toString('base64url');
const bytes=(n,value=1)=>new Uint8Array(n).fill(value);
const address=n=>'0x'+n.toString(16).padStart(2,'0').repeat(20);
const cases=JSON.parse(readFileSync(new URL('../src/wallet-api/schema/wallet-api-draft.examples.json',import.meta.url))).cases;
const capabilities=cases.find(c=>c.name==='getCapabilities.response').value.result;
async function fixture(){
 const actor={namespace:'eip155',chainId:'0x539',address:address(1)};
 const profile={profileDigest:'11'.repeat(32),chainId:'eip155:1337',assetDenom:'uclair',contractAddress:address(9)};
 const operation={operationId:handle(1),kind:'deposit',stepKind:'deposit',state:'awaiting_chain_signature',statusRevision:'1',durable:true,runtimeState:'unlocked',jobState:'queued',nextAction:'sign_chain',summary:{assetDenom:'uclair',amountBaseUnits:'7'},publicArtifact:{chainId:profile.chainId,chainActorHandle:handle(2),artifactBindingHash:'00'.repeat(32),bindingVersion:'cv-artifact-jcs-sha256-v1',transport:'evm',transaction:{from:actor.address,to:profile.contractAddress,chainId:actor.chainId,data:encodeEvmPrivacyDeposit({noteCommitment:bytes(32),encryptedNote:bytes(430),proof:bytes(96)}),value:'0x7',gas:'0x10000',nonce:'0x0',maxFeePerGas:'0x2',maxPriorityFeePerGas:'0x1'}}};
 const input={operation,actor,context:{sessionHandle:handle(3),accountHandle:handle(4),networkHandle:handle(5)},idempotencyKey:handle(6),networkProfileDigest:profile.profileDigest,chainActorAccountId:`eip155:1337:${actor.address}`};
 operation.publicArtifact.artifactBindingHash=await computeArtifactBinding({...input,operationId:operation.operationId,artifact:operation.publicArtifact});
 validateWalletValue('ClairveilOperation',operation,{response:true});
 const calls=[],state={hash:'0x'+'ab'.repeat(32),reject:false,replay:false,beforeBegin:null,beforeSend:null};
 const provider=createCustodyProvider({transport:{async request({method,params}){
  calls.push(method);
  if(method==='clairveil_getCapabilities')return capabilities;
  if(method==='clairveil_beginSubmission'){await state.beforeBegin?.();return{operationId:operation.operationId,attemptId:handle(7),statusRevision:'2',state:'submission_unknown',invokeWallet:!state.replay};}
  if(method==='clairveil_recordSubmission')return{operationId:operation.operationId,attemptId:handle(7),statusRevision:'3',state:params.outcome==='reported_submitted'?'submitted':'submission_unknown'};
  throw new Error('unexpected synthetic method');
 }}});
 await provider.request({method:'clairveil_getCapabilities',params:{protocolVersion:'1'}});
 const chainWallet={async getActor(){return{...actor};},async sendTransaction(){calls.push('wallet.send');await state.beforeSend?.();if(state.reject)throw new Error('synthetic rejection');return state.hash;}};
 const options={custodyProvider:provider,chainWallet,validateArtifact:createArtifactVerifier(profile)};
 return{input,provider,chainWallet,calls,state,client:createClairveilDappClient(options),secondClient:()=>createClairveilDappClient(options)};
}
test('valid EVM artifact consumes durable begin before exactly one ordinary-wallet call',async()=>{
 const h=await fixture();await h.client.submit(h.input);
 assert.deepEqual(h.calls,['clairveil_getCapabilities','clairveil_beginSubmission','wallet.send','clairveil_recordSubmission']);
 await assert.rejects(h.client.submit(h.input));assert.equal(h.calls.filter(c=>c==='wallet.send').length,1);
});
test('concurrent submissions through two clients on the same attachment cannot duplicate dispatch',async()=>{
 const h=await fixture();const result=await Promise.allSettled([h.client.submit(h.input),h.secondClient().submit(h.input)]);
 assert.equal(result.filter(x=>x.status==='fulfilled').length,1);assert.equal(h.calls.filter(x=>x==='wallet.send').length,1);
});
test('begin replay and attachment loss suppress wallet invocation',async()=>{
 const replay=await fixture();replay.state.replay=true;assert.equal((await replay.client.submit(replay.input)).invoked,false);
 assert.equal(replay.calls.includes('wallet.send'),false);
 const lost=await fixture();lost.state.beforeBegin=()=>lost.provider.invalidate();await assert.rejects(lost.client.submit(lost.input));assert.equal(lost.calls.includes('wallet.send'),false);
});
test('rejected or malformed wallet replies report unknown without retrying a wallet',async()=>{
 for(const reject of [true,false]){const h=await fixture();h.state.reject=reject;h.state.hash='bad';await assert.rejects(h.client.submit(h.input));assert.equal(h.calls.filter(x=>x==='wallet.send').length,1);assert.equal(h.calls.at(-1),'clairveil_recordSubmission');}
});
test('changed actor, artifact, calldata, network or effect fails before begin',async()=>{
 for(const mutate of [h=>h.input.operation.publicArtifact.transaction.value='0x8',h=>h.input.actor.address=address(2),h=>h.input.networkProfileDigest='22'.repeat(32)]){
  const h=await fixture();mutate(h);await assert.rejects(h.client.submit(h.input));assert.equal(h.calls.includes('clairveil_beginSubmission'),false);
 }
 const h=await fixture();h.input.operation.publicArtifact.transaction.data+='00';
 h.input.operation.publicArtifact.artifactBindingHash=await computeArtifactBinding({...h.input,operationId:h.input.operation.operationId,artifact:h.input.operation.publicArtifact});
 await assert.rejects(h.client.submit(h.input));assert.equal(h.calls.includes('clairveil_beginSubmission'),false);
});
test('public ABI decoder preserves existing SDK encodings and rejects offset/padding/trailing mutations',()=>{
 const deposit=encodeEvmPrivacyDeposit({noteCommitment:bytes(32),encryptedNote:bytes(430),proof:bytes(95)});
 assert.equal(decodePrivacyCall(deposit,'deposit')[0].length,64);
 const withdraw=encodeEvmPrivacyWithdraw({proof:bytes(96),root:bytes(32),nullifier:bytes(32),amount:'7uclair',recipient:address(3),chainId:'synthetic-chain',expiresAtUnix:1900000000n});
 assert.equal(decodePrivacyCall(withdraw,'withdraw')[3],'7uclair');
 const transfer=encodeEvmPrivacyTransfer({proof:bytes(96),root:bytes(32),nullifiers:[bytes(32)],newCommitments:[bytes(32),bytes(32)],cipherTexts:[bytes(48),bytes(48)],viewTags:[bytes(2),bytes(2)],userPrivacyPolicy:3,userDisclosureDigest:bytes(32),userDisclosureMode:2,userDisclosureTargetPubkey:bytes(33),userDisclosurePayload:bytes(64),auditDisclosureDigest:bytes(32),auditDisclosureTargetPubkey:bytes(33),auditDisclosurePayload:bytes(472),selfViewDisclosureDigest:bytes(32),selfViewDisclosurePayload:bytes(64),expiresAtUnix:1900000000n});
 assert.equal(decodePrivacyCall(transfer,'transfer')[16],1900000000n);
 for(const data of [deposit+'00',deposit.slice(0,-2)+'ff',deposit.slice(0,10)+'ff'.repeat(32)+deposit.slice(74)])assert.throws(()=>decodePrivacyCall(data,'deposit'));
});
test('Cosmos response verification binds exact bytes, key and a real synthetic signature',()=>{
 const privateKey=bytes(32,1),publicKey=secp256k1.getPublicKey(privateKey);
 const document={chainId:'synthetic',bodyBytes:bytes(2),authInfoBytes:bytes(2,2),accountNumber:1n};
 const signature=secp256k1.sign(sha256(SignDoc.encode(document).finish()),privateKey,{prehash:false,format:'compact'});
 const actor={pubKeyHex:Buffer.from(publicKey).toString('hex')};
 const response={signed:document,signature:{pub_key:{type:'tendermint/PubKeySecp256k1',value:Buffer.from(publicKey).toString('base64')},signature:Buffer.from(signature).toString('base64')}};
 assert.ok(verifyCosmosSignResponse(document,response,actor).length);
 assert.throws(()=>verifyCosmosSignResponse(document,{...response,signed:{...document,chainId:'changed'}},actor));
 assert.throws(()=>verifyCosmosSignResponse(document,{...response,signature:{...response.signature,signature:Buffer.alloc(64).toString('base64')}},actor));
});

test('Cosmos submission broadcasts only the exact signed artifact and quarantines changed replies',async()=>{
 const {TxBody,AuthInfo,TxRaw}=await import('cosmjs-types/cosmos/tx/v1beta1/tx');
 const {PubKey}=await import('cosmjs-types/cosmos/crypto/secp256k1/keys');
 const {MsgDeposit}=await import('../src/generated/clairveil/privacy/v1/tx.js');
 const {cosmosAddressFromPubKey}=await import('clairveiljs/cosmos');
 for(const changed of [false,true]){
  const h=await fixture(),key=bytes(32,1),pub=secp256k1.getPublicKey(key),pubKeyHex=Buffer.from(pub).toString('hex');
  const actor={namespace:'cosmos',chainId:'synthetic-1',address:cosmosAddressFromPubKey(pubKeyHex,'clair'),pubKeyHex};
  const body=TxBody.encode(TxBody.fromPartial({messages:[{typeUrl:MsgDeposit.typeUrl,value:MsgDeposit.encode(MsgDeposit.fromPartial({creator:actor.address,amount:'7uclair',noteCommitment:bytes(32),encryptedNote:bytes(430),proof:bytes(164)})).finish()}]})).finish();
  const auth=AuthInfo.encode(AuthInfo.fromPartial({signerInfos:[{publicKey:{typeUrl:'/cosmos.crypto.secp256k1.PubKey',value:PubKey.encode({key:pub}).finish()},modeInfo:{single:{mode:1}},sequence:0n}],fee:{amount:[],gasLimit:100000n}})).finish();
  h.input.actor=actor;h.input.chainActorAccountId=`cosmos:${actor.chainId}:${actor.address}`;
  h.input.operation.publicArtifact={transport:'cosmos',chainId:`cosmos:${actor.chainId}`,chainActorHandle:handle(2),bindingVersion:'cv-artifact-jcs-sha256-v1',artifactBindingHash:'00'.repeat(32),signDoc:{bodyBytesBase64:Buffer.from(body).toString('base64'),authInfoBytesBase64:Buffer.from(auth).toString('base64'),chainId:actor.chainId,accountNumber:'0'}};
  h.input.operation.publicArtifact.artifactBindingHash=await computeArtifactBinding({...h.input,operationId:h.input.operation.operationId,artifact:h.input.operation.publicArtifact});
  const chainWallet={getActor:async()=>actor,signDirect:async doc=>{h.calls.push('wallet.sign');return{signed:{...doc,...(changed?{chainId:'changed'}:{})},signature:{pub_key:{type:'tendermint/PubKeySecp256k1',value:Buffer.from(pub).toString('base64')},signature:Buffer.from(secp256k1.sign(sha256(SignDoc.encode(doc).finish()),key,{prehash:false,format:'compact'})).toString('base64')}};}};
  const client=createClairveilDappClient({custodyProvider:h.provider,chainWallet,validateArtifact:createArtifactVerifier({profileDigest:h.input.networkProfileDigest,chainId:`cosmos:${actor.chainId}`,assetDenom:'uclair'}),broadcastCosmos:async raw=>{h.calls.push('broadcast');assert.deepEqual(TxRaw.decode(raw).bodyBytes,body);return'ab'.repeat(32);}});
  if(changed)await assert.rejects(client.submit(h.input));else await client.submit(h.input);
  assert.equal(h.calls.filter(c=>c==='wallet.sign').length,1);
  assert.equal(h.calls.filter(c=>c==='broadcast').length,changed?0:1);
  assert.equal(h.calls.at(-1),'clairveil_recordSubmission');
 }
});
