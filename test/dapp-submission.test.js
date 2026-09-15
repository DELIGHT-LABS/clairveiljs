import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {createCustodyProvider} from 'clairveiljs/custody-provider';
import {createKeplrChainWalletAdapter,createOfflineSignerChainWalletAdapter,createEip1193ChainWalletAdapter} from 'clairveiljs/chain-wallet';
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
function clientFor(fixture, overrides = {}) {
  return createClairveilDappClient({
    custodyProvider: fixture.provider,
    chainWallet: fixture.chainWallet,
    validateArtifact: createArtifactVerifier(fixture.profile),
    ...overrides
  });
}

function signCosmosDocument(document, privateKey) {
  const encoded = { ...document, accountNumber: BigInt(document.accountNumber.toString()) };
  const publicKey = secp256k1.getPublicKey(privateKey);
  const signature = secp256k1.sign(sha256(SignDoc.encode(encoded).finish()), privateKey, { prehash: false, format: 'compact' });
  return {
    signed: document,
    signature: {
      pub_key: { type: 'tendermint/PubKeySecp256k1', value: Buffer.from(publicKey).toString('base64') },
      signature: Buffer.from(signature).toString('base64')
    }
  };
}

async function fixture(){
 const actor={namespace:'eip155',chainId:'0x539',address:address(1)};
 const profile={profileDigest:'11'.repeat(32),chainId:'eip155:1337',assetDenom:'uclair',contractAddress:address(9)};
 const operation={operationId:handle(1),kind:'deposit',stepKind:'deposit',state:'awaiting_chain_signature',statusRevision:'1',durable:true,runtimeState:'unlocked',jobState:'queued',nextAction:'sign_chain',summary:{assetDenom:'uclair',amountBaseUnits:'7'},publicArtifact:{chainId:profile.chainId,chainActorHandle:handle(2),artifactBindingHash:'00'.repeat(32),bindingVersion:'cv-artifact-jcs-sha256-v1',transport:'evm',transaction:{from:actor.address,to:profile.contractAddress,chainId:actor.chainId,data:encodeEvmPrivacyDeposit({noteCommitment:bytes(32),encryptedNote:bytes(430),proof:bytes(96)}),value:'0x7',gas:'0x10000',nonce:'0x0',maxFeePerGas:'0x2',maxPriorityFeePerGas:'0x1'}}};
 const input={operation,actor,context:{sessionHandle:handle(3),accountHandle:handle(4),networkHandle:handle(5)},idempotencyKey:handle(6),networkProfileDigest:profile.profileDigest,chainActorAccountId:`eip155:1337:${actor.address}`};
 operation.publicArtifact.artifactBindingHash=await computeArtifactBinding({...input,operationId:operation.operationId,artifact:operation.publicArtifact});
 validateWalletValue('ClairveilOperation',operation,{response:true});
 const calls=[],state={hash:'0x'+'ab'.repeat(32),reject:false,replay:false,beforeBegin:null,beforeSend:null,beginRevision:'2'};
 const provider=createCustodyProvider({transport:{async request({method,params}){
  calls.push(method);
  if(method==='clairveil_getCapabilities')return capabilities;
  if(method==='clairveil_beginSubmission'){await state.beforeBegin?.();return{operationId:operation.operationId,attemptId:handle(7),statusRevision:state.beginRevision,state:'submission_unknown',invokeWallet:!state.replay};}
  if(method==='clairveil_recordSubmission')return{operationId:operation.operationId,attemptId:handle(7),statusRevision:'3',state:params.outcome==='reported_submitted'?'submitted':'submission_unknown'};
  throw new Error('unexpected synthetic method');
 }}});
 await provider.request({method:'clairveil_getCapabilities',params:{protocolVersion:'1'}});
 const chainWallet={async getActor(){return{...actor};},async sendTransaction(){calls.push('wallet.send');await state.beforeSend?.();if(state.reject)throw new Error('synthetic rejection');return state.hash;}};
 const result = { input, provider, chainWallet, calls, state, profile };
 result.client = clientFor(result);
 result.secondClient = () => clientFor(result);
 return result;
}

async function cosmosSubmissionFixture() {
 const {TxBody,AuthInfo,TxRaw}=await import('cosmjs-types/cosmos/tx/v1beta1/tx');
 const {PubKey}=await import('cosmjs-types/cosmos/crypto/secp256k1/keys');
 const {MsgDeposit}=await import('../src/generated/clairveil/privacy/v1/tx.js');
 const {cosmosAddressFromPubKey}=await import('clairveiljs/cosmos');
  const h=await fixture(),key=bytes(32,1),pub=secp256k1.getPublicKey(key),pubKeyHex=Buffer.from(pub).toString('hex');
  const actor={namespace:'cosmos',chainId:'synthetic-1',address:cosmosAddressFromPubKey(pubKeyHex,'clair'),pubKeyHex};
  const body=TxBody.encode(TxBody.fromPartial({messages:[{typeUrl:MsgDeposit.typeUrl,value:MsgDeposit.encode(MsgDeposit.fromPartial({creator:actor.address,amount:'7uclair',noteCommitment:bytes(32),encryptedNote:bytes(430),proof:bytes(164)})).finish()}]})).finish();
  const auth=AuthInfo.encode(AuthInfo.fromPartial({signerInfos:[{publicKey:{typeUrl:'/cosmos.crypto.secp256k1.PubKey',value:PubKey.encode({key:pub}).finish()},modeInfo:{single:{mode:1}},sequence:0n}],fee:{amount:[],gasLimit:100000n}})).finish();
  h.input.actor=actor;h.input.chainActorAccountId=`cosmos:${actor.chainId}:${actor.address}`;
  h.input.operation.publicArtifact={transport:'cosmos',chainId:`cosmos:${actor.chainId}`,chainActorHandle:handle(2),bindingVersion:'cv-artifact-jcs-sha256-v1',artifactBindingHash:'00'.repeat(32),signDoc:{bodyBytesBase64:Buffer.from(body).toString('base64'),authInfoBytesBase64:Buffer.from(auth).toString('base64'),chainId:actor.chainId,accountNumber:'0'}};
  h.input.operation.publicArtifact.artifactBindingHash=await computeArtifactBinding({...h.input,operationId:h.input.operation.operationId,artifact:h.input.operation.publicArtifact});
  h.profile = { profileDigest: h.input.networkProfileDigest, chainId: `cosmos:${actor.chainId}`, assetDenom: 'uclair' };
  return { h, key, pub, actor, body, TxRaw };
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
 const actor={pubKeyHex:Buffer.from(publicKey).toString('hex')};
 const response = signCosmosDocument(document, privateKey);
 assert.ok(verifyCosmosSignResponse(document,response,actor).length);
 assert.throws(()=>verifyCosmosSignResponse(document,{...response,signed:{...document,chainId:'changed'}},actor));
 assert.throws(()=>verifyCosmosSignResponse(document,{...response,signature:{...response.signature,signature:Buffer.alloc(64).toString('base64')}},actor));
});

test('Cosmos submission broadcasts only the exact signed artifact and quarantines changed replies',async()=>{
 for(const mode of ['valid','changed_document','stale_epoch','stale_after_final_lookup']){
  const changed=mode==='changed_document';
  const { h, key, actor, body, TxRaw } = await cosmosSubmissionFixture();
  let actorReads = 0;
  const chainWallet={getActor:async()=>{
    // Invalidate after the nested assertWalletMatches check resolves, before
    // its caller resumes to broadcast. The final dispatch fence must recheck.
    if (++actorReads === 3 && mode === 'stale_after_final_lookup') queueMicrotask(() => queueMicrotask(() => h.provider.invalidate()));
    return actor;
  }, signDirect: async doc => {
    h.calls.push('wallet.sign');
    if (mode === 'stale_epoch') h.provider.invalidate();
    const response = signCosmosDocument(doc, key);
    if (changed) response.signed = { ...doc, chainId: 'changed' };
    return response;
  } };
  const client = clientFor(h, { chainWallet, broadcastCosmos: async raw => {
    h.calls.push('broadcast');
    assert.deepEqual(TxRaw.decode(raw).bodyBytes, body);
    return 'ab'.repeat(32);
  } });
  if(mode!=='valid')await assert.rejects(client.submit(h.input));else await client.submit(h.input);
  assert.equal(h.calls.filter(c=>c==='wallet.sign').length,1);
  assert.equal(h.calls.filter(c=>c==='broadcast').length,mode==='valid'?1:0);
  assert.equal(h.calls.at(-1),mode.startsWith('stale_')?'wallet.sign':'clairveil_recordSubmission');
 }
});


test('an already consumed attempt cannot invoke a wallet through a second client', async () => {
  const h = await fixture();
  await h.client.submit(h.input);
  // The reply passes revision checks and still claims invokeWallet, but repeats the attempt ID.
  h.state.beginRevision = '4';
  const replay = await h.secondClient().submit(h.input);
  assert.equal(replay.invoked, false);
  assert.equal(h.calls.filter(call => call === 'wallet.send').length, 1);
  assert.equal(h.calls.filter(call => call === 'clairveil_beginSubmission').length, 2);
  assert.equal(h.calls.filter(call => call === 'clairveil_recordSubmission').length, 1);
});

test('EIP-1193 adapter suppresses dispatch when custody is invalidated during any wallet lookup', async () => {
  // Three getActor calls, each awaiting chain ID, accounts and chain ID again.
  // 7–9 are inside the real adapter, after the coordinator's last epoch check.
  for (const invalidateAt of [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]) {
    const h = await fixture(), actor = h.input.actor;
    let reads = 0, sends = 0;
    const wallet = createEip1193ChainWalletAdapter({ chainId: actor.chainId, provider: {
      async request({ method }) {
        if (method === 'eth_sendTransaction') { sends++; return h.state.hash; }
        if (++reads === invalidateAt) h.provider.invalidate();
        if (method === 'eth_chainId') return actor.chainId;
        if (method === 'eth_accounts') return [actor.address];
        throw new Error('unexpected wallet method');
      }
    } });
    const client = clientFor(h, { chainWallet: wallet });
    if (invalidateAt) await assert.rejects(client.submit(h.input), /Submission unresolved/);
    else await client.submit(h.input);
    assert.equal(sends, invalidateAt ? 0 : 1, `wallet await ${invalidateAt}`);
    if (invalidateAt) assert.equal(h.calls.includes('clairveil_recordSubmission'), false);
  }
});

for (const kind of ['keplr', 'offline']) {
  test(`${kind} adapter suppresses signing when custody is invalidated during account lookup`, async () => {
    for (const invalidateAt of [0, 1, 2, 3]) {
      const { h, key, pub, actor } = await cosmosSubmissionFixture();
      let reads = 0, signatures = 0, broadcasts = 0;
      const read = async () => {
        if (++reads === invalidateAt) h.provider.invalidate();
        return { address: actor.address, pubkey: pub };
      };
      const sign = async document => {
        signatures++;
        return signCosmosDocument(document, key);
      };
      const wallet = kind === 'keplr'
        ? createKeplrChainWalletAdapter({ chainId: actor.chainId, keplr: {
          enable: async () => {},
          getKey: async () => { const account = await read(); return { bech32Address: account.address, pubKey: account.pubkey }; },
          signDirect: (_chain, _signer, document) => sign(document)
        } })
        : createOfflineSignerChainWalletAdapter({ chainId: actor.chainId, signer: {
          getAccounts: async () => [await read()], signDirect: (_signer, document) => sign(document)
        } });
      const client = clientFor(h, {
        chainWallet: wallet,
        broadcastCosmos: async () => { broadcasts++; return 'ab'.repeat(32); }
      });
      if (invalidateAt) await assert.rejects(client.submit(h.input), /Submission unresolved/);
      else await client.submit(h.input);
      assert.equal(signatures, invalidateAt ? 0 : 1);
      assert.equal(broadcasts, invalidateAt ? 0 : 1);
    }
  });
}

test('submission removes its invalidation listener after success, rejection and begin replay', async () => {
  for (const mode of ['success', 'rejected', 'replay']) {
    const h = await fixture();
    h.state.reject = mode === 'rejected'; h.state.replay = mode === 'replay';
    let listeners = 0;
    const provider = {
      ...h.provider, get generation() { return h.provider.generation; },
      onInvalidation(listener) {
        listeners++;
        const unsubscribe = h.provider.onInvalidation(listener);
        return () => { listeners--; unsubscribe(); };
      }
    };
    const client = clientFor(h, { custodyProvider: provider });
    if (mode === 'rejected') await assert.rejects(client.submit(h.input));
    else await client.submit(h.input);
    assert.equal(listeners, 0);
  }
});
