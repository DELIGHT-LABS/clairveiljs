import test from 'node:test';
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { toBech32,toHex,fromHex } from '@cosmjs/encoding';
import { TxBody } from 'cosmjs-types/cosmos/tx/v1beta1/tx';
import { buildCosmosTransactionV2,buildEvmTransactionV2 } from 'clairveiljs/transactions-v2';
import { createArtifactVerifier } from 'clairveiljs/dapp';
import { validateCosmosArtifact } from '../src/chain-wallet/verification.js';
import { vectors,snapshot,data } from './helpers/audit-prover.js';
const publicKey = secp256k1.getPublicKey(new Uint8Array(32).fill(7)); // Disposable synthetic signer.
const digest='1'.repeat(64), contract='0x'+'02'.repeat(20);
for (const kind of ['deposit','transfer','withdraw']) test(`V2 ${kind}: Cosmos signer and EVM value/calldata bind the selected profile`,async()=>{
  const state=await snapshot(),number=kind==='deposit'?1:kind==='withdraw'?2:3,row=vectors.cases.find(c=>c.kind===number);
  const message={...data(row),proof:new Uint8Array(164),audit:{keyId:fromHex(state.keyId),epoch:BigInt(state.epoch),envelope:fromHex(row.envelope)}};
  // Structural signing tests only. These zero proof bytes are never submitted.
  const cosmos={namespace:'cosmos',chainId:state.chainId,address:toBech32('clair',ripemd160(sha256(publicKey))),pubKeyHex:toHex(publicKey)};
  const common={kind,snapshot:state,message:{...message,creator:cosmos.address}};
  const built=buildCosmosTransactionV2({...common,actor:cosmos,accountNumber:'9007199254740993',sequence:'9007199254740994',gasLimit:8000000});
  const artifact={transport:'cosmos',chainId:`cosmos:${state.chainId}`,signDoc:{bodyBytesBase64:built.signDoc.bodyBytes,authInfoBytesBase64:built.signDoc.authInfoBytes,chainId:state.chainId,accountNumber:built.signDoc.accountNumber}};
  assert.equal(validateCosmosArtifact(artifact,cosmos,kind==='transfer'?'final_transfer':kind).accountNumber,9007199254740993n);
  assert.equal(TxBody.decode(Buffer.from(built.signDoc.bodyBytes,'base64')).messages[0].typeUrl,`/clairveil.privacy.v2.Msg${kind[0].toUpperCase()+kind.slice(1)}`);
  assert.throws(()=>buildCosmosTransactionV2({...common,actor:{...cosmos,address:row.creator},accountNumber:'1',sequence:'1',gasLimit:1}),/actor|signer/);
  const summary={assetDenom:'uclair',amountBaseUnits:kind==='transfer'?'3':message.amount.replace('uclair',''),expiresAtUnix:String(message.expiresAtUnix),...(kind==='withdraw'?{recipientAddress:message.recipient}:{})};
  const operation={kind:kind==='transfer'?'final_transfer':kind,summary};
  const verify=createArtifactVerifier({protocol:'audit-field-v2',profileDigest:digest,chainId:artifact.chainId,assetDenom:'uclair'});
  assert.equal(verify({operation,artifact,actor:cosmos,networkProfileDigest:digest}),true);
  assert.equal(createArtifactVerifier({profileDigest:digest,chainId:artifact.chainId,assetDenom:'uclair'})({operation,artifact,actor:cosmos,networkProfileDigest:digest}),false);
  const actor={namespace:'eip155',chainId:'0x539',address:'0x'+'01'.repeat(20)};
  const evmInput={...common,message:{...message,creator:toBech32('clair',fromHex(actor.address.slice(2)))},actor,nativeDenom:'uclair',contractAddress:contract,
    transactionOptions:{from:actor.address,to:contract,chainId:actor.chainId,gas:'0x7a1200',nonce:'0x0',maxFeePerGas:'0x1',maxPriorityFeePerGas:'0x0'}};
  const evm=buildEvmTransactionV2(evmInput),evmArtifact={transport:'evm',chainId:'eip155:1337',transaction:evm.transaction};
  if(kind==='withdraw') operation.summary.recipientAddress='0x'+toHex((await import('@cosmjs/encoding')).fromBech32(message.recipient,255).data);
  const evmVerify=createArtifactVerifier({protocol:'audit-field-v2',profileDigest:digest,chainId:'eip155:1337',assetDenom:'uclair',contractAddress:contract});
  assert.equal(evmVerify({operation,artifact:evmArtifact,actor,networkProfileDigest:digest}),true);
  assert.equal(evmVerify({operation,artifact:{...evmArtifact,transaction:{...evm.transaction,value:evm.transaction.value==='0x0'?'0x1':'0x0'}},actor,networkProfileDigest:digest}),false);
  assert.throws(()=>buildEvmTransactionV2({...evmInput,transactionOptions:{...evmInput.transactionOptions,to:actor.address}}),/options/);
  assert.throws(()=>evmVerify({operation,artifact:{...evmArtifact,transaction:{...evm.transaction,data:evm.transaction.data+'00'}},actor,networkProfileDigest:digest}));
});
