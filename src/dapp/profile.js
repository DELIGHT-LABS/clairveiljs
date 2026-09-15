import { snapshotJson, validateWalletValue } from '../wallet-api/index.js';
import { decodePrivacyCall } from './evm-abi.js';
import { validateCosmosArtifact, signDocFromArtifact } from '../chain-wallet/verification.js';
import { TxBody } from 'cosmjs-types/cosmos/tx/v1beta1/tx';
import { MsgDeposit, MsgTransfer, MsgWithdraw } from '../generated/clairveil/privacy/v1/tx.js';

/** Pinned default protocol profile; exact bytes are additionally bound by the custody artifact digest. */
export function createArtifactVerifier(input) {
  const profile = snapshotJson(input);
  validateWalletValue('Hex32',profile.profileDigest);
  if (typeof profile.chainId!=='string' || typeof profile.assetDenom!=='string')throw new Error('chain and asset profile required');
  return ({operation,artifact,actor,networkProfileDigest})=>{
    if(networkProfileDigest!==profile.profileDigest || artifact.chainId!==profile.chainId)return false;
    const action=['deposit','zero_helper'].includes(operation.kind)?'deposit':['self_merge','final_transfer'].includes(operation.kind)?'transfer':operation.kind==='withdraw'?'withdraw':null;
    if(!action)return false;
    const summary=operation.summary;
    if(!summary || summary.assetDenom!==profile.assetDenom)return false;
    if(artifact.transport==='evm') {
      const tx=artifact.transaction;
      if(tx.to!==profile.contractAddress)return false;
      const values=decodePrivacyCall(tx.data,action);
      if(action==='deposit')return summary.amountBaseUnits!==undefined && BigInt(tx.value)===BigInt(summary.amountBaseUnits);
      if(BigInt(tx.value)!==0n)return false;
      if(action==='withdraw')return values[3]===`${summary.amountBaseUnits}${profile.assetDenom}` && values[4]===summary.recipientAddress && values[5]===profile.protocolChainId && values[6]===BigInt(summary.expiresAtUnix);
      return summary.expiresAtUnix!==undefined && values[16]===BigInt(summary.expiresAtUnix);
    }
    validateCosmosArtifact(artifact,actor,operation.kind);
    const body=TxBody.decode(signDocFromArtifact(artifact).bodyBytes);
    if(action==='deposit')return MsgDeposit.decode(body.messages[0].value).amount===`${summary.amountBaseUnits}${profile.assetDenom}`;
    if(action==='withdraw') {
      const msg=MsgWithdraw.decode(body.messages[0].value);
      return msg.amount===`${summary.amountBaseUnits}${profile.assetDenom}` && msg.recipient===summary.recipientAddress && msg.chainId===actor.chainId && msg.expiresAtUnix===BigInt(summary.expiresAtUnix);
    }
    // Expiry is public even when amounts/recipients remain confidential.
    const msg=MsgTransfer.decode(body.messages[0].value);
    return summary.expiresAtUnix!==undefined && msg.expiresAtUnix===BigInt(summary.expiresAtUnix);
  };
}
