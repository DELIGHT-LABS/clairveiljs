import { fromBase64, toBase64, fromHex, toHex, toBech32 } from '@cosmjs/encoding';
import { SignDoc, TxRaw, TxBody, AuthInfo } from 'cosmjs-types/cosmos/tx/v1beta1/tx';
import { PubKey } from 'cosmjs-types/cosmos/crypto/secp256k1/keys';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { MsgDeposit, MsgTransfer, MsgWithdraw } from '../generated/clairveil/privacy/v1/tx.js';
import { MsgDeposit as MsgDepositV2, MsgTransfer as MsgTransferV2, MsgWithdraw as MsgWithdrawV2 } from '../generated/clairveil/privacy/v2/tx.js';
const equalBytes = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
function canonicalBase64(value) {
  if (typeof value !== 'string') throw new Error('base64 bytes required');
  const bytes = fromBase64(value);
  if (toBase64(bytes) !== value) throw new Error('noncanonical base64');
  return bytes;
}
function decodeCanonical(codec, bytes) {
  const result = codec.decode(bytes);
  if (!equalBytes(codec.encode(result).finish(), bytes)) throw new Error('noncanonical protobuf or unknown fields');
  return result;
}
export function signDocFromArtifact(artifact) {
  const value = artifact.signDoc;
  return { bodyBytes: canonicalBase64(value.bodyBytesBase64), authInfoBytes: canonicalBase64(value.authInfoBytesBase64), chainId: value.chainId, accountNumber: BigInt(value.accountNumber) };
}
export function validateCosmosArtifact(artifact, actor, kind) {
  const doc = signDocFromArtifact(artifact);
  if (doc.chainId !== actor.chainId || artifact.chainId !== `cosmos:${actor.chainId}`) throw new Error('Cosmos artifact network mismatch');
  const body = decodeCanonical(TxBody, doc.bodyBytes);
  const auth = decodeCanonical(AuthInfo, doc.authInfoBytes);
  if (body.messages.length !== 1 || body.extensionOptions.length || body.nonCriticalExtensionOptions.length || auth.signerInfos.length !== 1) throw new Error('unsupported Cosmos calls/signers');
  const audit = body.messages[0].typeUrl.startsWith('/clairveil.privacy.v2.');
  const types = audit ? [MsgDepositV2,MsgTransferV2,MsgWithdrawV2] : [MsgDeposit,MsgTransfer,MsgWithdraw];
  const expected = ['deposit', 'zero_helper'].includes(kind) ? types[0] : ['self_merge','final_transfer'].includes(kind) ? types[1] : kind === 'withdraw' ? types[2] : null;
  if (!expected || body.messages[0].typeUrl !== expected.typeUrl) throw new Error('Cosmos action mismatch');
  const message = decodeCanonical(expected, body.messages[0].value);
  if (message.creator !== actor.address) throw new Error('Cosmos creator mismatch');
  const signer = auth.signerInfos[0];
  if (signer.modeInfo?.single?.mode !== 1 || signer.modeInfo.multi || signer.publicKey?.typeUrl !== '/cosmos.crypto.secp256k1.PubKey') throw new Error('unsupported Cosmos signing mode');
  const key = decodeCanonical(PubKey, signer.publicKey.value).key;
  if (toHex(key) !== actor.pubKeyHex || toBech32(actor.address.slice(0, actor.address.indexOf('1')), ripemd160(sha256(key))) !== actor.address) throw new Error('Cosmos signer key mismatch');
  if (!auth.fee || auth.fee.gasLimit === 0n || auth.fee.granter || (auth.fee.payer && auth.fee.payer !== actor.address)) throw new Error('unsupported Cosmos fee payer or gas');
  return doc;
}
export function verifyCosmosSignResponse(document, response, actor) {
  const signed = response?.signed;
  if (!signed || !(signed.bodyBytes instanceof Uint8Array) || !(signed.authInfoBytes instanceof Uint8Array) || signed.chainId !== document.chainId || signed.accountNumber !== document.accountNumber || !equalBytes(signed.bodyBytes, document.bodyBytes) || !equalBytes(signed.authInfoBytes, document.authInfoBytes)) throw new Error('wallet changed the approved sign document');
  const pub = response.signature?.pub_key;
  if (pub?.type !== 'tendermint/PubKeySecp256k1') throw new Error('unsupported Cosmos public key type');
  const key = canonicalBase64(pub.value), signature = canonicalBase64(response.signature.signature);
  if (key.length !== 33 || signature.length !== 64 || toHex(key) !== actor.pubKeyHex || !secp256k1.verify(signature, sha256(SignDoc.encode(document).finish()), key, { prehash: false, lowS: true, format: 'compact' })) throw new Error('invalid Cosmos signature');
  return TxRaw.encode({ bodyBytes: document.bodyBytes, authInfoBytes: document.authInfoBytes, signatures: [signature] }).finish();
}
