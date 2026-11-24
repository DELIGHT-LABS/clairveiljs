import { fromBech32, toBech32 } from "@cosmjs/encoding";
import { deriveSpendKeys, deriveViewKeys, deriveDisclosureKeys, decodeShieldedAddress, packPoint, canonicalFieldBytes } from "../core/crypto.js";
import { base64FromBytes, bytesFromHex, hexFromBytes, utf8Bytes } from "../core/browser-crypto.js";
import { equalBytes, unsignedInteger } from "../core/encoding.js";
import { computeAssetId } from "./protocol-domain.js";
import { prepareDepositMaterialV2, prepareSpendInputsV2 } from "./preparation-v2.js";
import { prepareAuditAuthorizationV2 } from "./audit-authorization-v2.js";
import { assertAuditSnapshotCurrentV2 } from "./audit-config-v2.js";
import { validateFullAuditWitness } from "./audit-prover-wire.js";
import {
  MsgDeposit as MsgDepositV2,
  MsgWithdraw as MsgWithdrawV2,
  MsgTransfer as MsgTransferV2,
  OutputEffect as OutputEffectV2
} from "../generated/clairveil/privacy/v2/tx.js";

const kinds = {deposit:1, withdraw:2, transfer:3};
const codecs = {deposit:MsgDepositV2, withdraw:MsgWithdrawV2, transfer:MsgTransferV2};
function address(value, prefix) {
  if (typeof value !== "string") throw new Error("canonical account address required");
  const a=fromBech32(value, 512);
  if (a.prefix!==prefix || !a.data.length || a.data.length>255 || toBech32(prefix,a.data,512)!==value) throw new Error("account address/profile mismatch");
}
function nativeReply(raw, kind, codec) {
  if (!(raw instanceof Uint8Array) || raw.length<45 || raw.length>65536 || !equalBytes(raw.subarray(0,4),utf8Bytes("CVW2")) || raw[4]!==kind) throw new Error("invalid native witness frame");
  const d=new DataView(raw.buffer,raw.byteOffset,raw.byteLength), size=d.getUint32(5), offset=9+size;
  if (size>16384 || offset+36>raw.length || offset+36+d.getUint32(offset+32)!==raw.length) throw new Error("invalid native witness length");
  const encoded=raw.subarray(9,offset), message=codec.decode(encoded);
  if (!equalBytes(codec.encode(message).finish(),encoded) || message.proof.length || !message.audit) throw new Error("invalid native V2 message");
  return {message, scalar:raw.slice(offset,offset+32), witness:raw.slice(offset+36)};
}

/** Trusted custody-only orchestration. checkpoint must durably record approval
 * and selected-note reservations before the native owner signer is invoked. */
export async function prepareAuditWitnessV2(input) {
  const {kind, snapshot, rootSeed, creator, chainId, denom, backend, getCurrentSnapshot, checkpoint, signal}=input;
  const code=kinds[kind], codec=codecs[kind];
  if (!Object.hasOwn(kinds,kind) || typeof backend?.prepare!=="function" || typeof checkpoint!=="function" || typeof getCurrentSnapshot!=="function") throw new Error("V2 kind, native backend, checkpoint and snapshot provider required");
  assertAuditSnapshotCurrentV2(snapshot,snapshot);
  address(creator,snapshot.accountPrefix);
  if (typeof chainId!=="string" || !/^[a-zA-Z0-9_.-]{1,128}$/.test(chainId) || chainId!==snapshot.chainId) throw new Error("chain ID/snapshot mismatch");
  const expiry=unsignedInteger(input.expiresAtUnix,"expiry",(1n<<63n)-1n,1n);
  let material, request, reply, native, prepared, spend, view, disclosure;
  const check=()=>{ signal?.throwIfAborted(); if (BigInt(Math.floor(Date.now()/1000))>=expiry) throw new Error("V2 operation expired"); };
  try {
    check();
    material=kind==="deposit" ? prepareDepositMaterialV2({rootSeed,amount:input.amount,denom,memo:input.memo})
      : prepareSpendInputsV2({kind,rootSeed,amount:input.amount,denom,notes:input.notes});
    const wire={version:"audit-witness-v2",kind:code,accountPrefix:snapshot.accountPrefix,chainID:chainId,creator,
      amount:material.amount,expiresAtUnix:expiry.toString(),snapshot:{network:base64FromBytes(bytesFromHex(snapshot.networkDigest)),artifact:base64FromBytes(bytesFromHex(snapshot.artifactHash)),epoch:snapshot.epoch,height:snapshot.stateHeight,key:base64FromBytes(bytesFromHex(snapshot.publicKey))}};
    let plaintext;
    if (kind==="deposit") {
      wire.notes=[base64FromBytes(material.plaintext)]; wire.output=base64FromBytes(OutputEffectV2.encode(material.output).finish());
      plaintext=material.auditPlaintext;
    } else {
      spend=deriveSpendKeys(rootSeed); view=deriveViewKeys(rootSeed);
      wire.notes=material.plaintexts.map(base64FromBytes); wire.spendScalar=base64FromBytes(canonicalFieldBytes(spend.scalar));
      if (!Array.isArray(input.paths) || input.paths.length!==material.commitments.length) throw new Error("selected Merkle paths required");
      wire.paths=input.paths.map((p,i)=>{
        if (p.commitment!==hexFromBytes(material.commitments[i]) || !(p.root instanceof Uint8Array) || p.root.length!==32
          || !Array.isArray(p.path) || p.path.length!==32 || p.path.some(n=>typeof n!=="string" || !/^[0-9a-f]{64}$/.test(n))
          || !Array.isArray(p.helper) || p.helper.length!==32 || p.helper.some(n=>n!==0 && n!==1)
          || !equalBytes(p.root,input.paths[0].root)) throw new Error("selected Merkle path mismatch");
        return {commitment:p.commitment,root:base64FromBytes(p.root),path:p.path.slice(),helper:p.helper.slice()};
      });
      const asset=canonicalFieldBytes(computeAssetId(denom));
      if (kind==="withdraw") {
        address(input.recipient,snapshot.accountPrefix); wire.recipient=input.recipient;
        plaintext=[asset,material.commitments[0]];
      } else {
        const recipient=decodeShieldedAddress(input.recipient,{shieldedPrefix:input.shieldedPrefix??"clairs"});
        const policy=input.disclosure?.policy??0, mode=input.disclosure?.mode??0;
        if (!Number.isInteger(policy)||policy<0||policy>7 || ![0,1,2].includes(mode) || (policy===0)!==(mode===0)) throw new Error("invalid V2 disclosure policy");
        wire.recipientSpend=base64FromBytes(packPoint(recipient.spendPubKey)); wire.recipientView=base64FromBytes(packPoint(recipient.viewPubKey));
        disclosure=deriveDisclosureKeys(rootSeed);
        wire.disclosure={policy,mode,disableSelfView:input.disableSelfView===true,selfView:base64FromBytes(packPoint(disclosure.pubKey))};
        if (input.disclosure?.target) {
          if (mode!==2 || !(input.disclosure.target instanceof Uint8Array) || input.disclosure.target.length!==32) throw new Error("invalid V2 disclosure target");
          wire.disclosure.target=base64FromBytes(input.disclosure.target);
        } else if (mode===2) throw new Error("encrypted disclosure target required");
        plaintext=[asset,...material.commitments,...[BigInt(input.amount),recipient.spendPubKey.x,recipient.spendPubKey.y,recipient.viewPubKey.x,recipient.viewPubKey.y,
          material.change,spend.pubKey.x,spend.pubKey.y,view.pubKey.x,view.pubKey.y].map(canonicalFieldBytes)];
      }
    }
    request=utf8Bytes(JSON.stringify(wire)); wire.notes=[]; wire.spendScalar="";
    if (request.length>32768) throw new Error("native witness request bound");
    await checkpoint({kind,commitments:kind==="deposit"?[]:material.commitments.map(hexFromBytes),nullifiers:kind==="deposit"?[]:material.nullifiers.map(hexFromBytes)});
    assertAuditSnapshotCurrentV2(snapshot,await getCurrentSnapshot()); check();
    reply=await backend.prepare({request,signal}); check();
    native=nativeReply(reply,code,codec); const m=native.message;
    if (m.creator!==creator || m.expiresAtUnix!==expiry || (kind!=="transfer" && m.amount!==material.amount)) throw new Error("native transaction intent mismatch");
    if (kind==="deposit" && !equalBytes(OutputEffectV2.encode(m.output).finish(),OutputEffectV2.encode(material.output).finish())) throw new Error("native deposit output mismatch");
    if (kind!=="deposit") {
      const nf=kind==="withdraw"?[m.nullifier]:m.nullifiers;
      if (!equalBytes(m.root,input.paths[0].root) || nf.length!==material.nullifiers.length || nf.some((v,i)=>!equalBytes(v,material.nullifiers[i]))) throw new Error("native selected input mismatch");
      if (kind==="withdraw" && m.recipient!==input.recipient) throw new Error("native recipient mismatch");
      if (kind==="transfer" && (m.outputs[0].userPrivacyPolicy!==wire.disclosure.policy || m.outputs[0].userDisclosureMode!==wire.disclosure.mode
        || !equalBytes(m.outputs[0].userDisclosureTargetPubkey,input.disclosure?.target??new Uint8Array())
        || (m.outputs[0].selfViewDisclosurePayload.length===0)!==(input.disableSelfView===true))) throw new Error("native disclosure mismatch");
    }
    const {audit,proof,...message}=m;
    prepared=await prepareAuditAuthorizationV2({kind:code,snapshot,message,plaintext,getCurrentSnapshot,signal,
      backend:{encrypt:async ({publicInputs})=>{
        if (!equalBytes(publicInputs,native.witness.subarray(12,12+672))) throw new Error("native witness public input mismatch");
        return {envelope:audit.envelope.slice(),witness:native.scalar.slice()};
      }}});
    if (!equalBytes(prepared.messageData().audit.keyId,audit.keyId) || prepared.messageData().audit.epoch!==audit.epoch) throw new Error("native audit snapshot mismatch");
    validateFullAuditWitness(native.witness,prepared.publicInputs()); check();
    const witness=native.witness; native.witness=undefined;
    return {prepared,witness,clear(){ prepared.clear(); witness.fill(0); },toJSON(){throw new Error("private preparation cannot be serialized");}};
  } catch (error) { prepared?.clear(); throw error; }
  finally {
    request?.fill(0); reply?.fill(0); native?.scalar.fill(0); native?.witness?.fill(0); material?.clear();
    for (const key of [spend,view,disclosure]) if(key){key.seed.fill(0);key.scalar=0n;key.scalarHex="";}
  }
}
