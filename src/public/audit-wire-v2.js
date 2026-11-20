import { sha256 } from '@noble/hashes/sha2.js';
import { hexFromBytes } from './encoding.js';

// Public wire bounds only. Custody separately verifies the complete proof,
// curve points, ownership, disclosure digests, and approved transaction intent.
const fieldModulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const tag = value => sha256(new TextEncoder().encode(value)).subarray(0,16);
const auditTag = tag('clairveil.audit.envelope.v1'), cipherTag = tag('clairveil.encrypted-envelope.v2');
const equal = (a,b) => a.length===b.length && a.every((v,i)=>v===b[i]);
function bytes(value, length) { if(!(value instanceof Uint8Array)||value.length!==length)throw new Error('invalid V2 byte length');return value; }
function field(value, nonzero=false) { bytes(value,32);const n=BigInt('0x'+hexFromBytes(value));if(n>=fieldModulus||nonzero&&n===0n)throw new Error('invalid V2 field'); }
function cipher(value,kind) {
  bytes(value,kind===1?406:kind===2?438:480);
  if(!equal(value.subarray(0,16),cipherTag)||value[16]!==0||value[17]!==2||value[18]!==kind||value[19]!==0)throw new Error('invalid V2 cipher envelope');
}
function output(kind,index,o) {
  if(!o||typeof o!=='object')throw new Error('missing V2 output');
  field(o.commitment,true);cipher(o.ciphertext,kind===1?1:2);bytes(o.viewTag,kind===1?0:2);
  if(!Number.isInteger(o.userPrivacyPolicy)||o.userPrivacyPolicy<0||o.userPrivacyPolicy>7||!Number.isInteger(o.userDisclosureMode)||o.userDisclosureMode<0||o.userDisclosureMode>2)throw new Error('invalid V2 disclosure');
  const extras=['userDisclosureDigest','userDisclosureTargetPubkey','userDisclosurePayload','selfFullDisclosureDigest','selfViewDisclosurePayload'];
  if(kind===1||index===1) { if(o.userPrivacyPolicy||o.userDisclosureMode||extras.some(k=>!(o[k] instanceof Uint8Array)||o[k].length))throw new Error('unexpected V2 change/deposit disclosure');return; }
  field(o.selfFullDisclosureDigest,true);
  if(o.selfViewDisclosurePayload?.length)cipher(o.selfViewDisclosurePayload,5);else bytes(o.selfViewDisclosurePayload,0);
  if(o.userPrivacyPolicy===0) { if(o.userDisclosureMode||extras.slice(0,3).some(k=>!(o[k] instanceof Uint8Array)||o[k].length))throw new Error('unexpected V2 private disclosure');return; }
  field(o.userDisclosureDigest);
  if(o.userDisclosureMode===1) {bytes(o.userDisclosureTargetPubkey,0);bytes(o.userDisclosurePayload,400);}
  else if(o.userDisclosureMode===2) {bytes(o.userDisclosureTargetPubkey,32);cipher(o.userDisclosurePayload,3);}
  else throw new Error('missing V2 disclosure mode');
}
export function validateAuditWireV2(kind,message) {
  const k={deposit:1,withdraw:2,transfer:3}[kind],shape={1:[0,1,336],2:[1,0,208],3:[2,2,560]}[k];
  if(!shape||message.proof?.length!==164||message.audit?.keyId?.length!==32||typeof message.audit.epoch!=='bigint'||message.audit.epoch<=0n||message.audit.epoch>=1n<<64n
    ||typeof message.expiresAtUnix!=='bigint'||message.expiresAtUnix<=0n||message.expiresAtUnix>=1n<<63n)throw new Error('invalid V2 audit wire');
  const frame=bytes(message.audit.envelope,shape[2]),header=Uint8Array.from([...auditTag,0,2,0,2,k,shape[0],shape[1],...new Uint8Array(9)]);
  if(!equal(frame.subarray(0,32),header))throw new Error('invalid V2 audit header');
  for(let offset=48;offset<frame.length;offset+=32)field(frame.subarray(offset,offset+32));
  if(k===1)output(k,0,message.output);
  else {
    field(message.root);const nullifiers=k===2?[message.nullifier]:message.nullifiers;
    if(!Array.isArray(nullifiers)||nullifiers.length!==shape[0])throw new Error('invalid V2 input count');
    nullifiers.forEach(n=>field(n));
    if(k===3) { if(message.outputs?.length!==2||equal(nullifiers[0],nullifiers[1]))throw new Error('invalid V2 arity');message.outputs.forEach((o,i)=>output(k,i,o)); }
  }
}
