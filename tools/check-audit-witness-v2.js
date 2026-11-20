// Explicit synthetic native integration. Never logs private requests/witnesses.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { toBech32 } from "@cosmjs/encoding";
import { createAuditWitnessNativeBackendV2 } from "../src/privacy/audit-witness-node.js";
import { prepareAuditTransactionV2 } from "../src/wallet-kernel/audit-workflow.js";
import { buildAuditPublicInputsV2 } from "../src/privacy/audit-authorization-v2.js";
import { prepareDepositMaterialV2 } from "../src/privacy/preparation-v2.js";
import { createAuditNativeVerifierV2 } from "../src/privacy/audit-verifier-node.js";
import { queryActiveAuditSnapshotV2 } from "../src/privacy/audit-config-v2.js";
import { decryptDepositNoteV2,computeNoteCommitmentV2,computeNoteNullifierV2 } from "../src/privacy/protocol-v2.js";
import { computeNoteTreeNodeV1,emptyNoteTreeRootsV1 } from "../src/privacy/protocol-v1.js"; // unchanged hash domains; fixture tree only
import { deriveSpendKeys,deriveViewKeys,encodeShieldedAddress,canonicalFieldBytes } from "../src/core/crypto.js";
import { MsgDepositV2,MsgTransferV2,MsgWithdrawV2 } from "../src/transport/cosmos-v2.js";
import { encodeEvmPrivacyRequestV2 } from "../src/transport/evm-v2.js";

const {values}=parseArgs({options:{native:{type:"string"},verifier:{type:"string"},server:{type:"string"},artifacts:{type:"string"},report:{type:"string"}}});
for (const name of ["native","verifier","server","artifacts","report"]) assert(values[name],`${name} path required`);
const hash=b=>createHash("sha256").update(b).digest("hex");
const rootSeed=Uint8Array.from({length:32},(_,i)=>i), otherSeed=Uint8Array.from({length:32},(_,i)=>i+32);
let server;
try {
  const nativePath=resolve(values.native), verifierPath=resolve(values.verifier), serverPath=resolve(values.server), artifacts=resolve(values.artifacts);
  const nativeSHA256=hash(await readFile(nativePath)), verifierSHA256=hash(await readFile(verifierPath));
  const backend=await createAuditWitnessNativeBackendV2({executablePath:nativePath,sha256:nativeSHA256});
  const manifestBytes=await readFile(resolve(artifacts,"privacy_zk_manifest.json")), manifest=JSON.parse(manifestBytes), artifactHash=hash(manifestBytes);
  const ready=await new Promise((res,rej)=>{
    server=spawn(serverPath,["serve",artifacts],{env:{},stdio:["ignore","pipe","pipe"]});let text="";
    const timer=setTimeout(()=>rej(new Error("prover startup timeout")),120000);
    server.stdout.on("data",chunk=>{text+=chunk.toString();if(text.length>65536){clearTimeout(timer);rej(new Error("prover metadata bound"));}if(text.includes("\n")){clearTimeout(timer);try{res(JSON.parse(text.trim()));}catch{rej(new Error("prover metadata invalid"));}}});
    server.stderr.on("data",chunk=>chunk.fill(0));server.on("error",()=>{clearTimeout(timer);rej(new Error("prover startup failed"));});server.on("exit",()=>{clearTimeout(timer);rej(new Error("prover exited"));});
  });
  const verifier=await createAuditNativeVerifierV2({executablePath:verifierPath,sha256:verifierSHA256,artifactDirectory:artifacts,expectedArtifactHash:artifactHash,expectedCircuitIdentity:manifest.circuit_set_identity});
  const audit=JSON.parse(await readFile(new URL("../fixtures/clairveil-v0.6.1-audit/vectors.json",import.meta.url))), record=audit.records[1];
  function snapshot(accountPrefix) {return queryActiveAuditSnapshotV2({accountPrefix,chainId:audit.chain_id,expectedCircuitIdentity:manifest.circuit_set_identity,artifactManifestBytes:manifestBytes,expectedArtifactHash:artifactHash,query:{
    configuration:async()=>({networkNonce:Buffer.from(audit.network_nonce_hex,"hex"),initialHeight:audit.initial_height,circuitIdentity:Buffer.from(ready.identityBytes,"base64"),stateHeight:record.state_height}),
    keySchedule:async({height})=>({activeEpoch:record.epoch,nextEpoch:"0",nextActivationHeight:"0",halted:false,stateHeight:height}),
    key:async({height,epoch})=>{assert.equal(epoch,record.epoch);return {record:Buffer.from(record.record_hex,"hex"),stateHeight:height};}
  }});}
  const recipient=encodeShieldedAddress(deriveSpendKeys(otherSeed).pubKey,deriveViewKeys(otherSeed).pubKey);
  function found(amount) {const m=prepareDepositMaterialV2({rootSeed,amount,denom:"uclair"});const note=decryptDepositNoteV2(m.output.ciphertext,rootSeed);m.clear();return {note,nullifier:computeNoteNullifierV2(note).toString(16).padStart(64,"0"),nullifierStatus:"unspent",isSpent:false};}
  const notes=[found(1n<<65n),found(0n)], leaves=notes.map(n=>computeNoteCommitmentV2(n.note)), empty=emptyNoteTreeRootsV1(32);
  const paths=notes.map((_,i)=>{
    let root=computeNoteTreeNodeV1(0,leaves[0],leaves[1]);const path=[leaves[1-i]],helper=[i];
    for(let level=1;level<32;level++){path.push(empty[level]);helper.push(0);root=computeNoteTreeNodeV1(level,root,empty[level]);}
    return {commitment:leaves[i].toString(16).padStart(64,"0"),root:canonicalFieldBytes(root),path:path.map(v=>v.toString(16).padStart(64,"0")),helper};
  });
  const results=[];let checkpoints=0;
  for (const accountPrefix of ["clair","maroo"]) {
    const current=await snapshot(accountPrefix),creator=toBech32(accountPrefix,new Uint8Array(20).fill(1)),transparent=toBech32(accountPrefix,new Uint8Array(20).fill(2));
    for (const kind of ["deposit","transfer","withdraw"]) {
      process.stdout.write(`Preparing and proving ${accountPrefix} ${kind}.\n`);
      const input={kind,rootSeed,snapshot:current,creator,chainId:audit.chain_id,amount:kind==="withdraw"?1n<<65n:1n<<64n,denom:"uclair",expiresAtUnix:BigInt(Math.floor(Date.now()/1000)+1200),backend,getCurrentSnapshot:()=>snapshot(accountPrefix),checkpoint:async()=>{checkpoints++;},
        ...(kind!=="deposit"?{notes:kind==="withdraw"?notes.slice(0,1):notes,paths:kind==="withdraw"?paths.slice(0,1):paths,recipient:kind==="withdraw"?transparent:recipient}:{} )};
      let witnessBytes=0, nativeReply;
      const proved=await prepareAuditTransactionV2({...input,assertAuthority:()=>{},
        prover:{baseUrl:ready.baseUrl,verifier,timeoutMs:120000},
        backend:{prepare:async request=>{nativeReply=await backend.prepare(request);const view=new DataView(nativeReply.buffer,nativeReply.byteOffset,nativeReply.byteLength);witnessBytes=view.getUint32(9+view.getUint32(5)+32);return nativeReply;}}});
      const result=proved.message,publicInputs=buildAuditPublicInputsV2({kind:{deposit:1,withdraw:2,transfer:3}[kind],snapshot:current,message:result});
      assert.equal(result.proof.length,164);assert(nativeReply.every(x=>x===0));
      const codec={deposit:MsgDepositV2,transfer:MsgTransferV2,withdraw:MsgWithdrawV2}[kind];
      assert.deepEqual(codec.decode(codec.encode(result).finish()),result);
      const {creator:_,amount:depositAmount,...evmDeposit}=result;
      const {creator:__,...evmSpend}=result;
      if(kind==="withdraw")evmSpend.recipient="0x"+Buffer.from(new Uint8Array(20).fill(2)).toString("hex");
      const calldata=encodeEvmPrivacyRequestV2(kind,kind==="deposit"?evmDeposit:evmSpend);
      const changed=result.proof.slice();changed[10]^=1;
      await assert.rejects(verifier.verify({kind:{deposit:1,withdraw:2,transfer:3}[kind],artifactHash,circuitIdentity:current.circuitIdentity,publicInputs,proof:changed}));
      results.push({accountPrefix,kind,witnessBytes,proofBytes:result.proof.length,messageBytes:codec.encode(result).finish().length,calldataBytes:(calldata.length-2)/2,changedProofRejected:true});
    }
  }
  const report={status:"passed",synthetic:true,coreCommit:"fad307abddd0daa1c880f2e423668f5c58a0e578",nativeSHA256,verifierSHA256,artifactHash,checkpoints,results,signed:false,broadcast:false};
  await writeFile(resolve(values.report),JSON.stringify(report,null,2)+"\n");
  process.stdout.write("PASS: six native witness/proof/encoding paths; no wallet or chain submission.\n");
} catch(error) {
  // Adapter errors are deliberately static. Do not persist error objects or request state.
  process.stderr.write(`Native witness integration failed: ${error instanceof Error?error.message:"unknown"}\n`);process.exitCode=1;
} finally {rootSeed.fill(0);otherSeed.fill(0);server?.kill("SIGKILL");}
