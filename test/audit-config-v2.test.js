import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  computeAuditNetworkDigestV2, parseAuditKeyRecordV2, validateAuditCircuitIdentityV2,
  validateAuditArtifactManifestV2, queryActiveAuditSnapshotV2, assertAuditSnapshotCurrentV2, normalizeDisclosureConfigV2
} from "clairveiljs/audit-config-v2";
import { createClairveilClient } from "clairveiljs/cosmos-client";
import { bytesFromBase64, bytesFromHex, hexFromBytes, sha256Hex } from "clairveiljs/browser-crypto";
import { CircuitSetIdentity } from "clairveiljs/generated/clairveil/privacy/v1/genesis";
import { CURVE_ORDER, FIELD_MODULUS, canonicalFieldBytes } from "clairveiljs/crypto";

const f = JSON.parse(readFileSync(new URL("../fixtures/clairveil-v0.6.1-audit/vectors.json", import.meta.url)));
test("V2 disclosure configuration refuses legacy payloads and conflicting aliases",()=>{
  const v={payload_version:"privacy-fixed-v2",audit_disclosure_required:true,supported_user_policies:["all-private","amount"],supported_user_modes:["none","public"]};
  assert.equal(normalizeDisclosureConfigV2(v).payload_version,"privacy-fixed-v2");
  for(const change of [{payload_version:"privacy-fixed-v1"},{payloadVersion:"privacy-fixed-v1"},{audit_disclosure_required:false},{supported_user_policies:["amount"]},{supported_user_modes:["none","none"]}])assert.throws(()=>normalizeDisclosureConfigV2({...v,...change}));
});
const manifest = bytesFromBase64(f.manifest_base64);
function setup(index = 1) {
  const row = f.records[index];
  const responses = {
    configuration: { network_nonce: Buffer.from(f.network_nonce_hex,"hex").toString("base64"), initial_height: f.initial_height, circuit_identity: f.identity_base64, state_height: row.state_height },
    keySchedule: { active_epoch: row.epoch, next_activation_height: "0", next_epoch: "0", halted: false, state_height: row.state_height },
    key: { record: Buffer.from(row.record_hex,"hex").toString("base64"), state_height: row.state_height }
  };
  const calls = [];
  const query = Object.fromEntries(Object.keys(responses).map(name => [name, async args => { calls.push({ name, ...args }); return responses[name]; }]));
  const options = { query, chainId: f.chain_id, expectedCircuitIdentity: structuredClone(f.identity), artifactManifestBytes: manifest, expectedArtifactHash: f.artifact_hash,
    expectedNetworkNonce: bytesFromHex(f.network_nonce_hex), expectedInitialHeight: f.initial_height };
  return { options, responses, calls, row };
}
function mutateRecord(fn) { const raw=bytesFromHex(f.records[1].record_hex); fn(raw); return raw; }
function record(raw) { return parseAuditKeyRecordV2(raw, { networkDigest: bytesFromHex(f.network_digest_hex), initialHeight: f.initial_height }); }

test("audit network digest and all key records match independent Core Go vectors", () => {
  assert.equal(hexFromBytes(computeAuditNetworkDigestV2(f.chain_id, bytesFromHex(f.network_nonce_hex))), f.network_digest_hex);
  for (const row of f.records) {
    const result=record(bytesFromHex(row.record_hex));
    assert.equal(result.epoch,row.epoch); assert.equal(result.keyId,row.key_id_hex);
    assert.equal(result.publicKey,row.public_key_hex); assert.equal(result.activationHeight,row.activation_height);
    assert.equal(result.registeredHeight,row.registered_height); assert.equal(result.origin.kind,row.origin_kind);
    assert.equal(result.possessionProof,row.pop_hex); assert(Object.isFrozen(result.origin));
  }
});
test("audit record rejects every Core negative vector", () => {
  for (const row of f.invalid_records) assert.throws(()=>record(bytesFromHex(row.record_hex)),undefined,row.name);
});
test("audit PoP binds network, epoch and activation and validates canonical scalars/points", () => {
  assert.throws(()=>parseAuditKeyRecordV2(bytesFromHex(f.records[1].record_hex),{ networkDigest:new Uint8Array(32), initialHeight:"10" }),/possession|PoP/);
  for (const start of [44,165]) {
    assert.throws(()=>record(mutateRecord(raw=>{raw.fill(0,start,start+64);raw[start+63]=1;})),/point|identity/);
    assert.throws(()=>record(mutateRecord(raw=>raw.set(canonicalFieldBytes(FIELD_MODULUS-1n),start+32))),/point|subgroup|curve/);
    assert.throws(()=>record(mutateRecord(raw=>raw.set(Buffer.from(FIELD_MODULUS.toString(16).padStart(64,"0"),"hex"),start))),/canonical/);
  }
  assert.throws(()=>record(mutateRecord(raw=>raw.set(canonicalFieldBytes(CURVE_ORDER),229))),/response|scalar/);
  assert.throws(()=>record(mutateRecord(raw=>raw.fill(0,229))),/possession|PoP/);
  assert.throws(()=>parseAuditKeyRecordV2(bytesFromHex(f.records[0].record_hex),{networkDigest:bytesFromHex(f.network_digest_hex),initialHeight:"11"}),/initial/);
});
test("V2 identity and manifest enforce exact circuit order, schema, VK and local byte digest", () => {
  const identity=validateAuditCircuitIdentityV2(f.identity);
  assert.deepEqual(identity,f.identity);
  assert(Object.isFrozen(identity.circuits));
  assert.equal(validateAuditArtifactManifestV2(manifest,{expectedCircuitIdentity:identity,expectedArtifactHash:f.artifact_hash}).artifactHash,f.artifact_hash);
  for (const change of [m=>m.active_set_id="privacy-note-v1",m=>m.artifacts.reverse(),m=>m.artifacts.pop(),m=>m.artifacts[2].sha256="f".repeat(64),m=>m.circuit_set_identity.circuits[0].public_input_schema_sha256="0".repeat(64),m=>m.artifacts[0].filename="../key"]){
    const m=JSON.parse(new TextDecoder().decode(manifest));change(m);const raw=new TextEncoder().encode(JSON.stringify(m));
    assert.throws(()=>validateAuditArtifactManifestV2(raw,{expectedCircuitIdentity:identity,expectedArtifactHash:sha256Hex(raw)}));
  }
  assert.throws(()=>validateAuditArtifactManifestV2(new Uint8Array([...manifest,32]),{expectedCircuitIdentity:identity,expectedArtifactHash:f.artifact_hash}),/artifact.*mismatch/);
  assert.throws(()=>validateAuditCircuitIdentityV2({...f.identity,schemaVersion:"v2"}),/conflict/);
  assert.throws(()=>validateAuditCircuitIdentityV2({...f.identity,circuit_set_id:"privacy-note-v1"}),/identity|circuit/);
});
test("snapshot pins configuration, schedule and key at the same height without integer truncation", async () => {
  for (let i=0;i<f.records.length;i++){
    const {options,calls,row}=setup(i);const s=await queryActiveAuditSnapshotV2(options);
    assert.equal(s.epoch,row.epoch); assert.equal(s.stateHeight,row.state_height);assert.equal(s.keyId,row.key_id_hex);
    assert.equal(s.networkDigest,f.network_digest_hex);assert.equal(s.initialHeight,"10");assert.equal(s.artifactHash,f.artifact_hash);
    assert.deepEqual(calls,[{name:"configuration"},{name:"keySchedule",height:row.state_height},{name:"key",epoch:row.epoch,height:row.state_height}]);
    assert(Object.isFrozen(s));assert(Object.isFrozen(s.circuitIdentity.circuits[0]));
    assert.equal(assertAuditSnapshotCurrentV2(s,s),s);
  }
});
test("snapshot also accepts generated camelCase protobuf responses", async () => {
  const {options,responses}=setup();
  responses.configuration={networkNonce:bytesFromHex(f.network_nonce_hex),initialHeight:10n,circuitIdentity:bytesFromBase64(f.identity_base64),stateHeight:21n};
  responses.keySchedule={activeEpoch:2n,nextActivationHeight:0n,nextEpoch:0n,halted:false,stateHeight:21n};
  responses.key={record:bytesFromHex(f.records[1].record_hex),stateHeight:21n};
  assert.equal((await queryActiveAuditSnapshotV2(options)).epoch,"2");
});

test("structured and encoded circuit identities produce the same pinned snapshot", async () => {
  const reference = setup();
  const expected = await queryActiveAuditSnapshotV2(reference.options);
  const bytes = bytesFromBase64(f.identity_base64);
  const camel = CircuitSetIdentity.decode(bytes);
  for (const fields of [
    { circuitIdentity: camel },
    { circuit_identity: f.identity },
    { circuit_identity: bytes, circuitIdentity: camel }
  ]) {
    const { options, responses, calls } = setup();
    delete responses.configuration.circuit_identity;
    Object.assign(responses.configuration, fields);
    assert.deepEqual(await queryActiveAuditSnapshotV2(options), expected);
    assert.deepEqual(calls, reference.calls);
  }
});

test("structured circuit identities enforce the schema, deployment pin and alias agreement", async () => {
  const bytes = bytesFromBase64(f.identity_base64);
  const camel = CircuitSetIdentity.decode(bytes);
  const otherKey = structuredClone(camel);
  otherKey.circuits[0].verifyingKeySha256 = "e".repeat(64);
  const missingKey = structuredClone(camel);
  delete missingKey.circuits[0].verifyingKeySha256;
  const unknownCircuitField = structuredClone(camel);
  unknownCircuitField.circuits[0].extra = true;
  const noncanonical = Uint8Array.from([...bytes, 0x28, 1]);
  for (const [fields, error] of [
    [{ circuitIdentity: otherKey }, /verifier identity/],
    [{ circuitIdentity: missingKey }, /SHA256/],
    [{ circuitIdentity: { ...camel, circuits: [...camel.circuits].reverse() } }, /order/],
    [{ circuitIdentity: { ...camel, schema_version: "other" } }, /aliases conflict/],
    [{ circuitIdentity: { ...camel, extra: true } }, /unknown.*field/],
    [{ circuitIdentity: unknownCircuitField }, /unknown.*field/],
    [{ circuit_identity: bytes, circuitIdentity: otherKey }, /aliases conflict/],
    [{ circuit_identity: noncanonical }, /canonical protobuf/],
    [{ circuit_identity: noncanonical, circuitIdentity: camel }, /canonical protobuf/]
  ]) {
    const { options, responses, calls } = setup();
    delete responses.configuration.circuit_identity;
    Object.assign(responses.configuration, fields);
    await assert.rejects(queryActiveAuditSnapshotV2(options), error);
    assert.equal(calls.length, 1);
  }
});

test("structured circuit identities still require the audit key at the configuration height", async () => {
  const { options, responses } = setup();
  responses.configuration.circuit_identity = f.identity;
  responses.key.state_height = "22";
  await assert.rejects(queryActiveAuditSnapshotV2(options), /audit key query height mismatch/);
});

test("halt and missing active epoch stop before the key query", async () => {
  for (const patch of [{halted:true},{halted:"false"},{halted:undefined},{active_epoch:"0"}]) {
    const {options,responses,calls}=setup();Object.assign(responses.keySchedule,patch);
    await assert.rejects(queryActiveAuditSnapshotV2(options)); assert.equal(calls.length,2);
  }
});
test("mixed heights, absent/pruned snapshots and malformed pending schedules fail closed", async () => {
  for (const change of [r=>r.keySchedule.state_height="22",r=>r.key.state_height="22",r=>r.keySchedule=null,r=>r.key=null,r=>r.keySchedule.next_epoch="3",r=>{r.keySchedule.next_epoch="3";r.keySchedule.next_activation_height="20";}]){
    const {options,responses}=setup();change(responses);await assert.rejects(queryActiveAuditSnapshotV2(options));
  }
  const {options,calls}=setup();options.query.keySchedule=async()=>{throw new Error("height pruned");};
  await assert.rejects(queryActiveAuditSnapshotV2(options),/height pruned/);assert.equal(calls.length,1);
});
test("future active records are rejected while a valid pending rotation is retained", async()=>{
  const pending=setup();pending.responses.keySchedule.next_epoch="3";pending.responses.keySchedule.next_activation_height="30";
  const snapshot=await queryActiveAuditSnapshotV2(pending.options);
  assert.equal(snapshot.nextEpoch,"3");assert.equal(snapshot.nextActivationHeight,"30");
  const future=setup();for(const response of Object.values(future.responses))response.state_height="19";
  await assert.rejects(queryActiveAuditSnapshotV2(future.options),/schedule mismatch/);
});
test("nonce, initial height, circuit identity, key and artifact mismatch prevent a preparation snapshot", async () => {
  for(const change of [
    r=>r.configuration.network_nonce=Buffer.alloc(32,9).toString("base64"),
    r=>r.configuration.initial_height="11",r=>r.configuration.state_height="9",
    r=>r.keySchedule.active_epoch="3",r=>r.key.record=Buffer.from(f.records[0].record_hex,"hex").toString("base64"),
    r=>{const id=CircuitSetIdentity.decode(bytesFromBase64(f.identity_base64));id.circuits[0].verifyingKeySha256="e".repeat(64);r.configuration.circuit_identity=Buffer.from(CircuitSetIdentity.encode(id).finish()).toString("base64");}
  ]) {const {options,responses}=setup();change(responses);await assert.rejects(queryActiveAuditSnapshotV2(options));}
  const {options,calls}=setup();options.expectedArtifactHash="a".repeat(64);
  await assert.rejects(queryActiveAuditSnapshotV2(options),/artifact.*mismatch/);assert.deepEqual(calls,[]);
});
test("malformed configuration/aliases and unsafe numbers never become valid snapshots", async () => {
  for(const patch of [{network_nonce:"%%%"},{network_nonce:"AA=="},{initial_height:"0"},{initial_height:"01"},{initial_height:10},{state_height:"9223372036854775808"},{state_height:"-1"},{stateHeight:22n},{circuit_identity:"AA=="}]){
    const {options,responses,calls}=setup();Object.assign(responses.configuration,patch);
    await assert.rejects(queryActiveAuditSnapshotV2(options));assert.equal(calls.length,1);
  }
  for(const chainId of ["","한글","chain\n"]){const {options,calls}=setup();options.chainId=chainId;await assert.rejects(queryActiveAuditSnapshotV2(options));assert.equal(calls.length,0);}
});
test("snapshot namespace refresh permits newer heights, rejects rotation/artifact changes and fabricated snapshots", async () => {
  const a=setup();const old=await queryActiveAuditSnapshotV2(a.options);
  for(const r of Object.values(a.responses)) r.state_height="22";
  const fresh=await queryActiveAuditSnapshotV2(a.options);assert.equal(assertAuditSnapshotCurrentV2(old,fresh),fresh);
  assert.throws(()=>assertAuditSnapshotCurrentV2(fresh,old),/height|stale/);
  assert.throws(()=>assertAuditSnapshotCurrentV2(old,{...fresh}),/validated/);
  const rotated=await queryActiveAuditSnapshotV2(setup(3).options);
  assert.throws(()=>assertAuditSnapshotCurrentV2(old,rotated),/namespace|changed/);
  const m=JSON.parse(new TextDecoder().decode(manifest));m.generated_at="different";
  const changed=setup();changed.options.artifactManifestBytes=new TextEncoder().encode(JSON.stringify(m));changed.options.expectedArtifactHash=sha256Hex(changed.options.artifactManifestBytes);
  const artifactChanged=await queryActiveAuditSnapshotV2(changed.options);
  assert.throws(()=>assertAuditSnapshotCurrentV2(old,artifactChanged),/namespace|changed/);
});
test("Cosmos REST queries send exact block height headers and keep one endpoint throughout a snapshot",async t=>{
  const {options,responses,calls,row}=setup();delete options.query;delete options.chainId;
  const urls=[];const client=createClairveilClient({rpc:"http://rpc.invalid",rest:"http://rest.invalid",restEndpoints:["http://backup.invalid"],chainId:f.chain_id,queryRetry:{attempts:1}});
  t.mock.method(globalThis,"fetch",async(url,init)=>{
    urls.push({url,headers:init?.headers});
    const name=String(url).endsWith("configuration")?"configuration":String(url).endsWith("key_schedule")?"keySchedule":"key";
    if(name==="configuration")client.activeRestEndpoint="http://backup.invalid";
    return new Response(JSON.stringify(responses[name]),{status:200,headers:{"Content-Type":"application/json"}});
  });
  const s=await client.queryActiveAuditSnapshotV2(options);assert.equal(s.epoch,row.epoch);assert.deepEqual(calls,[]);
  assert.deepEqual(urls.map(r=>r.url),["configuration","key_schedule","keys/2"].map(p=>`http://rest.invalid/clairveil/privacy/v2/audit/${p}`));
  for(const r of urls.slice(1))assert.equal(new Headers(r.headers).get("x-cosmos-block-height"),row.state_height);
  assert.equal(new Headers(urls[0].headers).get("x-cosmos-block-height"),null);
});
test("Cosmos V2 preflight propagates missing endpoints and pruned heights without latest, V1 or endpoint fallback",async t=>{
  const {options,responses}=setup();delete options.query;delete options.chainId;
  const client=createClairveilClient({rpc:"http://rpc.invalid",rest:"http://rest.invalid",restEndpoints:["http://backup.invalid"],chainId:f.chain_id});
  const urls=[];
  t.mock.method(globalThis,"fetch",async(url)=>{
    urls.push(url);
    return String(url).endsWith("configuration")?new Response(JSON.stringify(responses.configuration),{status:200}):new Response("height pruned",{status:400});
  });
  await assert.rejects(client.queryActiveAuditSnapshotV2(options));
  assert.deepEqual(urls,["http://rest.invalid/clairveil/privacy/v2/audit/configuration","http://rest.invalid/clairveil/privacy/v2/audit/key_schedule"]);
});


test("audit snapshot pins address prefix and refuses changes on refresh", async () => {
  const {options}=setup();
  const core=await queryActiveAuditSnapshotV2(options);
  const maroo=await queryActiveAuditSnapshotV2({...options,accountPrefix:"maroo"});
  assert.equal(maroo.accountPrefix,"maroo");
  assert.throws(()=>assertAuditSnapshotCurrentV2(core,maroo),/namespace/);
  for (const accountPrefix of ["", "MAROO", "maroo1", null]) await assert.rejects(queryActiveAuditSnapshotV2({...options,accountPrefix}), /prefix/);
});
