import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as v2 from "clairveiljs/cosmos-v2";
import * as root from "clairveiljs";
import { createClairveilRegistry, MsgDeposit } from "clairveiljs/cosmos-client";
import { QueryReserveResponse } from "clairveiljs/generated/clairveil/privacy/v1/query.js";

const bytes = (...values) => Uint8Array.from(values);
const maxUint64 = (1n << 64n) - 1n;
const maxInt64 = (1n << 63n) - 1n;
const audit = { keyId: bytes(1, 2), epoch: maxUint64, envelope: bytes(3, 4, 5) };
const output = {
  commitment: bytes(6, 7), ciphertext: bytes(8, 9), viewTag: bytes(10, 11),
  userPrivacyPolicy: 7, userDisclosureMode: 2,
  userDisclosureDigest: bytes(12), userDisclosureTargetPubkey: bytes(13),
  userDisclosurePayload: bytes(14), selfFullDisclosureDigest: bytes(15),
  selfViewDisclosurePayload: bytes(16)
};
// Synthetic wire fixtures deliberately do not claim valid addresses, proofs,
// audit authorization, or executable transactions.
const cases = [
  [v2.AuditAuthorizationV2, audit],
  [v2.OutputEffectV2, output],
  [v2.MsgDepositV2, { creator: "actor", amount: "340282366920938463463374607431768211455uclair", output, proof: bytes(17, 18), expiresAtUnix: maxInt64, audit }],
  [v2.MsgWithdrawV2, { creator: "actor", amount: "1uclair", recipient: "recipient", root: bytes(19), nullifier: bytes(20), proof: bytes(21), expiresAtUnix: maxInt64, audit }],
  [v2.MsgTransferV2, { creator: "actor", root: bytes(22), nullifiers: [bytes(23), bytes(24)], outputs: [output, output], proof: bytes(25), expiresAtUnix: maxInt64, audit }],
  [v2.MsgBatchTransferV2, { creator: "actor", root: bytes(26), nullifiers: [bytes(27), bytes(28)], outputs: [output, output], proof: bytes(29), expiresAtUnix: maxInt64, audit }],
  [v2.MsgScheduleAuditKeyEpochV2, { authority: "authority", epoch: maxUint64, activationHeight: maxUint64, publicKey: bytes(30), suite: 2, possessionProof: bytes(31) }],
  [v2.MsgCancelPendingAuditEpochV2, { authority: "authority", epoch: maxUint64 }],
  [v2.MsgSetPrivacyHaltV2, { authority: "authority", halted: true }],
  [v2.QueryAuditKeyRequestV2, { epoch: maxUint64 }],
  [v2.QueryAuditRecordResponseV2, { record: bytes(32), storeKey: bytes(33), stateHeight: maxInt64 }],
  [v2.QueryAuditKeyScheduleResponseV2, { activeEpoch: maxUint64, nextActivationHeight: maxUint64, nextEpoch: maxUint64, halted: true, stateHeight: maxInt64 }],
  [v2.QueryAuditConfigurationResponseV2, { networkNonce: bytes(34), initialHeight: maxUint64, circuitIdentity: bytes(35), stateHeight: maxInt64 }]
];

test("V2 codecs match independently generated Core v0.6.1 Go wire vectors", () => {
  const fixture = JSON.parse(readFileSync(new URL("../fixtures/clairveil-v0.6.1-proto/wire-vectors.json", import.meta.url)));
  assert.equal(fixture.source.commit, "fad307abddd0daa1c880f2e423668f5c58a0e578");
  assert.equal(fixture.scope, "synthetic protobuf encoding only");
  assert.equal(fixture.vectors.length, cases.length);
  for (const [codec, input] of cases) {
    const expected = fixture.vectors.find(entry => entry.type_url === codec.typeUrl);
    assert.ok(expected, codec.typeUrl);
    const message = codec.fromPartial(input);
    const encoded = codec.encode(message).finish();
    assert.equal(Buffer.from(encoded).toString("hex"), expected.hex, codec.typeUrl);
    assert.deepEqual(codec.decode(encoded), message, codec.typeUrl);
  }
});

test("V2 registry registers all seven messages without replacing legacy defaults", () => {
  const registry = v2.createClairveilV2Registry();
  const names = ["Deposit", "Withdraw", "Transfer", "BatchTransfer", "ScheduleAuditKeyEpoch", "CancelPendingAuditEpoch", "SetPrivacyHalt"];
  for (const name of names) {
    const codec = v2[`Msg${name}V2`];
    assert.equal(registry.lookupType(`/clairveil.privacy.v2.Msg${name}`), codec);
    assert.equal(root[`Msg${name}V2`], codec);
    const [, input] = cases.find(([candidate]) => candidate === codec);
    const message = codec.fromPartial(input);
    assert.deepEqual(registry.decode({ typeUrl: codec.typeUrl, value: registry.encode({ typeUrl: codec.typeUrl, value: message }) }), message);
  }
  assert.equal(registry.lookupType(MsgDeposit.typeUrl), undefined);
  assert.equal(createClairveilRegistry().lookupType(MsgDeposit.typeUrl), MsgDeposit);
  assert.equal(root.MsgDeposit.typeUrl, "/clairveil.privacy.v1.MsgDeposit");
  assert.equal(createClairveilRegistry().lookupType(v2.MsgDepositV2.typeUrl), undefined);
});

test("V2 generated subpath exports resolve with and without the .js extension", async () => {
  for (const module of [
    await import("clairveiljs/generated/clairveil/privacy/v2/tx.js"),
    await import("clairveiljs/generated/clairveil/privacy/v2/tx")
  ]) assert.equal(module.MsgDeposit, v2.MsgDepositV2);
  assert.deepEqual(v2.QueryAuditConfigurationRequestV2.encode(v2.QueryAuditConfigurationRequestV2.fromPartial({})).finish(), bytes());
  assert.deepEqual(v2.QueryAuditKeyScheduleRequestV2.encode(v2.QueryAuditKeyScheduleRequestV2.fromPartial({})).finish(), bytes());
});

test("V1 reserve query codec carries additive v0.6.1 accounting fields losslessly", () => {
  const message = QueryReserveResponse.fromPartial({
    denom: "uclair", moduleBalance: "340282366920938463463374607431768211457",
    totalDeposited: "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
    totalWithdrawn: "999999999999999999999999999999999999999999999999659717633079061536536625392568231788544",
    expectedModuleBalance: "340282366920938463463374607431768211455",
    invariantHolds: false, liability: "340282366920938463463374607431768211455",
    collateralized: true, surplus: "2", shortfall: "0"
  });
  const decoded = QueryReserveResponse.decode(QueryReserveResponse.encode(message).finish());
  assert.equal(decoded.liability, message.expectedModuleBalance);
  assert.equal(decoded.collateralized, true);
  assert.equal(decoded.surplus, "2");
  assert.equal(decoded.shortfall, "0");
  assert.deepEqual(decoded, message);
});
