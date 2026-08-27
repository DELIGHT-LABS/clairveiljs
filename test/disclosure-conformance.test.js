import test from "node:test";
import assert from "node:assert/strict";
import {
  decodeAuditDisclosureFromEvent,
  decodeAuditDisclosureFromScanOutput,
  decodeSelfViewDisclosureFromEvent,
  decodeSelfViewDisclosureFromScanOutput,
  decodeUserDisclosureFromEvent,
  decodeUserDisclosureFromScanOutput,
  disclosureAmountAndAsset,
  publicPayloadReport,
  userDisclosureModeRecipientEncrypted
} from "clairveiljs/disclosure";
import {
  computeAssetIdV1,
  encryptedEnvelopeKindV1,
  encryptDisclosureV1,
  marshalDisclosurePlaintextV1
} from "clairveiljs/protocol-v1";
import { bytesFromHex } from "clairveiljs/browser-crypto";
import { validatePrivacyScanPageV2 } from "clairveiljs/scan";
import {
  asymEncrypt,
  derivePubKeyFromScalar,
  packPointHex
} from "clairveiljs/core";
import {
  fixtureTestOptions,
  readFixture
} from "./helpers.js";
import {
  createClairveilClient
} from "clairveiljs/cosmos";
import { validatePrivacyScanPageV2 } from "clairveiljs/scan";

const policyLabels = new Map([
  [0, "all-private"],
  [1, "amount"],
  [2, "to"],
  [3, "amount-to"],
  [4, "from"],
  [5, "amount-from"],
  [6, "from-to"],
  [7, "amount-from-to"]
]);

function fixedDisclosure({ plane, policy, disclosedFieldBitmap, assetDenom = "uclair" }) {
  const senderSpend = derivePubKeyFromScalar(17n);
  const senderView = derivePubKeyFromScalar(19n);
  const recipientSpend = derivePubKeyFromScalar(23n);
  const recipientView = derivePubKeyFromScalar(29n);
  return {
    plane,
    outputIndex: 0,
    policy,
    disclosedFieldBitmap,
    commitment: 101n,
    amount: 7n,
    assetID: computeAssetIdV1(assetDenom),
    senderSpendKeyX: plane === 1 && (policy & 4) === 0 ? 0n : senderSpend.x,
    senderSpendKeyY: plane === 1 && (policy & 4) === 0 ? 0n : senderSpend.y,
    senderViewKeyX: plane === 1 && (policy & 4) === 0 ? 0n : senderView.x,
    senderViewKeyY: plane === 1 && (policy & 4) === 0 ? 0n : senderView.y,
    recipientSpendKeyX: plane === 1 && (policy & 2) === 0 ? 0n : recipientSpend.x,
    recipientSpendKeyY: plane === 1 && (policy & 2) === 0 ? 0n : recipientSpend.y,
    recipientViewKeyX: plane === 1 && (policy & 2) === 0 ? 0n : recipientView.x,
    recipientViewKeyY: plane === 1 && (policy & 2) === 0 ? 0n : recipientView.y,
    disclosureBlinding: 13n
  };
}

test("fixed public disclosure rejects a full plane and an unbound asset denomination", () => {
  const full = fixedDisclosure({ plane: 2, policy: 0xffffffff, disclosedFieldBitmap: 7 });
  assert.throws(() => publicPayloadReport(Buffer.from(marshalDisclosurePlaintextV1(full)).toString("hex")));

  const user = fixedDisclosure({ plane: 1, policy: 1, disclosedFieldBitmap: 1 });
  assert.throws(
    () => publicPayloadReport(Buffer.from(marshalDisclosurePlaintextV1(user)).toString("hex"), "", "", { assetDenom: "uatom" }),
    /asset denom/
  );
});

test("fixed disclosure decoders reject legacy JSON, raw ciphertext, wrong kinds, and trailing bytes", () => {
  const legacyJson = Buffer.from(JSON.stringify({
    version: "v4",
    plane: "user",
    policy: 0,
    output_index: 0,
    commitment_hex: "00".repeat(32),
    disclosure_digest_hex: "00".repeat(32)
  }), "utf8");
  assert.throws(
    () => publicPayloadReport(legacyJson.toString("hex")),
    /DisclosurePlaintextV1 must be exactly/
  );

  const user = fixedDisclosure({ plane: 1, policy: 1, disclosedFieldBitmap: 1 });
  const userPlaintext = Buffer.from(marshalDisclosurePlaintextV1(user));
  assert.throws(
    () => publicPayloadReport(Buffer.concat([userPlaintext, Buffer.of(0)]).toString("hex")),
    /DisclosurePlaintextV1 must be exactly/
  );

  const legacyScalar = 31n;
  const legacyTarget = derivePubKeyFromScalar(legacyScalar);
  const legacyCiphertext = asymEncrypt(legacyJson, legacyTarget);
  const legacyEvent = {
    event_type: "shielded_transfer",
    attributes: [
      { key: "user_disclosure_mode", value: userDisclosureModeRecipientEncrypted },
      { key: "user_disclosure_target_pubkey", value: packPointHex(legacyTarget) },
      { key: "user_disclosure_payload", value: Buffer.from(legacyCiphertext).toString("hex") }
    ]
  };
  assert.throws(
    () => decodeUserDisclosureFromEvent(legacyEvent, legacyScalar, packPointHex(legacyTarget)),
    /encrypted envelope/
  );

  const full = fixedDisclosure({ plane: 2, policy: 0xffffffff, disclosedFieldBitmap: 7 });
  const selfScalar = 37n;
  const wrongKindPayload = encryptDisclosureV1(
    full,
    derivePubKeyFromScalar(selfScalar),
    encryptedEnvelopeKindV1.auditDisclosure
  );
  const wrongKindEvent = {
    event_type: "shielded_transfer",
    attributes: [{
      key: "self_view_disclosure_payload",
      value: Buffer.from(wrongKindPayload).toString("hex")
    }]
  };
  assert.throws(
    () => decodeSelfViewDisclosureFromEvent(wrongKindEvent, selfScalar),
    /encrypted envelope kind mismatch/
  );
});

function transferDisclosureEvent(payload, txHash = "AABBCC") {
  return {
    event_type: "shielded_transfer",
    tx_hash_hex: txHash,
    attributes: [
      { key: "user_disclosure_mode", value: userDisclosureModeRecipientEncrypted },
      { key: "user_disclosure_target_pubkey", value: payload.user_disclosure_target_pubkey_hex },
      { key: "user_disclosure_digest", value: payload.user_disclosure_digest_hex },
      { key: "user_disclosure_payload", value: payload.user_disclosure_payload_hex },
      { key: "audit_disclosure_target_pubkey", value: payload.audit_disclosure_target_pubkey_hex },
      { key: "audit_disclosure_digest", value: payload.audit_disclosure_digest_hex },
      { key: "audit_disclosure_payload", value: payload.audit_disclosure_payload_hex },
      { key: "self_view_disclosure_digest", value: payload.self_view_disclosure_digest_hex },
      { key: "self_view_disclosure_payload", value: payload.self_view_disclosure_payload_hex }
    ]
  };
}

function validatedTransferScanOutput(payload, {
  userPrivacyPolicy = payload.user_privacy_policy,
  txHash = new Uint8Array(32).fill(0xab)
} = {}) {
  const summary = {
    height: 10,
    globalSequence: 4,
    txHash,
    eventType: "shielded_transfer",
    nullifiers: payload.inputs.map(input => bytesFromHex(input.nullifier_hex)),
    outputCount: 2,
    effectId: new Uint8Array(),
    circuitSetId: "privacy-note-v1",
    payloadVersion: "privacy-fixed-v1",
    scanSchemaVersion: "privacy-scan-v2",
    auditKeyId: "",
    auditKeyEpoch: 0,
    auditTargetPubkey: bytesFromHex(payload.audit_disclosure_target_pubkey_hex)
  };
  const outputs = payload.outputs.map((output, outputIndex) => ({
    height: summary.height,
    globalSequence: summary.globalSequence,
    outputIndex,
    effectId: summary.effectId,
    txHash,
    eventType: summary.eventType,
    circuitSetId: summary.circuitSetId,
    payloadVersion: summary.payloadVersion,
    scanSchemaVersion: summary.scanSchemaVersion,
    auditKeyId: summary.auditKeyId,
    auditKeyEpoch: summary.auditKeyEpoch,
    auditTargetPubkey: summary.auditTargetPubkey,
    commitment: bytesFromHex(output.commitment_hex),
    ciphertext: bytesFromHex(payload.cipher_text_hexes[outputIndex]),
    viewTag: bytesFromHex(payload.view_tag_hexes[outputIndex]),
    leafIndexFound: true,
    leafIndex: outputIndex,
    userPrivacyPolicy: outputIndex === 0 ? userPrivacyPolicy : 0,
    userDisclosureMode: outputIndex === 0
      ? "USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED"
      : "",
    userDisclosureDigest: outputIndex === 0
      ? bytesFromHex(payload.user_disclosure_digest_hex)
      : new Uint8Array(),
    userDisclosureTargetPubkey: outputIndex === 0
      ? bytesFromHex(payload.user_disclosure_target_pubkey_hex)
      : new Uint8Array(),
    userDisclosurePayload: outputIndex === 0
      ? bytesFromHex(payload.user_disclosure_payload_hex)
      : new Uint8Array(),
    fullDisclosureDigest: outputIndex === 0
      ? bytesFromHex(payload.audit_disclosure_digest_hex)
      : new Uint8Array(),
    auditDisclosurePayload: outputIndex === 0
      ? bytesFromHex(payload.audit_disclosure_payload_hex)
      : new Uint8Array(),
    selfViewDisclosurePayload: outputIndex === 0
      ? bytesFromHex(payload.self_view_disclosure_payload_hex)
      : new Uint8Array()
  }));
  return validatePrivacyScanPageV2({
    scanSchemaVersion: summary.scanSchemaVersion,
    summaries: [summary],
    outputs,
    nextCursor: { height: summary.height, globalSequence: summary.globalSequence, outputIndex: 1 },
    hasMore: false
  }).outputs[0];
}

function compactReport(report) {
  return {
    plane: report.plane,
    policy: policyLabels.get(Number(report.payload.policy)) || report.policy,
    output_index: report.output_index,
    commitment_hex: report.commitment_hex,
    digest_hex: report.digest_hex,
    verified: report.verified,
    amount: report.amount,
    ...(report.asset_denom ? { asset_denom: report.asset_denom } : {}),
    from: report.from,
    to: report.to
  };
}

function expectedDisclosure(summary) {
  return {
    plane: summary.plane,
    policy: summary.policy,
    output_index: summary.output_index,
    commitment_hex: summary.commitment_hex,
    digest_hex: summary.digest_hex,
    verified: summary.verified,
    amount: summary.amount,
    ...(summary.asset_denom ? { asset_denom: summary.asset_denom } : {}),
    from: summary.from_shielded_address,
    to: summary.to_shielded_address
  };
}

function typedTransferRecipientOutput(payload, txHashHex = "aa".repeat(32)) {
  const txHash = Buffer.from(txHashHex, "hex");
  const auditTarget = Buffer.from(payload.audit_disclosure_target_pubkey_hex, "hex");
  const summary = {
    height: 12,
    globalSequence: 5,
    txHash,
    eventType: "shielded_transfer",
    nullifiers: payload.inputs.map(input => Buffer.from(input.nullifier_hex, "hex")),
    outputCount: 2,
    circuitSetId: "privacy-note-v1",
    payloadVersion: "privacy-fixed-v1",
    scanSchemaVersion: "privacy-scan-v2",
    auditTargetPubkey: auditTarget
  };
  const common = {
    height: summary.height,
    globalSequence: summary.globalSequence,
    txHash,
    eventType: summary.eventType,
    circuitSetId: summary.circuitSetId,
    payloadVersion: summary.payloadVersion,
    scanSchemaVersion: summary.scanSchemaVersion,
    auditTargetPubkey: auditTarget,
    leafIndexFound: true
  };
  const outputs = [{
    ...common,
    outputIndex: 0,
    commitment: Buffer.from(payload.outputs[0].commitment_hex, "hex"),
    ciphertext: Buffer.from(payload.cipher_text_hexes[0], "hex"),
    viewTag: Buffer.from(payload.view_tag_hexes[0], "hex"),
    leafIndex: 20,
    userPrivacyPolicy: payload.user_privacy_policy,
    userDisclosureMode: "USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED",
    userDisclosureDigest: Buffer.from(payload.user_disclosure_digest_hex, "hex"),
    userDisclosureTargetPubkey: Buffer.from(payload.user_disclosure_target_pubkey_hex, "hex"),
    userDisclosurePayload: Buffer.from(payload.user_disclosure_payload_hex, "hex"),
    fullDisclosureDigest: Buffer.from(payload.audit_disclosure_digest_hex, "hex"),
    auditDisclosurePayload: Buffer.from(payload.audit_disclosure_payload_hex, "hex"),
    selfViewDisclosurePayload: Buffer.from(payload.self_view_disclosure_payload_hex, "hex")
  }, {
    ...common,
    outputIndex: 1,
    commitment: Buffer.from(payload.outputs[1].commitment_hex, "hex"),
    ciphertext: Buffer.from(payload.cipher_text_hexes[1], "hex"),
    viewTag: Buffer.from(payload.view_tag_hexes[1], "hex"),
    leafIndex: 21
  }];
  return validatePrivacyScanPageV2({
    scanSchemaVersion: "privacy-scan-v2",
    summaries: [summary],
    outputs,
    nextCursor: { height: 12, globalSequence: 5, outputIndex: 1 },
    hasMore: false
  }).outputs[0];
}

test("disclosure asset validation uses the NoteV1 asset-ID derivation", () => {
  const assetIdHex = computeAssetIdV1("uclair").toString(16).padStart(64, "0");
  assert.deepEqual(
    disclosureAmountAndAsset({ amount: "7", asset_id_hex: assetIdHex, asset_denom: "uclair" }),
    { amount: 7n, assetId: computeAssetIdV1("uclair"), assetDenom: "uclair" }
  );
});

test("user public disclosure payload verifies against the golden vector", fixtureTestOptions, () => {
  const vectors = readFixture("privacy_wallet_golden_vectors.json");
  const report = publicPayloadReport(
    vectors.disclosure.payload_plaintext_hex,
    vectors.disclosure.digest_hex,
    vectors.scan.tx_hash_hex,
    { shieldedPrefix: "clairs", assetDenom: vectors.note.denom }
  );
  const compact = compactReport(report);

  assert.equal(compact.plane, "user");
  assert.equal(compact.policy, vectors.disclosure.policy);
  assert.equal(compact.verified, true);
  assert.equal(compact.amount, vectors.note.amount);
  assert.equal(compact.asset_denom, vectors.note.denom);
  assert.equal(compact.from, vectors.sender.shielded_address);
  assert.equal(compact.to, vectors.recipient.shielded_address);
  assert.equal(compact.digest_hex, vectors.disclosure.digest_hex);
});

test("user recipient-encrypted disclosure decodes and verifies against the send-capable fixture", fixtureTestOptions, () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const flow = readFixture("privacy_send_capable_reference_flow.json");
  const payload = examples.transfer.request.payload;
  const report = decodeUserDisclosureFromEvent(
    transferDisclosureEvent(payload),
    79n,
    payload.user_disclosure_target_pubkey_hex,
    "AABBCC",
    { shieldedPrefix: "clairs" }
  );

  assert.deepEqual(compactReport(report), expectedDisclosure(flow.transfer.user_disclosure));
});

test("audit disclosure decodes and verifies against the send-capable fixture", fixtureTestOptions, () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const flow = readFixture("privacy_send_capable_reference_flow.json");
  const report = decodeAuditDisclosureFromEvent(
    transferDisclosureEvent(examples.transfer.request.payload),
    83n,
    "AABBCC",
    { shieldedPrefix: "clairs" }
  );

  assert.deepEqual(compactReport(report), expectedDisclosure(flow.transfer.audit_disclosure));
});

test("self-view disclosure decodes and verifies against the send-capable fixture", fixtureTestOptions, () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const flow = readFixture("privacy_send_capable_reference_flow.json");
  const payload = examples.transfer.request.payload;
  const report = decodeSelfViewDisclosureFromEvent(
    transferDisclosureEvent(payload),
    89n,
    "AABBCC",
    { shieldedPrefix: "clairs" }
  );

  assert.deepEqual(compactReport(report), expectedDisclosure(flow.transfer.self_view_disclosure));
});

test("direct transfer typed-scan disclosure decoders verify user, audit, and self-view planes", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const flow = readFixture("privacy_send_capable_reference_flow.json");
  const payload = examples.transfer.request.payload;
  const output = validatedTransferScanOutput(payload);

  const user = decodeUserDisclosureFromScanOutput(output, {
    disclosureScalar: 79n,
    disclosurePubKeyHex: payload.user_disclosure_target_pubkey_hex,
    shieldedPrefix: "clairs"
  });
  const audit = decodeAuditDisclosureFromScanOutput(output, {
    disclosureScalar: 83n,
    shieldedPrefix: "clairs"
  });
  const selfView = decodeSelfViewDisclosureFromScanOutput(output, {
    disclosureScalar: 89n,
    shieldedPrefix: "clairs"
  });

  assert.deepEqual(compactReport(user), expectedDisclosure(flow.transfer.user_disclosure));
  assert.deepEqual(compactReport(audit), expectedDisclosure(flow.transfer.audit_disclosure));
  assert.deepEqual(compactReport(selfView), expectedDisclosure(flow.transfer.self_view_disclosure));
  assert.equal(user.verification.typed_scan_output, true);
  assert.equal(audit.verification.typed_scan_output, true);
  assert.equal(selfView.verification.typed_scan_output, true);
  assert.throws(
    () => decodeUserDisclosureFromScanOutput(output, {
      disclosureScalar: 79n,
      disclosurePubKeyHex: payload.user_disclosure_target_pubkey_hex,
      txHash: "cd".repeat(32)
    }),
    /transaction hash does not match/
  );
  assert.throws(
    () => decodeUserDisclosureFromScanOutput(
      validatedTransferScanOutput(payload, { txHash: new Uint8Array() }),
      {
        disclosureScalar: 79n,
        disclosurePubKeyHex: payload.user_disclosure_target_pubkey_hex,
        txHash: "ab".repeat(32)
      }
    ),
    /does not carry a transaction hash/
  );
  assert.throws(
    () => decodeUserDisclosureFromScanOutput(
      validatedTransferScanOutput(payload, {
        userPrivacyPolicy: payload.user_privacy_policy === 1 ? 2 : 1
      }),
      {
        disclosureScalar: 79n,
        disclosurePubKeyHex: payload.user_disclosure_target_pubkey_hex
      }
    ),
    /policy does not match/
  );
  assert.throws(
    () => decodeUserDisclosureFromScanOutput({ ...output }, {
      disclosureScalar: 79n,
      disclosurePubKeyHex: payload.user_disclosure_target_pubkey_hex
    }),
    /must come from validatePrivacyScanPageV2/
  );
  const inheritedOutput = Object.create(output);
  Object.defineProperty(inheritedOutput, "tx_hash", {
    value: new Uint8Array(32).fill(0xcd),
    enumerable: true
  });
  assert.throws(
    () => decodeUserDisclosureFromScanOutput(inheritedOutput, {
      disclosureScalar: 79n,
      disclosurePubKeyHex: payload.user_disclosure_target_pubkey_hex
    }),
    /must come from validatePrivacyScanPageV2/
  );
  const mutatedOutput = validatedTransferScanOutput(payload);
  mutatedOutput.full_disclosure_digest[0] ^= 0xff;
  assert.throws(
    () => decodeAuditDisclosureFromScanOutput(mutatedOutput, {
      disclosureScalar: 83n,
      shieldedPrefix: "clairs"
    }),
    /must come from validatePrivacyScanPageV2/
  );

  const client = createClairveilClient({
    rest: "http://127.0.0.1:1317",
    rpc: "http://127.0.0.1:26657",
    chainId: "clairveil-test-1",
    accountPrefix: "clair",
    shieldedPrefix: "clairs"
  });
  const wrapped = await client.decodeUserDisclosure({
    output,
    disclosureScalar: 79n,
    disclosurePubKeyHex: payload.user_disclosure_target_pubkey_hex
  });
  const wrappedAudit = await client.decodeAuditDisclosure({
    output,
    disclosurePrivKeyHex: 83n.toString(16).padStart(64, "0")
  });
  const wrappedSelfView = await client.decodeSelfViewDisclosure({
    output,
    disclosureScalar: 89n
  });
  assert.equal(wrapped.digest_hex, user.digest_hex);
  assert.equal(wrappedAudit.digest_hex, audit.digest_hex);
  assert.equal(wrappedSelfView.digest_hex, selfView.digest_hex);
  await assert.rejects(
    () => client.decodeUserDisclosure({
      output,
      scanOutput: validatedTransferScanOutput(payload),
      disclosureScalar: 79n,
      disclosurePubKeyHex: payload.user_disclosure_target_pubkey_hex
    }),
    /disclosure output aliases conflict/
  );
});

test("Cosmos client decodes self-view disclosure through the high-level API", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const flow = readFixture("privacy_send_capable_reference_flow.json");
  const payload = examples.transfer.request.payload;
  const client = createClairveilClient({
    rest: "http://127.0.0.1:1317",
    rpc: "http://127.0.0.1:26657",
    chainId: "clairveil-local-1",
    accountPrefix: "clair",
    shieldedPrefix: "clairs"
  });
  client.findPrivacyEventByTxHash = async txHash => transferDisclosureEvent(payload, txHash);

  const report = await client.decodeSelfViewDisclosure({
    txHash: "AABBCC",
    disclosureScalar: 89n
  });

  assert.deepEqual(compactReport(report), {
    ...expectedDisclosure(flow.transfer.self_view_disclosure),
    asset_denom: "uclair"
  });
});

test("direct disclosure decoders consume validated typed scan output without raw event lookup", fixtureTestOptions, async () => {
  const examples = readFixture("privacy_prover_example_bundle.json");
  const flow = readFixture("privacy_send_capable_reference_flow.json");
  const payload = examples.transfer.request.payload;
  const txHash = "aa".repeat(32);
  const output = typedTransferRecipientOutput(payload, txHash);

  assert.deepEqual(
    compactReport(decodeUserDisclosureFromScanOutput(
      output,
      79n,
      payload.user_disclosure_target_pubkey_hex,
      txHash,
      { shieldedPrefix: "clairs" }
    )),
    expectedDisclosure(flow.transfer.user_disclosure)
  );
  assert.deepEqual(
    compactReport(decodeAuditDisclosureFromScanOutput(output, 83n, txHash, { shieldedPrefix: "clairs" })),
    expectedDisclosure(flow.transfer.audit_disclosure)
  );
  assert.deepEqual(
    compactReport(decodeSelfViewDisclosureFromScanOutput(output, 89n, txHash, { shieldedPrefix: "clairs" })),
    expectedDisclosure(flow.transfer.self_view_disclosure)
  );

  const client = createClairveilClient({
    rest: "http://127.0.0.1:1317",
    rpc: "http://127.0.0.1:26657",
    chainId: "clairveil-local-1",
    shieldedPrefix: "clairs"
  });
  client.findPrivacyEventByTxHash = async () => {
    throw new Error("validated typed output must bypass raw event lookup");
  };
  const selfView = await client.decodeSelfViewDisclosure({
    output,
    txHash,
    disclosureScalar: 89n
  });
  assert.equal(selfView.verified, true);
  await assert.rejects(
    () => client.decodeSelfViewDisclosure({
      output,
      txHash: "bb".repeat(32),
      disclosureScalar: 89n
    }),
    /transaction hash does not match/
  );
});

test("Cosmos disclosure wrappers retain an explicitly verified non-default asset denom", async () => {
  const assetDenom = "uatom";
  const user = fixedDisclosure({ plane: 1, policy: 1, disclosedFieldBitmap: 1, assetDenom });
  const full = fixedDisclosure({ plane: 2, policy: 0xffffffff, disclosedFieldBitmap: 7, assetDenom });
  const selfScalar = 43n;
  const auditScalar = 47n;
  const events = new Map([
    ["USER", {
      event_type: "shielded_transfer",
      attributes: [
        { key: "user_disclosure_mode", value: "USER_DISCLOSURE_MODE_PUBLIC" },
        { key: "user_disclosure_payload", value: Buffer.from(marshalDisclosurePlaintextV1(user)).toString("hex") }
      ]
    }],
    ["SELF", {
      event_type: "shielded_transfer",
      attributes: [{
        key: "self_view_disclosure_payload",
        value: Buffer.from(encryptDisclosureV1(full, derivePubKeyFromScalar(selfScalar), encryptedEnvelopeKindV1.selfViewDisclosure)).toString("hex")
      }]
    }],
    ["AUDIT", {
      event_type: "shielded_transfer",
      attributes: [{
        key: "audit_disclosure_payload",
        value: Buffer.from(encryptDisclosureV1(full, derivePubKeyFromScalar(auditScalar), encryptedEnvelopeKindV1.auditDisclosure)).toString("hex")
      }]
    }]
  ]);
  const client = createClairveilClient({
    rest: "http://127.0.0.1:1317",
    rpc: "http://127.0.0.1:26657",
    chainId: "clairveil-local-1",
    defaultDenom: "uclair"
  });
  client.findPrivacyEventByTxHash = async txHash => events.get(txHash);

  const [userReport, selfReport, auditReport] = await Promise.all([
    client.decodeUserDisclosure({ txHash: "USER", assetDenom }),
    client.decodeSelfViewDisclosure({ txHash: "SELF", disclosureScalar: selfScalar, asset_denom: assetDenom }),
    client.decodeAuditDisclosure({ txHash: "AUDIT", disclosurePrivKeyHex: auditScalar.toString(16).padStart(64, "0"), assetDenom })
  ]);
  assert.deepEqual([userReport.asset_denom, selfReport.asset_denom, auditReport.asset_denom], [assetDenom, assetDenom, assetDenom]);
  await assert.rejects(
    () => client.decodeUserDisclosure({ txHash: "USER", assetDenom, asset_denom: "uclair" }),
    /assetDenom aliases conflict/
  );
});
