import test from "node:test";
import assert from "node:assert/strict";
import {
  canonicalFieldBytes,
  computeNoteCommitmentV1,
  derivePubKeyFromScalar,
  deriveSpendKeys,
  deriveViewKeys,
  packPoint
} from "clairveiljs/core";
import {
  activeCircuitSetIdV1,
  encryptDisclosureV1,
  encryptDepositNoteV1,
  encryptedEnvelopeKindV1,
  encryptNoteForTransferV1,
  privacyFixedV1
} from "clairveiljs/protocol-v1";
import {
  createPrivacyScanValidationStateV2,
  processPrivacyScanOutputV2,
  processPrivacyScanPageV2,
  validatePrivacyScanPageV2
} from "clairveiljs/scan";
import { createClairveilClient } from "clairveiljs/cosmos";

const scanSchemaVersion = "privacy-scan-v2";

function noteForScan(index = 0) {
  const spend = derivePubKeyFromScalar(BigInt(11 + index * 2));
  const view = derivePubKeyFromScalar(BigInt(17 + index * 2));
  return {
    receiverSpendPubKeyX: spend.x,
    receiverSpendPubKeyY: spend.y,
    receiverViewPubKeyX: view.x,
    receiverViewPubKeyY: view.y,
    amount: BigInt(5 + index),
    assetID: 1n,
    randomness: BigInt(31 + index),
    memo: `scan-${index}`
  };
}

function baseSummary(eventType, outputCount, overrides = {}) {
  return {
    height: 10,
    globalSequence: 4,
    txHash: new Uint8Array(32).fill(7),
    eventType,
    nullifiers: [],
    outputCount,
    circuitSetId: activeCircuitSetIdV1,
    payloadVersion: privacyFixedV1,
    scanSchemaVersion,
    ...overrides
  };
}

function validDepositPage() {
  const note = noteForScan();
  const commitment = canonicalFieldBytes(computeNoteCommitmentV1(note));
  const encryptedNote = encryptDepositNoteV1(note, new Uint8Array(32).fill(5));
  const summary = baseSummary("deposit", 1);
  return {
    scanSchemaVersion,
    summaries: [summary],
    outputs: [{
      height: summary.height,
      globalSequence: summary.globalSequence,
      outputIndex: 0,
      commitment,
      encryptedNote,
      leafIndexFound: true,
      leafIndex: 0,
      txHash: summary.txHash,
      eventType: summary.eventType,
      circuitSetId: summary.circuitSetId,
      payloadVersion: summary.payloadVersion,
      scanSchemaVersion
    }],
    nextCursor: { height: summary.height, globalSequence: summary.globalSequence, outputIndex: 0 },
    hasMore: false
  };
}

function validBatchOutput(index, auditTarget, selfViewEnabled, note = noteForScan(index + 1)) {
  const commitmentValue = computeNoteCommitmentV1(note);
  const commitment = canonicalFieldBytes(commitmentValue);
  const encrypted = encryptNoteForTransferV1(note, commitment, index);
  const disclosure = {
    plane: 2,
    outputIndex: index,
    policy: 0xffffffff,
    disclosedFieldBitmap: 7,
    commitment: commitmentValue,
    amount: note.amount,
    assetID: note.assetID,
    senderSpendKeyX: note.receiverSpendPubKeyX,
    senderSpendKeyY: note.receiverSpendPubKeyY,
    senderViewKeyX: note.receiverViewPubKeyX,
    senderViewKeyY: note.receiverViewPubKeyY,
    recipientSpendKeyX: note.receiverSpendPubKeyX,
    recipientSpendKeyY: note.receiverSpendPubKeyY,
    recipientViewKeyX: note.receiverViewPubKeyX,
    recipientViewKeyY: note.receiverViewPubKeyY,
    disclosureBlinding: BigInt(71 + index)
  };
  return {
    commitment,
    ciphertext: encrypted.ciphertext,
    viewTag: encrypted.viewTag,
    leafIndexFound: true,
    leafIndex: index,
    userPrivacyPolicy: 0,
    userDisclosureMode: "USER_DISCLOSURE_MODE_NONE",
    fullDisclosureDigest: canonicalFieldBytes(BigInt(101 + index)),
    auditDisclosurePayload: encryptDisclosureV1(disclosure, auditTarget, encryptedEnvelopeKindV1.auditDisclosure),
    selfViewDisclosurePayload: selfViewEnabled
      ? encryptDisclosureV1(disclosure, auditTarget, encryptedEnvelopeKindV1.selfViewDisclosure)
      : new Uint8Array()
  };
}

function validBatchPage({ selfViewEnabled = true, notes = null } = {}) {
  const auditTarget = derivePubKeyFromScalar(97n);
  const summary = baseSummary("batch_transfer", 2, {
    nullifiers: [canonicalFieldBytes(53n)],
    effectId: canonicalFieldBytes(59n),
    auditKeyId: "audit-key-1",
    auditKeyEpoch: 1,
    auditTargetPubkey: packPoint(auditTarget)
  });
  const outputs = [0, 1].map(index => ({
    height: summary.height,
    globalSequence: summary.globalSequence,
    outputIndex: index,
    effectId: summary.effectId,
    txHash: summary.txHash,
    eventType: summary.eventType,
    circuitSetId: summary.circuitSetId,
    payloadVersion: summary.payloadVersion,
    scanSchemaVersion,
    auditKeyId: summary.auditKeyId,
    auditKeyEpoch: summary.auditKeyEpoch,
    auditTargetPubkey: summary.auditTargetPubkey,
    ...validBatchOutput(index, auditTarget, selfViewEnabled, notes?.[index])
  }));
  return {
    scanSchemaVersion,
    summaries: [summary],
    outputs,
    nextCursor: { height: summary.height, globalSequence: summary.globalSequence, outputIndex: 1 },
    hasMore: false
  };
}

test("typed privacy scan rejects event-specific audit and disclosure sentinel violations", () => {
  const deposit = validDepositPage();
  assert.doesNotThrow(() => validatePrivacyScanPageV2(deposit));
  assert.throws(
    () => validatePrivacyScanPageV2({
      ...deposit,
      summaries: [{ ...deposit.summaries[0], auditKeyId: "unexpected-audit" }]
    }),
    /zero audit sentinel/
  );
  assert.throws(
    () => validatePrivacyScanPageV2({
      ...deposit,
      outputs: [{ ...deposit.outputs[0], fullDisclosureDigest: canonicalFieldBytes(1n) }]
    }),
    /exact zero disclosure sentinels/
  );

  const withdraw = {
    scanSchemaVersion,
    summaries: [baseSummary("withdraw", 0)],
    outputs: [],
    nextCursor: { height: 10, globalSequence: 4, outputIndex: 0 },
    hasMore: false
  };
  assert.throws(() => validatePrivacyScanPageV2(withdraw), /invalid withdraw framing/);

  const shieldedTransfer = {
    scanSchemaVersion,
    summaries: [baseSummary("shielded_transfer", 2, {
      nullifiers: [canonicalFieldBytes(3n), canonicalFieldBytes(5n)]
    })],
    outputs: [],
    nextCursor: { height: 0, globalSequence: 0, outputIndex: 0 },
    hasMore: false
  };
  assert.throws(() => validatePrivacyScanPageV2(shieldedTransfer), /canonical non-identity point/);
});

test("typed privacy scan decryptors only accept validator-issued outputs and pages", () => {
  const rawPage = validDepositPage();
  const rootSeed = new Uint8Array(32).fill(5);
  assert.throws(
    () => processPrivacyScanOutputV2(rawPage.outputs[0], { rootSeed }),
    /must be issued by validatePrivacyScanPageV2/
  );
  assert.throws(
    () => processPrivacyScanPageV2(rawPage, { rootSeed }),
    /must be issued by validatePrivacyScanPageV2/
  );

  const page = validatePrivacyScanPageV2(rawPage);
  assert.equal(processPrivacyScanOutputV2(page.outputs[0], { rootSeed })?.note.amount, 5n);
  assert.equal(processPrivacyScanPageV2(page, { rootSeed }).length, 1);
});

test("direct typed scan transfer decryption derives missing root-seed scalars", () => {
  const rootSeed = new Uint8Array(32).fill(23);
  const spend = deriveSpendKeys(rootSeed).pubKey;
  const view = deriveViewKeys(rootSeed).pubKey;
  const owned = {
    ...noteForScan(7),
    receiverSpendPubKeyX: spend.x,
    receiverSpendPubKeyY: spend.y,
    receiverViewPubKeyX: view.x,
    receiverViewPubKeyY: view.y
  };
  const page = validatePrivacyScanPageV2(validBatchPage({ notes: [owned, noteForScan(8)] }));
  assert.equal(processPrivacyScanOutputV2(page.outputs[0], { rootSeed })?.note.amount, owned.amount);
});

test("typed privacy scan rejects mixed batch self-view records and terminal output prefixes", () => {
  const batch = validBatchPage();
  assert.doesNotThrow(() => validatePrivacyScanPageV2(batch));

  const mixedSelfView = {
    ...batch,
    outputs: [batch.outputs[0], { ...batch.outputs[1], selfViewDisclosurePayload: new Uint8Array() }]
  };
  assert.throws(() => validatePrivacyScanPageV2(mixedSelfView), /self-view disclosure must be all-or-none/);

  const prefix = {
    ...batch,
    outputs: [batch.outputs[0]],
    nextCursor: { height: 10, globalSequence: 4, outputIndex: 0 }
  };
  assert.throws(() => validatePrivacyScanPageV2(prefix), /completed page ends with an incomplete output event/);
  assert.doesNotThrow(() => validatePrivacyScanPageV2({ ...prefix, hasMore: true }));
  assert.throws(
    () => validatePrivacyScanPageV2({
      ...batch,
      outputs: [],
      nextCursor: { height: 0, globalSequence: 0, outputIndex: 0 }
    }),
    /completed page omits an output from a summarized event/
  );
});

test("typed privacy scan accepts SHA-256 batch effect IDs outside the BN254 field", () => {
  const batch = validBatchPage();
  const effectId = new Uint8Array(32).fill(0xff);
  effectId[31] = 1;
  assert.doesNotThrow(() => validatePrivacyScanPageV2({
    ...batch,
    summaries: [{ ...batch.summaries[0], effectId }],
    outputs: batch.outputs.map(output => ({ ...output, effectId }))
  }));
});

test("typed privacy scan validation state binds batch self-view disclosure across cursor pages", () => {
  const batch = validBatchPage();
  const firstPage = {
    ...batch,
    outputs: [batch.outputs[0]],
    nextCursor: { height: 10, globalSequence: 4, outputIndex: 0 },
    hasMore: true
  };
  const finalPage = {
    ...batch,
    outputs: [batch.outputs[1]],
    hasMore: false
  };
  const state = createPrivacyScanValidationStateV2();
  const finalRequest = { after: firstPage.nextCursor, validationState: state };
  assert.doesNotThrow(() => validatePrivacyScanPageV2(firstPage, { validationState: state }));
  assert.equal(state.batch_self_view_by_event.get("10/4"), true);
  assert.throws(
    () => validatePrivacyScanPageV2({
      ...finalPage,
      outputs: [{ ...finalPage.outputs[0], selfViewDisclosurePayload: new Uint8Array() }]
    }, finalRequest),
    /self-view disclosure must be all-or-none/
  );
  assert.doesNotThrow(() => validatePrivacyScanPageV2(finalPage, finalRequest));
  assert.equal(state.batch_self_view_by_event.size, 0);
});

test("Cosmos pagination retains batch self-view validation state", async () => {
  const batch = validBatchPage();
  const pages = [{
    ...batch,
    outputs: [batch.outputs[0]],
    nextCursor: { height: 10, globalSequence: 4, outputIndex: 0 },
    hasMore: true
  }, {
    ...batch,
    outputs: [{ ...batch.outputs[1], selfViewDisclosurePayload: new Uint8Array() }],
    hasMore: false
  }];
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-test-1"
  });
  client.fetchPrivacyScan = async () => pages.shift();
  await assert.rejects(
    () => client.scanNotes({ rootSeed: new Uint8Array(32).fill(9), maxPages: 2 }),
    /self-view disclosure must be all-or-none/
  );
});

test("Cosmos queryPrivacyScan returns only validator-issued typed pages", async () => {
  const page = validBatchPage();
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-test-1"
  });
  const requests = [];
  client.fetchPrivacyScan = async request => {
    requests.push(request);
    return page;
  };

  const validated = await client.queryPrivacyScan({ outputLimit: 2 });
  assert.equal(validated.scan_schema_version, "privacy-scan-v2");
  assert.equal(validated.outputs.length, 2);
  assert.equal(requests[0].outputLimit, 2);

  client.fetchPrivacyScan = async () => ({ scanSchemaVersion: "privacy-scan-v1" });
  await assert.rejects(
    () => client.queryPrivacyScan(),
    /unsupported privacy scan schema version/
  );
});

test("durable privacy scan cursors retain partial batch validation across a restart", async () => {
  const batch = validBatchPage();
  const firstPage = {
    ...batch,
    outputs: [batch.outputs[0]],
    nextCursor: { height: 10, globalSequence: 4, outputIndex: 0 },
    hasMore: true
  };
  const finalPage = {
    ...batch,
    outputs: [{ ...batch.outputs[1], selfViewDisclosurePayload: new Uint8Array() }],
    hasMore: false
  };
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-test-1"
  });
  client.fetchPrivacyScan = async () => firstPage;
  const first = await client.scanNotes({ rootSeed: new Uint8Array(32).fill(9), maxPages: 1 });
  assert.deepEqual(first.scanCursor.validation_state, {
    version: "privacy-scan-validation-v2",
    batch_self_view_by_event: [{ event_key: "10/4", self_view_enabled: true }]
  });
  assert.deepEqual(first.nextScanOptions.validationStateSnapshot, first.scanCursor.validation_state);

  // JSON round-tripping is what a NoteStore/process restart does to the cursor.
  const resumed = JSON.parse(JSON.stringify(first.nextScanOptions));
  client.fetchPrivacyScan = async () => finalPage;
  await assert.rejects(
    () => client.scanNotes({ rootSeed: new Uint8Array(32).fill(9), ...resumed }),
    /self-view disclosure must be all-or-none/
  );
});
