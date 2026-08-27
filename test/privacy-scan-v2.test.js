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
  isValidatedPrivacyScanOutputV2,
  processPrivacyScanOutputV2,
  processPrivacyScanPageV2,
  restorePrivacyScanValidationStateV2,
  serializePrivacyScanValidationStateV2,
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

function validDepositEvent({ index = 0, height = 10, globalSequence = 4, txByte = 7, leafIndex = index } = {}) {
  const note = noteForScan(index);
  const commitment = canonicalFieldBytes(computeNoteCommitmentV1(note));
  const encryptedNote = encryptDepositNoteV1(note, new Uint8Array(32).fill(5));
  const summary = baseSummary("deposit", 1, {
    height,
    globalSequence,
    txHash: new Uint8Array(32).fill(txByte)
  });
  return {
    summary,
    output: {
      height: summary.height,
      globalSequence: summary.globalSequence,
      outputIndex: 0,
      commitment,
      encryptedNote,
      leafIndexFound: true,
      leafIndex,
      txHash: summary.txHash,
      eventType: summary.eventType,
      circuitSetId: summary.circuitSetId,
      payloadVersion: summary.payloadVersion,
      scanSchemaVersion
    }
  };
}

function typedScanResponse(base, overrides = {}) {
  const response = { ...base, ...overrides };
  return {
    scanSchemaVersion: response.scanSchemaVersion ?? scanSchemaVersion,
    summaries: response.summaries,
    outputs: response.outputs,
    nextCursor: response.nextCursor,
    hasMore: response.hasMore ?? false
  };
}

function validDepositPage() {
  const { summary, output } = validDepositEvent();
  return typedScanResponse({
    summaries: [summary],
    outputs: [output],
    nextCursor: { height: summary.height, globalSequence: summary.globalSequence, outputIndex: 0 }
  });
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

function validBatchPage({ selfViewEnabled = true, notes = null, outputCount = 2 } = {}) {
  const auditTarget = derivePubKeyFromScalar(97n);
  const summary = baseSummary("batch_transfer", outputCount, {
    nullifiers: [canonicalFieldBytes(53n)],
    effectId: canonicalFieldBytes(59n),
    auditKeyId: "audit-key-1",
    auditKeyEpoch: 1,
    auditTargetPubkey: packPoint(auditTarget)
  });
  const outputs = Array.from({ length: outputCount }, (_, index) => ({
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
  return typedScanResponse({
    summaries: [summary],
    outputs,
    nextCursor: {
      height: summary.height,
      globalSequence: summary.globalSequence,
      outputIndex: outputCount - 1
    }
  });
}

function partialBatchPage(batch, outputIndex = 0) {
  const output = batch.outputs[outputIndex];
  return typedScanResponse(batch, {
    outputs: [output],
    nextCursor: {
      height: output.height,
      globalSequence: output.globalSequence,
      outputIndex: output.outputIndex
    },
    hasMore: true
  });
}

function pendingBatchFixture(batchOptions) {
  const batch = validBatchPage(batchOptions);
  const firstPage = partialBatchPage(batch);
  const state = createPrivacyScanValidationStateV2();
  validatePrivacyScanPageV2(firstPage, { validationState: state });
  return { batch, firstPage, state };
}

function roundTripValidationState(state) {
  return restorePrivacyScanValidationStateV2(
    JSON.parse(JSON.stringify(serializePrivacyScanValidationStateV2(state)))
  );
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

  const inheritedOutput = Object.create(page.outputs[0]);
  Object.defineProperty(inheritedOutput, "tx_hash", {
    value: new Uint8Array(32).fill(0xff),
    enumerable: true
  });
  assert.equal(isValidatedPrivacyScanOutputV2(inheritedOutput), false);
  assert.throws(
    () => processPrivacyScanOutputV2(inheritedOutput, { rootSeed }),
    /must be issued by validatePrivacyScanPageV2/
  );

  const inheritedPage = Object.create(page);
  Object.defineProperty(inheritedPage, "outputs", {
    value: Object.freeze([]),
    enumerable: true
  });
  assert.throws(
    () => processPrivacyScanPageV2(inheritedPage, { rootSeed }),
    /must be issued by validatePrivacyScanPageV2/
  );

  const mutatedOutputPage = validatePrivacyScanPageV2(validDepositPage());
  mutatedOutputPage.outputs[0].commitment[0] ^= 0xff;
  assert.equal(isValidatedPrivacyScanOutputV2(mutatedOutputPage.outputs[0]), false);
  assert.throws(
    () => processPrivacyScanPageV2(mutatedOutputPage, { rootSeed }),
    /must be issued by validatePrivacyScanPageV2/
  );

  const mutatedSummaryPage = validatePrivacyScanPageV2(validDepositPage());
  mutatedSummaryPage.summaries[0].tx_hash[0] ^= 0xff;
  assert.throws(
    () => processPrivacyScanPageV2(mutatedSummaryPage, { rootSeed }),
    /must be issued by validatePrivacyScanPageV2/
  );
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

  const prefix = { ...partialBatchPage(batch), hasMore: false };
  assert.throws(() => validatePrivacyScanPageV2(prefix), /completed page ends with an incomplete output event/);
  assert.throws(
    () => validatePrivacyScanPageV2({ ...prefix, hasMore: true }),
    /partial page requires validation state/
  );
  assert.doesNotThrow(() => validatePrivacyScanPageV2(
    { ...prefix, hasMore: true },
    { validationState: createPrivacyScanValidationStateV2() }
  ));
  assert.throws(
    () => validatePrivacyScanPageV2({
      ...batch,
      outputs: [],
      nextCursor: { height: 0, globalSequence: 0, outputIndex: 0 }
    }),
    /completed page omits an output from a summarized event/
  );
});

test("typed privacy scan rejects a partial page that skips an earlier output-bearing summary", () => {
  const first = validDepositEvent();
  const second = validDepositEvent({ index: 1, height: 11, globalSequence: 5, txByte: 8, leafIndex: 1 });
  assert.throws(
    () => validatePrivacyScanPageV2(typedScanResponse({
      summaries: [first.summary, second.summary],
      outputs: [second.output],
      nextCursor: { height: second.summary.height, globalSequence: second.summary.globalSequence, outputIndex: 0 },
      hasMore: true
    })),
    /partial page omits an output from a summarized event/
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
  const firstPage = partialBatchPage(batch);
  const finalPage = typedScanResponse(batch, {
    outputs: [batch.outputs[1]],
    hasMore: false
  });
  const state = createPrivacyScanValidationStateV2();
  const finalRequest = { after: firstPage.nextCursor, validationState: state };
  assert.doesNotThrow(() => validatePrivacyScanPageV2(firstPage, { validationState: state }));
  assert.equal(state.batch_self_view_by_event.get("10/4"), true);
  assert.equal(state.pending_summary_by_event.get("10/4").output_count, 2);
  assert.throws(
    () => validatePrivacyScanPageV2({
      ...finalPage,
      outputs: [{ ...finalPage.outputs[0], selfViewDisclosurePayload: new Uint8Array() }]
    }, finalRequest),
    /self-view disclosure must be all-or-none/
  );
  assert.doesNotThrow(() => validatePrivacyScanPageV2(finalPage, finalRequest));
  assert.equal(state.batch_self_view_by_event.size, 0);
  assert.equal(state.pending_summary_by_event.size, 0);
});

test("typed privacy scan rejects a resumed summary that shrinks its original output count", () => {
  const { batch, firstPage, state } = pendingBatchFixture();

  assert.throws(
    () => validatePrivacyScanPageV2({
      ...batch,
      summaries: [{ ...batch.summaries[0], outputCount: 1 }],
      outputs: [],
      nextCursor: firstPage.nextCursor,
      hasMore: false
    }, { after: firstPage.nextCursor, validationState: state }),
    /does not match its pending summary identity/
  );
  assert.equal(state.pending_summary_by_event.get("10/4").output_count, 2);
});

test("typed privacy scan rejects a mid-event resume with missing or empty validation state", async () => {
  const changed = validBatchPage({ selfViewEnabled: false });
  const changedEffectId = canonicalFieldBytes(61n);
  const changedTxHash = new Uint8Array(32).fill(8);
  const summary = {
    ...changed.summaries[0],
    effectId: changedEffectId,
    txHash: changedTxHash
  };
  const resumedPage = {
    ...changed,
    summaries: [summary],
    outputs: [{
      ...changed.outputs[1],
      effectId: changedEffectId,
      txHash: changedTxHash
    }]
  };
  const after = { height: 10, globalSequence: 4, outputIndex: 0 };

  assert.throws(
    () => validatePrivacyScanPageV2(resumedPage, { after }),
    /mid-event resume requires pending summary validation state/
  );
  assert.throws(
    () => validatePrivacyScanPageV2(resumedPage, {
      after,
      validationState: createPrivacyScanValidationStateV2()
    }),
    /mid-event resume requires pending summary validation state/
  );

  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-test-1"
  });
  client.fetchPrivacyScan = async () => resumedPage;
  await assert.rejects(
    () => client.scanNotes({
      rootSeed: new Uint8Array(32).fill(9),
      after,
      maxPages: 1
    }),
    /mid-event resume requires pending summary validation state/
  );
});

test("typed privacy scan preserves pending summary identity across serialization and restart", () => {
  const { batch, firstPage, state } = pendingBatchFixture();
  const restored = roundTripValidationState(state);

  assert.throws(
    () => validatePrivacyScanPageV2({
      ...batch,
      summaries: [{ ...batch.summaries[0], txHash: new Uint8Array(32).fill(8) }],
      outputs: [],
      nextCursor: firstPage.nextCursor,
      hasMore: false
    }, { after: firstPage.nextCursor, validationState: restored }),
    /does not match its pending summary identity/
  );
  assert.equal(restored.pending_summary_by_event.get("10/4").tx_hash, "07".repeat(32));
  assert.doesNotThrow(() => validatePrivacyScanPageV2({
    ...batch,
    outputs: [batch.outputs[1]],
    hasMore: false
  }, { after: firstPage.nextCursor, validationState: restored }));
  assert.equal(restored.pending_summary_by_event.size, 0);
});

test("typed privacy scan rejects a resumed cursor that skips a pending output after restart", () => {
  const { batch, state } = pendingBatchFixture({ outputCount: 3 });
  const restored = roundTripValidationState(state);

  assert.throws(
    () => validatePrivacyScanPageV2({
      ...batch,
      outputs: [batch.outputs[2]],
      hasMore: false
    }, {
      after: { height: 10, globalSequence: 4, outputIndex: 1 },
      validationState: restored
    }),
    /pending summary does not match the request cursor/
  );
  assert.equal(restored.pending_summary_by_event.get("10/4").last_output_index, 0);
});

test("typed privacy scan rejects a snapshot with its pending-summary field removed", () => {
  const { state } = pendingBatchFixture();
  const snapshot = structuredClone(serializePrivacyScanValidationStateV2(state));
  delete snapshot.pending_summary_by_event;

  assert.throws(
    () => restorePrivacyScanValidationStateV2(snapshot),
    /validation state snapshot is invalid/
  );
});

test("typed privacy scan rejects inconsistent pending-summary and batch self-view state", () => {
  const { state } = pendingBatchFixture();
  const snapshot = structuredClone(serializePrivacyScanValidationStateV2(state));

  state.batch_self_view_by_event.clear();
  assert.throws(
    () => serializePrivacyScanValidationStateV2(state),
    /missing batch self-view state/
  );
  state.batch_self_view_by_event.set("10/4", true);
  state.pending_summary_by_event.clear();
  assert.throws(
    () => serializePrivacyScanValidationStateV2(state),
    /does not match a pending batch summary/
  );

  assert.throws(
    () => restorePrivacyScanValidationStateV2({
      ...snapshot,
      batch_self_view_by_event: []
    }),
    /missing batch self-view state/
  );
  assert.throws(
    () => restorePrivacyScanValidationStateV2({
      ...snapshot,
      pending_summary_by_event: []
    }),
    /does not match a pending batch summary/
  );
});

test("Cosmos pagination retains batch self-view validation state", async () => {
  const batch = validBatchPage();
  const pages = [partialBatchPage(batch), typedScanResponse(batch, {
    outputs: [{ ...batch.outputs[1], selfViewDisclosurePayload: new Uint8Array() }],
    hasMore: false
  })];
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

test("Cosmos typed scan rejects a tampered continuation before exposing a partial event", async () => {
  const batch = validBatchPage();
  const firstPage = partialBatchPage(batch);
  const finalPage = typedScanResponse(batch, {
    outputs: [{ ...batch.outputs[1], selfViewDisclosurePayload: new Uint8Array() }],
    hasMore: false
  });
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-test-1"
  });
  const requests = [];
  const pages = [firstPage, finalPage];
  client.fetchPrivacyScan = async request => {
    requests.push(request);
    return pages.shift();
  };
  await assert.rejects(
    () => client.scanNotes({ rootSeed: new Uint8Array(32).fill(9), maxPages: 1 }),
    /self-view disclosure must be all-or-none/
  );
  assert.equal(requests.length, 2);
  assert.equal(requests[1].outputLimit, 1);
});

test("Cosmos typed scan completes the current event beyond maxPages before returning notes", async () => {
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
  const batch = validBatchPage({ notes: [owned, noteForScan(8)] });
  const pages = [{
    ...batch,
    outputs: [batch.outputs[0]],
    nextCursor: { height: 10, globalSequence: 4, outputIndex: 0 },
    hasMore: true
  }, {
    ...batch,
    outputs: [batch.outputs[1]],
    hasMore: false
  }];
  const requests = [];
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-test-1"
  });
  client.fetchPrivacyScan = async request => {
    requests.push(request);
    return pages.shift();
  };
  client.checkNullifiers = async nullifiers => new Map(nullifiers.map(value => [value, false]));

  const result = await client.scanNotes({ rootSeed, maxPages: 1, includeFoundNotes: true });

  assert.equal(requests.length, 2);
  assert.equal(requests[1].outputLimit, 1);
  assert.equal(result.diagnostics.pages_scanned, 2);
  assert.equal(result.foundNotes.length, 1);
  assert.equal(result.foundNotes[0].note.amount, owned.amount);
  assert.equal("validation_state" in result.scanCursor, false);
  assert.equal(result.scanCursor.completed, true);
});
