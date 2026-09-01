import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { canonicalFieldBytes, derivePubKeyFromScalar, packPoint, signNoteHash } from "clairveiljs/core";
import { base64FromBytes, bytesFromBase64, hexFromBytes } from "clairveiljs/browser-crypto";
import {
  buildPreparedBatchTransferPayload,
  buildMsgBatchTransferFromPrepared,
  computePreparedBatchTransferPayloadHash,
  preparedBatchTransferProofVersion,
  signValidatedBatchTransferIntentV1,
  serializeBatchTransferProofRequest,
  validateBatchTransferSigningRequestV1,
  validatePreparedBatchTransferPayloadEnvelope
} from "clairveiljs/batch-transfer";
import {
  computeAssetIdV1,
  computeNoteCommitmentV1,
  computeNoteTreeNodeV1,
  emptyNoteTreeRootsV1,
  fieldHexV1,
  marshalDisclosurePlaintextV1,
  privacyFixedV1,
  unmarshalDisclosurePlaintextV1
} from "clairveiljs/protocol-v1";
import {
  createPrivacyScanValidationStateV2,
  validatePrivacyScanPageV2
} from "clairveiljs/scan";
import { createAsyncJobProverAdapter, createHttpProverAdapter } from "clairveiljs/prover";
import { ClairveilErrorCode } from "clairveiljs/errors";
import { createClairveilClient } from "clairveiljs/cosmos";
import {
  decodeBatchAuditDisclosureFromScanOutput,
  decodeBatchSelfViewDisclosureFromScanOutput,
  decodeBatchUserDisclosureFromScanOutput
} from "clairveiljs/disclosure";
import { batchTransferConformanceFixtureName } from "clairveiljs/conformance";
import { fixtureTestOptions, readFixture } from "./helpers.js";

function jsonResponse(body, status = 200, contentType = "application/json", extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "cache-control": "no-store",
      ...(status === 405 ? { allow: "POST" } : {}),
      ...(contentType == null ? {} : { "content-type": contentType }),
      ...extraHeaders
    }
  });
}

function batchMerklePaths(notes) {
  const emptyRoots = emptyNoteTreeRootsV1(32);
  const paths = notes.map(() => []);
  const helpers = notes.map(() => []);
  let layer = notes.map(computeNoteCommitmentV1);
  for (let level = 0; level < 32; level += 1) {
    for (let inputIndex = 0; inputIndex < notes.length; inputIndex += 1) {
      const nodeIndex = inputIndex >> level;
      const siblingIndex = nodeIndex ^ 1;
      paths[inputIndex].push(fieldHexV1(layer[siblingIndex] ?? emptyRoots[level]));
      helpers[inputIndex].push(nodeIndex & 1);
    }
    const next = [];
    for (let index = 0; index < layer.length; index += 2) {
      next.push(computeNoteTreeNodeV1(level, layer[index], layer[index + 1] ?? emptyRoots[level]));
    }
    layer = next;
  }
  return { paths, helpers, root: fieldHexV1(layer[0]) };
}

function disclosurePolicyForMode(mode, fallbackPolicy, fallbackMode) {
  if (!mode) return { privacyPolicy: fallbackPolicy, disclosureMode: fallbackMode };
  if (mode === "none") return { privacyPolicy: 0, disclosureMode: 0 };
  if (mode === "public") return { privacyPolicy: 1, disclosureMode: 1 };
  if (mode === "recipient-encrypted") return { privacyPolicy: 1, disclosureMode: 2 };
  throw new Error(`unsupported fixture disclosure mode ${mode}`);
}

async function batchPayload({
  privacyPolicy = 0,
  disclosureMode = 0,
  inputAmounts = [7],
  paymentAmounts = [7],
  disclosureModes = [],
  outputRoles = [],
  selfViewEnabled = true,
  auditDisclosureTargetPubKey = derivePubKeyFromScalar(31n),
  auditKeyEpoch = 1,
  disclosureTargetPubKey
} = {}) {
  const ownerSpend = derivePubKeyFromScalar(17n);
  const ownerView = derivePubKeyFromScalar(19n);
  const assetID = computeAssetIdV1("uclair");
  const inputs = inputAmounts.map((amount, index) => ({
    receiverSpendPubKeyX: ownerSpend.x, receiverSpendPubKeyY: ownerSpend.y,
    receiverViewPubKeyX: ownerView.x, receiverViewPubKeyY: ownerView.y,
    amount: BigInt(amount), assetID, randomness: BigInt(11 + index), memo: `input-${index}`
  }));
  const merkle = batchMerklePaths(inputs);
  const inputTotal = inputs.reduce((sum, note) => sum + note.amount, 0n);
  const paymentTotal = paymentAmounts.reduce((sum, amount) => sum + BigInt(amount), 0n);
  if (paymentTotal > inputTotal) throw new Error("fixture batch payments exceed inputs");
  const outputs = paymentAmounts.map((amount, index) => {
    const recipientSpend = derivePubKeyFromScalar(BigInt(23 + index * 2));
    const recipientView = derivePubKeyFromScalar(BigInt(29 + index * 2));
    const { privacyPolicy: outputPolicy, disclosureMode: outputMode } = disclosurePolicyForMode(
      disclosureModes[index], privacyPolicy, disclosureMode
    );
    return {
      kind: "payment",
      note: {
        receiverSpendPubKeyX: recipientSpend.x, receiverSpendPubKeyY: recipientSpend.y,
        receiverViewPubKeyX: recipientView.x, receiverViewPubKeyY: recipientView.y,
        amount: BigInt(amount), assetID, randomness: BigInt(101 + index), memo: `payment-${index}`
      },
      privacyPolicy: outputPolicy,
      disclosureMode: outputMode,
      ...(outputMode === 2 ? { disclosureTargetPubKey: disclosureTargetPubKey ?? derivePubKeyFromScalar(BigInt(401 + index)) } : {}),
      userDisclosureBlinding: outputPolicy ? BigInt(2001 + index) : 0n,
      fullDisclosureBlinding: BigInt(1001 + index)
    };
  });
  const change = inputTotal - paymentTotal;
  if (change > 0n) {
    const index = outputs.length;
    outputs.push({
      kind: "change",
      note: {
        receiverSpendPubKeyX: ownerSpend.x, receiverSpendPubKeyY: ownerSpend.y,
        receiverViewPubKeyX: ownerView.x, receiverViewPubKeyY: ownerView.y,
        amount: change, assetID, randomness: BigInt(101 + index), memo: "change"
      },
      privacyPolicy: 0, disclosureMode: 0, userDisclosureBlinding: 0n, fullDisclosureBlinding: BigInt(1001 + index)
    });
  }
  const paddingCount = outputRoles.filter(role => role === "padding").length;
  for (let index = 0; index < paddingCount; index += 1) {
    const outputIndex = outputs.length;
    outputs.push({
      kind: "padding",
      note: {
        receiverSpendPubKeyX: ownerSpend.x, receiverSpendPubKeyY: ownerSpend.y,
        receiverViewPubKeyX: ownerView.x, receiverViewPubKeyY: ownerView.y,
        amount: 0n, assetID, randomness: BigInt(101 + outputIndex), memo: `padding-${index}`
      },
      privacyPolicy: 0, disclosureMode: 0, userDisclosureBlinding: 0n, fullDisclosureBlinding: BigInt(1001 + outputIndex)
    });
  }
  return buildPreparedBatchTransferPayload({
    creator: "clair1creator",
    chainId: "clairveil-test-1",
    expiresAtUnix: 4_102_448_400,
    root: merkle.root,
    inputs: inputs.map((note, index) => ({ note, merklePath: merkle.paths[index], merklePathHelper: merkle.helpers[index] })),
    outputs,
    auditKeyId: "audit-key-1",
    auditKeyEpoch,
    auditDisclosureTargetPubKey,
    ...(selfViewEnabled ? { selfViewDisclosureTargetPubKey: derivePubKeyFromScalar(47n) } : { disableSelfViewDisclosure: true }),
    signer: {
      signBatchTransfer: request => signNoteHash(request.expectedIntent, { spendScalar: 17n, spendPubKey: ownerSpend })
    }
  });
}

function validatedBatchScanPage(message, payload) {
  const txHash = new Uint8Array(32).fill(0xab);
  const auditTarget = bytesFromBase64(payload.audit_disclosure_target_pubkey);
  const modeName = mode => [
    "USER_DISCLOSURE_MODE_NONE",
    "USER_DISCLOSURE_MODE_PUBLIC",
    "USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED"
  ][Number(mode)];
  const summary = {
    height: 10,
    globalSequence: 4,
    txHash,
    eventType: "batch_transfer",
    nullifiers: message.nullifiers,
    outputCount: message.outputs.length,
    effectId: canonicalFieldBytes(59n),
    circuitSetId: "privacy-note-v1",
    payloadVersion: privacyFixedV1,
    scanSchemaVersion: "privacy-scan-v2",
    auditKeyId: payload.audit_key_id,
    auditKeyEpoch: payload.audit_key_epoch,
    auditTargetPubkey: auditTarget
  };
  return validatePrivacyScanPageV2({
    scanSchemaVersion: "privacy-scan-v2",
    summaries: [summary],
    outputs: message.outputs.map((entry, outputIndex) => ({
      ...entry,
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
      userDisclosureMode: modeName(entry.userDisclosureMode),
      leafIndexFound: true,
      leafIndex: outputIndex
    })),
    nextCursor: { height: summary.height, globalSequence: summary.globalSequence, outputIndex: message.outputs.length - 1 },
    hasMore: false
  });
}

function validatedBatchScanOutput(message, payload, index) {
  return validatedBatchScanPage(message, payload).outputs[index];
}

test("one-proof batch prover uses the Clairveil v0.3.1 route and binds the response hash", async () => {
  const payload = await batchPayload();
  const proof = new Uint8Array(164).fill(7);
  let call;
  const adapter = createHttpProverAdapter({
    baseURL: "https://prover.example",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async (url, init) => {
      call = { url: String(url), body: JSON.parse(init.body) };
      return jsonResponse({
        version: "v1",
        proof: {
          version: preparedBatchTransferProofVersion,
          request_payload_hash: payload.payload_hash,
          proof: base64FromBytes(proof),
          circuit_set_id: "privacy-note-v1"
        }
      });
    }
  });
  const response = await adapter.proveBatchTransfer(payload);
  assert.equal(call.url, "https://prover.example/v1/proofs/batch-transfer");
  assert.deepEqual(call.body, JSON.parse(serializeBatchTransferProofRequest(payload)));
  assert.deepEqual(response.proof.proof_bytes, proof);

  const message = buildMsgBatchTransferFromPrepared(payload, response.proof, { nowUnix: 1_700_000_000 });
  assert.equal(message.proof.length, 164);
  assert.equal(message.nullifiers.length, 1);
  assert.equal(message.outputs.length, 1);
  assert.equal(message.creator, "clair1creator");
});

test("one-proof batch prover rejects unattested custom fetch before sending the payload", async () => {
  const payload = await batchPayload();
  let fetchCalls = 0;
  await assert.rejects(
    async () => createHttpProverAdapter({
      baseURL: "https://prover.example",
      fetchImpl: async () => {
        fetchCalls += 1;
        throw new Error("unattested fetch must not be called");
      }
    }).proveBatchTransfer(payload),
    /custom prover fetch implementation must set proverTransportRedirectsDisabled to true/
  );
  assert.equal(fetchCalls, 0);
});

test("one-proof batch prover rejects redirected or cross-endpoint custom-fetch responses", async () => {
  const payload = await batchPayload();
  const body = {
    version: "v1",
    proof: {
      version: preparedBatchTransferProofVersion,
      request_payload_hash: payload.payload_hash,
      proof: base64FromBytes(new Uint8Array(164).fill(7)),
      circuit_set_id: "privacy-note-v1"
    }
  };

  for (const responseIdentity of [
    { redirected: true, url: "https://other.example/proof" },
    { redirected: false, url: "https://other.example/proof" }
  ]) {
    const adapter = createHttpProverAdapter({
      baseURL: "https://prover.example",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => {
        const response = jsonResponse(body);
        Object.defineProperties(response, {
          redirected: { value: responseIdentity.redirected },
          url: { value: responseIdentity.url }
        });
        return response;
      }
    });
    await assert.rejects(
      () => adapter.proveBatchTransfer(payload),
      error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
        /must not redirect|configured endpoint/.test(error.message)
    );
  }
});

test("native one-proof batch fetch refuses redirects without disclosing the payload", async () => {
  const payload = await batchPayload();
  let originHits = 0;
  let targetHits = 0;
  const target = createServer((request, response) => {
    targetHits += 1;
    request.resume();
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{}");
  });
  await new Promise((resolve, reject) => {
    target.once("error", reject);
    target.listen(0, "127.0.0.1", resolve);
  });
  const targetURL = `http://127.0.0.1:${target.address().port}`;
  const origin = createServer((request, response) => {
    originHits += 1;
    request.resume();
    response.writeHead(307, { location: `${targetURL}${request.url}` });
    response.end();
  });
  await new Promise((resolve, reject) => {
    origin.once("error", reject);
    origin.listen(0, "127.0.0.1", resolve);
  });

  try {
    const adapter = createHttpProverAdapter({
      baseURL: `http://127.0.0.1:${origin.address().port}`
    });
    await assert.rejects(
      () => adapter.proveBatchTransfer(payload),
      error => error?.code === ClairveilErrorCode.PROVER_REJECTED
    );
    assert.equal(originHits, 1);
    assert.equal(targetHits, 0);
  } finally {
    await Promise.all([
      new Promise(resolve => origin.close(resolve)),
      new Promise(resolve => target.close(resolve))
    ]);
  }
});

test("one-proof batch HTTP prover requires exact JSON Content-Type on success and error", async () => {
  const payload = await batchPayload();
  const successBody = {
    version: "v1",
    proof: {
      version: preparedBatchTransferProofVersion,
      request_payload_hash: payload.payload_hash,
      proof: base64FromBytes(new Uint8Array(164).fill(7)),
      circuit_set_id: "privacy-note-v1"
    }
  };
  const errorBody = {
    version: "v1",
    code: "proof_failed",
    message: "must not be parsed without the declared JSON media type",
    retryable: false
  };

  for (const [status, body] of [
    [200, successBody],
    [500, errorBody]
  ]) {
    for (const contentType of [
      null,
      "text/plain",
      "application/json; charset=utf-8",
      "application/json; private=unknown"
    ]) {
      const adapter = createHttpProverAdapter({
        baseURL: "https://prover.example",
        proverTransportRedirectsDisabled: true,
        fetchImpl: async () => jsonResponse(body, status, contentType)
      });
      await assert.rejects(
        () => adapter.proveBatchTransfer(payload),
        error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
          /Content-Type: application\/json/.test(error.message)
      );
    }
  }
});

test("one-proof batch HTTP prover requires Cache-Control: no-store", async () => {
  const payload = await batchPayload();
  const successBody = {
    version: "v1",
    proof: {
      version: preparedBatchTransferProofVersion,
      request_payload_hash: payload.payload_hash,
      proof: base64FromBytes(new Uint8Array(164).fill(7)),
      circuit_set_id: "privacy-note-v1"
    }
  };

  for (const fetchImpl of [
    async () => new Response(JSON.stringify(successBody), {
      status: 200,
      headers: { "content-type": "application/json" }
    }),
    async () => jsonResponse(successBody, 200, "application/json", {
      "cache-control": "private"
    })
  ]) {
    const adapter = createHttpProverAdapter({
      baseURL: "https://prover.example",
      proverTransportRedirectsDisabled: true,
      fetchImpl
    });
    await assert.rejects(
      () => adapter.proveBatchTransfer(payload),
      error => error?.code === ClairveilErrorCode.PROVER_REJECTED &&
        /Cache-Control: no-store/.test(error.message)
    );
  }
});

test("one-proof batch rejects identity disclosure targets before encryption", async () => {
  const identity = { x: 0n, y: 1n };
  await assert.rejects(
    () => batchPayload({ auditDisclosureTargetPubKey: identity }),
    /identity is not allowed/
  );
  await assert.rejects(
    () => batchPayload({ privacyPolicy: 1, disclosureMode: 2, disclosureTargetPubKey: identity }),
    /identity is not allowed/
  );
});

test("async prover job adapter supports a batch-only one-proof prover", async () => {
  const payload = await batchPayload();
  const marker = "private-marker-must-not-cross-prover-boundary";
  const requestPayload = structuredClone(payload);
  requestPayload.private_marker = marker;
  requestPayload.inputs[0].private_marker = marker;
  requestPayload.outputs[0].private_marker = marker;
  const proof = new Uint8Array(164).fill(13);
  let submitted;
  const adapter = createAsyncJobProverAdapter({
    submitBatchTransferJob: async request => {
      submitted = request;
      return { job_id: "batch-job-1" };
    },
    getJob: async jobId => {
      assert.equal(jobId, "batch-job-1");
      return {
        status: "completed",
        result: {
          version: "v1",
          proof: {
            version: preparedBatchTransferProofVersion,
            request_payload_hash: payload.payload_hash,
            proof: base64FromBytes(proof),
            circuit_set_id: "privacy-note-v1"
          }
        }
      };
    },
    intervalMs: 0
  });

  const response = await adapter.proveBatchTransfer(requestPayload);

  assert.deepEqual(submitted, { version: "v1", payload });
  assert.equal(JSON.stringify(submitted).includes(marker), false);
  assert.deepEqual(response.proof.proof_bytes, proof);
  assert.equal(typeof adapter.proveTransfer, "undefined");
  assert.equal(typeof adapter.proveWithdraw, "undefined");
});

test("batch prover adapters reject missing or falsy versions on explicit envelopes", async () => {
  const payload = await batchPayload();
  let httpCalls = 0;
  let submissions = 0;
  const adapters = [
    createHttpProverAdapter({
      baseURL: "https://prover.example",
      proverTransportRedirectsDisabled: true,
      fetchImpl: async () => {
        httpCalls += 1;
        throw new Error("invalid envelope must not reach the prover");
      }
    }),
    createAsyncJobProverAdapter({
      submitBatchTransferJob: async () => {
        submissions += 1;
        throw new Error("invalid envelope must not reach the prover");
      },
      getJob: async () => ({ status: "pending" })
    })
  ];

  for (const adapter of adapters) {
    for (const invalidVersion of [undefined, "", null, 0]) {
      const envelope = invalidVersion === undefined
        ? { payload }
        : { version: invalidVersion, payload };
      await assert.rejects(
        () => adapter.proveBatchTransfer(envelope),
        /unsupported batch transfer proof request version/
      );
    }
  }
  assert.equal(httpCalls, 0);
  assert.equal(submissions, 0);
});

test("batch prover adapters validate with the caller's authoritative time", async () => {
  const payload = await batchPayload();
  const proof = {
    version: preparedBatchTransferProofVersion,
    request_payload_hash: payload.payload_hash,
    proof: base64FromBytes(new Uint8Array(164).fill(17)),
    circuit_set_id: "privacy-note-v1"
  };
  let httpCalls = 0;
  let submitCalls = 0;
  const adapters = [
    {
      adapter: createHttpProverAdapter({
        baseURL: "https://prover.example",
        proverTransportRedirectsDisabled: true,
        fetchImpl: async () => {
          httpCalls += 1;
          return jsonResponse({ version: "v1", proof });
        }
      }),
      calls: () => httpCalls
    },
    {
      adapter: createAsyncJobProverAdapter({
        submitBatchTransferJob: async () => {
          submitCalls += 1;
          return { job_id: "authoritative-batch-time" };
        },
        getJob: async () => ({ status: "completed", response: { version: "v1", proof } }),
        intervalMs: 0
      }),
      calls: () => submitCalls
    }
  ];

  for (const { adapter, calls } of adapters) {
    await adapter.proveBatchTransfer(payload, { nowUnix: payload.expires_at_unix - 1 });
    assert.equal(calls(), 1);
    await assert.rejects(
      () => adapter.proveBatchTransfer(payload, { nowUnix: payload.expires_at_unix }),
      /prepared batch transfer payload expired/
    );
    assert.equal(calls(), 1);
  }
});

test("one-proof batch prover rejects a proof bound to another prepared operation", async () => {
  const payload = await batchPayload();
  const adapter = createHttpProverAdapter({
    baseURL: "https://prover.example",
    proverTransportRedirectsDisabled: true,
    fetchImpl: async () => jsonResponse({
      version: "v1",
      proof: {
        version: preparedBatchTransferProofVersion,
        request_payload_hash: "0000000000000000000000000000000000000000000000000000000000000006",
        proof: base64FromBytes(new Uint8Array(164))
      }
    })
  });
  await assert.rejects(() => adapter.proveBatchTransfer(payload), /payload hash mismatch/);
});

test("one-proof batch preparation binds public disclosure and rejects post-signature mutation", async () => {
  const payload = await batchPayload({ privacyPolicy: 7, disclosureMode: 1 });
  const output = payload.message_outputs[0];
  const disclosure = unmarshalDisclosurePlaintextV1(bytesFromBase64(output.user_disclosure_payload));
  assert.equal(disclosure.plane, 1);
  assert.equal(disclosure.policy, 7);
  assert.equal(disclosure.disclosedFieldBitmap, 7);
  assert.notEqual(output.user_disclosure_digest, "");
  const tamperedPlaintext = marshalDisclosurePlaintextV1({
    ...disclosure,
    amount: disclosure.amount + 1n
  });
  const tamperedPayload = {
    ...payload,
    message_outputs: payload.message_outputs.map((candidate, index) => index === 0
      ? { ...candidate, user_disclosure_payload: base64FromBytes(tamperedPlaintext) }
      : candidate)
  };
  // The effect parser runs before the outer payload hash check, so this
  // exercises the signer-side plaintext-to-digest invariant directly.
  assert.throws(
    () => validatePreparedBatchTransferPayloadEnvelope(tamperedPayload),
    /public disclosure digest does not match plaintext/
  );
  assert.throws(
    () => validatePreparedBatchTransferPayloadEnvelope({ ...payload, audit_key_id: "another-audit-key" }),
    /payload hash mismatch/
  );
});

test("one-proof batch preserves uint64 audit epochs and rejects expired payloads by default", async () => {
  const payload = await batchPayload({ auditKeyEpoch: "9007199254740993" });
  assert.equal(payload.audit_key_epoch, "9007199254740993");
  assert.equal(validatePreparedBatchTransferPayloadEnvelope(payload), true);
  const message = buildMsgBatchTransferFromPrepared(payload, {
    version: preparedBatchTransferProofVersion,
    request_payload_hash: payload.payload_hash,
    proof: base64FromBytes(new Uint8Array(164).fill(7))
  });
  assert.equal(message.auditKeyEpoch, 9007199254740993n);

  const expired = { ...payload, expires_at_unix: 1, payload_hash: "" };
  expired.payload_hash = computePreparedBatchTransferPayloadHash(expired);
  assert.throws(() => validatePreparedBatchTransferPayloadEnvelope(expired), /payload expired/);
});

test("Batch V1 typed-scan disclosure decoders bind output index, commitment, policy, digest, and blinding", async () => {
  const payload = await batchPayload({
    inputAmounts: [5, 7, 9],
    paymentAmounts: [4, 5, 6],
    disclosureModes: ["none", "public", "recipient-encrypted"],
    selfViewEnabled: true
  });
  const proof = {
    version: preparedBatchTransferProofVersion,
    request_payload_hash: payload.payload_hash,
    proof: base64FromBytes(new Uint8Array(164).fill(7)),
    circuit_set_id: "privacy-note-v1"
  };
  const message = buildMsgBatchTransferFromPrepared(payload, proof, { nowUnix: 1_700_000_000 });
  const output = index => validatedBatchScanOutput(message, payload, index);

  const publicUser = decodeBatchUserDisclosureFromScanOutput(output(1), {
    shieldedPrefix: "clairs",
    assetDenom: "uclair"
  });
  assert.equal(publicUser.verified, true);
  assert.equal(publicUser.plane, "user");
  assert.equal(publicUser.output_index, 1);
  assert.equal(publicUser.policy, "amount");
  assert.equal(publicUser.amount, "5");
  assert.equal(publicUser.verification.plaintext_blinding_bound, true);
  assert.throws(
    () => decodeBatchUserDisclosureFromScanOutput(output(1), { assetDenom: "uatom" }),
    /asset denom/
  );

  const recipientScalar = 403n;
  const recipientUser = decodeBatchUserDisclosureFromScanOutput(output(2), {
    disclosureScalar: recipientScalar,
    disclosurePubKeyHex: hexFromBytes(packPoint(derivePubKeyFromScalar(recipientScalar))),
    shieldedPrefix: "clairs",
    assetDenom: "uclair"
  });
  assert.equal(recipientUser.verified, true);
  assert.equal(recipientUser.output_index, 2);
  assert.equal(recipientUser.source, "recipient_encrypted");

  const audit = decodeBatchAuditDisclosureFromScanOutput(output(2), {
    disclosureScalar: 31n,
    shieldedPrefix: "clairs",
    assetDenom: "uclair"
  });
  assert.equal(audit.verified, true);
  assert.equal(audit.plane, "audit");
  assert.equal(audit.output_index, 2);
  assert.equal(audit.amount, "6");

  const selfView = decodeBatchSelfViewDisclosureFromScanOutput(output(2), {
    disclosureScalar: 47n,
    shieldedPrefix: "clairs",
    assetDenom: "uclair"
  });
  assert.equal(selfView.verified, true);
  assert.equal(selfView.plane, "self-view");
  assert.equal(selfView.digest_hex, audit.digest_hex);

  const client = createClairveilClient({
    rest: "http://127.0.0.1:1317",
    rpc: "http://127.0.0.1:26657",
    chainId: "clairveil-test-1",
    accountPrefix: "clair",
    shieldedPrefix: "clairs"
  });
  const wrappedPublicUser = await client.decodeBatchUserDisclosure({
    output: output(1),
    assetDenom: "uclair"
  });
  assert.equal(wrappedPublicUser.digest_hex, publicUser.digest_hex);
  const wrappedAudit = await client.decodeBatchAuditDisclosure({
    output: output(2),
    disclosureScalar: 31n,
    assetDenom: "uclair"
  });
  assert.equal(wrappedAudit.digest_hex, audit.digest_hex);
  const validatedPage = validatedBatchScanPage(message, payload);
  let auditableRequest;
  client.fetchPrivacyScan = async request => {
    auditableRequest = request;
    return validatedPage;
  };
  const validationState = createPrivacyScanValidationStateV2();
  const auditablePage = await client.fetchAuditableBatchTransfers({
    after: { height: 9, globalSequence: 3, outputIndex: 0 },
    validationState
  });
  assert.deepEqual(auditableRequest.eventTypes, ["batch_transfer"]);
  assert.equal(auditableRequest.validationState, undefined);
  assert.equal(auditablePage.summaries.length, 1);
  assert.equal(auditablePage.outputs.length, message.outputs.length);
  assert.equal(auditablePage.outputs.every(entry => entry.event_type === "batch_transfer"), true);
  await assert.rejects(
    () => client.decodeBatchUserDisclosure({
      output: output(1),
      assetDenom: "uclair",
      asset_denom: "uatom"
    }),
    /assetDenom aliases conflict/
  );
  await assert.rejects(
    () => client.decodeBatchSelfViewDisclosure({
      output: output(2),
      disclosureScalar: 47n,
      assetDenom: "uclair",
      asset_denom: "uatom"
    }),
    /assetDenom aliases conflict/
  );
  await assert.rejects(
    () => client.decodeBatchAuditDisclosure({
      output: output(2),
      disclosureScalar: 31n,
      assetDenom: "uclair",
      asset_denom: "uatom"
    }),
    /assetDenom aliases conflict/
  );

  assert.throws(
    () => decodeBatchUserDisclosureFromScanOutput({ ...output(2), output_index: 1 }, {
      disclosureScalar: recipientScalar,
      disclosurePubKeyHex: hexFromBytes(packPoint(derivePubKeyFromScalar(recipientScalar)))
    }),
    /must come from validatePrivacyScanPageV2/
  );
  assert.throws(
    () => decodeBatchAuditDisclosureFromScanOutput(message.outputs[2], { disclosureScalar: 31n }),
    /must come from validatePrivacyScanPageV2/
  );
});

test("one-proof batch signer validates the complete effect and global secret freshness before callback", async () => {
  let request;
  const ownerSpend = derivePubKeyFromScalar(17n);
  const ownerView = derivePubKeyFromScalar(19n);
  const assetID = computeAssetIdV1("uclair");
  const inputNote = {
    receiverSpendPubKeyX: ownerSpend.x, receiverSpendPubKeyY: ownerSpend.y,
    receiverViewPubKeyX: ownerView.x, receiverViewPubKeyY: ownerView.y,
    amount: 7n, assetID, randomness: 11n, memo: "input"
  };
  const outputNote = {
    receiverSpendPubKeyX: derivePubKeyFromScalar(23n).x, receiverSpendPubKeyY: derivePubKeyFromScalar(23n).y,
    receiverViewPubKeyX: derivePubKeyFromScalar(29n).x, receiverViewPubKeyY: derivePubKeyFromScalar(29n).y,
    amount: 7n, assetID, randomness: 13n, memo: "payment"
  };
  await buildPreparedBatchTransferPayload({
    chainId: "clairveil-test-1", expiresAtUnix: 4_102_448_400,
    inputs: [{ note: inputNote, merklePath: emptyNoteTreeRootsV1(32).slice(0, 32).map(value => value.toString(16).padStart(64, "0")), merklePathHelper: Array(32).fill(0) }],
    outputs: [{ kind: "payment", note: outputNote, privacyPolicy: 0, disclosureMode: 0, userDisclosureBlinding: 0n, fullDisclosureBlinding: 15n }],
    auditKeyId: "audit-key-1", auditKeyEpoch: 1, auditDisclosureTargetPubKey: derivePubKeyFromScalar(31n), disableSelfViewDisclosure: true,
    signer: {
      signBatchTransfer(candidate) {
        request = candidate;
        const validated = validateBatchTransferSigningRequestV1(candidate);
        return signNoteHash(validated.expected_intent, { spendScalar: 17n, spendPubKey: ownerSpend });
      }
    }
  });
  assert.equal(request.orderedInputs.length, 1);
  assert.equal(request.orderedOutputs.length, 1);
  assert.equal(request.canonicalEffect.creator, "");

  let callbacks = 0;
  const reusedSecret = {
    ...request,
    orderedOutputs: [{
      ...request.orderedOutputs[0],
      fullDisclosureBlinding: request.orderedInputs[0].randomness
    }]
  };
  await assert.rejects(
    () => signValidatedBatchTransferIntentV1({
      signBatchTransfer() {
        callbacks += 1;
        return new Uint8Array(64);
      }
    }, reusedSecret),
    /reuses an input\/output secret/
  );
  assert.equal(callbacks, 0);
});

test("one-proof batch fixture defines the batch boundary and representative E2E", fixtureTestOptions, async () => {
  const contract = readFixture(batchTransferConformanceFixtureName);
  assert.equal(contract.schema_version, "clairveil.batch-transfer.contract.v1");
  assert.equal(contract.payload_version, "batch-transfer-payload-v1");
  assert.equal(contract.proof_version, "batch-transfer-proof-v1");
  assert.equal(contract.circuit_set_id, "privacy-note-v1");
  assert.equal(contract.circuit_id, "batch-joinsplit-16x32-v1");
  assert.equal(contract.prover_route, "/v1/proofs/batch-transfer");
  assert.equal(contract.request_version, "v1");
  assert.equal(contract.response_version, "v1");
  assert.equal(contract.max_inputs, 16);
  assert.equal(contract.max_outputs, 32);
  assert.deepEqual(contract.payroll, {
    operation_to_proof_job: "one-to-one",
    operation_to_input_reservations: "one-to-many",
    operation_to_item_outputs: "one-to-many",
    batch_and_item_status_separate: true,
    required_output_evidence: ["output_index", "commitment", "recipient_hash", "amount", "denom_or_asset_id", "user_digest", "full_digest", "audit_key_id", "audit_key_epoch"]
  });
  assert.deepEqual(contract.scan, {
    cursor_order: ["height", "global_sequence", "output_index"],
    typed_query_required: true,
    abci_fallback_after_typed_failure: false,
    safe_mode_decrypts_view_tag_mismatch: true,
    commitment_recomputation_required: true
  });
  assert.equal(contract.restart_retry.automatic_multi_prover_failover, false);
  assert.equal(contract.restart_retry.item_success_requires_output_evidence, true);

  for (const vector of contract.cases) {
    assert.ok(["enabled", "disabled"].includes(vector.self_view), vector.id);
    const inputTotal = vector.input_amounts.reduce((sum, amount) => sum + BigInt(amount), 0n);
    const paymentTotal = vector.payment_amounts.reduce((sum, amount) => sum + BigInt(amount), 0n);
    assert.ok(vector.input_amounts.length >= 1 && vector.input_amounts.length <= contract.max_inputs, vector.id);
    assert.ok(vector.expected_output_roles.length >= 1 && vector.expected_output_roles.length <= contract.max_outputs, vector.id);
    assert.equal(vector.expected_output_roles.length, vector.disclosure_modes.length, vector.id);
    assert.ok(paymentTotal <= inputTotal, vector.id);
    assert.deepEqual(
      vector.expected_output_roles.filter(role => role === "payment"),
      Array(vector.payment_amounts.length).fill("payment"),
      vector.id
    );
    assert.ok(vector.expected_output_roles.every((role, index) =>
      role === "payment" || (role === "change" && index === vector.payment_amounts.length) ||
      (role === "padding" && index >= vector.payment_amounts.length)
    ), vector.id);
    assert.ok(vector.disclosure_modes.every(mode => ["none", "public", "recipient-encrypted"].includes(mode)), vector.id);
  }

  for (const vector of contract.cases) {
    const payload = await batchPayload({
      inputAmounts: vector.input_amounts,
      paymentAmounts: vector.payment_amounts,
      disclosureModes: vector.disclosure_modes,
      outputRoles: vector.expected_output_roles,
      selfViewEnabled: vector.self_view === "enabled"
    });
    const proof = {
      version: preparedBatchTransferProofVersion,
      request_payload_hash: payload.payload_hash,
      proof: base64FromBytes(new Uint8Array(164).fill(7)),
      circuit_set_id: contract.circuit_set_id
    };
    const message = buildMsgBatchTransferFromPrepared(payload, proof, { nowUnix: 1_700_000_000 });
    assert.equal(message.nullifiers.length, vector.input_amounts.length, vector.id);
    assert.equal(message.outputs.length, vector.expected_output_roles.length, vector.id);
    assert.deepEqual(payload.outputs.map(output => output.kind), vector.expected_output_roles, vector.id);
    assert.equal(
      message.outputs.every(output => output.selfViewDisclosurePayload.length === (vector.self_view === "enabled" ? 472 : 0)),
      true,
      vector.id
    );
    assert.equal(JSON.parse(serializeBatchTransferProofRequest(payload)).version, contract.request_version, vector.id);
  }
});
