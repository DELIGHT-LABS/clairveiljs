import test from "node:test";
import assert from "node:assert/strict";
import {
  derivePubKeyFromScalar,
  deriveSpendKeys,
  deriveViewKeys,
  encodeShieldedAddress,
  FIELD_MODULUS,
  packPoint,
  createSpendNoteHashSigner
} from "clairveiljs/core";
import { createNote } from "clairveiljs/note";
import {
  computeAssetIdV1,
  computeNoteCommitmentV1,
  computeNoteTreeNodeV1,
  emptyNoteTreeRootsV1,
  encryptedEnvelopeKindV1,
  marshalDisclosurePlaintextV1,
  unmarshalDisclosurePlaintextV1,
  wrapEncryptedEnvelopeV1
} from "clairveiljs/protocol-v1";
import {
  buildTransferV5MsgFromPayloadAndProof,
  signValidatedJoinSplitOwnerIntentV1,
  computePreparedTransferV5PayloadHash,
  validateJoinSplitOwnerIntentSigningRequestV1,
  validatePreparedTransferV5PayloadAt,
  validatePreparedTransferV5PayloadMetadata,
  validatePreparedTransferV5Proof
} from "clairveiljs/transfer-v5";
import { buildPreparedTransferPayload } from "clairveiljs/payload";

function field(value) {
  return BigInt(value).toString(16).padStart(64, "0");
}

function signature(point) {
  return `${Buffer.from(packPoint(point)).toString("hex")}${field(1n)}`;
}

function pairedMerklePathProvider(notes) {
  const commitments = notes.map(computeNoteCommitmentV1);
  const emptyRoots = emptyNoteTreeRootsV1(32);
  const paths = commitments.map((commitment, index) => {
    const path = [commitments[index ^ 1]];
    const helper = [index & 1];
    let current = index === 0
      ? computeNoteTreeNodeV1(0, commitment, commitments[1])
      : computeNoteTreeNodeV1(0, commitments[0], commitment);
    for (let level = 1; level < 32; level += 1) {
      path.push(emptyRoots[level]);
      helper.push(0);
      current = computeNoteTreeNodeV1(level, current, emptyRoots[level]);
    }
    return { root: field(current), path: path.map(field), path_helper: helper };
  });
  const byCommitment = new Map(commitments.map((commitment, index) => [field(commitment), paths[index]]));
  return commitmentHex => {
    const path = byCommitment.get(commitmentHex);
    if (!path) throw new Error("unexpected transfer test commitment");
    return path;
  };
}

function validPayload() {
  const spend = derivePubKeyFromScalar(17n);
  const view = derivePubKeyFromScalar(19n);
  const recipientSpend = derivePubKeyFromScalar(23n);
  const recipientView = derivePubKeyFromScalar(29n);
  const audit = derivePubKeyFromScalar(31n);
  const transferCiphertext = wrapEncryptedEnvelopeV1(encryptedEnvelopeKindV1.transferNote, new Uint8Array(410));
  const auditPayload = wrapEncryptedEnvelopeV1(encryptedEnvelopeKindV1.auditDisclosure, new Uint8Array(452));
  const payload = {
    version: "v5",
    creator: "clair1creator",
    chain_id: "clairveil-test-1",
    expires_at_unix: 4_102_448_400,
    root_hex: field(1n),
    asset_id_hex: field(2n),
    inputs: [
      { amount: "7", randomness_hex: field(3n), spend_pubkey_hex: Buffer.from(packPoint(spend)).toString("hex"), view_pubkey_hex: Buffer.from(packPoint(view)).toString("hex"), merkle_path: Array(32).fill(field(1n)), merkle_path_helper: Array(32).fill(0), nullifier_hex: field(4n) },
      { amount: "5", randomness_hex: field(5n), spend_pubkey_hex: Buffer.from(packPoint(spend)).toString("hex"), view_pubkey_hex: Buffer.from(packPoint(view)).toString("hex"), merkle_path: Array(32).fill(field(2n)), merkle_path_helper: Array(32).fill(1), nullifier_hex: field(6n) }
    ],
    outputs: [
      { amount: "7", randomness_hex: field(7n), spend_pubkey_hex: Buffer.from(packPoint(recipientSpend)).toString("hex"), view_pubkey_hex: Buffer.from(packPoint(recipientView)).toString("hex"), commitment_hex: field(8n) },
      { amount: "5", randomness_hex: field(10n), spend_pubkey_hex: Buffer.from(packPoint(spend)).toString("hex"), view_pubkey_hex: Buffer.from(packPoint(view)).toString("hex"), commitment_hex: field(11n) }
    ],
    cipher_text_hexes: [Buffer.from(transferCiphertext).toString("hex"), Buffer.from(transferCiphertext).toString("hex")],
    view_tag_hexes: ["1234", "5678"],
    user_privacy_policy: 0,
    user_disclosure_mode: 0,
    user_disclosure_digest_hex: "",
    user_disclosure_target_pubkey_hex: "",
    user_disclosure_payload_hex: "",
    audit_disclosure_digest_hex: field(12n),
    audit_disclosure_target_pubkey_hex: Buffer.from(packPoint(audit)).toString("hex"),
    audit_disclosure_payload_hex: Buffer.from(auditPayload).toString("hex"),
    self_view_disclosure_digest_hex: "",
    self_view_disclosure_payload_hex: "",
    user_disclosure_blinding_hex: "",
    full_disclosure_blinding_hex: field(13n),
    owner_signature_hex: signature(spend)
  };
  payload.payload_hash = computePreparedTransferV5PayloadHash(payload);
  return payload;
}

test("transfer v5 prepared payload hash matches the Clairveil main line contract", () => {
  const payload = {
    version: "v5", creator: "clair1creator", chain_id: "clairveil-test-1", expires_at_unix: 4102448400,
    root_hex: field(1n), asset_id_hex: field(2n), user_privacy_policy: 0, user_disclosure_mode: 0,
    user_disclosure_digest_hex: "", user_disclosure_target_pubkey_hex: "", user_disclosure_payload_hex: "",
    audit_disclosure_digest_hex: field(3n), audit_disclosure_target_pubkey_hex: "04", audit_disclosure_payload_hex: "05",
    self_view_disclosure_digest_hex: "", self_view_disclosure_payload_hex: "", user_disclosure_blinding_hex: "", full_disclosure_blinding_hex: field(6n), owner_signature_hex: "07",
    inputs: [
      { amount: "7", randomness_hex: field(8n), spend_pubkey_hex: "09", view_pubkey_hex: "0a", merkle_path: ["01", "02"], merkle_path_helper: [0, 1], nullifier_hex: field(11n) },
      { amount: "5", randomness_hex: field(12n), spend_pubkey_hex: "0d", view_pubkey_hex: "0e", merkle_path: ["03"], merkle_path_helper: [1], nullifier_hex: field(15n) }
    ],
    outputs: [
      { amount: "7", randomness_hex: field(16n), spend_pubkey_hex: "11", view_pubkey_hex: "12", commitment_hex: field(19n) },
      { amount: "5", randomness_hex: field(20n), spend_pubkey_hex: "15", view_pubkey_hex: "16", commitment_hex: field(23n) }
    ],
    cipher_text_hexes: ["ab", "cd"], view_tag_hexes: ["1234", "5678"]
  };
  assert.equal(computePreparedTransferV5PayloadHash(payload), "eb71bb985eb351a750696347cc156d9a1fe535daa20d27c6e758df45ad49e62e");
});

test("transfer v5 rejects stale or tampered prepared effects before MsgTransfer construction", () => {
  const payload = validPayload();
  assert.equal(validatePreparedTransferV5PayloadMetadata(payload), true);
  assert.equal(validatePreparedTransferV5PayloadAt(payload, 1_700_000_000), true);
  const proof = { version: "v2", payload_hash: payload.payload_hash, proof_hex: `${"c0"}${"00".repeat(31)}${"c0"}${"00".repeat(63)}${"c0"}${"00".repeat(35)}${"c0"}${"00".repeat(31)}` };
  const message = buildTransferV5MsgFromPayloadAndProof(payload, proof, { nowUnix: 1_700_000_000 });
  assert.equal(message.expiresAtUnix, 4102448400n);
  assert.equal(message.viewTags.length, 2);
  assert.throws(() => validatePreparedTransferV5PayloadAt(payload, payload.expires_at_unix));
  assert.throws(() => validatePreparedTransferV5PayloadMetadata({ ...payload, creator: "clair1altered" }));
});

test("transfer v5 metadata rejects identity disclosure targets before message construction", () => {
  const payload = validPayload();
  const identityHex = Buffer.from(packPoint({ x: 0n, y: 1n })).toString("hex");
  const identityTarget = { ...payload, audit_disclosure_target_pubkey_hex: identityHex, payload_hash: "" };
  identityTarget.payload_hash = computePreparedTransferV5PayloadHash(identityTarget);
  const proof = { version: "v2", payload_hash: identityTarget.payload_hash, proof_hex: `${"c0"}${"00".repeat(31)}${"c0"}${"00".repeat(63)}${"c0"}${"00".repeat(35)}${"c0"}${"00".repeat(31)}` };
  assert.throws(() => validatePreparedTransferV5PayloadMetadata(identityTarget), /identity is not allowed/);
  assert.throws(() => buildTransferV5MsgFromPayloadAndProof(identityTarget, proof, { nowUnix: 1_700_000_000 }), /identity is not allowed/);
});

test("transfer v5 metadata accepts Go-compatible abbreviated paths while rejecting malformed witnesses", () => {
  const payload = validPayload();
  const abbreviated = structuredClone(payload);
  abbreviated.inputs[0].merkle_path = ["01", "02"];
  abbreviated.inputs[0].merkle_path_helper = [0, 1];
  abbreviated.payload_hash = computePreparedTransferV5PayloadHash(abbreviated);
  assert.equal(validatePreparedTransferV5PayloadMetadata(abbreviated), true);

  const malformed = structuredClone(payload);
  malformed.inputs[0].merkle_path[0] = "not-hex";
  malformed.payload_hash = computePreparedTransferV5PayloadHash(malformed);
  assert.throws(() => validatePreparedTransferV5PayloadMetadata(malformed), /valid hex/);

  const invalidHelper = structuredClone(payload);
  invalidHelper.inputs[0].merkle_path_helper[0] = 2;
  invalidHelper.payload_hash = computePreparedTransferV5PayloadHash(invalidHelper);
  assert.throws(() => validatePreparedTransferV5PayloadMetadata(invalidHelper), /must be 0 or 1/);

  const mismatchedPath = structuredClone(payload);
  mismatchedPath.inputs[0].merkle_path = [field(1n)];
  mismatchedPath.inputs[0].merkle_path_helper = [];
  mismatchedPath.payload_hash = computePreparedTransferV5PayloadHash(mismatchedPath);
  assert.throws(() => validatePreparedTransferV5PayloadMetadata(mismatchedPath), /matching lengths/);

  const oversizedPath = structuredClone(payload);
  oversizedPath.inputs[0].merkle_path.push(field(1n));
  oversizedPath.inputs[0].merkle_path_helper.push(0);
  oversizedPath.payload_hash = computePreparedTransferV5PayloadHash(oversizedPath);
  assert.throws(() => validatePreparedTransferV5PayloadMetadata(oversizedPath), /exceeds depth 32/);
});

test("transfer v5 proof and message builders reject expired payloads by default", () => {
  const payload = validPayload();
  payload.expires_at_unix = 1;
  payload.payload_hash = computePreparedTransferV5PayloadHash(payload);
  const proof = { version: "v2", payload_hash: payload.payload_hash, proof_hex: `${"c0"}${"00".repeat(31)}${"c0"}${"00".repeat(63)}${"c0"}${"00".repeat(35)}${"c0"}${"00".repeat(31)}` };

  assert.throws(() => validatePreparedTransferV5Proof(payload, proof), /payload expired/);
  assert.throws(() => buildTransferV5MsgFromPayloadAndProof(payload, proof), /payload expired/);
  assert.equal(validatePreparedTransferV5Proof(payload, proof, { nowUnix: 0 }), true);
});

test("standard transfer builder emits the Clairveil 0.2 V5 fixed-envelope contract", async () => {
  const rootSeed = new Uint8Array(32).fill(7);
  const senderSpend = deriveSpendKeys(rootSeed).pubKey;
  const senderView = deriveViewKeys(rootSeed).pubKey;
  const recipientSpend = derivePubKeyFromScalar(37n);
  const recipientView = derivePubKeyFromScalar(41n);
  const audit = derivePubKeyFromScalar(43n);
  const assetId = computeAssetIdV1("uclair");
  const inputs = [3n, 5n].map((randomness, index) => ({
    note: createNote({
      spendPubKey: senderSpend,
      viewPubKey: senderView,
      amount: index === 0 ? 7n : 5n,
      assetId,
      randomness
    }),
    nullifier: field(BigInt(100 + index)),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: field(BigInt(200 + index)),
    height: 1,
    sequence: index
  }));
  const payload = await buildPreparedTransferPayload({
    creator: "clair1creator",
    chainId: "clairveil-test-1",
    chainNowUnix: 1_700_000_000,
    inputs,
    recipient: encodeShieldedAddress(recipientSpend, recipientView, { prefix: "clairs" }),
    amount: "7uclair",
    rootSeed,
    merklePathProvider: pairedMerklePathProvider(inputs.map(input => input.note)),
    auditDisclosureTargetPubKeyHex: Buffer.from(packPoint(audit)).toString("hex")
  });

  assert.equal(payload.version, "v5");
  assert.equal(payload.expires_at_unix, 1_700_001_800);
  assert.equal(payload.asset_id_hex, field(assetId));
  assert.equal(payload.cipher_text_hexes[0].length, 860);
  assert.equal(payload.cipher_text_hexes[1].length, 860);
  assert.equal(payload.audit_disclosure_payload_hex.length, 944);
  assert.equal(payload.self_view_disclosure_payload_hex.length, 944);
  assert.equal(payload.owner_signature_hex.length, 128);
  assert.equal(validatePreparedTransferV5PayloadMetadata(payload), true);

  const selectivePayload = await buildPreparedTransferPayload({
    creator: "clair1creator",
    chainId: "clairveil-test-1",
    chainNowUnix: 1_700_000_000,
    inputs,
    recipient: encodeShieldedAddress(recipientSpend, recipientView, { prefix: "clairs" }),
    amount: "7uclair",
    rootSeed,
    merklePathProvider: pairedMerklePathProvider(inputs.map(input => input.note)),
    auditDisclosureTargetPubKeyHex: Buffer.from(packPoint(audit)).toString("hex"),
    userPrivacyPolicy: "amount-from-to",
    userDisclosureMode: "public"
  });
  assert.equal(selectivePayload.user_privacy_policy, 7);
  assert.equal(selectivePayload.user_disclosure_mode, 1);
  const disclosure = unmarshalDisclosurePlaintextV1(Buffer.from(selectivePayload.user_disclosure_payload_hex, "hex"));
  const tampered = {
    ...selectivePayload,
    user_disclosure_payload_hex: Buffer.from(marshalDisclosurePlaintextV1({
      ...disclosure,
      amount: disclosure.amount + 1n
    })).toString("hex")
  };
  assert.throws(
    () => validatePreparedTransferV5PayloadMetadata(tampered),
    /public transfer disclosure digest does not match plaintext/
  );

  let signerCalls = 0;
  await assert.rejects(
    () => buildPreparedTransferPayload({
      creator: "clair1creator",
      chainId: "clairveil-test-1",
      chainNowUnix: 1_700_000_000,
      inputs,
      recipient: encodeShieldedAddress(recipientSpend, recipientView, { prefix: "clairs" }),
      amount: "7uclair",
      rootSeed,
      merklePathProvider: () => ({ root: field(1n), path: [], path_helper: [] }),
      auditDisclosureTargetPubKeyHex: Buffer.from(packPoint(audit)).toString("hex"),
      ownerIntentSigner: {
        signJoinSplitOwnerIntent() {
          signerCalls += 1;
          return new Uint8Array(64);
        }
      }
    }),
    /merkle path must be 32 levels/
  );
  assert.equal(signerCalls, 0);
});

test("external transfer signer receives a validated full JoinSplit request before callback", async () => {
  const rootSeed = new Uint8Array(32).fill(12);
  const senderSpend = deriveSpendKeys(rootSeed).pubKey;
  const senderView = deriveViewKeys(rootSeed).pubKey;
  const recipientSpend = derivePubKeyFromScalar(47n);
  const recipientView = derivePubKeyFromScalar(53n);
  const audit = derivePubKeyFromScalar(59n);
  const assetId = computeAssetIdV1("uclair");
  const inputs = [31n, 37n].map((randomness, index) => ({
    note: createNote({
      spendPubKey: senderSpend,
      viewPubKey: senderView,
      amount: index === 0 ? 7n : 5n,
      assetId,
      randomness
    }),
    nullifier: field(BigInt(301 + index)),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: field(BigInt(401 + index)),
    height: 1,
    sequence: index
  }));
  const localSigner = createSpendNoteHashSigner(rootSeed);
  let request;
  const payload = await buildPreparedTransferPayload({
    creator: "clair1creator",
    chainId: "clairveil-test-1",
    chainNowUnix: 1_700_000_000,
    inputs,
    recipient: encodeShieldedAddress(recipientSpend, recipientView, { prefix: "clairs" }),
    amount: "7uclair",
    rootSeed,
    merklePathProvider: pairedMerklePathProvider(inputs.map(input => input.note)),
    auditDisclosureTargetPubKeyHex: Buffer.from(packPoint(audit)).toString("hex"),
    ownerIntentSigner: {
      async signJoinSplitOwnerIntent(candidate) {
        request = candidate;
        const validated = validateJoinSplitOwnerIntentSigningRequestV1(candidate);
        return localSigner.signSpendNoteHash(validated.expected_intent);
      }
    }
  });

  assert.equal(request.version, "joinsplit-owner-intent-signing-request-v1");
  assert.equal(request.input_notes.length, 2);
  assert.equal(request.output_notes.length, 2);
  assert.equal(request.final_effect.intent_hex.length, 64);
  assert.equal(payload.owner_signature_hex.length, 128);

  let callbacks = 0;
  const redirected = {
    ...request,
    final_effect: { ...request.final_effect, intent_hex: field(1n) }
  };
  await assert.rejects(
    () => signValidatedJoinSplitOwnerIntentV1({
      signJoinSplitOwnerIntent() {
        callbacks += 1;
        return new Uint8Array(64);
      }
    }, redirected),
    /final_effect.intent_hex does not match/
  );
  assert.equal(callbacks, 0);

  const aliasedNote = {
    ...request.input_notes[0],
    randomness: request.input_notes[0].randomness + FIELD_MODULUS
  };
  await assert.rejects(
    () => signValidatedJoinSplitOwnerIntentV1({
      signJoinSplitOwnerIntent() {
        callbacks += 1;
        return new Uint8Array(64);
      }
    }, { ...request, input_notes: [aliasedNote, request.input_notes[1]] }),
    /canonical BN254 field element/
  );
  assert.equal(callbacks, 0);
});
