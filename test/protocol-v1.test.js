import test from "node:test";
import assert from "node:assert/strict";
import {
  derivePubKeyFromScalar,
  packPoint
} from "clairveiljs/core";
import {
  canonicalBatchTransferPayloadBytesV1,
  computeAssetIdV1,
  computeBatchFullDisclosureDigestV1,
  computeBatchTransferIntentV1,
  computeBatchUserDisclosureDigestV1,
  computeBatchUserDisclosureVectorRootV1,
  computeBatchVectorRootV1,
  computeBatchTransferPayloadDigestV1,
  computeChainDomainV1,
  computeNoteCommitmentV1,
  computeNoteNullifierV1,
  computeTransferFullDisclosureDigestV2,
  computeTransferUserDisclosureDigestV2,
  decryptDisclosureV1,
  decryptTransferNoteV1,
  emptyNoteTreeRootsV1,
  encryptDisclosureV1,
  encryptNoteForTransferV1,
  encryptedEnvelopeKindV1,
  marshalDisclosurePlaintextV1,
  unmarshalDisclosurePlaintextV1,
  wrapEncryptedEnvelopeV1
} from "clairveiljs/protocol-v1";

function fieldBytes(value) {
  const output = new Uint8Array(32);
  output[31] = value;
  return output;
}

test("privacy-fixed-v1 note primitives match the Clairveil main golden vector", () => {
  const spend = derivePubKeyFromScalar(17n);
  const view = derivePubKeyFromScalar(19n);
  const note = {
    receiverSpendPubKeyX: spend.x,
    receiverSpendPubKeyY: spend.y,
    receiverViewPubKeyX: view.x,
    receiverViewPubKeyY: view.y,
    amount: 7n,
    assetID: computeAssetIdV1("uclair"),
    randomness: 13n,
    memo: "fixed"
  };

  assert.equal(
    computeAssetIdV1("uclair").toString(16).padStart(64, "0"),
    "238d5f23e4d918d40b0982ce3aef16a75c4d1760193d1c3b30b9f5df681903ca"
  );
  assert.equal(
    computeNoteCommitmentV1(note).toString(16).padStart(64, "0"),
    "023aab554dcb995210888fa4e28c3d718568c1de0623578c690a2b6ca9d3610a"
  );
  assert.equal(
    computeNoteNullifierV1(note).toString(16).padStart(64, "0"),
    "13b50fceae57ce77eee3f686abc1563aadc27ff6d1e32ce2fcc599463d28585b"
  );
  assert.deepEqual(
    emptyNoteTreeRootsV1(2).map(value => value.toString(16).padStart(64, "0")),
    [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "2a9932954f9328683b24310f96581603f12544f6da3910aeefebbfa84789b296",
      "29bae378ecc69a3c6e1c861407bd57c9c8cd34d37ebc2d4fe8c205952f62793a"
    ]
  );

  const encrypted = encryptNoteForTransferV1(note, fieldBytes(3), 0);
  assert.equal(encrypted.ciphertext.length, 430);
  assert.equal(encrypted.viewTag.length, 2);
  assert.deepEqual(decryptTransferNoteV1(encrypted.ciphertext, 19n), note);
});

test("batch canonical payload excludes creator and proof while binding every effect", () => {
  const spend = derivePubKeyFromScalar(17n);
  const view = derivePubKeyFromScalar(19n);
  const note = {
    receiverSpendPubKeyX: spend.x,
    receiverSpendPubKeyY: spend.y,
    receiverViewPubKeyX: view.x,
    receiverViewPubKeyY: view.y,
    amount: 7n,
    assetID: computeAssetIdV1("uclair"),
    randomness: 13n,
    memo: "batch"
  };
  const commitment = fieldBytes(3);
  const encrypted = encryptNoteForTransferV1(note, commitment, 0);
  const message = {
    creator: "clair1creator",
    proof: new Uint8Array(164).fill(1),
    root: fieldBytes(1),
    nullifiers: [fieldBytes(2)],
    outputs: [{
      commitment,
      ciphertext: encrypted.ciphertext,
      viewTag: encrypted.viewTag,
      userPrivacyPolicy: 0,
      userDisclosureMode: 0,
      userDisclosureDigest: new Uint8Array(),
      userDisclosureTargetPubkey: new Uint8Array(),
      userDisclosurePayload: new Uint8Array(),
      fullDisclosureDigest: fieldBytes(4),
      auditDisclosurePayload: wrapEncryptedEnvelopeV1(encryptedEnvelopeKindV1.auditDisclosure, new Uint8Array(452)),
      selfViewDisclosurePayload: new Uint8Array()
    }],
    auditKeyId: "audit-key-1",
    auditKeyEpoch: 1n,
    auditDisclosureTargetPubkey: packPoint(view),
    expiresAtUnix: 4_102_448_400n
  };
  const canonical = canonicalBatchTransferPayloadBytesV1(message);
  const digest = computeBatchTransferPayloadDigestV1(message);
  const mutated = { ...message, creator: "clair1replacement", proof: new Uint8Array(164).fill(9) };

  assert.deepEqual(canonicalBatchTransferPayloadBytesV1(mutated), canonical);
  assert.deepEqual(computeBatchTransferPayloadDigestV1(mutated).bytes, digest.bytes);
  assert.equal(digest.bytes.length, 32);
  assert.ok(canonical.length > 0);
});

test("privacy-fixed-v1 disclosure plaintext and transfer blinded digests are canonical", () => {
  const senderSpend = derivePubKeyFromScalar(17n);
  const senderView = derivePubKeyFromScalar(19n);
  const recipientSpend = derivePubKeyFromScalar(23n);
  const recipientView = derivePubKeyFromScalar(29n);
  const disclosure = {
    plane: 1,
    outputIndex: 0,
    policy: 7,
    disclosedFieldBitmap: 7,
    commitment: 101n,
    amount: 7n,
    assetID: computeAssetIdV1("uclair"),
    senderSpendKeyX: senderSpend.x,
    senderSpendKeyY: senderSpend.y,
    senderViewKeyX: senderView.x,
    senderViewKeyY: senderView.y,
    recipientSpendKeyX: recipientSpend.x,
    recipientSpendKeyY: recipientSpend.y,
    recipientViewKeyX: recipientView.x,
    recipientViewKeyY: recipientView.y,
    disclosureBlinding: 13n
  };
  const encoded = marshalDisclosurePlaintextV1(disclosure);
  assert.equal(encoded.length, 392);
  assert.deepEqual(unmarshalDisclosurePlaintextV1(encoded), disclosure);

  const digestInput = {
    commitment: disclosure.commitment,
    amount: disclosure.amount,
    assetID: disclosure.assetID,
    fromSpendPubKeyX: senderSpend.x,
    fromSpendPubKeyY: senderSpend.y,
    fromViewPubKeyX: senderView.x,
    fromViewPubKeyY: senderView.y,
    toSpendPubKeyX: recipientSpend.x,
    toSpendPubKeyY: recipientSpend.y,
    toViewPubKeyX: recipientView.x,
    toViewPubKeyY: recipientView.y,
    outputIndex: 0,
    disclosureBlinding: 13n
  };
  assert.equal(computeTransferUserDisclosureDigestV2({ ...digestInput, policy: 7 }).toString(16).padStart(64, "0"), "27c6806d9b24568889da32707c7a61515f1e83e00f9239aae42ee8840462288c");
  assert.equal(computeTransferFullDisclosureDigestV2(digestInput).toString(16).padStart(64, "0"), "18328bc0503673a4318c5431c24185ffa65b4903be7a252c27b7e51f9575a251");
  assert.equal(computeTransferUserDisclosureDigestV2({ policy: 0, commitment: disclosure.commitment }), 0n);
  assert.throws(() => marshalDisclosurePlaintextV1({ ...disclosure, policy: 1, disclosedFieldBitmap: 1, senderSpendKeyX: 1n }));

  const encrypted = encryptDisclosureV1(disclosure, recipientView, encryptedEnvelopeKindV1.auditDisclosure);
  assert.equal(encrypted.length, 472);
  assert.deepEqual(decryptDisclosureV1(encrypted, 29n, encryptedEnvelopeKindV1.auditDisclosure), disclosure);
  assert.throws(() => decryptDisclosureV1(encrypted, 29n, encryptedEnvelopeKindV1.userDisclosure), /kind mismatch/);
});

test("batch 16x32 vector, disclosure, and intent public inputs match Clairveil main", () => {
  const nullifiers = Array(16).fill(0n); nullifiers[0] = 1n;
  const commitments = Array(32).fill(0n); commitments[0] = 2n;
  const fullDigests = Array(32).fill(0n); fullDigests[0] = 3n;
  const rawUserDigests = Array(32).fill(0n);
  const policies = Array(32).fill(0);
  const nullifierRoot = computeBatchVectorRootV1("nullifier", 1, nullifiers);
  const commitmentRoot = computeBatchVectorRootV1("commitment", 1, commitments);
  const userRoot = computeBatchUserDisclosureVectorRootV1(1, policies, rawUserDigests);
  const fullRoot = computeBatchVectorRootV1("full_disclosure", 1, fullDigests);
  const pad = value => value.toString(16).padStart(64, "0");
  assert.deepEqual([nullifierRoot, commitmentRoot, userRoot, fullRoot].map(pad), [
    "021c58c9c3f7aa80fd13c1f0c2895441f5c974a4df42a7ec24cf0b6d0b6f8bdd",
    "2214fdd91882e60da9c1cecea7d3ede71a1879b649c4d4e7afe89953a0cad663",
    "0800ac722e07e30f4a9009e9a514f4a1f9d037abd2b9cf63b8ee3a92893df8ad",
    "11b02147c6388fbc4f7853591139fac5f9fed4a7b8d7a2e8c16f393a3b265dbd"
  ]);
  assert.equal(pad(computeBatchTransferIntentV1({
    chainDomain: computeChainDomainV1("clairveil-test-1"), merkleRoot: 4n, inputCount: 1, outputCount: 1, assetID: 5n,
    nullifierRoot, commitmentRoot, userDisclosureRoot: userRoot, fullDisclosureRoot: fullRoot,
    payloadDigestHi: 6n, payloadDigestLo: 7n, expiresAtUnix: 100
  })), "0a3b7787337b64960d2d28f4e812cbb84cd66053ede4c207524b6f6638de0ee0");

  const senderSpend = derivePubKeyFromScalar(17n); const senderView = derivePubKeyFromScalar(19n);
  const recipientSpend = derivePubKeyFromScalar(23n); const recipientView = derivePubKeyFromScalar(29n);
  const disclosureInput = {
    outputIndex: 0, commitment: 101n, policy: 7, disclosedFieldBitmap: 7, selectedAmount: 7n,
    selectedFromSpendKeyX: senderSpend.x, selectedFromSpendKeyY: senderSpend.y, selectedFromViewKeyX: senderView.x, selectedFromViewKeyY: senderView.y,
    selectedToSpendKeyX: recipientSpend.x, selectedToSpendKeyY: recipientSpend.y, selectedToViewKeyX: recipientView.x, selectedToViewKeyY: recipientView.y,
    assetID: computeAssetIdV1("uclair"), userDisclosureBlinding: 13n
  };
  assert.equal(pad(computeBatchUserDisclosureDigestV1(disclosureInput)), "03fed151a125937b87fb9f4651be30c4965378a4d91c7006380ab95e57925de2");
  assert.equal(pad(computeBatchFullDisclosureDigestV1({
    outputIndex: 0, commitment: 101n, amount: 7n, assetID: disclosureInput.assetID,
    senderSpendKeyX: senderSpend.x, senderSpendKeyY: senderSpend.y, senderViewKeyX: senderView.x, senderViewKeyY: senderView.y,
    recipientSpendKeyX: recipientSpend.x, recipientSpendKeyY: recipientSpend.y, recipientViewKeyX: recipientView.x, recipientViewKeyY: recipientView.y,
    fullDisclosureBlinding: 17n
  })), "113143773b99fdbdce53f4dd4ce914e887d0fb880a4be55eb3dae9075f75258b");
});
