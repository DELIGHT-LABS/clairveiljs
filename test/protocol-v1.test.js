import test from "node:test";
import assert from "node:assert/strict";
import {
  derivePubKeyFromScalar,
  packPoint
} from "clairveiljs/core";
import {
  canonicalBatchTransferPayloadBytesV1,
  computeAssetIdV1,
  computeBatchTransferPayloadDigestV1,
  computeNoteCommitmentV1,
  computeNoteNullifierV1,
  computeTransferFullDisclosureDigestV2,
  computeTransferUserDisclosureDigestV2,
  decryptTransferNoteV1,
  emptyNoteTreeRootsV1,
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
});
