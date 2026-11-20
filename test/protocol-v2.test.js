import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  privacyFixedV2, fixedBinaryVersionV2, notePlaintextV2Size, disclosurePlaintextV2Size,
  encryptedEnvelopeKindV2 as kinds, encryptedEnvelopeV2Size,
  validateNoteV2, computeNoteCommitmentV2, computeNoteNullifierV2,
  marshalNotePlaintextV2, unmarshalNotePlaintextV2,
  marshalDisclosurePlaintextV2, unmarshalDisclosurePlaintextV2,
  computeDisclosureDigestV2, verifyDisclosureDigestV2,
  wrapEncryptedEnvelopeV2, decodeEncryptedEnvelopeV2, unwrapEncryptedEnvelopeV2,
  encryptDepositNoteV2, decryptDepositNoteV2, encryptNoteForTransferV2, decryptTransferNoteV2,
  encryptDisclosureV2, decryptDisclosureV2
} from "clairveiljs/protocol-v2";
import { FIELD_MODULUS, CURVE_ORDER, canonicalFieldBytes, canonicalFieldHex } from "clairveiljs/crypto";
import { bytesFromHex, hexFromBytes } from "clairveiljs/browser-crypto";
import {
  marshalNotePlaintextV1, marshalDisclosurePlaintextV1, wrapEncryptedEnvelopeV1,
  unmarshalNotePlaintextV1, unmarshalDisclosurePlaintextV1, unwrapEncryptedEnvelopeV1
} from "clairveiljs/protocol-v1";

const fixture = JSON.parse(readFileSync(new URL("../fixtures/clairveil-v0.6.1-fixed/vectors.json", import.meta.url)));
const maximum = (1n << 128n) - 1n;
const seed = bytesFromHex(fixture.synthetic.root_seed_hex);
const viewScalar = BigInt(fixture.synthetic.note_view_scalar);
const disclosureScalar = BigInt(fixture.synthetic.disclosure_scalar);
const target = Object.fromEntries(Object.entries(fixture.synthetic.disclosure_target).map(([key, value]) => [key, BigInt(value)]));
const note = fixture.notes.at(-1).note;
const user = fixture.disclosures[0].disclosure;
const full = fixture.disclosures.at(-1).disclosure;
const normalized = value => Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, typeof entry === "string" && /^\d+$/.test(entry) ? BigInt(entry) : entry]));

function withEntropy(t, hex, run) {
  const entropy = bytesFromHex(hex);
  let offset = 0;
  const mock = t.mock.method(globalThis.crypto, "getRandomValues", out => {
    assert(offset + out.length <= entropy.length, "unexpected entropy request");
    out.set(entropy.subarray(offset, offset + out.length)); offset += out.length;
    return out;
  });
  try {
    const result = run();
    assert.equal(offset, entropy.length);
    return result;
  } finally { mock.mock.restore(); }
}

test("fixed-v2 notes, commitments and nullifiers match independent Core Go vectors", () => {
  assert.equal(privacyFixedV2, "privacy-fixed-v2");
  assert.equal(fixedBinaryVersionV2, 2);
  assert.equal(notePlaintextV2Size, 358);
  assert.equal(disclosurePlaintextV2Size, 400);
  for (const row of fixture.notes) {
    const encoded = marshalNotePlaintextV2(row.note);
    assert.equal(hexFromBytes(encoded), row.plaintext_hex);
    assert.deepEqual(unmarshalNotePlaintextV2(encoded), normalized(row.note));
    assert.equal(canonicalFieldHex(computeNoteCommitmentV2(row.note)), row.commitment_hex);
    assert.equal(canonicalFieldHex(computeNoteNullifierV2(row.note)), row.nullifier_hex);
    assert.equal(hexFromBytes(encoded.subarray(148, 164)), BigInt(row.note.amount).toString(16).padStart(32, "0"));
  }
});

test("fixed-v2 disclosure bytes and both digest schemes match all seven policies and full Go vectors", () => {
  for (const row of fixture.disclosures) {
    const encoded = marshalDisclosurePlaintextV2(row.disclosure);
    assert.equal(hexFromBytes(encoded), row.plaintext_hex);
    assert.deepEqual(unmarshalDisclosurePlaintextV2(encoded), normalized(row.disclosure));
    for (const scheme of ["transfer", "batch"]) {
      assert.equal(canonicalFieldHex(computeDisclosureDigestV2(row.disclosure, scheme)), row[`${scheme}_digest_hex`]);
      assert.equal(verifyDisclosureDigestV2(row.disclosure, row[`${scheme}_digest_hex`], scheme), true);
      assert.throws(() => verifyDisclosureDigestV2({ ...row.disclosure, outputIndex: 0 }, row[`${scheme}_digest_hex`], scheme), /digest mismatch/);
    }
  }
  assert.throws(() => computeDisclosureDigestV2(user), /scheme/);
  assert.throws(() => verifyDisclosureDigestV2(user, new Uint8Array(32), "transfer"), /non-zero/);
  assert.throws(() => verifyDisclosureDigestV2(user, canonicalFieldBytes(FIELD_MODULUS - 1n), "other"), /scheme/);
  assert.throws(() => verifyDisclosureDigestV2(user, fixture.disclosures[0].batch_digest_hex, "transfer"), /digest mismatch/);
  for (const key of ["amount", "assetID", "commitment", "disclosureBlinding"]) {
    const altered = { ...user, [key]: BigInt(user[key]) + (key === "amount" ? -1n : 1n) };
    assert.throws(() => verifyDisclosureDigestV2(altered, fixture.disclosures[0].batch_digest_hex, "batch"), /digest mismatch/);
  }
});

test("fixed-v2 deposit encryption and decryption match exact Go AES-GCM bytes", t => {
  for (const row of fixture.notes) {
    assert.deepEqual(decryptDepositNoteV2(row.deposit_hex, seed), normalized(row.note));
    const encrypted = withEntropy(t, row.deposit_entropy_hex, () => encryptDepositNoteV2(row.note, seed));
    assert.equal(hexFromBytes(encrypted), row.deposit_hex);
    assert.equal(encrypted.length, 406);
  }
});

test("fixed-v2 transfer encryption, view tags and bound decryption match exact Go ECIES bytes", t => {
  for (const row of fixture.notes) {
    const binding = { outputCommitment: row.commitment_hex, outputIndex: row.output_index, viewTag: row.view_tag_hex };
    assert.deepEqual(decryptTransferNoteV2(row.transfer_hex, viewScalar, binding), normalized(row.note));
    const encrypted = withEntropy(t, row.transfer_entropy_hex, () => encryptNoteForTransferV2(row.note, row.commitment_hex, row.output_index));
    assert.equal(hexFromBytes(encrypted.ciphertext), row.transfer_hex);
    assert.equal(hexFromBytes(encrypted.viewTag), row.view_tag_hex);
    assert.equal(encrypted.ciphertext.length, 438);
    assert.throws(() => decryptTransferNoteV2(row.transfer_hex, viewScalar, { ...binding, outputIndex: row.output_index + 1 }), /view tag/);
    assert.throws(() => encryptNoteForTransferV2(row.note, canonicalFieldBytes(1n), row.output_index), /commitment mismatch/);
  }
});

test("fixed-v2 user/audit/self-view disclosure encryption matches exact Go ECIES bytes", t => {
  for (const row of fixture.disclosures) for (const envelope of row.envelopes) {
    const decoded = decryptDisclosureV2(envelope.ciphertext_hex, disclosureScalar, envelope.kind);
    assert.deepEqual(decoded, normalized(row.disclosure));
    assert.equal(verifyDisclosureDigestV2(decoded, row.batch_digest_hex, "batch"), true);
    const encrypted = withEntropy(t, envelope.entropy_hex, () => encryptDisclosureV2(row.disclosure, target, envelope.kind));
    assert.equal(hexFromBytes(encrypted), envelope.ciphertext_hex);
    assert.equal(encrypted.length, 480);
  }
});

test("fixed-v2 rejects legacy plaintext/envelopes and V1 rejects fixed-v2 even for small amounts", () => {
  const smallNote = { ...normalized(note), amount: 1n };
  const smallDisclosure = { ...normalized(user), amount: 1n };
  assert.throws(() => unmarshalNotePlaintextV2(marshalNotePlaintextV1(smallNote)), /358/);
  assert.throws(() => unmarshalDisclosurePlaintextV2(marshalDisclosurePlaintextV1(smallDisclosure)), /400/);
  assert.throws(() => unmarshalNotePlaintextV1(marshalNotePlaintextV2(smallNote)));
  assert.throws(() => unmarshalDisclosurePlaintextV1(marshalDisclosurePlaintextV2(smallDisclosure)));
  for (const kind of Object.values(kinds)) {
    const v1 = wrapEncryptedEnvelopeV1(kind, new Uint8Array(kind === 1 ? 378 : kind === 2 ? 410 : 452));
    assert.throws(() => unwrapEncryptedEnvelopeV2(v1, kind), /domain/);
    const v2 = wrapEncryptedEnvelopeV2(kind, new Uint8Array(encryptedEnvelopeV2Size(kind) - 20));
    assert.throws(() => unwrapEncryptedEnvelopeV1(v2, kind), /domain/);
  }
});

test("fixed-v2 rejects truncated, extended, legacy-tagged, wrong-version and reserved-bit payloads", () => {
  for (const [hex, decode, reservedOffsets] of [
    [fixture.notes[0].plaintext_hex, unmarshalNotePlaintextV2, [18, 19]],
    [fixture.disclosures[0].plaintext_hex, unmarshalDisclosurePlaintextV2, [19]],
    [fixture.notes[0].transfer_hex, decodeEncryptedEnvelopeV2, [19]]
  ]) {
    const raw = bytesFromHex(hex);
    assert.throws(() => decode(raw.subarray(0, -1)));
    assert.throws(() => decode(new Uint8Array([...raw, 0])));
    for (const offset of [0, 16, 17, ...reservedOffsets]) {
      const altered = raw.slice(); altered[offset] ^= 1;
      assert.throws(() => decode(altered));
    }
  }
  const invalidKind = bytesFromHex(fixture.notes[0].transfer_hex); invalidKind[18] = 0;
  assert.throws(() => decodeEncryptedEnvelopeV2(invalidKind), /kind/);
  assert.throws(() => unwrapEncryptedEnvelopeV2(fixture.notes[0].transfer_hex, kinds.depositNote), /kind/);
  assert.throws(() => encryptedEnvelopeV2Size(1.5), /kind/);
  assert.throws(() => unmarshalNotePlaintextV2(Array.from(bytesFromHex(fixture.notes[0].plaintext_hex))), /bytes/);
});

test("fixed-v2 note validation rejects unsafe fields, noncanonical points and malformed UTF-8", () => {
  for (const amount of [1, -1n, maximum + 1n, "01", " 1"]) assert.throws(() => validateNoteV2({ ...note, amount }));
  for (const field of ["assetID", "randomness", "receiverSpendPubKeyX"]) {
    for (const value of [-1n, FIELD_MODULUS, 1.5, null]) assert.throws(() => validateNoteV2({ ...note, [field]: value }));
  }
  for (const point of [{ x: 0n, y: 1n }, { x: 0n, y: FIELD_MODULUS - 1n }, { x: 1n, y: 1n }]) {
    assert.throws(() => validateNoteV2({ ...note, receiverSpendPubKeyX: point.x, receiverSpendPubKeyY: point.y }));
  }
  for (const memo of ["a".repeat(129), "\ud800", 123]) assert.throws(() => marshalNotePlaintextV2({ ...note, memo }), /memo/);
  for (const memo of ["a".repeat(128), "🧪".repeat(32), "\ufeffhello", ""]) {
    assert.equal(unmarshalNotePlaintextV2(marshalNotePlaintextV2({ ...note, memo })).memo, memo);
  }
  for (const [offset, value] of [[228, 1], [229, 129], [357, 1], [230, 255]]) {
    const altered = marshalNotePlaintextV2({ ...note, memo: "x" }); altered[offset] = value;
    assert.throws(() => unmarshalNotePlaintextV2(altered));
  }
  const noncanonical = marshalNotePlaintextV2(note); noncanonical.set(bytesFromHex(FIELD_MODULUS.toString(16).padStart(64, "0")), 164);
  assert.throws(() => unmarshalNotePlaintextV2(noncanonical), /canonical/);
});

test("fixed-v2 disclosures enforce exact plane, policy, bitmap, sentinel and field bounds", () => {
  for (const patch of [
    { plane: 0 }, { plane: 2 }, { policy: 0 }, { policy: 8 }, { disclosedFieldBitmap: 0 },
    { amount: maximum + 1n }, { amount: 1 }, { commitment: 0n }, { assetID: 0n },
    { disclosureBlinding: 0n }, { senderSpendKeyX: 1n }, { recipientSpendKeyY: 1n },
    { outputIndex: 2 ** 32 }, { outputIndex: -1 }, { outputIndex: 1.5 }
  ]) assert.throws(() => marshalDisclosurePlaintextV2({ ...user, ...patch }));
  const hiddenAmount = fixture.disclosures[1].disclosure;
  assert.throws(() => marshalDisclosurePlaintextV2({ ...hiddenAmount, amount: 1n }), /undisclosed/);
  assert.throws(() => marshalDisclosurePlaintextV2({ ...full, policy: 7 }), /full/);
  assert.throws(() => marshalDisclosurePlaintextV2({ ...full, senderSpendKeyX: 0n, senderSpendKeyY: 1n }), /point/);
  assert.throws(() => encryptDisclosureV2(full, target, kinds.userDisclosure), /plane/);
  assert.throws(() => encryptDisclosureV2(user, target, kinds.auditDisclosure), /plane/);
  const relabeled = bytesFromHex(fixture.disclosures[0].envelopes[0].ciphertext_hex); relabeled[18] = kinds.auditDisclosure;
  assert.throws(() => decryptDisclosureV2(relabeled, disclosureScalar, kinds.auditDisclosure), /plane/);
});

test("fixed-v2 decryption rejects malformed keys, tampering and wrong keys without plaintext", () => {
  const row = fixture.notes.at(-1);
  for (const scalar of [0n, -1n, CURVE_ORDER, CURVE_ORDER + viewScalar, Number(viewScalar)]) {
    assert.throws(() => decryptTransferNoteV2(row.transfer_hex, scalar), /scalar/);
  }
  assert.throws(() => decryptTransferNoteV2(row.transfer_hex, viewScalar + 1n));
  assert.throws(() => decryptDepositNoteV2(row.deposit_hex, new Uint8Array(32).fill(9)));
  for (const badSeed of [new Uint8Array(31), new Uint8Array(33), "seed"]) {
    assert.throws(() => encryptDepositNoteV2(note, badSeed), /32/);
    assert.throws(() => decryptDepositNoteV2(row.deposit_hex, badSeed), /32/);
  }
  for (const offset of [20, 52, 64, 437]) {
    const altered = bytesFromHex(row.transfer_hex); altered[offset] ^= 1;
    assert.throws(() => decryptTransferNoteV2(altered, viewScalar));
  }
  const identity = bytesFromHex(row.transfer_hex); identity.fill(0, 20, 52); identity[20] = 1;
  assert.throws(() => decryptTransferNoteV2(identity, viewScalar), /point|identity/);
});

test("fixed-v2 rejects zero/out-of-range random scalars and propagates RNG failures", t => {
  const row = fixture.notes[0];
  const rejection = "00".repeat(32) + "ff".repeat(32) + row.transfer_entropy_hex;
  const result = withEntropy(t, rejection, () => encryptNoteForTransferV2(row.note, row.commitment_hex, row.output_index));
  assert.equal(hexFromBytes(result.ciphertext), row.transfer_hex);
  const mock = t.mock.method(globalThis.crypto, "getRandomValues", () => { throw new Error("synthetic RNG failure"); });
  try { assert.throws(() => encryptDepositNoteV2(note, seed), /synthetic RNG failure/); }
  finally { mock.mock.restore(); }
});

test("fixed-v2 envelope decoding returns detached bytes and leaves caller inputs unchanged", () => {
  const raw = bytesFromHex(fixture.notes[0].transfer_hex);
  const original = raw.slice();
  const decoded = decodeEncryptedEnvelopeV2(raw);
  assert.equal(decoded.kind, kinds.transferNote);
  decoded.ciphertext.fill(0);
  assert.deepEqual(raw, original);
  const root = seed.slice();
  decryptDepositNoteV2(fixture.notes[0].deposit_hex, root);
  assert.deepEqual(root, seed);
});
