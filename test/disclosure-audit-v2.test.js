import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decodeUserDisclosureFromScanOutputV2, decodeSelfViewDisclosureFromScanOutputV2 } from 'clairveiljs/disclosure-v2';
import { validatePrivacyScanPageV2 } from 'clairveiljs/scan-v2';
import { prepareDepositMaterialV2 } from 'clairveiljs/preparation-v2';
import { decryptDepositNoteV2, encryptNoteForTransferV2, marshalDisclosurePlaintextV2,
  computeDisclosureDigestV2, encryptDisclosureV2, encryptedEnvelopeKindV2 } from 'clairveiljs/protocol-v2';
import { canonicalFieldBytes, packPoint } from 'clairveiljs/crypto';

const audit = JSON.parse(readFileSync(new URL('../fixtures/clairveil-v0.6.1-audit/vectors.json', import.meta.url)));
const fixed = JSON.parse(readFileSync(new URL('../fixtures/clairveil-v0.6.1-fixed/vectors.json', import.meta.url)));
const target = Object.fromEntries(Object.entries(fixed.synthetic.disclosure_target).map(([k,v]) => [k, BigInt(v)]));
const options = { disclosureScalar: BigInt(fixed.synthetic.disclosure_scalar), disclosurePubKeyHex: Buffer.from(packPoint(target)).toString('hex') };
function fixture({ encrypted = false, policy = 7, mutate = () => {} } = {}) {
  const seed = new Uint8Array(32).fill(5), key = audit.records[1];
  const common = { height: '10', globalSequence: '4', txHash: new Uint8Array(32).fill(1), eventType: 'shielded_transfer',
    circuitSetId: 'privacy-note-v1-u128-audit-field-v1', payloadVersion: 'privacy-fixed-v2', scanSchemaVersion: 'privacy-scan-v2',
    auditKeyId: key.key_id_hex, auditKeyEpoch: key.epoch, auditTargetPubkey: Buffer.from(key.public_key_hex, 'hex'), effectId: new Uint8Array(32).fill(2) };
  const outputs = [0,1].map(index => {
    const material = prepareDepositMaterialV2({ rootSeed: seed, amount: 1n << 65n, denom: 'uclair' });
    const note = decryptDepositNoteV2(material.output.ciphertext, seed);
    const encryptedNote = encryptNoteForTransferV2(note, material.output.commitment, index);
    const output = { ...common, outputIndex: index, commitment: material.output.commitment, ciphertext: encryptedNote.ciphertext,
      viewTag: encryptedNote.viewTag, leafIndexFound: true, leafIndex: String(index) };
    material.clear(); return output;
  });
  const user = { ...fixed.disclosures.find(r => r.disclosure.policy === policy && r.disclosure.plane === 1).disclosure, outputIndex: 0,
    commitment: BigInt('0x' + Buffer.from(outputs[0].commitment).toString('hex')) };
  const full = { ...fixed.disclosures.at(-1).disclosure, outputIndex: 0, commitment: user.commitment };
  Object.assign(outputs[0], { userPrivacyPolicy: policy,
    userDisclosureMode: encrypted ? 'USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED' : 'USER_DISCLOSURE_MODE_PUBLIC',
    userDisclosureTargetPubkey: encrypted ? packPoint(target) : new Uint8Array(),
    userDisclosureDigest: canonicalFieldBytes(computeDisclosureDigestV2(user, 'transfer')),
    userDisclosurePayload: encrypted ? encryptDisclosureV2(user, target, encryptedEnvelopeKindV2.userDisclosure) : marshalDisclosurePlaintextV2(user),
    fullDisclosureDigest: canonicalFieldBytes(computeDisclosureDigestV2(full, 'transfer')),
    selfViewDisclosurePayload: encryptDisclosureV2(full, target, encryptedEnvelopeKindV2.selfViewDisclosure) });
  mutate(outputs[0]);
  const page = validatePrivacyScanPageV2({ scanSchemaVersion: 'privacy-scan-v2', summaries: [{ ...common, outputCount: 2, nullifiers: [canonicalFieldBytes(3n), canonicalFieldBytes(4n)] }],
    outputs, nextCursor: { height: '10', globalSequence: '4', outputIndex: 1 }, hasMore: false });
  return { output: page.outputs[0], change: page.outputs[1], user, full };
}
test('V2 typed disclosure decodes all seven policies, encrypted recipient and self view at uint128 width', () => {
  for (let policy = 1; policy <= 7; policy++) {
    const f = fixture({ policy }), r = decodeUserDisclosureFromScanOutputV2(f.output);
    assert.equal(r.verified, true); assert.equal(r.payload.version, 'privacy-fixed-v2');
    assert.equal(r.amount, policy & 1 ? f.user.amount : '');
    assert.equal(Boolean(r.from), Boolean(policy & 4)); assert.equal(Boolean(r.to), Boolean(policy & 2));
  }
  const f = fixture({ encrypted: true });
  assert.equal(decodeUserDisclosureFromScanOutputV2(f.output, options).amount, f.user.amount);
  assert.equal(decodeSelfViewDisclosureFromScanOutputV2(f.output, options).amount, f.full.amount);
});
test('V2 disclosure refuses unbranded records, mutations, change outputs, wrong targets, digests and transaction hashes', () => {
  const f = fixture({ encrypted: true });
  assert.throws(() => decodeUserDisclosureFromScanOutputV2({ ...f.output }, options));
  assert.throws(() => decodeUserDisclosureFromScanOutputV2(f.change, options));
  assert.throws(() => decodeUserDisclosureFromScanOutputV2(f.output, { ...options, disclosurePubKeyHex: '00'.repeat(32) }));
  assert.throws(() => decodeSelfViewDisclosureFromScanOutputV2(f.output, { disclosureScalar: 1n }));
  assert.throws(() => decodeUserDisclosureFromScanOutputV2(f.output, { ...options, txHash: 'ab'.repeat(32) }));
  assert.throws(() => decodeUserDisclosureFromScanOutputV2(f.output, { ...options, assetDenom: 'wrong' }));
  assert.throws(() => fixture({ mutate: o => { o.userDisclosureDigest = canonicalFieldBytes(1n); } }));
  const bad = fixture({ encrypted: true, mutate: o => { o.userDisclosureDigest = canonicalFieldBytes(1n); } });
  assert.throws(() => decodeUserDisclosureFromScanOutputV2(bad.output, options));
  f.output.user_disclosure_payload[30] ^= 1;
  assert.throws(() => decodeUserDisclosureFromScanOutputV2(f.output, options));
});
