import {
  CURVE_BASE, CURVE_ORDER, bytesToBigIntBE, canonicalFieldBytes,
  hashStringToField, mimcHash, packPoint, scalarMultiply, unpackPoint
} from "../core/crypto.js";
import {
  aesGcmDecrypt, aesGcmEncrypt, bytesFromHex, concatBytes, randomBytes, sha256, utf8Bytes
} from "../core/browser-crypto.js";
import { parseAmount128 } from "../core/amount.js";
import { domainField } from "./protocol-domain.js";
import { equalBytes as equal, integerBytes } from "../core/encoding.js";
import { canonicalField as field, canonicalPoint as point } from "../core/curve-validation.js";

// Core v0.6.1 retains Go's V1 type names and note hash domains while changing
// the fixed wire format to v2. Explicit JS names prevent a V1 wire fallback.
export const privacyFixedV2 = "privacy-fixed-v2";
export const fixedBinaryVersionV2 = 2;
export const notePlaintextV2Size = 358;
export const disclosurePlaintextV2Size = 400;
export const encryptedEnvelopeV2HeaderSize = 20;
export const noteMemoCapacityV2 = 128;
export const encryptedEnvelopeKindV2 = Object.freeze({
  depositNote: 1, transferNote: 2, userDisclosure: 3, auditDisclosure: 4, selfViewDisclosure: 5
});

const tags = Object.freeze({
  note: sha256("clairveil.note-plaintext.v2").slice(0, 16),
  disclosure: sha256("clairveil.disclosure-plaintext.v2").slice(0, 16),
  envelope: sha256("clairveil.encrypted-envelope.v2").slice(0, 16)
});
const noteKeys = ["receiverSpendPubKeyX", "receiverSpendPubKeyY", "receiverViewPubKeyX", "receiverViewPubKeyY"];
const senderKeys = ["senderSpendKeyX", "senderSpendKeyY", "senderViewKeyX", "senderViewKeyY"];
const recipientKeys = ["recipientSpendKeyX", "recipientSpendKeyY", "recipientViewKeyX", "recipientViewKeyY"];
const disclosureFields = ["assetID", ...senderKeys, ...recipientKeys, "disclosureBlinding"];
const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function bytes(value, label) {
  if (value instanceof Uint8Array) return Uint8Array.from(value);
  if (typeof value === "string" && /^(?:0x)?(?:[0-9a-fA-F]{2})+$/.test(value)) return bytesFromHex(value, label);
  throw new Error(`${label} must be bytes or a hexadecimal string`);
}
function fieldBytes(value, label, nonZero = false) {
  const raw = bytes(value, label);
  if (raw.length !== 32) throw new Error(`${label} must be exactly 32 bytes`);
  field(bytesToBigIntBE(raw), label, nonZero);
  return raw;
}
function uint32(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) throw new Error(`${label} must be a uint32 integer`);
  return value;
}
function integerAt(raw, offset, size) { return bytesToBigIntBE(raw.subarray(offset, offset + size)); }
function header(size, tag) {
  const raw = new Uint8Array(size);
  raw.set(tag); raw.set(integerBytes(fixedBinaryVersionV2, 2), 16);
  return raw;
}
function checkHeader(raw, size, tag, label) {
  if (raw.length !== size) throw new Error(`${label} must be exactly ${size} bytes`);
  if (!equal(raw.subarray(0, 16), tag)) throw new Error(`invalid ${label} domain tag`);
  if (integerAt(raw, 16, 2) !== 2n) throw new Error(`unsupported ${label} version`);
}
function noteCommitment(note) {
  return mimcHash(domainField("clairveil.note-commitment.v1"), ...noteKeys.map(key => note[key]), note.amount, note.assetID, note.randomness);
}
function noteNullifier(note, commitment = noteCommitment(note)) {
  return mimcHash(domainField("clairveil.note-nullifier.v1"), commitment, note.randomness, note.receiverSpendPubKeyX, note.receiverSpendPubKeyY);
}

export function validateNoteV2(note) {
  if (!note || typeof note !== "object") throw new Error("fixed-v2 note is required");
  const result = Object.fromEntries([...noteKeys, "assetID", "randomness"].map(key => [key, field(note[key], `note ${key}`)]));
  result.amount = parseAmount128(note.amount, "note amount");
  result.memo = note.memo ?? "";
  if (typeof result.memo !== "string") throw new Error("note memo must be a string");
  const memo = utf8Bytes(result.memo);
  if (memo.length > noteMemoCapacityV2 || utf8Decoder.decode(memo) !== result.memo) throw new Error("note memo must be valid UTF-8 within 128 bytes");
  point(result.receiverSpendPubKeyX, result.receiverSpendPubKeyY, "note spend public key");
  point(result.receiverViewPubKeyX, result.receiverViewPubKeyY, "note view public key");
  const commitment = noteCommitment(result);
  if (commitment === 0n || noteNullifier(result, commitment) === 0n) throw new Error("active note commitment and nullifier must be non-zero");
  return result;
}
export function computeNoteCommitmentV2(note) { return noteCommitment(validateNoteV2(note)); }
export function computeNoteNullifierV2(note) { return noteNullifier(validateNoteV2(note)); }

export function marshalNotePlaintextV2(note) {
  const value = validateNoteV2(note);
  const output = header(notePlaintextV2Size, tags.note);
  let offset = 20;
  for (const key of noteKeys) { output.set(canonicalFieldBytes(value[key]), offset); offset += 32; }
  output.set(integerBytes(value.amount, 16), offset); offset += 16;
  for (const key of ["assetID", "randomness"]) { output.set(canonicalFieldBytes(value[key]), offset); offset += 32; }
  const memo = utf8Bytes(value.memo);
  output.set(integerBytes(memo.length, 2), offset); output.set(memo, offset + 2);
  return output;
}
export function unmarshalNotePlaintextV2(input) {
  const raw = bytes(input, "NotePlaintextV2");
  checkHeader(raw, notePlaintextV2Size, tags.note, "NotePlaintextV2");
  if (raw[18] !== 0 || raw[19] !== 0) throw new Error("note reserved flags must be zero");
  const value = {};
  let offset = 20;
  for (const key of noteKeys) { value[key] = integerAt(raw, offset, 32); offset += 32; }
  value.amount = integerAt(raw, offset, 16); offset += 16;
  for (const key of ["assetID", "randomness"]) { value[key] = integerAt(raw, offset, 32); offset += 32; }
  const length = Number(integerAt(raw, offset, 2)); offset += 2;
  if (length > noteMemoCapacityV2) throw new Error("note memo exceeds fixed capacity");
  if (raw.subarray(offset + length).some(byte => byte !== 0)) throw new Error("note memo padding must be zero");
  value.memo = utf8Decoder.decode(raw.subarray(offset, offset + length));
  return validateNoteV2(value);
}

export function validateDisclosurePlaintextV2(payload) {
  if (!payload || typeof payload !== "object") throw new Error("fixed-v2 disclosure is required");
  const value = { plane: payload.plane, outputIndex: uint32(payload.outputIndex, "disclosure output index"),
    policy: uint32(payload.policy, "disclosure policy"), disclosedFieldBitmap: uint32(payload.disclosedFieldBitmap, "disclosure bitmap"),
    commitment: field(payload.commitment, "disclosure commitment", true), amount: parseAmount128(payload.amount, "disclosure amount") };
  for (const key of disclosureFields) value[key] = field(payload[key], `disclosure ${key}`, key === "assetID" || key === "disclosureBlinding");
  const bundle = keys => {
    point(value[keys[0]], value[keys[1]], "disclosure spend public key");
    point(value[keys[2]], value[keys[3]], "disclosure view public key");
  };
  if (value.plane === 1) {
    if (value.policy < 1 || value.policy > 7 || value.disclosedFieldBitmap !== value.policy) throw new Error("user disclosure requires matching policy/bitmap in 1..7");
    if (!(value.policy & 1) && value.amount !== 0n) throw new Error("undisclosed amount must be zero");
    for (const [keys, bit] of [[senderKeys, 4], [recipientKeys, 2]]) {
      if (value.policy & bit) bundle(keys);
      else if (keys.some(key => value[key] !== 0n)) throw new Error("undisclosed keys must be zero");
    }
  } else if (value.plane === 2) {
    if (value.policy !== 0xffffffff || value.disclosedFieldBitmap !== 7) throw new Error("full disclosure requires the full marker and bitmap");
    bundle(senderKeys); bundle(recipientKeys);
  } else throw new Error("unsupported disclosure plane");
  return value;
}
export function marshalDisclosurePlaintextV2(payload) {
  const value = validateDisclosurePlaintextV2(payload);
  const output = header(disclosurePlaintextV2Size, tags.disclosure);
  output[18] = value.plane;
  let offset = 20;
  for (const key of ["outputIndex", "policy", "disclosedFieldBitmap"]) { output.set(integerBytes(value[key], 4), offset); offset += 4; }
  output.set(canonicalFieldBytes(value.commitment), offset); offset += 32;
  output.set(integerBytes(value.amount, 16), offset); offset += 16;
  for (const key of disclosureFields) { output.set(canonicalFieldBytes(value[key]), offset); offset += 32; }
  return output;
}
export function unmarshalDisclosurePlaintextV2(input) {
  const raw = bytes(input, "DisclosurePlaintextV2");
  checkHeader(raw, disclosurePlaintextV2Size, tags.disclosure, "DisclosurePlaintextV2");
  if (raw[19] !== 0) throw new Error("disclosure reserved byte must be zero");
  const value = { plane: raw[18] };
  let offset = 20;
  for (const key of ["outputIndex", "policy", "disclosedFieldBitmap"]) { value[key] = Number(integerAt(raw, offset, 4)); offset += 4; }
  value.commitment = integerAt(raw, offset, 32); offset += 32;
  value.amount = integerAt(raw, offset, 16); offset += 16;
  for (const key of disclosureFields) { value[key] = integerAt(raw, offset, 32); offset += 32; }
  return validateDisclosurePlaintextV2(value);
}

// The transfer and batch circuits use distinct digest field orders/domains.
// Require the caller to select one explicitly; fixed-v2 framing does not select it.
export function computeDisclosureDigestV2(payload, scheme) {
  const d = validateDisclosurePlaintextV2(payload);
  const addresses = [...senderKeys, ...recipientKeys].map(key => d[key]);
  const index = BigInt(d.outputIndex);
  if (scheme === "transfer") return mimcHash(
    hashStringToField(d.plane === 1 ? "CLAIRVEIL_USER_DISCLOSURE_V2" : "CLAIRVEIL_FULL_DISCLOSURE_V2"),
    d.plane === 1 ? BigInt(d.policy) : 255n, index, d.commitment, d.amount, d.assetID, ...addresses, d.disclosureBlinding
  );
  if (scheme === "batch") return d.plane === 1
    ? mimcHash(domainField("clairveil.user-disclosure.v2"), index, d.commitment, BigInt(d.policy), BigInt(d.disclosedFieldBitmap), d.amount, ...addresses, d.assetID, d.disclosureBlinding)
    : mimcHash(domainField("clairveil.full-disclosure.v2"), index, d.commitment, d.amount, d.assetID, ...addresses, d.disclosureBlinding);
  throw new Error("disclosure digest scheme must be transfer or batch");
}
export function verifyDisclosureDigestV2(payload, expectedDigest, scheme) {
  const expected = fieldBytes(expectedDigest, "expected disclosure digest", true);
  if (!equal(canonicalFieldBytes(computeDisclosureDigestV2(payload, scheme)), expected)) throw new Error("disclosure digest mismatch");
  return true;
}

export function encryptedEnvelopeV2Size(kind) {
  switch (kind) {
    case 1: return encryptedEnvelopeV2HeaderSize + notePlaintextV2Size + 28;
    case 2: return encryptedEnvelopeV2HeaderSize + notePlaintextV2Size + 60;
    case 3: case 4: case 5: return encryptedEnvelopeV2HeaderSize + disclosurePlaintextV2Size + 60;
    default: throw new Error("unsupported encrypted envelope kind");
  }
}
export function wrapEncryptedEnvelopeV2(kind, ciphertext) {
  const size = encryptedEnvelopeV2Size(kind);
  const raw = bytes(ciphertext, "encrypted ciphertext");
  if (raw.length !== size - encryptedEnvelopeV2HeaderSize) throw new Error("encrypted ciphertext has invalid fixed length");
  const output = header(size, tags.envelope); output[18] = kind; output.set(raw, 20);
  return output;
}
export function decodeEncryptedEnvelopeV2(input) {
  const raw = bytes(input, "encrypted envelope");
  if (raw.length < encryptedEnvelopeV2HeaderSize) throw new Error("encrypted envelope is shorter than its header");
  if (!equal(raw.subarray(0, 16), tags.envelope)) throw new Error("invalid encrypted envelope domain tag");
  if (integerAt(raw, 16, 2) !== 2n) throw new Error("unsupported encrypted envelope version");
  if (raw.length !== encryptedEnvelopeV2Size(raw[18])) throw new Error("encrypted envelope has invalid fixed length");
  if (raw[19] !== 0) throw new Error("encrypted envelope reserved byte must be zero");
  return { kind: raw[18], ciphertext: raw.slice(encryptedEnvelopeV2HeaderSize) };
}
export function unwrapEncryptedEnvelopeV2(input, expectedKind) {
  encryptedEnvelopeV2Size(expectedKind);
  const decoded = decodeEncryptedEnvelopeV2(input);
  if (decoded.kind !== expectedKind) throw new Error("encrypted envelope kind mismatch");
  return decoded.ciphertext;
}

function privateScalar(value) {
  if (typeof value !== "bigint" || value <= 0n || value >= CURVE_ORDER) throw new Error("ECIES scalar must be a non-zero canonical subgroup scalar");
  return value;
}
function sampleScalar() {
  for (;;) {
    const entropy = randomBytes(32); entropy[0] &= 7;
    const value = bytesToBigIntBE(entropy); entropy.fill(0);
    if (value > 0n && value < CURVE_ORDER) return value;
  }
}
function encryptAsymmetric(plaintext, receiver) {
  const target = point(receiver?.x, receiver?.y, "receiver public key");
  const scalar = sampleScalar();
  const shared = scalarMultiply(target, scalar);
  const key = sha256(packPoint(shared));
  const nonce = randomBytes(12);
  try {
    return { ciphertext: concatBytes(packPoint(scalarMultiply(CURVE_BASE, scalar)), nonce, aesGcmEncrypt({ key, nonce, plaintext })), shared };
  } finally { key.fill(0); }
}
function sharedPoint(raw, scalar) {
  privateScalar(scalar);
  const ephemeral = unpackPoint(raw.subarray(0, 32));
  return scalarMultiply(point(ephemeral.x, ephemeral.y, "ephemeral public key"), scalar);
}
function decryptAsymmetric(raw, shared) {
  const key = sha256(packPoint(shared));
  try { return aesGcmDecrypt({ key, nonce: raw.subarray(32, 44), ciphertext: raw.subarray(44) }); }
  finally { key.fill(0); }
}
function viewTag(shared, commitment, index) {
  return canonicalFieldBytes(mimcHash(hashStringToField("clairveil.view_tag.v1"), shared.x, shared.y, bytesToBigIntBE(commitment), BigInt(index))).slice(0, 2);
}
function seedKey(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error("RootSeed must be exactly 32 bytes");
  return sha256(seed);
}

export function encryptDepositNoteV2(note, rootSeed) {
  const key = seedKey(rootSeed);
  let plaintext;
  try {
    plaintext = marshalNotePlaintextV2(note);
    const nonce = randomBytes(12);
    return wrapEncryptedEnvelopeV2(1, concatBytes(nonce, aesGcmEncrypt({ key, nonce, plaintext })));
  } finally { key.fill(0); plaintext?.fill(0); }
}
export function decryptDepositNoteV2(ciphertext, rootSeed) {
  const key = seedKey(rootSeed);
  let plaintext;
  try {
    const raw = unwrapEncryptedEnvelopeV2(ciphertext, 1);
    plaintext = aesGcmDecrypt({ key, nonce: raw.subarray(0, 12), ciphertext: raw.subarray(12) });
    return unmarshalNotePlaintextV2(plaintext);
  } finally { key.fill(0); plaintext?.fill(0); }
}
export function encryptNoteForTransferV2(note, outputCommitment, outputIndex) {
  const value = validateNoteV2(note);
  const commitment = fieldBytes(outputCommitment, "output commitment", true);
  const index = uint32(outputIndex, "output index");
  if (!equal(canonicalFieldBytes(noteCommitment(value)), commitment)) throw new Error("note commitment mismatch");
  const plaintext = marshalNotePlaintextV2(value);
  try {
    const { ciphertext, shared } = encryptAsymmetric(plaintext, { x: value.receiverViewPubKeyX, y: value.receiverViewPubKeyY });
    return { ciphertext: wrapEncryptedEnvelopeV2(2, ciphertext), viewTag: viewTag(shared, commitment, index) };
  } finally { plaintext.fill(0); }
}
export function decryptTransferNoteV2(ciphertext, scalar, binding) {
  const raw = unwrapEncryptedEnvelopeV2(ciphertext, 2);
  const shared = sharedPoint(raw, scalar);
  let commitment;
  if (binding !== undefined) {
    commitment = fieldBytes(binding?.outputCommitment, "output commitment", true);
    const index = uint32(binding?.outputIndex, "output index");
    const expectedTag = bytes(binding?.viewTag, "expected view tag");
    if (expectedTag.length !== 2 || !equal(viewTag(shared, commitment, index), expectedTag)) throw new Error("view tag mismatch");
  }
  const plaintext = decryptAsymmetric(raw, shared);
  try {
    const note = unmarshalNotePlaintextV2(plaintext);
    if (commitment && !equal(canonicalFieldBytes(noteCommitment(note)), commitment)) throw new Error("decrypted note commitment mismatch");
    return note;
  } finally { plaintext.fill(0); }
}
function disclosurePlane(kind) {
  if (kind === 3) return 1;
  if (kind === 4 || kind === 5) return 2;
  throw new Error("disclosure envelope kind must be user, audit or self-view");
}
export function encryptDisclosureV2(disclosure, target, kind) {
  const plane = disclosurePlane(kind);
  const value = validateDisclosurePlaintextV2(disclosure);
  if (value.plane !== plane) throw new Error("disclosure envelope plane mismatch");
  const plaintext = marshalDisclosurePlaintextV2(value);
  try { return wrapEncryptedEnvelopeV2(kind, encryptAsymmetric(plaintext, target).ciphertext); }
  finally { plaintext.fill(0); }
}
export function decryptDisclosureV2(ciphertext, scalar, expectedKind) {
  const plane = disclosurePlane(expectedKind);
  const raw = unwrapEncryptedEnvelopeV2(ciphertext, expectedKind);
  const plaintext = decryptAsymmetric(raw, sharedPoint(raw, scalar));
  try {
    const value = unmarshalDisclosurePlaintextV2(plaintext);
    if (value.plane !== plane) throw new Error("disclosure envelope plane mismatch");
    return value;
  } finally { plaintext.fill(0); }
}
