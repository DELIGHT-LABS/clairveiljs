import {
  CURVE_ORDER,
  FIELD_MODULUS,
  bytesToBigIntBE,
  canonicalFieldBytes,
  canonicalFieldHex,
  hashStringToField,
  mimcHash,
  packPoint,
  scalarMultiply,
  unpackPoint
} from "../core/crypto.js";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  bytesFromHex,
  concatBytes,
  hexFromBytes,
  randomBytes,
  sha256,
  utf8Bytes,
  utf8String
} from "../core/browser-crypto.js";
import { canonicalAssetDenomV1 } from "./asset-denom.js";

export const privacyFixedV1 = "privacy-fixed-v1";
export const activeCircuitSetIdV1 = "privacy-note-v1";
export const notePlaintextV1Size = 350;
export const disclosurePlaintextV1Size = 392;
export const encryptedEnvelopeV1HeaderSize = 20;
export const noteMemoCapacityV1 = 128;
export const batchTransferPayloadDomainV1 = "clairveil.batch-transfer-payload.v1";
export const transferPayloadDomainV1 = "clairveil.transfer-payload.v1";
export const batchVectorKindV1 = Object.freeze({
  nullifier: "nullifier",
  commitment: "commitment",
  userDisclosure: "user_disclosure",
  fullDisclosure: "full_disclosure"
});

export const encryptedEnvelopeKindV1 = Object.freeze({
  depositNote: 1,
  transferNote: 2,
  userDisclosure: 3,
  auditDisclosure: 4,
  selfViewDisclosure: 5
});

const fixedBinaryVersion = 1;
const maxUint64 = (1n << 64n) - 1n;

function bytes(value, label = "bytes") {
  if (value instanceof Uint8Array) return Uint8Array.from(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
  if (value instanceof ArrayBuffer) return new Uint8Array(value).slice();
  if (typeof value === "string") return bytesFromHex(value, label);
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new Error(`${label} must be bytes`);
}

function uint(value, bits, label) {
  const parsed = typeof value === "bigint" ? value : BigInt(value ?? 0);
  if (parsed < 0n || parsed >= (1n << BigInt(bits))) {
    throw new Error(`${label} must be an unsigned ${bits}-bit integer`);
  }
  return parsed;
}

function field(value, label, { nonZero = false } = {}) {
  const parsed = typeof value === "bigint" ? value : BigInt(value ?? 0);
  if (parsed < 0n || parsed >= FIELD_MODULUS || (nonZero && parsed === 0n)) {
    throw new Error(`${label} must be a${nonZero ? " non-zero" : ""} canonical BN254 field element`);
  }
  return parsed;
}

function fieldFromBytes(value, label, options) {
  const raw = bytes(value, label);
  if (raw.length !== 32) throw new Error(`${label} must be exactly 32 bytes`);
  field(bytesToBigIntBE(raw), label, options);
  return raw;
}

function u16be(value) {
  const parsed = Number(uint(value, 16, "u16"));
  return Uint8Array.of(parsed >>> 8, parsed & 0xff);
}

function u32be(value) {
  const parsed = Number(uint(value, 32, "u32"));
  return Uint8Array.of((parsed >>> 24) & 0xff, (parsed >>> 16) & 0xff, (parsed >>> 8) & 0xff, parsed & 0xff);
}

function u64be(value, label = "u64") {
  let parsed = uint(value, 64, label);
  const output = new Uint8Array(8);
  for (let index = 7; index >= 0; index -= 1) {
    output[index] = Number(parsed & 0xffn);
    parsed >>= 8n;
  }
  return output;
}

function readU16(data, offset) {
  return (data[offset] << 8) | data[offset + 1];
}

function readU32(data, offset) {
  return (((data[offset] << 24) >>> 0) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]) >>> 0;
}

function readU64(data, offset) {
  let value = 0n;
  for (let index = 0; index < 8; index += 1) value = (value << 8n) | BigInt(data[offset + index]);
  return value;
}

function writeLengthPrefixed(value, label = "field") {
  const raw = bytes(value, label);
  return concatBytes(u32be(raw.length), raw);
}

function writeByteSlice(values, label) {
  if (!Array.isArray(values)) throw new Error(`${label} must be an array`);
  return concatBytes(u32be(values.length), ...values.map((value, index) => writeLengthPrefixed(value, `${label} ${index}`)));
}

function fixedDomainTag(label) {
  return sha256(label).slice(0, 16);
}

function pointFromCoordinates(x, y, label) {
  const point = { x: field(x, `${label} x`), y: field(y, `${label} y`) };
  try {
    return unpackPoint(packPoint(point));
  } catch (error) {
    throw new Error(`${label} must be a canonical prime-subgroup point: ${error.message}`);
  }
}

function validUtf8(bytesValue) {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytesValue);
    return true;
  } catch {
    return false;
  }
}

function envelopeTag() {
  return fixedDomainTag("clairveil.encrypted-envelope.v1");
}

function envelopeCiphertextSize(kind) {
  switch (Number(kind)) {
    case encryptedEnvelopeKindV1.depositNote:
      return notePlaintextV1Size + 28;
    case encryptedEnvelopeKindV1.transferNote:
      return notePlaintextV1Size + 60;
    case encryptedEnvelopeKindV1.userDisclosure:
    case encryptedEnvelopeKindV1.auditDisclosure:
    case encryptedEnvelopeKindV1.selfViewDisclosure:
      return disclosurePlaintextV1Size + 60;
    default:
      throw new Error(`unsupported encrypted envelope kind ${kind}`);
  }
}

export function domainFieldV1(label) {
  const name = String(label || "");
  return bytesToBigIntBE(sha256(concatBytes(
    utf8Bytes("clairveil.field-domain.v1"),
    u32be(utf8Bytes(name).length),
    utf8Bytes(name)
  ))) % FIELD_MODULUS;
}

export function computeAssetIdV1(denom) {
  const canonicalDenom = canonicalAssetDenomV1(denom);
  const encoded = utf8Bytes(canonicalDenom);
  return bytesToBigIntBE(sha256(concatBytes(
    utf8Bytes("clairveil.asset-id.v1"),
    u32be(encoded.length),
    encoded
  ))) % FIELD_MODULUS;
}

export function computeNoteCommitmentV1(note) {
  const normalized = validateNoteV1(note);
  return mimcHash(
    domainFieldV1("clairveil.note-commitment.v1"),
    normalized.receiverSpendPubKeyX,
    normalized.receiverSpendPubKeyY,
    normalized.receiverViewPubKeyX,
    normalized.receiverViewPubKeyY,
    normalized.amount,
    normalized.assetID,
    normalized.randomness
  );
}

export function computeNoteNullifierV1(note) {
  const normalized = validateNoteV1(note);
  return mimcHash(
    domainFieldV1("clairveil.note-nullifier.v1"),
    computeNoteCommitmentV1(normalized),
    normalized.randomness,
    normalized.receiverSpendPubKeyX,
    normalized.receiverSpendPubKeyY
  );
}

export function computeNoteTreeNodeV1(level, left, right) {
  return mimcHash(
    domainFieldV1("clairveil.note-tree-node.v1"),
    uint(level, 32, "merkle level"),
    field(left, "merkle left"),
    field(right, "merkle right")
  );
}

export function emptyNoteTreeRootsV1(depth) {
  const parsedDepth = Number(uint(depth, 32, "merkle depth"));
  const roots = [0n];
  for (let level = 0; level < parsedDepth; level += 1) {
    roots.push(computeNoteTreeNodeV1(level, roots[level], roots[level]));
  }
  return roots;
}

export function validateNoteV1(note) {
  if (!note || typeof note !== "object") throw new Error("NoteV1 is required");
  const normalized = {
    receiverSpendPubKeyX: field(note.receiverSpendPubKeyX ?? note.rsx, "NoteV1 receiver spend pubkey x"),
    receiverSpendPubKeyY: field(note.receiverSpendPubKeyY ?? note.rsy, "NoteV1 receiver spend pubkey y"),
    receiverViewPubKeyX: field(note.receiverViewPubKeyX ?? note.rvx, "NoteV1 receiver view pubkey x"),
    receiverViewPubKeyY: field(note.receiverViewPubKeyY ?? note.rvy, "NoteV1 receiver view pubkey y"),
    amount: uint(note.amount ?? note.am, 64, "NoteV1 amount"),
    assetID: field(note.assetID ?? note.assetId ?? note.as, "NoteV1 asset id", { nonZero: true }),
    randomness: field(note.randomness ?? note.rn, "NoteV1 randomness"),
    memo: String(note.memo ?? note.mm ?? "")
  };
  if (utf8Bytes(normalized.memo).length > noteMemoCapacityV1) {
    throw new Error(`NoteV1 memo exceeds fixed capacity ${noteMemoCapacityV1}`);
  }
  pointFromCoordinates(normalized.receiverSpendPubKeyX, normalized.receiverSpendPubKeyY, "NoteV1 receiver spend public key");
  pointFromCoordinates(normalized.receiverViewPubKeyX, normalized.receiverViewPubKeyY, "NoteV1 receiver view public key");
  if (computeNoteCommitmentUnchecked(normalized) === 0n || computeNoteNullifierUnchecked(normalized) === 0n) {
    throw new Error("NoteV1 active commitment and nullifier must be non-zero");
  }
  return normalized;
}

function computeNoteCommitmentUnchecked(note) {
  return mimcHash(
    domainFieldV1("clairveil.note-commitment.v1"),
    note.receiverSpendPubKeyX, note.receiverSpendPubKeyY,
    note.receiverViewPubKeyX, note.receiverViewPubKeyY,
    note.amount, note.assetID, note.randomness
  );
}

function computeNoteNullifierUnchecked(note) {
  return mimcHash(
    domainFieldV1("clairveil.note-nullifier.v1"),
    computeNoteCommitmentUnchecked(note), note.randomness,
    note.receiverSpendPubKeyX, note.receiverSpendPubKeyY
  );
}

export function marshalNotePlaintextV1(note) {
  const normalized = validateNoteV1(note);
  const memo = utf8Bytes(normalized.memo);
  const output = new Uint8Array(notePlaintextV1Size);
  let offset = 0;
  output.set(fixedDomainTag("clairveil.note-plaintext.v1"), offset); offset += 16;
  output.set(u16be(fixedBinaryVersion), offset); offset += 2;
  offset += 2;
  for (const value of [
    normalized.receiverSpendPubKeyX, normalized.receiverSpendPubKeyY,
    normalized.receiverViewPubKeyX, normalized.receiverViewPubKeyY
  ]) {
    output.set(canonicalFieldBytes(value), offset); offset += 32;
  }
  output.set(u64be(normalized.amount, "NoteV1 amount"), offset); offset += 8;
  output.set(canonicalFieldBytes(normalized.assetID), offset); offset += 32;
  output.set(canonicalFieldBytes(normalized.randomness), offset); offset += 32;
  output.set(u16be(memo.length), offset); offset += 2;
  output.set(memo, offset);
  return output;
}

export function unmarshalNotePlaintextV1(value) {
  const encoded = bytes(value, "NotePlaintextV1");
  if (encoded.length !== notePlaintextV1Size) throw new Error(`NotePlaintextV1 must be exactly ${notePlaintextV1Size} bytes`);
  let offset = 0;
  const tag = fixedDomainTag("clairveil.note-plaintext.v1");
  if (!equalBytes(encoded.slice(offset, offset + 16), tag)) throw new Error("invalid NotePlaintextV1 domain tag");
  offset += 16;
  if (readU16(encoded, offset) !== fixedBinaryVersion) throw new Error("unsupported NotePlaintextV1 version");
  offset += 2;
  if (encoded[offset] !== 0 || encoded[offset + 1] !== 0) throw new Error("NotePlaintextV1 reserved flags must be zero");
  offset += 2;
  const fields = [];
  for (let index = 0; index < 4; index += 1) {
    fields.push(bytesToBigIntBE(fieldFromBytes(encoded.slice(offset, offset + 32), `NoteV1 key coordinate ${index}`)));
    offset += 32;
  }
  const amount = readU64(encoded, offset); offset += 8;
  const assetID = bytesToBigIntBE(fieldFromBytes(encoded.slice(offset, offset + 32), "NoteV1 asset id", { nonZero: true })); offset += 32;
  const randomness = bytesToBigIntBE(fieldFromBytes(encoded.slice(offset, offset + 32), "NoteV1 randomness")); offset += 32;
  const memoLength = readU16(encoded, offset); offset += 2;
  if (memoLength > noteMemoCapacityV1) throw new Error("NotePlaintextV1 memo exceeds fixed capacity");
  const memoBytes = encoded.slice(offset, offset + noteMemoCapacityV1);
  if (memoBytes.slice(memoLength).some(byte => byte !== 0)) throw new Error("NotePlaintextV1 memo padding must be zero");
  if (!validUtf8(memoBytes.slice(0, memoLength))) throw new Error("NotePlaintextV1 memo must be valid UTF-8");
  return validateNoteV1({
    receiverSpendPubKeyX: fields[0], receiverSpendPubKeyY: fields[1],
    receiverViewPubKeyX: fields[2], receiverViewPubKeyY: fields[3],
    amount, assetID, randomness, memo: utf8String(memoBytes.slice(0, memoLength))
  });
}

function disclosureField(payload, names, label, options) {
  for (const name of names) {
    if (payload?.[name] != null) return field(payload[name], label, options);
  }
  return field(0n, label, options);
}

function normalizeDisclosurePlaintextV1(payload) {
  if (!payload || typeof payload !== "object") throw new Error("DisclosurePlaintextV1 is required");
  const plane = Number(payload.plane ?? 0);
  const outputIndex = Number(uint(payload.outputIndex ?? payload.output_index ?? 0, 32, "disclosure output index"));
  const policy = Number(uint(payload.policy ?? 0, 32, "disclosure policy"));
  const disclosedFieldBitmap = Number(uint(payload.disclosedFieldBitmap ?? payload.disclosed_field_bitmap ?? 0, 32, "disclosure bitmap"));
  const value = {
    plane,
    outputIndex,
    policy,
    disclosedFieldBitmap,
    commitment: disclosureField(payload, ["commitment"], "disclosure commitment", { nonZero: true }),
    amount: uint(payload.amount ?? 0, 64, "disclosure amount"),
    assetID: disclosureField(payload, ["assetID", "assetId", "asset_id"], "disclosure asset ID", { nonZero: true }),
    senderSpendKeyX: disclosureField(payload, ["senderSpendKeyX", "sender_spend_key_x"], "disclosure sender spend x"),
    senderSpendKeyY: disclosureField(payload, ["senderSpendKeyY", "sender_spend_key_y"], "disclosure sender spend y"),
    senderViewKeyX: disclosureField(payload, ["senderViewKeyX", "sender_view_key_x"], "disclosure sender view x"),
    senderViewKeyY: disclosureField(payload, ["senderViewKeyY", "sender_view_key_y"], "disclosure sender view y"),
    recipientSpendKeyX: disclosureField(payload, ["recipientSpendKeyX", "recipient_spend_key_x"], "disclosure recipient spend x"),
    recipientSpendKeyY: disclosureField(payload, ["recipientSpendKeyY", "recipient_spend_key_y"], "disclosure recipient spend y"),
    recipientViewKeyX: disclosureField(payload, ["recipientViewKeyX", "recipient_view_key_x"], "disclosure recipient view x"),
    recipientViewKeyY: disclosureField(payload, ["recipientViewKeyY", "recipient_view_key_y"], "disclosure recipient view y"),
    disclosureBlinding: disclosureField(payload, ["disclosureBlinding", "disclosure_blinding", "fullDisclosureBlinding"], "disclosure blinding", { nonZero: true })
  };
  const sender = [value.senderSpendKeyX, value.senderSpendKeyY, value.senderViewKeyX, value.senderViewKeyY];
  const recipient = [value.recipientSpendKeyX, value.recipientSpendKeyY, value.recipientViewKeyX, value.recipientViewKeyY];
  const allZero = values => values.every(entry => entry === 0n);
  const validateSender = () => {
    pointFromCoordinates(value.senderSpendKeyX, value.senderSpendKeyY, "disclosure sender spend public key");
    pointFromCoordinates(value.senderViewKeyX, value.senderViewKeyY, "disclosure sender view public key");
  };
  const validateRecipient = () => {
    pointFromCoordinates(value.recipientSpendKeyX, value.recipientSpendKeyY, "disclosure recipient spend public key");
    pointFromCoordinates(value.recipientViewKeyX, value.recipientViewKeyY, "disclosure recipient view public key");
  };
  if (plane === 1) {
    if (policy < 1 || policy > 7 || disclosedFieldBitmap !== policy) throw new Error("user disclosure requires a matching policy bitmap in 1..7");
    if ((policy & 1) === 0 && value.amount !== 0n) throw new Error("undisclosed amount must be zero");
    if ((policy & 4) === 0) {
      if (!allZero(sender)) throw new Error("undisclosed sender fields must be zero");
    } else {
      validateSender();
    }
    if ((policy & 2) === 0) {
      if (!allZero(recipient)) throw new Error("undisclosed recipient fields must be zero");
    } else {
      validateRecipient();
    }
  } else if (plane === 2) {
    if (policy !== 0xffffffff || disclosedFieldBitmap !== 7) throw new Error("full disclosure must use the full marker and bitmap");
    validateSender();
    validateRecipient();
  } else {
    throw new Error("unsupported disclosure plane");
  }
  return value;
}

export function marshalDisclosurePlaintextV1(payload) {
  const value = normalizeDisclosurePlaintextV1(payload);
  const output = new Uint8Array(disclosurePlaintextV1Size);
  let offset = 0;
  output.set(fixedDomainTag("clairveil.disclosure-plaintext.v1"), offset); offset += 16;
  output.set(u16be(fixedBinaryVersion), offset); offset += 2;
  output[offset] = value.plane; offset += 1;
  offset += 1;
  output.set(u32be(value.outputIndex), offset); offset += 4;
  output.set(u32be(value.policy), offset); offset += 4;
  output.set(u32be(value.disclosedFieldBitmap), offset); offset += 4;
  output.set(canonicalFieldBytes(value.commitment), offset); offset += 32;
  output.set(u64be(value.amount, "disclosure amount"), offset); offset += 8;
  for (const entry of [
    value.assetID,
    value.senderSpendKeyX, value.senderSpendKeyY, value.senderViewKeyX, value.senderViewKeyY,
    value.recipientSpendKeyX, value.recipientSpendKeyY, value.recipientViewKeyX, value.recipientViewKeyY,
    value.disclosureBlinding
  ]) {
    output.set(canonicalFieldBytes(entry), offset); offset += 32;
  }
  return output;
}

export function unmarshalDisclosurePlaintextV1(value) {
  const encoded = bytes(value, "DisclosurePlaintextV1");
  if (encoded.length !== disclosurePlaintextV1Size) throw new Error(`DisclosurePlaintextV1 must be exactly ${disclosurePlaintextV1Size} bytes`);
  let offset = 0;
  if (!equalBytes(encoded.slice(0, 16), fixedDomainTag("clairveil.disclosure-plaintext.v1"))) throw new Error("invalid DisclosurePlaintextV1 domain tag");
  offset += 16;
  if (readU16(encoded, offset) !== fixedBinaryVersion) throw new Error("unsupported DisclosurePlaintextV1 version");
  offset += 2;
  const plane = encoded[offset]; offset += 1;
  if (encoded[offset] !== 0) throw new Error("DisclosurePlaintextV1 reserved byte must be zero");
  offset += 1;
  const outputIndex = readU32(encoded, offset); offset += 4;
  const policy = readU32(encoded, offset); offset += 4;
  const disclosedFieldBitmap = readU32(encoded, offset); offset += 4;
  const commitment = bytesToBigIntBE(fieldFromBytes(encoded.slice(offset, offset + 32), "disclosure commitment", { nonZero: true })); offset += 32;
  const amount = readU64(encoded, offset); offset += 8;
  const fields = [];
  for (let index = 0; index < 10; index += 1) {
    fields.push(bytesToBigIntBE(fieldFromBytes(encoded.slice(offset, offset + 32), `disclosure field ${index}`)));
    offset += 32;
  }
  return normalizeDisclosurePlaintextV1({
    plane, outputIndex, policy, disclosedFieldBitmap, commitment, amount,
    assetID: fields[0],
    senderSpendKeyX: fields[1], senderSpendKeyY: fields[2], senderViewKeyX: fields[3], senderViewKeyY: fields[4],
    recipientSpendKeyX: fields[5], recipientSpendKeyY: fields[6], recipientViewKeyX: fields[7], recipientViewKeyY: fields[8],
    disclosureBlinding: fields[9]
  });
}

export function computeTransferUserDisclosureDigestV2(input) {
  const policy = Number(input?.policy ?? 0);
  if (!Number.isInteger(policy) || policy < 0 || policy > 7) throw new Error("transfer user disclosure policy must be in 0..7");
  const commitment = field(input?.commitment, "transfer user disclosure commitment", { nonZero: true });
  if (policy === 0) return 0n;
  const required = (value, label) => {
    if (value == null) throw new Error(`${label} is required`);
    return field(value, label);
  };
  const selected = (value, enabled, label) => enabled ? required(value, label) : 0n;
  const assetID = required(input?.assetID ?? input?.assetId, "transfer user disclosure asset ID");
  if (assetID === 0n) throw new Error("transfer user disclosure asset ID must be non-zero");
  return mimcHash(
    hashStringToField("CLAIRVEIL_USER_DISCLOSURE_V2"),
    BigInt(policy),
    uint(input?.outputIndex ?? 0, 32, "transfer user disclosure output index"),
    commitment,
    selected(input?.amount, (policy & 1) !== 0, "transfer user disclosure amount"),
    assetID,
    selected(input?.fromSpendPubKeyX, (policy & 4) !== 0, "transfer user disclosure sender spend x"),
    selected(input?.fromSpendPubKeyY, (policy & 4) !== 0, "transfer user disclosure sender spend y"),
    selected(input?.fromViewPubKeyX, (policy & 4) !== 0, "transfer user disclosure sender view x"),
    selected(input?.fromViewPubKeyY, (policy & 4) !== 0, "transfer user disclosure sender view y"),
    selected(input?.toSpendPubKeyX, (policy & 2) !== 0, "transfer user disclosure recipient spend x"),
    selected(input?.toSpendPubKeyY, (policy & 2) !== 0, "transfer user disclosure recipient spend y"),
    selected(input?.toViewPubKeyX, (policy & 2) !== 0, "transfer user disclosure recipient view x"),
    selected(input?.toViewPubKeyY, (policy & 2) !== 0, "transfer user disclosure recipient view y"),
    field(input?.disclosureBlinding, "transfer user disclosure blinding", { nonZero: true })
  );
}

export function computeTransferFullDisclosureDigestV2(input) {
  const required = (names, label, options) => {
    for (const name of names) if (input?.[name] != null) return field(input[name], label, options);
    throw new Error(`${label} is required`);
  };
  return mimcHash(
    hashStringToField("CLAIRVEIL_FULL_DISCLOSURE_V2"),
    255n,
    uint(input?.outputIndex ?? 0, 32, "transfer full disclosure output index"),
    required(["commitment"], "transfer full disclosure commitment", { nonZero: true }),
    required(["amount"], "transfer full disclosure amount"),
    required(["assetID", "assetId"], "transfer full disclosure asset ID", { nonZero: true }),
    required(["fromSpendPubKeyX"], "transfer full disclosure sender spend x"), required(["fromSpendPubKeyY"], "transfer full disclosure sender spend y"),
    required(["fromViewPubKeyX"], "transfer full disclosure sender view x"), required(["fromViewPubKeyY"], "transfer full disclosure sender view y"),
    required(["toSpendPubKeyX"], "transfer full disclosure recipient spend x"), required(["toSpendPubKeyY"], "transfer full disclosure recipient spend y"),
    required(["toViewPubKeyX"], "transfer full disclosure recipient view x"), required(["toViewPubKeyY"], "transfer full disclosure recipient view y"),
    required(["disclosureBlinding", "fullDisclosureBlinding"], "transfer full disclosure blinding", { nonZero: true })
  );
}

function batchVectorCapacity(kind) {
  switch (kind) {
    case batchVectorKindV1.nullifier:
      return 16;
    case batchVectorKindV1.commitment:
    case batchVectorKindV1.userDisclosure:
    case batchVectorKindV1.fullDisclosure:
      return 32;
    default:
      throw new Error(`unsupported batch vector kind ${JSON.stringify(kind)}`);
  }
}

function batchVectorKindLabel(kind, part) {
  if (!["leaf", "node", "root"].includes(part)) throw new Error(`unsupported batch vector domain part ${JSON.stringify(part)}`);
  batchVectorCapacity(kind);
  return `clairveil.batch-vector.${kind}.${part}.v1`;
}

function requireBatchField(input, names, label, options) {
  for (const name of names) if (input?.[name] != null) return field(input[name], label, options);
  throw new Error(`${label} is required`);
}

function batchKeyBundle(input, prefix, label) {
  const values = [
    requireBatchField(input, [`${prefix}SpendKeyX`, `${prefix}_spend_key_x`], `${label} spend key x`),
    requireBatchField(input, [`${prefix}SpendKeyY`, `${prefix}_spend_key_y`], `${label} spend key y`),
    requireBatchField(input, [`${prefix}ViewKeyX`, `${prefix}_view_key_x`], `${label} view key x`),
    requireBatchField(input, [`${prefix}ViewKeyY`, `${prefix}_view_key_y`], `${label} view key y`)
  ];
  return values;
}

function validateBatchKeyBundle(values, label) {
  pointFromCoordinates(values[0], values[1], `${label} spend public key`);
  pointFromCoordinates(values[2], values[3], `${label} view public key`);
}

export function validateBatchJoinSplitCountsV1(inputCount, outputCount) {
  const inputs = Number(uint(inputCount, 32, "batch input count"));
  const outputs = Number(uint(outputCount, 32, "batch output count"));
  if (inputs < 1 || inputs > 16) throw new Error("batch input count must be in 1..16");
  if (outputs < 1 || outputs > 32) throw new Error("batch output count must be in 1..32");
  return true;
}

export function computeBatchVectorRootV1(kind, count, values) {
  const capacity = batchVectorCapacity(kind);
  const active = Number(uint(count, 32, `${kind} vector count`));
  if (active < 1 || active > capacity) throw new Error(`${kind} vector count must be in [1,${capacity}]`);
  if (!Array.isArray(values) || values.length !== capacity) throw new Error(`${kind} vector must contain exactly ${capacity} values`);
  const leafDomain = domainFieldV1(batchVectorKindLabel(kind, "leaf"));
  const nodeDomain = domainFieldV1(batchVectorKindLabel(kind, "node"));
  const rootDomain = domainFieldV1(batchVectorKindLabel(kind, "root"));
  let layer = values.map((value, index) => {
    const canonical = field(value, `${kind} vector value ${index}`);
    const enabled = index < active;
    if (enabled && canonical === 0n) throw new Error(`${kind} vector active value ${index} must be non-zero`);
    if (!enabled && canonical !== 0n) throw new Error(`${kind} vector disabled value ${index} must be zero`);
    return mimcHash(leafDomain, BigInt(index), enabled ? 1n : 0n, canonical);
  });
  for (let level = 0; layer.length > 1; level += 1) {
    const next = [];
    for (let index = 0; index < layer.length; index += 2) next.push(mimcHash(nodeDomain, BigInt(level), layer[index], layer[index + 1]));
    layer = next;
  }
  return mimcHash(rootDomain, BigInt(capacity), BigInt(active), layer[0]);
}

export function computeBatchUserDisclosureVectorRootV1(count, policies, rawDigests) {
  const active = Number(uint(count, 32, "batch user disclosure vector count"));
  if (active < 1 || active > 32) throw new Error("batch user disclosure vector count must be in [1,32]");
  if (!Array.isArray(policies) || policies.length !== 32 || !Array.isArray(rawDigests) || rawDigests.length !== 32) {
    throw new Error("batch user disclosure vector requires exactly 32 policies and raw digests");
  }
  const domain = domainFieldV1("clairveil.user-disclosure-leaf.v1");
  const values = rawDigests.map((rawDigest, index) => {
    const raw = field(rawDigest, `batch user disclosure raw digest ${index}`);
    const policy = Number(uint(policies[index], 32, `batch user disclosure policy ${index}`));
    if (policy > 7) throw new Error(`batch user disclosure policy ${index} exceeds 3-bit policy`);
    if (index >= active) {
      if (policy !== 0 || raw !== 0n) throw new Error(`batch disabled user disclosure output ${index} must use zero policy and digest`);
      return 0n;
    }
    if (policy === 0 && raw !== 0n) throw new Error(`batch all-private output ${index} must use zero user disclosure digest`);
    if (policy !== 0 && raw === 0n) throw new Error(`batch disclosed output ${index} must use a non-zero user disclosure digest`);
    return mimcHash(domain, BigInt(index), 1n, BigInt(policy), raw);
  });
  return computeBatchVectorRootV1(batchVectorKindV1.userDisclosure, active, values);
}

export function computeBatchUserDisclosureDigestV1(input) {
  const outputIndex = uint(input?.outputIndex ?? input?.output_index ?? 0, 32, "batch user disclosure output index");
  const commitment = requireBatchField(input, ["commitment"], "batch user disclosure commitment", { nonZero: true });
  const policy = Number(uint(input?.policy ?? 0, 32, "batch user disclosure policy"));
  const bitmap = Number(uint(input?.disclosedFieldBitmap ?? input?.disclosed_field_bitmap ?? 0, 32, "batch user disclosure bitmap"));
  const amount = requireBatchField(input, ["selectedAmount", "selected_amount", "amount"], "batch user disclosure selected amount");
  const sender = batchKeyBundle(input, "selectedFrom", "batch user disclosure sender");
  const recipient = batchKeyBundle(input, "selectedTo", "batch user disclosure recipient");
  const assetID = requireBatchField(input, ["assetID", "assetId", "asset_id"], "batch user disclosure asset ID");
  const blinding = input?.userDisclosureBlinding ?? input?.user_disclosure_blinding;
  const zero = values => values.every(value => value === 0n);
  if (policy === 0) {
    if (bitmap !== 0 || amount !== 0n || !zero(sender) || !zero(recipient) || assetID !== 0n || (blinding != null && field(blinding, "batch user disclosure blinding") !== 0n)) {
      throw new Error("batch all-private disclosure must use zero bitmap, selected fields, and blinding");
    }
    return 0n;
  }
  if (policy > 7 || bitmap !== policy) throw new Error("batch user disclosure bitmap must equal policy in 1..7");
  if (assetID === 0n) throw new Error("batch user disclosure asset ID must be non-zero");
  if ((policy & 1) === 0 && amount !== 0n) throw new Error("batch undisclosed amount must be zero");
  if ((policy & 4) === 0) {
    if (!zero(sender)) throw new Error("batch undisclosed sender keys must be zero");
  } else validateBatchKeyBundle(sender, "batch selected sender");
  if ((policy & 2) === 0) {
    if (!zero(recipient)) throw new Error("batch undisclosed recipient keys must be zero");
  } else validateBatchKeyBundle(recipient, "batch selected recipient");
  const userBlinding = field(blinding, "batch user disclosure blinding", { nonZero: true });
  return mimcHash(
    domainFieldV1("clairveil.user-disclosure.v2"), outputIndex, commitment, BigInt(policy), BigInt(bitmap), amount,
    ...sender, ...recipient, assetID, userBlinding
  );
}

export function computeBatchFullDisclosureDigestV1(input) {
  const outputIndex = uint(input?.outputIndex ?? input?.output_index ?? 0, 32, "batch full disclosure output index");
  const commitment = requireBatchField(input, ["commitment"], "batch full disclosure commitment", { nonZero: true });
  const amount = uint(input?.amount, 64, "batch full disclosure amount");
  const assetID = requireBatchField(input, ["assetID", "assetId", "asset_id"], "batch full disclosure asset ID", { nonZero: true });
  const sender = batchKeyBundle(input, "sender", "batch full disclosure sender");
  const recipient = batchKeyBundle(input, "recipient", "batch full disclosure recipient");
  validateBatchKeyBundle(sender, "batch full disclosure sender");
  validateBatchKeyBundle(recipient, "batch full disclosure recipient");
  const fullBlinding = requireBatchField(input, ["fullDisclosureBlinding", "full_disclosure_blinding", "disclosureBlinding"], "batch full disclosure blinding", { nonZero: true });
  return mimcHash(
    domainFieldV1("clairveil.full-disclosure.v2"), outputIndex, commitment, amount, assetID,
    ...sender, ...recipient, fullBlinding
  );
}

export function computeBatchTransferIntentV1(input = {}) {
  const inputCount = Number(uint(input.inputCount ?? input.input_count ?? 0, 32, "batch input count"));
  const outputCount = Number(uint(input.outputCount ?? input.output_count ?? 0, 32, "batch output count"));
  validateBatchJoinSplitCountsV1(inputCount, outputCount);
  const chainDomain = input.chainDomain || {};
  const payloadDigest = input.payloadDigest || {};
  const chainHi = requireBatchField({ ...input, chainDomainHi: input.chainDomainHi ?? chainDomain.hi }, ["chainDomainHi", "chain_domain_hi"], "batch chain domain hi");
  const chainLo = requireBatchField({ ...input, chainDomainLo: input.chainDomainLo ?? chainDomain.lo }, ["chainDomainLo", "chain_domain_lo"], "batch chain domain lo");
  const merkleRoot = requireBatchField(input, ["merkleRoot", "merkle_root", "root"], "batch merkle root");
  const assetID = requireBatchField(input, ["assetID", "assetId", "asset_id"], "batch asset ID");
  const nullifierRoot = requireBatchField(input, ["nullifierRoot", "nullifier_root"], "batch nullifier root");
  const commitmentRoot = requireBatchField(input, ["commitmentRoot", "commitment_root"], "batch commitment root");
  const userRoot = requireBatchField(input, ["userDisclosureRoot", "user_disclosure_root"], "batch user disclosure root");
  const fullRoot = requireBatchField(input, ["fullDisclosureRoot", "full_disclosure_root"], "batch full disclosure root");
  const digestHi = requireBatchField({ ...input, payloadDigestHi: input.payloadDigestHi ?? payloadDigest.hi }, ["payloadDigestHi", "payload_digest_hi"], "batch payload digest hi");
  const digestLo = requireBatchField({ ...input, payloadDigestLo: input.payloadDigestLo ?? payloadDigest.lo }, ["payloadDigestLo", "payload_digest_lo"], "batch payload digest lo");
  for (const [value, label] of [[chainHi, "chain domain hi"], [chainLo, "chain domain lo"], [digestHi, "payload digest hi"], [digestLo, "payload digest lo"]]) {
    if (value >= (1n << 128n)) throw new Error(`batch ${label} must be an unsigned 128-bit integer`);
  }
  const expiresAtUnix = uint(input.expiresAtUnix ?? input.expires_at_unix ?? 0, 63, "batch expires_at_unix");
  if (expiresAtUnix === 0n) throw new Error("batch expires_at_unix must be positive");
  return mimcHash(
    domainFieldV1("clairveil.batch-transfer-intent.v1"), chainHi, chainLo,
    domainFieldV1("clairveil.batch-joinsplit-16x32.v1"), merkleRoot,
    BigInt(inputCount), BigInt(outputCount), assetID, nullifierRoot, commitmentRoot,
    userRoot, fullRoot, digestHi, digestLo, expiresAtUnix
  );
}

/**
 * Compute the proof-independent BatchTransfer event/evidence identifier.
 * Unlike the owner intent, this deliberately excludes asset ID, creator, and
 * proof bytes so downstream reconciliation can bind to the public effect.
 */
export function computeBatchEffectIdV1(input = {}) {
  const inputCount = Number(uint(input.inputCount ?? input.input_count ?? 0, 32, "batch input count"));
  const outputCount = Number(uint(input.outputCount ?? input.output_count ?? 0, 32, "batch output count"));
  validateBatchJoinSplitCountsV1(inputCount, outputCount);
  const chainDomain = input.chainDomain || {};
  const payloadDigest = input.payloadDigest || {};
  const chainHi = requireBatchField({ ...input, chainDomainHi: input.chainDomainHi ?? chainDomain.hi }, ["chainDomainHi", "chain_domain_hi"], "batch chain domain hi");
  const chainLo = requireBatchField({ ...input, chainDomainLo: input.chainDomainLo ?? chainDomain.lo }, ["chainDomainLo", "chain_domain_lo"], "batch chain domain lo");
  const merkleRoot = requireBatchField(input, ["merkleRoot", "merkle_root", "root"], "batch merkle root");
  const nullifierRoot = requireBatchField(input, ["nullifierRoot", "nullifier_root"], "batch nullifier root");
  const commitmentRoot = requireBatchField(input, ["commitmentRoot", "commitment_root"], "batch commitment root");
  const userRoot = requireBatchField(input, ["userDisclosureRoot", "user_disclosure_root"], "batch user disclosure root");
  const fullRoot = requireBatchField(input, ["fullDisclosureRoot", "full_disclosure_root"], "batch full disclosure root");
  const digestHi = requireBatchField({ ...input, payloadDigestHi: input.payloadDigestHi ?? payloadDigest.hi }, ["payloadDigestHi", "payload_digest_hi"], "batch payload digest hi");
  const digestLo = requireBatchField({ ...input, payloadDigestLo: input.payloadDigestLo ?? payloadDigest.lo }, ["payloadDigestLo", "payload_digest_lo"], "batch payload digest lo");
  for (const [value, label] of [[chainHi, "chain domain hi"], [chainLo, "chain domain lo"], [digestHi, "payload digest hi"], [digestLo, "payload digest lo"]]) {
    if (value >= (1n << 128n)) throw new Error(`batch ${label} must be an unsigned 128-bit integer`);
  }
  const expiresAtUnix = uint(input.expiresAtUnix ?? input.expires_at_unix ?? 0, 64, "batch expires_at_unix");
  if (expiresAtUnix === 0n) throw new Error("batch expires_at_unix must be positive");
  return hexFromBytes(sha256(concatBytes(
    utf8Bytes("clairveil.batch-effect.v1"),
    canonicalFieldBytes(chainHi), canonicalFieldBytes(chainLo), canonicalFieldBytes(merkleRoot),
    u32be(inputCount), u32be(outputCount),
    canonicalFieldBytes(nullifierRoot), canonicalFieldBytes(commitmentRoot),
    canonicalFieldBytes(userRoot), canonicalFieldBytes(fullRoot),
    canonicalFieldBytes(digestHi), canonicalFieldBytes(digestLo), u64be(expiresAtUnix, "batch expires_at_unix")
  )));
}

export function wrapEncryptedEnvelopeV1(kind, ciphertext) {
  const raw = bytes(ciphertext, "encrypted envelope ciphertext");
  if (raw.length !== envelopeCiphertextSize(kind)) {
    throw new Error(`encrypted envelope kind ${kind} ciphertext must be exactly ${envelopeCiphertextSize(kind)} bytes`);
  }
  return concatBytes(envelopeTag(), u16be(fixedBinaryVersion), Uint8Array.of(Number(kind), 0), raw);
}

export function unwrapEncryptedEnvelopeV1(value, expectedKind) {
  const encoded = bytes(value, "encrypted envelope");
  if (encoded.length < encryptedEnvelopeV1HeaderSize) throw new Error("encrypted envelope is shorter than its header");
  if (!equalBytes(encoded.slice(0, 16), envelopeTag())) throw new Error("invalid encrypted envelope domain tag");
  if (readU16(encoded, 16) !== fixedBinaryVersion) throw new Error("unsupported encrypted envelope version");
  const kind = encoded[18];
  if (expectedKind != null && kind !== Number(expectedKind)) throw new Error(`encrypted envelope kind mismatch: got ${kind}, expected ${expectedKind}`);
  if (encoded[19] !== 0) throw new Error("encrypted envelope reserved byte must be zero");
  const raw = encoded.slice(encryptedEnvelopeV1HeaderSize);
  if (raw.length !== envelopeCiphertextSize(kind)) throw new Error(`encrypted envelope kind ${kind} has invalid fixed length`);
  return raw;
}

export function encryptNoteForTransferV1(note, outputCommitment, outputIndex) {
  const normalized = validateNoteV1(note);
  const raw = asymEncryptWithViewTagV1(
    marshalNotePlaintextV1(normalized),
    { x: normalized.receiverViewPubKeyX, y: normalized.receiverViewPubKeyY },
    outputCommitment,
    outputIndex
  );
  return {
    ciphertext: wrapEncryptedEnvelopeV1(encryptedEnvelopeKindV1.transferNote, raw.ciphertext),
    viewTag: raw.viewTag
  };
}

export function decryptTransferNoteV1(ciphertext, scalar) {
  return unmarshalNotePlaintextV1(asymDecryptV1(unwrapEncryptedEnvelopeV1(ciphertext, encryptedEnvelopeKindV1.transferNote), scalar));
}

export function encryptDisclosureV1(disclosure, target, kind) {
  const envelopeKind = disclosureEnvelopeKindV1(kind);
  return wrapEncryptedEnvelopeV1(
    envelopeKind,
    asymEncryptV1(marshalDisclosurePlaintextV1(disclosure), target).ciphertext
  );
}

export function decryptDisclosureV1(ciphertext, scalar, expectedKind) {
  const envelopeKind = disclosureEnvelopeKindV1(expectedKind);
  return unmarshalDisclosurePlaintextV1(
    asymDecryptV1(unwrapEncryptedEnvelopeV1(ciphertext, envelopeKind), scalar)
  );
}

export function encryptDepositNoteV1(note, rootSeed) {
  const nonce = randomBytes(12);
  const encrypted = aesGcmEncrypt({ key: sha256(rootSeed), nonce, plaintext: marshalNotePlaintextV1(note) });
  return wrapEncryptedEnvelopeV1(encryptedEnvelopeKindV1.depositNote, concatBytes(nonce, encrypted));
}

export function decryptDepositNoteV1(ciphertext, rootSeed) {
  const raw = unwrapEncryptedEnvelopeV1(ciphertext, encryptedEnvelopeKindV1.depositNote);
  return unmarshalNotePlaintextV1(aesGcmDecrypt({ key: sha256(rootSeed), nonce: raw.slice(0, 12), ciphertext: raw.slice(12) }));
}

function disclosureEnvelopeKindV1(kind) {
  const normalized = Number(kind);
  if (
    normalized !== encryptedEnvelopeKindV1.userDisclosure
    && normalized !== encryptedEnvelopeKindV1.auditDisclosure
    && normalized !== encryptedEnvelopeKindV1.selfViewDisclosure
  ) {
    throw new Error("disclosure envelope kind must be user, audit, or self-view disclosure");
  }
  return normalized;
}

function asymEncryptV1(plaintext, receiver) {
  const receiverPoint = pointFromCoordinates(receiver.x, receiver.y, "receiver public key");
  let scalar = 0n;
  while (scalar === 0n) scalar = bytesToBigIntBE(randomBytes(32)) % CURVE_ORDER;
  const ephemeral = scalarMultiply({ x: 9671717474070082183213120605117400219616337014328744928644933853176787189663n, y: 16950150798460657717958625567821834550301663161624707787222815936182638968203n }, scalar);
  const sharedPoint = scalarMultiply(receiverPoint, scalar);
  const nonce = randomBytes(12);
  const encrypted = aesGcmEncrypt({ key: sha256(packPoint(sharedPoint)), nonce, plaintext });
  return { ciphertext: concatBytes(packPoint(ephemeral), nonce, encrypted), sharedPoint };
}

function asymEncryptWithViewTagV1(plaintext, receiver, outputCommitment, outputIndex) {
  const { ciphertext, sharedPoint } = asymEncryptV1(plaintext, receiver);
  const commitment = fieldFromBytes(outputCommitment, "output commitment", { nonZero: true });
  const tag = canonicalFieldBytes(mimcHash(hashStringToField("clairveil.view_tag.v1"), sharedPoint.x, sharedPoint.y, bytesToBigIntBE(commitment), uint(outputIndex, 32, "output index"))).slice(0, 2);
  return { ciphertext, viewTag: tag };
}

function asymDecryptV1(ciphertext, scalar) {
  const raw = bytes(ciphertext, "ECIES ciphertext");
  if (raw.length < 60) throw new Error("ECIES ciphertext is too short");
  const ephemeral = unpackPoint(raw.slice(0, 32));
  const sharedPoint = scalarMultiply(ephemeral, field(scalar, "ECIES scalar", { nonZero: true }));
  return aesGcmDecrypt({ key: sha256(packPoint(sharedPoint)), nonce: raw.slice(32, 44), ciphertext: raw.slice(44) });
}

function equalBytes(left, right) {
  if (left.length !== right.length) return false;
  let different = 0;
  for (let index = 0; index < left.length; index += 1) different |= left[index] ^ right[index];
  return different === 0;
}

function normalizeBatchOutput(output, index) {
  if (!output || typeof output !== "object") throw new Error(`batch output ${index} is required`);
  const policy = Number(output.userPrivacyPolicy ?? output.user_privacy_policy ?? 0);
  const mode = Number(output.userDisclosureMode ?? output.user_disclosure_mode ?? 0);
  if (!Number.isInteger(policy) || policy < 0 || policy > 7) throw new Error(`batch output ${index} has invalid privacy policy`);
  if (!Number.isInteger(mode) || mode < 0 || mode > 2) throw new Error(`batch output ${index} has invalid disclosure mode`);
  const normalized = {
    commitment: fieldFromBytes(output.commitment, `batch output ${index} commitment`, { nonZero: true }),
    ciphertext: bytes(output.ciphertext, `batch output ${index} ciphertext`),
    viewTag: bytes(output.viewTag ?? output.view_tag, `batch output ${index} view tag`),
    userPrivacyPolicy: policy,
    userDisclosureMode: mode,
    userDisclosureDigest: optionalBytes(output.userDisclosureDigest ?? output.user_disclosure_digest, `batch output ${index} user disclosure digest`),
    userDisclosureTargetPubkey: optionalBytes(output.userDisclosureTargetPubkey ?? output.user_disclosure_target_pubkey, `batch output ${index} user disclosure target`),
    userDisclosurePayload: optionalBytes(output.userDisclosurePayload ?? output.user_disclosure_payload, `batch output ${index} user disclosure payload`),
    fullDisclosureDigest: fieldFromBytes(output.fullDisclosureDigest ?? output.full_disclosure_digest, `batch output ${index} full disclosure digest`, { nonZero: true }),
    auditDisclosurePayload: bytes(output.auditDisclosurePayload ?? output.audit_disclosure_payload, `batch output ${index} audit disclosure payload`),
    selfViewDisclosurePayload: optionalBytes(output.selfViewDisclosurePayload ?? output.self_view_disclosure_payload, `batch output ${index} self-view disclosure payload`)
  };
  unwrapEncryptedEnvelopeV1(normalized.ciphertext, encryptedEnvelopeKindV1.transferNote);
  if (normalized.viewTag.length !== 2) throw new Error(`batch output ${index} view tag must be exactly 2 bytes`);
  unwrapEncryptedEnvelopeV1(normalized.auditDisclosurePayload, encryptedEnvelopeKindV1.auditDisclosure);
  if (normalized.selfViewDisclosurePayload.length) unwrapEncryptedEnvelopeV1(normalized.selfViewDisclosurePayload, encryptedEnvelopeKindV1.selfViewDisclosure);
  if (policy === 0) {
    if (mode !== 0 || normalized.userDisclosureDigest.length || normalized.userDisclosureTargetPubkey.length || normalized.userDisclosurePayload.length) {
      throw new Error(`batch output ${index} all-private disclosure fields must be empty`);
    }
  } else {
    if (![1, 2].includes(mode) || normalized.userDisclosureDigest.length !== 32) throw new Error(`batch output ${index} user disclosure is incomplete`);
    fieldFromBytes(normalized.userDisclosureDigest, `batch output ${index} user disclosure digest`, { nonZero: true });
    if (mode === 1) {
      if (normalized.userDisclosureTargetPubkey.length || normalized.userDisclosurePayload.length !== disclosurePlaintextV1Size) {
        throw new Error(`batch output ${index} public disclosure must use fixed plaintext`);
      }
      const plaintext = unmarshalDisclosurePlaintextV1(normalized.userDisclosurePayload);
      if (plaintext.plane !== 1 || plaintext.outputIndex !== index || plaintext.policy !== policy || plaintext.commitment !== bytesToBigIntBE(normalized.commitment)) {
        throw new Error(`batch output ${index} public disclosure metadata does not match output`);
      }
      const digest = computeBatchUserDisclosureDigestV1({
        outputIndex: plaintext.outputIndex,
        commitment: plaintext.commitment,
        policy: plaintext.policy,
        disclosedFieldBitmap: plaintext.disclosedFieldBitmap,
        selectedAmount: plaintext.amount,
        selectedFromSpendKeyX: plaintext.senderSpendKeyX,
        selectedFromSpendKeyY: plaintext.senderSpendKeyY,
        selectedFromViewKeyX: plaintext.senderViewKeyX,
        selectedFromViewKeyY: plaintext.senderViewKeyY,
        selectedToSpendKeyX: plaintext.recipientSpendKeyX,
        selectedToSpendKeyY: plaintext.recipientSpendKeyY,
        selectedToViewKeyX: plaintext.recipientViewKeyX,
        selectedToViewKeyY: plaintext.recipientViewKeyY,
        assetID: plaintext.assetID,
        userDisclosureBlinding: plaintext.disclosureBlinding
      });
      if (!equalBytes(canonicalFieldBytes(digest), normalized.userDisclosureDigest)) {
        throw new Error(`batch output ${index} public disclosure digest does not match plaintext`);
      }
    } else {
      if (normalized.userDisclosureTargetPubkey.length !== 32 || !normalized.userDisclosurePayload.length) throw new Error(`batch output ${index} encrypted disclosure is incomplete`);
      try {
        unpackPoint(normalized.userDisclosureTargetPubkey);
      } catch (error) {
        throw new Error(`batch output ${index} encrypted disclosure target is invalid: ${error.message}`);
      }
      unwrapEncryptedEnvelopeV1(normalized.userDisclosurePayload, encryptedEnvelopeKindV1.userDisclosure);
    }
  }
  return normalized;
}

function optionalBytes(value, label) {
  if (value == null || value === "") return new Uint8Array();
  return bytes(value, label);
}

export function validateBatchTransferEffectsV1(message) {
  if (!message || typeof message !== "object") throw new Error("MsgBatchTransfer is required");
  const root = fieldFromBytes(message.root, "batch merkle root", { nonZero: true });
  const nullifiersRaw = message.nullifiers;
  if (!Array.isArray(nullifiersRaw) || nullifiersRaw.length < 1 || nullifiersRaw.length > 16) throw new Error("batch input count must be in 1..16");
  const nullifiers = nullifiersRaw.map((value, index) => fieldFromBytes(value, `batch nullifier ${index}`, { nonZero: true }));
  const seenNullifiers = new Set(nullifiers.map(hexFromBytes));
  if (seenNullifiers.size !== nullifiers.length) throw new Error("batch nullifiers must be distinct");
  if (!Array.isArray(message.outputs) || message.outputs.length < 1 || message.outputs.length > 32) throw new Error("batch output count must be in 1..32");
  const outputs = message.outputs.map(normalizeBatchOutput);
  const auditKeyId = String(message.auditKeyId ?? message.audit_key_id ?? "");
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(auditKeyId)) throw new Error("batch audit key ID must be canonical lowercase ASCII");
  const auditKeyEpoch = uint(message.auditKeyEpoch ?? message.audit_key_epoch ?? 0, 64, "batch audit key epoch");
  if (auditKeyEpoch === 0n) throw new Error("batch audit key epoch must be positive");
  const auditDisclosureTargetPubkey = bytes(message.auditDisclosureTargetPubkey ?? message.audit_disclosure_target_pubkey, "batch audit disclosure target public key");
  if (auditDisclosureTargetPubkey.length !== 32) throw new Error("batch audit disclosure target public key must be exactly 32 bytes");
  try {
    unpackPoint(auditDisclosureTargetPubkey);
  } catch (error) {
    throw new Error(`batch audit disclosure target public key is invalid: ${error.message}`);
  }
  const expiresAtUnix = uint(message.expiresAtUnix ?? message.expires_at_unix ?? 0, 63, "batch expires_at_unix");
  if (expiresAtUnix === 0n) throw new Error("batch expires_at_unix must be positive");
  const selfViewEnabled = outputs[0].selfViewDisclosurePayload.length !== 0;
  if (outputs.some(output => (output.selfViewDisclosurePayload.length !== 0) !== selfViewEnabled)) {
    throw new Error("batch self-view disclosure must be all-or-none");
  }
  const commitments = outputs.map(output => hexFromBytes(output.commitment));
  if (new Set(commitments).size !== commitments.length) throw new Error("batch commitments must be distinct");
  return { root, nullifiers, outputs, auditKeyId, auditKeyEpoch, auditDisclosureTargetPubkey, expiresAtUnix };
}

export function canonicalBatchTransferPayloadBytesV1(message) {
  const normalized = validateBatchTransferEffectsV1(message);
  const chunks = [u32be(1), writeLengthPrefixed(normalized.root, "batch root"), writeByteSlice(normalized.nullifiers, "batch nullifier"), u32be(normalized.outputs.length)];
  for (const output of normalized.outputs) {
    chunks.push(
      writeLengthPrefixed(output.commitment),
      writeLengthPrefixed(output.ciphertext),
      writeLengthPrefixed(output.viewTag),
      u32be(output.userPrivacyPolicy),
      u32be(output.userDisclosureMode),
      writeLengthPrefixed(output.userDisclosureDigest),
      writeLengthPrefixed(output.userDisclosureTargetPubkey),
      writeLengthPrefixed(output.userDisclosurePayload),
      writeLengthPrefixed(output.fullDisclosureDigest),
      writeLengthPrefixed(output.auditDisclosurePayload),
      writeLengthPrefixed(output.selfViewDisclosurePayload)
    );
  }
  chunks.push(
    writeLengthPrefixed(utf8Bytes(normalized.auditKeyId), "batch audit key ID"),
    u64be(normalized.auditKeyEpoch, "batch audit key epoch"),
    writeLengthPrefixed(normalized.auditDisclosureTargetPubkey),
    u64be(normalized.expiresAtUnix, "batch expires_at_unix")
  );
  return concatBytes(...chunks);
}

export function computeBatchTransferPayloadDigestV1(message) {
  const digest = sha256(concatBytes(utf8Bytes(batchTransferPayloadDomainV1), canonicalBatchTransferPayloadBytesV1(message)));
  return {
    bytes: digest,
    hex: hexFromBytes(digest),
    hi: bytesToBigIntBE(digest.slice(0, 16)),
    lo: bytesToBigIntBE(digest.slice(16))
  };
}

export function canonicalTransferPayloadBytesV1(message) {
  if (!message || typeof message !== "object") throw new Error("MsgTransfer is required");
  const root = fieldFromBytes(message.root, "transfer root", { nonZero: true });
  const nullifiers = message.nullifiers;
  const commitments = message.newCommitments ?? message.new_commitments;
  const cipherTexts = message.cipherTexts ?? message.cipher_texts;
  const viewTags = message.viewTags ?? message.view_tags;
  if (!Array.isArray(nullifiers) || !Array.isArray(commitments) || !Array.isArray(cipherTexts) || !Array.isArray(viewTags)) {
    throw new Error("transfer effect vectors are required");
  }
  const policy = Number(message.userPrivacyPolicy ?? message.user_privacy_policy ?? 0);
  const mode = Number(message.userDisclosureMode ?? message.user_disclosure_mode ?? 0);
  const expiresAtUnix = uint(message.expiresAtUnix ?? message.expires_at_unix ?? 0, 63, "transfer expires_at_unix");
  if (!Number.isInteger(policy) || policy < 0 || policy > 7 || !Number.isInteger(mode) || mode < 0 || mode > 2 || expiresAtUnix === 0n) {
    throw new Error("transfer effect has invalid policy, mode, or expiry");
  }
  return concatBytes(
    u32be(1),
    writeLengthPrefixed(root),
    writeByteSlice(nullifiers, "transfer nullifier"),
    writeByteSlice(commitments, "transfer commitment"),
    writeByteSlice(cipherTexts, "transfer ciphertext"),
    writeByteSlice(viewTags, "transfer view tag"),
    u32be(policy),
    u32be(mode),
    ...[
      message.userDisclosureDigest ?? message.user_disclosure_digest,
      message.userDisclosureTargetPubkey ?? message.user_disclosure_target_pubkey,
      message.userDisclosurePayload ?? message.user_disclosure_payload,
      message.auditDisclosureDigest ?? message.audit_disclosure_digest,
      message.auditDisclosureTargetPubkey ?? message.audit_disclosure_target_pubkey,
      message.auditDisclosurePayload ?? message.audit_disclosure_payload,
      message.selfViewDisclosureDigest ?? message.self_view_disclosure_digest,
      message.selfViewDisclosurePayload ?? message.self_view_disclosure_payload
    ].map((value, index) => writeLengthPrefixed(optionalBytes(value, `transfer disclosure ${index}`))),
    u64be(expiresAtUnix, "transfer expires_at_unix")
  );
}

export function computeTransferPayloadDigestV1(message) {
  const digest = sha256(concatBytes(utf8Bytes(transferPayloadDomainV1), canonicalTransferPayloadBytesV1(message)));
  return { bytes: digest, hex: hexFromBytes(digest), hi: bytesToBigIntBE(digest.slice(0, 16)), lo: bytesToBigIntBE(digest.slice(16)) };
}

export function computeChainDomainV1(chainId, circuitSetId = activeCircuitSetIdV1) {
  const chain = String(chainId || "");
  const circuit = String(circuitSetId || "");
  if (!chain || !circuit) throw new Error("chain ID and circuit set ID are required");
  const digest = sha256(concatBytes(
    utf8Bytes("clairveil.chain-domain.v1"),
    writeLengthPrefixed(utf8Bytes(chain), "chain ID"),
    writeLengthPrefixed(utf8Bytes(circuit), "circuit set ID")
  ));
  return { bytes: digest, hex: hexFromBytes(digest), hi: bytesToBigIntBE(digest.slice(0, 16)), lo: bytesToBigIntBE(digest.slice(16)) };
}

export function computeWithdrawRecipientDigestV1(recipientBytes) {
  const recipient = bytes(recipientBytes, "withdraw recipient bytes");
  if (!recipient.length) throw new Error("withdraw recipient bytes are required");
  const digest = sha256(concatBytes(
    utf8Bytes("clairveil.withdraw-recipient.v1"),
    writeLengthPrefixed(recipient, "withdraw recipient bytes")
  ));
  return { bytes: digest, hex: hexFromBytes(digest), hi: bytesToBigIntBE(digest.slice(0, 16)), lo: bytesToBigIntBE(digest.slice(16)) };
}

export function computeTransferIntentV2({ chainDomain, root, assetId, nullifiers, commitments, userDisclosureDigest, fullDisclosureDigest, payloadDigest, expiresAtUnix } = {}) {
  if (!chainDomain || !payloadDigest) throw new Error("transfer chain and payload digests are required");
  if (!Array.isArray(nullifiers) || nullifiers.length !== 2 || !Array.isArray(commitments) || commitments.length !== 2) {
    throw new Error("transfer intent requires exactly two nullifiers and commitments");
  }
  const orderedSet = (domain, values) => mimcHash(hashStringToField(domain), BigInt(values.length), ...values.map((value, index) => field(value, `transfer intent value ${index}`, { nonZero: true })));
  const expiry = uint(expiresAtUnix, 63, "transfer intent expiry");
  if (!expiry) throw new Error("transfer intent expiry must be positive");
  return mimcHash(
    hashStringToField("CLAIRVEIL_TRANSFER_INTENT_V2"),
    uint(chainDomain.hi, 128, "transfer chain digest hi"),
    uint(chainDomain.lo, 128, "transfer chain digest lo"),
    hashStringToField("CLAIRVEIL_JOINSPLIT_2X2_V2"),
    field(root, "transfer intent root", { nonZero: true }),
    2n, 2n,
    field(assetId, "transfer intent asset ID", { nonZero: true }),
    orderedSet("CLAIRVEIL_NULLIFIER_SET_V1", nullifiers),
    orderedSet("CLAIRVEIL_COMMITMENT_SET_V1", commitments),
    field(userDisclosureDigest ?? 0n, "transfer intent user disclosure digest"),
    field(fullDisclosureDigest, "transfer intent full disclosure digest", { nonZero: true }),
    uint(payloadDigest.hi, 128, "transfer payload digest hi"),
    uint(payloadDigest.lo, 128, "transfer payload digest lo"),
    expiry
  );
}

export function computeSpendIntentV2({ chainDomain, root, nullifier, amount, assetId, recipientDigest, expiresAtUnix } = {}) {
  if (!chainDomain || !recipientDigest) throw new Error("withdraw chain and recipient digests are required");
  const expiry = uint(expiresAtUnix, 63, "withdraw intent expiry");
  if (!expiry) throw new Error("withdraw intent expiry must be positive");
  const required = [
    [chainDomain.hi, "withdraw chain digest hi"], [chainDomain.lo, "withdraw chain digest lo"],
    [recipientDigest.hi, "withdraw recipient digest hi"], [recipientDigest.lo, "withdraw recipient digest lo"]
  ];
  for (const [value, label] of required) {
    field(value, label);
    if (BigInt(value) >= (1n << 128n)) throw new Error(`${label} must be an unsigned 128-bit integer`);
  }
  return mimcHash(
    hashStringToField("CLAIRVEIL_SPEND_INTENT_V2"),
    BigInt(chainDomain.hi), BigInt(chainDomain.lo),
    hashStringToField("CLAIRVEIL_SPEND_V2"),
    field(root, "withdraw intent root", { nonZero: true }),
    field(nullifier, "withdraw intent nullifier", { nonZero: true }),
    uint(amount, 64, "withdraw intent amount"),
    field(assetId, "withdraw intent asset ID", { nonZero: true }),
    BigInt(recipientDigest.hi), BigInt(recipientDigest.lo), expiry
  );
}

export function fieldHexV1(value) {
  return canonicalFieldHex(field(value, "field"));
}
