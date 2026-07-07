import {
  bigIntToBytesBE,
  bytesFromHex,
  bytesToBigIntBE,
  canonicalFieldBytes,
  canonicalFieldHex,
  CURVE_BASE,
  CURVE_ORDER,
  FIELD_MODULUS,
  decodeShieldedAddress,
  deriveSpendKeys,
  deriveViewKeys,
  hashStringToField,
  hexFromBytes,
  mimcHash,
  normalizeHex,
  packPoint,
  packPointHex,
  scalarMultiply,
  unpackPointHex
} from "./crypto.js";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  base64FromBytes,
  concatBytes,
  randomBytes,
  sha256,
  utf8Bytes
} from "./browser-crypto.js";

export const defaultAssetDenom = "uclair";

const maxUint256 = 1n << 256n;
const scalarLimit = maxUint256 - (maxUint256 % CURVE_ORDER);

function cloneBytes(bytes) {
  return Uint8Array.from(bytes);
}

function bytesFromBytesLike(value, label = "bytes") {
  if (value == null) return new Uint8Array();
  if (typeof value === "string") return bytesFromHex(value, label);
  if (value instanceof Uint8Array) return Uint8Array.from(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value).slice();
  }
  return Uint8Array.from(value);
}

function randomScalar({ allowZero = false } = {}) {
  while (true) {
    const candidate = BigInt(`0x${hexFromBytes(randomBytes(32))}`);
    if (candidate >= scalarLimit) continue;
    const scalar = candidate % CURVE_ORDER;
    if (!allowZero && scalar === 0n) continue;
    return scalar;
  }
}

function coerceBigInt(value, label) {
  if (value == null) {
    throw new Error(`${label} is required`);
  }
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error(`${label} must be a safe integer or decimal string`);
    }
    return BigInt(value);
  }
  const text = String(value).trim();
  if (!/^-?(0|[1-9][0-9]*)$/.test(text)) {
    throw new Error(`${label} must be a decimal integer`);
  }
  return BigInt(text);
}

function optionalBigInt(value, fallback, label) {
  return value == null || value === "" ? fallback : coerceBigInt(value, label);
}

function pointCoordinate(point, coordinate) {
  const value = point?.[coordinate];
  if (value == null) {
    throw new Error(`point ${coordinate} coordinate is required`);
  }
  return BigInt(value);
}

export function parseCoin(value, defaultDenom = defaultAssetDenom) {
  const text = String(value || "").trim();
  const match = text.match(/^(0|[1-9][0-9]*)([a-zA-Z][a-zA-Z0-9/:._-]*)?$/);
  if (!match) {
    throw new Error(`invalid coin amount ${JSON.stringify(value)}`);
  }
  return {
    amount: match[1],
    denom: match[2] || defaultDenom,
    raw: `${match[1]}${match[2] || defaultDenom}`
  };
}

export function noteFromShieldedAddress({ shieldedAddress, amount, assetDenom = defaultAssetDenom, randomness, memo = "", shieldedPrefix } = {}) {
  const bundle = decodeShieldedAddress(shieldedAddress, { shieldedPrefix });
  return createNote({
    spendPubKey: bundle.spendPubKey,
    viewPubKey: bundle.viewPubKey,
    amount,
    assetDenom,
    randomness,
    memo
  });
}

export function noteFromRootSeed({ rootSeed, amount, assetDenom = defaultAssetDenom, randomness, memo = "" }) {
  const spend = deriveSpendKeys(rootSeed);
  const view = deriveViewKeys(rootSeed);
  return createNote({
    spendPubKey: spend.pubKey,
    viewPubKey: view.pubKey,
    amount,
    assetDenom,
    randomness,
    memo
  });
}

export function createNote({ spendPubKey, viewPubKey, amount, assetDenom = defaultAssetDenom, assetId, randomness, memo = "" }) {
  if (!spendPubKey || !viewPubKey) {
    throw new Error("spendPubKey and viewPubKey are required to create a note");
  }
  const note = {
    receiverSpendPubKeyX: pointCoordinate(spendPubKey, "x"),
    receiverSpendPubKeyY: pointCoordinate(spendPubKey, "y"),
    receiverViewPubKeyX: pointCoordinate(viewPubKey, "x"),
    receiverViewPubKeyY: pointCoordinate(viewPubKey, "y"),
    amount: coerceBigInt(amount, "note amount"),
    assetID: optionalBigInt(assetId, hashStringToField(assetDenom), "asset id"),
    randomness: optionalBigInt(randomness, randomScalar({ allowZero: true }), "note randomness"),
    memo: String(memo || "")
  };
  if (note.amount < 0n) {
    throw new Error("note amount must be non-negative");
  }
  return note;
}

export function normalizeNote(note) {
  if (!note || typeof note !== "object") {
    throw new Error("note is required");
  }
  return {
    receiverSpendPubKeyX: coerceBigInt(note.receiverSpendPubKeyX ?? note.rsx, "note receiver spend pubkey x"),
    receiverSpendPubKeyY: coerceBigInt(note.receiverSpendPubKeyY ?? note.rsy, "note receiver spend pubkey y"),
    receiverViewPubKeyX: coerceBigInt(note.receiverViewPubKeyX ?? note.rvx, "note receiver view pubkey x"),
    receiverViewPubKeyY: coerceBigInt(note.receiverViewPubKeyY ?? note.rvy, "note receiver view pubkey y"),
    amount: coerceBigInt(note.amount ?? note.am, "note amount"),
    assetID: coerceBigInt(note.assetID ?? note.assetId ?? note.as, "note asset id"),
    randomness: coerceBigInt(note.randomness ?? note.rn, "note randomness"),
    memo: String(note.memo ?? note.mm ?? "")
  };
}

export function noteToGoJSON(noteLike) {
  const note = normalizeNote(noteLike);
  return [
    "{",
    `"rsx":${note.receiverSpendPubKeyX.toString()},`,
    `"rsy":${note.receiverSpendPubKeyY.toString()},`,
    `"rvx":${note.receiverViewPubKeyX.toString()},`,
    `"rvy":${note.receiverViewPubKeyY.toString()},`,
    `"am":${note.amount.toString()},`,
    `"as":${note.assetID.toString()},`,
    `"rn":${note.randomness.toString()},`,
    `"mm":${JSON.stringify(note.memo)}`,
    "}"
  ].join("");
}

export function noteToGoJSONBytes(noteLike) {
  return utf8Bytes(noteToGoJSON(noteLike));
}

export function computeNoteCommitment(noteLike) {
  const note = normalizeNote(noteLike);
  return mimcHash(
    note.receiverSpendPubKeyX,
    note.receiverSpendPubKeyY,
    note.receiverViewPubKeyX,
    note.receiverViewPubKeyY,
    note.amount,
    note.assetID,
    note.randomness
  );
}

export function computeNoteCommitmentHex(noteLike) {
  return canonicalFieldHex(computeNoteCommitment(noteLike));
}

export function computeNoteCommitmentBytes(noteLike) {
  return canonicalFieldBytes(computeNoteCommitment(noteLike));
}

export function computeNoteNullifier(noteLike) {
  const note = normalizeNote(noteLike);
  return mimcHash(
    note.randomness,
    note.receiverSpendPubKeyX,
    note.receiverSpendPubKeyY
  );
}

export function computeNoteNullifierHex(noteLike) {
  return canonicalFieldHex(computeNoteNullifier(noteLike));
}

export function noteSpendPubKey(noteLike) {
  const note = normalizeNote(noteLike);
  return {
    x: note.receiverSpendPubKeyX,
    y: note.receiverSpendPubKeyY
  };
}

export function noteViewPubKey(noteLike) {
  const note = normalizeNote(noteLike);
  return {
    x: note.receiverViewPubKeyX,
    y: note.receiverViewPubKeyY
  };
}

export function noteSpendPubKeyHex(noteLike) {
  return packPointHex(noteSpendPubKey(noteLike));
}

export function noteViewPubKeyHex(noteLike) {
  return packPointHex(noteViewPubKey(noteLike));
}

export function encryptWithRootSeed(plaintext, rootSeed) {
  const key = sha256(rootSeed);
  const nonce = randomBytes(12);
  const ciphertextAndTag = aesGcmEncrypt({
    key,
    nonce,
    plaintext
  });
  return concatBytes(nonce, ciphertextAndTag);
}

export function decryptWithRootSeed(ciphertextBytes, rootSeed) {
  const bytes = Uint8Array.from(ciphertextBytes);
  if (bytes.length < 12 + 16) {
    throw new Error("invalid root-seed ciphertext length");
  }
  const key = sha256(rootSeed);
  const nonce = bytes.slice(0, 12);
  const ciphertextAndTag = bytes.slice(12);
  return aesGcmDecrypt({
    key,
    nonce,
    ciphertext: ciphertextAndTag
  });
}

export function encryptNoteWithRootSeed(noteLike, rootSeed) {
  return encryptWithRootSeed(noteToGoJSONBytes(noteLike), rootSeed);
}

function asymEncryptWithSharedPoint(plaintext, receiverPubKey) {
  const ephemeralScalar = randomScalar();
  const ephemeralPubKey = scalarMultiply(CURVE_BASE, ephemeralScalar);
  const sharedPoint = scalarMultiply(receiverPubKey, ephemeralScalar);
  const sharedSecret = sha256(packPoint(sharedPoint));
  const nonce = randomBytes(12);
  const ciphertextAndTag = aesGcmEncrypt({
    key: sharedSecret,
    nonce,
    plaintext
  });
  return {
    cipherText: concatBytes(packPoint(ephemeralPubKey), nonce, ciphertextAndTag),
    sharedPoint
  };
}

export const viewTagLength = 2;

export function deriveViewTag(sharedPoint, outputCommitment, outputIndex) {
  const commitmentBytes = bytesFromBytesLike(outputCommitment, "output commitment");
  if (commitmentBytes.length !== 32) {
    throw new Error("output commitment must be exactly 32 bytes");
  }
  const tagFull = mimcHash(
    hashStringToField("clairveil.view_tag.v1"),
    pointCoordinate(sharedPoint, "x"),
    pointCoordinate(sharedPoint, "y"),
    bytesToBigIntBE(commitmentBytes),
    BigInt(outputIndex)
  );
  return canonicalFieldBytes(tagFull).slice(0, viewTagLength);
}

export function asymEncrypt(plaintext, receiverPubKey) {
  return asymEncryptWithSharedPoint(plaintext, receiverPubKey).cipherText;
}

export function asymEncryptWithViewTag(plaintext, receiverPubKey, outputCommitment, outputIndex) {
  const encrypted = asymEncryptWithSharedPoint(plaintext, receiverPubKey);
  return {
    cipherText: encrypted.cipherText,
    viewTag: deriveViewTag(encrypted.sharedPoint, outputCommitment, outputIndex)
  };
}

export function asymEncryptHex(plaintext, receiverPubKeyHex) {
  return hexFromBytes(asymEncrypt(plaintext, unpackPointHex(receiverPubKeyHex)));
}

export function encryptNoteForReceiver(noteLike) {
  return asymEncrypt(noteToGoJSONBytes(noteLike), noteViewPubKey(noteLike));
}

export function encryptNoteForReceiverWithViewTag(noteLike, outputCommitment, outputIndex) {
  return asymEncryptWithViewTag(
    noteToGoJSONBytes(noteLike),
    noteViewPubKey(noteLike),
    outputCommitment,
    outputIndex
  );
}

export function computeTransferNoteHash(noteLike) {
  const note = normalizeNote(noteLike);
  return mimcHash(note.amount, note.assetID, note.randomness);
}

export function computeWithdrawNoteHash(noteLike, recipientBytes) {
  const note = normalizeNote(noteLike);
  return mimcHash(
    note.amount,
    note.assetID,
    note.randomness,
    bytesToBigIntBE(recipientBytes)
  );
}

export function signNoteHash(messageHash, { spendScalar, spendPubKey }) {
  const scalar = BigInt(spendScalar);
  const pubKey = spendPubKey || scalarMultiply(CURVE_BASE, scalar);
  if (scalar <= 0n || scalar >= CURVE_ORDER) {
    throw new Error("spendScalar must satisfy 1 <= scalar < curve order");
  }

  while (true) {
    const r = randomScalar();
    const rPubKey = scalarMultiply(CURVE_BASE, r);
    const challenge = mimcHash(
      rPubKey.x,
      rPubKey.y,
      pubKey.x,
      pubKey.y,
      BigInt(messageHash)
    );
    const s = (r + challenge * scalar) % CURVE_ORDER;
    if (s >= FIELD_MODULUS) continue;
    const signature = new Uint8Array(64);
    signature.set(packPoint(rPubKey), 0);
    signature.set(bigIntToBytesBE(s, 32), 32);
    return signature;
  }
}

export function createSpendNoteHashSigner(rootSeed) {
  const spend = deriveSpendKeys(rootSeed);
  return {
    spendScalar: spend.scalar,
    spendPubKey: spend.pubKey,
    async signNoteHash(messageHash) {
      return signNoteHash(messageHash, {
        spendScalar: spend.scalar,
        spendPubKey: spend.pubKey
      });
    },
    async signSpendNoteHash(messageHash) {
      return signNoteHash(messageHash, {
        spendScalar: spend.scalar,
        spendPubKey: spend.pubKey
      });
    }
  };
}

export async function resolveTransferSignature(signer, messageHash) {
  if (!signer || typeof signer.signNoteHash !== "function") {
    throw new Error("a note hash signer with signNoteHash(messageHash) is required");
  }
  const signature = await signer.signNoteHash(messageHash);
  const bytes = Uint8Array.from(signature);
  if (bytes.length !== 64) {
    throw new Error("note hash signature must be 64 bytes");
  }
  return bytes;
}

export async function resolveWithdrawSignature(signer, messageHash) {
  if (!signer) {
    throw new Error("a spend note hash signer is required");
  }
  const fn = signer.signSpendNoteHash || signer.signNoteHash;
  if (typeof fn !== "function") {
    throw new Error("a spend note hash signer with signSpendNoteHash(messageHash) is required");
  }
  const signature = await fn.call(signer, messageHash);
  const bytes = Uint8Array.from(signature);
  if (bytes.length !== 64) {
    throw new Error("spend note hash signature must be 64 bytes");
  }
  return bytes;
}

export function buildDepositMaterial({ creator, rootSeed, shieldedAddress, amount, memo = "Deposit", assetDenom, shieldedPrefix } = {}) {
  const coin = parseCoin(amount, assetDenom || defaultAssetDenom);
  if (!rootSeed) {
    throw new Error("rootSeed is required to encrypt a deposit note for local wallet scanning");
  }
  const note = shieldedAddress
    ? noteFromShieldedAddress({
      shieldedAddress,
      amount: coin.amount,
      assetDenom: coin.denom,
      memo,
      shieldedPrefix
    })
    : noteFromRootSeed({
      rootSeed,
      amount: coin.amount,
      assetDenom: coin.denom,
      memo
    });
  const noteCommitment = computeNoteCommitmentBytes(note);
  const encryptedNote = encryptNoteWithRootSeed(note, rootSeed);
  return {
    creator: String(creator || ""),
    amount: coin.raw,
    note,
    note_json: noteToGoJSON(note),
    note_commitment: cloneBytes(noteCommitment),
    note_commitment_hex: hexFromBytes(noteCommitment),
    note_commitment_base64: base64FromBytes(noteCommitment),
    encrypted_note: cloneBytes(encryptedNote),
    encrypted_note_hex: hexFromBytes(encryptedNote),
    encrypted_note_base64: base64FromBytes(encryptedNote)
  };
}

export function normalizeFoundNote(foundNote) {
  if (!foundNote || typeof foundNote !== "object") {
    throw new Error("found note is required");
  }
  const note = normalizeNote(foundNote.note ?? foundNote.Note ?? foundNote);
  return {
    note,
    nullifier: String(foundNote.nullifier ?? foundNote.Nullifier ?? computeNoteNullifierHex(note)).toLowerCase(),
    isSpent: Boolean(foundNote.isSpent ?? foundNote.IsSpent ?? false),
    txHash: String(foundNote.txHash ?? foundNote.tx_hash ?? foundNote.TxHash ?? ""),
    height: Number(foundNote.height ?? foundNote.Height ?? 0),
    sequence: Number(foundNote.sequence ?? foundNote.Sequence ?? 0)
  };
}

export function pointFromHex(value, label = "public key") {
  return unpackPointHex(normalizeHex(value, label));
}

export function bytesFromOptionalHex(value, label) {
  const text = String(value || "").trim();
  return text ? bytesFromHex(text, label) : new Uint8Array();
}
