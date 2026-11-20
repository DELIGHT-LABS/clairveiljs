import { parseAmount128 } from "./amount.js";
import { CURVE_ORDER, bytesToBigIntBE } from "./crypto.js";
import { randomBytes } from "./browser-crypto.js";
import { canonicalField } from "./curve-validation.js";
import { requireObject, rejectAliases, unsignedInteger } from "./encoding.js";
import { defaultAssetDenom } from "./coin.js";
import { computeAssetId } from "../privacy/protocol-domain.js";

const noteFields = ["receiverSpendPubKeyX", "receiverSpendPubKeyY", "receiverViewPubKeyX", "receiverViewPubKeyY", "assetID", "randomness"];
const noteAliases = ["rsx", "rsy", "rvx", "rvy", "am", "as", "assetId", "rn", "mm"];
const inventoryAliases = ["Note", "Nullifier", "NullifierStatus", "nullifier_status", "IsSpent", "spent", "Spent", "tx_hash", "TxHash", "Height", "Sequence"];
const statuses = new Set(["spent", "unspent", "unknown", "unverified"]);
const maxUint64 = (1n << 64n) - 1n;
const scalarLimit = (1n << 256n) - ((1n << 256n) % CURVE_ORDER);

function randomScalar() {
  for (;;) {
    const candidate = bytesToBigIntBE(randomBytes(32));
    if (candidate < scalarLimit) return candidate % CURVE_ORDER;
  }
}

/** Validates the canonical amount/field model; fixed-v2 validates curve points and framing. */
export function normalizeNote128(note) {
  requireObject(note, "note");
  rejectAliases(note, noteAliases, "note");
  const result = Object.fromEntries(noteFields.map(key => [key, canonicalField(note[key], `note ${key}`)]));
  result.amount = parseAmount128(note.amount, "note amount");
  result.memo = note.memo ?? "";
  if (typeof result.memo !== "string") throw new Error("note memo must be a string");
  return result;
}

export function createNote128({ spendPubKey, viewPubKey, amount, assetDenom = defaultAssetDenom, assetId, randomness, memo = "" } = {}) {
  return normalizeNote128({
    receiverSpendPubKeyX: spendPubKey?.x, receiverSpendPubKeyY: spendPubKey?.y,
    receiverViewPubKeyX: viewPubKey?.x, receiverViewPubKeyY: viewPubKey?.y,
    amount, assetID: assetId === undefined ? computeAssetId(assetDenom) : assetId,
    randomness: randomness === undefined ? randomScalar() : randomness, memo
  });
}

function coordinate(value = "0", label) {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a non-negative safe integer`);
    value = BigInt(value);
  }
  return unsignedInteger(value, label, maxUint64).toString();
}

/** Inventory must supply its validated V2 nullifier; no legacy derivation or cache migration. */
export function normalizeFoundNote128(found) {
  requireObject(found, "found note");
  rejectAliases(found, inventoryAliases, "found note");
  const note = normalizeNote128(found.note);
  if (typeof found.nullifier !== "string" || !/^[0-9a-fA-F]{64}$/.test(found.nullifier)) {
    throw new Error("V2 found note requires an explicit 32-byte nullifier");
  }
  if (found.isSpent !== undefined && typeof found.isSpent !== "boolean") throw new Error("isSpent must be a boolean");
  let status = found.nullifierStatus ?? "unverified";
  if (!statuses.has(status)) throw new Error("unsupported nullifier status");
  if (found.isSpent === true) status = "spent";
  if (found.txHash !== undefined && typeof found.txHash !== "string") throw new Error("txHash must be a string");
  return { note, nullifier: found.nullifier.toLowerCase(), nullifierStatus: status, isSpent: status === "spent",
    txHash: found.txHash ?? "", height: coordinate(found.height, "height"), sequence: coordinate(found.sequence, "sequence") };
}
