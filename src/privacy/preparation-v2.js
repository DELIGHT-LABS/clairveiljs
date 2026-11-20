import { deriveSpendKeys, deriveViewKeys, canonicalFieldBytes, hexFromBytes } from "../core/crypto.js";
import { parseAmount128, sumAmounts128 } from "../core/amount.js";
import { createNote128, normalizeFoundNote128 } from "../core/note128.js";
import { computeAssetId } from "./protocol-domain.js";
import { validateNoteV2, computeNoteCommitmentV2, computeNoteNullifierV2, marshalNotePlaintextV2, encryptDepositNoteV2 } from "./protocol-v2.js";
import { createAuditOutputEffectV2 } from "./audit-authorization-v2.js";

function owner(rootSeed) {
  if (!(rootSeed instanceof Uint8Array) || rootSeed.length !== 32) throw new Error("32-byte custody RootSeed required");
  const spend=deriveSpendKeys(rootSeed), view=deriveViewKeys(rootSeed);
  try { return {spend:spend.pubKey, view:view.pubKey}; }
  finally { for (const key of [spend,view]) { key.seed.fill(0);key.scalar=0n;key.scalarHex=""; } }
}
function asset(denom) {
  if (typeof denom !== "string" || !/^[a-zA-Z][a-zA-Z0-9/:._-]{2,127}$/.test(denom)) throw new Error("canonical asset denom required");
  return computeAssetId(denom);
}

/** Trusted custody material. No chain account derivation and no public serialization. */
export function prepareDepositMaterialV2({ rootSeed, amount, denom, memo = "" }) {
  const keys = owner(rootSeed), value = parseAmount128(amount), assetID = asset(denom);
  const note = createNote128({spendPubKey:keys.spend, viewPubKey:keys.view, amount:value, assetId:assetID, memo});
  const plaintext = marshalNotePlaintextV2(note);
  const auditPlaintext = [assetID, value, note.receiverSpendPubKeyX, note.receiverSpendPubKeyY,
    note.receiverViewPubKeyX, note.receiverViewPubKeyY].map(canonicalFieldBytes);
  const output = createAuditOutputEffectV2(1, 0, {commitment:canonicalFieldBytes(computeNoteCommitmentV2(note)), ciphertext:encryptDepositNoteV2(note, rootSeed)});
  return { amount:`${value}${denom}`, output, plaintext, auditPlaintext,
    clear() { plaintext.fill(0); auditPlaintext.forEach(x=>x.fill(0)); },
    toJSON() { throw new Error("private deposit material cannot be serialized"); } };
}

/** Revalidate the selected, reserved notes immediately before native preparation.
 * Selection and reservation authority remain with the caller. */
export function prepareSpendInputsV2({ kind, rootSeed, notes, amount, denom }) {
  if (kind !== "transfer" && kind !== "withdraw") throw new Error("unsupported V2 spend kind");
  if (!Array.isArray(notes) || notes.length !== (kind === "transfer" ? 2 : 1)) throw new Error("incorrect selected note count");
  const keys = owner(rootSeed), value = parseAmount128(amount, "spend amount", {positive:true}), assetID = asset(denom);
  const selected = notes.map(input => {
    const found = normalizeFoundNote128(input), note = validateNoteV2(found.note);
    if (found.isSpent || found.nullifierStatus !== "unspent") throw new Error("selected note is not verified unspent");
    if (note.assetID !== assetID || note.receiverSpendPubKeyX !== keys.spend.x || note.receiverSpendPubKeyY !== keys.spend.y
      || note.receiverViewPubKeyX !== keys.view.x || note.receiverViewPubKeyY !== keys.view.y) throw new Error("selected note owner or asset mismatch");
    const nullifier = canonicalFieldBytes(computeNoteNullifierV2(note));
    if (hexFromBytes(nullifier) !== found.nullifier) throw new Error("selected note nullifier mismatch");
    return { note, nullifier, commitment:canonicalFieldBytes(computeNoteCommitmentV2(note)) };
  });
  if (new Set(selected.map(n=>hexFromBytes(n.nullifier))).size !== selected.length) throw new Error("duplicate selected note");
  const total = sumAmounts128(selected.map(n=>n.note.amount));
  if (total < value || (kind === "withdraw" && total !== value)) throw new Error("selected note amount mismatch");
  const plaintexts = selected.map(n=>marshalNotePlaintextV2(n.note));
  return { amount:`${value}${denom}`, total, change:total-value, plaintexts,
    commitments:selected.map(n=>n.commitment), nullifiers:selected.map(n=>n.nullifier),
    clear() { plaintexts.forEach(x=>x.fill(0)); },
    toJSON() { throw new Error("private spend material cannot be serialized"); } };
}
