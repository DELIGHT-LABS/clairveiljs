import {
  computeNoteCommitmentHex,
  defaultAssetDenom,
  normalizeFoundNote,
  noteSpendPubKeyHex,
  noteViewPubKeyHex
} from "../core/note.js";
import {
  canonicalFieldHex,
  hashStringToField
} from "../core/crypto.js";

function bigintToString(value) {
  return typeof value === "bigint" ? value.toString() : String(value ?? "0");
}

export function serializeFoundNote(foundLike) {
  const found = normalizeFoundNote(foundLike);
  const assetIdHex = String(
    foundLike?.asset_id_hex ??
    foundLike?.assetIdHex ??
    canonicalFieldHex(found.note.assetID)
  ).toLowerCase();
  const defaultAssetIdHex = canonicalFieldHex(hashStringToField(defaultAssetDenom)).toLowerCase();
  const assetDenom = String(
    foundLike?.asset_denom ??
    foundLike?.assetDenom ??
    (assetIdHex === defaultAssetIdHex ? defaultAssetDenom : "")
  );
  const txHash = String(found.txHash || "").toUpperCase();
  const height = Number(found.height || 0);
  const spent = Boolean(found.isSpent);

  return {
    note: {
      receiverSpendPubKeyX: bigintToString(found.note.receiverSpendPubKeyX),
      receiverSpendPubKeyY: bigintToString(found.note.receiverSpendPubKeyY),
      receiverViewPubKeyX: bigintToString(found.note.receiverViewPubKeyX),
      receiverViewPubKeyY: bigintToString(found.note.receiverViewPubKeyY),
      amount: bigintToString(found.note.amount),
      assetID: bigintToString(found.note.assetID),
      randomness: bigintToString(found.note.randomness),
      memo: found.note.memo || ""
    },
    commitment_hex: String(
      foundLike?.commitment_hex ??
      foundLike?.commitmentHex ??
      computeNoteCommitmentHex(found.note)
    ).toLowerCase(),
    nullifier_hex: String((foundLike?.nullifier_hex ?? found.nullifier) || "").toLowerCase(),
    amount: bigintToString(found.note.amount),
    asset_denom: assetDenom,
    asset_id_hex: assetIdHex,
    randomness_hex: String(
      foundLike?.randomness_hex ??
      foundLike?.randomnessHex ??
      canonicalFieldHex(found.note.randomness)
    ).toLowerCase(),
    spend_pubkey_hex: String(
      foundLike?.spend_pubkey_hex ??
      foundLike?.spendPubKeyHex ??
      noteSpendPubKeyHex(found.note)
    ).toLowerCase(),
    view_pubkey_hex: String(
      foundLike?.view_pubkey_hex ??
      foundLike?.viewPubKeyHex ??
      noteViewPubKeyHex(found.note)
    ).toLowerCase(),
    nullifier: String(found.nullifier || "").toLowerCase(),
    isSpent: spent,
    txHash,
    height,
    sequence: Number(found.sequence || foundLike?.sequence || foundLike?.Sequence || 0),
    tx_hash: txHash,
    spent
  };
}

export function deserializeFoundNote(serialized) {
  const found = normalizeFoundNote({
    ...serialized,
    note: {
      ...serialized.note,
      receiverSpendPubKeyX: BigInt(serialized.note.receiverSpendPubKeyX),
      receiverSpendPubKeyY: BigInt(serialized.note.receiverSpendPubKeyY),
      receiverViewPubKeyX: BigInt(serialized.note.receiverViewPubKeyX),
      receiverViewPubKeyY: BigInt(serialized.note.receiverViewPubKeyY),
      amount: BigInt(serialized.note.amount),
      assetID: BigInt(serialized.note.assetID),
      randomness: BigInt(serialized.note.randomness)
    }
  });
  return {
    ...found,
    commitment_hex: String(serialized.commitment_hex || "").toLowerCase(),
    nullifier_hex: String(serialized.nullifier_hex || found.nullifier || "").toLowerCase(),
    amount: String(serialized.amount ?? found.note.amount.toString()),
    asset_denom: String(serialized.asset_denom || ""),
    asset_id_hex: String(serialized.asset_id_hex || canonicalFieldHex(found.note.assetID)).toLowerCase(),
    randomness_hex: String(serialized.randomness_hex || canonicalFieldHex(found.note.randomness)).toLowerCase(),
    spend_pubkey_hex: String(serialized.spend_pubkey_hex || noteSpendPubKeyHex(found.note)).toLowerCase(),
    view_pubkey_hex: String(serialized.view_pubkey_hex || noteViewPubKeyHex(found.note)).toLowerCase(),
    tx_hash: String(serialized.tx_hash || found.txHash || "").toUpperCase(),
    sequence: Number(serialized.sequence || found.sequence || 0),
    spent: Boolean(serialized.spent ?? found.isSpent)
  };
}

function noteKey(foundLike) {
  const found = serializeFoundNote(foundLike);
  if (found.nullifier) return `nullifier:${found.nullifier}`;
  if (found.commitment_hex) return `commitment:${found.commitment_hex}`;
  return `event:${found.height}:${found.txHash}:${found.note.randomness}:${found.note.amount}`;
}

function emptyState(owner = "") {
  return {
    version: "v1",
    owner,
    lastScannedHeight: 0,
    lastScannedSequence: 0,
    lastScannedTxHash: "",
    rollbackHeight: 0,
    scanCursor: null,
    updatedAt: "",
    notes: []
  };
}

function latestNoteCursor(notes) {
  const sorted = [...notes].sort((left, right) => {
    const heightCompare = Number(left.height || 0) - Number(right.height || 0);
    if (heightCompare !== 0) return heightCompare;
    const sequenceCompare = Number(left.sequence || 0) - Number(right.sequence || 0);
    if (sequenceCompare !== 0) return sequenceCompare;
    return String(left.txHash || left.tx_hash || "").localeCompare(String(right.txHash || right.tx_hash || ""));
  });
  const latest = sorted.at(-1);
  return {
    height: Number(latest?.height || 0),
    sequence: Number(latest?.sequence || 0),
    txHash: String(latest?.txHash || latest?.tx_hash || "").toUpperCase()
  };
}

export class MemoryNoteStore {
  constructor({ owner = "", state } = {}) {
    this.state = state || emptyState(owner);
  }

  async load() {
    return {
      ...this.state,
      notes: this.state.notes.map(deserializeFoundNote)
    };
  }

  async save(state) {
    const normalized = {
      ...emptyState(state?.owner || this.state.owner),
      ...state,
      updatedAt: new Date().toISOString(),
      notes: (state?.notes || []).map(serializeFoundNote)
    };
    this.state = normalized;
    return this.load();
  }

  async clear() {
    this.state = emptyState(this.state.owner);
    return this.load();
  }

  async mergeScanResult(scanResult, {
    owner = this.state.owner,
    rollbackToHeight,
    rollback_to_height
  } = {}) {
    const current = await this.load();
    const rollbackHeight = Number(
      rollbackToHeight ??
      rollback_to_height ??
      scanResult?.rollbackToHeight ??
      scanResult?.rollback_to_height ??
      0
    );
    const currentNotes = rollbackHeight > 0
      ? current.notes.filter(found => Number(found.height || 0) <= rollbackHeight)
      : current.notes;
    const byKey = new Map();
    for (const found of currentNotes) {
      byKey.set(noteKey(found), serializeFoundNote(found));
    }
    for (const found of scanResult?.foundNotes || []) {
      byKey.set(noteKey(found), serializeFoundNote(found));
    }
    const notes = [...byKey.values()]
      .map(deserializeFoundNote)
      .sort((a, b) => Number(a.height) - Number(b.height));
    const scanCursor = scanResult?.scanCursor ?? scanResult?.scan_cursor ?? current.scanCursor ?? null;
    const latest = latestNoteCursor(notes);
    const hasMore = Boolean(scanCursor?.has_more ?? scanCursor?.hasMore);
    const cursorAfterHeight = Number(scanCursor?.after_height ?? scanCursor?.afterHeight ?? 0);
    const cursorAfterSequence = Number(scanCursor?.after_sequence ?? scanCursor?.afterSequence ?? 0);
    const lastScannedHeight = hasMore
      ? Math.max(
        rollbackHeight || 0,
        rollbackHeight > 0 ? 0 : current.lastScannedHeight || 0,
        cursorAfterHeight
      )
      : Math.max(
        rollbackHeight || 0,
        rollbackHeight > 0 ? 0 : current.lastScannedHeight || 0,
        Number(scanCursor?.latest_height || scanCursor?.latestHeight || 0),
        latest.height
      );
    const lastScannedSequence = hasMore
      ? Math.max(
        rollbackHeight > 0 ? 0 : current.lastScannedSequence || 0,
        cursorAfterSequence
      )
      : Number(
        scanCursor?.next_sequence ??
        scanCursor?.nextSequence ??
        scanCursor?.latest_sequence ??
        scanCursor?.latestSequence ??
        latest.sequence ??
        current.lastScannedSequence ??
        0
      );
    const lastScannedTxHash = String(
      scanCursor?.latest_tx_hash ??
      scanCursor?.latestTxHash ??
      latest.txHash ??
      current.lastScannedTxHash ??
      ""
    ).toUpperCase();
    return this.save({
      owner,
      lastScannedHeight,
      lastScannedSequence,
      lastScannedTxHash,
      rollbackHeight,
      scanCursor,
      notes
    });
  }

  async rollbackToHeight(height) {
    const rollbackHeight = Number(height || 0);
    if (!Number.isFinite(rollbackHeight) || rollbackHeight < 0) {
      throw new Error("rollback height must be a non-negative number");
    }
    const current = await this.load();
    const notes = current.notes.filter(found => Number(found.height || 0) <= rollbackHeight);
    const latest = latestNoteCursor(notes);
    return this.save({
      ...current,
      rollbackHeight,
      lastScannedHeight: Math.min(Number(current.lastScannedHeight || 0), rollbackHeight),
      lastScannedTxHash: latest.txHash,
      notes
    });
  }

  async markSpent(nullifiers = []) {
    const wanted = new Set((Array.isArray(nullifiers) ? nullifiers : [nullifiers]).map(value => String(value).toLowerCase()));
    const current = await this.load();
    return this.save({
      ...current,
      notes: current.notes.map(found => ({
        ...found,
        isSpent: wanted.has(String(found.nullifier || "").toLowerCase()) ? true : found.isSpent
      }))
    });
  }
}

export class LocalStorageNoteStore extends MemoryNoteStore {
  constructor({ storage = globalThis.localStorage, key = "clairveil:notes", owner = "", allowPlaintext = false } = {}) {
    if (!storage) {
      throw new Error("localStorage-compatible storage is required");
    }
    if (!allowPlaintext) {
      throw new Error("LocalStorageNoteStore stores privacy-sensitive notes in plaintext; pass allowPlaintext: true only for demos/tests");
    }
    const raw = storage.getItem(key);
    super({ owner, state: raw ? JSON.parse(raw) : emptyState(owner) });
    this.storage = storage;
    this.key = key;
  }

  async save(state) {
    const loaded = await super.save(state);
    this.storage.setItem(this.key, JSON.stringify(this.state));
    return loaded;
  }

  async clear() {
    this.storage.removeItem(this.key);
    return super.clear();
  }
}
