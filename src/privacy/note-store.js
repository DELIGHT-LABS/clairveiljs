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

const maxUint64 = (1n << 64n) - 1n;

function uint64CursorBigInt(value, label) {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative safe integer, bigint, or canonical uint64 string`);
    }
    return BigInt(value);
  }
  if (typeof value === "bigint") {
    if (value < 0n || value > maxUint64) throw new Error(`${label} must be within uint64 range`);
    return value;
  }
  const text = String(value ?? "").trim();
  if (!/^(0|[1-9][0-9]*)$/.test(text)) {
    throw new Error(`${label} must be a canonical uint64 decimal string`);
  }
  const parsed = BigInt(text);
  if (parsed > maxUint64) throw new Error(`${label} must be within uint64 range`);
  return parsed;
}

function uint64CursorValue(value, label) {
  const parsed = uint64CursorBigInt(value, label);
  return parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : parsed.toString();
}

function maxUint64Cursor(values, label) {
  let maximum = 0n;
  for (const value of values) {
    const parsed = uint64CursorBigInt(value ?? 0, label);
    if (parsed > maximum) maximum = parsed;
  }
  return maximum <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(maximum) : maximum.toString();
}

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
  const height = found.height;
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
    nullifier_status: found.nullifierStatus,
    nullifierStatus: found.nullifierStatus,
    txHash,
    height,
    sequence: found.sequence,
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
  const spent = serialized.spent === true || found.isSpent === true;
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
    sequence: found.sequence,
    spent,
    isSpent: spent,
    nullifier_status: spent ? "spent" : found.nullifierStatus,
    nullifierStatus: spent ? "spent" : found.nullifierStatus
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
    const leftHeight = uint64CursorBigInt(left.height ?? 0, "found note height");
    const rightHeight = uint64CursorBigInt(right.height ?? 0, "found note height");
    if (leftHeight !== rightHeight) return leftHeight < rightHeight ? -1 : 1;
    const leftSequence = uint64CursorBigInt(left.sequence ?? 0, "found note sequence");
    const rightSequence = uint64CursorBigInt(right.sequence ?? 0, "found note sequence");
    if (leftSequence !== rightSequence) return leftSequence < rightSequence ? -1 : 1;
    return String(left.txHash || left.tx_hash || "").localeCompare(String(right.txHash || right.tx_hash || ""));
  });
  const latest = sorted.at(-1);
  return {
    height: uint64CursorValue(latest?.height ?? 0, "found note height"),
    sequence: uint64CursorValue(latest?.sequence ?? 0, "found note sequence"),
    txHash: String(latest?.txHash || latest?.tx_hash || "").toUpperCase()
  };
}

function cursorValue(cursor, keys = []) {
  for (const key of keys) {
    const value = cursor?.[key];
    if (value === undefined || value === null || value === "") continue;
    return uint64CursorValue(value, `scan cursor ${key}`);
  }
  return null;
}

function rewindScanState(current, rollbackHeight) {
  const currentCursor = current.scanCursor || {};
  const scanEventsCursor =
    currentCursor.source === "scan_events" ||
    currentCursor.next_sequence != null ||
    currentCursor.nextSequence != null;
  const source = scanEventsCursor ? "scan_events" : "privacy_events";
  const requestedHeight = uint64CursorBigInt(rollbackHeight, "rollback height");
  const currentScannedHeight = uint64CursorBigInt(current.lastScannedHeight ?? 0, "last scanned height");
  const rewindBoundary = requestedHeight < currentScannedHeight ? requestedHeight : currentScannedHeight;
  // Legacy privacy_events starts from after_height + 1. Rewind one extra
  // height so the deleted rollback boundary is reconstructed on the next
  // scan; ScanEvents resumes at (height, sequence 0). Never advance a store
  // that has not scanned as far as the requested rollback boundary.
  const resumeHeight = uint64CursorValue(
    source === "privacy_events" && rewindBoundary > 0n
      ? rewindBoundary - 1n
      : rewindBoundary,
    "rollback resume height"
  );
  const scanCursor = source === "scan_events"
    ? {
        source,
        after_height: resumeHeight,
        after_sequence: 0,
        next_height: resumeHeight,
        next_sequence: 0,
        has_more: false,
        page: 1
      }
    : {
        source,
        after_height: resumeHeight,
        page: 1,
        has_more: false
      };
  return { resumeHeight, scanCursor };
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
    const rollbackValue =
      rollbackToHeight ??
      rollback_to_height ??
      scanResult?.rollbackToHeight ??
      scanResult?.rollback_to_height;
    const rollbackRequested =
      rollbackValue !== undefined &&
      rollbackValue !== null &&
      rollbackValue !== "";
    const rollbackHeight = rollbackRequested
      ? uint64CursorValue(rollbackValue, "rollback height")
      : 0;
    const rollbackHeightBigInt = rollbackRequested
      ? uint64CursorBigInt(rollbackHeight, "rollback height")
      : 0n;
    // The rollback boundary is re-scanned from its beginning, so cached notes
    // at that height cannot be trusted after a reorg.
    const currentNotes = rollbackRequested
      ? current.notes.filter(found =>
          uint64CursorBigInt(found.height ?? 0, "found note height") < rollbackHeightBigInt
        )
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
      .sort((a, b) => {
        const leftHeight = uint64CursorBigInt(a.height, "found note height");
        const rightHeight = uint64CursorBigInt(b.height, "found note height");
        if (leftHeight !== rightHeight) return leftHeight < rightHeight ? -1 : 1;
        const leftSequence = uint64CursorBigInt(a.sequence, "found note sequence");
        const rightSequence = uint64CursorBigInt(b.sequence, "found note sequence");
        if (leftSequence !== rightSequence) return leftSequence < rightSequence ? -1 : 1;
        return String(a.txHash || a.tx_hash || "").localeCompare(String(b.txHash || b.tx_hash || ""));
      });
    const incomingScanCursor = scanResult?.scanCursor ?? scanResult?.scan_cursor ?? null;
    const rollbackScanState = rollbackRequested && incomingScanCursor == null
      ? rewindScanState(current, rollbackHeight)
      : null;
    const scanCursor = incomingScanCursor ?? rollbackScanState?.scanCursor ?? current.scanCursor ?? null;
    const latest = latestNoteCursor(notes);
    const hasMore = Boolean(scanCursor?.has_more ?? scanCursor?.hasMore);
    const cursorAfterHeight = cursorValue(scanCursor, ["after_height", "afterHeight"]) ?? 0;
    const cursorAfterSequence = cursorValue(scanCursor, ["after_sequence", "afterSequence"]) ?? 0;
    const nextHeight = cursorValue(scanCursor, ["next_height", "nextHeight"]);
    const nextSequence = cursorValue(scanCursor, ["next_sequence", "nextSequence"]);
    const authoritativeHeight = nextHeight ?? cursorAfterHeight;
    const authoritativeSequence = nextSequence ?? cursorAfterSequence;
    const lastScannedHeight = rollbackScanState
      ? rollbackScanState.resumeHeight
      : hasMore
      ? maxUint64Cursor([
        rollbackHeight || 0,
        rollbackRequested ? 0 : current.lastScannedHeight || 0,
        authoritativeHeight
      ], "last scanned height")
      : maxUint64Cursor([
        rollbackHeight || 0,
        rollbackRequested ? 0 : current.lastScannedHeight || 0,
        authoritativeHeight,
        scanCursor?.latest_height ?? scanCursor?.latestHeight ?? 0,
        latest.height
      ], "last scanned height");
    const lastScannedSequence = rollbackScanState
      ? 0
      : nextSequence ?? (hasMore
        ? maxUint64Cursor([
          rollbackRequested ? 0 : current.lastScannedSequence || 0,
          authoritativeSequence
        ], "last scanned sequence")
        : uint64CursorValue(
          scanCursor?.latest_sequence ??
          scanCursor?.latestSequence ??
          latest.sequence ??
          current.lastScannedSequence ??
          0,
          "last scanned sequence"
        ));
    const lastScannedTxHash = rollbackScanState
      ? ""
      : String(
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
    const rollbackHeight = uint64CursorValue(height ?? 0, "rollback height");
    const rollbackHeightBigInt = uint64CursorBigInt(rollbackHeight, "rollback height");
    const current = await this.load();
    const notes = current.notes.filter(found =>
      uint64CursorBigInt(found.height ?? 0, "found note height") < rollbackHeightBigInt
    );
    const { resumeHeight, scanCursor } = rewindScanState(current, rollbackHeight);
    return this.save({
      ...current,
      rollbackHeight,
      lastScannedHeight: resumeHeight,
      // Re-read the rollback height from its beginning. A cursor beyond this
      // point can skip events that need to be reconstructed after a reorg.
      lastScannedSequence: 0,
      lastScannedTxHash: "",
      scanCursor,
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
        isSpent: wanted.has(String(found.nullifier || "").toLowerCase()) ? true : found.isSpent,
        nullifier_status: wanted.has(String(found.nullifier || "").toLowerCase())
          ? "spent"
          : found.nullifier_status,
        nullifierStatus: wanted.has(String(found.nullifier || "").toLowerCase())
          ? "spent"
          : found.nullifierStatus
      }))
    });
  }

  async setNullifierStatuses(statuses = new Map()) {
    const entries = statuses instanceof Map
      ? [...statuses.entries()]
      : Object.entries(statuses || {});
    const resolved = new Map(entries
      .map(([nullifier, status]) => [String(nullifier || "").trim().toLowerCase(), status])
      .filter(([nullifier]) => Boolean(nullifier)));
    const current = await this.load();
    return this.save({
      ...current,
      notes: current.notes.map(found => {
        const status = resolved.get(String(found.nullifier || "").toLowerCase());
        if (!["spent", "unspent", "unknown", "unverified"].includes(status)) return found;
        return {
          ...found,
          isSpent: status === "spent",
          spent: status === "spent",
          nullifier_status: status,
          nullifierStatus: status
        };
      })
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
