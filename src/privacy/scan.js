import {
  asymDecryptHex,
  deriveSpendKeys,
  deriveViewKeys
} from "../core/crypto.js";
import {
  computeNoteCommitmentHex,
  computeNoteNullifierHex,
  decryptWithRootSeed,
  normalizeFoundNote,
  normalizeNote
} from "../core/note.js";
import {
  bytesFromHex,
  utf8String
} from "../core/browser-crypto.js";

export function parseNullifierUsage(value) {
  if (typeof value === "boolean") return value;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const hasUsed = Object.prototype.hasOwnProperty.call(value, "used");
  const hasAlias = Object.prototype.hasOwnProperty.call(value, "Used");
  if (!hasUsed && !hasAlias) return null;
  if ((hasUsed && typeof value.used !== "boolean") ||
      (hasAlias && typeof value.Used !== "boolean")) return null;
  if (hasUsed && hasAlias && value.used !== value.Used) return null;
  return hasUsed ? value.used : value.Used;
}

function eventAttribute(event, key) {
  return (event?.attributes || []).find(attribute => attribute.key === key)?.value || "";
}

function stripQuotes(value) {
  const text = String(value || "").trim();
  if (text.length >= 2 && text.startsWith("\"") && text.endsWith("\"")) {
    return text.slice(1, -1);
  }
  return text;
}

function parseBigIntField(text, key) {
  const match = new RegExp(`"${key}"\\s*:\\s*(-?\\d+)`).exec(text);
  if (!match) {
    throw new Error(`note JSON is missing ${key}`);
  }
  return BigInt(match[1]);
}

function parseStringField(text, key) {
  const match = new RegExp(`"${key}"\\s*:\\s*("(?:\\\\.|[^"\\\\])*")`).exec(text);
  if (!match) return "";
  return JSON.parse(match[1]);
}

export function parseNoteBytes(bytes) {
  const text = utf8String(bytes).trim();
  return normalizeNote({
    rsx: parseBigIntField(text, "rsx"),
    rsy: parseBigIntField(text, "rsy"),
    rvx: parseBigIntField(text, "rvx"),
    rvy: parseBigIntField(text, "rvy"),
    am: parseBigIntField(text, "am"),
    as: parseBigIntField(text, "as"),
    rn: parseBigIntField(text, "rn"),
    mm: parseStringField(text, "mm")
  });
}

function foundNoteFromEvent(note, event) {
  return {
    note,
    nullifier: computeNoteNullifierHex(note).toLowerCase(),
    isSpent: false,
    nullifierStatus: "unverified",
    txHash: String(event?.tx_hash_hex ?? event?.txHashHex ?? "").toUpperCase(),
    height: event?.height ?? 0,
    sequence: event?.sequence ?? 0
  };
}

function outputField(output, snake, camel) {
  return output?.[snake] ?? output?.[camel] ?? "";
}

function noteCommitmentMatches(note, commitmentHex) {
  const text = String(commitmentHex || "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(text)) return false;
  try {
    return computeNoteCommitmentHex(note).toLowerCase() === text;
  } catch {
    return false;
  }
}

function processDepositEvent(event, rootSeed) {
  const encryptedNoteHex = stripQuotes(eventAttribute(event, "encrypted_note"));
  const commitmentHex = stripQuotes(eventAttribute(event, "commitment"));
  if (!encryptedNoteHex || !commitmentHex) return [];
  try {
    const noteBytes = decryptWithRootSeed(bytesFromHex(encryptedNoteHex, "encrypted note"), rootSeed);
    const note = parseNoteBytes(noteBytes);
    return noteCommitmentMatches(note, commitmentHex)
      ? [foundNoteFromEvent(note, event)]
      : [];
  } catch {
    return [];
  }
}

function processTransferEvent(event, spendScalar, viewScalar) {
  const found = [];
  for (const [key, commitmentKey] of [["cipher_text_1", "commitment_1"], ["cipher_text_2", "commitment_2"]]) {
    const cipherTextHex = stripQuotes(eventAttribute(event, key));
    const commitmentHex = stripQuotes(eventAttribute(event, commitmentKey));
    if (!cipherTextHex || !commitmentHex) continue;

    let noteBytes;
    try {
      noteBytes = asymDecryptHex(cipherTextHex, viewScalar);
    } catch {
      if (spendScalar == null || spendScalar === viewScalar) continue;
      try {
        noteBytes = asymDecryptHex(cipherTextHex, spendScalar);
      } catch {
        continue;
      }
    }

    try {
      const note = parseNoteBytes(noteBytes);
      if (noteCommitmentMatches(note, commitmentHex)) {
        found.push(foundNoteFromEvent(note, event));
      }
    } catch {
      // Ignore ciphertexts that decrypt but do not contain a note payload.
    }
  }
  return found;
}

function processScanProjectionEvent(event, rootSeed, spendScalar, viewScalar) {
  const found = [];
  for (const output of event?.outputs || event?.Outputs || []) {
    if (event?.event_type === "deposit" || event?.eventType === "deposit") {
      const encryptedNoteHex = outputField(output, "encrypted_note_hex", "encryptedNoteHex");
      if (!encryptedNoteHex) continue;
      try {
        const noteBytes = decryptWithRootSeed(bytesFromHex(encryptedNoteHex, "encrypted note"), rootSeed);
        const note = parseNoteBytes(noteBytes);
        if (!noteCommitmentMatches(note, outputField(output, "commitment_hex", "commitmentHex"))) continue;
        found.push(foundNoteFromEvent(note, event));
      } catch {
        // Ignore projection outputs that do not belong to this wallet.
      }
      continue;
    }

    if (event?.event_type === "shielded_transfer" || event?.eventType === "shielded_transfer") {
      const cipherTextHex = outputField(output, "cipher_text_hex", "cipherTextHex");
      if (!cipherTextHex) continue;

      let noteBytes;
      try {
        // View tags are untrusted scan hints. Safe default is full trial decrypt.
        noteBytes = asymDecryptHex(cipherTextHex, viewScalar);
      } catch {
        if (spendScalar == null || spendScalar === viewScalar) continue;
        try {
          noteBytes = asymDecryptHex(cipherTextHex, spendScalar);
        } catch {
          continue;
        }
      }

      try {
        const note = parseNoteBytes(noteBytes);
        if (!noteCommitmentMatches(note, outputField(output, "commitment_hex", "commitmentHex"))) continue;
        found.push(foundNoteFromEvent(note, event));
      } catch {
        // Ignore ciphertexts that decrypt but do not contain a note payload.
      }
    }
  }
  return found;
}

export function processPrivacyEvent(event, { rootSeed, spendScalar, viewScalar } = {}) {
  if (Array.isArray(event?.outputs) || Array.isArray(event?.Outputs)) {
    return processScanProjectionEvent(event, rootSeed, spendScalar, viewScalar);
  }
  const eventType = event?.event_type ?? event?.eventType;
  if (eventType === "deposit") {
    return processDepositEvent(event, rootSeed);
  }
  if (eventType === "shielded_transfer") {
    return processTransferEvent(event, spendScalar, viewScalar);
  }
  return [];
}

function foundNoteIdentityKey(found) {
  const nullifier = String(found?.nullifier || "").trim().toLowerCase();
  if (nullifier) return `nullifier:${nullifier}`;
  return `fallback:${found.height}:${String(found.txHash || "").toLowerCase()}:${found.note.amount}`;
}

export function normalizeFoundNotes(notes) {
  const byKey = new Map();
  for (const foundLike of notes) {
    const found = normalizeFoundNote(foundLike);
    const key = foundNoteIdentityKey(found);
    if (!byKey.has(key)) byKey.set(key, found);
  }
  return [...byKey.values()].sort((left, right) => {
    const leftHeight = BigInt(left.height);
    const rightHeight = BigInt(right.height);
    if (leftHeight !== rightHeight) return leftHeight < rightHeight ? -1 : 1;
    const leftSequence = BigInt(left.sequence);
    const rightSequence = BigInt(right.sequence);
    if (leftSequence !== rightSequence) return leftSequence < rightSequence ? -1 : 1;
    const txCompare = String(left.txHash).localeCompare(String(right.txHash));
    if (txCompare !== 0) return txCompare;
    const nullifierCompare = String(left.nullifier).localeCompare(String(right.nullifier));
    if (nullifierCompare !== 0) return nullifierCompare;
    return left.note.amount < right.note.amount ? -1 : left.note.amount > right.note.amount ? 1 : 0;
  });
}

function noteResponse(found, index) {
  const verifiedUnspent = found.nullifierStatus === "unspent" && !found.isSpent;
  return {
    index: index + 1,
    status: found.isSpent ? "spent" : (verifiedUnspent ? "spendable" : "unverified"),
    nullifier_status: found.nullifierStatus,
    amount: found.note.amount.toString(),
    nullifier: found.nullifier,
    tx_hash: found.txHash,
    height: found.height,
    sequence: found.sequence
  };
}

export async function scanNotes({
  rootSeed,
  events,
  checkNullifier,
  checkNullifiers,
  includeFoundNotes = false
} = {}) {
  if (!rootSeed) {
    throw new Error("rootSeed is required for note scan");
  }
  const spendScalar = deriveSpendKeys(rootSeed).scalar;
  const viewScalar = deriveViewKeys(rootSeed).scalar;
  let found = [];

  for (const event of events || []) {
    found.push(...processPrivacyEvent(event, { rootSeed, spendScalar, viewScalar }));
  }

  found = normalizeFoundNotes(found);

  let batchSpentRefreshSucceeded = false;
  let missingBatchNullifiers = null;
  if (checkNullifiers && found.length) {
    try {
      const nullifiers = [...new Set(found.map(note => String(note.nullifier || "").toLowerCase()).filter(Boolean))];
      const result = await checkNullifiers(nullifiers);
      const statuses = new Map();
      const invalidStatuses = new Set();
      const addStatus = (nullifier, value) => {
        const key = String(nullifier || "").trim().toLowerCase();
        if (!key || invalidStatuses.has(key)) return;
        const used = parseNullifierUsage(value);
        if (used === null || (statuses.has(key) && statuses.get(key) !== used)) {
          statuses.delete(key);
          invalidStatuses.add(key);
          return;
        }
        statuses.set(key, used);
      };
      if (result instanceof Map) {
        for (const [nullifier, value] of result) addStatus(nullifier, value);
      } else {
        if (Array.isArray(result?.statuses)) {
          for (const status of result.statuses) {
            const canonical = status?.nullifier;
            const alias = status?.Nullifier;
            if (canonical != null && alias != null &&
                String(canonical).trim().toLowerCase() !== String(alias).trim().toLowerCase()) {
              addStatus(canonical, null);
              addStatus(alias, null);
            } else {
              addStatus(canonical ?? alias, status);
            }
          }
        } else if (result && typeof result === "object") {
          for (const [key, value] of Object.entries(result)) {
            addStatus(key, value);
          }
        }
      }
      const missing = nullifiers.filter(nullifier => !statuses.has(nullifier));
      for (const note of found) {
        if (statuses.has(note.nullifier)) {
          note.isSpent = statuses.get(note.nullifier);
          note.nullifierStatus = note.isSpent ? "spent" : "unspent";
        }
      }
      batchSpentRefreshSucceeded = missing.length === 0;
      if (!batchSpentRefreshSucceeded) {
        missingBatchNullifiers = new Set(missing);
      }
    } catch {
      // Fall back to individual checks below when the batch path is unavailable.
    }
  }

  if (!batchSpentRefreshSucceeded && checkNullifier && (
    missingBatchNullifiers?.size || found.some(note => !note.isSpent)
  )) {
    for (const note of found) {
      if (missingBatchNullifiers) {
        if (!missingBatchNullifiers.has(note.nullifier)) continue;
      } else if (note.isSpent) {
        continue;
      }
      try {
        const result = await checkNullifier(note.nullifier);
        const used = parseNullifierUsage(result);
        if (used === null) {
          note.isSpent = false;
          note.nullifierStatus = "unknown";
        } else {
          note.isSpent = used;
          note.nullifierStatus = used ? "spent" : "unspent";
        }
      } catch {
        note.isSpent = false;
        note.nullifierStatus = "unknown";
      }
    }
  }

  const summary = {
    total_spendable: "0",
    spendable_count: 0,
    spent_count: 0,
    total_count: found.length
  };
  let total = 0n;
  for (const note of found) {
    if (note.isSpent) {
      summary.spent_count += 1;
    } else if (note.nullifierStatus === "unspent") {
      summary.spendable_count += 1;
      total += note.note.amount;
    }
  }
  summary.total_spendable = total.toString();

  const result = {
    notes: found.map(noteResponse),
    summary,
    diagnostics: {
      scanned_events: (events || []).length,
      new_notes_found: found.length,
      unverified_nullifier_count: found.filter(note =>
        note.nullifierStatus === "unknown" || note.nullifierStatus === "unverified"
      ).length
    }
  };
  if (includeFoundNotes) {
    result.foundNotes = found;
  }
  return result;
}
