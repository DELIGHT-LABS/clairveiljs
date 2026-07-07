import {
  asymDecryptHex,
  deriveSpendKeys,
  deriveViewKeys
} from "../core/crypto.js";
import {
  computeNoteCommitmentHex,
  computeNoteNullifierHex,
  decryptWithRootSeed,
  normalizeNote
} from "../core/note.js";
import {
  bytesFromHex,
  utf8String
} from "../core/browser-crypto.js";

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
    txHash: String(event?.tx_hash_hex ?? event?.txHashHex ?? "").toUpperCase(),
    height: Number(event?.height || 0),
    sequence: Number(event?.sequence || 0)
  };
}

function outputField(output, snake, camel) {
  return output?.[snake] ?? output?.[camel] ?? "";
}

function noteCommitmentMatches(note, commitmentHex) {
  const text = String(commitmentHex || "").trim().toLowerCase();
  if (!text) return true;
  try {
    return computeNoteCommitmentHex(note).toLowerCase() === text;
  } catch {
    return false;
  }
}

function processDepositEvent(event, rootSeed) {
  const encryptedNoteHex = stripQuotes(eventAttribute(event, "encrypted_note"));
  if (!encryptedNoteHex) return [];
  try {
    const noteBytes = decryptWithRootSeed(bytesFromHex(encryptedNoteHex, "encrypted note"), rootSeed);
    return [foundNoteFromEvent(parseNoteBytes(noteBytes), event)];
  } catch {
    return [];
  }
}

function processTransferEvent(event, spendScalar, viewScalar) {
  const found = [];
  for (const key of ["cipher_text_1", "cipher_text_2"]) {
    const cipherTextHex = stripQuotes(eventAttribute(event, key));
    if (!cipherTextHex) continue;

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
      found.push(foundNoteFromEvent(parseNoteBytes(noteBytes), event));
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
  for (const found of notes) {
    const key = foundNoteIdentityKey(found);
    if (!byKey.has(key)) byKey.set(key, found);
  }
  return [...byKey.values()].sort((left, right) => {
    if (left.height !== right.height) return left.height - right.height;
    const txCompare = String(left.txHash).localeCompare(String(right.txHash));
    if (txCompare !== 0) return txCompare;
    const nullifierCompare = String(left.nullifier).localeCompare(String(right.nullifier));
    if (nullifierCompare !== 0) return nullifierCompare;
    return left.note.amount < right.note.amount ? -1 : left.note.amount > right.note.amount ? 1 : 0;
  });
}

function noteResponse(found, index) {
  return {
    index: index + 1,
    status: found.isSpent ? "spent" : "spendable",
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
      const statuses = result instanceof Map ? result : new Map();
      if (!(result instanceof Map)) {
        if (Array.isArray(result?.statuses)) {
          for (const status of result.statuses) {
            statuses.set(String(status?.nullifier || "").toLowerCase(), Boolean(status?.used ?? status?.Used));
          }
        } else if (result && typeof result === "object") {
          for (const [key, value] of Object.entries(result)) {
            statuses.set(String(key).toLowerCase(), Boolean(value?.used ?? value?.Used ?? value));
          }
        }
      }
      const missing = nullifiers.filter(nullifier => !statuses.has(nullifier));
      for (const note of found) {
        if (statuses.has(note.nullifier)) {
          note.isSpent = Boolean(statuses.get(note.nullifier));
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
        note.isSpent = Boolean(result?.used ?? result?.Used ?? result);
      } catch {
        // Keep the note as locally spendable if the nullifier query is temporarily unavailable.
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
    } else {
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
      new_notes_found: found.length
    }
  };
  if (includeFoundNotes) {
    result.foundNotes = found;
  }
  return result;
}
