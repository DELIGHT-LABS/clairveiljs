import {
  asymDecryptHex,
  deriveSpendKeys,
  deriveViewKeys
} from "../core/crypto.js";
import {
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
    txHash: String(event?.tx_hash_hex || "").toUpperCase(),
    height: Number(event?.height || 0)
  };
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

export function processPrivacyEvent(event, { rootSeed, spendScalar, viewScalar } = {}) {
  if (event?.event_type === "deposit") {
    return processDepositEvent(event, rootSeed);
  }
  if (event?.event_type === "shielded_transfer") {
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
    height: found.height
  };
}

export async function scanNotes({
  rootSeed,
  events,
  checkNullifier,
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

  if (checkNullifier) {
    for (const note of found) {
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
