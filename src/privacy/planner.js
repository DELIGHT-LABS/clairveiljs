import {
  canonicalFieldHex,
  hashStringToField
} from "../core/crypto.js";
import {
  defaultAssetDenom,
  normalizeFoundNote,
  parseCoin
} from "../core/note.js";
import {
  selectTransferInputs,
  summarizeSpendableNotesByDenom
} from "./payload.js";
import {
  ClairveilError,
  plannerStatusToErrorCode
} from "../core/errors.js";

function coinString(amount, denom) {
  return `${amount.toString()}${denom}`;
}

function noteAmount(found) {
  return normalizeFoundNote(found).note.amount;
}

function spendableNotes(notes, denom) {
  return summarizeSpendableNotesByDenom(notes, denom).notes;
}

function maxBigInt(values) {
  return values.length ? values.reduce((max, value) => value > max ? value : max, values[0]) : 0n;
}

function sameDenomExactMatch(notes, denom, target) {
  const assetIdHex = canonicalFieldHex(hashStringToField(denom));
  for (const note of notes || []) {
    const found = normalizeFoundNote(note);
    if (found.isSpent) continue;
    if (found.note.amount !== target) continue;
    if (canonicalFieldHex(found.note.assetID) !== assetIdHex) continue;
    return found;
  }
  return null;
}

function plannerFacts({ requested, denom, spendable, selectedTotal = 0n }) {
  const amounts = spendable.map(noteAmount);
  return {
    requestedAmount: coinString(requested, denom),
    requestedAmountValue: requested.toString(),
    denom,
    spendableTotal: coinString(amounts.reduce((sum, value) => sum + value, 0n), denom),
    spendableTotalValue: amounts.reduce((sum, value) => sum + value, 0n).toString(),
    spendableCount: spendable.length,
    currentMaxNote: coinString(maxBigInt(amounts), denom),
    currentMaxNoteValue: maxBigInt(amounts).toString(),
    selectedInputTotal: coinString(selectedTotal, denom),
    selectedInputTotalValue: selectedTotal.toString()
  };
}

export function planTransferNotes({ notes, amount, denom = defaultAssetDenom } = {}) {
  const coin = parseCoin(amount, denom);
  const requested = BigInt(coin.amount);
  const spendable = spendableNotes(notes, coin.denom);
  const spendableTotal = spendable.reduce((sum, found) => sum + found.note.amount, 0n);
  const selection = selectTransferInputs(notes, coin.denom, coin.amount);
  const facts = plannerFacts({
    requested,
    denom: coin.denom,
    spendable,
    selectedTotal: selection.total
  });

  if (selection.needsZeroDummy) {
    return {
      status: "zero_dummy_required",
      canBuildTx: false,
      action: "create_zero_helper_note",
      message: "A second zero-value helper note is required before this transfer can be built.",
      facts,
      selection
    };
  }

  if (selection.total === 0n || (!selection.isFinal && spendableTotal < requested)) {
    const message = requested === 0n
      ? "No zero note is available; a 0uclair helper deposit is required."
      : `Need ${coin.raw}, but spendable total is ${spendableTotal}${coin.denom}.`;
    return {
      status: "insufficient_balance",
      canBuildTx: false,
      action: "deposit_or_receive_notes",
      message,
      facts,
      selection
    };
  }

  if (!selection.isFinal) {
    return {
      status: "self_merge_required",
      canBuildTx: true,
      action: "self_merge",
      message: "Merge two notes into a larger self note, then retry the requested transfer.",
      nextAmount: coinString(selection.total, coin.denom),
      facts,
      selection
    };
  }

  return {
    status: "final_transfer_ready",
    canBuildTx: true,
    action: "final_transfer",
    message: "The selected notes can satisfy the requested transfer.",
    nextAmount: coin.raw,
    facts,
    selection
  };
}

export function planWithdrawNotes({ notes, amount, denom = defaultAssetDenom } = {}) {
  const coin = parseCoin(amount, denom);
  const requested = BigInt(coin.amount);
  const spendable = spendableNotes(notes, coin.denom);
  const spendableTotal = spendable.reduce((sum, found) => sum + found.note.amount, 0n);
  const selected = sameDenomExactMatch(notes, coin.denom, requested);
  const facts = plannerFacts({
    requested,
    denom: coin.denom,
    spendable,
    selectedTotal: selected ? selected.note.amount : 0n
  });

  if (selected) {
    return {
      status: "withdraw_ready",
      canBuildTx: true,
      action: "withdraw_exact_note",
      message: "An exact-match note is available for withdraw.",
      facts,
      selectedNote: selected
    };
  }

  if (spendableTotal < requested) {
    return {
      status: "insufficient_balance",
      canBuildTx: false,
      action: "deposit_or_receive_notes",
      message: `Need ${coin.raw}, but spendable total is ${spendableTotal}${coin.denom}.`,
      facts,
      selectedNote: null
    };
  }

  return {
    status: "exact_note_required",
    canBuildTx: false,
    action: "self_transfer_exact_note",
    message: "Withdraw requires one exact-match note; create that note with a shielded self-transfer first.",
    facts,
    selectedNote: null
  };
}

export class ClairveilPlannerError extends ClairveilError {
  constructor(plan) {
    super(
      plannerStatusToErrorCode(plan?.status),
      plan?.message || "Clairveil planner could not build the requested transaction",
      { plan }
    );
    this.name = "ClairveilPlannerError";
    this.plan = plan;
  }
}

export function assertPlanCanBuildTx(plan) {
  if (!plan?.canBuildTx) {
    throw new ClairveilPlannerError(plan);
  }
  return plan;
}
