import { canonicalFieldHex } from "../core/crypto.js";
import { defaultAssetDenom } from "../core/coin.js";
import { computeAssetId } from "./protocol-domain.js";

// Internal policy injection keeps legacy V1 selection and explicit uint128
// planning on the same bounded search algorithm without changing wire codecs.
export function createNoteSelection({ maxShieldedAmount, maxTransactionAmount = null, normalizeInventoryNote, parseTargetAmount }) {
  function foundNoteIdentityKey(found) {
    const nullifier = String(found?.nullifier || "").trim().toLowerCase();
    if (nullifier) return `nullifier:${nullifier}`;
    return `fallback:${found.height}:${String(found.txHash || "").toLowerCase()}:${found.note.amount}`;
  }


  function foundNotePlannerLess(left, right) {
    if (left.note.amount !== right.note.amount) return left.note.amount < right.note.amount;
    const leftHeight = BigInt(left.height), rightHeight = BigInt(right.height);
    if (leftHeight !== rightHeight) return leftHeight < rightHeight;
    const txCompare = String(left.txHash || "").toLowerCase().localeCompare(String(right.txHash || "").toLowerCase());
    if (txCompare !== 0) return txCompare < 0;
    const nullifierCompare = String(left.nullifier || "").toLowerCase().localeCompare(String(right.nullifier || "").toLowerCase());
    if (nullifierCompare !== 0) return nullifierCompare < 0;
    return foundNoteIdentityKey(left) < foundNoteIdentityKey(right);
  }

  function foundNotePlannerCompare(left, right) {
    if (foundNotePlannerLess(left, right)) return -1;
    if (foundNotePlannerLess(right, left)) return 1;
    return 0;
  }

  function finalTransferOutputsWithinBound(total, target) {
    if (target < 0n || target > maxShieldedAmount) return false;
    if (total < target || (maxTransactionAmount !== null && total > maxTransactionAmount)) return false;
    return total - target <= maxShieldedAmount;
  }

  function betterSufficientPairCandidate(left, right, total, bestLeft, bestRight, bestTotal) {
    if (total !== bestTotal) return total < bestTotal;
    if (right.note.amount !== bestRight.note.amount) return right.note.amount < bestRight.note.amount;
    if (left.note.amount !== bestLeft.note.amount) return left.note.amount < bestLeft.note.amount;
    if (foundNotePlannerLess(left, bestLeft)) return true;
    if (foundNotePlannerLess(bestLeft, left)) return false;
    return foundNotePlannerLess(right, bestRight);
  }

  function betterMergePairCandidate(left, right, total, bestLeft, bestRight, bestTotal) {
    if (total !== bestTotal) return total > bestTotal;
    if (right.note.amount !== bestRight.note.amount) return right.note.amount > bestRight.note.amount;
    if (left.note.amount !== bestLeft.note.amount) return left.note.amount > bestLeft.note.amount;
    if (foundNotePlannerLess(left, bestLeft)) return true;
    if (foundNotePlannerLess(bestLeft, left)) return false;
    return foundNotePlannerLess(right, bestRight);
  }

  function summarizeSpendableNotesByDenom(notes, denom = defaultAssetDenom) {
    const targetAssetIdHex = canonicalFieldHex(computeAssetId(denom));
    const spendable = [...(notes || [])]
      .map(normalizeInventoryNote)
      .filter(found => (found.nullifierStatus === "unspent" && found.isSpent === false) && canonicalFieldHex(found.note.assetID) === targetAssetIdHex)
      .sort(foundNotePlannerCompare);
    if (maxTransactionAmount !== null) {
      const identities = new Set();
      for (const found of spendable) {
        const key = foundNoteIdentityKey(found);
        if (identities.has(key)) throw new Error("duplicate spendable note identity");
        identities.add(key);
      }
    }
    const total = spendable.reduce((sum, found) => sum + found.note.amount, 0n);
    return { notes: spendable, total };
  }

  function findZeroNote(notes, excludeIndex) {
    for (let i = 0; i < notes.length; i += 1) {
      if (i === excludeIndex) continue;
      if (notes[i].note.amount === 0n) return i;
    }
    return -1;
  }

  function selectTransferInputs(notes, denom, targetAmount) {
    const target = parseTargetAmount(targetAmount, "transfer amount");
    const sameDenomNotes = summarizeSpendableNotesByDenom(notes, denom).notes;
    const inputs = [];
    let requiresDummyForSingleNote = false;

    for (let i = 0; i < sameDenomNotes.length; i += 1) {
      const note = sameDenomNotes[i];
      if (finalTransferOutputsWithinBound(note.note.amount, target)) {
        const zeroNoteIndex = findZeroNote(sameDenomNotes, i);
        if (zeroNoteIndex !== -1) {
          return {
            inputs: [note, sameDenomNotes[zeroNoteIndex]],
            total: note.note.amount,
            isFinal: true,
            needsZeroDummy: false
          };
        }
        requiresDummyForSingleNote = true;
      }
    }

    let bestPair = null;
    let bestPairTotal = 0n;
    for (let i = 0; i < sameDenomNotes.length; i += 1) {
      if (sameDenomNotes[i].note.amount === 0n) continue;
      for (let j = i + 1; j < sameDenomNotes.length; j += 1) {
        if (sameDenomNotes[j].note.amount === 0n) continue;
        const total = sameDenomNotes[i].note.amount + sameDenomNotes[j].note.amount;
        if (finalTransferOutputsWithinBound(total, target) && (!bestPair || betterSufficientPairCandidate(
          sameDenomNotes[i],
          sameDenomNotes[j],
          total,
          bestPair[0],
          bestPair[1],
          bestPairTotal
        ))) {
          bestPair = [sameDenomNotes[i], sameDenomNotes[j]];
          bestPairTotal = total;
        }
      }
    }
    if (bestPair) {
      return { inputs: bestPair, total: bestPairTotal, isFinal: true, needsZeroDummy: false };
    }

    let bestMerge = null;
    let bestMergeTotal = 0n;
    for (let i = 0; i < sameDenomNotes.length; i += 1) {
      if (sameDenomNotes[i].note.amount === 0n) continue;
      for (let j = i + 1; j < sameDenomNotes.length; j += 1) {
        if (sameDenomNotes[j].note.amount === 0n) continue;
        const total = sameDenomNotes[i].note.amount + sameDenomNotes[j].note.amount;
        if (total > maxShieldedAmount) continue;
        if (!bestMerge || betterMergePairCandidate(
          sameDenomNotes[i],
          sameDenomNotes[j],
          total,
          bestMerge[0],
          bestMerge[1],
          bestMergeTotal
        )) {
          bestMerge = [sameDenomNotes[i], sameDenomNotes[j]];
          bestMergeTotal = total;
        }
      }
    }
    if (bestMerge) {
      return { inputs: bestMerge, total: bestMergeTotal, isFinal: false, needsZeroDummy: false };
    }

    if (requiresDummyForSingleNote) {
      return { inputs, total: 0n, isFinal: false, needsZeroDummy: true };
    }

    return { inputs, total: 0n, isFinal: false, needsZeroDummy: false };
  }

  const batchTransferMaxInputs = 16;
  const batchTransferSearchStepLimit = 250000;

  function betterBatchInputSelection(candidate, current, target) {
    if (!current) return true;
    const candidateExact = candidate.total === target;
    const currentExact = current.total === target;
    if (candidateExact !== currentExact) return candidateExact;
    if (candidate.total !== current.total) return candidate.total < current.total;
    if (candidate.inputs.length !== current.inputs.length) return candidate.inputs.length < current.inputs.length;
    return candidate.inputs.map(foundNoteIdentityKey).join("\0") < current.inputs.map(foundNoteIdentityKey).join("\0");
  }

  /** Select one non-overlapping 1..16-input witness for one-proof batch transfer. */
  function selectBatchTransferInputs(notes, denom, targetAmount) {
    const target = parseTargetAmount(targetAmount, "batch transfer total amount");
    if (target <= 0n) throw new Error("batch transfer total amount must be positive");
    // V1 bounds each output; V2 also bounds the entire transaction input sum.
    const maxSelectedTotal = maxTransactionAmount ?? (target + maxShieldedAmount);
    const available = summarizeSpendableNotesByDenom(notes, denom).notes;
    if (!available.length) return { inputs: [], total: 0n, isFinal: false, needsZeroDummy: false };

    const candidates = [...available].sort((left, right) => {
      if (left.note.amount !== right.note.amount) return left.note.amount > right.note.amount ? -1 : 1;
      return foundNotePlannerCompare(left, right);
    });
    let best = null;
    let steps = 0;

    const consider = selected => {
      const total = selected.reduce((sum, found) => sum + found.note.amount, 0n);
      if (total < target || total > maxSelectedTotal) return false;
      const candidate = {
        inputs: [...selected].sort(foundNotePlannerCompare),
        total,
        isFinal: true,
        needsZeroDummy: false
      };
      if (betterBatchInputSelection(candidate, best, target)) best = candidate;
      return total === target;
    };

    const search = (index, selected, total) => {
      steps += 1;
      if (steps > batchTransferSearchStepLimit || best?.total === target) return;
      if (total >= target) {
        consider(selected);
        return;
      }
      if (index >= candidates.length || selected.length >= batchTransferMaxInputs) return;
      const remainingSlots = batchTransferMaxInputs - selected.length;
      let maxReachable = total;
      for (let offset = index; offset < candidates.length && offset < index + remainingSlots; offset += 1) {
        maxReachable += candidates[offset].note.amount;
      }
      if (maxReachable < target) return;
      const candidate = candidates[index];
      if (total + candidate.note.amount <= maxSelectedTotal) {
        search(index + 1, [...selected, candidate], total + candidate.note.amount);
      }
      search(index + 1, selected, total);
    };
    search(0, [], 0n);

    if (!best) {
      const greedy = [];
      let total = 0n;
      for (const candidate of candidates) {
        if (greedy.length >= batchTransferMaxInputs || total >= target) break;
        if (total + candidate.note.amount > maxSelectedTotal) continue;
        greedy.push(candidate);
        total += candidate.note.amount;
      }
      if (total >= target) consider(greedy);
    }
    return best || { inputs: [], total: 0n, isFinal: false, needsZeroDummy: false };
  }
  return { summarizeSpendableNotesByDenom, selectTransferInputs, selectBatchTransferInputs };
}
