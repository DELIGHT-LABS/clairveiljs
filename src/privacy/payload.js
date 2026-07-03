import { fromBech32 } from "@cosmjs/encoding";
import {
  bytesFromHex,
  canonicalFieldHex,
  defaultAccountPrefix,
  decodeCanonicalFieldHex,
  decodeShieldedAddress,
  deriveDisclosureKeys,
  deriveSpendKeys,
  deriveViewKeys,
  encodeShieldedAddress,
  hashStringToField,
  hexFromBytes,
  normalizeHex,
  normalizeBech32Prefix,
  unpackPointHex
} from "../core/crypto.js";
import {
  computeAuditTransferDisclosureDigestHex,
  computeSelfViewTransferDisclosureDigestHex,
  computeTransferDisclosureDigestHex,
  payloadVersion,
  planeAudit,
  planeSelfView,
  planeUser,
  transferDisclosureRecipientOutputIndex,
  transferPrivacyPolicyAllPrivate,
  transferPrivacyPolicyDiscloseAmount,
  transferPrivacyPolicyDiscloseFrom,
  transferPrivacyPolicyDiscloseTo,
  userDisclosureModeNone,
  userDisclosureModePublic,
  userDisclosureModeRecipientEncrypted
} from "../core/disclosure.js";
import {
  computeNoteCommitmentHex,
  computeNoteNullifierHex,
  computeTransferNoteHash,
  computeWithdrawNoteHash,
  createNote,
  createSpendNoteHashSigner,
  defaultAssetDenom,
  encryptNoteForReceiver,
  normalizeFoundNote,
  normalizeNote,
  noteSpendPubKeyHex,
  noteViewPubKeyHex,
  parseCoin,
  resolveTransferSignature,
  resolveWithdrawSignature,
  asymEncrypt
} from "../core/note.js";
import {
  sha256Hex as digestSha256Hex,
  utf8Bytes
} from "../core/browser-crypto.js";

export const preparedTransferPayloadVersion = "v2";
export const preparedTransferProofVersion = "v1";
export const preparedWithdrawProverPayloadVersion = "v1";
export const preparedWithdrawProofVersion = "v1";
export const preparedWithdrawPayloadVersion = "v1";

export const userDisclosureModeValue = {
  none: 0,
  public: 1,
  "recipient-encrypted": 2,
  [userDisclosureModeNone]: 0,
  [userDisclosureModePublic]: 1,
  [userDisclosureModeRecipientEncrypted]: 2
};

export const userDisclosureModeName = {
  0: userDisclosureModeNone,
  1: userDisclosureModePublic,
  2: userDisclosureModeRecipientEncrypted
};

export const privacyPolicyValue = {
  "all-private": 0,
  amount: 1,
  to: 2,
  "amount-to": 3,
  from: 4,
  "amount-from": 5,
  "from-to": 6,
  "to-from": 6,
  "amount-from-to": 7,
  "amount-to-from": 7
};

function sha256Hex(text) {
  return digestSha256Hex(text);
}

function writeLines(values) {
  let out = "";
  for (const value of values) {
    out += `${value}\n`;
  }
  return out;
}

function hexToBytes(value, label) {
  return bytesFromHex(normalizeHex(value, label), label);
}

function optionalHexToBytes(value, label) {
  const text = String(value || "").trim();
  return text ? hexToBytes(text, label) : new Uint8Array();
}

function bigintDecimal(value, label) {
  if (typeof value === "bigint") return value.toString();
  const text = String(value ?? "").trim();
  if (!/^(0|[1-9][0-9]*)$/.test(text)) {
    throw new Error(`${label} must be a non-negative decimal integer`);
  }
  return text;
}

function positiveBigInt(value, label) {
  const parsed = BigInt(bigintDecimal(value, label));
  if (parsed <= 0n) {
    throw new Error(`${label} must be positive`);
  }
  return parsed;
}

function normalizePolicy(value) {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0 || value > 7) {
      throw new Error("unsupported transfer privacy policy");
    }
    return value;
  }
  if (typeof value === "bigint") return normalizePolicy(Number(value));
  const key = String(value ?? "all-private").trim() || "all-private";
  if (Object.prototype.hasOwnProperty.call(privacyPolicyValue, key)) {
    return privacyPolicyValue[key];
  }
  if (/^(0|[1-7])$/.test(key)) return Number(key);
  throw new Error(`unsupported transfer privacy policy ${JSON.stringify(value)}`);
}

function normalizeDisclosureMode(value, policy) {
  if (policy === transferPrivacyPolicyAllPrivate) return 0;
  if (typeof value === "number") {
    if (![1, 2].includes(value)) {
      throw new Error("disclosure mode must be public or recipient-encrypted when disclosure is enabled");
    }
    return value;
  }
  const key = String(value ?? "recipient-encrypted").trim() || "recipient-encrypted";
  if (!Object.prototype.hasOwnProperty.call(userDisclosureModeValue, key)) {
    throw new Error(`unsupported disclosure mode ${JSON.stringify(value)}`);
  }
  const mode = userDisclosureModeValue[key];
  if (mode === 0) {
    throw new Error("disclosure mode none is only valid for all-private transfers");
  }
  return mode;
}

function normalizeDisclosurePubKey(value, label) {
  const text = String(value || "").trim();
  if (!text) return { point: null, hex: "" };
  const normalized = normalizeHex(text, label);
  return {
    point: unpackPointHex(normalized),
    hex: normalized
  };
}

function noteAddress(noteLike, shieldedPrefix) {
  const note = normalizeNote(noteLike);
  return encodeShieldedAddress(
    { x: note.receiverSpendPubKeyX, y: note.receiverSpendPubKeyY },
    { x: note.receiverViewPubKeyX, y: note.receiverViewPubKeyY },
    { shieldedPrefix }
  );
}

function foundNoteIdentityKey(found) {
  const nullifier = String(found?.nullifier || "").trim().toLowerCase();
  if (nullifier) return `nullifier:${nullifier}`;
  return `fallback:${found.height}:${String(found.txHash || "").toLowerCase()}:${found.note.amount}`;
}

function foundNotePlannerLess(left, right) {
  if (left.note.amount !== right.note.amount) return left.note.amount < right.note.amount;
  if (left.height !== right.height) return left.height < right.height;
  const txCompare = String(left.txHash || "").toLowerCase().localeCompare(String(right.txHash || "").toLowerCase());
  if (txCompare !== 0) return txCompare < 0;
  const nullifierCompare = String(left.nullifier || "").toLowerCase().localeCompare(String(right.nullifier || "").toLowerCase());
  if (nullifierCompare !== 0) return nullifierCompare < 0;
  return foundNoteIdentityKey(left) < foundNoteIdentityKey(right);
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

export function summarizeSpendableNotesByDenom(notes, denom = defaultAssetDenom) {
  const targetAssetIdHex = canonicalFieldHex(hashStringToField(denom));
  const spendable = [...(notes || [])]
    .map(normalizeFoundNote)
    .filter(found => !found.isSpent && canonicalFieldHex(found.note.assetID) === targetAssetIdHex)
    .sort(foundNotePlannerLess);
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

export function selectTransferInputs(notes, denom, targetAmount) {
  const target = BigInt(bigintDecimal(targetAmount, "transfer amount"));
  const sameDenomNotes = summarizeSpendableNotesByDenom(notes, denom).notes;
  const inputs = [];
  let requiresDummyForSingleNote = false;

  for (let i = 0; i < sameDenomNotes.length; i += 1) {
    const note = sameDenomNotes[i];
    if (note.note.amount >= target) {
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
      if (total >= target && (!bestPair || betterSufficientPairCandidate(
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

function disclosureCommon({ outputCommitmentHex, fromNote, recipientNote }) {
  const from = normalizeNote(fromNote);
  const to = normalizeNote(recipientNote);
  return {
    outputIndex: transferDisclosureRecipientOutputIndex,
    commitment: outputCommitmentHex,
    amount: to.amount,
    assetId: to.assetID,
    fromSpendPubKeyX: from.receiverSpendPubKeyX,
    fromSpendPubKeyY: from.receiverSpendPubKeyY,
    fromViewPubKeyX: from.receiverViewPubKeyX,
    fromViewPubKeyY: from.receiverViewPubKeyY,
    toSpendPubKeyX: to.receiverSpendPubKeyX,
    toSpendPubKeyY: to.receiverSpendPubKeyY,
    toViewPubKeyX: to.receiverViewPubKeyX,
    toViewPubKeyY: to.receiverViewPubKeyY
  };
}

function buildDisclosurePayload({
  plane,
  policy,
  outputCommitmentHex,
  digestHex,
  transferDenom,
  fromNote,
  recipientNote,
  shieldedPrefix
}) {
  const payload = {
    version: payloadVersion,
    plane,
    policy,
    output_index: transferDisclosureRecipientOutputIndex,
    commitment_hex: outputCommitmentHex,
    disclosure_digest_hex: digestHex
  };

  if (plane === planeAudit || (policy & transferPrivacyPolicyDiscloseAmount) !== 0) {
    payload.amount = normalizeNote(recipientNote).amount.toString();
    payload.asset_id_hex = canonicalFieldHex(normalizeNote(recipientNote).assetID);
    payload.asset_denom = transferDenom;
  }
  if (plane === planeAudit || (policy & transferPrivacyPolicyDiscloseFrom) !== 0) {
    payload.from_shielded_address = noteAddress(fromNote, shieldedPrefix);
  }
  if (plane === planeAudit || (policy & transferPrivacyPolicyDiscloseTo) !== 0) {
    payload.to_shielded_address = noteAddress(recipientNote, shieldedPrefix);
  }

  return payload;
}

export function buildUserDisclosureData({
  policy,
  mode,
  outputCommitmentHex,
  transferDenom = defaultAssetDenom,
  fromNote,
  recipientNote,
  targetPubKeyHex,
  shieldedPrefix
}) {
  const numericPolicy = normalizePolicy(policy);
  if (numericPolicy === transferPrivacyPolicyAllPrivate) return null;
  const numericMode = normalizeDisclosureMode(mode, numericPolicy);
  const digestHex = computeTransferDisclosureDigestHex({
    ...disclosureCommon({ outputCommitmentHex, fromNote, recipientNote }),
    policy: numericPolicy
  });
  const payload = buildDisclosurePayload({
    plane: planeUser,
    policy: numericPolicy,
    outputCommitmentHex,
    digestHex,
    transferDenom,
    fromNote,
    recipientNote,
    shieldedPrefix
  });
  const payloadBytes = utf8Bytes(JSON.stringify(payload));

  if (numericMode === userDisclosureModeValue.public) {
    return {
      payload,
      digest_hex: digestHex,
      target_pubkey_hex: "",
      payload_hex: hexFromBytes(payloadBytes),
      mode: numericMode
    };
  }

  const target = normalizeDisclosurePubKey(targetPubKeyHex, "user disclosure target pubkey");
  if (!target.point) {
    throw new Error("recipient-encrypted disclosure requires a target pubkey");
  }
  const cipherText = asymEncrypt(payloadBytes, target.point);
  return {
    payload,
    digest_hex: digestHex,
    target_pubkey_hex: target.hex,
    payload_hex: hexFromBytes(cipherText),
    mode: numericMode
  };
}

export function buildAuditDisclosureData({
  outputCommitmentHex,
  transferDenom = defaultAssetDenom,
  fromNote,
  recipientNote,
  auditPubKeyHex,
  shieldedPrefix
}) {
  const target = normalizeDisclosurePubKey(auditPubKeyHex, "audit disclosure target pubkey");
  if (!target.point) {
    throw new Error("audit disclosure target pubkey is required");
  }
  const digestHex = computeAuditTransferDisclosureDigestHex(
    disclosureCommon({ outputCommitmentHex, fromNote, recipientNote })
  );
  const payload = buildDisclosurePayload({
    plane: planeAudit,
    policy: 7,
    outputCommitmentHex,
    digestHex,
    transferDenom,
    fromNote,
    recipientNote,
    shieldedPrefix
  });
  const cipherText = asymEncrypt(utf8Bytes(JSON.stringify(payload)), target.point);
  return {
    payload,
    digest_hex: digestHex,
    target_pubkey_hex: target.hex,
    payload_hex: hexFromBytes(cipherText),
    mode: userDisclosureModeValue["recipient-encrypted"]
  };
}

export function buildSelfViewDisclosureData({
  outputCommitmentHex,
  transferDenom = defaultAssetDenom,
  fromNote,
  recipientNote,
  targetPubKeyHex,
  shieldedPrefix
}) {
  const target = normalizeDisclosurePubKey(targetPubKeyHex, "self-view disclosure target pubkey");
  if (!target.point) {
    throw new Error("self-view disclosure target pubkey is required");
  }
  const digestHex = computeSelfViewTransferDisclosureDigestHex(
    disclosureCommon({ outputCommitmentHex, fromNote, recipientNote })
  );
  const payload = buildDisclosurePayload({
    plane: planeSelfView,
    policy: 7,
    outputCommitmentHex,
    digestHex,
    transferDenom,
    fromNote,
    recipientNote,
    shieldedPrefix
  });
  const cipherText = asymEncrypt(utf8Bytes(JSON.stringify(payload)), target.point);
  return {
    payload,
    digest_hex: digestHex,
    payload_hex: hexFromBytes(cipherText),
    mode: userDisclosureModeValue["recipient-encrypted"]
  };
}

async function lookupMerklePath(provider, commitmentHex) {
  if (!provider) {
    throw new Error("a merkle path provider is required");
  }
  if (typeof provider === "function") {
    return provider(commitmentHex);
  }
  if (typeof provider.lookupMerklePath === "function") {
    return provider.lookupMerklePath(commitmentHex);
  }
  if (typeof provider.LookupMerklePath === "function") {
    return provider.LookupMerklePath(commitmentHex);
  }
  throw new Error("merkle path provider must expose lookupMerklePath(commitmentHex)");
}

function normalizeMerklePathResult(result, label) {
  const rootHex = String(result?.root ?? result?.Root ?? "").trim();
  if (!rootHex) {
    throw new Error(`${label} merkle path result missing root`);
  }
  return {
    rootHex: hexFromBytes(decodeCanonicalFieldHex(rootHex, `${label} root`)),
    path: [...(result?.path ?? result?.Path ?? [])].map(value => String(value)),
    pathHelper: [...(result?.path_helper ?? result?.pathHelper ?? result?.PathHelper ?? [])].map(value => Number(value))
  };
}

function transferPayloadHashIncludesSelfView(version) {
  return String(version || "") !== "v1";
}

export function computePreparedTransferPayloadHash(payload) {
  const lines = [
    payload.version,
    payload.creator,
    payload.root_hex,
    payload.asset_id_hex,
    String(payload.user_privacy_policy),
    String(payload.user_disclosure_mode),
    payload.user_disclosure_digest_hex || "",
    payload.user_disclosure_target_pubkey_hex || "",
    payload.user_disclosure_payload_hex || "",
    payload.audit_disclosure_digest_hex,
    payload.audit_disclosure_target_pubkey_hex,
    payload.audit_disclosure_payload_hex
  ];
  if (transferPayloadHashIncludesSelfView(payload.version)) {
    lines.push(
      payload.self_view_disclosure_digest_hex || "",
      payload.self_view_disclosure_payload_hex || ""
    );
  }
  lines.push(String(payload.inputs.length));
  for (const input of payload.inputs) {
    lines.push(
      input.amount,
      input.randomness_hex,
      input.spend_pubkey_hex,
      input.view_pubkey_hex,
      String(input.merkle_path.length),
      ...input.merkle_path,
      String(input.merkle_path_helper.length),
      ...input.merkle_path_helper.map(String),
      input.note_hash_signature_hex,
      input.nullifier_hex
    );
  }
  lines.push(String(payload.outputs.length));
  for (const output of payload.outputs) {
    lines.push(
      output.amount,
      output.randomness_hex,
      output.spend_pubkey_hex,
      output.view_pubkey_hex,
      output.commitment_hex
    );
  }
  lines.push(String(payload.cipher_text_hexes.length), ...payload.cipher_text_hexes);
  return sha256Hex(writeLines(lines));
}

export async function buildPreparedTransferPayload({
  creator,
  inputs,
  recipient,
  amount,
  transferAmount,
  transferDenom,
  rootSeed,
  senderSpendPubKey,
  senderViewPubKey,
  merklePathProvider,
  noteHashSigner,
  userPrivacyPolicy = "all-private",
  userDisclosureMode,
  userDisclosureTargetPubKeyHex = "",
  auditDisclosureTargetPubKeyHex,
  disableSelfViewDisclosure = false,
  selfViewDisclosureTargetPubKeyHex,
  shieldedPrefix
} = {}) {
  const coin = parseCoin(amount ?? transferAmount, transferDenom || defaultAssetDenom);
  const targetAmount = positiveBigInt(coin.amount, "transfer amount");
  const foundInputs = [...(inputs || [])].map(normalizeFoundNote);
  if (foundInputs.length !== 2) {
    throw new Error(`transfer prepared payload requires exactly 2 input notes; got ${foundInputs.length}`);
  }
  const targetAssetIdHex = canonicalFieldHex(hashStringToField(coin.denom));
  foundInputs.forEach((found, index) => {
    const inputAssetIdHex = canonicalFieldHex(found.note.assetID);
    if (inputAssetIdHex !== targetAssetIdHex) {
      throw new Error(`transfer input ${index} asset does not match requested denom ${coin.denom}`);
    }
  });
  const totalInput = foundInputs.reduce((sum, input) => sum + input.note.amount, 0n);
  const changeAmount = totalInput - targetAmount;
  if (changeAmount < 0n) {
    throw new Error(`insufficient selected input total ${totalInput} for transfer amount ${targetAmount}`);
  }

  const recipientBundle = decodeShieldedAddress(recipient, { shieldedPrefix });
  const senderSpend = senderSpendPubKey || (rootSeed ? deriveSpendKeys(rootSeed).pubKey : null);
  const senderView = senderViewPubKey || (rootSeed ? deriveViewKeys(rootSeed).pubKey : null);
  if (!senderSpend || !senderView) {
    throw new Error("sender spend/view public keys or rootSeed are required");
  }
  const signer = noteHashSigner || (rootSeed ? createSpendNoteHashSigner(rootSeed) : null);
  if (!signer) {
    throw new Error("noteHashSigner or rootSeed is required");
  }

  const recipientNote = createNote({
    spendPubKey: recipientBundle.spendPubKey,
    viewPubKey: recipientBundle.viewPubKey,
    amount: targetAmount,
    assetId: foundInputs[0].note.assetID,
    memo: "Transfer"
  });
  const changeNote = createNote({
    spendPubKey: senderSpend,
    viewPubKey: senderView,
    amount: changeAmount,
    assetId: foundInputs[0].note.assetID,
    memo: "Change"
  });
  const outputNotes = [recipientNote, changeNote];
  const outputCommitmentHexes = outputNotes.map(computeNoteCommitmentHex);
  const recipientCommitmentHex = outputCommitmentHexes[0];
  const policy = normalizePolicy(userPrivacyPolicy);
  const mode = normalizeDisclosureMode(userDisclosureMode, policy);
  const userDisclosure = buildUserDisclosureData({
    policy,
    mode,
    outputCommitmentHex: recipientCommitmentHex,
    transferDenom: coin.denom,
    fromNote: foundInputs[0].note,
    recipientNote,
    targetPubKeyHex: userDisclosureTargetPubKeyHex,
    shieldedPrefix
  });
  const auditDisclosure = buildAuditDisclosureData({
    outputCommitmentHex: recipientCommitmentHex,
    transferDenom: coin.denom,
    fromNote: foundInputs[0].note,
    recipientNote,
    auditPubKeyHex: auditDisclosureTargetPubKeyHex,
    shieldedPrefix
  });
  const explicitSelfViewTargetPubKeyHex = String(selfViewDisclosureTargetPubKeyHex || "").trim();
  const selfViewTargetPubKeyHex = explicitSelfViewTargetPubKeyHex
    || (rootSeed ? deriveDisclosureKeys(rootSeed).pubKeyHex : "");
  const selfViewDisclosure = !disableSelfViewDisclosure && selfViewTargetPubKeyHex
    ? buildSelfViewDisclosureData({
      outputCommitmentHex: recipientCommitmentHex,
      transferDenom: coin.denom,
      fromNote: foundInputs[0].note,
      recipientNote,
      targetPubKeyHex: selfViewTargetPubKeyHex,
      shieldedPrefix
    })
    : null;

  const preparedInputs = [];
  let commonRootHex = "";
  for (let i = 0; i < foundInputs.length; i += 1) {
    const found = foundInputs[i];
    const commitmentHex = computeNoteCommitmentHex(found.note);
    const merkle = normalizeMerklePathResult(await lookupMerklePath(merklePathProvider, commitmentHex), `input ${i}`);
    if (!commonRootHex) {
      commonRootHex = merkle.rootHex;
    } else if (commonRootHex !== merkle.rootHex) {
      throw new Error("merkle root mismatch across input notes");
    }
    const signature = await resolveTransferSignature(signer, computeTransferNoteHash(found.note));
    preparedInputs.push({
      amount: found.note.amount.toString(),
      randomness_hex: canonicalFieldHex(found.note.randomness),
      spend_pubkey_hex: noteSpendPubKeyHex(found.note),
      view_pubkey_hex: noteViewPubKeyHex(found.note),
      merkle_path: merkle.path,
      merkle_path_helper: merkle.pathHelper,
      note_hash_signature_hex: hexFromBytes(signature),
      nullifier_hex: computeNoteNullifierHex(found.note)
    });
  }

  const payload = {
    version: preparedTransferPayloadVersion,
    creator: String(creator || ""),
    root_hex: commonRootHex,
    asset_id_hex: canonicalFieldHex(foundInputs[0].note.assetID),
    inputs: preparedInputs,
    outputs: outputNotes.map((note, i) => ({
      amount: note.amount.toString(),
      randomness_hex: canonicalFieldHex(note.randomness),
      spend_pubkey_hex: noteSpendPubKeyHex(note),
      view_pubkey_hex: noteViewPubKeyHex(note),
      commitment_hex: outputCommitmentHexes[i]
    })),
    cipher_text_hexes: outputNotes.map(note => hexFromBytes(encryptNoteForReceiver(note))),
    user_privacy_policy: policy,
    user_disclosure_mode: mode,
    user_disclosure_digest_hex: userDisclosure?.digest_hex || "",
    user_disclosure_target_pubkey_hex: userDisclosure?.target_pubkey_hex || "",
    user_disclosure_payload_hex: userDisclosure?.payload_hex || "",
    audit_disclosure_digest_hex: auditDisclosure.digest_hex,
    audit_disclosure_target_pubkey_hex: auditDisclosure.target_pubkey_hex,
    audit_disclosure_payload_hex: auditDisclosure.payload_hex,
    self_view_disclosure_digest_hex: selfViewDisclosure?.digest_hex || "",
    self_view_disclosure_payload_hex: selfViewDisclosure?.payload_hex || ""
  };
  payload.payload_hash = computePreparedTransferPayloadHash(payload);
  return payload;
}

export function validatePreparedTransferProof(payload, proof) {
  if (!proof || proof.version !== preparedTransferProofVersion) {
    throw new Error(`unsupported transfer proof version ${JSON.stringify(proof?.version)}`);
  }
  if (proof.payload_hash !== payload.payload_hash) {
    throw new Error("transfer proof payload hash mismatch");
  }
  normalizeHex(proof.proof_hex, "transfer proof");
  return true;
}

export function buildTransferMsgFromPayloadAndProof(payload, proof) {
  validatePreparedTransferProof(payload, proof);
  return {
    creator: payload.creator,
    proof: hexToBytes(proof.proof_hex, "transfer proof"),
    root: hexToBytes(payload.root_hex, "transfer root"),
    nullifiers: payload.inputs.map(input => hexToBytes(input.nullifier_hex, "transfer nullifier")),
    newCommitments: payload.outputs.map(output => hexToBytes(output.commitment_hex, "transfer commitment")),
    cipherTexts: payload.cipher_text_hexes.map(value => hexToBytes(value, "transfer ciphertext")),
    userPrivacyPolicy: payload.user_privacy_policy,
    userDisclosureDigest: optionalHexToBytes(payload.user_disclosure_digest_hex, "user disclosure digest"),
    userDisclosureMode: payload.user_disclosure_mode,
    userDisclosureTargetPubkey: optionalHexToBytes(payload.user_disclosure_target_pubkey_hex, "user disclosure target pubkey"),
    userDisclosurePayload: optionalHexToBytes(payload.user_disclosure_payload_hex, "user disclosure payload"),
    auditDisclosureDigest: hexToBytes(payload.audit_disclosure_digest_hex, "audit disclosure digest"),
    auditDisclosureTargetPubkey: hexToBytes(payload.audit_disclosure_target_pubkey_hex, "audit disclosure target pubkey"),
    auditDisclosurePayload: hexToBytes(payload.audit_disclosure_payload_hex, "audit disclosure payload"),
    selfViewDisclosureDigest: optionalHexToBytes(payload.self_view_disclosure_digest_hex, "self-view disclosure digest"),
    selfViewDisclosurePayload: optionalHexToBytes(payload.self_view_disclosure_payload_hex, "self-view disclosure payload")
  };
}

export async function buildTransferMessage({ proverAdapter, ...input } = {}) {
  if (!proverAdapter?.proveTransfer) {
    throw new Error("proverAdapter.proveTransfer is required");
  }
  const payload = await buildPreparedTransferPayload(input);
  const response = await proverAdapter.proveTransfer({
    version: "v1",
    payload
  });
  const proof = response?.proof || response;
  return {
    payload,
    proof,
    message: buildTransferMsgFromPayloadAndProof(payload, proof)
  };
}

function selectExactMatchNote(notes, denom, targetAmount) {
  const targetAssetIdHex = canonicalFieldHex(hashStringToField(denom));
  for (const found of notes) {
    if (found.isSpent) continue;
    if (found.note.amount !== targetAmount) continue;
    if (canonicalFieldHex(found.note.assetID) !== targetAssetIdHex) continue;
    return found;
  }
  return null;
}

export function computePreparedWithdrawProverPayloadHash(payload) {
  return sha256Hex(writeLines([
    payload.version,
    payload.root_hex,
    payload.nullifier_hex,
    payload.amount,
    payload.asset_denom,
    payload.asset_id_hex,
    payload.recipient,
    payload.recipient_bytes_hex,
    payload.chain_id,
    String(payload.expires_at_unix),
    payload.note_randomness_hex,
    payload.spend_pubkey_hex,
    payload.view_pubkey_hex,
    String(payload.merkle_path.length),
    ...payload.merkle_path,
    String(payload.merkle_path_helper.length),
    ...payload.merkle_path_helper.map(String),
    payload.spend_note_hash_signature_hex
  ]));
}

export async function buildPreparedWithdrawProverPayload({
  notes,
  amount,
  denom,
  assetDenom,
  recipient,
  chainId,
  expiresAtUnix = Math.floor(Date.now() / 1000) + 1800,
  rootSeed,
  merklePathProvider,
  spendNoteHashSigner,
  accountPrefix
} = {}) {
  const coin = parseCoin(amount, assetDenom ?? denom ?? defaultAssetDenom);
  const targetAmount = positiveBigInt(coin.amount, "withdraw amount");
  const foundNotes = [...(notes || [])].map(normalizeFoundNote);
  const targetAssetIdHex = canonicalFieldHex(hashStringToField(coin.denom));
  const selected = selectExactMatchNote(foundNotes, coin.denom, targetAmount);
  if (!selected) {
    const sameDenom = foundNotes.filter(found => !found.isSpent && canonicalFieldHex(found.note.assetID) === targetAssetIdHex);
    const total = sameDenom.reduce((sum, found) => sum + found.note.amount, 0n);
    throw new Error(`withdraw requires one exact-match note for ${coin.raw}; spendable ${coin.denom} total is ${total}${coin.denom} across ${sameDenom.length} notes`);
  }
  const commitmentHex = computeNoteCommitmentHex(selected.note);
  const merkle = normalizeMerklePathResult(await lookupMerklePath(merklePathProvider, commitmentHex), "withdraw selected note");
  const recipientDecoded = fromBech32(recipient);
  const expectedAccountPrefix = normalizeBech32Prefix(accountPrefix ?? defaultAccountPrefix, "accountPrefix");
  if (recipientDecoded.prefix !== expectedAccountPrefix) {
    throw new Error(`withdraw recipient prefix mismatch: expected ${expectedAccountPrefix}, got ${recipientDecoded.prefix}`);
  }
  const recipientBytes = Uint8Array.from(recipientDecoded.data);
  const signer = spendNoteHashSigner || (rootSeed ? createSpendNoteHashSigner(rootSeed) : null);
  if (!signer) {
    throw new Error("spendNoteHashSigner or rootSeed is required");
  }
  const normalizedExpiresAtUnix = assertFutureUnixTimestamp(
    expiresAtUnix,
    Math.floor(Date.now() / 1000),
    "withdraw prover payload expired",
    "withdraw prover payload expires_at_unix"
  );
  const signature = await resolveWithdrawSignature(signer, computeWithdrawNoteHash(selected.note, recipientBytes));
  const payload = {
    version: preparedWithdrawProverPayloadVersion,
    root_hex: merkle.rootHex,
    nullifier_hex: computeNoteNullifierHex(selected.note),
    amount: targetAmount.toString(),
    asset_denom: coin.denom,
    asset_id_hex: canonicalFieldHex(selected.note.assetID),
    recipient: String(recipient),
    recipient_bytes_hex: hexFromBytes(recipientBytes),
    chain_id: String(chainId || "").trim(),
    expires_at_unix: normalizedExpiresAtUnix,
    note_randomness_hex: canonicalFieldHex(selected.note.randomness),
    spend_pubkey_hex: noteSpendPubKeyHex(selected.note),
    view_pubkey_hex: noteViewPubKeyHex(selected.note),
    merkle_path: merkle.path,
    merkle_path_helper: merkle.pathHelper,
    spend_note_hash_signature_hex: hexFromBytes(signature)
  };
  if (!payload.chain_id) {
    throw new Error("chainId is required for withdraw");
  }
  payload.payload_hash = computePreparedWithdrawProverPayloadHash(payload);
  return {
    selectedNote: selected,
    payload
  };
}

export function computePreparedWithdrawPayloadHash({
  proof_hex,
  root_hex,
  nullifier_hex,
  amount,
  recipient,
  chain_id,
  version,
  expires_at_unix
}) {
  return sha256Hex(`${version}\n${proof_hex}\n${root_hex}\n${nullifier_hex}\n${amount}\n${recipient}\n${chain_id}\n${expires_at_unix}`);
}

export function validatePreparedWithdrawProof(proverPayload, proof, nowUnix = Math.floor(Date.now() / 1000)) {
  if (!proof || proof.version !== preparedWithdrawProofVersion) {
    throw new Error(`unsupported withdraw proof version ${JSON.stringify(proof?.version)}`);
  }
  if (proof.payload_hash !== proverPayload.payload_hash) {
    throw new Error("withdraw proof payload hash mismatch");
  }
  assertFutureUnixTimestamp(
    proverPayload.expires_at_unix,
    nowUnix,
    "withdraw prover payload expired",
    "withdraw prover payload expires_at_unix"
  );
  normalizeHex(proof.proof_hex, "withdraw proof");
  return true;
}

export function buildPreparedWithdrawPayloadFromProof(proverPayload, proof, nowUnix) {
  validatePreparedWithdrawProof(proverPayload, proof, nowUnix);
  const amount = `${proverPayload.amount}${proverPayload.asset_denom}`;
  const payload = {
    proof_hex: normalizeHex(proof.proof_hex, "withdraw proof"),
    root_hex: hexFromBytes(decodeCanonicalFieldHex(proverPayload.root_hex, "withdraw root")),
    nullifier_hex: hexFromBytes(decodeCanonicalFieldHex(proverPayload.nullifier_hex, "withdraw nullifier")),
    amount,
    recipient: proverPayload.recipient,
    chain_id: proverPayload.chain_id,
    version: preparedWithdrawPayloadVersion,
    expires_at_unix: Number(proverPayload.expires_at_unix)
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);
  return payload;
}

function assertFutureUnixTimestamp(value, nowUnix, expiredMessage, label) {
  const timestamp = Number(value);
  if (!Number.isSafeInteger(timestamp)) {
    throw new Error(`${label} must be a safe integer unix timestamp`);
  }
  if (timestamp <= nowUnix) {
    throw new Error(expiredMessage);
  }
  return timestamp;
}

export function validatePreparedWithdrawPayload(payload, nowUnix = Math.floor(Date.now() / 1000)) {
  if (payload.version !== preparedWithdrawPayloadVersion) {
    throw new Error(`unsupported withdraw payload version ${JSON.stringify(payload.version)}`);
  }
  assertFutureUnixTimestamp(
    payload.expires_at_unix,
    nowUnix,
    "withdraw payload expired",
    "withdraw payload expires_at_unix"
  );
  if (payload.payload_hash !== computePreparedWithdrawPayloadHash(payload)) {
    throw new Error("withdraw payload hash mismatch");
  }
  return true;
}

export function validateRelayWithdrawPayload(payload, {
  nowUnix,
  expectedChainId,
  expectedRecipient,
  accountPrefix
} = {}) {
  validatePreparedWithdrawPayload(payload, nowUnix);
  if (!String(payload.chain_id || "").trim()) {
    throw new Error("withdraw payload chain_id is required");
  }
  const coinText = String(payload.amount || "").trim();
  if (!/^(0|[1-9][0-9]*)[a-zA-Z][a-zA-Z0-9/:._-]*$/.test(coinText)) {
    throw new Error("withdraw payload amount must be a positive coin string with denom");
  }
  positiveBigInt(parseCoin(coinText).amount, "withdraw payload amount");
  const proofHex = normalizeHex(payload.proof_hex, "withdraw proof");
  if (!proofHex) {
    throw new Error("withdraw proof is required");
  }
  if (normalizeHex(payload.root_hex, "withdraw root").length !== 64) {
    throw new Error("withdraw root must be a 32-byte hex string");
  }
  if (normalizeHex(payload.nullifier_hex, "withdraw nullifier").length !== 64) {
    throw new Error("withdraw nullifier must be a 32-byte hex string");
  }
  const recipientDecoded = fromBech32(payload.recipient);
  if (accountPrefix != null) {
    const expectedPrefix = normalizeBech32Prefix(accountPrefix, "accountPrefix");
    if (recipientDecoded.prefix !== expectedPrefix) {
      throw new Error(`withdraw recipient prefix mismatch: expected ${expectedPrefix}, got ${recipientDecoded.prefix}`);
    }
  }
  if (expectedChainId != null && String(payload.chain_id) !== String(expectedChainId)) {
    throw new Error(`withdraw payload chain_id mismatch: expected ${expectedChainId}, got ${payload.chain_id}`);
  }
  if (expectedRecipient != null && String(payload.recipient) !== String(expectedRecipient)) {
    throw new Error(`withdraw payload recipient mismatch: expected ${expectedRecipient}, got ${payload.recipient}`);
  }
  return true;
}

export function buildWithdrawMsgFromPayload(payload, creator, nowUnix) {
  validatePreparedWithdrawPayload(payload, nowUnix);
  return {
    creator: String(creator || ""),
    proof: hexToBytes(payload.proof_hex, "withdraw proof"),
    root: hexToBytes(payload.root_hex, "withdraw root"),
    nullifier: hexToBytes(payload.nullifier_hex, "withdraw nullifier"),
    amount: payload.amount,
    recipient: payload.recipient,
    chainId: payload.chain_id,
    expiresAtUnix: BigInt(payload.expires_at_unix)
  };
}

export function buildRelayWithdrawMsgFromPayload(payload, relayer, options = {}) {
  validateRelayWithdrawPayload(payload, options);
  const creator = String(relayer || "").trim();
  if (!creator) {
    throw new Error("relayer is required for relay withdraw");
  }
  const relayerDecoded = fromBech32(creator);
  if (options.accountPrefix != null) {
    const expectedPrefix = normalizeBech32Prefix(options.accountPrefix, "accountPrefix");
    if (relayerDecoded.prefix !== expectedPrefix) {
      throw new Error(`relayer prefix mismatch: expected ${expectedPrefix}, got ${relayerDecoded.prefix}`);
    }
  }
  return buildWithdrawMsgFromPayload(payload, creator, options.nowUnix);
}

export async function buildRelayWithdrawPayload({ proverAdapter, ...input } = {}) {
  if (!proverAdapter?.proveWithdraw) {
    throw new Error("proverAdapter.proveWithdraw is required");
  }
  const { selectedNote, payload: proverPayload } = await buildPreparedWithdrawProverPayload(input);
  const response = await proverAdapter.proveWithdraw({
    version: "v1",
    payload: proverPayload
  });
  const proof = response?.proof || response;
  const payload = buildPreparedWithdrawPayloadFromProof(proverPayload, proof);
  return {
    selectedNote,
    proverPayload,
    proof,
    payload
  };
}

export async function buildWithdrawMessage({ proverAdapter, creator, ...input } = {}) {
  const { selectedNote, proverPayload, proof, payload } = await buildRelayWithdrawPayload({
    proverAdapter,
    ...input
  });
  return {
    selectedNote,
    proverPayload,
    proof,
    payload,
    message: buildWithdrawMsgFromPayload(payload, creator)
  };
}

export function createRestMerklePathProvider({ rest, fetchImpl = fetch, timeoutMs = 30000 } = {}) {
  const base = String(rest || "").replace(/\/$/, "");
  if (!base) {
    throw new Error("rest endpoint is required");
  }
  return {
    async lookupMerklePath(commitmentHex) {
      const resolvedTimeoutMs = Number(timeoutMs);
      if (!Number.isFinite(resolvedTimeoutMs) || resolvedTimeoutMs <= 0) {
        throw new Error("merkle path timeoutMs must be positive");
      }
      const url = `${base}/clairveil/privacy/v1/merkle_path/${commitmentHex}`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), resolvedTimeoutMs);
      try {
        const response = await fetchImpl(url, {
          headers: { accept: "application/json" },
          signal: controller.signal
        });
        if (!response.ok) {
          throw new Error(`merkle path query failed with status ${response.status}: ${await response.text()}`);
        }
        return response.json();
      } catch (error) {
        if (error?.name === "AbortError") {
          throw new Error(`merkle path query timed out after ${resolvedTimeoutMs}ms: ${url}`);
        }
        throw error;
      } finally {
        clearTimeout(timeout);
      }
    }
  };
}
