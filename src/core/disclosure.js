import {
  bytesToBigIntBE,
  CURVE_ORDER,
  decodeCanonicalFieldHex,
  encodeShieldedAddress,
  hexFromBytes,
  normalizeHex,
  unpackPoint
} from "./crypto.js";
import { bytesFromHex } from "./browser-crypto.js";
import {
  computeBatchFullDisclosureDigestV1,
  computeBatchUserDisclosureDigestV1,
  computeTransferFullDisclosureDigestV2,
  computeTransferUserDisclosureDigestV2,
  computeAssetIdV1,
  decryptDisclosureV1,
  encryptedEnvelopeKindV1,
  fieldHexV1,
  unwrapEncryptedEnvelopeV1,
  unmarshalDisclosurePlaintextV1
} from "../privacy/protocol-v1.js";
import { canonicalAssetDenomV1 } from "../privacy/asset-registry.js";
import { isValidatedPrivacyScanOutputV2 } from "../privacy/scan.js";

export const planeUser = "user";
export const planeAudit = "audit";
export const planeSelfView = "self-view";
export const userDisclosureModeNone = "USER_DISCLOSURE_MODE_NONE";
export const userDisclosureModePublic = "USER_DISCLOSURE_MODE_PUBLIC";
export const userDisclosureModeRecipientEncrypted = "USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED";

export const transferPrivacyPolicyAllPrivate = 0;
export const transferPrivacyPolicyDiscloseAmount = 1;
export const transferPrivacyPolicyDiscloseTo = 2;
export const transferPrivacyPolicyDiscloseFrom = 4;

const supportedPolicies = new Set([0, 1, 2, 3, 4, 5, 6, 7]);
const batchTransferScanEventType = "batch_transfer";
const batchUserDisclosureModes = Object.freeze({
  none: "USER_DISCLOSURE_MODE_NONE",
  public: "USER_DISCLOSURE_MODE_PUBLIC",
  recipientEncrypted: "USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED"
});

export function privacyPolicyLabel(policy) {
  switch (Number(policy || 0)) {
    case 0:
      return "all-private";
    case 1:
      return "amount";
    case 2:
      return "to";
    case 3:
      return "amount-to";
    case 4:
      return "from";
    case 5:
      return "amount-from";
    case 6:
      return "from-to";
    case 7:
      return "amount-from-to";
    default:
      return `unknown-${policy}`;
  }
}

function fixedDisclosurePlaneName(value, expectedPlane) {
  if (expectedPlane === planeUser) {
    if (value.plane !== 1) throw new Error(`DisclosurePlaintextV1 plane ${value.plane} is not a user disclosure`);
    return planeUser;
  }
  if (expectedPlane !== planeAudit && expectedPlane !== planeSelfView) {
    throw new Error(`unsupported expected disclosure plane ${JSON.stringify(expectedPlane)}`);
  }
  if (value.plane !== 2) throw new Error(`DisclosurePlaintextV1 plane ${value.plane} is not a full disclosure`);
  return expectedPlane;
}

function verifiedAssetDenom(value, assetDenom) {
  if (!assetDenom) return "";
  const denom = canonicalAssetDenomV1(assetDenom);
  if (computeAssetIdV1(denom) !== value.assetID) {
    throw new Error(`disclosure asset denom ${JSON.stringify(denom)} does not match the committed asset ID`);
  }
  return denom;
}

function fixedDisclosureDigest(value) {
  const common = {
    outputIndex: value.outputIndex,
    commitment: value.commitment,
    amount: value.amount,
    assetID: value.assetID,
    fromSpendPubKeyX: value.senderSpendKeyX,
    fromSpendPubKeyY: value.senderSpendKeyY,
    fromViewPubKeyX: value.senderViewKeyX,
    fromViewPubKeyY: value.senderViewKeyY,
    toSpendPubKeyX: value.recipientSpendKeyX,
    toSpendPubKeyY: value.recipientSpendKeyY,
    toViewPubKeyX: value.recipientViewKeyX,
    toViewPubKeyY: value.recipientViewKeyY,
    disclosureBlinding: value.disclosureBlinding
  };
  return value.plane === 1
    ? computeTransferUserDisclosureDigestV2({ ...common, policy: value.policy })
    : computeTransferFullDisclosureDigestV2(common);
}

function optionalFixedAddress(value, prefix) {
  const fields = [value.senderSpendKeyX, value.senderSpendKeyY, value.senderViewKeyX, value.senderViewKeyY];
  if (fields.every(entry => entry === 0n)) return "";
  return encodeShieldedAddress(
    { x: value.senderSpendKeyX, y: value.senderSpendKeyY },
    { x: value.senderViewKeyX, y: value.senderViewKeyY },
    { shieldedPrefix: prefix }
  );
}

function optionalFixedRecipientAddress(value, prefix) {
  const fields = [value.recipientSpendKeyX, value.recipientSpendKeyY, value.recipientViewKeyX, value.recipientViewKeyY];
  if (fields.every(entry => entry === 0n)) return "";
  return encodeShieldedAddress(
    { x: value.recipientSpendKeyX, y: value.recipientSpendKeyY },
    { x: value.recipientViewKeyX, y: value.recipientViewKeyY },
    { shieldedPrefix: prefix }
  );
}

function fixedDisclosureReport(value, onChainDigestHex, txHash, { expectedPlane = planeUser, source, delivery, shieldedPrefix, assetDenom = "" } = {}) {
  const plane = fixedDisclosurePlaneName(value, expectedPlane);
  const verifiedDenom = verifiedAssetDenom(value, assetDenom);
  const expectedDigestHex = fieldHexV1(fixedDisclosureDigest(value));
  const onChain = String(onChainDigestHex || "").trim().toLowerCase();
  if (onChain && onChain !== expectedDigestHex) throw new Error(`on-chain disclosure digest mismatch: event has ${onChainDigestHex}, expected ${expectedDigestHex}`);
  const full = value.plane === 2;
  const policy = full ? 7 : value.policy;
  const payload = {
    version: "privacy-fixed-v1",
    plane,
    policy,
    output_index: value.outputIndex,
    commitment_hex: fieldHexV1(value.commitment),
    disclosure_digest_hex: expectedDigestHex,
    disclosure_blinding_hex: fieldHexV1(value.disclosureBlinding),
    asset_id_hex: fieldHexV1(value.assetID),
    ...(full || (policy & transferPrivacyPolicyDiscloseAmount) !== 0 ? { amount: value.amount.toString(), asset_denom: verifiedDenom } : {}),
    ...(full || (policy & transferPrivacyPolicyDiscloseFrom) !== 0 ? { from_shielded_address: optionalFixedAddress(value, shieldedPrefix) } : {}),
    ...(full || (policy & transferPrivacyPolicyDiscloseTo) !== 0 ? { to_shielded_address: optionalFixedRecipientAddress(value, shieldedPrefix) } : {})
  };
  const amount = payload.amount || "";
  const from = payload.from_shielded_address || "";
  const to = payload.to_shielded_address || "";
  return {
    plane,
    policy: plane === planeAudit ? "audit-full" : plane === planeSelfView ? "amount-from-to" : privacyPolicyLabel(policy),
    output_index: value.outputIndex,
    commitment_hex: payload.commitment_hex,
    digest_hex: expectedDigestHex,
    verified: true,
    amount,
    asset_denom: payload.asset_denom || "",
    from,
    to,
    source,
    tx_hash: txHash ? String(txHash).toUpperCase() : "",
    verification: {
      verified: true,
      fixed_encoding: true,
      local_disclosure_digest_match: true,
      on_chain_disclosure_digest_used: Boolean(onChain),
      on_chain_disclosure_digest_match: onChain ? true : undefined
    },
    summary: {
      plane,
      delivery,
      policy: plane === planeAudit ? "audit-full" : plane === planeSelfView ? "amount-from-to" : privacyPolicyLabel(policy),
      disclosed_fields: disclosedFields(payload),
      amount,
      asset_denom: payload.asset_denom || "",
      from_shielded_address: from,
      to_shielded_address: to
    },
    payload
  };
}

export function disclosedFields(payload) {
  const fields = [];
  if (payload?.amount) fields.push("amount");
  if (payload?.from_shielded_address) fields.push("from_shielded_address");
  if (payload?.to_shielded_address) fields.push("to_shielded_address");
  return fields;
}

export function disclosureAmountAndAsset(payload) {
  const amountRaw = String(payload?.amount || "").trim();
  const assetIdRaw = String(payload?.asset_id_hex || "").trim();
  const assetDenom = String(payload?.asset_denom || "").trim();
  if (!amountRaw && !assetIdRaw && !assetDenom) {
    return { amount: null, assetId: null, assetDenom: "" };
  }
  if (!amountRaw || !assetIdRaw || !assetDenom) {
    throw new Error("amount disclosure payload must include amount, asset_id_hex, and asset_denom together");
  }
  if (!/^(0|[1-9][0-9]*)$/.test(amountRaw)) {
    throw new Error(`invalid disclosure amount ${JSON.stringify(amountRaw)}`);
  }
  const amount = BigInt(amountRaw);
  const assetId = bytesToBigIntBE(decodeCanonicalFieldHex(assetIdRaw, "asset id"));
  const expectedAssetId = computeAssetIdV1(assetDenom);
  if (assetId !== expectedAssetId) {
    throw new Error(`asset denom ${JSON.stringify(assetDenom)} does not match asset_id_hex ${assetIdRaw}`);
  }
  return { amount, assetId, assetDenom };
}

function equalDisclosureBytes(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function typedScanBytes(value, label) {
  if (value instanceof Uint8Array) return Uint8Array.from(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
  if (value instanceof ArrayBuffer) return new Uint8Array(value).slice();
  throw new Error(`${label} must be bytes from PrivacyScanOutputV2`);
}

function typedScanAliasedValue(output, camel, snake, label) {
  const camelValue = output?.[camel];
  const snakeValue = output?.[snake];
  if (camelValue != null && snakeValue != null) {
    const camelBytes = camelValue instanceof Uint8Array || ArrayBuffer.isView(camelValue) || camelValue instanceof ArrayBuffer;
    const snakeBytes = snakeValue instanceof Uint8Array || ArrayBuffer.isView(snakeValue) || snakeValue instanceof ArrayBuffer;
    if (camelBytes || snakeBytes) {
      if (!camelBytes || !snakeBytes || !equalDisclosureBytes(typedScanBytes(camelValue, label), typedScanBytes(snakeValue, label))) {
        throw new Error(`${label} aliases conflict`);
      }
    } else if (String(camelValue) !== String(snakeValue)) {
      throw new Error(`${label} aliases conflict`);
    }
  }
  return camelValue ?? snakeValue;
}

function typedScanOptionalBytes(output, camel, snake, label) {
  const value = typedScanAliasedValue(output, camel, snake, label);
  return value == null ? new Uint8Array() : typedScanBytes(value, label);
}

function typedScanRequiredBytes(output, camel, snake, label, expectedLength) {
  const value = typedScanAliasedValue(output, camel, snake, label);
  if (value == null) throw new Error(`${label} is required`);
  const bytes = typedScanBytes(value, label);
  if (expectedLength != null && bytes.length !== expectedLength) throw new Error(`${label} must be exactly ${expectedLength} bytes`);
  return bytes;
}

function typedScanField(bytes, label, { nonZero = false } = {}) {
  if (bytes.length !== 32) throw new Error(`${label} must be exactly 32 bytes`);
  const value = bytesToBigIntBE(bytes);
  // fieldHexV1 both checks canonicality and supplies the exact wire form used
  // by the batch disclosure digest contract.
  fieldHexV1(value);
  if (nonZero && value === 0n) throw new Error(`${label} must be non-zero`);
  return value;
}

function typedScanOutputIndex(output) {
  const value = typedScanAliasedValue(output, "outputIndex", "output_index", "privacy scan batch output index");
  const index = Number(value);
  if (!Number.isSafeInteger(index) || index < 0 || index > 31) {
    throw new Error("privacy scan batch output index must be in 0..31");
  }
  return index;
}

function typedScanPolicy(output) {
  const value = typedScanAliasedValue(output, "userPrivacyPolicy", "user_privacy_policy", "privacy scan batch user privacy policy");
  const policy = Number(value);
  if (!Number.isSafeInteger(policy) || !supportedPolicies.has(policy)) {
    throw new Error("privacy scan batch user privacy policy is invalid");
  }
  return policy;
}

function typedScanUserDisclosureMode(output) {
  const value = typedScanAliasedValue(output, "userDisclosureMode", "user_disclosure_mode", "privacy scan batch user disclosure mode");
  if (value === 0 || value === "0") return batchUserDisclosureModes.none;
  if (value === 1 || value === "1") return batchUserDisclosureModes.public;
  if (value === 2 || value === "2") return batchUserDisclosureModes.recipientEncrypted;
  const mode = String(value || "").trim();
  if (!Object.values(batchUserDisclosureModes).includes(mode)) {
    throw new Error("privacy scan batch user disclosure mode is invalid");
  }
  return mode;
}

function typedScanTxHash(output, txHash) {
  if (txHash != null && String(txHash).trim()) return String(txHash).trim();
  const value = typedScanAliasedValue(output, "txHash", "tx_hash", "privacy scan batch transaction hash");
  if (value == null) return "";
  return hexFromBytes(typedScanBytes(value, "privacy scan batch transaction hash"));
}

/**
 * Strictly normalize one validated Batch V1 typed-scan disclosure record.
 * The private validator brand closes the raw protobuf-shaped input boundary:
 * callers must validate the complete page (including its summary) first.
 */
function normalizedBatchScanDisclosureOutput(output) {
  if (!isValidatedPrivacyScanOutputV2(output)) {
    throw new Error("batch disclosure output must come from validatePrivacyScanPageV2");
  }
  const eventType = String(typedScanAliasedValue(output, "eventType", "event_type", "privacy scan batch event type") || "").trim();
  if (eventType !== batchTransferScanEventType) {
    throw new Error("selected PrivacyScanOutputV2 is not a batch transfer output");
  }
  const outputIndex = typedScanOutputIndex(output);
  const commitmentBytes = typedScanRequiredBytes(output, "commitment", "commitment", "privacy scan batch commitment", 32);
  const commitment = typedScanField(commitmentBytes, "privacy scan batch commitment", { nonZero: true });
  const policy = typedScanPolicy(output);
  const mode = typedScanUserDisclosureMode(output);
  const userDigestBytes = typedScanOptionalBytes(output, "userDisclosureDigest", "user_disclosure_digest", "privacy scan batch user disclosure digest");
  const userTarget = typedScanOptionalBytes(output, "userDisclosureTargetPubkey", "user_disclosure_target_pubkey", "privacy scan batch user disclosure target");
  const userPayload = typedScanOptionalBytes(output, "userDisclosurePayload", "user_disclosure_payload", "privacy scan batch user disclosure payload");
  const fullDigestBytes = typedScanRequiredBytes(output, "fullDisclosureDigest", "full_disclosure_digest", "privacy scan batch full disclosure digest", 32);
  const fullDigest = typedScanField(fullDigestBytes, "privacy scan batch full disclosure digest", { nonZero: true });
  const auditPayload = typedScanRequiredBytes(output, "auditDisclosurePayload", "audit_disclosure_payload", "privacy scan batch audit disclosure payload");
  const selfViewPayload = typedScanOptionalBytes(output, "selfViewDisclosurePayload", "self_view_disclosure_payload", "privacy scan batch self-view disclosure payload");

  try {
    unwrapBatchDisclosureEnvelope(auditPayload, encryptedEnvelopeKindV1.auditDisclosure);
    if (selfViewPayload.length) unwrapBatchDisclosureEnvelope(selfViewPayload, encryptedEnvelopeKindV1.selfViewDisclosure);
  } catch (error) {
    throw new Error(`privacy scan batch disclosure envelope is invalid: ${error.message}`);
  }

  if (policy === 0) {
    if (mode !== batchUserDisclosureModes.none || userDigestBytes.length || userTarget.length || userPayload.length) {
      throw new Error("privacy scan batch all-private user disclosure framing is invalid");
    }
  } else if (mode === batchUserDisclosureModes.public) {
    typedScanField(userDigestBytes, "privacy scan batch user disclosure digest", { nonZero: true });
    if (userTarget.length || userPayload.length !== 392) {
      throw new Error("privacy scan batch public user disclosure framing is invalid");
    }
  } else if (mode === batchUserDisclosureModes.recipientEncrypted) {
    typedScanField(userDigestBytes, "privacy scan batch user disclosure digest", { nonZero: true });
    if (userTarget.length !== 32) throw new Error("privacy scan batch encrypted user disclosure target is invalid");
    try {
      // This establishes canonical, non-identity point encoding before a
      // caller's target key is compared or ECIES is attempted.
      unpackBatchDisclosureTarget(userTarget);
      unwrapBatchDisclosureEnvelope(userPayload, encryptedEnvelopeKindV1.userDisclosure);
    } catch (error) {
      throw new Error(`privacy scan batch encrypted user disclosure is invalid: ${error.message}`);
    }
  } else {
    throw new Error("privacy scan batch user disclosure mode is invalid for the selected policy");
  }
  return {
    outputIndex,
    commitment,
    policy,
    mode,
    userDigestBytes,
    userTarget,
    userPayload,
    fullDigest,
    auditPayload,
    selfViewPayload
  };
}

// Keep protocol-v1 imports narrow above; these wrappers make the validation
// calls readable and keep all typed-scan envelope handling in this module.
function unwrapBatchDisclosureEnvelope(payload, kind) {
  return unwrapEncryptedEnvelopeV1(payload, kind);
}

function unpackBatchDisclosureTarget(value) {
  const point = unpackPoint(value);
  if (point.x === 0n && point.y === 1n) {
    throw new Error("identity disclosure target is not allowed");
  }
  return point;
}

function batchDisclosurePlaintextPayload(value, digest, { plane, shieldedPrefix, assetDenom = "" }) {
  const full = plane === planeAudit || plane === planeSelfView;
  const policy = full ? 7 : value.policy;
  const verifiedDenom = verifiedAssetDenom(value, assetDenom);
  const payload = {
    version: "privacy-fixed-v1",
    plane,
    policy,
    output_index: value.outputIndex,
    commitment_hex: fieldHexV1(value.commitment),
    disclosure_digest_hex: fieldHexV1(digest),
    disclosure_blinding_hex: fieldHexV1(value.disclosureBlinding),
    asset_id_hex: fieldHexV1(value.assetID),
    ...(full || (policy & transferPrivacyPolicyDiscloseAmount) !== 0 ? { amount: value.amount.toString(), asset_denom: verifiedDenom } : {}),
    ...(full || (policy & transferPrivacyPolicyDiscloseFrom) !== 0 ? { from_shielded_address: optionalFixedAddress(value, shieldedPrefix) } : {}),
    ...(full || (policy & transferPrivacyPolicyDiscloseTo) !== 0 ? { to_shielded_address: optionalFixedRecipientAddress(value, shieldedPrefix) } : {})
  };
  return payload;
}

function batchDisclosureReport(value, digest, txHash, { plane, source, delivery, shieldedPrefix, assetDenom = "" }) {
  const payload = batchDisclosurePlaintextPayload(value, digest, { plane, shieldedPrefix, assetDenom });
  const amount = payload.amount || "";
  const from = payload.from_shielded_address || "";
  const to = payload.to_shielded_address || "";
  const policy = plane === planeAudit ? "audit-full" : plane === planeSelfView ? "amount-from-to" : privacyPolicyLabel(payload.policy);
  return {
    plane,
    policy,
    output_index: value.outputIndex,
    commitment_hex: payload.commitment_hex,
    digest_hex: payload.disclosure_digest_hex,
    verified: true,
    amount,
    asset_denom: payload.asset_denom || "",
    from,
    to,
    source,
    tx_hash: txHash ? String(txHash).toUpperCase() : "",
    verification: {
      verified: true,
      fixed_encoding: true,
      batch_typed_scan_output: true,
      output_index_match: true,
      output_commitment_match: true,
      output_policy_match: true,
      plaintext_blinding_bound: true,
      local_disclosure_digest_match: true,
      typed_scan_disclosure_digest_match: true
    },
    summary: {
      plane,
      delivery,
      policy,
      disclosed_fields: disclosedFields(payload),
      amount,
      asset_denom: payload.asset_denom || "",
      from_shielded_address: from,
      to_shielded_address: to
    },
    payload
  };
}

function batchPlaintextMatchesOutput(value, record, expectedPlane) {
  if (value.plane !== expectedPlane) {
    throw new Error(`batch disclosure plaintext has unexpected plane ${value.plane}`);
  }
  if (value.outputIndex !== record.outputIndex) {
    throw new Error(`batch disclosure output index mismatch: plaintext has ${value.outputIndex}, typed scan has ${record.outputIndex}`);
  }
  if (value.commitment !== record.commitment) {
    throw new Error("batch disclosure commitment mismatch between plaintext and typed scan output");
  }
  if (expectedPlane === 1) {
    if (value.policy !== record.policy || value.disclosedFieldBitmap !== record.policy) {
      throw new Error("batch user disclosure policy mismatch between plaintext and typed scan output");
    }
  }
}

function computeBatchUserPlaintextDigest(value) {
  return computeBatchUserDisclosureDigestV1({
    outputIndex: value.outputIndex,
    commitment: value.commitment,
    policy: value.policy,
    disclosedFieldBitmap: value.disclosedFieldBitmap,
    selectedAmount: value.amount,
    selectedFromSpendKeyX: value.senderSpendKeyX,
    selectedFromSpendKeyY: value.senderSpendKeyY,
    selectedFromViewKeyX: value.senderViewKeyX,
    selectedFromViewKeyY: value.senderViewKeyY,
    selectedToSpendKeyX: value.recipientSpendKeyX,
    selectedToSpendKeyY: value.recipientSpendKeyY,
    selectedToViewKeyX: value.recipientViewKeyX,
    selectedToViewKeyY: value.recipientViewKeyY,
    assetID: value.assetID,
    userDisclosureBlinding: value.disclosureBlinding
  });
}

function computeBatchFullPlaintextDigest(value) {
  return computeBatchFullDisclosureDigestV1({
    outputIndex: value.outputIndex,
    commitment: value.commitment,
    amount: value.amount,
    assetID: value.assetID,
    senderSpendKeyX: value.senderSpendKeyX,
    senderSpendKeyY: value.senderSpendKeyY,
    senderViewKeyX: value.senderViewKeyX,
    senderViewKeyY: value.senderViewKeyY,
    recipientSpendKeyX: value.recipientSpendKeyX,
    recipientSpendKeyY: value.recipientSpendKeyY,
    recipientViewKeyX: value.recipientViewKeyX,
    recipientViewKeyY: value.recipientViewKeyY,
    fullDisclosureBlinding: value.disclosureBlinding
  });
}

function assertBatchDigestMatchesTypedOutput(digest, outputDigest, label) {
  const actual = fieldHexV1(digest);
  const expected = fieldHexV1(outputDigest);
  if (actual !== expected) {
    throw new Error(`${label} mismatch: typed scan has ${expected}, decoded plaintext resolves to ${actual}`);
  }
  return digest;
}

/**
 * Decode and verify one public or recipient-encrypted user disclosure carried
 * by a Batch V1 PrivacyScanOutputV2 record. The proof-bound digest is
 * recomputed from the plaintext, including its per-output blinding.
 */
export function decodeBatchUserDisclosureFromScanOutput(output, {
  disclosureScalar,
  disclosurePubKeyHex,
  txHash,
  shieldedPrefix,
  assetDenom = ""
} = {}) {
  const record = normalizedBatchScanDisclosureOutput(output);
  if (record.policy === 0) throw new Error("selected batch output has no user disclosure");
  let value;
  if (record.mode === batchUserDisclosureModes.public) {
    value = unmarshalDisclosurePlaintextV1(record.userPayload);
  } else {
    const target = String(disclosurePubKeyHex || "").trim().toLowerCase();
    if (!target || target !== hexFromBytes(record.userTarget).toLowerCase()) {
      throw new Error("This batch output is not targeted to the provided disclosure public key");
    }
    if (disclosureScalar == null) throw new Error("recipient-encrypted batch disclosure requires a disclosure scalar");
    value = decryptDisclosureV1(record.userPayload, disclosureScalar, encryptedEnvelopeKindV1.userDisclosure);
  }
  batchPlaintextMatchesOutput(value, record, 1);
  const digest = assertBatchDigestMatchesTypedOutput(
    computeBatchUserPlaintextDigest(value),
    typedScanField(record.userDigestBytes, "privacy scan batch user disclosure digest", { nonZero: true }),
    "batch user disclosure digest"
  );
  return batchDisclosureReport(value, digest, typedScanTxHash(output, txHash), {
    plane: planeUser,
    source: record.mode === batchUserDisclosureModes.public ? "public" : "recipient_encrypted",
    delivery: record.mode === batchUserDisclosureModes.public ? "public" : "recipient-encrypted",
    shieldedPrefix,
    assetDenom
  });
}

function decodeBatchFullDisclosureFromScanOutput(output, {
  disclosureScalar,
  txHash,
  shieldedPrefix,
  assetDenom = "",
  plane,
  source,
  delivery
}) {
  const record = normalizedBatchScanDisclosureOutput(output);
  if (disclosureScalar == null) throw new Error(`${plane} batch disclosure requires a disclosure scalar`);
  const payload = plane === planeAudit ? record.auditPayload : record.selfViewPayload;
  if (!payload.length) throw new Error(`selected batch output has no ${plane} disclosure`);
  const kind = plane === planeAudit ? encryptedEnvelopeKindV1.auditDisclosure : encryptedEnvelopeKindV1.selfViewDisclosure;
  const value = decryptDisclosureV1(payload, disclosureScalar, kind);
  batchPlaintextMatchesOutput(value, record, 2);
  const digest = assertBatchDigestMatchesTypedOutput(
    computeBatchFullPlaintextDigest(value),
    record.fullDigest,
    `batch ${plane} disclosure digest`
  );
  return batchDisclosureReport(value, digest, typedScanTxHash(output, txHash), {
    plane,
    source,
    delivery,
    shieldedPrefix,
    assetDenom
  });
}

/** Decode and verify the mandatory auditor full-disclosure envelope for one Batch V1 typed-scan output. */
export function decodeBatchAuditDisclosureFromScanOutput(output, options = {}) {
  return decodeBatchFullDisclosureFromScanOutput(output, {
    ...options,
    plane: planeAudit,
    source: "audit_encrypted",
    delivery: "audit-encrypted"
  });
}

/** Decode and verify the optional sender self-view full-disclosure envelope for one Batch V1 typed-scan output. */
export function decodeBatchSelfViewDisclosureFromScanOutput(output, options = {}) {
  return decodeBatchFullDisclosureFromScanOutput(output, {
    ...options,
    plane: planeSelfView,
    source: "self_view_encrypted",
    delivery: "self-view-encrypted"
  });
}

export function eventAttribute(event, key) {
  return (event?.attributes || []).find(attribute => attribute.key === key)?.value || "";
}

export function disclosureTargetPubKeyFromEvent(event, plane = planeUser) {
  if (plane === planeAudit) {
    return eventAttribute(event, "audit_disclosure_target_pubkey");
  }
  return eventAttribute(event, "user_disclosure_target_pubkey");
}

export function decodeUserDisclosureFromEvent(event, disclosureScalar, disclosurePubKeyHex, txHash = event?.tx_hash_hex || "", options = {}) {
  if (event?.event_type !== "shielded_transfer") {
    throw new Error("selected event is not a shielded transfer");
  }
  const mode = eventAttribute(event, "user_disclosure_mode");
  const targetPubKey = eventAttribute(event, "user_disclosure_target_pubkey");
  const payloadHex = eventAttribute(event, "user_disclosure_payload");
  const digestHex = eventAttribute(event, "user_disclosure_digest");
  if (!payloadHex) {
    throw new Error("selected transfer has no user disclosure");
  }
  if (mode === userDisclosureModePublic) {
    return publicPayloadReport(payloadHex, digestHex, txHash, options);
  }
  if (mode !== userDisclosureModeRecipientEncrypted) {
    throw new Error(`selected transfer uses unsupported user disclosure mode ${JSON.stringify(mode || "none")}`);
  }
  if (!targetPubKey || targetPubKey.toLowerCase() !== String(disclosurePubKeyHex || "").toLowerCase()) {
    throw new Error("This transfer is not targeted to the provided disclosure public key");
  }
  return fixedDisclosureReport(
    decryptDisclosureV1(bytesFromHex(payloadHex, "user disclosure payload"), disclosureScalar, encryptedEnvelopeKindV1.userDisclosure),
    digestHex,
    txHash,
    { ...options, expectedPlane: planeUser, source: "recipient_encrypted", delivery: "recipient-encrypted" }
  );
}

export function decodeSelfViewDisclosureFromEvent(event, disclosureScalar, txHash = event?.tx_hash_hex || "", options = {}) {
  if (event?.event_type !== "shielded_transfer") {
    throw new Error("selected event is not a shielded transfer");
  }
  const payloadHex = eventAttribute(event, "self_view_disclosure_payload");
  const digestHex = eventAttribute(event, "self_view_disclosure_digest");
  if (!payloadHex) {
    throw new Error("selected transfer has no self-view disclosure");
  }
  return fixedDisclosureReport(
    decryptDisclosureV1(bytesFromHex(payloadHex, "self-view disclosure payload"), disclosureScalar, encryptedEnvelopeKindV1.selfViewDisclosure),
    digestHex,
    txHash,
    { ...options, expectedPlane: planeSelfView, source: "self_view_encrypted", delivery: "self-view-encrypted" }
  );
}

export function decodeAuditDisclosureFromEvent(event, disclosureScalar, txHash = event?.tx_hash_hex || "", options = {}) {
  if (event?.event_type !== "shielded_transfer") {
    throw new Error("selected event is not a shielded transfer");
  }
  const payloadHex = eventAttribute(event, "audit_disclosure_payload");
  const digestHex = eventAttribute(event, "audit_disclosure_digest");
  if (!payloadHex) {
    throw new Error("selected transfer has no audit disclosure");
  }
  return fixedDisclosureReport(
    decryptDisclosureV1(bytesFromHex(payloadHex, "audit disclosure payload"), disclosureScalar, encryptedEnvelopeKindV1.auditDisclosure),
    digestHex,
    txHash,
    { ...options, expectedPlane: planeAudit, source: "audit_encrypted", delivery: "audit-encrypted" }
  );
}

export function disclosureScalarFromHex(value) {
  const scalar = bytesToBigIntBE(bytesFromHex(normalizeHex(value, "disclosure private key scalar"), "disclosure private key scalar"));
  if (scalar <= 0n) {
    throw new Error("disclosure private key must be greater than zero");
  }
  if (scalar >= CURVE_ORDER) {
    throw new Error("disclosure private key must be smaller than the BN254 Edwards curve order");
  }
  return scalar;
}

export function publicPayloadReport(payloadHex, onChainDigestHex = "", txHash = "", options = {}) {
  return fixedDisclosureReport(
    unmarshalDisclosurePlaintextV1(bytesFromHex(payloadHex, "public disclosure payload")),
    onChainDigestHex,
    txHash,
    { ...options, expectedPlane: planeUser, source: "public", delivery: "public" }
  );
}
