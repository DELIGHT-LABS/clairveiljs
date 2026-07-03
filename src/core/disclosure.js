import {
  asymDecryptHex,
  bytesToBigIntBE,
  canonicalFieldHex,
  CURVE_ORDER,
  decodeCanonicalFieldHex,
  decodeShieldedAddress,
  hashStringToField,
  hexFromBytes,
  mimcHash,
  normalizeHex
} from "./crypto.js";
import {
  bytesFromHex,
  utf8Bytes,
  utf8String
} from "./browser-crypto.js";

export const payloadVersion = "v4";
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
export const transferAuditDisclosureDomain = 255;
export const transferSelfViewDisclosureDomain = 254;
export const transferDisclosureRecipientOutputIndex = 0;

const supportedPolicies = new Set([0, 1, 2, 3, 4, 5, 6, 7]);

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

export function decodePublicPayloadHex(payloadHex) {
  const bytes = bytesFromHex(normalizeHex(payloadHex, "disclosure payload"), "disclosure payload");
  try {
    return JSON.parse(utf8String(bytes));
  } catch (error) {
    throw new Error(`failed to decode disclosure payload JSON: ${error.message}`);
  }
}

export function decryptPayloadHex(ciphertextHex, disclosureScalar) {
  const plaintext = asymDecryptHex(ciphertextHex, disclosureScalar);
  try {
    return JSON.parse(utf8String(plaintext));
  } catch (error) {
    throw new Error(`failed to decode disclosure payload JSON: ${error.message}`);
  }
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
  const expectedAssetId = hashStringToField(assetDenom);
  if (assetId !== expectedAssetId) {
    throw new Error(`asset denom ${JSON.stringify(assetDenom)} does not match asset_id_hex ${assetIdRaw}`);
  }
  return { amount, assetId, assetDenom };
}

function decodeOptionalShieldedAddress(address, label, options = {}) {
  const value = String(address || "").trim();
  if (!value) return null;
  try {
    return decodeShieldedAddress(value, options);
  } catch (error) {
    throw new Error(`invalid ${label} shielded address: ${error.message}`);
  }
}

function bundleCoordinate(bundle, key, coordinate) {
  if (!bundle) return null;
  return bundle[key][coordinate];
}

function requireValue(value, message) {
  if (value == null) {
    throw new Error(message);
  }
  return value;
}

function selectedValue(value, enabled) {
  return enabled ? requireValue(value, "required disclosure field is missing") : 0n;
}

export function computeTransferDisclosureDigestHex({
  policy,
  outputIndex = transferDisclosureRecipientOutputIndex,
  commitment,
  amount,
  assetId,
  fromSpendPubKeyX,
  fromSpendPubKeyY,
  fromViewPubKeyX,
  fromViewPubKeyY,
  toSpendPubKeyX,
  toSpendPubKeyY,
  toViewPubKeyX,
  toViewPubKeyY
}) {
  const numericPolicy = Number(policy || 0);
  if (!supportedPolicies.has(numericPolicy)) {
    throw new Error(`unsupported transfer privacy policy ${numericPolicy}`);
  }
  const commitmentBytes = commitment instanceof Uint8Array ? commitment : decodeCanonicalFieldHex(commitment, "disclosure commitment");
  const commitmentField = bytesToBigIntBE(commitmentBytes);
  if (numericPolicy === transferPrivacyPolicyAllPrivate) {
    return canonicalFieldHex(0n);
  }

  const discloseAmount = (numericPolicy & transferPrivacyPolicyDiscloseAmount) !== 0;
  const discloseFrom = (numericPolicy & transferPrivacyPolicyDiscloseFrom) !== 0;
  const discloseTo = (numericPolicy & transferPrivacyPolicyDiscloseTo) !== 0;

  if (discloseAmount && (amount == null || assetId == null)) {
    throw new Error("amount and asset id are required for amount disclosure");
  }
  if (discloseFrom && [fromSpendPubKeyX, fromSpendPubKeyY, fromViewPubKeyX, fromViewPubKeyY].some(value => value == null)) {
    throw new Error("full sender shielded address is required for from disclosure");
  }
  if (discloseTo && [toSpendPubKeyX, toSpendPubKeyY, toViewPubKeyX, toViewPubKeyY].some(value => value == null)) {
    throw new Error("full recipient shielded address is required for to disclosure");
  }

  return canonicalFieldHex(mimcHash(
    BigInt(numericPolicy),
    BigInt(outputIndex),
    commitmentField,
    selectedValue(amount, discloseAmount),
    selectedValue(assetId, discloseAmount),
    selectedValue(fromSpendPubKeyX, discloseFrom),
    selectedValue(fromSpendPubKeyY, discloseFrom),
    selectedValue(fromViewPubKeyX, discloseFrom),
    selectedValue(fromViewPubKeyY, discloseFrom),
    selectedValue(toSpendPubKeyX, discloseTo),
    selectedValue(toSpendPubKeyY, discloseTo),
    selectedValue(toViewPubKeyX, discloseTo),
    selectedValue(toViewPubKeyY, discloseTo)
  ));
}

export function computeAuditTransferDisclosureDigestHex({
  outputIndex = transferDisclosureRecipientOutputIndex,
  commitment,
  amount,
  assetId,
  fromSpendPubKeyX,
  fromSpendPubKeyY,
  fromViewPubKeyX,
  fromViewPubKeyY,
  toSpendPubKeyX,
  toSpendPubKeyY,
  toViewPubKeyX,
  toViewPubKeyY
}) {
  const commitmentBytes = commitment instanceof Uint8Array ? commitment : decodeCanonicalFieldHex(commitment, "audit disclosure commitment");
  if (amount == null || assetId == null) {
    throw new Error("audit disclosure requires amount and asset id");
  }
  if ([fromSpendPubKeyX, fromSpendPubKeyY, fromViewPubKeyX, fromViewPubKeyY].some(value => value == null)) {
    throw new Error("audit disclosure requires the full sender shielded address");
  }
  if ([toSpendPubKeyX, toSpendPubKeyY, toViewPubKeyX, toViewPubKeyY].some(value => value == null)) {
    throw new Error("audit disclosure requires the full recipient shielded address");
  }

  return canonicalFieldHex(mimcHash(
    BigInt(transferAuditDisclosureDomain),
    BigInt(outputIndex),
    bytesToBigIntBE(commitmentBytes),
    amount,
    assetId,
    fromSpendPubKeyX,
    fromSpendPubKeyY,
    fromViewPubKeyX,
    fromViewPubKeyY,
    toSpendPubKeyX,
    toSpendPubKeyY,
    toViewPubKeyX,
    toViewPubKeyY
  ));
}

export function computeSelfViewTransferDisclosureDigestHex({
  outputIndex = transferDisclosureRecipientOutputIndex,
  commitment,
  amount,
  assetId,
  fromSpendPubKeyX,
  fromSpendPubKeyY,
  fromViewPubKeyX,
  fromViewPubKeyY,
  toSpendPubKeyX,
  toSpendPubKeyY,
  toViewPubKeyX,
  toViewPubKeyY
}) {
  const commitmentBytes = commitment instanceof Uint8Array ? commitment : decodeCanonicalFieldHex(commitment, "self-view disclosure commitment");
  if (amount == null || assetId == null) {
    throw new Error("self-view disclosure requires amount and asset id");
  }
  if ([fromSpendPubKeyX, fromSpendPubKeyY, fromViewPubKeyX, fromViewPubKeyY].some(value => value == null)) {
    throw new Error("self-view disclosure requires the full sender shielded address");
  }
  if ([toSpendPubKeyX, toSpendPubKeyY, toViewPubKeyX, toViewPubKeyY].some(value => value == null)) {
    throw new Error("self-view disclosure requires the full recipient shielded address");
  }

  return canonicalFieldHex(mimcHash(
    BigInt(transferSelfViewDisclosureDomain),
    BigInt(outputIndex),
    bytesToBigIntBE(commitmentBytes),
    amount,
    assetId,
    fromSpendPubKeyX,
    fromSpendPubKeyY,
    fromViewPubKeyX,
    fromViewPubKeyY,
    toSpendPubKeyX,
    toSpendPubKeyY,
    toViewPubKeyX,
    toViewPubKeyY
  ));
}

export function computeExpectedDisclosureDigestHex(payload, options = {}) {
  const commitment = decodeCanonicalFieldHex(payload?.commitment_hex || "", "commitment");
  const { amount, assetId } = disclosureAmountAndAsset(payload);
  const fromBundle = decodeOptionalShieldedAddress(payload?.from_shielded_address, "from", options);
  const toBundle = decodeOptionalShieldedAddress(payload?.to_shielded_address, "to", options);

  const common = {
    outputIndex: Number(payload?.output_index || 0),
    commitment,
    amount,
    assetId,
    fromSpendPubKeyX: bundleCoordinate(fromBundle, "spendPubKey", "x"),
    fromSpendPubKeyY: bundleCoordinate(fromBundle, "spendPubKey", "y"),
    fromViewPubKeyX: bundleCoordinate(fromBundle, "viewPubKey", "x"),
    fromViewPubKeyY: bundleCoordinate(fromBundle, "viewPubKey", "y"),
    toSpendPubKeyX: bundleCoordinate(toBundle, "spendPubKey", "x"),
    toSpendPubKeyY: bundleCoordinate(toBundle, "spendPubKey", "y"),
    toViewPubKeyX: bundleCoordinate(toBundle, "viewPubKey", "x"),
    toViewPubKeyY: bundleCoordinate(toBundle, "viewPubKey", "y")
  };

  switch (payload?.plane || planeUser) {
    case planeAudit:
      return computeAuditTransferDisclosureDigestHex(common);
    case planeSelfView:
      return computeSelfViewTransferDisclosureDigestHex(common);
    case "":
    case planeUser:
      return computeTransferDisclosureDigestHex({
        ...common,
        policy: Number(payload?.policy || 0)
      });
    default:
      throw new Error(`unsupported disclosure payload plane ${JSON.stringify(payload?.plane)}`);
  }
}

export function verifyPayload(payload, onChainDigestHex = "", options = {}) {
  const expectedDigestHex = computeExpectedDisclosureDigestHex(payload, options);
  const payloadDigestHex = String(payload?.disclosure_digest_hex || "").trim();
  const localDisclosureDigestMatch = payloadDigestHex.toLowerCase() === expectedDigestHex.toLowerCase();
  if (!localDisclosureDigestMatch) {
    throw new Error(`disclosure digest mismatch: payload has ${payloadDigestHex}, expected ${expectedDigestHex}`);
  }

  const verification = {
    verified: false,
    local_disclosure_digest_match: localDisclosureDigestMatch,
    asset_denom_verified: Boolean(payload?.amount),
    on_chain_disclosure_digest_used: false
  };

  const onChain = String(onChainDigestHex || "").trim();
  if (onChain) {
    verification.on_chain_disclosure_digest_used = true;
    verification.on_chain_disclosure_digest_match = onChain.toLowerCase() === expectedDigestHex.toLowerCase();
    if (!verification.on_chain_disclosure_digest_match) {
      throw new Error(`on-chain disclosure digest mismatch: event has ${onChain}, decoded payload resolves to ${expectedDigestHex}`);
    }
  }

  verification.verified = verification.local_disclosure_digest_match &&
    (!verification.on_chain_disclosure_digest_used || verification.on_chain_disclosure_digest_match);
  return verification;
}

export function buildDisclosureReport({
  payload,
  onChainDigestHex = "",
  txHash = "",
  source,
  delivery,
  shieldedPrefix
}) {
  const verification = verifyPayload(payload, onChainDigestHex, { shieldedPrefix });
  const plane = payload?.plane === planeAudit
    ? planeAudit
    : payload?.plane === planeSelfView
      ? planeSelfView
      : planeUser;
  const resolvedSource = source || (plane === planeAudit
    ? "audit_encrypted"
    : plane === planeSelfView
      ? "self_view_encrypted"
      : "recipient_encrypted");
  const resolvedDelivery = delivery || (plane === planeAudit
    ? "audit-encrypted"
    : plane === planeSelfView
      ? "self-view-encrypted"
      : "recipient-encrypted");
  const policy = plane === planeAudit
    ? "audit-full"
    : plane === planeSelfView
      ? "amount-from-to"
      : privacyPolicyLabel(payload?.policy);
  const amount = payload?.amount || "";
  const assetDenom = payload?.asset_denom || "";
  const from = payload?.from_shielded_address || "";
  const to = payload?.to_shielded_address || "";
  return {
    plane,
    policy,
    output_index: Number(payload?.output_index || 0),
    commitment_hex: payload?.commitment_hex || "",
    digest_hex: payload?.disclosure_digest_hex || onChainDigestHex || "",
    verified: verification.verified,
    amount,
    asset_denom: assetDenom,
    from,
    to,
    source: resolvedSource,
    tx_hash: txHash ? txHash.toUpperCase() : "",
    verification,
    summary: {
      plane,
      delivery: resolvedDelivery,
      policy,
      disclosed_fields: disclosedFields(payload),
      amount,
      asset_denom: assetDenom,
      from_shielded_address: from,
      to_shielded_address: to
    },
    payload
  };
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
  const payload = decryptPayloadHex(payloadHex, disclosureScalar);
  return buildDisclosureReport({
    payload,
    onChainDigestHex: digestHex,
    txHash,
    source: "recipient_encrypted",
    delivery: "recipient-encrypted",
    shieldedPrefix: options.shieldedPrefix
  });
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
  const payload = decryptPayloadHex(payloadHex, disclosureScalar);
  return buildDisclosureReport({
    payload,
    onChainDigestHex: digestHex,
    txHash,
    source: "self_view_encrypted",
    delivery: "self-view-encrypted",
    shieldedPrefix: options.shieldedPrefix
  });
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
  const payload = decryptPayloadHex(payloadHex, disclosureScalar);
  return buildDisclosureReport({
    payload,
    onChainDigestHex: digestHex,
    txHash,
    source: "audit_encrypted",
    delivery: "audit-encrypted",
    shieldedPrefix: options.shieldedPrefix
  });
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
  const payload = decodePublicPayloadHex(payloadHex);
  return buildDisclosureReport({
    payload,
    onChainDigestHex,
    txHash,
    source: "public",
    delivery: "public",
    shieldedPrefix: options.shieldedPrefix
  });
}

export function payloadHex(payload) {
  return hexFromBytes(utf8Bytes(JSON.stringify(payload)));
}
