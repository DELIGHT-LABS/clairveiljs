import { bytesFromHex, hexFromBytes, unpackPoint } from "../core/crypto.js";
import { canonicalAssetDenomV1 } from "./asset-registry.js";
import { privacyFixedV1 } from "./protocol-v1.js";

const maxUint64 = (1n << 64n) - 1n;
const policyNames = new Set([
  "all-private",
  "amount",
  "to",
  "amount-to",
  "from",
  "amount-from",
  "from-to",
  "amount-from-to"
]);
const disclosureModes = new Set(["none", "public", "recipient-encrypted"]);

function object(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is required`);
  return value;
}

function alias(source, names, label, normalize) {
  const values = names
    .filter(name => source[name] !== undefined && source[name] !== null)
    .map(name => normalize(source[name]));
  if (!values.length) throw new Error(`${label} is required`);
  const equal = (left, right) => Array.isArray(left) && Array.isArray(right)
    ? left.length === right.length && left.every((entry, index) => entry === right[index])
    : left === right;
  if (values.some(value => !equal(value, values[0]))) throw new Error(`${label} aliases disagree`);
  return values[0];
}

function strictText(value, label) {
  if (typeof value !== "string" || value !== value.trim() || !value) throw new Error(`${label} is required`);
  return value;
}

function uint64(value, label, { positive = false } = {}) {
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    throw new Error(`${label} must be a safe integer when supplied as a number`);
  }
  const text = typeof value === "bigint" ? value.toString() : String(value ?? "");
  if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error(`${label} must be a canonical uint64 decimal string`);
  const parsed = BigInt(text);
  if (parsed > maxUint64 || (positive && parsed === 0n)) throw new Error(`${label} must be a${positive ? " positive" : ""} uint64`);
  return parsed.toString();
}

function fixedStringList(value, label, allowed, required) {
  if (!Array.isArray(value) || !value.length) throw new Error(`${label} must be a non-empty array`);
  const normalized = value.map((entry, index) => strictText(entry, `${label}[${index}]`));
  if (new Set(normalized).size !== normalized.length || normalized.some(entry => !allowed.has(entry))) {
    throw new Error(`${label} contains an unsupported or duplicate value`);
  }
  for (const requiredValue of required) {
    if (!normalized.includes(requiredValue)) throw new Error(`${label} must include ${requiredValue}`);
  }
  return Object.freeze([...normalized]);
}

/** Validate QueryAuditConfigResponse against the privacy-note-v1 wire contract. */
export function normalizeAuditConfigV1(response) {
  const source = object(response, "audit config response");
  const pubkey = alias(source, ["audit_master_pubkey_hex", "auditMasterPubkeyHex"], "audit config master public key", value => {
    const text = strictText(value, "audit config master public key");
    if (!/^[0-9a-fA-F]{64}$/.test(text)) throw new Error("audit config master public key must be canonical 32-byte hex");
    const bytes = bytesFromHex(text, "audit config master public key");
    const point = unpackPoint(bytes);
    if (point.x === 0n && point.y === 1n) throw new Error("audit config master public key must be a canonical non-identity point");
    return hexFromBytes(bytes);
  });
  const keyID = alias(source, ["audit_key_id", "auditKeyId"], "audit config key ID", value => {
    const text = strictText(value, "audit config key ID");
    if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(text)) throw new Error("audit config key ID must match [a-z0-9][a-z0-9._-]{0,63}");
    return text;
  });
  const epoch = alias(source, ["audit_key_epoch", "auditKeyEpoch"], "audit config key epoch", value => uint64(value, "audit config key epoch", { positive: true }));
  return Object.freeze({ audit_master_pubkey_hex: pubkey, audit_key_id: keyID, audit_key_epoch: epoch });
}

/** Validate QueryDisclosureConfigResponse and reject a chain that disables required audit disclosure. */
export function normalizeDisclosureConfigV1(response) {
  const source = object(response, "disclosure config response");
  const payloadVersion = alias(source, ["payload_version", "payloadVersion"], "disclosure config payload version", value => strictText(value, "disclosure config payload version"));
  if (payloadVersion !== privacyFixedV1) throw new Error(`unsupported disclosure payload version ${JSON.stringify(payloadVersion)}`);
  const auditRequired = alias(source, ["audit_disclosure_required", "auditDisclosureRequired"], "disclosure config audit requirement", value => {
    if (typeof value !== "boolean") throw new Error("disclosure config audit requirement must be boolean");
    return value;
  });
  if (!auditRequired) throw new Error("privacy-note-v1 requires audit disclosure");
  const policies = alias(source, ["supported_user_policies", "supportedUserPolicies"], "disclosure config policies", value => fixedStringList(value, "disclosure config policies", policyNames, ["all-private"]));
  const modes = alias(source, ["supported_user_modes", "supportedUserModes"], "disclosure config modes", value => fixedStringList(value, "disclosure config modes", disclosureModes, ["none"]));
  return Object.freeze({
    payload_version: payloadVersion,
    audit_disclosure_required: auditRequired,
    supported_user_policies: policies,
    supported_user_modes: modes
  });
}

/** Validate QueryReserveResponse arithmetic as well as the server's invariant flag. */
export function normalizeReserveResponseV1(response, expectedDenom) {
  const source = object(response, "reserve response");
  const denom = alias(source, ["denom"], "reserve denom", value => canonicalAssetDenomV1(strictText(value, "reserve denom")));
  if (expectedDenom != null && denom !== canonicalAssetDenomV1(expectedDenom)) throw new Error("reserve denom does not match the requested denom");
  const moduleBalance = alias(source, ["module_balance", "moduleBalance"], "reserve module balance", value => uint64(value, "reserve module balance"));
  const deposited = alias(source, ["total_deposited", "totalDeposited"], "reserve total deposited", value => uint64(value, "reserve total deposited"));
  const withdrawn = alias(source, ["total_withdrawn", "totalWithdrawn"], "reserve total withdrawn", value => uint64(value, "reserve total withdrawn"));
  const expected = alias(source, ["expected_module_balance", "expectedModuleBalance"], "reserve expected module balance", value => uint64(value, "reserve expected module balance"));
  const invariant = alias(source, ["invariant_holds", "invariantHolds"], "reserve invariant", value => {
    if (typeof value !== "boolean") throw new Error("reserve invariant must be boolean");
    return value;
  });
  if (!invariant) throw new Error("reserve invariant does not hold");
  const calculated = BigInt(deposited) - BigInt(withdrawn);
  if (calculated < 0n || calculated !== BigInt(expected) || BigInt(moduleBalance) !== BigInt(expected)) {
    throw new Error("reserve balances do not satisfy the accounting invariant");
  }
  return Object.freeze({
    denom,
    module_balance: moduleBalance,
    total_deposited: deposited,
    total_withdrawn: withdrawn,
    expected_module_balance: expected,
    invariant_holds: invariant
  });
}
