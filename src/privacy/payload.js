import { createNoteSelection } from "./note-selection.js";
import { fromBech32 } from "@cosmjs/encoding";
import {
  bytesFromHex,
  bytesToBigIntBE,
  canonicalFieldHex,
  defaultAccountPrefix,
  decodeCanonicalFieldHex,
  hexFromBytes,
  normalizeHex,
  normalizeBech32Prefix
} from "../core/crypto.js";
import {
  transferPrivacyPolicyAllPrivate,
  userDisclosureModeNone,
  userDisclosureModePublic,
  userDisclosureModeRecipientEncrypted
} from "../core/disclosure.js";
import {
  createSpendNoteHashSigner,
  defaultAssetDenom,
  isVerifiedUnspentFoundNote,
  normalizeFoundNote,
  noteSpendPubKeyHex,
  noteViewPubKeyHex,
  parseCoin,
  resolveWithdrawSignature
} from "../core/note.js";
import { sha256Hex as digestSha256Hex } from "../core/browser-crypto.js";
import {
  buildPreparedTransferV5Payload,
  buildTransferV5MsgFromPayloadAndProof,
  computePreparedTransferV5PayloadHash,
  preparedTransferV5PayloadVersion,
  preparedTransferV5ProofVersion,
  validateCanonicalGroth16ProofBytes,
  validatePreparedTransferV5PayloadMetadata,
  validatePreparedTransferV5Proof
} from "./transfer-v5.js";
import {
  activeCircuitSetIdV1,
  computeAssetIdV1,
  computeChainDomainV1,
  computeNoteCommitmentV1,
  computeNoteNullifierV1,
  computeNoteTreeNodeV1,
  computeSpendIntentV2,
  computeWithdrawRecipientDigestV1
} from "./protocol-v1.js";

export const preparedTransferPayloadVersion = preparedTransferV5PayloadVersion;
export const preparedTransferProofVersion = preparedTransferV5ProofVersion;
export const preparedWithdrawProverPayloadVersion = "v2";
export const preparedWithdrawProofVersion = "v2";
export const preparedWithdrawPayloadVersion = "v2";

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

export { privacyPolicyValue } from "./disclosure-policy.js";
import { privacyPolicyValue } from "./disclosure-policy.js";

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

const legacyNoteSelection = createNoteSelection({
  maxShieldedAmount: (1n << 64n) - 1n,
  normalizeInventoryNote: normalizeFoundNote,
  parseTargetAmount: (value, label) => BigInt(bigintDecimal(value, label))
});
export const { summarizeSpendableNotesByDenom, selectTransferInputs, selectBatchTransferInputs } = legacyNoteSelection;

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

function normalizeMerklePathResult(result, label, commitmentHex) {
  const rootText = String(result?.root ?? result?.Root ?? "").trim();
  if (!rootText) {
    throw new Error(`${label} merkle path result missing root`);
  }
  const rootHex = canonicalFieldHex(bytesToBigIntBE(decodeCanonicalFieldHex(rootText, `${label} root`)));
  const path = [...(result?.path ?? result?.Path ?? [])].map((value, index) => canonicalFieldHex(
    bytesToBigIntBE(decodeCanonicalFieldHex(value, `${label} merkle path ${index}`))
  ));
  const pathHelper = [...(result?.path_helper ?? result?.pathHelper ?? result?.PathHelper ?? [])].map((value, index) => {
    const helper = Number(value);
    if (!Number.isSafeInteger(helper) || (helper !== 0 && helper !== 1)) {
      throw new Error(`${label} merkle path helper ${index} must be 0 or 1`);
    }
    return helper;
  });
  if (path.length !== 32 || pathHelper.length !== 32) {
    throw new Error(`${label} merkle path must be 32 levels`);
  }
  let current = bytesToBigIntBE(decodeCanonicalFieldHex(commitmentHex, `${label} commitment`));
  for (let level = 0; level < 32; level += 1) {
    const sibling = bytesToBigIntBE(decodeCanonicalFieldHex(path[level], `${label} merkle path ${level}`));
    current = pathHelper[level] === 0
      ? computeNoteTreeNodeV1(level, current, sibling)
      : computeNoteTreeNodeV1(level, sibling, current);
  }
  if (canonicalFieldHex(current) !== rootHex) {
    throw new Error(`${label} merkle path does not reconstruct its root`);
  }
  return { rootHex, path, pathHelper };
}

export function validatePreparedTransferPayloadMetadata(payload) {
  return validatePreparedTransferV5PayloadMetadata(payload);
}

export function computePreparedTransferPayloadHash(payload) {
  return computePreparedTransferV5PayloadHash(payload);
}

export function validatePreparedTransferProof(payload, proof, options) {
  return validatePreparedTransferV5Proof(payload, proof, options);
}

export function buildTransferMsgFromPayloadAndProof(payload, proof, options) {
  return buildTransferV5MsgFromPayloadAndProof(payload, proof, options);
}

export async function buildPreparedTransferPayload(input = {}) {
  return buildPreparedTransferV5Payload(input);
}

function literalNullifierUsage(value) {
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

async function assertProverNullifiersUnspent(nullifierHexes, checkNullifiers) {
  if (typeof checkNullifiers !== "function") {
    throw new Error("checkNullifiers is required before proof generation");
  }
  const nullifiers = [...new Set((nullifierHexes || []).map(value => String(value || "").trim().toLowerCase()))];
  if (!nullifiers.length || nullifiers.some(value => !value)) {
    throw new Error("proof generation requires non-empty nullifiers");
  }
  let result;
  try {
    result = await checkNullifiers(nullifiers);
  } catch {
    throw new Error("verify nullifiers before proof generation: query failed");
  }
  const statuses = new Map();
  const invalidStatuses = new Set();
  const add = (nullifier, value) => {
    const key = String(nullifier || "").trim().toLowerCase();
    if (!key || invalidStatuses.has(key)) return;
    const used = literalNullifierUsage(value);
    if (used === null || (statuses.has(key) && statuses.get(key) !== used)) {
      statuses.delete(key);
      invalidStatuses.add(key);
      return;
    }
    statuses.set(key, used);
  };
  if (result instanceof Map) {
    for (const [nullifier, value] of result) add(nullifier, value);
  } else if (Array.isArray(result?.statuses)) {
    for (const status of result.statuses) {
      const canonical = status?.nullifier;
      const alias = status?.Nullifier;
      if (canonical != null && alias != null &&
          String(canonical).trim().toLowerCase() !== String(alias).trim().toLowerCase()) {
        add(canonical, null);
        add(alias, null);
      } else {
        add(canonical ?? alias, status);
      }
    }
  } else if (result && typeof result === "object") {
    for (const [nullifier, value] of Object.entries(result)) add(nullifier, value);
  }
  for (const nullifier of nullifiers) {
    if (!statuses.has(nullifier)) {
      throw new Error("verify nullifiers before proof generation: missing or malformed status");
    }
    if (statuses.get(nullifier)) {
      throw new Error("proof generation blocked because an input nullifier is already spent");
    }
  }
}

export async function buildTransferMessage({ proverAdapter, ...input } = {}) {
  if (!proverAdapter?.proveTransfer) {
    throw new Error("proverAdapter.proveTransfer is required");
  }
  const hasChainNowCamel = input.chainNowUnix !== undefined && input.chainNowUnix !== null;
  const hasChainNowSnake = input.chain_now_unix !== undefined && input.chain_now_unix !== null;
  const chainNowCamel = hasChainNowCamel ? input.chainNowUnix : undefined;
  const chainNowSnake = hasChainNowSnake ? input.chain_now_unix : undefined;
  if ((hasChainNowCamel && (!Number.isSafeInteger(chainNowCamel) || chainNowCamel < 0)) ||
      (hasChainNowSnake && (!Number.isSafeInteger(chainNowSnake) || chainNowSnake < 0)) ||
      (!hasChainNowCamel && !hasChainNowSnake)) {
    throw new Error("transfer chainNowUnix is required from authoritative chain time");
  }
  if (hasChainNowCamel && hasChainNowSnake && chainNowCamel !== chainNowSnake) {
    throw new Error("chainNowUnix aliases conflict");
  }
  const hasExpiryCamel = input.expiresAtUnix !== undefined && input.expiresAtUnix !== null;
  const hasExpirySnake = input.expires_at_unix !== undefined && input.expires_at_unix !== null;
  const expiryCamel = hasExpiryCamel ? input.expiresAtUnix : undefined;
  const expirySnake = hasExpirySnake ? input.expires_at_unix : undefined;
  if ((hasExpiryCamel && (!Number.isSafeInteger(expiryCamel) || expiryCamel < 0)) ||
      (hasExpirySnake && (!Number.isSafeInteger(expirySnake) || expirySnake < 0))) {
    throw new Error("transfer expiresAtUnix must be a non-negative safe integer");
  }
  if (hasExpiryCamel && hasExpirySnake && expiryCamel !== expirySnake) {
    throw new Error("expiresAtUnix aliases conflict");
  }
  const chainNowUnix = hasChainNowCamel ? chainNowCamel : chainNowSnake;
  const expiresAtUnix = hasExpiryCamel ? expiryCamel : expirySnake;
  const payload = await buildPreparedTransferPayload({
    ...input,
    chainNowUnix,
    ...(expiresAtUnix === undefined ? {} : { expiresAtUnix })
  });
  await assertProverNullifiersUnspent(
    payload.inputs.map(inputNote => inputNote.nullifier_hex),
    input.checkNullifiers,
  );
  const response = await proverAdapter.proveTransfer({
    version: "v2",
    payload
  }, { signal: input.signal, nowUnix: chainNowUnix });
  const proof = response?.proof || response;
  return {
    payload,
    proof,
    message: buildTransferMsgFromPayloadAndProof(payload, proof, {
      nowUnix: chainNowUnix,
      expectedChainId: input.chainId
    })
  };
}

function selectExactMatchNote(notes, denom, targetAmount) {
  const targetAssetIdHex = canonicalFieldHex(computeAssetIdV1(denom));
  for (const found of notes) {
    if (!isVerifiedUnspentFoundNote(found)) continue;
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
    payload.spend_intent_signature_hex
  ]));
}

export async function buildPreparedWithdrawProverPayload({
  notes,
  amount,
  denom,
  assetDenom,
  recipient,
  chainId,
  expiresAtUnix,
  chainNowUnix,
  rootSeed,
  merklePathProvider,
  spendNoteHashSigner,
  accountPrefix
} = {}) {
  const localNowUnix = Math.floor(Date.now() / 1000);
  const authoritativeNowUnix = chainNowUnix == null
    ? localNowUnix
    : Number(chainNowUnix);
  if (!Number.isSafeInteger(authoritativeNowUnix) || authoritativeNowUnix < 0) {
    throw new Error("chainNowUnix must be a non-negative safe integer");
  }
  const resolvedExpiresAtUnix = expiresAtUnix ?? authoritativeNowUnix + 1800;
  const coin = parseCoin(amount, assetDenom ?? denom ?? defaultAssetDenom);
  const targetAmount = positiveBigInt(coin.amount, "withdraw amount");
  const foundNotes = [...(notes || [])].map(normalizeFoundNote);
  const targetAssetIdHex = canonicalFieldHex(computeAssetIdV1(coin.denom));
  const selected = selectExactMatchNote(foundNotes, coin.denom, targetAmount);
  if (!selected) {
    const sameDenom = foundNotes.filter(found => isVerifiedUnspentFoundNote(found) && canonicalFieldHex(found.note.assetID) === targetAssetIdHex);
    const total = sameDenom.reduce((sum, found) => sum + found.note.amount, 0n);
    throw new Error(`withdraw requires one exact-match note for ${coin.raw}; spendable ${coin.denom} total is ${total}${coin.denom} across ${sameDenom.length} notes`);
  }
  const commitmentHex = canonicalFieldHex(computeNoteCommitmentV1(selected.note));
  const recipientDecoded = fromBech32(recipient, 90);
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
    resolvedExpiresAtUnix,
    authoritativeNowUnix,
    "withdraw prover payload expired",
    "withdraw prover payload expires_at_unix"
  );
  const merkle = normalizeMerklePathResult(
    await lookupMerklePath(merklePathProvider, commitmentHex),
    "withdraw selected note",
    commitmentHex
  );
  const nullifier = computeNoteNullifierV1(selected.note);
  const intent = computeSpendIntentV2({
    chainDomain: computeChainDomainV1(String(chainId || "").trim(), activeCircuitSetIdV1),
    root: bytesToBigIntBE(decodeCanonicalFieldHex(merkle.rootHex, "withdraw root")),
    nullifier,
    amount: targetAmount,
    assetId: selected.note.assetID,
    recipientDigest: computeWithdrawRecipientDigestV1(recipientBytes),
    expiresAtUnix: normalizedExpiresAtUnix
  });
  const signature = await resolveWithdrawSignature(signer, intent);
  const payload = {
    version: preparedWithdrawProverPayloadVersion,
    root_hex: merkle.rootHex,
    nullifier_hex: canonicalFieldHex(nullifier),
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
    spend_intent_signature_hex: hexFromBytes(signature)
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
  validatePreparedWithdrawProverPayloadMetadata(proverPayload, nowUnix);
  if (!proof || proof.version !== preparedWithdrawProofVersion) {
    throw new Error(`unsupported withdraw proof version ${JSON.stringify(proof?.version)}`);
  }
  if (proof.payload_hash !== proverPayload.payload_hash) {
    throw new Error("withdraw proof payload hash mismatch");
  }
  const proofHex = normalizeHex(proof.proof_hex, "withdraw proof");
  if (proofHex.length !== 328) throw new Error("withdraw proof must be exactly 164 bytes");
  validateCanonicalGroth16ProofBytes(proofHex, "withdraw proof");
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

export function validatePreparedWithdrawProverPayloadMetadata(payload, nowUnix = Math.floor(Date.now() / 1000)) {
  if (!payload || payload.version !== preparedWithdrawProverPayloadVersion) {
    throw new Error(`unsupported withdraw prover payload version ${JSON.stringify(payload?.version)}`);
  }
  if (!payload.payload_hash || payload.payload_hash !== computePreparedWithdrawProverPayloadHash(payload)) {
    throw new Error("withdraw prover payload hash mismatch; the file may have been modified after preparation");
  }
  if (!String(payload.chain_id || "").trim()) throw new Error("withdraw prover payload chain_id is required");
  assertFutureUnixTimestamp(payload.expires_at_unix, nowUnix, "withdraw prover payload expired", "withdraw prover payload expires_at_unix");
  if (normalizeHex(payload.root_hex, "withdraw root").length !== 64 || normalizeHex(payload.nullifier_hex, "withdraw nullifier").length !== 64) {
    throw new Error("withdraw prover root and nullifier must be 32-byte hex strings");
  }
  if (canonicalFieldHex(computeAssetIdV1(payload.asset_denom)) !== normalizeHex(payload.asset_id_hex, "withdraw asset ID")) {
    throw new Error("withdraw prover payload asset_denom does not match asset_id_hex");
  }
  const recipientBytes = Uint8Array.from(fromBech32(payload.recipient, 90).data);
  if (hexFromBytes(recipientBytes) !== normalizeHex(payload.recipient_bytes_hex, "withdraw recipient bytes")) {
    throw new Error("withdraw prover payload recipient_bytes_hex does not match recipient");
  }
  const signature = hexToBytes(normalizeHex(payload.spend_intent_signature_hex, "withdraw spend intent signature"), "withdraw spend intent signature");
  if (signature.length !== 64) throw new Error("withdraw spend intent signature must be 64 bytes");
  return true;
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

function requireRelayChainNowUnix(value) {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new Error("chainNowUnix is required for relay withdraw payload validation");
  }
  return value;
}

export function validateRelayWithdrawPayload(payload, {
  chainNowUnix,
  expectedChainId,
  expectedRecipient,
  accountPrefix
} = {}) {
  validatePreparedWithdrawPayload(payload, requireRelayChainNowUnix(chainNowUnix));
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
  const recipientDecoded = fromBech32(payload.recipient, 90);
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
  const relayerDecoded = fromBech32(creator, 90);
  if (options.accountPrefix != null) {
    const expectedPrefix = normalizeBech32Prefix(options.accountPrefix, "accountPrefix");
    if (relayerDecoded.prefix !== expectedPrefix) {
      throw new Error(`relayer prefix mismatch: expected ${expectedPrefix}, got ${relayerDecoded.prefix}`);
    }
  }
  return buildWithdrawMsgFromPayload(payload, creator, requireRelayChainNowUnix(options.chainNowUnix));
}

async function buildWithdrawPayloadWithProof({ proverAdapter, ...input } = {}) {
  if (!proverAdapter?.proveWithdraw) {
    throw new Error("proverAdapter.proveWithdraw is required");
  }
  const { selectedNote, payload: proverPayload } = await buildPreparedWithdrawProverPayload(input);
  await assertProverNullifiersUnspent([proverPayload.nullifier_hex], input.checkNullifiers);
  const response = await proverAdapter.proveWithdraw({
    version: "v2",
    payload: proverPayload
  }, { signal: input.signal, nowUnix: input.chainNowUnix });
  const proof = response?.proof || response;
  const payload = buildPreparedWithdrawPayloadFromProof(
    proverPayload,
    proof,
    input.chainNowUnix,
  );
  return {
    selectedNote,
    proverPayload,
    proof,
    payload
  };
}

export async function buildRelayWithdrawPayload({ proverAdapter, ...input } = {}) {
  const chainNowUnix = requireRelayChainNowUnix(input.chainNowUnix);
  return buildWithdrawPayloadWithProof({
    proverAdapter,
    ...input,
    chainNowUnix
  });
}

export async function buildWithdrawMessage({ proverAdapter, creator, ...input } = {}) {
  const { selectedNote, proverPayload, proof, payload } = await buildWithdrawPayloadWithProof({
    proverAdapter,
    ...input
  });
  return {
    selectedNote,
    proverPayload,
    proof,
    payload,
    message: buildWithdrawMsgFromPayload(payload, creator, input.chainNowUnix)
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
          throw new Error(`merkle path query failed with status ${response.status}`);
        }
        return response.json();
      } catch (error) {
        if (error?.name === "AbortError") {
          throw new Error(`merkle path query timed out after ${resolvedTimeoutMs}ms`);
        }
        throw error;
      } finally {
        clearTimeout(timeout);
      }
    }
  };
}
