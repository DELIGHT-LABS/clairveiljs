import {
  assertSignerPubKey,
  buildRootSigningMessage,
  createClairveilClient,
  verifySignerPubKey
} from "../transport/cosmos-client.js";
import {
  createEvmAuthorizationProfile,
  createEvmFinalityPolicy,
  createClairveilEvmClient,
  defaultEvmDepositMode,
  evmDepositModePayableExactValue,
  evmDepositValueForAmount,
  evmTransactionBindingHash,
  evmAddressToBech32,
  isEvmAddress,
  markEvmTransactionReservationRequired,
  normalizeEvmDepositMode,
  normalizeEvmAddress,
  waitForEvmFinality
} from "../transport/evm.js";
import {
  resolveCosmosFeeAmount as resolveBrowserCosmosFeeAmount,
  resolveCosmosGasLimit as resolveBrowserCosmosGasLimit,
  resolveDirectOperationEvidenceHashes,
  transferProofReadyMetadata
} from "../transport/cosmos-options.js";
import {
  derivePrivacyMaterial,
  hexFromBytes
} from "../core/crypto.js";
import {
  ClairveilError,
  ClairveilErrorCode,
  plannerStatusToErrorCode
} from "../core/errors.js";
import {
  parseCoin
} from "../core/note.js";
import {
  assertPlanCanBuildTx,
  planTransferNotes,
  planWithdrawNotes
} from "../privacy/planner.js";
import {
  preparePlanReservation,
  rollbackPlanReservation,
  rollbackPlanReservationPreservingError
} from "../privacy/reservation.js";
import {
  appendReservationCleanupErrors,
  markReservationProofReady,
  reservationAvailableNotes,
  reservationBatchSummary,
  reservationReconciliationFields,
  withReservationHeartbeat
} from "../privacy/reservation-workflow.js";
import {
  createHttpDepositProofProvider,
  createHttpProverAdapter,
  defaultDepositProofTimeoutMs,
  defaultProverResponseMaxBytes
} from "../privacy/prover.js";

const defaultFetchTimeoutMs = 30000;
const readOnlyEvmJsonRpcMethods = new Set([
  "eth_blockNumber",
  "eth_call",
  "eth_chainId",
  "eth_coinbase",
  "eth_estimateGas",
  "eth_feeHistory",
  "eth_gasPrice",
  "eth_getBalance",
  "eth_getBlockByHash",
  "eth_getBlockByNumber",
  "eth_getBlockTransactionCountByHash",
  "eth_getBlockTransactionCountByNumber",
  "eth_getCode",
  "eth_getLogs",
  "eth_getProof",
  "eth_getStorageAt",
  "eth_getTransactionByBlockHashAndIndex",
  "eth_getTransactionByBlockNumberAndIndex",
  "eth_getTransactionByHash",
  "eth_getTransactionCount",
  "eth_getTransactionReceipt",
  "eth_maxPriorityFeePerGas",
  "eth_protocolVersion",
  "eth_syncing",
  "net_listening",
  "net_peerCount",
  "net_version",
  "web3_clientVersion",
  "web3_sha3"
]);

function assertReadOnlyEvmJsonRpcMethod(method) {
  if (typeof method !== "string") {
    throw new Error("EVM JSON-RPC method must be a permitted read-only string");
  }
  const normalizedMethod = method.trim();
  if (!readOnlyEvmJsonRpcMethods.has(normalizedMethod)) {
    throw new Error(`EVM JSON-RPC method ${normalizedMethod || "<empty>"} is not permitted for read-only queries`);
  }
  return normalizedMethod;
}

function trimTrailingSlash(value) {
  return String(value || "").replace(/\/$/, "");
}

function normalizeRpcEndpoint(value) {
  return trimTrailingSlash(String(value || "").replace(/^tcp:\/\//, "http://"));
}

function normalizeRestEndpoints(primary, restEndpoints = [], { allowEmpty = false } = {}) {
  const endpoints = [];
  for (const endpoint of [primary, ...(Array.isArray(restEndpoints) ? restEndpoints : [])]) {
    const normalized = trimTrailingSlash(endpoint);
    if (normalized && !endpoints.includes(normalized)) {
      endpoints.push(normalized);
    }
  }
  if (!endpoints.length && !allowEmpty) {
    throw new Error("rest endpoint is required");
  }
  return endpoints;
}

const browserProfileKeys = new Set([
  "id",
  "label",
  "chainName",
  "transport",
  "wallet",
  "chainId",
  "rpc",
  "rest",
  "restEndpoints",
  "proverUrl",
  "depositProofUrl",
  "accountPrefix",
  "shieldedPrefix",
  "denom",
  "displayDenom",
  "coinDecimals",
  "keplrCoinType",
  "gasPriceStep",
  "keplrChainInfo",
  "evmRpc",
  "evmChainId",
  "evmChainName",
  "evmPrivacyPrecompileAddress",
  "evmDepositMode",
  "evmNativeDenom",
  "evmAuthorizationProfile",
  "evmGasLimit",
  "evmSendGasLimit"
]);

const browserConfigKeys = new Set([
  "schemaVersion",
  "activeChainProfileId",
  "chainProfiles",
  "serverBacked",
  "modeLabel",
  "home",
  "localSignerHome",
  "localSignerBin",
  "localTestMode",
  "chainId",
  "rpc",
  "rest",
  "proverUrl",
  "transport",
  "denom",
  "displayDenom",
  "coinDecimals",
  "accountPrefix",
  "shieldedPrefix",
  "keplrChainInfo",
  "evmRpc",
  "evmChainId",
  "evmChainName",
  "evmPrivacyPrecompileAddress",
  "evmDepositMode",
  "evmNativeDenom",
  "evmAuthorizationProfile",
  "evmGasLimit",
  "evmSendGasLimit",
  "serverFeatures"
]);

const browserConfigCompatibilityFields = [
  "chainId",
  "rpc",
  "rest",
  "proverUrl",
  "transport",
  "denom",
  "displayDenom",
  "coinDecimals",
  "accountPrefix",
  "shieldedPrefix",
  "keplrChainInfo",
  "evmRpc",
  "evmChainId",
  "evmChainName",
  "evmPrivacyPrecompileAddress",
  "evmDepositMode",
  "evmNativeDenom",
  "evmAuthorizationProfile",
  "evmGasLimit",
  "evmSendGasLimit"
];

const browserServerFeatureKeys = new Set([
  "localTestMode",
  "localSigners",
  "faucet",
  "depositProof",
  "auditorAdmin",
  "localSignerAdmin",
  "localSignerSetup",
  "relayer",
  "proverProxy",
  "batchTransfer"
]);

function requiredProfileString(profile, key, {
  minLength = 1,
  maxLength = Infinity,
  pattern = null
} = {}) {
  const value = profile?.[key];
  if (typeof value !== "string" || value.length < minLength || value.length > maxLength) {
    throw new Error(`profile.${key} must be a string with ${minLength}-${maxLength === Infinity ? "unbounded" : maxLength} characters`);
  }
  if (pattern && !pattern.test(value)) {
    throw new Error(`profile.${key} has an invalid format`);
  }
  return value;
}

function optionalProfileUrl(profile, key, { required = false } = {}) {
  const value = profile?.[key];
  if (value == null && !required) return "";
  const url = requiredProfileString(profile, key);
  if (!/^https?:\/\/[^/?#]+(?:\/[^?#]*)?$/u.test(url)) {
    throw new Error(`profile.${key} must be an http(s) URL without query, fragment, or credentials`);
  }
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`profile.${key} must be a valid URL`);
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username || parsed.password) {
    throw new Error(`profile.${key} must be an http(s) URL without query, fragment, or credentials`);
  }
  return url;
}

function requiredProfileInteger(profile, key, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  const value = profile?.[key];
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`profile.${key} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

function requiredProfileObject(profile, key) {
  const value = profile?.[key];
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`profile.${key} must be an object`);
  }
  return value;
}

function assertExactProfileKeys(value, keys, label) {
  for (const key of Object.keys(value)) {
    if (!keys.has(key)) throw new Error(`${label}.${key} is not supported by the Clairveil Web profile schema`);
  }
}

function validateEvmAuthorizationProfileConfig(profile) {
  const value = profile?.evmAuthorizationProfile;
  if (value == null) return null;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("profile.evmAuthorizationProfile must be an object");
  }
  const label = "profile.evmAuthorizationProfile";
  assertExactProfileKeys(value, new Set(["typedDataDomain", "supportedAuthorizationKinds"]), label);
  if (value.typedDataDomain != null) {
    if (!value.typedDataDomain || typeof value.typedDataDomain !== "object" || Array.isArray(value.typedDataDomain)) {
      throw new Error(`${label}.typedDataDomain must be an object`);
    }
    assertExactProfileKeys(value.typedDataDomain, new Set(["name", "version"]), `${label}.typedDataDomain`);
    requiredProfileString(value.typedDataDomain, "name", { maxLength: 128 });
    if (value.typedDataDomain.version != null) {
      requiredProfileString(value.typedDataDomain, "version", { maxLength: 128 });
    }
  }
  if (value.supportedAuthorizationKinds != null) {
    if (!Array.isArray(value.supportedAuthorizationKinds)) {
      throw new Error(`${label}.supportedAuthorizationKinds must be an array`);
    }
    for (const [index, kind] of value.supportedAuthorizationKinds.entries()) {
      if (typeof kind !== "string" && typeof kind !== "number") {
        throw new Error(`${label}.supportedAuthorizationKinds[${index}] must be a uint8 value`);
      }
    }
  }
  if (value.typedDataDomain == null && value.supportedAuthorizationKinds == null) {
    throw new Error(`${label} must configure typedDataDomain or supportedAuthorizationKinds`);
  }
  // Reuse the transport parser so JSON profile validation and the runtime
  // adapter have identical uint8 and duplicate-value rules.
  createEvmAuthorizationProfile(value);
  return Object.freeze({
    ...value,
    ...(value.typedDataDomain ? { typedDataDomain: Object.freeze({ ...value.typedDataDomain }) } : {}),
    ...(value.supportedAuthorizationKinds ? { supportedAuthorizationKinds: Object.freeze([...value.supportedAuthorizationKinds]) } : {})
  });
}

function validateProfileGasPriceStep(value, label = "profile.gasPriceStep") {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  assertExactProfileKeys(value, new Set(["low", "average", "high"]), label);
  for (const key of ["low", "average", "high"]) {
    if (typeof value[key] !== "number" || !Number.isFinite(value[key]) || value[key] <= 0) {
      throw new Error(`${label}.${key} must be a positive number`);
    }
  }
}

function validateProfileKeplrCurrency(value, label, { fee = false } = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const keys = new Set(["coinDenom", "coinMinimalDenom", "coinDecimals", ...(fee ? ["gasPriceStep"] : [])]);
  assertExactProfileKeys(value, keys, label);
  requiredProfileString(value, "coinDenom", { maxLength: 32 });
  requiredProfileString(value, "coinMinimalDenom", {
    minLength: 3,
    maxLength: 128,
    pattern: /^[A-Za-z][A-Za-z0-9/:._-]*$/u
  });
  requiredProfileInteger(value, "coinDecimals", { maximum: 255 });
  if (fee) validateProfileGasPriceStep(value.gasPriceStep, `${label}.gasPriceStep`);
}

function validateProfileKeplrChainInfo(profile) {
  const value = requiredProfileObject(profile, "keplrChainInfo");
  const label = "profile.keplrChainInfo";
  assertExactProfileKeys(value, new Set([
    "chainId", "chainName", "rpc", "rest", "bip44", "bech32Config",
    "currencies", "feeCurrencies", "stakeCurrency", "features"
  ]), label);
  requiredProfileString(value, "chainId", { maxLength: 128 });
  requiredProfileString(value, "chainName", { maxLength: 128 });
  optionalProfileUrl(value, "rpc", { required: true });
  optionalProfileUrl(value, "rest", { required: true });
  const bip44 = requiredProfileObject(value, "bip44");
  assertExactProfileKeys(bip44, new Set(["coinType"]), `${label}.bip44`);
  requiredProfileInteger(bip44, "coinType", { maximum: 4294967295 });
  const bech32Config = requiredProfileObject(value, "bech32Config");
  const bech32Keys = [
    "bech32PrefixAccAddr", "bech32PrefixAccPub", "bech32PrefixValAddr",
    "bech32PrefixValPub", "bech32PrefixConsAddr", "bech32PrefixConsPub"
  ];
  assertExactProfileKeys(bech32Config, new Set(bech32Keys), `${label}.bech32Config`);
  for (const key of bech32Keys) {
    requiredProfileString(bech32Config, key, { maxLength: 32, pattern: /^[a-z][a-z0-9]*$/u });
  }
  for (const [key, fee] of [["currencies", false], ["feeCurrencies", true]]) {
    if (!Array.isArray(value[key]) || value[key].length !== 1) {
      throw new Error(`${label}.${key} must contain exactly one currency`);
    }
    validateProfileKeplrCurrency(value[key][0], `${label}.${key}[0]`, { fee });
  }
  validateProfileKeplrCurrency(value.stakeCurrency, `${label}.stakeCurrency`);
  if (!Array.isArray(value.features) || value.features.length !== 0) {
    throw new Error(`${label}.features must be an empty array`);
  }
}

function sameJsonValue(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function assertProfileKeplrCompatibility(profile) {
  const info = profile.keplrChainInfo;
  for (const field of ["chainId", "chainName", "rpc", "rest"]) {
    if (info[field] !== profile[field]) {
      throw new Error(`profile.keplrChainInfo.${field} must match profile.${field}`);
    }
  }
  if (info.bip44.coinType !== profile.keplrCoinType) {
    throw new Error("profile.keplrChainInfo.bip44.coinType must match profile.keplrCoinType");
  }
  if (!sameJsonValue(info.feeCurrencies[0].gasPriceStep, profile.gasPriceStep)) {
    throw new Error("profile.keplrChainInfo.feeCurrencies[0].gasPriceStep must match profile.gasPriceStep");
  }
  for (const [index, currency] of [
    info.currencies[0],
    info.feeCurrencies[0],
    info.stakeCurrency
  ].entries()) {
    const label = ["currencies", "feeCurrencies", "stakeCurrency"][index];
    if (currency.coinDenom !== profile.displayDenom ||
        currency.coinMinimalDenom !== profile.denom ||
        currency.coinDecimals !== profile.coinDecimals) {
      throw new Error(`profile.keplrChainInfo.${label} must match profile denom display metadata`);
    }
  }
}

function validateBrowserWalletProfileContract(profile, {
  allowMissingEvmCosmosEndpoints = false
} = {}) {
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
    throw new Error("profile must be an object");
  }
  assertExactProfileKeys(profile, browserProfileKeys, "profile");
  requiredProfileString(profile, "id", { maxLength: 128, pattern: /^[A-Za-z0-9][A-Za-z0-9._-]*$/u });
  requiredProfileString(profile, "label", { maxLength: 128 });
  requiredProfileString(profile, "chainName", { maxLength: 128 });
  const transport = walletTypeFromBody({}, profile.transport);
  const wallet = requiredProfileString(profile, "wallet");
  requiredProfileString(profile, "chainId", { maxLength: 128 });
  const requireCosmosEndpoints = transport !== "evm" || !allowMissingEvmCosmosEndpoints;
  optionalProfileUrl(profile, "rpc", { required: requireCosmosEndpoints });
  optionalProfileUrl(profile, "rest", { required: requireCosmosEndpoints });
  optionalProfileUrl(profile, "proverUrl", { required: true });
  optionalProfileUrl(profile, "depositProofUrl");
  requiredProfileString(profile, "accountPrefix", { maxLength: 32, pattern: /^[a-z][a-z0-9]*$/u });
  requiredProfileString(profile, "shieldedPrefix", { maxLength: 32, pattern: /^[a-z][a-z0-9]*$/u });
  requiredProfileString(profile, "denom", {
    minLength: 3,
    maxLength: 128,
    pattern: /^[A-Za-z][A-Za-z0-9/:._-]*$/u
  });
  requiredProfileString(profile, "displayDenom", { maxLength: 32 });
  requiredProfileInteger(profile, "coinDecimals", { maximum: 255 });
  if (profile.restEndpoints != null) {
    if (!Array.isArray(profile.restEndpoints) || !profile.restEndpoints.length) {
      throw new Error("profile.restEndpoints must be a non-empty array");
    }
    const endpoints = profile.restEndpoints.map((_, index) => optionalProfileUrl(profile.restEndpoints, String(index), { required: true }));
    if (new Set(endpoints).size !== endpoints.length) {
      throw new Error("profile.restEndpoints must not contain duplicates");
    }
  }

  if (transport === "cosmos") {
    if (wallet !== "keplr") throw new Error("profile.wallet must be keplr for Cosmos profiles");
    requiredProfileInteger(profile, "keplrCoinType", { maximum: 4294967295 });
    validateProfileGasPriceStep(profile.gasPriceStep);
    validateProfileKeplrChainInfo(profile);
    assertProfileKeplrCompatibility(profile);
  } else {
    if (wallet !== "metamask") throw new Error("profile.wallet must be metamask for EVM profiles");
    for (const key of ["keplrCoinType", "gasPriceStep", "keplrChainInfo"]) {
      if (Object.prototype.hasOwnProperty.call(profile, key)) {
        throw new Error(`profile.${key} is not permitted for EVM profiles`);
      }
    }
    optionalProfileUrl(profile, "evmRpc", { required: true });
    requiredProfileString(profile, "evmChainId", { pattern: /^0x[0-9a-fA-F]+$/u });
    normalizedEvmChainId(profile.evmChainId, "profile.evmChainId");
    requiredProfileString(profile, "evmChainName", { maxLength: 128 });
    normalizeEvmAddress(profile.evmPrivacyPrecompileAddress, "profile.evmPrivacyPrecompileAddress");
    const evmDepositMode = normalizeEvmDepositMode(
      profile.evmDepositMode ?? defaultEvmDepositMode
    );
    if (evmDepositMode !== evmDepositModePayableExactValue) {
      throw new Error("EVM profiles require payable-exact-value deposits for the Clairveil privacy precompile");
    }
    if (profile.evmNativeDenom != null) {
      requiredProfileString(profile, "evmNativeDenom", {
        minLength: 3,
        maxLength: 128,
        pattern: /^[A-Za-z][A-Za-z0-9/:._-]*$/u
      });
    }
    requiredProfileString(profile, "evmNativeDenom", {
      minLength: 3,
      maxLength: 128,
      pattern: /^[A-Za-z][A-Za-z0-9/:._-]*$/u
    });
    if (profile.evmNativeDenom !== profile.denom) {
      throw new Error(
        "profile.evmNativeDenom must match profile.denom for payable EVM deposits"
      );
    }
    validateEvmAuthorizationProfileConfig(profile);
    requiredProfileString(profile, "evmGasLimit", { pattern: /^0x[0-9a-fA-F]+$/u });
    requiredProfileString(profile, "evmSendGasLimit", { pattern: /^0x[0-9a-fA-F]+$/u });
  }
  return Object.freeze({
    ...profile,
    ...(profile.restEndpoints ? { restEndpoints: Object.freeze([...profile.restEndpoints]) } : {})
  });
}

/**
 * Fail-closed validator for the serializable BrowserWalletProfile contract,
 * including the transport-specific wallet and endpoint requirements.
 */
export function validateBrowserWalletProfile(profile) {
  return validateBrowserWalletProfileContract(profile);
}

/**
 * Validate and resolve the complete ClairveilWebClientConfig contract. The
 * browser client deliberately receives only the resulting active profile, so
 * this helper keeps profile selection and every deprecated flattened
 * compatibility field fail-closed.
 */
export function validateClairveilWebClientConfig(config) {
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    throw new Error("Clairveil Web client config must be an object");
  }
  assertExactProfileKeys(config, browserConfigKeys, "config");
  if (config.schemaVersion !== "clairveil-web-client-config-v1") {
    throw new Error("config.schemaVersion must be clairveil-web-client-config-v1");
  }
  requiredProfileString(config, "activeChainProfileId", {
    maxLength: 128,
    pattern: /^[A-Za-z0-9][A-Za-z0-9._-]*$/u
  });
  if (!Array.isArray(config.chainProfiles) || config.chainProfiles.length < 1) {
    throw new Error("config.chainProfiles must be a non-empty array");
  }
  const chainProfiles = config.chainProfiles.map((profile, index) => {
    try {
      return validateBrowserWalletProfile(profile);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`config.chainProfiles[${index}] is invalid: ${message}`);
    }
  });
  if (new Set(chainProfiles.map(profile => profile.id)).size !== chainProfiles.length) {
    throw new Error("config.chainProfiles must not contain duplicate profile IDs");
  }
  const activeProfile = chainProfiles.find(profile => profile.id === config.activeChainProfileId);
  if (!activeProfile) {
    throw new Error("config.activeChainProfileId must identify a configured chain profile");
  }
  for (const field of ["serverBacked", "localTestMode"]) {
    if (config[field] != null && typeof config[field] !== "boolean") {
      throw new Error(`config.${field} must be a boolean`);
    }
  }
  for (const field of ["modeLabel", "home", "localSignerHome", "localSignerBin"]) {
    if (config[field] != null && typeof config[field] !== "string") {
      throw new Error(`config.${field} must be a string`);
    }
  }
  if (config.serverFeatures != null) {
    if (!config.serverFeatures || typeof config.serverFeatures !== "object" || Array.isArray(config.serverFeatures)) {
      throw new Error("config.serverFeatures must be an object");
    }
    assertExactProfileKeys(config.serverFeatures, browserServerFeatureKeys, "config.serverFeatures");
    for (const [key, value] of Object.entries(config.serverFeatures)) {
      if (typeof value !== "boolean") throw new Error(`config.serverFeatures.${key} must be a boolean`);
    }
  }
  if (activeProfile.transport === "evm" && config.keplrChainInfo !== undefined) {
    throw new Error("config.keplrChainInfo is not permitted for an active EVM profile");
  }
  for (const field of browserConfigCompatibilityFields) {
    if (config[field] === undefined) continue;
    if (activeProfile[field] === undefined || !sameJsonValue(config[field], activeProfile[field])) {
      throw new Error(`config.${field} must match the active chain profile`);
    }
  }
  return Object.freeze({
    ...config,
    chainProfiles: Object.freeze(chainProfiles),
    ...(config.serverFeatures ? { serverFeatures: Object.freeze({ ...config.serverFeatures }) } : {}),
    activeProfile
  });
}

export function resolveActiveClairveilWebClientProfile(config) {
  return validateClairveilWebClientConfig(config).activeProfile;
}

function browserJsonReplacer(_key, value) {
  return typeof value === "bigint" ? value.toString() : value;
}

function normalizeTimeoutMs(value, label = "timeoutMs") {
  const timeoutMs = Number(value);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error(`${label} must be positive`);
  }
  return timeoutMs;
}

function normalizeResponseMaxBytes(value, label) {
  const maxBytes = Number(value);
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return maxBytes;
}

const maxHealthTreeDepth = 32;
const maxHealthTreeLeaves = 1n << BigInt(maxHealthTreeDepth);

function healthObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function healthAliasedValue(source, names, label, normalize) {
  const values = names
    .filter(name => source[name] !== undefined && source[name] !== null)
    .map(name => normalize(source[name]));
  if (!values.length) throw new Error(`${label} is required`);
  if (values.some(value => value !== values[0])) throw new Error(`${label} aliases disagree`);
  return values[0];
}

function healthUint64(value, label) {
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    throw new Error(`${label} must be a safe integer when supplied as a number`);
  }
  const text = typeof value === "bigint" ? value.toString() : String(value ?? "");
  if (!/^(0|[1-9][0-9]*)$/.test(text)) {
    throw new Error(`${label} must be a canonical uint64 decimal string`);
  }
  const parsed = BigInt(text);
  if (parsed > ((1n << 64n) - 1n)) throw new Error(`${label} must be a uint64`);
  return parsed;
}

function validateHealthStatus(response, expectedChainId) {
  const result = healthObject(healthObject(response, "node status response").result, "node status result");
  const nodeInfo = healthObject(result.node_info ?? result.nodeInfo, "node status node info");
  const network = String(nodeInfo.network ?? "").trim();
  if (!network) throw new Error("node status network is required");
  if (network !== expectedChainId) {
    throw new Error(`node status network ${network} does not match configured chain ID ${expectedChainId}`);
  }
  return result;
}

function validateHealthTreeState(response, { allowUninitializedTree = false } = {}) {
  const source = healthObject(response, "tree state response");
  const root = healthAliasedValue(source, ["root", "root_hex", "rootHex"], "tree state root", value => {
    const text = String(value ?? "").trim();
    if (!/^[0-9a-fA-F]{64}$/.test(text)) throw new Error("tree state root must be canonical 32-byte hex");
    return text.toLowerCase();
  });
  const leafCount = healthAliasedValue(source, ["leaf_count", "leafCount"], "tree state leaf count", value => healthUint64(value, "tree state leaf count"));
  const depth = healthAliasedValue(source, ["depth"], "tree state depth", value => {
    const text = String(value ?? "");
    if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error("tree state depth must be a canonical integer");
    const parsed = Number(text);
    if (!Number.isSafeInteger(parsed)) throw new Error("tree state depth must be a safe integer");
    return parsed;
  });
  const initialized = healthAliasedValue(source, ["initialized"], "tree state initialized", value => {
    if (typeof value !== "boolean") throw new Error("tree state initialized must be boolean");
    return value;
  });
  const maxLeaves = healthAliasedValue(source, ["max_leaves", "maxLeaves"], "tree state max leaves", value => healthUint64(value, "tree state max leaves"));
  const remainingLeaves = healthAliasedValue(source, ["remaining_leaves", "remainingLeaves"], "tree state remaining leaves", value => healthUint64(value, "tree state remaining leaves"));
  if (depth !== maxHealthTreeDepth) throw new Error(`tree state depth must be ${maxHealthTreeDepth}`);
  if (maxLeaves !== maxHealthTreeLeaves) throw new Error(`tree state max leaves must be ${maxHealthTreeLeaves}`);
  if (leafCount > maxLeaves || remainingLeaves !== maxLeaves - leafCount) {
    throw new Error("tree state leaf counts are inconsistent");
  }
  if (!initialized) {
    if (!allowUninitializedTree) throw new Error("tree state is not initialized");
    if (leafCount !== 0n) {
      throw new Error("an uninitialized tree state must have zero leaves");
    }
  }
  return Object.freeze({
    ...source,
    root,
    leaf_count: leafCount.toString(),
    depth,
    initialized,
    max_leaves: maxLeaves.toString(),
    remaining_leaves: remainingLeaves.toString()
  });
}

function auditTargetBindingFromBody(body = {}) {
  const values = [body.auditDisclosureTargetPubKeyHex, body.audit_disclosure_target_pubkey_hex]
    .filter(value => value !== undefined && value !== null)
    .map(value => String(value).trim().toLowerCase())
    .filter(Boolean);
  if (values.length > 1 && values.some(value => value !== values[0])) {
    throw new Error("auditDisclosureTargetPubKeyHex aliases conflict");
  }
  return values[0] || "";
}

function browserAliasedInputValue(body, camelName, snakeName, label, normalize = value => value) {
  return browserAliasedInputValues(body, [camelName, snakeName], label, normalize);
}

function browserAliasedInputValues(body, names, label, normalize = value => value) {
  const values = names
    .map(name => body?.[name])
    .filter(value => value !== undefined && value !== null);
  if (values.length > 1 && values.some(value => normalize(value) !== normalize(values[0]))) {
    throw new Error(`${label} aliases conflict`);
  }
  return values[0];
}

function canonicalBrowserAliasScalar(value) {
  return typeof value === "bigint" ? value.toString() : String(value).trim();
}

function canonicalBrowserTransferUnix(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("transfer time must be a non-negative safe integer");
  }
  return value;
}

function canonicalBrowserAliasHex(value) {
  return canonicalBrowserAliasScalar(value).replace(/^0x/i, "").toLowerCase();
}

function canonicalBrowserAliasBoolean(value) {
  return `${typeof value}:${String(value)}`;
}

function canonicalBrowserAliasReference(value) {
  return value;
}

function canonicalBrowserAliasFeeAmount(value) {
  if (!Array.isArray(value)) return JSON.stringify(value);
  return JSON.stringify(value.map(coin => ({
    denom: String(coin?.denom ?? "").trim(),
    amount: String(coin?.amount ?? "").trim()
  })).sort((left, right) => left.denom.localeCompare(right.denom)));
}

function hasEvmAuthorizationSignature(authorization) {
  const signature = authorization?.signature;
  if (signature == null) return false;
  if (typeof signature === "string") {
    const normalized = signature.trim().toLowerCase();
    return normalized !== "" && normalized !== "0x";
  }
  if (signature instanceof Uint8Array) return signature.length > 0;
  return true;
}

async function fetchJson(url, options = {}) {
  const { timeoutMs = defaultFetchTimeoutMs, ...fetchOptions } = options;
  const resolvedTimeoutMs = normalizeTimeoutMs(timeoutMs, "fetch timeoutMs");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), resolvedTimeoutMs);
  if (fetchOptions.signal) {
    if (fetchOptions.signal.aborted) {
      controller.abort();
    } else {
      fetchOptions.signal.addEventListener("abort", () => controller.abort(), { once: true });
    }
  }
  try {
    const response = await fetch(url, {
      ...fetchOptions,
      headers: {
        accept: "application/json",
        ...(fetchOptions.body ? { "content-type": "application/json" } : {}),
        ...(fetchOptions.headers || {})
      },
      signal: controller.signal
    });
    const text = await response.text();
    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = { error: text };
      }
    }
    if (!response.ok || data?.error) {
      const message = data?.error?.message || data?.error || response.statusText;
      throw new Error(message);
    }
    return data;
  } catch (error) {
    if (error?.name === "AbortError") {
      const timeoutError = new Error(`fetch request timed out after ${resolvedTimeoutMs}ms`);
      timeoutError.code = "FETCH_TIMEOUT";
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function privacyEventsQuery({
  afterHeight,
  after_height,
  afterSequence,
  after_sequence,
  page,
  limit,
  eventTypes,
  event_types
} = {}) {
  const params = new URLSearchParams();
  const resolvedAfterHeight = afterHeight ?? after_height;
  if (resolvedAfterHeight != null) params.set("after_height", String(resolvedAfterHeight));
  const resolvedAfterSequence = afterSequence ?? after_sequence;
  if (resolvedAfterSequence != null) params.set("after_sequence", String(resolvedAfterSequence));
  if (page != null) params.set("page", String(page));
  if (limit != null) params.set("limit", String(limit));
  const resolvedEventTypes = eventTypes ?? event_types;
  if (Array.isArray(resolvedEventTypes)) {
    for (const eventType of resolvedEventTypes) {
      if (String(eventType || "").trim()) params.append("event_types", String(eventType).trim());
    }
  } else if (resolvedEventTypes != null && String(resolvedEventTypes).trim()) {
    params.set("event_types", String(resolvedEventTypes).trim());
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

function walletTypeFromBody(body = {}, fallback = "cosmos") {
  const walletType = body.walletType ?? body.wallet_type ?? fallback;
  if (walletType === "cosmos" || walletType === "evm") return walletType;
  throw new ClairveilError(
    ClairveilErrorCode.INVALID_ARGUMENT,
    `unsupported wallet type: ${String(walletType)}`
  );
}

function normalizedEvmChainId(value, label = "evmChainId") {
  const raw = String(value ?? "").trim();
  if (!raw) throw new Error(`${label} is required`);
  try {
    const chainId = BigInt(raw);
    if (chainId < 0n) throw new Error();
    return `0x${chainId.toString(16)}`;
  } catch {
    throw new Error(`${label} must be a non-negative EVM quantity`);
  }
}

function profileBoundEvmTransaction(transaction, chainId, defaultGas) {
  const configuredChainId = normalizedEvmChainId(chainId);
  if (transaction?.chainId != null &&
      normalizedEvmChainId(transaction.chainId, "prepared EVM transaction chainId") !== configuredChainId) {
    throw new Error("prepared EVM transaction chainId does not match the active profile");
  }
  return {
    ...transaction,
    chainId: configuredChainId,
    ...(transaction?.gas == null && defaultGas != null ? { gas: defaultGas } : {})
  };
}

function deferredProverAdapter(resolveAdapter, methodName) {
  let resolved = null;
  return {
    async [methodName](...args) {
      resolved ??= resolveAdapter();
      const method = resolved?.[methodName];
      if (typeof method !== "function") {
        throw new Error(`proverAdapter.${methodName} is required`);
      }
      return method.apply(resolved, args);
    }
  };
}

function addIfPresent(target, key, value) {
  if (value != null) {
    target[key] = value;
  }
}

function evmReceiptStatusKind(status) {
  if (typeof status === "number") {
    if (status === 1) return "success";
    if (status === 0) return "failure";
    return "unknown";
  }
  if (typeof status === "bigint") {
    if (status === 1n) return "success";
    if (status === 0n) return "failure";
    return "unknown";
  }
  if (typeof status !== "string") return "unknown";
  const normalized = status.trim().toLowerCase();
  if (/^0x0*1$/.test(normalized)) return "success";
  if (/^0x0+$/.test(normalized)) return "failure";
  return "unknown";
}

function normalizedBrowserEvmTransactionHash(value, label = "EVM transaction hash") {
  const clean = String(value ?? "").trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error(`${label} must be a 32-byte hex value`);
  }
  return `0x${clean}`;
}

function scanOptionsFromBody(body = {}) {
  const scan = body.scan || {};
  return {
    after: scan.after ?? body.scanAfter ?? body.scan_after ?? body.after,
    afterHeight: scan.afterHeight ?? scan.after_height ?? body.scanAfterHeight ?? body.scan_after_height ?? body.afterHeight ?? body.after_height,
    afterSequence: scan.afterSequence ?? scan.after_sequence ?? body.scanAfterSequence ?? body.scan_after_sequence ?? body.afterSequence ?? body.after_sequence,
    page: scan.page ?? body.scanPage ?? body.scan_page ?? body.page,
    limit: scan.limit ?? body.scanLimit ?? body.scan_limit ?? body.limit,
    maxPages: scan.maxPages ?? scan.max_pages ?? body.scanMaxPages ?? body.scan_max_pages ?? body.maxPages ?? body.max_pages,
    eventTypes: scan.eventTypes ?? scan.event_types ?? body.eventTypes ?? body.event_types,
    outputLimit: scan.outputLimit ?? scan.output_limit ?? body.outputLimit ?? body.output_limit,
    eventLimit: scan.eventLimit ?? scan.event_limit ?? body.eventLimit ?? body.event_limit,
    maxEncodedBytes: scan.maxEncodedBytes ?? scan.max_encoded_bytes ?? body.maxEncodedBytes ?? body.max_encoded_bytes,
    validationStateSnapshot: scan.validationStateSnapshot ?? scan.validation_state_snapshot ?? body.validationStateSnapshot ?? body.validation_state_snapshot,
    scanSource: scan.scanSource ?? scan.scan_source ?? body.scanSource ?? body.scan_source,
    strictPrivacyScan: scan.strictPrivacyScan
      ?? scan.strict_privacy_scan
      ?? body.strictPrivacyScan
      ?? body.strict_privacy_scan
  };
}

function typedWalletScanOptionsFromBody(body = {}) {
  const scan = body.scan || {};
  const eventTypeAliases = [
    scan.eventTypes,
    scan.event_types,
    body.eventTypes,
    body.event_types
  ].filter(value => value !== undefined && value !== null);
  for (const eventTypes of eventTypeAliases) {
    if (!Array.isArray(eventTypes)) {
      throw new Error("wallet and spend scan eventTypes must be an array");
    }
    if (eventTypes.length > 0) {
      throw new Error("wallet and spend scans must not filter event types; typed privacy_scan summaries are required");
    }
  }

  const sourceAliases = [
    scan.scanSource,
    scan.scan_source,
    body.scanSource,
    body.scan_source
  ].filter(value => value !== undefined && value !== null);
  for (const source of sourceAliases) {
    if (String(source).trim().toLowerCase() !== "privacy_scan") {
      throw new Error("wallet and spend scans only support the typed privacy_scan source");
    }
  }

  const strictAliases = [
    scan.strictPrivacyScan,
    scan.strict_privacy_scan,
    body.strictPrivacyScan,
    body.strict_privacy_scan
  ].filter(value => value !== undefined && value !== null);
  if (strictAliases.some(value => value !== true)) {
    throw new Error("wallet and spend scans require strictPrivacyScan=true");
  }

  return {
    ...scanOptionsFromBody(body),
    scanSource: "privacy_scan",
    strictPrivacyScan: true
  };
}

function relayChainNowUnixFromBody(body = {}) {
  return body.chainNowUnix
    ?? body.chain_now_unix
    ?? body.nowUnix
    ?? body.now_unix;
}

function withdrawProofReadyMetadata(built, context = {}) {
  const expiresAtUnix = String(
    built?.payload?.expires_at_unix ||
    built?.payload?.expiresAtUnix ||
    built?.proverPayload?.expires_at_unix ||
    built?.proverPayload?.expiresAtUnix ||
    ""
  );
  return {
    payloadHash: built?.payload?.payload_hash || built?.proverPayload?.payload_hash || "",
    txBytesHash: context.txBytesHash ?? context.tx_bytes_hash ?? "",
    metadata: expiresAtUnix ? { payload_expires_at_unix: expiresAtUnix } : {}
  };
}

async function markReservationReplanRequired(reservationManager, reservation, error, reason) {
  if (!reservationManager || !reservation?.reservation_ids?.length) return [];
  if (typeof reservationManager.markReplanRequired !== "function") {
    throw new Error("reservationManager.markReplanRequired is required");
  }
  return reservationManager.markReplanRequired(reservation.reservation_ids, {
    leaseToken: reservation.lease_token || reservation.reservations?.[0]?.lease_token || "",
    error: reason,
    metadata: {
      reconcile_reason: reason,
      no_broadcast_attempt: true,
      proof_discarded: true
    }
  });
}

async function replanProofReadyReservationPreservingError(reservationManager, reservation, error, reason) {
  try {
    await markReservationReplanRequired(reservationManager, reservation, error, reason);
  } catch (cleanupError) {
    appendReservationCleanupErrors(error, [cleanupError]);
  }
}

function positiveCoinForDenom(amount, denom, label) {
  const coin = parseCoin(amount, denom);
  if (coin.denom !== denom) {
    throw new Error(`${label} denom must be ${denom}, got ${coin.denom}`);
  }
  if (BigInt(coin.amount) <= 0n) {
    throw new Error(`${label} amount must be greater than 0.`);
  }
  return coin;
}

function txEventAttribute(event, key) {
  return (event?.attributes || []).find(attribute => attribute.key === key)?.value || "";
}

function txEventsOfType(tx, type) {
  return (tx?.tx_result?.events || tx?.events || []).filter(event => event.type === type);
}

function firstTxEventOfType(tx, type) {
  return txEventsOfType(tx, type)[0] || null;
}

function txMessageAction(tx) {
  return txEventsOfType(tx, "message")
    .map(event => txEventAttribute(event, "action"))
    .find(Boolean) || "";
}

function evmFailureFromTx(tx) {
  return txEventsOfType(tx, "ethereum_tx")
    .map(event => txEventAttribute(event, "ethereumTxFailed"))
    .find(Boolean) || "";
}

function blockEventType(tx) {
  const action = txMessageAction(tx);
  const evmFailure = evmFailureFromTx(tx);
  if (action === "/cosmos.bank.v1beta1.MsgSend") return "bank send";
  if (action === "/clairveil.privacy.v1.MsgDeposit") return "privacy deposit";
  if (action === "/clairveil.privacy.v1.MsgBatchTransfer") return "privacy batch transfer";
  if (action === "/clairveil.privacy.v1.MsgTransfer") return "privacy transfer";
  if (action === "/clairveil.privacy.v1.MsgWithdraw") return "privacy withdraw";
  if (action === "/cosmos.evm.vm.v1.MsgEthereumTx" && evmFailure) return "ethereumtx failed";
  return action ? action.split(".").pop()?.replace(/^Msg/, "").toLowerCase() || "tx" : "tx";
}

function blockEventSummary(tx) {
  const transfer = firstTxEventOfType(tx, "transfer");
  const spent = firstTxEventOfType(tx, "coin_spent");
  const received = firstTxEventOfType(tx, "coin_received");
  const shieldedTransfer = firstTxEventOfType(tx, "shielded_transfer");
  const deposit = firstTxEventOfType(tx, "shielded_deposit") || firstTxEventOfType(tx, "deposit");
  const withdraw = firstTxEventOfType(tx, "shielded_withdraw") || firstTxEventOfType(tx, "withdraw");
  const messageSender = txEventsOfType(tx, "message")
    .map(event => txEventAttribute(event, "sender"))
    .find(Boolean);

  return {
    action: txMessageAction(tx),
    amount: txEventAttribute(transfer, "amount") || txEventAttribute(spent, "amount") || txEventAttribute(received, "amount"),
    from: txEventAttribute(transfer, "sender") || txEventAttribute(spent, "spender") || txEventAttribute(shieldedTransfer, "relayer") || messageSender,
    to: txEventAttribute(transfer, "recipient") || txEventAttribute(received, "receiver") || txEventAttribute(withdraw, "recipient"),
    commitment: txEventAttribute(deposit, "commitment") || txEventAttribute(shieldedTransfer, "commitment_1") || txEventAttribute(withdraw, "commitment"),
    disclosureTarget: txEventAttribute(shieldedTransfer, "user_disclosure_target_pubkey") || txEventAttribute(shieldedTransfer, "audit_disclosure_target_pubkey"),
    evmFailure: evmFailureFromTx(tx)
  };
}

function plannerError(result) {
  const error = new ClairveilError(
    plannerStatusToErrorCode(result?.status),
    result?.plan?.message || `privacy transaction is not ready: ${result?.status || "unknown"}`,
    {
      status: result?.status || "",
      plan: result?.plan || null,
      prepared: result?.prepared || null
    }
  );
  error.status = error.details.status;
  error.plan = error.details.plan;
  error.prepared = error.details.prepared;
  return error;
}

function asBytesBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.slice(i, i + 0x8000));
  }
  return btoa(binary);
}

export class ClairveilBrowserClient {
  constructor({
    profile,
    transport,
    walletType,
    rpc,
    rest,
    restEndpoints,
    chainId,
    accountPrefix,
    shieldedPrefix,
    denom,
    proverUrl,
    proverAdapter,
    proverBearerToken,
    proverTimeoutMs = 120000,
    depositProofUrl,
    depositProofProvider,
    depositProofTimeoutMs = defaultDepositProofTimeoutMs,
    depositProofResponseMaxBytes = defaultProverResponseMaxBytes,
    queryTimeoutMs = defaultFetchTimeoutMs,
    fetchTimeoutMs,
    queryRetry,
    nullifierFailover,
    merklePathFailover,
    privacyStateAdapter,
    enableExperimentalBatchTransfer = false,
    enable_experimental_batch_transfer,
    evmRpc,
    evmChainId,
    evmPrivacyPrecompileAddress,
    evmDepositMode = defaultEvmDepositMode,
    evmNativeDenom,
    evmAuthorizationProfile,
    evmContractAdapter,
    evmFinalityPolicy,
    evmGasLimit = "0x989680",
    evmSendGasLimit = "0x5208"
  } = {}) {
    const hasProfile = profile !== undefined && profile !== null;
    const resolved = hasProfile
      ? validateBrowserWalletProfileContract(profile, {
          allowMissingEvmCosmosEndpoints: privacyStateAdapter != null
        })
      : {};
    this.profile = resolved;
    const directTransport = transport ?? walletType ?? null;
    this.profileTransport = hasProfile
      ? walletTypeFromBody({}, resolved.transport)
      : directTransport == null ? null : walletTypeFromBody({}, directTransport);
    this.defaultWalletType = this.profileTransport || walletTypeFromBody({}, "cosmos");
    // A validated profile is the sole source of chain transport and endpoint
    // values. Keeping top-level fallbacks here would let a caller silently
    // compose one profile with a different network.
    this.rpc = normalizeRpcEndpoint(hasProfile ? resolved.rpc : rpc);
    this.restEndpoints = normalizeRestEndpoints(
      hasProfile ? resolved.rest : rest,
      hasProfile ? resolved.restEndpoints : restEndpoints,
      { allowEmpty: privacyStateAdapter != null }
    );
    this.rest = this.restEndpoints[0] || "";
    this.chainId = hasProfile ? resolved.chainId : chainId;
    this.accountPrefix = (hasProfile ? resolved.accountPrefix : accountPrefix) || "clair";
    this.shieldedPrefix = (hasProfile ? resolved.shieldedPrefix : shieldedPrefix) || `${this.accountPrefix}s`;
    this.denom = (hasProfile ? resolved.denom : denom) || "uclair";
    this.proverUrl = trimTrailingSlash(hasProfile ? resolved.proverUrl || "" : proverUrl || "");
    this.configuredProverAdapter = proverAdapter || null;
    this.proverBearerToken = String(proverBearerToken || "").trim();
    this.proverTimeoutMs = proverTimeoutMs;
    // Deposit proof traffic is a distinct privacy boundary from the transfer
    // prover. A validated profile may pin one exact endpoint; never inherit or
    // derive it from proverUrl.
    this.depositProofUrl = String(hasProfile ? resolved.depositProofUrl || "" : depositProofUrl || "").trim();
    this.configuredDepositProofProvider = depositProofProvider || null;
    this.depositProofTimeoutMs = normalizeTimeoutMs(depositProofTimeoutMs, "depositProofTimeoutMs");
    this.depositProofResponseMaxBytes = normalizeResponseMaxBytes(
      depositProofResponseMaxBytes,
      "depositProofResponseMaxBytes"
    );
    this.queryTimeoutMs = normalizeTimeoutMs(fetchTimeoutMs ?? queryTimeoutMs, "queryTimeoutMs");
    this.evmRpc = hasProfile ? resolved.evmRpc || "" : evmRpc || "";
    this.evmChainId = hasProfile ? resolved.evmChainId || "" : evmChainId || "";
    this.evmDepositMode = normalizeEvmDepositMode(
      hasProfile ? resolved.evmDepositMode ?? defaultEvmDepositMode : evmDepositMode
    );
    this.evmNativeDenom = String(
      hasProfile ? resolved.evmNativeDenom || this.denom : evmNativeDenom || this.denom
    ).trim();
    const configuredEvmAuthorizationProfile = hasProfile
      ? resolved.evmAuthorizationProfile ?? null
      : evmAuthorizationProfile ?? null;
    this.evmAuthorizationProfile = configuredEvmAuthorizationProfile == null
      ? null
      : createEvmAuthorizationProfile(configuredEvmAuthorizationProfile);
    this.evmFinalityPolicy = evmFinalityPolicy == null
      ? null
      : createEvmFinalityPolicy(evmFinalityPolicy);
    if (this.evmDepositMode === evmDepositModePayableExactValue &&
        this.evmNativeDenom !== this.denom) {
      throw new Error("evmNativeDenom must match denom for payable EVM deposits");
    }
    this.evmGasLimit = hasProfile ? resolved.evmGasLimit || "0x989680" : evmGasLimit;
    this.evmSendGasLimit = hasProfile ? resolved.evmSendGasLimit || "0x5208" : evmSendGasLimit;
    this.cosmos = createClairveilClient({
      rpc: this.rpc,
      rest: this.rest,
      chainId: this.chainId,
      accountPrefix: this.accountPrefix,
      shieldedPrefix: this.shieldedPrefix,
      defaultDenom: this.denom,
      restEndpoints: this.restEndpoints,
      queryTimeoutMs: this.queryTimeoutMs,
      queryRetry,
      nullifierFailover,
      merklePathFailover,
      privacyStateAdapter,
      // This is an explicit caller opt-in, not a chain endpoint or identity
      // field. It must remain usable with a strict active profile; product
      // code still decides whether to pass it after validating its
      // serverFeatures.batchTransfer policy.
      enableExperimentalBatchTransfer: enable_experimental_batch_transfer
        ?? enableExperimentalBatchTransfer
    });
    const configuredEvmContractAddress = hasProfile
      ? resolved.evmPrivacyPrecompileAddress
      : evmPrivacyPrecompileAddress;
    const hasEvmContract = Boolean(
      String(configuredEvmContractAddress ?? "").trim() || evmContractAdapter
    );
    if (this.profileTransport === "evm" && !hasEvmContract) {
      throw new Error(
        "EVM browser client requires evmPrivacyPrecompileAddress or evmContractAdapter.contractAddress"
      );
    }
    this.evm = hasEvmContract
      ? createClairveilEvmClient({
          contractAddress: configuredEvmContractAddress,
          chainId: this.chainId,
          evmChainId: this.evmChainId,
          accountPrefix: this.accountPrefix,
          shieldedPrefix: this.shieldedPrefix,
          defaultDenom: this.denom,
          depositMode: this.evmDepositMode,
          nativeDenom: this.evmNativeDenom,
          authorizationProfile: this.evmAuthorizationProfile,
          contractAdapter: evmContractAdapter
        })
      : null;
    this.privacyStateAdapter = this.cosmos.privacyStateAdapter;
  }

  restUrl(path) {
    if (!this.rest) throw new Error("rest endpoint is not configured; use PrivacyStateAdapter-backed privacy queries");
    return `${this.rest}${path.startsWith("/") ? path : `/${path}`}`;
  }

  rpcUrl(path) {
    if (!this.rpc) throw new Error("rpc endpoint is not configured for Cosmos queries");
    return `${this.rpc}${path.startsWith("/") ? path : `/${path}`}`;
  }

  fetchJson(url, options = {}) {
    return fetchJson(url, { timeoutMs: this.queryTimeoutMs, ...options });
  }

  proverAdapter(adapter = null) {
    if (adapter) return adapter;
    if (this.configuredProverAdapter) return this.configuredProverAdapter;
    if (!this.proverUrl) {
      throw new ClairveilError(
        ClairveilErrorCode.PROVER_UNAVAILABLE,
        "proverUrl is required for transfer and withdraw proof generation"
      );
    }
    return createHttpProverAdapter({
      baseURL: this.proverUrl,
      bearerToken: this.proverBearerToken,
      timeoutMs: this.proverTimeoutMs
    });
  }

  /**
   * Resolve a DepositCircuit provider without ever treating the main prover
   * base URL as a deposit endpoint. Local/WASM callers can inject a provider;
   * otherwise the exact profile URL receives a bounded, strict HTTP request.
   */
  depositProofProvider(provider = null) {
    if (provider) return provider;
    if (this.configuredDepositProofProvider) return this.configuredDepositProofProvider;
    if (!this.depositProofUrl) return null;
    return createHttpDepositProofProvider({
      url: this.depositProofUrl,
      timeoutMs: this.depositProofTimeoutMs,
      maxResponseBytes: this.depositProofResponseMaxBytes
    });
  }

  async health({ allowUninitializedTree = false } = {}) {
    try {
      const [status, tree, audit] = await Promise.all([
        this.rpc
          ? this.fetchJson(this.rpcUrl("/status")).then(value => validateHealthStatus(value, this.chainId))
          : this.profileTransport === "evm"
            ? this.assertEvmNetwork().then(evmChainId => Object.freeze({
                transport: "evm",
                chainId: this.chainId,
                evmChainId
              }))
            : Promise.reject(new Error("Cosmos RPC endpoint is required for browser health")),
        this.cosmos.fetchTreeState(),
        this.cosmos.queryAuditConfig()
      ]);
      return {
        status,
        tree: validateHealthTreeState(tree, { allowUninitializedTree }),
        audit,
        errors: []
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`browser health check failed: ${message}`);
    }
  }

  async fetchBlockEvents(rawLimit = 30) {
    const limit = Math.min(Math.max(Number.parseInt(rawLimit, 10) || 30, 1), 50);
    const url = new URL(this.rpcUrl("/tx_search"));
    url.searchParams.set("query", "\"tx.height>=1\"");
    url.searchParams.set("prove", "false");
    url.searchParams.set("page", "1");
    url.searchParams.set("per_page", String(limit));
    url.searchParams.set("order_by", "\"desc\"");

    const data = await this.fetchJson(url);
    return {
      events: (data.result?.txs || []).map(tx => ({
        type: blockEventType(tx),
        height: tx.height,
        tx_hash_hex: tx.hash,
        code: Number(tx.tx_result?.code ?? tx.code ?? 0),
        gas_used: tx.tx_result?.gas_used || "",
        gas_wanted: tx.tx_result?.gas_wanted || "",
        summary: blockEventSummary(tx)
      }))
    };
  }

  async fetchPrivacyEvents(options = {}) {
    return this.cosmos.fetchPrivacyEvents(options);
  }

  async fetchScanEvents(options = {}) {
    return this.cosmos.fetchScanEvents(options);
  }

  async queryPrivacyScan(options = {}) {
    return this.cosmos.queryPrivacyScan(options);
  }

  async fetchAuditableTransfers(options = {}) {
    return this.cosmos.fetchAuditableTransfers(options);
  }

  async fetchAuditableBatchTransfers(options = {}) {
    return this.cosmos.fetchAuditableBatchTransfers(options);
  }

  async fetchAuditConfig() {
    return this.cosmos.fetchAuditConfig();
  }

  async fetchDisclosureConfig() {
    return this.cosmos.fetchDisclosureConfig();
  }

  async queryAuditConfig() {
    return this.cosmos.queryAuditConfig();
  }

  async queryDisclosureConfig() {
    return this.cosmos.queryDisclosureConfig();
  }

  /** Fetch and fail-closed validate the active consensus circuit set. */
  async fetchCircuitConfig(options) {
    return this.cosmos.fetchCircuitConfig(options);
  }

  /** Assert the browser profile is using the active consensus circuit set. */
  async assertCircuitConfig(options) {
    return this.cosmos.assertCircuitConfig(options);
  }

  async fetchReserve(denom) {
    return this.cosmos.fetchReserve(denom);
  }

  async queryReserve(denom) {
    return this.cosmos.queryReserve(denom);
  }

  async fetchAssetByDenom(denom) {
    return this.cosmos.fetchAssetByDenom(denom);
  }

  async fetchAssetByID(assetIdHex) {
    return this.cosmos.fetchAssetByID(assetIdHex);
  }

  async queryAssetByDenom(denom) {
    return this.cosmos.queryAssetByDenom(denom);
  }

  async queryAssetByID(assetIdHex) {
    return this.cosmos.queryAssetByID(assetIdHex);
  }

  async resolveAsset(denom) {
    return this.cosmos.resolveAsset(denom);
  }

  async resolveAssetByDenom(denom) {
    return this.cosmos.resolveAssetByDenom(denom);
  }

  async resolveAssetByID(assetIdHex) {
    return this.cosmos.resolveAssetByID(assetIdHex);
  }

  async assertProtocolPreflight(denom) {
    return this.cosmos.assertProtocolPreflight(denom);
  }

  /**
   * Read and validate all immutable protocol settings required by ordinary
   * single-transfer browser flows before constructing a proof request.
   */
  async assertTransferProtocolConfig(denom) {
    return this.cosmos.assertTransferProtocolConfig(denom);
  }

  async fetchTreeState() {
    return this.cosmos.fetchTreeState();
  }

  async fetchCommitmentInfo(commitmentHex) {
    return this.cosmos.fetchCommitmentInfo(commitmentHex);
  }

  async lookupMerklePath(commitmentHex) {
    return this.cosmos.lookupMerklePath(commitmentHex);
  }

  async fetchCommitmentPathsAtRoot(options) {
    return this.cosmos.fetchCommitmentPathsAtRoot(options);
  }

  async queryCommitmentPathsAtRoot(options) {
    return this.cosmos.queryCommitmentPathsAtRoot(options);
  }

  async createCommitmentPathSnapshotProvider(options) {
    return this.cosmos.createCommitmentPathSnapshotProvider(options);
  }

  buildRootSigningMessage(address, pubKeyHex) {
    return buildRootSigningMessage(address, pubKeyHex);
  }

  verifySignerPubKey(address, pubKeyHex) {
    return verifySignerPubKey(address, pubKeyHex, this.accountPrefix);
  }

  evmAccountIdentity(value) {
    const evmAddress = normalizeEvmAddress(value, "EVM account");
    return {
      evmAddress,
      address: evmAddressToBech32(evmAddress, this.accountPrefix),
      pubKeyHex: evmAddress.slice(2)
    };
  }

  derivePrivacyAccount(input) {
    return this.cosmos.derivePrivacyAccount(input);
  }

  walletTypeFromBody(body = {}) {
    const walletType = walletTypeFromBody(body, this.defaultWalletType);
    if (this.profileTransport && walletType !== this.profileTransport) {
      throw new ClairveilError(
        ClairveilErrorCode.INVALID_ARGUMENT,
        `wallet type ${walletType} does not match active profile transport ${this.profileTransport}`
      );
    }
    return walletType;
  }

  privacyMaterial(body, walletType = this.walletTypeFromBody(body)) {
    const material = derivePrivacyMaterial({
      address: body.address,
      pubKeyHex: body.pubKeyHex ?? body.pub_key_hex,
      signatureBase64: body.signatureBase64 ?? body.signature_base64,
      shieldedPrefix: this.shieldedPrefix
    });
    if (walletType !== "evm") {
      assertSignerPubKey(material.address, material.pubKeyHex, this.accountPrefix);
    }
    return material;
  }

  async getBalances(address) {
    return this.cosmos.fetchJson(`/cosmos/bank/v1beta1/balances/${address}`, { failover: true });
  }

  async waitForTx(txHash, options) {
    return this.cosmos.waitForTx(txHash, options);
  }

  async confirmDeposit(input) {
    return this.cosmos.confirmDeposit(input);
  }

  async waitForEvmReceipt(txHash, { attempts = 30, intervalMs = 1000 } = {}) {
    const hash = normalizedBrowserEvmTransactionHash(txHash);
    for (let i = 0; i < attempts; i += 1) {
      const receipt = await this.evmJsonRpc("eth_getTransactionReceipt", [hash]);
      if (receipt) return receipt;
      await new Promise(resolve => setTimeout(resolve, intervalMs));
    }
    return null;
  }

  async evmJsonRpc(method, params = []) {
    const readOnlyMethod = assertReadOnlyEvmJsonRpcMethod(method);
    const evmRpc = String(this.evmRpc || "").trim();
    if (!evmRpc) {
      throw new Error("evmRpc is required for EVM JSON-RPC queries");
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.queryTimeoutMs);
    try {
      const response = await fetch(evmRpc, {
        method: "POST",
        headers: { "content-type": "application/json" },
        signal: controller.signal,
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: Date.now(),
          method: readOnlyMethod,
          params
        })
      });
      const data = await response.json();
      if (!response.ok) {
        const message = data?.error?.message || data?.message || response.statusText || `HTTP ${response.status}`;
        throw new Error(`EVM RPC ${readOnlyMethod} failed: ${message}`);
      }
      if (data?.error) {
        throw new Error(data.error.message || `EVM RPC ${readOnlyMethod} failed`);
      }
      return data?.result;
    } catch (error) {
      if (error?.name === "AbortError") {
        throw new Error(`EVM RPC ${readOnlyMethod} timed out after ${this.queryTimeoutMs}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  /** Verify the configured read-only EVM RPC is the exact network in the active EVM profile. */
  async assertEvmNetwork() {
    if (this.profileTransport !== "evm") return null;
    const expectedChainId = normalizedEvmChainId(this.evmChainId);
    const actualChainId = normalizedEvmChainId(
      await this.evmJsonRpc("eth_chainId"),
      "EVM RPC eth_chainId result"
    );
    if (actualChainId !== expectedChainId) {
      throw new Error(`EVM RPC chain ID ${actualChainId} does not match configured evmChainId ${expectedChainId}`);
    }
    return actualChainId;
  }

  /**
   * Verify the connected signing wallet, separately from the read-only RPC.
   * The check deliberately happens before EVM preparation so a wrong-wallet
   * request never reaches a prover or produces a stale prepared artifact.
   */
  async assertEvmWalletNetwork(wallet) {
    if (this.profileTransport !== "evm") return null;
    if (!wallet || typeof wallet.getChainId !== "function") {
      throw new Error("EVM preparation requires an evmWallet with getChainId()");
    }
    const expectedChainId = normalizedEvmChainId(this.evmChainId);
    const actualChainId = normalizedEvmChainId(
      await wallet.getChainId(),
      "EVM wallet chain ID"
    );
    if (actualChainId !== expectedChainId) {
      throw new Error(`EVM wallet chain ID ${actualChainId} does not match configured evmChainId ${expectedChainId}`);
    }
    return actualChainId;
  }

  evmWalletFromBody(body = {}) {
    const camel = body.evmWallet;
    const snake = body.evm_wallet;
    if (camel != null && snake != null && camel !== snake) {
      throw new Error("evmWallet aliases conflict");
    }
    return camel ?? snake ?? null;
  }

  async assertEvmPreparationNetwork(body = {}) {
    if (!this.evm) {
      throw new Error("EVM privacy contract is not configured");
    }
    await Promise.all([
      this.assertEvmNetwork(),
      this.assertEvmWalletNetwork(this.evmWalletFromBody(body))
    ]);
  }

  async waitForEvmTransaction(txHash, {
    privacyTransaction,
    sender,
    attempts,
    intervalMs,
    finalityPolicy
  } = {}) {
    if (!this.evm) {
      throw new Error("EVM privacy contract is not configured");
    }
    if (!privacyTransaction) {
      throw new Error("waitForEvmTransaction requires the original SDK-prepared privacyTransaction");
    }
    if (!sender) {
      throw new Error("waitForEvmTransaction requires the actual EVM sender");
    }
    const evmTxHash = normalizedBrowserEvmTransactionHash(txHash);
    const txBytesHash = evmTransactionBindingHash(privacyTransaction);
    const receipt = await this.waitForEvmReceipt(evmTxHash, {
      ...(attempts == null ? {} : { attempts }),
      ...(intervalMs == null ? {} : { intervalMs })
    });
    if (!receipt) {
      const error = `EVM tx was broadcast but receipt was not found yet: ${evmTxHash}`;
      return {
        executionTransport: "evm",
        txHash: evmTxHash.slice(2).toUpperCase(),
        evmTxHash,
        txBytesHash,
        receipt: null,
        tx: null,
        transactionVerification: null,
        privacyReceipt: null,
        finality: null,
        evmTransactionVerified: false,
        evmPrivacyReceiptVerified: false,
        evmFinalityVerified: false,
        ok: false,
        error,
        errors: [error]
      };
    }

    const [tx, actualChainId] = await Promise.all([
      this.evmJsonRpc("eth_getTransactionByHash", [evmTxHash]),
      this.evmJsonRpc("eth_chainId")
    ]);
    const errors = [];
    const receiptStatus = evmReceiptStatusKind(receipt.status);
    const receiptSucceeded = receiptStatus === "success";
    if (!receiptSucceeded) {
      errors.push(receiptStatus === "failure"
        ? `EVM tx failed with receipt status ${String(receipt.status)}`
        : `EVM tx did not include an explicit successful receipt status: ${String(receipt.status ?? "missing")}`);
    }
    try {
      if (normalizedBrowserEvmTransactionHash(
        receipt.transactionHash,
        "EVM receipt transaction hash"
      ) !== evmTxHash) {
        throw new Error("EVM receipt transaction hash does not match the requested transaction");
      }
    } catch (error) {
      errors.push(String(error?.message || error));
    }

    let transactionVerification = null;
    try {
      transactionVerification = this.evm.verifyTransactionIdentity({
        transaction: privacyTransaction,
        rpcTransaction: tx,
        txHash: evmTxHash,
        sender,
        expectedChainId: this.evmChainId,
        actualChainId
      });
    } catch (error) {
      errors.push(String(error?.message || error || "EVM transaction identity mismatch"));
    }

    let privacyReceipt = null;
    if (receiptSucceeded) {
      try {
        privacyReceipt = this.evm.verifyPrivacyReceipt({
          transaction: privacyTransaction,
          receipt,
          sender
        });
      } catch (error) {
        errors.push(String(error?.message || error || "privacy receipt evidence mismatch"));
      }
    }
    let finality = null;
    if (receiptSucceeded) {
      const resolvedFinalityPolicy = finalityPolicy ?? this.evmFinalityPolicy;
      if (resolvedFinalityPolicy == null) {
        errors.push(
          "EVM finality policy is required; configure confirmations, safe, finalized, custom, or explicitly opt into low-finality receipt mode"
        );
      } else {
        finality = await waitForEvmFinality({
          txHash: evmTxHash,
          receipt,
          rpc: (method, params) => this.evmJsonRpc(method, params),
          policy: resolvedFinalityPolicy,
          ...(attempts == null ? {} : { attempts }),
          ...(intervalMs == null ? {} : { intervalMs })
        });
        if (finality.verified !== true) {
          errors.push(finality.error || "EVM finality policy did not verify the transaction");
        }
      }
    }
    const uniqueErrors = [...new Set(errors)];
    const evmTransactionVerified = transactionVerification?.verified === true;
    const evmPrivacyReceiptVerified = privacyReceipt?.verified === true;
    const evmFinalityVerified = finality?.verified === true;
    const ok = receiptSucceeded &&
      evmTransactionVerified &&
      evmPrivacyReceiptVerified &&
      evmFinalityVerified &&
      uniqueErrors.length === 0;
    return {
      executionTransport: "evm",
      txHash: evmTxHash.slice(2).toUpperCase(),
      evmTxHash,
      txBytesHash,
      receipt,
      tx,
      transactionVerification,
      privacyReceipt,
      finality,
      evmTransactionVerified,
      evmPrivacyReceiptVerified,
      evmFinalityVerified,
      ok,
      error: uniqueErrors[0] || "",
      errors: uniqueErrors
    };
  }

  evmNativeSendTransaction({ to, amount }) {
    const coin = positiveCoinForDenom(amount, this.denom, "send");
    return {
      to: normalizeEvmAddress(to, "send recipient"),
      chainId: this.evmChainId,
      value: `0x${BigInt(coin.amount).toString(16)}`,
      gas: this.evmSendGasLimit
    };
  }

  /**
   * Submit a prepared EVM transaction through the reservation-aware transport
   * path. This is intentionally the browser facade's only EVM broadcast API:
   * it verifies both configured and connected-wallet networks before crossing
   * the wallet boundary and preserves reservation lifecycle bookkeeping.
   */
  async sendEvmTransaction(input = {}) {
    if (this.profileTransport !== "evm") {
      throw new Error("EVM transaction submission requires an active EVM profile");
    }
    const { wallet, transaction, ...reservationOptions } = input;
    if (!wallet || typeof wallet.sendTransaction !== "function" || typeof wallet.getChainId !== "function") {
      throw new Error("EVM transaction submission requires a wallet with getChainId() and sendTransaction()");
    }
    if (!transaction || typeof transaction !== "object" || Array.isArray(transaction)) {
      throw new Error("EVM transaction submission requires a transaction object");
    }
    const relayPayload = reservationOptions.relayPayload ?? reservationOptions.relay_payload ?? null;
    if (relayPayload) {
      const configuredEvmChainId = normalizedEvmChainId(this.evmChainId);
      const requestedChainId = reservationOptions.expectedChainId ?? reservationOptions.expected_chain_id;
      if (requestedChainId != null && String(requestedChainId) !== this.chainId) {
        throw new Error("relay expectedChainId must match the active profile chainId");
      }
      const requestedAccountPrefix = reservationOptions.accountPrefix ?? reservationOptions.account_prefix;
      if (requestedAccountPrefix != null && String(requestedAccountPrefix) !== this.accountPrefix) {
        throw new Error("relay accountPrefix must match the active profile accountPrefix");
      }
      const requestedEvmChainId = reservationOptions.expectedEvmChainId ?? reservationOptions.expected_evm_chain_id;
      if (requestedEvmChainId != null && normalizedEvmChainId(requestedEvmChainId, "relay expectedEvmChainId") !== configuredEvmChainId) {
        throw new Error("relay expectedEvmChainId must match the active profile evmChainId");
      }
      reservationOptions.expectedChainId = this.chainId;
      reservationOptions.accountPrefix = this.accountPrefix;
      reservationOptions.expectedEvmChainId = configuredEvmChainId;
      delete reservationOptions.expected_chain_id;
      delete reservationOptions.account_prefix;
      delete reservationOptions.expected_evm_chain_id;
    }
    await this.assertEvmPreparationNetwork({ evmWallet: wallet });
    if (reservationOptions.reservationManager || reservationOptions.reservation_manager || relayPayload) {
      // The browser client owns the active privacy-state source. Do not let a
      // caller replace the final spend-nullifier read with a stale callback.
      delete reservationOptions.check_nullifiers;
      reservationOptions.checkNullifiers = nullifiers => this.cosmos.checkNullifiers(nullifiers);
    }
    return this.evm.sendTransaction(wallet, transaction, reservationOptions);
  }

  async buildBankSendSignDoc({
    from,
    pubKeyHex,
    to,
    amount,
    gasLimit,
    gas_limit,
    feeAmount,
    fee_amount
  }) {
    const coin = positiveCoinForDenom(amount, this.denom, "send");
    const resolvedGasLimit = resolveBrowserCosmosGasLimit(gasLimit, gas_limit, 200000);
    const resolvedFeeAmount = resolveBrowserCosmosFeeAmount(feeAmount, fee_amount);
    return this.cosmos.buildDirectSignDoc({
      signer: from,
      pubKeyHex,
      gasLimit: resolvedGasLimit,
      feeAmount: resolvedFeeAmount,
      messages: [
        {
          typeUrl: "/cosmos.bank.v1beta1.MsgSend",
          value: {
            fromAddress: from,
            toAddress: to,
            amount: [{
              denom: coin.denom,
              amount: coin.amount
            }]
          }
        }
      ],
      memo: "Clairveil DApp signed send"
    });
  }

  async broadcastSignedTx(input, waitOptions) {
    return this.cosmos.broadcastSignedTx(input, waitOptions);
  }

  async broadcastTxRawBytes(txRawBytes, waitOptions) {
    return this.cosmos.broadcastTxRawBytes(txRawBytes, waitOptions);
  }

  async signDirect(input) {
    return this.cosmos.signDirect(input);
  }

  async signDirectAndBroadcast(input) {
    return this.cosmos.signDirectAndBroadcast(input);
  }

  async prepareDeposit(body) {
    const walletType = this.walletTypeFromBody(body);
    if (walletType === "evm") {
      await this.assertEvmPreparationNetwork(body);
      if (this.evmDepositMode === evmDepositModePayableExactValue) {
        // Validate the exact msg.value/native-denom binding before invoking a
        // deposit proof provider or opening a wallet.
        evmDepositValueForAmount(body.amount, this.evmNativeDenom);
        const suppliedMaterial = body.depositMaterial ?? body.deposit_material;
        if (suppliedMaterial) {
          const requestedAmount = parseCoin(body.amount, this.evmNativeDenom).raw;
          const materialAmount = parseCoin(
            suppliedMaterial.amount,
            this.evmNativeDenom
          ).raw;
          if (materialAmount !== requestedAmount) {
            throw new Error(
              `deposit material amount mismatch: expected ${requestedAmount}, got ${materialAmount}`
            );
          }
        }
      }
      // Cosmos deposits already run this validation in prepareDeposit. EVM
      // deposits build locally, so perform the same consensus circuit and
      // asset preflight before producing an EIP-1193 transaction.
      await this.cosmos.assertProtocolPreflight(this.denom);
    }
    const material = this.privacyMaterial(body, walletType);
    const amount = body.amount;
    let depositMaterial = body.depositMaterial ?? body.deposit_material ?? null;
    let depositProof = body.proof ?? null;
    let depositProofHex = body.proofHex ?? body.proof_hex ?? "";
    const suppliedDepositProofProvider = body.depositProofProvider ?? body.deposit_proof_provider;
    if (body.depositProofProvider != null && body.deposit_proof_provider != null &&
        body.depositProofProvider !== body.deposit_proof_provider) {
      throw new Error("depositProofProvider aliases conflict");
    }
    const resolvedDepositProofProvider = this.depositProofProvider(suppliedDepositProofProvider);
    if (!depositProof && !depositProofHex && typeof resolvedDepositProofProvider === "function") {
      depositMaterial = depositMaterial ?? this.cosmos.buildDepositMaterial({
        creator: material.address,
        rootSeed: material.rootSeed,
        amount,
        assetDenom: this.denom
      });
      const proof = await resolvedDepositProofProvider({
        material: depositMaterial,
        amount: depositMaterial.amount,
        note: depositMaterial.note,
        noteJson: depositMaterial.note_json,
        note_json: depositMaterial.note_json,
        noteCommitmentHex: depositMaterial.note_commitment_hex,
        note_commitment_hex: depositMaterial.note_commitment_hex,
        signal: body.signal
      });
      depositProof = proof?.proof ?? proof?.depositProof ?? proof?.deposit_proof ?? null;
      depositProofHex = proof?.proofHex ?? proof?.proof_hex ?? proof?.depositProofHex ?? proof?.deposit_proof_hex ?? "";
    }
    if (!depositProof && !depositProofHex) {
      throw new Error("deposit proof is required; provide proof/proofHex, a depositProofProvider, or the active profile's depositProofUrl");
    }
    if (walletType === "evm") {
      const built = this.evm.buildDepositTransaction({
        material: depositMaterial,
        creator: material.address,
        rootSeed: material.rootSeed,
        amount,
        assetDenom: this.denom,
        proof: depositProof ?? depositProofHex
      });
      return {
        transaction: profileBoundEvmTransaction(
          built.transaction,
          this.evmChainId,
          this.evmGasLimit
        ),
        prepared: {
          shieldedAddress: built.material.shieldedAddress || material.shieldedAddress,
          noteCommitmentHex: built.material.note_commitment_hex,
          encryptedNoteHex: built.material.encrypted_note_hex,
          amount: built.material.amount
        }
      };
    }
    const prepared = await this.cosmos.prepareDeposit({
      material,
      depositMaterial,
      amount,
      gasLimit: body.gasLimit,
      gas_limit: body.gas_limit,
      feeAmount: body.feeAmount,
      fee_amount: body.fee_amount,
      proof: depositProof,
      proofHex: depositProofHex
    });
    return {
      signDoc: prepared.signDoc,
      prepared: {
        shieldedAddress: prepared.privacyAccount.shielded_address,
        noteCommitmentHex: prepared.material.note_commitment_hex,
        // Keep the exact encrypted output alongside the commitment. A browser
        // caller must be able to pass both values to confirmDeposit after the
        // wallet broadcasts; checking only a tx hash would accept an unrelated
        // successful deposit before the local encrypted note is recovered.
        encryptedNoteHex: prepared.material.encrypted_note_hex,
        amount: prepared.material.amount
      }
    };
  }

  async prepareTransfer(body) {
    const walletType = this.walletTypeFromBody(body);
    if (walletType === "evm") await this.assertEvmPreparationNetwork(body);
    const expiresAtUnix = browserAliasedInputValue(
      body,
      "expiresAtUnix",
      "expires_at_unix",
      "expiresAtUnix",
      canonicalBrowserTransferUnix
    );
    const chainNowUnix = browserAliasedInputValue(
      body,
      "chainNowUnix",
      "chain_now_unix",
      "chainNowUnix",
      canonicalBrowserTransferUnix
    );
    const material = this.privacyMaterial(body, walletType);
    const amount = body.amount;
    const recipient = body.recipient;
    const userPrivacyPolicy = body.privacyPolicy ?? body.privacy_policy ?? "all-private";
    const userDisclosureMode = body.disclosureMode ?? body.disclosure_mode ?? "none";
    const userDisclosureTargetPubKeyHex = body.disclosurePubKeyHex ?? body.disclosure_pubkey_hex ?? "";
    const auditDisclosureTargetPubKeyHex = auditTargetBindingFromBody(body);
    const allowPlanStep = Boolean(body.allowPlanStep ?? body.allow_plan_step);
    const scanOptions = typedWalletScanOptionsFromBody(body);
    const reservationManager = body.reservationManager ?? body.reservation_manager ?? null;
    const suppliedProverAdapter = body.proverAdapter ?? body.prover_adapter;
    const prepared = await this.cosmos.prepareTransfer({
      proverAdapter: suppliedProverAdapter ?? deferredProverAdapter(
        () => this.proverAdapter(),
        "proveTransfer"
      ),
      material,
      signal: body.signal,
      recipient,
      amount,
      userPrivacyPolicy,
      userDisclosureMode,
      userDisclosureTargetPubKeyHex,
      disableSelfViewDisclosure: body.disableSelfViewDisclosure,
      disable_self_view_disclosure: body.disable_self_view_disclosure,
      selfViewDisclosureTargetPubKeyHex: body.selfViewDisclosureTargetPubKeyHex,
      self_view_disclosure_target_pubkey: body.self_view_disclosure_target_pubkey,
      auditDisclosureTargetPubKeyHex,
      expectedRecipientHash: body.expectedRecipientHash,
      expected_recipient_hash: body.expected_recipient_hash,
      expectedAmountHash: body.expectedAmountHash,
      expected_amount_hash: body.expected_amount_hash,
      expiresAtUnix: body.expiresAtUnix,
      expires_at_unix: body.expires_at_unix,
      chainNowUnix: body.chainNowUnix,
      chain_now_unix: body.chain_now_unix,
      allowPlanStep,
      scan: scanOptions,
      gasLimit: body.gasLimit,
      gas_limit: body.gas_limit,
      feeAmount: body.feeAmount,
      fee_amount: body.fee_amount,
      reservationManager,
      ...(walletType === "evm" ? {
        executionBuilder: this.evmDirectExecutionBuilder("transfer")
      } : {})
    });
    if (prepared.status !== "ready") throw plannerError(prepared);

    const common = {
      ...reservationReconciliationFields(prepared),
      reservation: prepared.reservation || null,
      prepared: {
        ...prepared.prepared,
        shieldedAddress: prepared.privacyAccount.shielded_address,
        finalAmount: amount,
        finalRecipient: recipient,
        privacyPolicy: userPrivacyPolicy,
        disclosureMode: userDisclosureMode,
        planStatus: prepared.plan?.status || "",
        planAction: prepared.prepared?.planAction || prepared.plan?.action || "",
        payload: prepared.payload,
        proof: prepared.proof,
        message: prepared.execution?.message || prepared.message
      },
      plan: prepared.plan
    };
    if (walletType !== "evm") {
      const gasLimit = resolveBrowserCosmosGasLimit(body.gasLimit, body.gas_limit, 8000000);
      const feeAmount = resolveBrowserCosmosFeeAmount(body.feeAmount, body.fee_amount);
      const prepared = await this.cosmos.prepareTransfer({
        proverAdapter: body.proverAdapter ?? body.prover_adapter ?? this.proverAdapter(),
        material,
        signal: body.signal,
        recipient,
        amount,
        userPrivacyPolicy,
        userDisclosureMode,
        userDisclosureTargetPubKeyHex,
        disableSelfViewDisclosure,
        selfViewDisclosureTargetPubKeyHex,
        auditDisclosureTargetPubKeyHex,
        ...(operationEvidence.provided ? {
          expectedRecipientHash: operationEvidence.expectedRecipientHash,
          expectedAmountHash: operationEvidence.expectedAmountHash
        } : {}),
        expiresAtUnix,
        chainNowUnix,
        allowPlanStep,
        scan: scanOptions,
        gasLimit,
        feeAmount,
        reservationManager
      });
      if (prepared.status !== "ready") throw plannerError(prepared);
      return {
        ...reservationReconciliationFields(prepared),
        signDoc: prepared.signDoc,
        reservation: prepared.reservation || null,
        prepared: {
          ...prepared.prepared,
          shieldedAddress: prepared.privacyAccount.shielded_address,
          finalAmount: amount,
          finalRecipient: recipient,
          privacyPolicy: userPrivacyPolicy,
          disclosureMode: userDisclosureMode,
          planStatus: prepared.plan?.status || "",
          planAction: prepared.prepared?.planAction || prepared.plan?.action || "",
          payload: prepared.payload,
          proof: prepared.proof,
          message: prepared.message
        },
        plan: prepared.plan
      };
    }
    const transaction = prepared.execution?.transaction;
    const txBytesHash = String(
      prepared.execution?.txBytesHash ?? prepared.execution?.tx_bytes_hash ?? ""
    ).trim();
    if (!transaction || !txBytesHash) {
      throw new Error("EVM transfer preparation did not produce a transaction and binding hash");
    }
    return { ...common, transaction, txBytesHash };
  }

    const isFinal = plan.status === "final_transfer_ready";
    assertTransferDisclosureCapabilities(transferProtocolConfig.disclosure_config, {
      userPrivacyPolicy: isFinal ? userPrivacyPolicy : "all-private",
      userDisclosureMode: isFinal ? userDisclosureMode : "none"
    });
    const auditPubKeyHex = transferProtocolConfig.audit_config.audit_master_pubkey_hex;
    const stepRecipient = isFinal ? recipient : material.shieldedAddress;
    const stepAmount = isFinal ? amount : plan.nextAmount;
    let reservationBatch = null;
    try {
      reservationBatch = await preparePlanReservation(reservationManager, {
        plan,
        kind: isFinal ? "transfer" : "self_merge",
        metadata: {
          amount: stepAmount,
          recipient: stepRecipient,
          finalAmount: amount,
          finalRecipient: recipient
        }
      });
      const heartbeatResult = await withReservationHeartbeat(reservationManager, reservationBatch, async ({ assertHeartbeatHealthy, heartbeatNow }) => {
        const built = await this.cosmos.buildTransferMessage({
          proverAdapter: body.proverAdapter ?? body.prover_adapter ?? this.proverAdapter(),
          signal: body.signal,
          creator: material.address,
          inputs: plan.selection.inputs,
          recipient: stepRecipient,
          amount: stepAmount,
          transferDenom: this.denom,
          rootSeed: material.rootSeed,
          shieldedPrefix: this.shieldedPrefix,
          userPrivacyPolicy: isFinal ? userPrivacyPolicy : "all-private",
          userDisclosureMode: isFinal ? userDisclosureMode : "none",
          userDisclosureTargetPubKeyHex: isFinal ? userDisclosureTargetPubKeyHex : "",
          auditDisclosureTargetPubKeyHex: auditPubKeyHex,
          disableSelfViewDisclosure,
          selfViewDisclosureTargetPubKeyHex,
          expiresAtUnix,
          chainNowUnix
        });
        assertHeartbeatHealthy();
        const evmBuilt = await this.evm.buildTransferTransaction({
          message: built.message,
          payload: built.payload,
          proof: built.proof,
          expiresAtUnix: built.payload.expires_at_unix,
          chainNowUnix
        });
        let transaction = {
          chainId: this.evmChainId,
          gas: this.evmGasLimit,
          ...evmBuilt.transaction
        };
        if (reservationBatch) transaction = markEvmTransactionReservationRequired(transaction);
        const txBytesHash = reservationBatch ? evmTransactionBindingHash(transaction) : "";
        await heartbeatNow();
        await markReservationProofReady(reservationManager, reservationBatch, transferProofReadyMetadata(built, {
          amount: stepAmount,
          denom: this.denom,
          expectedRecipientHash: isFinal ? operationEvidence.expectedRecipientHash : "",
          expectedAmountHash: isFinal ? operationEvidence.expectedAmountHash : "",
          txBytesHash
        }, "txBytesHash"));
        return { built, transaction };
      });
      const { built, transaction } = heartbeatResult;
      return {
        executionTransport: "evm",
        transaction,
        reservation: reservationBatchSummary(reservationBatch),
        prepared: {
          ...built,
          planAction: isFinal ? "final_transfer" : "self_merge",
          isFinal,
          amount: stepAmount,
          recipient: stepRecipient,
          finalAmount: amount,
          finalRecipient: recipient,
          selectedInputTotal: plan.selection.total.toString(),
          shieldedAddress: material.shieldedAddress,
          privacyPolicy: userPrivacyPolicy,
          disclosureMode: userDisclosureMode,
          planStatus: plan.status,
          expiresAtUnix: built.payload.expires_at_unix,
          chainNowUnix,
          reservation: reservationBatchSummary(reservationBatch)
        },
        plan
      };
    };
  }

  evmBatchTransferExecutionBuilder(body, { authorization, authorizationSigner } = {}) {
    if (authorizationSigner != null && authorization == null) {
      throw new Error("EVM batch authorizationSigner requires authorization");
    }
    const transactionOptions = browserAliasedInputValue(
      body,
      "transactionOptions",
      "transaction_options",
      "transactionOptions",
      canonicalBrowserAliasReference
    );
    return async ({ message }) => {
      let resolvedAuthorization = null;
      let authorizationTypedData = null;
      if (authorization) {
        resolvedAuthorization = { ...authorization };
        if (!hasEvmAuthorizationSignature(resolvedAuthorization)) {
          if (!authorizationSigner || typeof authorizationSigner.signTypedData !== "function") {
            throw new Error("EVM batch authorization requires a signature or authorizationSigner.signTypedData()");
          }
          authorizationTypedData = this.evm.buildAuthorizationTypedData({
            action: "singleProofBatchTransfer",
            request: message,
            authorization: resolvedAuthorization,
            cosmosChainId: this.chainId,
            evmChainId: this.evmChainId,
            contractAddress: this.evm.contract.contractAddress
          });
          resolvedAuthorization.signature = await authorizationSigner.signTypedData(authorizationTypedData);
        }
      }
      const evmBuilt = resolvedAuthorization
        ? this.evm.buildSingleProofBatchTransferWithAuthorizationTransaction({
            message,
            authorization: resolvedAuthorization,
            transactionOptions
          })
        : this.evm.buildSingleProofBatchTransferTransaction({
            message,
            transactionOptions
          });
      const transaction = markEvmTransactionReservationRequired(
        profileBoundEvmTransaction(evmBuilt.transaction, this.evmChainId, this.evmGasLimit)
      );
      return {
        executionTransport: "evm",
        transaction,
        txBytesHash: evmTransactionBindingHash(transaction),
        ...(resolvedAuthorization ? { authorization: resolvedAuthorization } : {}),
        ...(authorizationTypedData ? { authorizationTypedData } : {})
      };
    };
  }

  async prepareTransferBatch(body) {
    const walletType = this.walletTypeFromBody(body);
    if (walletType === "evm") await this.assertEvmPreparationNetwork(body);
    const suppliedProverAdapter = browserAliasedInputValue(
      body,
      "proverAdapter",
      "prover_adapter",
      "proverAdapter"
    );
    const userPrivacyPolicy = browserAliasedInputValue(
      body,
      "privacyPolicy",
      "privacy_policy",
      "privacyPolicy",
      canonicalBrowserAliasScalar
    ) ?? "all-private";
    const userDisclosureMode = browserAliasedInputValue(
      body,
      "disclosureMode",
      "disclosure_mode",
      "disclosureMode",
      canonicalBrowserAliasScalar
    ) ?? "none";
    const userDisclosureTargetPubKeyHex = browserAliasedInputValue(
      body,
      "disclosurePubKeyHex",
      "disclosure_pubkey_hex",
      "disclosurePubKeyHex",
      canonicalBrowserAliasHex
    ) ?? "";
    const gasLimit = browserAliasedInputValue(
      body,
      "gasLimit",
      "gas_limit",
      "gasLimit",
      canonicalBrowserAliasScalar
    ) ?? 25000000;
    const expiresAtUnix = browserAliasedInputValue(
      body,
      "expiresAtUnix",
      "expires_at_unix",
      "expiresAtUnix",
      canonicalBrowserAliasScalar
    );
    const chainNowUnix = browserAliasedInputValue(
      body,
      "chainNowUnix",
      "chain_now_unix",
      "chainNowUnix",
      canonicalBrowserAliasScalar
    );
    const rootHex = browserAliasedInputValue(
      body,
      "rootHex",
      "root_hex",
      "rootHex",
      canonicalBrowserAliasHex
    );
    const snapshotHeight = browserAliasedInputValue(
      body,
      "snapshotHeight",
      "snapshot_height",
      "snapshotHeight",
      canonicalBrowserAliasScalar
    );
    const disableSelfViewDisclosure = browserAliasedInputValue(
      body,
      "disableSelfViewDisclosure",
      "disable_self_view_disclosure",
      "disableSelfViewDisclosure",
      canonicalBrowserAliasBoolean
    );
    const selfViewDisclosureTargetPubKeyHex = browserAliasedInputValue(
      body,
      "selfViewDisclosureTargetPubKeyHex",
      "self_view_disclosure_target_pubkey",
      "selfViewDisclosureTargetPubKeyHex",
      canonicalBrowserAliasHex
    );
    const material = this.privacyMaterial(body, walletType);
    const payments = body.payments;
    const amounts = body.amounts;
    const recipient = body.recipient;
    const scanOptions = typedWalletScanOptionsFromBody(body);
    const prepared = await this.cosmos.prepareTransferBatch({
      proverAdapter: suppliedProverAdapter ?? this.proverAdapter(),
      material,
      signal: body.signal,
      payments,
      recipient,
      amounts,
      // Preserve these aliases for the Cosmos layer, which accepts exact32 and
      // exact-32 as equivalent spellings while still rejecting true conflicts.
      outputMode: body.outputMode,
      output_mode: body.output_mode,
      onPreparedPayload: body.onPreparedPayload,
      on_prepared_payload: body.on_prepared_payload,
      onPreparedProof: body.onPreparedProof,
      on_prepared_proof: body.on_prepared_proof,
      userPrivacyPolicy,
      userDisclosureMode,
      userDisclosureTargetPubKeyHex,
      auditDisclosureTargetPubKeyHex: body.auditDisclosureTargetPubKeyHex,
      audit_disclosure_target_pubkey_hex: body.audit_disclosure_target_pubkey_hex,
      expectedRecipientHash: body.expectedRecipientHash,
      expected_recipient_hash: body.expected_recipient_hash,
      expectedRecipientHashes: body.expectedRecipientHashes,
      expected_recipient_hashes: body.expected_recipient_hashes,
      expectedAmountHashes: body.expectedAmountHashes,
      expected_amount_hashes: body.expected_amount_hashes,
      scan: scanOptions,
      gasLimit,
      feeAmount: body.feeAmount,
      fee_amount: body.fee_amount,
      expiresAtUnix,
      chainNowUnix,
      rootHex,
      snapshotHeight,
      inputCommitmentHexes: body.inputCommitmentHexes,
      input_commitment_hexes: body.input_commitment_hexes,
      disableSelfViewDisclosure,
      selfViewDisclosureTargetPubKeyHex,
      reservationManager: body.reservationManager,
      reservation_manager: body.reservation_manager,
      executionBuilder
    });
    if (prepared.status !== "ready") throw plannerError(prepared);
    const transaction = prepared.execution?.transaction;
    const txBytesHash = String(
      prepared.execution?.txBytesHash ?? prepared.execution?.tx_bytes_hash ?? ""
    ).trim();
    if (walletType === "evm" && (!transaction || !txBytesHash)) {
      throw new Error("EVM batch preparation did not produce a transaction and binding hash");
    }
    return {
      ...reservationReconciliationFields(prepared),
      ...(walletType === "evm" ? { transaction, txBytesHash } : { signDoc: prepared.signDoc }),
      ...(walletType === "evm" && prepared.execution?.authorization
        ? { authorization: prepared.execution.authorization }
        : {}),
      ...(walletType === "evm" && prepared.execution?.authorizationTypedData
        ? { authorizationTypedData: prepared.execution.authorizationTypedData }
        : {}),
      reservation: prepared.reservation || null,
      prepared: {
        ...prepared.prepared,
        shieldedAddress: prepared.privacyAccount.shielded_address,
        // Keep the operation evidence on the browser result as promised by
        // PreparedTransferBatchSummary.  The Cosmos core returns these fields
        // beside `prepared`; dropping them here made an EVM caller unable to
        // reconcile the aggregate one-proof operation without reaching into
        // reservation-store internals.
        operationEvidence: prepared.operationEvidence,
        operationEvidenceHash: prepared.operationEvidenceHash,
        ...(prepared.prepared?.payments?.every(payment => payment.privacyPolicy === prepared.prepared.payments[0].privacyPolicy)
          ? { privacyPolicy: prepared.prepared.payments[0].privacyPolicy }
          : {}),
        ...(prepared.prepared?.payments?.every(payment => payment.disclosureMode === prepared.prepared.payments[0].disclosureMode)
          ? { disclosureMode: prepared.prepared.payments[0].disclosureMode }
          : {}),
        planStatus: prepared.plan?.status || "",
        planAction: prepared.prepared?.planAction || prepared.plan?.action || "",
        selectedInputTotal: prepared.prepared?.selectedInputTotal,
        payload: prepared.payload,
        proof: prepared.proof,
        message: prepared.message,
        inputCount: prepared.prepared?.inputCount,
        outputCount: prepared.prepared?.outputCount
      },
      plan: prepared.plan
    };
  }

  async provePreparedBatchTransfer(body = {}) {
    const suppliedProverAdapter = browserAliasedInputValue(
      body,
      "proverAdapter",
      "prover_adapter",
      "proverAdapter"
    );
    const chainNowUnix = browserAliasedInputValue(
      body,
      "chainNowUnix",
      "chain_now_unix",
      "chainNowUnix",
      canonicalBrowserAliasScalar
    ) ?? body.nowUnix;
    return this.cosmos.provePreparedBatchTransfer({
      payload: body.payload,
      proverAdapter: suppliedProverAdapter ?? this.proverAdapter(),
      creator: body.creator ?? body.address ?? body.payload?.creator,
      denom: body.denom ?? this.denom,
      operationId: body.operationId,
      operation_id: body.operation_id,
      reservation: body.reservation,
      reservationBatch: body.reservationBatch,
      reservation_batch: body.reservation_batch,
      chainNowUnix,
      signal: body.signal,
      onPreparedProof: body.onPreparedProof,
      on_prepared_proof: body.on_prepared_proof
    });
  }

  /**
   * Finish a checkpointed batch after `provePreparedBatchTransfer` has durably
   * stored its proof. Cosmos builds a sign doc while EVM builds the canonical
   * transaction binding; both use the same evidence and reservation transition.
   */
  async finalizePreparedBatchTransfer(body = {}) {
    const walletType = this.walletTypeFromBody(body);
    if (walletType === "evm") await this.assertEvmPreparationNetwork(body);
    const authorization = browserAliasedInputValue(
      body,
      "authorization",
      "privacy_authorization",
      "authorization",
      canonicalBrowserAliasReference
    );
    const authorizationSigner = browserAliasedInputValue(
      body,
      "authorizationSigner",
      "authorization_signer",
      "authorizationSigner",
      canonicalBrowserAliasReference
    );
    if (walletType !== "evm" && (authorization != null || authorizationSigner != null)) {
      throw new Error("batch authorization is only supported for EVM wallet profiles");
    }
    const executionBuilder = walletType === "evm"
      ? this.evmBatchTransferExecutionBuilder(body, { authorization, authorizationSigner })
      : undefined;
    const pubKeyHex = browserAliasedInputValue(
      body,
      "pubKeyHex",
      "pub_key_hex",
      "pubKeyHex",
      canonicalBrowserAliasHex
    );
    const gasLimit = browserAliasedInputValue(
      body,
      "gasLimit",
      "gas_limit",
      "gasLimit",
      canonicalBrowserAliasScalar
    ) ?? 25000000;
    const userPrivacyPolicy = browserAliasedInputValue(
      body,
      "privacyPolicy",
      "privacy_policy",
      "privacyPolicy",
      canonicalBrowserAliasScalar
    ) ?? "all-private";
    const userDisclosureMode = browserAliasedInputValue(
      body,
      "disclosureMode",
      "disclosure_mode",
      "disclosureMode",
      canonicalBrowserAliasScalar
    ) ?? "none";
    const userDisclosureTargetPubKeyHex = browserAliasedInputValue(
      body,
      "disclosurePubKeyHex",
      "disclosure_pubkey_hex",
      "disclosurePubKeyHex",
      canonicalBrowserAliasHex
    ) ?? "";
    const chainNowUnix = browserAliasedInputValue(
      body,
      "chainNowUnix",
      "chain_now_unix",
      "chainNowUnix",
      canonicalBrowserAliasScalar
    );
    const finalized = await this.cosmos.finalizePreparedBatchTransfer({
      payload: body.payload,
      proof: body.proof,
      signer: body.signer ?? body.address ?? body.payload?.creator,
      pubKeyHex,
      gasLimit,
      feeAmount: body.feeAmount,
      fee_amount: body.fee_amount,
      memo: body.memo,
      payments: body.payments,
      amounts: body.amounts,
      recipient: body.recipient,
      userPrivacyPolicy,
      userDisclosureMode,
      userDisclosureTargetPubKeyHex,
      expectedRecipientHash: body.expectedRecipientHash,
      expected_recipient_hash: body.expected_recipient_hash,
      expectedRecipientHashes: body.expectedRecipientHashes,
      expected_recipient_hashes: body.expected_recipient_hashes,
      expectedAmountHashes: body.expectedAmountHashes,
      expected_amount_hashes: body.expected_amount_hashes,
      denom: body.denom ?? this.denom,
      operationId: body.operationId,
      operation_id: body.operation_id,
      reservationManager: body.reservationManager,
      reservation_manager: body.reservation_manager,
      reservation: body.reservation,
      reservationBatch: body.reservationBatch,
      reservation_batch: body.reservation_batch,
      chainNowUnix,
      executionBuilder
    });
    if (walletType !== "evm") return finalized;
    const transaction = finalized.execution?.transaction;
    const txBytesHash = String(
      finalized.execution?.txBytesHash ?? finalized.execution?.tx_bytes_hash ?? ""
    ).trim();
    if (!transaction || !txBytesHash) {
      throw new Error("EVM batch finalization did not produce a transaction and binding hash");
    }
    return {
      ...finalized,
      transaction,
      txBytesHash,
      ...(finalized.execution?.authorization
        ? { authorization: finalized.execution.authorization }
        : {}),
      ...(finalized.execution?.authorizationTypedData
        ? { authorizationTypedData: finalized.execution.authorizationTypedData }
        : {})
    };
  }

  async prepareWithdraw(body) {
    const expiresAtUnix = browserAliasedInputValue(
      body,
      "expiresAtUnix",
      "expires_at_unix",
      "expiresAtUnix",
      canonicalBrowserAliasScalar
    );
    const chainNowUnix = browserAliasedInputValue(
      body,
      "chainNowUnix",
      "chain_now_unix",
      "chainNowUnix",
      canonicalBrowserAliasScalar
    );
    const walletType = this.walletTypeFromBody(body);
    if (walletType === "evm") await this.assertEvmPreparationNetwork(body);
    const material = this.privacyMaterial(body, walletType);
    const amount = body.amount;
    const rawRecipient = body.recipient;
    const evmRecipient = isEvmAddress(rawRecipient) ? normalizeEvmAddress(rawRecipient, "withdraw recipient") : "";
    const recipient = evmRecipient ? evmAddressToBech32(evmRecipient, this.accountPrefix) : rawRecipient;
    const reservationManager = body.reservationManager ?? body.reservation_manager ?? null;
    const suppliedProverAdapter = body.proverAdapter ?? body.prover_adapter;
    const prepared = await this.cosmos.prepareWithdraw({
      proverAdapter: suppliedProverAdapter ?? deferredProverAdapter(
        () => this.proverAdapter(),
        "proveWithdraw"
      ),
      material,
      signal: body.signal,
      amount,
      recipient,
      assetDenom: this.denom,
      scan: typedWalletScanOptionsFromBody(body),
      expiresAtUnix,
      chainNowUnix,
      gasLimit: body.gasLimit,
      gas_limit: body.gas_limit,
      feeAmount: body.feeAmount,
      fee_amount: body.fee_amount,
      reservationManager,
      ...(walletType === "evm" ? {
        executionBuilder: this.evmDirectExecutionBuilder("withdraw", { evmRecipient })
      } : {})
    });
    if (prepared.status !== "ready") throw plannerError(prepared);

    if (walletType !== "evm") {
      const gasLimit = resolveBrowserCosmosGasLimit(body.gasLimit, body.gas_limit, 5000000);
      const feeAmount = resolveBrowserCosmosFeeAmount(body.feeAmount, body.fee_amount);
      const prepared = await this.cosmos.prepareWithdraw({
        proverAdapter: body.proverAdapter ?? body.prover_adapter ?? this.proverAdapter(),
        material,
        signal: body.signal,
        amount,
        recipient,
        scan: typedWalletScanOptionsFromBody(body),
        expiresAtUnix: body.expiresAtUnix ?? body.expires_at_unix,
        chainNowUnix: body.chainNowUnix ?? body.chain_now_unix,
        gasLimit,
        feeAmount,
        reservationManager
      });
      if (prepared.status !== "ready") throw plannerError(prepared);
      return {
        ...reservationReconciliationFields(prepared),
        signDoc: prepared.signDoc,
        payload: prepared.payload,
        proof: prepared.proof,
        message: prepared.message,
        reservation: prepared.reservation || null,
        prepared: {
          shieldedAddress: prepared.privacyAccount.shielded_address,
          amount: prepared.payload.amount,
          recipient: prepared.payload.recipient,
          selectedNoteNullifier: prepared.selectedNote?.nullifier || prepared.payload.nullifier_hex,
          expiresAtUnix: prepared.payload.expires_at_unix,
          payload: prepared.payload,
          proof: prepared.proof,
          message: prepared.message,
          reservation: prepared.reservation || null
        },
        plan: prepared.plan
      };
    }

    const scanOptions = typedWalletScanOptionsFromBody(body);
    const scan = await this.cosmos.scanNotes({
      rootSeed: material.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    const availableFoundNotes = await reservationAvailableNotes(reservationManager, scan.foundNotes);
    const plan = planWithdrawNotes({ notes: availableFoundNotes, amount, denom: this.denom });
    if (!plan.canBuildTx) throw plannerError({ status: plan.status, plan, scan });
    assertPlanCanBuildTx(plan);
    let reservationBatch = null;
    try {
      reservationBatch = await preparePlanReservation(reservationManager, {
        plan,
        kind: "withdraw",
        metadata: {
          amount,
          recipient
        }
      });
      const heartbeatResult = await withReservationHeartbeat(reservationManager, reservationBatch, async ({ assertHeartbeatHealthy, heartbeatNow }) => {
        const built = await this.cosmos.buildWithdrawMessage({
          proverAdapter: body.proverAdapter ?? body.prover_adapter ?? this.proverAdapter(),
          signal: body.signal,
          creator: material.address,
          notes: [plan.selectedNote],
          amount,
          assetDenom: this.denom,
          recipient,
          rootSeed: material.rootSeed,
          chainId: this.chainId,
          expiresAtUnix: body.expiresAtUnix ?? body.expires_at_unix,
          chainNowUnix: body.chainNowUnix ?? body.chain_now_unix
        });
        assertHeartbeatHealthy();
        const message = evmRecipient ? { ...built.message, evmRecipient } : built.message;
        const evmBuilt = await this.evm.buildWithdrawTransaction({
          message,
          payload: built.payload,
          proof: built.proof
        });
        let transaction = {
          chainId: this.evmChainId,
          gas: this.evmGasLimit,
          ...evmBuilt.transaction
        };
        if (reservationBatch) transaction = markEvmTransactionReservationRequired(transaction);
        const txBytesHash = reservationBatch ? evmTransactionBindingHash(transaction) : "";
        await heartbeatNow();
        await markReservationProofReady(reservationManager, reservationBatch, withdrawProofReadyMetadata(built, { txBytesHash }));
        return { built, transaction, message };
      });
      const { built, transaction, message } = heartbeatResult;
      return {
        ...reservationReconciliationFields(heartbeatResult),
        transaction,
        payload: built.payload,
        proof: built.proof,
        message,
        reservation: prepared.reservation || null
      },
      plan: prepared.plan
    };
    if (walletType !== "evm") {
      return { ...common, signDoc: prepared.signDoc };
    }
    const transaction = prepared.execution?.transaction;
    const txBytesHash = String(
      prepared.execution?.txBytesHash ?? prepared.execution?.tx_bytes_hash ?? ""
    ).trim();
    if (!transaction || !txBytesHash) {
      throw new Error("EVM withdraw preparation did not produce a transaction and binding hash");
    }
    return { ...common, transaction, txBytesHash };
  }

  async prepareRelayWithdraw(body) {
    const expiresAtUnix = browserAliasedInputValue(
      body,
      "expiresAtUnix",
      "expires_at_unix",
      "expiresAtUnix",
      canonicalBrowserAliasScalar
    );
    const chainNowUnix = relayChainNowUnixFromBody(body);
    const walletType = this.walletTypeFromBody(body);
    if (walletType === "evm") await this.assertEvmPreparationNetwork(body);
    const material = this.privacyMaterial(body, walletType);
    const amount = body.amount;
    const rawRecipient = body.recipient;
    const evmRecipient = isEvmAddress(rawRecipient) ? normalizeEvmAddress(rawRecipient, "withdraw recipient") : "";
    const recipient = evmRecipient ? evmAddressToBech32(evmRecipient, this.accountPrefix) : rawRecipient;
    const reservationManager = body.reservationManager ?? body.reservation_manager ?? null;
    const suppliedProverAdapter = body.proverAdapter ?? body.prover_adapter;
    const transactionOptions = browserAliasedInputValue(
      body,
      "transactionOptions",
      "transaction_options",
      "transactionOptions",
      canonicalBrowserAliasReference
    );
    const prepared = await this.cosmos.prepareRelayWithdraw({
      proverAdapter: suppliedProverAdapter ?? deferredProverAdapter(
        () => this.proverAdapter(),
        "proveWithdraw"
      ),
      material,
      signal: body.signal,
      amount,
      recipient,
      scan: typedWalletScanOptionsFromBody(body),
      expiresAtUnix: body.expiresAtUnix ?? body.expires_at_unix,
      chainNowUnix: relayChainNowUnixFromBody(body),
      reservationManager
    });
    if (prepared.status !== "ready") throw plannerError(prepared);
    if (walletType === "evm") {
      const transaction = prepared.execution?.transaction;
      const txBytesHash = String(
        prepared.execution?.txBytesHash ?? prepared.execution?.tx_bytes_hash ?? ""
      ).trim();
      if (!transaction || !txBytesHash) {
        throw new Error("EVM relay withdraw preparation did not produce a transaction and binding hash");
      }
      const message = prepared.execution?.message;
      return {
        ...reservationReconciliationFields(prepared),
        payload: prepared.payload,
        transaction,
        txBytesHash,
        reservation: prepared.reservation || null,
        prepared: {
          shieldedAddress: prepared.privacyAccount.shielded_address,
          amount: prepared.payload.amount,
          recipient: prepared.payload.recipient,
          evmRecipient,
          selectedNoteNullifier: prepared.selectedNote?.nullifier || prepared.payload.nullifier_hex,
          expiresAtUnix: prepared.payload.expires_at_unix,
          payload: prepared.payload,
          proof: prepared.proof,
          message,
          reservation: prepared.reservation || null
        },
        plan: prepared.plan
      };
    }
    return {
      ...reservationReconciliationFields(prepared),
      payload: prepared.payload,
      reservation: prepared.reservation || null,
      prepared: {
        shieldedAddress: prepared.privacyAccount.shielded_address,
        amount: prepared.payload.amount,
        recipient: prepared.payload.recipient,
        evmRecipient,
        selectedNoteNullifier: prepared.selectedNote?.nullifier || prepared.payload.nullifier_hex,
        expiresAtUnix: prepared.payload.expires_at_unix,
        payload: prepared.payload,
        proof: prepared.proof,
        reservation: prepared.reservation || null
      },
      plan: prepared.plan
    };
  }

  buildRelayWithdrawMessageFromPayload(body = {}) {
    return this.cosmos.buildRelayWithdrawMessageFromPayload({
      payload: body.payload,
      relayer: body.relayer ?? body.creator ?? body.address,
      chainNowUnix: relayChainNowUnixFromBody(body),
      expectedChainId: body.expectedChainId ?? body.expected_chain_id,
      expectedRecipient: body.expectedRecipient ?? body.expected_recipient,
      accountPrefix: body.accountPrefix ?? body.account_prefix
    });
  }

  async createRelayWithdrawSignDoc(body = {}) {
    const gasLimit = resolveBrowserCosmosGasLimit(body.gasLimit, body.gas_limit, 5000000);
    const feeAmount = resolveBrowserCosmosFeeAmount(body.feeAmount, body.fee_amount);
    const result = await this.cosmos.createRelayWithdrawSignDoc({
      payload: body.payload,
      relayer: body.relayer ?? body.creator ?? body.address,
      pubKeyHex: body.pubKeyHex ?? body.pub_key_hex,
      gasLimit,
      feeAmount,
      memo: body.memo,
      chainNowUnix: relayChainNowUnixFromBody(body),
      expectedChainId: body.expectedChainId ?? body.expected_chain_id,
      expectedRecipient: body.expectedRecipient ?? body.expected_recipient,
      accountPrefix: body.accountPrefix ?? body.account_prefix
    });
    return {
      signDoc: result.signDoc,
      message: result.message,
      payload: result.payload,
      relayer: result.relayer
    };
  }

  async scanWalletNotes(body) {
    const material = this.privacyMaterial(body);
    const {
      after,
      afterHeight,
      after_height,
      afterSequence,
      after_sequence,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types,
      outputLimit,
      output_limit,
      eventLimit,
      event_limit,
      maxEncodedBytes,
      max_encoded_bytes,
      validationStateSnapshot,
      validation_state_snapshot,
      scanSource,
      scan_source,
      strictPrivacyScan,
      strict_privacy_scan,
      noteStore,
      note_store,
      includeFoundNotes = false
    } = body || {};
    const scanOptions = typedWalletScanOptionsFromBody(body);
    return this.cosmos.scanWalletNotes({
      material,
      after,
      afterHeight,
      after_height,
      afterSequence,
      after_sequence,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types,
      outputLimit,
      output_limit,
      eventLimit,
      event_limit,
      maxEncodedBytes,
      max_encoded_bytes,
      validationStateSnapshot,
      validation_state_snapshot,
      scanSource,
      scan_source,
      strictPrivacyScan,
      strict_privacy_scan,
      noteStore: noteStore ?? note_store,
      includeFoundNotes
    });
  }

  async checkNullifier(nullifierHex) {
    return this.cosmos.checkNullifier(nullifierHex);
  }

  async checkNullifiers(nullifierHexes) {
    return this.cosmos.checkNullifiers(nullifierHexes);
  }

  async decodeUserDisclosure(body) {
    const request = {
      txHash: body.txHash ?? body.tx_hash
    };
    addIfPresent(request, "output", body.output ?? body.scanOutput);
    addIfPresent(request, "afterHeight", body.afterHeight ?? body.after_height);
    addIfPresent(request, "afterSequence", body.afterSequence ?? body.after_sequence);
    addIfPresent(request, "page", body.page);
    addIfPresent(request, "limit", body.limit);
    addIfPresent(request, "maxPages", body.maxPages ?? body.max_pages);
    addIfPresent(request, "eventTypes", body.eventTypes ?? body.event_types);
    addIfPresent(request, "scanSource", body.scanSource ?? body.scan_source);
    addIfPresent(request, "assetDenom", body.assetDenom);
    addIfPresent(request, "asset_denom", body.asset_denom);
    addIfPresent(request, "disclosureScalar", body.disclosureScalar ?? body.disclosure_scalar);
    addIfPresent(request, "disclosureScalarHex", body.disclosureScalarHex ?? body.disclosure_scalar_hex);
    addIfPresent(request, "disclosurePubKeyHex", body.disclosurePubKeyHex ?? body.disclosure_pubkey_hex);
    if (body.address && (body.pubKeyHex || body.pub_key_hex) && (body.signatureBase64 || body.signature_base64)) {
      const walletType = this.walletTypeFromBody(body);
      Object.assign(request, walletType === "evm"
        ? { ...body, skipSignerPubKeyCheck: true }
        : body);
    }
    return this.cosmos.decodeUserDisclosure(request);
  }

  async decodeSelfViewDisclosure(body) {
    const request = {
      txHash: body.txHash ?? body.tx_hash
    };
    addIfPresent(request, "output", body.output ?? body.scanOutput);
    addIfPresent(request, "afterHeight", body.afterHeight ?? body.after_height);
    addIfPresent(request, "afterSequence", body.afterSequence ?? body.after_sequence);
    addIfPresent(request, "page", body.page);
    addIfPresent(request, "limit", body.limit);
    addIfPresent(request, "maxPages", body.maxPages ?? body.max_pages);
    addIfPresent(request, "eventTypes", body.eventTypes ?? body.event_types);
    addIfPresent(request, "scanSource", body.scanSource ?? body.scan_source);
    addIfPresent(request, "assetDenom", body.assetDenom);
    addIfPresent(request, "asset_denom", body.asset_denom);
    addIfPresent(request, "disclosureScalar", body.disclosureScalar ?? body.disclosure_scalar);
    addIfPresent(request, "disclosureScalarHex", body.disclosureScalarHex ?? body.disclosure_scalar_hex);
    if (body.address && (body.pubKeyHex || body.pub_key_hex) && (body.signatureBase64 || body.signature_base64)) {
      const walletType = this.walletTypeFromBody(body);
      Object.assign(request, walletType === "evm"
        ? { ...body, skipSignerPubKeyCheck: true }
        : body);
    }
    return this.cosmos.decodeSelfViewDisclosure(request);
  }

  async decodeAuditDisclosure(body = {}) {
    const request = {
      txHash: body.txHash ?? body.tx_hash,
      disclosurePrivKeyHex: body.disclosurePrivKeyHex ?? body.disclosure_privkey_hex
    };
    addIfPresent(request, "output", body.output ?? body.scanOutput);
    addIfPresent(request, "afterHeight", body.afterHeight ?? body.after_height);
    addIfPresent(request, "afterSequence", body.afterSequence ?? body.after_sequence);
    addIfPresent(request, "page", body.page);
    addIfPresent(request, "limit", body.limit);
    addIfPresent(request, "maxPages", body.maxPages ?? body.max_pages);
    addIfPresent(request, "eventTypes", body.eventTypes ?? body.event_types);
    addIfPresent(request, "scanSource", body.scanSource ?? body.scan_source);
    addIfPresent(request, "assetDenom", body.assetDenom);
    addIfPresent(request, "asset_denom", body.asset_denom);
    return this.cosmos.decodeAuditDisclosure(request);
  }

  async decodeBatchUserDisclosure(body = {}) {
    const request = { ...body };
    if (body.address && (body.pubKeyHex || body.pub_key_hex) && (body.signatureBase64 || body.signature_base64)) {
      const walletType = this.walletTypeFromBody(body);
      if (walletType === "evm") request.skipSignerPubKeyCheck = true;
    }
    return this.cosmos.decodeBatchUserDisclosure(request);
  }

  async decodeBatchSelfViewDisclosure(body = {}) {
    const request = { ...body };
    if (body.address && (body.pubKeyHex || body.pub_key_hex) && (body.signatureBase64 || body.signature_base64)) {
      const walletType = this.walletTypeFromBody(body);
      if (walletType === "evm") request.skipSignerPubKeyCheck = true;
    }
    return this.cosmos.decodeBatchSelfViewDisclosure(request);
  }

  async decodeBatchAuditDisclosure(body = {}) {
    return this.cosmos.decodeBatchAuditDisclosure({ ...body });
  }

  txRawBytesBase64({ bodyBytes, authInfoBytes, signature }) {
    return asBytesBase64(this.cosmos.buildTxRawBytes({ bodyBytes, authInfoBytes, signature }));
  }
}

export function createClairveilBrowserClient(options) {
  return new ClairveilBrowserClient(options);
}

export const ClairveilBrowserDappClient = ClairveilBrowserClient;

export function createClairveilBrowserDappClient(options) {
  return createClairveilBrowserClient(options);
}

export {
  buildRootSigningMessage,
  evmAddressToBech32,
  verifySignerPubKey
};
