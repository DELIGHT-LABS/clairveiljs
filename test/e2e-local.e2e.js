import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { stringToPath } from "@cosmjs/crypto";
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import {
  cosmosSignDocBindingHash,
  createClairveilClient,
  createHttpProverAdapter
} from "clairveiljs";
import {
  createOfflineSignerWalletAdapter,
  createWalletAdapter
} from "clairveiljs/wallet-adapter";
import {
  bytesToBigIntBE,
  createSpendNoteHashSigner,
  encodeShieldedAddress,
  computeNoteCommitmentV1,
  fieldHexV1
} from "clairveiljs/core";
import {
  computeBatchEffectIdV1,
  computeChainDomainV1
} from "clairveiljs/protocol-v1";
import {
  planOneProofPayroll,
  prepareOneProofPayrollOperation,
  prepareOneProofPayrollReservation,
  provePreparedOneProofPayrollOperation,
  createOneProofPayrollBatchSignDoc,
  createOneProofPayrollArtifact,
  inspectOneProofPayrollArtifactRetry,
  markOneProofPayrollReservationProofReady,
  reconcileOneProofPayrollReservation,
  retransmitOneProofPayrollArtifact
} from "clairveiljs/reference-payroll";
import {
  MemoryReservationStore,
  createNoteReservationManager,
  hashAmount,
  hashRecipient,
  reservationStatuses
} from "clairveiljs/reservation";
import {
  createPrivacyScanValidationStateV2,
  privacyScanEventTypeV2,
  processPrivacyScanPageV2,
  validatePrivacyScanPageV2
} from "clairveiljs/scan";
import {
  hexFromBytes
} from "clairveiljs/browser-crypto";
import {
  batchTransferConformanceFixtureName,
  readClairveilConformanceFixture,
  suggestClairveilConformanceFixtureDirs
} from "clairveiljs/conformance";

const env = process.env;
const localE2eEnabled = env.CLAIRVEIL_E2E_LOCAL === "1";
const testnetE2eEnabled = env.CLAIRVEIL_E2E_TESTNET === "1";
if (localE2eEnabled && testnetE2eEnabled) {
  throw new Error("CLAIRVEIL_E2E_LOCAL and CLAIRVEIL_E2E_TESTNET are mutually exclusive");
}
const cosmosE2eEnabled = localE2eEnabled || testnetE2eEnabled;
const fullFlowEnabled = cosmosE2eEnabled && env.CLAIRVEIL_E2E_FULL_FLOW === "1";
const oneProofBatchEnabled = fullFlowEnabled && env.CLAIRVEIL_E2E_ONE_PROOF_BATCH === "1";
const e2eRequired = testnetE2eEnabled || env.CLAIRVEIL_E2E_REQUIRED === "1";
const pinnedBatchTransferContract = readClairveilConformanceFixture(
  batchTransferConformanceFixtureName,
  { fixtureDir: suggestClairveilConformanceFixtureDirs()[0] }
);

function skipOrRequire(t, message) {
  if (e2eRequired) throw new Error(message);
  t.skip(message);
}

function positiveIntegerEnv(name, fallback) {
  const value = env[name];
  if (value == null || String(value).trim() === "") return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function coinEnv(name, fallbackAmount, denom) {
  const value = String(env[name] ?? "").trim();
  if (!value) return `${fallbackAmount}${denom}`;
  if (/^(0|[1-9][0-9]*)$/.test(value)) return `${value}${denom}`;
  return value;
}

function coinEnvOrDefaultCoin(name, defaultCoin, denom) {
  const value = String(env[name] ?? "").trim();
  if (!value) return defaultCoin;
  if (/^(0|[1-9][0-9]*)$/.test(value)) return `${value}${denom}`;
  return value;
}

function assertTestnetEndpoint(value, name) {
  let endpoint;
  try {
    endpoint = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute HTTP(S) URL for testnet E2E`);
  }
  if (endpoint.protocol !== "http:" && endpoint.protocol !== "https:") {
    throw new Error(`${name} must be an HTTP(S) URL for testnet E2E`);
  }
  const hostname = endpoint.hostname.toLowerCase();
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.startsWith("127.") ||
    hostname === "0.0.0.0" ||
    hostname === "::1" ||
    hostname === "[::1]"
  ) {
    throw new Error(`${name} must not use a loopback endpoint for testnet E2E`);
  }
}

const requiredTestnetEnvNames = Object.freeze([
  "CLAIRVEIL_E2E_CHAIN_ID",
  "CLAIRVEIL_E2E_RPC",
  "CLAIRVEIL_E2E_REST",
  "CLAIRVEIL_E2E_PROVER_URL",
  "CLAIRVEIL_E2E_ACCOUNT_PREFIX",
  "CLAIRVEIL_E2E_SHIELDED_PREFIX",
  "CLAIRVEIL_E2E_DENOM"
]);

function assertTestnetDeployment(config) {
  if (/local/i.test(config.chainId)) {
    throw new Error("CLAIRVEIL_E2E_CHAIN_ID must identify a testnet, not a local chain");
  }
  assertTestnetEndpoint(config.rpc, "CLAIRVEIL_E2E_RPC");
  assertTestnetEndpoint(config.rest, "CLAIRVEIL_E2E_REST");
  assertTestnetEndpoint(config.proverUrl, "CLAIRVEIL_E2E_PROVER_URL");
}

function assertExplicitTestnetConfig(config) {
  for (const name of requiredTestnetEnvNames) {
    if (!String(env[name] ?? "").trim()) {
      throw new Error(`${name} is required for Cosmos testnet E2E`);
    }
  }
  assertTestnetDeployment(config);
}

function configFromEnv() {
  const denom = String(env.CLAIRVEIL_E2E_DENOM || "uclair");
  const transferAmount = coinEnv("CLAIRVEIL_E2E_TRANSFER_AMOUNT", "1", denom);
  const config = {
    chainId: String(env.CLAIRVEIL_E2E_CHAIN_ID || "clairveil-local-1"),
    rpc: String(env.CLAIRVEIL_E2E_RPC || "http://127.0.0.1:26657"),
    rest: String(env.CLAIRVEIL_E2E_REST || "http://127.0.0.1:1317"),
    proverUrl: String(env.CLAIRVEIL_E2E_PROVER_URL || "http://127.0.0.1:8080"),
    accountPrefix: String(env.CLAIRVEIL_E2E_ACCOUNT_PREFIX || "clair"),
    shieldedPrefix: String(env.CLAIRVEIL_E2E_SHIELDED_PREFIX || "clairs"),
    denom,
    depositAmount: coinEnv("CLAIRVEIL_E2E_DEPOSIT_AMOUNT", "10", denom),
    transferAmount,
    withdrawAmount: coinEnvOrDefaultCoin("CLAIRVEIL_E2E_WITHDRAW_AMOUNT", transferAmount, denom),
    relayWithdrawAmount: coinEnvOrDefaultCoin("CLAIRVEIL_E2E_RELAY_WITHDRAW_AMOUNT", transferAmount, denom),
    relayWithdrawGasLimit: positiveIntegerEnv("CLAIRVEIL_E2E_RELAY_WITHDRAW_GAS_LIMIT", 5000000),
    relayWithdrawExpirySeconds: positiveIntegerEnv("CLAIRVEIL_E2E_RELAY_WITHDRAW_EXPIRY_SECONDS", 1800),
    oneProofBatchGasLimit: positiveIntegerEnv("CLAIRVEIL_E2E_ONE_PROOF_BATCH_GAS_LIMIT", 25000000),
    scanLimit: positiveIntegerEnv("CLAIRVEIL_E2E_SCAN_LIMIT", 200),
    scanMaxPages: positiveIntegerEnv("CLAIRVEIL_E2E_SCAN_MAX_PAGES", 1000),
    maxPlannerSteps: positiveIntegerEnv("CLAIRVEIL_E2E_MAX_PLANNER_STEPS", 8),
    proverTimeoutMs: positiveIntegerEnv("CLAIRVEIL_E2E_PROVER_TIMEOUT_MS", 120000),
    auditDisclosurePrivKeyHex: String(
      env.CLAIRVEIL_E2E_AUDIT_DISCLOSURE_PRIVKEY_HEX ||
      env.CLAIRVEIL_E2E_AUDIT_DISCLOSURE_SCALAR_HEX ||
      ""
    ).trim(),
    waitOptions: {
      attempts: positiveIntegerEnv("CLAIRVEIL_E2E_TX_ATTEMPTS", 30),
      intervalMs: positiveIntegerEnv("CLAIRVEIL_E2E_TX_INTERVAL_MS", 1500)
    }
  };
  if (testnetE2eEnabled) assertExplicitTestnetConfig(config);
  return config;
}

function requireAuditDisclosureKey(config, flowLabel) {
  if (e2eRequired && !config.auditDisclosurePrivKeyHex) {
    throw new Error(
      `set CLAIRVEIL_E2E_AUDIT_DISCLOSURE_PRIVKEY_HEX for required ${flowLabel} audit-disclosure E2E`
    );
  }
}

function createClient(config) {
  return createClairveilClient({
    rpc: config.rpc,
    rest: config.rest,
    chainId: config.chainId,
    accountPrefix: config.accountPrefix,
    shieldedPrefix: config.shieldedPrefix,
    defaultDenom: config.denom,
    enableExperimentalBatchTransfer: oneProofBatchEnabled
  });
}

function hexToBase64(value) {
  const hex = String(value || "").trim().replace(/^0x/i, "");
  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(hex)) {
    throw new Error("CLAIRVEIL_E2E_ROOT_SIGNATURE_HEX must be even-length hex");
  }
  return Buffer.from(hex, "hex").toString("base64");
}

function rootSignatureBase64FromEnv() {
  const base64 = String(env.CLAIRVEIL_E2E_ROOT_SIGNATURE_BASE64 || "").trim();
  if (base64) return base64;
  const hex = String(env.CLAIRVEIL_E2E_ROOT_SIGNATURE_HEX || "").trim();
  return hex ? hexToBase64(hex) : "";
}

async function loadWalletFromModule(config) {
  const modulePath = String(env.CLAIRVEIL_E2E_WALLET_MODULE || "").trim();
  if (!modulePath) return null;
  const specifier = modulePath.startsWith("file:")
    ? modulePath
    : pathToFileURL(resolve(modulePath)).href;
  const mod = await import(specifier);
  const factoryOrWallet = mod.default ?? mod.createWallet ?? mod.wallet;
  const walletLike = typeof factoryOrWallet === "function"
    ? await factoryOrWallet(config)
    : factoryOrWallet;
  const wallet = walletLike?.wallet ?? walletLike;
  if (!wallet) {
    throw new Error("CLAIRVEIL_E2E_WALLET_MODULE must export a wallet object or wallet factory");
  }
  return createWalletAdapter(wallet);
}

function mnemonicWalletOptions(config) {
  const explicitPath = String(env.CLAIRVEIL_E2E_HD_PATH || "").trim();
  const coinType = String(env.CLAIRVEIL_E2E_COIN_TYPE || "").trim();
  if (explicitPath && coinType) {
    throw new Error("set only one of CLAIRVEIL_E2E_HD_PATH or CLAIRVEIL_E2E_COIN_TYPE");
  }
  if (coinType && !/^(0|[1-9][0-9]*)$/.test(coinType)) {
    throw new Error("CLAIRVEIL_E2E_COIN_TYPE must be a non-negative integer");
  }
  const hdPath = explicitPath || (coinType ? `m/44'/${coinType}'/0'/0/0` : "");
  return {
    prefix: config.accountPrefix,
    ...(hdPath ? { hdPaths: [stringToPath(hdPath)] } : {})
  };
}

async function loadDepositProofProvider(config) {
  const modulePath = String(env.CLAIRVEIL_E2E_DEPOSIT_PROOF_MODULE || "").trim();
  if (!modulePath) return null;
  const specifier = modulePath.startsWith("file:")
    ? modulePath
    : pathToFileURL(resolve(modulePath)).href;
  const mod = await import(specifier);
  const provider = mod.default ?? mod.createDepositProof ?? mod.depositProofProvider;
  if (typeof provider !== "function") {
    throw new Error("CLAIRVEIL_E2E_DEPOSIT_PROOF_MODULE must export default, createDepositProof, or depositProofProvider");
  }
  return input => provider(input, config);
}

async function loadWalletFromMnemonic(config) {
  const mnemonic = String(env.CLAIRVEIL_E2E_MNEMONIC || "").trim();
  const signatureBase64 = rootSignatureBase64FromEnv();
  if (!mnemonic || !signatureBase64) return null;
  const signer = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, mnemonicWalletOptions(config));
  return createOfflineSignerWalletAdapter({
    signer,
    address: String(env.CLAIRVEIL_E2E_ADDRESS || "").trim() || undefined,
    accountPrefix: config.accountPrefix,
    signPrivacyRootBase64: async () => signatureBase64
  });
}

async function loadE2eWallet(config) {
  return await loadWalletFromModule(config) || await loadWalletFromMnemonic(config);
}

async function loadRelayerWalletFromModule(config) {
  const modulePath = String(env.CLAIRVEIL_E2E_RELAYER_WALLET_MODULE || "").trim();
  if (!modulePath) return null;
  const specifier = modulePath.startsWith("file:")
    ? modulePath
    : pathToFileURL(resolve(modulePath)).href;
  const mod = await import(specifier);
  const factoryOrWallet = mod.createRelayerWallet ?? mod.relayerWallet ?? mod.default;
  const walletLike = typeof factoryOrWallet === "function"
    ? await factoryOrWallet(config)
    : factoryOrWallet;
  const wallet = walletLike?.relayerWallet ?? walletLike?.wallet ?? walletLike;
  if (!wallet) {
    throw new Error("CLAIRVEIL_E2E_RELAYER_WALLET_MODULE must export a relayer wallet or factory");
  }
  return createWalletAdapter(wallet);
}

async function loadRelayerWalletFromMnemonic(config) {
  const mnemonic = String(env.CLAIRVEIL_E2E_RELAYER_MNEMONIC || "").trim();
  if (!mnemonic) return null;
  const signer = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, {
    prefix: config.accountPrefix
  });
  return createOfflineSignerWalletAdapter({
    signer,
    address: String(env.CLAIRVEIL_E2E_RELAYER_ADDRESS || "").trim() || undefined,
    accountPrefix: config.accountPrefix,
    // A transparent relayer never derives shielded material. Keep the adapter
    // boundary explicit so an accidental privacy-root request fails closed.
    signPrivacyRoot: async () => {
      throw new Error("the transparent E2E relayer must not sign a privacy root");
    }
  });
}

async function loadE2eRelayerWallet(config) {
  return await loadRelayerWalletFromModule(config) || await loadRelayerWalletFromMnemonic(config);
}

function assertBroadcastOk(result, label) {
  const txhash = result?.broadcast?.txhash || result?.tx?.txhash || result?.txhash;
  assert.match(String(txhash || ""), /^[0-9A-F]{64}$/i, `${label} should return a tx hash`);
  assert.equal(result?.broadcast?.code, 0, `${label} broadcast failed`);
  assert.equal(result?.ok, true, `${label} was broadcast but not confirmed: ${result?.error || ""}`);
  if (result?.tx?.code != null) {
    assert.equal(result.tx.code, 0, `${label} tx failed: ${result.tx.raw_log || ""}`);
  }
  return txhash.toUpperCase();
}

function assertDisclosureReport(report, label, config, amount) {
  const verified = report?.verified ?? report?.verification?.verified;
  assert.equal(verified, true, `${label} disclosure should verify`);
  if (amount) {
    assert.equal(report.amount ?? report.summary?.amount, amount.replace(config.denom, ""));
  }
  assert.equal(report.asset_denom ?? report.summary?.asset_denom, config.denom);
}

async function latestChainBlock(config) {
  const response = await fetch(`${config.rest}/cosmos/base/tendermint/v1beta1/blocks/latest`);
  if (!response.ok) {
    throw new Error(`latest block query failed with HTTP ${response.status}`);
  }
  const data = await response.json();
  const header = data?.block?.header ?? data?.sdk_block?.header;
  const value = header?.time;
  const milliseconds = Date.parse(String(value || ""));
  if (!Number.isFinite(milliseconds)) throw new Error("latest block response omitted a valid block time");
  const height = String(header?.height ?? "").trim();
  if (!/^(0|[1-9][0-9]*)$/.test(height)) {
    throw new Error("latest block response omitted a valid block height");
  }
  return { timeUnix: Math.floor(milliseconds / 1000), height };
}

async function latestChainBlockTimeUnix(config) {
  return (await latestChainBlock(config)).timeUnix;
}

async function broadcastPrepared(client, wallet, prepared, label, config, { withdrawPayload = false } = {}) {
  assert.equal(prepared.status, "ready", `${label} should be ready`);
  assert.ok(prepared.signDoc, `${label} should include a signDoc`);
  if (withdrawPayload) assert.ok(prepared.payload, `${label} should include a withdraw payload`);
  const result = await client.signDirectAndBroadcast({
    wallet,
    signDoc: prepared.signDoc,
    getChainNowUnix: () => latestChainBlockTimeUnix(config),
    ...(withdrawPayload ? {
      relayPayload: prepared.payload,
    } : {}),
    waitOptions: config.waitOptions
  });
  return assertBroadcastOk(result, label);
}

async function scanWallet(client, wallet, material, config) {
  return client.scanWalletNotes({
    wallet,
    material,
    includeFoundNotes: true,
    limit: config.scanLimit,
    maxPages: config.scanMaxPages
  });
}

async function prepareDepositAndBroadcast(client, wallet, material, amount, config, depositProofProvider) {
  const depositMaterial = client.buildDepositMaterial({
    creator: material.address,
    rootSeed: material.rootSeed,
    amount,
    assetDenom: config.denom
  });
  const proof = await depositProofProvider({
    material: depositMaterial,
    amount: depositMaterial.amount,
    note: depositMaterial.note,
    noteJson: depositMaterial.note_json,
    note_json: depositMaterial.note_json,
    noteCommitmentHex: depositMaterial.note_commitment_hex,
    note_commitment_hex: depositMaterial.note_commitment_hex
  });
  const prepared = await client.prepareDeposit({
    wallet,
    material,
    depositMaterial,
    amount,
    denom: config.denom,
    proof: proof?.proof,
    proofHex: proof?.proofHex ?? proof?.proof_hex ?? proof?.depositProofHex ?? proof?.deposit_proof_hex
  });
  const txHash = await broadcastPrepared(client, wallet, prepared, `deposit ${amount}`, config);
  const confirmation = await client.confirmDeposit({ txHash, prepared });
  assert.equal(confirmation.status, "confirmed", `deposit ${amount} evidence should confirm`);
  return txHash;
}

async function prepareFinalTransfer(
  client,
  wallet,
  material,
  proverAdapter,
  recipient,
  amount,
  config,
  depositProofProvider,
  disclosure = {}
) {
  let createdZeroHelper = false;
  for (let step = 1; step <= config.maxPlannerSteps; step += 1) {
    const chainNowUnix = await latestChainBlockTimeUnix(config);
    const prepared = await client.prepareTransfer({
      wallet,
      material,
      amount,
      recipient,
      proverAdapter,
      userPrivacyPolicy: disclosure.userPrivacyPolicy ?? "amount-from-to",
      userDisclosureMode: disclosure.userDisclosureMode ?? "public",
      userDisclosureTargetPubKeyHex: disclosure.userDisclosureTargetPubKeyHex ?? "",
      allowPlanStep: true,
      chainNowUnix,
      expiresAtUnix: chainNowUnix + 1800,
      denom: config.denom,
      limit: config.scanLimit,
      maxPages: config.scanMaxPages
    });

    if (prepared.status !== "ready") {
      if (prepared.status === "zero_dummy_required" && !createdZeroHelper) {
        await prepareDepositAndBroadcast(client, wallet, material, `0${config.denom}`, config, depositProofProvider);
        createdZeroHelper = true;
        continue;
      }
      throw new Error(prepared.plan?.message || `transfer planner is not ready: ${prepared.status}`);
    }

    if (prepared.prepared?.isFinal) {
      return prepared;
    }

    await broadcastPrepared(client, wallet, prepared, `transfer planner step ${step}`, config);
  }

  throw new Error(`transfer planner did not produce a final transfer within ${config.maxPlannerSteps} steps`);
}

function coinAmount(coin, denom, label) {
  const match = String(coin || "").match(/^(0|[1-9][0-9]*)([A-Za-z][A-Za-z0-9/:._-]{2,127})$/);
  if (!match || match[2] !== denom) throw new Error(`${label} must be a canonical ${denom} coin`);
  return match[1];
}

async function createCurrentRootPathProvider(client, commitmentHexes) {
  const configuredRoot = String(env.CLAIRVEIL_E2E_ONE_PROOF_ROOT_HEX || "").trim();
  const configuredHeight = String(env.CLAIRVEIL_E2E_ONE_PROOF_SNAPSHOT_HEIGHT || "").trim();
  if (Boolean(configuredRoot) !== Boolean(configuredHeight)) {
    throw new Error("CLAIRVEIL_E2E_ONE_PROOF_ROOT_HEX and CLAIRVEIL_E2E_ONE_PROOF_SNAPSHOT_HEIGHT must be set together");
  }
  const treeState = await client.fetchTreeState();
  const rootHex = configuredRoot || String(treeState?.root ?? treeState?.root_hex ?? treeState?.rootHex ?? "").trim();
  if (!rootHex) throw new Error("one-proof batch E2E requires a current tree root");
  return client.createCommitmentPathSnapshotProvider({
    commitmentHexes: Array.isArray(commitmentHexes) ? commitmentHexes : [commitmentHexes],
    rootHex,
    // For a dynamically fetched current root, let the endpoint resolve and
    // return the root's authoritative snapshot height. A deposit event height
    // is not necessarily the same snapshot when the testnet is active.
    ...(configuredHeight ? { snapshotHeight: configuredHeight } : {})
  });
}

async function typedBatchOutputsForTransaction(client, txHash, commitmentHexes, material, config) {
  const requested = [...commitmentHexes].map(value => String(value).toLowerCase());
  const remaining = new Set(requested);
  const foundByCommitment = new Map();
  let after = { height: 0, globalSequence: 0, outputIndex: 0 };
  const validationState = createPrivacyScanValidationStateV2();
  let lastError = null;
  for (let attempt = 1; attempt <= config.waitOptions.attempts; attempt += 1) {
    let after = { height: 0, globalSequence: 0, outputIndex: 0 };
    try {
      for (let page = 0; page < config.scanMaxPages; page += 1) {
        const request = {
          after,
          outputLimit: config.scanLimit,
          eventLimit: config.scanLimit,
          eventTypes: [],
          validationState
        };
        const scanned = validatePrivacyScanPageV2(await client.fetchPrivacyScan(request), request);
        const output = scanned.outputs.find(candidate =>
          candidate.event_type === privacyScanEventTypeV2.shieldedTransfer &&
          hexFromBytes(candidate.tx_hash).toUpperCase() === txHash.toUpperCase() &&
          hexFromBytes(candidate.commitment).toLowerCase() === requestedCommitment
        );
        if (output) return output;
        if (!scanned.has_more) break;
        after = {
          height: scanned.next_cursor.height,
          globalSequence: scanned.next_cursor.global_sequence,
          outputIndex: scanned.next_cursor.output_index
        };
      }
      lastError = new Error("typed privacy scan has not indexed the direct transfer output yet");
    } catch (error) {
      lastError = error;
    }
    if (attempt < config.waitOptions.attempts) {
      await new Promise(resolve => setTimeout(resolve, config.waitOptions.intervalMs));
    }
  }
  throw lastError || new Error("typed privacy scan did not return the direct transfer output");
}

async function typedBatchOutputsForTransaction(client, txHash, outputCount, material, config, expectedSummary) {
  if (!Number.isSafeInteger(outputCount) || outputCount < 1 || outputCount > 32) {
    throw new Error("typed batch E2E requires an output count in 1..32");
  }
  let lastError = null;
  for (let attempt = 1; attempt <= config.waitOptions.attempts; attempt += 1) {
    let after = { height: 0, globalSequence: 0, outputIndex: 0 };
    const foundByIndex = new Map();
    let matchingSummarySeen = false;
    try {
      for (let page = 0; page < config.scanMaxPages; page += 1) {
        const request = {
          after,
          outputLimit: config.scanLimit,
          eventLimit: config.scanLimit,
          eventTypes: []
        };
        const scanned = validatePrivacyScanPageV2(await client.fetchPrivacyScan(request), request);
        for (const summary of scanned.summaries) {
          if (summary.event_type === privacyScanEventTypeV2.batchTransfer &&
              hexFromBytes(summary.tx_hash).toUpperCase() === txHash.toUpperCase()) {
            matchingSummarySeen = true;
            if (summary.output_count !== outputCount) {
              throw new Error("typed batch summary output count differs from the prepared operation");
            }
            if (hexFromBytes(summary.effect_id).toLowerCase() !== expectedSummary.effectIdHex) {
              throw new Error("typed batch summary effect ID differs from the executed operation");
            }
            assert.deepEqual(
              summary.nullifiers.map(value => hexFromBytes(value).toLowerCase()),
              expectedSummary.nullifierHexes,
              "typed batch summary nullifiers differ from the executed operation"
            );
            if (hexFromBytes(summary.audit_target_pubkey).toLowerCase() !== expectedSummary.auditTargetHex) {
              throw new Error("typed batch summary audit target differs from the executed operation");
            }
          }
        }
        const matchingOutputs = scanned.outputs.filter(candidate =>
          candidate.event_type === privacyScanEventTypeV2.batchTransfer &&
          hexFromBytes(candidate.tx_hash).toUpperCase() === txHash.toUpperCase()
        );
        if (matchingOutputs.length) {
          const found = processPrivacyScanPageV2(scanned, { rootSeed: material.rootSeed });
          for (const output of matchingOutputs) {
            const index = Number(output.output_index);
            if (!Number.isSafeInteger(index) || index < 0 || index >= outputCount) {
              throw new Error("typed batch output index is outside the prepared output set");
            }
            const commitment = hexFromBytes(output.commitment).toLowerCase();
            const note = found.find(candidate => fieldHexV1(computeNoteCommitmentV1(candidate.note)) === commitment);
            if (!note) throw new Error("typed batch output did not decrypt for the configured E2E wallet");
            const prior = foundByIndex.get(index);
            if (prior && hexFromBytes(prior.output.commitment).toLowerCase() !== commitment) {
              throw new Error("typed batch output index maps to conflicting commitments");
            }
            foundByIndex.set(index, { output, found: note });
          }
          if (matchingSummarySeen && foundByIndex.size === outputCount) {
            return Array.from({ length: outputCount }, (_, index) => {
              const entry = foundByIndex.get(index);
              if (!entry) throw new Error("typed batch output indexes are not a contiguous prefix");
              return entry;
            });
          }
        }
        if (!scanned.has_more) break;
        after = {
          height: scanned.next_cursor.height,
          globalSequence: scanned.next_cursor.global_sequence,
          outputIndex: scanned.next_cursor.output_index
        };
      }
      lastError = new Error("typed privacy scan has not indexed the complete one-proof batch output set yet");
    } catch (error) {
      lastError = error;
    }
    if (attempt < config.waitOptions.attempts) {
      await new Promise(resolve => setTimeout(resolve, config.waitOptions.intervalMs));
    }
  }
  throw lastError || new Error("typed privacy scan did not return the complete one-proof batch output set");
}

async function typedTransferOutputForTransaction(client, txHash, config) {
  let after = { height: 0, globalSequence: 0, outputIndex: 0 };
  const validationState = createPrivacyScanValidationStateV2();
  let lastError = null;
  for (let attempt = 1; attempt <= config.waitOptions.attempts; attempt += 1) {
    try {
      for (let page = 0; page < config.scanMaxPages; page += 1) {
        const request = {
          after,
          outputLimit: config.scanLimit,
          eventLimit: config.scanLimit,
          eventTypes: [],
          validationState
        };
        const scanned = validatePrivacyScanPageV2(await client.fetchPrivacyScan(request), request);
        const output = scanned.outputs.find(candidate =>
          candidate.event_type === privacyScanEventTypeV2.shieldedTransfer &&
          candidate.output_index === 0 &&
          hexFromBytes(candidate.tx_hash).toUpperCase() === txHash.toUpperCase()
        );
        if (output) return output;
        if (!scanned.has_more) break;
        after = {
          height: scanned.next_cursor.height,
          globalSequence: scanned.next_cursor.global_sequence,
          outputIndex: scanned.next_cursor.output_index
        };
      }
      lastError = new Error("typed privacy scan has not indexed the shielded transfer output yet");
    } catch (error) {
      lastError = error;
    }
    if (attempt < config.waitOptions.attempts) {
      await new Promise(resolve => setTimeout(resolve, config.waitOptions.intervalMs));
    }
  }
  throw lastError || new Error("typed privacy scan did not return the shielded transfer output");
}

function oneProofBatchShape(selectedValue, config) {
  const selected = String(selectedValue || "one-input-one-payment").trim().toLowerCase();
  const aliases = {
    "1-1": "one-input-one-payment",
    "three-input-four-output": "three-input-four-output-mixed-disclosure",
    "3-4": "three-input-four-output-mixed-disclosure",
    "16-31-change": "thirty-one-payments-plus-change",
    "16-32": "exact-thirty-two-payments",
    padding: "explicit-zero-padding"
  };
  const canonicalID = aliases[selected] ?? selected;
  const vector = pinnedBatchTransferContract.cases?.find(candidate => candidate.id === canonicalID);
  if (!vector) {
    throw new Error(
      "CLAIRVEIL_E2E_ONE_PROOF_BATCH_SHAPE must select one of the five pinned privacy_batch_transfer_v1_contract.json cases"
    );
  }
  const coin = amount => `${amount}${config.denom}`;
  const inputTotal = vector.input_amounts.reduce((sum, amount) => sum + BigInt(amount), 0n);
  const paymentTotal = vector.payment_amounts.reduce((sum, amount) => sum + BigInt(amount), 0n);
  let paymentIndex = 0;
  const expectedOutputAmounts = vector.expected_output_roles.map(role => {
    if (role === "payment") return String(vector.payment_amounts[paymentIndex++]);
    if (role === "change") return String(inputTotal - paymentTotal);
    if (role === "padding") return "0";
    throw new Error(`pinned batch fixture ${vector.id} has unsupported output role ${role}`);
  });
  if (paymentIndex !== vector.payment_amounts.length) {
    throw new Error(`pinned batch fixture ${vector.id} payment/output roles do not match`);
  }
  return {
    id: vector.id,
    inputAmounts: vector.input_amounts.map(coin),
    paymentAmounts: vector.payment_amounts.map(coin),
    disclosureModes: vector.disclosure_modes.slice(0, vector.payment_amounts.length),
    expectedDisclosureModes: [...vector.disclosure_modes],
    expectedOutputRoles: [...vector.expected_output_roles],
    expectedOutputAmounts,
    outputMode: vector.output_mode,
    selfViewEnabled: vector.self_view === "enabled"
  };
}

function selectedOneProofBatchShape(config) {
  return oneProofBatchShape(env.CLAIRVEIL_E2E_ONE_PROOF_BATCH_SHAPE, config);
}

function selectedOneProofBatchShapes(config) {
  const selected = String(env.CLAIRVEIL_E2E_ONE_PROOF_BATCH_SHAPE || "one-input-one-payment").trim().toLowerCase();
  if (selected !== "all") return [selectedOneProofBatchShape(config)];
  return pinnedBatchTransferContract.cases.map(vector => oneProofBatchShape(vector.id, config));
}

test("one-proof Cosmos E2E shapes are generated from the pinned Clairveil v0.3.1 fixture", () => {
  const config = { denom: "uclair" };
  assert.equal(pinnedBatchTransferContract.schema_version, "clairveil.batch-transfer.contract.v1");
  assert.equal(pinnedBatchTransferContract.cases.length, 5);
  for (const vector of pinnedBatchTransferContract.cases) {
    const shape = oneProofBatchShape(vector.id, config);
    assert.deepEqual(shape.inputAmounts, vector.input_amounts.map(amount => `${amount}uclair`), vector.id);
    assert.deepEqual(shape.paymentAmounts, vector.payment_amounts.map(amount => `${amount}uclair`), vector.id);
    assert.deepEqual(shape.expectedOutputRoles, vector.expected_output_roles, vector.id);
    assert.deepEqual(shape.expectedDisclosureModes, vector.disclosure_modes, vector.id);
    assert.deepEqual(
      shape.disclosureModes,
      vector.disclosure_modes.slice(0, vector.payment_amounts.length),
      vector.id
    );
    assert.equal(shape.selfViewEnabled, vector.self_view === "enabled", vector.id);
    assert.equal(shape.outputMode, vector.output_mode, vector.id);
  }
  assert.equal(
    oneProofBatchShape("three-input-four-output", config).id,
    "three-input-four-output-mixed-disclosure"
  );
});

test("Cosmos testnet E2E rejects local deployment identities and endpoints", () => {
  const deployment = {
    chainId: "clairveil-test-1",
    rpc: "https://rpc.testnet.example",
    rest: "https://rest.testnet.example",
    proverUrl: "https://prover.testnet.example"
  };
  assert.doesNotThrow(() => assertTestnetDeployment(deployment));
  assert.throws(
    () => assertTestnetDeployment({ ...deployment, chainId: "clairveil-local-1" }),
    /must identify a testnet/
  );
  for (const [field, endpoint] of [
    ["rpc", "http://127.0.0.2:26657"],
    ["rest", "http://localhost:1317"],
    ["proverUrl", "http://[::1]:8080"]
  ]) {
    assert.throws(
      () => assertTestnetDeployment({ ...deployment, [field]: endpoint }),
      /must not use a loopback endpoint/
    );
  }
});

test("configured Cosmos node passes the Clairveil v0.3.1 query preflight", {
  skip: cosmosE2eEnabled
    ? false
    : "set CLAIRVEIL_E2E_LOCAL=1 or CLAIRVEIL_E2E_TESTNET=1 to run Cosmos endpoint preflight"
}, async () => {
  const config = configFromEnv();
  const client = createClient(config);
  const probeNullifier = "01".repeat(32);

  try {
    const [treeState, protocol, auditConfig, disclosureConfig, reserve, scan, nullifiers] = await Promise.all([
      client.fetchTreeState(),
      client.assertProtocolPreflight(config.denom),
      client.queryAuditConfig(),
      client.queryDisclosureConfig(),
      client.queryReserve(config.denom),
      client.queryPrivacyScan({
        after: { height: 0, globalSequence: 0, outputIndex: 0 },
        outputLimit: 1,
        eventLimit: 1
      }),
      client.checkNullifiers([probeNullifier])
    ]);
    const reverseAsset = await client.queryAssetByID(protocol.asset.asset_id_hex);

    assert.equal(typeof treeState, "object", "tree state should be an object");
    assert.equal(
      protocol.circuit_config.circuit_set_identity.circuit_set_id,
      "privacy-note-v1",
      "circuit preflight should use the Clairveil v0.3.1 circuit set"
    );
    assert.equal(protocol.asset.canonical_denom, config.denom, "asset registry should resolve the configured denom");
    assert.equal(reverseAsset.asset.canonical_denom, config.denom, "asset registry reverse lookup should agree");
    assert.equal(typeof auditConfig, "object", "audit config should be an object");
    assert.equal(disclosureConfig.audit_disclosure_required, true, "disclosure config should require audit disclosure");
    assert.equal(reserve.denom, config.denom, "reserve response should echo denom");
    assert.equal(reserve.invariant_holds, true, "reserve invariant should hold before E2E execution");
    assert.equal(scan.scan_schema_version, "privacy-scan-v2", "wallet state must expose typed privacy_scan v2");
    assert.equal(typeof nullifiers.get(probeNullifier), "boolean", "nullifier batch query must return an explicit status");
  } finally {
    await client.disconnect();
  }
});

test("local full deposit, typed scan, disclosure, direct withdraw, and separately signed relay flow", {
  timeout: positiveIntegerEnv("CLAIRVEIL_E2E_FULL_FLOW_TIMEOUT_MS", 600000),
  skip: fullFlowEnabled
    ? false
    : "enable local or testnet Cosmos E2E and set CLAIRVEIL_E2E_FULL_FLOW=1 to run tx flow"
}, async t => {
  const config = configFromEnv();
  requireAuditDisclosureKey(config, "Cosmos full-flow");
  const wallet = await loadE2eWallet(config);
  if (!wallet) {
    skipOrRequire(t, "set CLAIRVEIL_E2E_WALLET_MODULE or CLAIRVEIL_E2E_MNEMONIC plus CLAIRVEIL_E2E_ROOT_SIGNATURE_BASE64");
    return;
  }
  const depositProofProvider = await loadDepositProofProvider(config);
  if (!depositProofProvider) {
    skipOrRequire(t, "set CLAIRVEIL_E2E_DEPOSIT_PROOF_MODULE to run the full deposit flow");
    return;
  }
  const relayerWallet = await loadE2eRelayerWallet(config);
  if (!relayerWallet) {
    skipOrRequire(t, "set CLAIRVEIL_E2E_RELAYER_WALLET_MODULE or CLAIRVEIL_E2E_RELAYER_MNEMONIC for a separately signed relay withdraw");
    return;
  }
  if (!config.auditDisclosurePrivKeyHex) {
    skipOrRequire(t, "set CLAIRVEIL_E2E_AUDIT_DISCLOSURE_PRIVKEY_HEX to verify audit disclosures");
    return;
  }

  const client = createClient(config);
  const proverAdapter = createHttpProverAdapter({
    baseURL: config.proverUrl,
    timeoutMs: config.proverTimeoutMs
  });

  try {
    const material = await client.deriveWalletPrivacyMaterial(wallet);
    const relayerAddress = await relayerWallet.getAddress();
    const relayerPubKeyHex = await relayerWallet.getPubKeyHex();
    assert.match(material.address, new RegExp(`^${config.accountPrefix}1`));
    assert.match(material.shieldedAddress, new RegExp(`^${config.shieldedPrefix}1`));
    assert.match(relayerAddress, new RegExp(`^${config.accountPrefix}1`));
    assert.notEqual(relayerAddress, material.address, "relay withdraw must use a separate transparent account");

    await prepareDepositAndBroadcast(client, wallet, material, config.depositAmount, config, depositProofProvider);
    assert.equal((await client.queryReserve(config.denom)).invariant_holds, true, "reserve invariant should hold after deposit");

    const depositScan = await scanWallet(client, wallet, material, config);
    assert.ok(
      BigInt(depositScan.summary?.total_spendable ?? "0") > 0n,
      "deposit scan should find spendable notes"
    );

    const transferRecipient = String(env.CLAIRVEIL_E2E_RECIPIENT_SHIELDED || "").trim()
      || material.shieldedAddress;
    const transfer = await prepareFinalTransfer(
      client,
      wallet,
      material,
      proverAdapter,
      transferRecipient,
      config.transferAmount,
      config,
      depositProofProvider
    );
    const transferTxHash = await broadcastPrepared(client, wallet, transfer, "final transfer", config);
    const transferOutput = await typedTransferOutputForTransaction(client, transferTxHash, config);

    const disclosure = await client.decodeUserDisclosure({
      output: transferOutput,
      txHash: transferTxHash
    });
    assertDisclosureReport(disclosure, "public transfer", config, config.transferAmount);
    assert.equal(disclosure.verification?.typed_scan_output, true);

    const selfViewDisclosure = await client.decodeSelfViewDisclosure({
      output: transferOutput,
      txHash: transferTxHash,
      disclosureScalar: material.disclosureScalar
    });
    assertDisclosureReport(selfViewDisclosure, "sender self-view", config, config.transferAmount);
    assert.equal(selfViewDisclosure.verification?.typed_scan_output, true);

    const auditDisclosure = await client.decodeAuditDisclosure({
      output: transferOutput,
      txHash: transferTxHash,
      disclosurePrivKeyHex: config.auditDisclosurePrivKeyHex
    });
    assertDisclosureReport(auditDisclosure, "audit", config, config.transferAmount);

    await prepareDepositAndBroadcast(
      client,
      wallet,
      material,
      config.transferAmount,
      config,
      depositProofProvider
    );
    const encryptedTransfer = await prepareFinalTransfer(
      client,
      wallet,
      material,
      proverAdapter,
      material.shieldedAddress,
      config.transferAmount,
      config,
      depositProofProvider,
      {
        userPrivacyPolicy: "amount-from-to",
        userDisclosureMode: "recipient-encrypted",
        userDisclosureTargetPubKeyHex: material.disclosurePubKeyHex
      }
    );
    const encryptedTransferTxHash = await broadcastPrepared(
      client,
      wallet,
      encryptedTransfer,
      "recipient-encrypted transfer",
      config
    );
    const encryptedTransferOutput = await typedTransferOutputForTransaction(
      client,
      encryptedTransferTxHash,
      config
    );
    const recipientDisclosure = await client.decodeUserDisclosure({
      output: encryptedTransferOutput,
      txHash: encryptedTransferTxHash,
      address: material.address,
      pubKeyHex: material.pubKeyHex,
      signatureBase64: material.signatureBase64
    });
    assertDisclosureReport(recipientDisclosure, "recipient-encrypted transfer", config, config.transferAmount);

    const withdrawRecipient = String(env.CLAIRVEIL_E2E_WITHDRAW_RECIPIENT || "").trim()
      || material.address;
    await prepareDepositAndBroadcast(
      client,
      wallet,
      material,
      config.withdrawAmount,
      config,
      depositProofProvider
    );
    const withdraw = await client.prepareWithdraw({
      wallet,
      material,
      amount: config.withdrawAmount,
      recipient: withdrawRecipient,
      proverAdapter,
      denom: config.denom,
      limit: config.scanLimit,
      maxPages: config.scanMaxPages
    });
    assert.equal(withdraw.status, "ready", withdraw.plan?.message || "withdraw should be ready");

    await broadcastPrepared(client, wallet, withdraw, "direct withdraw", config, {
      withdrawPayload: true
    });

    await prepareDepositAndBroadcast(
      client,
      wallet,
      material,
      config.withdrawAmount,
      config,
      depositProofProvider
    );
    const relayReservationStore = new MemoryReservationStore();
    const relayReservationManager = createNoteReservationManager({
      store: relayReservationStore,
      ownerKeyId: material.address,
      indexKey: material.rootSeed,
      leaseOwner: "cosmos-e2e-relay-owner"
    });
    const relayChainNowUnix = await latestChainBlockTimeUnix(config);
    const relayWithdraw = await client.prepareRelayWithdraw({
      wallet,
      material,
      amount: config.withdrawAmount,
      recipient: withdrawRecipient,
      proverAdapter,
      denom: config.denom,
      limit: config.scanLimit,
      maxPages: config.scanMaxPages,
      chainNowUnix: relayChainNowUnix,
      expiresAtUnix: relayChainNowUnix + 1800,
      reservationManager: relayReservationManager
    });
    assert.equal(relayWithdraw.status, "ready", relayWithdraw.plan?.message || "relay withdraw should be ready");
    assert.ok(relayWithdraw.reservation, "relay withdraw must reserve its exact input before handoff");
    const relayReservationIDs = relayWithdraw.reservation.reservation_ids;
    await relayReservationManager.recordRelayHandoff(relayReservationIDs, {
      leaseToken: relayWithdraw.reservation.lease_token,
      payloadHash: relayWithdraw.payload.payload_hash
    });
    const relaySignDoc = await client.createRelayWithdrawSignDoc({
      payload: relayWithdraw.payload,
      relayer: relayerAddress,
      pubKeyHex: relayerPubKeyHex,
      chainNowUnix: await latestChainBlockTimeUnix(config),
      expectedChainId: config.chainId,
      expectedRecipient: withdrawRecipient,
      accountPrefix: config.accountPrefix
    });
    const relayResult = await client.signDirectAndBroadcast({
      wallet: relayerWallet,
      signDoc: relaySignDoc.signDoc,
      relayPayload: relayWithdraw.payload,
      getChainNowUnix: () => latestChainBlockTimeUnix(config),
      waitOptions: config.waitOptions
    });
    const relayTxHash = assertBroadcastOk(relayResult, "separately signed relay withdraw");
    const relayTx = relayResult.tx ?? await client.getTx(relayTxHash);
    const checkedHeight = String(relayTx?.height ?? "");
    assert.match(checkedHeight, /^[1-9][0-9]*$/, "relay transaction evidence requires a positive included height");
    const relayReservation = await relayReservationManager.getReservation(relayReservationIDs[0]);
    await relayReservationManager.recordRelayTransactionEvidence({
      operationId: relayReservation.operation_id,
      payloadHash: relayWithdraw.payload.payload_hash,
      txHash: relayTxHash,
      checkedHeight,
      transactionIncludedConfirmed: true,
      payloadHashMatched: true
    });
    const relayNullifier = relayWithdraw.payload.nullifier_hex;
    assert.equal(
      (await client.checkNullifiers([relayNullifier])).get(relayNullifier),
      true,
      "relay withdraw nullifier must be spent before reservation reconciliation"
    );
    await relayReservationManager.reconcileSpentNotes([{
      ...relayWithdraw.selectedNote,
      isSpent: true
    }]);
    assert.equal(
      (await relayReservationManager.getReservation(relayReservationIDs[0])).status,
      "ConfirmedSpent"
    );
    assert.equal((await client.queryReserve(config.denom)).invariant_holds, true, "reserve invariant should hold after withdraw");

    if (!relayerWallet) {
      t.diagnostic("Cosmos relayed withdraw skipped: configure a separately funded relayer wallet");
      return;
    }
    const relayerAddress = await relayerWallet.getAddress();
    const relayerPubKeyHex = await relayerWallet.getPubKeyHex();
    assert.notEqual(relayerAddress, material.address, "relay E2E requires a distinct relayer account");

    await prepareDepositAndBroadcast(
      client,
      wallet,
      material,
      config.relayWithdrawAmount,
      config,
      depositProofProvider
    );
    const relayReservationManager = createNoteReservationManager({
      store: new MemoryReservationStore(),
      ownerKeyId: material.address,
      indexKey: material.rootSeed
    });
    const relayRecipient = String(env.CLAIRVEIL_E2E_RELAY_WITHDRAW_RECIPIENT || "").trim()
      || material.address;
    const relayChainNowUnix = await latestChainBlockTimeUnix(config);
    const relay = await client.prepareRelayWithdraw({
      wallet,
      material,
      amount: config.relayWithdrawAmount,
      recipient: relayRecipient,
      proverAdapter,
      denom: config.denom,
      limit: config.scanLimit,
      maxPages: config.scanMaxPages,
      expiresAtUnix: relayChainNowUnix + config.relayWithdrawExpirySeconds,
      chainNowUnix: relayChainNowUnix,
      reservationManager: relayReservationManager
    });
    assert.equal(relay.status, "ready", relay.plan?.message || "relay withdraw should be ready");
    assert.ok(relay.reservation?.reservation_ids?.length, "relay withdraw should reserve its exact input note");

    const relaySignDoc = await client.createRelayWithdrawSignDoc({
      payload: relay.payload,
      relayer: relayerAddress,
      pubKeyHex: relayerPubKeyHex,
      gasLimit: config.relayWithdrawGasLimit,
      chainNowUnix: await latestChainBlockTimeUnix(config),
      expectedChainId: config.chainId,
      expectedRecipient: relayRecipient
    });
    await relayReservationManager.recordRelayHandoff(relay.reservation.reservation_ids, {
      leaseToken: relay.reservation.lease_token,
      payloadHash: relay.payload.payload_hash,
      signDocHash: cosmosSignDocBindingHash(relaySignDoc.signDoc),
      metadata: { e2e: "cosmos-relay-withdraw" }
    });
    const relayResult = await client.signDirectAndBroadcast({
      wallet: relayerWallet,
      signDoc: relaySignDoc.signDoc,
      // The relayer validates and submits independently. The owner's handed-off
      // reservation is reconciled from authoritative spent evidence below.
      relayPayload: relay.payload,
      getChainNowUnix: () => latestChainBlockTimeUnix(config),
      expectedChainId: config.chainId,
      expectedRecipient: relayRecipient,
      waitOptions: config.waitOptions
    });
    const relayTxHash = assertBroadcastOk(relayResult, "relayed withdraw");
    assert.equal(relaySignDoc.message.creator, relayerAddress);
    assert.equal(relaySignDoc.message.recipient, relayRecipient);
    const handedOffReservation = await relayReservationManager.getReservation(
      relay.reservation.reservation_ids[0]
    );
    assert.equal(handedOffReservation.status, reservationStatuses.ProofReady);
    assert.equal(handedOffReservation.metadata?.relay_handed_off, true);
    const relayNullifier = String(relay.payload.nullifier_hex).toLowerCase();
    assert.equal((await client.checkNullifiers([relayNullifier])).get(relayNullifier), true);
    await relayReservationManager.reconcileSpentNotes([{
      ...relay.selectedNote,
      isSpent: true,
      spent: true,
      nullifierStatus: "spent",
      operationSuccessEvidence: {
        txHash: relayTxHash,
        txResult: relayResult.tx
      }
    }]);
    assert.equal(
      (await relayReservationManager.getReservation(relay.reservation.reservation_ids[0])).status,
      reservationStatuses.ConfirmedSpent
    );
    assert.equal((await client.queryReserve(config.denom)).invariant_holds, true, "reserve invariant should hold after relayed withdraw");
  } finally {
    await client.disconnect();
  }
});

test("Cosmos one-proof payroll batch proves, broadcasts, and reconciles typed output evidence", {
  timeout: positiveIntegerEnv("CLAIRVEIL_E2E_ONE_PROOF_BATCH_TIMEOUT_MS", 1800000),
  skip: oneProofBatchEnabled
    ? false
    : "enable local or testnet Cosmos E2E, full flow, and one-proof batch flags to run batch E2E"
}, async t => {
  const config = configFromEnv();
  requireAuditDisclosureKey(config, "Cosmos one-proof batch");
  const wallet = await loadE2eWallet(config);
  if (!wallet) {
    skipOrRequire(t, "set CLAIRVEIL_E2E_WALLET_MODULE or CLAIRVEIL_E2E_MNEMONIC plus CLAIRVEIL_E2E_ROOT_SIGNATURE_BASE64");
    return;
  }
  const depositProofProvider = await loadDepositProofProvider(config);
  if (!depositProofProvider) {
    skipOrRequire(t, "set CLAIRVEIL_E2E_DEPOSIT_PROOF_MODULE to fund the one-proof batch input note");
    return;
  }
  if (!config.auditDisclosurePrivKeyHex) {
    skipOrRequire(t, "set CLAIRVEIL_E2E_AUDIT_DISCLOSURE_PRIVKEY_HEX to verify typed batch audit disclosures");
    return;
  }

  const client = createClient(config);
  const proverAdapter = createHttpProverAdapter({
    baseURL: config.proverUrl,
    timeoutMs: config.proverTimeoutMs
  });
  try {
    const material = await client.deriveWalletPrivacyMaterial(wallet);
    const shapes = selectedOneProofBatchShapes(config);
    for (const shape of shapes) {
    const depositTxHashes = [];
    for (const amount of shape.inputAmounts) {
      depositTxHashes.push(await prepareDepositAndBroadcast(client, wallet, material, amount, config, depositProofProvider));
    }
    const scan = await scanWallet(client, wallet, material, config);
    const inputNotes = depositTxHashes.map((txHash, index) => {
      const amount = coinAmount(shape.inputAmounts[index], config.denom, `one-proof ${shape.id} deposit amount`);
      const inputNote = scan.foundNotes.find(found =>
        String(found.txHash || "").toUpperCase() === txHash &&
        String(found.note?.amount ?? "") === amount &&
        found.nullifierStatus === "unspent"
      );
      assert.ok(inputNote, `typed wallet scan should find one-proof ${shape.id} input ${index}`);
      return inputNote;
    });
    const inputCommitmentHexes = inputNotes.map(note => fieldHexV1(computeNoteCommitmentV1(note.note)));
    const pathProvider = await createCurrentRootPathProvider(
      client,
      inputCommitmentHexes
    );
    const treasuryNotes = await Promise.all(inputNotes.map(async (inputNote, index) => {
      const commitmentHex = inputCommitmentHexes[index];
      const path = await pathProvider.lookupMerklePath(commitmentHex);
      return {
        note_id: commitmentHex,
        owner_key_id: material.address,
        nullifier_lookup_key: inputNote.nullifier,
        nullifier_lookup_key_id: "e2e",
        denom: config.denom,
        amount: inputNote.note.amount.toString(),
        note: inputNote.note,
        merkle_path: path.path,
        merkle_path_helper: path.path_helper
      };
    }));
    // The E2E recipient is deliberately this wallet so the test can decrypt
    // the typed output and recompute recipient/amount evidence independently.
    const recipient = material.shieldedAddress;
    const plan = planOneProofPayroll({
      company_id: "clairveiljs-e2e",
      payroll_id: `one-proof-${shape.id}`,
      batch_id: `cosmos-e2e-${depositTxHashes[0].slice(0, 16).toLowerCase()}`,
      denom: config.denom,
      default_disclosure_policy: { user_privacy_policy: "all-private", user_disclosure_mode: "none" },
      items: shape.paymentAmounts.map((amount, index) => {
        const mode = shape.disclosureModes[index];
        const disclosurePolicy = mode === "public"
          ? { user_privacy_policy: "amount", user_disclosure_mode: "public" }
          : mode === "recipient-encrypted"
            ? { user_privacy_policy: "amount-from-to", user_disclosure_mode: "recipient-encrypted", user_disclosure_target_pubkey_hex: material.disclosurePubKeyHex }
            : undefined;
        return {
          item_id: `one-proof-item-${String(index).padStart(2, "0")}`,
          employee_id: `cosmos-e2e-recipient-${String(index).padStart(2, "0")}`,
          recipient_address: recipient,
          amount: coinAmount(amount, config.denom, `one-proof ${shape.id} payroll amount`),
          ...(disclosurePolicy ? { disclosure_policy: disclosurePolicy } : {})
        };
      })
    }, treasuryNotes, { shieldedPrefix: config.shieldedPrefix, outputMode: shape.outputMode });
    assert.equal(plan.operations.length, 1, `${shape.id} should produce one canonical batch operation`);
    assert.equal(plan.operations[0].input_notes.length, shape.inputAmounts.length, shape.id);
    const expectedOutputCount = shape.paymentAmounts.length +
      (plan.operations[0].has_change ? 1 : 0) +
      Number(plan.operations[0].padding_count ?? 0);
    assert.equal(plan.operations[0].output_count, expectedOutputCount, shape.id);
    assert.equal(expectedOutputCount, shape.expectedOutputRoles.length, `${shape.id} output count must match the pinned fixture`);
    const expectedPaymentDisclosure = shape.disclosureModes.map(mode => {
      if (mode === "public") return [1, 1];
      if (mode === "recipient-encrypted") return [7, 2]; // amount-from-to / recipient-encrypted
      return [0, 0];
    });
    assert.deepEqual(
      plan.operations[0].items.map(item => [item.disclosure_policy.user_privacy_policy, item.disclosure_policy.user_disclosure_mode]),
      expectedPaymentDisclosure,
      `${shape.id} payment disclosure policies must retain the selected shape contract`
    );

    const [auditConfig, latest] = await Promise.all([
      client.fetchAuditConfig(),
      latestChainBlock(config)
    ]);
    const auditKeyId = String(auditConfig?.audit_key_id ?? auditConfig?.auditKeyId ?? "").trim();
    const auditKeyEpoch = String(auditConfig?.audit_key_epoch ?? auditConfig?.auditKeyEpoch ?? "").trim();
    const auditTarget = String(auditConfig?.audit_master_pubkey_hex ?? auditConfig?.auditMasterPubkeyHex ?? "").trim();
    assert.ok(auditKeyId, "audit config must expose an audit key id");
    assert.match(auditKeyEpoch, /^[1-9][0-9]*$/, "audit config must expose a positive audit key epoch");
    assert.match(auditTarget, /^[0-9a-f]{64}$/i, "audit config must expose a compressed audit disclosure key");
    const noteHashSigner = createSpendNoteHashSigner(material.rootSeed);
    const prepared = await prepareOneProofPayrollOperation({
      operation: plan.operations[0],
      cosmos_client: client,
      creator: material.address,
      chain_id: config.chainId,
      expires_at_unix: latest.timeUnix + 1800,
      audit_key_id: auditKeyId,
      audit_key_epoch: auditKeyEpoch,
      audit_disclosure_target_pubkey: auditTarget,
      ...(shape.selfViewEnabled
        ? { self_view_disclosure_target_pubkey: material.disclosurePubKeyHex }
        : { disable_self_view_disclosure: true }),
      signer: {
        signBatchTransfer: request => noteHashSigner.signNoteHash(request.expectedIntent)
      }
    });
    assert.deepEqual(
      prepared.payload.outputs.slice(0, shape.paymentAmounts.length).map(output => [output.privacy_policy, output.disclosure_mode]),
      expectedPaymentDisclosure,
      `${shape.id} prepared payload must retain per-payment disclosure policy`
    );
    assert.deepEqual(
      prepared.payload.outputs.map(output => output.kind),
      shape.expectedOutputRoles,
      `${shape.id} prepared output roles must match the pinned fixture`
    );
    assert.deepEqual(
      prepared.payload.outputs.map(output => String(output.note.am)),
      shape.expectedOutputAmounts,
      `${shape.id} prepared output amounts must match the pinned fixture`
    );
    const expectedOutputDisclosure = shape.expectedDisclosureModes.map(mode => {
      if (mode === "public") return [1, 1];
      if (mode === "recipient-encrypted") return [7, 2];
      return [0, 0];
    });
    assert.deepEqual(
      prepared.payload.outputs.map(output => [output.privacy_policy, output.disclosure_mode]),
      expectedOutputDisclosure,
      `${shape.id} all output disclosure modes must match the pinned fixture`
    );
    for (const [index, mode] of shape.disclosureModes.entries()) {
      if (mode === "recipient-encrypted") {
        assert.notEqual(
          prepared.payload.message_outputs[index].user_disclosure_target_pubkey,
          "",
          `${shape.id} recipient-encrypted payment must carry its disclosure target`
        );
      }
    }
    const reservationStore = new MemoryReservationStore();
    const reservationManager = createNoteReservationManager({
      store: reservationStore,
      ownerKeyId: material.address,
      indexKey: material.rootSeed,
      leaseOwner: `one-proof-${shape.id}-pre-broadcast`
    });
    const reservationBatch = await prepareOneProofPayrollReservation(reservationManager, prepared, {
      metadata: { e2e: "one-proof-payroll" }
    });
    assert.equal(reservationBatch.reservations.length, shape.inputAmounts.length, shape.id);
    assert.equal(reservationBatch.reservations.every(reservation => reservation.status === "Proving"), true, shape.id);
    const execution = await provePreparedOneProofPayrollOperation(prepared, proverAdapter, {
      creator: material.address,
      checkNullifiers: values => client.checkNullifiers(values),
      nowUnix: latest.timeUnix
    });
    assert.equal(
      execution.message.outputs.every(output => output.selfViewDisclosurePayload.length === (shape.selfViewEnabled ? 472 : 0)),
      true,
      `${shape.id} self-view disclosure shape must match the pinned Clairveil contract`
    );
    const signDoc = await createOneProofPayrollBatchSignDoc(execution, {
      cosmosClient: client,
      signer: material.address,
      pubKeyHex: material.pubKeyHex,
      gasLimit: config.oneProofBatchGasLimit,
      nowUnix: latest.timeUnix
    });
    const signedCheckpoint = await client.signDirect({
      wallet,
      signDoc: signDoc.sign_doc
    });
    const signedArtifact = createOneProofPayrollArtifact({
      prepared,
      execution,
      reservationBatch,
      signDoc: signDoc.sign_doc,
      signedTxBytes: signedCheckpoint.txRawBytes,
      txHash: signedCheckpoint.txHash,
      txBytesHash: signedCheckpoint.txBytesHash,
      signDocHash: signedCheckpoint.signDocHash
    });
    const spentFenceSignDoc = await createOneProofPayrollBatchSignDoc(execution, {
      cosmosClient: client,
      signer: material.address,
      pubKeyHex: material.pubKeyHex,
      gasLimit: config.oneProofBatchGasLimit,
      nowUnix: latest.timeUnix,
      memo: `Clairveil spent-nullifier fence ${shape.id}`
    });
    const spentFenceCheckpoint = await client.signDirect({
      wallet,
      signDoc: spentFenceSignDoc.sign_doc
    });
    const spentFenceArtifact = createOneProofPayrollArtifact({
      prepared,
      execution,
      reservationBatch,
      signDoc: spentFenceSignDoc.sign_doc,
      signedTxBytes: spentFenceCheckpoint.txRawBytes,
      txHash: spentFenceCheckpoint.txHash,
      txBytesHash: spentFenceCheckpoint.txBytesHash,
      signDocHash: spentFenceCheckpoint.signDocHash
    });
    assert.notEqual(
      spentFenceArtifact.tx_hash,
      signedArtifact.tx_hash,
      `${shape.id} spent-nullifier fence must use a distinct exact signed TxRaw`
    );
    const retryInspection = await inspectOneProofPayrollArtifactRetry(signedArtifact, {
      nowUnix: latest.timeUnix,
      queryTransaction: async txHash => {
        const transaction = await client.getTx(txHash);
        if (!transaction) return "not-found";
        return Number(transaction.code) === 0 ? "succeeded" : "failed";
      },
      checkNullifiers: values => client.checkNullifiers(values)
    });
    assert.equal(retryInspection.next_action, "retransmit-signed-transaction", shape.id);
    const result = await retransmitOneProofPayrollArtifact(signedArtifact, {
      reservationManager,
      retryDecision: retryInspection.retry_decision,
      nowUnix: latest.timeUnix,
      broadcastSignedTx: bytes => client.broadcastTxRawBytes(bytes, {
        ...config.waitOptions,
        reservationManager,
        reservation: reservationBatch,
        getChainNowUnix: () => latestChainBlockTimeUnix(config)
      })
    });
    const batchTxHash = assertBroadcastOk(result, "one-proof payroll batch");
    assert.equal(batchTxHash, signedCheckpoint.txHash, shape.id);
    const restartedReservationStore = new MemoryReservationStore({
      state: JSON.parse(JSON.stringify(await reservationStore.load()))
    });
    const restartedReservationManager = createNoteReservationManager({
      store: restartedReservationStore,
      ownerKeyId: material.address,
      indexKey: material.rootSeed,
      leaseOwner: `one-proof-${shape.id}-after-restart`
    });
    const restartInspection = await inspectOneProofPayrollArtifactRetry(signedArtifact, {
      nowUnix: (await latestChainBlock(config)).timeUnix,
      queryTransaction: async txHash => {
        const transaction = await client.getTx(txHash);
        if (!transaction) return "not-found";
        return Number(transaction.code) === 0 ? "succeeded" : "failed";
      },
      checkNullifiers: values => client.checkNullifiers(values)
    });
    assert.equal(restartInspection.next_action, "reconcile-succeeded", `${shape.id} restart tx-hash lookup`);
    const spentFenceInspection = await inspectOneProofPayrollArtifactRetry(spentFenceArtifact, {
      nowUnix: (await latestChainBlock(config)).timeUnix,
      queryTransaction: async txHash => {
        const transaction = await client.getTx(txHash);
        if (!transaction) return "not-found";
        return Number(transaction.code) === 0 ? "succeeded" : "failed";
      },
      checkNullifiers: values => client.checkNullifiers(values)
    });
    assert.equal(spentFenceInspection.next_action, "manual-review", `${shape.id} spent-nullifier fence`);
    let spentFenceBroadcastCalls = 0;
    await assert.rejects(
      async () => retransmitOneProofPayrollArtifact(spentFenceArtifact, {
        reservationManager: restartedReservationManager,
        retryDecision: spentFenceInspection.retry_decision,
        nowUnix: (await latestChainBlock(config)).timeUnix,
        broadcastSignedTx: async () => {
          spentFenceBroadcastCalls += 1;
          throw new Error("spent-nullifier TxRaw must not reach broadcast");
        }
      }),
      /retry-safe decision|manual-review|cannot be retried/
    );
    assert.equal(spentFenceBroadcastCalls, 0, `${shape.id} spent-nullifier TxRaw must be rejected before RPC`);
    const submittedReservations = await Promise.all(
      reservationBatch.reservation_ids.map(id => restartedReservationManager.getReservation(id))
    );
    assert.equal(submittedReservations.every(reservation => reservation.status === "Submitted"), true, shape.id);
    assert.equal(submittedReservations.every(reservation =>
      reservation.submitted_tx_hash === signedArtifact.tx_hash &&
      reservation.tx_bytes_hash === signedArtifact.tx_bytes_hash &&
      reservation.sign_doc_hash === signedArtifact.sign_doc_hash
    ), true, `${shape.id} must persist the exact signed artifact identity`);
    const expected = execution.operation_evidence.expected_evidence;
    const chainDomain = computeChainDomainV1(prepared.payload.chain_id, prepared.payload.circuit_set_id);
    const expectedSummary = {
      effectIdHex: computeBatchEffectIdV1({
        chainDomainHi: chainDomain.hi,
        chainDomainLo: chainDomain.lo,
        merkleRoot: bytesToBigIntBE(execution.message.root),
        inputCount: execution.message.nullifiers.length,
        outputCount: execution.message.outputs.length,
        nullifierRoot: BigInt(prepared.payload.nullifier_root),
        commitmentRoot: BigInt(prepared.payload.commitment_root),
        userDisclosureRoot: BigInt(prepared.payload.user_disclosure_root),
        fullDisclosureRoot: BigInt(prepared.payload.full_disclosure_root),
        payloadDigestHi: BigInt(prepared.payload.payload_digest_hi),
        payloadDigestLo: BigInt(prepared.payload.payload_digest_lo),
        expiresAtUnix: prepared.payload.expires_at_unix
      }),
      nullifierHexes: execution.message.nullifiers.map(value => hexFromBytes(value).toLowerCase()),
      auditTargetHex: hexFromBytes(execution.message.auditDisclosureTargetPubkey).toLowerCase()
    };
    const typed = await typedBatchOutputsForTransaction(
      client,
      batchTxHash,
      expectedOutputCount,
      material,
      config,
      expectedSummary
    );
    for (const [index, entry] of typed.entries()) {
      const mode = shape.disclosureModes[index];
      const amount = shape.paymentAmounts[index];
      if (mode !== "none") {
        const userDisclosure = await client.decodeBatchUserDisclosure({
          output: entry.output,
          txHash: batchTxHash,
          disclosureScalar: material.disclosureScalar,
          disclosurePubKeyHex: material.disclosurePubKeyHex,
          assetDenom: config.denom
        });
        assertDisclosureReport(userDisclosure, `${shape.id} user output ${index}`, config, amount);
      }
      if (shape.selfViewEnabled) {
        const selfViewDisclosure = await client.decodeBatchSelfViewDisclosure({
          output: entry.output,
          txHash: batchTxHash,
          disclosureScalar: material.disclosureScalar,
          assetDenom: config.denom
        });
        assertDisclosureReport(selfViewDisclosure, `${shape.id} self-view output ${index}`, config, amount);
      }
      const auditDisclosure = await client.decodeBatchAuditDisclosure({
        output: entry.output,
        txHash: batchTxHash,
        disclosurePrivKeyHex: config.auditDisclosurePrivKeyHex,
        assetDenom: config.denom
      });
      assertDisclosureReport(auditDisclosure, `${shape.id} audit output ${index}`, config, amount);
    }
    const observedOutputs = typed.map(entry => {
      const observedRecipient = encodeShieldedAddress({
        x: entry.found.note.receiverSpendPubKeyX,
        y: entry.found.note.receiverSpendPubKeyY
      }, {
        x: entry.found.note.receiverViewPubKeyX,
        y: entry.found.note.receiverViewPubKeyY
      }, { prefix: config.shieldedPrefix });
      return {
        output_index: entry.output.output_index,
        commitment: hexFromBytes(entry.output.commitment),
        user_disclosure_digest: entry.output.user_disclosure_digest.length
          ? hexFromBytes(entry.output.user_disclosure_digest)
          : "",
        full_disclosure_digest: hexFromBytes(entry.output.full_disclosure_digest),
        recipient_hash: hashRecipient(observedRecipient, { shieldedPrefix: config.shieldedPrefix }),
        amount_hash: hashAmount(config.denom, entry.found.note.amount),
        denom: config.denom,
        audit_key_id: entry.output.audit_key_id,
        audit_key_epoch: entry.output.audit_key_epoch
      };
    });
    const reconciliation = await reconcileOneProofPayrollReservation({
      reservationManager: restartedReservationManager,
      reservationBatch,
      prepared,
      operation_evidence: execution.operation_evidence,
      checkNullifiers: values => client.checkNullifiers(values),
      tx_succeeded: true,
      tx_hash: batchTxHash,
      observed_outputs: observedOutputs
    });
    assert.equal(reconciliation.reconciliation.status, "Succeeded");
    assert.equal(reconciliation.reconciliation.items.every(item => item.status === "Succeeded"), true, shape.id);
    assert.equal(reconciliation.reservation_action, "ConfirmedSpent");
    assert.equal(reconciliation.reservations.every(reservation => reservation.status === "ConfirmedSpent"), true, shape.id);
    }
  } finally {
    await client.disconnect();
  }
});
