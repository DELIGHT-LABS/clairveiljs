import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import {
  createClairveilClient,
  createHttpProverAdapter
} from "clairveiljs";
import {
  createOfflineSignerWalletAdapter,
  createWalletAdapter
} from "clairveiljs/wallet-adapter";

const env = process.env;
const localE2eEnabled = env.CLAIRVEIL_E2E_LOCAL === "1";
const fullFlowEnabled = localE2eEnabled && env.CLAIRVEIL_E2E_FULL_FLOW === "1";

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

function configFromEnv() {
  const denom = String(env.CLAIRVEIL_E2E_DENOM || "uclair");
  const transferAmount = coinEnv("CLAIRVEIL_E2E_TRANSFER_AMOUNT", "1", denom);
  return {
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
}

function createClient(config) {
  return createClairveilClient({
    rpc: config.rpc,
    rest: config.rest,
    chainId: config.chainId,
    accountPrefix: config.accountPrefix,
    shieldedPrefix: config.shieldedPrefix,
    defaultDenom: config.denom
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
  const signer = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, {
    prefix: config.accountPrefix
  });
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

async function latestChainBlockTimeUnix(config) {
  const response = await fetch(`${config.rest}/cosmos/base/tendermint/v1beta1/blocks/latest`);
  if (!response.ok) {
    throw new Error(`latest block time query failed with HTTP ${response.status}`);
  }
  const data = await response.json();
  const value = data?.block?.header?.time ?? data?.sdk_block?.header?.time;
  const milliseconds = Date.parse(String(value || ""));
  if (!Number.isFinite(milliseconds)) throw new Error("latest block response omitted a valid block time");
  return Math.floor(milliseconds / 1000);
}

async function broadcastPrepared(client, wallet, prepared, label, config, { relayWithdraw = false } = {}) {
  assert.equal(prepared.status, "ready", `${label} should be ready`);
  assert.ok(prepared.signDoc, `${label} should include a signDoc`);
  if (relayWithdraw) assert.ok(prepared.payload, `${label} should include a withdraw payload`);
  const result = await client.signDirectAndBroadcast({
    wallet,
    signDoc: prepared.signDoc,
    ...(relayWithdraw ? {
      relayPayload: prepared.payload,
      getChainNowUnix: () => latestChainBlockTimeUnix(config)
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
  return broadcastPrepared(client, wallet, prepared, `deposit ${amount}`, config);
}

async function prepareFinalTransfer(client, wallet, material, proverAdapter, recipient, amount, config, depositProofProvider) {
  let createdZeroHelper = false;
  for (let step = 1; step <= config.maxPlannerSteps; step += 1) {
    const prepared = await client.prepareTransfer({
      wallet,
      material,
      amount,
      recipient,
      proverAdapter,
      userPrivacyPolicy: "amount-from-to",
      userDisclosureMode: "public",
      allowPlanStep: true,
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

test("local Clairveil node endpoints respond", {
  skip: localE2eEnabled ? false : "set CLAIRVEIL_E2E_LOCAL=1 to run against a local Clairveil node"
}, async () => {
  const config = configFromEnv();
  const client = createClient(config);

  try {
    const [events, treeState, auditConfig, reserve] = await Promise.all([
      client.fetchPrivacyEvents({ limit: 1 }),
      client.fetchTreeState(),
      client.fetchAuditConfig(),
      client.fetchReserve(config.denom)
    ]);

    assert.ok(Array.isArray(events.events), "privacy events response should include events");
    assert.equal(typeof treeState, "object", "tree state should be an object");
    assert.equal(typeof auditConfig, "object", "audit config should be an object");
    assert.equal(reserve.denom, config.denom, "reserve response should echo denom");
  } finally {
    await client.disconnect();
  }
});

test("local full deposit, scan, transfer, disclosure, and withdraw flow", {
  timeout: positiveIntegerEnv("CLAIRVEIL_E2E_FULL_FLOW_TIMEOUT_MS", 600000),
  skip: fullFlowEnabled
    ? false
    : "set CLAIRVEIL_E2E_LOCAL=1 and CLAIRVEIL_E2E_FULL_FLOW=1 to run tx flow"
}, async t => {
  const config = configFromEnv();
  const wallet = await loadE2eWallet(config);
  if (!wallet) {
    t.skip("set CLAIRVEIL_E2E_WALLET_MODULE or CLAIRVEIL_E2E_MNEMONIC plus CLAIRVEIL_E2E_ROOT_SIGNATURE_BASE64");
    return;
  }
  const depositProofProvider = await loadDepositProofProvider(config);
  if (!depositProofProvider) {
    t.skip("set CLAIRVEIL_E2E_DEPOSIT_PROOF_MODULE to run the full deposit flow");
    return;
  }

  const client = createClient(config);
  const proverAdapter = createHttpProverAdapter({
    baseURL: config.proverUrl,
    timeoutMs: config.proverTimeoutMs
  });

  try {
    const material = await client.deriveWalletPrivacyMaterial(wallet);
    assert.match(material.address, new RegExp(`^${config.accountPrefix}1`));
    assert.match(material.shieldedAddress, new RegExp(`^${config.shieldedPrefix}1`));

    await prepareDepositAndBroadcast(client, wallet, material, config.depositAmount, config, depositProofProvider);

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

    const disclosure = await client.decodeUserDisclosure({ txHash: transferTxHash });
    assertDisclosureReport(disclosure, "public transfer", config, config.transferAmount);

    const selfViewDisclosure = await client.decodeSelfViewDisclosure({
      txHash: transferTxHash,
      disclosureScalar: material.disclosureScalar
    });
    assertDisclosureReport(selfViewDisclosure, "sender self-view", config, config.transferAmount);

    if (config.auditDisclosurePrivKeyHex) {
      const auditDisclosure = await client.decodeAuditDisclosure({
        txHash: transferTxHash,
        disclosurePrivKeyHex: config.auditDisclosurePrivKeyHex
      });
      assertDisclosureReport(auditDisclosure, "audit", config, config.transferAmount);
    }

    const withdrawRecipient = String(env.CLAIRVEIL_E2E_WITHDRAW_RECIPIENT || "").trim()
      || material.address;
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

    await broadcastPrepared(client, wallet, withdraw, "withdraw", config, { relayWithdraw: true });
  } finally {
    await client.disconnect();
  }
});
