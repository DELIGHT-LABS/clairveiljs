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
import {
  createSpendNoteHashSigner,
  encodeShieldedAddress,
  computeNoteCommitmentV1,
  fieldHexV1
} from "clairveiljs/core";
import {
  planOneProofPayroll,
  prepareOneProofPayrollOperation,
  prepareOneProofPayrollReservation,
  provePreparedOneProofPayrollOperation,
  createOneProofPayrollBatchSignDoc,
  markOneProofPayrollReservationProofReady,
  markOneProofPayrollReservationBroadcastAttempting,
  markOneProofPayrollReservationSubmitted,
  reconcileOneProofPayrollReservation
} from "clairveiljs/reference-payroll";
import {
  MemoryReservationStore,
  createNoteReservationManager,
  hashAmount,
  hashRecipient
} from "clairveiljs/reservation";
import {
  privacyScanEventTypeV2,
  processPrivacyScanPageV2,
  validatePrivacyScanPageV2
} from "clairveiljs/scan";
import {
  hexFromBytes
} from "clairveiljs/browser-crypto";

const env = process.env;
const localE2eEnabled = env.CLAIRVEIL_E2E_LOCAL === "1";
const fullFlowEnabled = localE2eEnabled && env.CLAIRVEIL_E2E_FULL_FLOW === "1";
const oneProofBatchEnabled = fullFlowEnabled && env.CLAIRVEIL_E2E_ONE_PROOF_BATCH === "1";
const e2eRequired = env.CLAIRVEIL_E2E_REQUIRED === "1";

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
    oneProofBatchDepositAmount: coinEnv("CLAIRVEIL_E2E_ONE_PROOF_DEPOSIT_AMOUNT", "10", denom),
    oneProofBatchPayrollAmount: coinEnvOrDefaultCoin(
      "CLAIRVEIL_E2E_ONE_PROOF_PAYROLL_AMOUNT",
      coinEnv("CLAIRVEIL_E2E_ONE_PROOF_DEPOSIT_AMOUNT", "10", denom),
      denom
    ),
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

function coinAmount(coin, denom, label) {
  const match = String(coin || "").match(/^(0|[1-9][0-9]*)([A-Za-z][A-Za-z0-9/:._-]{2,127})$/);
  if (!match || match[2] !== denom) throw new Error(`${label} must be a canonical ${denom} coin`);
  return match[1];
}

async function createCurrentRootPathProvider(client, commitmentHexes, snapshotHeight) {
  const configuredRoot = String(env.CLAIRVEIL_E2E_ONE_PROOF_ROOT_HEX || "").trim();
  const configuredHeight = String(env.CLAIRVEIL_E2E_ONE_PROOF_SNAPSHOT_HEIGHT || "").trim();
  if (Boolean(configuredRoot) !== Boolean(configuredHeight)) {
    throw new Error("CLAIRVEIL_E2E_ONE_PROOF_ROOT_HEX and CLAIRVEIL_E2E_ONE_PROOF_SNAPSHOT_HEIGHT must be set together");
  }
  const treeState = await client.fetchTreeState();
  const rootHex = configuredRoot || String(treeState?.root ?? treeState?.root_hex ?? treeState?.rootHex ?? "").trim();
  const exactSnapshotHeight = configuredHeight || String(snapshotHeight ?? "").trim();
  if (!rootHex || !/^(0|[1-9][0-9]*)$/.test(exactSnapshotHeight)) {
    throw new Error("one-proof batch E2E requires a current tree root and exact snapshot height");
  }
  return client.createCommitmentPathSnapshotProvider({
    commitmentHexes: Array.isArray(commitmentHexes) ? commitmentHexes : [commitmentHexes],
    rootHex,
    snapshotHeight: exactSnapshotHeight
  });
}

async function typedBatchOutputsForTransaction(client, txHash, commitmentHexes, material, config) {
  const requested = [...commitmentHexes].map(value => String(value).toLowerCase());
  const remaining = new Set(requested);
  const foundByCommitment = new Map();
  let after = { height: 0, globalSequence: 0, outputIndex: 0 };
  let lastError = null;
  for (let attempt = 1; attempt <= config.waitOptions.attempts; attempt += 1) {
    try {
      for (let page = 0; page < config.scanMaxPages; page += 1) {
        const request = {
          after,
          outputLimit: config.scanLimit,
          eventLimit: config.scanLimit,
          eventTypes: []
        };
        const scanned = validatePrivacyScanPageV2(await client.fetchPrivacyScan(request), request);
        const matchingOutputs = scanned.outputs.filter(candidate =>
          candidate.event_type === privacyScanEventTypeV2.batchTransfer &&
          hexFromBytes(candidate.tx_hash).toUpperCase() === txHash.toUpperCase() &&
          remaining.has(hexFromBytes(candidate.commitment).toLowerCase())
        );
        if (matchingOutputs.length) {
          const found = processPrivacyScanPageV2(scanned, { rootSeed: material.rootSeed });
          for (const output of matchingOutputs) {
            const commitment = hexFromBytes(output.commitment).toLowerCase();
            const note = found.find(candidate => fieldHexV1(computeNoteCommitmentV1(candidate.note)) === commitment);
            if (!note) throw new Error("typed batch output did not decrypt for the configured E2E wallet");
            foundByCommitment.set(commitment, { output, found: note });
            remaining.delete(commitment);
          }
          if (!remaining.size) return requested.map(commitment => foundByCommitment.get(commitment));
        }
        if (!scanned.has_more) break;
        after = {
          height: scanned.next_cursor.height,
          globalSequence: scanned.next_cursor.global_sequence,
          outputIndex: scanned.next_cursor.output_index
        };
      }
      lastError = new Error("typed privacy scan has not indexed every one-proof batch output yet");
    } catch (error) {
      lastError = error;
    }
    if (attempt < config.waitOptions.attempts) {
      await new Promise(resolve => setTimeout(resolve, config.waitOptions.intervalMs));
    }
  }
  throw lastError || new Error("typed privacy scan did not return every one-proof batch output");
}

function oneProofBatchShape(selectedValue, config) {
  const selected = String(selectedValue || "one-input-one-payment").trim().toLowerCase();
  const coin = amount => `${amount}${config.denom}`;
  if (selected === "one-input-one-payment" || selected === "1-1") {
    return {
      id: "one-input-one-payment",
      inputAmounts: [config.oneProofBatchDepositAmount],
      paymentAmounts: [config.oneProofBatchPayrollAmount],
      disclosureModes: ["none"],
      outputMode: "compact",
      selfViewEnabled: true
    };
  }
  if (selected === "three-input-four-output" || selected === "3-4") {
    return {
      id: "three-input-four-output",
      inputAmounts: [coin(4), coin(5), coin(7)],
      paymentAmounts: [coin(4), coin(5), coin(6)],
      disclosureModes: ["none", "public", "recipient-encrypted"],
      outputMode: "compact",
      selfViewEnabled: true
    };
  }
  if (selected === "thirty-one-payments-plus-change" || selected === "16-31-change") {
    return {
      id: "thirty-one-payments-plus-change",
      inputAmounts: Array(16).fill(coin(100)),
      paymentAmounts: Array(31).fill(coin(50)),
      disclosureModes: Array(31).fill("none"),
      outputMode: "compact",
      selfViewEnabled: false
    };
  }
  if (selected === "exact-thirty-two-payments" || selected === "16-32") {
    return {
      id: "exact-thirty-two-payments",
      inputAmounts: Array(16).fill(coin(64)),
      paymentAmounts: Array(32).fill(coin(32)),
      disclosureModes: Array(32).fill("none"),
      outputMode: "compact",
      selfViewEnabled: true
    };
  }
  if (selected === "explicit-zero-padding" || selected === "padding") {
    return {
      id: "explicit-zero-padding",
      inputAmounts: [coin(5)],
      paymentAmounts: [coin(5)],
      disclosureModes: ["none"],
      outputMode: "exact32",
      selfViewEnabled: false
    };
  }
  throw new Error("CLAIRVEIL_E2E_ONE_PROOF_BATCH_SHAPE must be one-input-one-payment, three-input-four-output, thirty-one-payments-plus-change, exact-thirty-two-payments, or explicit-zero-padding");
}

function selectedOneProofBatchShape(config) {
  return oneProofBatchShape(env.CLAIRVEIL_E2E_ONE_PROOF_BATCH_SHAPE, config);
}

function selectedOneProofBatchShapes(config) {
  const selected = String(env.CLAIRVEIL_E2E_ONE_PROOF_BATCH_SHAPE || "one-input-one-payment").trim().toLowerCase();
  if (selected !== "all") return [selectedOneProofBatchShape(config)];
  return [
    "one-input-one-payment",
    "three-input-four-output",
    "thirty-one-payments-plus-change",
    "exact-thirty-two-payments",
    "explicit-zero-padding"
  ].map(shape => oneProofBatchShape(shape, config));
}

test("one-proof local E2E shape profiles retain the v0.2 disclosure contract", () => {
  const config = {
    denom: "uclair",
    oneProofBatchDepositAmount: "10uclair",
    oneProofBatchPayrollAmount: "10uclair"
  };
  const cases = [
    {
      id: "one-input-one-payment",
      selfViewEnabled: true,
      outputMode: "compact",
      inputCount: 1,
      paymentCount: 1,
      disclosureModes: ["none"]
    },
    {
      id: "three-input-four-output",
      selfViewEnabled: true,
      outputMode: "compact",
      inputCount: 3,
      paymentCount: 3,
      disclosureModes: ["none", "public", "recipient-encrypted"]
    },
    {
      id: "thirty-one-payments-plus-change",
      selfViewEnabled: false,
      outputMode: "compact",
      inputCount: 16,
      paymentCount: 31,
      disclosureModes: Array(31).fill("none")
    },
    {
      id: "exact-thirty-two-payments",
      selfViewEnabled: true,
      outputMode: "compact",
      inputCount: 16,
      paymentCount: 32,
      disclosureModes: Array(32).fill("none")
    },
    {
      id: "explicit-zero-padding",
      selfViewEnabled: false,
      outputMode: "exact32",
      inputCount: 1,
      paymentCount: 1,
      disclosureModes: ["none"]
    }
  ];
  for (const expected of cases) {
    const shape = oneProofBatchShape(expected.id, config);
    assert.equal(shape.selfViewEnabled, expected.selfViewEnabled, expected.id);
    assert.equal(shape.outputMode, expected.outputMode, expected.id);
    assert.equal(shape.inputAmounts.length, expected.inputCount, expected.id);
    assert.equal(shape.paymentAmounts.length, expected.paymentCount, expected.id);
    assert.deepEqual(shape.disclosureModes, expected.disclosureModes, expected.id);
  }
});

test("local Clairveil node endpoints respond", {
  skip: localE2eEnabled ? false : "set CLAIRVEIL_E2E_LOCAL=1 to run against a local Clairveil node"
}, async () => {
  const config = configFromEnv();
  const client = createClient(config);

  try {
    const [events, treeState, auditConfig, disclosureConfig, reserve] = await Promise.all([
      client.fetchPrivacyEvents({ limit: 1 }),
      client.fetchTreeState(),
      client.queryAuditConfig(),
      client.queryDisclosureConfig(),
      client.queryReserve(config.denom)
    ]);

    assert.ok(Array.isArray(events.events), "privacy events response should include events");
    assert.equal(typeof treeState, "object", "tree state should be an object");
    assert.equal(typeof auditConfig, "object", "audit config should be an object");
    assert.equal(disclosureConfig.audit_disclosure_required, true, "disclosure config should require audit disclosure");
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
    skipOrRequire(t, "set CLAIRVEIL_E2E_WALLET_MODULE or CLAIRVEIL_E2E_MNEMONIC plus CLAIRVEIL_E2E_ROOT_SIGNATURE_BASE64");
    return;
  }
  const depositProofProvider = await loadDepositProofProvider(config);
  if (!depositProofProvider) {
    skipOrRequire(t, "set CLAIRVEIL_E2E_DEPOSIT_PROOF_MODULE to run the full deposit flow");
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
    assert.equal((await client.queryReserve(config.denom)).invariant_holds, true, "reserve invariant should hold after withdraw");
  } finally {
    await client.disconnect();
  }
});

test("local one-proof payroll batch proves, broadcasts, and reconciles typed output evidence", {
  timeout: positiveIntegerEnv("CLAIRVEIL_E2E_ONE_PROOF_BATCH_TIMEOUT_MS", 1800000),
  skip: oneProofBatchEnabled
    ? false
    : "set CLAIRVEIL_E2E_LOCAL=1, CLAIRVEIL_E2E_FULL_FLOW=1, and CLAIRVEIL_E2E_ONE_PROOF_BATCH=1 to run one-proof batch E2E"
}, async t => {
  const config = configFromEnv();
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
    const snapshotHeight = inputNotes.reduce((latestHeight, note) =>
      BigInt(note.height) > BigInt(latestHeight) ? String(note.height) : latestHeight,
    String(inputNotes[0].height));
    const inputCommitmentHexes = inputNotes.map(note => fieldHexV1(computeNoteCommitmentV1(note.note)));
    const pathProvider = await createCurrentRootPathProvider(
      client,
      inputCommitmentHexes,
      snapshotHeight
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
      batch_id: `localnet-${depositTxHashes[0].slice(0, 16).toLowerCase()}`,
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
          employee_id: `localnet-recipient-${String(index).padStart(2, "0")}`,
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
    for (const [index, mode] of shape.disclosureModes.entries()) {
      if (mode === "recipient-encrypted") {
        assert.notEqual(
          prepared.payload.message_outputs[index].user_disclosure_target_pubkey,
          "",
          `${shape.id} recipient-encrypted payment must carry its disclosure target`
        );
      }
    }
    const reservationManager = createNoteReservationManager({
      store: new MemoryReservationStore(),
      ownerKeyId: material.address,
      indexKey: material.rootSeed
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
      `${shape.id} self-view disclosure shape must match the Clairveil localnet contract`
    );
    const proofReadyReservations = await markOneProofPayrollReservationProofReady(
      reservationManager,
      reservationBatch,
      execution
    );
    assert.equal(proofReadyReservations.every(reservation => reservation.status === "ProofReady"), true, shape.id);
    const signDoc = await createOneProofPayrollBatchSignDoc(execution, {
      cosmosClient: client,
      signer: material.address,
      pubKeyHex: material.pubKeyHex,
      gasLimit: config.oneProofBatchGasLimit,
      nowUnix: latest.timeUnix
    });
    const broadcastingReservations = await markOneProofPayrollReservationBroadcastAttempting(
      reservationManager,
      reservationBatch,
      execution,
      { metadata: { e2e: "one-proof-payroll" } }
    );
    assert.equal(broadcastingReservations.every(reservation => reservation.broadcast_in_flight === true), true, shape.id);
    const result = await client.signDirectAndBroadcast({
      wallet,
      signDoc: signDoc.sign_doc,
      waitOptions: config.waitOptions
    });
    const batchTxHash = assertBroadcastOk(result, "one-proof payroll batch");
    const submittedReservations = await markOneProofPayrollReservationSubmitted(
      reservationManager,
      reservationBatch,
      execution,
      { txHash: batchTxHash }
    );
    assert.equal(submittedReservations.every(reservation => reservation.status === "Submitted"), true, shape.id);
    const expected = execution.operation_evidence.expected_evidence;
    const typed = await typedBatchOutputsForTransaction(
      client,
      batchTxHash,
      expected.map(item => item.expected_output_commitment),
      material,
      config
    );
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
        denom: config.denom
      };
    });
    const reconciliation = await reconcileOneProofPayrollReservation({
      reservationManager,
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
