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
  encodeShieldedAddress
} from "clairveiljs/core";
import {
  planOneProofPayroll,
  prepareOneProofPayrollOperation,
  provePreparedOneProofPayrollOperation,
  createOneProofPayrollBatchSignDoc,
  reconcileOneProofPayrollOperationEvidence
} from "clairveiljs/reference-payroll";
import {
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

async function createCurrentRootPathProvider(client, commitmentHex, snapshotHeight) {
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
    commitmentHexes: [commitmentHex],
    rootHex,
    snapshotHeight: exactSnapshotHeight
  });
}

async function typedBatchOutputForTransaction(client, txHash, commitmentHex, material, config) {
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
        const output = scanned.outputs.find(candidate =>
          candidate.event_type === privacyScanEventTypeV2.batchTransfer &&
          hexFromBytes(candidate.tx_hash).toUpperCase() === txHash.toUpperCase() &&
          hexFromBytes(candidate.commitment).toLowerCase() === commitmentHex.toLowerCase()
        );
        if (output) {
          const found = processPrivacyScanPageV2(scanned, { rootSeed: material.rootSeed })
            .find(candidate => String(candidate.commitment_hex || "").toLowerCase() === commitmentHex.toLowerCase());
          if (!found) throw new Error("typed batch output did not decrypt for the configured E2E wallet");
          return { output, found };
        }
        if (!scanned.has_more) break;
        after = {
          height: scanned.next_cursor.height,
          globalSequence: scanned.next_cursor.global_sequence,
          outputIndex: scanned.next_cursor.output_index
        };
      }
      lastError = new Error("typed privacy scan has not indexed the one-proof batch output yet");
    } catch (error) {
      lastError = error;
    }
    if (attempt < config.waitOptions.attempts) {
      await new Promise(resolve => setTimeout(resolve, config.waitOptions.intervalMs));
    }
  }
  throw lastError || new Error("typed privacy scan did not return the one-proof batch output");
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

test("local one-proof payroll batch proves, broadcasts, and reconciles typed output evidence", {
  timeout: positiveIntegerEnv("CLAIRVEIL_E2E_ONE_PROOF_BATCH_TIMEOUT_MS", 600000),
  skip: oneProofBatchEnabled
    ? false
    : "set CLAIRVEIL_E2E_LOCAL=1, CLAIRVEIL_E2E_FULL_FLOW=1, and CLAIRVEIL_E2E_ONE_PROOF_BATCH=1 to run one-proof batch E2E"
}, async t => {
  const config = configFromEnv();
  const wallet = await loadE2eWallet(config);
  if (!wallet) {
    t.skip("set CLAIRVEIL_E2E_WALLET_MODULE or CLAIRVEIL_E2E_MNEMONIC plus CLAIRVEIL_E2E_ROOT_SIGNATURE_BASE64");
    return;
  }
  const depositProofProvider = await loadDepositProofProvider(config);
  if (!depositProofProvider) {
    t.skip("set CLAIRVEIL_E2E_DEPOSIT_PROOF_MODULE to fund the one-proof batch input note");
    return;
  }

  const client = createClient(config);
  const proverAdapter = createHttpProverAdapter({
    baseURL: config.proverUrl,
    timeoutMs: config.proverTimeoutMs
  });
  try {
    const material = await client.deriveWalletPrivacyMaterial(wallet);
    const depositTxHash = await prepareDepositAndBroadcast(
      client,
      wallet,
      material,
      config.oneProofBatchDepositAmount,
      config,
      depositProofProvider
    );
    const scan = await scanWallet(client, wallet, material, config);
    const inputNote = scan.foundNotes.find(found =>
      String(found.txHash || "").toUpperCase() === depositTxHash &&
      String(found.note?.amount ?? "") === coinAmount(config.oneProofBatchDepositAmount, config.denom, "one-proof deposit amount") &&
      found.nullifierStatus === "unspent"
    );
    assert.ok(inputNote, "typed wallet scan should find the freshly deposited one-proof input note");

    const pathProvider = await createCurrentRootPathProvider(client, inputNote.commitment_hex, inputNote.height);
    const path = await pathProvider.lookupMerklePath(inputNote.commitment_hex);
    // The E2E recipient is deliberately this wallet so the test can decrypt
    // the typed output and recompute recipient/amount evidence independently.
    const recipient = material.shieldedAddress;
    const payrollAmount = coinAmount(config.oneProofBatchPayrollAmount, config.denom, "one-proof payroll amount");
    const plan = planOneProofPayroll({
      company_id: "clairveiljs-e2e",
      payroll_id: "one-proof-payroll",
      batch_id: `localnet-${depositTxHash.slice(0, 16).toLowerCase()}`,
      denom: config.denom,
      default_disclosure_policy: { user_privacy_policy: "all-private", user_disclosure_mode: "none" },
      items: [{
        item_id: "one-proof-item-0",
        employee_id: "localnet-recipient",
        recipient_address: recipient,
        amount: payrollAmount
      }]
    }, [{
      note_id: inputNote.commitment_hex,
      owner_key_id: material.address,
      nullifier_lookup_key: inputNote.nullifier,
      nullifier_lookup_key_id: "e2e",
      denom: config.denom,
      amount: inputNote.note.amount.toString(),
      note: inputNote.note,
      merkle_path: path.path,
      merkle_path_helper: path.path_helper
    }], { shieldedPrefix: config.shieldedPrefix });
    assert.equal(plan.operations.length, 1, "one input should produce one canonical batch operation");

    const [auditConfig, latest] = await Promise.all([
      client.fetchAuditConfig(),
      latestChainBlock(config)
    ]);
    const auditKeyId = String(auditConfig?.audit_key_id ?? auditConfig?.auditKeyId ?? "").trim();
    const auditKeyEpoch = Number(auditConfig?.audit_key_epoch ?? auditConfig?.auditKeyEpoch);
    const auditTarget = String(auditConfig?.audit_master_pubkey_hex ?? auditConfig?.auditMasterPubkeyHex ?? "").trim();
    assert.ok(auditKeyId, "audit config must expose an audit key id");
    assert.ok(Number.isSafeInteger(auditKeyEpoch) && auditKeyEpoch > 0, "audit config must expose a positive audit key epoch");
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
      disable_self_view_disclosure: true,
      signer: {
        signBatchTransfer: request => noteHashSigner.signNoteHash(request.expected_intent)
      }
    });
    const execution = await provePreparedOneProofPayrollOperation(prepared, proverAdapter, {
      creator: material.address,
      checkNullifiers: values => client.checkNullifiers(values),
      nowUnix: latest.timeUnix
    });
    const signDoc = await createOneProofPayrollBatchSignDoc(execution, {
      cosmosClient: client,
      signer: material.address,
      pubKeyHex: material.pubKeyHex,
      gasLimit: config.oneProofBatchGasLimit,
      nowUnix: latest.timeUnix
    });
    const result = await client.signDirectAndBroadcast({
      wallet,
      signDoc: signDoc.sign_doc,
      waitOptions: config.waitOptions
    });
    const batchTxHash = assertBroadcastOk(result, "one-proof payroll batch");
    const expected = execution.operation_evidence.expected_evidence[0];
    const typed = await typedBatchOutputForTransaction(
      client,
      batchTxHash,
      expected.expected_output_commitment,
      material,
      config
    );
    const observedRecipient = encodeShieldedAddress({
      x: typed.found.note.receiverSpendPubKeyX,
      y: typed.found.note.receiverSpendPubKeyY
    }, {
      x: typed.found.note.receiverViewPubKeyX,
      y: typed.found.note.receiverViewPubKeyY
    }, { prefix: config.shieldedPrefix });
    const reconciliation = await reconcileOneProofPayrollOperationEvidence({
      prepared,
      operation_evidence: execution.operation_evidence,
      checkNullifiers: values => client.checkNullifiers(values),
      tx_succeeded: true,
      observed_outputs: [{
        output_index: typed.output.output_index,
        commitment: hexFromBytes(typed.output.commitment),
        user_disclosure_digest: typed.output.user_disclosure_digest.length
          ? hexFromBytes(typed.output.user_disclosure_digest)
          : "",
        full_disclosure_digest: hexFromBytes(typed.output.full_disclosure_digest),
        recipient_hash: hashRecipient(observedRecipient, { shieldedPrefix: config.shieldedPrefix }),
        amount_hash: hashAmount(config.denom, typed.found.note.amount),
        denom: config.denom
      }]
    });
    assert.equal(reconciliation.status, "Succeeded");
    assert.equal(reconciliation.items[0].status, "Succeeded");
  } finally {
    await client.disconnect();
  }
});
