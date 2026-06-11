import {
  assertSignerPubKey,
  buildRootSigningMessage,
  createClairveilClient,
  verifySignerPubKey
} from "../transport/cosmos-client.js";
import {
  createClairveilEvmClient,
  evmAddressToBech32,
  isEvmAddress,
  normalizeEvmAddress
} from "../transport/evm.js";
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
  assertPlanCanBuildTx,
  planTransferNotes,
  planWithdrawNotes
} from "../privacy/planner.js";
import {
  createHttpProverAdapter
} from "../privacy/prover.js";

const defaultPrepareScanMaxPages = 1000;

function trimTrailingSlash(value) {
  return String(value || "").replace(/\/$/, "");
}

function normalizeRpcEndpoint(value) {
  return trimTrailingSlash(String(value || "").replace(/^tcp:\/\//, "http://"));
}

function browserJsonReplacer(_key, value) {
  return typeof value === "bigint" ? value.toString() : value;
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      accept: "application/json",
      ...(options.body ? { "content-type": "application/json" } : {}),
      ...(options.headers || {})
    }
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
}

function privacyEventsQuery({
  afterHeight,
  after_height,
  page,
  limit,
  eventTypes,
  event_types
} = {}) {
  const params = new URLSearchParams();
  const resolvedAfterHeight = afterHeight ?? after_height;
  if (resolvedAfterHeight != null) params.set("after_height", String(resolvedAfterHeight));
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

function walletTypeFromBody(body = {}) {
  const walletType = body.walletType ?? body.wallet_type ?? "cosmos";
  if (walletType === "cosmos" || walletType === "evm") return walletType;
  throw new ClairveilError(
    ClairveilErrorCode.INVALID_ARGUMENT,
    `unsupported wallet type: ${String(walletType)}`
  );
}

function addIfPresent(target, key, value) {
  if (value != null) {
    target[key] = value;
  }
}

function scanOptionsFromBody(body = {}) {
  const scan = body.scan || {};
  return {
    afterHeight: scan.afterHeight ?? scan.after_height ?? body.scanAfterHeight ?? body.scan_after_height ?? body.afterHeight ?? body.after_height,
    page: scan.page ?? body.scanPage ?? body.scan_page ?? body.page,
    limit: scan.limit ?? body.scanLimit ?? body.scan_limit ?? body.limit,
    maxPages: scan.maxPages ?? scan.max_pages ?? body.scanMaxPages ?? body.scan_max_pages ?? body.maxPages ?? body.max_pages,
    eventTypes: scan.eventTypes ?? scan.event_types ?? body.eventTypes ?? body.event_types
  };
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
    rpc,
    rest,
    chainId,
    accountPrefix,
    shieldedPrefix,
    denom,
    proverUrl,
    proverTimeoutMs = 120000,
    evmRpc,
    evmChainId,
    evmPrivacyPrecompileAddress,
    evmGasLimit = "0x989680",
    evmSendGasLimit = "0x5208"
  } = {}) {
    const resolved = profile || {};
    this.profile = resolved;
    this.rpc = normalizeRpcEndpoint(resolved.rpc || rpc);
    this.rest = trimTrailingSlash(resolved.rest || rest);
    this.chainId = resolved.chainId || chainId;
    this.accountPrefix = resolved.accountPrefix || accountPrefix || "clair";
    this.shieldedPrefix = resolved.shieldedPrefix || shieldedPrefix || `${this.accountPrefix}s`;
    this.denom = resolved.denom || denom || "uclair";
    this.proverUrl = trimTrailingSlash(resolved.proverUrl || proverUrl || "");
    this.proverTimeoutMs = proverTimeoutMs;
    this.evmRpc = resolved.evmRpc || evmRpc || "";
    this.evmChainId = resolved.evmChainId || evmChainId || "";
    this.evmGasLimit = resolved.evmGasLimit || evmGasLimit;
    this.evmSendGasLimit = resolved.evmSendGasLimit || evmSendGasLimit;
    this.cosmos = createClairveilClient({
      rpc: this.rpc,
      rest: this.rest,
      chainId: this.chainId,
      accountPrefix: this.accountPrefix,
      shieldedPrefix: this.shieldedPrefix,
      defaultDenom: this.denom
    });
    this.evm = createClairveilEvmClient({
      contractAddress: resolved.evmPrivacyPrecompileAddress || evmPrivacyPrecompileAddress,
      chainId: this.chainId,
      accountPrefix: this.accountPrefix,
      shieldedPrefix: this.shieldedPrefix,
      defaultDenom: this.denom
    });
  }

  restUrl(path) {
    return `${this.rest}${path.startsWith("/") ? path : `/${path}`}`;
  }

  rpcUrl(path) {
    return `${this.rpc}${path.startsWith("/") ? path : `/${path}`}`;
  }

  proverAdapter() {
    if (!this.proverUrl) {
      throw new ClairveilError(
        ClairveilErrorCode.PROVER_UNAVAILABLE,
        "proverUrl is required for transfer and withdraw proof generation"
      );
    }
    return createHttpProverAdapter({
      baseURL: this.proverUrl,
      timeoutMs: this.proverTimeoutMs
    });
  }

  async health() {
    const [status, tree, audit] = await Promise.allSettled([
      fetchJson(this.rpcUrl("/status")),
      fetchJson(this.restUrl("/clairveil/privacy/v1/tree_state")),
      fetchJson(this.restUrl("/clairveil/privacy/v1/audit_config"))
    ]);
    return {
      status: status.status === "fulfilled" ? status.value.result : null,
      tree: tree.status === "fulfilled" ? tree.value : null,
      audit: audit.status === "fulfilled" ? audit.value : null,
      errors: [status, tree, audit]
        .filter(result => result.status === "rejected")
        .map(result => result.reason.message)
    };
  }

  async fetchBlockEvents(rawLimit = 30) {
    const limit = Math.min(Math.max(Number.parseInt(rawLimit, 10) || 30, 1), 50);
    const url = new URL(this.rpcUrl("/tx_search"));
    url.searchParams.set("query", "\"tx.height>=1\"");
    url.searchParams.set("prove", "false");
    url.searchParams.set("page", "1");
    url.searchParams.set("per_page", String(limit));
    url.searchParams.set("order_by", "\"desc\"");

    const data = await fetchJson(url);
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

  async fetchAuditableTransfers(options = {}) {
    return this.cosmos.fetchAuditableTransfers(options);
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

  privacyMaterial(body, walletType = walletTypeFromBody(body)) {
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
    return fetchJson(this.restUrl(`/cosmos/bank/v1beta1/balances/${address}`));
  }

  async waitForTx(txHash, options) {
    return this.cosmos.waitForTx(txHash, options);
  }

  async waitForEvmReceipt(txHash, { attempts = 30, intervalMs = 1000 } = {}) {
    const hash = `0x${String(txHash || "").replace(/^0x/i, "").toLowerCase()}`;
    for (let i = 0; i < attempts; i += 1) {
      const receipt = await this.evmJsonRpc("eth_getTransactionReceipt", [hash]);
      if (receipt) return receipt;
      await new Promise(resolve => setTimeout(resolve, intervalMs));
    }
    return null;
  }

  async evmJsonRpc(method, params = []) {
    const response = await fetch(this.evmRpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: Date.now(),
        method,
        params
      })
    });
    const data = await response.json();
    if (data.error) {
      throw new Error(data.error.message || `EVM RPC ${method} failed`);
    }
    return data.result;
  }

  async waitForEvmTransaction(txHash) {
    const receipt = await this.waitForEvmReceipt(txHash);
    return {
      txHash: String(txHash || "").replace(/^0x/i, "").toUpperCase(),
      evmTxHash: `0x${String(txHash || "").replace(/^0x/i, "").toLowerCase()}`,
      receipt,
      tx: null,
      ok: Boolean(receipt && (!receipt.status || receipt.status === "0x1")),
      error: receipt?.status && receipt.status !== "0x1" ? `EVM tx failed with receipt status ${receipt.status}` : "",
      errors: receipt ? [] : [`EVM tx was broadcast but receipt was not found yet: ${txHash}`]
    };
  }

  evmNativeSendTransaction({ to, amount }) {
    return {
      to: normalizeEvmAddress(to, "send recipient"),
      chainId: this.evmChainId,
      value: `0x${BigInt(String(amount).replace(this.denom, "")).toString(16)}`,
      gas: this.evmSendGasLimit
    };
  }

  async buildBankSendSignDoc({ from, pubKeyHex, to, amount }) {
    return this.cosmos.buildDirectSignDoc({
      signer: from,
      pubKeyHex,
      messages: [
        {
          typeUrl: "/cosmos.bank.v1beta1.MsgSend",
          value: {
            fromAddress: from,
            toAddress: to,
            amount: [{
              denom: this.denom,
              amount: String(amount).replace(this.denom, "")
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

  async prepareDeposit(body) {
    const walletType = walletTypeFromBody(body);
    const material = this.privacyMaterial(body, walletType);
    const amount = body.amount;
    if (walletType === "evm") {
      const built = this.evm.buildDepositTransaction({
        creator: material.address,
        rootSeed: material.rootSeed,
        amount,
        assetDenom: this.denom
      });
      return {
        transaction: {
          chainId: this.evmChainId,
          gas: this.evmGasLimit,
          ...built.transaction
        },
        prepared: {
          shieldedAddress: built.material.shieldedAddress || material.shieldedAddress,
          noteCommitmentHex: built.material.note_commitment_hex,
          amount: built.material.amount
        }
      };
    }
    const prepared = await this.cosmos.prepareDeposit({
      material,
      amount,
      gasLimit: 2500000
    });
    return {
      signDoc: prepared.signDoc,
      prepared: {
        shieldedAddress: prepared.privacyAccount.shielded_address,
        noteCommitmentHex: prepared.material.note_commitment_hex,
        amount: prepared.material.amount
      }
    };
  }

  async prepareTransfer(body) {
    const walletType = walletTypeFromBody(body);
    const material = this.privacyMaterial(body, walletType);
    const amount = body.amount;
    const recipient = body.recipient;
    const userPrivacyPolicy = body.privacyPolicy ?? body.privacy_policy ?? "all-private";
    const userDisclosureMode = body.disclosureMode ?? body.disclosure_mode ?? "none";
    const userDisclosureTargetPubKeyHex = body.disclosurePubKeyHex ?? body.disclosure_pubkey_hex ?? "";
    const allowPlanStep = Boolean(body.allowPlanStep ?? body.allow_plan_step);
    const scanOptions = scanOptionsFromBody(body);

    if (walletType !== "evm") {
      const prepared = await this.cosmos.prepareTransfer({
        proverAdapter: this.proverAdapter(),
        material,
        recipient,
        amount,
        userPrivacyPolicy,
        userDisclosureMode,
        userDisclosureTargetPubKeyHex,
        allowPlanStep,
        scan: scanOptions,
        gasLimit: 8000000
      });
      if (prepared.status !== "ready") throw plannerError(prepared);
      return {
        signDoc: prepared.signDoc,
        prepared: {
          ...prepared.prepared,
          shieldedAddress: prepared.privacyAccount.shielded_address,
          finalAmount: amount,
          finalRecipient: recipient,
          privacyPolicy: userPrivacyPolicy,
          disclosureMode: userDisclosureMode,
          planStatus: prepared.plan?.status || "",
          planAction: prepared.prepared?.planAction || prepared.plan?.action || ""
        },
        plan: prepared.plan
      };
    }

    const scan = await this.cosmos.scanNotes({
      rootSeed: material.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    const plan = planTransferNotes({ notes: scan.foundNotes, amount, denom: this.denom });
    if (plan.status === "self_merge_required" && !allowPlanStep) throw plannerError({ status: plan.status, plan, scan });
    if (!plan.canBuildTx) throw plannerError({ status: plan.status, plan, scan });
    assertPlanCanBuildTx(plan);

    const audit = await this.cosmos.fetchAuditConfig();
    const auditPubKeyHex = audit.audit_master_pubkey_hex || "";
    const isFinal = plan.status === "final_transfer_ready";
    const stepRecipient = isFinal ? recipient : material.shieldedAddress;
    const stepAmount = isFinal ? amount : plan.nextAmount;
    const built = await this.cosmos.buildTransferMessage({
      proverAdapter: this.proverAdapter(),
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
      auditDisclosureTargetPubKeyHex: auditPubKeyHex
    });
    const transaction = this.evm.contract.buildTransferTransaction(built.message);
    return {
      transaction: { chainId: this.evmChainId, gas: this.evmGasLimit, ...transaction },
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
        planStatus: plan.status
      },
      plan
    };
  }

  async prepareWithdraw(body) {
    const walletType = walletTypeFromBody(body);
    const material = this.privacyMaterial(body, walletType);
    const amount = body.amount;
    const rawRecipient = body.recipient;
    const evmRecipient = isEvmAddress(rawRecipient) ? normalizeEvmAddress(rawRecipient, "withdraw recipient") : "";
    const recipient = evmRecipient ? evmAddressToBech32(evmRecipient, this.accountPrefix) : rawRecipient;

    if (walletType !== "evm") {
      const prepared = await this.cosmos.prepareWithdraw({
        proverAdapter: this.proverAdapter(),
        material,
        amount,
        recipient,
        scan: scanOptionsFromBody(body),
        gasLimit: 5000000
      });
      if (prepared.status !== "ready") throw plannerError(prepared);
      return {
        signDoc: prepared.signDoc,
        prepared: {
          shieldedAddress: prepared.privacyAccount.shielded_address,
          amount: prepared.payload.amount,
          recipient: prepared.payload.recipient,
          selectedNoteNullifier: prepared.selectedNote?.nullifier || prepared.payload.nullifier_hex,
          expiresAtUnix: prepared.payload.expires_at_unix
        },
        plan: prepared.plan
      };
    }

    const scanOptions = scanOptionsFromBody(body);
    const scan = await this.cosmos.scanNotes({
      rootSeed: material.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    const plan = planWithdrawNotes({ notes: scan.foundNotes, amount, denom: this.denom });
    if (!plan.canBuildTx) throw plannerError({ status: plan.status, plan, scan });
    assertPlanCanBuildTx(plan);
    const built = await this.cosmos.buildWithdrawMessage({
      proverAdapter: this.proverAdapter(),
      creator: material.address,
      notes: scan.foundNotes,
      amount,
      assetDenom: this.denom,
      recipient,
      rootSeed: material.rootSeed,
      chainId: this.chainId
    });
    const message = evmRecipient ? { ...built.message, evmRecipient } : built.message;
    const transaction = this.evm.contract.buildWithdrawTransaction(message);
    return {
      transaction: { chainId: this.evmChainId, gas: this.evmGasLimit, ...transaction },
      prepared: {
        shieldedAddress: material.shieldedAddress,
        amount: built.payload.amount,
        recipient: built.payload.recipient,
        evmRecipient,
        selectedNoteNullifier: built.selectedNote?.nullifier || built.payload.nullifier_hex,
        expiresAtUnix: built.payload.expires_at_unix
      },
      plan
    };
  }

  async scanWalletNotes(body) {
    const material = this.privacyMaterial(body);
    const {
      afterHeight,
      after_height,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types,
      includeFoundNotes = false
    } = body || {};
    return this.cosmos.scanWalletNotes({
      material,
      afterHeight,
      after_height,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types,
      includeFoundNotes
    });
  }

  async checkNullifier(nullifierHex) {
    return this.cosmos.checkNullifier(nullifierHex);
  }

  async decodeUserDisclosure(body) {
    const request = { txHash: body.txHash ?? body.tx_hash };
    addIfPresent(request, "afterHeight", body.afterHeight ?? body.after_height);
    addIfPresent(request, "page", body.page);
    addIfPresent(request, "limit", body.limit);
    addIfPresent(request, "maxPages", body.maxPages ?? body.max_pages);
    addIfPresent(request, "eventTypes", body.eventTypes ?? body.event_types);
    if (body.address && (body.pubKeyHex || body.pub_key_hex) && (body.signatureBase64 || body.signature_base64)) {
      const walletType = walletTypeFromBody(body);
      Object.assign(request, walletType === "evm"
        ? { ...body, skipSignerPubKeyCheck: true }
        : body);
    }
    return this.cosmos.decodeUserDisclosure(request);
  }

  async decodeAuditDisclosure(body = {}) {
    const request = {
      txHash: body.txHash ?? body.tx_hash,
      disclosurePrivKeyHex: body.disclosurePrivKeyHex ?? body.disclosure_privkey_hex
    };
    addIfPresent(request, "afterHeight", body.afterHeight ?? body.after_height);
    addIfPresent(request, "page", body.page);
    addIfPresent(request, "limit", body.limit);
    addIfPresent(request, "maxPages", body.maxPages ?? body.max_pages);
    addIfPresent(request, "eventTypes", body.eventTypes ?? body.event_types);
    return this.cosmos.decodeAuditDisclosure(request);
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
