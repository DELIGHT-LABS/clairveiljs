import { toBech32 } from "@cosmjs/encoding";
import { Registry, encodePubkey, makeAuthInfoBytes, makeSignDoc } from "@cosmjs/proto-signing";
import { defaultRegistryTypes, StargateClient } from "@cosmjs/stargate";
import { TxRaw } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import {
  MsgDeposit as GeneratedMsgDeposit,
  MsgTransfer as GeneratedMsgTransfer,
  MsgWithdraw as GeneratedMsgWithdraw,
  UserDisclosureMode
} from "../generated/clairveil/privacy/v1/tx.js";
import {
  defaultAccountPrefix,
  derivePrivacyMaterial,
  normalizeBech32Prefix
} from "../core/crypto.js";
import {
  decodeAuditDisclosureFromEvent,
  decodeUserDisclosureFromEvent,
  disclosureScalarFromHex
} from "../core/disclosure.js";
import {
  buildDepositMaterial as buildDepositMaterialCore,
  defaultAssetDenom
} from "../core/note.js";
import {
  buildPreparedTransferPayload as buildPreparedTransferPayloadCore,
  buildTransferMessage as buildTransferMessageCore,
  buildPreparedWithdrawProverPayload as buildPreparedWithdrawProverPayloadCore,
  buildRelayWithdrawMsgFromPayload as buildRelayWithdrawMsgFromPayloadCore,
  buildRelayWithdrawPayload as buildRelayWithdrawPayloadCore,
  buildWithdrawMessage as buildWithdrawMessageCore,
  createRestMerklePathProvider
} from "../privacy/payload.js";
import {
  assertPlanCanBuildTx,
  planTransferNotes,
  planWithdrawNotes
} from "../privacy/planner.js";
import { scanNotes as scanNotesCore } from "../privacy/scan.js";
import {
  createWalletAdapter,
  derivePrivacyMaterialFromWallet
} from "../wallet/adapter.js";
import {
  base64FromBytes,
  bytesFromBase64,
  bytesFromHex as rawBytesFromHex,
  hash160
} from "../core/browser-crypto.js";

export * from "../core/crypto.js";
export * from "../core/disclosure.js";
export * from "../core/errors.js";
export * from "../core/note.js";
export * from "../privacy/payload.js";
export * from "../privacy/planner.js";
export * from "../privacy/prover.js";
export * from "../privacy/scan.js";
export * from "../privacy/note-store.js";
export * from "../core/schemas.js";
export * from "../wallet/adapter.js";
export {
  userDisclosureModeFromJSON,
  userDisclosureModeToJSON
} from "../generated/clairveil/privacy/v1/tx.js";

export const msgDepositTypeUrl = GeneratedMsgDeposit.typeUrl;
export const msgTransferTypeUrl = GeneratedMsgTransfer.typeUrl;
export const msgWithdrawTypeUrl = GeneratedMsgWithdraw.typeUrl;
const defaultPrepareScanMaxPages = 1000;

export const MsgDeposit = GeneratedMsgDeposit;
export const MsgTransfer = GeneratedMsgTransfer;
export const MsgWithdraw = GeneratedMsgWithdraw;
export { UserDisclosureMode };

export function createClairveilRegistry(extraTypes = []) {
  return new Registry([
    ...defaultRegistryTypes,
    [msgDepositTypeUrl, MsgDeposit],
    [msgTransferTypeUrl, MsgTransfer],
    [msgWithdrawTypeUrl, MsgWithdraw],
    ...extraTypes
  ]);
}

export function normalizeRpcEndpoint(rpc) {
  return rpc.replace(/^tcp:\/\//, "http://").replace(/\/$/, "");
}

export function normalizeRestEndpoint(rest) {
  return rest.replace(/\/$/, "");
}

export function buildRootSigningMessage(address, pubKeyHex) {
  return [
    "clairveil-root-v1",
    `address:${address}`,
    `pubkey:${pubKeyHex}`
  ].join("\n");
}

export function cosmosAddressFromPubKey(pubKeyHex, prefix = "clair") {
  return toBech32(prefix, hash160(rawBytesFromHex(pubKeyHex, "pubKeyHex")));
}

export function verifySignerPubKey(address, pubKeyHex, prefix = defaultAccountPrefix) {
  const expectedAddress = cosmosAddressFromPubKey(pubKeyHex, prefix);
  return {
    address,
    expectedAddress,
    matches: address === expectedAddress
  };
}

export function assertSignerPubKey(address, pubKeyHex, prefix = defaultAccountPrefix) {
  const signerCheck = verifySignerPubKey(address, pubKeyHex, prefix);
  if (!signerCheck.matches) {
    throw new Error(`signer address/pubKey mismatch. ${address} maps to ${signerCheck.expectedAddress}`);
  }
  return signerCheck;
}

export function eventAttribute(event, key) {
  return (event?.attributes || []).find(attribute => attribute.key === key)?.value || "";
}

export function isAuditableTransfer(event) {
  return event?.event_type === "shielded_transfer" && Boolean(eventAttribute(event, "audit_disclosure_payload"));
}

function toBase64(bytes) {
  return base64FromBytes(bytes);
}

function fromBase64(value, label = "base64") {
  return bytesFromBase64(value, label);
}

function directSignDocFromBase64(signDoc) {
  return {
    bodyBytes: fromBase64(signDoc.bodyBytes, "bodyBytes"),
    authInfoBytes: fromBase64(signDoc.authInfoBytes, "authInfoBytes"),
    chainId: signDoc.chainId,
    accountNumber: BigInt(signDoc.accountNumber)
  };
}

function fromHex(value, label = "hex") {
  return rawBytesFromHex(value, label);
}

async function fetchJson(url) {
  const response = await fetch(url, { headers: { accept: "application/json" } });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
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
  if (resolvedAfterHeight != null) {
    params.set("after_height", String(resolvedAfterHeight));
  }
  if (page != null) {
    params.set("page", String(page));
  }
  if (limit != null) {
    params.set("limit", String(limit));
  }
  const resolvedEventTypes = eventTypes ?? event_types;
  if (Array.isArray(resolvedEventTypes)) {
    for (const eventType of resolvedEventTypes) {
      if (String(eventType || "").trim()) {
        params.append("event_types", String(eventType).trim());
      }
    }
  } else if (resolvedEventTypes != null && String(resolvedEventTypes).trim()) {
    params.set("event_types", String(resolvedEventTypes).trim());
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

function privacyEventsCursor(data, request = {}) {
  const events = data?.events || [];
  let latestHeight = 0;
  let latestTxHash = "";
  for (const event of events) {
    const height = Number(event?.height || 0);
    if (height >= latestHeight) {
      latestHeight = height;
      latestTxHash = String(event?.tx_hash_hex || "").toUpperCase();
    }
  }
  return {
    after_height: Number(request.afterHeight ?? request.after_height ?? 0),
    page: Number(data?.page ?? request.page ?? 1),
    limit: Number(data?.limit ?? request.limit ?? events.length),
    event_types: request.eventTypes ?? request.event_types ?? [],
    has_more: Boolean(data?.has_more),
    latest_height: latestHeight,
    latest_tx_hash: latestTxHash
  };
}

export function nextPrivacyScanOptions(scanOrCursor = {}, defaults = {}) {
  const cursor = scanOrCursor?.scanCursor || scanOrCursor || {};
  const afterHeight = Number(cursor.after_height ?? cursor.afterHeight ?? defaults.afterHeight ?? defaults.after_height ?? 0);
  const latestHeight = Number(cursor.latest_height ?? cursor.latestHeight ?? 0);
  const hasMore = Boolean(cursor.has_more ?? cursor.hasMore);
  const nextPage = hasMore
    ? Number(cursor.next_page ?? cursor.nextPage ?? (Number(cursor.page || 1) + 1))
    : 1;
  const nextAfterHeight = hasMore ? afterHeight : Math.max(afterHeight, latestHeight);
  const next = {
    afterHeight: nextAfterHeight,
    page: nextPage,
    limit: Number(cursor.limit ?? defaults.limit ?? 200),
    eventTypes: cursor.event_types ?? cursor.eventTypes ?? defaults.eventTypes ?? defaults.event_types ?? []
  };
  const maxPages = defaults.maxPages ?? defaults.max_pages;
  if (maxPages != null) next.maxPages = maxPages;
  const includeFoundNotes = defaults.includeFoundNotes ?? defaults.include_found_notes;
  if (includeFoundNotes != null) next.includeFoundNotes = Boolean(includeFoundNotes);
  next.hasMore = hasMore;
  next.completed = !hasMore;
  return next;
}

function resolveScanOptions({
  scan,
  afterHeight,
  after_height,
  page,
  limit,
  maxPages,
  max_pages,
  eventTypes,
  event_types
} = {}) {
  return {
    afterHeight: scan?.afterHeight ?? scan?.after_height ?? afterHeight ?? after_height,
    page: scan?.page ?? page,
    limit: scan?.limit ?? limit,
    maxPages: scan?.maxPages ?? scan?.max_pages ?? maxPages ?? max_pages,
    eventTypes: scan?.eventTypes ?? scan?.event_types ?? eventTypes ?? event_types
  };
}

function indexedTxToRestish(tx) {
  if (!tx) return null;
  return {
    height: String(tx.height),
    txhash: tx.hash,
    code: tx.code,
    raw_log: tx.rawLog,
    events: tx.events || [],
    tx: tx.tx
  };
}

function publicPrivacyAccount(material) {
  return {
    address: material.address,
    pubKeyHex: material.pubKeyHex,
    signing_message: material.signingMessage,
    shielded_address: material.shieldedAddress,
    disclosure_pubkey_hex: material.disclosurePubKeyHex,
    root_signature_hash: material.rootSignatureHash
  };
}

export class ClairveilJS {
  constructor({ rpc, rest, chainId, accountPrefix, bech32Prefix, shieldedPrefix, defaultDenom = defaultAssetDenom, assetDenom, registry = createClairveilRegistry() }) {
    this.rpc = normalizeRpcEndpoint(rpc);
    this.rest = normalizeRestEndpoint(rest);
    this.chainId = chainId;
    this.accountPrefix = normalizeBech32Prefix(accountPrefix ?? bech32Prefix ?? defaultAccountPrefix, "accountPrefix");
    this.bech32Prefix = this.accountPrefix;
    this.shieldedPrefix = normalizeBech32Prefix(shieldedPrefix ?? `${this.accountPrefix}s`, "shieldedPrefix");
    this.defaultDenom = String(assetDenom ?? defaultDenom ?? defaultAssetDenom);
    this.registry = registry;
    this.clientPromise = null;
  }

  async connect() {
    if (!this.clientPromise) {
      this.clientPromise = StargateClient.connect(this.rpc);
    }
    return this.clientPromise;
  }

  async disconnect() {
    if (!this.clientPromise) return;
    const client = await this.clientPromise;
    client.disconnect();
    this.clientPromise = null;
  }

  restUrl(path) {
    return `${this.rest}${path}`;
  }

  async getAccountInfo(address) {
    const data = await fetchJson(this.restUrl(`/cosmos/auth/v1beta1/account_info/${address}`));
    const info = data.info;
    if (!info?.account_number || info.sequence == null) {
      throw new Error("account not found on-chain; fund it first");
    }
    return {
      accountNumber: BigInt(info.account_number),
      sequence: BigInt(info.sequence)
    };
  }

  async getBalances(address) {
    const client = await this.connect();
    const balances = await client.getAllBalances(address);
    return {
      balances: balances.map(balance => ({ denom: balance.denom, amount: balance.amount })),
      pagination: null
    };
  }

  async getTx(txHash) {
    const client = await this.connect();
    return indexedTxToRestish(await client.getTx(txHash));
  }

  async waitForTx(txHash, { attempts = 20, intervalMs = 1500 } = {}) {
    for (let i = 0; i < attempts; i += 1) {
      const tx = await this.getTx(txHash);
      if (tx) return tx;
      await new Promise(resolve => setTimeout(resolve, intervalMs));
    }
    return null;
  }

  async fetchPrivacyEvents(options = {}) {
    return fetchJson(this.restUrl(`/clairveil/privacy/v1/events${privacyEventsQuery(options)}`));
  }

  async fetchTreeState() {
    return fetchJson(this.restUrl("/clairveil/privacy/v1/tree_state"));
  }

  async fetchCommitmentInfo(commitmentHex) {
    return fetchJson(this.restUrl(`/clairveil/privacy/v1/commitment/${commitmentHex}`));
  }

  async lookupMerklePath(commitmentHex) {
    return createRestMerklePathProvider({ rest: this.rest }).lookupMerklePath(commitmentHex);
  }

  async fetchAuditConfig() {
    return fetchJson(this.restUrl("/clairveil/privacy/v1/audit_config"));
  }

  async fetchDisclosureConfig() {
    return fetchJson(this.restUrl("/clairveil/privacy/v1/disclosure_config"));
  }

  async fetchCircuitConfig() {
    return fetchJson(this.restUrl("/clairveil/privacy/v1/circuit_config"));
  }

  async checkNullifier(nullifierHex) {
    return fetchJson(this.restUrl(`/clairveil/privacy/v1/nullifier/${nullifierHex}`));
  }

  async deriveWalletPrivacyMaterial(wallet) {
    return derivePrivacyMaterialFromWallet(wallet, {
      shieldedPrefix: this.shieldedPrefix
    });
  }

  async scanNotes({
    rootSeed,
    afterHeight,
    after_height,
    page = 1,
    limit = 200,
    maxPages = 1,
    eventTypes = ["deposit", "shielded_transfer"],
    event_types,
    includeFoundNotes = false
  } = {}) {
    const resolvedEventTypes = event_types ?? eventTypes;
    const startPage = Math.max(1, Number(page || 1));
    const pageLimit = Math.max(1, Number(limit || 200));
    const pageBudget = Math.max(1, Number(maxPages || 1));
    const baseRequest = {
      afterHeight,
      after_height,
      limit: pageLimit,
      eventTypes: resolvedEventTypes
    };
    const events = [];
    let currentPage = startPage;
    let pagesScanned = 0;
    let hasMore = false;
    let lastData = null;

    for (; pagesScanned < pageBudget;) {
      const request = { ...baseRequest, page: currentPage };
      const data = await this.fetchPrivacyEvents(request);
      lastData = data;
      events.push(...(data.events || []));
      pagesScanned += 1;
      hasMore = Boolean(data.has_more);
      if (!hasMore) break;
      currentPage = Number(data.page || currentPage) + 1;
    }

    const result = await scanNotesCore({
      rootSeed,
      events,
      checkNullifier: nullifierHex => this.checkNullifier(nullifierHex),
      includeFoundNotes
    });
    const cursor = privacyEventsCursor({
      ...(lastData || {}),
      events,
      has_more: hasMore
    }, { ...baseRequest, page: lastData?.page ?? currentPage });
    return {
      ...result,
      diagnostics: {
        ...result.diagnostics,
        pages_scanned: pagesScanned,
        max_pages: pageBudget
      },
      scanCursor: {
        ...cursor,
        pages_scanned: pagesScanned,
        next_page: hasMore ? currentPage : 1,
        completed: !hasMore
      },
      nextScanOptions: nextPrivacyScanOptions({
        ...cursor,
        pages_scanned: pagesScanned,
        next_page: hasMore ? currentPage : 1,
        completed: !hasMore
      }, {
        maxPages: pageBudget,
        includeFoundNotes,
        eventTypes: resolvedEventTypes
      })
    };
  }

  async fetchAuditableTransfers(options = {}) {
    const data = await this.fetchPrivacyEvents(options);
    return {
      ...data,
      events: (data.events || []).filter(isAuditableTransfer)
    };
  }

  async findPrivacyEventByTxHash(txHash, {
    afterHeight,
    after_height,
    page = 1,
    limit = 200,
    maxPages = defaultPrepareScanMaxPages,
    max_pages,
    eventTypes = ["shielded_transfer"],
    event_types
  } = {}) {
    const normalizedTxHash = String(txHash || "").trim().toUpperCase();
    if (!normalizedTxHash) {
      throw new Error("txHash is required");
    }
    const pageBudget = Math.max(1, Number(max_pages ?? maxPages ?? defaultPrepareScanMaxPages));
    const pageLimit = Math.max(1, Number(limit || 200));
    const resolvedEventTypes = event_types ?? eventTypes;
    let currentPage = Math.max(1, Number(page || 1));

    for (let pagesScanned = 0; pagesScanned < pageBudget; pagesScanned += 1) {
      const data = await this.fetchPrivacyEvents({
        afterHeight,
        after_height,
        page: currentPage,
        limit: pageLimit,
        eventTypes: resolvedEventTypes
      });
      const event = (data.events || []).find(item => String(item.tx_hash_hex || "").toUpperCase() === normalizedTxHash);
      if (event) {
        return event;
      }
      if (!data.has_more) break;
      currentPage = Number(data.page || currentPage) + 1;
    }
    throw new Error(`transfer event not found for tx ${normalizedTxHash}`);
  }

  derivePrivacyAccount({ address, pubKeyHex, pub_key_hex, signatureBase64, signature_base64 }) {
    const material = derivePrivacyMaterial({
      address,
      pubKeyHex: pubKeyHex ?? pub_key_hex,
      signatureBase64: signatureBase64 ?? signature_base64,
      shieldedPrefix: this.shieldedPrefix
    });
    return {
      signing_message: material.signingMessage,
      shielded_address: material.shieldedAddress,
      disclosure_pubkey_hex: material.disclosurePubKeyHex,
      root_signature_hash: material.rootSignatureHash
    };
  }

  buildDepositMaterial(input) {
    return buildDepositMaterialCore({
      shieldedPrefix: this.shieldedPrefix,
      assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
      ...input
    });
  }

  buildDepositMessage(input) {
    const material = buildDepositMaterialCore({
      shieldedPrefix: this.shieldedPrefix,
      assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
      ...input
    });
    return {
      material,
      message: {
        creator: material.creator,
        amount: material.amount,
        noteCommitment: material.note_commitment,
        encryptedNote: material.encrypted_note
      }
    };
  }

  async scanWalletNotes({
    wallet,
    material,
    limit = 200,
    maxPages = 1,
    max_pages,
    noteStore,
    includeFoundNotes = false,
    afterHeight,
    after_height,
    page,
    eventTypes,
    event_types
  } = {}) {
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    let resolvedAfterHeight = afterHeight ?? after_height;
    let resolvedPage = page;
    if (resolvedAfterHeight == null && noteStore) {
      const cached = await noteStore.load();
      const cachedCursor = cached.scanCursor || {};
      if (cachedCursor.has_more && (cachedCursor.next_page || cachedCursor.nextPage)) {
        resolvedAfterHeight = cachedCursor.after_height ?? cachedCursor.afterHeight ?? cached.lastScannedHeight ?? 0;
        resolvedPage = resolvedPage ?? cachedCursor.next_page ?? cachedCursor.nextPage;
      } else {
        resolvedAfterHeight = cached.lastScannedHeight || 0;
      }
    }
    const scan = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      limit,
      maxPages: max_pages ?? maxPages,
      afterHeight: resolvedAfterHeight,
      page: resolvedPage,
      eventTypes: event_types ?? eventTypes,
      includeFoundNotes: true
    });
    if (noteStore) {
      await noteStore.mergeScanResult(scan, { owner: privacy.address });
      await this.refreshNoteStoreSpentStatuses(noteStore);
    }
    if (includeFoundNotes) {
      return {
        ...scan,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    const { foundNotes: _foundNotes, ...safeScan } = scan;
    return {
      ...safeScan,
      privacyAccount: publicPrivacyAccount(privacy)
    };
  }

  async refreshNoteStoreSpentStatuses(noteStore) {
    if (!noteStore) return null;
    const current = await noteStore.load();
    const nullifiers = [];
    for (const note of current.notes || []) {
      const nullifier = String(note?.nullifier || "").trim().toLowerCase();
      if (!nullifier || note.isSpent || note.spent) continue;
      try {
        const result = await this.checkNullifier(nullifier);
        if (Boolean(result?.used ?? result?.Used ?? result)) {
          nullifiers.push(nullifier);
        }
      } catch {
        // Leave cached notes unchanged when the nullifier query is temporarily unavailable.
      }
    }
    return nullifiers.length ? noteStore.markSpent(nullifiers) : current;
  }

  async planWalletTransfer({ wallet, material, amount, denom, limit = 200, maxPages = defaultPrepareScanMaxPages, scan: scanOptions } = {}) {
    const resolvedScanOptions = resolveScanOptions({ scan: scanOptions, limit, maxPages });
    const scan = await this.scanWalletNotes({
      wallet,
      material,
      ...resolvedScanOptions,
      limit: resolvedScanOptions.limit ?? 200,
      maxPages: resolvedScanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    return {
      plan: planTransferNotes({
        notes: scan.foundNotes,
        amount,
        denom: denom ?? this.defaultDenom
      }),
      scan
    };
  }

  async planWalletWithdraw({ wallet, material, amount, denom, limit = 200, maxPages = defaultPrepareScanMaxPages, scan: scanOptions } = {}) {
    const resolvedScanOptions = resolveScanOptions({ scan: scanOptions, limit, maxPages });
    const scan = await this.scanWalletNotes({
      wallet,
      material,
      ...resolvedScanOptions,
      limit: resolvedScanOptions.limit ?? 200,
      maxPages: resolvedScanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    return {
      plan: planWithdrawNotes({
        notes: scan.foundNotes,
        amount,
        denom: denom ?? this.defaultDenom
      }),
      scan
    };
  }

  async prepareDeposit({ wallet, material, amount, memo = "Clairveil deposit", gasLimit = 2500000, denom, assetDenom } = {}) {
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const prepared = this.buildDepositMessage({
      creator: privacy.address,
      rootSeed: privacy.rootSeed,
      amount,
      assetDenom: assetDenom ?? denom ?? this.defaultDenom,
      memo
    });
    const signDoc = await this.buildDirectSignDoc({
      signer: privacy.address,
      pubKeyHex: privacy.pubKeyHex,
      gasLimit,
      messages: [
        {
          typeUrl: msgDepositTypeUrl,
          value: prepared.message
        }
      ],
      memo: "Clairveil privacy deposit"
    });

    return {
      status: "ready",
      signDoc,
      message: prepared.message,
      material: prepared.material,
      privacyAccount: publicPrivacyAccount(privacy)
    };
  }

  async prepareTransfer({
    wallet,
    material,
    amount,
    recipient,
    proverAdapter,
    userPrivacyPolicy = "all-private",
    userDisclosureMode,
    userDisclosureTargetPubKeyHex = "",
    auditDisclosureTargetPubKeyHex,
    denom,
    allowPlanStep = false,
    scan,
    afterHeight,
    after_height,
    page,
    limit = 200,
    maxPages = defaultPrepareScanMaxPages,
    max_pages,
    eventTypes,
    event_types,
    gasLimit = 8000000
  } = {}) {
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const scanOptions = resolveScanOptions({
      scan,
      afterHeight,
      after_height,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types
    });
    const scanResult = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    const plan = planTransferNotes({
      notes: scanResult.foundNotes,
      amount,
      denom: denom ?? this.defaultDenom
    });
    if (plan.status === "self_merge_required" && !allowPlanStep) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    if (!plan.canBuildTx) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    assertPlanCanBuildTx(plan);

    const auditPubKeyHex = auditDisclosureTargetPubKeyHex
      || (await this.fetchAuditConfig()).audit_master_pubkey_hex;
    const isFinal = plan.status === "final_transfer_ready";
    const stepRecipient = isFinal ? recipient : privacy.shieldedAddress;
    const stepAmount = isFinal ? amount : plan.nextAmount;
    const built = await this.buildTransferMessage({
      proverAdapter,
      creator: privacy.address,
      inputs: plan.selection.inputs,
      recipient: stepRecipient,
      amount: stepAmount,
      transferDenom: denom ?? this.defaultDenom,
      rootSeed: privacy.rootSeed,
      shieldedPrefix: this.shieldedPrefix,
      userPrivacyPolicy: isFinal ? userPrivacyPolicy : "all-private",
      userDisclosureMode: isFinal ? userDisclosureMode : "none",
      userDisclosureTargetPubKeyHex: isFinal ? userDisclosureTargetPubKeyHex : "",
      auditDisclosureTargetPubKeyHex: auditPubKeyHex
    });
    const signDoc = await this.buildDirectSignDoc({
      signer: privacy.address,
      pubKeyHex: privacy.pubKeyHex,
      gasLimit,
      messages: [
        {
          typeUrl: msgTransferTypeUrl,
          value: built.message
        }
      ],
      memo: "Clairveil veiled transfer"
    });

    return {
      status: "ready",
      plan,
      scan: scanResult,
      signDoc,
      payload: built.payload,
      proof: built.proof,
      message: built.message,
      prepared: {
        planAction: isFinal ? "final_transfer" : "self_merge",
        isFinal,
        amount: stepAmount,
        recipient: stepRecipient,
        finalAmount: amount,
        finalRecipient: recipient,
        selectedInputTotal: plan.selection.total.toString()
      },
      privacyAccount: publicPrivacyAccount(privacy)
    };
  }

  async prepareWithdraw({
    wallet,
    material,
    amount,
    recipient,
    proverAdapter,
    denom,
    assetDenom,
    scan,
    afterHeight,
    after_height,
    page,
    limit = 200,
    maxPages = defaultPrepareScanMaxPages,
    max_pages,
    eventTypes,
    event_types,
    gasLimit = 5000000
  } = {}) {
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const scanOptions = resolveScanOptions({
      scan,
      afterHeight,
      after_height,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types
    });
    const scanResult = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    const plan = planWithdrawNotes({
      notes: scanResult.foundNotes,
      amount,
      denom: assetDenom ?? denom ?? this.defaultDenom
    });
    if (!plan.canBuildTx) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    assertPlanCanBuildTx(plan);

    const built = await this.buildWithdrawMessage({
      proverAdapter,
      creator: privacy.address,
      notes: scanResult.foundNotes,
      amount,
      assetDenom: assetDenom ?? denom ?? this.defaultDenom,
      recipient,
      rootSeed: privacy.rootSeed,
      chainId: this.chainId
    });
    const signDoc = await this.buildDirectSignDoc({
      signer: privacy.address,
      pubKeyHex: privacy.pubKeyHex,
      gasLimit,
      messages: [
        {
          typeUrl: msgWithdrawTypeUrl,
          value: built.message
        }
      ],
      memo: "Clairveil veiled withdraw"
    });

    return {
      status: "ready",
      plan,
      scan: scanResult,
      signDoc,
      proverPayload: built.proverPayload,
      proof: built.proof,
      payload: built.payload,
      message: built.message,
      selectedNote: built.selectedNote,
      privacyAccount: publicPrivacyAccount(privacy)
    };
  }

  async prepareRelayWithdraw({
    wallet,
    material,
    amount,
    recipient,
    proverAdapter,
    denom,
    assetDenom,
    scan,
    afterHeight,
    after_height,
    page,
    limit = 200,
    maxPages = defaultPrepareScanMaxPages,
    max_pages,
    eventTypes,
    event_types,
    expiresAtUnix
  } = {}) {
    const privacy = material || await this.deriveWalletPrivacyMaterial(wallet);
    const scanOptions = resolveScanOptions({
      scan,
      afterHeight,
      after_height,
      page,
      limit,
      maxPages,
      max_pages,
      eventTypes,
      event_types
    });
    const scanResult = await this.scanNotes({
      rootSeed: privacy.rootSeed,
      ...scanOptions,
      limit: scanOptions.limit ?? 200,
      maxPages: scanOptions.maxPages ?? defaultPrepareScanMaxPages,
      includeFoundNotes: true
    });
    const plan = planWithdrawNotes({
      notes: scanResult.foundNotes,
      amount,
      denom: assetDenom ?? denom ?? this.defaultDenom
    });
    if (!plan.canBuildTx) {
      return {
        status: plan.status,
        plan,
        scan: scanResult,
        privacyAccount: publicPrivacyAccount(privacy)
      };
    }
    assertPlanCanBuildTx(plan);

    const built = await this.buildRelayWithdrawPayload({
      proverAdapter,
      notes: scanResult.foundNotes,
      amount,
      assetDenom: assetDenom ?? denom ?? this.defaultDenom,
      recipient,
      rootSeed: privacy.rootSeed,
      chainId: this.chainId,
      expiresAtUnix
    });

    return {
      status: "ready",
      plan,
      scan: scanResult,
      proverPayload: built.proverPayload,
      proof: built.proof,
      payload: built.payload,
      selectedNote: built.selectedNote,
      privacyAccount: publicPrivacyAccount(privacy)
    };
  }

  async createDepositSignDoc(input) {
    return this.prepareDeposit(input);
  }

  async createTransferSignDoc(input) {
    const result = await this.prepareTransfer(input);
    if (result.status !== "ready") {
      throw new Error(result.plan?.message || `transfer is not ready: ${result.status}`);
    }
    return result;
  }

  async createWithdrawSignDoc(input) {
    const result = await this.prepareWithdraw(input);
    if (result.status !== "ready") {
      throw new Error(result.plan?.message || `withdraw is not ready: ${result.status}`);
    }
    return result;
  }

  async createRelayWithdrawPayload(input) {
    const result = await this.prepareRelayWithdraw(input);
    if (result.status !== "ready") {
      throw new Error(result.plan?.message || `relay withdraw is not ready: ${result.status}`);
    }
    return result;
  }

  async buildPreparedTransferPayload(input) {
    return buildPreparedTransferPayloadCore({
      merklePathProvider: this,
      shieldedPrefix: this.shieldedPrefix,
      transferDenom: input?.transferDenom ?? input?.denom ?? this.defaultDenom,
      ...input
    });
  }

  async buildTransferMessage(input) {
    return buildTransferMessageCore({
      merklePathProvider: this,
      shieldedPrefix: this.shieldedPrefix,
      transferDenom: input?.transferDenom ?? input?.denom ?? this.defaultDenom,
      ...input
    });
  }

  async buildPreparedWithdrawProverPayload(input) {
    return buildPreparedWithdrawProverPayloadCore({
      merklePathProvider: this,
      accountPrefix: this.accountPrefix,
      assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
      ...input,
      chainId: input?.chainId ?? this.chainId
    });
  }

  async buildRelayWithdrawPayload(input) {
    return buildRelayWithdrawPayloadCore({
      merklePathProvider: this,
      accountPrefix: this.accountPrefix,
      assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
      ...input,
      chainId: input?.chainId ?? this.chainId
    });
  }

  async buildWithdrawMessage(input) {
    return buildWithdrawMessageCore({
      merklePathProvider: this,
      accountPrefix: this.accountPrefix,
      assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
      ...input,
      chainId: input?.chainId ?? this.chainId
    });
  }

  buildRelayWithdrawMessageFromPayload({
    payload,
    relayer,
    creator,
    nowUnix,
    expectedChainId,
    expectedRecipient,
    accountPrefix
  } = {}) {
    if (!payload) {
      throw new Error("payload is required for relay withdraw");
    }
    return buildRelayWithdrawMsgFromPayloadCore(payload, relayer ?? creator, {
      nowUnix,
      expectedChainId: expectedChainId ?? this.chainId,
      expectedRecipient,
      accountPrefix: accountPrefix ?? this.accountPrefix
    });
  }

  async createRelayWithdrawSignDoc({
    payload,
    relayer,
    creator,
    pubKeyHex,
    pub_key_hex,
    gasLimit = 5000000,
    feeAmount = [],
    memo = "Clairveil relay withdraw",
    nowUnix,
    expectedChainId,
    expectedRecipient,
    accountPrefix
  } = {}) {
    const signer = relayer ?? creator;
    const message = this.buildRelayWithdrawMessageFromPayload({
      payload,
      relayer: signer,
      nowUnix,
      expectedChainId,
      expectedRecipient,
      accountPrefix
    });
    const signDoc = await this.buildDirectSignDoc({
      signer: String(signer || ""),
      pubKeyHex: pubKeyHex ?? pub_key_hex,
      gasLimit,
      feeAmount,
      messages: [
        {
          typeUrl: msgWithdrawTypeUrl,
          value: message
        }
      ],
      memo
    });
    return {
      status: "ready",
      relayer: message.creator,
      payload,
      message,
      signDoc
    };
  }

  async decodeUserDisclosure({
    txHash,
    tx_hash,
    address,
    pubKeyHex,
    pub_key_hex,
    signatureBase64,
    signature_base64,
    skipSignerPubKeyCheck,
    skip_signer_pubkey_check,
    ...eventQuery
  }) {
    const normalizedTxHash = String(txHash ?? tx_hash ?? "").trim().toUpperCase();
    const event = await this.findPrivacyEventByTxHash(normalizedTxHash, eventQuery);
    if (eventAttribute(event, "user_disclosure_mode") === "USER_DISCLOSURE_MODE_PUBLIC") {
      return decodeUserDisclosureFromEvent(
        event,
        1n,
        "",
        normalizedTxHash,
        { shieldedPrefix: this.shieldedPrefix }
      );
    }
    const signerPubKeyHex = pubKeyHex ?? pub_key_hex;
    const skipSignerCheck = Boolean(skipSignerPubKeyCheck ?? skip_signer_pubkey_check);
    if (!skipSignerCheck) {
      assertSignerPubKey(address, signerPubKeyHex, this.bech32Prefix);
    }
    const material = derivePrivacyMaterial({
      address,
      pubKeyHex: signerPubKeyHex,
      signatureBase64: signatureBase64 ?? signature_base64,
      shieldedPrefix: this.shieldedPrefix
    });
    return decodeUserDisclosureFromEvent(
      event,
      material.disclosureScalar,
      material.disclosurePubKeyHex,
      normalizedTxHash,
      { shieldedPrefix: this.shieldedPrefix }
    );
  }

  async decodeAuditDisclosure({ txHash, tx_hash, disclosurePrivKeyHex, disclosure_privkey_hex, ...eventQuery }) {
    const normalizedTxHash = String(txHash ?? tx_hash ?? "").trim().toUpperCase();
    const event = await this.findPrivacyEventByTxHash(normalizedTxHash, eventQuery);
    return decodeAuditDisclosureFromEvent(
      event,
      disclosureScalarFromHex(disclosurePrivKeyHex ?? disclosure_privkey_hex),
      normalizedTxHash,
      { shieldedPrefix: this.shieldedPrefix }
    );
  }

  async buildDirectSignDoc({ signer, pubKeyHex, messages, memo = "", gasLimit = 200000, feeAmount = [] }) {
    assertSignerPubKey(signer, pubKeyHex, this.bech32Prefix);
    const account = await this.getAccountInfo(signer);
    const pubkey = encodePubkey({
      type: "tendermint/PubKeySecp256k1",
      value: toBase64(fromHex(pubKeyHex, "pubKeyHex"))
    });
    const bodyBytes = this.registry.encodeTxBody({
      messages,
      memo
    });
    const authInfoBytes = makeAuthInfoBytes(
      [{ pubkey, sequence: account.sequence }],
      feeAmount,
      gasLimit,
      undefined,
      undefined
    );
    const signDoc = makeSignDoc(bodyBytes, authInfoBytes, this.chainId, account.accountNumber);
    return {
      bodyBytes: toBase64(signDoc.bodyBytes),
      authInfoBytes: toBase64(signDoc.authInfoBytes),
      chainId: signDoc.chainId,
      accountNumber: signDoc.accountNumber.toString()
    };
  }

  buildTxRawBytes({ bodyBytes, authInfoBytes, signature }) {
    const txRaw = TxRaw.fromPartial({
      bodyBytes: fromBase64(bodyBytes, "bodyBytes"),
      authInfoBytes: fromBase64(authInfoBytes, "authInfoBytes"),
      signatures: [fromBase64(signature, "signature")]
    });
    return TxRaw.encode(txRaw).finish();
  }

  async broadcastSignedTx(signedTx, waitOptions) {
    const client = await this.connect();
    const txBytes = this.buildTxRawBytes(signedTx);
    const txhash = await client.broadcastTxSync(txBytes);
    const tx = await this.waitForTx(txhash, waitOptions);
    return {
      broadcast: {
        txhash,
        code: 0,
        raw_log: ""
      },
      tx
    };
  }

  async signDirectAndBroadcast({ wallet, signDoc, waitOptions } = {}) {
    const adapter = createWalletAdapter(wallet);
    const signed = await adapter.signDirect(directSignDocFromBase64(signDoc), { signDoc });
    const signedDoc = signed.signed || {};
    const signature = signed.signature?.signature || signed.signature;
    return this.broadcastSignedTx({
      bodyBytes: toBase64(signedDoc.bodyBytes || fromBase64(signDoc.bodyBytes, "bodyBytes")),
      authInfoBytes: toBase64(signedDoc.authInfoBytes || fromBase64(signDoc.authInfoBytes, "authInfoBytes")),
      signature
    }, waitOptions);
  }
}

export function createClairveilClient(options) {
  return new ClairveilJS(options);
}
