import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  assertPreparedTransferPayloadShape,
  buildPreparedTransferPayload,
  buildPreparedWithdrawProverPayload,
  buildRelayWithdrawMsgFromPayload,
  buildWithdrawMsgFromPayload,
  computePreparedWithdrawPayloadHash,
  createNote,
  createSpendNoteHashSigner,
  decodeShieldedAddress,
  derivePrivacyMaterial,
  deriveSpendKeys,
  deriveViewKeys,
  hashStringToField,
  ClairveilErrorCode,
  plannerStatusToErrorCode
} from "clairveiljs/core";
import {
  createClairveilClient,
  MemoryNoteStore,
  MsgDeposit,
  MsgWithdraw,
  nextPrivacyScanOptions,
  userDisclosureModeRecipientEncrypted
} from "clairveiljs/cosmos";
import { conformanceFixtureRelativePath } from "clairveiljs/conformance";
import {
  bech32AddressToEvm,
  createClairveilEvmClient,
  createEip1193WalletAdapter,
  encodeEvmPrivacyDeposit,
  encodeFunctionData,
  encodeReferenceEvmDeposit,
  encodeReferenceEvmWithdraw,
  evmAddressToBech32,
  functionSelector,
  encodeEvmPrivacyTransfer,
  encodeEvmPrivacyWithdraw,
  evmPrivacyPrecompileAddress
} from "clairveiljs/evm";
import { createWalletAdapter } from "clairveiljs/wallet-adapter";
import { createClairveilPublicClient } from "clairveiljs/browser-public";
import { createClairveilBrowserDappClient } from "clairveiljs/browser-dapp";
import {
  planTransferNotes,
  planWithdrawNotes
} from "clairveiljs/planner";

const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

test("core/cosmos/evm entrypoints load", () => {
  assert.equal(typeof derivePrivacyMaterial, "function");
  assert.equal(typeof createClairveilClient, "function");
  assert.equal(typeof createClairveilPublicClient, "function");
  assert.equal(typeof createClairveilBrowserDappClient, "function");
  assert.equal(typeof createClairveilEvmClient, "function");
  assert.equal(functionSelector("deposit((string,bytes,bytes))").length, 8);
  assert.equal(evmPrivacyPrecompileAddress, "0x100000000000000000000000000000000000000b");
});

test("browser-dapp entrypoint instantiates a DApp client", async () => {
  const browserDapp = await import("clairveiljs/browser-dapp");
  const client = browserDapp.createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair",
    proverUrl: "http://127.0.0.1:8080"
  });

  assert.equal(typeof client.prepareDeposit, "function");
  assert.equal(typeof client.prepareTransfer, "function");
  assert.equal(typeof client.prepareWithdraw, "function");
  assert.equal(typeof client.prepareRelayWithdraw, "function");
  assert.equal(typeof client.createRelayWithdrawSignDoc, "function");
  assert.equal(typeof client.scanWalletNotes, "function");
  assert.equal(typeof client.fetchReserve, "function");
  assert.equal(typeof client.checkNullifier, "function");
  assert.equal(typeof browserDapp.ClairveilBrowserDappClient, "function");
});

test("browser-dapp client uses restEndpoints when rest is omitted", async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  globalThis.fetch = async url => {
    requestedUrls.push(String(url));
    return new Response(JSON.stringify({ balances: [], pagination: null }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  try {
    const client = createClairveilBrowserDappClient({
      rpc: "http://127.0.0.1:26657",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      chainId: "clairveil-local-3",
      accountPrefix: "clair",
      shieldedPrefix: "clairs",
      denom: "uclair"
    });

    await client.getBalances("clair1abc");
    assert.deepEqual(requestedUrls, [
      "http://rest-a.local/cosmos/bank/v1beta1/balances/clair1abc"
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("browser-dapp profile transport is the default wallet type", async () => {
  const client = createClairveilBrowserDappClient({
    profile: {
      transport: "evm",
      rpc: "http://127.0.0.1:26657",
      rest: "http://127.0.0.1:1317",
      chainId: "evm-local-1",
      accountPrefix: "demo",
      shieldedPrefix: "demos",
      denom: "udemo",
      evmChainId: "0x32f",
      evmPrivacyPrecompileAddress: evmPrivacyPrecompileAddress
    }
  });

  const prepared = await client.prepareDeposit({
    address: "0x1111111111111111111111111111111111111111",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: Buffer.from("profile-transport-evm").toString("base64"),
    amount: "3udemo"
  });

  assert.equal(prepared.signDoc, undefined);
  assert.equal(prepared.transaction.chainId, "0x32f");
  assert.equal(prepared.transaction.to, evmPrivacyPrecompileAddress);
  assert.equal(prepared.prepared.amount, "3udemo");
});

test("MsgDeposit includes the required deposit proof field", () => {
  const message = {
    creator: "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48",
    amount: "1uclair",
    noteCommitment: new Uint8Array(32).fill(1),
    encryptedNote: new Uint8Array([2, 3]),
    proof: new Uint8Array([4, 5, 6])
  };
  const encoded = MsgDeposit.encode(message).finish();
  const decoded = MsgDeposit.decode(encoded);
  assert.deepEqual([...decoded.proof], [4, 5, 6]);
});

test("browser-dapp deposit proof provider reuses the proven deposit material", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair"
  });
  let providerCommitmentHex = "";
  let capturedMessage = null;
  client.cosmos.buildDirectSignDoc = async ({ messages }) => {
    capturedMessage = messages[0].value;
    return { chainId: "clairveil-local-3", bodyBytes: "", authInfoBytes: "", accountNumber: "0" };
  };

  const prepared = await client.prepareDeposit({
    address: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: Buffer.from("deposit-proof-provider").toString("base64"),
    amount: "7uclair",
    depositProofProvider({ material }) {
      providerCommitmentHex = material.note_commitment_hex;
      return { proof_hex: "ab" };
    }
  });

  assert.equal(prepared.prepared.noteCommitmentHex, providerCommitmentHex);
  assert.equal(Buffer.from(capturedMessage.noteCommitment).toString("hex"), providerCommitmentHex);
  assert.deepEqual([...capturedMessage.proof], [0xab]);
});

test("wallet adapter accepts hex privacy root signatures", async () => {
  const signatureHex = "ab".repeat(64);
  const adapter = createWalletAdapter({
    address: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
    pubKeyHex: "02".padEnd(66, "0"),
    async signPrivacyRoot() {
      return `0x${signatureHex}`;
    }
  });

  const signature = await adapter.signPrivacyRoot(new Uint8Array([1, 2, 3]));
  const signatureBase64 = await adapter.signPrivacyRootBase64(new Uint8Array([1, 2, 3]));

  assert.equal(Buffer.from(signature).toString("hex"), signatureHex);
  assert.equal(Buffer.from(signatureBase64, "base64").toString("hex"), signatureHex);
});

test("wallet adapter rejects ambiguous unprefixed hex privacy root signatures", async () => {
  const signatureHex = "ab".repeat(64);
  const adapter = createWalletAdapter({
    address: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
    pubKeyHex: "02".padEnd(66, "0"),
    async signPrivacyRoot() {
      return signatureHex;
    }
  });

  await assert.rejects(
    () => adapter.signPrivacyRootBase64(new Uint8Array([1, 2, 3])),
    /hex strings must be prefixed with 0x/
  );
});

test("EIP-1193 wallet adapter returns only 0x-prefixed privacy root signatures", async () => {
  const calls = [];
  const provider = {
    async request(input) {
      calls.push(input);
      if (input.method === "eth_requestAccounts") {
        return ["0x1111111111111111111111111111111111111111"];
      }
      if (input.method === "personal_sign") {
        return "0x" + "ab".repeat(65);
      }
      throw new Error(`unexpected method ${input.method}`);
    }
  };
  const adapter = createEip1193WalletAdapter({ provider });

  const signature = await adapter.signPrivacyRoot(new Uint8Array([1, 2, 3]));

  assert.equal(signature, "0x" + "ab".repeat(65));
  assert.deepEqual(calls[1], {
    method: "personal_sign",
    params: ["0x010203", "0x1111111111111111111111111111111111111111"]
  });
});

test("EIP-1193 wallet adapter rejects non-hex privacy root signatures", async () => {
  const provider = {
    async request(input) {
      if (input.method === "eth_requestAccounts") {
        return ["0x1111111111111111111111111111111111111111"];
      }
      if (input.method === "personal_sign") {
        return "not-a-hex-signature";
      }
      throw new Error(`unexpected method ${input.method}`);
    }
  };
  const adapter = createEip1193WalletAdapter({ provider });

  await assert.rejects(
    () => adapter.signPrivacyRoot(new Uint8Array([1, 2, 3])),
    /0x-prefixed hex signature/
  );
});

test("deposit preparation requires a deposit proof", async () => {
  const browserClient = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair"
  });

  await assert.rejects(
    () => browserClient.prepareDeposit({
      address: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
      pubKeyHex: "02".padEnd(66, "0"),
      signatureBase64: Buffer.from("missing-deposit-proof").toString("base64"),
      amount: "7uclair"
    }),
    /deposit proof is required/
  );

  const cosmosClient = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });

  assert.throws(
    () => cosmosClient.buildDepositMessage({
      creator: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
      rootSeed: new Uint8Array(32),
      amount: "7uclair"
    }),
    /deposit proof is required/
  );

  const hexProofDeposit = cosmosClient.buildDepositMessage({
    creator: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
    rootSeed: new Uint8Array(32),
    amount: "7uclair",
    proof: "0xab"
  });
  assert.deepEqual([...hexProofDeposit.message.proof], [0xab]);

  const staleCreatorMaterial = cosmosClient.buildDepositMaterial({
    creator: "clair1other",
    rootSeed: new Uint8Array(32).fill(1),
    amount: "7uclair"
  });
  assert.throws(
    () => cosmosClient.buildDepositMessage({
      creator: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
      depositMaterial: staleCreatorMaterial,
      amount: "7uclair",
      proof: "0xab"
    }),
    /deposit material creator mismatch/
  );

  const staleAmountMaterial = cosmosClient.buildDepositMaterial({
    creator: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
    rootSeed: new Uint8Array(32).fill(2),
    amount: "8uclair"
  });
  assert.throws(
    () => cosmosClient.buildDepositMessage({
      creator: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
      depositMaterial: staleAmountMaterial,
      amount: "7uclair",
      proof: "0xab"
    }),
    /deposit material amount mismatch/
  );
});

test("cosmos deposit preparation forwards custom memo", async () => {
  const cosmosClient = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  let capturedMemo = "";
  cosmosClient.buildDirectSignDoc = async ({ memo }) => {
    capturedMemo = memo;
    return { chainId: "clairveil-local-3", bodyBytes: "", authInfoBytes: "", accountNumber: "0" };
  };

  await cosmosClient.prepareDeposit({
    material: {
      address: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
      pubKeyHex: "02".padEnd(66, "0"),
      rootSeed: new Uint8Array(32),
      signingMessage: "",
      shieldedAddress: "clairs1demo",
      disclosurePubKeyHex: "",
      rootSignatureHash: ""
    },
    amount: "7uclair",
    proofHex: "ab",
    memo: "custom deposit memo"
  });

  assert.equal(capturedMemo, "custom deposit memo");
});

test("prepared transfer payload shape accepts v2 self-view fields", () => {
  const payload = {
    version: "v2",
    creator: "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48",
    root_hex: "00".repeat(32),
    asset_id_hex: "01".repeat(32),
    inputs: [{}, {}],
    outputs: [{}, {}],
    cipher_text_hexes: ["aa", "bb"],
    audit_disclosure_digest_hex: "02".repeat(32),
    audit_disclosure_target_pubkey_hex: "03".repeat(32),
    self_view_disclosure_digest_hex: "04".repeat(32),
    self_view_disclosure_payload_hex: "abcd",
    payload_hash: "05".repeat(32)
  };

  assert.equal(assertPreparedTransferPayloadShape(payload), payload);
  assert.throws(
    () => assertPreparedTransferPayloadShape({
      ...payload,
      version: "v1"
    }),
    /self_view_disclosure_\* fields require version v2/
  );
});

test("browser-dapp public send helpers validate recipients and coin amounts", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "evm-local-1",
    accountPrefix: "maroo",
    shieldedPrefix: "clairs",
    denom: "aokrw",
    evmChainId: "0x32f"
  });

  const transaction = client.evmNativeSendTransaction({
    to: "0x1111111111111111111111111111111111111111",
    amount: "7aokrw"
  });

  assert.equal(transaction.to, "0x1111111111111111111111111111111111111111");
  assert.equal(transaction.value, "0x7");
  assert.throws(
    () => client.evmNativeSendTransaction({
      to: "maroo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqf5k0v7",
      amount: "1aokrw"
    }),
    /send recipient must be 20-byte hex/
  );
  assert.throws(
    () => client.evmNativeSendTransaction({
      to: "0x1111111111111111111111111111111111111111",
      amount: "0aokrw"
    }),
    /send amount must be greater than 0/
  );
  assert.throws(
    () => client.evmNativeSendTransaction({
      to: "0x1111111111111111111111111111111111111111",
      amount: "1uclair"
    }),
    /send denom must be aokrw, got uclair/
  );

  client.cosmos.buildDirectSignDoc = async input => input;
  const signDoc = await client.buildBankSendSignDoc({
    from: "maroo1sender",
    pubKeyHex: "02".padEnd(66, "0"),
    to: "maroo1recipient",
    amount: "9aokrw"
  });
  assert.deepEqual(signDoc.messages[0].value.amount, [{
    denom: "aokrw",
    amount: "9"
  }]);
  await assert.rejects(
    () => client.buildBankSendSignDoc({
      from: "maroo1sender",
      pubKeyHex: "02".padEnd(66, "0"),
      to: "maroo1recipient",
      amount: "0aokrw"
    }),
    /send amount must be greater than 0/
  );
});

test("browser-dapp scanWalletNotes forwards query options", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair"
  });
  client.privacyMaterial = () => ({ rootSeed: new Uint8Array(32) });
  let forwarded = null;
  client.cosmos.scanWalletNotes = async input => {
    forwarded = input;
    return {
      privacyAccount: {},
      summary: { total_spendable: "0uclair" },
      foundNotes: []
    };
  };

  await client.scanWalletNotes({
    address: "clair1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    limit: 50,
    maxPages: 4,
    afterHeight: 12,
    page: 3,
    eventTypes: ["deposit", "shielded_transfer"],
    includeFoundNotes: true
  });

  assert.equal(forwarded.limit, 50);
  assert.equal(forwarded.maxPages, 4);
  assert.equal(forwarded.afterHeight, 12);
  assert.equal(forwarded.page, 3);
  assert.deepEqual(forwarded.eventTypes, ["deposit", "shielded_transfer"]);
  assert.equal(forwarded.includeFoundNotes, true);
});

test("browser-dapp exposes chain nullifier checks", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair"
  });
  let requested = "";
  client.cosmos.checkNullifier = async nullifierHex => {
    requested = nullifierHex;
    return { used: true };
  };

  const result = await client.checkNullifier("aa".repeat(32));

  assert.equal(requested, "aa".repeat(32));
  assert.equal(result.used, true);
});

test("cosmos note scan paginates within the requested page budget", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  const requests = [];
  client.fetchPrivacyEvents = async request => {
    requests.push(request);
    return {
      events: [
        {
          event_type: "withdraw",
          height: request.page,
          tx_hash_hex: `PAGE${request.page}`
        }
      ],
      page: request.page,
      limit: request.limit,
      has_more: request.page < 2
    };
  };

  const result = await client.scanNotes({
    rootSeed: new Uint8Array(32),
    limit: 200,
    maxPages: 2
  });

  assert.deepEqual(requests.map(request => request.page), [1, 2]);
  assert.equal(result.diagnostics.scanned_events, 2);
  assert.equal(result.diagnostics.pages_scanned, 2);
  assert.equal(result.scanCursor.has_more, false);
  assert.equal(result.scanCursor.completed, true);
  assert.equal(result.scanCursor.next_page, 1);
  assert.equal(result.nextScanOptions.afterHeight, 2);
  assert.equal(result.nextScanOptions.page, 1);
  assert.equal(result.nextScanOptions.completed, true);

  requests.length = 0;
  const partial = await client.scanNotes({
    rootSeed: new Uint8Array(32),
    limit: 200,
    maxPages: 1
  });

  assert.deepEqual(requests.map(request => request.page), [1]);
  assert.equal(partial.scanCursor.has_more, true);
  assert.equal(partial.scanCursor.next_page, 2);
  assert.equal(partial.nextScanOptions.afterHeight, 0);
  assert.equal(partial.nextScanOptions.page, 2);
  assert.equal(partial.nextScanOptions.hasMore, true);
  assert.deepEqual(
    nextPrivacyScanOptions(partial).eventTypes,
    ["deposit", "shielded_transfer"]
  );
});

test("cosmos wallet note store refreshes cached spent statuses", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  const nullifier = "01".padStart(64, "0");
  const store = new MemoryNoteStore({ owner: "clair1example" });
  await store.mergeScanResult({
    foundNotes: [{
      height: 7,
      txHash: "AA01",
      isSpent: false,
      nullifier,
      note: {
        receiverSpendPubKeyX: 1n,
        receiverSpendPubKeyY: 2n,
        receiverViewPubKeyX: 3n,
        receiverViewPubKeyY: 4n,
        amount: 10n,
        assetID: hashStringToField("uclair"),
        randomness: 11n,
        memo: "cached"
      }
    }]
  });
  client.fetchPrivacyEvents = async request => ({
    events: [],
    page: request.page,
    limit: request.limit,
    has_more: false
  });
  client.checkNullifier = async value => ({ used: value === nullifier });

  await client.scanWalletNotes({
    material: {
      rootSeed: new Uint8Array(32),
      address: "clair1example",
      pubKeyHex: "02".padEnd(66, "0"),
      signingMessage: "",
      shieldedAddress: "clairs1example",
      disclosurePubKeyHex: "",
      rootSignatureHash: ""
    },
    noteStore: store
  });

  const loaded = await store.load();
  assert.equal(loaded.notes[0].isSpent, true);
  assert.equal(loaded.notes[0].spent, true);
});

test("browser-dapp prepare forwards scan options into EVM note scans", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair",
    evmPrivacyPrecompileAddress: "0x100000000000000000000000000000000000000b"
  });
  client.privacyMaterial = () => ({
    rootSeed: new Uint8Array(32),
    address: "clair1example",
    pubKeyHex: "02".padEnd(66, "0"),
    shieldedAddress: "clairs1example"
  });
  const scans = [];
  client.cosmos.scanNotes = async input => {
    scans.push(input);
    return {
      notes: [],
      summary: { total_spendable: "0", spendable_count: 0, spent_count: 0, total_count: 0 },
      diagnostics: { scanned_events: 0, new_notes_found: 0 },
      foundNotes: [],
      scanCursor: { has_more: false }
    };
  };

  await assert.rejects(() => client.prepareTransfer({
    walletType: "evm",
    address: "clair1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1uclair",
    recipient: "clairs1recipient"
  }));
  await assert.rejects(() => client.prepareTransfer({
    walletType: "evm",
    address: "clair1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1uclair",
    recipient: "clairs1recipient",
    scan: { afterHeight: 9, limit: 123, maxPages: 7 }
  }));
  await assert.rejects(() => client.prepareWithdraw({
    walletType: "evm",
    address: "clair1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1uclair",
    recipient: "clair1recipient",
    scan: { afterHeight: 10, limit: 124, maxPages: 8 }
  }));

  const [defaultTransferScan, transferScan, withdrawScan] = scans;
  assert.equal(defaultTransferScan.limit, 200);
  assert.equal(defaultTransferScan.maxPages > 50, true);
  assert.equal(transferScan.afterHeight, 9);
  assert.equal(transferScan.limit, 123);
  assert.equal(transferScan.maxPages, 7);
  assert.equal(withdrawScan.afterHeight, 10);
  assert.equal(withdrawScan.limit, 124);
  assert.equal(withdrawScan.maxPages, 8);
});

test("planner rejects zero transfer and withdraw amounts before note planning", () => {
  const transfer = planTransferNotes({
    notes: [],
    amount: "0uclair",
    denom: "uclair"
  });
  const withdraw = planWithdrawNotes({
    notes: [],
    amount: "0uclair",
    denom: "uclair"
  });

  assert.equal(transfer.status, "invalid_amount");
  assert.equal(transfer.canBuildTx, false);
  assert.equal(transfer.action, "enter_positive_amount");
  assert.match(transfer.message, /greater than 0/);
  assert.equal(plannerStatusToErrorCode(transfer.status), ClairveilErrorCode.INVALID_AMOUNT);
  assert.equal(withdraw.status, "invalid_amount");
  assert.equal(withdraw.canBuildTx, false);
  assert.equal(withdraw.action, "enter_positive_amount");
  assert.match(withdraw.message, /greater than 0/);
  assert.equal(plannerStatusToErrorCode(withdraw.status), ClairveilErrorCode.INVALID_AMOUNT);
});

test("browser-dapp rejects unknown wallet types", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair"
  });

  await assert.rejects(
    () => client.prepareDeposit({
      address: "clair1example",
      pubKeyHex: "02".padEnd(66, "0"),
      signatureBase64: "AQID",
      walletType: "evmm",
      amount: "1uclair"
    }),
    error => error?.code === "INVALID_ARGUMENT" && /unsupported wallet type: evmm/.test(error.message)
  );
});

test("browser-dapp exposes audit disclosure decoding", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair"
  });
  let forwarded = null;
  client.cosmos.decodeAuditDisclosure = async input => {
    forwarded = input;
    return {
      plane: "audit",
      policy: "audit-full",
      output_index: 0,
      commitment_hex: "aa".repeat(32),
      digest_hex: "bb".repeat(32),
      verified: true,
      amount: "1",
      asset_denom: "uclair",
      from: "clairs1from",
      to: "clairs1to"
    };
  };

  const report = await client.decodeAuditDisclosure({
    txHash: "aabb",
    disclosurePrivKeyHex: "01".repeat(32)
  });

  assert.deepEqual(forwarded, {
    txHash: "aabb",
    disclosurePrivKeyHex: "01".repeat(32)
  });
  assert.equal(report.plane, "audit");
  assert.equal(report.verified, true);
});

test("browser public client reads events directly and filters auditable transfers", async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  globalThis.fetch = async url => {
    requestedUrls.push(String(url));
    return new Response(JSON.stringify({
      events: [
        {
          event_type: "shielded_transfer",
          attributes: [{ key: "audit_disclosure_payload", value: "aa" }]
        },
        {
          event_type: "shielded_transfer",
          attributes: []
        },
        {
          event_type: "deposit",
          attributes: [{ key: "audit_disclosure_payload", value: "bb" }]
        }
      ]
    }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  try {
    const client = createClairveilPublicClient({ rest: "http://chain.local:1317/" });
    const data = await client.fetchAuditableTransfers({ limit: 5, eventTypes: ["shielded_transfer"] });
    assert.equal(data.events.length, 1);
    assert.equal(requestedUrls[0], "http://chain.local:1317/clairveil/privacy/v1/events?limit=5&event_types=shielded_transfer");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Reserve query is exposed across public, browser-dapp, and cosmos clients", async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  globalThis.fetch = async url => {
    requestedUrls.push(String(url));
    return new Response(JSON.stringify({
      denom: "factory/demo/uclair",
      module_balance: "7",
      total_deposited: "10",
      total_withdrawn: "3",
      expected_module_balance: "7",
      invariant_holds: true
    }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  try {
    const publicClient = createClairveilPublicClient({ rest: "http://chain.local:1317/" });
    const cosmosClient = createClairveilClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://chain.local:1317/",
      chainId: "clairveil-local-3"
    });
    const browserClient = createClairveilBrowserDappClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://chain.local:1317/",
      chainId: "clairveil-local-3"
    });

    const [publicReserve, cosmosReserve, browserReserve] = await Promise.all([
      publicClient.fetchReserve("factory/demo/uclair"),
      cosmosClient.fetchReserve("factory/demo/uclair"),
      browserClient.fetchReserve("factory/demo/uclair")
    ]);

    assert.equal(publicReserve.invariant_holds, true);
    assert.equal(cosmosReserve.expected_module_balance, "7");
    assert.equal(browserReserve.denom, "factory/demo/uclair");
    assert.deepEqual(requestedUrls, [
      "http://chain.local:1317/clairveil/privacy/v1/reserve/factory%2Fdemo%2Fuclair",
      "http://chain.local:1317/clairveil/privacy/v1/reserve/factory%2Fdemo%2Fuclair",
      "http://chain.local:1317/clairveil/privacy/v1/reserve/factory%2Fdemo%2Fuclair"
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("chain REST queries abort after the configured timeout", async () => {
  const originalFetch = globalThis.fetch;
  let aborts = 0;
  globalThis.fetch = async (_url, options = {}) => new Promise((_resolve, reject) => {
    options.signal?.addEventListener("abort", () => {
      aborts += 1;
      const error = new Error("aborted");
      error.name = "AbortError";
      reject(error);
    });
  });
  try {
    const publicClient = createClairveilPublicClient({
      rest: "http://chain.local:1317/",
      queryTimeoutMs: 5,
      queryRetry: false
    });
    await assert.rejects(
      () => publicClient.fetchReserve("uclair"),
      /fetch request timed out after 5ms/
    );

    const cosmosClient = createClairveilClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://chain.local:1317/",
      chainId: "clairveil-local-3",
      queryTimeoutMs: 5,
      queryRetry: false
    });
    await assert.rejects(
      () => cosmosClient.fetchReserve("uclair"),
      /fetch request timed out after 5ms/
    );

    const browserClient = createClairveilBrowserDappClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://chain.local:1317/",
      chainId: "clairveil-local-3",
      queryTimeoutMs: 5,
      queryRetry: false
    });
    await assert.rejects(
      () => browserClient.getBalances("clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48"),
      /fetch request timed out after 5ms/
    );

    assert.equal(aborts, 3);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("public chain read queries retry and fail over across REST endpoints", async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  globalThis.fetch = async url => {
    const text = String(url);
    requestedUrls.push(text);
    if (text.startsWith("http://rest-a.local")) {
      return new Response("busy", { status: 503 });
    }
    return new Response(JSON.stringify({
      denom: "uclair",
      module_balance: "1",
      total_deposited: "1",
      total_withdrawn: "0",
      expected_module_balance: "1",
      invariant_holds: true
    }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  try {
    const client = createClairveilClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://rest-a.local",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      chainId: "clairveil-local-3",
      queryRetry: {
        retries: 1,
        baseDelayMs: 1,
        maxDelayMs: 1,
        jitter: false
      }
    });

    const reserve = await client.fetchReserve("uclair");
    assert.equal(reserve.invariant_holds, true);
    assert.deepEqual(requestedUrls, [
      "http://rest-a.local/clairveil/privacy/v1/reserve/uclair",
      "http://rest-a.local/clairveil/privacy/v1/reserve/uclair",
      "http://rest-b.local/clairveil/privacy/v1/reserve/uclair"
    ]);

    requestedUrls.length = 0;
    await client.fetchReserve("uclair");
    assert.equal(requestedUrls[0], "http://rest-b.local/clairveil/privacy/v1/reserve/uclair");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("browser-dapp balance and health REST queries fail over across endpoints", async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  globalThis.fetch = async url => {
    const text = String(url);
    requestedUrls.push(text);
    if (text.startsWith("http://rest-a.local")) {
      return new Response("busy", { status: 503 });
    }
    if (text.endsWith("/cosmos/bank/v1beta1/balances/clair1abc")) {
      return new Response(JSON.stringify({ balances: [{ denom: "uclair", amount: "7" }], pagination: null }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    if (text.endsWith("/clairveil/privacy/v1/tree_state")) {
      return new Response(JSON.stringify({ tree_size: "1" }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    if (text.endsWith("/clairveil/privacy/v1/audit_config")) {
      return new Response(JSON.stringify({ audit_master_pubkey_hex: "" }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    if (text.endsWith("/status")) {
      return new Response(JSON.stringify({ result: { node_info: { network: "local" } } }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    throw new Error(`unexpected URL ${text}`);
  };
  try {
    const client = createClairveilBrowserDappClient({
      rpc: "http://rpc.local",
      rest: "http://rest-a.local",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      chainId: "clairveil-local-3",
      queryRetry: {
        retries: 1,
        baseDelayMs: 1,
        maxDelayMs: 1,
        jitter: false
      }
    });

    const balances = await client.getBalances("clair1abc");
    const health = await client.health();

    assert.equal(balances.balances[0].amount, "7");
    assert.equal(health.tree.tree_size, "1");
    assert.equal(health.audit.audit_master_pubkey_hex, "");
    assert.deepEqual(requestedUrls, [
      "http://rest-a.local/cosmos/bank/v1beta1/balances/clair1abc",
      "http://rest-a.local/cosmos/bank/v1beta1/balances/clair1abc",
      "http://rest-b.local/cosmos/bank/v1beta1/balances/clair1abc",
      "http://rpc.local/status",
      "http://rest-b.local/clairveil/privacy/v1/tree_state",
      "http://rest-b.local/clairveil/privacy/v1/audit_config"
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("chain read query failover does not mask non-retryable errors", async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  globalThis.fetch = async url => {
    const text = String(url);
    requestedUrls.push(text);
    if (text.startsWith("http://rest-a.local")) {
      return new Response("bad request", { status: 400 });
    }
    return new Response(JSON.stringify({ invariant_holds: true }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  try {
    const cosmosClient = createClairveilClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://rest-a.local",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      chainId: "clairveil-local-3",
      queryRetry: {
        retries: 1,
        baseDelayMs: 1,
        maxDelayMs: 1,
        jitter: false
      }
    });
    await assert.rejects(
      () => cosmosClient.fetchReserve("uclair"),
      /400/
    );

    const publicClient = createClairveilPublicClient({
      rest: "http://rest-a.local",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      queryRetry: {
        retries: 1,
        baseDelayMs: 1,
        maxDelayMs: 1,
        jitter: false
      }
    });
    await assert.rejects(
      () => publicClient.fetchReserve("uclair"),
      /400/
    );

    assert.deepEqual(requestedUrls, [
      "http://rest-a.local/clairveil/privacy/v1/reserve/uclair",
      "http://rest-a.local/clairveil/privacy/v1/reserve/uclair"
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("public and cosmos fetchJson honor absolute URLs", async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  globalThis.fetch = async url => {
    const text = String(url);
    requestedUrls.push(text);
    return new Response(JSON.stringify({ url: text }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  try {
    const cosmosClient = createClairveilClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://rest-a.local",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      chainId: "clairveil-local-3",
      queryRetry: false
    });
    const publicClient = createClairveilPublicClient({
      rest: "http://rest-a.local",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      queryRetry: false
    });

    const cosmosResult = await cosmosClient.fetchJson("http://external.local/custom?x=1");
    const publicResult = await publicClient.fetchJson("http://external.local/other?y=2");

    assert.equal(cosmosResult.url, "http://external.local/custom?x=1");
    assert.equal(publicResult.url, "http://external.local/other?y=2");
    assert.equal(cosmosClient.activeRestEndpoint, "http://rest-a.local");
    assert.equal(publicClient.activeRestEndpoint, "http://rest-a.local");
    assert.deepEqual(requestedUrls, [
      "http://external.local/custom?x=1",
      "http://external.local/other?y=2"
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("cosmos broadcastSignedTx rejects failed indexed transactions", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  client.connect = async () => ({
    broadcastTxSync: async () => "ABC123"
  });
  client.buildTxRawBytes = () => new Uint8Array([1, 2, 3]);
  client.waitForTx = async () => ({
    height: "9",
    txhash: "ABC123",
    code: 18,
    raw_log: "invalid request",
    events: []
  });

  await assert.rejects(
    () => client.broadcastSignedTx({
      bodyBytes: "",
      authInfoBytes: "",
      signature: ""
    }),
    error => {
      assert.equal(error.broadcast.code, 18);
      assert.equal(error.tx.code, 18);
      return /failed with code 18/.test(error.message);
    }
  );
});

test("cosmos broadcastSignedTx does not mark unindexed transactions as ok", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  client.connect = async () => ({
    broadcastTxSync: async () => "ABC123"
  });
  client.buildTxRawBytes = () => new Uint8Array([1, 2, 3]);
  client.waitForTx = async () => null;

  const result = await client.broadcastSignedTx({
    bodyBytes: "",
    authInfoBytes: "",
    signature: ""
  });

  assert.equal(result.ok, false);
  assert.equal(result.tx, null);
  assert.equal(result.broadcast.code, 0);
  assert.match(result.error, /broadcast but not found yet/);
});

test("nullifier queries retry on the same endpoint unless failover is explicit", async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  globalThis.fetch = async url => {
    const text = String(url);
    requestedUrls.push(text);
    if (text.startsWith("http://rest-a.local")) {
      return new Response("busy", { status: 503 });
    }
    return new Response(JSON.stringify({ used: false }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  try {
    const defaultClient = createClairveilClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://rest-a.local",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      chainId: "clairveil-local-3",
      queryRetry: {
        retries: 1,
        baseDelayMs: 1,
        maxDelayMs: 1,
        jitter: false
      }
    });
    await assert.rejects(
      () => defaultClient.checkNullifier("aa".repeat(32)),
      /503/
    );
    assert.deepEqual(requestedUrls, [
      `http://rest-a.local/clairveil/privacy/v1/nullifier/${"aa".repeat(32)}`,
      `http://rest-a.local/clairveil/privacy/v1/nullifier/${"aa".repeat(32)}`
    ]);

    requestedUrls.length = 0;
    const optInClient = createClairveilClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://rest-a.local",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      chainId: "clairveil-local-3",
      nullifierFailover: true,
      queryRetry: {
        retries: 1,
        baseDelayMs: 1,
        maxDelayMs: 1,
        jitter: false
      }
    });
    const result = await optInClient.checkNullifier("bb".repeat(32));
    assert.equal(result.used, false);
    assert.deepEqual(requestedUrls, [
      `http://rest-a.local/clairveil/privacy/v1/nullifier/${"bb".repeat(32)}`,
      `http://rest-a.local/clairveil/privacy/v1/nullifier/${"bb".repeat(32)}`,
      `http://rest-b.local/clairveil/privacy/v1/nullifier/${"bb".repeat(32)}`
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("cosmos disclosure lookup paginates privacy events by tx hash", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  const requests = [];
  client.fetchPrivacyEvents = async request => {
    requests.push(request);
    if (request.page === 1) {
      return {
        events: [{ event_type: "shielded_transfer", tx_hash_hex: "NOTME" }],
        page: 1,
        limit: request.limit,
        has_more: true
      };
    }
    return {
      events: [{ event_type: "shielded_transfer", tx_hash_hex: "AABBCC" }],
      page: 2,
      limit: request.limit,
      has_more: false
    };
  };

  const event = await client.findPrivacyEventByTxHash("aabbcc", {
    limit: 1,
    maxPages: 3,
    afterHeight: 10
  });

  assert.equal(event.tx_hash_hex, "AABBCC");
  assert.deepEqual(requests.map(request => request.page), [1, 2]);
  assert.equal(requests[0].limit, 1);
  assert.equal(requests[0].afterHeight, 10);
  assert.deepEqual(requests[0].eventTypes, ["shielded_transfer"]);
});

test("root and cosmos-client entrypoints expose the Cosmos client surface", async () => {
  const root = await import("clairveiljs");
  const cosmosClient = await import("clairveiljs/cosmos-client");

  assert.equal(typeof root.createClairveilClient, "function");
  assert.equal(typeof root.prepareDeposit, "undefined");
  assert.equal(typeof cosmosClient.createClairveilClient, "function");
  assert.equal(cosmosClient.msgDepositTypeUrl, "/clairveil.privacy.v1.MsgDeposit");
});

test("generated Clairveil protobuf bindings are exposed", async () => {
  const tx = await import("clairveiljs/generated/clairveil/privacy/v1/tx");
  const txWithExtension = await import("clairveiljs/generated/clairveil/privacy/v1/tx.js");
  const query = await import("clairveiljs/generated/clairveil/privacy/v1/query");

  assert.equal(typeof tx.MsgDeposit.encode, "function");
  assert.equal(typeof tx.MsgTransfer.decode, "function");
  assert.equal(tx.MsgWithdraw.typeUrl, "/clairveil.privacy.v1.MsgWithdraw");
  assert.equal(typeof txWithExtension.MsgDeposit.encode, "function");
  assert.equal(txWithExtension.MsgWithdraw.typeUrl, "/clairveil.privacy.v1.MsgWithdraw");
  assert.equal(query.QueryReserveResponse.typeUrl, "/clairveil.privacy.v1.QueryReserveResponse");
});

test("package metadata is ready for public npm publishing", () => {
  assert.equal(packageJson.name, "clairveiljs");
  assert.notEqual(packageJson.version, "0.0.0");
  assert.equal(packageJson.license, "Apache-2.0");
  assert.equal(packageJson.publishConfig?.access, "public");
  assert.ok(packageJson.repository?.url?.includes("clairveiljs"));
  assert.ok(packageJson.bugs?.url?.includes("issues"));
  assert.ok(packageJson.files.includes("src"));
  assert.ok(packageJson.files.includes("proto"));
  assert.ok(packageJson.files.includes("README.md"));
  assert.ok(packageJson.files.includes("README.ko.md"));
  assert.ok(packageJson.files.includes("LICENSE"));
  assert.ok(packageJson.files.includes("test/e2e-local.e2e.js"));
  assert.ok(packageJson.dependencies["@cosmjs/stargate"]);
  assert.ok(packageJson.dependencies["cosmjs-types"]);
  assert.ok(packageJson.scripts["test:conformance:required"]?.includes("require-conformance-fixtures.js"));
  assert.ok(packageJson.scripts.prepublishOnly.includes("test:conformance:required"));
  assert.equal(conformanceFixtureRelativePath, "x/privacy/client/sdk/conformance/testdata");
});

test("custom shielded prefix works in standalone package", () => {
  const material = derivePrivacyMaterial({
    address: "demo1example0000000000000000000000000000000",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: Buffer.from("standalone-signature").toString("base64"),
    shieldedPrefix: "demos"
  });

  assert.match(material.shieldedAddress, /^demos1/);
  assert.doesNotThrow(() => decodeShieldedAddress(material.shieldedAddress, { shieldedPrefix: "demos" }));
});

test("withdraw message omits legacy output-note fields", () => {
  const payload = {
    version: "v1",
    proof_hex: "aa",
    root_hex: "01".repeat(32),
    nullifier_hex: "02".repeat(32),
    amount: "1uclair",
    recipient: "clair1abc",
    chain_id: "chain",
    expires_at_unix: Math.floor(Date.now() / 1000) + 3600
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);

  const message = buildWithdrawMsgFromPayload(payload, "clair1creator");
  assert.equal("newNoteCommitment" in message, false);
  assert.equal("encryptedNote" in message, false);

  const partial = MsgWithdraw.fromPartial({
    ...message,
    newNoteCommitment: new Uint8Array(32).fill(4),
    encryptedNote: new Uint8Array(32).fill(5)
  });
  assert.equal("newNoteCommitment" in partial, false);
  assert.equal("encryptedNote" in partial, false);

  const encoded = MsgWithdraw.encode({
    ...message,
    newNoteCommitment: new Uint8Array(32).fill(4),
    encryptedNote: new Uint8Array(32).fill(5)
  }).finish();
  assert.equal(encoded.includes(42), false);
  assert.equal(encoded.includes(50), false);
});

test("relay withdraw message uses relayer as creator and payload recipient as recipient", () => {
  const payload = {
    version: "v1",
    proof_hex: "40".repeat(96),
    root_hex: "00".repeat(31) + "01",
    nullifier_hex: "02".repeat(32),
    amount: "1uclair",
    recipient: "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48",
    chain_id: "clairveil-local-1",
    expires_at_unix: 4102448400
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);

  const message = buildRelayWithdrawMsgFromPayload(
    payload,
    "clair1pyysjzgfpyysjzgfpyysjzgfpyysjzgf0j5ga5",
    {
      nowUnix: 4102444800,
      expectedChainId: "clairveil-local-1",
      expectedRecipient: payload.recipient,
      accountPrefix: "clair"
    }
  );

  assert.equal(message.creator, "clair1pyysjzgfpyysjzgfpyysjzgfpyysjzgf0j5ga5");
  assert.equal(message.recipient, payload.recipient);
  assert.equal(message.chainId, "clairveil-local-1");

  const badExpiry = { ...payload, expires_at_unix: "not-a-number" };
  badExpiry.payload_hash = computePreparedWithdrawPayloadHash(badExpiry);
  assert.throws(
    () => buildRelayWithdrawMsgFromPayload(
      badExpiry,
      "clair1pyysjzgfpyysjzgfpyysjzgfpyysjzgf0j5ga5",
      {
        nowUnix: 4102444800,
        expectedChainId: "clairveil-local-1",
        expectedRecipient: badExpiry.recipient,
        accountPrefix: "clair"
      }
    ),
    /withdraw payload expires_at_unix must be a safe integer unix timestamp/
  );

  const missingExpiry = { ...payload };
  delete missingExpiry.expires_at_unix;
  missingExpiry.payload_hash = computePreparedWithdrawPayloadHash(missingExpiry);
  assert.throws(
    () => buildRelayWithdrawMsgFromPayload(
      missingExpiry,
      "clair1pyysjzgfpyysjzgfpyysjzgfpyysjzgf0j5ga5",
      {
        nowUnix: 4102444800,
        expectedChainId: "clairveil-local-1",
        expectedRecipient: missingExpiry.recipient,
        accountPrefix: "clair"
      }
    ),
    /withdraw payload expires_at_unix must be a safe integer unix timestamp/
  );
});

test("withdraw prover payload rejects invalid expiry before proof handoff", async () => {
  const note = {
    receiverSpendPubKeyX: 1n,
    receiverSpendPubKeyY: 2n,
    receiverViewPubKeyX: 3n,
    receiverViewPubKeyY: 4n,
    amount: 1n,
    assetID: hashStringToField("uclair"),
    randomness: 5n,
    memo: "expiry"
  };
  const baseInput = {
    notes: [{ note, isSpent: false }],
    amount: "1uclair",
    recipient: "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48",
    chainId: "clairveil-local-1",
    rootSeed: new Uint8Array(32).fill(1),
    merklePathProvider: {
      async lookupMerklePath() {
        return { root: "01".padStart(64, "0"), path: [], path_helper: [] };
      }
    }
  };

  await assert.rejects(
    () => buildPreparedWithdrawProverPayload({
      ...baseInput,
      expiresAtUnix: "not-a-number"
    }),
    /withdraw prover payload expires_at_unix must be a safe integer unix timestamp/
  );
  await assert.rejects(
    () => buildPreparedWithdrawProverPayload({
      ...baseInput,
      expiresAtUnix: 1
    }),
    /withdraw prover payload expired/
  );
});

test("prepared transfer payload skips self-view disclosure when signer material is external", async () => {
  const senderRootSeed = new Uint8Array(32).fill(9);
  const senderSpend = deriveSpendKeys(senderRootSeed).pubKey;
  const senderView = deriveViewKeys(senderRootSeed).pubKey;
  const recipientMaterial = derivePrivacyMaterial({
    address: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
    pubKeyHex: "03".padEnd(66, "0"),
    signatureBase64: Buffer.from("recipient-root-signature").toString("base64"),
    shieldedPrefix: "clairs"
  });
  const inputs = [
    {
      note: createNote({
        spendPubKey: senderSpend,
        viewPubKey: senderView,
        amount: 1n,
        assetDenom: "uclair",
        randomness: 101n
      }),
      isSpent: false
    },
    {
      note: createNote({
        spendPubKey: senderSpend,
        viewPubKey: senderView,
        amount: 1n,
        assetDenom: "uclair",
        randomness: 102n
      }),
      isSpent: false
    }
  ];
  const payload = await buildPreparedTransferPayload({
    creator: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
    inputs,
    recipient: recipientMaterial.shieldedAddress,
    amount: "1uclair",
    senderSpendPubKey: senderSpend,
    senderViewPubKey: senderView,
    noteHashSigner: createSpendNoteHashSigner(senderRootSeed),
    auditDisclosureTargetPubKeyHex: recipientMaterial.disclosurePubKeyHex,
    merklePathProvider: {
      async lookupMerklePath() {
        return { root: "01".padStart(64, "0"), path: [], path_helper: [] };
      }
    },
    shieldedPrefix: "clairs"
  });

  assertPreparedTransferPayloadShape(payload);
  assert.equal(payload.self_view_disclosure_digest_hex, "");
  assert.equal(payload.self_view_disclosure_payload_hex, "");
});

test("EVM client builds and sends deposit transaction with mock provider", async () => {
  const sent = [];
  const provider = {
    async request({ method, params }) {
      if (method === "eth_requestAccounts") {
        return ["0x1111111111111111111111111111111111111111"];
      }
      if (method === "eth_sendTransaction") {
        sent.push(params[0]);
        return "0x" + "cd".repeat(32);
      }
      throw new Error(`unexpected method ${method}`);
    }
  };
  const client = createClairveilEvmClient({
    provider,
    shieldedPrefix: "demos",
    accountPrefix: "demo",
    defaultDenom: "udemo"
  });
  const material = derivePrivacyMaterial({
    address: "0x1111111111111111111111111111111111111111",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: Buffer.from("evm-standalone-signature").toString("base64"),
    shieldedPrefix: "demos"
  });
  const prepared = client.buildDepositTransaction({
    creator: material.address,
    rootSeed: material.rootSeed,
    amount: "3"
  });
  const sameMaterial = client.buildDepositTransaction({
    material: prepared.material
  });
  const sameMessage = client.buildDepositTransaction({
    message: prepared.message
  });
  assert.throws(
    () => client.buildDepositTransaction({
      material: prepared.material,
      creator: "0x2222222222222222222222222222222222222222"
    }),
    /deposit material creator mismatch/
  );
  const wallet = createEip1193WalletAdapter({ provider });
  const txHash = await client.sendTransaction(wallet, prepared.transaction);

  assert.equal(prepared.material.amount, "3udemo");
  assert.equal(prepared.transaction.to, evmPrivacyPrecompileAddress);
  assert.equal(prepared.transaction.data.slice(2, 10), functionSelector("deposit((string,bytes,bytes))"));
  assert.equal(prepared.transaction.data, sameMaterial.transaction.data);
  assert.equal(prepared.transaction.data, sameMessage.transaction.data);
  assert.equal(sameMessage.material, undefined);
  assert.equal(txHash, "0x" + "cd".repeat(32));
  assert.equal(sent[0].from, "0x1111111111111111111111111111111111111111");
});

test("EVM client wraps existing transfer and withdraw messages without prepared material", async () => {
  const client = createClairveilEvmClient({
    shieldedPrefix: "demos",
    accountPrefix: "demo",
    defaultDenom: "udemo"
  });
  const transferMessage = {
    proof: new Uint8Array([1, 2, 3]),
    root: new Uint8Array(32).fill(1),
    nullifiers: [new Uint8Array(32).fill(2), new Uint8Array(32).fill(3)],
    newCommitments: [new Uint8Array(32).fill(4), new Uint8Array(32).fill(5)],
    cipherTexts: [new Uint8Array([6]), new Uint8Array([7])],
    auditDisclosureDigest: new Uint8Array(),
    auditDisclosureTargetPubkey: new Uint8Array(),
    auditDisclosurePayload: new Uint8Array()
  };
  const withdrawMessage = {
    proof: new Uint8Array([1, 2, 3]),
    root: new Uint8Array(32).fill(8),
    nullifier: new Uint8Array(32).fill(9),
    amount: "1udemo",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chainId: "demo-1",
    expiresAtUnix: 4102448400n
  };

  const transfer = await client.buildTransferTransaction({ message: transferMessage });
  const withdraw = await client.buildWithdrawTransaction({ message: withdrawMessage });

  assert.equal(transfer.message, transferMessage);
  assert.equal(transfer.payload, undefined);
  assert.equal(transfer.proof, undefined);
  assert.equal(transfer.transaction.to, evmPrivacyPrecompileAddress);
  assert.equal(transfer.transaction.data.slice(2, 10), functionSelector("transfer((bytes,bytes,bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes))"));
  assert.equal(withdraw.message, withdrawMessage);
  assert.equal(withdraw.payload, undefined);
  assert.equal(withdraw.proof, undefined);
  assert.equal(withdraw.proverPayload, undefined);
  assert.equal(withdraw.selectedNote, undefined);
  assert.equal(withdraw.transaction.to, evmPrivacyPrecompileAddress);
  assert.equal(withdraw.transaction.data.slice(2, 10), functionSelector("withdraw((bytes,bytes,bytes,bytes,bytes,string,address,string,uint64))"));
});

test("EVM client wraps prepared relay withdraw payloads into withdraw transactions", async () => {
  const client = createClairveilEvmClient({
    shieldedPrefix: "demos",
    accountPrefix: "demo",
    chainId: "demo-1",
    defaultDenom: "udemo"
  });
  const payload = {
    proof_hex: "01",
    root_hex: "08".repeat(32),
    nullifier_hex: "09".repeat(32),
    amount: "1udemo",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chain_id: "demo-1",
    version: "v1",
    expires_at_unix: 4102448400
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);

  const withdraw = await client.buildWithdrawTransaction({ payload });

  assert.equal(withdraw.payload, payload);
  assert.equal(withdraw.message.recipient, payload.recipient);
  assert.equal(withdraw.transaction.to, evmPrivacyPrecompileAddress);
  assert.equal(withdraw.transaction.data.slice(2, 10), functionSelector("withdraw((bytes,bytes,bytes,bytes,bytes,string,address,string,uint64))"));
});

test("EVM client requires an expected chain id for relay withdraw payload transactions", async () => {
  const client = createClairveilEvmClient({
    shieldedPrefix: "demos",
    accountPrefix: "demo",
    defaultDenom: "udemo"
  });
  const payload = {
    proof_hex: "01",
    root_hex: "08".repeat(32),
    nullifier_hex: "09".repeat(32),
    amount: "1udemo",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chain_id: "demo-1",
    version: "v1",
    expires_at_unix: 4102448400
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);

  await assert.rejects(
    () => client.buildWithdrawTransaction({ payload }),
    /expectedChainId is required for relay withdraw payload validation/
  );

  const withdraw = await client.buildWithdrawTransaction({
    payload,
    expectedChainId: "demo-1"
  });
  assert.equal(withdraw.message.chainId, "demo-1");
});

test("EVM withdraw transaction rejects payload and evmRecipient mismatches", async () => {
  const client = createClairveilEvmClient({
    shieldedPrefix: "demos",
    accountPrefix: "demo",
    chainId: "demo-1",
    defaultDenom: "udemo"
  });
  const payload = {
    proof_hex: "01",
    root_hex: "08".repeat(32),
    nullifier_hex: "09".repeat(32),
    amount: "1udemo",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chain_id: "demo-1",
    version: "v1",
    expires_at_unix: 4102448400
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);

  await assert.rejects(
    () => client.buildWithdrawTransaction({
      payload,
      evmRecipient: "0x2222222222222222222222222222222222222222"
    }),
    /evmRecipient does not match message recipient/
  );
});

test("EVM withdraw transaction validates relay payload chain id and message recipient aliases", async () => {
  const client = createClairveilEvmClient({
    shieldedPrefix: "demos",
    accountPrefix: "demo",
    chainId: "demo-1",
    defaultDenom: "udemo"
  });
  const payload = {
    proof_hex: "01",
    root_hex: "08".repeat(32),
    nullifier_hex: "09".repeat(32),
    amount: "1udemo",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chain_id: "other-chain",
    version: "v1",
    expires_at_unix: 4102448400
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);

  await assert.rejects(
    () => client.buildWithdrawTransaction({ payload }),
    /withdraw payload chain_id mismatch/
  );

  await assert.rejects(
    () => client.buildWithdrawTransaction({
      message: {
        creator: "demo1example",
        proof: new Uint8Array([1]),
        root: new Uint8Array(32),
        nullifier: new Uint8Array(32),
        amount: "1udemo",
        recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
        recipientAddress: "0x2222222222222222222222222222222222222222",
        chainId: "demo-1",
        expiresAtUnix: 4102448400n
      }
    }),
    /evmRecipient does not match message recipient/
  );
});

test("browser-dapp prepareRelayWithdraw returns an EVM transaction for EVM profiles", async () => {
  const client = createClairveilBrowserDappClient({
    profile: {
      transport: "evm",
      chainId: "demo-1",
      accountPrefix: "demo",
      shieldedPrefix: "demos",
      denom: "udemo",
      rpc: "http://127.0.0.1:26657",
      rest: "http://127.0.0.1:1317",
      evmRpc: "http://127.0.0.1:8545",
      evmChainId: "0x539",
      evmPrivacyPrecompileAddress: evmPrivacyPrecompileAddress
    },
    proverUrl: "http://127.0.0.1:8080"
  });
  client.privacyMaterial = () => ({
    rootSeed: new Uint8Array(32),
    address: "demo1example",
    pubKeyHex: "02".padEnd(66, "0"),
    shieldedAddress: "demos1example"
  });
  let captured = null;
  client.cosmos.prepareRelayWithdraw = async input => {
    captured = input;
    const payload = {
      proof_hex: "01",
      root_hex: "08".repeat(32),
      nullifier_hex: "09".repeat(32),
      amount: input.amount,
      recipient: input.recipient,
      chain_id: "demo-1",
      version: "v1",
      expires_at_unix: 4102448400
    };
    payload.payload_hash = computePreparedWithdrawPayloadHash(payload);
    return {
      status: "ready",
      plan: { status: "final_withdraw_ready", canBuildTx: true },
      payload,
      proof: { version: "v1", payload_hash: payload.payload_hash, proof_hex: "01" },
      proverPayload: { payload_hash: payload.payload_hash },
      selectedNote: { nullifier: "09".repeat(32) },
      privacyAccount: { shielded_address: "demos1example" }
    };
  };

  const prepared = await client.prepareRelayWithdraw({
    walletType: "evm",
    address: "demo1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1udemo",
    recipient: "0x1111111111111111111111111111111111111111"
  });

  assert.equal(captured.recipient, evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"));
  assert.equal(prepared.payload, prepared.prepared.payload);
  assert.equal(prepared.prepared.evmRecipient, "0x1111111111111111111111111111111111111111");
  assert.equal(prepared.transaction.chainId, "0x539");
  assert.equal(prepared.transaction.to, evmPrivacyPrecompileAddress);
  assert.equal(prepared.transaction.data.slice(2, 10), functionSelector("withdraw((bytes,bytes,bytes,bytes,bytes,string,address,string,uint64))"));
});

test("EVM address helpers round-trip through custom bech32 accounts", () => {
  const address = "0x1111111111111111111111111111111111111111";
  const bech32 = evmAddressToBech32(address, "demo");

  assert.match(bech32, /^demo1/);
  assert.equal(bech32AddressToEvm(bech32, "demo"), address);
});

test("EVM privacy precompile encoders use tuple selectors", () => {
  const deposit = encodeEvmPrivacyDeposit({
    amount: "1aokrw",
    noteCommitment: new Uint8Array(32).fill(1),
    encryptedNote: new Uint8Array([2, 3])
  });
  const transferMessage = {
    proof: new Uint8Array([1, 2, 3]),
    root: new Uint8Array(32).fill(1),
    nullifiers: [new Uint8Array(32).fill(2), new Uint8Array(32).fill(3)],
    newCommitments: [new Uint8Array(32).fill(4), new Uint8Array(32).fill(5)],
    cipherTexts: [new Uint8Array([6]), new Uint8Array([7])],
    userPrivacyPolicy: 0,
    userDisclosureMode: 0,
    auditDisclosureDigest: new Uint8Array(32).fill(8),
    auditDisclosureTargetPubkey: new Uint8Array(32).fill(9),
    auditDisclosurePayload: new Uint8Array([10])
  };
  const transfer = encodeEvmPrivacyTransfer(transferMessage);
  assert.throws(
    () => encodeEvmPrivacyTransfer({
      ...transferMessage,
      selfViewDisclosureDigest: new Uint8Array(32).fill(11)
    }),
    /does not support self-view disclosure/
  );
  const withdraw = encodeEvmPrivacyWithdraw({
    proof: new Uint8Array([1, 2, 3]),
    root: new Uint8Array(32).fill(1),
    nullifier: new Uint8Array(32).fill(2),
    amount: "1aokrw",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chainId: "evm-privacy-local-1",
    expiresAtUnix: 1234
  }, { accountPrefix: "demo" });

  assert.equal(deposit.slice(2, 10), functionSelector("deposit((string,bytes,bytes))"));
  assert.equal(transfer.slice(2, 10), functionSelector("transfer((bytes,bytes,bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes))"));
  assert.equal(withdraw.slice(2, 10), functionSelector("withdraw((bytes,bytes,bytes,bytes,bytes,string,address,string,uint64))"));
});

test("EVM reference deposit encoder matches the proofless precompile signature", () => {
  const encoded = encodeReferenceEvmDeposit({
    amount: "1aokrw",
    noteCommitment: new Uint8Array(32).fill(1),
    encryptedNote: new Uint8Array([2, 3])
  });
  assert.equal(encoded.slice(2, 10), functionSelector("deposit(uint256,bytes32,bytes)"));
});

test("EVM reference withdraw encoder compares evmRecipient with bech32 recipient", () => {
  const encoded = encodeReferenceEvmWithdraw({
    proof: new Uint8Array([1, 2, 3]),
    root: new Uint8Array(32).fill(1),
    nullifier: new Uint8Array(32).fill(2),
    amount: "1aokrw",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    evmRecipient: "0x1111111111111111111111111111111111111111",
    expiresAtUnix: 1234
  });
  assert.equal(encoded.slice(2, 10), functionSelector("withdraw(bytes,bytes32,bytes32,uint256,address,string,uint64)"));

  assert.throws(
    () => encodeReferenceEvmWithdraw({
      proof: new Uint8Array([1, 2, 3]),
      root: new Uint8Array(32).fill(1),
      nullifier: new Uint8Array(32).fill(2),
      amount: "1aokrw",
      recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
      evmRecipient: "0x2222222222222222222222222222222222222222",
      expiresAtUnix: 1234
    }),
    /evmRecipient does not match message recipient/
  );
});

test("ABI encoder uses Solidity offsets for bytes arrays inside tuples", () => {
  const encoded = encodeFunctionData(
    "f((bytes[],bytes))",
    [{
      type: "tuple",
      components: [
        { name: "a", type: "bytes[]" },
        { name: "b", type: "bytes" }
      ]
    }],
    [{
      a: [new Uint8Array([1, 2]), new Uint8Array([3])],
      b: new Uint8Array([4, 5, 6])
    }]
  );
  const word = index => encoded.slice(10 + (index * 64), 10 + ((index + 1) * 64));

  assert.equal(word(0), "20".padStart(64, "0"));
  assert.equal(word(1), "40".padStart(64, "0"));
  assert.equal(word(2), "120".padStart(64, "0"));
  assert.equal(word(3), "2".padStart(64, "0"));
  assert.equal(word(4), "40".padStart(64, "0"));
  assert.equal(word(5), "80".padStart(64, "0"));
});

test("Cosmos client disclosure decode can skip signer pubkey checks for EVM identity material", async () => {
  const client = createClairveilClient({
    rest: "http://127.0.0.1:1",
    rpc: "http://127.0.0.1:2",
    chainId: "evm-test",
    accountPrefix: "demo"
  });
  client.findPrivacyEventByTxHash = async txHash => ({
    event_type: "shielded_transfer",
    tx_hash_hex: txHash,
    attributes: [
      { key: "user_disclosure_mode", value: userDisclosureModeRecipientEncrypted },
      { key: "user_disclosure_target_pubkey", value: "ab".repeat(32) }
    ]
  });
  const input = {
    txHash: "aa",
    address: "demo1rcrtmxgycp0vgukkvkm7v49kyed6grpn4w49lx",
    pubKeyHex: "11".repeat(20),
    signatureBase64: "AQID"
  };

  await assert.rejects(
    () => client.decodeUserDisclosure(input),
    /signer address\/pubKey mismatch/
  );
  await assert.rejects(
    () => client.decodeUserDisclosure({ ...input, skipSignerPubKeyCheck: true }),
    /selected transfer has no user disclosure/
  );
});
