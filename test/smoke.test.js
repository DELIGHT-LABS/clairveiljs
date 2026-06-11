import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  derivePrivacyMaterial,
  decodeShieldedAddress,
  buildWithdrawMsgFromPayload,
  computePreparedWithdrawPayloadHash,
  hashStringToField
} from "clairveiljs/core";
import {
  createClairveilClient,
  MemoryNoteStore,
  MsgWithdraw,
  nextPrivacyScanOptions,
  userDisclosureModeRecipientEncrypted
} from "clairveiljs/cosmos";
import { conformanceFixtureRelativePath } from "clairveiljs/conformance";
import {
  bech32AddressToEvm,
  createClairveilEvmClient,
  createEip1193WalletAdapter,
  encodeFunctionData,
  evmAddressToBech32,
  functionSelector,
  encodeEvmPrivacyTransfer,
  encodeEvmPrivacyWithdraw,
  evmPrivacyPrecompileAddress
} from "clairveiljs/evm";
import { createClairveilPublicClient } from "clairveiljs/browser-public";
import { createClairveilBrowserDappClient } from "clairveiljs/browser-dapp";

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
  assert.equal(typeof client.scanWalletNotes, "function");
  assert.equal(typeof client.checkNullifier, "function");
  assert.equal(typeof browserDapp.ClairveilBrowserDappClient, "function");
});

test("browser-dapp EVM native send requires a 0x recipient", () => {
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

  assert.equal(typeof tx.MsgDeposit.encode, "function");
  assert.equal(typeof tx.MsgTransfer.decode, "function");
  assert.equal(tx.MsgWithdraw.typeUrl, "/clairveil.privacy.v1.MsgWithdraw");
  assert.equal(typeof txWithExtension.MsgDeposit.encode, "function");
  assert.equal(txWithExtension.MsgWithdraw.typeUrl, "/clairveil.privacy.v1.MsgWithdraw");
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
  const wallet = createEip1193WalletAdapter({ provider });
  const txHash = await client.sendTransaction(wallet, prepared.transaction);

  assert.equal(prepared.material.amount, "3udemo");
  assert.equal(prepared.transaction.to, evmPrivacyPrecompileAddress);
  assert.equal(prepared.transaction.data.slice(2, 10), functionSelector("deposit((string,bytes,bytes))"));
  assert.equal(txHash, "0x" + "cd".repeat(32));
  assert.equal(sent[0].from, "0x1111111111111111111111111111111111111111");
});

test("EVM address helpers round-trip through custom bech32 accounts", () => {
  const address = "0x1111111111111111111111111111111111111111";
  const bech32 = evmAddressToBech32(address, "demo");

  assert.match(bech32, /^demo1/);
  assert.equal(bech32AddressToEvm(bech32, "demo"), address);
});

test("EVM privacy precompile encoders use tuple selectors", () => {
  const transfer = encodeEvmPrivacyTransfer({
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
  });
  const withdraw = encodeEvmPrivacyWithdraw({
    proof: new Uint8Array([1, 2, 3]),
    root: new Uint8Array(32).fill(1),
    nullifier: new Uint8Array(32).fill(2),
    amount: "1aokrw",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chainId: "evm-privacy-local-1",
    expiresAtUnix: 1234
  }, { accountPrefix: "demo" });

  assert.equal(transfer.slice(2, 10), functionSelector("transfer((bytes,bytes,bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes))"));
  assert.equal(withdraw.slice(2, 10), functionSelector("withdraw((bytes,bytes,bytes,bytes,bytes,string,address,string,uint64))"));
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
