import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { toBech32 } from "@cosmjs/encoding";
import { BroadcastTxError } from "@cosmjs/stargate";
import {
  createNoteReservationManager as createRootNoteReservationManager
} from "clairveiljs";
import {
  assertPreparedTransferPayloadShape,
  buildPreparedTransferPayload,
  buildPreparedWithdrawProverPayload,
  buildDepositMaterial,
  buildRelayWithdrawPayload,
  buildRelayWithdrawMsgFromPayload,
  buildWithdrawMsgFromPayload,
  canonicalFieldBytes,
  computeNoteCommitmentV1,
  computeNoteTreeNodeV1,
  computePreparedWithdrawPayloadHash,
  createNote,
  createSpendNoteHashSigner,
  CURVE_BASE,
  CURVE_IDENTITY,
  decodeShieldedAddress,
  encodeShieldedAddress,
  derivePrivacyMaterial,
  deriveSpendKeys,
  deriveViewTag,
  deriveViewKeys,
  encryptDepositNoteV1,
  encryptNoteForTransferV1,
  encryptedEnvelopeKindV1,
  fieldHexV1,
  hashStringToField,
  hexFromBytes,
  isVerifiedUnspentFoundNote,
  normalizeFoundNote,
  packPoint,
  ClairveilErrorCode,
  plannerStatusToErrorCode,
  unpackPoint,
  validatePreparedTransferPayloadMetadata,
  wrapEncryptedEnvelopeV1,
  activeCircuitSetIdV1,
  privacyFixedV1
} from "clairveiljs/core";
import {
  createClairveilClient,
  createClairveilRegistry,
  cosmosSignDocBindingHash,
  MemoryNoteStore,
  MsgBatchTransfer,
  MsgDeposit,
  MsgTransfer,
  MsgWithdraw,
  nextPrivacyScanOptions,
  normalizeFoundNotes,
  parseNoteBytes,
  scanNotes,
  userDisclosureModeRecipientEncrypted
} from "clairveiljs/cosmos";
import { conformanceFixtureRelativePath } from "clairveiljs/conformance";
import { computeAssetIdV1 } from "clairveiljs/protocol-v1";
import {
  bech32AddressToEvm,
  createClairveilEvmClient,
  createEip1193WalletAdapter,
  encodeEvmPrivacyDeposit,
  encodeFunctionData,
  evmTransactionBindingHash,
  evmAddressToBech32,
  functionSelector,
  encodeEvmPrivacyTransfer,
  encodeEvmPrivacyWithdraw,
  markEvmTransactionReservationRequired
} from "clairveiljs/evm";
import {
  createKeplrWalletAdapter,
  createWalletAdapter
} from "clairveiljs/wallet-adapter";
import { createClairveilPublicClient } from "clairveiljs/browser-public";
import { createClairveilBrowserDappClient } from "clairveiljs/browser-dapp";
import {
  planTransferBatchNotes,
  planTransferNotes,
  planWithdrawNotes
} from "clairveiljs/planner";
import {
  createRestMerklePathProvider,
  summarizeSpendableNotesByDenom
} from "clairveiljs/payload";
import {
  deserializeFoundNote,
  privacyNoteCacheStateVersionV1,
  serializeFoundNote
} from "../src/privacy/note-store.js";
import {
  createNoteReservationManager,
  hashAmount,
  hashTransparentRecipient,
  MemoryReservationStore,
  operationStatuses,
  reservationStatuses
} from "clairveiljs/reservation";

const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const testPrivacyContractAddress = "0x0000000000000000000000000000000000000900";
const validV2ProofHex = `${"c0"}${"00".repeat(31)}${"c0"}${"00".repeat(63)}${"c0"}${"00".repeat(35)}${"c0"}${"00".repeat(31)}`;
const validClairsRecipient = encodeShieldedAddress(CURVE_BASE, CURVE_BASE, {
  shieldedPrefix: "clairs"
});

function signedTxFixture(signatureBytes = []) {
  return {
    bodyBytes: "",
    authInfoBytes: "",
    signature: Buffer.from(signatureBytes).toString("base64")
  };
}

function signedTxFixture(signatureBytes = []) {
  return {
    bodyBytes: "",
    authInfoBytes: "",
    signature: Buffer.from(signatureBytes).toString("base64")
  };
}

function cosmosTestClient(overrides = {}) {
  return createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    ...overrides
  });
}

function signedTxIdentity(client, signedTx) {
  const txRawBytes = client.buildTxRawBytes(signedTx);
  const txBytesHash = createHash("sha256").update(txRawBytes).digest("hex");
  return { txRawBytes, txBytesHash, txHash: txBytesHash.toUpperCase() };
}

function signedMessageTx(client, typeUrl, value, { memo = "", signature = "" } = {}) {
  return {
    bodyBytes: Buffer.from(client.registry.encodeTxBody({
      messages: [{ typeUrl, value }],
      memo
    })).toString("base64"),
    authInfoBytes: "",
    signature
  };
}

async function assertProofReadyNotAttempted(store, reservation) {
  const stored = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(stored.status, reservationStatuses.ProofReady);
  assert.equal(stored.broadcast_attempt_count, 0);
  assert.equal(stored.broadcast_in_flight, false);
  return stored;
}

function browserEvmProfile(overrides = {}) {
  return {
    id: "clairveil-evm-test",
    label: "Clairveil EVM Test",
    chainName: "Clairveil EVM Test",
    transport: "evm",
    wallet: "metamask",
    chainId: "demo-1",
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    proverUrl: "http://127.0.0.1:8080",
    accountPrefix: "demo",
    shieldedPrefix: "demos",
    denom: "udemo",
    displayDenom: "DEMO",
    coinDecimals: 6,
    evmRpc: "http://127.0.0.1:8545",
    evmChainId: "0x539",
    evmChainName: "Clairveil EVM Test",
    evmPrivacyPrecompileAddress: testPrivacyContractAddress,
    evmDepositMode: "payable-exact-value",
    evmNativeDenom: "udemo",
    evmAuthorizationProfile: {
      typedDataDomain: { name: "Test EVM Privacy", version: "1" },
      supportedAuthorizationKinds: [1, 2, 3]
    },
    evmGasLimit: "0x989680",
    evmSendGasLimit: "0x5208",
    ...overrides
  };
}

function browserCosmosProfile(overrides = {}) {
  return {
    id: "clairveil-cosmos-test",
    label: "Clairveil Cosmos Test",
    chainName: "Clairveil Cosmos Test",
    transport: "cosmos",
    wallet: "keplr",
    chainId: "profile-chain",
    rpc: "http://profile-rpc.local",
    rest: "http://profile-rest.local",
    proverUrl: "http://profile-prover.local",
    accountPrefix: "profile",
    shieldedPrefix: "profiles",
    denom: "uprofile",
    displayDenom: "PROFILE",
    coinDecimals: 6,
    keplrCoinType: 118,
    gasPriceStep: { low: 0.01, average: 0.025, high: 0.04 },
    keplrChainInfo: {
      chainId: "profile-chain",
      chainName: "Clairveil Cosmos Test",
      rpc: "http://profile-rpc.local",
      rest: "http://profile-rest.local",
      bip44: { coinType: 118 },
      bech32Config: {
        bech32PrefixAccAddr: "profile",
        bech32PrefixAccPub: "profilepub",
        bech32PrefixValAddr: "profilevaloper",
        bech32PrefixValPub: "profilevaloperpub",
        bech32PrefixConsAddr: "profilevalcons",
        bech32PrefixConsPub: "profilevalconspub"
      },
      currencies: [{ coinDenom: "PROFILE", coinMinimalDenom: "uprofile", coinDecimals: 6 }],
      feeCurrencies: [{
        coinDenom: "PROFILE",
        coinMinimalDenom: "uprofile",
        coinDecimals: 6,
        gasPriceStep: { low: 0.01, average: 0.025, high: 0.04 }
      }],
      stakeCurrency: { coinDenom: "PROFILE", coinMinimalDenom: "uprofile", coinDecimals: 6 },
      features: []
    },
    ...overrides
  };
}

function transferProtocolConfig({ policies = ["all-private"], modes = ["none"] } = {}) {
  return {
    audit_config: {
      audit_key_id: "audit-key-1",
      audit_key_epoch: 1,
      audit_master_pubkey_hex: Buffer.from(packPoint(CURVE_BASE)).toString("hex")
    },
    circuit_config: {
      circuit_set_identity: {
        schema_version: "v1",
        circuit_set_id: "privacy-note-v1",
        curve: "BN254",
        circuits: [
          {
            circuit_id: "deposit",
            verifying_key_sha256: "5bd1bb4e4240db8b277095791528f0473dd5f44317ddf6b2f8d479afa677e19a",
            public_input_schema_sha256: "c3231fb5ae62539d2e4baeb78aa4be8a4c44e3cd8fa325ba60f13b7f563d5a1e"
          },
          {
            circuit_id: "spend",
            verifying_key_sha256: "e223a161d451f328efee501d9f7ec699b4a7805828cd2ca5ea58e168b6598a6e",
            public_input_schema_sha256: "d0a033aa2f7b6e098873307a815545ee3e83d974026c0e52bf39a038e08f4872"
          },
          {
            circuit_id: "joinsplit",
            verifying_key_sha256: "6bd0a17db07f099d4ec1271d4c8d02f6729d5c365cb113a119a972ad31090d85",
            public_input_schema_sha256: "4946e23db34529c6fce0a95ce69f6df08563a305ddcc70c7b6b786471e03aa82"
          },
          {
            circuit_id: "batch-joinsplit-16x32-v1",
            verifying_key_sha256: "f31844fcc7349bfdd68babe8f00638179ee7f608e0060baee8b8f4c443f186ee",
            public_input_schema_sha256: "5606327d69dcb06c00811f2135291d39a2ea1cedf554f114f7eb4a178098d333"
          }
        ]
      }
    },
    disclosure_config: {
      supported_user_policies: policies,
      supported_user_modes: modes
    }
  };
}

function validBatchTransferMessage(creator = "clair1batch") {
  const note = createNote({
    spendPubKey: CURVE_BASE,
    viewPubKey: CURVE_BASE,
    amount: 1n,
    assetDenom: "uclair",
    randomness: 19n,
    memo: "batch-sign-doc"
  });
  const commitment = canonicalFieldBytes(computeNoteCommitmentV1(note));
  const encrypted = encryptNoteForTransferV1(note, commitment, 0);
  return {
    creator,
    proof: new Uint8Array(164).fill(7),
    root: canonicalFieldBytes(1n),
    nullifiers: [canonicalFieldBytes(2n)],
    outputs: [{
      commitment,
      ciphertext: encrypted.ciphertext,
      viewTag: encrypted.viewTag,
      userPrivacyPolicy: 0,
      userDisclosureMode: 0,
      userDisclosureDigest: new Uint8Array(),
      userDisclosureTargetPubkey: new Uint8Array(),
      userDisclosurePayload: new Uint8Array(),
      fullDisclosureDigest: canonicalFieldBytes(4n),
      auditDisclosurePayload: wrapEncryptedEnvelopeV1(
        encryptedEnvelopeKindV1.auditDisclosure,
        new Uint8Array(452)
      ),
      selfViewDisclosurePayload: new Uint8Array()
    }],
    auditKeyId: "audit-key-1",
    auditKeyEpoch: 1n,
    auditDisclosureTargetPubkey: packPoint(CURVE_BASE),
    expiresAtUnix: 4_102_448_400n
  };
}

function signedBatchTransferTx(client, message, memo = "") {
  return {
    bodyBytes: Buffer.from(client.registry.encodeTxBody({
      messages: [{ typeUrl: MsgBatchTransfer.typeUrl, value: message }],
      memo
    })).toString("base64"),
    authInfoBytes: "",
    signature: ""
  };
}

function strictMerklePathProvider(notes) {
  const commitments = notes.map(note => computeNoteCommitmentV1(note));
  const capacity = 1 << Math.ceil(Math.log2(Math.max(commitments.length, 2)));
  const leaves = [...commitments];
  while (leaves.length < capacity) leaves.push(BigInt(leaves.length + 1));
  const paths = commitments.map(() => []);
  const helpers = commitments.map(() => []);
  let nodes = leaves;

  for (let level = 0; nodes.length > 1; level += 1) {
    for (let index = 0; index < commitments.length; index += 1) {
      const nodeIndex = index >> level;
      paths[index].push(fieldHexV1(nodes[nodeIndex ^ 1]));
      helpers[index].push(nodeIndex & 1);
    }
    const next = [];
    for (let index = 0; index < nodes.length; index += 2) {
      next.push(computeNoteTreeNodeV1(level, nodes[index], nodes[index + 1]));
    }
    nodes = next;
  }

  let root = nodes[0];
  for (let level = Math.log2(capacity); level < 32; level += 1) {
    const sibling = BigInt(level + 1);
    for (let index = 0; index < commitments.length; index += 1) {
      paths[index].push(fieldHexV1(sibling));
      helpers[index].push(0);
    }
    root = computeNoteTreeNodeV1(level, root, sibling);
  }

  const byCommitment = new Map(commitments.map((commitment, index) => [fieldHexV1(commitment), {
    root: fieldHexV1(root),
    path: paths[index],
    path_helper: helpers[index]
  }]));
  return {
    async lookupMerklePath(commitmentHex) {
      const result = byCommitment.get(String(commitmentHex).toLowerCase());
      if (!result) throw new Error("unexpected commitment requested from strict merkle path provider");
      return result;
    }
  };
}

function broadcastReservationNote(suffix) {
  return {
    note: {
      receiverSpendPubKeyX: 1n,
      receiverSpendPubKeyY: 2n,
      receiverViewPubKeyX: 3n,
      receiverViewPubKeyY: 4n,
      amount: 5n,
      assetID: 7n,
      randomness: 8n,
      memo: ""
    },
    nullifier: suffix.padStart(2, "0").repeat(32),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: "ABCD",
    height: 10,
    sequence: Number.parseInt(suffix, 16) || 1
  };
}

async function readyBroadcastReservation(suffix = "01", options = {}) {
  const store = new MemoryReservationStore({ now: options.now });
  const reservationManager = createNoteReservationManager({
    store,
    ownerKeyId: `chain:clair1broadcast${suffix}`,
    indexKey: `broadcast-index-${suffix}`,
    ...(options.leaseDurationMs != null ? { leaseDurationMs: options.leaseDurationMs } : {}),
    ...(options.now ? { now: options.now } : {})
  });
  const notes = options.notes || [broadcastReservationNote(suffix)];
  const reservation = await reservationManager.reserveNotes({ notes, kind: "transfer" });
  await reservationManager.markProving(reservation.reservation_ids, {
    leaseToken: reservation.lease_token
  });
  const proofReady = options.proofReady || {};
  const ready = await reservationManager.markProofReady(reservation.reservation_ids, {
    leaseToken: reservation.lease_token,
    payloadHash: options.payloadHash ?? `payload-${suffix}`,
    signDocHash: options.signDocHash ?? "",
    txBytesHash: options.txBytesHash ?? "",
    ...proofReady,
    metadata: {
      ...(proofReady.metadata || {}),
      ...(options.metadata || {})
    }
  });
  reservation.reservations = ready;
  reservation.lease_until = ready[0].lease_until;
  return { store, reservationManager, reservation, note: notes[0], notes };
}

test("core/cosmos/evm entrypoints load", () => {
  assert.equal(typeof derivePrivacyMaterial, "function");
  assert.equal(typeof createClairveilClient, "function");
  assert.equal(typeof createClairveilPublicClient, "function");
  assert.equal(typeof createClairveilBrowserDappClient, "function");
  assert.equal(typeof createClairveilEvmClient, "function");
  assert.equal(typeof createNoteReservationManager, "function");
  assert.equal(typeof createRootNoteReservationManager, "function");
  assert.equal(functionSelector("deposit((bytes,bytes,bytes))").length, 8);
  assert.equal(testPrivacyContractAddress, "0x0000000000000000000000000000000000000900");
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
  assert.equal(typeof client.prepareTransferBatch, "function");
  assert.equal(typeof client.prepareWithdraw, "function");
  assert.equal(typeof client.prepareRelayWithdraw, "function");
  assert.equal(typeof client.createRelayWithdrawSignDoc, "function");
  assert.equal(typeof client.scanWalletNotes, "function");
  assert.equal(typeof client.fetchReserve, "function");
  assert.equal(typeof client.checkNullifier, "function");
  assert.equal(typeof client.evmJsonRpc, "function");
  assert.equal(typeof client.assertCircuitConfig, "function");
  assert.equal(typeof client.assertTransferProtocolConfig, "function");
  assert.equal(typeof client.queryAssetByDenom, "function");
  assert.equal(typeof client.fetchAssetByID, "function");
  assert.equal(typeof client.queryAssetByID, "function");
  assert.equal(typeof client.resolveAssetByID, "function");
  assert.equal(typeof client.fetchTreeState, "function");
  assert.equal(typeof client.fetchCommitmentInfo, "function");
  assert.equal(typeof client.lookupMerklePath, "function");
  assert.equal(typeof client.fetchCommitmentPathsAtRoot, "function");
  assert.equal(typeof client.queryCommitmentPathsAtRoot, "function");
  assert.equal(typeof client.createCommitmentPathSnapshotProvider, "function");
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
    profile: browserEvmProfile({ chainId: "evm-local-1", evmChainId: "0x32f" })
  });
  client.evmJsonRpc = async () => "0x32f";
  client.cosmos.assertProtocolPreflight = async () => ({});

  const prepared = await client.prepareDeposit({
    address: "0x1111111111111111111111111111111111111111",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: Buffer.from("profile-transport-evm").toString("base64"),
    amount: "3udemo",
    proofHex: "ab",
    evmWallet: { getChainId: async () => "0x32f" }
  });

  assert.equal(prepared.signDoc, undefined);
  assert.equal(prepared.transaction.chainId, "0x32f");
  assert.equal(prepared.transaction.to, testPrivacyContractAddress);
  assert.equal(prepared.prepared.amount, "3udemo");
});

test("browser-dapp profile is the sole source for transport endpoints and wallet type", async () => {
  const client = createClairveilBrowserDappClient({
    profile: browserCosmosProfile(),
    rpc: "http://override-rpc.local",
    rest: "http://override-rest.local",
    chainId: "override-chain",
    denom: "uoverride",
    proverUrl: "http://override-prover.local",
    evmRpc: "http://override-evm.local",
    evmChainId: "0x1"
  });

  assert.equal(client.rpc, "http://profile-rpc.local");
  assert.equal(client.rest, "http://profile-rest.local");
  assert.equal(client.chainId, "profile-chain");
  assert.equal(client.denom, "uprofile");
  assert.equal(client.proverUrl, "http://profile-prover.local");
  assert.equal(client.evmRpc, "");
  await assert.rejects(
    () => client.prepareTransferBatch({ walletType: "evm" }),
    /does not match active profile transport cosmos/
  );
});

test("browser-dapp EVM profiles reject a configured RPC on another network", async () => {
  const client = createClairveilBrowserDappClient({
    profile: browserEvmProfile({
      rpc: "http://profile-rpc.local",
      rest: "http://profile-rest.local",
      chainId: "profile-chain",
      evmRpc: "http://profile-evm.local"
    })
  });
  client.evmJsonRpc = async () => "0x1";
  await assert.rejects(
    () => client.assertEvmNetwork(),
    /EVM RPC chain ID 0x1 does not match configured evmChainId 0x539/
  );
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

test("view tag derivation matches the Go reference vector", () => {
  const commitmentHex = "03".repeat(32);
  const commitmentBytes = Uint8Array.from({ length: 32 }, () => 0x03);

  assert.equal(hexFromBytes(deriveViewTag(CURVE_BASE, commitmentHex, 1)), "0d26");
  assert.equal(hexFromBytes(deriveViewTag(CURVE_BASE, commitmentBytes, 1)), "0d26");
});

test("public note decoding rejects the removed legacy JSON plaintext format", () => {
  const legacyJson = Buffer.from(JSON.stringify({
    receiver_spend_pubkey_x: "1",
    receiver_spend_pubkey_y: "2",
    receiver_view_pubkey_x: "3",
    receiver_view_pubkey_y: "4",
    amount: "5",
    asset_id: "6",
    randomness: "7",
    memo: "legacy"
  }));

  assert.throws(() => parseNoteBytes(legacyJson), /NoteV1|plaintext|length|version/i);
});

test("scan projection events decrypt notes and use batch nullifier status", async () => {
  const rootSeed = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const material = buildDepositMaterial({
    creator: "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48",
    rootSeed,
    amount: "5uclair"
  });

  const result = await scanNotes({
    rootSeed,
    events: [{
      event_type: "deposit",
      height: 12,
      sequence: 7,
      tx_hash_hex: "AABB",
      outputs: [{
        output_index: 0,
        commitment_hex: material.note_commitment_hex,
        encrypted_note_hex: material.encrypted_note_hex
      }]
    }],
    checkNullifiers: async nullifiers => new Map(nullifiers.map(value => [value, true])),
    includeFoundNotes: true
  });

  assert.equal(result.summary.total_count, 1);
  assert.equal(result.summary.spent_count, 1);
  assert.equal(result.notes[0].sequence, 7);
  assert.equal(result.foundNotes[0].height, 12);
  assert.equal(result.foundNotes[0].sequence, 7);
});

test("found-note event coordinates preserve uint64 precision through scan and storage", async () => {
  const rootSeed = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const material = buildDepositMaterial({
    creator: "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48",
    rootSeed,
    amount: "5uclair"
  });
  const height = "9007199254740993";
  const sequence = "9007199254740995";
  const result = await scanNotes({
    rootSeed,
    events: [{
      event_type: "deposit",
      height,
      sequence,
      tx_hash_hex: "AACC",
      outputs: [{
        output_index: 0,
        commitment_hex: material.note_commitment_hex,
        encrypted_note_hex: material.encrypted_note_hex
      }]
    }],
    checkNullifiers: async nullifiers => new Map(nullifiers.map(value => [value, false])),
    includeFoundNotes: true
  });

  assert.equal(result.notes[0].height, height);
  assert.equal(result.notes[0].sequence, sequence);
  assert.equal(result.foundNotes[0].height, height);
  assert.equal(result.foundNotes[0].sequence, sequence);
  const persisted = await new MemoryNoteStore().mergeScanResult(result);
  assert.equal(persisted.notes[0].height, height);
  assert.equal(persisted.notes[0].sequence, sequence);
  assert.equal(persisted.lastScannedHeight, height);
  assert.equal(persisted.lastScannedSequence, sequence);
});

test("scan falls back to individual nullifier checks when batch statuses are partial", async () => {
  const rootSeed = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const first = buildDepositMaterial({
    creator: "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48",
    rootSeed,
    amount: "5uclair"
  });
  const second = buildDepositMaterial({
    creator: "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48",
    rootSeed,
    amount: "6uclair"
  });
  const individuallyChecked = [];

  const result = await scanNotes({
    rootSeed,
    events: [
      {
        event_type: "deposit",
        height: 12,
        sequence: 7,
        tx_hash_hex: "AABB",
        outputs: [{
          output_index: 0,
          commitment_hex: first.note_commitment_hex,
          encrypted_note_hex: first.encrypted_note_hex
        }]
      },
      {
        event_type: "deposit",
        height: 12,
        sequence: 8,
        tx_hash_hex: "AABC",
        outputs: [{
          output_index: 0,
          commitment_hex: second.note_commitment_hex,
          encrypted_note_hex: second.encrypted_note_hex
        }]
      }
    ],
    checkNullifiers: async nullifiers => new Map([[nullifiers[0], false]]),
    checkNullifier: async nullifier => {
      individuallyChecked.push(nullifier);
      return { used: true };
    },
    includeFoundNotes: true
  });

  assert.equal(result.summary.total_count, 2);
  assert.equal(result.summary.spendable_count, 1);
  assert.equal(result.summary.spent_count, 1);
  assert.deepEqual(individuallyChecked, [result.foundNotes[1].nullifier]);
});

test("scan excludes notes when nullifier responses are unavailable or malformed", async () => {
  const rootSeed = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const material = buildDepositMaterial({
    creator: "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48",
    rootSeed,
    amount: "5uclair"
  });
  const result = await scanNotes({
    rootSeed,
    events: [{
      event_type: "deposit",
      height: 12,
      sequence: 7,
      tx_hash_hex: "AABB",
      outputs: [{
        output_index: 0,
        commitment_hex: material.note_commitment_hex,
        encrypted_note_hex: material.encrypted_note_hex
      }]
    }],
    checkNullifiers: async nullifiers => new Map([[nullifiers[0], {}]]),
    checkNullifier: async () => {
      return { used: "false" };
    },
    includeFoundNotes: true
  });

  assert.equal(result.notes[0].status, "unverified");
  assert.equal(result.foundNotes[0].nullifierStatus, "unknown");
  assert.equal(result.summary.spendable_count, 0);
  assert.equal(planTransferNotes({ notes: result.foundNotes, amount: "5uclair" }).canBuildTx, false);
});

test("scan rejects contradictory and duplicate nullifier status evidence", async () => {
  const rootSeed = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const material = buildDepositMaterial({
    creator: "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48",
    rootSeed,
    amount: "5uclair"
  });
  const event = {
    event_type: "deposit",
    height: 13,
    sequence: 8,
    tx_hash_hex: "AABD",
    outputs: [{
      output_index: 0,
      commitment_hex: material.note_commitment_hex,
      encrypted_note_hex: material.encrypted_note_hex
    }]
  };
  const contradictoryAliases = await scanNotes({
    rootSeed,
    events: [event],
    checkNullifiers: async nullifiers => ({
      statuses: [{ nullifier: nullifiers[0], used: false, Used: true }]
    }),
    includeFoundNotes: true
  });
  const duplicateRows = await scanNotes({
    rootSeed,
    events: [event],
    checkNullifiers: async nullifiers => ({
      statuses: [
        { nullifier: nullifiers[0], used: false },
        { nullifier: nullifiers[0], used: true }
      ]
    }),
    includeFoundNotes: true
  });

  assert.equal(contradictoryAliases.notes[0].status, "unverified");
  assert.equal(duplicateRows.notes[0].status, "unverified");
});

test("found notes without a nullifier check stay unverified", () => {
  const note = createNote({
    spendPubKey: CURVE_BASE,
    viewPubKey: CURVE_BASE,
    amount: 5n,
    assetDenom: "uclair",
    randomness: 42n
  });
  const unverified = normalizeFoundNote({ note, isSpent: false, height: 1, sequence: 1 });
  assert.equal(unverified.nullifierStatus, "unverified");
  assert.equal(isVerifiedUnspentFoundNote(unverified), false);

  const verified = normalizeFoundNote({
    ...unverified,
    nullifierStatus: "unspent"
  });
  assert.equal(isVerifiedUnspentFoundNote(verified), true);
});

test("found-note migration recognizes only literal spent evidence", () => {
  const note = createNote({
    spendPubKey: CURVE_BASE,
    viewPubKey: CURVE_BASE,
    amount: 5n,
    assetDenom: "uclair",
    randomness: 43n
  });
  const spentLegacy = normalizeFoundNote({
    note,
    spent: true,
    nullifier_status: "unspent"
  });
  assert.equal(spentLegacy.isSpent, true);
  assert.equal(spentLegacy.nullifierStatus, "spent");

  const stringFalse = normalizeFoundNote({
    note,
    spent: "false",
    nullifier_status: "unspent"
  });
  assert.equal(stringFalse.isSpent, false);
  assert.equal(isVerifiedUnspentFoundNote(stringFalse), true);

  const conflictingStatusAliases = normalizeFoundNote({
    note,
    nullifierStatus: "unspent",
    nullifier_status: "spent"
  });
  assert.equal(conflictingStatusAliases.isSpent, false);
  assert.equal(conflictingStatusAliases.nullifierStatus, "unverified");
  assert.equal(isVerifiedUnspentFoundNote(conflictingStatusAliases), false);

  const literalSpentWins = normalizeFoundNote({
    note,
    spent: true,
    nullifierStatus: "unspent",
    nullifier_status: "spent"
  });
  assert.equal(literalSpentWins.isSpent, true);
  assert.equal(literalSpentWins.nullifierStatus, "spent");
});

test("scan note normalization materializes the declared nullifier status", () => {
  const note = createNote({
    spendPubKey: CURVE_BASE,
    viewPubKey: CURVE_BASE,
    amount: 5n,
    assetDenom: "uclair",
    randomness: 45n
  });
  const unverified = normalizeFoundNotes([{ note, isSpent: false, height: 1, sequence: 1 }]);
  const spent = normalizeFoundNotes([{ note, spent: true, height: 1, sequence: 1 }]);
  assert.equal(unverified[0].nullifierStatus, "unverified");
  assert.equal(unverified[0].isSpent, false);
  assert.equal(spent[0].nullifierStatus, "spent");
  assert.equal(spent[0].isSpent, true);
});

test("shielded address subgroup validation stays within a browser-safe latency budget", () => {
  const material = derivePrivacyMaterial({
    address: "demo1performance",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: Buffer.from("subgroup-performance").toString("base64"),
    shieldedPrefix: "demos"
  });
  const startedAt = Date.now();
  for (let index = 0; index < 20; index += 1) {
    decodeShieldedAddress(material.shieldedAddress, { shieldedPrefix: "demos" });
  }
  assert.ok(Date.now() - startedAt < 2_500, "20 address decodes must complete in under 2.5 seconds");
});

test("generic point codec round-trips identity while shielded keys reject it", () => {
  assert.deepEqual(unpackPoint(packPoint(CURVE_IDENTITY)), CURVE_IDENTITY);

  const identityAddress = encodeShieldedAddress(CURVE_IDENTITY, CURVE_BASE, {
    shieldedPrefix: "demos"
  });
  assert.throws(
    () => decodeShieldedAddress(identityAddress, { shieldedPrefix: "demos" }),
    /point identity is not allowed/
  );
});

test("found-note persistence preserves only literal boolean spent evidence", () => {
  const note = createNote({
    spendPubKey: CURVE_BASE,
    viewPubKey: CURVE_BASE,
    amount: 5n,
    assetDenom: "uclair",
    randomness: 44n
  });
  const serialized = serializeFoundNote({
    note,
    nullifier: "44".repeat(32),
    nullifierStatus: "unspent"
  });
  for (const value of ["false", "true", 0, 1, undefined]) {
    const candidate = { ...serialized };
    if (value === undefined) delete candidate.spent;
    else candidate.spent = value;
    const restored = deserializeFoundNote(candidate);
    assert.equal(restored.spent, false);
    assert.equal(restored.isSpent, false);
  }
  const restoredSpent = deserializeFoundNote({ ...serialized, spent: true });
  assert.equal(restoredSpent.spent, true);
  assert.equal(restoredSpent.isSpent, true);
  assert.equal(restoredSpent.nullifierStatus, "spent");
});

test("note store clears pre-v0.2 cache state instead of migrating old notes or cursors", async () => {
  const note = createNote({
    spendPubKey: CURVE_BASE,
    viewPubKey: CURVE_BASE,
    amount: 5n,
    assetDenom: "uclair",
    randomness: 45n
  });
  const legacy = new MemoryNoteStore({
    owner: "clair1fresh-genesis",
    state: {
      version: "v1",
      owner: "clair1fresh-genesis",
      lastScannedHeight: 99,
      scanCursor: { source: "privacy_scan", next_cursor: { height: 99, global_sequence: 7, output_index: 3 } },
      notes: [serializeFoundNote({ note, nullifier: "45".repeat(32), height: 99 })]
    }
  });
  const cleared = await legacy.load();
  assert.equal(cleared.version, privacyNoteCacheStateVersionV1);
  assert.equal(cleared.circuit_set_id, "privacy-note-v1");
  assert.equal(cleared.payload_version, "privacy-fixed-v1");
  assert.deepEqual(cleared.notes, []);
  assert.equal(cleared.lastScannedHeight, 0);
  assert.equal(cleared.scanCursor, null);
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
  client.cosmos.assertProtocolPreflight = async () => ({});
  let providerCommitmentHex = "";
  let capturedMessage = null;
  let capturedGasLimit = 0;
  let capturedFeeAmount = [];
  client.cosmos.buildDirectSignDoc = async ({ messages, gasLimit, feeAmount }) => {
    capturedMessage = messages[0].value;
    capturedGasLimit = gasLimit;
    capturedFeeAmount = feeAmount;
    return { chainId: "clairveil-local-3", bodyBytes: "", authInfoBytes: "", accountNumber: "0" };
  };

  const prepared = await client.prepareDeposit({
    address: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: Buffer.from("deposit-proof-provider").toString("base64"),
    amount: "7uclair",
    gasLimit: 2800000,
    feeAmount: [{ denom: "uclair", amount: "19" }],
    depositProofProvider({ material }) {
      providerCommitmentHex = material.note_commitment_hex;
      return { proof_hex: "ab" };
    }
  });

  assert.equal(prepared.prepared.noteCommitmentHex, providerCommitmentHex);
  assert.equal(Buffer.from(capturedMessage.noteCommitment).toString("hex"), providerCommitmentHex);
  assert.deepEqual([...capturedMessage.proof], [0xab]);
  assert.equal(capturedGasLimit, 2800000);
  assert.deepEqual(capturedFeeAmount, [{ denom: "uclair", amount: "19" }]);
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

test("Keplr wallet adapter preserves the prepared fee and memo during direct signing", async () => {
  const calls = [];
  const address = "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2";
  const signDoc = {
    bodyBytes: new Uint8Array(),
    authInfoBytes: new Uint8Array(),
    chainId: "clairveil-local-3",
    accountNumber: 1n
  };
  const adapter = createKeplrWalletAdapter({
    chainId: "clairveil-local-3",
    address,
    keplr: {
      async enable() {},
      async getKey() {
        return {
          bech32Address: address,
          pubKey: new Uint8Array([2, ...new Uint8Array(32)])
        };
      },
      async signDirect(...input) {
        calls.push(input);
        return {
          signed: signDoc,
          signature: { signature: "AQ==" }
        };
      }
    }
  });

  await adapter.signDirect(signDoc);

  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], "clairveil-local-3");
  assert.equal(calls[0][1], address);
  assert.equal(calls[0][2], signDoc);
  assert.deepEqual(calls[0][3], {
    preferNoSetFee: true,
    preferNoSetMemo: true
  });
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

test("EIP-1193 wallet adapter strips Clairveil transaction metadata", async () => {
  const calls = [];
  const provider = {
    async request(input) {
      calls.push(input);
      if (input.method === "eth_sendTransaction") {
        return "0x" + "12".repeat(32);
      }
      if (input.method === "eth_call") return "0x";
      throw new Error(`unexpected method ${input.method}`);
    }
  };
  const adapter = createEip1193WalletAdapter({
    provider,
    account: "0x1111111111111111111111111111111111111111"
  });
  const transaction = markEvmTransactionReservationRequired({
    to: testPrivacyContractAddress,
    data: "0x1234",
    value: "0x0"
  });

  await adapter.sendTransaction(transaction);
  await adapter.call(transaction);

  assert.equal(calls[0].params[0].__clairveilEvmTransaction, undefined);
  assert.equal(calls[1].params[0].__clairveilEvmTransaction, undefined);
  assert.deepEqual(Object.keys(calls[0].params[0]).sort(), ["data", "from", "to", "value"]);
});

test("EVM transaction submission verifies the connected wallet network", async () => {
  const client = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
    evmChainId: "0x539"
  });
  let sendCalls = 0;
  const mismatchedWallet = {
    async getChainId() {
      return "0x1";
    },
    async sendTransaction() {
      sendCalls += 1;
      return "0x" + "11".repeat(32);
    }
  };
  await assert.rejects(
    () => client.sendTransaction(mismatchedWallet, { to: testPrivacyContractAddress }),
    /EVM wallet chain ID 0x1 does not match configured evmChainId 0x539/
  );
  assert.equal(sendCalls, 0);

  const matchingWallet = {
    async getChainId() {
      return "0x0539";
    },
    async sendTransaction() {
      sendCalls += 1;
      return "0x" + "12".repeat(32);
    }
  };
  await client.sendTransaction(matchingWallet, { to: testPrivacyContractAddress });
  assert.equal(sendCalls, 1);
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
  const requestedFee = [{ denom: "uclair", amount: "17" }];
  cosmosClient.assertProtocolPreflight = async () => {
    requestedFee[0].amount = "999";
    requestedFee.push({ denom: "ustale", amount: "1" });
    return {};
  };
  let capturedMemo = "";
  let capturedGasLimit = 0;
  let capturedFeeAmount = [];
  cosmosClient.buildDirectSignDoc = async ({ memo, gasLimit, feeAmount }) => {
    capturedMemo = memo;
    capturedGasLimit = gasLimit;
    capturedFeeAmount = feeAmount;
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
    memo: "custom deposit memo",
    gas_limit: 2700000,
    fee_amount: requestedFee
  });

  assert.equal(capturedMemo, "custom deposit memo");
  assert.equal(capturedGasLimit, 2700000);
  assert.deepEqual(capturedFeeAmount, [{ denom: "uclair", amount: "17" }]);
});

test("prepared transfer payload shape rejects pre-0.2 transfer payloads", () => {
  assert.throws(
    () => assertPreparedTransferPayloadShape({ version: "v2" }),
    /prepared transfer payload.version must be v5/
  );
});

test("prepared transfer metadata rejects legacy payload versions before proving", () => {
  assert.throws(
    () => validatePreparedTransferPayloadMetadata({ version: "v2" }),
    /unsupported transfer payload version "v2" \(expected "v5"\)/
  );
});

test("browser-dapp public send helpers validate recipients and coin amounts", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "evm-local-1",
    accountPrefix: "evmchain",
    shieldedPrefix: "clairs",
    denom: "utest",
    evmChainId: "0x7a69"
  });

  const transaction = client.evmNativeSendTransaction({
    to: "0x1111111111111111111111111111111111111111",
    amount: "7utest"
  });

  assert.equal(transaction.to, "0x1111111111111111111111111111111111111111");
  assert.equal(transaction.value, "0x7");
  assert.throws(
    () => client.evmNativeSendTransaction({
      to: "evmchain1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7m0r8",
      amount: "1utest"
    }),
    /send recipient must be 20-byte hex/
  );
  assert.throws(
    () => client.evmNativeSendTransaction({
      to: "0x1111111111111111111111111111111111111111",
      amount: "0utest"
    }),
    /send amount must be greater than 0/
  );
  assert.throws(
    () => client.evmNativeSendTransaction({
      to: "0x1111111111111111111111111111111111111111",
      amount: "1uclair"
    }),
    /send denom must be utest, got uclair/
  );

  client.cosmos.buildDirectSignDoc = async input => input;
  const signDoc = await client.buildBankSendSignDoc({
    from: "evmchain1sender",
    pubKeyHex: "02".padEnd(66, "0"),
    to: "evmchain1recipient",
    amount: "9utest",
    gas_limit: 240000,
    fee_amount: [
      { denom: "zfee", amount: "2" },
      { denom: "utest", amount: "7" }
    ]
  });
  assert.deepEqual(signDoc.messages[0].value.amount, [{
    denom: "utest",
    amount: "9"
  }]);
  assert.equal(signDoc.gasLimit, 240000);
  assert.deepEqual(signDoc.feeAmount, [
    { denom: "utest", amount: "7" },
    { denom: "zfee", amount: "2" }
  ]);
  await assert.rejects(
    () => client.buildBankSendSignDoc({
      from: "evmchain1sender",
      pubKeyHex: "02".padEnd(66, "0"),
      to: "evmchain1recipient",
      amount: "1utest",
      gasLimit: 200000,
      gas_limit: 200001
    }),
    /gasLimit aliases conflict/
  );
  await assert.rejects(
    () => client.buildBankSendSignDoc({
      from: "evmchain1sender",
      pubKeyHex: "02".padEnd(66, "0"),
      to: "evmchain1recipient",
      amount: "0utest"
    }),
    /send amount must be greater than 0/
  );
});

test("browser-dapp scanWalletNotes forwards typed query options", async () => {
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
  const noteStore = { load() {}, mergeScanResult() {} };
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
    afterSequence: 34,
    after: { height: 56, globalSequence: 78, outputIndex: 1 },
    page: 3,
    eventTypes: [],
    outputLimit: 90,
    eventLimit: 91,
    maxEncodedBytes: 92,
    scanSource: "privacy_scan",
    strictPrivacyScan: true,
    noteStore,
    includeFoundNotes: true
  });

  assert.equal(forwarded.limit, 50);
  assert.equal(forwarded.maxPages, 4);
  assert.equal(forwarded.afterHeight, 12);
  assert.equal(forwarded.afterSequence, 34);
  assert.deepEqual(forwarded.after, { height: 56, globalSequence: 78, outputIndex: 1 });
  assert.equal(forwarded.page, 3);
  assert.deepEqual(forwarded.eventTypes, []);
  assert.equal(forwarded.outputLimit, 90);
  assert.equal(forwarded.eventLimit, 91);
  assert.equal(forwarded.maxEncodedBytes, 92);
  assert.equal(forwarded.scanSource, "privacy_scan");
  assert.equal(forwarded.strictPrivacyScan, true);
  assert.equal(forwarded.noteStore, noteStore);
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

test("cosmos note scan follows ScanEvents cursor within the requested page budget", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  const requests = [];
  client.fetchScanEvents = async request => {
    requests.push(request);
    const page = Number(request.afterHeight || 0) + 1;
    return {
      events: [
        {
          event_type: "shielded_transfer",
          height: page,
          sequence: page,
          tx_hash_hex: page.toString(16).padStart(2, "0"),
          outputs: [0, 1].map(outputIndex => ({
            output_index: outputIndex,
            commitment_hex: "11".repeat(32),
            cipher_text_hex: "00",
            view_tag_hex: "0000"
          })),
          nullifier_hexes: []
        }
      ],
      next_height: page,
      next_sequence: page,
      limit: request.limit,
      has_more: page < 2,
      scan_format_version: 1,
      view_tag_version: 1
    };
  };

  const result = await client.scanNotes({
    rootSeed: new Uint8Array(32),
    limit: 200,
    maxPages: 2,
    scanSource: "scan_events"
  });

  assert.deepEqual(requests.map(request => [request.afterHeight, request.afterSequence]), [[0, 0], [1, 1]]);
  assert.equal(result.diagnostics.scanned_events, 2);
  assert.equal(result.diagnostics.pages_scanned, 2);
  assert.equal(result.scanCursor.has_more, false);
  assert.equal(result.scanCursor.completed, true);
  assert.equal(result.scanCursor.next_height, 2);
  assert.equal(result.scanCursor.next_sequence, 2);
  assert.equal(result.nextScanOptions.afterHeight, 2);
  assert.equal(result.nextScanOptions.afterSequence, 2);
  assert.equal(result.nextScanOptions.completed, true);

  requests.length = 0;
  const partial = await client.scanNotes({
    rootSeed: new Uint8Array(32),
    limit: 200,
    maxPages: 1,
    scanSource: "scan_events"
  });

  assert.deepEqual(requests.map(request => [request.afterHeight, request.afterSequence]), [[0, 0]]);
  assert.equal(partial.scanCursor.has_more, true);
  assert.equal(partial.scanCursor.next_height, 1);
  assert.equal(partial.scanCursor.next_sequence, 1);
  assert.equal(partial.nextScanOptions.afterHeight, 1);
  assert.equal(partial.nextScanOptions.afterSequence, 1);
  assert.equal(partial.nextScanOptions.hasMore, true);
  assert.deepEqual(
    nextPrivacyScanOptions(partial).eventTypes,
    ["deposit", "shielded_transfer"]
  );
});

test("filtered scans require an explicitly selected low-level legacy source", async () => {
  const client = cosmosTestClient();
  const requests = [];
  client.fetchPrivacyScan = async () => {
    throw new Error("privacy_scan must not receive a legacy event filter");
  };
  client.fetchScanEvents = async request => {
    requests.push(request);
    return {
      events: [],
      next_height: request.afterHeight,
      next_sequence: request.afterSequence,
      limit: request.limit,
      has_more: false,
      scan_format_version: 1,
      view_tag_version: 1
    };
  };

  await assert.rejects(() => client.scanNotes({
    rootSeed: new Uint8Array(32),
    eventTypes: ["deposit"]
  }), /unified privacy scan must not filter event types/);
  const result = await client.scanNotes({
    rootSeed: new Uint8Array(32),
    eventTypes: ["deposit"],
    scanSource: "scan_events"
  });
  assert.equal(result.scanCursor.source, "scan_events");
  assert.deepEqual(requests[0].eventTypes, ["deposit"]);
});

test("cosmos ScanEvents preserves uint64 cursors above the safe integer range", async () => {
  const client = cosmosTestClient();
  const height = "9007199254740993";
  const firstSequence = "9007199254740992";
  const secondSequence = "9007199254740993";
  const finalSequence = "9007199254740994";
  const requests = [];
  client.fetchScanEvents = async request => {
    requests.push(request);
    const firstPage = request.afterSequence === firstSequence;
    return {
      events: [],
      next_height: height,
      next_sequence: firstPage ? secondSequence : finalSequence,
      limit: request.limit,
      has_more: firstPage,
      scan_format_version: 1,
      view_tag_version: 1
    };
  };

  const result = await client.scanNotes({
    rootSeed: new Uint8Array(32),
    afterHeight: height,
    afterSequence: firstSequence,
    maxPages: 2,
    scanSource: "scan_events"
  });

  assert.deepEqual(
    requests.map(request => [request.afterHeight, request.afterSequence]),
    [[height, firstSequence], [height, secondSequence]]
  );
  assert.equal(result.scanCursor.next_height, height);
  assert.equal(result.scanCursor.next_sequence, finalSequence);
  assert.equal(result.nextScanOptions.afterHeight, height);
  assert.equal(result.nextScanOptions.afterSequence, finalSequence);

  const noteStore = new MemoryNoteStore();
  const persisted = await noteStore.mergeScanResult(result);
  assert.equal(persisted.scanCursor.next_height, height);
  assert.equal(persisted.scanCursor.next_sequence, finalSequence);
  assert.equal(persisted.lastScannedHeight, height);
  assert.equal(persisted.lastScannedSequence, finalSequence);

  requests.length = 0;
  client.fetchScanEvents = async request => {
    requests.push(request);
    if (request.afterSequence === firstSequence) {
      return {
        events: [{
          sequence: secondSequence,
          height,
          event_type: "shielded_transfer",
          tx_hash_hex: "DEAD",
          outputs: [0, 1].map(outputIndex => ({
            output_index: outputIndex,
            commitment_hex: "11".repeat(32),
            cipher_text_hex: "00",
            view_tag_hex: "0000"
          })),
          nullifier_hexes: []
        }],
        next_height: height,
        next_sequence: secondSequence,
        limit: request.limit,
        has_more: true,
        scan_format_version: 1,
        view_tag_version: 1
      };
    }
    return {
      events: [{
        sequence: finalSequence,
        height,
        event_type: "shielded_transfer",
        tx_hash_hex: "AABBCC",
        outputs: [0, 1].map(outputIndex => ({
          output_index: outputIndex,
          commitment_hex: "11".repeat(32),
          cipher_text_hex: "00",
          view_tag_hex: "0000"
        })),
        nullifier_hexes: []
      }],
      next_height: height,
      next_sequence: finalSequence,
      limit: request.limit,
      has_more: false,
      scan_format_version: 1,
      view_tag_version: 1
    };
  };
  const event = await client.findPrivacyEventByTxHash("0xaabbcc", {
    afterHeight: height,
    afterSequence: firstSequence,
    scanSource: "scan_events",
    maxPages: 2
  });
  assert.equal(event.tx_hash_hex, "AABBCC");
  assert.deepEqual(
    requests.map(request => [request.afterHeight, request.afterSequence]),
    [[height, firstSequence], [height, secondSequence]]
  );
});

test("cosmos legacy scan resumes from the returned page without retrying ScanEvents", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  let scanEventsCalls = 0;
  const legacyPages = [];
  client.fetchScanEvents = async () => {
    scanEventsCalls += 1;
    const error = new Error("scan_events unavailable");
    error.status = 404;
    throw error;
  };
  client.fetchPrivacyEvents = async request => {
    legacyPages.push(request.page);
    return {
      events: [{ event_type: "withdraw", height: request.page, tx_hash_hex: `LEGACY${request.page}` }],
      page: request.page,
      limit: request.limit,
      has_more: request.page < 4,
      latest_height: 4
    };
  };

  const first = await client.scanNotes({
    rootSeed: new Uint8Array(32),
    limit: 200,
    maxPages: 2,
    scanSource: "scan_events"
  });
  assert.deepEqual(legacyPages, [1, 2]);
  assert.equal(first.scanCursor.source, "privacy_events");
  assert.equal(first.nextScanOptions.scanSource, "privacy_events");
  assert.equal(first.nextScanOptions.page, 3);

  const second = await client.scanNotes({
    rootSeed: new Uint8Array(32),
    ...first.nextScanOptions
  });
  assert.equal(scanEventsCalls, 1);
  assert.deepEqual(legacyPages, [1, 2, 3, 4]);
  assert.equal(second.scanCursor.completed, true);
});

test("cosmos planning rejects legacy scan sources and always selects typed privacy_scan", async () => {
  const client = cosmosTestClient();
  const captured = [];
  client.scanWalletNotes = async options => {
    captured.push(options);
    return { foundNotes: [] };
  };

  await assert.rejects(() => client.planWalletTransfer({
    material: {},
    amount: "1uclair",
    scan: { scanSource: "privacy_events" }
  }), /only support the typed privacy_scan source/);
  await assert.rejects(() => client.planWalletWithdraw({
    material: {},
    amount: "1uclair",
    scan_source: "scan_events"
  }), /only support the typed privacy_scan source/);
  await client.planWalletTransfer({ material: {}, amount: "1uclair" });
  await client.planWalletWithdraw({ material: {}, amount: "1uclair" });

  assert.deepEqual(captured.map(options => options.scanSource), [
    "privacy_scan",
    "privacy_scan"
  ]);
  assert.deepEqual(captured.map(options => options.strictPrivacyScan), [true, true]);
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
  const suppliedNullifier = "01".padStart(64, "0");
  const suppliedMissingBatchNullifier = "02".padStart(64, "0");
  const store = new MemoryNoteStore({ owner: "clair1example" });
  await store.mergeScanResult({
    foundNotes: [
      {
        height: 7,
        txHash: "AA01",
        isSpent: false,
        nullifierStatus: "unspent",
        nullifier: suppliedNullifier,
        note: {
          receiverSpendPubKeyX: CURVE_BASE.x,
          receiverSpendPubKeyY: CURVE_BASE.y,
          receiverViewPubKeyX: CURVE_BASE.x,
          receiverViewPubKeyY: CURVE_BASE.y,
          amount: 10n,
          assetID: hashStringToField("uclair"),
          randomness: 11n,
          memo: "cached"
        }
      },
      {
        height: 8,
        txHash: "AA02",
        isSpent: false,
        nullifierStatus: "unspent",
        nullifier: suppliedMissingBatchNullifier,
        note: {
          receiverSpendPubKeyX: CURVE_BASE.x,
          receiverSpendPubKeyY: CURVE_BASE.y,
          receiverViewPubKeyX: CURVE_BASE.x,
          receiverViewPubKeyY: CURVE_BASE.y,
          amount: 11n,
          assetID: hashStringToField("uclair"),
          randomness: 12n,
          memo: "cached2"
        }
      }
    ]
  });
  const [cachedNote, missingBatchNote] = (await store.load()).notes;
  const nullifier = cachedNote.nullifier;
  const missingBatchNullifier = missingBatchNote.nullifier;
  assert.notEqual(nullifier, suppliedNullifier);
  assert.notEqual(missingBatchNullifier, suppliedMissingBatchNullifier);
  client.fetchPrivacyScan = async request => ({
    scanSchemaVersion: "privacy-scan-v2",
    summaries: [],
    outputs: [],
    nextCursor: request.after,
    hasMore: false
  });
  client.checkNullifiers = async values => new Map([[values[0], values[0] === nullifier]]);
  const individuallyChecked = [];
  client.checkNullifier = async value => {
    individuallyChecked.push(value);
    return { used: value === missingBatchNullifier };
  };

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
  const byNullifier = new Map(loaded.notes.map(note => [note.nullifier, note]));
  assert.equal(byNullifier.get(nullifier).isSpent, true);
  assert.equal(byNullifier.get(nullifier).spent, true);
  assert.equal(byNullifier.get(missingBatchNullifier).isSpent, true);
  assert.equal(byNullifier.get(missingBatchNullifier).spent, true);
  assert.deepEqual(individuallyChecked, [missingBatchNullifier]);
});

test("cosmos wallet note store resumes cached scan cursors from their next position", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  const material = {
    rootSeed: new Uint8Array(32),
    address: "clair1cursor",
    pubKeyHex: "02".padEnd(66, "0"),
    signingMessage: "",
    shieldedAddress: "clairs1cursor",
    disclosurePubKeyHex: "",
    rootSignatureHash: ""
  };
  const requests = [];
  client.scanNotes = async input => {
    requests.push(input);
    return {
      foundNotes: [],
      scanCursor: {
        source: "privacy_scan",
        after: input.after,
        has_more: false,
        next_cursor: input.after
      }
    };
  };

  const scanEventsStore = new MemoryNoteStore({ owner: material.address });
  await scanEventsStore.mergeScanResult({
    foundNotes: [],
    scanCursor: {
      source: "scan_events",
      after_height: 50,
      after_sequence: 1,
      next_height: 73,
      next_sequence: 9,
      has_more: true
    }
  });
  await client.scanWalletNotes({ material, noteStore: scanEventsStore });
  assert.equal(requests[0].scanSource, "privacy_scan");
  assert.equal(requests[0].strictPrivacyScan, true);
  assert.deepEqual(requests[0].after, { height: 72, globalSequence: 0, outputIndex: 0 });

  await assert.rejects(() => client.scanWalletNotes({
    material,
    noteStore: scanEventsStore,
    scanSource: "privacy_events"
  }), /only support the typed privacy_scan source/);

  const privacyEventsStore = new MemoryNoteStore({ owner: material.address });
  await privacyEventsStore.mergeScanResult({
    foundNotes: [],
    scanCursor: {
      source: "privacy_events",
      after_height: 50,
      page: 1,
      next_page: 2,
      has_more: true
    }
  });
  await client.scanWalletNotes({ material, noteStore: privacyEventsStore });
  assert.deepEqual(requests[1].after, { height: 49, globalSequence: 0, outputIndex: 0 });

  const typedScanStore = new MemoryNoteStore({ owner: material.address });
  await typedScanStore.mergeScanResult({
    foundNotes: [],
    scanCursor: {
      source: "privacy_scan",
      after: { height: 80, global_sequence: 4, output_index: 1 },
      next_cursor: { height: 81, global_sequence: 2, output_index: 0 },
      has_more: true
    }
  });
  await client.scanWalletNotes({ material, noteStore: typedScanStore });
  assert.equal(requests[2].scanSource, "privacy_scan");
  assert.deepEqual(requests[2].after, {
    height: 81,
    globalSequence: 2,
    outputIndex: 0
  });
});

test("note store preserves completed ScanEvents next cursor without matching notes", async () => {
  const store = new MemoryNoteStore({ owner: "clair1empty" });
  const state = await store.mergeScanResult({
    foundNotes: [],
    scanCursor: {
      source: "scan_events",
      has_more: false,
      next_height: 200,
      next_sequence: 77,
      latest_height: 0,
      latest_sequence: 0
    }
  });
  assert.equal(state.lastScannedHeight, 200);
  assert.equal(state.lastScannedSequence, 77);
  assert.equal(state.scanCursor.next_height, 200);
  assert.equal(state.scanCursor.next_sequence, 77);

  const rolledBack = await store.rollbackToHeight(100);
  assert.equal(rolledBack.lastScannedHeight, 100);
  assert.equal(rolledBack.lastScannedSequence, 0);
  assert.equal(rolledBack.lastScannedTxHash, "");
  assert.equal(rolledBack.scanCursor.source, "scan_events");
  assert.equal(rolledBack.scanCursor.after_height, 100);
  assert.equal(rolledBack.scanCursor.after_sequence, 0);
});

test("note store merge rewinds a stale cursor when rollback has no replacement cursor", async () => {
  const store = new MemoryNoteStore({ owner: "clair1merge-rollback" });
  await store.mergeScanResult({
    foundNotes: [],
    scanCursor: {
      source: "scan_events",
      has_more: false,
      next_height: 200,
      next_sequence: 77
    }
  });

  const rolledBack = await store.mergeScanResult({
    foundNotes: [],
    rollbackToHeight: 100
  });
  assert.equal(rolledBack.lastScannedHeight, 100);
  assert.equal(rolledBack.lastScannedSequence, 0);
  assert.equal(rolledBack.lastScannedTxHash, "");
  assert.equal(rolledBack.scanCursor.source, "scan_events");
  assert.equal(rolledBack.scanCursor.after_height, 100);
  assert.equal(rolledBack.scanCursor.after_sequence, 0);
  assert.equal(rolledBack.scanCursor.next_height, 100);
  assert.equal(rolledBack.scanCursor.next_sequence, 0);
});

test("note store merge honors an explicit genesis rollback boundary", async () => {
  for (const rollbackField of ["rollbackToHeight", "rollback_to_height"]) {
    const store = new MemoryNoteStore({ owner: `clair1genesis-${rollbackField}` });
    await store.mergeScanResult({
      foundNotes: [{
        height: 1,
        sequence: 7,
        txHash: "GENESIS-ORPHAN",
        isSpent: false,
        nullifierStatus: "unspent",
        nullifier: "04".padStart(64, "0"),
        note: {
          receiverSpendPubKeyX: CURVE_BASE.x,
          receiverSpendPubKeyY: CURVE_BASE.y,
          receiverViewPubKeyX: CURVE_BASE.x,
          receiverViewPubKeyY: CURVE_BASE.y,
          amount: 1n,
          assetID: hashStringToField("uclair"),
          randomness: 14n,
          memo: "orphaned-after-genesis"
        }
      }],
      scanCursor: {
        source: "scan_events",
        has_more: false,
        next_height: 1,
        next_sequence: 8
      }
    });

    const rolledBack = await store.mergeScanResult({
      foundNotes: [],
      [rollbackField]: 0
    });
    assert.deepEqual(rolledBack.notes, []);
    assert.equal(rolledBack.rollbackHeight, 0);
    assert.equal(rolledBack.lastScannedHeight, 0);
    assert.equal(rolledBack.lastScannedSequence, 0);
    assert.equal(rolledBack.lastScannedTxHash, "");
    assert.equal(rolledBack.scanCursor.source, "scan_events");
    assert.equal(rolledBack.scanCursor.after_height, 0);
    assert.equal(rolledBack.scanCursor.after_sequence, 0);
    assert.equal(rolledBack.scanCursor.next_height, 0);
    assert.equal(rolledBack.scanCursor.next_sequence, 0);
  }
});

test("note store discards notes at the rollback boundary before re-scanning it", async () => {
  const store = new MemoryNoteStore({ owner: "clair1reorg" });
  await store.mergeScanResult({
    foundNotes: [{
      height: 100,
      txHash: "REORG100",
      isSpent: false,
      nullifierStatus: "unspent",
      nullifier: "03".padStart(64, "0"),
      note: {
        receiverSpendPubKeyX: CURVE_BASE.x,
        receiverSpendPubKeyY: CURVE_BASE.y,
        receiverViewPubKeyX: CURVE_BASE.x,
        receiverViewPubKeyY: CURVE_BASE.y,
        amount: 1n,
        assetID: hashStringToField("uclair"),
        randomness: 13n,
        memo: "orphaned-at-boundary"
      }
    }]
  });

  const rolledBack = await store.rollbackToHeight(100);
  assert.deepEqual(rolledBack.notes, []);
});

test("note store rewinds legacy privacy-events one height before a rollback boundary", async () => {
  const store = new MemoryNoteStore({ owner: "clair1legacy" });
  await store.mergeScanResult({
    foundNotes: [],
    scanCursor: {
      source: "privacy_events",
      after_height: 250,
      page: 1,
      has_more: false
    }
  });

  const rolledBack = await store.rollbackToHeight(100);
  assert.equal(rolledBack.lastScannedHeight, 99);
  assert.equal(rolledBack.scanCursor.source, "privacy_events");
  assert.equal(rolledBack.scanCursor.after_height, 99);
});

test("note store rollback never advances an unscanned or behind cursor", async () => {
  const freshStore = new MemoryNoteStore({ owner: "clair1fresh-rollback" });
  const freshRolledBack = await freshStore.rollbackToHeight(100);
  assert.equal(freshRolledBack.lastScannedHeight, 0);
  assert.equal(freshRolledBack.scanCursor.source, "privacy_events");
  assert.equal(freshRolledBack.scanCursor.after_height, 0);

  const behindStore = new MemoryNoteStore({ owner: "clair1behind-rollback" });
  await behindStore.mergeScanResult({
    foundNotes: [],
    scanCursor: {
      source: "scan_events",
      has_more: false,
      next_height: 50,
      next_sequence: 7
    }
  });
  const behindRolledBack = await behindStore.rollbackToHeight(100);
  assert.equal(behindRolledBack.lastScannedHeight, 50);
  assert.equal(behindRolledBack.lastScannedSequence, 0);
  assert.equal(behindRolledBack.scanCursor.source, "scan_events");
  assert.equal(behindRolledBack.scanCursor.after_height, 50);
  assert.equal(behindRolledBack.scanCursor.after_sequence, 0);
});

test("note store rollback preserves uint64 heights above the safe integer range", async () => {
  const lowerHeight = "9007199254740992";
  const rollbackHeight = "9007199254740993";
  const laterHeight = "9007199254740994";
  const foundNote = (height, suffix) => ({
    height,
    sequence: 1,
    txHash: `PRECISE-${suffix}`,
    isSpent: false,
    nullifierStatus: "unspent",
    nullifier: suffix.padStart(64, "0"),
    note: {
      receiverSpendPubKeyX: CURVE_BASE.x,
      receiverSpendPubKeyY: CURVE_BASE.y,
      receiverViewPubKeyX: CURVE_BASE.x,
      receiverViewPubKeyY: CURVE_BASE.y,
      amount: 1n,
      assetID: hashStringToField("uclair"),
      randomness: BigInt(suffix),
      memo: "precise rollback"
    }
  });

  const legacyStore = new MemoryNoteStore({ owner: "clair1precise-legacy" });
  await legacyStore.mergeScanResult({
    foundNotes: [foundNote(lowerHeight, "11"), foundNote(rollbackHeight, "12")],
    scanCursor: {
      source: "privacy_events",
      after_height: laterHeight,
      page: 1,
      has_more: false
    }
  });
  const directlyRolledBack = await legacyStore.rollbackToHeight(rollbackHeight);
  assert.deepEqual(directlyRolledBack.notes.map(note => note.height), [lowerHeight]);
  assert.equal(directlyRolledBack.rollbackHeight, rollbackHeight);
  assert.equal(directlyRolledBack.lastScannedHeight, lowerHeight);
  assert.equal(directlyRolledBack.scanCursor.after_height, lowerHeight);

  const scanEventsStore = new MemoryNoteStore({ owner: "clair1precise-scan-events" });
  await scanEventsStore.mergeScanResult({
    foundNotes: [foundNote(lowerHeight, "21"), foundNote(rollbackHeight, "22")],
    scanCursor: {
      source: "scan_events",
      next_height: laterHeight,
      next_sequence: 7,
      has_more: false
    }
  });
  const mergeRolledBack = await scanEventsStore.mergeScanResult({
    foundNotes: [],
    rollbackToHeight: rollbackHeight
  });
  assert.deepEqual(mergeRolledBack.notes.map(note => note.height), [lowerHeight]);
  assert.equal(mergeRolledBack.rollbackHeight, rollbackHeight);
  assert.equal(mergeRolledBack.lastScannedHeight, rollbackHeight);
  assert.equal(mergeRolledBack.scanCursor.after_height, rollbackHeight);
  assert.equal(mergeRolledBack.scanCursor.after_sequence, 0);
});

test("cached spent notes are rechecked and restored when a reorg makes them unspent", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  const nullifier = "03".padStart(64, "0");
  const store = new MemoryNoteStore({ owner: "clair1reorg-status" });
  await store.mergeScanResult({
    foundNotes: [{
      height: 9,
      txHash: "REORG-SPENT",
      isSpent: true,
      nullifierStatus: "spent",
      nullifier,
      note: {
        receiverSpendPubKeyX: CURVE_BASE.x,
        receiverSpendPubKeyY: CURVE_BASE.y,
        receiverViewPubKeyX: CURVE_BASE.x,
        receiverViewPubKeyY: CURVE_BASE.y,
        amount: 1n,
        assetID: hashStringToField("uclair"),
        randomness: 14n,
        memo: "reorg-status"
      }
    }]
  });
  client.checkNullifiers = async values => new Map([[values[0], false]]);

  await client.refreshNoteStoreSpentStatuses(store);
  const [restored] = (await store.load()).notes;
  assert.equal(restored.isSpent, false);
  assert.equal(restored.nullifierStatus, "unspent");
});

test("memory note store normalizes nullifier status keys before applying them", async () => {
  const suppliedNullifier = "ab".repeat(32);
  const store = new MemoryNoteStore({ owner: "clair1statuscase" });
  await store.mergeScanResult({
    foundNotes: [{
      height: 10,
      txHash: "STATUS-CASE",
      isSpent: false,
      nullifierStatus: "unspent",
      nullifier: suppliedNullifier,
      note: {
        receiverSpendPubKeyX: CURVE_BASE.x,
        receiverSpendPubKeyY: CURVE_BASE.y,
        receiverViewPubKeyX: CURVE_BASE.x,
        receiverViewPubKeyY: CURVE_BASE.y,
        amount: 1n,
        assetID: hashStringToField("uclair"),
        randomness: 15n,
        memo: "status-case"
      }
    }]
  });

  const [stored] = (await store.load()).notes;
  assert.notEqual(stored.nullifier, suppliedNullifier);
  await store.setNullifierStatuses(new Map([[stored.nullifier.toUpperCase(), "spent"]]));
  const [updated] = (await store.load()).notes;
  assert.equal(updated.isSpent, true);
  assert.equal(updated.nullifierStatus, "spent");
});

test("Cosmos prepare methods forward complete typed scan cursors and snake-case page budgets", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    enableExperimentalBatchTransfer: true
  });
  const scans = [];
  client.assertTransferProtocolConfig = async () => transferProtocolConfig();
  client.scanNotes = async input => {
    scans.push(input);
    throw new Error("scan captured");
  };
  const material = {
    rootSeed: new Uint8Array(32),
    address: "clair1example",
    pubKeyHex: "02".padEnd(66, "0"),
    shieldedAddress: "clairs1example"
  };
  const proverAdapter = {};
  const calls = [
    () => client.prepareTransfer({
      material,
      amount: "1uclair",
      recipient: validClairsRecipient,
      proverAdapter,
      afterHeight: 10,
      afterSequence: 11,
      strictPrivacyScan: true
    }),
    () => client.prepareTransferBatch({
      material,
      amounts: ["1uclair"],
      recipient: "clairs1recipient",
      proverAdapter,
      reservationManager: {},
      onPreparedPayload() {},
      onPreparedProof() {},
      max_pages: 12,
      after: { height: 22, globalSequence: 23, outputIndex: 1 },
      outputLimit: 24,
      eventLimit: 25,
      maxEncodedBytes: 26,
      strict_privacy_scan: true
    }),
    () => client.prepareWithdraw({
      material,
      amount: "1uclair",
      recipient: "clair1recipient",
      proverAdapter,
      afterHeight: 30,
      afterSequence: 31,
      strict_privacy_scan: true
    }),
    () => client.prepareRelayWithdraw({
      material,
      amount: "1uclair",
      recipient: "clair1recipient",
      proverAdapter,
      after_height: 40,
      after_sequence: 41,
      strictPrivacyScan: true,
      expiresAtUnix: 4102448400,
      chainNowUnix: 4102444800
    })
  ];

  for (const call of calls) {
    await assert.rejects(call, /scan captured/);
  }
  assert.deepEqual(scans.map(scan => scan.after), [
    { height: 10, globalSequence: 11, outputIndex: 1 },
    { height: 22, globalSequence: 23, outputIndex: 1 },
    { height: 30, globalSequence: 31, outputIndex: 1 },
    { height: 40, globalSequence: 41, outputIndex: 1 }
  ]);
  assert.deepEqual(scans[1].after, { height: 22, globalSequence: 23, outputIndex: 1 });
  assert.equal(scans[1].outputLimit, 24);
  assert.equal(scans[1].eventLimit, 25);
  assert.equal(scans[1].maxEncodedBytes, 26);
  assert.deepEqual(scans.map(scan => scan.strictPrivacyScan), [true, true, true, true]);
});

test("browser-dapp prepare forwards scan options into EVM note scans", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair",
    evmPrivacyPrecompileAddress: "0x0000000000000000000000000000000000000900"
  });
  client.privacyMaterial = () => ({
    rootSeed: new Uint8Array(32),
    address: "clair1example",
    pubKeyHex: "02".padEnd(66, "0"),
    shieldedAddress: "clairs1example"
  });
  client.cosmos.assertTransferProtocolConfig = async () => transferProtocolConfig();
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
    recipient: validClairsRecipient
  }));
  await assert.rejects(() => client.prepareTransfer({
    walletType: "evm",
    address: "clair1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1uclair",
    recipient: validClairsRecipient,
    scan: { after: { height: 9, globalSequence: 10, outputIndex: 1 }, limit: 123, maxPages: 7 }
  }));
  await assert.rejects(() => client.prepareWithdraw({
    walletType: "evm",
    address: "clair1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1uclair",
    recipient: "clair1recipient",
    scan: { after: { height: 10, globalSequence: 11, outputIndex: 2 }, limit: 124, maxPages: 8 }
  }));
  await assert.rejects(() => client.prepareTransfer({
    walletType: "evm",
    address: "clair1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1uclair",
    recipient: validClairsRecipient,
    strictPrivacyScan: false
  }), /wallet and spend scans require strictPrivacyScan=true/);

  const [defaultTransferScan, transferScan, withdrawScan] = scans;
  assert.equal(defaultTransferScan.limit, 200);
  assert.equal(defaultTransferScan.maxPages > 50, true);
  assert.equal(defaultTransferScan.scanSource, "privacy_scan");
  assert.equal(defaultTransferScan.strictPrivacyScan, true);
  assert.equal(transferScan.afterHeight, 9);
  assert.equal(transferScan.limit, 123);
  assert.equal(transferScan.maxPages, 7);
  assert.equal(transferScan.scanSource, "privacy_scan");
  assert.equal(transferScan.strictPrivacyScan, true);
  assert.equal(withdrawScan.afterHeight, 10);
  assert.equal(withdrawScan.limit, 124);
  assert.equal(withdrawScan.maxPages, 8);
  assert.equal(withdrawScan.scanSource, "privacy_scan");
  assert.equal(withdrawScan.strictPrivacyScan, true);

  await assert.rejects(() => client.prepareTransfer({
    walletType: "evm",
    address: "clair1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1uclair",
    recipient: "clairs1recipient",
    scanSource: "scan_events"
  }), /only support the typed privacy_scan source/);
  await assert.rejects(() => client.prepareWithdraw({
    walletType: "evm",
    address: "clair1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1uclair",
    recipient: "clair1recipient",
    strictPrivacyScan: false
  }), /require strictPrivacyScan=true/);
});

test("browser-dapp EVM prepareTransfer enables full operation success evidence", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair",
    evmChainId: "0x7a69",
    evmPrivacyPrecompileAddress: "0x0000000000000000000000000000000000000900"
  });
  const selectedNote = {
    note: createNote({
      spendPubKey: CURVE_BASE,
      viewPubKey: CURVE_BASE,
      amount: 1n,
      assetDenom: "uclair",
      randomness: 101n
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: "TX-EVM-TRANSFER",
    height: 101
  };
  const helperNote = (height, randomness) => ({
    note: createNote({
      spendPubKey: CURVE_BASE,
      viewPubKey: CURVE_BASE,
      amount: 0n,
      assetDenom: "uclair",
      randomness
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: `TX-EVM-HELPER-${height}`,
    height
  });
  client.privacyMaterial = () => ({
    rootSeed: new Uint8Array(32),
    address: "clair1sender",
    pubKeyHex: "02".padEnd(66, "0"),
    shieldedAddress: validClairsRecipient
  });
  client.cosmos.scanNotes = async () => ({
    notes: [],
    summary: { total_spendable: "1", spendable_count: 3, spent_count: 0, total_count: 3 },
    diagnostics: { scanned_events: 0, new_notes_found: 0 },
    foundNotes: [helperNote(99, 99n), helperNote(100, 100n), selectedNote],
    scanCursor: { source: "privacy_scan", has_more: false }
  });
  client.cosmos.assertTransferProtocolConfig = async () => transferProtocolConfig();
  client.proverAdapter = () => null;
  let evmAuditTarget = null;
  let evmSelfViewOptOut = null;
  let evmChainNowUnix = null;
  let evmExpiresAtUnix = null;
  client.cosmos.buildTransferMessage = async input => {
    evmAuditTarget = input.auditDisclosureTargetPubKeyHex;
    evmSelfViewOptOut = input.disableSelfViewDisclosure;
    evmChainNowUnix = input.chainNowUnix;
    evmExpiresAtUnix = input.expiresAtUnix;
    return {
      payload: {
        payload_hash: "payload-evm-transfer",
        inputs: input.inputs.map(found => ({
          nullifier_hex: normalizeFoundNote(found).nullifier
        })),
        outputs: [{ amount: "1", commitment_hex: "commitment-evm-transfer" }],
        audit_disclosure_digest_hex: "audit-digest-evm-transfer",
        expires_at_unix: input.expiresAtUnix
      },
      proof: { payload_hash: "payload-evm-transfer", proof_hex: "01" },
      message: {
        proof: new Uint8Array([1]),
        expiresAtUnix: BigInt(input.expiresAtUnix)
      }
    };
  };
  let evmBuildInput = null;
  client.evm.buildTransferTransaction = async input => {
    evmBuildInput = input;
    return {
      status: "ready",
      message: input.message,
      payload: input.payload,
      proof: input.proof,
      transaction: {
        to: evmPrivacyPrecompileAddress,
        data: "0x1234"
      }
    };
  };
  const store = new MemoryReservationStore();
  const reservationManager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1sender",
    indexKey: "index-key-v1"
  });

  const result = await client.prepareTransfer({
    walletType: "evm",
    address: "clair1sender",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1uclair",
    recipient: "clairs1recipient",
    chainNowUnix: 1_700_000_000,
    expiresAtUnix: 1_700_000_777,
    expectedRecipientHash: "recipient-hash",
    expectedAmountHash: "amount-hash",
    reservationManager
  });

  assert.equal(result.transaction.data, "0x1234");
  assert.equal(result.txBytesHash, evmTransactionBindingHash(result.transaction));
  assert.equal(evmAuditTarget, transferProtocolConfig().audit_config.audit_master_pubkey_hex);
  assert.equal(evmSelfViewOptOut, undefined);
  assert.equal(evmChainNowUnix, 1_700_000_000);
  assert.equal(evmExpiresAtUnix, 1_700_000_777);
  assert.equal(evmBuildInput.chainNowUnix, 1_700_000_000);
  assert.equal(evmBuildInput.expiresAtUnix, 1_700_000_777);
  assert.equal(evmBuildInput.message.expiresAtUnix, 1_700_000_777n);
  assert.equal(evmBuildInput.payload.expires_at_unix, 1_700_000_777);
  assert.equal(result.reservation.reservations.length > 0, true);
  for (const reservationID of result.reservation.reservation_ids) {
    const reservation = await store.getReservation(reservationID);
    assert.equal(reservation.status, reservationStatuses.ProofReady);
    assert.equal(reservation.expected_output_commitment, "commitment-evm-transfer");
    assert.equal(reservation.expected_disclosure_digest, "audit-digest-evm-transfer");
    assert.equal(
      reservation.expected_recipient_hash,
      hashRecipient(validClairsRecipient, { shieldedPrefix: "clairs" })
    );
    assert.equal(reservation.expected_amount_hash, hashAmount("uclair", "1"));
    assert.equal(reservation.tx_bytes_hash, result.txBytesHash);
    assert.equal(reservation.batch_item_index_known, false);
    assert.equal(reservation.metadata.execution_transport, "evm");
    assert.equal(reservation.metadata.operation_success_evidence_required, true);
    assert.deepEqual(
      reservation.metadata.input_nullifier_hexes,
      result.prepared.payload.inputs.map(input => input.nullifier_hex)
    );
  }

  await assert.rejects(
    () => client.prepareTransfer({
      walletType: "evm",
      address: "clair1sender",
      pubKeyHex: "02".padEnd(66, "0"),
      signatureBase64: "AQID",
      amount: "1uclair",
      recipient: validClairsRecipient,
      expectedRecipientHash: "00".repeat(32)
    }),
    /expectedRecipientHash does not match the transfer recipient/
  );

  const selfMergeNote = (amount, height, randomness) => ({
    note: createNote({
      spendPubKey: CURVE_BASE,
      viewPubKey: CURVE_BASE,
      amount: BigInt(amount),
      assetDenom: "uclair",
      randomness: BigInt(randomness)
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: `TX-EVM-SELF-MERGE-${height}`,
    height
  });
  client.cosmos.scanNotes = async () => ({
    notes: [],
    summary: { total_spendable: "10", spendable_count: 3, spent_count: 0, total_count: 3 },
    diagnostics: { scanned_events: 0, new_notes_found: 0 },
    foundNotes: [
      selfMergeNote(1, 201, 201),
      selfMergeNote(1, 202, 202),
      selfMergeNote(8, 203, 203)
    ],
    scanCursor: { source: "privacy_scan", has_more: false }
  });
  client.cosmos.buildTransferMessage = async input => ({
    payload: {
      payload_hash: "payload-evm-self-merge",
      inputs: input.inputs.map(found => ({
        nullifier_hex: normalizeFoundNote(found).nullifier
      })),
      outputs: [{ amount: input.amount.replace(/[^0-9].*$/, ""), commitment_hex: "commitment-evm-self-merge" }],
      audit_disclosure_digest_hex: "audit-digest-evm-self-merge",
      expires_at_unix: input.expiresAtUnix
    },
    proof: { payload_hash: "payload-evm-self-merge", proof_hex: "01" },
    message: {
      proof: new Uint8Array([1]),
      expiresAtUnix: BigInt(input.expiresAtUnix)
    }
  });
  const selfMergeStore = new MemoryReservationStore();
  const selfMergeManager = createNoteReservationManager({
    store: selfMergeStore,
    ownerKeyId: "chain:clair1sender",
    indexKey: "index-key-v1"
  });
  const selfMerge = await client.prepareTransfer({
    walletType: "evm",
    address: "clair1sender",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "10uclair",
    recipient: "clairs1recipient",
    chainNowUnix: 1_700_000_000,
    expiresAtUnix: 1_700_000_777,
    allowPlanStep: true,
    expectedRecipientHash: "recipient-hash",
    expectedAmountHash: "amount-hash",
    reservationManager: selfMergeManager
  });
  assert.equal(selfMerge.prepared.isFinal, false);
  for (const reservationID of selfMerge.reservation.reservation_ids) {
    const reservation = await selfMergeStore.getReservation(reservationID);
    assert.equal(reservation.expected_recipient_hash, "");
    assert.equal(reservation.expected_amount_hash, "");
    assert.notEqual(reservation.metadata.operation_success_evidence_required, true);
  }

  await assert.rejects(
    () => client.prepareTransfer({
      walletType: "evm",
      address: "clair1sender",
      pubKeyHex: "02".padEnd(66, "0"),
      signatureBase64: "AQID",
      amount: "10uclair",
      recipient: validClairsRecipient,
      expectedAmountHash: "00".repeat(32),
      allowPlanStep: true
    }),
    /expectedAmountHash does not match the transfer amount/
  );
  const selfMergeStore = new MemoryReservationStore();
  const selfMergeManager = createNoteReservationManager({
    store: selfMergeStore,
    ownerKeyId: "chain:clair1sender",
    indexKey: "index-key-v1"
  });
  await assert.rejects(
    () => client.prepareTransfer({
      walletType: "evm",
      address: "clair1sender",
      pubKeyHex: "02".padEnd(66, "0"),
      signatureBase64: "AQID",
      amount: "10uclair",
      recipient: "clairs1recipient",
      allowPlanStep: true,
      reservationManager: selfMergeManager
    }),
    /recipient must be a valid shielded address/
  );
  assert.deepEqual(await selfMergeStore.listReservations(), []);
  const selfMerge = await client.prepareTransfer({
    walletType: "evm",
    address: "clair1sender",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "10uclair",
    recipient: validClairsRecipient,
    allowPlanStep: true,
    reservationManager: selfMergeManager
  });
  assert.equal(selfMerge.prepared.isFinal, false);
  const selfMergeCoin = String(selfMerge.prepared.amount).match(/^(0|[1-9][0-9]*)([A-Za-z][A-Za-z0-9/:._-]{2,127})$/);
  assert.ok(selfMergeCoin, "self-merge prepared amount must be a canonical coin");
  const [, selfMergeAmount, selfMergeDenom] = selfMergeCoin;
  for (const reservationID of selfMerge.reservation.reservation_ids) {
    const reservation = await selfMergeStore.getReservation(reservationID);
    assert.equal(
      reservation.expected_recipient_hash,
      hashRecipient(selfMerge.prepared.recipient, { shieldedPrefix: "clairs" })
    );
    assert.equal(reservation.expected_amount, selfMergeAmount);
    assert.equal(reservation.expected_amount_hash, hashAmount(selfMergeDenom, selfMergeAmount));
    assert.equal(reservation.expected_denom, selfMergeDenom);
    assert.equal(reservation.metadata.operation_success_evidence_required, true);
  }

});

test("cosmos prepareTransfer returns its artifact with reconciliation warning after a final heartbeat failure", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  client.assertTransferProtocolConfig = async () => transferProtocolConfig();
  client.scanNotes = async () => heartbeatTestScanResult();
  client.buildTransferMessage = async () => heartbeatTestBuiltTransfer();
  client.buildDirectSignDoc = async input => input;

  const store = new MemoryReservationStore();
  const reservationManager = heartbeatFailureReservationManager(store, "chain:clair1cosmos-heartbeat");

  const prepared = await client.prepareTransfer({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient: validClairsRecipient,
    proverAdapter: null,
    chainNowUnix: 1_700_000_000,
    gas_limit: 8_123_456,
    feeAmount: [{ denom: "uclair", amount: "200000" }],
    reservationManager
  });
  assert.equal(prepared.status, "ready");
  assert.ok(prepared.signDoc);
  assert.equal(prepared.signDoc.gasLimit, 8_123_456);
  assert.deepEqual(prepared.signDoc.feeAmount, [{ denom: "uclair", amount: "200000" }]);
  assert.ok(prepared.proof);
  assert.equal(prepared.reservationReconciliationRequired, true);
  assert.equal(
    prepared.reservationReconciliationWarning.code,
    "reservation_heartbeat_failed_after_proof_ready"
  );

  const reservations = (await store.load()).reservations;
  assert.equal(reservations.length > 0, true);
  assert.equal(reservations.every(reservation => reservation.status === reservationStatuses.ProofReady), true);
  assert.equal(reservations.every(reservation => reservation.metadata.execution_transport === "cosmos"), true);
});

test("cosmos prepareTransfer validates disclosure capabilities before reserving or proving", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  client.assertTransferProtocolConfig = async () => transferProtocolConfig();
  client.scanNotes = async () => heartbeatTestScanResult();
  let buildCalls = 0;
  client.buildTransferMessage = async () => {
    buildCalls += 1;
    return heartbeatTestBuiltTransfer();
  };

  await assert.rejects(
    () => client.prepareTransfer({
      material: heartbeatTestMaterial(),
      amount: "1uclair",
      recipient: validClairsRecipient,
      proverAdapter: null,
      chainNowUnix: 1_700_000_000,
      userPrivacyPolicy: "amount",
      userDisclosureMode: "public"
    }),
    /does not support transfer privacy policy amount/
  );
  assert.equal(buildCalls, 0);
});

test("cosmos prepareTransfer validates and forwards self-view disclosure aliases", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  client.assertTransferProtocolConfig = async () => transferProtocolConfig();
  let scanCalls = 0;
  client.scanNotes = async () => {
    scanCalls += 1;
    return heartbeatTestScanResult();
  };
  let buildInput;
  client.buildTransferMessage = async input => {
    buildInput = input;
    return heartbeatTestBuiltTransfer();
  };
  client.buildDirectSignDoc = async input => input;
  const target = Buffer.from(packPoint(CURVE_BASE)).toString("hex");

  await client.prepareTransfer({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient: "clairs1recipient",
    proverAdapter: null,
    chainNowUnix: 1_700_000_000,
    disableSelfViewDisclosure: true,
    disable_self_view_disclosure: true,
    selfViewDisclosureTargetPubKeyHex: `0x${target}`,
    self_view_disclosure_target_pubkey: target
  });
  assert.equal(buildInput.disableSelfViewDisclosure, true);
  assert.equal(buildInput.selfViewDisclosureTargetPubKeyHex, `0x${target}`);

  await assert.rejects(
    () => client.prepareTransfer({ disableSelfViewDisclosure: "false" }),
    /disableSelfViewDisclosure must be a boolean/
  );
  await assert.rejects(
    () => client.prepareTransfer({
      disableSelfViewDisclosure: true,
      disable_self_view_disclosure: false
    }),
    /disableSelfViewDisclosure aliases conflict/
  );
  await assert.rejects(
    () => client.prepareTransfer({
      selfViewDisclosureTargetPubKeyHex: "03".repeat(32),
      self_view_disclosure_target_pubkey: "04".repeat(32)
    }),
    /selfViewDisclosureTargetPubKeyHex aliases conflict/
  );
  assert.equal(scanCalls, 1);
});

test("single transfer preserves authoritative expiry through payload, proof, and MsgTransfer", async () => {
  const chainNowUnix = 1_700_000_000;
  const expiresAtUnix = 1_700_000_777;
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  client.assertTransferProtocolConfig = async () => transferProtocolConfig();
  client.scanNotes = async () => heartbeatTestScanResult();
  let buildInput;
  let signedMessage;
  client.buildTransferMessage = async input => {
    buildInput = input;
    const payload = {
      payload_hash: "expiry-bound-payload",
      expires_at_unix: input.expiresAtUnix,
      outputs: [{ amount: "1", commitment_hex: "expiry-output" }],
      audit_disclosure_digest_hex: "expiry-digest"
    };
    return {
      payload,
      proof: {
        version: "v2",
        payload_hash: payload.payload_hash,
        proof_hex: validV2ProofHex
      },
      message: {
        expiresAtUnix: BigInt(input.expiresAtUnix),
        proof: Buffer.from(validV2ProofHex, "hex")
      }
    };
  };
  client.buildDirectSignDoc = async input => {
    signedMessage = input.messages[0].value;
    return input;
  };

  const prepared = await client.prepareTransfer({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient: "clairs1recipient",
    proverAdapter: null,
    chainNowUnix,
    chain_now_unix: chainNowUnix,
    expiresAtUnix,
    expires_at_unix: expiresAtUnix
  });
  assert.equal(buildInput.chainNowUnix, chainNowUnix);
  assert.equal(buildInput.expiresAtUnix, expiresAtUnix);
  assert.equal(prepared.payload.expires_at_unix, expiresAtUnix);
  assert.equal(prepared.proof.payload_hash, prepared.payload.payload_hash);
  assert.equal(prepared.message.expiresAtUnix, BigInt(expiresAtUnix));
  assert.equal(signedMessage.expiresAtUnix, BigInt(expiresAtUnix));
  assert.equal(prepared.prepared.chainNowUnix, chainNowUnix);
  assert.equal(prepared.prepared.expiresAtUnix, expiresAtUnix);

  await assert.rejects(
    () => client.prepareTransfer({
      chainNowUnix: 10,
      chain_now_unix: 11
    }),
    /chainNowUnix aliases conflict/
  );
  await assert.rejects(
    () => client.prepareTransfer({
      expiresAtUnix: 20,
      expires_at_unix: 21
    }),
    /expiresAtUnix aliases conflict/
  );
  await assert.rejects(
    () => client.prepareTransfer({ chainNowUnix: false }),
    /chainNowUnix must be a non-negative safe integer/
  );
  await assert.rejects(
    () => client.prepareTransfer({ chainNowUnix: 0, expiresAtUnix: true }),
    /expiresAtUnix must be a non-negative safe integer/
  );
  await assert.rejects(
    () => client.prepareTransfer({
      material: heartbeatTestMaterial(),
      amount: "1uclair",
      recipient: "clairs1recipient",
      proverAdapter: null
    }),
    /chainNowUnix is required from authoritative chain time/
  );
});

test("browser EVM prepareTransfer returns its transaction with reconciliation warning after a final heartbeat failure", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair",
    evmChainId: "0x7a69",
    evmPrivacyPrecompileAddress: "0x0000000000000000000000000000000000000900"
  });
  client.privacyMaterial = heartbeatTestMaterial;
  client.proverAdapter = () => null;
  client.cosmos.scanNotes = async () => heartbeatTestScanResult();
  client.cosmos.assertTransferProtocolConfig = async () => transferProtocolConfig();
  client.cosmos.buildTransferMessage = async () => heartbeatTestBuiltTransfer();
  client.proverAdapter = () => null;
  client.evm.buildTransferTransaction = async input => ({
    status: "ready",
    message: input.message,
    payload: input.payload,
    proof: input.proof,
    transaction: {
      to: evmPrivacyPrecompileAddress,
      data: "0x1234"
    }
  });

  const store = new MemoryReservationStore();
  const reservationManager = heartbeatFailureReservationManager(store, "chain:clair1browser-heartbeat");

  const prepared = await client.prepareTransfer({
    walletType: "evm",
    address: "clair1sender",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1uclair",
    recipient: "clairs1recipient",
    chainNowUnix: 1_700_000_000,
    expiresAtUnix: 1_700_001_800,
    reservationManager
  });
  assert.equal(prepared.transaction.data, "0x1234");
  assert.ok(prepared.prepared.proof);
  assert.equal(prepared.reservationReconciliationRequired, true);
  assert.equal(
    prepared.reservationReconciliationWarning.code,
    "reservation_heartbeat_failed_after_proof_ready"
  );

  const reservations = (await store.load()).reservations;
  assert.equal(reservations.length > 0, true);
  assert.equal(reservations.every(reservation => reservation.status === reservationStatuses.ProofReady), true);
});

test("cosmos prepareWithdraw resolves expiry and chain-time aliases without a reservation manager", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  client.assertProtocolPreflight = async () => ({});
  client.scanNotes = async () => heartbeatTestScanResult();
  let capturedWithdrawInput = null;
  client.buildWithdrawMessage = async input => {
    capturedWithdrawInput = input;
    return heartbeatTestBuiltWithdraw(input);
  };
  client.buildDirectSignDoc = async input => input;

  const prepared = await client.prepareWithdraw({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient: "clair1recipient",
    proverAdapter: null,
    expires_at_unix: 4_102_448_400,
    chain_now_unix: 4_102_444_800
  });

  assert.equal(prepared.status, "ready");
  assert.equal(capturedWithdrawInput.expiresAtUnix, 4_102_448_400);
  assert.equal(capturedWithdrawInput.chainNowUnix, 4_102_444_800);
  assert.equal(prepared.reservation, null);

  await assert.rejects(() => client.prepareWithdraw({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient: "clair1recipient",
    proverAdapter: null,
    expiresAtUnix: 4_102_448_400,
    expires_at_unix: 4_102_448_401,
    chainNowUnix: 4_102_444_800
  }), /expiresAtUnix aliases conflict/);
  await assert.rejects(() => client.prepareWithdraw({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient: "clair1recipient",
    proverAdapter: null,
    expiresAtUnix: 4_102_448_400,
    chainNowUnix: 4_102_444_800,
    chain_now_unix: 4_102_444_801
  }), /chainNowUnix aliases conflict/);
  await assert.rejects(() => client.prepareRelayWithdraw({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient: "clair1recipient",
    proverAdapter: null,
    expiresAtUnix: 4_102_448_400,
    expires_at_unix: 4_102_448_401,
    chainNowUnix: 4_102_444_800
  }), /expiresAtUnix aliases conflict/);
  await assert.rejects(() => client.prepareRelayWithdraw({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient: "clair1recipient",
    proverAdapter: null,
    expiresAtUnix: 4_102_448_400,
    chainNowUnix: 4_102_444_800,
    chain_now_unix: 4_102_444_801
  }), /chainNowUnix aliases conflict/);
});

test("reserved Cosmos withdraw snapshots caller fees and binds transparent success evidence", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  client.assertProtocolPreflight = async () => ({});
  client.scanNotes = async () => heartbeatTestScanResult();
  client.buildWithdrawMessage = async input => heartbeatTestBuiltWithdraw(input);
  let capturedSignDocInput = null;
  client.buildDirectSignDoc = async input => {
    capturedSignDocInput = input;
    return { bodyBytes: "", authInfoBytes: "", chainId: "clairveil-local-3", accountNumber: "0" };
  };
  const store = new MemoryReservationStore();
  const reservationManager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1withdraw-owner",
    indexKey: "withdraw-index-key"
  });
  const recipient = toBech32("clair", new Uint8Array(20).fill(7));
  const feeAmount = [{ denom: "uclair", amount: "125000" }];

  const prepared = await client.prepareWithdraw({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient,
    proverAdapter: null,
    chainNowUnix: 4_102_444_800,
    gas_limit: 5_123_456,
    feeAmount,
    reservationManager
  });
  feeAmount[0].amount = "999999";

  assert.equal(capturedSignDocInput.gasLimit, 5_123_456);
  assert.deepEqual(capturedSignDocInput.feeAmount, [{ denom: "uclair", amount: "125000" }]);
  const ready = await store.getReservation(prepared.reservation.reservation_ids[0]);
  assert.equal(ready.status, reservationStatuses.ProofReady);
  assert.equal(
    ready.expected_recipient_hash,
    hashTransparentRecipient(recipient, { accountPrefix: "clair" })
  );
  assert.equal(ready.expected_amount, "1");
  assert.equal(ready.expected_amount_hash, hashAmount("uclair", "1"));
  assert.equal(ready.expected_denom, "uclair");
  assert.equal(ready.metadata.operation_success_evidence_required, true);
});

test("reserved Cosmos relay withdraw binds transparent success evidence before handoff", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  client.assertProtocolPreflight = async () => ({});
  client.scanNotes = async () => heartbeatTestScanResult();
  client.buildRelayWithdrawPayload = async input => heartbeatTestBuiltWithdraw(input);
  const store = new MemoryReservationStore();
  const reservationManager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1relay-withdraw-owner",
    indexKey: "relay-withdraw-index-key"
  });
  const recipient = toBech32("clair", new Uint8Array(20).fill(11));

  const prepared = await client.prepareRelayWithdraw({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient,
    proverAdapter: null,
    chainNowUnix: 4_102_444_800,
    expiresAtUnix: 4_102_448_400,
    reservationManager
  });

  const ready = await store.getReservation(prepared.reservation.reservation_ids[0]);
  assert.equal(ready.status, reservationStatuses.ProofReady);
  assert.equal(
    ready.expected_recipient_hash,
    hashTransparentRecipient(recipient, { accountPrefix: "clair" })
  );
  assert.equal(ready.expected_amount, "1");
  assert.equal(ready.expected_amount_hash, hashAmount("uclair", "1"));
  assert.equal(ready.expected_denom, "uclair");
  assert.equal(ready.metadata.operation_success_evidence_required, true);
});

test("reserved Cosmos withdraw snapshots caller fees and binds transparent success evidence", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  client.assertProtocolPreflight = async () => ({});
  client.scanNotes = async () => heartbeatTestScanResult();
  client.buildWithdrawMessage = async input => heartbeatTestBuiltWithdraw(input);
  let capturedSignDocInput = null;
  client.buildDirectSignDoc = async input => {
    capturedSignDocInput = input;
    return { bodyBytes: "", authInfoBytes: "", chainId: "clairveil-local-3", accountNumber: "0" };
  };
  const store = new MemoryReservationStore();
  const reservationManager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1withdraw-owner",
    indexKey: "withdraw-index-key"
  });
  const recipient = toBech32("clair", new Uint8Array(20).fill(7));
  const feeAmount = [{ denom: "uclair", amount: "125000" }];

  const prepared = await client.prepareWithdraw({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient,
    proverAdapter: null,
    chainNowUnix: 4_102_444_800,
    gas_limit: 5_123_456,
    feeAmount,
    reservationManager
  });
  feeAmount[0].amount = "999999";

  assert.equal(capturedSignDocInput.gasLimit, 5_123_456);
  assert.deepEqual(capturedSignDocInput.feeAmount, [{ denom: "uclair", amount: "125000" }]);
  const reservationID = prepared.reservation.reservation_ids[0];
  const ready = await store.getReservation(reservationID);
  assert.equal(ready.status, reservationStatuses.ProofReady);
  assert.equal(ready.expected_recipient_hash, hashTransparentRecipient(recipient, { accountPrefix: "clair" }));
  assert.equal(ready.expected_amount, "1");
  assert.equal(ready.expected_amount_hash, hashAmount("uclair", "1"));
  assert.equal(ready.expected_denom, "uclair");
  assert.equal(ready.expected_output_commitment, "");
  assert.equal(ready.expected_disclosure_digest, "");
  assert.equal(ready.metadata.operation_success_evidence_required, true);

  await reservationManager.markBroadcastAttempting(prepared.reservation.reservation_ids, {
    leaseToken: prepared.reservation.lease_token,
    txHash: "EXPECTED-WITHDRAW-TX"
  });
  await reservationManager.reconcileSpentNotes([{
    ...prepared.selectedNote,
    isSpent: true,
    operationSuccessEvidence: {
      txHash: "OTHER-WITHDRAW-TX",
      txResult: { code: 0 },
      recipientHash: ready.expected_recipient_hash,
      amount: "1",
      amountHash: ready.expected_amount_hash,
      denom: "uclair"
    }
  }]);
  const conflicted = await store.getReservation(reservationID);
  assert.equal(conflicted.status, reservationStatuses.ConfirmedSpent);
  assert.equal(conflicted.metadata.operation_status, operationStatuses.ConflictSpent);
  assert.equal(conflicted.metadata.operation_success_evidence_matches, false);
});

test("reserved Cosmos relay withdraw binds transparent success evidence before handoff", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  client.assertProtocolPreflight = async () => ({});
  client.scanNotes = async () => heartbeatTestScanResult();
  client.buildRelayWithdrawPayload = async input => heartbeatTestBuiltWithdraw(input);
  const store = new MemoryReservationStore();
  const reservationManager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1relay-withdraw-owner",
    indexKey: "relay-withdraw-index-key"
  });
  const recipient = toBech32("clair", new Uint8Array(20).fill(11));

  const prepared = await client.prepareRelayWithdraw({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient,
    proverAdapter: null,
    chainNowUnix: 4_102_444_800,
    expiresAtUnix: 4_102_448_400,
    reservationManager
  });

  assert.equal(prepared.status, "ready");
  const ready = await store.getReservation(prepared.reservation.reservation_ids[0]);
  assert.equal(ready.status, reservationStatuses.ProofReady);
  assert.equal(ready.expected_recipient_hash, hashTransparentRecipient(recipient, { accountPrefix: "clair" }));
  assert.equal(ready.expected_amount, "1");
  assert.equal(ready.expected_amount_hash, hashAmount("uclair", "1"));
  assert.equal(ready.expected_denom, "uclair");
  assert.equal(ready.expected_output_commitment, "");
  assert.equal(ready.expected_disclosure_digest, "");
  assert.equal(ready.metadata.operation_success_evidence_required, true);
});

test("browser Cosmos prepareWithdraw exposes broadcast validation artifacts", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair"
  });
  client.privacyMaterial = heartbeatTestMaterial;
  client.proverAdapter = () => null;
  const built = heartbeatTestBuiltWithdraw({ amount: "1uclair", recipient: "clair1recipient" });
  let receivedWithdrawInput = null;
  client.cosmos.prepareWithdraw = async input => {
    receivedWithdrawInput = input;
    return ({
    status: "ready",
    signDoc: { bodyBytes: "", authInfoBytes: "", chainId: "clairveil-local-3", accountNumber: "0" },
    reservation: null,
    privacyAccount: { shielded_address: "clairs1sender" },
    plan: { status: "withdraw_ready" },
    ...built
    });
  };
  const prepared = await client.prepareWithdraw({
    walletType: "cosmos",
    address: "clair1sender",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1uclair",
    recipient: "clair1recipient",
    gas_limit: 5123456,
    fee_amount: [{ denom: "uclair", amount: "125000" }]
  });
  assert.equal(prepared.payload, built.payload);
  assert.equal(prepared.proof, built.proof);
  assert.equal(prepared.message, built.message);
  assert.equal(receivedWithdrawInput.gasLimit, 5123456);
  assert.deepEqual(receivedWithdrawInput.feeAmount, [{ denom: "uclair", amount: "125000" }]);
  assert.equal(receivedWithdrawInput.fee_amount, undefined);
});

test("browser EVM prepareWithdraw works without a reservation manager and forwards chain time", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair",
    evmChainId: "0x7a69",
    evmPrivacyPrecompileAddress: "0x0000000000000000000000000000000000000900"
  });
  client.privacyMaterial = heartbeatTestMaterial;
  client.cosmos.assertProtocolPreflight = async () => ({});
  client.cosmos.scanNotes = async () => heartbeatTestScanResult();
  client.proverAdapter = () => null;
  let capturedChainNowUnix = null;
  client.cosmos.buildWithdrawMessage = async input => {
    capturedChainNowUnix = input.chainNowUnix;
    return heartbeatTestBuiltWithdraw(input);
  };
  client.evm.contract.buildWithdrawTransaction = () => ({
    to: testPrivacyContractAddress,
    data: "0x1234"
  });

  const prepared = await client.prepareWithdraw({
    walletType: "evm",
    address: "clair1sender",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1uclair",
    recipient: "clair1recipient",
    chainNowUnix: 4_102_444_800
  });

  assert.equal(prepared.transaction.data, "0x1234");
  assert.equal(capturedChainNowUnix, 4_102_444_800);
  assert.equal(prepared.reservation, null);
  assert.equal(prepared.payload.payload_hash, "payload-withdraw-no-reservation");
  assert.equal(prepared.proof.payload_hash, prepared.payload.payload_hash);
  assert.deepEqual(prepared.message.proof, new Uint8Array([1]));
});

function heartbeatTestMaterial() {
  return {
    rootSeed: new Uint8Array(32),
    address: "clair1sender",
    pubKeyHex: "02".padEnd(66, "0"),
    shieldedAddress: "clairs1sender"
  };
}

function heartbeatTestScanResult() {
  const note = (amount, randomness, height) => ({
    note: createNote({
      spendPubKey: CURVE_BASE,
      viewPubKey: CURVE_BASE,
      amount,
      assetDenom: "uclair",
      randomness
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: `TX-HEARTBEAT-${height}`,
    height
  });
  return {
    notes: [],
    summary: { total_spendable: "1", spendable_count: 2, spent_count: 0, total_count: 2 },
    diagnostics: { scanned_events: 0, new_notes_found: 0 },
    foundNotes: [note(0n, 301n, 301), note(1n, 302n, 302)],
    scanCursor: { has_more: false }
  };
}

function heartbeatTestBuiltWithdraw(input) {
  const payload = {
    payload_hash: "payload-withdraw-no-reservation",
    nullifier_hex: "01".repeat(32),
    amount: input.amount,
    recipient: input.recipient,
    expires_at_unix: 4_102_448_400
  };
  return {
    payload,
    proof: {
      payload_hash: payload.payload_hash,
      proof_hex: "01"
    },
    message: {
      proof: new Uint8Array([1])
    },
    selectedNote: heartbeatTestScanResult().foundNotes[1]
  };
}

function heartbeatTestBuiltTransfer() {
  return {
    payload: {
      payload_hash: "payload-heartbeat",
      inputs: heartbeatTestScanResult().foundNotes.map(found => ({
        nullifier_hex: normalizeFoundNote(found).nullifier
      })),
      outputs: [{ amount: "1", commitment_hex: "commitment-heartbeat" }],
      audit_disclosure_digest_hex: "audit-digest-heartbeat",
      expires_at_unix: 1_700_001_800
    },
    proof: { payload_hash: "payload-heartbeat", proof_hex: "01" },
    message: {
      proof: new Uint8Array([1]),
      expiresAtUnix: 1_700_001_800n
    }
  };
}

function heartbeatFailureReservationManager(store, ownerKeyId) {
  const manager = createNoteReservationManager({
    store,
    ownerKeyId,
    indexKey: "index-key-v1",
    leaseDurationMs: 1000
  });
  const renewLease = manager.renewLease.bind(manager);
  let renewCalls = 0;
  manager.renewLease = async (...args) => {
    renewCalls += 1;
    if (renewCalls >= 3) throw new Error("injected final heartbeat failure");
    return renewLease(...args);
  };
  const markProofReady = manager.markProofReady.bind(manager);
  manager.markProofReady = async (...args) => {
    const result = await markProofReady(...args);
    await new Promise(resolve => setTimeout(resolve, 350));
    return result;
  };
  return manager;
}

test("Cosmos prepareTransfer rejects empty operation evidence assertions before scanning", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  await assert.rejects(
    () => client.prepareTransfer({
      amount: "1uclair",
      recipient: "clairs1recipient",
      expectedRecipientHash: "",
      expectedAmountHash: ""
    }),
    /expectedRecipientHash must not be empty/
  );
});

test("planner selects one aggregate input witness for batch transfer", () => {
  const note = (amount, randomness, height) => ({
    note: createNote({
      spendPubKey: CURVE_BASE,
      viewPubKey: CURVE_BASE,
      amount,
      assetDenom: "uclair",
      randomness
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: `TX${height}`,
    height
  });
  const plan = planTransferBatchNotes({
    notes: [
      note(0, 1, 1),
      note(0, 2, 2),
      note(5, 3, 3),
      note(7, 4, 4)
    ],
    amounts: ["5uclair", "7uclair"],
    denom: "uclair"
  });

  assert.equal(plan.status, "batch_transfer_ready");
  assert.equal(plan.canBuildTx, true);
  assert.equal(plan.action, "build_one_proof_batch_transfer");
  assert.equal(plan.selections.length, 1);
  assert.equal(plan.selection.inputs.length, 2);
  assert.equal(plan.selection.total, 12n);
});

test("planner finds one bounded witness for a larger batch payment list", () => {
  const note = (amount, randomness, height) => ({
    note: createNote({
      spendPubKey: CURVE_BASE,
      viewPubKey: CURVE_BASE,
      amount,
      assetDenom: "uclair",
      randomness
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: `TX${height}`,
    height
  });
  const noteAmounts = [4, 8, 4, 4, 9, 20, 13, 6, 10, 2, 17, 4, 8, 10, 4, 20, 19, 2, 2, 3, 2, 11, 12, 7, 11, 1, 1];
  const targetAmounts = [10, 19, 14, 3, 20, 11, 16, 8, 9, 18, 10, 17, 19];

  const plan = planTransferBatchNotes({
    notes: noteAmounts.map((amount, index) => note(amount, index + 1, index + 1)),
    amounts: targetAmounts.map(amount => `${amount}uclair`),
    denom: "uclair"
  });

  assert.equal(plan.status, "batch_transfer_ready");
  assert.equal(plan.selections.length, 1);
  assert.equal(plan.selection.isFinal, true);
  assert.ok(plan.selection.inputs.length <= 16);
  assert.ok(plan.selection.total >= BigInt(targetAmounts.reduce((sum, amount) => sum + amount, 0)));
});

test("planner sorts spendable notes before batch candidate search", () => {
  const note = (amount, randomness, height) => ({
    note: createNote({
      spendPubKey: CURVE_BASE,
      viewPubKey: CURVE_BASE,
      amount,
      assetDenom: "uclair",
      randomness
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: `TX${height}`,
    height
  });
  const summary = summarizeSpendableNotesByDenom([
    note(7, 1, 1),
    note(0, 2, 2),
    note(5, 3, 3),
    note(0, 4, 4),
    note(1, 5, 5)
  ], "uclair");

  assert.deepEqual(
    summary.notes.map(found => found.note.amount.toString()),
    ["0", "0", "1", "5", "7"]
  );
});

test("planner does not propose overflow self-merge notes", () => {
  const maxShieldedAmount = (1n << 64n) - 1n;
  const note = (amount, randomness, height) => ({
    note: createNote({
      spendPubKey: CURVE_BASE,
      viewPubKey: CURVE_BASE,
      amount,
      assetDenom: "uclair",
      randomness
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: `TX${height}`,
    height
  });
  const plan = planTransferNotes({
    notes: [
      note(maxShieldedAmount, 1, 1),
      note(maxShieldedAmount, 2, 2)
    ],
    amount: "1uclair",
    denom: "uclair"
  });

  assert.equal(plan.status, "zero_dummy_required");
  assert.equal(plan.selection.total, 0n);
});

test("planner batch transfer uses bounded candidates for large note sets", () => {
  const note = (amount, randomness, height) => ({
    note: createNote({
      spendPubKey: CURVE_BASE,
      viewPubKey: CURVE_BASE,
      amount,
      assetDenom: "uclair",
      randomness
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: `TX${height}`,
    height
  });
  const notes = [
    note(0, 1, 1),
    ...Array.from({ length: 40 }, (_, index) => note(1n + BigInt(index), index + 2, index + 2)),
    note(100, 90, 90),
    note(101, 91, 91),
    note(102, 92, 92),
    note(103, 93, 93),
    note(104, 94, 94),
    note(105, 95, 95),
    note(106, 96, 96),
    note(107, 97, 97)
  ];

  const plan = planTransferBatchNotes({
    notes,
    amounts: ["100uclair", "101uclair", "102uclair", "103uclair"],
    denom: "uclair"
  });

  assert.equal(plan.status, "batch_transfer_ready");
  assert.equal(plan.selections.length, 1);
  assert.equal(plan.selection.isFinal, true);
  assert.ok(plan.selection.inputs.length <= 16);
  assert.ok(plan.selection.total >= 406n);
});

test("planner permits aggregate batch totals above uint64 when every note and change remain valid", () => {
  const maxShieldedAmount = (1n << 64n) - 1n;
  const note = (amount, randomness, height) => ({
    note: createNote({
      spendPubKey: CURVE_BASE,
      viewPubKey: CURVE_BASE,
      amount,
      assetDenom: "uclair",
      randomness
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: `TX${height}`,
    height
  });
  const plan = planTransferBatchNotes({
    notes: [
      note(maxShieldedAmount, 1, 1),
      note(1, 2, 2)
    ],
    amounts: [`${maxShieldedAmount}uclair`, "1uclair"],
    denom: "uclair"
  });

  assert.equal(plan.status, "batch_transfer_ready");
  assert.equal(plan.selection.inputs.length, 2);
  assert.equal(plan.selection.total, maxShieldedAmount + 1n);
});

test("planner considers notes beyond an arbitrary 48-note prefix for exact-32 batches", () => {
  const note = (amount, randomness, height) => ({
    note: createNote({
      spendPubKey: CURVE_BASE,
      viewPubKey: CURVE_BASE,
      amount,
      assetDenom: "uclair",
      randomness,
      memo: `candidate-${height}`
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: `TX${height}`,
    height
  });
  const notes = [
    ...Array.from({ length: 48 }, (_, index) => note(99n, BigInt(index + 1), index + 1)),
    note(1n, 100n, 100)
  ];
  const plan = planTransferBatchNotes({
    notes,
    amounts: [...Array(31).fill("3uclair"), "7uclair"],
    denom: "uclair"
  });

  assert.equal(plan.status, "batch_transfer_ready");
  assert.equal(plan.selection.total, 100n);
  assert.deepEqual(plan.selection.inputs.map(found => found.note.amount), [1n, 99n]);
});

test("planner rejects a batch payment above the uint64 NoteV1 amount bound", () => {
  const maxShieldedAmount = (1n << 64n) - 1n;
  const plan = planTransferBatchNotes({
    notes: [],
    amounts: [`${maxShieldedAmount + 1n}uclair`],
    denom: "uclair"
  });

  assert.equal(plan.status, "invalid_amount");
  assert.equal(plan.canBuildTx, false);
});

test("one-proof batch transfer stays disabled until the downstream release gate is explicitly enabled", async () => {
  const client = cosmosTestClient();

  await assert.rejects(
    () => client.prepareTransferBatch({
      material: {},
      amounts: ["1uclair"],
      recipient: "clairs1recipient",
      proverAdapter: {}
    }),
    /one-proof batch transfer is feature-gated/
  );
  await assert.rejects(
    () => client.provePreparedBatchTransfer({
      payload: {},
      proverAdapter: {}
    }),
    /one-proof batch transfer is feature-gated/
  );
  await assert.rejects(
    () => client.createBatchTransferSignDoc({
      signer: "clair1sender",
      pubKeyHex: "02".repeat(33),
      gasLimit: 1,
      message: {}
    }),
    /one-proof batch transfer is feature-gated/
  );
});

test("one-proof batch transfer rejects conflicting safety aliases before scan or proving", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    enableExperimentalBatchTransfer: true
  });
  let scanCalls = 0;
  client.scanNotes = async () => {
    scanCalls += 1;
    throw new Error("scan must not be called for conflicting aliases");
  };
  const conflicts = [
    [{ gasLimit: 1, gas_limit: 2 }, /gasLimit aliases conflict/],
    [{
      feeAmount: [{ denom: "uclair", amount: "1" }],
      fee_amount: [{ denom: "uclair", amount: "2" }]
    }, /feeAmount aliases conflict/],
    [{ outputMode: "compact", output_mode: "exact32" }, /outputMode aliases conflict/],
    [{
      feeAmount: [{ denom: "uclair", amount: "1" }],
      fee_amount: [{ denom: "uclair", amount: "2" }]
    }, /feeAmount aliases conflict/],
    [{ chainNowUnix: 1, chain_now_unix: 2 }, /chainNowUnix aliases conflict/],
    [{ expiresAtUnix: 3, expires_at_unix: 4 }, /expiresAtUnix aliases conflict/],
    [{ rootHex: "01".repeat(32), root_hex: "02".repeat(32) }, /rootHex aliases conflict/],
    [{ snapshotHeight: 5, snapshot_height: 6 }, /snapshotHeight aliases conflict/],
    [{
      inputCommitmentHexes: ["01".repeat(32)],
      input_commitment_hexes: ["02".repeat(32)]
    }, /inputCommitmentHexes aliases conflict/],
    [{ disableSelfViewDisclosure: true, disable_self_view_disclosure: false }, /disableSelfViewDisclosure aliases conflict/],
    [{
      selfViewDisclosureTargetPubKeyHex: "03".repeat(32),
      self_view_disclosure_target_pubkey: "04".repeat(32)
    }, /selfViewDisclosureTargetPubKeyHex aliases conflict/]
  ];
  for (const [input, expected] of conflicts) {
    await assert.rejects(() => client.prepareTransferBatch(input), expected);
  }
  await assert.rejects(
    () => client.prepareTransferBatch({ disableSelfViewDisclosure: "false" }),
    /disableSelfViewDisclosure must be a boolean/
  );
  assert.equal(scanCalls, 0);
});

test("cosmos prepareTransferBatch builds one mixed-disclosure exact-32 MsgBatchTransfer and supports staged resume", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair",
    enableExperimentalBatchTransfer: true
  });
  const activeTransferProtocolConfig = transferProtocolConfig({
    policies: ["all-private", "amount", "to"],
    modes: ["none", "public", "recipient-encrypted"]
  });
  client.assertTransferProtocolConfig = async () => activeTransferProtocolConfig;
  const rootSeed = new Uint8Array(32);
  const ownerSpend = deriveSpendKeys(rootSeed).pubKey;
  const ownerView = deriveViewKeys(rootSeed).pubKey;
  const recipients = [3, 4, 5].map(fill => {
    const recipientRootSeed = new Uint8Array(32).fill(fill);
    return encodeShieldedAddress(
      deriveSpendKeys(recipientRootSeed).pubKey,
      deriveViewKeys(recipientRootSeed).pubKey,
      { shieldedPrefix: "clairs" }
    );
  });
  const note = (amount, randomness, height) => ({
    note: createNote({
      spendPubKey: ownerSpend,
      viewPubKey: ownerView,
      amount,
      assetDenom: "uclair",
      randomness
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: `TX${height}`,
    height
  });
  const inputNotes = [note(5, 3, 3), note(7, 4, 4), note(9, 5, 5)];
  const inputCommitments = inputNotes.map(found =>
    fieldHexV1(computeNoteCommitmentV1(found.note)));
  const merklePathProvider = strictMerklePathProvider(inputNotes.map(found => found.note));
  const rootHex = (await merklePathProvider.lookupMerklePath(
    inputCommitments[0]
  )).root;
  const chainNowUnix = Math.floor(Date.now() / 1000);
  client.scanNotes = async () => ({
    notes: [],
    summary: { total_spendable: "21", spendable_count: 3, spent_count: 0, total_count: 3 },
    diagnostics: { scanned_events: 0, new_notes_found: 0 },
    foundNotes: inputNotes,
    scanCursor: { source: "privacy_scan", has_more: false }
  });
  let snapshotRequest = null;
  client.fetchTreeState = async () => ({ root: rootHex });
  client.createCommitmentPathSnapshotProvider = async input => {
    snapshotRequest = input;
    return merklePathProvider;
  };
  client.checkNullifiers = async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false]));
  let proveBatchTransferCalls = 0;
  const checkpointOrder = [];
  let checkpointedPayload = null;
  let checkpointedProof = null;
  const proverAdapter = {
    async proveBatchTransfer(payload) {
      checkpointOrder.push("prove");
      proveBatchTransferCalls += 1;
      return {
        version: "v1",
        proof: {
          version: "batch-transfer-proof-v1",
          request_payload_hash: payload.payload_hash,
          proof: Buffer.from(new Uint8Array(164).fill(7)).toString("base64"),
          circuit_set_id: "privacy-note-v1"
        }
      };
    }
  };
  client.buildDirectSignDoc = async input => ({
    ...input,
    bodyBytes: Buffer.from(client.registry.encodeTxBody({
      messages: input.messages,
      memo: input.memo
    })).toString("base64"),
    authInfoBytes: "",
    chainId: "clairveil-local-3",
    accountNumber: "0"
  });
  const store = new MemoryReservationStore();
  const reservationManager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1sender",
    indexKey: "index-key-v1"
  });
  const safetyInput = {
    material: {
      rootSeed,
      address: "clair1sender",
      pubKeyHex: "02".padEnd(66, "0"),
      shieldedAddress: "clairs1sender"
    },
    amounts: ["12uclair"],
    recipient: recipients[0],
    proverAdapter,
    rootHex,
    snapshotHeight: 3,
    chainNowUnix,
    expiresAtUnix: chainNowUnix + 1_800
  };
  await assert.rejects(
    () => client.prepareTransferBatch({
      ...safetyInput,
      onPreparedPayload() {},
      onPreparedProof() {}
    }),
    /requires a reservationManager/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      ...safetyInput,
      rootHex: undefined
    }),
    /rootHex and snapshotHeight must be supplied together/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      ...safetyInput,
      reservationManager,
      onPreparedProof() {}
    }),
    /requires onPreparedPayload/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      ...safetyInput,
      reservationManager,
      onPreparedPayload() {}
    }),
    /requires onPreparedProof/
  );

  const batchPayments = [
    {
      itemId: "private-payment",
      amount: "4uclair",
      recipient: recipients[0],
      userPrivacyPolicy: "all-private",
      userDisclosureMode: "none"
    },
    {
      itemId: "public-amount-payment",
      amount: "5uclair",
      recipient: recipients[1],
      userPrivacyPolicy: "amount",
      userDisclosureMode: "public"
    },
    {
      itemId: "recipient-encrypted-payment",
      amount: "6uclair",
      recipient: recipients[2],
      userPrivacyPolicy: "to",
      userDisclosureMode: "recipient-encrypted",
      userDisclosureTargetPubKeyHex: Buffer.from(packPoint(CURVE_BASE)).toString("hex")
    }
  ];
  const batchFee = [{ denom: "uclair", amount: "23" }];
  const result = await client.prepareTransferBatch({
    material: {
      rootSeed,
      address: "clair1sender",
      pubKeyHex: "02".padEnd(66, "0"),
      shieldedAddress: "clairs1sender"
    },
    payments: batchPayments,
    outputMode: "exact32",
    inputCommitmentHexes: inputCommitments,
    proverAdapter,
    gas_limit: 26000000,
    fee_amount: batchFee,
    audit_disclosure_target_pubkey_hex: activeTransferProtocolConfig.audit_config.audit_master_pubkey_hex,
    chainNowUnix,
    expiresAtUnix: chainNowUnix + 1_800,
    feeAmount: [{ denom: "uclair", amount: "23" }],
    reservation_manager: reservationManager,
    async onPreparedPayload(payload) {
      checkpointOrder.push("payload");
      checkpointedPayload = payload;
      batchFee[0].amount = "999";
      batchFee.push({ denom: "ustale", amount: "1" });
    },
    async onPreparedProof(proof) {
      checkpointOrder.push("proof");
      checkpointedProof = proof;
    }
  });

  assert.equal(result.status, "ready");
  assert.equal(proveBatchTransferCalls, 1);
  assert.deepEqual(checkpointOrder, ["payload", "prove", "proof"]);
  assert.equal(checkpointedPayload.payload_hash, result.payload.payload_hash);
  assert.equal(checkpointedProof.request_payload_hash, result.payload.payload_hash);
  assert.equal(result.signDoc.messages.length, 1);
  assert.deepEqual(result.signDoc.feeAmount, [{ denom: "uclair", amount: "23" }]);
  assert.equal(result.signDoc.messages[0].typeUrl, MsgBatchTransfer.typeUrl);
  assert.equal(result.signDoc.gasLimit, 26000000);
  assert.deepEqual(result.signDoc.feeAmount, [{ denom: "uclair", amount: "23" }]);
  assert.equal(result.message.nullifiers.length, 1);
  assert.equal(result.message.outputs.length, 32);
  const persistedReservations = await store.listReservations({
    ownerKeyId: "chain:clair1sender"
  });
  assert.equal(persistedReservations.length, 3);
  assert.equal(persistedReservations.every(reservation =>
    reservation.metadata.circuit_set_id === "privacy-note-v1"), true);
  assert.equal(snapshotRequest.rootHex, rootHex);
  assert.equal("snapshotHeight" in snapshotRequest, false);
  assert.deepEqual(result.payload.outputs.slice(0, 3).map(output => output.kind), [
    "payment",
    "payment",
    "payment"
  ]);
  assert.equal(result.payload.outputs[3].kind, "change");
  assert.equal(result.payload.outputs[3].note.am, "6");
  assert.equal(result.payload.outputs.slice(4).every(output => output.kind === "padding"), true);
  // The alternate execution builder must see the exact same proof-stage
  // artifacts before the reservation transition, but bind an EVM transaction
  // hash rather than a Cosmos sign-doc hash.
  const proveCallsBeforeExecutionBuilder = proveBatchTransferCalls;
  const executionStore = new MemoryReservationStore();
  const executionReservationManager = createNoteReservationManager({
    store: executionStore,
    ownerKeyId: "chain:clair1execution",
    indexKey: "index-key-v1"
  });
  const executionEvmClient = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
    chainId: "clairveil-local-3",
    evmChainId: "0x539",
    accountPrefix: "clair",
    defaultDenom: "uclair",
    nativeDenom: "uclair"
  });
  let executionInput = null;
  const executionResult = await client.prepareTransferBatch({
    ...safetyInput,
    reservationManager: executionReservationManager,
    async onPreparedPayload() {},
    async onPreparedProof() {},
    async executionBuilder(input) {
      executionInput = input;
      const evmBuilt = executionEvmClient.buildSingleProofBatchTransferTransaction({
        message: input.message
      });
      const transaction = markEvmTransactionReservationRequired({
        chainId: "0x539",
        gas: "0x989680",
        ...evmBuilt.transaction
      });
      return {
        executionTransport: "evm",
        transaction,
        txBytesHash: evmTransactionBindingHash(transaction)
      };
    }
  });
  assert.equal(executionResult.signDoc, undefined);
  assert.equal(
    executionResult.execution.txBytesHash,
    evmTransactionBindingHash(executionResult.execution.transaction)
  );
  assert.equal(executionInput.message.outputs.length, 1);
  assert.equal(executionInput.operationEvidence.expected_outputs.length, 1);
  assert.equal(proveBatchTransferCalls, proveCallsBeforeExecutionBuilder + 1);
  const executionReservations = await executionStore.listReservations({
    ownerKeyId: "chain:clair1execution"
  });
  assert.equal(
    executionReservations[0].tx_bytes_hash,
    evmTransactionBindingHash(executionResult.execution.transaction)
  );
  assert.equal(executionReservations[0].metadata.execution_transport, "evm");
  const submittedHash = await executionEvmClient.sendTransaction({
    async getChainId() { return "0x539"; },
    async sendTransaction(transaction) {
      assert.equal(transaction.data, executionResult.execution.transaction.data);
      return `0x${"aa".repeat(32)}`;
    }
  }, executionResult.execution.transaction, {
    reservationManager: executionReservationManager,
    reservation: executionResult.reservation,
    checkNullifiers: async nullifiers => new Map(
      nullifiers.map(nullifier => [nullifier, false])
    )
  });
  assert.equal(submittedHash, `0x${"aa".repeat(32)}`);
  const mismatchReservationManager = createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "chain:clair1sender-mismatch",
    indexKey: "index-key-v1"
  });
  await assert.rejects(
    () => client.prepareTransferBatch({
      material: {
        rootSeed,
        address: "clair1sender",
        pubKeyHex: "02".padEnd(66, "0"),
        shieldedAddress: "clairs1sender"
      },
      payments: [{
        amount: "12uclair",
        recipient: recipients[0],
        expectedRecipientHash: "00".repeat(32)
      }],
      proverAdapter,
      rootHex,
      snapshotHeight: 3,
      chainNowUnix,
      expiresAtUnix: chainNowUnix + 1_800,
      reservationManager: mismatchReservationManager,
      onPreparedPayload() {},
      onPreparedProof() {}
    }),
    /expected recipient hash does not match its recipient/
  );
  assert.equal(proveBatchTransferCalls, proveCallsBeforeExecutionBuilder + 1);
  const serializedReservedSignDoc = JSON.parse(JSON.stringify(
    result.signDoc,
    (_key, value) => typeof value === "bigint" ? value.toString() : value
  ));
  let directBroadcastCalls = 0;
  client.connect = async () => {
    directBroadcastCalls += 1;
    return { broadcastTxSync: async () => "UNREACHABLE" };
  };
  await assert.rejects(
    () => client.broadcastSignedTx({
      ...serializedReservedSignDoc,
      signature: ""
    }),
    /requires reservationManager and reservation/
  );
  assert.equal(directBroadcastCalls, 0);
  await assert.rejects(
    () => client.broadcastSignedTx({
      bodyBytes: result.signDoc.bodyBytes,
      authInfoBytes: result.signDoc.authInfoBytes,
      signature: ""
    }),
    /requires reservationManager and reservation/
  );
  assert.equal(directBroadcastCalls, 0);
  const reloadedClient = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  let reloadedBroadcastCalls = 0;
  reloadedClient.connect = async () => {
    reloadedBroadcastCalls += 1;
    return { broadcastTxSync: async () => "UNREACHABLE" };
  };
  await assert.rejects(
    () => reloadedClient.broadcastSignedTx({
      bodyBytes: result.signDoc.bodyBytes,
      authInfoBytes: result.signDoc.authInfoBytes,
      signature: ""
    }),
    /requires reservationManager and reservation/
  );
  assert.equal(reloadedBroadcastCalls, 0);
  let signCalls = 0;
  await assert.rejects(
    () => client.signDirectAndBroadcast({
      wallet: {
        async signDirect() {
          signCalls += 1;
          throw new Error("signing should not be reached");
        }
      },
      signDoc: serializedReservedSignDoc
    }),
    /requires reservationManager and reservation/
  );
  assert.equal(signCalls, 0);
  let metadataFreeSignCalls = 0;
  await assert.rejects(
    () => client.signDirectAndBroadcast({
      wallet: {
        async signDirect() {
          metadataFreeSignCalls += 1;
          throw new Error("metadata-free signing should not be reached");
        }
      },
      signDoc: {
        bodyBytes: result.signDoc.bodyBytes,
        authInfoBytes: result.signDoc.authInfoBytes,
        chainId: result.signDoc.chainId,
        accountNumber: result.signDoc.accountNumber
      }
    }),
    /requires reservationManager and reservation/
  );
  assert.equal(metadataFreeSignCalls, 0);
  await assert.rejects(
    () => client.signDirectAndBroadcast({
      wallet: {
        async signDirect(_directSignDoc, context) {
          signCalls += 1;
          assert.equal(
            Object.keys(context.signDoc).some(key => key.startsWith("__clairveil")),
            false
          );
          throw new Error("stop after checking the wallet boundary");
        }
      },
      signDoc: serializedReservedSignDoc,
      reservationManager,
      reservation: result.reservation
    }),
    /stop after checking the wallet boundary/
  );
  assert.equal(signCalls, 1);
  for (const alias of ["reservationBatch", "reservation_batch"]) {
    await assert.rejects(
      () => client.signDirectAndBroadcast({
        wallet: {
          async signDirect() {
            signCalls += 1;
            throw new Error(`stop after checking ${alias}`);
          }
        },
        signDoc: serializedReservedSignDoc,
        reservationManager,
        [alias]: result.reservation
      }),
      new RegExp(`stop after checking ${alias}`)
    );
  }
  assert.equal(signCalls, 3);
  const forwardedReservations = [];
  client.broadcastTxRawBytes = async (_txRawBytes, options) => {
    forwardedReservations.push(options.reservation);
    return { ok: true };
  };
  for (const alias of ["reservationBatch", "reservation_batch"]) {
    await client.signDirectAndBroadcast({
      wallet: {
        async signDirect(directSignDoc) {
          return {
            signed: directSignDoc,
            signature: { signature: "AQ==" }
          };
        }
      },
      signDoc: serializedReservedSignDoc,
      reservationManager,
      [alias]: result.reservation
    });
  }
  assert.deepEqual(forwardedReservations, [result.reservation, result.reservation]);
  assert.equal(result.prepared.selectedInputTotal, "21");
  assert.equal(result.prepared.inputCount, 3);
  assert.equal(result.prepared.outputCount, 32);
  assert.equal(result.prepared.outputMode, "exact32");
  assert.equal(result.prepared.recipient, undefined);
  assert.deepEqual(result.prepared.payments.map(payment => payment.recipient), recipients);
  assert.deepEqual(result.prepared.payments.map(payment => payment.privacyPolicy), [
    "all-private",
    "amount",
    "to"
  ]);
  assert.deepEqual(result.prepared.payments.map(payment => payment.disclosureMode), [
    "none",
    "public",
    "recipient-encrypted"
  ]);
  assert.equal(result.operationEvidence.expected_outputs.length, 3);
  assert.equal(result.operationEvidence.expected_outputs[0].batch_item_index, 0);
  assert.equal(result.operationEvidence.expected_outputs[1].batch_item_index, 1);
  assert.equal(result.operationEvidence.expected_outputs[2].batch_item_index, 2);
  assert.match(result.operationEvidenceHash, /^[0-9a-f]{64}$/);
  assert.equal(result.reservation.reservations.length, 3);
  for (const reservation of result.reservation.reservations) {
    assert.equal(reservation.status, reservationStatuses.ProofReady);
    assert.equal(reservation.expected_recipient_hash, "");
    assert.equal(reservation.expected_denom, "");
    assert.equal(reservation.batch_item_index_known, false);
    assert.equal(reservation.expected_operation_evidence_hash, result.operationEvidenceHash);
    assert.equal(reservation.metadata.operation_success_evidence_required, true);
    assert.deepEqual(
      reservation.metadata.batch_transfer_operation_evidence.expected_outputs,
      result.operationEvidence.expected_outputs
    );
  }

  for (const [overrides, pattern] of [
    [{ onPreparedProof() {} }, /requires the original operationId/],
    [{ operationId: result.operationEvidence.operation_id, onPreparedProof() {} }, /requires the original reservation batch/],
    [{
      operationId: result.operationEvidence.operation_id,
      reservation: result.reservation
    }, /requires onPreparedProof/]
  ]) {
    await assert.rejects(
      () => client.provePreparedBatchTransfer({
        payload: checkpointedPayload,
        creator: "clair1sender",
        nowUnix: chainNowUnix,
        proverAdapter,
        ...overrides
      }),
      pattern
    );
  }
  assert.equal(proveBatchTransferCalls, proveCallsBeforeExecutionBuilder + 1);

  await assert.rejects(
    () => client.provePreparedBatchTransfer({
      payload: checkpointedPayload,
      creator: "clair1sender",
      operationId: result.operationEvidence.operation_id,
      reservation: result.reservation,
      nowUnix: chainNowUnix,
      onPreparedProof() {},
      proverAdapter: {
        async proveBatchTransfer(payload) {
          return {
            version: "v2",
            proof: {
              version: "batch-transfer-proof-v1",
              request_payload_hash: payload.payload_hash,
              proof: Buffer.from(new Uint8Array(164).fill(8)).toString("base64"),
              circuit_set_id: "privacy-note-v1"
            }
          };
        }
      }
    }),
    /unsupported batch transfer proof response version/
  );

  let resumedProverCalls = 0;
  let resumedProofContext = null;
  const resumedProverAdapter = {
    async proveBatchTransfer(payload) {
      resumedProverCalls += 1;
      return {
        version: "batch-transfer-proof-v1",
        request_payload_hash: payload.payload_hash,
        proof: Buffer.from(new Uint8Array(164).fill(8)).toString("base64"),
        circuit_set_id: "privacy-note-v1"
      };
    }
  };
  client.assertTransferProtocolConfig = async () => ({
    ...activeTransferProtocolConfig,
    audit_config: {
      ...activeTransferProtocolConfig.audit_config,
      audit_key_id: "rotated-audit-key"
    }
  });
  await assert.rejects(
    () => client.provePreparedBatchTransfer({
      payload: checkpointedPayload,
      creator: "clair1sender",
      operationId: result.operationEvidence.operation_id,
      reservation: result.reservation,
      nowUnix: chainNowUnix,
      onPreparedProof() {},
      proverAdapter: resumedProverAdapter
    }),
    /audit identity does not match the active chain config/
  );
  assert.equal(resumedProverCalls, 0);
  client.assertTransferProtocolConfig = async () => activeTransferProtocolConfig;
  const resumed = await client.provePreparedBatchTransfer({
    payload: checkpointedPayload,
    creator: "clair1sender",
    operationId: result.operationEvidence.operation_id,
    reservation: result.reservation,
    nowUnix: chainNowUnix,
    onPreparedProof(_proof, context) {
      resumedProofContext = context;
    },
    proverAdapter: resumedProverAdapter
  });
  assert.equal(resumedProverCalls, 1);
  assert.equal(resumed.payload.payload_hash, result.payload.payload_hash);
  assert.equal(resumed.proof.request_payload_hash, result.payload.payload_hash);
  assert.equal(resumed.message.outputs.length, 32);
  assert.equal(resumed.proofStageOnly, true);
  assert.equal(resumed.reservationFinalizationRequired, true);
  assert.equal(resumedProofContext.operationId, result.operationEvidence.operation_id);
  assert.deepEqual(resumedProofContext.reservation, result.reservation);

  // Simulate a process restart: the new manager restores the original
  // reservation batch in Proving, then the public recovery primitive binds the
  // durable payload/proof back to the original payment rows before it permits
  // signing or broadcasting.
  const resumedReservationManager = createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "chain:clair1sender-resumed",
    indexKey: "index-key-v1"
  });
  const resumedReservation = await resumedReservationManager.reserveNotes({
    notes: inputNotes,
    operationId: result.operationEvidence.operation_id,
    kind: "batch_transfer",
    metadata: { batch_transfer_output_mode: "exact32" }
  });
  const provingReservations = await resumedReservationManager.markProving(
    resumedReservation.reservation_ids,
    { leaseToken: resumedReservation.lease_token }
  );
  resumedReservation.reservations = provingReservations;
  const resumedFee = [{ denom: "uclair", amount: "29" }];
  let mutateResumedFee = false;
  client.assertCircuitConfig = async () => activeTransferProtocolConfig.circuit_config;
  client.assertTransferProtocolConfig = async () => {
    if (mutateResumedFee) {
      resumedFee[0].amount = "999";
      resumedFee.push({ denom: "ustale", amount: "1" });
    }
    return activeTransferProtocolConfig;
  };
  const finalizationInput = {
    payload: checkpointedPayload,
    proof: resumed.proof,
    signer: "clair1sender",
    pubKeyHex: "02".padEnd(66, "0"),
    gas_limit: 27000000,
    fee_amount: resumedFee,
    payments: batchPayments,
    operationId: result.operationEvidence.operation_id,
    reservationManager: resumedReservationManager,
    reservation: resumedReservation,
    chainNowUnix
  };
  const mismatchedReservationManager = createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "chain:clair1sender-resumed",
    indexKey: "index-key-v1"
  });
  const mismatchedReservation = await mismatchedReservationManager.reserveNotes({
    notes: [note(12, 4, 4)],
    operationId: result.operationEvidence.operation_id,
    kind: "batch_transfer",
    metadata: { batch_transfer_output_mode: "exact32" }
  });
  mismatchedReservation.reservations = await mismatchedReservationManager.markProving(
    mismatchedReservation.reservation_ids,
    { leaseToken: mismatchedReservation.lease_token }
  );
  await assert.rejects(
    () => client.finalizePreparedBatchTransfer({
      ...finalizationInput,
      reservationManager: mismatchedReservationManager,
      reservation: mismatchedReservation
    }),
    /reservation inputs do not match the payload nullifiers/
  );
  assert.equal(
    (await mismatchedReservationManager.getReservation(mismatchedReservation.reservation_ids[0])).status,
    reservationStatuses.Proving
  );
  await assert.rejects(
    () => client.finalizePreparedBatchTransfer({
      ...finalizationInput,
      reservation: {
        ...resumedReservation,
        lease_token: "00".repeat(16)
      }
    }),
    /do not have the recovered Proving lease/
  );
  assert.equal(
    (await resumedReservationManager.getReservation(resumedReservation.reservation_ids[0])).status,
    reservationStatuses.Proving
  );
  await assert.rejects(
    () => client.finalizePreparedBatchTransfer({
      ...finalizationInput,
      payments: [{ ...batchPayments[0], amount: "3uclair" }, ...batchPayments.slice(1)]
    }),
    /prepared batch payment output 0 does not match its payment/
  );
  assert.equal(
    (await resumedReservationManager.getReservation(resumedReservation.reservation_ids[0])).status,
    reservationStatuses.Proving
  );
  mutateResumedFee = true;
  const finalized = await client.finalizePreparedBatchTransfer(finalizationInput);
  assert.equal(finalized.signDoc.messages[0].typeUrl, MsgBatchTransfer.typeUrl);
  assert.equal(finalized.signDoc.gasLimit, 27000000);
  assert.deepEqual(finalized.signDoc.feeAmount, [{ denom: "uclair", amount: "29" }]);
  assert.equal(finalized.message.outputs.length, 32);
  assert.equal(finalized.operationEvidence.expected_outputs.length, 3);
  assert.match(finalized.operationEvidenceHash, /^[0-9a-f]{64}$/);
  assert.equal(finalized.reservation.reservations[0].status, reservationStatuses.ProofReady);
  assert.equal(
    finalized.reservation.reservations[0].expected_operation_evidence_hash,
    finalized.operationEvidenceHash
  );
  assert.deepEqual(
    finalized.reservation.reservations[0].metadata.batch_transfer_operation_evidence.expected_outputs,
    finalized.operationEvidence.expected_outputs
  );

  const checkpointRecoveryManager = createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "chain:clair1sender-checkpoint-recovery",
    indexKey: "index-key-v1"
  });
  const checkpointRecoveryReservation = await checkpointRecoveryManager.reserveNotes({
    notes: inputNotes,
    operationId: result.operationEvidence.operation_id,
    kind: "batch_transfer",
    metadata: { batch_transfer_output_mode: "exact32" }
  });
  checkpointRecoveryReservation.reservations = await checkpointRecoveryManager.markProving(
    checkpointRecoveryReservation.reservation_ids,
    { leaseToken: checkpointRecoveryReservation.lease_token }
  );
  await checkpointRecoveryManager.markManualReview(
    checkpointRecoveryReservation.reservation_ids,
    {
      leaseToken: checkpointRecoveryReservation.lease_token,
      error: "batch_checkpointed_artifact_requires_recovery",
      metadata: {
        reconcile_reason: "batch_checkpointed_artifact_requires_recovery",
        batch_payload_checkpoint_started: true,
        batch_proof_checkpoint_started: true,
        batch_transfer_payload_hash: checkpointedPayload.payload_hash
      }
    }
  );
  let recoveredExecutionInput = null;
  await assert.rejects(
    () => client.finalizePreparedBatchTransfer({
      ...finalizationInput,
      reservationManager: checkpointRecoveryManager,
      reservation: checkpointRecoveryReservation,
      executionBuilder(input) {
        recoveredExecutionInput = input;
        return {
          executionTransport: "evm",
          transaction: { to: "0x1111111111111111111111111111111111111111", data: "0x1234" },
          txBytesHash: "evm-transaction-binding"
        };
      }
    }),
    /ManualReview reservations require operator resolution/
  );
  assert.equal(recoveredExecutionInput, null);
  const recoveredReservation = await checkpointRecoveryManager.getReservation(
    checkpointRecoveryReservation.reservation_ids[0]
  );
  assert.equal(recoveredReservation.status, reservationStatuses.ManualReview);
  assert.equal(recoveredReservation.tx_bytes_hash, "");
});

test("REST Merkle-path failures do not echo response bodies or commitment URLs", async () => {
  let responseBodyReads = 0;
  const provider = createRestMerklePathProvider({
    rest: "https://privacy.example",
    fetchImpl: async () => ({
      ok: false,
      status: 500,
      async text() {
        responseBodyReads += 1;
        return "private-witness-canary";
      }
    })
  });
  const commitment = "ab".repeat(32);
  await assert.rejects(
    () => provider.lookupMerklePath(commitment),
    error => error.message === "merkle path query failed with status 500" &&
      !error.message.includes("private-witness-canary") &&
      !error.message.includes(commitment)
  );
  assert.equal(responseBodyReads, 0);
});

test("cosmos prepareTransferBatch rejects partial operation evidence arrays", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair",
    enableExperimentalBatchTransfer: true
  });
  const input = {
    material: {
      rootSeed: new Uint8Array(32),
      address: "clair1sender",
      pubKeyHex: "02".padEnd(66, "0"),
      shieldedAddress: "clairs1sender"
    },
    amounts: ["5uclair", "7uclair"],
    recipient: "clairs1recipient",
    proverAdapter: null,
    reservationManager: {},
    onPreparedPayload() {},
    onPreparedProof() {}
  };

  await assert.rejects(
    () => client.prepareTransferBatch({
      ...input,
      expectedRecipientHash: "recipient-hash",
      expectedAmountHashes: ["amount-hash-0"]
    }),
    /expectedAmountHashes length must match batch amounts length/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      ...input,
      expectedAmountHashes: ["amount-hash-0", "amount-hash-1"]
    }),
    /expected recipient hash is required for batch item 0/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      ...input,
      expectedRecipientHash: "recipient-hash"
    }),
    /expectedAmountHashes length must match batch amounts length/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      ...input,
      expectedRecipientHashes: [],
      expectedAmountHashes: []
    }),
    /expectedRecipientHashes length must match batch amounts length/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      ...input,
      expectedRecipientHashes: ["recipient-hash-0", "   "],
      expectedAmountHashes: ["amount-hash-0", "amount-hash-1"]
    }),
    /expected recipient hash is required for batch item 1/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      ...input,
      expectedRecipientHash: "recipient-hash",
      expectedAmountHashes: ["amount-hash-0", "\t"]
    }),
    /expected amount hash is required for batch item 1/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      ...input,
      scanSource: "scan_events"
    }),
    /only support the typed privacy_scan source/
  );
});

test("cosmos prepareTransferBatch keeps the one-proof reservation transition atomic", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair",
    enableExperimentalBatchTransfer: true
  });
  client.assertTransferProtocolConfig = async () => transferProtocolConfig();
  const rootSeed = new Uint8Array(32);
  const ownerSpend = deriveSpendKeys(rootSeed).pubKey;
  const ownerView = deriveViewKeys(rootSeed).pubKey;
  const recipientRootSeed = new Uint8Array(32).fill(3);
  const recipient = encodeShieldedAddress(
    deriveSpendKeys(recipientRootSeed).pubKey,
    deriveViewKeys(recipientRootSeed).pubKey,
    { shieldedPrefix: "clairs" }
  );
  const note = (amount, randomness, height) => ({
    note: createNote({
      spendPubKey: ownerSpend,
      viewPubKey: ownerView,
      amount,
      assetDenom: "uclair",
      randomness
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: `TX${height}`,
    height
  });
  const inputNote = note(12, 3, 3);
  const merklePathProvider = strictMerklePathProvider([inputNote.note]);
  const rootHex = (await merklePathProvider.lookupMerklePath(
    fieldHexV1(computeNoteCommitmentV1(inputNote.note))
  )).root;
  const chainNowUnix = Math.floor(Date.now() / 1000);
  client.scanNotes = async () => ({
    notes: [],
    summary: { total_spendable: "12", spendable_count: 1, spent_count: 0, total_count: 1 },
    diagnostics: { scanned_events: 0, new_notes_found: 0 },
    foundNotes: [inputNote],
    scanCursor: { source: "privacy_scan", has_more: false }
  });
  client.createCommitmentPathSnapshotProvider = async () => merklePathProvider;
  client.checkNullifiers = async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false]));
  const proverAdapter = {
    async proveBatchTransfer(payload) {
      return {
        version: "v1",
        proof: {
          version: "batch-transfer-proof-v1",
          request_payload_hash: payload.payload_hash,
          proof: Buffer.from(new Uint8Array(164).fill(7)).toString("base64"),
          circuit_set_id: "privacy-note-v1"
        }
      };
    }
  };
  const persistPreparedPayload = () => {};
  const persistPreparedProof = () => {};
  client.buildDirectSignDoc = async input => ({
    ...input,
    bodyBytes: Buffer.from(client.registry.encodeTxBody({
      messages: input.messages,
      memo: input.memo
    })).toString("base64"),
    authInfoBytes: "",
    chainId: "clairveil-local-3",
    accountNumber: "0"
  });
  const store = new MemoryReservationStore();
  const reservationManager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1sender",
    indexKey: "index-key-v1"
  });
  let markProofReadyBatchCalls = 0;
  reservationManager.markProofReadyBatch = async () => {
    markProofReadyBatchCalls += 1;
    throw new Error("injected proof-ready failure");
  };

  await assert.rejects(
    () => client.prepareTransferBatch({
      material: {
        rootSeed,
        address: "clair1sender",
        pubKeyHex: "02".padEnd(66, "0"),
        shieldedAddress: "clairs1sender"
      },
      amounts: ["5uclair", "7uclair"],
      recipient,
      proverAdapter,
      rootHex,
      snapshotHeight: 3,
      chainNowUnix,
      expiresAtUnix: chainNowUnix + 1_800,
      reservation_manager: reservationManager,
      onPreparedPayload: persistPreparedPayload,
      onPreparedProof: persistPreparedProof
    }),
    /injected proof-ready failure/
  );

  const reservations = await store.listReservations({ ownerKeyId: "chain:clair1sender" });
  assert.equal(reservations.length, 1);
  assert.equal(markProofReadyBatchCalls, 1);
  assert.equal(reservations.some(reservation => reservation.status === reservationStatuses.ProofReady), false);
  assert.equal(reservations.some(reservation => reservation.status === reservationStatuses.Reserved), false);
  assert.equal(reservations.some(reservation => reservation.status === reservationStatuses.Proving), false);
  assert.equal(reservations[0].status, reservationStatuses.ManualReview);

  const cleanupStore = new MemoryReservationStore();
  const cleanupManager = createNoteReservationManager({
    store: cleanupStore,
    ownerKeyId: "chain:clair1cleanup",
    indexKey: "index-key-v1"
  });
  const cleanupMarkProofReadyBatch = cleanupManager.markProofReadyBatch.bind(cleanupManager);
  cleanupManager.markProofReadyBatch = async (...args) => {
    await cleanupMarkProofReadyBatch(...args);
    throw new Error("injected proof-ready failure with cleanup failure");
  };
  cleanupManager.markManualReview = async () => {
    throw new Error("injected manual-review cleanup failure");
  };
  await assert.rejects(
    () => client.prepareTransferBatch({
      material: {
        rootSeed,
        address: "clair1cleanup",
        pubKeyHex: "02".padEnd(66, "0"),
        shieldedAddress: "clairs1cleanup"
      },
      amounts: ["5uclair", "7uclair"],
      recipient,
      proverAdapter,
      rootHex,
      snapshotHeight: 3,
      chainNowUnix,
      expiresAtUnix: chainNowUnix + 1_800,
      reservation_manager: cleanupManager,
      onPreparedPayload: persistPreparedPayload,
      onPreparedProof: persistPreparedProof
    }),
    error =>
      /injected proof-ready failure with cleanup failure/.test(error?.message || "") &&
      Array.isArray(error?.reservationCleanupErrors) &&
      /injected manual-review cleanup failure/.test(error.reservationCleanupErrors[0]?.message || "")
  );
  const cleanupReservations = await cleanupStore.listReservations({
    ownerKeyId: "chain:clair1cleanup"
  });
  assert.equal(
    cleanupReservations.filter(reservation => reservation.status === reservationStatuses.ProofReady).length,
    1
  );

  const frozenStore = new MemoryReservationStore();
  const frozenManager = createNoteReservationManager({
    store: frozenStore,
    ownerKeyId: "chain:clair1frozen",
    indexKey: "index-key-v1"
  });
  const frozenOriginal = Object.freeze(new Error("frozen batch build failure"));
  const frozenMarkProofReadyBatch = frozenManager.markProofReadyBatch.bind(frozenManager);
  frozenManager.markProofReadyBatch = async (...args) => {
    await frozenMarkProofReadyBatch(...args);
    throw frozenOriginal;
  };
  frozenManager.markManualReview = async () => {
    throw new Error("frozen batch cleanup failure");
  };
  await assert.rejects(
    () => client.prepareTransferBatch({
      material: {
        rootSeed,
        address: "clair1frozen",
        pubKeyHex: "02".padEnd(66, "0"),
        shieldedAddress: "clairs1frozen"
      },
      amounts: ["5uclair", "7uclair"],
      recipient,
      proverAdapter,
      rootHex,
      snapshotHeight: 3,
      chainNowUnix,
      expiresAtUnix: chainNowUnix + 1_800,
      reservation_manager: frozenManager,
      onPreparedPayload: persistPreparedPayload,
      onPreparedProof: persistPreparedProof
    }),
    error => error === frozenOriginal
  );

  const checkpointStore = new MemoryReservationStore();
  const checkpointManager = createNoteReservationManager({
    store: checkpointStore,
    ownerKeyId: "chain:clair1checkpoint",
    indexKey: "index-key-v1"
  });
  let checkpointProverCalls = 0;
  await assert.rejects(
    () => client.prepareTransferBatch({
      material: {
        rootSeed,
        address: "clair1checkpoint",
        pubKeyHex: "02".padEnd(66, "0"),
        shieldedAddress: "clairs1checkpoint"
      },
      amounts: ["5uclair", "7uclair"],
      recipient,
      proverAdapter: {
        async proveBatchTransfer(payload) {
          checkpointProverCalls += 1;
          return proverAdapter.proveBatchTransfer(payload);
        }
      },
      rootHex,
      snapshotHeight: 3,
      chainNowUnix,
      expiresAtUnix: chainNowUnix + 1_800,
      reservation_manager: checkpointManager,
      async onPreparedPayload() {
        throw new Error("injected payload checkpoint failure");
      },
      onPreparedProof: persistPreparedProof
    }),
    /injected payload checkpoint failure/
  );
  assert.equal(checkpointProverCalls, 0);
  const checkpointReservations = await checkpointStore.listReservations({
    ownerKeyId: "chain:clair1checkpoint"
  });
  assert.equal(checkpointReservations.length, 1);
  assert.equal(checkpointReservations[0].status, reservationStatuses.ManualReview);
  assert.equal(
    checkpointReservations[0].metadata.reconcile_reason,
    "batch_checkpointed_artifact_requires_recovery"
  );
  assert.equal(
    checkpointReservations[0].last_broadcast_error,
    "batch_checkpointed_artifact_requires_recovery"
  );
  assert.equal(checkpointReservations[0].metadata.batch_payload_checkpoint_started, true);
  assert.equal(checkpointReservations[0].metadata.batch_proof_checkpoint_started, false);

  const proofCheckpointStore = new MemoryReservationStore();
  const proofCheckpointManager = createNoteReservationManager({
    store: proofCheckpointStore,
    ownerKeyId: "chain:clair1proofcheckpoint",
    indexKey: "index-key-v1"
  });
  let proofCheckpointProverCalls = 0;
  await assert.rejects(
    () => client.prepareTransferBatch({
      material: {
        rootSeed,
        address: "clair1proofcheckpoint",
        pubKeyHex: "02".padEnd(66, "0"),
        shieldedAddress: "clairs1proofcheckpoint"
      },
      amounts: ["5uclair", "7uclair"],
      recipient,
      proverAdapter: {
        async proveBatchTransfer(payload) {
          proofCheckpointProverCalls += 1;
          return proverAdapter.proveBatchTransfer(payload);
        }
      },
      rootHex,
      snapshotHeight: 3,
      chainNowUnix,
      expiresAtUnix: chainNowUnix + 1_800,
      reservation_manager: proofCheckpointManager,
      onPreparedPayload: persistPreparedPayload,
      async onPreparedProof() {
        throw new Error("injected proof checkpoint failure");
      }
    }),
    /injected proof checkpoint failure/
  );
  assert.equal(proofCheckpointProverCalls, 1);
  const proofCheckpointReservations = await proofCheckpointStore.listReservations({
    ownerKeyId: "chain:clair1proofcheckpoint"
  });
  assert.equal(proofCheckpointReservations.length, 1);
  assert.equal(proofCheckpointReservations[0].status, reservationStatuses.ManualReview);
  assert.equal(proofCheckpointReservations[0].metadata.batch_payload_checkpoint_started, true);
  assert.equal(proofCheckpointReservations[0].metadata.batch_proof_checkpoint_started, true);
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

test("browser disclosure decoders forward scan cursor and source options", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair"
  });
  const forwarded = [];
  client.cosmos.decodeUserDisclosure = async input => forwarded.push(input);
  client.cosmos.decodeSelfViewDisclosure = async input => forwarded.push(input);
  client.cosmos.decodeAuditDisclosure = async input => forwarded.push(input);

  await client.decodeUserDisclosure({
    txHash: "user",
    afterSequence: 7,
    scanSource: "scan_events"
  });
  await client.decodeSelfViewDisclosure({
    tx_hash: "self",
    after_sequence: 8,
    scan_source: "privacy_events"
  });
  await client.decodeAuditDisclosure({
    txHash: "audit",
    disclosurePrivKeyHex: "01".repeat(32),
    afterSequence: 9,
    scan_source: "scan_events"
  });

  assert.deepEqual(
    forwarded.map(({ txHash, afterSequence, scanSource }) => ({
      txHash,
      afterSequence,
      scanSource
    })),
    [
      { txHash: "user", afterSequence: 7, scanSource: "scan_events" },
      { txHash: "self", afterSequence: 8, scanSource: "privacy_events" },
      { txHash: "audit", afterSequence: 9, scanSource: "scan_events" }
    ]
  );
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
  const sensitiveDenom = `factory/secret/${"ab".repeat(32)}`;
  const sensitiveNullifier = "cd".repeat(32);
  const sensitiveAddress = "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48";
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
      () => publicClient.fetchReserve(sensitiveDenom),
      error => error.code === "FETCH_TIMEOUT" &&
        /fetch request timed out after 5ms/.test(error.message) &&
        !error.message.includes(sensitiveDenom) &&
        !error.message.includes(encodeURIComponent(sensitiveDenom))
    );

    const cosmosClient = createClairveilClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://chain.local:1317/",
      chainId: "clairveil-local-3",
      queryTimeoutMs: 5,
      queryRetry: false
    });
    await assert.rejects(
      () => cosmosClient.checkNullifier(sensitiveNullifier),
      error => error.code === "FETCH_TIMEOUT" &&
        /fetch request timed out after 5ms/.test(error.message) &&
        !error.message.includes(sensitiveNullifier)
    );

    const browserClient = createClairveilBrowserDappClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://chain.local:1317/",
      chainId: "clairveil-local-3",
      queryTimeoutMs: 5,
      queryRetry: false
    });
    await assert.rejects(
      () => browserClient.getBalances(sensitiveAddress),
      error => error.code === "FETCH_TIMEOUT" &&
        /fetch request timed out after 5ms/.test(error.message) &&
        !error.message.includes(sensitiveAddress)
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
      return new Response(JSON.stringify({
        root: "00".repeat(31) + "01",
        leaf_count: "1",
        depth: 32,
        initialized: true,
        max_leaves: "4294967296",
        remaining_leaves: "4294967295"
      }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    if (text.endsWith("/clairveil/privacy/v1/audit_config")) {
      return new Response(JSON.stringify({
        audit_master_pubkey_hex: Buffer.from(packPoint(CURVE_BASE)).toString("hex"),
        audit_key_id: "audit-key-1",
        audit_key_epoch: "1"
      }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    if (text.endsWith("/status")) {
      return new Response(JSON.stringify({ result: { node_info: { network: "clairveil-local-3" } } }), {
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
    assert.equal(health.tree.leaf_count, "1");
    assert.equal(health.audit.audit_key_id, "audit-key-1");
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

test("native 2x2 prepareTransfer binds an asserted audit key to the active chain config", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  client.scanNotes = async () => heartbeatTestScanResult();
  client.assertTransferProtocolConfig = async () => transferProtocolConfig();
  let buildCalls = 0;
  client.buildTransferMessage = async () => {
    buildCalls += 1;
    throw new Error("transfer build must not run");
  };

  await assert.rejects(
    () => client.prepareTransfer({
      material: heartbeatTestMaterial(),
      amount: "1uclair",
      recipient: validClairsRecipient,
      proverAdapter: null,
      chainNowUnix: 1_700_000_000,
      auditDisclosureTargetPubKeyHex: "00".repeat(32)
    }),
    /transfer audit disclosure target must exactly match the active chain audit config/
  );
  assert.equal(buildCalls, 0);
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

test("typed privacy scan capability discovery continues across REST endpoints", async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  globalThis.fetch = async url => {
    const text = String(url);
    requestedUrls.push(text);
    if (text.startsWith("http://rest-a.local")) {
      return new Response("not implemented", { status: 404 });
    }
    return new Response(JSON.stringify({ endpoint: "rest-b" }), {
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
      queryRetry: false
    });
    assert.deepEqual(await client.fetchPrivacyScan(), { endpoint: "rest-b" });
    const publicClient = createClairveilPublicClient({
      rest: "http://rest-a.local",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      queryRetry: false
    });
    assert.deepEqual(await publicClient.fetchPrivacyScan(), { endpoint: "rest-b" });
    assert.deepEqual(requestedUrls, [
      "http://rest-a.local/clairveil/privacy/v1/privacy_scan",
      "http://rest-b.local/clairveil/privacy/v1/privacy_scan",
      "http://rest-a.local/clairveil/privacy/v1/privacy_scan",
      "http://rest-b.local/clairveil/privacy/v1/privacy_scan"
    ]);
    assert.equal(client.activeRestEndpoint, "http://rest-b.local");
    assert.equal(publicClient.activeRestEndpoint, "http://rest-b.local");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("typed privacy scan capability discovery preserves a transient endpoint failure", async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  globalThis.fetch = async url => {
    const text = String(url);
    requestedUrls.push(text);
    return text.startsWith("http://rest-a.local")
      ? new Response("temporarily unavailable", { status: 503 })
      : new Response("not implemented", { status: 404 });
  };
  try {
    const factories = [
      () => createClairveilClient({
        rpc: "http://127.0.0.1:26657",
        rest: "http://rest-a.local",
        restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
        chainId: "clairveil-local-3",
        queryRetry: false
      }),
      () => createClairveilPublicClient({
        rest: "http://rest-a.local",
        restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
        queryRetry: false
      })
    ];
    for (const createClient of factories) {
      await assert.rejects(
        () => createClient().fetchPrivacyScan(),
        error => error?.status === 503
      );
    }
    assert.deepEqual(requestedUrls, [
      "http://rest-a.local/clairveil/privacy/v1/privacy_scan",
      "http://rest-b.local/clairveil/privacy/v1/privacy_scan",
      "http://rest-a.local/clairveil/privacy/v1/privacy_scan",
      "http://rest-b.local/clairveil/privacy/v1/privacy_scan"
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
  const client = cosmosTestClient();
  const signedTx = signedTxFixture([1, 2, 3]);
  const { txHash: signedTxHash } = signedTxIdentity(client, signedTx);
  client.connect = async () => ({
    broadcastTxSync: async () => signedTxHash
  });
  client.waitForTx = async () => ({
    height: "9",
    txhash: signedTxHash,
    code: 18,
    raw_log: "invalid request",
    events: []
  });

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx),
    error => {
      assert.equal(error.broadcast.code, 18);
      assert.equal(error.tx.code, 18);
      return /explicit successful result/.test(error.message);
    }
  );
});

test("cosmos broadcastSignedTx rejects missing or malformed indexed result codes", async () => {
  for (const code of [undefined, "", "bogus", -1, 1.5]) {
    const client = cosmosTestClient();
    const signedTx = signedTxFixture([1, 2, 3]);
    const { txHash: signedTxHash } = signedTxIdentity(client, signedTx);
    client.connect = async () => ({ broadcastTxSync: async () => signedTxHash });
    client.waitForTx = async () => ({ txhash: signedTxHash, code, events: [] });

    await assert.rejects(
      () => client.broadcastSignedTx(signedTx),
      error => error.txHash === signedTxHash && error.broadcast?.code === null && /explicit successful result/.test(error.message)
    );
  }
});

test("cosmos broadcast errors retain tx bytes and tx hash evidence", async () => {
  const signedTx = signedTxFixture([1, 2, 3]);
  const beforeHash = cosmosTestClient();
  const { txBytesHash: expectedTxBytesHash } = signedTxIdentity(beforeHash, signedTx);
  beforeHash.connect = async () => ({
    broadcastTxSync: async () => {
      throw new Error("rpc unavailable");
    }
  });
  await assert.rejects(
    () => beforeHash.broadcastSignedTx(signedTx),
    error => error.txBytesHash === expectedTxBytesHash &&
      error.txHash === expectedTxBytesHash.toUpperCase()
  );

  const afterHash = cosmosTestClient();
  afterHash.connect = async () => ({ broadcastTxSync: async () => expectedTxBytesHash.toUpperCase() });
  afterHash.waitForTx = async () => {
    throw new Error("index temporarily unavailable");
  };
  await assert.rejects(
    () => afterHash.broadcastSignedTx(signedTx),
    error =>
      error.txHash === expectedTxBytesHash.toUpperCase() &&
      error.txBytesHash === expectedTxBytesHash
  );

  const decoratedError = cosmosTestClient();
  decoratedError.connect = async () => ({
    broadcastTxSync: async () => {
      const error = new Error("rpc response lost");
      error.txhash = "REMOTE-DECORATION";
      error.txHash = "ff".repeat(32);
      throw error;
    }
  });
  await assert.rejects(
    () => decoratedError.broadcastSignedTx(signedTx),
    error => error.txhash === "REMOTE-DECORATION" &&
      error.txHash === expectedTxBytesHash.toUpperCase() &&
      error.txBytesHash === expectedTxBytesHash
  );
});

test("cosmos rejects an RPC tx hash that does not identify the signed TxRaw bytes", async () => {
  const signedTx = signedTxFixture([31, 32, 33]);
  const rpcTxHash = "ff".repeat(32);
  const client = cosmosTestClient();
  const { txHash: signedTxHash } = signedTxIdentity(client, signedTx);
  const { store, reservationManager, reservation } = await readyBroadcastReservation("30", {
    signDocHash: cosmosSignDocBindingHash(signedTx)
  });
  let waitCalls = 0;
  client.connect = async () => ({ broadcastTxSync: async () => `0x${rpcTxHash}` });
  client.waitForTx = async () => {
    waitCalls += 1;
    return { code: 0 };
  };

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, { reservationManager, reservation }),
    error => error.code === "COSMOS_TX_HASH_MISMATCH" &&
      error.txHash === signedTxHash &&
      error.rpcTxHash === `0x${rpcTxHash}`
  );
  assert.equal(waitCalls, 0);
  const stored = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(stored.status, reservationStatuses.Unknown);
  assert.equal(stored.submitted_tx_hash, signedTxHash);
  assert.equal(stored.tx_bytes_hash, signedTxHash.toLowerCase());
});

test("cosmos rejects missing or mismatched indexed transaction hashes", async () => {
  const signedTx = signedTxFixture([34, 35, 36]);
  const encoder = cosmosTestClient();
  const { txHash: signedTxHash } = signedTxIdentity(encoder, signedTx);

  for (const indexedTxHash of [undefined, "ee".repeat(32)]) {
    const { store, reservationManager, reservation } = await readyBroadcastReservation(
      indexedTxHash ? "32" : "31",
      { signDocHash: cosmosSignDocBindingHash(signedTx) }
    );
    const client = cosmosTestClient();
    client.connect = async () => ({ broadcastTxSync: async () => signedTxHash });
    client.waitForTx = async () => ({ txhash: indexedTxHash, code: 0, events: [] });

    await assert.rejects(
      () => client.broadcastSignedTx(signedTx, { reservationManager, reservation }),
      error => error.code === "COSMOS_TX_HASH_MISMATCH" &&
        error.txHash === signedTxHash &&
        error.indexedTxHash === String(indexedTxHash || "")
    );
    const stored = await store.getReservation(reservation.reservation_ids[0]);
    assert.equal(stored.status, reservationStatuses.Unknown);
    assert.equal(stored.submitted_tx_hash, signedTxHash);
  }
});

test("cosmos signs to an exact TxRaw checkpoint and retransmits those unchanged bytes", async () => {
  const client = cosmosTestClient();
  const signDoc = {
    chainId: "clairveil-local-3",
    bodyBytes: "",
    authInfoBytes: "",
    accountNumber: "0"
  };
  let walletCalls = 0;
  const checkpoint = await client.signDirect({
    wallet: {
      async signDirect(directSignDoc) {
        walletCalls += 1;
        return {
          signed: directSignDoc,
          signature: { signature: "AQ==" }
        };
      }
    },
    signDoc
  });
  assert.equal(walletCalls, 1);
  assert.deepEqual(
    checkpoint.txRawBytes,
    client.buildTxRawBytes(checkpoint.signedTx)
  );
  assert.equal(
    checkpoint.txBytesHash,
    createHash("sha256").update(checkpoint.txRawBytes).digest("hex")
  );
  assert.equal(checkpoint.txHash, checkpoint.txBytesHash.toUpperCase());
  assert.equal(checkpoint.signDocHash, cosmosSignDocBindingHash(signDoc));

  const exactCheckpoint = Uint8Array.from(checkpoint.txRawBytes);
  const signedTxHash = checkpoint.txHash;
  client.buildTxRawBytes = () => {
    throw new Error("a raw checkpoint must not be reconstructed before broadcast");
  };
  let submittedBytes;
  client.connect = async () => ({
    async broadcastTxSync(txBytes) {
      submittedBytes = Uint8Array.from(txBytes);
      return signedTxHash;
    }
  });
  client.waitForTx = async () => ({
    height: "9",
    txhash: signedTxHash,
    code: 0,
    raw_log: "",
    events: []
  });

  const result = await client.broadcastTxRawBytes(checkpoint.txRawBytes);
  assert.equal(result.ok, true);
  assert.equal(result.txHash, signedTxHash);
  assert.equal(result.txBytesHash, checkpoint.txBytesHash);
  assert.deepEqual(submittedBytes, exactCheckpoint);
  assert.equal(walletCalls, 1);
});

test("cosmos raw TxRaw retransmission preserves reservation attempt evidence", async () => {
  const unsigned = {
    bodyBytes: "",
    authInfoBytes: "",
    signature: "AQ=="
  };
  const client = cosmosTestClient();
  const txRawBytes = client.buildTxRawBytes(unsigned);
  const txBytesHash = createHash("sha256").update(txRawBytes).digest("hex");
  const signedTxHash = txBytesHash.toUpperCase();
  const { store, reservationManager, reservation } = await readyBroadcastReservation("2c", {
    signDocHash: cosmosSignDocBindingHash(unsigned),
    txBytesHash
  });
  client.connect = async () => ({
    async broadcastTxSync(txBytes) {
      assert.deepEqual(txBytes, txRawBytes);
      const stored = await store.getReservation(reservation.reservation_ids[0]);
      assert.equal(stored.broadcast_in_flight, true);
      assert.equal(stored.tx_bytes_hash, txBytesHash);
      return signedTxHash;
    }
  });
  client.waitForTx = async () => ({
    height: "9",
    txhash: signedTxHash,
    code: 0,
    raw_log: "",
    events: []
  });
  client.checkNullifiers = async nullifiers =>
    new Map(nullifiers.map(nullifier => [nullifier, false]));

  const result = await client.broadcastTxRawBytes(txRawBytes, {
    reservationManager,
    reservation
  });
  assert.equal(result.ok, true);
  const stored = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(stored.status, reservationStatuses.Submitted);
  assert.equal(stored.tx_bytes_hash, txBytesHash);
});

test("low-level batch sign docs require authoritative reservations and recheck their exact nullifiers", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    enableExperimentalBatchTransfer: true
  });
  const message = validBatchTransferMessage();
  const nullifier = hexFromBytes(message.nullifiers[0]);
  client.assertCircuitConfig = async () => ({});
  client.buildDirectSignDoc = async ({ messages, memo }) => ({
    bodyBytes: Buffer.from(client.registry.encodeTxBody({ messages, memo })).toString("base64"),
    authInfoBytes: "",
    chainId: "clairveil-local-3",
    accountNumber: "0"
  });
  const signDoc = await client.createBatchTransferSignDoc({
    signer: message.creator,
    pubKeyHex: "02".repeat(33),
    message,
    chainNowUnix: 1_700_000_000
  });
  const signedTx = { ...signDoc, signature: "" };
  const { store, reservationManager, reservation } = await readyBroadcastReservation("4d", {
    signDocHash: cosmosSignDocBindingHash(signedTx),
    notes: [{ ...broadcastReservationNote("4d"), nullifier }]
  });
  const signedTx = {
    bodyBytes: "",
    authInfoBytes: "",
    signature: Buffer.from([41, 42, 43]).toString("base64")
  };
  const txRawBytes = client.buildTxRawBytes(signedTx);
  const txBytesHash = createHash("sha256").update(txRawBytes).digest("hex");
  const signedTxHash = txBytesHash.toUpperCase();
  const events = [];
  client.connect = async () => ({
    async broadcastTxSync(submittedBytes) {
      events.push("rpc");
      assert.deepEqual(submittedBytes, txRawBytes);
      assert.deepEqual(events, ["beforeBroadcast", "rpc"]);
      return signedTxHash;
    }
  });
  client.waitForTx = async txHash => ({
    height: "9",
    txhash: txHash,
    code: 0,
    raw_log: "",
    events: []
  });

  const result = await client.broadcastSignedTx(signedTx, {
    beforeBroadcast(identity) {
      events.push("beforeBroadcast");
      assert.equal(Object.isFrozen(identity), true);
      assert.deepEqual(identity, {
        txHash: signedTxHash,
        txBytesHash,
        signDocHash: cosmosSignDocBindingHash(signedTx)
      });
    }
  });

  assert.equal(result.ok, true);
  assert.equal(result.txHash, signedTxHash);
  assert.deepEqual(events, ["beforeBroadcast", "rpc"]);
});

test("cosmos beforeBroadcast rejects asynchronous callbacks without invoking RPC", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  const signedTx = {
    bodyBytes: "",
    authInfoBytes: "",
    signature: Buffer.from([44, 45, 46]).toString("base64")
  };
  const txRawBytes = client.buildTxRawBytes(signedTx);
  const signedTxHash = createHash("sha256").update(txRawBytes).digest("hex").toUpperCase();
  const { store, reservationManager, reservation } = await readyBroadcastReservation("2f", {
    signDocHash: cosmosSignDocBindingHash(signedTx)
  });
  let broadcastCalls = 0;
  client.connect = async () => ({
    async broadcastTxSync() {
      broadcastCalls += 1;
      return "";
    }
  });

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, {
      reservationManager,
      reservation,
      beforeBroadcast: async () => {}
    }),
    error => error.txHash === signedTxHash &&
      error.rpcInvoked === false &&
      /must not return a Promise/.test(error.message)
  );
  assert.equal(broadcastCalls, 0);
  const stored = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(stored.status, reservationStatuses.ReplanRequired);
  assert.equal(stored.submitted_tx_hash, signedTxHash);
  assert.equal(stored.metadata.rpc_invoked, false);
  assert.equal(stored.metadata.broadcast_aborted_before_rpc, true);
});

test("reserved batch broadcast rechecks persisted input nullifiers immediately before submission", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  const message = validBatchTransferMessage();
  const nullifier = hexFromBytes(message.nullifiers[0]);
  const signedTx = signedBatchTransferTx(client, message);
  const { store, reservationManager, reservation } = await readyBroadcastReservation("4d", {
    signDocHash: cosmosSignDocBindingHash(signedTx),
    notes: [{ ...broadcastReservationNote("4d"), nullifier }],
    metadata: { batch_transfer_nullifier_hexes: [nullifier] }
  });
  let nullifierChecks = 0;
  let broadcastCalls = 0;
  client.connect = async () => ({
    async broadcastTxSync() {
      broadcastCalls += 1;
      return "BATCH-UNREACHABLE";
    }
  });
  client.checkNullifiers = async values => {
    nullifierChecks += 1;
    assert.deepEqual(values, [nullifier]);
    return new Map([[nullifier, true]]);
  };

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, {
      getChainNowUnix: async () => 1_700_000_000
    }),
    /requires reservationManager and reservation/
  );
  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, {
      reservationManager,
      reservation,
      getChainNowUnix: async () => {
        throw new Error("chain time must not be queried after a spent nullifier");
      }
    }),
    /batch transfer input nullifier at index 0 is spent/
  );
  assert.equal(nullifierChecks, 1);
  assert.equal(broadcastCalls, 0);
  await assertProofReadyNotAttempted(store, reservation);
});

test("signed batch expiry is checked with fresh chain time after nullifiers and before its attempt marker", async () => {
  const client = cosmosTestClient();
  const message = {
    ...validBatchTransferMessage(),
    expiresAtUnix: 2_000n
  };
  const nullifier = hexFromBytes(message.nullifiers[0]);
  const signedTx = signedBatchTransferTx(client, message);
  const { store, reservationManager, reservation } = await readyBroadcastReservation("4c", {
    signDocHash: cosmosSignDocBindingHash(signedTx),
    notes: [{ ...broadcastReservationNote("4c"), nullifier }],
    metadata: { batch_transfer_nullifier_hexes: [nullifier] }
  });
  const events = [];
  client.checkNullifiers = async values => {
    events.push("nullifiers");
    assert.deepEqual(values, [nullifier]);
    return new Map([[nullifier, false]]);
  };
  let broadcastCalls = 0;
  client.connect = async () => ({
    async broadcastTxSync() {
      broadcastCalls += 1;
      return "BATCH-UNREACHABLE";
    }
  });
  const originalMarkBroadcastAttempting = reservationManager.markBroadcastAttempting.bind(reservationManager);
  reservationManager.markBroadcastAttempting = async (...args) => {
    events.push("marker");
    return originalMarkBroadcastAttempting(...args);
  };

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, {
      reservationManager,
      reservation,
      getChainNowUnix: async () => {
        events.push("chain-time");
        return 2_000;
      }
    }),
    /signed MsgBatchTransfer expired at the final broadcast fence/
  );
  assert.deepEqual(events, ["nullifiers", "chain-time"]);
  assert.equal(broadcastCalls, 0);
  const stored = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(stored.status, reservationStatuses.ProofReady);
  assert.equal(stored.broadcast_attempt_count, 0);
});

test("reserved direct transfer rechecks its signed input nullifier immediately before submission", async () => {
  const suffix = "4e";
  const nullifier = suffix.repeat(32);
  const helperSuffix = "5e";
  const helperNullifier = helperSuffix.repeat(32);
  const client = cosmosTestClient();
  const signedTx = signedMessageTx(client, MsgTransfer.typeUrl, MsgTransfer.fromPartial({
    nullifiers: [nullifier, helperNullifier].map(value => Buffer.from(value, "hex"))
  }));
  const { store, reservationManager, reservation } = await readyBroadcastReservation(suffix, {
    signDocHash: cosmosSignDocBindingHash(signedTx),
    notes: [broadcastReservationNote(suffix), broadcastReservationNote(helperSuffix)]
  });
  let nullifierChecks = 0;
  let broadcastCalls = 0;
  client.connect = async () => ({
    async broadcastTxSync() {
      broadcastCalls += 1;
      return "TRANSFER-UNREACHABLE";
    }
  });
  client.checkNullifiers = async values => {
    nullifierChecks += 1;
    assert.deepEqual(values, [nullifier, helperNullifier]);
    return new Map([[nullifier, true], [helperNullifier, false]]);
  };

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, { reservationManager, reservation }),
    /reserved direct privacy input nullifier at index 0 is spent/
  );
  assert.equal(nullifierChecks, 1);
  assert.equal(broadcastCalls, 0);
  await assertProofReadyNotAttempted(store, reservation);
});

test("exact signed MsgTransfer applies a fresh authoritative expiry fence before attempt marker and RPC", async () => {
  const suffixes = ["54", "55"];
  const nullifiers = suffixes.map(suffix => suffix.repeat(32));
  const client = cosmosTestClient();
  const signedTx = signedMessageTx(client, MsgTransfer.typeUrl, MsgTransfer.fromPartial({
    nullifiers: nullifiers.map(value => Buffer.from(value, "hex")),
    expiresAtUnix: 2_000n
  }));
  const { txRawBytes, txHash } = signedTxIdentity(client, signedTx);
  const { store, reservationManager, reservation } = await readyBroadcastReservation(suffixes[0], {
    signDocHash: cosmosSignDocBindingHash(signedTx),
    notes: suffixes.map(broadcastReservationNote)
  });
  const events = [];
  client.checkNullifiers = async values => {
    events.push("nullifiers");
    assert.deepEqual(values, nullifiers);
    return new Map(values.map(value => [value, false]));
  };
  let broadcastCalls = 0;
  client.connect = async () => ({
    async broadcastTxSync(bytes) {
      events.push("rpc");
      broadcastCalls += 1;
      assert.deepEqual(bytes, txRawBytes);
      return txHash;
    }
  });
  client.waitForTx = async () => ({ txhash: txHash, code: 0, raw_log: "", events: [] });
  const originalMarkBroadcastAttempting = reservationManager.markBroadcastAttempting.bind(reservationManager);
  reservationManager.markBroadcastAttempting = async (...args) => {
    events.push("marker");
    return originalMarkBroadcastAttempting(...args);
  };

  await assert.rejects(
    () => client.broadcastTxRawBytes(txRawBytes, { reservationManager, reservation }),
    /requires getChainNowUnix/
  );
  await assert.rejects(
    () => client.broadcastTxRawBytes(txRawBytes, {
      reservationManager,
      reservation,
      getChainNowUnix: async () => "malformed"
    }),
    /must be a non-negative safe integer/
  );
  await assert.rejects(
    () => client.broadcastTxRawBytes(txRawBytes, {
      reservationManager,
      reservation,
      getChainNowUnix: async () => {
        throw new Error("chain time unavailable");
      }
    }),
    /authoritative chain time query failed/
  );
  await assert.rejects(
    () => client.broadcastTxRawBytes(txRawBytes, {
      reservationManager,
      reservation,
      getChainNowUnix: async () => 2_000
    }),
    /expired at the final broadcast fence/
  );
  assert.equal(broadcastCalls, 0);
  await assertProofReadyNotAttempted(store, reservation);

  events.length = 0;
  const result = await client.broadcastTxRawBytes(txRawBytes, {
    reservationManager,
    reservation,
    getChainNowUnix: async () => {
      events.push("chain-time");
      return 1_999;
    },
    beforeBroadcast() {
      events.push("synchronous-fence");
    }
  });
  assert.equal(result.ok, true);
  assert.deepEqual(events, [
    "nullifiers",
    "chain-time",
    "marker",
    "synchronous-fence",
    "rpc"
  ]);
  const submitted = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(submitted.status, reservationStatuses.Submitted);
  assert.equal(submitted.submitted_tx_hash, txHash);
});

test("unreserved signed MsgTransfer still rechecks nullifiers before its final expiry fence", async () => {
  const nullifiers = ["56".repeat(32), "57".repeat(32)];
  const client = cosmosTestClient();
  const signedTx = signedMessageTx(client, MsgTransfer.typeUrl, MsgTransfer.fromPartial({
    nullifiers: nullifiers.map(value => Buffer.from(value, "hex")),
    expiresAtUnix: 2_000n
  }));
  const { txRawBytes, txHash } = signedTxIdentity(client, signedTx);
  const events = [];
  client.checkNullifiers = async values => {
    events.push("nullifiers");
    assert.deepEqual(values, nullifiers);
    return new Map(values.map(value => [value, false]));
  };
  client.connect = async () => ({
    async broadcastTxSync(bytes) {
      events.push("rpc");
      assert.deepEqual(bytes, txRawBytes);
      return txHash;
    }
  });
  client.waitForTx = async () => ({ txhash: txHash, code: 0, raw_log: "", events: [] });

  const result = await client.broadcastSignedTx(signedTx, {
    getChainNowUnix: async () => {
      events.push("chain-time");
      return 1_999;
    }
  });
  assert.equal(result.ok, true);
  assert.deepEqual(events, ["nullifiers", "chain-time", "rpc"]);
});

test("broadcastSignedTx validates the exact encoded TxRaw instead of a later object mutation", async () => {
  const nullifiers = ["58".repeat(32), "59".repeat(32)];
  const client = cosmosTestClient();
  const transferBody = expiresAtUnix => signedMessageTx(
    client,
    MsgTransfer.typeUrl,
    MsgTransfer.fromPartial({
      nullifiers: nullifiers.map(value => Buffer.from(value, "hex")),
      expiresAtUnix: BigInt(expiresAtUnix)
    })
  ).bodyBytes;
  const signedTx = {
    bodyBytes: transferBody(10),
    authInfoBytes: "",
    signature: ""
  };
  const originalTxRawBytes = client.buildTxRawBytes(signedTx);
  let broadcastCalls = 0;
  client.checkNullifiers = async values => new Map(values.map(value => [value, false]));
  client.connect = async () => ({
    async broadcastTxSync() {
      broadcastCalls += 1;
      return createHash("sha256").update(originalTxRawBytes).digest("hex").toUpperCase();
    }
  });

  const broadcast = client.broadcastSignedTx(signedTx, {
    getChainNowUnix: async () => 100
  });
  signedTx.bodyBytes = transferBody(1_000);
  await assert.rejects(broadcast, /expired at the final broadcast fence/);
  assert.equal(broadcastCalls, 0);
});

test("reserved direct transfer rejects an extra signed nullifier before querying or submitting", async () => {
  const suffix = "50";
  const nullifier = suffix.repeat(32);
  const extraNullifier = "51".repeat(32);
  const client = cosmosTestClient();
  const signedTx = signedMessageTx(client, MsgTransfer.typeUrl, MsgTransfer.fromPartial({
    nullifiers: [nullifier, extraNullifier].map(value => Buffer.from(value, "hex"))
  }));
  const { store, reservationManager, reservation } = await readyBroadcastReservation(suffix, {
    signDocHash: cosmosSignDocBindingHash(signedTx)
  });
  let nullifierChecks = 0;
  let broadcastCalls = 0;
  client.connect = async () => ({
    async broadcastTxSync() {
      broadcastCalls += 1;
      return "TRANSFER-UNREACHABLE";
    }
  });
  client.checkNullifiers = async () => {
    nullifierChecks += 1;
    return new Map();
  };

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, { reservationManager, reservation }),
    /reserved direct privacy inputs do not match the signed transaction nullifiers/
  );
  assert.equal(nullifierChecks, 0);
  assert.equal(broadcastCalls, 0);
  await assertProofReadyNotAttempted(store, reservation);
});

test("reserved direct transfer rejects a missing signed nullifier before querying or submitting", async () => {
  const suffix = "52";
  const nullifier = suffix.repeat(32);
  const missingSuffix = "53";
  const client = cosmosTestClient();
  const signedTx = signedMessageTx(client, MsgTransfer.typeUrl, MsgTransfer.fromPartial({
    nullifiers: [Buffer.from(nullifier, "hex")]
  }));
  const { store, reservationManager, reservation } = await readyBroadcastReservation(suffix, {
    signDocHash: cosmosSignDocBindingHash(signedTx),
    notes: [broadcastReservationNote(suffix), broadcastReservationNote(missingSuffix)]
  });
  let nullifierChecks = 0;
  let broadcastCalls = 0;
  client.connect = async () => ({
    async broadcastTxSync() {
      broadcastCalls += 1;
      return "TRANSFER-UNREACHABLE";
    }
  });
  client.checkNullifiers = async () => {
    nullifierChecks += 1;
    return new Map();
  };

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, { reservationManager, reservation }),
    /reserved direct privacy inputs do not match the signed transaction nullifiers/
  );
  assert.equal(nullifierChecks, 0);
  assert.equal(broadcastCalls, 0);
  for (const reservationID of reservation.reservation_ids) {
    const stored = await store.getReservation(reservationID);
    assert.equal(stored.status, reservationStatuses.ProofReady);
    assert.equal(stored.broadcast_attempt_count, 0);
  }
});

test("reserved direct withdraw rechecks its signed input nullifier immediately before submission", async () => {
  const suffix = "4f";
  const nullifier = suffix.repeat(32);
  const chainId = "clairveil-local-3";
  const recipient = toBech32("clair", new Uint8Array(20).fill(7));
  const creator = toBech32("clair", new Uint8Array(20).fill(8));
  const payload = {
    version: "v2",
    proof_hex: validV2ProofHex,
    root_hex: fieldHexV1(1n),
    nullifier_hex: nullifier,
    amount: "1uclair",
    recipient,
    chain_id: chainId,
    expires_at_unix: 2_000
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);
  const client = cosmosTestClient({ chainId });
  const message = buildWithdrawMsgFromPayload(payload, creator, 1_000);
  const signedTx = signedMessageTx(client, MsgWithdraw.typeUrl, message);
  const { store, reservationManager, reservation } = await readyBroadcastReservation(suffix, {
    payloadHash: payload.payload_hash,
    signDocHash: cosmosSignDocBindingHash(signedTx)
  });
  let nullifierChecks = 0;
  let broadcastCalls = 0;
  client.connect = async () => ({
    async broadcastTxSync() {
      broadcastCalls += 1;
      return "WITHDRAW-UNREACHABLE";
    }
  });
  client.checkNullifiers = async values => {
    nullifierChecks += 1;
    assert.deepEqual(values, [nullifier]);
    return new Map([[nullifier, true]]);
  };

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, {
      reservationManager,
      reservation,
      relayPayload: payload,
      getChainNowUnix: async () => {
        throw new Error("chain time must not be queried after a spent nullifier");
      }
    }),
    /reserved direct privacy input nullifier at index 0 is spent/
  );
  assert.equal(nullifierChecks, 1);
  assert.equal(broadcastCalls, 0);
  await assertProofReadyNotAttempted(store, reservation);
});

test("signed withdraw uses a provider-only final chain-time fence after its nullifier recheck", async () => {
  const suffix = "5a";
  const nullifier = suffix.repeat(32);
  const chainId = "clairveil-local-3";
  const recipient = toBech32("clair", new Uint8Array(20).fill(9));
  const creator = toBech32("clair", new Uint8Array(20).fill(10));
  const payload = {
    version: "v2",
    proof_hex: validV2ProofHex,
    root_hex: fieldHexV1(1n),
    nullifier_hex: nullifier,
    amount: "1uclair",
    recipient,
    chain_id: chainId,
    expires_at_unix: 2_000
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);
  const client = cosmosTestClient({ chainId });
  const signedTx = signedMessageTx(
    client,
    MsgWithdraw.typeUrl,
    buildWithdrawMsgFromPayload(payload, creator, 1_000)
  );
  const { store, reservationManager, reservation } = await readyBroadcastReservation(suffix, {
    payloadHash: payload.payload_hash,
    signDocHash: cosmosSignDocBindingHash(signedTx)
  });
  let broadcastCalls = 0;
  client.connect = async () => ({
    async broadcastTxSync() {
      broadcastCalls += 1;
      return "WITHDRAW-UNREACHABLE";
    }
  });
  const events = [];
  client.checkNullifiers = async values => {
    events.push("nullifiers");
    assert.deepEqual(values, [nullifier]);
    return new Map([[nullifier, false]]);
  };
  const originalMarkBroadcastAttempting = reservationManager.markBroadcastAttempting.bind(reservationManager);
  reservationManager.markBroadcastAttempting = async (...args) => {
    events.push("marker");
    return originalMarkBroadcastAttempting(...args);
  };

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, {
      reservationManager,
      reservation,
      relayPayload: payload,
      chainNowUnix: 1_999
    }),
    /does not accept chainNowUnix/
  );
  assert.deepEqual(events, []);

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, {
      reservationManager,
      reservation,
      relayPayload: payload,
      getChainNowUnix: async () => {
        events.push("chain-time");
        return 2_000;
      }
    }),
    /withdraw payload expired/
  );
  assert.deepEqual(events, ["nullifiers", "chain-time"]);
  assert.equal(broadcastCalls, 0);
  await assertProofReadyNotAttempted(store, reservation);
});

test("cosmos beforeBroadcast synchronously fences session invalidation after async prechecks", async () => {
  const nullifier = "2e".repeat(32);
  const client = cosmosTestClient();
  const signedTx = signedMessageTx(client, MsgTransfer.typeUrl, MsgTransfer.fromPartial({
    nullifiers: [Buffer.from(nullifier, "hex")],
    expiresAtUnix: 2_000n
  }), { signature: Buffer.from([10, 11, 12]).toString("base64") });
  const { txHash: signedTxHash } = signedTxIdentity(client, signedTx);
  const { store, reservationManager, reservation } = await readyBroadcastReservation("2e", {
    signDocHash: cosmosSignDocBindingHash(signedTx)
  });
  let sessionGeneration = 1;
  const capturedGeneration = sessionGeneration;
  let nullifierChecks = 0;
  let boundaryChecks = 0;
  let broadcastCalls = 0;
  client.checkNullifiers = async values => {
    nullifierChecks += 1;
    assert.deepEqual(values, [nullifier]);
    sessionGeneration += 1;
    return new Map([[nullifier, false]]);
  };
  client.connect = async () => ({
    async broadcastTxSync() {
      broadcastCalls += 1;
      return signedTxHash;
    }
  });

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, {
      reservationManager,
      reservation,
      getChainNowUnix: async () => 1_000,
      beforeBroadcast(identity) {
        boundaryChecks += 1;
        assert.equal(identity.txHash, signedTxHash);
        if (sessionGeneration !== capturedGeneration) {
          throw new Error("wallet session invalidated before broadcast");
        }
      }
    }),
    error => error.txHash === signedTxHash && /session invalidated/.test(error.message)
  );
  assert.equal(nullifierChecks, 1);
  assert.equal(boundaryChecks, 1);
  assert.equal(broadcastCalls, 0);
  const stored = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(stored.status, reservationStatuses.ReplanRequired);
  assert.equal(stored.broadcast_attempt_count, 1);
  assert.equal(stored.broadcast_in_flight, false);
  assert.equal(stored.submitted_tx_hash, signedTxHash);
  assert.equal(stored.metadata.rpc_invoked, false);
  assert.equal(stored.metadata.broadcast_aborted_before_rpc, true);
  assert.equal(stored.metadata.check_tx_rejected, false);
  assert.equal(stored.metadata.proof_discarded, true);
});

test("cosmos beforeBroadcast rejects Promise-returning callbacks without submitting", async () => {
  const signedTx = signedTxFixture([13, 14, 15]);
  const client = cosmosTestClient();
  const { txHash: signedTxHash } = signedTxIdentity(client, signedTx);
  const { store, reservationManager, reservation } = await readyBroadcastReservation("2f", {
    signDocHash: cosmosSignDocBindingHash(signedTx)
  });
  let broadcastCalls = 0;
  client.connect = async () => ({
    async broadcastTxSync() {
      broadcastCalls += 1;
      return signedTxHash;
    }
  });

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, {
      reservationManager,
      reservation,
      beforeBroadcast: async () => {}
    }),
    error => error.txHash === signedTxHash && /must not return a Promise/.test(error.message)
  );
  assert.equal(broadcastCalls, 0);
  const stored = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(stored.status, reservationStatuses.ReplanRequired);
  assert.equal(stored.submitted_tx_hash, signedTxHash);
  assert.equal(stored.metadata.rpc_invoked, false);
  assert.equal(stored.metadata.broadcast_aborted_before_rpc, true);
});

test("cosmos explicit CheckTx rejection replans instead of becoming Unknown", async () => {
  const signedTx = signedTxFixture([16, 17, 18]);
  const client = cosmosTestClient();
  const { txHash: signedTxHash } = signedTxIdentity(client, signedTx);
  const { store, reservationManager, reservation } = await readyBroadcastReservation("30", {
    signDocHash: cosmosSignDocBindingHash(signedTx)
  });
  client.connect = async () => ({
    async broadcastTxSync() {
      throw Object.freeze(new BroadcastTxError(32, "sdk", "account sequence mismatch"));
    }
  });

  await assert.rejects(
    () => client.broadcastSignedTx(signedTx, { reservationManager, reservation }),
    error => error instanceof BroadcastTxError &&
      error.code === 32 &&
      error.txHash === signedTxHash &&
      error.rpcInvoked === true &&
      error.checkTxRejected === true
  );
  const stored = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(stored.status, reservationStatuses.ReplanRequired);
  assert.equal(stored.broadcast_attempt_count, 1);
  assert.equal(stored.broadcast_in_flight, false);
  assert.equal(stored.submitted_tx_hash, signedTxHash);
  assert.equal(stored.metadata.rpc_invoked, true);
  assert.equal(stored.metadata.check_tx_rejected, true);
  assert.equal(stored.metadata.broadcast_aborted_before_rpc, false);
  assert.equal(stored.metadata.no_broadcast_attempt, false);
  assert.equal(stored.metadata.provider_rejection_code, "32");
  assert.equal(stored.metadata.provider_rejection_codespace, "sdk");
  assert.equal(stored.metadata.provider_rejection_log, "account sequence mismatch");
  assert.equal(stored.metadata.proof_discarded, true);
});

test("cosmos broadcastSignedTx does not mark unindexed transactions as ok", async () => {
  const client = cosmosTestClient();
  const signedTx = signedTxFixture([1, 2, 3]);
  const { txHash: signedTxHash } = signedTxIdentity(client, signedTx);
  client.connect = async () => ({
    broadcastTxSync: async () => signedTxHash
  });
  client.waitForTx = async () => null;

  const result = await client.broadcastSignedTx(signedTx);

  assert.equal(result.ok, false);
  assert.equal(result.tx, null);
  assert.equal(result.broadcast.code, null);
  assert.match(result.error, /broadcast but not found yet/);
});

test("cosmos broadcast persists an attempt before RPC and blocks retry when bookkeeping fails", async () => {
  const signedTx = signedTxFixture([4, 5, 6]);
  const { store, reservationManager, reservation } = await readyBroadcastReservation("21", {
    signDocHash: cosmosSignDocBindingHash(signedTx)
  });
  const client = cosmosTestClient();
  const { txBytesHash: expectedTxBytesHash } = signedTxIdentity(client, signedTx);
  const transportError = Object.freeze(new Error("RPC response was lost"));
  const expectedTxBytesHash = createHash("sha256")
    .update(client.buildTxRawBytes(signedTx))
    .digest("hex");
  let broadcastCalls = 0;
  client.connect = async () => ({
    broadcastTxSync: async () => {
      broadcastCalls += 1;
      const stored = await store.getReservation(reservation.reservation_ids[0]);
      assert.equal(stored.broadcast_in_flight, true);
      assert.equal(stored.broadcast_attempt_count, 1);
      assert.equal(stored.submitted_tx_hash, expectedTxBytesHash.toUpperCase());
      assert.equal(stored.tx_bytes_hash, expectedTxBytesHash);
      throw transportError;
    }
  });
  reservationManager.markUnknown = async () => {
    throw new Error("IndexedDB write failed");
  };

  const broadcast = () => client.broadcastSignedTx(
    signedTx,
    { reservationManager, reservation }
  );
  await assert.rejects(
    broadcast,
    error => error.message === "RPC response was lost" &&
      error.cause === transportError &&
      error.reservationReconciliationRequired === true &&
      /IndexedDB write failed/.test(error.reservationBookkeepingError?.message || "")
  );
  const unresolved = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(unresolved.status, reservationStatuses.ProofReady);
  assert.equal(unresolved.broadcast_in_flight, true);
  assert.equal(unresolved.submitted_tx_hash, expectedTxBytesHash.toUpperCase());
  assert.equal(unresolved.tx_bytes_hash, expectedTxBytesHash);

  await assert.rejects(broadcast, /broadcast attempt already started; reconcile before retry/);
  assert.equal(broadcastCalls, 1);
});

test("cosmos accepted transaction with a lost RPC response reconciles by its precomputed TxHash", async () => {
  const signedTx = signedTxFixture([7, 8, 9]);
  const { store, reservationManager, reservation, note } = await readyBroadcastReservation("29", {
    signDocHash: cosmosSignDocBindingHash(signedTx),
    proofReady: {
      expectedOutputCommitment: "OUT",
      expectedDisclosureDigest: "DIGEST",
      expectedRecipientHash: "RECIPIENT",
      expectedAmount: "5",
      expectedAmountHash: "AMOUNT",
      expectedDenom: "uclair",
      batchItemIndexKnown: false,
      operationSuccessEvidenceRequired: true
    }
  });
  const client = cosmosTestClient();
  const { txRawBytes, txHash: signedTxHash } = signedTxIdentity(client, signedTx);
  client.connect = async () => ({
    async broadcastTxSync(bytes) {
      assert.deepEqual(bytes, txRawBytes);
      const attempting = await store.getReservation(reservation.reservation_ids[0]);
      assert.equal(attempting.submitted_tx_hash, signedTxHash);
      assert.equal(attempting.tx_bytes_hash, signedTxHash.toLowerCase());
      throw new Error("RPC response was lost after node acceptance");
    }
  });

  await assert.rejects(
    () => client.broadcastSignedTx(
      signedTx,
      { reservationManager, reservation }
    ),
    error => error.txHash === signedTxHash && /response was lost/.test(error.message)
  );
  const unknown = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(unknown.status, reservationStatuses.Unknown);
  assert.equal(unknown.submitted_tx_hash, signedTxHash);

  await reservationManager.reconcileSpentNotes([{
    ...note,
    isSpent: true,
    nullifierStatus: "spent",
    operationSuccessEvidence: {
      txHash: signedTxHash,
      outputCommitment: "OUT",
      disclosureDigest: "DIGEST",
      recipientHash: "RECIPIENT",
      amount: "5",
      amountHash: "AMOUNT",
      denom: "uclair"
    }
  }]);
  const reconciled = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(reconciled.status, reservationStatuses.ConfirmedSpent);
  assert.equal(reconciled.metadata.operation_status, operationStatuses.Succeeded);
});

test("reserved Cosmos broadcasts reject sign docs changed after ProofReady", async () => {
  const { reservationManager, reservation } = await readyBroadcastReservation("28", {
    signDocHash: cosmosSignDocBindingHash({ bodyBytes: "", authInfoBytes: "" })
  });
  const client = cosmosTestClient();
  let connectCalls = 0;
  client.connect = async () => {
    connectCalls += 1;
    return { broadcastTxSync: async () => "UNREACHABLE" };
  };
  await assert.rejects(
    () => client.broadcastSignedTx({
      bodyBytes: "",
      authInfoBytes: Buffer.from([1]).toString("base64"),
      signature: ""
    }, { reservationManager, reservation }),
    /does not match the reservation ProofReady artifact/
  );
  assert.equal(connectCalls, 0);
});

test("relay broadcasts recheck authoritative chain time before external submission", async () => {
  const cosmosPayload = {
    version: "v2",
    proof_hex: "01",
    root_hex: "08".repeat(32),
    nullifier_hex: "09".repeat(32),
    amount: "1udemo",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "clair"),
    chain_id: "clairveil-local-3",
    expires_at_unix: 1_001
  };
  cosmosPayload.payload_hash = computePreparedWithdrawPayloadHash(cosmosPayload);
  const cosmos = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  let cosmosBroadcastCalls = 0;
  cosmos.connect = async () => ({
    async broadcastTxSync() {
      cosmosBroadcastCalls += 1;
      return "COSMOS-TX";
    }
  });

  const relayAddress = evmAddressToBech32(
    "0x2222222222222222222222222222222222222222",
    "clair"
  );
  const staleCosmosMessage = cosmos.buildRelayWithdrawMessageFromPayload({
    payload: cosmosPayload,
    relayer: relayAddress,
    chainNowUnix: 1_000
  });
  const legacyCosmosMessage = cosmos.buildRelayWithdrawMessageFromPayload({
    payload: cosmosPayload,
    relayer: relayAddress,
    nowUnix: 1_000
  });
  assert.deepEqual(legacyCosmosMessage, staleCosmosMessage);
  cosmos.buildDirectSignDoc = async input => input;
  const legacyCosmosSignDoc = await cosmos.createRelayWithdrawSignDoc({
    payload: cosmosPayload,
    relayer: relayAddress,
    pubKeyHex: "02".padEnd(66, "0"),
    nowUnix: 1_000
  });
  assert.deepEqual(legacyCosmosSignDoc.message, staleCosmosMessage);
  assert.deepEqual(
    cosmos.buildRelayWithdrawMessageFromPayload({
      payload: cosmosPayload,
      relayer: relayAddress,
      chainNowUnix: 1_000,
      nowUnix: 1_500
    }),
    staleCosmosMessage
  );
  const staleCosmosSignedTx = {
    bodyBytes: Buffer.from(cosmos.registry.encodeTxBody({
      messages: [{ typeUrl: MsgWithdraw.typeUrl, value: staleCosmosMessage }],
      memo: ""
    })).toString("base64"),
    authInfoBytes: "",
    signature: ""
  };
  cosmos.checkNullifiers = async nullifiers => new Map(
    nullifiers.map(nullifier => [nullifier, false])
  );
  await assert.rejects(
    () => cosmos.broadcastSignedTx(
      staleCosmosSignedTx,
      { relayPayload: cosmosPayload, getChainNowUnix: async () => 1_002 }
    ),
    /withdraw payload expired/
  );
  assert.equal(cosmosBroadcastCalls, 0);
  await assert.rejects(
    () => cosmos.broadcastSignedTx(staleCosmosSignedTx),
    /withdraw broadcast requires relayPayload/
  );
  const freshCosmosPayload = {
    ...cosmosPayload,
    nullifier_hex: "0a".repeat(32),
    expires_at_unix: 2_000
  };
  freshCosmosPayload.payload_hash = computePreparedWithdrawPayloadHash(freshCosmosPayload);
  await assert.rejects(
    () => cosmos.broadcastSignedTx(staleCosmosSignedTx, {
      relayPayload: freshCosmosPayload,
      getChainNowUnix: async () => 1_500
    }),
    /does not match the Cosmos signed transaction/
  );
  assert.equal(cosmosBroadcastCalls, 0);

  const evmPayload = {
    ...cosmosPayload,
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chain_id: "demo-1"
  };
  evmPayload.payload_hash = computePreparedWithdrawPayloadHash(evmPayload);
  const evm = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
    chainId: "demo-1",
    accountPrefix: "demo"
  });
  let evmBroadcastCalls = 0;
  await assert.rejects(
    () => evm.sendTransaction({
      async sendTransaction() {
        evmBroadcastCalls += 1;
        return "0x" + "42".repeat(32);
      }
    }, { to: testPrivacyContractAddress }, {
      relayPayload: evmPayload,
      chainNowUnix: 1_002
    }),
    /withdraw payload expired/
  );
  assert.equal(evmBroadcastCalls, 0);

  const staleEvmTransaction = await evm.buildWithdrawTransaction({
    payload: evmPayload,
    chainNowUnix: 1_000
  });
  let submittedEvmTransaction = null;
  const wallet = {
    async sendTransaction(transaction) {
      submittedEvmTransaction = transaction;
      evmBroadcastCalls += 1;
      return "0x" + "42".repeat(32);
    }
  };
  await assert.rejects(
    () => evm.sendTransaction(wallet, staleEvmTransaction.transaction),
    /withdraw broadcast requires relayPayload/
  );
  const freshEvmPayload = {
    ...evmPayload,
    nullifier_hex: "0b".repeat(32),
    expires_at_unix: 2_000
  };
  freshEvmPayload.payload_hash = computePreparedWithdrawPayloadHash(freshEvmPayload);
  await assert.rejects(
    () => evm.sendTransaction(wallet, staleEvmTransaction.transaction, {
      relayPayload: freshEvmPayload,
      chainNowUnix: 1_500
    }),
    /does not match the EVM transaction/
  );
  assert.equal(evmBroadcastCalls, 0);
  await assert.rejects(
    () => evm.sendTransaction(wallet, {
      ...staleEvmTransaction.transaction,
      value: "0x1"
    }, {
      relayPayload: evmPayload,
      chainNowUnix: 1_000
    }),
    /binding was modified|does not match the EVM transaction/
  );
  await assert.rejects(
    () => evm.sendTransaction(wallet, {
      ...staleEvmTransaction.transaction,
      chainId: "0x1"
    }, {
      relayPayload: evmPayload,
      chainNowUnix: 1_000
    }),
    /expectedEvmChainId is required/
  );
  await evm.sendTransaction(wallet, staleEvmTransaction.transaction, {
    relayPayload: evmPayload,
    getChainNowUnix: async () => 1_000,
    checkNullifiers: async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false]))
  });
  assert.equal(evmBroadcastCalls, 1);
  await evm.sendTransaction(wallet, {
    ...staleEvmTransaction.transaction,
    chainId: "0x01",
    from: "0x3333333333333333333333333333333333333333",
    gas: "0x5208",
    maxFeePerGas: "0x10"
  }, {
    relayPayload: evmPayload,
    getChainNowUnix: async () => 1_000,
    expectedEvmChainId: "0x1",
    checkNullifiers: async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false]))
  });
  assert.equal(evmBroadcastCalls, 2);
  assert.equal(submittedEvmTransaction.chainId, "0x1");
  assert.equal("from" in submittedEvmTransaction, false);
  assert.equal("gas" in submittedEvmTransaction, false);
  assert.equal("maxFeePerGas" in submittedEvmTransaction, false);
});

test("custom EVM withdraw encoders retain the relay validation marker", async () => {
  const payload = {
    version: "v2",
    proof_hex: "01",
    root_hex: "08".repeat(32),
    nullifier_hex: "09".repeat(32),
    amount: "1udemo",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chain_id: "demo-1",
    expires_at_unix: 2_000
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);
  const contractAdapter = {
    contractAddress: testPrivacyContractAddress,
    buildDepositTransaction: () => ({ to: testPrivacyContractAddress, data: "0x01" }),
    buildTransferTransaction: () => ({ to: testPrivacyContractAddress, data: "0x02" }),
    buildWithdrawTransaction: () => ({ to: testPrivacyContractAddress, data: "0xcafebabe", value: "0x0" })
  };
  const client = createClairveilEvmClient({
    chainId: "demo-1",
    accountPrefix: "demo",
    contractAdapter
  });
  const prepared = await client.buildWithdrawTransaction({ payload, chainNowUnix: 1_000 });
  let calls = 0;
  await assert.rejects(
    () => client.sendTransaction({
      async sendTransaction() {
        calls += 1;
        return "0x" + "42".repeat(32);
      }
    }, prepared.transaction),
    /withdraw broadcast requires relayPayload/
  );
  assert.equal(calls, 0);
});

test("reserved EVM broadcasts validate authoritative reservation records", async () => {
  const payload = {
    version: "v2",
    proof_hex: "01",
    root_hex: "08".repeat(32),
    nullifier_hex: "0c".repeat(32),
    amount: "1udemo",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chain_id: "demo-1",
    expires_at_unix: 2_000
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);
  const client = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
    chainId: "demo-1",
    accountPrefix: "demo"
  });
  const prepared = await client.buildWithdrawTransaction({ payload, chainNowUnix: 1_000 });
  const context = await readyBroadcastReservation("27", {
    payloadHash: payload.payload_hash,
    inputNullifiers: [payload.nullifier_hex]
  });
  const callerSnapshotWithoutRecords = { ...context.reservation, reservations: [] };
  const otherPayload = {
    ...payload,
    nullifier_hex: "0d".repeat(32)
  };
  otherPayload.payload_hash = computePreparedWithdrawPayloadHash(otherPayload);
  let calls = 0;
  let submittedTransaction = null;
  const wallet = {
    async sendTransaction(transaction) {
      submittedTransaction = transaction;
      calls += 1;
      return "0x" + "27".repeat(32);
    }
  };
  await assert.rejects(
    () => client.sendTransaction(wallet, prepared.transaction, {
      reservationManager: context.reservationManager,
      reservation: callerSnapshotWithoutRecords,
      relayPayload: otherPayload,
      chainNowUnix: 1_000
    }),
    /reserved payload hash/
  );
  assert.equal(calls, 0);
  const callerTransaction = {
    ...prepared.transaction,
    chainId: "0x01",
    from: "0x3333333333333333333333333333333333333333",
    gas: "0x5208",
    maxFeePerGas: "0x10",
    nonce: "0x2"
  };
  await client.sendTransaction(wallet, callerTransaction, {
    reservationManager: context.reservationManager,
    reservation: callerSnapshotWithoutRecords,
    relayPayload: payload,
    chainNowUnix: 1_000,
    expectedEvmChainId: "0x1",
    checkNullifiers: async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false]))
  });
  assert.equal(calls, 1);
  assert.equal(submittedTransaction.chainId, "0x1");
  assert.equal("from" in submittedTransaction, false);
  assert.equal("gas" in submittedTransaction, false);
  assert.equal("maxFeePerGas" in submittedTransaction, false);
  assert.equal("nonce" in submittedTransaction, false);
  const stored = await context.store.getReservation(context.reservation.reservation_ids[0]);
  assert.equal(stored.tx_bytes_hash, evmTransactionBindingHash(submittedTransaction));
  assert.notEqual(stored.tx_bytes_hash, evmTransactionBindingHash(callerTransaction));

  const boundTransaction = {
    ...prepared.transaction,
    chainId: "0x1",
    gas: "0x5208",
    accessList: [{ address: "0x4444444444444444444444444444444444444444", storageKeys: [] }],
    customData: { unbound: true }
  };
  const boundContext = await readyBroadcastReservation("28", {
    payloadHash: payload.payload_hash,
    txBytesHash: evmTransactionBindingHash(boundTransaction),
    inputNullifiers: [payload.nullifier_hex]
  });
  let submittedBoundTransaction = null;
  await client.sendTransaction({
    async sendTransaction(transaction) {
      submittedBoundTransaction = transaction;
      return "0x" + "28".repeat(32);
    }
  }, boundTransaction, {
    reservationManager: boundContext.reservationManager,
    reservation: boundContext.reservation,
    relayPayload: payload,
    chainNowUnix: 1_000,
    expectedEvmChainId: "0x1",
    checkNullifiers: async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false]))
  });
  assert.equal(submittedBoundTransaction.gas, "0x5208");
  assert.equal("accessList" in submittedBoundTransaction, false);
  assert.equal("customData" in submittedBoundTransaction, false);
  assert.equal(
    Object.keys(submittedBoundTransaction).some(key => key.startsWith("__clairveil")),
    false
  );
  const storedBound = await boundContext.store.getReservation(
    boundContext.reservation.reservation_ids[0]
  );
  assert.equal(storedBound.tx_bytes_hash, evmTransactionBindingHash(submittedBoundTransaction));
});

test("reserved EVM broadcasts preserve frozen wallet errors when bookkeeping also fails", async () => {
  const payload = {
    version: "v2",
    proof_hex: "01",
    root_hex: "08".repeat(32),
    nullifier_hex: "0e".repeat(32),
    amount: "1udemo",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chain_id: "demo-1",
    expires_at_unix: 2_000
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);
  const client = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
    chainId: "demo-1",
    accountPrefix: "demo"
  });
  const prepared = await client.buildWithdrawTransaction({ payload, chainNowUnix: 1_000 });
  const context = await readyBroadcastReservation("29", {
    payloadHash: payload.payload_hash,
    inputNullifiers: [payload.nullifier_hex]
  });
  const transportError = Object.freeze(new Error("wallet response was lost"));
  context.reservationManager.markManualReview = async () => {
    throw new Error("IndexedDB write failed");
  };

  await assert.rejects(
    () => client.sendTransaction({
      async sendTransaction() {
        throw transportError;
      }
    }, prepared.transaction, {
      reservationManager: context.reservationManager,
      reservation: context.reservation,
      relayPayload: payload,
      chainNowUnix: 1_000,
      checkNullifiers: async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false]))
    }),
    error => error.message === "wallet response was lost" &&
      error.cause === transportError &&
      error.reservationReconciliationRequired === true &&
      /IndexedDB write failed/.test(error.reservationBookkeepingError?.message || "")
  );
});

test("reserved EVM transaction guards survive JSON serialization", async () => {
  const client = createClairveilEvmClient({ contractAddress: testPrivacyContractAddress });
  const selectors = [
    functionSelector("transfer((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes,bytes,bytes,uint64))"),
    functionSelector("withdraw((bytes,bytes,bytes,string,address,string,uint64))")
  ];
  let calls = 0;

  for (const selector of selectors) {
    const transaction = JSON.parse(JSON.stringify(markEvmTransactionReservationRequired({
      to: testPrivacyContractAddress,
      data: `0x${selector}`,
      value: "0x0"
    })));
    await assert.rejects(
      () => client.sendTransaction({
        async sendTransaction() {
          calls += 1;
          return "0x" + "29".repeat(32);
        }
      }, transaction),
      /requires reservationManager and reservation/
    );
  }

  assert.equal(calls, 0);
});

test("cosmos signDirectAndBroadcast replans a ProofReady reservation after wallet rejection", async () => {
  const signDoc = {
    chainId: "clairveil-local-3",
    bodyBytes: "",
    authInfoBytes: "",
    accountNumber: "0"
  };
  const { store, reservationManager, reservation } = await readyBroadcastReservation("26", {
    signDocHash: cosmosSignDocBindingHash(signDoc)
  });
  const client = cosmosTestClient();
  const rejected = new Error("User rejected the request");
  rejected.code = 4001;

  await assert.rejects(
    () => client.signDirectAndBroadcast({
      wallet: {
        async signDirect() {
          throw rejected;
        }
      },
      signDoc,
      reservationManager,
      reservation
    }),
    error => error === rejected
  );

  const stored = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(stored.status, reservationStatuses.ReplanRequired);
  assert.equal(stored.broadcast_attempt_count, 0);
  assert.equal(stored.broadcast_in_flight, false);
  assert.equal(stored.metadata.wallet_rejected_before_broadcast, true);
  assert.equal(stored.metadata.no_broadcast_attempt, true);
  assert.equal(stored.metadata.proof_discarded, true);
});

test("cosmos signDirectAndBroadcast validates authoritative sign-doc binding before wallet access", async () => {
  const preparedSignDoc = {
    chainId: "clairveil-local-3",
    bodyBytes: "",
    authInfoBytes: "",
    accountNumber: "0"
  };
  const mismatchedSignDoc = {
    ...preparedSignDoc,
    authInfoBytes: Buffer.from([1]).toString("base64")
  };
  const { store, reservationManager, reservation } = await readyBroadcastReservation("2a", {
    signDocHash: cosmosSignDocBindingHash(preparedSignDoc)
  });
  const client = cosmosTestClient();
  let signCalls = 0;

  await assert.rejects(
    () => client.signDirectAndBroadcast({
      wallet: {
        async signDirect() {
          signCalls += 1;
          throw new Error("wallet must not be called");
        }
      },
      signDoc: mismatchedSignDoc,
      reservationManager,
      reservation
    }),
    /does not match the reservation ProofReady artifact/
  );

  assert.equal(signCalls, 0);
  const stored = await store.getReservation(reservation.reservation_ids[0]);
  assert.equal(stored.status, reservationStatuses.ProofReady);
  assert.equal(stored.metadata.wallet_rejected_before_broadcast, undefined);
  assert.equal(stored.broadcast_attempt_count, 0);
});

test("cosmos signDirectAndBroadcast heartbeats from wallet approval through terminal reservation recording", async () => {
  const signDoc = {
    chainId: "clairveil-local-3",
    bodyBytes: "",
    authInfoBytes: "",
    accountNumber: "0"
  };
  const { store, reservationManager, reservation } = await readyBroadcastReservation("2b", {
    signDocHash: cosmosSignDocBindingHash(signDoc),
    leaseDurationMs: 90
  });
  const originalRenewLease = reservationManager.renewLease.bind(reservationManager);
  let renewCalls = 0;
  let terminalRenewFailures = 0;
  reservationManager.renewLease = async (...args) => {
    renewCalls += 1;
    try {
      return await originalRenewLease(...args);
    } catch (error) {
      const current = await store.getReservation(reservation.reservation_ids[0]);
      if (current.status === reservationStatuses.Submitted) {
        terminalRenewFailures += 1;
      }
      throw error;
    }
  };
  const originalMarkSubmitted = reservationManager.markSubmitted.bind(reservationManager);
  reservationManager.markSubmitted = async (...args) => {
    const submitted = await originalMarkSubmitted(...args);
    // Keep the method pending after its durable terminal CAS so the timer can
    // observe the now-inactive record. That race must not turn a successful
    // terminal write into a false reconciliation warning.
    await new Promise(resolve => setTimeout(resolve, 220));
    return submitted;
  };
  const client = cosmosTestClient();
  client.connect = async () => ({
    broadcastTxSync: async bytes => createHash("sha256").update(bytes).digest("hex").toUpperCase()
  });
  client.waitForTx = async txHash => ({ txhash: txHash, code: 0, raw_log: "", events: [] });

  const result = await client.signDirectAndBroadcast({
    wallet: {
      async signDirect(directSignDoc) {
        await new Promise(resolve => setTimeout(resolve, 140));
        return {
          signed: directSignDoc,
          signature: { signature: "AQ==" }
        };
      }
    },
    signDoc,
    reservationManager,
    reservation
  });

  assert.equal(result.ok, true);
  assert.ok(renewCalls >= 3, `expected repeated lease renewal, got ${renewCalls}`);
  assert.ok(
    terminalRenewFailures >= 1,
    `expected the in-flight timer to observe the durable terminal status (renew calls: ${renewCalls})`
  );
  assert.equal(result.reservationReconciliationRequired, undefined);
  assert.equal((await store.getReservation(reservation.reservation_ids[0])).status, reservationStatuses.Submitted);
});

test("cosmos signDirectAndBroadcast fails before wallet access when reservation heartbeat is unavailable", async () => {
  const signDoc = {
    chainId: "clairveil-local-3",
    bodyBytes: "",
    authInfoBytes: "",
    accountNumber: "0"
  };
  let signCalls = 0;
  const client = cosmosTestClient();
  await assert.rejects(
    () => client.signDirectAndBroadcast({
      wallet: {
        async signDirect() {
          signCalls += 1;
          throw new Error("wallet must not be reached");
        }
      },
      signDoc,
      reservationManager: { async markBroadcastAttempting() {} },
      reservation: {
        reservation_ids: ["reservation-no-heartbeat"],
        lease_token: "lease-no-heartbeat"
      }
    }),
    /renewLease is required/
  );
  assert.equal(signCalls, 0);

  const context = await readyBroadcastReservation("2c", {
    signDocHash: cosmosSignDocBindingHash(signDoc)
  });
  context.reservationManager.renewLease = async () => {
    throw new Error("durable heartbeat failed");
  };
  await assert.rejects(
    () => client.signDirectAndBroadcast({
      wallet: {
        async signDirect() {
          signCalls += 1;
          throw new Error("wallet must not be reached");
        }
      },
      signDoc,
      reservationManager: context.reservationManager,
      reservation: context.reservation
    }),
    /durable heartbeat failed/
  );
  assert.equal(signCalls, 0);
  assert.equal(
    (await context.store.getReservation(context.reservation.reservation_ids[0])).status,
    reservationStatuses.ProofReady
  );
});

test("cosmos signDirectAndBroadcast forwards top-level polling options", async () => {
  const client = cosmosTestClient();
  const signDoc = {
    chainId: "clairveil-local-3",
    bodyBytes: "",
    authInfoBytes: "",
    accountNumber: "0"
  };
  let signCalls = 0;
  let forwardedOptions;
  const wallet = {
    async signDirect(directSignDoc) {
      signCalls += 1;
      return {
        signed: directSignDoc,
        signature: { signature: "AQ==" }
      };
    }
  };
  client.broadcastTxRawBytes = async (_txRawBytes, options) => {
    forwardedOptions = options;
    return { ok: true };
  };

  await client.signDirectAndBroadcast({
    wallet,
    signDoc,
    attempts: 3,
    intervalMs: 7
  });
  assert.equal(forwardedOptions.attempts, 3);
  assert.equal(forwardedOptions.intervalMs, 7);

  await assert.rejects(
    () => client.signDirectAndBroadcast({
      wallet,
      signDoc,
      attempts: 3,
      waitOptions: { attempts: 4 }
    }),
    /attempts conflicts with waitOptions\.attempts/
  );
  assert.equal(signCalls, 1);
});

test("EVM sendTransaction records Submitted or ManualReview after a durable attempt", async () => {
  const submittedContext = await readyBroadcastReservation("22", {
    txBytesHash: evmTransactionBindingHash({ to: testPrivacyContractAddress })
  });
  let submittedCalls = 0;
  const submittedClient = createClairveilEvmClient({ contractAddress: testPrivacyContractAddress });
  const txHash = await submittedClient.sendTransaction({
    async sendTransaction() {
      submittedCalls += 1;
      const stored = await submittedContext.store.getReservation(
        submittedContext.reservation.reservation_ids[0]
      );
      assert.equal(stored.broadcast_in_flight, true);
      return "0x" + "22".repeat(32);
    }
  }, { to: testPrivacyContractAddress }, {
    reservationManager: submittedContext.reservationManager,
    reservation: submittedContext.reservation,
    checkNullifiers: async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false]))
  });
  assert.equal(txHash, "0x" + "22".repeat(32));
  assert.equal(submittedCalls, 1);
  const submitted = await submittedContext.store.getReservation(
    submittedContext.reservation.reservation_ids[0]
  );
  assert.equal(submitted.status, reservationStatuses.Submitted);
  assert.equal(submitted.broadcast_in_flight, false);

  const ambiguousContext = await readyBroadcastReservation("23", {
    txBytesHash: evmTransactionBindingHash({ to: testPrivacyContractAddress })
  });
  let ambiguousCalls = 0;
  const ambiguousClient = createClairveilEvmClient({ contractAddress: testPrivacyContractAddress });
  await assert.rejects(
    () => ambiguousClient.sendTransaction({
      async sendTransaction() {
        ambiguousCalls += 1;
        const stored = await ambiguousContext.store.getReservation(
          ambiguousContext.reservation.reservation_ids[0]
        );
        assert.equal(stored.broadcast_in_flight, true);
        throw new Error("provider response unavailable");
      }
    }, { to: testPrivacyContractAddress }, {
      reservationManager: ambiguousContext.reservationManager,
      reservation: ambiguousContext.reservation,
      checkNullifiers: async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false]))
    }),
    /provider response unavailable/
  );
  const reviewed = await ambiguousContext.store.getReservation(
    ambiguousContext.reservation.reservation_ids[0]
  );
  assert.equal(reviewed.status, reservationStatuses.ManualReview);
  assert.equal(reviewed.broadcast_in_flight, false);
  assert.equal(reviewed.last_broadcast_error, "sdk_evm_broadcast_result_unknown");
  await assert.rejects(
    () => ambiguousClient.sendTransaction({
      async sendTransaction() {
        ambiguousCalls += 1;
        return "0x" + "23".repeat(32);
      }
    }, { to: testPrivacyContractAddress }, {
      reservationManager: ambiguousContext.reservationManager,
      reservation: ambiguousContext.reservation,
      checkNullifiers: async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false]))
    }),
    /broadcast attempt requires ProofReady reservation: ManualReview/
  );
  assert.equal(ambiguousCalls, 1);

  const rejectedContext = await readyBroadcastReservation("24", {
    txBytesHash: evmTransactionBindingHash({ to: testPrivacyContractAddress })
  });
  const rejectedClient = createClairveilEvmClient({ contractAddress: testPrivacyContractAddress });
  await assert.rejects(
    () => rejectedClient.sendTransaction({
      async sendTransaction() {
        const error = new Error("User rejected the request");
        error.code = 4001;
        throw error;
      }
    }, { to: testPrivacyContractAddress }, {
      reservationManager: rejectedContext.reservationManager,
      reservation: rejectedContext.reservation,
      checkNullifiers: async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false]))
    }),
    error => error.code === 4001
  );
  const rejected = await rejectedContext.store.getReservation(
    rejectedContext.reservation.reservation_ids[0]
  );
  assert.equal(rejected.status, reservationStatuses.ReplanRequired);
  assert.equal(rejected.broadcast_in_flight, false);
  assert.equal(rejected.last_broadcast_error, "wallet_rejected_before_broadcast");
  assert.equal(rejected.metadata.wallet_rejected_before_broadcast, true);
});

test("EVM sendTransaction rejects malformed provider transaction hashes", async () => {
  const context = await readyBroadcastReservation("25", {
    txBytesHash: evmTransactionBindingHash({ to: testPrivacyContractAddress })
  });
  const client = createClairveilEvmClient({ contractAddress: testPrivacyContractAddress });

  await assert.rejects(
    () => client.sendTransaction({
      async sendTransaction() {
        return "provider-request-id";
      }
    }, { to: testPrivacyContractAddress }, {
      reservationManager: context.reservationManager,
      reservation: context.reservation,
      checkNullifiers: async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false]))
    }),
    /invalid transaction hash/
  );

  const reviewed = await context.store.getReservation(context.reservation.reservation_ids[0]);
  assert.equal(reviewed.status, reservationStatuses.ManualReview);
  assert.equal(reviewed.broadcast_in_flight, false);
  assert.equal(reviewed.submitted_tx_hash, "");
});

test("relay handoff README snippets bind the prepared payload hash", () => {
  for (const filename of ["README.md", "README.ko.md"]) {
    const source = readFileSync(new URL(`../${filename}`, import.meta.url), "utf8");
    assert.match(source, /async function fetchLatestChainBlockTimeUnix\(\)/);
    assert.match(source, /cosmos\/base\/tendermint\/v1beta1\/blocks\/latest/);
    assert.match(source, /sdk_block\?\.header\?\.time/);
    const prepareBlocks = source.match(/prepareRelayWithdraw\(\{[\s\S]{0,420}?\}\);/g) || [];
    assert.ok(prepareBlocks.length > 0, `${filename} must document relay preparation`);
    const chainTimeRefreshes = source.match(
      /latestChainBlockTimeUnix\s*=\s*await fetchLatestChainBlockTimeUnix\(\)/g
    ) || [];
    assert.ok(
      chainTimeRefreshes.length >= prepareBlocks.length,
      `${filename} must refresh chain time before each relay preparation example`
    );
    for (const block of prepareBlocks) {
      assert.match(block, /chainNowUnix:\s*latestChainBlockTimeUnix/);
    }
    const handoffBlocks = source.match(/recordRelayHandoff\([\s\S]{0,280}?\);/g) || [];
    assert.ok(handoffBlocks.length > 0, `${filename} must document relay handoff`);
    for (const block of handoffBlocks) {
      assert.match(block, /payloadHash:\s*prepared\.payload\.payload_hash/);
    }
    const encryptDefinition = source.indexOf("const encryptReservationState = async state =>");
    const decryptDefinition = source.indexOf("const decryptReservationState = async value =>");
    const reservationStore = source.indexOf("const reservationStore = createBrowserReservationStore");
    assert.ok(encryptDefinition >= 0 && encryptDefinition < reservationStore);
    assert.ok(decryptDefinition >= 0 && decryptDefinition < reservationStore);
    assert.match(source, /clairveil\/reservation-state\/v1/);
    assert.match(source, /name:\s*"AES-GCM"/);
  }
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
    assert.equal(result.nullifier, "bb".repeat(32));
    assert.deepEqual(requestedUrls, [
      `http://rest-a.local/clairveil/privacy/v1/nullifier/${"bb".repeat(32)}`,
      `http://rest-a.local/clairveil/privacy/v1/nullifier/${"bb".repeat(32)}`,
      `http://rest-b.local/clairveil/privacy/v1/nullifier/${"bb".repeat(32)}`
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("default nullifier queries stay pinned after REST failover", async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  globalThis.fetch = async url => {
    const text = String(url);
    requestedUrls.push(text);
    if (text.includes("/events")) {
      if (text.startsWith("http://rest-a.local")) {
        return new Response("busy", { status: 503 });
      }
      return new Response(JSON.stringify({ events: [] }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    if (text.includes("/nullifier/")) {
      return new Response(JSON.stringify({ used: text.startsWith("http://rest-a.local") ? false : true }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    throw new Error(`unexpected request: ${text}`);
  };
  try {
    const factories = [
      () => createClairveilClient({
        rpc: "http://127.0.0.1:26657",
        rest: "http://rest-a.local",
        restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
        chainId: "clairveil-local-3",
        queryRetry: false
      }),
      () => createClairveilPublicClient({
        rest: "http://rest-a.local",
        restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
        queryRetry: false
      })
    ];
    for (const createClient of factories) {
      requestedUrls.length = 0;
      const client = createClient();
      await client.fetchPrivacyEvents();
      assert.equal(client.activeRestEndpoint, "http://rest-b.local");
      const result = await client.checkNullifier("cc".repeat(32));
      assert.equal(result.used, false);
      assert.equal(result.nullifier, "cc".repeat(32));
      assert.equal(client.activeRestEndpoint, "http://rest-b.local");
      assert.deepEqual(requestedUrls, [
        "http://rest-a.local/clairveil/privacy/v1/events",
        "http://rest-b.local/clairveil/privacy/v1/events",
        `http://rest-a.local/clairveil/privacy/v1/nullifier/${"cc".repeat(32)}`
      ]);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Merkle witness and exact-snapshot queries stay pinned unless failover is explicit", async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  globalThis.fetch = async url => {
    const text = String(url);
    requestedUrls.push(text);
    if (text.startsWith("http://rest-a.local")) {
      return new Response("busy", { status: 503 });
    }
    return new Response(JSON.stringify({}), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  const commitmentHex = "01".repeat(32);
  const rootHex = "02".repeat(32);
  const defaultFactories = [
    () => createClairveilClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://rest-a.local",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      chainId: "clairveil-local-3",
      queryRetry: false
    }),
    () => createClairveilPublicClient({
      rest: "http://rest-a.local",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      queryRetry: false
    })
  ];
  const failoverFactories = [
    () => createClairveilClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://rest-a.local",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      chainId: "clairveil-local-3",
      queryRetry: false,
      merklePathFailover: true
    }),
    () => createClairveilPublicClient({
      rest: "http://rest-a.local",
      restEndpoints: ["http://rest-a.local", "http://rest-b.local"],
      queryRetry: false,
      merklePathFailover: true
    })
  ];
  try {
    for (const createClient of defaultFactories) {
      const client = createClient();
      requestedUrls.length = 0;
      await assert.rejects(() => client.lookupMerklePath(commitmentHex), /503/);
      assert.deepEqual(requestedUrls, [
        `http://rest-a.local/clairveil/privacy/v1/merkle_path/${commitmentHex}`
      ]);

      requestedUrls.length = 0;
      await assert.rejects(
        () => client.fetchCommitmentPathsAtRoot({ commitmentHexes: [commitmentHex], rootHex }),
        /503/
      );
      assert.deepEqual(requestedUrls, [
        "http://rest-a.local/clairveil/privacy/v1/commitment_paths_at_root"
      ]);
    }

    for (const createClient of failoverFactories) {
      const client = createClient();
      requestedUrls.length = 0;
      await client.lookupMerklePath(commitmentHex);
      assert.deepEqual(requestedUrls, [
        `http://rest-a.local/clairveil/privacy/v1/merkle_path/${commitmentHex}`,
        `http://rest-b.local/clairveil/privacy/v1/merkle_path/${commitmentHex}`
      ]);

      requestedUrls.length = 0;
      client.activeRestEndpoint = client.rest;
      await client.fetchCommitmentPathsAtRoot({ commitmentHexes: [commitmentHex], rootHex });
      assert.deepEqual(requestedUrls, [
        "http://rest-a.local/clairveil/privacy/v1/commitment_paths_at_root",
        "http://rest-b.local/clairveil/privacy/v1/commitment_paths_at_root"
      ]);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("native 2x2 transfer builds both witnesses from one exact Merkle snapshot", async () => {
  const rootSeed = new Uint8Array(32).fill(17);
  const spendPubKey = deriveSpendKeys(rootSeed).pubKey;
  const viewPubKey = deriveViewKeys(rootSeed).pubKey;
  const inputs = [7n, 5n].map((amount, index) => ({
    note: createNote({
      spendPubKey,
      viewPubKey,
      amount,
      assetDenom: "uclair",
      randomness: BigInt(index + 31)
    }),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: `transfer-snapshot-${index}`,
    height: 1,
    sequence: index
  }));
  const directPathProvider = strictMerklePathProvider(inputs.map(input => input.note));
  const rootHex = (await directPathProvider.lookupMerklePath(
    fieldHexV1(computeNoteCommitmentV1(inputs[0].note))
  )).root;
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  client.assertTransferProtocolConfig = async () => transferProtocolConfig();
  client.fetchTreeState = async () => ({ root: rootHex });
  let snapshotRequest = null;
  client.createCommitmentPathSnapshotProvider = async request => {
    snapshotRequest = request;
    return directPathProvider;
  };
  const result = await client.buildTransferMessage({
    creator: "clair1snapshot",
    inputs,
    recipient: encodeShieldedAddress(spendPubKey, viewPubKey, { prefix: "clairs" }),
    amount: "7uclair",
    rootSeed,
    auditDisclosureTargetPubKeyHex: Buffer.from(packPoint(CURVE_BASE)).toString("hex"),
    chainNowUnix: Math.floor(Date.now() / 1000),
    checkNullifiers: async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false])),
    proverAdapter: {
      async proveTransfer({ payload }) {
        return { version: "v2", payload_hash: payload.payload_hash, proof_hex: validV2ProofHex };
      }
    }
  });

  assert.deepEqual(snapshotRequest, {
    commitmentHexes: inputs.map(input => fieldHexV1(computeNoteCommitmentV1(input.note))),
    rootHex
  });
  assert.equal(result.payload.root_hex, rootHex);
});

test("scan_events fallback rewinds a mid-block cursor for legacy scans", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://rest-a.local",
    chainId: "clairveil-local-3"
  });
  const legacyRequests = [];
  client.fetchScanEvents = async () => {
    const error = new Error("scan events unsupported");
    error.status = 404;
    throw error;
  };
  client.fetchPrivacyEvents = async request => {
    legacyRequests.push(request);
    return {
      events: [],
      page: request.page,
      limit: request.limit,
      has_more: false
    };
  };

  const result = await client.scanNotes({
    rootSeed: new Uint8Array(32),
    afterHeight: 100,
    afterSequence: 5,
    page: 9,
    limit: 10,
    maxPages: 1,
    // Exercise the scan_events -> privacy_events migration path directly;
    // privacy_scan is the default and has its own absent-endpoint fallback.
    scanSource: "scan_events"
  });

  assert.deepEqual(legacyRequests, [{
    afterHeight: 99,
    after_height: 99,
    limit: 10,
    eventTypes: ["deposit", "shielded_transfer"],
    page: 1
  }]);
  assert.equal(result.scanCursor.source, "privacy_events");
});

test("scan_events fallback does not downgrade version or transient failures", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://rest-a.local",
    chainId: "clairveil-local-3"
  });
  let rawCalls = 0;
  client.fetchPrivacyEvents = async () => {
    rawCalls += 1;
    return { events: [], has_more: false };
  };

  const transientFailure = new Error("scan_events temporarily unavailable");
  transientFailure.status = 503;
  client.fetchScanEvents = async () => { throw transientFailure; };
  await assert.rejects(
    () => client.scanNotes({ rootSeed: new Uint8Array(32), scanSource: "scan_events" }),
    error => error === transientFailure
  );

  const unsupportedVersion = new Error("unsupported scan_events version");
  unsupportedVersion.code = "UNSUPPORTED_SCAN_EVENTS_VERSION";
  client.fetchScanEvents = async () => { throw unsupportedVersion; };
  await assert.rejects(
    () => client.scanNotes({ rootSeed: new Uint8Array(32), scanSource: "scan_events" }),
    error => error === unsupportedVersion
  );
  assert.equal(rawCalls, 0);
});

test("scan_events fallback does not discard a successfully fetched first page", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://rest-a.local",
    chainId: "clairveil-local-3"
  });
  const terminalFailure = new Error("scan_events disappeared after the first page");
  terminalFailure.status = 404;
  let typedCalls = 0;
  let rawCalls = 0;
  client.fetchScanEvents = async request => {
    typedCalls += 1;
    if (typedCalls === 2) throw terminalFailure;
    return {
      events: [],
      has_more: true,
      next_height: request.afterHeight,
      next_sequence: Number(request.afterSequence) + 1,
      limit: request.limit,
      scan_format_version: 1,
      view_tag_version: 1
    };
  };
  client.fetchPrivacyEvents = async () => {
    rawCalls += 1;
    throw new Error("raw fallback must not run after typed scan progress");
  };

  await assert.rejects(
    () => client.scanNotes({
      rootSeed: new Uint8Array(32),
      scanSource: "scan_events",
      maxPages: 2
    }),
    error => error === terminalFailure
  );
  assert.equal(typedCalls, 2);
  assert.equal(rawCalls, 0);
});

test("scan_events accepts protobuf JSON uint64 strings for the response limit", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  client.fetchScanEvents = async request => ({
    events: [],
    next_height: String(request.afterHeight),
    next_sequence: String(request.afterSequence),
    limit: String(request.limit),
    has_more: false,
    scan_format_version: 1,
    view_tag_version: 1
  });

  const result = await client.scanNotes({
    rootSeed: new Uint8Array(32),
    scanSource: "scan_events",
    limit: 200
  });

  assert.equal(result.scanCursor.source, "scan_events");
  assert.equal(result.scanCursor.limit, 200);
});

test("scan_events rejects malformed projection payloads before wallet processing", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  client.fetchScanEvents = async request => ({
    events: [{
      sequence: 1,
      height: 1,
      tx_hash_hex: "aa",
      event_type: "deposit",
      outputs: [{
        output_index: 0,
        commitment_hex: "11".repeat(32)
      }],
      nullifier_hexes: []
    }],
    next_height: 1,
    next_sequence: 1,
    limit: request.limit,
    has_more: false,
    scan_format_version: 1,
    view_tag_version: 1
  });

  await assert.rejects(
    () => client.scanNotes({
      rootSeed: new Uint8Array(32),
      scanSource: "scan_events"
    }),
    /encrypted_note_hex is required/
  );
});

test("batch nullifier query uses POST chunks", async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  const malformedNullifier = "00".repeat(32);
  const conflictingNullifier = "01".padStart(64, "0");
  globalThis.fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    requests.push({ url: String(url), method: init.method, body });
    return new Response(JSON.stringify({
      statuses: body.nullifiers.flatMap(nullifier => nullifier === conflictingNullifier
        ? [{ nullifier, used: false }, { nullifier, used: true }]
        : [{
            nullifier,
            used: nullifier === malformedNullifier ? "false" : nullifier.endsWith("ff")
          }])
    }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  try {
    const client = createClairveilClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://rest-a.local",
      chainId: "clairveil-local-3",
      queryRetry: false
    });
    const nullifiers = Array.from({ length: 1001 }, (_, index) => (
      index === 1000 ? "ff".repeat(32) : index.toString(16).padStart(64, "0")
    ));
    const result = await client.checkNullifiers(nullifiers);

    assert.equal(requests.length, 2);
    assert.equal(requests[0].method, "POST");
    assert.equal(requests[0].url, "http://rest-a.local/clairveil/privacy/v1/nullifiers");
    assert.equal(requests[0].body.nullifiers.length, 1000);
    assert.equal(requests[1].body.nullifiers.length, 1);
    assert.equal(result.has(malformedNullifier), false);
    assert.equal(result.has(conflictingNullifier), false);
    assert.equal(result.get("ff".repeat(32)), true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("batch nullifier query consumes both status list aliases and rejects conflicts", async () => {
  const originalFetch = globalThis.fetch;
  const conflictingNullifier = "10".repeat(32);
  const aliasOnlyNullifier = "20".repeat(32);
  globalThis.fetch = async () => new Response(JSON.stringify({
    statuses: [{ nullifier: conflictingNullifier, used: false }],
    Statuses: [
      { Nullifier: conflictingNullifier.toUpperCase(), Used: true },
      { Nullifier: aliasOnlyNullifier.toUpperCase(), Used: false }
    ]
  }), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
  try {
    const client = createClairveilClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://rest-a.local",
      chainId: "clairveil-local-3",
      queryRetry: false
    });
    const result = await client.checkNullifiers([
      conflictingNullifier,
      aliasOnlyNullifier
    ]);

    assert.equal(result.has(conflictingNullifier), false);
    assert.equal(result.get(aliasOnlyNullifier), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("browser public batch nullifier query consumes both status list aliases and rejects conflicts", async () => {
  const originalFetch = globalThis.fetch;
  const conflictingNullifier = "30".repeat(32);
  const aliasOnlyNullifier = "40".repeat(32);
  globalThis.fetch = async () => new Response(JSON.stringify({
    statuses: [{ nullifier: conflictingNullifier, used: false }],
    Statuses: [
      { Nullifier: conflictingNullifier.toUpperCase(), Used: true },
      { Nullifier: aliasOnlyNullifier.toUpperCase(), Used: false }
    ]
  }), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
  try {
    const client = createClairveilPublicClient({
      rest: "http://rest-a.local",
      queryRetry: false
    });
    const result = await client.checkNullifiers([
      conflictingNullifier,
      aliasOnlyNullifier
    ]);

    assert.equal(result.has(conflictingNullifier), false);
    assert.equal(result.get(aliasOnlyNullifier), false);
    assert.equal(result.size, 1);
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

test("cosmos disclosure lookup preserves a mid-block ScanEvents cursor", async () => {
  const client = cosmosTestClient();
  const requests = [];
  let legacyCalls = 0;
  client.fetchPrivacyEvents = async () => {
    legacyCalls += 1;
    return { events: [], has_more: false };
  };
  client.fetchScanEvents = async request => {
    requests.push(request);
    if (request.afterSequence === 7) {
      return {
        events: [{
          sequence: 8,
          height: 100,
          event_type: "shielded_transfer",
          tx_hash_hex: "DEAD",
          outputs: [0, 1].map(outputIndex => ({
            output_index: outputIndex,
            commitment_hex: "11".repeat(32),
            cipher_text_hex: "00",
            view_tag_hex: "0000"
          })),
          nullifier_hexes: []
        }],
        has_more: true,
        next_height: 100,
        next_sequence: 8,
        limit: request.limit,
        scan_format_version: 1,
        view_tag_version: 1
      };
    }
    return {
      events: [{
        sequence: 9,
        height: 100,
        event_type: "shielded_transfer",
        tx_hash_hex: "AABBCC",
        outputs: [0, 1].map(outputIndex => ({
          output_index: outputIndex,
          commitment_hex: "11".repeat(32),
          cipher_text_hex: "00",
          view_tag_hex: "0000"
        })),
        nullifier_hexes: []
      }],
      has_more: false,
      next_height: 100,
      next_sequence: 9,
      limit: request.limit,
      scan_format_version: 1,
      view_tag_version: 1
    };
  };

  const event = await client.findPrivacyEventByTxHash("aabbcc", {
    afterHeight: 100,
    afterSequence: 7,
    scanSource: "scan_events",
    limit: 1,
    maxPages: 3
  });

  assert.equal(event.tx_hash_hex, "AABBCC");
  assert.equal(legacyCalls, 0);
  assert.deepEqual(
    requests.map(request => [request.afterHeight, request.afterSequence]),
    [[100, 7], [100, 8]]
  );
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

test("BatchTransfer protobuf binding is registered and preserves its expiry", () => {
  const message = {
    creator: "clair1batch",
    proof: new Uint8Array([1, 2, 3]),
    root: new Uint8Array(32).fill(1),
    nullifiers: [new Uint8Array(32).fill(2)],
    outputs: [{
      commitment: new Uint8Array(32).fill(3),
      ciphertext: new Uint8Array([4]),
      viewTag: new Uint8Array([5, 6]),
      userPrivacyPolicy: 0,
      userDisclosureMode: 0,
      userDisclosureDigest: new Uint8Array(),
      userDisclosureTargetPubkey: new Uint8Array(),
      userDisclosurePayload: new Uint8Array(),
      fullDisclosureDigest: new Uint8Array(32).fill(7),
      auditDisclosurePayload: new Uint8Array([8]),
      selfViewDisclosurePayload: new Uint8Array()
    }],
    auditKeyId: "audit-key-1",
    auditKeyEpoch: 3n,
    auditDisclosureTargetPubkey: new Uint8Array(32).fill(9),
    expiresAtUnix: 4_102_448_400n
  };
  const decoded = MsgBatchTransfer.decode(MsgBatchTransfer.encode(message).finish());
  assert.equal(decoded.expiresAtUnix, 4_102_448_400n);
  assert.equal(decoded.outputs.length, 1);

  const registry = createClairveilRegistry();
  const encoded = registry.encode({
    typeUrl: MsgBatchTransfer.typeUrl,
    value: MsgBatchTransfer.fromPartial(message)
  });
  assert.ok(encoded.length > 0);
});

test("SDK exposes the typed privacy protocol queries and batch sign-doc boundary", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    enableExperimentalBatchTransfer: true
  });
  const calls = [];
  client.fetchJson = async (path, options = {}) => {
    calls.push({ path, options });
    return { path };
  };

  await client.fetchPrivacyScan({
    after: { height: 7n, global_sequence: 8n, output_index: 1 },
    output_limit: 12,
    eventTypes: ["batch_transfer"]
  });
  await client.fetchAssetByDenom("factory/clair1/module/uclair");
  await client.fetchAssetByID("ab".repeat(32));
  await client.fetchCommitmentPathsAtRoot({
    commitmentHexes: ["cd".repeat(32)],
    rootHex: "ef".repeat(32),
    snapshotHeight: 9n
  });

  assert.equal(calls[0].path, "/clairveil/privacy/v1/privacy_scan");
  assert.deepEqual(JSON.parse(calls[0].options.body), {
    after: { height: "7", globalSequence: "8", outputIndex: 1 },
    outputLimit: 12,
    eventTypes: ["batch_transfer"]
  });
  assert.equal(calls[1].path, "/clairveil/privacy/v1/assets/by_denom/factory%2Fclair1%2Fmodule%2Fuclair");
  assert.equal(calls[2].path, `/clairveil/privacy/v1/assets/by_id/${"ab".repeat(32)}`);
  assert.deepEqual(JSON.parse(calls[3].options.body), {
    commitmentHexes: ["cd".repeat(32)],
    rootHex: "ef".repeat(32),
    snapshotHeight: "9"
  });

  let signDocInput;
  const requestedBatchFee = [{ denom: "uclair", amount: "31" }];
  client.assertCircuitConfig = async () => {
    requestedBatchFee[0].amount = "999";
    requestedBatchFee.push({ denom: "ustale", amount: "1" });
    return {};
  };
  client.buildDirectSignDoc = async input => {
    signDocInput = input;
    return { bodyBytes: "", authInfoBytes: "", chainId: "clairveil-local-3", accountNumber: "0" };
  };
  await assert.rejects(
    () => client.createBatchTransferSignDoc({
      signer: "clair1batch",
      pubKeyHex: "02".repeat(33),
      gasLimit: 1,
      message: {
        ...validBatchTransferMessage(),
        nullifiers: []
      },
      chainNowUnix: 1_700_000_000
    }),
    /input count must be in 1\.\.16/
  );
  await assert.rejects(
    () => client.createBatchTransferSignDoc({
      signer: "clair1batch",
      pubKeyHex: "02".repeat(33),
      gasLimit: 1,
      message: {
        ...validBatchTransferMessage(),
        proof: new Uint8Array(163)
      },
      chainNowUnix: 1_700_000_000
    }),
    /proof must be exactly 164 bytes/
  );
  await client.createBatchTransferSignDoc({
    signer: "clair1batch",
    pubKeyHex: "02".repeat(33),
    gas_limit: 26000000n,
    fee_amount: requestedBatchFee,
    message: validBatchTransferMessage(),
    chainNowUnix: 1_700_000_000
  });
  assert.equal(signDocInput.messages[0].typeUrl, MsgBatchTransfer.typeUrl);
  assert.deepEqual(signDocInput.feeAmount, [{ denom: "uclair", amount: "31" }]);
  assert.equal(signDocInput.messages[0].value.expiresAtUnix, 4_102_448_400n);
  assert.equal(signDocInput.gasLimit, 26000000);
  assert.deepEqual(signDocInput.feeAmount, [{ denom: "uclair", amount: "31" }]);
});

test("Cosmos sign-doc convenience methods reject non-Cosmos execution builders", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    enableExperimentalBatchTransfer: true
  });
  let prepareCalls = 0;
  client.prepareTransfer = async () => { prepareCalls += 1; return { status: "ready" }; };
  client.prepareTransferBatch = async () => { prepareCalls += 1; return { status: "ready" }; };
  client.prepareWithdraw = async () => { prepareCalls += 1; return { status: "ready" }; };
  for (const [method, message] of [
    ["createTransferSignDoc", /createTransferSignDoc does not accept executionBuilder/],
    ["createTransferBatchSignDoc", /createTransferBatchSignDoc does not accept executionBuilder/],
    ["createWithdrawSignDoc", /createWithdrawSignDoc does not accept executionBuilder/]
  ]) {
    await assert.rejects(
      () => client[method]({ executionBuilder() {} }),
      message
    );
  }
  assert.equal(prepareCalls, 0);

  await assert.rejects(
    () => client.createTransferSignDoc({}),
    /did not produce a Cosmos sign doc/
  );
});

test("unified privacy scan validates a whole cursor page before decrypting and persisting notes", async () => {
  const client = cosmosTestClient();
  const rootSeed = new Uint8Array(32).fill(7);
  const note = createNote({
    spendPubKey: CURVE_BASE,
    viewPubKey: CURVE_BASE,
    amount: 19n,
    assetDenom: "uclair",
    randomness: 71n,
    memo: "privacy-scan-v2"
  });
  const commitment = canonicalFieldBytes(computeNoteCommitmentV1(note));
  const encryptedNote = encryptDepositNoteV1(note, rootSeed);
  const txHash = new Uint8Array(32).fill(11);
  const requests = [];
  client.fetchPrivacyScan = async request => {
    requests.push(request);
    return {
      scanSchemaVersion: "privacy-scan-v2",
      summaries: [
        {
          height: 10,
          globalSequence: 1,
          txHash,
          eventType: "deposit",
          outputCount: 1,
          circuitSetId: activeCircuitSetIdV1,
          payloadVersion: privacyFixedV1,
          scanSchemaVersion: "privacy-scan-v2"
        },
        {
          height: 10,
          globalSequence: 2,
          txHash: new Uint8Array(32).fill(12),
          eventType: "withdraw",
          nullifiers: [canonicalFieldBytes(13n)],
          outputCount: 0,
          circuitSetId: activeCircuitSetIdV1,
          payloadVersion: privacyFixedV1,
          scanSchemaVersion: "privacy-scan-v2"
        }
      ],
      outputs: [{
        height: 10,
        globalSequence: 1,
        outputIndex: 0,
        commitment,
        encryptedNote,
        leafIndexFound: true,
        leafIndex: 4,
        txHash,
        eventType: "deposit",
        circuitSetId: activeCircuitSetIdV1,
        payloadVersion: privacyFixedV1,
        scanSchemaVersion: "privacy-scan-v2"
      }],
      nextCursor: { height: 10, globalSequence: 2, outputIndex: 0 },
      hasMore: false,
      scannedEventCount: 2
    };
  };
  client.checkNullifiers = async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, false]));

  const result = await client.scanNotes({
    rootSeed,
    after: { height: 9, globalSequence: 99, outputIndex: 2 },
    outputLimit: 4,
    eventLimit: 3,
    maxEncodedBytes: 4096,
    includeFoundNotes: true
  });

  assert.deepEqual(requests, [{
    after: { height: 9, globalSequence: 99, outputIndex: 2 },
    outputLimit: 4,
    eventLimit: 3,
    maxEncodedBytes: 4096,
    eventTypes: []
  }]);
  assert.equal(result.summary.spendable_count, 1);
  assert.equal(result.foundNotes[0].note.amount, 19n);
  assert.equal(result.diagnostics.scanned_events, 2);
  assert.equal(result.scanCursor.source, "privacy_scan");
  assert.deepEqual(result.nextScanOptions.after, {
    height: 10,
    globalSequence: 2,
    outputIndex: 0
  });
  assert.equal(result.nextScanOptions.scanSource, "privacy_scan");
});

test("unified privacy scan falls back only when the typed endpoint is initially absent", async () => {
  const rootSeed = new Uint8Array(32).fill(8);
  const client = cosmosTestClient();
  let legacyCalls = 0;
  client.fetchPrivacyScan = async () => ({ scanSchemaVersion: "privacy-scan-v2" });
  client.fetchScanEvents = async request => {
    legacyCalls += 1;
    return {
      events: [],
      next_height: request.afterHeight,
      next_sequence: request.afterSequence,
      limit: request.limit,
      has_more: false,
      scan_format_version: 1,
      view_tag_version: 1
    };
  };
  await assert.rejects(
    () => client.scanNotes({ rootSeed }),
    /privacy scan next cursor is required/
  );
  assert.equal(legacyCalls, 0);

  const unsupportedVersion = new Error("unsupported typed scan version");
  unsupportedVersion.code = "UNSUPPORTED_PRIVACY_SCAN_VERSION";
  client.fetchPrivacyScan = async () => { throw unsupportedVersion; };
  await assert.rejects(
    () => client.scanNotes({ rootSeed }),
    error => error === unsupportedVersion
  );
  assert.equal(legacyCalls, 0);

  const transientFailure = new Error("typed scan temporarily unavailable");
  transientFailure.status = 503;
  client.fetchPrivacyScan = async () => { throw transientFailure; };
  await assert.rejects(
    () => client.scanNotes({ rootSeed }),
    error => error === transientFailure
  );
  assert.equal(legacyCalls, 0);

  await assert.rejects(
    () => client.scanNotes({
      rootSeed,
      strictPrivacyScan: true,
      strict_privacy_scan: false
    }),
    /strictPrivacyScan aliases conflict/
  );
  assert.equal(legacyCalls, 0);

  await assert.rejects(
    () => client.scanNotes({ rootSeed, maxPages: 1, max_pages: 2 }),
    /maxPages aliases conflict/
  );
  assert.equal(legacyCalls, 0);

  const strictMissingEndpoint = new Error("strict typed scan is unavailable");
  strictMissingEndpoint.status = 404;
  client.fetchPrivacyScan = async () => { throw strictMissingEndpoint; };
  await assert.rejects(
    () => client.scanNotes({ rootSeed, strict_privacy_scan: true }),
    error => error === strictMissingEndpoint
  );
  assert.equal(legacyCalls, 0);

  for (const status of [404, 405, 501]) {
    const missingEndpoint = new Error(`privacy scan unavailable (${status})`);
    missingEndpoint.status = status;
    client.fetchPrivacyScan = async () => { throw missingEndpoint; };
    const fallback = await client.scanNotes({ rootSeed });
    assert.equal(fallback.scanCursor.source, "scan_events");
  }
  assert.equal(legacyCalls, 3);
});

test("typed privacy scan does not fall back after pagination starts", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  const terminalFailure = new Error("typed privacy scan disappeared after the first page");
  terminalFailure.status = 404;
  let typedCalls = 0;
  let legacyCalls = 0;
  client.fetchPrivacyScan = async () => {
    typedCalls += 1;
    if (typedCalls === 2) throw terminalFailure;
    return {
      scanSchemaVersion: "privacy-scan-v2",
      summaries: [{
        height: 1,
        globalSequence: 1,
        txHash: new Uint8Array(32).fill(1),
        eventType: "withdraw",
        nullifiers: [canonicalFieldBytes(1n)],
        outputCount: 0,
        circuitSetId: activeCircuitSetIdV1,
        payloadVersion: privacyFixedV1,
        scanSchemaVersion: "privacy-scan-v2"
      }],
      outputs: [],
      nextCursor: { height: 1, globalSequence: 1, outputIndex: 0 },
      hasMore: true,
      scannedEventCount: 1
    };
  };
  client.fetchScanEvents = async () => {
    legacyCalls += 1;
    throw new Error("compatibility fallback must not run after typed scan progress");
  };

  await assert.rejects(
    () => client.scanNotes({ rootSeed: new Uint8Array(32), max_pages: 2 }),
    error => error === terminalFailure
  );
  assert.equal(typedCalls, 2);
  assert.equal(legacyCalls, 0);
});

test("wallet sync falls back only when a fresh typed privacy scan endpoint is absent", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  const typedMissing = new Error("typed privacy scan is not implemented");
  typedMissing.status = 404;
  let typedCalls = 0;
  const legacyRequests = [];
  client.fetchPrivacyScan = async () => {
    typedCalls += 1;
    throw typedMissing;
  };
  client.fetchScanEvents = async request => {
    legacyRequests.push(request);
    return {
      events: [],
      next_height: request.afterHeight,
      next_sequence: request.afterSequence,
      limit: request.limit,
      has_more: false,
      scan_format_version: 1,
      view_tag_version: 1
    };
  };
  await assert.rejects(
    () => client.scanNotes({ rootSeed, strictPrivacyScan: true }),
    /typed privacy-scan-v2 is required; legacy scan fallback is disabled/
  );
  assert.equal(legacyCalls, 0);
  let noteStoreWrites = 0;
  await assert.rejects(
    () => client.scanWalletNotes({
      material: {
        rootSeed,
        address: "clair1strict",
        pubKeyHex: "02".padEnd(66, "0"),
        shieldedAddress: "clairs1strict"
      },
      noteStore: {
        async load() {
          return { notes: [], scanCursor: {}, lastScannedHeight: 0, lastScannedSequence: 0 };
        },
        async mergeScanResult() {
          noteStoreWrites += 1;
        }
      }
    }),
    /typed privacy-scan-v2 is required; legacy scan fallback is disabled/
  );
  assert.equal(legacyCalls, 0);
  assert.equal(noteStoreWrites, 0);

  const fallback = await client.scanNotes({ rootSeed });
  assert.equal(legacyCalls, 1);
  assert.equal(fallback.scanCursor.source, "scan_events");
});

test("same-root Merkle path snapshots are batch-verified before use by the prover", async () => {
  const commitmentHex = fieldHexV1(73n);
  const siblings = [];
  const helpers = [];
  let current = 73n;
  for (let level = 0; level < 32; level += 1) {
    const sibling = BigInt(level + 101);
    const helper = Number((5n >> BigInt(level)) & 1n);
    siblings.push(fieldHexV1(sibling));
    helpers.push(helper);
    current = helper === 0
      ? computeNoteTreeNodeV1(level, current, sibling)
      : computeNoteTreeNodeV1(level, sibling, current);
  }
  const rootHex = fieldHexV1(current);
  const client = cosmosTestClient();
  let request;
  client.fetchCommitmentPathsAtRoot = async input => {
    request = input;
    return {
      rootHex,
      snapshotHeight: "22",
      leafCount: "23",
      paths: [{
        commitmentHex,
        leafIndex: 5,
        path: siblings,
        pathHelper: helpers
      }]
    };
  };

  const snapshot = await client.queryCommitmentPathsAtRoot({
    commitmentHexes: [commitmentHex],
    rootHex,
    snapshotHeight: 22
  });
  assert.deepEqual(request, {
    commitmentHexes: [commitmentHex],
    rootHex,
    snapshotHeight: 22
  });
  assert.equal(snapshot.root_hex, rootHex);
  const provider = await client.createCommitmentPathSnapshotProvider({
    commitmentHexes: [commitmentHex],
    rootHex,
    snapshotHeight: 22
  });
  assert.deepEqual(await provider.lookupMerklePath(commitmentHex), {
    root: rootHex,
    path: siblings,
    path_helper: helpers,
    leaf_index: 5,
    snapshot_height: 22
  });

  const publicClient = createClairveilPublicClient({ rest: "http://127.0.0.1:1317" });
  publicClient.fetchCommitmentPathsAtRoot = async input => {
    assert.deepEqual(input, { commitmentHexes: [commitmentHex], rootHex, snapshotHeight: 22 });
    return {
      rootHex,
      snapshotHeight: 22,
      leafCount: 23,
      paths: [{
        commitmentHex,
        leafIndex: 5,
        path: siblings,
        pathHelper: helpers
      }]
    };
  };
  assert.equal(
    (await publicClient.queryCommitmentPathsAtRoot({ commitmentHexes: [commitmentHex], rootHex, snapshotHeight: 22 })).paths[0].commitment_hex,
    commitmentHex
  );

  client.fetchCommitmentPathsAtRoot = async input => {
    assert.deepEqual(input, { commitmentHexes: [commitmentHex], rootHex });
    return {
      rootHex,
      snapshotHeight: 22,
      leafCount: 23,
      paths: [{ commitmentHex, leafIndex: 5, path: siblings, pathHelper: helpers }]
    };
  };
  assert.equal(
    (await client.queryCommitmentPathsAtRoot({ commitmentHexes: [commitmentHex], rootHex })).snapshot_height,
    22
  );

  client.fetchCommitmentPathsAtRoot = async () => ({
    rootHex,
    snapshotHeight: 22,
    leafCount: 23,
    paths: [{
      commitmentHex,
      leafIndex: 5,
      path: [...siblings.slice(0, 31), fieldHexV1(1n)],
      pathHelper: helpers
    }]
  });
  await assert.rejects(
    () => client.queryCommitmentPathsAtRoot({ commitmentHexes: [commitmentHex], rootHex, snapshotHeight: 22 }),
    /does not reconstruct/
  );
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
  assert.ok(packageJson.files.includes("fixtures"));
  assert.ok(packageJson.files.includes("README.md"));
  assert.ok(packageJson.files.includes("README.ko.md"));
  assert.ok(packageJson.files.includes("LICENSE"));
  assert.ok(packageJson.files.includes("test/e2e-local.e2e.js"));
  assert.ok(packageJson.dependencies["@cosmjs/stargate"]);
  assert.ok(packageJson.dependencies["cosmjs-types"]);
  assert.ok(packageJson.scripts["test:conformance:required"]?.includes("require-conformance-fixtures.js"));
  assert.equal(packageJson.scripts.prepack, "npm run verify:package");
  assert.equal(packageJson.scripts.prepublishOnly, "npm run verify:release:integration");
  assert.ok(!packageJson.scripts["verify:package"].includes("test:conformance:required"));
  assert.ok(packageJson.scripts["verify:release"].includes("test:conformance:required"));
  assert.equal(
    packageJson.scripts["test:e2e:cosmos:testnet"],
    "node tools/run-cosmos-e2e.js testnet"
  );
  assert.equal(
    packageJson.scripts["test:e2e:local:one-proof-all"],
    "node tools/run-cosmos-e2e.js local"
  );
  assert.equal(
    packageJson.scripts["test:e2e:evm"],
    "node tools/verify-evm-integration.js"
  );
  assert.equal(
    packageJson.scripts["test:e2e:evm:one-proof-all"],
    "CLAIRVEIL_EVM_E2E_REQUIRED=1 node tools/verify-evm-integration.js"
  );
  assert.equal(
    packageJson.scripts["test:e2e:evm-payable"],
    "node tools/verify-evm-payable-integration.js"
  );
  assert.ok(
    packageJson.scripts["verify:release:integration"].includes(
      "npm run test:e2e:evm:one-proof-all"
    )
  );
  assert.ok(
    packageJson.scripts["verify:release:integration"].includes(
      "npm run test:e2e:cosmos:testnet"
    )
  );
  assert.ok(
    packageJson.scripts["verify:release:integration"].includes(
      "npm run test:e2e:local:one-proof-all"
    )
  );
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
    version: "v2",
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
    version: "v2",
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
      chainNowUnix: 4102444800,
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
        chainNowUnix: 4102444800,
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
        chainNowUnix: 4102444800,
        expectedChainId: "clairveil-local-1",
        expectedRecipient: missingExpiry.recipient,
        accountPrefix: "clair"
      }
    ),
    /withdraw payload expires_at_unix must be a safe integer unix timestamp/
  );
});

test("withdraw prover payload rejects invalid expiry before proof handoff", async () => {
  const rootSeed = new Uint8Array(32).fill(1);
  const note = createNote({
    spendPubKey: deriveSpendKeys(rootSeed).pubKey,
    viewPubKey: deriveViewKeys(rootSeed).pubKey,
    amount: 1n,
    randomness: 5n,
    memo: "expiry"
  });
  const baseInput = {
    notes: [{ note, isSpent: false, nullifierStatus: "unspent" }],
    amount: "1uclair",
    recipient: "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48",
    chainId: "clairveil-local-1",
    rootSeed,
    merklePathProvider: strictMerklePathProvider([note])
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

test("relay withdraw keeps authoritative chain time through proof finalization", async () => {
  const rootSeed = new Uint8Array(32).fill(1);
  const note = createNote({
    spendPubKey: deriveSpendKeys(rootSeed).pubKey,
    viewPubKey: deriveViewKeys(rootSeed).pubKey,
    amount: 1n,
    randomness: 6n,
    memo: "chain-time"
  });
  const input = {
    notes: [{ note, isSpent: false, nullifierStatus: "unspent" }],
    amount: "1uclair",
    recipient: "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48",
    chainId: "clairveil-local-1",
    expiresAtUnix: 2_000,
    rootSeed,
    merklePathProvider: strictMerklePathProvider([note]),
    checkNullifiers: async (nullifiers) =>
      new Map(nullifiers.map((nullifier) => [nullifier, false])),
    proverAdapter: {
      async proveWithdraw({ payload }) {
        return {
          version: "v2",
          payload_hash: payload.payload_hash,
          proof_hex: validV2ProofHex,
        };
      },
    },
  };

  await assert.rejects(
    () => buildRelayWithdrawPayload(input),
    /chainNowUnix is required for relay withdraw payload validation/
  );
  const result = await buildRelayWithdrawPayload({
    ...input,
    chainNowUnix: 1_000
  });

  assert.equal(result.payload.expires_at_unix, 2_000);
});

test("prepared transfer requires explicit self-view opt-out when signer material is external", async () => {
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
      isSpent: false,
      nullifierStatus: "unspent"
    },
    {
      note: createNote({
        spendPubKey: senderSpend,
        viewPubKey: senderView,
        amount: 1n,
        assetDenom: "uclair",
        randomness: 102n
      }),
      isSpent: false,
      nullifierStatus: "unspent"
    }
  ];
  const input = {
    creator: "clair1xcjufgh2jarkp2qkx68azh08w9v5gah8sx9zu2",
    chainId: "clairveil-local-1",
    chainNowUnix: 1_700_000_000,
    inputs,
    recipient: recipientMaterial.shieldedAddress,
    amount: "1uclair",
    senderSpendPubKey: senderSpend,
    senderViewPubKey: senderView,
    noteHashSigner: createSpendNoteHashSigner(senderRootSeed),
    auditDisclosureTargetPubKeyHex: recipientMaterial.disclosurePubKeyHex,
    merklePathProvider: strictMerklePathProvider(inputs.map(input => input.note)),
    shieldedPrefix: "clairs"
  };

  await assert.rejects(
    () => buildPreparedTransferPayload(input),
    /self-view disclosure requires rootSeed or selfViewDisclosureTargetPubKeyHex/
  );
  const payload = await buildPreparedTransferPayload({ ...input, disableSelfViewDisclosure: true });

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
    contractAddress: testPrivacyContractAddress,
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
    amount: "3",
    proof: new Uint8Array([1, 2, 3])
  });
  const sameMaterial = client.buildDepositTransaction({
    material: prepared.material,
    proof: new Uint8Array([1, 2, 3])
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
  assert.equal(prepared.transaction.to, testPrivacyContractAddress);
  assert.equal(prepared.transaction.data.slice(2, 10), functionSelector("deposit((bytes,bytes,bytes))"));
  assert.equal(prepared.transaction.data, sameMaterial.transaction.data);
  assert.equal(prepared.transaction.data, sameMessage.transaction.data);
  assert.equal(sameMessage.material, undefined);
  assert.equal(txHash, "0x" + "cd".repeat(32));
  assert.equal(sent[0].from, "0x1111111111111111111111111111111111111111");
});

test("EVM client wraps existing transfer and withdraw messages without prepared material", async () => {
  const client = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
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
    viewTags: [new Uint8Array([8, 9]), new Uint8Array([10, 11])],
    auditDisclosureDigest: new Uint8Array(),
    auditDisclosureTargetPubkey: new Uint8Array(),
    auditDisclosurePayload: new Uint8Array(),
    expiresAtUnix: 4102448400n
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

  await assert.rejects(
    () => client.buildTransferTransaction({ message: transferMessage }),
    /chainNowUnix is required from authoritative chain time/
  );
  await assert.rejects(
    () => client.buildTransferTransaction({
      message: transferMessage,
      chainNowUnix: false
    }),
    /chainNowUnix must be a non-negative safe integer/
  );
  await assert.rejects(
    () => client.buildTransferTransaction({
      message: transferMessage,
      chainNowUnix: 4102444800,
      chain_now_unix: 4102444801
    }),
    /chainNowUnix aliases conflict/
  );
  await assert.rejects(
    () => client.buildTransferTransaction({
      message: transferMessage,
      chainNowUnix: 4102444800,
      expiresAtUnix: 4102448399
    }),
    /message expiry does not match the requested expiresAtUnix/
  );
  await assert.rejects(
    () => client.buildTransferTransaction({
      message: {
        ...transferMessage,
        expires_at_unix: 4102448401n
      },
      chainNowUnix: 4102444800
    }),
    /message expiresAtUnix aliases conflict/
  );
  await assert.rejects(
    () => client.buildTransferTransaction({
      message: transferMessage,
      payload: {},
      chainNowUnix: 4102444800
    }),
    /payload and proof must be supplied together/
  );

  const transfer = await client.buildTransferTransaction({
    message: transferMessage,
    chainNowUnix: 4102444800
  });
  const withdraw = await client.buildWithdrawTransaction({ message: withdrawMessage });

  assert.equal(transfer.message, transferMessage);
  assert.equal(transfer.payload, undefined);
  assert.equal(transfer.proof, undefined);
  assert.equal(transfer.transaction.to, testPrivacyContractAddress);
  assert.equal(transfer.transaction.data.slice(2, 10), functionSelector("transfer((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes,bytes,bytes,uint64))"));
  assert.equal(withdraw.message, withdrawMessage);
  assert.equal(withdraw.payload, undefined);
  assert.equal(withdraw.proof, undefined);
  assert.equal(withdraw.proverPayload, undefined);
  assert.equal(withdraw.selectedNote, undefined);
  assert.equal(withdraw.transaction.to, testPrivacyContractAddress);
  assert.equal(withdraw.transaction.data.slice(2, 10), functionSelector("withdraw((bytes,bytes,bytes,string,address,string,uint64))"));

  const frozenTransferRequest = Object.freeze({ to: testPrivacyContractAddress, data: "0x1234", value: "0x0" });
  const frozenWithdrawRequest = Object.freeze({ to: testPrivacyContractAddress, data: "0x5678", value: "0x0" });
  const immutableAdapterClient = createClairveilEvmClient({
    accountPrefix: "demo",
    contractAdapter: {
      contractAddress: testPrivacyContractAddress,
      buildDepositTransaction: () => ({ to: testPrivacyContractAddress, data: "0x01" }),
      buildTransferTransaction: () => frozenTransferRequest,
      buildWithdrawTransaction: () => frozenWithdrawRequest
    }
  });
  const immutableTransfer = await immutableAdapterClient.buildTransferTransaction({
    message: transferMessage,
    chainNowUnix: 4102444800
  });
  const immutableWithdraw = await immutableAdapterClient.buildWithdrawTransaction({ message: withdrawMessage });
  assert.notEqual(immutableTransfer.transaction, frozenTransferRequest);
  assert.notEqual(immutableWithdraw.transaction, frozenWithdrawRequest);
  assert.deepEqual(
    { to: immutableTransfer.transaction.to, data: immutableTransfer.transaction.data, value: immutableTransfer.transaction.value },
    frozenTransferRequest
  );
  assert.deepEqual(
    { to: immutableWithdraw.transaction.to, data: immutableWithdraw.transaction.data, value: immutableWithdraw.transaction.value },
    frozenWithdrawRequest
  );
});

test("EVM client verifies nullifiers in direct transfer and withdraw preparation", async () => {
  const rootSeed = new Uint8Array(32).fill(9);
  const spendPubKey = deriveSpendKeys(rootSeed).pubKey;
  const viewPubKey = deriveViewKeys(rootSeed).pubKey;
  const recipientMaterial = derivePrivacyMaterial({
    address: "0x1111111111111111111111111111111111111111",
    pubKeyHex: "03".padEnd(66, "0"),
    signatureBase64: Buffer.from("evm-direct-recipient").toString("base64"),
    shieldedPrefix: "demos"
  });
  const foundNote = randomness => ({
    note: createNote({
      spendPubKey,
      viewPubKey,
      amount: 1n,
      assetDenom: "udemo",
      randomness
    }),
    isSpent: false,
    nullifierStatus: "unspent"
  });
  const contradictoryNote = foundNote(100n);
  const transferNotes = [foundNote(101n), foundNote(102n)];
  const withdrawNote = foundNote(103n);
  const merklePathProvider = strictMerklePathProvider([
    contradictoryNote.note,
    ...transferNotes.map(found => found.note),
    withdrawNote.note
  ]);
  const checkedBatches = [];
  const checkNullifiers = async nullifiers => {
    checkedBatches.push([...nullifiers]);
    return new Map(nullifiers.map(nullifier => [nullifier, false]));
  };
  const client = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
    accountPrefix: "demo",
    shieldedPrefix: "demos",
    chainId: "demo-1",
    defaultDenom: "udemo"
  });

  await assert.rejects(
    () => client.buildWithdrawTransaction({
      notes: [contradictoryNote],
      amount: "1udemo",
      recipient: "0x2222222222222222222222222222222222222222",
      rootSeed,
      merklePathProvider,
      chain_now_unix: 1_000,
      expiresAtUnix: 2_000,
      checkNullifiers: async nullifiers => ({
        statuses: [
          { nullifier: nullifiers[0], used: false },
          { nullifier: nullifiers[0], used: true }
        ]
      }),
      proverAdapter: {
        async proveWithdraw() {
          throw new Error("prover must not run with contradictory nullifier evidence");
        }
      }
    }),
    /missing or malformed status/
  );

  const transfer = await client.buildTransferTransaction({
    creator: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    inputs: transferNotes,
    recipient: recipientMaterial.shieldedAddress,
    amount: "1udemo",
    rootSeed,
    merklePathProvider,
    chainNowUnix: 1_000,
    expiresAtUnix: 2_000,
    auditDisclosureTargetPubKeyHex: recipientMaterial.disclosurePubKeyHex,
    checkNullifiers,
    proverAdapter: {
      async proveTransfer({ payload }, options) {
        assert.equal(checkedBatches.length, 1);
        assert.equal(options.nowUnix, 1_000);
        return { version: "v2", payload_hash: payload.payload_hash, proof_hex: validV2ProofHex };
      }
    }
  });
  const withdraw = await client.buildWithdrawTransaction({
    notes: [withdrawNote],
    amount: "1udemo",
    recipient: "0x2222222222222222222222222222222222222222",
    rootSeed,
    merklePathProvider,
    chain_now_unix: 1_000,
    expiresAtUnix: 2_000,
    checkNullifiers,
    proverAdapter: {
      async proveWithdraw({ payload }) {
        assert.equal(checkedBatches.length, 2);
        return { version: "v2", payload_hash: payload.payload_hash, proof_hex: validV2ProofHex };
      }
    }
  });

  assert.equal(checkedBatches[0].length, 2);
  assert.equal(checkedBatches[1].length, 1);
  assert.equal(transfer.status, "ready");
  assert.equal(withdraw.status, "ready");
  assert.equal(withdraw.message.recipient, evmAddressToBech32("0x2222222222222222222222222222222222222222", "demo"));
  await assert.rejects(
    () => client.buildTransferTransaction({
      message: {
        ...transfer.message,
        expiresAtUnix: 2_001n
      },
      payload: transfer.payload,
      proof: transfer.proof,
      expiresAtUnix: 2_001,
      chainNowUnix: 1_000
    }),
    /message does not match the supplied payload and proof/
  );
});

test("EVM client wraps prepared relay withdraw payloads into withdraw transactions", async () => {
  const client = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
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
    version: "v2",
    expires_at_unix: 4102448400
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);

  const withdraw = await client.buildWithdrawTransaction({ payload, chainNowUnix: 4102444800 });
  const legacyCamel = await client.buildWithdrawTransaction({ payload, nowUnix: 4102444800 });
  const legacySnake = await client.buildWithdrawTransaction({ payload, now_unix: 4102444800 });
  const canonicalWins = await client.buildWithdrawTransaction({
    payload,
    chainNowUnix: 4102444800,
    nowUnix: 4102449000
  });

  assert.equal(withdraw.payload, payload);
  assert.equal(withdraw.message.recipient, payload.recipient);
  assert.deepEqual(legacyCamel.message, withdraw.message);
  assert.deepEqual(legacySnake.message, withdraw.message);
  assert.deepEqual(canonicalWins.message, withdraw.message);
  assert.equal(withdraw.transaction.to, testPrivacyContractAddress);
  assert.equal(withdraw.transaction.data.slice(2, 10), functionSelector("withdraw((bytes,bytes,bytes,string,address,string,uint64))"));
});

test("Cosmos operation evidence rejects conflicting direct and batch aliases", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    enableExperimentalBatchTransfer: true
  });

  await assert.rejects(
    () => client.prepareTransfer({
      expectedRecipientHash: "recipient-a",
      expected_recipient_hash: "recipient-b",
      expectedAmountHash: "amount-a",
      expected_amount_hash: "amount-a"
    }),
    /expectedRecipientHash aliases conflict/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      amounts: ["1uclair"],
      recipient: "clairs1recipient",
      expectedRecipientHashes: ["recipient-a"],
      expected_recipient_hashes: ["recipient-b"],
      expectedAmountHashes: ["amount-a"],
      expected_amount_hashes: ["amount-a"]
    }),
    /expectedRecipientHashes aliases conflict/
  );
});

test("EVM client requires an expected chain id for relay withdraw payload transactions", async () => {
  const client = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
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
    version: "v2",
    expires_at_unix: 4102448400
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);

  await assert.rejects(
    () => client.buildWithdrawTransaction({ payload }),
    /expectedChainId is required for relay withdraw payload validation/
  );

  const withdraw = await client.buildWithdrawTransaction({
    payload,
    expectedChainId: "demo-1",
    chainNowUnix: 4102444800
  });
  assert.equal(withdraw.message.chainId, "demo-1");
});

test("EVM withdraw transaction rejects payload and evmRecipient mismatches", async () => {
  const client = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
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
    version: "v2",
    expires_at_unix: 4102448400
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);

  await assert.rejects(
    () => client.buildWithdrawTransaction({
      payload,
      evmRecipient: "0x2222222222222222222222222222222222222222",
      chainNowUnix: 4102444800
    }),
    /evmRecipient does not match message recipient/
  );
});

test("EVM withdraw transaction validates relay payload chain id and message recipient aliases", async () => {
  const client = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
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
    version: "v2",
    expires_at_unix: 4102448400
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);

  await assert.rejects(
    () => client.buildWithdrawTransaction({ payload, chainNowUnix: 4102444800 }),
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
    profile: browserEvmProfile()
  });
  client.privacyMaterial = () => ({
    rootSeed: new Uint8Array(32),
    address: "demo1example",
    pubKeyHex: "02".padEnd(66, "0"),
    shieldedAddress: "demos1example"
  });
  client.evmJsonRpc = async () => "0x539";
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
      version: "v2",
      expires_at_unix: 4102448400
    };
    payload.payload_hash = computePreparedWithdrawPayloadHash(payload);
    const built = {
      payload,
      proof: { version: "v2", payload_hash: payload.payload_hash, proof_hex: "01" },
      proverPayload: { payload_hash: payload.payload_hash },
      selectedNote: { nullifier: "09".repeat(32) }
    };
    const execution = await input.executionBuilder({
      ...built,
      plan: { status: "final_withdraw_ready", canBuildTx: true },
      reservation: null
    });
    return {
      status: "ready",
      plan: { status: "final_withdraw_ready", canBuildTx: true },
      ...built,
      execution,
      reservation: null,
      privacyAccount: { shielded_address: "demos1example" }
    };
  };

  const prepared = await client.prepareRelayWithdraw({
    walletType: "evm",
    address: "demo1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1udemo",
    recipient: "0x1111111111111111111111111111111111111111",
    chainNowUnix: 4102444800,
    evmWallet: { getChainId: async () => "0x539" }
  });

  assert.equal(captured.recipient, evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"));
  assert.equal(prepared.payload, prepared.prepared.payload);
  assert.equal(prepared.prepared.evmRecipient, "0x1111111111111111111111111111111111111111");
  assert.equal(prepared.transaction.chainId, "0x539");
  assert.equal(prepared.transaction.to, testPrivacyContractAddress);
  assert.equal(prepared.txBytesHash, evmTransactionBindingHash(prepared.transaction));
  assert.equal(typeof captured.executionBuilder, "function");
  assert.equal(prepared.transaction.data.slice(2, 10), functionSelector("withdraw((bytes,bytes,bytes,string,address,string,uint64))"));
});

test("browser-dapp EVM batch preparation binds the one-proof batch reservation to canonical calldata", async () => {
  const client = createClairveilBrowserDappClient({
    profile: browserEvmProfile(),
    enableExperimentalBatchTransfer: true
  });
  client.privacyMaterial = () => ({
    rootSeed: new Uint8Array(32),
    address: "demo1example",
    pubKeyHex: "02".padEnd(66, "0"),
    shieldedAddress: "demos1example"
  });
  client.evmJsonRpc = async () => "0x539";
  const message = {
    proof: new Uint8Array(128).fill(1),
    root: new Uint8Array(32).fill(2),
    nullifiers: [new Uint8Array(32).fill(3)],
    outputs: [{
      commitment: new Uint8Array(32).fill(4),
      ciphertext: new Uint8Array(430).fill(5),
      viewTag: new Uint8Array(2).fill(6),
      userPrivacyPolicy: 0,
      userDisclosureMode: 0,
      userDisclosureDigest: "0x",
      userDisclosureTargetPubkey: "0x",
      userDisclosurePayload: "0x",
      fullDisclosureDigest: new Uint8Array(32).fill(7),
      auditDisclosurePayload: new Uint8Array(472).fill(8),
      selfViewDisclosurePayload: "0x"
    }],
    auditKeyId: "audit-key-1",
    auditKeyEpoch: 1n,
    auditDisclosureTargetPubkey: new Uint8Array(33).fill(9),
    expiresAtUnix: 4_102_448_400n
  };
  let captured = null;
  client.cosmos.prepareTransferBatch = async input => {
    captured = input;
    const execution = await input.executionBuilder({ message });
    return {
      status: "ready",
      plan: { status: "batch_transfer_ready", canBuildTx: true },
      execution,
      reservation: {
        reservation_ids: ["batch-reservation"],
        lease_token: "batch-lease"
      },
      privacyAccount: { shielded_address: "demos1example" },
      prepared: {
        payments: [{ privacyPolicy: "all-private", disclosureMode: "none" }],
        planAction: "batch_transfer"
      }
    };
  };

  const prepared = await client.prepareTransferBatch({
    walletType: "evm",
    address: "demo1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    evmWallet: { getChainId: async () => "0x539" },
    amounts: ["1udemo"],
    recipient: "demos1recipient",
    fee_amount: [{ denom: "udemo", amount: "37" }],
    reservationManager: {},
    onPreparedPayload() {},
    onPreparedProof() {}
  });

  assert.equal(typeof captured.executionBuilder, "function");
  assert.deepEqual(captured.fee_amount, [{ denom: "udemo", amount: "37" }]);
  assert.equal(prepared.signDoc, undefined);
  assert.equal(prepared.transaction.chainId, "0x539");
  assert.equal(prepared.transaction.to, testPrivacyContractAddress);
  assert.equal(prepared.txBytesHash, evmTransactionBindingHash(prepared.transaction));
  assert.equal(
    prepared.transaction.data.slice(2, 10),
    functionSelector("singleProofBatchTransfer((bytes,bytes,bytes[],(bytes,bytes,bytes,uint32,uint8,bytes,bytes,bytes,bytes,bytes,bytes)[],string,uint64,bytes,uint64))")
  );
  assert.equal(prepared.transaction.__clairveilEvmTransaction.reservationRequired, true);
  assert.equal(
    prepared.transaction.__clairveilEvmTransaction.expectedData,
    prepared.transaction.data.toLowerCase()
  );

  let typedData = null;
  const authorized = await client.prepareTransferBatch({
    walletType: "evm",
    address: "demo1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    evmWallet: { getChainId: async () => "0x539" },
    amounts: ["1udemo"],
    recipient: "demos1recipient",
    reservationManager: {},
    onPreparedPayload() {},
    onPreparedProof() {},
    authorization: {
      effectiveSender: "0x1111111111111111111111111111111111111111",
      executor: "0x2222222222222222222222222222222222222222",
      nonce: 7,
      deadline: 4_102_448_500,
      authorizationKind: 1
    },
    authorizationSigner: {
      async signTypedData(value) {
        typedData = value;
        return `0x${"ab".repeat(65)}`;
      }
    }
  });
  assert.equal(typedData.primaryType, "PrivacyActionAuthorization");
  assert.equal(typedData.message.authorizationActionSelector, `0x${functionSelector("singleProofBatchTransfer((bytes,bytes,bytes[],(bytes,bytes,bytes,uint32,uint8,bytes,bytes,bytes,bytes,bytes,bytes)[],string,uint64,bytes,uint64))")}`);
  assert.equal(
    authorized.transaction.data.slice(2, 10),
    functionSelector("singleProofBatchTransferWithAuthorization((bytes,bytes,bytes[],(bytes,bytes,bytes,uint32,uint8,bytes,bytes,bytes,bytes,bytes,bytes)[],string,uint64,bytes,uint64),(address,address,uint256,uint64,uint8,bytes))")
  );
  assert.equal(authorized.authorization.signature, `0x${"ab".repeat(65)}`);
  assert.equal(authorized.txBytesHash, evmTransactionBindingHash(authorized.transaction));

  await assert.rejects(
    () => client.prepareTransferBatch({
      walletType: "evm",
      address: "demo1example",
      pubKeyHex: "02".padEnd(66, "0"),
      signatureBase64: "AQID",
      evmWallet: { getChainId: async () => "0x539" },
      amounts: ["1udemo"],
      recipient: "demos1recipient",
      reservationManager: {},
      onPreparedPayload() {},
      onPreparedProof() {},
      authorizationSigner: { async signTypedData() { return `0x${"ef".repeat(65)}`; } }
    }),
    /authorizationSigner requires authorization/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      walletType: "evm",
      address: "demo1example",
      pubKeyHex: "02".padEnd(66, "0"),
      signatureBase64: "AQID",
      evmWallet: { getChainId: async () => "0x539" },
      amounts: ["1udemo"],
      recipient: "demos1recipient",
      reservationManager: {},
      onPreparedPayload() {},
      onPreparedProof() {},
      transactionOptions: { value: "0x0" },
      transaction_options: { value: "0x0" }
    }),
    /transactionOptions aliases conflict/
  );

  let finalizedInput = null;
  let finalizedTypedData = null;
  client.cosmos.finalizePreparedBatchTransfer = async input => {
    finalizedInput = input;
    const execution = await input.executionBuilder({
      payload: { payload_hash: "checkpointed-payload" },
      proof: { request_payload_hash: "checkpointed-payload" },
      message,
      operationEvidence: { operation_id: "batch-operation" },
      operationEvidenceHash: "operation-evidence-hash",
      reservation: { reservation_ids: ["batch-reservation"] }
    });
    return {
      payload: input.payload,
      proof: input.proof,
      message,
      effects: {},
      operationEvidence: { operation_id: "batch-operation" },
      operationEvidenceHash: "operation-evidence-hash",
      execution,
      reservation: { reservation_ids: ["batch-reservation"] }
    };
  };
  const finalized = await client.finalizePreparedBatchTransfer({
    walletType: "evm",
    address: "demo1example",
    evmWallet: { getChainId: async () => "0x539" },
    payload: { creator: "demo1example" },
    proof: { request_payload_hash: "checkpointed-payload" },
    amounts: ["1udemo"],
    recipient: "demos1recipient",
    operationId: "batch-operation",
    reservationManager: {},
    reservation: { reservation_ids: ["batch-reservation"] },
    authorization: {
      effectiveSender: "0x1111111111111111111111111111111111111111",
      executor: "0x2222222222222222222222222222222222222222",
      nonce: 8,
      deadline: 4_102_448_500,
      authorizationKind: 1
    },
    authorizationSigner: {
      async signTypedData(value) {
        finalizedTypedData = value;
        return `0x${"cd".repeat(65)}`;
      }
    }
  });
  assert.equal(typeof finalizedInput.executionBuilder, "function");
  assert.equal(finalized.signDoc, undefined);
  assert.equal(finalized.transaction.chainId, "0x539");
  assert.equal(finalized.txBytesHash, evmTransactionBindingHash(finalized.transaction));
  assert.equal(
    finalized.transaction.data.slice(2, 10),
    functionSelector("singleProofBatchTransferWithAuthorization((bytes,bytes,bytes[],(bytes,bytes,bytes,uint32,uint8,bytes,bytes,bytes,bytes,bytes,bytes)[],string,uint64,bytes,uint64),(address,address,uint256,uint64,uint8,bytes))")
  );
  assert.equal(finalized.authorization.signature, `0x${"cd".repeat(65)}`);
  assert.equal(finalizedTypedData.primaryType, "PrivacyActionAuthorization");
});

test("browser-dapp EVM relay withdraw binds ProofReady to the prepared EVM artifact", async () => {
  const client = createClairveilBrowserDappClient({
    profile: browserEvmProfile()
  });
  client.privacyMaterial = () => ({
    rootSeed: new Uint8Array(32),
    address: "demo1example",
    pubKeyHex: "02".padEnd(66, "0"),
    shieldedAddress: "demos1example"
  });
  client.evmJsonRpc = async () => "0x539";

  const now = () => new Date("2026-01-02T03:04:05.000Z");
  const store = new MemoryReservationStore({ now });
  const reservationManager = createNoteReservationManager({
    store,
    ownerKeyId: "demo-1:demo1example",
    indexKey: "index-key-v1",
    now
  });
  const selectedNote = {
    note: {
      receiverSpendPubKeyX: 1n,
      receiverSpendPubKeyY: 2n,
      receiverViewPubKeyX: 3n,
      receiverViewPubKeyY: 4n,
      amount: 1n,
      assetID: 7n,
      randomness: 8n,
      memo: ""
    },
    nullifier: "09".repeat(32),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: "ABCD",
    height: 10,
    sequence: 1
  };
  const payload = {
    proof_hex: "01",
    root_hex: "08".repeat(32),
    nullifier_hex: selectedNote.nullifier,
    amount: "1udemo",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chain_id: "demo-1",
    version: "v2",
    expires_at_unix: 4102448400
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);
  selectedNote.note.assetID = computeAssetIdV1("udemo");
  client.cosmos.scanNotes = async () => ({ foundNotes: [selectedNote] });
  client.cosmos.assertProtocolPreflight = async () => ({});
  client.cosmos.buildRelayWithdrawPayload = async () => ({
    payload,
    proof: { version: "v2", payload_hash: payload.payload_hash, proof_hex: "01" },
    proverPayload: { payload_hash: payload.payload_hash },
    selectedNote
  });

  const prepared = await client.prepareRelayWithdraw({
    walletType: "evm",
    address: "demo1example",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1udemo",
    recipient: "0x1111111111111111111111111111111111111111",
    chainNowUnix: 4102444800,
    reservationManager,
    evmWallet: { getChainId: async () => "0x539" }
  });

  const updated = await reservationManager.getReservation(
    prepared.reservation.reservation_ids[0]
  );
  assert.equal(updated.status, reservationStatuses.ProofReady);
  assert.equal(updated.metadata.execution_transport, "evm");
  assert.deepEqual(updated.metadata.input_nullifier_hexes, [payload.nullifier_hex]);
  assert.equal(updated.tx_bytes_hash, prepared.txBytesHash);
  assert.equal(prepared.txBytesHash, evmTransactionBindingHash(prepared.transaction));
});

test("EVM address helpers round-trip through custom bech32 accounts", () => {
  const address = "0x1111111111111111111111111111111111111111";
  const bech32 = evmAddressToBech32(address, "demo");

  assert.match(bech32, /^demo1/);
  assert.equal(bech32AddressToEvm(bech32, "demo"), address);
});

test("EVM privacy precompile encoders use tuple selectors", () => {
  const deposit = encodeEvmPrivacyDeposit({
    amount: "1utest",
    noteCommitment: new Uint8Array(32).fill(1),
    encryptedNote: new Uint8Array([2, 3]),
    proof: new Uint8Array([4, 5])
  });
  const transferMessage = {
    proof: new Uint8Array([1, 2, 3]),
    root: new Uint8Array(32).fill(1),
    nullifiers: [new Uint8Array(32).fill(2), new Uint8Array(32).fill(3)],
    newCommitments: [new Uint8Array(32).fill(4), new Uint8Array(32).fill(5)],
    cipherTexts: [new Uint8Array([6]), new Uint8Array([7])],
    viewTags: [new Uint8Array([8, 9]), new Uint8Array([10, 11])],
    userPrivacyPolicy: 0,
    userDisclosureMode: 0,
    auditDisclosureDigest: new Uint8Array(32).fill(8),
    auditDisclosureTargetPubkey: new Uint8Array(32).fill(9),
    auditDisclosurePayload: new Uint8Array([10]),
    selfViewDisclosureDigest: new Uint8Array(32).fill(11),
    selfViewDisclosurePayload: new Uint8Array([12]),
    expiresAtUnix: 1234
  };
  const transfer = encodeEvmPrivacyTransfer(transferMessage);
  const withdraw = encodeEvmPrivacyWithdraw({
    proof: new Uint8Array([1, 2, 3]),
    root: new Uint8Array(32).fill(1),
    nullifier: new Uint8Array(32).fill(2),
    amount: "1utest",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chainId: "evm-privacy-local-1",
    expiresAtUnix: 1234
  }, { accountPrefix: "demo" });

  assert.equal(deposit.slice(2, 10), functionSelector("deposit((bytes,bytes,bytes))"));
  assert.equal(transfer.slice(2, 10), functionSelector("transfer((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes,bytes,bytes,uint64))"));
  assert.equal(withdraw.slice(2, 10), functionSelector("withdraw((bytes,bytes,bytes,string,address,string,uint64))"));
  assert.throws(
    () => encodeEvmPrivacyTransfer({ ...transferMessage, expiresAtUnix: undefined }),
    /transfer expiresAtUnix is required/
  );
  assert.throws(
    () => encodeEvmPrivacyWithdraw({
      proof: new Uint8Array([1]),
      root: new Uint8Array(32),
      nullifier: new Uint8Array(32),
      amount: "1utest",
      recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
      chainId: "evm-privacy-local-1"
    }, { accountPrefix: "demo" }),
    /withdraw expiresAtUnix is required/
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
