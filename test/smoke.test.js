import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
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
  hashStringToField,
  hexFromBytes,
  isVerifiedUnspentFoundNote,
  normalizeFoundNote,
  packPoint,
  ClairveilErrorCode,
  plannerStatusToErrorCode,
  unpackPoint,
  validatePreparedTransferPayloadMetadata
} from "clairveiljs/core";
import {
  createClairveilClient,
  cosmosSignDocBindingHash,
  MemoryNoteStore,
  MsgDeposit,
  MsgWithdraw,
  nextPrivacyScanOptions,
  normalizeFoundNotes,
  scanNotes,
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
  evmTransactionBindingHash,
  evmAddressToBech32,
  functionSelector,
  encodeEvmPrivacyTransfer,
  encodeEvmPrivacyWithdraw,
  evmPrivacyPrecompileAddress,
  markEvmTransactionReservationRequired
} from "clairveiljs/evm";
import { createWalletAdapter } from "clairveiljs/wallet-adapter";
import { createClairveilPublicClient } from "clairveiljs/browser-public";
import { createClairveilBrowserDappClient } from "clairveiljs/browser-dapp";
import {
  planTransferBatchNotes,
  planTransferNotes,
  planWithdrawNotes
} from "clairveiljs/planner";
import { summarizeSpendableNotesByDenom } from "clairveiljs/payload";
import {
  deserializeFoundNote,
  serializeFoundNote
} from "../src/privacy/note-store.js";
import {
  createNoteReservationManager,
  MemoryReservationStore,
  reservationStatuses
} from "clairveiljs/reservation";

const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

async function readyBroadcastReservation(suffix = "01", options = {}) {
  const store = new MemoryReservationStore();
  const reservationManager = createNoteReservationManager({
    store,
    ownerKeyId: `chain:clair1broadcast${suffix}`,
    indexKey: `broadcast-index-${suffix}`
  });
  const note = {
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
  const reservation = await reservationManager.reserveNotes({ notes: [note], kind: "transfer" });
  await reservationManager.markProving(reservation.reservation_ids, {
    leaseToken: reservation.lease_token
  });
  const ready = await reservationManager.markProofReady(reservation.reservation_ids, {
    leaseToken: reservation.lease_token,
    payloadHash: options.payloadHash ?? `payload-${suffix}`,
    signDocHash: options.signDocHash ?? "",
    txBytesHash: options.txBytesHash ?? ""
  });
  reservation.reservations = ready;
  reservation.lease_until = ready[0].lease_until;
  return { store, reservationManager, reservation };
}

test("core/cosmos/evm entrypoints load", () => {
  assert.equal(typeof derivePrivacyMaterial, "function");
  assert.equal(typeof createClairveilClient, "function");
  assert.equal(typeof createClairveilPublicClient, "function");
  assert.equal(typeof createClairveilBrowserDappClient, "function");
  assert.equal(typeof createClairveilEvmClient, "function");
  assert.equal(typeof createNoteReservationManager, "function");
  assert.equal(typeof createRootNoteReservationManager, "function");
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
  assert.equal(typeof client.prepareTransferBatch, "function");
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

test("view tag derivation matches the Go reference vector", () => {
  const commitmentHex = "03".repeat(32);
  const commitmentBytes = Uint8Array.from({ length: 32 }, () => 0x03);

  assert.equal(hexFromBytes(deriveViewTag(CURVE_BASE, commitmentHex, 1)), "0d26");
  assert.equal(hexFromBytes(deriveViewTag(CURVE_BASE, commitmentBytes, 1)), "0d26");
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
    to: evmPrivacyPrecompileAddress,
    data: "0x1234",
    value: "0x0"
  });

  await adapter.sendTransaction(transaction);
  await adapter.call(transaction);

  assert.equal(calls[0].params[0].__clairveilEvmTransaction, undefined);
  assert.equal(calls[1].params[0].__clairveilEvmTransaction, undefined);
  assert.deepEqual(Object.keys(calls[0].params[0]).sort(), ["data", "from", "to", "value"]);
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
    /self_view_disclosure_\* fields require version v2 or v3/
  );
});

test("prepared transfer metadata rejects legacy payload versions before proving", () => {
  assert.throws(
    () => validatePreparedTransferPayloadMetadata({ version: "v2" }),
    /legacy transfer payload version "v2" does not include required view tags/
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
    page: 3,
    eventTypes: ["deposit", "shielded_transfer"],
    noteStore,
    includeFoundNotes: true
  });

  assert.equal(forwarded.limit, 50);
  assert.equal(forwarded.maxPages, 4);
  assert.equal(forwarded.afterHeight, 12);
  assert.equal(forwarded.afterSequence, 34);
  assert.equal(forwarded.page, 3);
  assert.deepEqual(forwarded.eventTypes, ["deposit", "shielded_transfer"]);
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
          event_type: "withdraw",
          height: page,
          sequence: page,
          tx_hash_hex: `PAGE${page}`
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
    maxPages: 2
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
    maxPages: 1
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

test("cosmos ScanEvents preserves uint64 cursors above the safe integer range", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
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
    maxPages: 2
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
        events: [{ event_type: "shielded_transfer", tx_hash_hex: "NOTME" }],
        next_height: height,
        next_sequence: secondSequence,
        has_more: true
      };
    }
    return {
      events: [{ event_type: "shielded_transfer", tx_hash_hex: "AABBCC" }],
      next_height: height,
      next_sequence: finalSequence,
      has_more: false
    };
  };
  const event = await client.findPrivacyEventByTxHash("aabbcc", {
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
    maxPages: 2
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

test("cosmos planning preserves nested and top-level scan source options", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  const captured = [];
  client.scanWalletNotes = async options => {
    captured.push(options);
    return { foundNotes: [] };
  };

  await client.planWalletTransfer({
    material: {},
    amount: "1uclair",
    scan: { scanSource: "privacy_events" }
  });
  await client.planWalletWithdraw({
    material: {},
    amount: "1uclair",
    scan_source: "privacy_events"
  });

  assert.deepEqual(captured.map(options => options.scanSource), [
    "privacy_events",
    "privacy_events"
  ]);
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
  const missingBatchNullifier = "02".padStart(64, "0");
  const store = new MemoryNoteStore({ owner: "clair1example" });
  await store.mergeScanResult({
    foundNotes: [
      {
        height: 7,
        txHash: "AA01",
        isSpent: false,
        nullifierStatus: "unspent",
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
      },
      {
        height: 8,
        txHash: "AA02",
        isSpent: false,
        nullifierStatus: "unspent",
        nullifier: missingBatchNullifier,
        note: {
          receiverSpendPubKeyX: 1n,
          receiverSpendPubKeyY: 2n,
          receiverViewPubKeyX: 3n,
          receiverViewPubKeyY: 4n,
          amount: 11n,
          assetID: hashStringToField("uclair"),
          randomness: 12n,
          memo: "cached2"
        }
      }
    ]
  });
  client.fetchScanEvents = async request => ({
    events: [],
    next_height: request.afterHeight ?? 0,
    next_sequence: request.afterSequence ?? 0,
    limit: request.limit,
    has_more: false,
    scan_format_version: 1,
    view_tag_version: 1
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
        source: "scan_events",
        has_more: false,
        next_height: input.afterHeight,
        next_sequence: input.afterSequence
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
  assert.equal(requests[0].afterHeight, 73);
  assert.equal(requests[0].afterSequence, 9);

  await client.scanWalletNotes({
    material,
    noteStore: scanEventsStore,
    scanSource: "privacy_events"
  });
  assert.equal(requests[1].scanSource, "privacy_events");
  assert.equal(requests[1].afterHeight, 72);
  assert.equal(requests[1].afterSequence, 0);
  assert.equal(requests[1].page, 1);

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
  assert.equal(requests[2].afterHeight, 50);
  assert.equal(requests[2].page, 2);
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
          receiverSpendPubKeyX: 1n,
          receiverSpendPubKeyY: 2n,
          receiverViewPubKeyX: 3n,
          receiverViewPubKeyY: 4n,
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
        receiverSpendPubKeyX: 1n,
        receiverSpendPubKeyY: 2n,
        receiverViewPubKeyX: 3n,
        receiverViewPubKeyY: 4n,
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
      receiverSpendPubKeyX: 1n,
      receiverSpendPubKeyY: 2n,
      receiverViewPubKeyX: 3n,
      receiverViewPubKeyY: 4n,
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
        receiverSpendPubKeyX: 1n,
        receiverSpendPubKeyY: 2n,
        receiverViewPubKeyX: 3n,
        receiverViewPubKeyY: 4n,
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
  const nullifier = "ab".repeat(32);
  const store = new MemoryNoteStore({ owner: "clair1statuscase" });
  await store.mergeScanResult({
    foundNotes: [{
      height: 10,
      txHash: "STATUS-CASE",
      isSpent: false,
      nullifierStatus: "unspent",
      nullifier,
      note: {
        receiverSpendPubKeyX: 1n,
        receiverSpendPubKeyY: 2n,
        receiverViewPubKeyX: 3n,
        receiverViewPubKeyY: 4n,
        amount: 1n,
        assetID: hashStringToField("uclair"),
        randomness: 15n,
        memo: "status-case"
      }
    }]
  });

  await store.setNullifierStatuses(new Map([[nullifier.toUpperCase(), "spent"]]));
  const [updated] = (await store.load()).notes;
  assert.equal(updated.isSpent, true);
  assert.equal(updated.nullifierStatus, "spent");
});

test("Cosmos prepare methods forward top-level scan sequence cursors", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  const scans = [];
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
      recipient: "clairs1recipient",
      proverAdapter,
      afterHeight: 10,
      afterSequence: 11
    }),
    () => client.prepareTransferBatch({
      material,
      amounts: ["1uclair"],
      recipient: "clairs1recipient",
      proverAdapter,
      after_height: 20,
      after_sequence: 21
    }),
    () => client.prepareWithdraw({
      material,
      amount: "1uclair",
      recipient: "clair1recipient",
      proverAdapter,
      afterHeight: 30,
      afterSequence: 31
    }),
    () => client.prepareRelayWithdraw({
      material,
      amount: "1uclair",
      recipient: "clair1recipient",
      proverAdapter,
      after_height: 40,
      after_sequence: 41,
      expiresAtUnix: 4102448400,
      chainNowUnix: 4102444800
    })
  ];

  for (const call of calls) {
    await assert.rejects(call, /scan captured/);
  }
  assert.deepEqual(
    scans.map(scan => [scan.afterHeight, scan.afterSequence]),
    [[10, 11], [20, 21], [30, 31], [40, 41]]
  );
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

test("browser-dapp EVM prepareTransfer enables full operation success evidence", async () => {
  const client = createClairveilBrowserDappClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair",
    evmChainId: "0x7a69",
    evmPrivacyPrecompileAddress: "0x100000000000000000000000000000000000000b"
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
    shieldedAddress: "clairs1sender"
  });
  client.cosmos.scanNotes = async () => ({
    notes: [],
    summary: { total_spendable: "1", spendable_count: 3, spent_count: 0, total_count: 3 },
    diagnostics: { scanned_events: 0, new_notes_found: 0 },
    foundNotes: [helperNote(99, 99n), helperNote(100, 100n), selectedNote],
    scanCursor: { has_more: false }
  });
  client.cosmos.fetchAuditConfig = async () => ({ audit_master_pubkey_hex: "aa".repeat(32) });
  client.proverAdapter = () => null;
  client.cosmos.buildTransferMessage = async () => ({
    payload: {
      payload_hash: "payload-evm-transfer",
      outputs: [{ amount: "1", commitment_hex: "commitment-evm-transfer" }],
      audit_disclosure_digest_hex: "audit-digest-evm-transfer"
    },
    proof: { payload_hash: "payload-evm-transfer", proof_hex: "01" },
    message: { proof: new Uint8Array([1]) }
  });
  client.evm.contract.buildTransferTransaction = () => ({
    to: evmPrivacyPrecompileAddress,
    data: "0x1234"
  });
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
    expectedRecipientHash: "recipient-hash",
    expectedAmountHash: "amount-hash",
    reservationManager
  });

  assert.equal(result.transaction.data, "0x1234");
  assert.equal(result.reservation.reservations.length > 0, true);
  for (const reservationID of result.reservation.reservation_ids) {
    const reservation = await store.getReservation(reservationID);
    assert.equal(reservation.status, reservationStatuses.ProofReady);
    assert.equal(reservation.expected_output_commitment, "commitment-evm-transfer");
    assert.equal(reservation.expected_disclosure_digest, "audit-digest-evm-transfer");
    assert.equal(reservation.expected_recipient_hash, "recipient-hash");
    assert.equal(reservation.expected_amount_hash, "amount-hash");
    assert.equal(reservation.metadata.operation_success_evidence_required, true);
  }

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
    scanCursor: { has_more: false }
  });
  client.cosmos.buildTransferMessage = async input => ({
    payload: {
      payload_hash: "payload-evm-self-merge",
      outputs: [{ amount: input.amount.replace(/[^0-9].*$/, ""), commitment_hex: "commitment-evm-self-merge" }],
      audit_disclosure_digest_hex: "audit-digest-evm-self-merge"
    },
    proof: { payload_hash: "payload-evm-self-merge", proof_hex: "01" },
    message: { proof: new Uint8Array([1]) }
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
      amount: "1uclair",
      recipient: "clairs1recipient",
      expectedRecipientHash: "recipient-hash",
      reservationManager
    }),
    /expected recipient hash and expected amount hash must be provided together/
  );
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
  client.scanNotes = async () => heartbeatTestScanResult();
  client.fetchAuditConfig = async () => ({ audit_master_pubkey_hex: "aa".repeat(32) });
  client.buildTransferMessage = async () => heartbeatTestBuiltTransfer();
  client.buildDirectSignDoc = async input => input;

  const store = new MemoryReservationStore();
  const reservationManager = heartbeatFailureReservationManager(store, "chain:clair1cosmos-heartbeat");

  const prepared = await client.prepareTransfer({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient: "clairs1recipient",
    proverAdapter: null,
    reservationManager
  });
  assert.equal(prepared.status, "ready");
  assert.ok(prepared.signDoc);
  assert.ok(prepared.proof);
  assert.equal(prepared.reservationReconciliationRequired, true);
  assert.equal(
    prepared.reservationReconciliationWarning.code,
    "reservation_heartbeat_failed_after_proof_ready"
  );

  const reservations = (await store.load()).reservations;
  assert.equal(reservations.length > 0, true);
  assert.equal(reservations.every(reservation => reservation.status === reservationStatuses.ProofReady), true);
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
    evmPrivacyPrecompileAddress: "0x100000000000000000000000000000000000000b"
  });
  client.privacyMaterial = heartbeatTestMaterial;
  client.proverAdapter = () => null;
  client.cosmos.scanNotes = async () => heartbeatTestScanResult();
  client.cosmos.fetchAuditConfig = async () => ({ audit_master_pubkey_hex: "aa".repeat(32) });
  client.cosmos.buildTransferMessage = async () => heartbeatTestBuiltTransfer();
  client.proverAdapter = () => null;
  client.evm.contract.buildTransferTransaction = () => ({
    to: evmPrivacyPrecompileAddress,
    data: "0x1234"
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

test("cosmos prepareWithdraw works without a reservation manager and forwards chain time", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
  client.scanNotes = async () => heartbeatTestScanResult();
  let capturedChainNowUnix = null;
  client.buildWithdrawMessage = async input => {
    capturedChainNowUnix = input.chainNowUnix;
    return heartbeatTestBuiltWithdraw(input);
  };
  client.buildDirectSignDoc = async input => input;

  const prepared = await client.prepareWithdraw({
    material: heartbeatTestMaterial(),
    amount: "1uclair",
    recipient: "clair1recipient",
    proverAdapter: null,
    chainNowUnix: 4_102_444_800
  });

  assert.equal(prepared.status, "ready");
  assert.equal(capturedChainNowUnix, 4_102_444_800);
  assert.equal(prepared.reservation, null);
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
  client.cosmos.prepareWithdraw = async () => ({
    status: "ready",
    signDoc: { bodyBytes: "", authInfoBytes: "", chainId: "clairveil-local-3", accountNumber: "0" },
    reservation: null,
    privacyAccount: { shielded_address: "clairs1sender" },
    plan: { status: "withdraw_ready" },
    ...built
  });
  const prepared = await client.prepareWithdraw({
    walletType: "cosmos",
    address: "clair1sender",
    pubKeyHex: "02".padEnd(66, "0"),
    signatureBase64: "AQID",
    amount: "1uclair",
    recipient: "clair1recipient"
  });
  assert.equal(prepared.payload, built.payload);
  assert.equal(prepared.proof, built.proof);
  assert.equal(prepared.message, built.message);
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
    evmPrivacyPrecompileAddress: "0x100000000000000000000000000000000000000b"
  });
  client.privacyMaterial = heartbeatTestMaterial;
  client.cosmos.scanNotes = async () => heartbeatTestScanResult();
  client.proverAdapter = () => null;
  let capturedChainNowUnix = null;
  client.cosmos.buildWithdrawMessage = async input => {
    capturedChainNowUnix = input.chainNowUnix;
    return heartbeatTestBuiltWithdraw(input);
  };
  client.evm.contract.buildWithdrawTransaction = () => ({
    to: evmPrivacyPrecompileAddress,
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
      outputs: [{ amount: "1", commitment_hex: "commitment-heartbeat" }],
      audit_disclosure_digest_hex: "audit-digest-heartbeat"
    },
    proof: { payload_hash: "payload-heartbeat", proof_hex: "01" },
    message: { proof: new Uint8Array([1]) }
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

test("Cosmos prepareTransfer rejects partial operation evidence hashes before scanning", async () => {
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
      expectedAmountHash: "amount-hash"
    }),
    /expected recipient hash and expected amount hash must be provided together/
  );
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

test("planner selects non-overlapping notes for batch transfer", () => {
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
  assert.equal(plan.selections.length, 2);
  const inputKeys = plan.selections.flatMap(selection => (
    selection.inputs.map(input => `${input.height}:${input.note.amount}`)
  ));
  assert.equal(new Set(inputKeys).size, 4);
});

test("planner backtracks batch transfers beyond the small-item exact limit", () => {
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
  assert.equal(plan.selections.length, targetAmounts.length);
  const inputKeys = plan.selections.flatMap(selection => (
    selection.inputs.map(input => `${input.height}:${input.note.amount}`)
  ));
  assert.equal(new Set(inputKeys).size, inputKeys.length);
  assert.deepEqual(
    plan.selections.map((selection, index) => selection.total >= BigInt(targetAmounts[index])),
    targetAmounts.map(() => true)
  );
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

test("planner batch transfer uses bounded exact candidates for large note sets", () => {
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
  assert.equal(plan.selections.length, 4);
  assert.equal(plan.selections.every(selection => selection.isFinal), true);
  const inputKeys = plan.selections.flatMap(selection => (
    selection.inputs.map(input => `${input.height}:${input.note.amount}`)
  ));
  assert.equal(new Set(inputKeys).size, inputKeys.length);
});

test("cosmos prepareTransferBatch accepts reservation_manager and builds one sign doc with multiple transfer messages", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
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
  client.scanNotes = async () => ({
    notes: [],
    summary: { total_spendable: "12", spendable_count: 4, spent_count: 0, total_count: 4 },
    diagnostics: { scanned_events: 0, new_notes_found: 0 },
    foundNotes: [
      note(0, 1, 1),
      note(0, 2, 2),
      note(5, 3, 3),
      note(7, 4, 4)
    ],
    scanCursor: { has_more: false }
  });
  client.fetchAuditConfig = async () => ({ audit_master_pubkey_hex: "aa".repeat(32) });
  const builtAmounts = [];
  client.buildTransferMessage = async input => {
    builtAmounts.push(input.amount);
    const itemIndex = builtAmounts.length - 1;
    const outputAmount = input.amount.replace(/[^0-9].*$/, "");
    return {
      payload: {
        payload_hash: `payload-${builtAmounts.length}`,
        outputs: [{ amount: outputAmount, commitment_hex: `commitment-${itemIndex}` }],
        audit_disclosure_digest_hex: `audit-digest-${itemIndex}`
      },
      proof: { payload_hash: `payload-${builtAmounts.length}`, proof_hex: "01" },
      message: { creator: input.creator, amount: input.amount }
    };
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

  const result = await client.prepareTransferBatch({
    material: {
      rootSeed: new Uint8Array(32),
      address: "clair1sender",
      pubKeyHex: "02".padEnd(66, "0"),
      shieldedAddress: "clairs1sender"
    },
    amounts: ["5uclair", "7uclair"],
    recipient: "clairs1recipient",
    proverAdapter: null,
    expectedRecipientHash: "recipient-hash",
    expectedAmountHashes: ["amount-hash-0", "amount-hash-1"],
    reservation_manager: reservationManager
  });

  assert.equal(result.status, "ready");
  assert.equal(result.signDoc.messages.length, 2);
  const serializedReservedSignDoc = JSON.parse(JSON.stringify(result.signDoc));
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
  client.broadcastSignedTx = async (_signedTx, options) => {
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
  assert.deepEqual(builtAmounts, ["5uclair", "7uclair"]);
  assert.equal(result.messages.length, 2);
  assert.deepEqual(result.prepared.selectedInputTotals, ["5", "7"]);
  assert.equal(result.reservation.reservations.length, 4);
  for (const reservation of result.reservation.reservations) {
    assert.equal(reservation.status, reservationStatuses.ProofReady);
    assert.equal(reservation.expected_recipient_hash, "recipient-hash");
    assert.equal(reservation.expected_denom, "uclair");
    assert.equal(reservation.batch_item_index_known, true);
    assert.equal(reservation.metadata.operation_success_evidence_required, true);
  }
  const reservationsByItem = new Map();
  for (const reservation of result.reservation.reservations) {
    const group = reservationsByItem.get(reservation.batch_item_index) || [];
    group.push(reservation);
    reservationsByItem.set(reservation.batch_item_index, group);
  }
  assert.deepEqual([...reservationsByItem.keys()].sort(), [0, 1]);
  for (const reservation of reservationsByItem.get(0)) {
    assert.equal(reservation.expected_output_commitment, "commitment-0");
    assert.equal(reservation.expected_disclosure_digest, "audit-digest-0");
    assert.equal(reservation.expected_amount, "5");
    assert.equal(reservation.expected_amount_hash, "amount-hash-0");
  }
  for (const reservation of reservationsByItem.get(1)) {
    assert.equal(reservation.expected_output_commitment, "commitment-1");
    assert.equal(reservation.expected_disclosure_digest, "audit-digest-1");
    assert.equal(reservation.expected_amount, "7");
    assert.equal(reservation.expected_amount_hash, "amount-hash-1");
  }
});

test("cosmos prepareTransferBatch rejects partial operation evidence arrays", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
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
    proverAdapter: null
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
});

test("cosmos prepareTransferBatch keeps ProofReady transitions atomic across every batch item", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    defaultDenom: "uclair"
  });
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
  client.scanNotes = async () => ({
    notes: [],
    summary: { total_spendable: "12", spendable_count: 4, spent_count: 0, total_count: 4 },
    diagnostics: { scanned_events: 0, new_notes_found: 0 },
    foundNotes: [
      note(0, 1, 1),
      note(0, 2, 2),
      note(5, 3, 3),
      note(7, 4, 4)
    ],
    scanCursor: { has_more: false }
  });
  client.fetchAuditConfig = async () => ({ audit_master_pubkey_hex: "aa".repeat(32) });
  client.buildTransferMessage = async input => {
    const outputAmount = input.amount.replace(/[^0-9].*$/, "");
    return {
      payload: {
        payload_hash: `payload-${outputAmount}`,
        outputs: [{ amount: outputAmount, commitment_hex: `commitment-${outputAmount}` }],
        audit_disclosure_digest_hex: `audit-digest-${outputAmount}`
      },
      proof: { payload_hash: `payload-${outputAmount}`, proof_hex: "01" },
      message: { creator: input.creator, amount: input.amount }
    };
  };
  client.buildDirectSignDoc = async input => input;
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
        rootSeed: new Uint8Array(32),
        address: "clair1sender",
        pubKeyHex: "02".padEnd(66, "0"),
        shieldedAddress: "clairs1sender"
      },
      amounts: ["5uclair", "7uclair"],
      recipient: "clairs1recipient",
      proverAdapter: null,
      reservation_manager: reservationManager
    }),
    /injected proof-ready failure/
  );

  const reservations = await store.listReservations({ ownerKeyId: "chain:clair1sender" });
  assert.equal(reservations.length, 4);
  assert.equal(markProofReadyBatchCalls, 1);
  assert.equal(reservations.some(reservation => reservation.status === reservationStatuses.ProofReady), false);
  assert.equal(reservations.some(reservation => reservation.status === reservationStatuses.Reserved), false);
  assert.equal(reservations.some(reservation => reservation.status === reservationStatuses.Proving), false);
  assert.equal(
    reservations.filter(reservation => reservation.status === reservationStatuses.Released).length,
    4
  );

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
  cleanupManager.markReplanRequired = async () => {
    throw new Error("injected replan cleanup failure");
  };
  await assert.rejects(
    () => client.prepareTransferBatch({
      material: {
        rootSeed: new Uint8Array(32),
        address: "clair1cleanup",
        pubKeyHex: "02".padEnd(66, "0"),
        shieldedAddress: "clairs1cleanup"
      },
      amounts: ["5uclair", "7uclair"],
      recipient: "clairs1recipient",
      proverAdapter: null,
      reservation_manager: cleanupManager
    }),
    error =>
      /injected proof-ready failure with cleanup failure/.test(error?.message || "") &&
      Array.isArray(error?.reservationCleanupErrors) &&
      /injected replan cleanup failure/.test(error.reservationCleanupErrors[0]?.message || "")
  );
  const cleanupReservations = await cleanupStore.listReservations({
    ownerKeyId: "chain:clair1cleanup"
  });
  assert.equal(
    cleanupReservations.filter(reservation => reservation.status === reservationStatuses.ProofReady).length,
    4
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
  frozenManager.markReplanRequired = async () => {
    throw new Error("frozen batch cleanup failure");
  };
  await assert.rejects(
    () => client.prepareTransferBatch({
      material: {
        rootSeed: new Uint8Array(32),
        address: "clair1frozen",
        pubKeyHex: "02".padEnd(66, "0"),
        shieldedAddress: "clairs1frozen"
      },
      amounts: ["5uclair", "7uclair"],
      recipient: "clairs1recipient",
      proverAdapter: null,
      reservation_manager: frozenManager
    }),
    error => error === frozenOriginal
  );
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
      return /explicit successful result/.test(error.message);
    }
  );
});

test("cosmos broadcastSignedTx rejects missing or malformed indexed result codes", async () => {
  for (const code of [undefined, "", "bogus", -1, 1.5]) {
    const client = createClairveilClient({
      rpc: "http://127.0.0.1:26657",
      rest: "http://127.0.0.1:1317",
      chainId: "clairveil-local-3"
    });
    client.connect = async () => ({ broadcastTxSync: async () => "ABC123" });
    client.buildTxRawBytes = () => new Uint8Array([1, 2, 3]);
    client.waitForTx = async () => ({ txhash: "ABC123", code, events: [] });

    await assert.rejects(
      () => client.broadcastSignedTx({ bodyBytes: "", authInfoBytes: "", signature: "" }),
      error => error.txHash === "ABC123" && error.broadcast?.code === null && /explicit successful result/.test(error.message)
    );
  }
});

test("cosmos broadcast errors retain tx bytes and tx hash evidence", async () => {
  const expectedTxBytesHash = createHash("sha256")
    .update(new Uint8Array([1, 2, 3]))
    .digest("hex");
  const beforeHash = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  beforeHash.connect = async () => ({
    broadcastTxSync: async () => {
      throw new Error("rpc unavailable");
    }
  });
  beforeHash.buildTxRawBytes = () => new Uint8Array([1, 2, 3]);
  await assert.rejects(
    () => beforeHash.broadcastSignedTx({ bodyBytes: "", authInfoBytes: "", signature: "" }),
    error => error.txBytesHash === expectedTxBytesHash && !error.txHash
  );

  const afterHash = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  afterHash.connect = async () => ({ broadcastTxSync: async () => "ABC123" });
  afterHash.buildTxRawBytes = () => new Uint8Array([1, 2, 3]);
  afterHash.waitForTx = async () => {
    throw new Error("index temporarily unavailable");
  };
  await assert.rejects(
    () => afterHash.broadcastSignedTx({ bodyBytes: "", authInfoBytes: "", signature: "" }),
    error =>
      error.txHash === "ABC123" &&
      error.txBytesHash === expectedTxBytesHash
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
  assert.equal(result.broadcast.code, null);
  assert.match(result.error, /broadcast but not found yet/);
});

test("cosmos broadcast persists an attempt before RPC and blocks retry when bookkeeping fails", async () => {
  const { store, reservationManager, reservation } = await readyBroadcastReservation("21", {
    signDocHash: cosmosSignDocBindingHash({ bodyBytes: "", authInfoBytes: "" })
  });
  const expectedTxBytesHash = createHash("sha256")
    .update(new Uint8Array([4, 5, 6]))
    .digest("hex");
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
  const transportError = Object.freeze(new Error("RPC response was lost"));
  let broadcastCalls = 0;
  client.connect = async () => ({
    broadcastTxSync: async () => {
      broadcastCalls += 1;
      const stored = await store.getReservation(reservation.reservation_ids[0]);
      assert.equal(stored.broadcast_in_flight, true);
      assert.equal(stored.broadcast_attempt_count, 1);
      assert.equal(stored.tx_bytes_hash, expectedTxBytesHash);
      throw transportError;
    }
  });
  client.buildTxRawBytes = () => new Uint8Array([4, 5, 6]);
  reservationManager.markUnknown = async () => {
    throw new Error("IndexedDB write failed");
  };

  const broadcast = () => client.broadcastSignedTx(
    { bodyBytes: "", authInfoBytes: "", signature: "" },
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
  assert.equal(unresolved.tx_bytes_hash, expectedTxBytesHash);

  await assert.rejects(broadcast, /broadcast attempt already started; reconcile before retry/);
  assert.equal(broadcastCalls, 1);
});

test("reserved Cosmos broadcasts reject sign docs changed after ProofReady", async () => {
  const { reservationManager, reservation } = await readyBroadcastReservation("28", {
    signDocHash: cosmosSignDocBindingHash({ bodyBytes: "", authInfoBytes: "" })
  });
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
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
    version: "v1",
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
  cosmos.buildTxRawBytes = () => new Uint8Array([1, 2, 3]);
  await assert.rejects(
    () => cosmos.broadcastSignedTx(
      { bodyBytes: "", authInfoBytes: "", signature: "" },
      { relayPayload: cosmosPayload, getChainNowUnix: async () => 1_002 }
    ),
    /withdraw payload expired/
  );
  assert.equal(cosmosBroadcastCalls, 0);

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
      chainNowUnix: 1_500
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
  const evm = createClairveilEvmClient({ chainId: "demo-1", accountPrefix: "demo" });
  let evmBroadcastCalls = 0;
  await assert.rejects(
    () => evm.sendTransaction({
      async sendTransaction() {
        evmBroadcastCalls += 1;
        return "0x" + "42".repeat(32);
      }
    }, { to: evmPrivacyPrecompileAddress }, {
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
    /does not match the EVM transaction/
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
    getChainNowUnix: async () => 1_000
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
    expectedEvmChainId: "0x1"
  });
  assert.equal(evmBroadcastCalls, 2);
  assert.equal(submittedEvmTransaction.chainId, "0x1");
  assert.equal("from" in submittedEvmTransaction, false);
  assert.equal("gas" in submittedEvmTransaction, false);
  assert.equal("maxFeePerGas" in submittedEvmTransaction, false);
});

test("custom EVM withdraw encoders retain the relay validation marker", async () => {
  const payload = {
    version: "v1",
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
    buildDepositTransaction: () => ({ to: evmPrivacyPrecompileAddress, data: "0x01" }),
    buildTransferTransaction: () => ({ to: evmPrivacyPrecompileAddress, data: "0x02" }),
    buildWithdrawTransaction: () => ({ to: evmPrivacyPrecompileAddress, data: "0xcafebabe", value: "0x0" })
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
    version: "v1",
    proof_hex: "01",
    root_hex: "08".repeat(32),
    nullifier_hex: "0c".repeat(32),
    amount: "1udemo",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chain_id: "demo-1",
    expires_at_unix: 2_000
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);
  const client = createClairveilEvmClient({ chainId: "demo-1", accountPrefix: "demo" });
  const prepared = await client.buildWithdrawTransaction({ payload, chainNowUnix: 1_000 });
  const context = await readyBroadcastReservation("27", {
    payloadHash: payload.payload_hash
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
    expectedEvmChainId: "0x1"
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
    txBytesHash: evmTransactionBindingHash(boundTransaction)
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
    expectedEvmChainId: "0x1"
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
    version: "v1",
    proof_hex: "01",
    root_hex: "08".repeat(32),
    nullifier_hex: "0e".repeat(32),
    amount: "1udemo",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chain_id: "demo-1",
    expires_at_unix: 2_000
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);
  const client = createClairveilEvmClient({ chainId: "demo-1", accountPrefix: "demo" });
  const prepared = await client.buildWithdrawTransaction({ payload, chainNowUnix: 1_000 });
  const context = await readyBroadcastReservation("29", {
    payloadHash: payload.payload_hash
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
      chainNowUnix: 1_000
    }),
    error => error.message === "wallet response was lost" &&
      error.cause === transportError &&
      error.reservationReconciliationRequired === true &&
      /IndexedDB write failed/.test(error.reservationBookkeepingError?.message || "")
  );
});

test("reserved EVM transaction guards survive JSON serialization", async () => {
  const client = createClairveilEvmClient();
  const selectors = [
    functionSelector("transfer((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes))"),
    functionSelector("withdraw((bytes,bytes,bytes,bytes,bytes,string,address,string,uint64))")
  ];
  let calls = 0;

  for (const selector of selectors) {
    const transaction = JSON.parse(JSON.stringify(markEvmTransactionReservationRequired({
      to: evmPrivacyPrecompileAddress,
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
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
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
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
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

test("cosmos signDirectAndBroadcast forwards top-level polling options", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
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
  client.broadcastSignedTx = async (_signedTx, options) => {
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
    txBytesHash: evmTransactionBindingHash({ to: evmPrivacyPrecompileAddress })
  });
  let submittedCalls = 0;
  const submittedClient = createClairveilEvmClient();
  const txHash = await submittedClient.sendTransaction({
    async sendTransaction() {
      submittedCalls += 1;
      const stored = await submittedContext.store.getReservation(
        submittedContext.reservation.reservation_ids[0]
      );
      assert.equal(stored.broadcast_in_flight, true);
      return "0x" + "22".repeat(32);
    }
  }, { to: evmPrivacyPrecompileAddress }, {
    reservationManager: submittedContext.reservationManager,
    reservation: submittedContext.reservation
  });
  assert.equal(txHash, "0x" + "22".repeat(32));
  assert.equal(submittedCalls, 1);
  const submitted = await submittedContext.store.getReservation(
    submittedContext.reservation.reservation_ids[0]
  );
  assert.equal(submitted.status, reservationStatuses.Submitted);
  assert.equal(submitted.broadcast_in_flight, false);

  const ambiguousContext = await readyBroadcastReservation("23", {
    txBytesHash: evmTransactionBindingHash({ to: evmPrivacyPrecompileAddress })
  });
  let ambiguousCalls = 0;
  const ambiguousClient = createClairveilEvmClient();
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
    }, { to: evmPrivacyPrecompileAddress }, {
      reservationManager: ambiguousContext.reservationManager,
      reservation: ambiguousContext.reservation
    }),
    /provider response unavailable/
  );
  const reviewed = await ambiguousContext.store.getReservation(
    ambiguousContext.reservation.reservation_ids[0]
  );
  assert.equal(reviewed.status, reservationStatuses.ManualReview);
  assert.equal(reviewed.broadcast_in_flight, false);
  await assert.rejects(
    () => ambiguousClient.sendTransaction({
      async sendTransaction() {
        ambiguousCalls += 1;
        return "0x" + "23".repeat(32);
      }
    }, { to: evmPrivacyPrecompileAddress }, {
      reservationManager: ambiguousContext.reservationManager,
      reservation: ambiguousContext.reservation
    }),
    /broadcast attempt requires ProofReady reservation: ManualReview/
  );
  assert.equal(ambiguousCalls, 1);

  const rejectedContext = await readyBroadcastReservation("24", {
    txBytesHash: evmTransactionBindingHash({ to: evmPrivacyPrecompileAddress })
  });
  const rejectedClient = createClairveilEvmClient();
  await assert.rejects(
    () => rejectedClient.sendTransaction({
      async sendTransaction() {
        const error = new Error("User rejected the request");
        error.code = 4001;
        throw error;
      }
    }, { to: evmPrivacyPrecompileAddress }, {
      reservationManager: rejectedContext.reservationManager,
      reservation: rejectedContext.reservation
    }),
    error => error.code === 4001
  );
  const rejected = await rejectedContext.store.getReservation(
    rejectedContext.reservation.reservation_ids[0]
  );
  assert.equal(rejected.status, reservationStatuses.ReplanRequired);
  assert.equal(rejected.broadcast_in_flight, false);
  assert.equal(rejected.metadata.wallet_rejected_before_broadcast, true);
});

test("EVM sendTransaction rejects malformed provider transaction hashes", async () => {
  const context = await readyBroadcastReservation("25", {
    txBytesHash: evmTransactionBindingHash({ to: evmPrivacyPrecompileAddress })
  });
  const client = createClairveilEvmClient();

  await assert.rejects(
    () => client.sendTransaction({
      async sendTransaction() {
        return "provider-request-id";
      }
    }, { to: evmPrivacyPrecompileAddress }, {
      reservationManager: context.reservationManager,
      reservation: context.reservation
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
    maxPages: 1
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
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
  });
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
        events: [{ event_type: "shielded_transfer", tx_hash_hex: "NOTME" }],
        has_more: true,
        next_height: 100,
        next_sequence: 8
      };
    }
    return {
      events: [{ event_type: "shielded_transfer", tx_hash_hex: "AABBCC" }],
      has_more: false,
      next_height: 100,
      next_sequence: 9
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
  assert.equal(packageJson.scripts.prepack, "npm run verify:package");
  assert.equal(packageJson.scripts.prepublishOnly, "npm run verify:release");
  assert.ok(!packageJson.scripts["verify:package"].includes("test:conformance:required"));
  assert.ok(packageJson.scripts["verify:release"].includes("test:conformance:required"));
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
    notes: [{ note, isSpent: false, nullifierStatus: "unspent" }],
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

test("relay withdraw keeps authoritative chain time through proof finalization", async () => {
  const note = {
    receiverSpendPubKeyX: 1n,
    receiverSpendPubKeyY: 2n,
    receiverViewPubKeyX: 3n,
    receiverViewPubKeyY: 4n,
    amount: 1n,
    assetID: hashStringToField("uclair"),
    randomness: 6n,
    memo: "chain-time",
  };
  const input = {
    notes: [{ note, isSpent: false, nullifierStatus: "unspent" }],
    amount: "1uclair",
    recipient: "clair1qgpqyqszqgpqyqszqgpqyqszqgpqyqsz378u48",
    chainId: "clairveil-local-1",
    expiresAtUnix: 2_000,
    rootSeed: new Uint8Array(32).fill(1),
    merklePathProvider: {
      async lookupMerklePath() {
        return { root: "01".padStart(64, "0"), path: [], path_helper: [] };
      },
    },
    checkNullifiers: async (nullifiers) =>
      new Map(nullifiers.map((nullifier) => [nullifier, false])),
    proverAdapter: {
      async proveWithdraw({ payload }) {
        return {
          version: "v1",
          payload_hash: payload.payload_hash,
          proof_hex: "01",
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
    viewTags: [new Uint8Array([8, 9]), new Uint8Array([10, 11])],
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
  assert.equal(transfer.transaction.data.slice(2, 10), functionSelector("transfer((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes))"));
  assert.equal(withdraw.message, withdrawMessage);
  assert.equal(withdraw.payload, undefined);
  assert.equal(withdraw.proof, undefined);
  assert.equal(withdraw.proverPayload, undefined);
  assert.equal(withdraw.selectedNote, undefined);
  assert.equal(withdraw.transaction.to, evmPrivacyPrecompileAddress);
  assert.equal(withdraw.transaction.data.slice(2, 10), functionSelector("withdraw((bytes,bytes,bytes,bytes,bytes,string,address,string,uint64))"));

  const frozenTransferRequest = Object.freeze({ to: evmPrivacyPrecompileAddress, data: "0x1234", value: "0x0" });
  const frozenWithdrawRequest = Object.freeze({ to: evmPrivacyPrecompileAddress, data: "0x5678", value: "0x0" });
  const immutableAdapterClient = createClairveilEvmClient({
    accountPrefix: "demo",
    contractAdapter: {
      buildDepositTransaction: () => ({ to: evmPrivacyPrecompileAddress, data: "0x01" }),
      buildTransferTransaction: () => frozenTransferRequest,
      buildWithdrawTransaction: () => frozenWithdrawRequest
    }
  });
  const immutableTransfer = await immutableAdapterClient.buildTransferTransaction({ message: transferMessage });
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
  const merklePathProvider = {
    async lookupMerklePath() {
      return { root: "01".padStart(64, "0"), path: [], path_helper: [] };
    }
  };
  const checkedBatches = [];
  const checkNullifiers = async nullifiers => {
    checkedBatches.push([...nullifiers]);
    return new Map(nullifiers.map(nullifier => [nullifier, false]));
  };
  const client = createClairveilEvmClient({
    accountPrefix: "demo",
    shieldedPrefix: "demos",
    chainId: "demo-1",
    defaultDenom: "udemo"
  });

  await assert.rejects(
    () => client.buildWithdrawTransaction({
      notes: [foundNote(100n)],
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
    inputs: [foundNote(101n), foundNote(102n)],
    recipient: recipientMaterial.shieldedAddress,
    amount: "1udemo",
    rootSeed,
    merklePathProvider,
    auditDisclosureTargetPubKeyHex: recipientMaterial.disclosurePubKeyHex,
    checkNullifiers,
    proverAdapter: {
      async proveTransfer({ payload }) {
        assert.equal(checkedBatches.length, 1);
        return { version: "v1", payload_hash: payload.payload_hash, proof_hex: "01" };
      }
    }
  });
  const withdraw = await client.buildWithdrawTransaction({
    notes: [foundNote(103n)],
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
        return { version: "v1", payload_hash: payload.payload_hash, proof_hex: "01" };
      }
    }
  });

  assert.equal(checkedBatches[0].length, 2);
  assert.equal(checkedBatches[1].length, 1);
  assert.equal(transfer.status, "ready");
  assert.equal(withdraw.status, "ready");
  assert.equal(withdraw.message.recipient, evmAddressToBech32("0x2222222222222222222222222222222222222222", "demo"));
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
  assert.equal(withdraw.transaction.to, evmPrivacyPrecompileAddress);
  assert.equal(withdraw.transaction.data.slice(2, 10), functionSelector("withdraw((bytes,bytes,bytes,bytes,bytes,string,address,string,uint64))"));
});

test("Cosmos operation evidence rejects conflicting direct and batch aliases", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3"
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
    expectedChainId: "demo-1",
    chainNowUnix: 4102444800
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
      evmRecipient: "0x2222222222222222222222222222222222222222",
      chainNowUnix: 4102444800
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
    const built = {
      payload,
      proof: { version: "v1", payload_hash: payload.payload_hash, proof_hex: "01" },
      proverPayload: { payload_hash: payload.payload_hash },
      selectedNote: { nullifier: "09".repeat(32) }
    };
    return {
      status: "ready",
      plan: { status: "final_withdraw_ready", canBuildTx: true },
      ...built,
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
    chainNowUnix: 4102444800
  });

  assert.equal(captured.recipient, evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"));
  assert.equal(prepared.payload, prepared.prepared.payload);
  assert.equal(prepared.prepared.evmRecipient, "0x1111111111111111111111111111111111111111");
  assert.equal(prepared.transaction.chainId, "0x539");
  assert.equal(prepared.transaction.to, evmPrivacyPrecompileAddress);
  assert.equal(prepared.transaction.data.slice(2, 10), functionSelector("withdraw((bytes,bytes,bytes,bytes,bytes,string,address,string,uint64))"));
});

test("browser-dapp EVM relay withdraw build failure replans the durable ProofReady reservation", async () => {
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
      evmPrivacyPrecompileAddress
    },
    proverUrl: "http://127.0.0.1:8080"
  });
  client.privacyMaterial = () => ({
    rootSeed: new Uint8Array(32),
    address: "demo1example",
    pubKeyHex: "02".padEnd(66, "0"),
    shieldedAddress: "demos1example"
  });

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
  const batch = await reservationManager.reserveNotes({
    notes: [selectedNote],
    kind: "relay_withdraw"
  });
  await reservationManager.markProving(batch.reservation_ids, {
    leaseToken: batch.lease_token
  });
  const payload = {
    proof_hex: "01",
    root_hex: "08".repeat(32),
    nullifier_hex: selectedNote.nullifier,
    amount: "1udemo",
    recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
    chain_id: "demo-1",
    version: "v1",
    expires_at_unix: 4102448400
  };
  payload.payload_hash = computePreparedWithdrawPayloadHash(payload);
  const readyReservations = await reservationManager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    payloadHash: payload.payload_hash
  });
  batch.reservations = readyReservations;
  batch.lease_until = readyReservations[0].lease_until;
  client.cosmos.prepareRelayWithdraw = async () => {
    return {
      status: "ready",
      plan: { status: "final_withdraw_ready", canBuildTx: true },
      payload,
      proof: { version: "v1", payload_hash: payload.payload_hash, proof_hex: "01" },
      proverPayload: { payload_hash: payload.payload_hash },
      selectedNote,
      reservation: batch,
      privacyAccount: { shielded_address: "demos1example" }
    };
  };
  client.evm.buildWithdrawTransaction = async () => {
    throw new Error("evm transaction build failed");
  };

  await assert.rejects(
    () => client.prepareRelayWithdraw({
      walletType: "evm",
      address: "demo1example",
      pubKeyHex: "02".padEnd(66, "0"),
      signatureBase64: "AQID",
      amount: "1udemo",
      recipient: "0x1111111111111111111111111111111111111111",
      chainNowUnix: 4102444800,
      reservationManager
    }),
    /evm transaction build failed/
  );

  const updated = await store.getReservation(batch.reservation_ids[0]);
  assert.equal(updated.status, reservationStatuses.ReplanRequired);
  assert.equal(await reservationManager.reservationForNote(selectedNote), null);
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
    viewTags: [new Uint8Array([8, 9]), new Uint8Array([10, 11])],
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
  assert.equal(transfer.slice(2, 10), functionSelector("transfer((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes))"));
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
