import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { fromBech32, toBech32 } from "@cosmjs/encoding";
import {
  createBrowserReservationStore,
  createNoteReservationManager,
  IndexedDbReservationStore,
  MemoryReservationStore,
  hashAmount,
  hashRecipient,
  nullifierLookupKey,
  nullifierLookupKeyFromHex,
  noteReservationIdentity,
  operationStatuses,
  preparePlanReservation,
  reservationHeartbeatIntervalMs,
  reservationStatuses,
  rollbackPlanReservation,
  rollbackPlanReservationPreservingError
} from "clairveiljs/reservation";

const canonicalRecipient = "clairs19x5u4mf4l4zqcpvr7d809fh4tjy5j50p2mwgky0nj38jpqpj7svndu3hqshu5e3s8w6pea5p30xek5p9flxjf7f44xh7cnfrlsd84pc7upgh3";
const lowOrderRecipient = "clairs1qqqqpuyn7hs58ytsh9u536pn9pw43qvpkez4pwpf5qc7zujwvscqqqqq7zfltc2rj9ctj72gaqejsh2csxqmv32shq56qv0pwf8xgvqkr7743";

function noteFixture({
  nullifier = "11".repeat(32),
  amount = 5,
  height = 10,
  sequence = 1,
  txHash = "ABCD",
  spent = false
} = {}) {
  return {
    note: {
      receiverSpendPubKeyX: 1n,
      receiverSpendPubKeyY: 2n,
      receiverViewPubKeyX: 3n,
      receiverViewPubKeyY: 4n,
      amount: BigInt(amount),
      assetID: 7n,
      randomness: 8n,
      memo: ""
    },
    nullifier,
    isSpent: spent,
    nullifierStatus: spent ? "spent" : "unspent",
    txHash,
    height,
    sequence
  };
}

async function markSubmittedAfterAttempt(manager, batch, metadata) {
  await manager.markBroadcastAttempting(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    txHash: metadata.txHash || metadata.tx_hash || "",
    txBytesHash: metadata.txBytesHash || metadata.tx_bytes_hash || "",
    signDocHash: metadata.signDocHash || metadata.sign_doc_hash || "",
    reason: "test_broadcast"
  });
  return manager.markSubmitted(batch.reservation_ids, metadata);
}

async function markUnknownAfterAttempt(manager, batch, metadata) {
  await manager.markBroadcastAttempting(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    txHash: metadata.txHash || metadata.tx_hash || "",
    txBytesHash: metadata.txBytesHash || metadata.tx_bytes_hash || "",
    signDocHash: metadata.signDocHash || metadata.sign_doc_hash || "",
    reason: "test_broadcast"
  });
  return manager.markUnknown(batch.reservation_ids, metadata);
}

function indexedDbHarness(initialValue) {
  let storedValue = initialValue;
  const db = {
    transaction() {
      const tx = {
        objectStore() {
          return {
            get() {
              const request = {};
              setTimeout(() => {
                request.result = storedValue;
                request.onsuccess?.();
                setTimeout(() => tx.oncomplete?.(), 0);
              }, 0);
              return request;
            },
            put(value) {
              storedValue = value;
              setTimeout(() => tx.oncomplete?.(), 0);
            }
          };
        }
      };
      return tx;
    }
  };
  return {
    db,
    get storedValue() {
      return storedValue;
    }
  };
}

test("nullifier lookup key matches the handoff vector", () => {
  assert.equal(
    nullifierLookupKey("index-key-v1", "nullifier-0001"),
    "be314f12370f9e73eac4d34dab5efbfded54b813389666e6e6e547762b61159a"
  );
  assert.throws(
    () => nullifierLookupKey("index-key-v1", "aa".repeat(32)),
    /nullifierLookupKeyFromHex/
  );
  assert.throws(
    () => nullifierLookupKey("index-key-v1", `0X${"aB".repeat(32)}`),
    /nullifierLookupKeyFromHex/
  );
  assert.equal(
    nullifierLookupKeyFromHex("index-key-v1", "aa".repeat(32)),
    "1e654644d0ca0a1a733ed461e6ee08ea5733b40be5d13d5235b9e872e5310049"
  );
  assert.throws(
    () => nullifierLookupKeyFromHex("index-key-v1", "aa".repeat(31)),
    /exactly 32 bytes/
  );
  assert.throws(
    () => nullifierLookupKeyFromHex("index-key-v1", "zz".repeat(32)),
    /exactly 32 bytes/
  );
});

test("recipient hash canonicalizes and validates Go-compatible shielded addresses", () => {
  const expected = "8a3344bcbfdd71e8346f1fcc5d9d09d493c3345b0e94d26371f89b2574545d3c";
  assert.equal(hashRecipient(canonicalRecipient), expected);
  assert.equal(hashRecipient(canonicalRecipient.toUpperCase()), expected);
  assert.throws(
    () => hashRecipient("clairs1llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllct37x5k"),
    /valid shielded address/
  );
  assert.throws(() => hashRecipient(lowOrderRecipient), /valid shielded address/);
  assert.throws(() => hashRecipient("clair1recipient"), /shielded address|bech32/i);

  const decoded = fromBech32(canonicalRecipient, 200);
  const customRecipient = toBech32("demos", decoded.data, 200);
  const customExpected = createHash("sha256").update(customRecipient, "utf8").digest("hex");
  assert.equal(hashRecipient(customRecipient, { shieldedPrefix: "demos" }), customExpected);
  assert.throws(() => hashRecipient(customRecipient), /valid shielded address/);
});

test("amount hash rejects non-canonical Cosmos denominations", () => {
  assert.throws(() => hashAmount("bad!denom", "10"), /Cosmos SDK denomination/);
  assert.throws(() => hashAmount(" uclair", "10"), /Cosmos SDK denomination/);
  assert.throws(() => hashAmount(["uclair"], "10"), /denomination string/);
  assert.throws(() => hashAmount("uclair", true), /safe integer, bigint/);
  assert.throws(() => hashAmount("uclair", [1]), /safe integer, bigint/);
  assert.throws(() => hashAmount("uclair", { toString: () => "1" }), /safe integer, bigint/);
  assert.doesNotThrow(() => hashAmount("uclair", "10"));
  assert.doesNotThrow(() => hashAmount("uclair", 10));
  assert.doesNotThrow(() => hashAmount("uclair", 10n));
});

test("reservation note ids do not embed raw nullifier prefixes", () => {
  const note = noteFixture({ nullifier: "de".repeat(32), height: 44, sequence: 9, txHash: "AABB" });
  const identity = noteReservationIdentity(note);
  assert.equal(identity.noteId, "44:9:AABB");
  assert.equal(identity.noteId.includes(note.nullifier.slice(0, 12)), false);

  const precise = noteReservationIdentity(noteFixture({
    nullifier: "df".repeat(32),
    height: "9007199254740993",
    sequence: "9007199254740995",
    txHash: "CCDD"
  }));
  assert.equal(precise.height, "9007199254740993");
  assert.equal(precise.sequence, "9007199254740995");
  assert.equal(precise.noteId, "9007199254740993:9007199254740995:CCDD");
});

test("reservation manager requires private index key unless explicitly unsafe", () => {
  assert.throws(
    () => createNoteReservationManager({
      ownerKeyId: "chain:clair1owner",
      indexKey: "index-key-v1"
    }),
    /reservation store is required/
  );
  assert.throws(
    () => createNoteReservationManager({
      store: new MemoryReservationStore(),
      ownerKeyId: "chain:clair1owner"
    }),
    /indexKey is required/
  );
  assert.throws(
    () => createNoteReservationManager({
      store: new MemoryReservationStore(),
      ownerKeyId: "chain:clair1owner",
      unsafeAllowPublicIndexKey: "false"
    }),
    /unsafeAllowPublicIndexKey must be a boolean/
  );

  const unsafe = createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "chain:clair1owner",
    unsafeAllowPublicIndexKey: true
  });
  assert.equal(unsafe.ownerKeyId, "chain:clair1owner");
});

test("reservation stores expose raw replacement only through explicit unsafe APIs", () => {
  const store = new MemoryReservationStore();
  assert.equal("save" in store, false);
  assert.equal("updateReservation" in store, false);
  assert.equal(typeof store.unsafeReplaceState, "function");
  assert.equal(typeof store.unsafeReplaceReservation, "function");
});

test("reservation state fails closed on unsupported versions and statuses", async () => {
  assert.throws(
    () => new MemoryReservationStore({ state: { version: 2, reservations: [] } }),
    /unsupported reservation state version/
  );
  assert.throws(
    () => new MemoryReservationStore({
      state: {
        version: 1,
        reservations: [{
          reservation_id: "future-reservation",
          owner_key_id: "owner-a",
          nullifier_lookup_key: "lookup-a",
          status: "FutureProofReady"
        }]
      }
    }),
    /unsupported reservation status/
  );

  const active = {
    reservation_id: "state-reservation-a",
    owner_key_id: "owner-a",
    nullifier_lookup_key: "lookup-a",
    status: reservationStatuses.Reserved
  };
  assert.throws(
    () => new MemoryReservationStore({
      state: { version: 1, reservations: [active, { ...active }] }
    }),
    /duplicate reservation_id/
  );
  assert.throws(
    () => new MemoryReservationStore({
      state: {
        version: 1,
        reservations: [active, { ...active, reservation_id: "state-reservation-b" }]
      }
    }),
    /duplicate active reservation/
  );
  assert.throws(
    () => new MemoryReservationStore({
      state: {
        version: 1,
        reservations: [active, {
          ...active,
          reservation_id: "state-reservation-spent",
          status: reservationStatuses.ConfirmedSpent
        }]
      }
    }),
    /confirmed spent reservation conflicts/
  );

  const store = new MemoryReservationStore();
  await assert.rejects(
    () => store.unsafeReplaceState({ version: 99, reservations: [] }),
    /unsupported reservation state version/
  );
  assert.deepEqual(await store.load(), { version: 1, reservations: [] });
});

test("browser IndexedDB reservation storage requires encryption or an explicit demo opt-in", () => {
  const indexedDB = {
    open() {
      return {};
    }
  };
  const locks = {
    async request(_name, _options, callback) {
      return callback();
    }
  };
  assert.throws(
    () => new IndexedDbReservationStore({ indexedDB, locks }),
    /requires at-rest state encryption callbacks/
  );
  assert.throws(
    () => new IndexedDbReservationStore({
      indexedDB,
      locks,
      unsafeAllowPlaintext: "false"
    }),
    /unsafeAllowPlaintext must be a boolean/
  );
});

test("IndexedDB reservation codecs reject nullish decoded and encoded state", async () => {
  const persisted = { ciphertext: "existing-reservations" };
  const decodeHarness = indexedDbHarness(persisted);
  const decodeStore = new IndexedDbReservationStore({
    indexedDB: {},
    locks: null,
    requireLocks: false,
    encodeState: state => state,
    decodeState: () => null
  });
  decodeStore.dbPromise = Promise.resolve(decodeHarness.db);
  await assert.rejects(
    () => decodeStore.load(),
    /decoder returned an invalid state/
  );
  assert.deepEqual(decodeHarness.storedValue, persisted);

  const encodeHarness = indexedDbHarness(undefined);
  const encodeStore = new IndexedDbReservationStore({
    indexedDB: {},
    locks: null,
    requireLocks: false,
    encodeState: () => undefined,
    decodeState: value => value
  });
  encodeStore.dbPromise = Promise.resolve(encodeHarness.db);
  await assert.rejects(
    () => encodeStore.unsafeReplaceState({ version: 1, reservations: [] }),
    /encoder returned an invalid value/
  );
  assert.equal(encodeHarness.storedValue, undefined);
});

test("browser reservation storage fails closed when IndexedDB is unavailable", () => {
  assert.throws(
    () => createBrowserReservationStore({ indexedDB: null }),
    /IndexedDB is unavailable/
  );
  assert.ok(
    createBrowserReservationStore({
      indexedDB: null,
      unsafeAllowMemoryFallback: true
    }) instanceof MemoryReservationStore
  );
  assert.throws(
    () => createBrowserReservationStore({
      indexedDB: null,
      unsafeAllowMemoryFallback: "false"
    }),
    /unsafeAllowMemoryFallback must be a boolean/
  );
});

test("empty reservation batches keep the public ReservationBatch shape", async () => {
  const manager = createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1",
    leaseOwner: "test-wallet"
  });

  assert.deepEqual(await manager.reserveNotes({
    notes: [],
    operationId: "empty-op"
  }), {
    operation_id: "empty-op",
    lease_owner: "test-wallet",
    lease_token: "",
    lease_until: "",
    reservation_ids: [],
    reservations: []
  });
});

test("reservation heartbeat interval follows the active lease window", () => {
  assert.equal(reservationHeartbeatIntervalMs({ leaseDurationMs: 30 }), 10);
  assert.equal(reservationHeartbeatIntervalMs({ leaseDurationMs: 90 }), 30);
  assert.equal(reservationHeartbeatIntervalMs({ leaseDurationMs: 1000 }), 333);
  assert.equal(reservationHeartbeatIntervalMs({ leaseDurationMs: 90_000 }), 30_000);
  assert.equal(reservationHeartbeatIntervalMs({ leaseDurationMs: 15 * 60_000 }), 60_000);
  assert.equal(reservationHeartbeatIntervalMs({
    leaseDurationMs: 15 * 60_000,
    leaseUntil: "2026-01-02T03:04:06.000Z",
    now: "2026-01-02T03:04:05.100Z"
  }), 300);
  assert.equal(reservationHeartbeatIntervalMs({
    leaseDurationMs: 15 * 60_000,
    leaseUntil: "2026-01-02T03:04:05.090Z",
    now: "2026-01-02T03:04:05.000Z"
  }), 30);
});

test("indexeddb reservation store requires web locks unless explicitly scoped to single-tab", async () => {
  const indexedDB = {
    open() {
      throw new Error("unexpected IndexedDB open");
    }
  };
  assert.throws(
    () => new IndexedDbReservationStore({ indexedDB }),
    /Web Locks API is required/
  );

  const calls = [];
  const locks = {
    async request(name, options, callback) {
      calls.push({ name, options });
      return callback();
    }
  };
  const store = new IndexedDbReservationStore({
    dbName: "db",
    namespace: "wallet",
    indexedDB,
    locks,
    unsafeAllowPlaintext: true
  });
  assert.equal(store.lockName, "clairveil-reservations:db:wallet");
  assert.equal(await store.withMutationLock(() => "ok"), "ok");
  assert.deepEqual(calls, [
    {
      name: "clairveil-reservations:db:wallet",
      options: { mode: "exclusive" }
    }
  ]);

  const singleTabStore = new IndexedDbReservationStore({
    indexedDB,
    locks: null,
    requireLocks: false,
    unsafeAllowPlaintext: true
  });
  assert.equal(singleTabStore.requireLocks, false);

  const mutationOrder = [];
  let releaseFirstMutation;
  const waitForFirstMutation = new Promise(resolve => {
    releaseFirstMutation = resolve;
  });
  const firstMutation = singleTabStore.withMutationLock(async () => {
    mutationOrder.push("first:start");
    await waitForFirstMutation;
    mutationOrder.push("first:end");
  });
  await Promise.resolve();
  const secondMutation = singleTabStore.withMutationLock(async () => {
    mutationOrder.push("second:start");
    mutationOrder.push("second:end");
  });
  await Promise.resolve();
  assert.deepEqual(mutationOrder, ["first:start"]);
  releaseFirstMutation();
  await Promise.all([firstMutation, secondMutation]);
  assert.deepEqual(mutationOrder, ["first:start", "first:end", "second:start", "second:end"]);
});

test("memory reservation manager blocks active duplicate note reservations", async () => {
  const now = () => new Date("2026-01-02T03:04:05.000Z");
  const manager = createNoteReservationManager({
    store: new MemoryReservationStore({ now }),
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1",
    now
  });
  const first = noteFixture();
  const second = noteFixture({
    nullifier: "22".repeat(32),
    amount: 9,
    sequence: 2
  });

  const batch = await preparePlanReservation(manager, {
    plan: { selection: { inputs: [first] } },
    kind: "transfer"
  });

  assert.equal(batch.reservation_ids.length, 1);
  assert.match(batch.lease_token, /^[0-9a-f]{32}$/);
  assert.equal(batch.reservations[0].status, reservationStatuses.Proving);
  assert.equal(batch.reservations[0].lease_token, batch.lease_token);
  assert.equal((await manager.reservationForNote(first)).status, reservationStatuses.Proving);
  await assert.rejects(
    () => manager.markProofReady(batch.reservation_ids),
    /lease token is required/
  );
  await assert.rejects(
    () => manager.markProofReady(batch.reservation_ids, { leaseToken: "wrong" }),
    /lease token mismatch/
  );
  await assert.rejects(
    () => preparePlanReservation(manager, {
      plan: { selection: { inputs: [first] } },
      kind: "transfer"
    }),
    /active reservation already exists/
  );

  assert.deepEqual(await manager.filterAvailableNotes([first, second]), [second]);

  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    payloadHash: "payload-hash",
    expectedOutputCommitment: "commitment"
  });
  const proofReady = await manager.reservationForNote(first);
  assert.equal(proofReady.status, reservationStatuses.ProofReady);
  assert.equal(proofReady.payload_hash, "payload-hash");
  assert.equal(proofReady.expected_output_commitment, "commitment");

  await assert.rejects(
    () => manager.markUnknown(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      error: "user rejected before broadcast"
    }),
    /markUnknown requires broadcast attempt metadata/
  );
  await assert.rejects(
    () => manager.markSubmitted(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      signDocHash: "sign-doc-before-broadcast"
    }),
    /markSubmitted requires submitted tx hash or tx bytes hash/
  );
  await assert.rejects(
    () => manager.markUnknown(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      signDocHash: "sign-doc-hash",
      error: "broadcast result could not be found"
    }),
    /markUnknown requires broadcast attempt metadata/
  );
  await markUnknownAfterAttempt(manager, batch, {
    leaseToken: batch.lease_token,
    txBytesHash: "tx-bytes-hash",
    signDocHash: "supplemental-sign-doc-hash",
    error: "broadcast result could not be found"
  });
  const unknown = await manager.reservationForNote(first);
  assert.equal(unknown.status, reservationStatuses.Unknown);
  assert.equal(unknown.tx_bytes_hash, "tx-bytes-hash");
  assert.equal(unknown.sign_doc_hash, "supplemental-sign-doc-hash");
});

test("reservation metadata rejects values outside its JSON persistence contract", async () => {
  const manager = createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "2a".repeat(32), sequence: 21 });

  await assert.rejects(
    () => manager.reserveNotes({ notes: [note], metadata: { requestedAmount: 5n } }),
    /metadata must contain only JSON values/
  );
  const cyclic = {};
  cyclic.self = cyclic;
  await assert.rejects(
    () => manager.reserveNotes({ notes: [note], metadata: cyclic }),
    /metadata must not contain cycles/
  );
  assert.deepEqual(await manager.listActiveReservations(), []);
});

test("operation-success evidence policy flags require literal booleans", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: noteFixture({ nullifier: "2b".repeat(32), sequence: 22 }) },
    kind: "payment"
  });

  await assert.rejects(
    () => manager.markProofReady(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      operationSuccessEvidenceRequired: "true"
    }),
    /operationSuccessEvidenceRequired metadata must be a boolean/
  );
  const unchanged = await manager.getReservation(batch.reservation_ids[0]);
  assert.equal(unchanged.status, reservationStatuses.Proving);

  const invalidState = await store.load();
  invalidState.reservations[0].metadata.operation_success_evidence_required = "true";
  assert.throws(
    () => new MemoryReservationStore({ state: invalidState }),
    /operation_success_evidence_required metadata must be a boolean/
  );
});

test("reservation transitions reject application-supplied lifecycle metadata", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: noteFixture({ nullifier: "2c".repeat(32), sequence: 23 }) },
    kind: "payment"
  });

  for (const metadata of [
    { relay_handed_off: false },
    { relayHandedOff: true },
    { operation_status: operationStatuses.Succeeded },
    { operationStatus: operationStatuses.Succeeded }
  ]) {
    await assert.rejects(
      () => manager.markProofReady(batch.reservation_ids, {
        leaseToken: batch.lease_token,
        metadata
      }),
      /lifecycle metadata|operation_status metadata/
    );
  }
  assert.equal(
    (await store.getReservation(batch.reservation_ids[0])).status,
    reservationStatuses.Proving
  );
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token
  });
});

test("public reservation transitions cannot bypass broadcast evidence validation", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "6f".repeat(32), sequence: 79 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "withdraw"
  });
  await manager.markProofReady(batch.reservation_ids, { leaseToken: batch.lease_token });

  await assert.rejects(
    () => manager.transitionBatch(
      batch.reservation_ids,
      reservationStatuses.ProofReady,
      reservationStatuses.Submitted,
      { lease_token: batch.lease_token }
    ),
    /ProofReady -> Submitted requires submitted tx hash or tx bytes hash/
  );
  await assert.rejects(
    () => store.compareAndSetReservationStatusBatch([{
      reservationID: batch.reservation_ids[0],
      from: reservationStatuses.ProofReady,
      to: reservationStatuses.Unknown,
      patch: { lease_token: batch.lease_token }
    }]),
    /durable broadcast attempt is required/
  );
  await assert.rejects(
    () => manager.markSubmitted(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      txHash: "TX-WITHOUT-DURABLE-ATTEMPT"
    }),
    /durable broadcast attempt is required/
  );
  assert.equal((await manager.reservationForNote(note)).status, reservationStatuses.ProofReady);
});

test("a failed asynchronous receipt accepts an equivalent normalized tx identity", async () => {
  const manager = createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "chain:clair1receipt",
    indexKey: "receipt-index-key",
  });
  const note = noteFixture({ nullifier: "7f".repeat(32), sequence: 80 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "withdraw",
  });
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
  });
  await markSubmittedAfterAttempt(manager, batch, {
    leaseToken: batch.lease_token,
    txHash: "0xAbCd",
  });

  await manager.markUnknown(batch.reservation_ids, {
    fromStatus: reservationStatuses.Submitted,
    txHash: "abcd",
    error: "receipt status 0x0",
  });

  const reservation = await manager.getReservation(batch.reservation_ids[0]);
  assert.equal(reservation.status, reservationStatuses.Unknown);
  assert.equal(reservation.submitted_tx_hash, "0xAbCd");
});

test("ConfirmedSpent is restricted to spent-note reconciliation", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "70".repeat(32), sequence: 80 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "withdraw"
  });
  await manager.markProofReady(batch.reservation_ids, { leaseToken: batch.lease_token });

  await assert.rejects(
    () => manager.transitionBatch(
      batch.reservation_ids,
      reservationStatuses.ProofReady,
      reservationStatuses.ConfirmedSpent,
      { lease_token: batch.lease_token }
    ),
    /ConfirmedSpent transitions require reconcileSpentNotes chain spent evidence/
  );
  await assert.rejects(
    () => store.compareAndSetReservationStatusBatch([{
      reservationID: batch.reservation_ids[0],
      from: reservationStatuses.ProofReady,
      to: reservationStatuses.ConfirmedSpent,
      patch: { lease_token: batch.lease_token }
    }]),
    /ConfirmedSpent transitions require reconcileSpentNotes chain spent evidence/
  );

  const reconciled = await manager.reconcileSpentNotes([{
    ...note,
    isSpent: true,
    spent: true,
    nullifierStatus: "spent"
  }]);
  assert.equal(reconciled.length, 1);
  assert.equal(
    (await store.getReservation(batch.reservation_ids[0])).status,
    reservationStatuses.ConfirmedSpent
  );
});

test("spent reconciliation accepts only a literal boolean true", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "73".repeat(32), sequence: 83 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "withdraw"
  });
  await manager.markProofReady(batch.reservation_ids, { leaseToken: batch.lease_token });

  const reconciled = await manager.reconcileSpentNotes([{
    ...note,
    isSpent: "false",
    spent: "false",
    nullifierStatus: "unspent"
  }]);

  assert.deepEqual(reconciled, []);
  assert.equal(
    (await store.getReservation(batch.reservation_ids[0])).status,
    reservationStatuses.ProofReady
  );
  const record = await store.getReservation(batch.reservation_ids[0]);
  await assert.rejects(
    () => store.reconcileSpentByLookupKey(
      record.owner_key_id,
      record.nullifier_lookup_key,
      { ...note, isSpent: false }
    ),
    /literal spent evidence/
  );
  assert.equal(
    (await store.getReservation(batch.reservation_ids[0])).status,
    reservationStatuses.ProofReady
  );
});

test("replan evidence accepts only literal boolean true", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "74".repeat(32), sequence: 84 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "withdraw"
  });
  await manager.markProofReady(batch.reservation_ids, { leaseToken: batch.lease_token });
  await markSubmittedAfterAttempt(manager, batch, {
    leaseToken: batch.lease_token,
    txHash: "TX-74"
  });

  await assert.rejects(
    () => manager.markReplanRequired(batch.reservation_ids, {
      fromStatus: reservationStatuses.Submitted,
      nullifierUnspentConfirmed: "true",
      txAbsentOrFailedConfirmed: 1,
      checkedHeight: 84,
      txHashChecked: "TX-74"
    }),
    /nullifier unspent evidence must be a boolean/
  );
  await assert.rejects(
    () => manager.markReplanRequired(batch.reservation_ids, {
      fromStatus: reservationStatuses.Submitted,
      nullifierUnspentConfirmed: true,
      txAbsentOrFailedConfirmed: true,
      checkedHeight: 84,
      txHashChecked: "TX-74",
      metadata: {
        nullifier_unspent_confirmed: false
      }
    }),
    /nullifier unspent evidence aliases conflict/
  );
  assert.equal(
    (await store.getReservation(batch.reservation_ids[0])).status,
    reservationStatuses.Submitted
  );
});

test("ConfirmedSpent quarantines matching inactive siblings and prevents note reuse", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "71".repeat(32), sequence: 81 });
  const first = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "withdraw"
  });
  await manager.markProofReady(first.reservation_ids, { leaseToken: first.lease_token });
  await manager.markReplanRequired(first.reservation_ids, {
    fromStatus: reservationStatuses.ProofReady,
    leaseToken: first.lease_token,
    metadata: {
      no_broadcast_attempt: true,
      proof_discarded: true
    }
  });

  // A stale ReplanRequired record used to be ignored, allowing a new active
  // reservation for the same note. Chain spent evidence must quarantine both.
  const second = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "withdraw"
  });
  const reconciled = await manager.reconcileSpentNotes([{ ...note, isSpent: true }]);
  assert.equal(reconciled.length, 2);
  for (const reservationID of [...first.reservation_ids, ...second.reservation_ids]) {
    assert.equal(
      (await store.getReservation(reservationID)).status,
      reservationStatuses.ConfirmedSpent
    );
  }
  assert.equal(
    (await manager.reservationForNote(note)).status,
    reservationStatuses.ConfirmedSpent
  );
  assert.deepEqual(await manager.filterAvailableNotes([note]), []);
  await assert.rejects(
    () => preparePlanReservation(manager, {
      plan: { selectedNote: note },
      kind: "withdraw"
    }),
    /confirmed spent reservation prevents note reuse/
  );
});

test("spent reconciliation atomically quarantines a concurrent matching reservation", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "72".repeat(32), sequence: 82 });
  const stale = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "withdraw"
  });
  await manager.markProofReady(stale.reservation_ids, { leaseToken: stale.lease_token });
  await manager.markReplanRequired(stale.reservation_ids, {
    fromStatus: reservationStatuses.ProofReady,
    leaseToken: stale.lease_token,
    proofDiscarded: true,
    metadata: { no_broadcast_attempt: true }
  });

  await Promise.allSettled([
    manager.reconcileSpentNotes([{ ...note, isSpent: true }]),
    manager.reservePlan({ plan: { selectedNote: note }, kind: "withdraw" })
  ]);

  const records = await store.findReservationsByLookupKey(
    manager.ownerKeyId,
    await manager.lookupKeyForNote(note)
  );
  assert.ok(records.some(record => record.status === reservationStatuses.ConfirmedSpent));
  const activeStatuses = new Set([
    reservationStatuses.Reserved,
    reservationStatuses.Proving,
    reservationStatuses.ProofReady,
    reservationStatuses.Submitted,
    reservationStatuses.Unknown
  ]);
  assert.ok(!records.some(record => activeStatuses.has(record.status)));
});

test("a live ProofReady lease blocks other workers from replan or manual review", async () => {
  let currentTime = new Date("2026-01-02T03:04:05.000Z");
  const now = () => currentTime;
  const store = new MemoryReservationStore({ now });
  const owner = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1",
    leaseOwner: "worker-one",
    leaseDurationMs: 1000,
    now
  });
  const otherWorker = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1",
    leaseOwner: "worker-two",
    leaseDurationMs: 1000,
    now
  });
  const note = noteFixture({ nullifier: "71".repeat(32), sequence: 81 });
  const batch = await preparePlanReservation(owner, {
    plan: { selectedNote: note },
    kind: "relay_withdraw"
  });
  await owner.markProofReady(batch.reservation_ids, { leaseToken: batch.lease_token });

  await assert.rejects(
    () => otherWorker.markReplanRequired(batch.reservation_ids, {
      error: "other tab attempted recovery"
    }),
    /lease token is required for reservation transition: ProofReady -> ReplanRequired/
  );
  await assert.rejects(
    () => otherWorker.markManualReview(batch.reservation_ids, {
      error: "other tab attempted recovery"
    }),
    /lease token is required for reservation transition: ProofReady -> ManualReview/
  );
  assert.equal((await otherWorker.reservationForNote(note)).status, reservationStatuses.ProofReady);

  currentTime = new Date("2026-01-02T03:04:06.001Z");
  await otherWorker.markManualReview(batch.reservation_ids, {
    error: "expired lease recovery"
  });
  const recovered = await store.getReservation(batch.reservation_ids[0]);
  assert.equal(recovered.status, reservationStatuses.ManualReview);
  assert.equal(recovered.lease_token, "");
});

test("a live Proving lease blocks other workers until expiry, even with its token", async () => {
  let currentTime = new Date("2026-01-02T03:04:05.000Z");
  const now = () => currentTime;
  const store = new MemoryReservationStore({ now });
  const owner = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1",
    leaseOwner: "worker-one",
    leaseDurationMs: 1000,
    now
  });
  const otherWorker = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1",
    leaseOwner: "worker-two",
    leaseDurationMs: 1000,
    now
  });
  const note = noteFixture({ nullifier: "72".repeat(32), sequence: 82 });
  const batch = await preparePlanReservation(owner, {
    plan: { selectedNote: note },
    kind: "transfer"
  });

  await assert.rejects(
    () => otherWorker.markManualReview(batch.reservation_ids, {
      error: "other tab attempted cleanup"
    }),
    /lease token is required for reservation transition: Proving -> ManualReview/
  );
  await assert.rejects(
    () => otherWorker.markReplanRequired(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      error: "other tab has the token but not the lease owner"
    }),
    /reservation lease owner mismatch/
  );
  assert.equal((await store.getReservation(batch.reservation_ids[0])).status, reservationStatuses.Proving);

  currentTime = new Date("2026-01-02T03:04:06.001Z");
  await otherWorker.markManualReview(batch.reservation_ids, {
    error: "expired proving recovery"
  });
  const recovered = await store.getReservation(batch.reservation_ids[0]);
  assert.equal(recovered.status, reservationStatuses.ManualReview);
  assert.equal(recovered.lease_token, "");
});

test("prepare rolls back a reserved batch when proving cannot start", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const first = noteFixture({ nullifier: "67".repeat(32), sequence: 67 });
  const second = noteFixture({ nullifier: "68".repeat(32), sequence: 68 });
  manager.markProving = async () => {
    throw new Error("proving worker failed to start");
  };

  await assert.rejects(
    () => preparePlanReservation(manager, {
      plan: { selection: { inputs: [first, second] } },
      kind: "transfer"
    }),
    /proving worker failed to start/
  );

  const reservations = await store.listReservations({ ownerKeyId: "chain:clair1owner" });
  assert.equal(reservations.length, 2);
  assert.deepEqual(
    reservations.map(reservation => reservation.status),
    [reservationStatuses.Released, reservationStatuses.Released]
  );
  assert.ok(reservations.every(reservation => !reservation.lease_token && !reservation.lease_until));
});

test("rollback atomically releases a Proving operation without an intermediate Reserved state", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const batch = await preparePlanReservation(manager, {
    plan: {
      selection: {
        inputs: [
          noteFixture({ nullifier: "69".repeat(32), sequence: 69 }),
          noteFixture({ nullifier: "6a".repeat(32), sequence: 70 })
        ]
      }
    },
    kind: "transfer"
  });
  const releaseReservationBatch = store.releaseReservationBatch.bind(store);
  const compareAndSetReservationStatusBatch = store.compareAndSetReservationStatusBatch.bind(store);
  let releaseCalls = 0;
  let compareAndSetCalls = 0;
  store.compareAndSetReservationStatusBatch = async transitions => {
    compareAndSetCalls += 1;
    return compareAndSetReservationStatusBatch(transitions);
  };
  store.releaseReservationBatch = async options => {
    releaseCalls += 1;
    assert.deepEqual(options.reservationIDs, batch.reservation_ids);
    for (const reservationID of options.reservationIDs) {
      assert.equal(
        (await store.getReservation(reservationID)).status,
        reservationStatuses.Proving
      );
    }
    return releaseReservationBatch(options);
  };

  await manager.releaseReservedOrProving(batch.reservation_ids, {
    leaseToken: batch.lease_token
  });

  assert.equal(releaseCalls, 1);
  assert.equal(compareAndSetCalls, 0);
  store.releaseReservationBatch = releaseReservationBatch;
  store.compareAndSetReservationStatusBatch = compareAndSetReservationStatusBatch;

  const reservations = await store.listReservations({ ownerKeyId: "chain:clair1owner" });
  assert.deepEqual(
    reservations.map(reservation => reservation.status),
    [reservationStatuses.Released, reservationStatuses.Released]
  );
  assert.ok(reservations.every(reservation => !reservation.lease_token && !reservation.lease_until));
});

test("same-status CAS cannot erase broadcast evidence", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "6c".repeat(32), sequence: 72 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "withdraw"
  });
  await manager.markProofReady(batch.reservation_ids, { leaseToken: batch.lease_token });
  await markSubmittedAfterAttempt(manager, batch, {
    leaseToken: batch.lease_token,
    txHash: "TX-WRITE-ONCE"
  });

  await assert.rejects(
    () => store.compareAndSetReservationStatusBatch([{
      reservationID: batch.reservation_ids[0],
      from: reservationStatuses.Submitted,
      to: reservationStatuses.Submitted,
      patch: {
        submitted_tx_hash: "",
        broadcast_attempt_count: 0,
        metadata: {}
      }
    }]),
    /same-status reservation mutations are limited to lease renewal fields/
  );
  const stored = await store.getReservation(batch.reservation_ids[0]);
  assert.equal(stored.submitted_tx_hash, "TX-WRITE-ONCE");
  assert.equal(stored.broadcast_attempt_count, 1);
});

test("durable broadcast attempt is atomic and blocks retry until reconciliation", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const batch = await preparePlanReservation(manager, {
    plan: {
      selection: {
        inputs: [
          noteFixture({ nullifier: "6e".repeat(32), sequence: 74 }),
          noteFixture({ nullifier: "6f".repeat(32), sequence: 75 })
        ]
      }
    },
    kind: "transfer"
  });
  await manager.markProofReady(batch.reservation_ids, { leaseToken: batch.lease_token });

  const attempting = await manager.markBroadcastAttempting(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    reason: "test_broadcast"
  });
  assert.equal(attempting.length, 2);
  assert.ok(attempting.every(record => record.broadcast_in_flight === true));
  assert.ok(attempting.every(record => record.broadcast_attempt_count === 1));
  assert.ok(attempting.every(record => record.metadata.no_broadcast_attempt === false));

  await assert.rejects(
    () => manager.markBroadcastAttempting(batch.reservation_ids, {
      leaseToken: batch.lease_token
    }),
    /broadcast attempt already started; reconcile before retry/
  );

  const reconciled = await manager.markUnknown(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    txBytesHash: "ab".repeat(32),
    error: "RPC response unavailable"
  });
  assert.ok(reconciled.every(record => record.status === reservationStatuses.Unknown));
  assert.ok(reconciled.every(record => record.broadcast_in_flight === false));
});

test("operation outcome metadata can only be set by managed reconciliation", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "8d".repeat(32), sequence: 141 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "withdraw"
  });

  await assert.rejects(
    () => manager.markProofReady(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      metadata: { operation_status: "Succeeded" }
    }),
    /operation_status metadata may only be set by operation reconciliation/
  );
  assert.equal((await store.getReservation(batch.reservation_ids[0])).status, reservationStatuses.Proving);

  await manager.markProofReady(batch.reservation_ids, { leaseToken: batch.lease_token });
  await assert.rejects(
    () => manager.markBroadcastAttempting(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      metadata: { operation_status: "Succeeded" }
    }),
    /operation_status metadata may only be set by operation reconciliation/
  );
  const ready = await store.getReservation(batch.reservation_ids[0]);
  assert.equal(ready.status, reservationStatuses.ProofReady);
  assert.equal(ready.broadcast_attempt_count, 0);
  assert.equal(ready.metadata.operation_status, undefined);
});

test("proof discard accepts local prepared hashes and manual review resolution needs an operator", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const proofNote = noteFixture({ nullifier: "6d".repeat(32), sequence: 73 });
  const proofBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: proofNote },
    kind: "withdraw"
  });
  await manager.transitionBatch(
    proofBatch.reservation_ids,
    reservationStatuses.Proving,
    reservationStatuses.ProofReady,
    { lease_token: proofBatch.lease_token, sign_doc_hash: "SIGN-DOC-EVIDENCE" }
  );
  const replannedSignDoc = await manager.markReplanRequired(proofBatch.reservation_ids, {
    leaseToken: proofBatch.lease_token,
    metadata: { no_broadcast_attempt: true, proof_discarded: true }
  });
  assert.equal(replannedSignDoc[0].status, reservationStatuses.ReplanRequired);

  const txBytesNote = noteFixture({ nullifier: "6f".repeat(32), sequence: 75 });
  const txBytesBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: txBytesNote },
    kind: "transfer"
  });
  await manager.markProofReady(txBytesBatch.reservation_ids, {
    leaseToken: txBytesBatch.lease_token,
    txBytesHash: "TX-BYTES-TEMPLATE-EVIDENCE"
  });
  const replannedTxBytes = await manager.markReplanRequired(txBytesBatch.reservation_ids, {
    leaseToken: txBytesBatch.lease_token,
    metadata: { no_broadcast_attempt: true, proof_discarded: true }
  });
  assert.equal(replannedTxBytes[0].status, reservationStatuses.ReplanRequired);

  const reviewNote = noteFixture({ nullifier: "6e".repeat(32), sequence: 74 });
  const reviewBatch = await manager.reserveNotes({ notes: [reviewNote] });
  await manager.transitionBatch(
    reviewBatch.reservation_ids,
    reservationStatuses.Reserved,
    reservationStatuses.ManualReview
  );
  await assert.rejects(
    () => store.compareAndSetReservationStatusBatch([{
      reservationID: reviewBatch.reservation_ids[0],
      from: reservationStatuses.ManualReview,
      to: reservationStatuses.Released,
      patch: {
        metadata: {
          operator_approved: true,
          operator_approval_reference: "missing-operator"
        }
      }
    }]),
    /operator approval evidence/
  );
});

test("reservation identity and persisted batch index are immutable", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "6b".repeat(32), sequence: 71 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "transfer"
  });

  await assert.rejects(
    () => manager.transitionBatch(
      batch.reservation_ids,
      reservationStatuses.Proving,
      reservationStatuses.ProofReady,
      {
        lease_token: batch.lease_token,
        nullifier_lookup_key: "mutated-lookup-key"
      }
    ),
    /identity field cannot be changed/
  );
  assert.equal((await manager.reservationForNote(note)).status, reservationStatuses.Proving);

  const state = await store.load();
  state.reservations[0].batch_item_index = "garbage";
  state.reservations[0].batch_item_index_known = true;
  assert.throws(
    () => new MemoryReservationStore({ state }),
    /batch_item_index must be a non-negative safe integer when known/
  );
});

test("persisted reservation safety fields reject malformed values and conflicting aliases", async () => {
  const baseState = {
    version: 1,
    reservations: [{
      reservation_id: "reservation-persisted-validation",
      owner_key_id: "chain:clair1owner",
      nullifier_lookup_key: "lookup-key",
      status: reservationStatuses.ProofReady,
      batch_item_index: 0,
      batch_item_index_known: true,
      broadcast_attempt_count: 0
    }]
  };
  const withRecord = patch => ({
    ...baseState,
    reservations: [{ ...baseState.reservations[0], ...patch }]
  });

  for (const value of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(
      () => new MemoryReservationStore({
        state: withRecord({ broadcast_attempt_count: value })
      }),
      /broadcast_attempt_count must be a non-negative safe integer/
    );
  }
  assert.throws(
    () => new MemoryReservationStore({
      state: withRecord({
        broadcast_attempt_count: 0,
        broadcastAttemptCount: 1
      })
    }),
    /broadcast_attempt_count aliases conflict/
  );
  assert.throws(
    () => new MemoryReservationStore({
      state: withRecord({ batch_item_index_known: "true" })
    }),
    /batch_item_index_known must be a boolean/
  );
  assert.throws(
    () => new MemoryReservationStore({
      state: withRecord({
        batch_item_index_known: true,
        batchItemIndexKnown: false
      })
    }),
    /batch_item_index_known aliases conflict/
  );
  assert.throws(
    () => new MemoryReservationStore({
      state: withRecord({ broadcast_in_flight: "true" })
    }),
    /broadcast_in_flight must be a boolean/
  );
  assert.throws(
    () => new MemoryReservationStore({
      state: withRecord({
        broadcast_in_flight: true,
        broadcastInFlight: false
      })
    }),
    /broadcast_in_flight aliases conflict/
  );
  for (const value of [[], " "]) {
    assert.throws(
      () => new MemoryReservationStore({
        state: withRecord({
          batch_item_index: value,
          batch_item_index_known: true
        })
      }),
      /batch_item_index must be a non-negative safe integer when known/
    );
  }
});

test("lease renew and heartbeat extend active reservations", async () => {
  let currentTime = new Date("2026-01-02T03:04:05.000Z");
  const now = () => currentTime;
  const manager = createNoteReservationManager({
    store: new MemoryReservationStore({ now }),
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1",
    leaseDurationMs: 1000,
    now
  });
  const note = noteFixture({ nullifier: "55".repeat(32) });
  const batch = await preparePlanReservation(manager, {
    plan: { selection: { inputs: [note] } },
    kind: "transfer"
  });

  currentTime = new Date("2026-01-02T03:04:05.500Z");
  const renewed = await manager.renewLease(batch.reservation_ids, {
    leaseToken: batch.lease_token
  });
  assert.equal(renewed[0].lease_until, "2026-01-02T03:04:06.500Z");
  assert.equal(renewed[0].last_heartbeat_at, "2026-01-02T03:04:05.500Z");

  currentTime = new Date("2026-01-02T03:04:06.000Z");
  const heartbeat = await manager.heartbeatLease(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    leaseDurationMs: 2000
  });
  assert.equal(heartbeat[0].lease_until, "2026-01-02T03:04:08.000Z");

  const extended = await manager.renewLease(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    leaseUntil: "2026-01-04T03:04:08.000Z"
  });
  currentTime = new Date("2026-01-02T03:04:06.500Z");
  const preserved = await manager.renewLease(batch.reservation_ids, {
    leaseToken: batch.lease_token
  });
  assert.equal(extended[0].lease_until, "2026-01-04T03:04:08.000Z");
  assert.equal(preserved[0].lease_until, "2026-01-04T03:04:08.000Z");

  await assert.rejects(
    () => manager.renewLease(batch.reservation_ids, { leaseToken: "wrong" }),
    /lease token mismatch/
  );

  currentTime = new Date("2026-01-04T03:04:08.001Z");
  await assert.rejects(
    () => manager.markProofReady(batch.reservation_ids, {
      leaseToken: batch.lease_token
    }),
    /lease expired/
  );
});

test("lease renewal updates an entire reservation batch atomically", async () => {
  let currentTime = new Date("2026-01-02T03:04:05.000Z");
  const now = () => currentTime;
  class BatchOnlyStore extends MemoryReservationStore {
    failNextBatch = false;

    async compareAndSetReservationStatus() {
      throw new Error("renewLease must use the batch compare-and-set path");
    }

    async compareAndSetReservationStatusBatch(transitions) {
      if (this.failNextBatch) {
        this.failNextBatch = false;
        throw new Error("simulated atomic batch failure");
      }
      return super.compareAndSetReservationStatusBatch(transitions);
    }
  }
  const store = new BatchOnlyStore({ now });
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1",
    leaseDurationMs: 1000,
    now
  });
  const batch = await preparePlanReservation(manager, {
    plan: {
      selection: {
        inputs: [
          noteFixture({ nullifier: "56".repeat(32), sequence: 51 }),
          noteFixture({ nullifier: "57".repeat(32), sequence: 52 })
        ]
      }
    },
    kind: "transfer"
  });
  const before = await Promise.all(batch.reservation_ids.map(id => store.getReservation(id)));

  currentTime = new Date("2026-01-02T03:04:05.500Z");
  store.failNextBatch = true;
  await assert.rejects(
    () => manager.renewLease(batch.reservation_ids, { leaseToken: batch.lease_token }),
    /simulated atomic batch failure/
  );
  const afterFailedRenewal = await Promise.all(batch.reservation_ids.map(id => store.getReservation(id)));
  assert.deepEqual(
    afterFailedRenewal.map(reservation => reservation.lease_until),
    before.map(reservation => reservation.lease_until)
  );

  const renewed = await manager.renewLease(batch.reservation_ids, {
    leaseToken: batch.lease_token
  });
  assert.equal(renewed.length, 2);
  assert.deepEqual(
    renewed.map(reservation => reservation.lease_until),
    ["2026-01-02T03:04:06.500Z", "2026-01-02T03:04:06.500Z"]
  );
});

test("store CAS validates lease tokens and expiry inside the mutation", async () => {
  let currentTime = new Date("2026-01-02T03:04:05.000Z");
  const now = () => currentTime;
  const store = new MemoryReservationStore({ now });
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1",
    leaseDurationMs: 1000,
    now
  });
  const direct = await manager.reserveNotes({
    notes: [noteFixture({ nullifier: "5c".repeat(32), sequence: 13 })],
    kind: "transfer"
  });
  await assert.rejects(
    () => store.compareAndSetReservationStatus(
      direct.reservation_ids[0],
      reservationStatuses.Reserved,
      reservationStatuses.Proving
    ),
    /future lease owner, token, and expiry/
  );
  await assert.rejects(
    () => store.compareAndSetReservationStatus(
      direct.reservation_ids[0],
      reservationStatuses.Reserved,
      reservationStatuses.Proving,
      {
        lease_owner: direct.lease_owner,
        lease_token: "forged-lease-token",
        lease_until: direct.lease_until
      }
    ),
    /reservation claim token mismatch/
  );
  await store.compareAndSetReservationStatus(
    direct.reservation_ids[0],
    reservationStatuses.Reserved,
    reservationStatuses.Proving,
    {
      lease_owner: direct.lease_owner,
      lease_token: direct.lease_token,
      lease_until: direct.lease_until,
    }
  );
  await assert.rejects(
    () => store.compareAndSetReservationStatus(
      direct.reservation_ids[0],
      reservationStatuses.Proving,
      reservationStatuses.ProofReady,
      {
        lease_owner: "other-worker",
        lease_token: direct.lease_token,
      }
    ),
    /reservation lease owner mismatch/
  );

  const expired = await manager.reserveNotes({
    notes: [noteFixture({ nullifier: "5d".repeat(32), sequence: 14 })],
    kind: "transfer"
  });
  currentTime = new Date("2026-01-02T03:04:06.001Z");
  await assert.rejects(
    () => store.compareAndSetReservationStatus(
      expired.reservation_ids[0],
      reservationStatuses.Reserved,
      reservationStatuses.Proving,
      {
        lease_owner: expired.lease_owner,
        lease_token: expired.lease_token,
        lease_until: expired.lease_until,
      }
    ),
    /lease expired/
  );
});

test("store CAS enforces replan, failure, and ManualReview evidence without a manager", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });

  const proofReadyNote = noteFixture({ nullifier: "5e".repeat(32), sequence: 15 });
  const proofReadyBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: proofReadyNote },
    kind: "withdraw"
  });
  await manager.markProofReady(proofReadyBatch.reservation_ids, {
    leaseToken: proofReadyBatch.lease_token
  });
  const proofReady = await store.getReservation(proofReadyBatch.reservation_ids[0]);
  await assert.rejects(
    () => store.compareAndSetReservationStatus(
      proofReady.reservation_id,
      reservationStatuses.ProofReady,
      reservationStatuses.ReplanRequired,
      {
        lease_owner: proofReady.lease_owner,
        lease_token: proofReady.lease_token
      }
    ),
    /ProofReady -> ReplanRequired requires/
  );

  const submittedNote = noteFixture({ nullifier: "5f".repeat(32), sequence: 16 });
  const submittedBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: submittedNote },
    kind: "withdraw"
  });
  await manager.markProofReady(submittedBatch.reservation_ids, {
    leaseToken: submittedBatch.lease_token
  });
  await markSubmittedAfterAttempt(manager, submittedBatch, {
    leaseToken: submittedBatch.lease_token,
    txHash: "TX-FAILED"
  });
  await assert.rejects(
    () => store.compareAndSetReservationStatus(
      submittedBatch.reservation_ids[0],
      reservationStatuses.Submitted,
      reservationStatuses.Failed
    ),
    /requires nullifier_unspent_confirmed/
  );

  const reviewNote = noteFixture({ nullifier: "60".repeat(32), sequence: 17 });
  const reviewBatch = await manager.reserveNotes({ notes: [reviewNote] });
  await manager.markManualReview(reviewBatch.reservation_ids, {
    error: "operator review required"
  });
  await assert.rejects(
    () => store.compareAndSetReservationStatus(
      reviewBatch.reservation_ids[0],
      reservationStatuses.ManualReview,
      reservationStatuses.Released
    ),
    /operator approval evidence/
  );
});

test("store CAS cannot rewrite a ProofReady operation success predicate", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "6a".repeat(32), sequence: 18 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "payment"
  });
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    expectedOutputCommitment: "OUTPUT",
    expectedDisclosureDigest: "AUDIT",
    expectedRecipientHash: "RECIPIENT",
    expectedAmount: "9",
    expectedAmountHash: "AMOUNT",
    expectedDenom: "uclair",
    batchItemIndex: 0,
    batchItemIndexKnown: true,
    operationSuccessEvidenceRequired: true
  });
  await manager.markBroadcastAttempting(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    txHash: "TX-PREDICATE"
  });
  const record = await store.getReservation(batch.reservation_ids[0]);
  const mutations = [
    { expected_output_commitment: "FORGED" },
    { expected_disclosure_digest: "FORGED" },
    { expected_recipient_hash: "FORGED" },
    { expected_amount: "10" },
    { expected_amount_hash: "FORGED" },
    { expected_denom: "uforged" },
    { batch_item_index: 1 },
    { batch_item_index_known: false },
    { metadata: { ...record.metadata, operation_success_evidence_required: false } }
  ];
  for (const mutation of mutations) {
    await assert.rejects(
      () => store.compareAndSetReservationStatus(
        record.reservation_id,
        reservationStatuses.ProofReady,
        reservationStatuses.Submitted,
        {
          lease_owner: record.lease_owner,
          lease_token: record.lease_token,
          submitted_tx_hash: "TX-PREDICATE",
          ...mutation
        }
      ),
      /not allowed|write-once/
    );
  }
  const unchanged = await store.getReservation(record.reservation_id);
  assert.equal(unchanged.expected_output_commitment, "OUTPUT");
  assert.equal(unchanged.expected_recipient_hash, "RECIPIENT");
  assert.equal(unchanged.metadata.operation_success_evidence_required, true);

  const migratedState = await store.load();
  const migratedRecord = migratedState.reservations.find(candidate =>
    candidate.reservation_id === record.reservation_id
  );
  migratedRecord.metadata.operationSuccessEvidenceRequired = true;
  delete migratedRecord.metadata.operation_success_evidence_required;
  const migratedStore = new MemoryReservationStore({ state: migratedState });
  const canonical = await migratedStore.getReservation(record.reservation_id);
  assert.equal(canonical.metadata.operation_success_evidence_required, true);
  assert.equal(canonical.metadata.operationSuccessEvidenceRequired, undefined);
  await assert.rejects(
    () => migratedStore.compareAndSetReservationStatus(
      canonical.reservation_id,
      reservationStatuses.ProofReady,
      reservationStatuses.Submitted,
      {
        lease_owner: canonical.lease_owner,
        lease_token: canonical.lease_token,
        submitted_tx_hash: "TX-PREDICATE",
        metadata: {
          ...canonical.metadata,
          operationSuccessEvidenceRequired: false
        }
      }
    ),
    /aliases conflict|write-once/
  );
});

test("reservation creation rejects reuse of a historical operation id", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const first = await manager.reserveNotes({
    notes: [noteFixture({ nullifier: "6b".repeat(32), sequence: 19 })],
    operationId: "operation-reused"
  });
  await manager.releaseReservedOrProving(first.reservation_ids, {
    leaseToken: first.lease_token
  });
  await assert.rejects(
    () => manager.reserveNotes({
      notes: [noteFixture({ nullifier: "6c".repeat(32), sequence: 20 })],
      operationId: "operation-reused"
    }),
    /operation_id has already been used/
  );
  const reservations = await store.listReservations();
  assert.equal(reservations.length, 1);
  assert.equal(reservations[0].status, reservationStatuses.Released);
});

test("expired proof-ready leases reject submitted or unknown evidence", async () => {
  let currentTime = new Date("2026-01-02T03:04:05.000Z");
  const now = () => currentTime;
  const manager = createNoteReservationManager({
    store: new MemoryReservationStore({ now }),
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1",
    leaseDurationMs: 1000,
    now
  });
  const submittedNote = noteFixture({ nullifier: "5a".repeat(32), sequence: 11 });
  const submittedBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: submittedNote },
    kind: "withdraw"
  });
  await manager.markProofReady(submittedBatch.reservation_ids, {
    leaseToken: submittedBatch.lease_token
  });

  currentTime = new Date("2026-01-02T03:04:06.001Z");
  await assert.rejects(
    () => manager.markSubmitted(submittedBatch.reservation_ids, {
      leaseToken: "wrong",
      txHash: "TX-LATE"
    }),
    /lease token mismatch/
  );
  await assert.rejects(
    () => manager.markSubmitted(submittedBatch.reservation_ids, {
      leaseToken: submittedBatch.lease_token,
      signDocHash: "late-sign-doc-only"
    }),
    /markSubmitted requires submitted tx hash or tx bytes hash/
  );
  await assert.rejects(
    () => manager.markSubmitted(submittedBatch.reservation_ids, {
      leaseToken: submittedBatch.lease_token,
      submitted_tx_hash: "TX-LATE"
    }),
    /lease expired/
  );
  const submitted = await manager.reservationForNote(submittedNote);
  assert.equal(submitted.status, reservationStatuses.ProofReady);
  assert.equal(submitted.submitted_tx_hash, "");

  currentTime = new Date("2026-01-02T03:04:07.000Z");
  const unknownNote = noteFixture({ nullifier: "5b".repeat(32), sequence: 12 });
  const unknownBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: unknownNote },
    kind: "withdraw"
  });
  await manager.markProofReady(unknownBatch.reservation_ids, {
    leaseToken: unknownBatch.lease_token
  });
  currentTime = new Date("2026-01-02T03:04:08.001Z");
  await assert.rejects(
    () => manager.markUnknown(unknownBatch.reservation_ids, {
      leaseToken: unknownBatch.lease_token,
      submitted_tx_hash: "TX-LATE-UNKNOWN",
      signDocHash: "late-sign-doc",
      error: "broadcast submitted but tx query timed out"
    }),
    /lease expired/
  );
  const unknown = await manager.reservationForNote(unknownNote);
  assert.equal(unknown.status, reservationStatuses.ProofReady);
  assert.equal(unknown.submitted_tx_hash, "");
  assert.equal(unknown.sign_doc_hash, "");
  await assert.rejects(
    () => manager.markReplanRequired(unknownBatch.reservation_ids, {
      leaseToken: unknownBatch.lease_token,
      error: "expired worker attempted to discard proof",
      metadata: {
        no_broadcast_attempt: true,
        proof_discarded: true
      }
    }),
    /lease expired/
  );

  const expiredRelayNote = noteFixture({ nullifier: "5c".repeat(32), sequence: 13 });
  const expiredRelayBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: expiredRelayNote },
    kind: "relay_withdraw"
  });
  await manager.markProofReady(expiredRelayBatch.reservation_ids, {
    leaseToken: expiredRelayBatch.lease_token
  });
  currentTime = new Date("2026-01-02T03:04:10.000Z");
  await assert.rejects(
    () => manager.markReplanRequired(expiredRelayBatch.reservation_ids, {
      leaseToken: expiredRelayBatch.lease_token,
      authoritativeExpiryConfirmed: true,
      metadata: {
        relay_payload_expired: true,
        nullifier_unspent_confirmed: true,
        checked_height: 123
      }
    }),
    /lease expired/
  );
  const reviewed = await manager.markManualReview(expiredRelayBatch.reservation_ids, {
    error: "relay payload expired after worker lease",
    metadata: {
      relay_payload_expired: true,
      authoritative_expiry_confirmed: true,
      nullifier_unspent_confirmed: true,
      checked_height: 123
    }
  });
  assert.equal(reviewed[0].status, reservationStatuses.ManualReview);
});

test("store rejects partial operation rollback before mutating any record", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const first = noteFixture({ nullifier: "66".repeat(32), sequence: 1 });
  const second = noteFixture({ nullifier: "77".repeat(32), sequence: 2 });
  const batch = await preparePlanReservation(manager, {
    plan: { selection: { inputs: [first, second] } },
    kind: "transfer"
  });

  await assert.rejects(
    () => store.compareAndSetReservationStatus(
      batch.reservation_ids[1],
      reservationStatuses.Proving,
      reservationStatuses.Reserved,
      {
        lease_owner: manager.leaseOwner,
        lease_token: batch.lease_token
      }
    ),
    /exact linked reservation set/
  );

  assert.equal(
    (await store.getReservation(batch.reservation_ids[0])).status,
    reservationStatuses.Proving
  );
  assert.equal(
    (await store.getReservation(batch.reservation_ids[1])).status,
    reservationStatuses.Proving
  );
});

test("reservation rollback releases proving notes and spent reconciliation clears active locks", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const rollbackNote = noteFixture({ nullifier: "33".repeat(32) });
  const spentNote = noteFixture({ nullifier: "44".repeat(32), sequence: 2 });

  const rollbackBatch = await preparePlanReservation(manager, {
    plan: { selection: { inputs: [rollbackNote] } },
    kind: "transfer"
  });
  await assert.rejects(
    () => manager.releaseReservedOrProving(rollbackBatch.reservation_ids),
    /lease token is required/
  );
  await assert.rejects(
    () => manager.releaseReservedOrProving(rollbackBatch.reservation_ids, {
      leaseToken: "wrong"
    }),
    /reservation lease token mismatch/
  );
  assert.equal(
    (await store.getReservation(rollbackBatch.reservation_ids[0])).status,
    reservationStatuses.Proving
  );
  await rollbackPlanReservation(manager, rollbackBatch);
  assert.equal(await manager.reservationForNote(rollbackNote), null);

  const reservedNote = noteFixture({ nullifier: "34".repeat(32), sequence: 3 });
  const reservedBatch = await manager.reserveNotes({
    notes: [reservedNote],
    kind: "transfer"
  });
  assert.equal((await store.getReservation(reservedBatch.reservation_ids[0])).lease_token, "");
  await manager.releaseReservedOrProving(reservedBatch.reservation_ids);
  assert.equal(await manager.reservationForNote(reservedNote), null);

  const spentBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: spentNote },
    kind: "withdraw"
  });
  await manager.markProofReady(spentBatch.reservation_ids, {
    leaseToken: spentBatch.lease_token
  });
  await assert.rejects(
    () => manager.markSubmitted(spentBatch.reservation_ids, { txHash: "TX123" }),
    /lease token is required/
  );
  await assert.rejects(
    () => manager.markSubmitted(spentBatch.reservation_ids, {
      leaseToken: spentBatch.lease_token
    }),
    /markSubmitted requires submitted tx hash or tx bytes hash/
  );
  await markSubmittedAfterAttempt(manager, spentBatch, {
    leaseToken: spentBatch.lease_token,
    txHash: "TX123"
  });
  await assert.rejects(
    () => manager.markReplanRequired(spentBatch.reservation_ids, {
      fromStatus: reservationStatuses.Submitted,
      error: "receipt failed but nullifier was not checked"
    }),
    /Submitted -> ReplanRequired requires nullifier_unspent_confirmed/
  );
  assert.equal(
    (await manager.reservationForNote(spentNote)).status,
    reservationStatuses.Submitted
  );
  await assert.rejects(
    () => manager.markReplanRequired(spentBatch.reservation_ids, {
      fromStatus: reservationStatuses.Submitted,
      nullifierUnspentConfirmed: true,
      error: "nullifier is unspent but tx outcome was not checked"
    }),
    /tx_absent_or_failed_confirmed/
  );
  await manager.markReplanRequired(spentBatch.reservation_ids, {
    fromStatus: reservationStatuses.Submitted,
    txHash: "",
    error: "receipt failed and nullifier is unspent",
    nullifierUnspentConfirmed: true,
    txAbsentOrFailedConfirmed: true,
    checkedHeight: 12345,
    txHashChecked: "TX123"
  });
  const replanRecord = await store.getReservation(spentBatch.reservation_ids[0]);
  assert.equal(replanRecord.submitted_tx_hash, "TX123");
  assert.equal(replanRecord.status, reservationStatuses.ReplanRequired);
  assert.equal(replanRecord.submitted_tx_hash, "TX123");
  assert.equal(replanRecord.last_broadcast_error, "receipt failed and nullifier is unspent");
  assert.equal(replanRecord.metadata.nullifier_unspent_confirmed, true);
  assert.equal(replanRecord.metadata.tx_absent_or_failed_confirmed, true);
  assert.equal(replanRecord.metadata.checked_height, 12345);
  assert.equal(replanRecord.metadata.tx_hash_checked, "TX123");

  const resubmittedBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: spentNote },
    kind: "withdraw"
  });
  await manager.markProofReady(resubmittedBatch.reservation_ids, {
    leaseToken: resubmittedBatch.lease_token
  });
  await markSubmittedAfterAttempt(manager, resubmittedBatch, {
    leaseToken: resubmittedBatch.lease_token,
    txHash: "TX456"
  });
  await manager.reconcileSpentNotes([{ ...spentNote, isSpent: true }]);

  assert.equal(
    (await manager.reservationForNote(spentNote)).status,
    reservationStatuses.ConfirmedSpent
  );
  const spentRecord = (await store.listReservations({ ownerKeyId: "chain:clair1owner" }))
    .find(record => record.reservation_id === resubmittedBatch.reservation_ids[0]);
  assert.equal(spentRecord.status, reservationStatuses.ConfirmedSpent);
  assert.equal(spentRecord.submitted_tx_hash, "TX456");
});

test("spent reconciliation records operation success evidence matches and conflicts", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const matchingNote = noteFixture({ nullifier: "8a".repeat(32), sequence: 81 });
  const matchingBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: matchingNote },
    kind: "transfer"
  });
  await manager.markProofReady(matchingBatch.reservation_ids, {
    leaseToken: matchingBatch.lease_token,
    expectedOutputCommitment: "OUT-COMMITMENT",
    expectedDisclosureDigest: "AUDIT-DIGEST",
    expectedRecipientHash: "RECIPIENT-HASH",
    expectedAmountHash: "AMOUNT-HASH",
    expectedAmount: "100",
    expectedDenom: "uclair",
    batchItemIndex: 0,
    batchItemIndexKnown: true,
    operationSuccessEvidenceRequired: true
  });
  const proofReady = await store.getReservation(matchingBatch.reservation_ids[0]);
  assert.equal(proofReady.expected_recipient_hash, "RECIPIENT-HASH");
  assert.equal(proofReady.expected_amount, "100");
  assert.equal(proofReady.expected_amount_hash, "AMOUNT-HASH");
  assert.equal(proofReady.expected_denom, "uclair");
  assert.equal(proofReady.batch_item_index, 0);
  assert.equal(proofReady.batch_item_index_known, true);
  await markSubmittedAfterAttempt(manager, matchingBatch, {
    leaseToken: matchingBatch.lease_token,
    txHash: "TX-MATCH"
  });
  await manager.reconcileSpentNotes([{
    ...matchingNote,
    isSpent: true,
    operationSuccessEvidence: {
      txHash: "tx-match",
      outputCommitment: "out-commitment",
      auditDisclosureDigest: "audit-digest",
      recipientHash: "recipient-hash",
      amount: "100",
      amountHash: "amount-hash",
      denom: "uclair",
      batchItemIndex: 0
    }
  }]);
  const matchedRecord = await store.getReservation(matchingBatch.reservation_ids[0]);
  assert.equal(matchedRecord.status, reservationStatuses.ConfirmedSpent);
  assert.equal(matchedRecord.metadata.operation_status, operationStatuses.Succeeded);
  assert.equal(matchedRecord.metadata.operation_success_evidence_matches, true);
  assert.deepEqual(matchedRecord.metadata.operation_success_evidence_errors, []);
  assert.deepEqual(
    await manager.reconcileSpentNotes([{ ...matchingNote, isSpent: true }]),
    []
  );
  assert.deepEqual(await store.getReservation(matchingBatch.reservation_ids[0]), matchedRecord);

  const conflictNote = noteFixture({ nullifier: "8b".repeat(32), sequence: 82 });
  const conflictBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: conflictNote },
    kind: "transfer"
  });
  await manager.markProofReady(conflictBatch.reservation_ids, {
    leaseToken: conflictBatch.lease_token,
    expectedOutputCommitment: "EXPECTED-OUTPUT",
    expectedDisclosureDigest: "EXPECTED-DIGEST",
    expectedRecipientHash: "EXPECTED-RECIPIENT",
    expectedAmount: "100",
    expectedAmountHash: "EXPECTED-AMOUNT",
    expectedDenom: "uclair",
    batchItemIndex: 1,
    batchItemIndexKnown: true,
    operationSuccessEvidenceRequired: true
  });
  await markSubmittedAfterAttempt(manager, conflictBatch, {
    leaseToken: conflictBatch.lease_token,
    txHash: "TX-CONFLICT"
  });
  await manager.reconcileSpentNotes([{
    ...conflictNote,
    isSpent: true,
    operationSuccessEvidence: {
      txHash: "TX-CONFLICT",
      outputCommitment: "expected-output",
      auditDisclosureDigest: "expected-digest",
      recipientHash: "OTHER-RECIPIENT",
      amount: "101",
      amountHash: "EXPECTED-AMOUNT",
      denom: "uatom",
      batchItemIndex: 2
    }
  }]);
  const conflictRecord = await store.getReservation(conflictBatch.reservation_ids[0]);
  assert.equal(conflictRecord.status, reservationStatuses.ConfirmedSpent);
  assert.equal(conflictRecord.metadata.operation_status, operationStatuses.ConflictSpent);
  assert.equal(conflictRecord.metadata.operation_success_evidence_matches, false);
  assert.deepEqual(conflictRecord.metadata.operation_success_evidence_errors, [
    "expected_recipient_hash mismatch",
    "expected_amount mismatch",
    "expected_denom mismatch",
    "batch_item_index mismatch"
  ]);

  const missingTxNote = noteFixture({ nullifier: "8c".repeat(32), sequence: 83 });
  const missingTxBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: missingTxNote },
    kind: "transfer"
  });
  await manager.markProofReady(missingTxBatch.reservation_ids, {
    leaseToken: missingTxBatch.lease_token,
    expectedOutputCommitment: "OUTPUT",
    expectedDisclosureDigest: "AUDIT",
    expectedRecipientHash: "RECIPIENT",
    expectedAmount: "9",
    expectedAmountHash: "AMOUNT-HASH",
    expectedDenom: "uclair",
    batchItemIndex: 0,
    batchItemIndexKnown: true,
    operationSuccessEvidenceRequired: true
  });
  await markSubmittedAfterAttempt(manager, missingTxBatch, {
    leaseToken: missingTxBatch.lease_token,
    txHash: "TX-MISSING-EVIDENCE"
  });
  await manager.reconcileSpentNotes([{
    ...missingTxNote,
    isSpent: true,
    operationSuccessEvidence: {
      outputCommitment: "output",
      auditDisclosureDigest: "audit",
      recipientHash: "recipient",
      amount: "9",
      amountHash: "amount-hash",
      denom: "uclair",
      batchItemIndex: 0
    }
  }]);
  const missingTxRecord = await store.getReservation(missingTxBatch.reservation_ids[0]);
  assert.equal(missingTxRecord.status, reservationStatuses.ConfirmedSpent);
  assert.equal(missingTxRecord.metadata.operation_status, operationStatuses.ConflictSpent);
  assert.equal(missingTxRecord.metadata.operation_success_evidence_matches, false);
  assert.deepEqual(missingTxRecord.metadata.operation_success_evidence_errors, [
    "tx_hash_or_tx_result identity missing"
  ]);
});

test("operation success reconciliation requires a matching persisted tx identity", async () => {
  const makeManager = () => createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const proofReady = async (manager, note, identity = {}) => {
    const batch = await preparePlanReservation(manager, {
      plan: { selectedNote: note },
      kind: "transfer"
    });
    await manager.markProofReady(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      expectedOutputCommitment: "OUT",
      expectedDisclosureDigest: "DIGEST",
      expectedRecipientHash: "RECIPIENT",
      expectedAmount: "100",
      expectedAmountHash: "AMOUNT",
      expectedDenom: "uclair",
      batchItemIndexKnown: false,
      operationSuccessEvidenceRequired: true
    });
    await markSubmittedAfterAttempt(manager, batch, {
      leaseToken: batch.lease_token,
      txHash: "EXPECTED-TX",
      ...identity
    });
    return batch;
  };
  const evidence = {
    outputCommitment: "OUT",
    disclosureDigest: "DIGEST",
    recipientHash: "RECIPIENT",
    amount: "100",
    amountHash: "AMOUNT",
    denom: "uclair"
  };

  const emptyResultManager = makeManager();
  const emptyResultNote = noteFixture({ nullifier: "9a".repeat(32), sequence: 90 });
  const emptyResultBatch = await proofReady(emptyResultManager, emptyResultNote);
  await emptyResultManager.reconcileSpentNotes([{
    ...emptyResultNote,
    isSpent: true,
    operationSuccessEvidence: { txResult: { code: 0 }, ...evidence }
  }]);
  const emptyResult = await emptyResultManager.getReservation(emptyResultBatch.reservation_ids[0]);
  assert.equal(emptyResult.metadata.operation_status, operationStatuses.ConflictSpent);
  assert.deepEqual(emptyResult.metadata.operation_success_evidence_errors, [
    "tx_hash_or_tx_result identity missing"
  ]);

  const wrongTxManager = makeManager();
  const wrongTxNote = noteFixture({ nullifier: "9b".repeat(32), sequence: 91 });
  const wrongTxBatch = await proofReady(wrongTxManager, wrongTxNote);
  await wrongTxManager.reconcileSpentNotes([{
    ...wrongTxNote,
    isSpent: true,
    operationSuccessEvidence: { txHash: "OTHER-TX", ...evidence }
  }]);
  const wrongTx = await wrongTxManager.getReservation(wrongTxBatch.reservation_ids[0]);
  assert.equal(wrongTx.metadata.operation_status, operationStatuses.ConflictSpent);
  assert.deepEqual(wrongTx.metadata.operation_success_evidence_errors, [
    "tx_hash_or_tx_bytes mismatch"
  ]);

  const swappedTxHashManager = makeManager();
  const swappedTxHashNote = noteFixture({ nullifier: "9d".repeat(32), sequence: 93 });
  const swappedTxHashBatch = await proofReady(swappedTxHashManager, swappedTxHashNote, {
    txBytesHash: "EXPECTED-BYTES"
  });
  await swappedTxHashManager.reconcileSpentNotes([{
    ...swappedTxHashNote,
    isSpent: true,
    operationSuccessEvidence: { txHash: "EXPECTED-BYTES", ...evidence }
  }]);
  const swappedTxHash = await swappedTxHashManager.getReservation(
    swappedTxHashBatch.reservation_ids[0]
  );
  assert.equal(swappedTxHash.metadata.operation_status, operationStatuses.ConflictSpent);
  assert.deepEqual(swappedTxHash.metadata.operation_success_evidence_errors, [
    "tx_hash_or_tx_bytes mismatch"
  ]);

  const conflictingIdentityManager = makeManager();
  const conflictingIdentityNote = noteFixture({ nullifier: "8d".repeat(32), sequence: 193 });
  const conflictingIdentityBatch = await proofReady(
    conflictingIdentityManager,
    conflictingIdentityNote,
    { txHash: null, txBytesHash: "EXPECTED-BYTES" }
  );
  await conflictingIdentityManager.reconcileSpentNotes([{
    ...conflictingIdentityNote,
    isSpent: true,
    operationSuccessEvidence: {
      txHash: "OTHER-TX",
      txBytesHash: "EXPECTED-BYTES",
      ...evidence
    }
  }]);
  const conflictingIdentity = await conflictingIdentityManager.getReservation(
    conflictingIdentityBatch.reservation_ids[0]
  );
  assert.equal(
    conflictingIdentity.metadata.operation_status,
    operationStatuses.ConflictSpent
  );
  assert.deepEqual(conflictingIdentity.metadata.operation_success_evidence_errors, [
    "tx_hash_or_tx_bytes mismatch"
  ]);

  const contradictorySourceManager = makeManager();
  const contradictorySourceNote = noteFixture({ nullifier: "7d".repeat(32), sequence: 195 });
  const contradictorySourceBatch = await proofReady(
    contradictorySourceManager,
    contradictorySourceNote
  );
  await contradictorySourceManager.reconcileSpentNotes([{
    ...contradictorySourceNote,
    isSpent: true,
    operationSuccessEvidence: {
      txHash: "EXPECTED-TX",
      txResult: { code: 0, txhash: "OTHER-TX" },
      ...evidence
    }
  }]);
  const contradictorySource = await contradictorySourceManager.getReservation(
    contradictorySourceBatch.reservation_ids[0]
  );
  assert.equal(
    contradictorySource.metadata.operation_status,
    operationStatuses.ConflictSpent
  );
  assert.ok(
    contradictorySource.metadata.operation_success_evidence_errors.includes(
      "tx_hash evidence conflict"
    )
  );

  const normalizedIdentityManager = makeManager();
  const normalizedIdentityNote = noteFixture({ nullifier: "8e".repeat(32), sequence: 194 });
  const normalizedIdentityBatch = await proofReady(
    normalizedIdentityManager,
    normalizedIdentityNote,
    { txHash: "0xABCDEF" }
  );
  await normalizedIdentityManager.reconcileSpentNotes([{
    ...normalizedIdentityNote,
    isSpent: true,
    operationSuccessEvidence: { txHash: "abcdef", ...evidence }
  }]);
  const normalizedIdentity = await normalizedIdentityManager.getReservation(
    normalizedIdentityBatch.reservation_ids[0]
  );
  assert.equal(normalizedIdentity.metadata.operation_status, operationStatuses.Succeeded);

  const signDocOnlyManager = makeManager();
  const signDocOnlyNote = noteFixture({ nullifier: "9f".repeat(32), sequence: 94 });
  const signDocOnlyBatch = await proofReady(signDocOnlyManager, signDocOnlyNote, {
    signDocHash: "EXPECTED-SIGN-DOC"
  });
  await signDocOnlyManager.reconcileSpentNotes([{
    ...signDocOnlyNote,
    isSpent: true,
    operationSuccessEvidence: { signDocHash: "EXPECTED-SIGN-DOC", ...evidence }
  }]);
  const signDocOnly = await signDocOnlyManager.getReservation(signDocOnlyBatch.reservation_ids[0]);
  assert.equal(signDocOnly.metadata.operation_status, operationStatuses.ConflictSpent);
  assert.deepEqual(signDocOnly.metadata.operation_success_evidence_errors, [
    "matching persisted tx identity missing"
  ]);

  const matchingManager = makeManager();
  const matchingNote = noteFixture({ nullifier: "9c".repeat(32), sequence: 92 });
  const matchingBatch = await proofReady(matchingManager, matchingNote);
  await matchingManager.reconcileSpentNotes([{
    ...matchingNote,
    isSpent: true,
    operationSuccessEvidence: { txHash: "expected-tx", ...evidence }
  }]);
  const matching = await matchingManager.getReservation(matchingBatch.reservation_ids[0]);
  assert.equal(matching.metadata.operation_status, operationStatuses.Succeeded);
  assert.deepEqual(matching.metadata.operation_success_evidence_errors, []);

  const nestedCosmosManager = makeManager();
  const nestedCosmosNote = noteFixture({ nullifier: "6d".repeat(32), sequence: 196 });
  const nestedCosmosBatch = await proofReady(nestedCosmosManager, nestedCosmosNote);
  await nestedCosmosManager.reconcileSpentNotes([{
    ...nestedCosmosNote,
    isSpent: true,
    operationSuccessEvidence: {
      txResult: { tx_response: { code: 0, txhash: "EXPECTED-TX" } },
      ...evidence
    }
  }]);
  const nestedCosmos = await nestedCosmosManager.getReservation(
    nestedCosmosBatch.reservation_ids[0]
  );
  assert.equal(nestedCosmos.metadata.operation_status, operationStatuses.Succeeded);

  const nestedEvmManager = makeManager();
  const nestedEvmNote = noteFixture({ nullifier: "6e".repeat(32), sequence: 197 });
  const nestedEvmBatch = await proofReady(nestedEvmManager, nestedEvmNote);
  await nestedEvmManager.reconcileSpentNotes([{
    ...nestedEvmNote,
    isSpent: true,
    operationSuccessEvidence: {
      txResult: {
        receipt: {
          transactionHash: "EXPECTED-TX",
          status: "0x1"
        }
      },
      ...evidence
    }
  }]);
  const nestedEvm = await nestedEvmManager.getReservation(
    nestedEvmBatch.reservation_ids[0]
  );
  assert.equal(nestedEvm.metadata.operation_status, operationStatuses.Succeeded);

  const mismatchedSignDocManager = makeManager();
  const mismatchedSignDocNote = noteFixture({ nullifier: "9e".repeat(32), sequence: 94 });
  const mismatchedSignDocBatch = await proofReady(
    mismatchedSignDocManager,
    mismatchedSignDocNote,
    { txBytesHash: "EXPECTED-BYTES", signDocHash: "EXPECTED-SIGN-DOC" }
  );
  await mismatchedSignDocManager.reconcileSpentNotes([{
    ...mismatchedSignDocNote,
    isSpent: true,
    operationSuccessEvidence: {
      txBytesHash: "EXPECTED-BYTES",
      signDocHash: "OTHER-SIGN-DOC",
      ...evidence
    }
  }]);
  const mismatchedSignDoc = await mismatchedSignDocManager.getReservation(
    mismatchedSignDocBatch.reservation_ids[0]
  );
  assert.equal(mismatchedSignDoc.metadata.operation_status, operationStatuses.ConflictSpent);
  assert.deepEqual(mismatchedSignDoc.metadata.operation_success_evidence_errors, [
    "sign_doc_hash mismatch"
  ]);
});

test("operation evidence rejects malformed batch indices and ignores extra sign-doc hashes", async () => {
  const manager = createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const malformedNote = noteFixture({ nullifier: "9f".repeat(32), sequence: 95 });
  const malformedBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: malformedNote },
    kind: "payment"
  });
  await manager.markProofReady(malformedBatch.reservation_ids, {
    leaseToken: malformedBatch.lease_token,
    expectedOutputCommitment: "OUT",
    expectedDisclosureDigest: "DIGEST",
    expectedRecipientHash: "RECIPIENT",
    expectedAmount: "1",
    expectedAmountHash: "AMOUNT",
    expectedDenom: "uclair",
    batchItemIndex: 0,
    batchItemIndexKnown: true,
    operationSuccessEvidenceRequired: true
  });
  await markSubmittedAfterAttempt(manager, malformedBatch, {
    leaseToken: malformedBatch.lease_token,
    txHash: "EXPECTED-TX"
  });
  await manager.reconcileSpentNotes([{
    ...malformedNote,
    isSpent: true,
    operationSuccessEvidence: {
      txHash: "EXPECTED-TX",
      outputCommitment: "OUT",
      disclosureDigest: "DIGEST",
      recipientHash: "RECIPIENT",
      amount: "1",
      amountHash: "AMOUNT",
      denom: "uclair",
      batchItemIndex: "bogus"
    }
  }]);
  const malformed = await manager.getReservation(malformedBatch.reservation_ids[0]);
  assert.equal(malformed.metadata.operation_status, operationStatuses.ConflictSpent);
  assert.deepEqual(malformed.metadata.operation_success_evidence_errors, [
    "batch_item_index invalid"
  ]);

  const missingIndexNote = noteFixture({ nullifier: "bf".repeat(32), sequence: 196 });
  const missingIndexBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: missingIndexNote },
    kind: "payment"
  });
  await assert.rejects(
    manager.markProofReady(missingIndexBatch.reservation_ids, {
      leaseToken: missingIndexBatch.lease_token,
      batchItemIndexKnown: true
    }),
    /batch item index/
  );
  await assert.rejects(
    manager.markProofReady(missingIndexBatch.reservation_ids, {
      leaseToken: missingIndexBatch.lease_token,
      batchItemIndex: [],
      batchItemIndexKnown: true
    }),
    /batch item index/
  );
  await manager.markProofReady(missingIndexBatch.reservation_ids, {
    leaseToken: missingIndexBatch.lease_token,
    expectedOutputCommitment: "OUT",
    expectedDisclosureDigest: "DIGEST",
    expectedRecipientHash: "RECIPIENT",
    expectedAmount: "1",
    expectedAmountHash: "AMOUNT",
    expectedDenom: "uclair",
    batchItemIndex: 0,
    batchItemIndexKnown: true,
    operationSuccessEvidenceRequired: true
  });
  await markSubmittedAfterAttempt(manager, missingIndexBatch, {
    leaseToken: missingIndexBatch.lease_token,
    txHash: "EXPECTED-MISSING-INDEX-TX"
  });
  await manager.reconcileSpentNotes([{
    ...missingIndexNote,
    isSpent: true,
    operationSuccessEvidence: {
      txHash: "EXPECTED-MISSING-INDEX-TX",
      outputCommitment: "OUT",
      disclosureDigest: "DIGEST",
      recipientHash: "RECIPIENT",
      amount: "1",
      amountHash: "AMOUNT",
      denom: "uclair",
      batchItemIndexKnown: true
    }
  }]);
  const missingIndex = await manager.getReservation(missingIndexBatch.reservation_ids[0]);
  assert.equal(missingIndex.metadata.operation_status, operationStatuses.ConflictSpent);
  assert.deepEqual(missingIndex.metadata.operation_success_evidence_errors, [
    "batch_item_index missing"
  ]);

  const directNote = noteFixture({ nullifier: "af".repeat(32), sequence: 96 });
  const directBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: directNote },
    kind: "payment"
  });
  await manager.markProofReady(directBatch.reservation_ids, {
    leaseToken: directBatch.lease_token,
    expectedOutputCommitment: "OUT",
    expectedDisclosureDigest: "DIGEST",
    expectedRecipientHash: "RECIPIENT",
    expectedAmount: "1",
    expectedAmountHash: "AMOUNT",
    expectedDenom: "uclair",
    batchItemIndexKnown: false,
    operationSuccessEvidenceRequired: true
  });
  await markSubmittedAfterAttempt(manager, directBatch, {
    leaseToken: directBatch.lease_token,
    txHash: "EXPECTED-DIRECT-TX"
  });
  await manager.reconcileSpentNotes([{
    ...directNote,
    isSpent: true,
    operationSuccessEvidence: {
      txHash: "EXPECTED-DIRECT-TX",
      signDocHash: "extra-sign-doc-evidence",
      outputCommitment: "OUT",
      disclosureDigest: "DIGEST",
      recipientHash: "RECIPIENT",
      amount: "1",
      amountHash: "AMOUNT",
      denom: "uclair"
    }
  }]);
  const direct = await manager.getReservation(directBatch.reservation_ids[0]);
  assert.equal(direct.metadata.operation_status, operationStatuses.Succeeded);
});

test("submitted and unknown transitions clear worker lease fields", async () => {
  const manager = createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const submittedNote = noteFixture({ nullifier: "ba".repeat(32), sequence: 97 });
  const submittedBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: submittedNote },
    kind: "withdraw"
  });
  await manager.markProofReady(submittedBatch.reservation_ids, {
    leaseToken: submittedBatch.lease_token
  });
  await markSubmittedAfterAttempt(manager, submittedBatch, {
    leaseToken: submittedBatch.lease_token,
    txHash: "TX-SUBMITTED"
  });
  const submitted = await manager.getReservation(submittedBatch.reservation_ids[0]);
  assert.equal(submitted.lease_token, "");
  assert.equal(submitted.lease_until, "");

  const unknownNote = noteFixture({ nullifier: "bb".repeat(32), sequence: 98 });
  const unknownBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: unknownNote },
    kind: "withdraw"
  });
  await manager.markProofReady(unknownBatch.reservation_ids, {
    leaseToken: unknownBatch.lease_token
  });
  await markUnknownAfterAttempt(manager, unknownBatch, {
    leaseToken: unknownBatch.lease_token,
    txHash: "TX-UNKNOWN"
  });
  const unknown = await manager.getReservation(unknownBatch.reservation_ids[0]);
  assert.equal(unknown.lease_token, "");
  assert.equal(unknown.lease_until, "");
});

test("dynamic replan preserves existing reservation metadata", async () => {
  const manager = createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: noteFixture({ nullifier: "9d".repeat(32), sequence: 93 }) },
    kind: "relay_withdraw"
  });
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    payloadHash: "payload-hash",
    metadata: {
      recipient: "clair1recipient",
      operation_success_evidence_required: true
    }
  });
  await manager.markReplanRequired(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    error: "payload discarded before handoff",
    metadata: {
      reconcile_reason: "local_payload_discarded",
      no_broadcast_attempt: true,
      proof_discarded: true
    }
  });
  const record = await manager.getReservation(batch.reservation_ids[0]);
  assert.equal(record.status, reservationStatuses.ReplanRequired);
  assert.equal(record.metadata.recipient, "clair1recipient");
  assert.equal(record.metadata.operation_success_evidence_required, true);
  assert.equal(record.metadata.reconcile_reason, "local_payload_discarded");
});

test("spent reconciliation leaves partial operation evidence in note-lock mode", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "8d".repeat(32), sequence: 84 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "transfer"
  });
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    expectedOutputCommitment: "OUTPUT",
    expectedDisclosureDigest: "AUDIT",
    expectedAmount: "9",
    expectedDenom: "uclair"
  });
  await markSubmittedAfterAttempt(manager, batch, {
    leaseToken: batch.lease_token,
    txHash: "TX-NOTE-LOCK"
  });
  await manager.reconcileSpentNotes([{ ...note, isSpent: true }]);
  const record = await store.getReservation(batch.reservation_ids[0]);
  assert.equal(record.status, reservationStatuses.ConfirmedSpent);
  assert.equal(record.metadata.operation_status, undefined);
  assert.equal(record.metadata.operation_success_evidence_matches, undefined);
  await assert.doesNotReject(() => manager.reconcileSpentNotes([{ ...note, isSpent: true }]));
  assert.deepEqual(await store.getReservation(batch.reservation_ids[0]), record);
});

test("partial multi-input spent reconciliation cannot mark an operation as succeeded", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const first = noteFixture({ nullifier: "c1".repeat(32), sequence: 101 });
  const second = noteFixture({ nullifier: "c2".repeat(32), sequence: 102 });
  const batch = await preparePlanReservation(manager, {
    plan: { selection: { inputs: [first, second] } },
    kind: "payment"
  });
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    expectedOutputCommitment: "OUTPUT",
    expectedDisclosureDigest: "AUDIT",
    expectedRecipientHash: "RECIPIENT",
    expectedAmountHash: "AMOUNT",
    expectedAmount: "9",
    expectedDenom: "uclair",
    batchItemIndex: 0,
    batchItemIndexKnown: true,
    operationSuccessEvidenceRequired: true
  });
  await markSubmittedAfterAttempt(manager, batch, {
    leaseToken: batch.lease_token,
    txHash: "TX-MULTI"
  });
  await manager.reconcileSpentNotes([{
    ...first,
    isSpent: true,
    operationSuccessEvidence: {
      txHash: "TX-MULTI",
      outputCommitment: "OUTPUT",
      auditDisclosureDigest: "AUDIT",
      recipientHash: "RECIPIENT",
      amount: "9",
      amountHash: "AMOUNT",
      denom: "uclair",
      batchItemIndex: 0
    }
  }]);
  const firstRecord = await store.getReservation(batch.reservation_ids[0]);
  const secondRecord = await store.getReservation(batch.reservation_ids[1]);
  assert.equal(firstRecord.status, reservationStatuses.ConfirmedSpent);
  assert.equal(firstRecord.metadata.operation_status, operationStatuses.ManualReview);
  assert.deepEqual(firstRecord.metadata.operation_success_evidence_errors, [
    "operation input evidence incomplete"
  ]);
  assert.equal(secondRecord.status, reservationStatuses.Submitted);
  assert.equal(secondRecord.metadata.operation_status, operationStatuses.ManualReview);

  await manager.markManualReview([batch.reservation_ids[1]], {
    error: "partial spend requires manual review"
  });
  assert.deepEqual(
    (await Promise.all(batch.reservation_ids.map(id => store.getReservation(id))))
      .map(record => record.status),
    [reservationStatuses.ConfirmedSpent, reservationStatuses.ManualReview]
  );

  const evidence = {
    txHash: "TX-MULTI",
    outputCommitment: "OUTPUT",
    auditDisclosureDigest: "AUDIT",
    recipientHash: "RECIPIENT",
    amount: "9",
    amountHash: "AMOUNT",
    denom: "uclair",
    batchItemIndex: 0
  };
  await manager.reconcileSpentNotes([
    { ...first, isSpent: true, operationSuccessEvidence: evidence },
    { ...second, isSpent: true, operationSuccessEvidence: evidence }
  ]);
  const resolved = await Promise.all(batch.reservation_ids.map(id => store.getReservation(id)));
  assert.deepEqual(resolved.map(record => record.status), [
    reservationStatuses.ConfirmedSpent,
    reservationStatuses.ConfirmedSpent
  ]);
  assert.deepEqual(resolved.map(record => record.metadata.operation_status), [
    operationStatuses.Succeeded,
    operationStatuses.Succeeded
  ]);
  assert.deepEqual(resolved.map(record => record.metadata.operation_success_evidence_matches), [true, true]);
  assert.deepEqual(
    await manager.reconcileSpentNotes([{ ...first, isSpent: true }]),
    []
  );
  assert.deepEqual(
    await manager.reconcileSpentNotes([{
      ...first,
      isSpent: true,
      operationSuccessEvidence: evidence
    }]),
    []
  );
  await assert.rejects(
    () => manager.reconcileSpentNotes([{
      ...first,
      isSpent: true,
      operationSuccessEvidence: {
        ...evidence,
        recipientHash: "CONFLICTING-RECIPIENT"
      }
    }]),
    /retry evidence conflicts with a succeeded operation reconciliation/
  );
});

test("required operation evidence cannot succeed with missing expected recipient or amount hashes", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "8e".repeat(32), sequence: 85 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "transfer"
  });
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    expectedOutputCommitment: "OUTPUT",
    expectedDisclosureDigest: "AUDIT",
    expectedAmount: "9",
    expectedDenom: "uclair",
    batchItemIndex: 0,
    batchItemIndexKnown: true,
    operationSuccessEvidenceRequired: true
  });
  await markSubmittedAfterAttempt(manager, batch, {
    leaseToken: batch.lease_token,
    txHash: "TX-MISSING-EXPECTED"
  });
  await manager.reconcileSpentNotes([{
    ...note,
    isSpent: true,
    operationSuccessEvidence: {
      txHash: "TX-MISSING-EXPECTED",
      outputCommitment: "output",
      auditDisclosureDigest: "audit",
      amount: "9",
      denom: "uclair",
      batchItemIndex: 0
    }
  }]);
  const record = await store.getReservation(batch.reservation_ids[0]);
  assert.equal(record.status, reservationStatuses.ConfirmedSpent);
  assert.equal(record.metadata.operation_status, operationStatuses.ConflictSpent);
  assert.deepEqual(record.metadata.operation_success_evidence_errors, [
    "expected_recipient_hash expected value missing",
    "expected_amount_hash expected value missing"
  ]);
});

test("unknown reservations require reconcile evidence before replan releases the note", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "88".repeat(32), sequence: 8 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "withdraw"
  });
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token
  });
  await markUnknownAfterAttempt(manager, batch, {
    leaseToken: batch.lease_token,
    txHash: "TX-UNKNOWN",
    error: "broadcast submitted but query timed out"
  });

  await assert.rejects(
    () => manager.markReplanRequired(batch.reservation_ids, {
      fromStatus: reservationStatuses.Unknown,
      error: "timeout"
    }),
    /Unknown -> ReplanRequired requires nullifier_unspent_confirmed/
  );
  assert.equal(
    (await manager.reservationForNote(note)).status,
    reservationStatuses.Unknown
  );

  await manager.markReplanRequired(batch.reservation_ids, {
    fromStatus: reservationStatuses.Unknown,
    error: "tx failed and nullifier is unspent",
    metadata: {
      nullifier_unspent_confirmed: true,
      tx_absent_or_failed_confirmed: true,
      checked_height: "12346",
      tx_hash_checked: "TX-UNKNOWN"
    }
  });

  const replanRecord = await store.getReservation(batch.reservation_ids[0]);
  assert.equal(replanRecord.status, reservationStatuses.ReplanRequired);
  assert.equal(replanRecord.submitted_tx_hash, "TX-UNKNOWN");
  assert.equal(replanRecord.metadata.nullifier_unspent_confirmed, true);
  assert.equal(replanRecord.metadata.tx_absent_or_failed_confirmed, true);
  assert.equal(replanRecord.metadata.checked_height, "12346");
  assert.equal(replanRecord.metadata.tx_hash_checked, "TX-UNKNOWN");
  assert.equal(await manager.reservationForNote(note), null);
});

test("rollback with an expired lease moves proving reservations to manual review", async () => {
  let currentTime = new Date("2026-01-02T03:04:05.000Z");
  const now = () => currentTime;
  const store = new MemoryReservationStore({ now });
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1",
    leaseDurationMs: 1000,
    now
  });
  const note = noteFixture({ nullifier: "9a".repeat(32), sequence: 10 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "withdraw"
  });

  currentTime = new Date("2026-01-02T03:04:06.001Z");
  await rollbackPlanReservation(manager, batch);

  const record = await store.getReservation(batch.reservation_ids[0]);
  assert.equal(record.status, reservationStatuses.ManualReview);
  assert.equal(record.metadata.reconcile_reason, "rollback_lease_expired");
  assert.match(record.last_broadcast_error, /lease expired/);
  assert.equal((await manager.reservationForNote(note)).status, reservationStatuses.ManualReview);
  await assert.rejects(
    () => preparePlanReservation(manager, {
      plan: { selectedNote: note },
      kind: "withdraw"
    }),
    /active reservation already exists/
  );
});

test("rollback cleanup errors do not replace the original prepare error", async () => {
  const original = new Error("prover response is invalid");
  await rollbackPlanReservationPreservingError(
    {
      async releaseReservedOrProving() {
        throw new Error("reservation rollback failed");
      }
    },
    { reservation_ids: ["reservation-1"], lease_token: "lease-token" },
    original
  );
  assert.equal(original.message, "prover response is invalid");
  assert.equal(original.reservationCleanupErrors.length, 1);
  assert.match(original.reservationCleanupErrors[0].message, /rollback failed/);
});

test("expired-lease rollback reports a failed manual-review quarantine", async () => {
  const quarantineError = new Error("IndexedDB write failed");
  const manager = {
    async releaseReservedOrProving() {
      throw new Error("reservation lease expired");
    },
    async markManualReview() {
      throw quarantineError;
    }
  };
  const batch = { reservation_ids: ["reservation-1"], lease_token: "expired-lease" };

  await assert.rejects(
    () => rollbackPlanReservation(manager, batch),
    error => error === quarantineError
  );

  const original = new Error("prover response is invalid");
  await rollbackPlanReservationPreservingError(manager, batch, original);
  assert.equal(original.message, "prover response is invalid");
  assert.deepEqual(original.reservationCleanupErrors, [quarantineError]);
});

test("cleanup annotation cannot replace a frozen original error", async () => {
  const original = Object.freeze(new Error("frozen prover error"));
  await assert.doesNotReject(() => rollbackPlanReservationPreservingError(
    {
      async releaseReservedOrProving() {
        throw new Error("reservation rollback failed");
      }
    },
    { reservation_ids: ["reservation-1"], lease_token: "lease-token" },
    original
  ));
  assert.equal(original.message, "frozen prover error");
  assert.equal("reservationCleanupErrors" in original, false);
});

test("id-based reservation mutations enforce the manager owner boundary", async () => {
  const store = new MemoryReservationStore();
  const owner = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const otherOwner = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1other",
    indexKey: "other-index-key-v1"
  });
  const note = noteFixture({ nullifier: "99".repeat(32), sequence: 9 });
  const batch = await preparePlanReservation(owner, {
    plan: { selectedNote: note },
    kind: "withdraw"
  });

  await assert.rejects(
    () => otherOwner.markProofReady(batch.reservation_ids, {
      leaseToken: batch.lease_token
    }),
    /reservation owner mismatch/
  );
  await assert.rejects(
    () => otherOwner.renewLease(batch.reservation_ids, {
      leaseToken: batch.lease_token
    }),
    /reservation owner mismatch/
  );
  await assert.rejects(
    () => otherOwner.releaseReservedOrProving(batch.reservation_ids),
    /reservation owner mismatch/
  );

  const record = await store.getReservation(batch.reservation_ids[0]);
  assert.equal(record.owner_key_id, "chain:clair1owner");
  assert.equal(record.status, reservationStatuses.Proving);
});

test("failed Cosmos and EVM execution evidence cannot mark an operation succeeded", async () => {
  for (const [sequence, txResult, expectedError] of [
    [201, { code: 9, txhash: "TX-COSMOS-FAILED" }, "tx_result_code indicates failure"],
    [202, { txhash: "TX-EVM-FAILED", receipt: { status: "0x0" } }, "evm_receipt_status indicates failure"],
    [205, { txhash: "TX-EVM-RAW-FAILED", status: "0x0" }, "evm_receipt_status indicates failure"],
    [206, { code: false, txhash: "TX-COSMOS-MALFORMED" }, "tx_result_code indicates failure"],
    [207, { txhash: "TX-EVM-EMPTY-RECEIPT", status: "0x0", receipt: {} }, "evm_receipt_status indicates failure"],
    [212, { txhash: "TX-EVM-REVERTED", status: "reverted" }, "evm_receipt_status indicates failure"]
  ]) {
    const store = new MemoryReservationStore();
    const manager = createNoteReservationManager({
      store,
      ownerKeyId: "chain:clair1owner",
      indexKey: "index-key-v1"
    });
    const note = noteFixture({
      nullifier: (
        sequence === 201 ? "c1" :
          sequence === 202 ? "c2" :
            sequence === 205 ? "c5" :
              sequence === 207 ? "c7" :
                sequence === 212 ? "cc" :
                "c6"
      ).repeat(32),
      sequence
    });
    const batch = await preparePlanReservation(manager, {
      plan: { selectedNote: note },
      kind: "payment"
    });
    await manager.markProofReady(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      expectedOutputCommitment: "OUTPUT",
      expectedDisclosureDigest: "DISCLOSURE",
      expectedRecipientHash: "RECIPIENT",
      expectedAmount: "1",
      expectedAmountHash: "AMOUNT",
      expectedDenom: "uclair",
      batchItemIndexKnown: false,
      operationSuccessEvidenceRequired: true
    });
    await markSubmittedAfterAttempt(manager, batch, {
      leaseToken: batch.lease_token,
      txHash: txResult.txhash
    });
    await manager.reconcileSpentNotes([{
      ...note,
      isSpent: true,
      operationSuccessEvidence: sequence === 205 ? {
        transactionHash: txResult.txhash,
        status: txResult.status,
        outputCommitment: "OUTPUT",
        disclosureDigest: "DISCLOSURE",
        recipientHash: "RECIPIENT",
        amount: "1",
        amountHash: "AMOUNT",
        denom: "uclair"
      } : {
        txResult,
        outputCommitment: "OUTPUT",
        disclosureDigest: "DISCLOSURE",
        recipientHash: "RECIPIENT",
        amount: "1",
        amountHash: "AMOUNT",
        denom: "uclair"
      }
    }]);
    const record = await store.getReservation(batch.reservation_ids[0]);
    assert.equal(record.status, reservationStatuses.ConfirmedSpent);
    assert.equal(record.metadata.operation_status, operationStatuses.ConflictSpent);
    assert.ok(record.metadata.operation_success_evidence_errors.includes(expectedError));
  }
});

test("explicit EVM success statuses mark the operation succeeded", async () => {
  for (const [sequence, nullifier, status] of [
    [203, "c3".repeat(32), "0x01"],
    [211, "cb".repeat(32), "success"]
  ]) {
    const store = new MemoryReservationStore();
    const manager = createNoteReservationManager({
      store,
      ownerKeyId: "chain:clair1owner",
      indexKey: "index-key-v1"
    });
    const note = noteFixture({ nullifier, sequence });
    const batch = await preparePlanReservation(manager, {
      plan: { selectedNote: note },
      kind: "payment"
    });
    await manager.markProofReady(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      expectedOutputCommitment: "OUTPUT",
      expectedDisclosureDigest: "DISCLOSURE",
      expectedRecipientHash: "RECIPIENT",
      expectedAmount: "1",
      expectedAmountHash: "AMOUNT",
      expectedDenom: "uclair",
      batchItemIndexKnown: false,
      operationSuccessEvidenceRequired: true
    });
    await markSubmittedAfterAttempt(manager, batch, {
      leaseToken: batch.lease_token,
      txHash: "TX-EVM-SUCCEEDED"
    });
    await manager.reconcileSpentNotes([{
      ...note,
      isSpent: true,
      operationSuccessEvidence: {
        transactionHash: "TX-EVM-SUCCEEDED",
        status,
        outputCommitment: "OUTPUT",
        disclosureDigest: "DISCLOSURE",
        recipientHash: "RECIPIENT",
        amount: "1",
        amountHash: "AMOUNT",
        denom: "uclair"
      }
    }]);

    const record = await store.getReservation(batch.reservation_ids[0]);
    assert.equal(record.status, reservationStatuses.ConfirmedSpent);
    assert.equal(record.metadata.operation_status, operationStatuses.Succeeded);
    assert.deepEqual(record.metadata.operation_success_evidence_errors, []);
  }
});

test("top-level failed EVM receipt overrides a nested successful tx result", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "c4".repeat(32), sequence: 204 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "payment"
  });
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    expectedOutputCommitment: "OUTPUT",
    expectedDisclosureDigest: "DISCLOSURE",
    expectedRecipientHash: "RECIPIENT",
    expectedAmount: "1",
    expectedAmountHash: "AMOUNT",
    expectedDenom: "uclair",
    operationSuccessEvidenceRequired: true
  });
  await markSubmittedAfterAttempt(manager, batch, {
    leaseToken: batch.lease_token,
    txHash: "TX-FAILED"
  });
  await manager.reconcileSpentNotes([{
    ...note,
    isSpent: true,
    operationSuccessEvidence: {
      transactionHash: "TX-FAILED",
      status: "0x0",
      txResult: { transactionHash: "TX-FAILED", status: "0x1" },
      outputCommitment: "OUTPUT",
      disclosureDigest: "DISCLOSURE",
      recipientHash: "RECIPIENT",
      amount: "1",
      amountHash: "AMOUNT",
      denom: "uclair"
    }
  }]);
  const record = await store.getReservation(batch.reservation_ids[0]);
  assert.equal(record.metadata.operation_status, operationStatuses.ConflictSpent);
  assert.ok(record.metadata.operation_success_evidence_errors.includes("evm_receipt_status indicates failure"));
});

test("a failed execution-result alias overrides an earlier successful alias", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "c8".repeat(32), sequence: 208 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "payment"
  });
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    expectedOutputCommitment: "OUTPUT",
    expectedDisclosureDigest: "DISCLOSURE",
    expectedRecipientHash: "RECIPIENT",
    expectedAmount: "1",
    expectedAmountHash: "AMOUNT",
    expectedDenom: "uclair",
    operationSuccessEvidenceRequired: true
  });
  await markSubmittedAfterAttempt(manager, batch, {
    leaseToken: batch.lease_token,
    txHash: "TX-ALIASED-FAILED"
  });
  await manager.reconcileSpentNotes([{
    ...note,
    isSpent: true,
    operationSuccessEvidence: {
      txResult: {
        transactionHash: "TX-ALIASED-FAILED",
        status: "0x1"
      },
      transactionResult: {
        transactionHash: "TX-ALIASED-FAILED",
        status: "0x0"
      },
      outputCommitment: "OUTPUT",
      disclosureDigest: "DISCLOSURE",
      recipientHash: "RECIPIENT",
      amount: "1",
      amountHash: "AMOUNT",
      denom: "uclair"
    }
  }]);
  const record = await store.getReservation(batch.reservation_ids[0]);
  assert.equal(record.metadata.operation_status, operationStatuses.ConflictSpent);
  assert.ok(record.metadata.operation_success_evidence_errors.includes("evm_receipt_status indicates failure"));
});

test("operation evidence rejects flattened failures and contradictory aliases", async () => {
  for (const [sequence, txHash, evidence, expectedError] of [
    [
      209,
      "TX-FLAT-FAILED",
      { txHash: "TX-FLAT-FAILED", status: "0x0" },
      "evm_receipt_status indicates failure"
    ],
    [
      210,
      "TX-PREDICATE-CONFLICT",
      {
        txHash: "TX-PREDICATE-CONFLICT",
        status: "0x1",
        expectedRecipientHash: "RECIPIENT",
        recipientHash: "OTHER"
      },
      "expected_recipient_hash evidence aliases conflict"
    ],
    [
      211,
      "TX-BATCH-INDEX-CONFLICT",
      {
        txHash: "TX-BATCH-INDEX-CONFLICT",
        status: "0x1",
        batchItemIndex: 0,
        batch_item_index: 1
      },
      "batch_item_index evidence aliases conflict"
    ],
    [
      212,
      "TX-BATCH-KNOWN-CONFLICT",
      {
        txHash: "TX-BATCH-KNOWN-CONFLICT",
        status: "0x1",
        batchItemIndexKnown: true,
        batch_item_index_known: false
      },
      "batch_item_index_known evidence aliases conflict"
    ]
  ]) {
    const store = new MemoryReservationStore();
    const manager = createNoteReservationManager({
      store,
      ownerKeyId: "chain:clair1owner",
      indexKey: "index-key-v1"
    });
    const note = noteFixture({
      nullifier: (sequence === 209 ? "c9" : "ca").repeat(32),
      sequence
    });
    const batch = await preparePlanReservation(manager, {
      plan: { selectedNote: note },
      kind: "payment"
    });
    await manager.markProofReady(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      expectedOutputCommitment: "OUTPUT",
      expectedDisclosureDigest: "DISCLOSURE",
      expectedRecipientHash: "RECIPIENT",
      expectedAmount: "1",
      expectedAmountHash: "AMOUNT",
      expectedDenom: "uclair",
      operationSuccessEvidenceRequired: true
    });
    await markSubmittedAfterAttempt(manager, batch, {
      leaseToken: batch.lease_token,
      txHash
    });
    await manager.reconcileSpentNotes([{
      ...note,
      isSpent: true,
      operationSuccessEvidence: {
        ...evidence,
        outputCommitment: "OUTPUT",
        disclosureDigest: "DISCLOSURE",
        recipientHash: evidence.recipientHash ?? "RECIPIENT",
        amount: "1",
        amountHash: "AMOUNT",
        denom: "uclair"
      }
    }]);
    const record = await store.getReservation(batch.reservation_ids[0]);
    assert.equal(record.metadata.operation_status, operationStatuses.ConflictSpent);
    assert.ok(record.metadata.operation_success_evidence_errors.includes(expectedError));
  }
});

test("nested operation evidence ignores outer flattened-note fields", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "cd".repeat(32), amount: 5, sequence: 213 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "payment"
  });
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    expectedOutputCommitment: "OUTPUT",
    expectedDisclosureDigest: "DISCLOSURE",
    expectedRecipientHash: "RECIPIENT",
    expectedAmount: "3",
    expectedAmountHash: "AMOUNT",
    expectedDenom: "uclair",
    operationSuccessEvidenceRequired: true
  });
  await markSubmittedAfterAttempt(manager, batch, {
    leaseToken: batch.lease_token,
    txHash: "TX-NESTED-EVIDENCE"
  });
  await manager.reconcileSpentNotes([{
    ...note,
    amount: "5",
    tx_hash: "OUTER-NOTE-TX",
    status: "0x0",
    isSpent: true,
    operationSuccessEvidence: {
      txResult: {
        transactionHash: "TX-NESTED-EVIDENCE",
        status: "0x1"
      },
      outputCommitment: "OUTPUT",
      disclosureDigest: "DISCLOSURE",
      recipientHash: "RECIPIENT",
      amount: "3",
      amountHash: "AMOUNT",
      denom: "uclair"
    }
  }]);
  const record = await store.getReservation(batch.reservation_ids[0]);
  assert.equal(record.metadata.operation_status, operationStatuses.Succeeded);
  assert.deepEqual(record.metadata.operation_success_evidence_errors, []);
});

test("proof-ready transitions reject contradictory evidence aliases atomically", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: noteFixture({ nullifier: "ce".repeat(32), sequence: 214 }) },
    kind: "payment"
  });

  await assert.rejects(
    () => manager.markProofReady(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      expectedRecipientHash: "RECIPIENT-A",
      expected_recipient_hash: "RECIPIENT-B"
    }),
    /expected_recipient_hash evidence aliases conflict/
  );
  await assert.rejects(
    () => manager.markProofReadyBatch([{
      reservationIDs: batch.reservation_ids,
      metadata: {
        leaseToken: batch.lease_token,
        batchItemIndex: 0,
        batch_item_index: 1
      }
    }]),
    /batch_item_index evidence aliases conflict/
  );
  assert.equal(
    (await store.getReservation(batch.reservation_ids[0])).status,
    reservationStatuses.Proving
  );
});

test("reservation transition identifier aliases must agree", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: noteFixture({ nullifier: "cf".repeat(32), sequence: 215 }) },
    kind: "payment"
  });
  const reservationID = batch.reservation_ids[0];
  const before = await store.getReservation(reservationID);

  await assert.rejects(
    () => store.compareAndSetReservationStatusBatch([{
      reservationID,
      reservation_id: "different-reservation",
      from: reservationStatuses.Proving,
      to: reservationStatuses.ProofReady,
      patch: {}
    }]),
    /reservationID aliases conflict/
  );
  await assert.rejects(
    () => manager.markProofReadyBatch([{
      reservationIDs: [reservationID],
      reservation_ids: ["different-reservation"],
      metadata: { leaseToken: batch.lease_token }
    }]),
    /reservationIDs aliases conflict/
  );
  assert.deepEqual(await store.getReservation(reservationID), before);
});

test("reconciliation rejects contradictory nested evidence envelopes atomically", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "d0".repeat(32), sequence: 216 });
  const batch = await preparePlanReservation(manager, {
    plan: { selectedNote: note },
    kind: "payment"
  });
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    expectedRecipientHash: "RECIPIENT",
    operationSuccessEvidenceRequired: true
  });
  await markSubmittedAfterAttempt(manager, batch, {
    leaseToken: batch.lease_token,
    txHash: "TX-ENVELOPE-CONFLICT"
  });
  const successfulEvidence = {
    txResult: {
      transactionHash: "TX-ENVELOPE-CONFLICT",
      status: "0x1"
    },
    recipientHash: "RECIPIENT"
  };

  await assert.rejects(
    () => manager.reconcileSpentNotes([{
      ...note,
      isSpent: true,
      operationSuccessEvidence: successfulEvidence,
      successEvidence: {
        ...successfulEvidence,
        txResult: {
          transactionHash: "TX-ENVELOPE-CONFLICT",
          status: "0x0"
        }
      }
    }]),
    /operation success evidence envelope aliases conflict/
  );
  assert.equal(
    (await store.getReservation(batch.reservation_ids[0])).status,
    reservationStatuses.Submitted
  );
});

test("inactive transitions require reconciled discard or operator evidence", async () => {
  const manager = createNoteReservationManager({
    store: new MemoryReservationStore(),
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const proofNote = noteFixture({ nullifier: "c3".repeat(32), sequence: 203 });
  const proofBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: proofNote },
    kind: "withdraw"
  });
  await manager.markProofReady(proofBatch.reservation_ids, {
    leaseToken: proofBatch.lease_token
  });
  await assert.rejects(
    () => manager.markReplanRequired(proofBatch.reservation_ids, {
      leaseToken: proofBatch.lease_token,
      error: "discard without durable proof"
    }),
    /ProofReady -> ReplanRequired requires/
  );
  await assert.rejects(
    () => manager.markReplanRequired(proofBatch.reservation_ids, {
      leaseToken: proofBatch.lease_token,
      proofDiscarded: true,
      metadata: {
        proof_discarded: false,
        no_broadcast_attempt: true
      }
    }),
    /proof discarded evidence aliases conflict/
  );
  await assert.rejects(
    () => manager.markReplanRequired(proofBatch.reservation_ids, {
      leaseToken: proofBatch.lease_token,
      txHash: "SUBMITTED-DURING-DISCARD",
      proofDiscarded: true,
      metadata: {
        no_broadcast_attempt: true
      }
    }),
    /ProofReady -> ReplanRequired requires/
  );
  assert.equal(
    (await manager.store.getReservation(proofBatch.reservation_ids[0])).status,
    reservationStatuses.ProofReady
  );
  await manager.markReplanRequired(proofBatch.reservation_ids, {
    leaseToken: proofBatch.lease_token,
    proofDiscarded: true,
    error: "proof discarded before broadcast",
    metadata: {
      no_broadcast_attempt: true
    }
  });
  assert.equal(
    (await manager.store.getReservation(proofBatch.reservation_ids[0])).metadata.proof_discarded,
    true
  );

  const submittedNote = noteFixture({ nullifier: "c4".repeat(32), sequence: 204 });
  const submittedBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: submittedNote },
    kind: "withdraw"
  });
  await manager.markProofReady(submittedBatch.reservation_ids, {
    leaseToken: submittedBatch.lease_token
  });
  await markSubmittedAfterAttempt(manager, submittedBatch, {
    leaseToken: submittedBatch.lease_token,
    txHash: "TX-FAILED"
  });
  await assert.rejects(
    () => manager.transitionBatch(
      submittedBatch.reservation_ids,
      reservationStatuses.Submitted,
      reservationStatuses.Failed
    ),
    /Submitted -> Failed requires nullifier_unspent_confirmed/
  );
  await manager.transitionBatch(
    submittedBatch.reservation_ids,
    reservationStatuses.Submitted,
    reservationStatuses.Failed,
    {
      nullifierUnspentConfirmed: true,
      txAbsentOrFailedConfirmed: true,
      checkedHeight: 204,
      txHashChecked: "TX-FAILED"
    }
  );
  const failedRecord = await manager.store.getReservation(
    submittedBatch.reservation_ids[0]
  );
  assert.equal(failedRecord.metadata.nullifier_unspent_confirmed, true);
  assert.equal(failedRecord.metadata.tx_absent_or_failed_confirmed, true);
  assert.equal(failedRecord.metadata.checked_height, 204);
  assert.equal(failedRecord.metadata.tx_hash_checked, "TX-FAILED");

  const reviewNote = noteFixture({ nullifier: "c5".repeat(32), sequence: 205 });
  const reviewBatch = await manager.reserveNotes({ notes: [reviewNote] });
  await manager.transitionBatch(
    reviewBatch.reservation_ids,
    reservationStatuses.Reserved,
    reservationStatuses.ManualReview
  );
  await assert.rejects(
    () => manager.resolveManualReview(reviewBatch.reservation_ids, {
      target: reservationStatuses.Released,
      operatorId: "ops@example.test"
    }),
    /approvalReference/
  );
  const resolvedReview = await manager.resolveManualReview(
    reviewBatch.reservation_ids,
    {
      target: reservationStatuses.Released,
      operatorId: "ops@example.test",
      approvalReference: "case-205",
      reason: "operator confirmed no active transaction"
    }
  );
  assert.equal(resolvedReview[0].metadata.operator_id, "ops@example.test");
  assert.equal(resolvedReview[0].metadata.operator_approval_reference, "case-205");
});

test("spent-note reconciliation applies multi-note updates in one atomic batch", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1owner",
    indexKey: "index-key-v1"
  });
  const firstNote = noteFixture({ nullifier: "d1".repeat(32), sequence: 301 });
  const secondNote = noteFixture({ nullifier: "d2".repeat(32), sequence: 302 });
  const firstBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: firstNote },
    kind: "transfer"
  });
  const secondBatch = await preparePlanReservation(manager, {
    plan: { selectedNote: secondNote },
    kind: "transfer"
  });
  for (const [batch, txHash] of [[firstBatch, "TX-FIRST"], [secondBatch, "TX-SECOND"]]) {
    await manager.markProofReady(batch.reservation_ids, { leaseToken: batch.lease_token });
    await markSubmittedAfterAttempt(manager, batch, { leaseToken: batch.lease_token, txHash });
  }

  const originalBatchCAS = store.compareAndSetReservationStatusBatch.bind(store);
  store.compareAndSetReservationStatusBatch = async transitions => {
    assert.equal(transitions.length, 2);
    throw new Error("injected reconciliation batch failure");
  };
  await assert.rejects(
    () => manager.reconcileSpentNotes([
      { ...firstNote, isSpent: true },
      { ...secondNote, isSpent: true }
    ]),
    /injected reconciliation batch failure/
  );
  store.compareAndSetReservationStatusBatch = originalBatchCAS;

  for (const reservationID of [...firstBatch.reservation_ids, ...secondBatch.reservation_ids]) {
    const reservation = await store.getReservation(reservationID);
    assert.equal(reservation.status, reservationStatuses.Submitted);
  }
});

test("reservation creation accepts only clean Reserved records and relay handoff binds the payload hash", async () => {
  const store = new MemoryReservationStore();
  const base = {
    reservation_id: "initial-reservation",
    owner_key_id: "owner-a",
    nullifier_lookup_key: "lookup-a",
    status: reservationStatuses.Reserved
  };
  await assert.rejects(
    () => store.createReservationBatch([{
      ...base,
      reservation_id: "forged-submitted",
      status: reservationStatuses.Submitted,
      submitted_tx_hash: "FORGED-TX"
    }]),
    /must start as Reserved/
  );
  await assert.rejects(
    () => store.createReservationBatch([{
      ...base,
      reservation_id: "forged-relay",
      payload_hash: "forged-payload",
      metadata: { relay_handed_off: true }
    }]),
    /cannot include lifecycle, broadcast, or relay evidence/
  );
  for (const [reservationID, metadata] of [
    ["forged-false-approval", { operator_approved: false }],
    ["forged-approval-alias", { operatorApproved: false }],
    ["forged-relay-alias", { relayHandedOff: true }]
  ]) {
    await assert.rejects(
      () => store.createReservationBatch([{
        ...base,
        reservation_id: reservationID,
        metadata
      }]),
      /cannot include lifecycle evidence metadata/
    );
  }
  await assert.rejects(
    () => store.createReservationBatch([{
      ...base,
      reservation_id: "forged-claim-token",
      metadata: { reservation_claim_token_hash: "attacker-chosen-hash" }
    }]),
    /cannot include manager claim-token metadata/
  );
  const indexedHarness = indexedDbHarness();
  const indexedStore = new IndexedDbReservationStore({
    indexedDB: {},
    locks: { request: (_name, _options, callback) => callback() },
    unsafeAllowPlaintext: true
  });
  indexedStore.dbPromise = Promise.resolve(indexedHarness.db);
  await assert.rejects(
    () => indexedStore.createReservationBatch([{
      ...base,
      reservation_id: "indexed-forged-claim-token",
      metadata: { reservation_claim_token_hash: "attacker-chosen-hash" }
    }]),
    /cannot include manager claim-token metadata/
  );

  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "owner-a",
    indexKey: "index-key-v1"
  });
  const note = noteFixture({ nullifier: "f1".repeat(32), sequence: 401 });
  const batch = await manager.reserveNotes({ notes: [note], operationId: "relay-op" });
  await manager.markProving(batch.reservation_ids, {
    leaseToken: batch.lease_token
  });
  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    payloadHash: "relay-payload-a"
  });
  await assert.rejects(
    () => manager.recordRelayHandoff(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      payloadHash: "relay-payload-b"
    }),
    /payload hash does not match/
  );
  const handedOff = await manager.recordRelayHandoff(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    payloadHash: "relay-payload-a"
  });
  assert.equal(handedOff[0].payload_hash, "relay-payload-a");
  assert.equal(handedOff[0].metadata.relay_handed_off, true);
  await assert.rejects(
    () => manager.markBroadcastAttempting(batch.reservation_ids, {
      leaseToken: batch.lease_token,
      txBytesHash: "handed-off-transaction"
    }),
    /relay payload was handed off/
  );

  const attemptedNotes = [
    noteFixture({ nullifier: "f4".repeat(32), sequence: 404 }),
    noteFixture({ nullifier: "f5".repeat(32), sequence: 405 })
  ];
  const attemptedBatch = await manager.reserveNotes({
    notes: attemptedNotes,
    operationId: "broadcast-before-relay-op"
  });
  await manager.markProving(attemptedBatch.reservation_ids, {
    leaseToken: attemptedBatch.lease_token
  });
  await manager.markProofReady(attemptedBatch.reservation_ids, {
    leaseToken: attemptedBatch.lease_token,
    payloadHash: "relay-payload-after-attempt"
  });
  await manager.markBroadcastAttempting(attemptedBatch.reservation_ids, {
    leaseToken: attemptedBatch.lease_token,
    txBytesHash: "broadcast-before-relay-transaction"
  });
  await assert.rejects(
    () => manager.recordRelayHandoff(attemptedBatch.reservation_ids, {
      leaseToken: attemptedBatch.lease_token,
      payloadHash: "relay-payload-after-attempt"
    }),
    /broadcast attempt already started; reconcile before relay handoff/
  );
  for (const reservationID of attemptedBatch.reservation_ids) {
    const attempted = await store.getReservation(reservationID);
    assert.equal(attempted.broadcast_in_flight, true);
    assert.equal(attempted.broadcast_attempt_count, 1);
    assert.equal(attempted.metadata.relay_handed_off, undefined);
  }
});

test("operation lifecycle transitions require the exact linked reservation set", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "owner-a",
    indexKey: "index-key-v1"
  });
  const first = noteFixture({ nullifier: "f2".repeat(32), sequence: 402 });
  const second = noteFixture({ nullifier: "f3".repeat(32), sequence: 403 });
  const batch = await manager.reserveNotes({
    notes: [first, second],
    operationId: "atomic-operation"
  });
  await assert.rejects(
    () => store.compareAndSetReservationStatusBatch([
      {
        reservationID: batch.reservation_ids[0],
        from: reservationStatuses.Reserved,
        to: reservationStatuses.Proving,
        patch: {
          lease_owner: manager.leaseOwner,
          lease_token: batch.lease_token,
          lease_until: new Date(Date.now() + 60_000).toISOString(),
          last_heartbeat_at: new Date().toISOString()
        }
      },
      {
        reservationID: batch.reservation_ids[1],
        from: reservationStatuses.Reserved,
        to: reservationStatuses.ManualReview,
        patch: {}
      }
    ]),
    /one target status/
  );
  for (const reservationID of batch.reservation_ids) {
    assert.equal((await store.getReservation(reservationID)).status, reservationStatuses.Reserved);
  }
  await assert.rejects(
    () => manager.markProving([batch.reservation_ids[0]], { leaseToken: batch.lease_token }),
    /exact linked reservation set/
  );
  for (const reservationID of batch.reservation_ids) {
    assert.equal((await store.getReservation(reservationID)).status, reservationStatuses.Reserved);
  }
  await manager.markProving(batch.reservation_ids, { leaseToken: batch.lease_token });
  await assert.rejects(
    () => manager.markProofReady([batch.reservation_ids[0]], {
      leaseToken: batch.lease_token,
      payloadHash: "atomic-payload"
    }),
    /exact linked reservation set/
  );
  for (const reservationID of batch.reservation_ids) {
    assert.equal((await store.getReservation(reservationID)).status, reservationStatuses.Proving);
  }

  await manager.markProofReady(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    payloadHash: "atomic-payload"
  });
  await assert.rejects(
    () => manager.recordRelayHandoff([batch.reservation_ids[0]], {
      leaseToken: batch.lease_token,
      payloadHash: "atomic-payload"
    }),
    /exact linked reservation set/
  );
  await assert.rejects(
    () => manager.markReplanRequired([batch.reservation_ids[0]], {
      leaseToken: batch.lease_token,
      metadata: {
        no_broadcast_attempt: true,
        proof_discarded: true
      }
    }),
    /exact linked reservation set/
  );
  await manager.markBroadcastAttempting(batch.reservation_ids, {
    leaseToken: batch.lease_token,
    txHash: "ATOMIC-TX"
  });
  await assert.rejects(
    () => manager.markSubmitted([batch.reservation_ids[0]], {
      leaseToken: batch.lease_token,
      txHash: "ATOMIC-TX"
    }),
    /exact linked reservation set/
  );
  await assert.rejects(
    () => manager.markUnknown([batch.reservation_ids[0]], {
      leaseToken: batch.lease_token,
      txHash: "ATOMIC-TX",
      error: "rpc timeout"
    }),
    /exact linked reservation set/
  );
  await assert.rejects(
    () => manager.markManualReview([batch.reservation_ids[0]], {
      leaseToken: batch.lease_token,
      error: "partial recovery"
    }),
    /exact linked reservation set/
  );
  for (const reservationID of batch.reservation_ids) {
    assert.equal((await store.getReservation(reservationID)).status, reservationStatuses.ProofReady);
  }
});

test("candidate filtering loads reservation state once for a note batch", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1bulk",
    indexKey: "bulk-index-key"
  });
  const reserved = noteFixture({ nullifier: "d3".repeat(32), sequence: 303 });
  await manager.reserveNotes({ notes: [reserved], kind: "transfer" });

  let listCalls = 0;
  let lookupCalls = 0;
  const listReservations = store.listReservations.bind(store);
  const findReservationsByLookupKey = store.findReservationsByLookupKey.bind(store);
  store.listReservations = async options => {
    listCalls += 1;
    return listReservations(options);
  };
  store.findReservationsByLookupKey = async (...args) => {
    lookupCalls += 1;
    return findReservationsByLookupKey(...args);
  };

  const notes = [reserved, ...Array.from({ length: 199 }, (_, index) => noteFixture({
    nullifier: (index + 1).toString(16).padStart(64, "0"),
    sequence: 400 + index
  }))];
  const statuses = await manager.reservationStatusByNote(notes);
  assert.equal(statuses.size, 200);
  assert.equal(listCalls, 1);
  assert.equal(lookupCalls, 0);

  const available = await manager.filterAvailableNotes(notes);
  assert.equal(available.length, 199);
  assert.equal(listCalls, 2);
  assert.equal(lookupCalls, 0);
});

test("batch lifecycle preflight loads reservation state once per operation", async () => {
  const store = new MemoryReservationStore();
  const manager = createNoteReservationManager({
    store,
    ownerKeyId: "chain:clair1batch-load",
    indexKey: "batch-load-index-key"
  });
  const batch = await manager.reserveNotes({
    notes: [
      noteFixture({ nullifier: "d4".repeat(32), sequence: 304 }),
      noteFixture({ nullifier: "d5".repeat(32), sequence: 305 })
    ],
    kind: "transfer"
  });

  let listCalls = 0;
  let getCalls = 0;
  const listReservations = store.listReservations.bind(store);
  const getReservation = store.getReservation.bind(store);
  store.listReservations = async options => {
    listCalls += 1;
    return listReservations(options);
  };
  store.getReservation = async reservationID => {
    getCalls += 1;
    return getReservation(reservationID);
  };

  await manager.markProving(batch.reservation_ids, {
    leaseToken: batch.lease_token
  });
  assert.equal(listCalls, 1);
  assert.equal(getCalls, 0);

  await manager.renewLease(batch.reservation_ids, {
    leaseToken: batch.lease_token
  });
  assert.equal(listCalls, 2);
  assert.equal(getCalls, 0);
});
