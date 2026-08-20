# ClairveilJS Storage and Persistence Implementation Guide

## Purpose and scope

This document explains how a browser wallet or DApp using ClairveilJS can safely persist **decrypted notes and scan cursors**, **note reservations**, and **transaction evidence** in production.

ClairveilJS provides `MemoryNoteStore` for validating and merging note state, `LocalStorageNoteStore` for demos/tests, and `createBrowserReservationStore(...)` for browsers. Production Note Store encryption-key management and wallet DB implementation remain the responsibility of the app or wallet.

- Components and trust boundaries: [System architecture](./architecture.md)
- Reservation states and evidence guards: [Note Reservation State Transitions](./reservation-state-machine.md)
- Deployment profiles and store options: [Configuration guide](./configuration.md)
- Retry and restart recovery: [Errors and recovery](./errors-and-recovery.md)

This guide makes the current ClairveilJS public API concrete based on the Clairveil v0.3.1 documents `docs/clairveil-js-sdk-handoff-kr.md`, `docs/clairveil-reference-payroll-wallet-handoff-kr.md`, `docs/clairveil-client-risk-decisions-kr.md`, and `docs/clairveil-note-reservation-design-kr.md`. The Clairveil v0.3.1 documents leave wallet DB schema and encrypted local-storage methods to the downstream JS SDK/product. The IndexedDB wrapper and AES-GCM codec below are **recommended ClairveilJS implementation structures**, not wire contracts fixed by the v0.3.1 protocol or a completed wallet DB exported by ClairveilJS.

## Stored data and separation of responsibility

| Data | Recommended location | Persistence requirement |
| --- | --- | --- |
| Privacy root signature, root seed, spend/view/disclosure private material | Wallet secure store or memory for as long as needed | Do not store in ordinary `localStorage`, plaintext IndexedDB, or a server DB. |
| Decrypted notes, nullifier state, scan cursor | Encrypted Note Store implemented by the app/wallet | Isolate by chain/profile/wallet/account namespace and save notes and cursor atomically. |
| Reservation, lease, payload/proof binding, broadcast evidence | Encrypted Reservation Store | In a browser, use IndexedDB, Web Locks, and full-state encryption together. |
| Prepared payload or proof checkpoint | Memory by default | Persist in a separate encrypted checkpoint only when required for async batch/relay recovery. |
| Public chain config and non-sensitive UI settings | Ordinary configuration store | Do not mix with privacy material or its encryption-key namespace. |

The Note Store and Reservation Store have different purposes and lifetimes, so do not merge them into one state object.

- The Note Store is wallet inventory that can be rebuilt by scanning the chain again.
- The Reservation Store is safety state that prevents duplicate note use and reconciles transactions that may already have been submitted.
- Losing the note cache permits a full rescan, but losing a reservation after `Proving` or ambiguous broadcast evidence may make safe automatic recovery impossible.

### Mapping the Clairveil wallet projection

The minimum wallet projection required by the Clairveil v0.3.1 documents should be split across these two stores and product operation metadata. Products may choose their actual column names, but must preserve equivalent information and atomicity.

| Clairveil projection | ClairveilJS storage |
| --- | --- |
| `commitment_hex`, `nullifier_hex`, `amount`, `denom`, `spent` | Note inventory in the encrypted Note Store |
| `last_scan_height`, `last_scan_sequence`, and output position | Complete `(height, global_sequence, output_index)` cursor in the Note Store |
| `nullifier_lookup_key`, `nullifier_lookup_key_id` | Encrypted Reservation Store; do not replace the lookup key with a public account ID |
| `reservation_id`, `reservation_status`, `operation_id` | CAS/lease/evidence records in the Reservation Store |
| `tx_hash` | Network transaction lookup and receipt evidence in the Reservation Store |
| `tx_bytes_hash` | Artifact binding for exact signed Cosmos TxRaw or the EVM canonical transaction request; not a network transaction lookup key on EVM |
| `payroll_id`, `batch_id` | Reference-payroll or product operation DB, linked to reservation `operation_id` |

A note linked to an active reservation must be excluded from candidates for every other transfer, split, merge, and batch. Even when Note Store and Reservation Store are separate databases, apply reservation lookup before displaying wallet inventory or building a plan.

## Production requirements

A production store must satisfy all of the following:

1. Encrypt decrypted notes and reservation state with AEAD.
2. Do not store the encryption key in the same IndexedDB record as the ciphertext.
3. Separate namespaces by chain, profile, wallet type, and account.
4. Perform the entire read-modify-write inside the same exclusive lock.
5. Save notes and the complete scan cursor in one atomic change.
6. Fail closed on authentication failure, schema mismatch, or a corrupted record instead of automatically replacing it with an empty state.
7. Do not release `Unknown`, `Submitted`, or `ManualReview` reservations based only on TTL.
8. After account changes and restarts, reconcile stored evidence with on-chain nullifier and transaction state.
9. Run only one scan worker per note namespace, or serialize the entire scan call through a separate single-writer coordinator.

The following options and implementations are demo/test-only:

- `LocalStorageNoteStore({ allowPlaintext: true })`
- `MemoryReservationStore`
- `unsafeAllowPlaintext`
- `unsafeAllowMemoryFallback`
- `unsafeAllowPublicIndexKey`

## Namespace and account isolation

A store namespace must include at least the schema epoch, chain ID, deployment profile, wallet type, and account scope.

```text
clairveil:wallet-notes:v2:<chain-id>:<profile-scope>:<wallet-kind>:<account-scope>
clairveil:note-reservations:v2:<chain-id>:<profile-scope>:<wallet-kind>:<account-scope>
```

First decide whether the product can safely use the public address as `account-scope`. When a local DB key must not reveal account relationships, use a stable opaque ID derived from a wallet-private key dedicated to the namespace. Keep this separate from the Reservation `indexKey` used for nullifier lookup so rotation and migration boundaries remain clear.

- Never read state from a different namespace as a fallback.
- When the account or chain changes, do not copy the old namespace's record into the new namespace.
- If schema/circuit/payload identity is incompatible, do not force-decode the old state; use a new namespace and full rescan.
- Multiple tabs for the same account share the same namespace and store-lock name. The current SDK does not serialize the full network scan across tabs, so use one scan leader or a separate coordinator.

The current ClairveilJS note-cache identity is `privacy-note-v1-cache-v1`, and the reservation-state identity is `privacy-note-v1-reservation-v1`. Both states also include `circuit_set_id: "privacy-note-v1"` and `payload_version: "privacy-fixed-v1"`. Keep DB schema version and these protocol identities as separate fields.

> **Clairveil v0.3.1 cutover rule:** The current `MemoryNoteStore` treats an
> incompatible cache identity as fresh state, and `IndexedDbReservationStore`
> also normalizes incompatible state to fresh state. This matches the intentional
> compatibility break in Clairveil v0.3.1. When switching to `privacy-note-v1` /
> `privacy-fixed-v1`, use a fresh genesis/reset, delete old note/reservation/scan/proof
> state, queued proof jobs, cached prepared payloads, and development artifacts,
> recreate the exact artifact set, and perform a full rescan. Do not import legacy
> state into the new namespace or keep it as a read-only production recovery source;
> do not fall back to decoding raw ciphertext or legacy JSON. Work that can be
> reconciled in the old runtime may be reconciled before the cutover, but this does
> not permit migration into the new protocol state.

## Encrypted record contract

### Recommended envelope

Store a strict envelope instead of plaintext state in an IndexedDB record.

```js
{
  envelopeVersion: 1,
  kind: "clairveil-note-store",
  namespace: "...",
  keyId: "wallet-db-key-v2",
  algorithm: "AES-GCM",
  iv: "<base64url 12-byte random nonce>",
  ciphertext: "<base64url ciphertext + authentication tag>"
}
```

The encryption implementation must follow these rules:

- Generate a new 96-bit AES-GCM IV with a CSPRNG on every write. Never reuse a key/IV pair.
- Authenticate the canonical encoding of `envelopeVersion`, `kind`, `namespace`, and `keyId` as AES-GCM `additionalData`.
- Derive the key per namespace with a reviewed KDF such as HKDF from wallet-private material or an OS/keychain-protected secret, and keep it as a non-extractable `CryptoKey` where possible.
- Never store the raw root signature or root seed in IndexedDB. The product defines the wallet-approval flow required to derive the key again.
- Strictly validate allowed envelope fields, lengths, algorithm, namespace, and version before decoding.
- Treat authentication failure, an unknown `keyId`, and JSON/schema errors as a store error, not as “no notes.”

If encryption fails and the app automatically creates an empty DB, users may see their balance disappear or reuse a note while ignoring an unresolved reservation. Stop initialization and provide a recovery or user-confirmed reset/full-rescan path.

## Production Note Store implementation

### Contract expected by the SDK

An app's Note Store can be injected as `noteStore` into the browser/Cosmos client when it implements the same methods as `MemoryNoteStore` from `clairveiljs/note-store`.

| Method | Store implementation requirement |
| --- | --- |
| `load()` | Read the encrypted record and return the current state after authentication, decoding, and state validation. |
| `save(state)` | The SDK type accepts a partial state patch. `MemoryNoteStore.save(...)` merges with current state and normalizes an incompatible identity to fresh state instead of throwing, so a production wrapper must validate the patch and identity separately before passing it through. |
| `clear()` | Delete without decoding existing ciphertext so even a corrupted record can be removed. Production UI must require explicit user confirmation. |
| `mergeScanResult(result, options)` | Merge and save existing notes and cursor in the same lock/transaction. |
| `rollbackToHeight(height)` | Roll back notes/cursor after a reorg height in one atomic change. |
| `markSpent(nullifiers)` | Atomically change notes for confirmed nullifiers. |
| `setNullifierStatuses(statuses)` | Atomically apply batch nullifier results. Do not treat a missing response as `unspent`. |

Rather than reimplement note merging and cursor rollback rules, wrap `MemoryNoteStore` as the note-shape and mutation engine. However, `MemoryNoteStore` is not a strict production state validator. Its constructor and `save(...)` normalize an incompatible cache identity to fresh state, and `save(...)` merges partial patches into current state. Therefore, the product must validate the encrypted envelope and persisted full state in `record.read()`, and validate incoming `save(...)` patches fail-closed in `record.validateSavePatch(...)`. Perform the intentional protocol-cutover reset in a separate new namespace; do not delegate a corrupted runtime record to this automatic normalization.

```js
import { MemoryNoteStore } from "clairveiljs/note-store";

// record is an encrypted IndexedDB abstraction implemented by the application.
// exclusive(): runs a callback inside the namespace's Web Lock
// read(): returns a strictly authenticated/decrypted NoteStoreState or null
// validateSavePatch(): strictly validates the partial save patch and optional identity fields
// write(): canonical-encodes, encrypts, and atomically puts hydrated NoteStoreState
// delete(): deletes the namespace record without decoding its ciphertext
export class EncryptedNoteStore {
  #owner;
  #record;

  constructor({ owner = "", record }) {
    this.#owner = owner;
    this.#record = record;
  }

  async #run(mutates, callback) {
    return this.#record.exclusive(async () => {
      const state = await this.#record.read();
      const memory = new MemoryNoteStore({
        owner: this.#owner,
        state: state ?? undefined
      });
      const result = await callback(memory);
      if (mutates) {
        await this.#record.write(await memory.load());
      }
      return result;
    });
  }

  load() {
    return this.#run(false, (store) => store.load());
  }

  save(state) {
    return this.#run(true, async (store) => {
      // This is an application record contract, not an SDK-exported validator.
      // It must run before MemoryNoteStore.save() so incompatible identities
      // cannot be silently normalized to fresh state and written.
      await this.#record.validateSavePatch(state);
      return store.save(state);
    });
  }

  mergeScanResult(result, options) {
    return this.#run(true, (store) => store.mergeScanResult(result, options));
  }

  rollbackToHeight(height) {
    return this.#run(true, (store) => store.rollbackToHeight(height));
  }

  markSpent(nullifiers) {
    return this.#run(true, (store) => store.markSpent(nullifiers));
  }

  setNullifierStatuses(statuses) {
    return this.#run(true, (store) => store.setNullifierStatuses(statuses));
  }

  clear() {
    return this.#record.exclusive(async () => {
      await this.#record.delete();
      return new MemoryNoteStore({ owner: this.#owner }).load();
    });
  }
}
```

`record.exclusive(...)` must cover the entire **read → MemoryNoteStore mutation → encrypted write**, not each read and write separately. In a browser, use a namespace-specific Web Lock together with an IndexedDB transaction. This lock serializes individual Note Store methods but not the entire network scan. Do not continue production functionality with a memory fallback in an environment that lacks Web Locks.

The current `scanWalletNotes(...)` reads the cursor from the Note Store, waits for the network scan outside the lock, and then calls `mergeScanResult(...)`. `MemoryNoteStore.mergeScanResult(...)` has no CAS comparing the starting cursor and no stale-result rejection. Two tabs scanning the same namespace can therefore finish out of order and let an older result lower the latest `scanCursor`. A production product must use a tab leader/single-writer queue or a scan-coordinator lock with a different name to serialize **the entire call from cursor load through network scan and final merge**. Do not assume the current SDK provides this coordinator automatically.

A large wallet DB can also be normalized into one record per note. Even then, the `NoteStoreState` snapshot returned to the SDK and the cursor update must be made consistent in one IndexedDB transaction, and duplicate commitment/nullifier and rollback rules must be tested.

### Scan cursor and reorg

- Commit scan-result notes together with the complete wire `(height, global_sequence, output_index)` cursor. Never save the cursor before all outputs and nullifier state through that cursor are durable.
- Do not allow concurrent scan completion in one namespace. The current merge does not automatically reject stale cursors or perform a monotonic CAS.
- Do not treat the cursor from an intermediate page with `has_more: true` as the completed scan cursor.
- If a nullifier response is missing or malformed, do not promote the note to `unspent`.
- When a reorg is detected, run `rollbackToHeight(...)` under the same namespace lock and rescan from that height.
- Do not automatically delete linked reservations when rolling back notes. Reconcile active reservations with separate evidence.
- When protocol/cache identities are incompatible, choose a new namespace and full rescan over permissive migration.

## Production Reservation Store implementation

In a browser, use the IndexedDB adapter provided by the SDK and inject an application-owned encryption codec for the full state.

```js
import {
  createBrowserReservationStore,
  createNoteReservationManager
} from "clairveiljs/reservation";

const reservationStore = createBrowserReservationStore({
  dbName: "clairveil-reservations",
  namespace: reservationNamespace,
  requireLocks: true,
  encodeState: (state) => reservationCodec.encrypt(state),
  decodeState: (record) => reservationCodec.decryptAndValidate(record)
});

const reservationManager = createNoteReservationManager({
  store: reservationStore,
  ownerKeyId,
  indexKey: rootSeed,
  nullifierLookupKeyId: "privacy-root-v1",
  leaseOwner: `browser-tab:${crypto.randomUUID()}`
});
```

`reservationCodec` is not a ClairveilJS export; it is an AEAD codec implemented and reviewed by the product. `encodeState` and `decodeState` must authenticate and encrypt the entire `ReservationStoreState`, not only selected metadata. `decryptAndValidate(...)` must check the current reservation `version`, `circuit_set_id`, and `payload_version` in addition to authentication, and throw on mismatch.

The `reservationNamespace` in the example is built from the chain/profile/wallet/account scope described above, and `ownerKeyId` is a stable opaque ID for the wallet owner. Use `rootSeed` only from the currently approved wallet session's memory; do not store it in the DB.

- Keep `requireLocks` set to `true` in production.
- Create a new random `leaseOwner` for every tab/process start and never share lease tokens with another tab. The SDK also creates a random owner when omitted, but an opaque prefix containing the process type can help operations diagnostics.
- `indexKey` is the wallet-private key used to derive `nullifier_lookup_key` from a private nullifier. Do not replace it with a public account ID.
- `nullifierLookupKeyId` identifies the index-key version. It has a different purpose from the encryption envelope's `keyId`.
- Do not overwrite records directly; use the batch, lease, CAS, broadcast, and reconciliation helpers from `createNoteReservationManager(...)`.

For a backend or desktop adapter, implement the `ReservationStore` interface. A database transaction or equivalent atomicity must guarantee:

- Only one active reservation exists for the same `owner_key_id + nullifier_lookup_key`.
- Status changes use compare-and-set and cannot bypass lease-token or evidence guards.
- Batch reserve/release/transition operations either all succeed or all roll back.
- `Submitted`, `Unknown`, and `ManualReview` are not ordinary expiration-cleanup targets.

## Key rotation and migration

Do not handle different changes as one generic “key rotation.”

| Change | Safe handling |
| --- | --- |
| Rotate the store-encryption key | Identify the old key with envelope `keyId`, authenticate/decrypt it, and re-encrypt under the new key inside the namespace lock. Preserve the old ciphertext if migration fails. |
| Rotate `indexKey` | Every reservation lookup key changes. Perform an explicit migration that preserves active reservations and the old `nullifier_lookup_key_id`; do not handle this as a simple configuration change. |
| DB schema change | Test strict versioned decoders and one-way migrations separately. Do not overwrite in place without an original backup or rollback path. |
| App DB schema/key change within the same protocol identity | A strict decoder and reviewed one-way migration may be used. Preserve active reservations and transaction evidence. |
| Protocol switch to `privacy-note-v1` / `privacy-fixed-v1` | Follow the Clairveil v0.3.1 contract: fresh genesis/reset, delete incompatible state/jobs/artifacts, and full rescan. Do not provide legacy decoding or in-place migration. |
| Future circuit/payload/cache identity change | Unless the Clairveil release handoff explicitly permits migration, treat it as incompatible and use a fresh namespace/reset and full rescan. |

For a normal user reset, do not combine Note Store reset and Reservation Store reset behind one button. Deleting unresolved reservations requires a separate warning, exportable diagnostic evidence, and manual confirmation. The exception is a protocol cutover that explicitly requires a fresh reset; in that deployment procedure, remove old note, reservation, scan, proof state, and artifacts together.

Before a protocol cutover, query non-terminal reservations in the old runtime and reconcile available transaction/nullifier evidence. Once the cutover starts, do not open the old encrypted DB as a compatibility source in the new runtime or import reservations. Build the new fresh-genesis inventory only through a canonical `privacy-scan-v2` full rescan.

## Account changes and asynchronous work

When the wallet account, profile, or chain changes, follow this order:

1. Stop existing scans, prover polling, and reservation heartbeats.
2. Invalidate the current session generation.
3. Close DB handles and memory caches for the old namespace.
4. Derive the namespace and encryption/index keys after approving the new wallet session.
5. Validate the new namespace state, complete required scan/reconciliation, and only then display spendable inventory.

Every long-running async task must verify after each `await` that the chain/account/session generation from its start still matches the current value. A scan or prover callback that completes late for the old account must not write to the new account's DB.

## Restart and disaster recovery

On app startup, open the stores and inspect active reservations first.

1. If `Submitted` or `Unknown` has a network `tx_hash`, query the Cosmos transaction or EVM receipt through the transport-specific lookup API.
2. Cosmos `tx_bytes_hash` is the SHA-256 of the exact signed TxRaw and can verify the preserved signed bytes against network identity. EVM `tx_bytes_hash` is a pre-signing canonical request binding created by `evmTransactionBindingHash(...)`; do not use it as the lookup key for `eth_getTransactionByHash` or `eth_getTransactionReceipt`.
3. If an EVM record has no network `tx_hash`, do not conclude that the transaction is absent from the binding hash alone. Check wallet/relayer operation records and nullifier/output/event evidence together; if evidence is insufficient, keep the reservation in `Unknown` or `ManualReview`.
4. Batch-query the linked input nullifiers.
5. If a nullifier is spent, set `ConfirmedSpent`, but determine payment/operation success separately from output evidence.
6. Consider `Failed` or `ReplanRequired` only after the correct network identity confirms transaction failure/absence and the nullifier is confirmed unused.
7. Keep the reservation in `ManualReview` when evidence is insufficient or conflicting.

To resume an async prover job, relay handoff, or batch callback after restart, store only the opaque job ID, request/payload hash, artifact identity, and reservation ID in a separate encrypted checkpoint. Avoid storing the raw private prover payload where possible, and delete the checkpoint only after terminal reconciliation.

## Recommended forms by implementation

| Environment | Note Store | Reservation Store | Key custody |
| --- | --- | --- | --- |
| Browser DApp/extension | Encrypted IndexedDB + store Web Lock + one scan leader per namespace | `createBrowserReservationStore(...)` + AEAD codec | Non-extractable Web Crypto key derived after wallet re-approval |
| Desktop wallet | Encrypted column in SQLite/embedded DB or an encrypted DB | Separate table with transaction/CAS support | OS Keychain/KeyStore/secure enclave integration |
| Backend relayer | In principle, do not store decrypted notes | Store only required relay operation/evidence in a transaction DB | KMS/HSM and service-identity-specific key |

If a relayer is extended to act as the wallet Note Store, the trust model changes. It is no longer an ordinary endpoint proxy and requires a separate security review as a custody or server-backed wallet design.

## Verification checklist

Automate at least these tests:

- Note amount, randomness, nullifier, and private material do not appear in raw IndexedDB data or logs.
- Saving the same state twice produces different IVs and ciphertexts.
- A wrong key, modified ciphertext/AAD, or unknown version stops with an authentication error.
- A corrupted record is not automatically converted into an empty wallet.
- Two tabs in the same namespace cannot reserve the same note concurrently.
- A different chain/account namespace cannot read the other namespace's state.
- A crash while saving a scan page does not leave notes and cursor pointing to different heights.
- After a reorg rollback, notes/cursor recover but unresolved reservations are not automatically deleted.
- After restart, input notes from `Submitted`/`Unknown` are not reused before on-chain evidence reconciles them.
- `LocalStorageNoteStore` and unsafe reservation options are rejected by production build/configuration.
- If key rotation fails, rollback to the old ciphertext is possible and active reservation identity remains intact.
- A callback started before an account change cannot write to the new namespace.
- During `privacy-note-v1` / `privacy-fixed-v1` cutover, old note/reservation/scan/proof state and artifacts are deleted and cannot be reopened through a legacy decoder or in-place migration.
- The complete `(height, global_sequence, output_index)` scan cursor is part of the same atomic commit as note/output persistence.
- Concurrent scans in one namespace are blocked, and deliberately reversed scan completion cannot let an old cursor overwrite a newer cursor.

## Implementation references

- Note Store state and invariants: `src/privacy/note-store.js`, `src/privacy/note-store.d.ts`
- Reservation Store, Web Locks, leases, and CAS: `src/privacy/reservation.js`, `src/privacy/reservation.d.ts`
- Browser client Note Store/reservation wiring: `src/browser/wallet-client.js`, `src/browser/wallet-client.d.ts`
- Scan cursor and nullifier checks: `src/privacy/scan.js`, `src/privacy/scan.d.ts`
