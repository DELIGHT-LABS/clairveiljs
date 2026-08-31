# Note Reservation State Transitions

## Purpose

This document describes the complete lifecycle in which a private note enters the scan inventory, is planned, proved, submitted, and reconciled, together with the **reservation states** that ClairveilJS persists to prevent duplicate use.

`Discovered` and `Available` are conceptual pre-states from the scan/inventory perspective. They are part of the state vocabulary and transition contract, but a new persisted reservation record created by `reserveNotes(...)` or `reservePlan(...)` must always start at `Reserved`. Therefore, the normal persisted lifecycle in the Reservation Store is `Reserved → Proving → ProofReady → Submitted → ConfirmedSpent`.

These states describe safely locking and releasing a particular note while it is being planned, proved, submitted, and reconciled; they do not describe whether the payment itself succeeded. `operation_status` is separate metadata and must not be confused with the states in this document.

## State graph

![ClairveilJS Note Reservation Lifecycle State Diagram](./assets/note-reservation-lifecycle.svg)

The top shows normal flow and the bottom shows exception/recovery paths. `Discovered → Available` is conceptual; persistence begins at `Reserved`, and dotted boxes alias states elsewhere in the graph. There is no `Proving → Released` shortcut: uncertain preparation after proof execution may have started is isolated instead of reused.

Regenerate and commit the diagram with `npm run docs:diagram:reservation`; build and install do not generate it. The generator verifies all 34 `allowedReservationTransitions` exactly once and writes nothing on mismatch. `npm run docs:diagram:check` compares without overwriting.

## Meaning of the main states

| State | Meaning | Important note |
| --- | --- | --- |
| `Discovered` | A conceptual state for a note found by scan but not yet confirmed as spendable inventory | It is not created as a new persisted reservation record. A validation failure is conceptually `Failed`. |
| `Available` | A verified note that can be used for planning | It is not created as a new persisted reservation record. When selected, the manager creates a `Reserved` record. |
| `Reserved` | The selected note is held by a durable inventory lock | This is the start of the persisted reservation lifecycle. There is no worker lease yet, and cancellation can move it to `Released`. |
| `Proving` | A batch lease has been acquired for prover execution | This state requires a lease token. An uncertain preparation failure is quarantined in `ManualReview`; it is not automatically released. |
| `ProofReady` | The proof and prepared payload are ready | Proof disposal before broadcast, wallet rejection, and relay handoff must be recorded and handled safely. |
| `Submitted` | Submission metadata has been recorded by the manager | A reservation tagged with `execution_transport: "evm"` requires a network `txHash`. Legacy or external records require either `txHash` or `txBytesHash`. `signDocHash` alone is insufficient. |
| `Unknown` | The transaction may have reached the network, but the result cannot be determined | Reconcile the transaction and nullifier state before retransmitting. |
| `ConfirmedSpent` | Consumption of the input note has been confirmed by on-chain evidence | This is a terminal state. |
| `ReplanRequired` | A new transaction plan is required | A new plan starts again at `Reserved`. |
| `ManualReview` | An isolated state in which the note must not be reused based on automatic judgment | Operator approval and review of chain/payload history are required. |
| `Released` | The lock on the current persisted reservation has been released | From the note-inventory perspective it is available again, and the next high-level plan can start with a new `Reserved` record. |
| `Failed` | The current path failed | Move to `ReplanRequired` when a new plan is needed. |

The graph matches `allowedReservationTransitions`, but new records start at `Reserved` and the compatibility-named `releaseReservedOrProving(...)` releases only that state. The v0.3.1 fixture still rejects `Proving → Released`.

## Reservation state and operation result

`ConfirmedSpent` means that the input note's nullifier was used on chain. It does not by itself mean that the payment or payroll item succeeded.

High-level preparation records `execution_transport` at `ProofReady`. Cosmos retains the sign-doc binding, while EVM retains the prepared request's `tx_bytes_hash`. EVM operation success requires the stored network `submitted_tx_hash` and `tx_bytes_hash` to match their respective reconciliation evidence, plus an explicitly successful receipt, exact RPC transaction-identity verification, action-specific privacy-event verification, finality verification, and matching expected output evidence. An EVM `txBytesHash` alone cannot establish success. Untagged legacy records retain the generic matcher for compatibility. If evidence is incomplete, the reservation may remain isolated as spent while the operation is placed in `ManualReview`; an explicit mismatch becomes `ConflictSpent`.

| Category | Representative state | Meaning |
| --- | --- | --- |
| Reservation status | `Reserved`, `ProofReady`, `ConfirmedSpent` | Safely locks each input note and tracks whether it was consumed. |
| Operation status | `Planned`, `Submitted`, `Succeeded`, `ConflictSpent` | Tracks the result of a transaction or payment containing multiple inputs/outputs. |

Multiple reservations linked to the same `operation_id` must have lifecycle states that agree atomically. If only some inputs move to another state, handle it as `OPERATION_STATE_MIXED`; output evidence conflicts are reported as `OPERATION_EVIDENCE_CONFLICT`.

## State-change APIs

The manager API table below covers the persisted reservation lifecycle that starts at `Reserved`. `reserveNotes(...)` and `reservePlan(...)` do not persist `Discovered` or `Available` records.

| API | State change or effect | Conditions checked by the current implementation |
| --- | --- | --- |
| `reserveNotes(...)` / `reservePlan(...)` | Atomically creates a `Reserved` record for the selected note | No active reservation may already block the same note. |
| `markProving(...)` | `Reserved → Proving` | A batch lease token issued by the manager |
| `markProofReady(...)` / `markProofReadyBatch(...)` | `Proving → ProofReady` | A valid lease and payload/proof binding evidence |
| `heartbeatLease(...)` / `renewLease(...)` | Keeps the state and extends the lease | A current, unexpired lease owned by the manager |
| `recordRelayHandoff(...)` | Keeps `ProofReady` and records relay payload handoff evidence | Matching payload hash, before broadcast begins, with a valid lease |
| `recordRelayTransactionEvidence(...)` | Atomically moves every reservation in one relay operation from `ProofReady` to `Submitted` | Exact payload transaction inclusion and either a recorded external handoff or durable same-origin local-relay attempt. This lease-free API records transaction evidence only; reconciliation decides success/release. |
| `markBroadcastAttempting(...)` | Keeps `ProofReady` and records `broadcast_in_flight` and the attempt count | Call immediately before crossing the external broadcast boundary, with a valid lease |
| `markSubmitted(...)` | `ProofReady → Submitted` | A prior `markBroadcastAttempting(...)` record and a valid lease. An EVM-tagged reservation requires a network `txHash`; other records accept `txHash` or `txBytesHash`. |
| `markUnknown(...)` | `ProofReady/Submitted → Unknown` | A prior broadcast attempt, a valid lease, and either `txHash` or `txBytesHash`. `signDocHash` alone is insufficient. |
| `markBroadcastRejected(...)` | `ProofReady → ReplanRequired` | The wallet rejected before broadcast and proof disposal can be recorded. |
| `markBroadcastFailed(...)` | `ProofReady/Submitted/Unknown → ReplanRequired` | Exact failed/absent transaction identity and every input explicitly unspent. Live `ProofReady` also needs the current matching, unexpired manager lease; `Submitted`/`Unknown` are lease-free. |
| `recoverExpiredProofReadyBroadcastFailure(...)` | `ProofReady → ReplanRequired` | Complete operation, expired lease, complete stored network-tx/tx-bytes/sign-doc identity, positive height, confirmed execution failure (not absence), exact raw input-nullifier set, and all inputs unspent; atomic and idempotent across restart. |
| `markReplanRequired(...)` | Moves an allowed source state to `ReplanRequired` | Source-specific evidence for proof disposal, expiry, nullifier state, and transaction failure |
| `transitionBatch(...)` | Atomically applies an allowed generic transition to multiple reservations | A low-level CAS API for transitions without a dedicated helper. It applies the allowed-transition, lease, and source-specific evidence rules unchanged. |
| `releaseReservedOrProving(...)` | `Reserved → Released` | Compatibility name retained; `Proving` is rejected rather than released |
| `markManualReview(...)` | Moves an allowed source state to `ManualReview` | The current lease is required for source states that require a lease. |
| `resolveManualReview(...)` | `ManualReview → Released/ReplanRequired/Failed` | `operatorId`, `approvalReference`; recording `reason` is recommended |
| `reconcileSpentNotes(...)` | Moves an allowed state to `ConfirmedSpent`, or quarantines/determines operation success from evidence | Literal spent evidence and required output evidence. An EVM tag requires the network `txHash`, artifact `txBytesHash`, successful receipt, RPC call identity, privacy-event verification, and finality verification. |

## Safety rules

1. The conceptual note-use flow is `Discovered → Available → Reserved → Proving → ProofReady → Submitted → ConfirmedSpent`. The normal persisted reservation path starts at `Reserved`.
2. `Proving` and `ProofReady` retain a worker lease. For an expired lease, use reconciliation, `ManualReview`, or the evidence-gated expired-`ProofReady` recovery API, not a generic transition.
3. If the wallet rejects at `ProofReady` or the proof is discarded, move to `ReplanRequired` only when disposal of the proof can be evidenced. Otherwise isolate the reservation in `ManualReview`.
4. Moving `Submitted`/`Unknown` to `ReplanRequired`/`Failed` requires both an unused input nullifier and an absent/failed recorded transaction. Live `ProofReady` also needs the current manager-owned, unexpired lease so inputs cannot be released under an active submitter.
5. After handing a relay payload to a relayer, do not release the note based only on TTL expiry or local cancellation. Reconcile with on-chain evidence, including the possibility that the relayer submitted it.
6. Resolving `ManualReview` requires `operatorId` and `approvalReference`; recording `reason` is recommended for the operational audit trail. The allowed outcomes are `Released`, `ReplanRequired`, and `Failed`; there is no direct transition back to `ProofReady`.
7. Do not use `ConfirmedSpent` and operation `Succeeded` as synonyms. Reconcile every linked reservation and all output evidence for a multi-input operation.
8. On preparation failure, `rollbackPlanReservation(...)` releases only `Reserved`; with a valid lease it quarantines `Proving`/`ProofReady` in `ManualReview`, otherwise the operation stays locked for reconciliation.

## Implementation references

- State definitions and allowed transitions: `src/privacy/reservation.js`
- Manager APIs and per-transition input conditions: `src/privacy/reservation.d.ts`
- Reservation operations in the browser DApp: the `Note reservation` section of `README.md`
