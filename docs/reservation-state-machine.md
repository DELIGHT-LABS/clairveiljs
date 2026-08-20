# Note Reservation State Transitions

## Purpose

This document describes the complete lifecycle in which a private note enters the scan inventory, is planned, proved, submitted, and reconciled, together with the **reservation states** that ClairveilJS persists to prevent duplicate use.

`Discovered` and `Available` are conceptual pre-states from the scan/inventory perspective. They are part of the state vocabulary and transition contract, but a new persisted reservation record created by `reserveNotes(...)` or `reservePlan(...)` must always start at `Reserved`. Therefore, the normal persisted lifecycle in the Reservation Store is `Reserved → Proving → ProofReady → Submitted → ConfirmedSpent`.

These states describe safely locking and releasing a particular note while it is being planned, proved, submitted, and reconciled; they do not describe whether the payment itself succeeded. `operation_status` is separate metadata and must not be confused with the states in this document.

## State graph

![ClairveilJS Note Reservation Lifecycle State Diagram](./assets/note-reservation-lifecycle.svg)

The top shows the normal flow, while the bottom shows source-state-specific exception and recovery paths. The top `Discovered → Available` path is the conceptual pre-flow for note inventory; the persisted reservation lifecycle starts at the `Available → Reserved` boundary. The dotted boxes at the bottom point to the same states shown in the top or another card and are not separate states. `Proving → Released`, marked `SPECIAL`, is a ClairveilJS store-specific atomic release path that verifies a valid lease token; it is not a generic transition. The generic transition table in the Clairveil v0.3.1 fixture rejects this transition, so `SPECIAL` in the diagram does not mean that it is identical to the upstream generic transition. It denotes behavior additionally provided by the current SDK.

The diagram is intentionally regenerated with `npm run docs:diagram:reservation`, and the resulting SVG is committed. It is not generated automatically during build or package install. The generator reads `allowedReservationTransitions` from `src/privacy/reservation.js`, verifies that all 34 generic transitions are included exactly once, and fails without writing the SVG if they do not match. This check does not verify whether the separate store helper for `Proving → Released` matches the upstream fixture. `npm run docs:diagram:check` compares the committed SVG with the generated result without overwriting it.

## Meaning of the main states

| State | Meaning | Important note |
| --- | --- | --- |
| `Discovered` | A conceptual state for a note found by scan but not yet confirmed as spendable inventory | It is not created as a new persisted reservation record. A validation failure is conceptually `Failed`. |
| `Available` | A verified note that can be used for planning | It is not created as a new persisted reservation record. When selected, the manager creates a `Reserved` record. |
| `Reserved` | The selected note is held by a durable inventory lock | This is the start of the persisted reservation lifecycle. There is no worker lease yet, and cancellation can move it to `Released`. |
| `Proving` | A batch lease has been acquired for prover execution | This state requires a lease token. The current general prepare helper can atomically roll back a valid lease to `Released` when preparation fails. |
| `ProofReady` | The proof and prepared payload are ready | Proof disposal before broadcast, wallet rejection, and relay handoff must be recorded and handled safely. |
| `Submitted` | Submission metadata has been recorded by the manager | The low-level manager does not distinguish transports and requires either `txHash` or `txBytesHash`. `signDocHash` alone is insufficient. |
| `Unknown` | The transaction may have reached the network, but the result cannot be determined | Reconcile the transaction and nullifier state before retransmitting. |
| `ConfirmedSpent` | Consumption of the input note has been confirmed by on-chain evidence | This is a terminal state. |
| `ReplanRequired` | A new transaction plan is required | A new plan starts again at `Reserved`. |
| `ManualReview` | An isolated state in which the note must not be reused based on automatic judgment | Operator approval and review of chain/payload history are required. |
| `Released` | The lock on the current persisted reservation has been released | From the note-inventory perspective it is available again, and the next high-level plan can start with a new `Reserved` record. |
| `Failed` | The current path failed | Move to `ReplanRequired` when a new plan is needed. |

The generic state transitions in the graph match the full lifecycle vocabulary in `allowedReservationTransitions`. However, the contract for creating a new record is narrower and allows only `Reserved`. `Proving → Released` is not applied by generic `transitionBatch(...)`; it is the atomic release path in `releaseReservedOrProving(...)`, which verifies a valid lease token. It is a separate exception implemented by the ClairveilJS store, not an addition of the v0.3.1 fixture's rejected transition to the generic table.

## Reservation state and operation result

`ConfirmedSpent` means that the input note's nullifier was used on chain. It does not by itself mean that the payment or payroll item succeeded.

The current generic matcher in `reconcileSpentNotes(...)` does not store or distinguish the transport. If one of the stored `submitted_tx_hash` or `tx_bytes_hash` values matches the same identity in reconciliation evidence, and the expected output commitment, disclosure digest, recipient/amount/denom evidence all match, the operation can be considered successful. Therefore, an EVM `txBytesHash`, which is a pre-signing canonical request binding, is also treated as an identity match inside the manager. The high-level EVM send helper records the network `txHash` returned by the wallet in `Submitted`, but a policy that requires an EVM receipt or RPC identity must be enforced separately by the caller's operation database or reconciliation input validation. If evidence is incomplete, the reservation may remain isolated as spent while the operation is placed in `ManualReview`; an explicit mismatch becomes `ConflictSpent`.

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
| `markBroadcastAttempting(...)` | Keeps `ProofReady` and records `broadcast_in_flight` and the attempt count | Call immediately before crossing the external broadcast boundary, with a valid lease |
| `markSubmitted(...)` | `ProofReady → Submitted` | A prior `markBroadcastAttempting(...)` record, a valid lease, and either `txHash` or `txBytesHash`. The manager does not distinguish transport or hash meaning. |
| `markUnknown(...)` | `ProofReady/Submitted → Unknown` | A prior broadcast attempt, a valid lease, and either `txHash` or `txBytesHash`. `signDocHash` alone is insufficient. |
| `markBroadcastRejected(...)` | `ProofReady → ReplanRequired` | The wallet rejected before broadcast and proof disposal can be recorded. |
| `markReplanRequired(...)` | Moves an allowed source state to `ReplanRequired` | Source-specific evidence for proof disposal, expiry, nullifier state, and transaction failure |
| `transitionBatch(...)` | Atomically applies an allowed generic transition to multiple reservations | A low-level CAS API for transitions without a dedicated helper. It applies the allowed-transition, lease, and source-specific evidence rules unchanged. |
| `releaseReservedOrProving(...)` | `Reserved/Proving → Released` | `Proving` requires the current batch lease token |
| `markManualReview(...)` | Moves an allowed source state to `ManualReview` | The current lease is required for source states that require a lease. |
| `resolveManualReview(...)` | `ManualReview → Released/ReplanRequired/Failed` | `operatorId`, `approvalReference`; recording `reason` is recommended |
| `reconcileSpentNotes(...)` | Moves an allowed state to `ConfirmedSpent`, or quarantines/determines operation success from evidence | Literal spent evidence, a match for one stored `txHash`/`txBytesHash`, and required output evidence. Network identity requirements specific to a transport are not enforced here. |

## Safety rules

1. The conceptual note-use flow is `Discovered → Available → Reserved → Proving → ProofReady → Submitted → ConfirmedSpent`. The normal persisted reservation path starts at `Reserved`.
2. `Proving` and `ProofReady` retain a worker lease. Do not advance a state with an expired lease; use reconciliation or `ManualReview`.
3. If the wallet rejects at `ProofReady` or the proof is discarded, move to `ReplanRequired` only when disposal of the proof can be evidenced. Otherwise isolate the reservation in `ManualReview`.
4. To move `Submitted` or `Unknown` to `ReplanRequired` or `Failed`, confirm both that the input nullifier is unused and that the recorded transaction is absent or failed. A single failure response is not enough for either transition.
5. After handing a relay payload to a relayer, do not release the note based only on TTL expiry or local cancellation. Reconcile with on-chain evidence, including the possibility that the relayer submitted it.
6. Resolving `ManualReview` requires `operatorId` and `approvalReference`; recording `reason` is recommended for the operational audit trail.
7. Do not use `ConfirmedSpent` and operation `Succeeded` as synonyms. Reconcile every linked reservation and all output evidence for a multi-input operation.
8. The current general prepare helper calls `rollbackPlanReservation(...)` when prover/payload preparation fails. A valid `Proving` reservation is directly released in this path; that is not evidence that a remote solver or async job actually stopped.

## Implementation references

- State definitions and allowed transitions: `src/privacy/reservation.js`
- Manager APIs and per-transition input conditions: `src/privacy/reservation.d.ts`
- Reservation operations in the browser DApp: the `Note reservation` section of `README.md`
