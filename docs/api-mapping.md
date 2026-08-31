# ClairveilJS API Mapping

## Purpose and scope

This document traces how the ClairveilJS APIs called by a browser DApp map to actual **chain REST/RPC**, **prover HTTP contracts**, **Cosmos messages**, and the **EVM privacy precompile**.

It covers high-level flows that communicate with external systems or create transactions, rather than a complete symbol reference for pure crypto, codec, and schema helpers. The package export map's TypeScript declarations are the source of truth for the complete arguments and return types of each method.

- System deployment and trust boundaries: [System architecture](./architecture.md)
- Preventing duplicate note use and recovering after submission: [Note Reservation State Transitions](./reservation-state-machine.md)
- Endpoint and client options: [Deployment and client configuration](./configuration.md)
- Error forms and retry decisions: [Errors and recovery](./errors-and-recovery.md)

## Contract categories

| Category | Meaning | Example |
| --- | --- | --- |
| SDK-fixed contract | ClairveilJS and the Clairveil protocol fix the route, shape, and version. | `/clairveil/privacy/v1/privacy_scan`, `/v1/prover/transfer`, Cosmos message type URLs |
| Profile-fixed endpoint | The product places an exact reviewed URL in the profile and the SDK calls only that URL. | `depositProofUrl` |
| Injected adapter | The caller provides the function implementation; ClairveilJS assumes no fixed HTTP route. | local/WASM prover, submit/poll functions for `createAsyncJobProverAdapter(...)` |
| Product-defined API | The product defines authentication, fees, queueing, and URLs. It is not a common ClairveilJS server contract. | relay-withdraw handoff, DApp proxy route |

`/v1/prover/transfer`, `/v1/prover/withdraw`, and `/v1/proofs/batch-transfer` are not chain REST endpoints from `clairveil.d`. The **browser's ClairveilJS** makes these requests directly to `proverUrl` when the default HTTP prover adapter is selected. A request passes through a DApp proxy only when `proverUrl` points to that proxy.

## Clairveil v0.3.1 fixed contract

This document and the SDK support the current Clairveil `v0.3.1` SDK handoff,
commit `0ff92839872de26b787a60d8e4d5822cc459855b`. The values below are not deployment-profile
settings; they are protocol contracts fixed by the conformance fixtures and consensus
identity.

| Contract | Fixed value |
| --- | --- |
| Active circuit set | `privacy-note-v1`, BN254, required order `deposit` → `spend` → `joinsplit` → `batch-joinsplit-16x32-v1` |
| Public-input schema SHA-256 | `deposit`: `c3231fb5ae62539d2e4baeb78aa4be8a4c44e3cd8fa325ba60f13b7f563d5a1e`; `spend`: `d0a033aa2f7b6e098873307a815545ee3e83d974026c0e52bf39a038e08f4872`; `joinsplit`: `4946e23db34529c6fce0a95ce69f6df08563a305ddcc70c7b6b786471e03aa82`; batch: `5606327d69dcb06c00811f2135291d39a2ea1cedf554f114f7eb4a178098d333` |
| Canonical binary encoding | `privacy-fixed-v1`; `NotePlaintextV1` 350 bytes, `DisclosurePlaintextV1` 392 bytes, typed envelope header 20 bytes |
| Transfer | prepared payload `v5`; proof/request/response `v2` |
| Withdraw | prover/final payload and proof/request/response all `v2`; no output-note field |
| Relay withdraw | handoff/schema `v2`; separates relayer `creator` from the owner-bound recipient |
| One-Proof batch | payload `batch-transfer-payload-v1`, proof `batch-transfer-proof-v1`, request/response `v1`; executes as Cosmos `MsgBatchTransfer` or EVM `singleProofBatchTransfer` |

Public inputs are used in the following order without sorting or renaming their names.

- Deposit, 3: `Commitment`, `Amount`, `AssetID`.
- Native transfer / JoinSplit, 13: `MerkleRoot`, `ChainDomainHi`, `ChainDomainLo`, `ExpiresAtUnix`, `Nullifier0`, `Nullifier1`, `Commitment0`, `Commitment1`, `UserPrivacyPolicy`, `UserDisclosureDigest`, `FullDisclosureDigest`, `PayloadDigestHi`, `PayloadDigestLo`.
- Withdraw / Spend, 9: `MerkleRoot`, `ChainDomainHi`, `ChainDomainLo`, `ExpiresAtUnix`, `Nullifier`, `Amount`, `RecipientDigestHi`, `RecipientDigestLo`, `AssetID`.
- BatchJoinSplit16x32, 12: `MerkleRoot`, `ChainDomainHi`, `ChainDomainLo`, `ExpiresAtUnix`, `InputCount`, `OutputCount`, `NullifierRoot`, `CommitmentRoot`, `UserDisclosureRoot`, `FullDisclosureRoot`, `PayloadDigestHi`, `PayloadDigestLo`.

Use only `AssetRegistryV1` as the authoritative source for denom/asset-ID mapping, and fail closed on missing entries, collisions, or inconsistent bidirectional mappings. Audit disclosure is required, and sender self-view is included by default with explicit opt-out. Native transfer uses exactly two 2-byte view tags; a tag is an untrusted hint, so the default scan attempts full decryption even on a mismatch. Transfer/withdraw `creator` is replaceable, but output, disclosure, recipient, chain, and expiry are bound to owner intent/proof.

Raw ciphertext, legacy JSON plaintext, wrong envelope kind, non-zero reserved bytes, trailing bytes, and cross-kind decoding are rejected without compatibility fallback. Clairveil v0.3.1 is `PUBLICATION_READY_EXPERIMENTAL`; implementing this contract alone does not close the production release gates.

## End-to-end task mapping

| User task | Main SDK API | Queries during preparation | Proof contract | Prepared result | Signing/final submission | Completion criterion |
| --- | --- | --- | --- | --- | --- | --- |
| Deposit | `prepareDeposit(...)` | Circuit config, asset mapping; Cosmos sign doc also queries account metadata | Local/WASM `depositProofProvider` or exact `depositProofUrl` | Cosmos `MsgDeposit` sign doc or EVM `IPrivacy.deposit` transaction | User Cosmos wallet or EIP-1193 wallet | Both profiles preserve the exact commitment and `encryptedNoteHex`. Cosmos uses `confirmDeposit(...)`; EVM uses `waitForEvmTransaction(...)` to verify the exact RPC call and `PrivacyDeposit` event. |
| Note scan | `scanWalletNotes(...)`, `queryPrivacyScan(...)` | Typed privacy scan and nullifier state | None | Verified found note, cursor, and nullifier status | No submission | Malformed pages or ambiguous nullifiers are not treated as spendable. |
| Native transfer | `prepareTransfer(...)` | Scan, circuit/asset/audit/disclosure config, same-root path, nullifier state | `POST /v1/prover/transfer` | Cosmos `MsgTransfer` sign doc or EVM `IPrivacy.transfer` transaction | User wallet | Reconcile tx identity, input nullifier, and expected output/disclosure evidence. |
| One-Proof Batch Transfer | `prepareTransferBatch(...)`, `provePreparedBatchTransfer(...)`, `finalizePreparedBatchTransfer(...)` | Typed scan, protocol config, same-root path snapshot, every input nullifier | `POST /v1/proofs/batch-transfer` | Cosmos `MsgBatchTransfer` sign doc or EVM `singleProofBatchTransfer` transaction with optional EIP-712 authorization | User Cosmos/EVM wallet | Atomically reconcile every input nullifier, the exact transaction binding, and every typed output evidence for the same operation. |
| Direct withdraw | `prepareWithdraw(...)` | Scan, circuit/asset config, Merkle path, nullifier state | `POST /v1/prover/withdraw` | Cosmos `MsgWithdraw` sign doc or EVM `IPrivacy.withdraw` transaction | User wallet | Check tx/receipt, nullifier, and withdraw evidence. |
| Relay withdraw | `prepareRelayWithdraw(...)` | Same as direct withdraw | `POST /v1/prover/withdraw` | Final relay payload; EVM also returns a candidate `IPrivacy.withdraw` transaction | Product Relayer reconstructs/validates a transaction from the payload and submits using its own account | Call `recordRelayHandoff(...)` before handoff, then reconcile with tx/nullifier/evidence. |
| Disclosure query | `decodeUserDisclosure(...)`, `decodeSelfViewDisclosure(...)`, `decodeAuditDisclosure(...)`, batch decode APIs | Privacy event, scan event, or typed privacy scan | None | Locally verified and decrypted disclosure report | No submission | Commitment, output index, policy, digest, and target key must all match for `verified`. |

The fact that `prepare*` returned does not mean that the transaction was submitted or succeeded. A Cosmos sign doc or EVM transaction is a `ProofReady` artifact until it crosses the wallet/relayer boundary; after submission, apply the evidence rules in [Note Reservation State Transitions](./reservation-state-machine.md).

## Prover and deposit-proof mapping

| SDK API / adapter | HTTP target | Request contract | Response contract | Flow |
| --- | --- | --- | --- | --- |
| `createHttpDepositProofProvider({ url })` | `POST <profile.depositProofUrl>` | `{ note_json, note_commitment_hex }` | `version: "v1"`, `proof_hex`, same `note_commitment_hex` | Deposit only. Redirects are not allowed and the URL is not derived from `proverUrl`. |
| `createHttpProverAdapter(...).proveTransfer(...)` | `POST {proverUrl}/v1/prover/transfer` | request `v2`, prepared transfer payload `v5` | response `v2`, request payload hash and proof binding | Native transfer and self-merge |
| `createHttpProverAdapter(...).proveWithdraw(...)` | `POST {proverUrl}/v1/prover/withdraw` | request/prover payload `v2` | response/proof `v2`, request payload hash binding | Direct and relay withdraw |
| `createHttpProverAdapter(...).proveBatchTransfer(...)` | `POST {proverUrl}/v1/proofs/batch-transfer` | request `v1`, payload `batch-transfer-payload-v1` | response `v1`, proof `batch-transfer-proof-v1`, payload/circuit binding | Cosmos/EVM One-Proof Batch Transfer |
| `createAsyncJobProverAdapter(...)` | Product-defined | Caller-provided submit function | Caller-provided `getJob` result validated against the proof contract above | Queue/poll remote prover |

If a browser client receives only `proverUrl` without an injected `proverAdapter`, the SDK creates the default HTTP adapter. Inject an adapter directly for a local/WASM prover or an internal authentication/queue contract.

## Clairveil chain REST query mapping

The routes below are the contracts shared by the HTTP annotations in [Query proto](../proto/clairveil/privacy/v1/query.proto) and the browser/Cosmos public-client implementations.

| SDK method | HTTP | Clairveil REST route | Purpose |
| --- | --- | --- | --- |
| `fetchPrivacyEvents(...)` | GET | `/clairveil/privacy/v1/events` | Raw privacy-event diagnostic page |
| `fetchScanEvents(...)` | GET | `/clairveil/privacy/v1/scan_events` | Compatibility/debugging sequence-cursor page; wallet sync uses it only when the typed endpoint is unavailable from the first request |
| `fetchPrivacyScan(...)`, `queryPrivacyScan(...)` | POST | `/clairveil/privacy/v1/privacy_scan` | `privacy-scan-v2` typed summary/output and complete cursor |
| `fetchTreeState()` | GET | `/clairveil/privacy/v1/tree_state` | Current Merkle root, leaf count, and depth |
| `fetchCommitmentInfo(...)` | GET | `/clairveil/privacy/v1/commitment/{commitment_hex}` | Commitment existence and leaf position |
| `lookupMerklePath(...)` | GET | `/clairveil/privacy/v1/merkle_path/{commitment_hex}` | Single commitment witness |
| `fetchCommitmentPathsAtRoot(...)`, `queryCommitmentPathsAtRoot(...)` | POST | `/clairveil/privacy/v1/commitment_paths_at_root` | Same-root/path snapshot for up to 16 inputs |
| `checkNullifier(...)` | GET | `/clairveil/privacy/v1/nullifier/{nullifier}` | Whether one nullifier has been used |
| `checkNullifiers(...)` | POST | `/clairveil/privacy/v1/nullifiers` | Batch check for up to 1,000 nullifiers. Proto also has a GET binding, but the SDK batch helper uses POST. |
| `fetchAuditConfig()`, `queryAuditConfig()` | GET | `/clairveil/privacy/v1/audit_config` | Active audit-key identity |
| `fetchDisclosureConfig()`, `queryDisclosureConfig()` | GET | `/clairveil/privacy/v1/disclosure_config` | Supported policies/modes and payload contract |
| `fetchCircuitConfig()`, `assertCircuitConfig()` | GET | `/clairveil/privacy/v1/circuit_config` | Active circuit and artifact identity |
| `fetchReserve(...)`, `queryReserve(...)` | GET | `/clairveil/privacy/v1/reserve/{denom=**}` | Module reserve and accounting invariant. The SDK URL-encodes the canonical denom for substitution. |
| `fetchAssetByDenom(...)`, `queryAssetByDenom(...)` | GET | `/clairveil/privacy/v1/assets/by_denom/{canonical_denom=**}` | Canonical denom → asset ID. The SDK URL-encodes the canonical denom for substitution. |
| `fetchAssetByID(...)`, `queryAssetByID(...)` | GET | `/clairveil/privacy/v1/assets/by_id/{asset_id_hex}` | Asset ID → canonical denom |

`scanWalletNotes(...)` and all high-level spend preparation use only typed `privacy_scan`, without event filters. An unavailable endpoint or malformed typed response fails closed and does not advance or replace the wallet cursor. `scanNotes({ scanSource: "scan_events" })` and `fetchScanEvents(...)` remain low-level diagnostic/compatibility surfaces. The wallet uses the complete `(height, global_sequence, output_index)` wire cursor and must commit it in the same transaction only after every output and nullifier state up to that cursor is durably reflected.

`commitment_paths_at_root` uses paths from a snapshot with exactly the requested root/height. Current-root paths read persisted incremental nodes and do not consume the online historical-rebuild budget. A non-current historical public query requires complete root/count/height metadata and is limited to 1,024 leaves and two concurrent rebuilds per keeper process. Beyond those limits it returns `ResourceExhausted`; use the current root or a trusted local historical-path index. The separate offline recovery/export limit is `MaxMerkleRebuildLeaves = 1,048,576`. A remote historical root/path request reveals the wallet's time and state of interest to the provider.

Nullifier and Merkle-path requests can reveal spend linkage to a query provider. By default, `nullifierFailover: false` and `merklePathFailover: false` pin the request to the first configured REST endpoint. Enable failover only when the product has decided that this disclosure to multiple endpoints is acceptable.

## Common Cosmos / EVM auxiliary calls

| SDK function | External call | Note |
| --- | --- | --- |
| Cosmos sign-doc preparation | `GET /cosmos/auth/v1beta1/accounts/{address}` | Account number and sequence lookup |
| `getBalances(...)` | `GET /cosmos/bank/v1beta1/balances/{address}` | Transparent account balance |
| `signDirectAndBroadcast(...)`, `broadcastSignedTx(...)` | CosmJS/Comet RPC broadcast and tx lookup | ClairveilJS does not define a separate product REST broadcast route |
| EVM prepare preflight | Read-only `eth_chainId` | Checks configured `evmRpc` and the connected wallet network separately |
| `sendEvmTransaction(...)` | Wallet `eth_sendTransaction` | Transaction authority belongs to the EIP-1193 wallet or relayer |
| `waitForEvmTransaction(...)` | Read-only `eth_getTransactionReceipt`, `eth_getTransactionByHash`, and `eth_chainId`; policy-dependent `eth_blockNumber` and `eth_getBlockByNumber` | Given the prepared request and sender, verifies the receipt, hash/from/to/input/value/network identity, action-specific privacy event, and explicit finality policy. It fails closed without a policy; depth/`safe`/`finalized` policies recheck the canonical inclusion-block hash. |
| Chain time for relay expiry validation | Caller supplies the latest chain block time | The README latest-block REST helper is an example, not a fixed SDK relayer API |

Privacy scan, circuit, asset, Merkle path, and nullifier queries use the configured Clairveil REST endpoint by default. An EVM chain may inject a complete `PrivacyStateAdapter` to provide the same reads through contract getters or an indexer. Only a runtime EVM profile that receives the adapter in the same constructor call may omit Cosmos `rpc` and `rest`; serialized `BrowserWalletProfile` and `ClairveilWebClientConfig` values remain complete deployment contracts and continue to require both endpoints. Adapter reads use `queryTimeoutMs` and bounded `queryRetry` within the same adapter without silently switching providers. The SDK applies the same typed-scan, circuit, asset, Merkle, and reserve validation behind the adapter boundary. `evmRpc` is used for network identity, receipts, finality, and reorg verification.

## On-chain execution mapping

| Operation | Cosmos type URL | EVM execution | Prepared result | Submitting account |
| --- | --- | --- | --- | --- |
| Deposit | `/clairveil.privacy.v1.MsgDeposit` | `IPrivacy.deposit(...)` | Sign doc or EVM transaction | User wallet |
| Native transfer | `/clairveil.privacy.v1.MsgTransfer` | `IPrivacy.transfer(...)` | Sign doc or EVM transaction | User wallet |
| One-Proof Batch Transfer | `/clairveil.privacy.v1.MsgBatchTransfer` | `IPrivacy.singleProofBatchTransfer(...)` or authorization variant | Cosmos sign doc or EVM transaction | User wallet |
| Direct withdraw | `/clairveil.privacy.v1.MsgWithdraw` | `IPrivacy.withdraw(...)` | Sign doc or EVM transaction | User wallet |
| Relay withdraw | `/clairveil.privacy.v1.MsgWithdraw` | `IPrivacy.withdraw(...)` | Relay payload and optional candidate transaction | Product Relayer |

One-Proof Batch Transfer maps the same frozen payload, proof, and operation evidence to Cosmos and EVM execution artifacts. The EVM path uses the precompile's canonical single-proof selector and exact calldata; it never falls back to multiple independent `transfer` calls.

## Relay and proxy non-fixed contracts

The `/relayer/withdraw` and `/relayer/evm-withdraw` routes in the README are integration examples, not fixed endpoints provided or called by the package. A Product Relayer must define these responsibilities separately:

- Authentication and replay prevention
- Fee, rate-limit, and queue policy
- Authoritative chain-time and expiry validation
- Payload hash, recipient, and chain-ID validation
- Rebuilding the EVM `to`/`data` or Cosmos `MsgWithdraw`
- Returning submission result and transaction identity

The DApp proxy is also a product contract. Even a simple CORS proxy must not collect or log the privacy-root signature, root seed, private scalar, or decrypted notes.

## Boundary between success and state

| Observed value | What it establishes | What it does not establish |
| --- | --- | --- |
| Prepared sign doc / EVM transaction | Proof and transaction artifact are ready | Network submission or success |
| Network `txHash` or Cosmos exact signed `txBytesHash` | A transaction identity exists that can be queried on chain | Chain success or creation of the desired output |
| EVM `txBytesHash` | Local binding between the prepared EVM transaction request and reservation | Network submission, RPC transaction identity, or chain success. A `txHash` returned by `eth_sendTransaction` is still required. |
| Successful tx result / receipt | The transaction executed successfully | That it matches the expected payment/output |
| Input nullifier spent | The input note was consumed | Payment or payroll-item success |
| EVM network `txHash` + prepared `txBytesHash` + successful receipt + verified RPC call/event + verified finality policy + expected output evidence match | The EVM operation can be considered successful | A state where only some linked inputs have been verified |

Direct submission flows that use the Reservation API must record durable `markBroadcastAttempting(...)` evidence immediately before external broadcast, then call `markSubmitted(...)` after submission or `markUnknown(...)` when the result is uncertain. Do not start a local broadcast for a payload that has already crossed an external boundary through `recordRelayHandoff(...)`. A hash returned by a relayer cannot establish `Submitted` by itself; first confirm inclusion of the exact payload through an authoritative chain lookup, then call `recordRelayTransactionEvidence(...)` with the payload hash, network transaction hash, checked height, and literal inclusion evidence. High-level EVM preparation records `execution_transport: "evm"` and the prepared `txBytesHash` at `ProofReady`. `markSubmitted(...)` and `recordRelayTransactionEvidence(...)` require a network `txHash` for that record, while `reconcileSpentNotes(...)` requires both network and artifact hashes plus the successful receipt, RPC transaction identity, privacy-event, and finality verification returned by `waitForEvmTransaction(...)`. A custom low-level EVM path must set the same transport tag through `markProofReady(...)`. The SDK broadcast helper can manage this lifecycle for the caller.

## Related package entry points

| Entry point | Role |
| --- | --- |
| `clairveiljs/browser-dapp` | High-level browser wallet/DApp facade |
| `clairveiljs/browser-public` | Read-only privacy REST client |
| `clairveiljs/cosmos`, `clairveiljs/cosmos-client` | Cosmos messages, sign docs, broadcast, and queries |
| `clairveiljs/evm` | `IPrivacy` calldata, transactions, and EIP-1193 adapter |
| `clairveiljs/prover` | HTTP, async, and static prover adapters |
| `clairveiljs/reservation` | Note reservations, leases, and broadcast/reconciliation evidence |
| `clairveiljs/generated/...` | Generated protobuf message/query bindings |

## Implementation baseline

- Clairveil REST routes: [`proto/clairveil/privacy/v1/query.proto`](../proto/clairveil/privacy/v1/query.proto)
- Browser public query mapping: [`src/browser/public-client.js`](../src/browser/public-client.js)
- Browser DApp orchestration: [`src/browser/wallet-client.js`](../src/browser/wallet-client.js)
- Prover and deposit-proof HTTP contracts: [`src/privacy/prover.js`](../src/privacy/prover.js)
- One-Proof payload and route version: [`src/privacy/batch-transfer.js`](../src/privacy/batch-transfer.js)
- Cosmos messages and broadcast: [`src/transport/cosmos-client.js`](../src/transport/cosmos-client.js)
- EVM privacy precompile: [`src/transport/evm.js`](../src/transport/evm.js)
