# ClairveilJS API Mapping

## Purpose and scope

This document traces how the ClairveilJS APIs called by a browser DApp map to actual **chain REST/RPC**, **prover HTTP contracts**, **Cosmos messages**, and the **EVM privacy precompile**.

It covers high-level flows that communicate with external systems or create transactions, rather than a complete symbol reference for pure crypto, codec, and schema helpers. The package export map's TypeScript declarations are the source of truth for the complete arguments and return types of each method.

- System deployment and trust boundaries: [System architecture](./architecture.md)
- Preventing duplicate note use and recovering after submission: [Note Reservation State Transitions](./reservation-state-machine.md)
- Endpoint and client options: [Deployment and client configuration](./configuration.md)
- Error forms and retry decisions: [Errors and recovery](./errors-and-recovery.md)

## Trusted RootSeed identity (CC-002)

The unreleased `clairveiljs/wallet-kernel` entrypoint starts the CC-002 extraction with `createPrivacyIdentity({ rootSeed, shieldedPrefix? })`. It accepts a 32-byte `Uint8Array` already held by the trusted wallet runtime and copies it before deriving spend, view and disclosure keys with the existing protocol algorithms. Custody generates and backs up fresh entropy; this constructor does not generate a seed, request a root signature or contact an ordinary wallet. Other input fields, including legacy signature material and chain actors, are rejected.

The returned `WalletPrivacyIdentity` contains the copied RootSeed and private key pairs and stays inside the trusted runtime. Its frozen `publicIdentity` projection contains only `shieldedAddress`, `spendPubKeyHex`, `viewPubKeyHex` and `disclosurePubKeyHex`. This projection is an internal SDK type, not a custody RPC account DTO or a permission to disclose it. Custody still owns grants, public DTO projection, vault persistence and secret lifetime; JavaScript does not guarantee erasure of all key copies.

Ordinary account/network selection is maintained separately and is not constructor input. Reusing the same RootSeed preserves the privacy keys; `shieldedPrefix` changes address encoding only. The new entrypoint does not wrap or inherit the legacy `PrivacyMaterial` object, and does not add address/signature placeholders to satisfy existing transaction builders. Ordinary chain adapters are separated below; private workflows now accept these two independent inputs as described below. Existing legacy entrypoints and their exact derivation vectors remain unchanged; the new surface is not reexported through the broad root or DApp entrypoints.

`test/wallet-kernel.test.js` directly loads the pinned sender/recipient Go vectors without a skip path. It checks exact scalar/public-key/address correspondence, independent synthetic seed construction, copied input ownership, public projection and rejected legacy/invalid input. The test also runs under `test:conformance:required`; TypeScript checks cover the new package export and rejected secret/actor fields.

## Ordinary chain wallets (CC-002)

The unreleased `clairveiljs/chain-wallet` entrypoint exports `createKeplrChainWalletAdapter`, `createOfflineSignerChainWalletAdapter` and `createEip1193ChainWalletAdapter`. These are ordinary wallet primitives, separate from the legacy root-signing adapters. They import no wallet kernel, private workflow or prover module, expose no privacy-root or typed-data signing method, and are not reexported from the broad root or DApp entrypoints. Existing legacy adapters and vectors remain unchanged.

All constructors require an explicit `chainId` and perform no wallet calls. `connect()` explicitly enables Keplr or requests EIP-1193 accounts; the offline signer only reads its accounts. `getActor()` reads already available accounts without requesting access. Cosmos returns `{ namespace: "cosmos", chainId, address, pubKeyHex }`; EVM returns `{ namespace: "eip155", chainId, address }`. These frozen public snapshots are local SDK types, not custody RPC DTOs, CAIP-normalized account IDs, grants or authenticated privacy-account links. Cosmos uses a native chain ID, an optional pinned address and a Bech32 prefix (default `clair`) with a 20-byte address. EVM requires canonical hexadecimal chain IDs, normalizes addresses to lowercase and optionally pins an account.

`signDirect(signDoc, actor, { signal }?)` and `sendTransaction(transaction, actor, { signal }?)` require a separately captured actor. Before awaiting account discovery they copy the actor and project the input onto public fields; immediately before dispatch they compare the current account/network (and Cosmos public key) to that actor. EVM also reads the network before and after account discovery. The optional `AbortSignal` is captured before any await and checked again after the final account lookup, immediately before calling the wallet without another await. Custody submission always supplies this signal and aborts it synchronously on provider invalidation. Custom adapters and wrappers must preserve and honor it at that same dispatch boundary. A detected mismatch or aborted signal fails before signing or sending; it does not undo a wallet call that already started. Each invocation dispatches at most once and never falls back to a root signature, another wallet or another network.

Cosmos copies `bodyBytes` and `authInfoBytes`, requires the configured chain ID and a uint64 `bigint` account number, and omits extra fields. Keplr receives a real unsigned `Long` from pinned `long` 5.3.2, plus `preferNoSetFee` and `preferNoSetMemo`; the caller document and offline-signer `bigint` contract stay unchanged. The provider input declaration uses `KeplrSignDoc`, and `test/types.ts` compiles against the actual pinned `@keplr-wallet/types` 0.13.41 interface (with `@types/long` 4.0.2 for its Long 4 dependency), not a self-declared mock. These type packages and Keplr's Starknet peer are development-only dependencies. The returned direct-sign response remains wallet-supplied: callers must verify its signed bytes, public key, signature and intended effect before broadcast. This adapter does not broadcast or claim wallet responses are verified.

Keplr's protobufjs `Long` response is normalized from its two 32-bit words to an exact uint64 `bigint`, including values above `2^63` returned with `unsigned:false`; no floating-point conversion or wallet-supplied coercion is used. This preserves the signed protobuf value and does not bypass the submission coordinator's exact document/signature checks. SDK Bech32 decoders pass explicit finite limits (90 for ordinary addresses, 200 for shielded addresses), avoiding the incompatible `Infinity` default in CosmJS encoding with newer `@scure/base` consumer resolutions. The local custody integration harness exposed both issues using actual Keplr signing and a freshly installed packed SDK.

EVM requires `to`, binds `from` and `chainId` to the actor, and accepts only `data`, `value`, `gas`, `gasPrice`, `maxFeePerGas`, `maxPriorityFeePerGas` and `nonce` in addition to those fields. Data must be hexadecimal bytes and numeric fields canonical hexadecimal quantities. Extra metadata is omitted. Contract creation, access lists and typed-data signing are outside this initial surface. `eth_sendTransaction` must return a 32-byte transaction hash; a rejection or malformed reply after dispatch never causes automatic replay. Callers must retain an unresolved submission until reconciliation establishes its outcome.

These provider reads cannot atomically freeze the external wallet while its UI is open. Custody's grant/epoch checks, `beginSubmission` journal, signed-artifact validation and finality/effect reconciliation remain required at the workflow layer and are not implemented by this primitive. Neither these adapters nor the RootSeed constructor make the existing DApp client custody-ready.

`test/chain-wallet.test.js` uses synthetic providers to check stale accounts/keys/networks, input mutation while discovery awaits, explicit connection, public field projection, failure without replay and independent identity retention. Its source import-graph check permits only the local chain-wallet modules, `@cosmjs/encoding` and `long`; an actual browser bundle must also be audited when dependencies change. The tests run under required conformance, and TypeScript checks reject missing/wrong actors, private fields and legacy root-signing calls. Real-wallet and chain/prover qualification remain separate gates.

## Custody SDK surfaces (CC-002)

`clairveiljs/wallet-api` owns the single editable draft in `src/wallet-api/schema/`. `npm run generate:wallet-api` generates DTO types, registry and Ajv 8.17.1 Draft 2020-12 standalone validators; `npm run check:wallet-api` rejects stale output. All 15 methods have closed DTOs. Generated types describe shapes; runtime validation also enforces conditional constraints. Strict JSON parsing rejects duplicate keys, malformed UTF-8/Unicode, accessors, prototypes and byte/depth/list-limit violations. Results are copied/frozen and correlated to method/IDs, the reviewed digest and requested balance assets. `node tools/sync-wallet-api-mirror.js --check|--write CUSTODY_REPOSITORY` checks or updates four generated custody mirrors; edit only the SDK source.

`createWalletKernel({ identity, client, evmClient?, evmChainId?, checkpoint, assertAuthority, reservationManager? })` is trusted-runtime-only. It offers `scan`, `proveDeposit`, `prepareDeposit`, `prepareTransfer`, `prepareWithdraw`, public identity projection and disposal. Transactions require a separate `actor` and `operationId`; scan ownership follows the privacy identity. Existing private client methods accept `privacyIdentity`/`chainActor` separately from legacy `material`/`wallet`. Note, intent signing, audit/self-view, Merkle, nullifier, planner, proof and reservation algorithms are reused. EVM's numeric wallet chain ID is pinned separately from the protocol chain string. Own deposits and native transfers/withdrawals reuse existing Cosmos/EVM builders; third-party deposits, relaying and batch are absent from this facade.

The host supplies authoritative profile/time, encrypted storage and live permission/epoch checks. `checkpoint` must atomically persist the exact operation/export barrier and reservations before resolving. The kernel awaits it and rechecks authority before invoking the explicitly selected prover; checkpoint failure prevents export. After the final asynchronous authority helper returns, deposit/transfer/withdraw each check disposal synchronously with prover invocation, so disposal in an intervening microtask blocks export. The same synchronous fence applies to the final return of scan, deposit proof and all three preparation results; disposal between the final authority helper and return rejects the completed result. `proveDeposit` declares the actual `DepositMaterial` and string/byte proof union accepted by `prepareDeposit`; non-string EVM `proofHex` responses are rejected. Scan declares `privacyAccount` as `PublicPrivacyIdentity`. Strict TypeScript regression coverage connects proof to deposit preparation and reads the scanned public identity without casts. The host must dispose the kernel on runtime authority loss; the asynchronous hook alone is not an atomic revocation subscription. Existing reservation rollback quarantines failures after proving starts. These hooks are integration obligations, not an implemented vault/journal. Kernel results contain private notes/witnesses and must never cross public DTOs. Disposal blocks new work and clears owned byte arrays, without promising erasure of every JavaScript secret copy.

`clairveiljs/custody-provider` exports `createCustodyProvider` and `createDirectBridgeTransport`. Transport and invalidation subscription are explicit. The exchange host authenticates origin/document or topic; the adapter does not implement extension authentication, grants or a WalletConnect responder. Construction performs no I/O. Discovery must match the pinned schema before other methods. Pending requests, timeout and polling are bounded; invalidation discards capability/revision state and late replies; disposal is permanent. Errors use only fixed schema fields. After successful discovery, a listed method absent from capabilities returns `4102 UNSUPPORTED_CAPABILITY`; missing discovery or an invalidated attachment remains `4103 UNAUTHORIZED`, and an unknown method remains `-32601`. After bounded JSON capture, unsupported string `protocolVersion`/`schemaRevision` values return `4101 UNSUPPORTED_VERSION` before exact-params or discovery admission; missing/non-string version fields remain `-32602`. Discovery does not accept a schemaRevision field. Both direct transport and provider use this shared check without invoking getters. Capabilities are compared as bounded JSON values: object key order, including nested objects, does not invalidate the attachment; changed values or array contents/order still do. Equivalent discovery replies preserve polling and revision guards. The nested operation in `cancelOperation` is correlated with the requested operation ID and participates in the same monotonic revision tracking as direct operation results. A stale cancel result or a delayed poll older than an accepted cancel result is rejected with a sanitized internal error; the public nested response shape is unchanged.

`clairveiljs/dapp` exports `createClairveilDappClient({ custodyProvider })` with 15 logical methods and no `.cosmos`, private callback or automatic legacy fallback. Adding `chainWallet` and explicit `validateArtifact` enables `submit`; Cosmos also requires `broadcastCosmos`. `createArtifactVerifier` pins chain/asset/profile digest and EVM contract/protocol chain, decodes allowlisted protobuf/ABI and checks public effects. Cosmos self-merge/final-transfer messages must match the public summary expiry, just as EVM transfers do; missing or different expiry stops submission before begin, signing or broadcast. The approved digest binds all bytes, actor and fees; private intent and fresh chain-state checks remain in custody. A digest supplied by an untrusted page is not approval.

Submission consumes each permitted begin response once per provider attachment before a wallet call, shares in-flight/attempt guards across clients and rejects stale revisions/epochs/accounts. Cosmos verifies exact signed document, key and secp256k1 signature before one broadcast; EVM requires the explicit EIP-1559 artifact. Cosmos preserves an independent approved document and byte arrays for verification, so even a custom adapter that mutates its input cannot redefine the approved bytes. Uncertain/rejected responses are reported unknown, with no dispatch retry. Memory guards complement the host's durable `beginSubmission` journal and cannot replace it after process loss. `clairveiljs/legacy-browser` explicitly aliases the previous secret-bearing browser client; old `browser-dapp` remains legacy and is never chosen automatically.

The provider keeps admission, capability/revision state and request cleanup in `custody-provider/provider.js`; `direct-bridge.js` only frames and correlates JSON-RPC. `chain-wallet/cosmos-signing.js` owns public sign-document copying and the two Keplr conversion directions. Both ordinary adapters use `dispatchToActor` in `chain-wallet/actor.js` so the final actor/abort checks and actual wallet call share one synchronous continuation; the submission coordinator reuses the same actor comparison. Submission tests share client/profile and synthetic-signature fixtures while keeping each failure injection and assertion explicit. The public entrypoint still exports the same two constructors. Submission stages explicitly separate artifact validation, begin, synchronous attempt consumption, dispatch and reporting. Each submission subscribes to attachment invalidation, passes an abort signal into the chain adapter and removes the subscription on every completion path. Kernel helpers separate actor capture, execution building and checkpoint payload construction. `activeResult` centralizes the final result check and return without adding an async boundary; final prover checks stay synchronous with invocation. EVM proof normalization uses explicit hex and string/byte branches. Workflow declarations retain exactly the same tokens with readable field layout; kernel tests share construction, EVM context, canonical deposit replies and microtask scheduling while retaining explicit failure assertions. Regression cases exercise reserved control slots, timeout cleanup, transport envelope mutation, repeated attempt IDs across clients, attachment loss at every account/network lookup inside the real SDK adapters, attachment loss after Cosmos signing, subscription cleanup and disposal during a checkpoint. The optional dispatch signal and Keplr input declaration refine the SDK adapter contract; wire schemas, protocol algorithms and trust boundaries are unchanged.

New wallet-api/provider/submission/kernel-workflow/public-boundary tests run in default and required conformance suites. Synthetic Cosmos/EVM deposit, transfer and withdraw preparation uses existing private algorithms with mocked chain reads and framed proof replies. Checkpoint loss, actor/epoch changes, signature/calldata mutation and public import graphs are covered. Actual proving, live wallet/chain settlement, encrypted-host fault injection and WalletConnect qualification remain separate. Browser bundle/CSP and immutable package measurements are recorded in custody's CC-002 task. New exports remain unreleased under the unchanged package version.

## Contract categories

| Category | Meaning | Example |
| --- | --- | --- |
| SDK-fixed contract | ClairveilJS and the Clairveil protocol fix the route, shape, and version. | `/clairveil/privacy/v1/privacy_scan`, `/v1/prover/transfer`, `/v1/prover/deposit`, Cosmos message type URLs |
| Profile-fixed endpoint | The product places an exact reviewed URL in the profile and the SDK calls only that URL. | optional `depositProofUrl` override |
| Injected adapter | The caller provides the function implementation; ClairveilJS assumes no fixed HTTP route. | local/WASM prover, submit/poll functions for `createAsyncJobProverAdapter(...)` |
| Product-defined API | The product defines authentication, fees, queueing, and URLs. It is not a common ClairveilJS server contract. | relay-withdraw handoff, DApp proxy route |

`/v1/prover/transfer`, `/v1/prover/withdraw`, `/v1/proofs/batch-transfer`, and `/v1/prover/deposit` are not chain REST endpoints from `clairveil.d`. The **browser's ClairveilJS** makes these requests directly to `proverUrl` when the default HTTP prover adapter is selected. A request passes through a DApp proxy only when `proverUrl` points to that proxy.

## Clairveil v0.3.1 fixed contract

This document and the SDK support the current Clairveil `v0.3.1` SDK handoff,
commit `0ff92839872de26b787a60d8e4d5822cc459855b`. The values below are not deployment-profile
settings; they are protocol contracts fixed by the conformance fixtures and consensus
identity.

Cosmos deposit proving additionally follows the canonical Core `v0.4.0` prover
HTTP contract at tag commit `ca85b02708fdd75259d4d2ee2d671c21198cec69`.
The Cosmos protobuf and on-chain `MsgDeposit` wire are unchanged; the added
contract is the strict off-chain request/response and proof-frame boundary.

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
| Deposit | `prepareDeposit(...)` | Circuit config, asset mapping; Cosmos sign doc also queries account metadata | Cosmos: canonical `POST /v1/prover/deposit`, local provider, or canonical V1 exact URL override; EVM behavior unchanged | Cosmos `MsgDeposit` sign doc or EVM `IPrivacy.deposit` transaction | User Cosmos wallet or EIP-1193 wallet | Both profiles preserve the exact commitment and `encryptedNoteHex`. Cosmos validates the response binding and 164-byte proof frame, then uses `confirmDeposit(...)`; EVM uses `waitForEvmTransaction(...)` to verify the exact RPC call and `PrivacyDeposit` event. |
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
| `createHttpProverAdapter(...).proveDeposit(...)` | `POST {proverUrl}/v1/prover/deposit` | request `v1`, memo-free payload `v1` with compressed receiver keys, amount, asset ID, randomness, and commitment | response `v1`, nested proof `v1`, exact commitment, canonical 164-byte proof | Default Cosmos deposit route from Core v0.4.0 |
| `createHttpDepositProofProviderV1({ url })` | `POST <depositProofUrl>` | Same canonical request/payload `v1` | Same canonical response/proof `v1`; exact HTTP 200 and JSON content type | Cosmos Core v0.4.0 exact endpoint override; redirects are not allowed |
| `createHttpDepositProofProvider({ url })` | `POST <product endpoint>` | Legacy flat `{ note_json, note_commitment_hex }` | Legacy flat `{ version: "v1", proof_hex, note_commitment_hex }` | Existing EVM/product-specific endpoint compatibility; not the Cosmos Core v0.4.0 wire |
| `createHttpProverAdapter(...).proveTransfer(...)` | `POST {proverUrl}/v1/prover/transfer` | request `v2`, prepared transfer payload `v5` | response `v2`, request payload hash and proof binding | Native transfer and self-merge |
| `createHttpProverAdapter(...).proveWithdraw(...)` | `POST {proverUrl}/v1/prover/withdraw` | request/prover payload `v2` | response/proof `v2`, request payload hash binding | Direct and relay withdraw |
| `createHttpProverAdapter(...).proveBatchTransfer(...)` | `POST {proverUrl}/v1/proofs/batch-transfer` | request `v1`, payload `batch-transfer-payload-v1` | response `v1`, proof `batch-transfer-proof-v1`, payload/circuit binding | Cosmos/EVM One-Proof Batch Transfer |
| `createAsyncJobProverAdapter(...)` | Product-defined | Caller-provided submit function | Caller-provided `getJob` result validated against the proof contract above | Queue/poll remote prover |

If a Cosmos browser client receives only `proverUrl` without an injected
adapter or exact deposit URL, the SDK creates the default HTTP adapter and uses
its canonical deposit route. Inject an adapter directly for a local/WASM prover
or an internal authentication/queue contract. Automatic cross-endpoint
failover remains disabled.

A Cosmos profile's exact `depositProofUrl` is resolved with
`createHttpDepositProofProviderV1`. The unversioned
`createHttpDepositProofProvider` name intentionally retains its legacy flat
wire for existing EVM and product-specific integrations; do not use it as a
Core v0.4.0 Cosmos prover client.

## Clairveil chain REST query mapping

The routes below are the contracts shared by the HTTP annotations in [Query proto](../proto/clairveil/privacy/v1/query.proto) and the browser/Cosmos public-client implementations.

| SDK method | HTTP | Clairveil REST route | Purpose |
| --- | --- | --- | --- |
| `fetchPrivacyEvents(...)` | GET | `/clairveil/privacy/v1/events` | Raw privacy-event diagnostic page |
| `fetchScanEvents(...)` | GET | `/clairveil/privacy/v1/scan_events` | Low-level compatibility/debugging sequence-cursor page; high-level wallet and spend scans never fall back to it |
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
