# Changelog

All notable changes to ClairveilJS are documented in this file.

## 0.6.1 - 2026-11-20

Git source version for Core v0.6.1 integration. npm publication remains separate.

### Changed

- Isolated the V2 runtime and declarations from V1 execution modules; extracted
  pure payroll planning, protocol domains and shared validation, and separated
  audit identity/manifest, key-record verification and query orchestration.
- Retired compact/PascalCase V1 note/cache aliases in `note128` and V2 payroll
  forwarding exports from `reference-payroll`. V2 inventory heights are exact
  decimal strings; explicit note randomness no longer requests fresh entropy.
- Fixed note selection ordering for block heights above JavaScript's safe integer
  limit. Core protocol bytes and current hash domains remain unchanged.

### Added

- Added explicit trusted `wallet-kernel-v2` preparation/proving orchestration,
  typed `disclosure-v2` user/self-view decoding and a public-only V2 DApp example.
- Required actual native proofs and all six witness/encoding paths in the V2
  release gate; native builds use the exact annotated Core v0.6.1 source.

- Added `audit-prover-v2` for single-use full-witness V2 HTTP proving, strict
  response/PI23 binding, deadline/cancellation and fresh-snapshot checks.
  Node-only `audit-verifier-node` verifies canonical BN254 Groth16 proofs with
  pinned Core code, manifest and verification keys. Real four-circuit development
  proofs and a Core HTTP deposit round trip are required by `verify:audit-prover`.
- Added V2 OutputEffect/AuditAuthorization construction, PI23/context/owner-intent
  binding for all four audit shapes and a pinned Core native Node encryption
  adapter. Independent Go vectors and native KATs cover the current wire contract;
  full note-to-witness builders and V2 wallet submission remain separate work.

- Added explicit `privacy-fixed-v2` note/disclosure codecs, uint128 binary
  amounts, envelope encryption/decryption and transfer/batch digest verification
  against independent Core v0.6.1 Go vectors. V1 wire behavior is preserved.
- Added explicit uint128 amount/note models, V2 transfer/batch/withdraw planners
  and bounded payroll planning with unbounded wallet/payroll totals. Existing
  V1 planners and binary codecs retain their original contracts.

- Added Core v0.6.1 protobuf bindings, explicit `clairveiljs/cosmos-v2`
  exports and a V2 registry for all seven messages, preserving V1 defaults.
- Pinned current proto sources separately from historical lifecycle/prover
  fixtures; verified V2 encoding against independently generated Go vectors.
- Added the four additive Core v0.6.1 reserve query accounting fields.
- Added Cosmos support for Clairveil Core v0.4.0's canonical
  `POST /v1/prover/deposit` request, response, bearer-auth, and error contract.
- Added strict local validation for canonical 164-byte gnark BN254 Groth16
  deposit proof frames before constructing `MsgDeposit`.
- Added `createHttpDepositProofProviderV1(...)` for canonical Cosmos exact-URL
  endpoints and `validateDepositMaterial(...)` for proof-independent deposit
  binding checks before prover handoff.
- Added an exact Core `v0.4.0` prover fixture/schema bundle and source-identity
  release gate while retaining the existing v3 lifecycle snapshot provenance.

### Changed

- Cosmos browser profiles now use `{proverUrl}/v1/prover/deposit` by default;
  an injected provider or exact `depositProofUrl` remains an explicit override.
- Cosmos deposits now bind receiver spend/view keys and encrypted-note recovery
  to the wallet root seed before proving or signing. The unversioned
  `createHttpDepositProofProvider(...)` retains its legacy flat EVM/product wire.
- Canonical deposit HTTP handling now requires exact status `200`, redacts
  malformed remote response details, recognizes browser network failures, and
  accepts the full IPv4 loopback range used by Core.
- NoteV1 validation now permits an individually zero asset ID or randomness when
  the resulting active commitment and nullifier remain non-zero, matching Core
  v0.4.0.

## 0.3.1 - 2026-07-31

### Added

- Added explicit `payable-exact-value` EVM deposit support for downstream chains
  wired to Clairveil v0.3.1 `Keeper.DepositWithFunder`.
- Added exact native-denom-to-`msg.value` binding, payable deposit ABI metadata,
  browser profile fields, TypeScript declarations, and submission-time
  transaction binding checks.
- Added a pinned Clairveil core commit-snapshot source/protobuf verification gate.
- Added a self-contained gate for the SDK-owned EVM `IPrivacy` ABI, selectors,
  events, mutability, and adapter surface.

### Changed

- Aligned the package contract snapshot with the first joint Clairveil core commit
  `0ff92839872de26b787a60d8e4d5822cc459855b` that contains both the v3 reservation
  contract and hardened trusted deposit funding, without presenting the snapshot as
  the immutable Clairveil core `v0.3.1` tag.
- Made payable exact-value the default EVM deposit mode; explicit nonpayable mode remains an opt-in compatibility setting.
- Kept deprecated public aliases for the v0.3.1 bundle label and legacy EVM
  precompile constants, while requiring every EVM client to use an explicit
  chain-configured privacy contract address.
- Reject non-zero EVM value on nonpayable deposits, transfers, and withdrawals.
- Require downstream payable EVM evidence for publish releases, covering
  successful escrow funding, policy-failure rollback, and zero-value deposits.

### Fixed

- Preserve deployment path prefixes when appending HTTP prover routes.
- Validate payroll artifacts against their canonical signed Cosmos TxRaw and
  make exact-byte retries persist their own broadcast outcome.
- Persist the exact Cosmos transaction identity before RPC, reject response or
  index hash mismatches, and expose a synchronous final-boundary callback.
- Split operation reconciliation diagnostics into `OPERATION_STATE_MIXED` and
  `OPERATION_EVIDENCE_CONFLICT`, preserving reservation-level states and
  field-level expected/actual evidence in structured error details.
- Removed legacy JSON and raw-ciphertext disclosure fallbacks; disclosure
  decoders now require exact `privacy-fixed-v1` plaintexts and typed envelopes.
- Synchronized the bundled reservation fixture and wallet-contract schema with
  the current v0.3.1 SDK handoff and enforce the reservation contract as v3-only.
- Updated the EVM scan-option test harness for the protocol preflight boundary.
- Bound prepared privacy transaction targets, calldata, and values through
  submission so deposits, transfers, and withdrawals cannot be redirected or
  value-mutated after preparation.
