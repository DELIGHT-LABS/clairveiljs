# Changelog

All notable changes to ClairveilJS are documented in this file.

## 0.3.1 - 2026-07-31

### Added

- Added explicit `payable-exact-value` EVM deposit support for downstream chains
  wired to Clairveil v0.3.1 `Keeper.DepositWithFunder`.
- Added exact native-denom-to-`msg.value` binding, payable deposit ABI metadata,
  browser profile fields, TypeScript declarations, and submission-time
  transaction binding checks.
- Added a pinned Clairveil core commit-snapshot source/protobuf verification gate.

### Changed

- Aligned the package contract snapshot with Clairveil core commit
  `621c24a3ef1118b6ab2b8b780ab00da6fbc00e1b` without mislabeling that divergent
  snapshot as the immutable Clairveil core `v0.3.1` tag.
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
