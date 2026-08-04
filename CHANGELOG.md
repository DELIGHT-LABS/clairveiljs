# Changelog

All notable changes to ClairveilJS are documented in this file.

## 0.3.1 - 2026-07-31

### Added

- Added explicit `payable-exact-value` EVM deposit support for downstream chains
  wired to Clairveil v0.3.1 `Keeper.DepositWithFunder`.
- Added exact native-denom-to-`msg.value` binding, payable deposit ABI metadata,
  browser profile fields, TypeScript declarations, and submission-time
  transaction binding checks.
- Added an immutable Clairveil v0.3.1 source/protobuf verification gate.

### Changed

- Aligned the package version and release conformance target with Clairveil
  v0.3.1 (`1a6ce6a0a0e10b765c025072b44c2364e9711b48`).
- Kept the default EVM deposit mode nonpayable for existing deployments.
- Reject non-zero EVM value on nonpayable deposits, transfers, and withdrawals.
- Require downstream payable EVM evidence for publish releases, covering
  successful escrow funding, policy-failure rollback, and zero-value deposits.

### Fixed

- Split operation reconciliation diagnostics into `OPERATION_STATE_MIXED` and
  `OPERATION_EVIDENCE_CONFLICT`, preserving reservation-level states and
  field-level expected/actual evidence in structured error details.
- Removed legacy JSON and raw-ciphertext disclosure fallbacks; disclosure
  decoders now require exact `privacy-fixed-v1` plaintexts and typed envelopes.
- Separated the immutable upstream v0.3.1 reservation fixture contract from
  later client-only reservation revisions.
- Updated the EVM scan-option test harness for the protocol preflight boundary.
- Bound prepared privacy transaction targets, calldata, and values through
  submission so deposits, transfers, and withdrawals cannot be redirected or
  value-mutated after preparation.
