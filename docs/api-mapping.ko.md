# ClairveilJS API 매핑

## 목적과 범위

이 문서는 브라우저 DApp에서 호출하는 ClairveilJS API가 실제로 어떤 **chain REST/RPC**, **prover HTTP 계약**, **Cosmos message**, **EVM privacy precompile**로 이어지는지 추적할 수 있게 한다.

순수 crypto·codec·schema helper의 전체 symbol reference가 아니라, 외부 시스템과 통신하거나 transaction을 만드는 고수준 흐름을 대상으로 한다. 각 메서드의 전체 인자와 반환 타입은 package export map의 TypeScript declaration을 기준으로 한다.

- 시스템 배치와 신뢰 경계: [시스템 아키텍처](./architecture.ko.md)
- note 중복 사용 방지와 제출 후 복구: [Note Reservation 상태 전이](./reservation-state-machine.ko.md)

## 계약 분류

| 분류 | 의미 | 예시 |
| --- | --- | --- |
| SDK 고정 계약 | ClairveilJS와 Clairveil protocol이 경로·shape·version을 정한다. | `/clairveil/privacy/v1/privacy_scan`, `/v1/prover/transfer`, Cosmos Msg type URL |
| Profile 고정 endpoint | 제품이 검토한 정확한 URL을 profile에 넣고 SDK가 그 URL만 호출한다. | `depositProofUrl` |
| 주입형 adapter | 호출자가 함수 구현을 제공하며 ClairveilJS는 고정 HTTP route를 가정하지 않는다. | local/WASM prover, `createAsyncJobProverAdapter(...)`의 submit/poll 함수 |
| Product-defined API | 인증·수수료·queue·URL을 제품이 정의한다. ClairveilJS 공통 서버 계약이 아니다. | relay withdraw handoff, DApp proxy route |

`/v1/prover/transfer`, `/v1/prover/withdraw`, `/v1/proofs/batch-transfer`는 `clairveil.d`의 chain REST endpoint가 아니다. 기본 HTTP prover adapter를 선택한 **브라우저의 ClairveilJS**가 `proverUrl`에 직접 요청한다. `proverUrl`이 DApp proxy를 가리킬 때만 요청이 그 서버를 경유한다.

## End-to-End 작업 매핑

| 사용자 작업 | 주 SDK API | 준비 중 조회 | proof 계약 | 준비 결과 | 서명·최종 제출 | 완료 판단 |
| --- | --- | --- | --- | --- | --- | --- |
| Deposit | `prepareDeposit(...)` | circuit config, asset mapping; Cosmos sign doc은 account metadata도 조회 | local/WASM `depositProofProvider` 또는 exact `depositProofUrl` | Cosmos `MsgDeposit` sign doc 또는 EVM `IPrivacy.deposit` transaction | 사용자 Cosmos wallet 또는 EIP-1193 wallet | Cosmos는 `confirmDeposit(...)`이 성공 tx와 정확한 commitment·encrypted note를 확인. EVM은 successful receipt와 제품이 요구하는 event/state evidence를 확인 |
| Note scan | `scanWalletNotes(...)`, `queryPrivacyScan(...)` | typed privacy scan과 nullifier 상태 | 없음 | 검증된 found note, cursor, nullifier status | 제출 없음 | malformed page나 불명확한 nullifier는 spendable로 취급하지 않음 |
| Native transfer | `prepareTransfer(...)` | scan, circuit/asset/audit/disclosure config, same-root path, nullifier 상태 | `POST /v1/prover/transfer` | Cosmos `MsgTransfer` sign doc 또는 EVM `IPrivacy.transfer` transaction | 사용자 wallet | tx identity, input nullifier, 예상 output/disclosure evidence를 reconcile |
| One-Proof Batch Transfer | `prepareTransferBatch(...)`, `provePreparedBatchTransfer(...)`, `finalizePreparedBatchTransfer(...)` | typed scan, protocol config, same-root path snapshot, 모든 input nullifier | `POST /v1/proofs/batch-transfer` | Cosmos `MsgBatchTransfer` sign doc | 사용자 Cosmos wallet | 같은 operation의 모든 input nullifier와 모든 typed output evidence를 원자적으로 reconcile |
| Direct withdraw | `prepareWithdraw(...)` | scan, circuit/asset config, Merkle path, nullifier 상태 | `POST /v1/prover/withdraw` | Cosmos `MsgWithdraw` sign doc 또는 EVM `IPrivacy.withdraw` transaction | 사용자 wallet | tx/receipt와 nullifier 및 withdraw evidence를 확인 |
| Relay withdraw | `prepareRelayWithdraw(...)` | direct withdraw와 동일 | `POST /v1/prover/withdraw` | final relay payload; EVM은 candidate `IPrivacy.withdraw` transaction도 반환 | Product Relayer가 payload에서 transaction을 재구성·검증하고 자기 계정으로 제출 | handoff 전 `recordRelayHandoff(...)`; 이후 tx/nullifier/evidence로 reconcile |
| Disclosure 조회 | `decodeUserDisclosure(...)`, `decodeSelfViewDisclosure(...)`, `decodeAuditDisclosure(...)`, batch decode API | privacy event, scan event 또는 typed privacy scan | 없음 | 로컬에서 검증·복호화한 disclosure report | 제출 없음 | commitment, output index, policy, digest와 대상 key가 모두 일치해야 `verified` |

`prepare*`가 반환됐다는 사실은 transaction 제출이나 성공을 뜻하지 않는다. Cosmos sign doc 또는 EVM transaction은 wallet·relayer 경계를 넘기기 전까지 `ProofReady` artifact이며, 제출 후에는 [상태 전이 문서](./reservation-state-machine.ko.md)의 evidence 규칙으로 처리한다.

## Prover와 Deposit Proof 매핑

| SDK API / adapter | HTTP 대상 | 요청 계약 | 응답 계약 | 호출되는 흐름 |
| --- | --- | --- | --- | --- |
| `createHttpDepositProofProvider({ url })` | `POST <profile.depositProofUrl>` | `{ note_json, note_commitment_hex }` | `version: "v1"`, `proof_hex`, 동일한 `note_commitment_hex` | Deposit 전용. redirect를 허용하지 않으며 `proverUrl`에서 URL을 만들지 않음 |
| `createHttpProverAdapter(...).proveTransfer(...)` | `POST {proverUrl}/v1/prover/transfer` | request `v2`, prepared transfer payload `v5` | response `v2`, request payload hash와 proof binding | native transfer와 self-merge |
| `createHttpProverAdapter(...).proveWithdraw(...)` | `POST {proverUrl}/v1/prover/withdraw` | request/prover payload `v2` | response/proof `v2`, request payload hash binding | direct withdraw와 relay withdraw |
| `createHttpProverAdapter(...).proveBatchTransfer(...)` | `POST {proverUrl}/v1/proofs/batch-transfer` | request `v1`, payload `batch-transfer-payload-v1` | response `v1`, proof `batch-transfer-proof-v1`, payload/circuit binding | Cosmos One-Proof Batch Transfer |
| `createAsyncJobProverAdapter(...)` | Product-defined | caller의 submit 함수 | caller의 `getJob` 결과를 위 proof 계약으로 검증 | queue/poll 기반 remote prover |

브라우저 client에 `proverUrl`만 제공하고 `proverAdapter`를 주입하지 않으면 SDK가 기본 HTTP adapter를 생성한다. Local/WASM prover나 사내 인증·queue contract를 쓰려면 adapter를 직접 주입한다.

## Clairveil Chain REST 조회 매핑

아래 route는 [Query proto](../proto/clairveil/privacy/v1/query.proto)의 HTTP annotation과 browser/Cosmos public client 구현이 공통으로 사용하는 계약이다.

| SDK 메서드 | HTTP | Clairveil REST route | 용도 |
| --- | --- | --- | --- |
| `fetchPrivacyEvents(...)` | GET | `/clairveil/privacy/v1/events` | legacy/general privacy event page |
| `fetchScanEvents(...)` | GET | `/clairveil/privacy/v1/scan_events` | sequence cursor가 있는 legacy wallet scan projection |
| `fetchPrivacyScan(...)`, `queryPrivacyScan(...)` | POST | `/clairveil/privacy/v1/privacy_scan` | `privacy-scan-v2` typed summary/output와 완전한 cursor |
| `fetchTreeState()` | GET | `/clairveil/privacy/v1/tree_state` | 현재 Merkle root, leaf count, depth |
| `fetchCommitmentInfo(...)` | GET | `/clairveil/privacy/v1/commitment/{commitment_hex}` | commitment 존재와 leaf 위치 |
| `lookupMerklePath(...)` | GET | `/clairveil/privacy/v1/merkle_path/{commitment_hex}` | 단일 commitment witness |
| `fetchCommitmentPathsAtRoot(...)`, `queryCommitmentPathsAtRoot(...)` | POST | `/clairveil/privacy/v1/commitment_paths_at_root` | 최대 16개 input의 동일 root/height path snapshot |
| `checkNullifier(...)` | GET | `/clairveil/privacy/v1/nullifier/{nullifier}` | 단일 nullifier 사용 여부 |
| `checkNullifiers(...)` | POST | `/clairveil/privacy/v1/nullifiers` | 최대 1,000개 단위 batch nullifier 확인. Proto에는 GET binding도 있으나 SDK batch helper는 POST 사용 |
| `fetchAuditConfig()`, `queryAuditConfig()` | GET | `/clairveil/privacy/v1/audit_config` | active audit key identity |
| `fetchDisclosureConfig()`, `queryDisclosureConfig()` | GET | `/clairveil/privacy/v1/disclosure_config` | 지원 policy/mode와 payload contract |
| `fetchCircuitConfig()`, `assertCircuitConfig()` | GET | `/clairveil/privacy/v1/circuit_config` | active circuit와 artifact identity |
| `fetchReserve(...)`, `queryReserve(...)` | GET | `/clairveil/privacy/v1/reserve/{denom=**}` | module reserve와 accounting invariant. SDK는 canonical denom을 URL encode해 치환 |
| `fetchAssetByDenom(...)`, `queryAssetByDenom(...)` | GET | `/clairveil/privacy/v1/assets/by_denom/{canonical_denom=**}` | canonical denom → asset ID. SDK는 canonical denom을 URL encode해 치환 |
| `fetchAssetByID(...)`, `queryAssetByID(...)` | GET | `/clairveil/privacy/v1/assets/by_id/{asset_id_hex}` | asset ID → canonical denom |

`scanWalletNotes(...)`는 event filter를 명시하지 않은 기본 wallet scan에서 typed `privacy_scan`을 사용한다. Typed endpoint가 명시적으로 없음을 뜻하는 응답일 때만 `scan_events`로 fallback하며, malformed typed response는 fallback하지 않고 실패한다. One-Proof Batch Transfer는 typed scan만 허용한다.

Nullifier와 Merkle path 요청은 spend 대상의 linkage를 query provider에 노출할 수 있다. 기본값에서는 각각 `nullifierFailover: false`, `merklePathFailover: false`로 최초 configured REST endpoint에 고정하며, 여러 endpoint에 노출해도 된다는 제품 결정이 있을 때만 failover를 켠다.

## 공통 Cosmos / EVM 보조 호출

| SDK 기능 | 외부 호출 | 비고 |
| --- | --- | --- |
| Cosmos sign doc 준비 | `GET /cosmos/auth/v1beta1/accounts/{address}` | account number와 sequence 조회 |
| `getBalances(...)` | `GET /cosmos/bank/v1beta1/balances/{address}` | transparent account balance |
| `signDirectAndBroadcast(...)`, `broadcastSignedTx(...)` | CosmJS/Comet RPC broadcast와 tx lookup | ClairveilJS가 별도 product REST broadcast route를 정의하지 않음 |
| EVM prepare preflight | read-only `eth_chainId` | configured `evmRpc`와 연결 wallet network를 각각 확인 |
| `sendEvmTransaction(...)` | wallet `eth_sendTransaction` | transaction 권한은 EIP-1193 wallet 또는 relayer에 있음 |
| `waitForEvmTransaction(...)` | read-only `eth_getTransactionReceipt` | configured `evmRpc` 사용. injected wallet provider를 조회에 사용하지 않음 |
| relay expiry 검증용 chain time | caller가 최신 chain block time 제공 | README의 latest-block REST helper는 예시이며 SDK 고정 relayer API가 아님 |

EVM profile도 privacy scan, circuit, asset, Merkle path, nullifier 같은 Clairveil module 조회에는 configured Clairveil REST endpoint를 사용한다. `evmRpc`는 network ID, receipt 등 EVM JSON-RPC 조회에 사용한다.

## 온체인 실행 매핑

| 작업 | Cosmos type URL | EVM 실행 | 준비 결과 | 제출 계정 |
| --- | --- | --- | --- | --- |
| Deposit | `/clairveil.privacy.v1.MsgDeposit` | `IPrivacy.deposit(...)` | sign doc 또는 EVM transaction | 사용자 wallet |
| Native transfer | `/clairveil.privacy.v1.MsgTransfer` | `IPrivacy.transfer(...)` | sign doc 또는 EVM transaction | 사용자 wallet |
| One-Proof Batch Transfer | `/clairveil.privacy.v1.MsgBatchTransfer` | 지원하지 않음 | Cosmos sign doc | 사용자 Cosmos wallet |
| Direct withdraw | `/clairveil.privacy.v1.MsgWithdraw` | `IPrivacy.withdraw(...)` | sign doc 또는 EVM transaction | 사용자 wallet |
| Relay withdraw | `/clairveil.privacy.v1.MsgWithdraw` | `IPrivacy.withdraw(...)` | relay payload와 optional candidate transaction | Product Relayer |

현재 One-Proof Batch Transfer는 Cosmos 전용이다. EVM profile의 `prepareTransferBatch(...)`는 거부되며, ClairveilJS는 `IPrivacy.batchTransfer` ABI나 EVM batch fallback을 제공하지 않는다.

## Relay와 Proxy의 비고정 계약

README의 `/relayer/withdraw`, `/relayer/evm-withdraw`는 integration 예시일 뿐 package가 제공하거나 호출하는 고정 endpoint가 아니다. Product Relayer는 다음 책임을 별도로 정의해야 한다.

- 인증과 replay 방지
- 수수료·rate limit·queue 정책
- authoritative chain time과 expiry 검증
- payload hash, recipient, chain ID 검증
- EVM `to`/`data` 또는 Cosmos `MsgWithdraw` 재구성
- 제출 결과와 tx identity 반환

DApp proxy도 마찬가지로 제품 계약이다. 단순 CORS proxy라도 privacy root signature, root seed, private scalar, 복호화 note를 수집하거나 로그에 남기면 안 된다.

## 성공과 상태의 경계

| 관찰한 값 | 말할 수 있는 것 | 아직 말할 수 없는 것 |
| --- | --- | --- |
| prepared sign doc / EVM transaction | proof와 transaction artifact가 준비됨 | network 제출 또는 성공 |
| `txHash` / `txBytesHash` | 특정 transaction identity가 존재함 | chain 성공과 원하는 output 생성 |
| successful tx result / receipt | 해당 transaction 실행 성공 | 기대한 payment/output과의 일치 |
| input nullifier spent | 입력 note가 소비됨 | payment 또는 payroll item 성공 |
| tx identity + expected output/disclosure evidence 일치 | operation 성공 판정 가능 | 없음. 단, linked input 전체를 함께 검증해야 함 |

Reservation API를 사용하는 흐름은 외부 broadcast 직전에 `markBroadcastAttempting(...)`, 실제 제출 후 `markSubmitted(...)` 또는 불확실한 경우 `markUnknown(...)`에 해당하는 durable evidence를 남겨야 한다. SDK broadcast helper는 이 lifecycle을 대신 관리할 수 있다.

## 관련 package entrypoint

| Entrypoint | 역할 |
| --- | --- |
| `clairveiljs/browser-dapp` | 브라우저 wallet/DApp 고수준 facade |
| `clairveiljs/browser-public` | read-only privacy REST client |
| `clairveiljs/cosmos`, `clairveiljs/cosmos-client` | Cosmos message, sign doc, broadcast와 query |
| `clairveiljs/evm` | `IPrivacy` calldata, transaction, EIP-1193 adapter |
| `clairveiljs/prover` | HTTP·async·static prover adapter |
| `clairveiljs/reservation` | note reservation, lease, broadcast/reconciliation evidence |
| `clairveiljs/generated/...` | generated protobuf message/query binding |

## 구현 기준

- Clairveil REST route: [`proto/clairveil/privacy/v1/query.proto`](../proto/clairveil/privacy/v1/query.proto)
- Browser public query mapping: [`src/browser/public-client.js`](../src/browser/public-client.js)
- Browser DApp orchestration: [`src/browser/wallet-client.js`](../src/browser/wallet-client.js)
- Prover와 deposit proof HTTP 계약: [`src/privacy/prover.js`](../src/privacy/prover.js)
- One-Proof payload와 route version: [`src/privacy/batch-transfer.js`](../src/privacy/batch-transfer.js)
- Cosmos message와 broadcast: [`src/transport/cosmos-client.js`](../src/transport/cosmos-client.js)
- EVM privacy precompile: [`src/transport/evm.js`](../src/transport/evm.js)
