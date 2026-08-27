# ClairveilJS 오류·복구 가이드

## 목적과 원칙

이 문서는 ClairveilJS 호출이 실패했을 때 오류를 분류하고, transaction을 재시도해도 되는지 또는 먼저 reservation과 온체인 상태를 reconcile해야 하는지 판단하는 기준을 설명한다.

가장 중요한 원칙은 다음과 같다.

> Transaction이 네트워크에 도달했을 가능성이 한 번이라도 있으면 새 transaction을 만들거나 재제출하기 전에 기존 transaction identity, nullifier와 output evidence를 reconcile한다.

- 배포와 endpoint 설정: [설정 가이드](./configuration.ko.md)
- 저장소 초기화, 재시작과 key rotation: [저장소·영속성](./storage-and-persistence.ko.md)
- reservation 상태와 evidence guard: [Note Reservation 상태 전이](./reservation-state-machine.ko.md)
- 외부 endpoint와 성공 판정: [API 매핑](./api-mapping.ko.md)

## 오류가 나타나는 네 가지 형태

ClairveilJS의 실패는 하나의 예외 형식으로만 나타나지 않는다.

| 형태 | 예 | 처리 기준 |
| --- | --- | --- |
| `ClairveilError` throw | planner, prover, operation consistency | `isClairveilError(error)`와 `error.code`로 분기하고 `details`를 진단에 사용 |
| 일반 `Error` throw | profile 검증, endpoint/response shape, wallet/network mismatch, reservation guard | message는 진단용이다. 문자열 전체를 장기적인 프로그램 계약으로 사용하지 않는다. |
| 결과 객체 | planner의 `status`, 일부 broadcast/wait API의 `ok`, `error`, `errors` | Promise가 resolve됐다는 이유만으로 성공으로 판단하지 않고 명시적 status를 확인 |
| Reservation/operation 상태 | `Unknown`, `ManualReview`, `ConfirmedSpent`, `ConflictSpent` | 현재 durable state를 읽고 상태 전이 문서의 evidence 규칙을 따른다. 원래 exception보다 이 상태가 재사용 안전성의 기준이다. |

외부 wallet/provider가 돌려주는 `code`는 `ClairveilErrorCode`와 같은 namespace가 아니다. 예를 들어 EIP-1193의 사용자 거절 `4001`은 provider code이며 SDK의 stable error code로 바꾸지 않고 원래 오류로 다시 throw될 수 있다.

## `ClairveilError` 사용법

```js
import {
  ClairveilErrorCode,
  isClairveilError
} from "clairveiljs/errors";

try {
  await runPrivacyOperation();
} catch (error) {
  if (isClairveilError(error, ClairveilErrorCode.PROVER_TIMEOUT)) {
    // 현재 reservation 상태와 broadcast evidence를 확인한 뒤 복구한다.
  } else {
    throw error;
  }
}
```

`ClairveilError`의 공통 필드는 `code`, `message`, `details`다. Prover 오류는 가능한 경우 `status`, `proverCode`, `retryable`도 노출한다. `details.cause`에는 원래 오류나 민감한 request 정보가 포함될 수 있으므로 사용자 메시지나 원격 로그에 그대로 직렬화하지 않는다.

## 현재 발생하는 Stable Error Code

아래 코드는 현재 SDK가 `ClairveilError`로 생성하는 계약이다.

| 코드 | 발생 조건 | 권장 처리 |
| --- | --- | --- |
| `INVALID_ARGUMENT` | 지원하지 않는 wallet type 또는 분류되지 않은 planner 실패 | 입력과 active profile을 수정하고 처음부터 다시 준비 |
| `INVALID_AMOUNT` | 0 이하 또는 유효하지 않은 amount plan | 사용자 입력 수정 |
| `INSUFFICIENT_BALANCE` | 검증된 spendable note 합계 부족 | deposit/수신 또는 scan 갱신 후 새 plan |
| `SELF_MERGE_REQUIRED` | input 제한 때문에 먼저 self-merge가 필요 | `error.details.plan`의 action과 next amount로 별도 self-merge 수행 |
| `ZERO_DUMMY_REQUIRED` | transfer shape에 zero helper note가 필요 | helper note 생성 후 새 plan |
| `EXACT_NOTE_REQUIRED` | withdraw에 정확히 일치하는 단일 note가 필요 | shielded self-transfer로 exact note를 만든 뒤 재계획 |
| `PROVER_UNAVAILABLE` | prover URL 없음, retryable HTTP/network failure | endpoint 상태를 확인. reservation이 안전한 pre-broadcast 상태인지 확인한 뒤 동일 checkpoint에서 재시도 |
| `PROVER_TIMEOUT` | prover 요청 또는 async job timeout/abort | 응답이 늦게 완료될 수 있는 adapter인지 확인하고 checkpoint/job ID로 조회. 새 proof를 무조건 중복 요청하지 않음 |
| `PROVER_CANCELLED` | client의 prover 대기 또는 async job poll 취소 | client wait가 끝났다는 뜻일 뿐 in-process solver 종료를 보장하지 않는다. Durable reservation을 다시 읽는다. `Proving`/`ProofReady`는 자동 release 대신 격리되며 만료·foreign lease는 명시적 reconcile이 필요할 수 있다. Job/checkpoint는 별도 operation store에서 추적한다. |
| `PROVER_REJECTED` | non-retryable prover 응답 또는 proof job 실패 | payload/circuit/config 불일치 조사. 같은 입력의 blind retry 금지 |
| `OPERATION_STATE_MIXED` | 같은 operation의 linked reservation 상태가 서로 다름 | `details.reservations`를 확인하고 operation 전체를 격리·reconcile |
| `OPERATION_EVIDENCE_CONFLICT` | tx/output/disclosure evidence가 persisted expectation과 충돌 | `details.conflicts`를 보존하고 `ManualReview` 또는 `ConflictSpent` 처리 |

다음 상수도 export되지만 현재 SDK 구현이 일관되게 생성하는 runtime outcome으로 보장되지는 않는다.

- `WALLET_UNAVAILABLE`
- `ROOT_SIGNATURE_REQUIRED`
- `SIGNER_MISMATCH`
- `DISCLOSURE_UNAVAILABLE`
- `TX_BROADCAST_FAILED`

이 값만을 기대해 catch 분기를 만들지 않는다. Wallet, disclosure, broadcast 경로는 일반 `Error`, provider 오류, 결과 객체 또는 reservation 상태로 실패할 수 있다. 향후 release에서 실제 발생 계약이 추가되면 해당 버전의 changelog와 이 문서를 함께 갱신한다.

## 단계별 복구 기준

| 실패 단계 | 네트워크 도달 가능성 | 안전한 다음 행동 |
| --- | --- | --- |
| Profile/config 검증, `health()`, chain/wallet network mismatch | 없음 | 설정을 수정하고 preflight부터 다시 실행 |
| Planner가 `canBuildTx: false` 또는 planner error | 없음 | plan의 `status`, `action`, `facts`에 따라 잔액·note shape를 해결하고 새 plan 생성 |
| Prover 호출 전 payload/config 검증 실패 | 없음 | 입력, circuit, audit/disclosure/asset config를 수정. 기존 reservation은 helper가 기록한 상태에 따라 release/replan |
| Prover timeout/unavailable/rejected/cancelled | 일반적으로 broadcast 전이지만 proof job과 in-process solver는 남을 수 있음 | adapter job/checkpoint와 현재 reservation을 확인. 같은 witness를 다른 endpoint로 보내거나 proof를 중복 생성하지 말고 reconcile 후 retry/replan |
| Wallet이 명시적으로 서명·제출을 거절 | 명시적 provider 거절이 broadcast 전임을 보장할 때 없음 | SDK helper가 proof 폐기 evidence와 `ReplanRequired`를 기록했는지 확인. 단순 catch만으로 note를 release하지 않음 |
| RPC broadcast가 시작됐거나 결과가 불명 | 있음 | `Unknown`으로 유지하고 network `txHash`, artifact binding, nullifier와 chain evidence로 reconcile. Cosmos exact signed `txBytesHash`는 network identity로 연결할 수 있지만 EVM request binding hash는 RPC 조회 키가 아님. 새 transaction 재제출 금지 |
| Tx/receipt가 명시적으로 실패 | 있음 | 입력 nullifier가 미사용이고 기록된 tx가 실패 또는 부재했음을 모두 확인한 뒤 `Failed` 또는 `ReplanRequired` |
| Nullifier spent 확인 | 확정 | reservation은 `ConfirmedSpent`. Payment/operation 성공은 별도 output evidence로 판정 |
| Evidence 부족·충돌 또는 lease/bookkeeping 오류 | 불명 | `ManualReview`로 격리하고 operator/chain evidence 확인 |

Historical Merkle path 조회가 `ResourceExhausted`를 반환하면 public
non-current rebuild 한계에 도달한 것이다. 같은 historical request를 여러 public
provider로 자동 failover하지 말고 current root로 다시 계획하거나 trusted local
historical-path index를 사용한다. Clairveil v0.3.1의 public 한계는 1,024 leaves와
keeper process당 동시 rebuild 2개이고, offline recovery/export 상한은
1,048,576 leaves다.

## Prover 취소·재시도 경계

`AbortSignal`, HTTP timeout 또는 async poll 취소는 **client wait cancellation**이다.
이미 admission permit을 얻은 in-process solver를 preempt하거나 memory를 반환했다는
evidence가 아니다. Hard termination과 OOM containment는 prover 운영자가
supervised process isolation으로 제공해야 한다.

- `retryable=true`, HTTP 429, timeout과 queue saturation은 다른 prover endpoint로 failover할 권한이 아니다.
- 기본 정책은 명시적으로 선택한 endpoint 한 곳과 automatic failover 비활성화다.
- Same-endpoint retry를 제품 adapter에서 구현한다면 원래 payload/checkpoint와 duplicate proof job 여부를 먼저 확인한다. 일반 prepare helper가 실패를 반환한 뒤에는 release 또는 ownership 유지 어느 쪽도 가정하지 말고 durable reservation을 다시 읽는다.
- 추가 endpoint로 같은 private witness를 보내려면 privacy boundary 확대를 사용자 또는 제품 정책이 명시적으로 승인해야 한다.
- 현재 일반 transfer/withdraw prepare helper는 준비 중 오류를 catch하면 `rollbackPlanReservation(...)`을 호출한다. `Reserved`만 release하고 `Proving`/`ProofReady`는 lease 전이가 허용될 때 `ManualReview`로 이동한다. 만료·foreign lease 때문에 전이가 거부되면 cleanup failure를 원래 error에 첨부하고 durable operation은 reconcile 전까지 잠긴 상태로 둔다.

## Broadcast 경계와 `Unknown`

Reservation-aware broadcast helper는 외부 호출 직전에 `broadcast_in_flight`와 attempt evidence를 기록한다. 이후 결과를 다음처럼 처리한다.

- 고수준 broadcast helper가 제출 결과 identity를 받으면 `Submitted`
- transaction이 도달했을 수 있으나 결과가 불명확하면 `Unknown`
- 명시적인 pre-broadcast wallet rejection이며 proof 폐기를 안전하게 기록할 수 있으면 `ReplanRequired`
- provider 응답이나 bookkeeping 상태를 안전하게 판정할 수 없으면 `ManualReview`

오류 객체에 `reservationReconciliationRequired: true`와 `reservationBookkeepingError`가 붙어 있으면 transaction은 broadcast됐거나 broadcast 결과를 처리하는 과정에서 durable 상태 기록이 실패한 것이다. 원래 오류와 transaction identity를 보존하고 즉시 reconcile한다.

Cosmos 고수준 signer는 signed TxRaw에서 정확한 network `txHash`를 파생해 RPC 전에
저장한다. 즉시·indexed hash는 그 byte를 식별해야 하며 없거나 다르면 `Unknown`을
유지한다. 선택적인 synchronous `beforeBroadcast(identity)`는 RPC 직전 non-sensitive
identity를 caller fence에 복사할 수 있고, async callback은 거부된다.

Reservation-bound `signDirectAndBroadcast(...)`는 `renewLease`를 요구하고 wallet 접근
전부터 durable outcome 기록까지 heartbeat를 유지한다. 최초 갱신 실패는 wallet 접근
전에 중단하며, RPC 이후 실패는 attempt/`Unknown` 복구 경로를 따른다.

Signed one-proof payroll artifact에는 canonical 64-byte secp256k1
`SIGN_MODE_DIRECT` signature 하나만 허용한다. SDK는 exact body/auth byte, chain ID,
account number에 대한 signature를 검증한 뒤 signer에서 파생한 유일한
`MsgBatchTransfer.creator`와 proven execution에서 재구성한 message를 확인한다.
`tx_hash`(TxRaw SHA-256 대문자), `tx_bytes_hash`(같은 digest 소문자),
`sign_doc_hash`(canonical SignDoc binding)를 SDK가 파생하며 caller hash는 identity
input이 아닌 assertion이다.

`inspectOneProofPayrollArtifactRetry(...)`는 transaction을 모든 input nullifier보다 먼저
조회하고, transaction 부재와 전체 input 미사용이 확인될 때만 저장하지 않는 일회용
`retry_decision`을 발급한다. Decision은 artifact와 exact identity에 binding되고 process
clock 기준 30초 또는 payload expiry 중 이른 시점에 만료된다.

`retransmitOneProofPayrollArtifact(...)`는 authoritative manager를 요구하며 불일치,
만료, 재사용, 위조 decision을 거부한다. Exact reservation set을 다시 읽고 identity
3개와 현재 `ProofReady` owner/token lease를 검증한 뒤 heartbeat하며 exact byte를 보낸다.
성공은 `Submitted`, 모호한 callback 또는 bookkeeping 실패는 `Unknown`을 기록한다.
Exact `Submitted`/`Unknown` retry는 lease 없이 기존 상태를 유지한다.
`markOneProofPayrollReservationBroadcastAttempting(...)`의 idempotency는 RPC 권한이
아니며 restart나 만료된 `ProofReady` lease도 재전송 권한이 아니다.
`markOneProofPayrollReservationSubmitted(...)`는 identity 3개를 모두 요구한다. Restart
또는 실패 후에는 tx/nullifier evidence를 새로 조회한다. 만료 lease 복구는 아래 절을
따른다.

Staged batch finalize는 exact reservation ID를 다시 읽고 operation, lease owner/token,
nullifier lookup-key 집합을 검증하므로 같은 수의 다른 reservation으로 바꿀 수 없다.
Concrete store는 fresh-state 초기화만 허용하며 production 변경은 검증된 CAS, lease,
reconciliation API로만 수행한다. 전체 transition guard는
[reservation state machine](./reservation-state-machine.ko.md)을 참고한다.

`signDocHash`는 prepared/signed artifact의 binding을 보조하며 단독으로 `Submitted`를 만들 수 없다. 현재 저수준 `markSubmitted(...)`은 transport를 구분하지 않고 `txHash` 또는 `txBytesHash` 중 하나를 받으므로 EVM canonical request binding만으로도 형식상 `Submitted`를 만들 수 있다. 반면 고수준 EVM send helper는 wallet/provider가 반환한 network `txHash`를 기록한다. EVM의 `txBytesHash`는 receipt 조회 키가 아니므로, 저수준 manager를 직접 사용하는 caller는 state 이름만으로 network 제출이 증명됐다고 해석하지 않는다.

## `Failed`와 `ReplanRequired`의 이중 Evidence

`Submitted` 또는 `Unknown`에서 `Failed`나 `ReplanRequired`로 이동하려면 다음 두 조건이 모두 필요하다.

1. `nullifier_unspent_confirmed`: input nullifier가 미사용임을 확인
2. `tx_absent_or_failed_confirmed`: 기록된 transaction이 부재하거나 실패했음을 확인

```js
await reservationManager.transitionBatch(
  reservationIds,
  "Unknown",
  "Failed",
  {
    metadata: {
      nullifier_unspent_confirmed: true,
      tx_absent_or_failed_confirmed: true,
      checked_height: checkedHeight,
      tx_hash_checked: txHash
    }
  }
);
```

실패 receipt 하나만 확인하고 nullifier 조회를 생략하거나, nullifier 미사용만 보고 tx lookup을 생략하면 안 된다. 어느 한쪽이 불명확하면 `Unknown` 또는 `ManualReview`에 유지한다.

`markBroadcastFailed(...)`는 이 evidence 검증을 `ProofReady`, `Submitted`, `Unknown`에
적용한다. `Submitted`/`Unknown`은 lease 없이 reconcile할 수 있지만 live `ProofReady`는
현재 manager의 일치하는 미만료 `leaseToken`도 요구한다. 누락·foreign·stale·expired
credential은 fail closed한다.

Foreign lease가 만료된 attempted `ProofReady` operation에는
`recoverExpiredProofReadyBroadcastFailure(...)`만 사용한다. 이 API는 complete linked
operation과 lookup-key 집합, 저장된 network-tx/tx-bytes/sign-doc identity, positive
height, confirmed execution failure(단순 부재는 불충분), 전체 input 미사용을 원자적으로
검증한다. 성공 시 identity·attempt·failure evidence를 보존하고 lease/marker만 정리하며
동일 evidence는 idempotent하다. Live lease, mixed/partial state, spent input, identity
conflict는 operation을 바꾸지 않는다.

`transitionBatch(...)`는 전용 helper가 없는 전이에 사용하는 저수준 CAS API다. 허용 전이, lease와 evidence guard를 우회하지 않으며, 일반 제품 코드에서는 `markSubmitted`, `markUnknown`, `markReplanRequired`, `resolveManualReview` 같은 전용 helper를 우선한다.

## `ConfirmedSpent`와 Operation 성공

`ConfirmedSpent`는 input note의 nullifier가 온체인에서 소비됐다는 뜻이다. 다음 항목을 검증하기 전에는 payment, payroll item 또는 transfer가 의도대로 성공했다고 보고하지 않는다.

- Cosmos/legacy는 저장된 transaction identity와 reconcile evidence의 일치. EVM tag는 저장된 network `txHash`와 prepared `txBytesHash`가 각각 일치하고 successful receipt, RPC transaction identity, privacy event 검증이 모두 참이어야 함
- expected output commitment
- recipient, amount, denom 또는 그 binding hash
- disclosure digest와 policy evidence
- multi-input operation의 모든 linked reservation

Evidence가 부족하면 spent input을 재사용하지 못하게 유지하면서 operation을 `ManualReview`로 둘 수 있다. 명시적인 mismatch는 `ConflictSpent`와 `OPERATION_EVIDENCE_CONFLICT`로 기록한다.

## Manual Review 해제

`ManualReview`에서 `Released`, `ReplanRequired` 또는 `Failed`로 이동하려면 다음 operator evidence가 필요하다.

- `operatorId`
- `approvalReference`
- 감사 로그를 위한 `reason` 권장

Operator는 저장된 payload/proof hash, transaction identity, relay handoff, chain height, nullifier와 output evidence를 확인한다. 단순 TTL 만료, 로컬 취소 또는 “오래 기다렸다”는 이유만으로 note를 release하지 않는다.

`ManualReview`에서 `ProofReady`로 직접 돌아가는 자동 복구 전이는 없다. Checkpoint 이후 격리된 batch도 운영자가 evidence를 검토해 `Released`, `ReplanRequired`, `Failed` 중 하나로 해결해야 하며, 계속 실행하려면 그 결과에 맞춰 새 plan과 proof를 만든다.

## 안전한 로그와 사용자 메시지

다음 값은 로그, analytics, error-reporting 서비스에 남기지 않는다.

- privacy root signature와 root seed
- spend/view/disclosure private material
- note amount, randomness, nullifier, 복호화된 note와 note plaintext JSON
- Merkle path와 prepared payload body
- prover request/response body, private payload와 proof checkpoint 원문
- disclosure plaintext와 검증 report 원문
- reservation 암호화 키와 `indexKey`
- bearer token, wallet provider request 원문

운영 로그에는 error code, 단계, profile ID, endpoint의 origin, reservation/operation의 비밀이 아닌 opaque ID, 축약된 tx hash, checked height 정도만 남긴다. 전체 tx hash는 transaction 조회와 reconcile에 필요한 access-controlled operation store에만 보관하고 일반 로그, analytics, crash report에는 남기지 않는다. `error.details`, `cause`, request body를 자동 직렬화하지 않고 allowlist 기반으로 redaction한다.

사용자에게는 “재시도 가능”, “체인 확인 중”, “수동 검토 필요”처럼 행동 가능한 메시지를 보여주고 내부 exception message나 provider 응답 전체를 노출하지 않는다.

## 구현 참조

- Error code와 wrapper: `src/core/errors.js`
- Planner status와 error: `src/privacy/planner.js`
- Prover 오류 정규화: `src/privacy/prover.js`
- Cosmos broadcast와 reservation bookkeeping: `src/transport/cosmos-client.js`
- EVM submit과 reservation bookkeeping: `src/transport/evm.js`
- Evidence guard와 reconcile: `src/privacy/reservation.js`
