# Note Reservation 상태 전이

## 목적

이 문서는 private note가 scan inventory에 들어온 뒤 계획·증명·제출·재조정되는 전체 사용 lifecycle과, ClairveilJS의 `NoteReservationManager`가 중복 사용을 막기 위해 영속화하는 **reservation 상태**를 함께 설명한다.

`Discovered`와 `Available`은 scan/note inventory 관점의 개념적 사전 상태다. 상태 vocabulary와 전이 계약에는 포함되지만, `reserveNotes(...)`와 `reservePlan(...)`이 만드는 신규 persisted reservation record는 반드시 `Reserved`에서 시작한다. 따라서 실제 Reservation Store의 정상 영속 lifecycle은 `Reserved → Proving → ProofReady → Submitted → ConfirmedSpent`다.

이 상태는 payment 자체의 성공 여부가 아니라, 특정 note를 계획·증명·제출·재조정하는 동안 안전하게 잠그고 해제하는 lifecycle이다. `operation_status`는 별도의 메타데이터이므로 이 문서의 상태와 혼동하지 않는다.

## 상태 그래프

![ClairveilJS Note Reservation Lifecycle State Diagram](./assets/note-reservation-lifecycle.svg)

상단은 정상 흐름이고, 하단은 source 상태별 예외·복구 전이다. 상단의 `Discovered → Available`은 note inventory의 개념적 사전 흐름이며 `Available → Reserved` 경계에서 persisted reservation lifecycle이 시작된다. 하단의 점선 박스는 별도 상태가 아니라 상단 또는 다른 카드에 있는 같은 상태를 가리킨다. `SPECIAL`로 표시한 `Proving → Released`는 generic transition이 아니라 유효한 lease token을 확인하는 ClairveilJS store 전용 atomic release 경로다. Clairveil v0.3.1 fixture의 일반 전이 표는 이 전이를 거부하므로, 다이어그램의 `SPECIAL`은 upstream 일반 전이와 동일하다는 뜻이 아니라 현재 SDK가 추가로 제공하는 동작을 뜻한다.

다이어그램은 `npm run docs:diagram:reservation`으로 의도적으로 다시 생성한 뒤 결과 SVG를 커밋한다. 빌드나 package install에서는 자동 생성하지 않는다. 생성기는 `src/privacy/reservation.js`의 `allowedReservationTransitions`를 읽어 일반 전이 34개가 빠짐없이 정확히 한 번씩 포함됐는지 확인하고, 불일치하면 SVG를 쓰지 않고 실패한다. 이 검사는 별도 store helper인 `Proving → Released`의 upstream fixture 일치 여부를 검증하지 않는다. `npm run docs:diagram:check`는 커밋된 SVG를 덮어쓰지 않고 생성 결과와 같은지만 확인한다.

## 주요 상태의 의미

| 상태 | 의미 | 주의할 점 |
| --- | --- | --- |
| `Discovered` | scan에서 발견됐으나 아직 spendable inventory로 확정되지 않은 note의 개념 상태 | 신규 persisted reservation record로 생성되는 상태가 아니다. 검증 실패는 개념적으로 `Failed`에 해당한다. |
| `Available` | 계획에 사용할 수 있는 검증된 note의 inventory 상태 | 신규 persisted reservation record로 생성되는 상태가 아니다. 선택 시 manager가 `Reserved` record를 만든다. |
| `Reserved` | 선택된 note를 durable inventory lock으로 확보한 상태 | persisted reservation lifecycle의 시작이다. worker lease는 아직 없고 취소 시 `Released`로 이동할 수 있다. |
| `Proving` | prover 실행을 위해 batch lease를 획득한 상태 | lease token이 필요한 상태다. 현재 일반 prepare helper는 준비 중 오류가 나면 유효한 lease로 atomic rollback을 호출해 `Released`로 만들 수 있다. |
| `ProofReady` | proof와 prepared payload가 준비된 상태 | broadcast 전 proof 폐기, wallet 거절, relay handoff를 안전하게 기록·처리해야 한다. |
| `Submitted` | manager에 제출 metadata가 기록된 상태 | 저수준 manager는 transport를 구분하지 않고 `txHash` 또는 `txBytesHash` 중 하나를 요구한다. `signDocHash`만으로는 만들 수 없다. |
| `Unknown` | transaction이 네트워크에 도달했을 가능성이 있으나 결과를 확정할 수 없는 상태 | 재전송하기 전에 transaction과 nullifier 상태를 reconcile해야 한다. |
| `ConfirmedSpent` | 온체인 evidence로 입력 note의 소비가 확인된 상태 | terminal 상태다. |
| `ReplanRequired` | 새 transaction 계획이 필요한 상태 | 새 계획은 다시 `Reserved`로 시작한다. |
| `ManualReview` | 자동 판단으로 note를 재사용하면 안 되는 격리 상태 | operator 승인과 chain/payload 이력 검토가 필요하다. |
| `Released` | 현재 persisted reservation의 lock을 해제한 상태 | note inventory 관점에서는 다시 available하며, 다음 고수준 계획은 새 `Reserved` record로 시작할 수 있다. |
| `Failed` | 현재 경로가 실패한 상태 | 필요하면 `ReplanRequired`로 옮겨 새 계획을 세운다. |

그래프의 일반 상태 전이는 전체 lifecycle vocabulary인 `allowedReservationTransitions`와 일치한다. 다만 store의 신규 record 생성 계약은 이보다 좁아서 `Reserved`만 허용한다. `Proving → Released`는 generic `transitionBatch(...)`가 아니라 유효한 lease token을 확인하는 `releaseReservedOrProving(...)`의 atomic release 경로이며, v0.3.1 fixture의 rejected transition을 일반 표에 추가한 것이 아니라 ClairveilJS store가 별도로 구현한 예외다.

## Reservation 상태와 Operation 결과

`ConfirmedSpent`는 input note의 nullifier가 온체인에서 사용됐다는 뜻이다. 이것만으로 payment 또는 payroll item의 성공을 의미하지 않는다.

현재 `reconcileSpentNotes(...)`의 generic matcher는 transport를 저장하거나 구분하지 않는다. 저장된 `submitted_tx_hash` 또는 `tx_bytes_hash` 중 하나와 reconcile evidence의 같은 identity가 일치하고 예상 output commitment, disclosure digest, recipient/amount/denom evidence가 모두 맞으면 operation 성공으로 판정할 수 있다. 따라서 EVM의 서명 전 canonical request binding인 `txBytesHash`도 manager 내부에서는 identity match로 계산된다. 고수준 EVM send helper는 wallet이 반환한 network `txHash`를 `Submitted`에 기록하지만, EVM receipt나 RPC identity를 반드시 요구하는 정책은 caller의 operation DB 또는 reconcile 입력 검증에서 별도로 강제해야 한다. Evidence가 부족하면 reservation은 spent 상태로 격리하면서 operation은 `ManualReview`가 될 수 있고, 명시적인 불일치는 `ConflictSpent`가 된다.

| 구분 | 대표 상태 | 의미 |
| --- | --- | --- |
| Reservation status | `Reserved`, `ProofReady`, `ConfirmedSpent` | 개별 input note를 안전하게 잠그고 소비 여부를 관리한다. |
| Operation status | `Planned`, `Submitted`, `Succeeded`, `ConflictSpent` | 여러 input/output을 포함한 transaction 또는 payment 결과를 관리한다. |

같은 `operation_id`에 연결된 여러 reservation은 lifecycle 상태가 원자적으로 일치해야 한다. 일부 input만 다른 상태가 되면 `OPERATION_STATE_MIXED`로 처리하며, output evidence 충돌은 `OPERATION_EVIDENCE_CONFLICT`로 보고한다.

## 상태 변경 API

아래 manager API 표는 `Reserved`에서 시작하는 persisted reservation lifecycle을 대상으로 한다. `reserveNotes(...)`와 `reservePlan(...)`은 `Discovered` 또는 `Available` record를 저장하지 않는다.

| API | 상태 변화 또는 효과 | 현재 구현이 검사하는 조건 |
| --- | --- | --- |
| `reserveNotes(...)` / `reservePlan(...)` | 선택한 note의 `Reserved` record를 원자적으로 생성 | 동일 note를 막는 active reservation이 없어야 한다. |
| `markProving(...)` | `Reserved → Proving` | manager가 발급한 batch lease token |
| `markProofReady(...)` / `markProofReadyBatch(...)` | `Proving → ProofReady` | 유효한 lease와 payload/proof binding evidence |
| `heartbeatLease(...)` / `renewLease(...)` | 상태 유지, lease 연장 | 현재 manager 소유의 만료되지 않은 lease |
| `recordRelayHandoff(...)` | `ProofReady` 유지, relay payload handoff evidence 기록 | payload hash 일치, broadcast 시작 전, 유효한 lease |
| `markBroadcastAttempting(...)` | `ProofReady` 유지, `broadcast_in_flight`와 attempt count 기록 | 외부 broadcast 경계를 넘기기 직전 호출, 유효한 lease |
| `markSubmitted(...)` | `ProofReady → Submitted` | 사전 `markBroadcastAttempting(...)` 기록, 유효한 lease와 `txHash` 또는 `txBytesHash`. manager는 transport나 hash 의미를 구분하지 않음 |
| `markUnknown(...)` | `ProofReady/Submitted → Unknown` | 사전 broadcast attempt, 유효한 lease와 `txHash` 또는 `txBytesHash`. `signDocHash`만으로는 부족 |
| `markBroadcastRejected(...)` | `ProofReady → ReplanRequired` | wallet이 broadcast 전에 거절했고 proof 폐기를 기록할 수 있어야 한다. |
| `markReplanRequired(...)` | 허용된 상태에서 `ReplanRequired` | source 상태별 proof 폐기·expiry·nullifier·transaction failure evidence |
| `transitionBatch(...)` | 허용된 일반 전이를 여러 reservation에 원자적으로 적용 | 전용 helper가 없는 전이에만 사용하는 저수준 CAS API. 허용 전이, lease, source 상태별 evidence 규칙을 그대로 검증한다. |
| `releaseReservedOrProving(...)` | `Reserved/Proving → Released` | `Proving`은 현재 batch lease token 필요 |
| `markManualReview(...)` | 허용된 상태에서 `ManualReview` | lease가 필요한 source 상태에서는 현재 lease 필요 |
| `resolveManualReview(...)` | `ManualReview → Released/ReplanRequired/Failed` | `operatorId`, `approvalReference`; `reason` 기록 권장 |
| `reconcileSpentNotes(...)` | 허용된 상태에서 `ConfirmedSpent`, operation evidence에 따라 quarantine/성공 판정 | literal spent evidence와 저장된 `txHash`/`txBytesHash` 중 하나에 대한 match 및 필요한 output evidence. transport별 network identity는 별도로 강제하지 않음 |

## 안전 규칙

1. 전체 note 사용 흐름은 개념적으로 `Discovered → Available → Reserved → Proving → ProofReady → Submitted → ConfirmedSpent`다. 이 중 persisted reservation 정상 경로는 `Reserved`에서 시작한다.
2. `Proving`과 `ProofReady`는 worker lease를 유지한다. 만료된 lease로 상태를 진행시키지 않고 reconcile 또는 `ManualReview` 경로를 사용한다.
3. `ProofReady`에서 wallet이 거절하거나 proof를 폐기했다면, proof가 실제로 폐기됐음을 증명할 수 있을 때만 `ReplanRequired`로 이동한다. 그렇지 않으면 `ManualReview`로 격리한다.
4. `Submitted`나 `Unknown`을 `ReplanRequired` 또는 `Failed`로 바꾸려면 input nullifier가 미사용이며 기록된 transaction이 부재하거나 실패했음을 모두 확인해야 한다. 실패 응답 하나만으로는 어느 상태로도 이동할 수 없다.
5. Relay payload를 relayer에 전달한 뒤에는 TTL 만료나 로컬 취소만으로 note를 release하지 않는다. relayer가 제출했을 가능성을 포함해 온체인 evidence로 reconcile한다.
6. `ManualReview` 해제에는 `operatorId`와 `approvalReference`가 필수이며 `reason`도 운영 감사용으로 기록하는 것이 좋다.
7. `ConfirmedSpent`와 operation `Succeeded`를 같은 의미로 사용하지 않는다. 다중 input operation은 모든 linked reservation과 output evidence를 한 번에 reconcile한다.
8. 현재 일반 prepare helper는 prover/payload 준비 중 오류에서 `rollbackPlanReservation(...)`을 호출한다. lease가 유효한 `Proving` reservation은 이때 직접 `Released`가 되며, 이는 remote solver나 async job이 실제로 중단됐다는 evidence가 아니다.

## 구현 참조

- 상태 정의와 허용 전이: `src/privacy/reservation.js`
- manager API와 전이별 입력 조건: `src/privacy/reservation.d.ts`
- browser DApp에서의 reservation 운영 예시: `README.ko.md`의 `Note reservation` 절
