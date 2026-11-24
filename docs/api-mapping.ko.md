# ClairveilJS API 매핑

## 목적과 범위

이 문서는 브라우저 DApp에서 호출하는 ClairveilJS API가 실제로 어떤 **chain REST/RPC**, **prover HTTP 계약**, **Cosmos message**, **EVM privacy precompile**로 이어지는지 추적할 수 있게 한다.

순수 crypto·codec·schema helper의 전체 symbol reference가 아니라, 외부 시스템과 통신하거나 transaction을 만드는 고수준 흐름을 대상으로 한다. 각 메서드의 전체 인자와 반환 타입은 package export map의 TypeScript declaration을 기준으로 한다.

- 시스템 배치와 신뢰 경계: [시스템 아키텍처](./architecture.ko.md)
- note 중복 사용 방지와 제출 후 복구: [Note Reservation 상태 전이](./reservation-state-machine.ko.md)
- endpoint와 client option: [배포·클라이언트 설정](./configuration.ko.md)
- 오류 형태와 재시도 판단: [오류·복구](./errors-and-recovery.ko.md)


## Core v0.6.1 protobuf 바인딩

미출시 `clairveiljs/cosmos-v2` 진입점은 `AuditAuthorizationV2`, `OutputEffectV2`, 7종 `Msg*V2` codec과 응답, audit query codec 6종, `msg*V2TypeUrl` 상수 7종, `createClairveilV2Registry(extraTypes?)`를 제공한다. Root도 V2 접미사가 붙은 이름을 export한다. 원본 생성 바인딩은 `clairveiljs/generated/clairveil/privacy/v2/tx`와 `/query`에서 `.js` 확장자 유무와 관계없이 import할 수 있다.

이 범위는 wire 바인딩이다. Amount는 문자열, protobuf `uint64`/`int64`는 `bigint`, byte 필드는 `Uint8Array`다. V2 registry는 표준 Cosmos 메시지와 자산 메시지 4종·관리 메시지 3종을 등록하며 privacy V1 메시지는 등록하지 않는다. 기존 `MsgDeposit`과 `createClairveilRegistry`는 V1을 유지한다. 아래 전용 V2 workflow는 준비·audit authorization·proving을 연결하며 일반 체인 서명·제출은 host가 담당한다. Codec import만으로 해당 흐름이 활성화되거나 거래 의미가 검증되지는 않는다.

생성 입력은 Core `v0.6.1`, commit `fad307abddd0daa1c880f2e423668f5c58a0e578`의 V1/V2 proto 6개이며 `fixtures/clairveil-v0.6.1-proto/manifest.json`으로 고정한다. V1 reserve query에는 `liability`, `collateralized`, `surplus`, `shortfall`이 추가된다. 과거 V1 proto 원본은 `fixtures/clairveil-v0.3.1/proto/`로 옮겼다. 기존 lifecycle fixture와 v0.4.0 deposit prover의 기준 소스는 각각 유지한다. `supportedClairveilProtoRelease`/`supportedClairveilProtoCommit`은 proto 출처만 나타내며 실제 protocol 지원 선언이 아니다.

`npm run codegen:proto`로 TypeScript·JavaScript·선언을 재생성하고, `npm run check:proto-freshness`로 격리된 clean 재생성과 비교한다. `npm run verify:clairveil-source`는 정확한 Core commit object와 annotated release tag에서 원본 byte를 대조한다. `test/cosmos-v2.test.js`는 중첩·반복 필드와 64비트 최댓값을 포함한 V2 메시지·audit 응답을 독립 Go vector 13개와 비교한다. 주소·proof는 합성 값으로, 실행 가능한 거래가 아니다.

Go vector 재현 시 Core에서 `git archive v0.6.1 go.mod go.sum x/privacy/types/v2`로 임시 디렉터리에 module을 추출한다. 해당 디렉터리에서 `go run -mod=readonly /absolute/path/to/clairveiljs/tools/generate-v2-proto-vectors.go`를 실행한다. 표준 출력이 `fixtures/clairveil-v0.6.1-proto/wire-vectors.json`과 정확히 같아야 한다. 검증 대상 JS codec으로 기준 byte를 생성하지 않는다.

## Uint128 금액 계획 (Core v0.6.1)

`clairveiljs/amount`는 `parseAmount128`, `sumAmounts128`, `sumAmountTotals`, `amount128ToJSON`, `amount128FromJSON`과 `maxShieldedAmountV2 = 2^128 - 1`을 제공한다. 새 금액 입력은 canonical decimal string 또는 `bigint`만 받으며 JavaScript number는 거절한다. JSON 금액은 따옴표가 있는 decimal string이다. `sumAmounts128`은 한 거래의 개별 입력과 합계를 검사한다. `sumAmountTotals`는 지갑·payroll·누적 합계를 uint128 상한 없이 음이 아닌 임의 정밀도로 계산한다. Height·epoch·account number와 기존 uint64 wire 필드의 폭은 유지한다.

`clairveiljs/note128`는 독립적인 `Note128`·`FoundNote128Input`·`NormalizedFoundNote128` 타입과 생성/정규화 함수를 제공한다. Canonical 필드만 허용하며 compact note(`am`, `rsx` 등)와 구형 cache alias(`Note`, `NullifierStatus`, `spent` 등)는 canonical 필드와 함께 있어도 거절한다. 명시적인 32바이트 nullifier가 필수이고 status 누락은 `unverified`, `isSpent: true`는 `spent`가 된다. 높이·sequence는 uint64 범위의 정확한 10진 문자열로 정규화하며 큰 높이도 숫자 순서로 정렬한다. 지정한 randomness를 사용하면 새 난수를 요청하지 않는다. 필드/금액 모델 검증이며 curve·memo·commitment를 포함한 완전한 검증은 `protocol-v2`가 담당한다. 구형 note/cache 자동 이관은 제공하지 않는다.

`clairveiljs/planner-v2`는 `planTransferNotesV2`, `planTransferBatchNotesV2`, `planWithdrawNotesV2`, `selectTransferInputsV2`, `selectBatchTransferInputsV2`, `summarizeSpendableNotesByDenomV2`를 제공한다. 기존 탐색 한도가 있는 선택 알고리즘에 Core v0.6.1 금액 정책을 적용한다. 개별 note·요청 금액·선택 입력 합계·payment와 change 합계가 uint128 범위여야 한다. Transfer는 입력 2개가 필요하며 상황에 따라 명시적인 0원 helper를 사용한다. Batch는 입력 1..16개, change 포함 출력 최대 32개다. 잘못된 금액은 `invalid_amount`, 충분한 잔액이 있지만 가능한 입력 쌍이 없으면 `note_preparation_required`를 반환한다. 지갑 합계는 uint128을 넘어도 되며 중복된 spendable nullifier는 거절한다.

`clairveiljs/reference-payroll-v2`는 `normalizePayrollInputV2`, `planOneProofPayrollV2`를 제공한다. 전체 payroll이 uint128을 넘으면 현재 존재하는 서로 다른 note를 사용해 거래별로 나눈다. Owner·reservation·output capacity를 유지하고 `total_payroll_amount`와 `total_spendable_amount`는 상한 없는 합계를 반환한다. 아직 생성되지 않은 future change를 사용하지 않는다. Plan/operation에는 `amount_model: "uint128"`, operation ID에는 `:uint128` 접미사가 붙고 circuit identity는 선언하지 않는다. 소액이라도 V1 preparer에 넘기면 거절한다. 이는 금액 계획이며 proof 준비가 완료된 거래가 아니다. Note planner의 `canBuildTx`는 금액·입력 조건 충족만 뜻한다.

01–04 구현의 V2 전용 진입점(`amount`, `note128`, `planner-v2`, `reference-payroll-v2`, `protocol-v2`, `audit-config-v2`, `cosmos-v2`)은 런타임과 타입 선언 모두 V1 실행 모듈에 의존하지 않는다. 순수한 계획/DTO·해시 domain·검증 primitive를 공유하고 payroll 실행 및 audit 조회를 분리한다. V2 payroll은 전용 진입점 또는 root/core에서 가져온다. 구형 `reference-payroll`의 V2 재수출은 폐기했다. 미출시 V1의 입력/캐시 호환을 V2에 추가하지 않는다. 기존 지갑·scan·증명·제출 구현의 교체는 후속 workflow 범위이며 현재 broad root에는 이 코드가 남아 있다. Core가 현재 규격에 사용하는 `v1` 해시 domain과 config protobuf namespace는 그대로 유지한다.

금액 규칙은 Core `v0.6.1@fad307abddd0daa1c880f2e423668f5c58a0e578`의 `x/privacy/amount/amount.go`, `x/privacy/types/amount.go`, `x/privacy/client/sdk/transfer/transfer.go`, `x/privacy/client/sdk/payroll/batch_plan.go`가 소유한다. `test/amount-planner-v2.test.js`는 0·2^64·uint128 최댓값·잘못된/numeric JSON·overflow·정확한 change·제한된 입력 선택·큰 지갑 합계·payroll 분할을 검사한다. `fixtures/clairveil-v0.6.1-amount/vectors.json`의 parse 18개·addition 6개 기준은 Go로 생성했으며 문자열 JSON 표현도 대조한다. Source 검증은 고정 commit의 원본 파일 hash를 확인한다. 재현하려면 해당 tag의 `go.mod`, `go.sum`, `x/privacy/amount`를 임시 디렉터리에 추출하고 그곳에서 `go run -mod=readonly /absolute/path/to/clairveiljs/tools/generate-amount-vectors.go`를 실행한다. 표준 출력은 fixture byte와 같아야 한다.

## Fixed-v2 codec (Core v0.6.1)

`clairveiljs/protocol-v2`와 root/core export는 `privacy-fixed-v2`, binary version 2를 구현한다. Note·disclosure 금액은 big-endian 16바이트다. SHA-256으로 만든 16바이트 tag는 `clairveil.note-plaintext.v2`, `clairveil.disclosure-plaintext.v2`, `clairveil.encrypted-envelope.v2`를 사용한다. Core는 `Note`, `MarshalNotePlaintextV1` 같은 Go 이름을 유지하며 JS에서는 명시적인 V2 이름으로 새 wire byte를 선택한다. Note commitment/nullifier·asset·view-tag hash domain은 기존 Core 식별자를 유지한다.

| Payload | 정확한 바이트 수 |
| --- | ---: |
| Note 평문 / disclosure 평문 | 358 / 400 |
| Deposit note envelope / transfer note envelope | 406 / 438 |
| User / audit / self-view disclosure envelope | 480 |

`validateNoteV2`, `marshalNotePlaintextV2`, `unmarshalNotePlaintextV2`, `computeNoteCommitmentV2`, `computeNoteNullifierV2`는 uint128 금액, canonical BN254 field, identity가 아닌 prime-subgroup key, 최대 128바이트 UTF-8 memo를 검사한다. `validateDisclosurePlaintextV2`, `marshalDisclosurePlaintextV2`, `unmarshalDisclosurePlaintextV2`는 user policy 1..7·동일 bitmap·숨긴 필드의 0 sentinel 또는 full-disclosure marker를 강제한다. Decoder는 잘못된 길이·domain·version·reserved bit·비정규 field·구형 payload를 거절한다. `decodeEncryptedEnvelopeV2`는 분리된 ciphertext 사본을 반환하고 `unwrapEncryptedEnvelopeV2`는 예상 kind까지 요구한다.

`encryptDepositNoteV2`/`decryptDepositNoteV2`는 32바이트 RootSeed와 Core의 AES-GCM seed-key 형식을 사용한다. `encryptNoteForTransferV2`/`decryptTransferNoteV2`, `encryptDisclosureV2`/`decryptDisclosureV2`는 기존 Edwards ECIES/AES-GCM primitive를 사용한다. Transfer 암호화는 제공된 commitment와 note의 일치를 검사한다. 선택적인 transfer 복호화 binding은 commitment·output index·2바이트 view tag를 함께 요구하며 tag와 복구 note commitment를 모두 검사한다. Disclosure 암복호화는 예상 user/full plane을 검사한다. 비밀 scalar는 0보다 크고 subgroup order보다 작아야 하며 난수 생성 실패는 fallback 없이 전파한다.

`computeDisclosureDigestV2(payload, scheme)`, `verifyDisclosureDigestV2(payload, expectedDigest, scheme)`는 circuit마다 필드 순서·domain이 다르므로 `"transfer"` 또는 `"batch"` scheme을 명시해야 한다. Digest 검증은 canonical 0이 아닌 32바이트 expected digest와 불일치하면 거절한다. Raw decode/복호화만으로 외부 digest나 chain metadata를 검증하지 않는다. 이 API는 고정 wire·암호 호환 helper이며 scan admission·audit-field authorization·거래 준비 또는 native constant-time 실행 보장을 뜻하지 않는다. 기존 V1 진입점은 원래 wire 동작을 유지한다.

`test/protocol-v2.test.js`는 note 경계값 4건, user policy 7종, full disclosure를 독립 Core Go 출력과 비교한다. 정확한 평문·commitment/nullifier·두 disclosure digest scheme·deposit/transfer/disclosure ciphertext·view-tag byte와 잘못된 입력·V1/V2 교차 사용 거절을 검사한다. `fixtures/clairveil-v0.6.1-fixed/vectors.json`의 key·seed·고정 entropy는 공개 합성 시험 데이터다. 운영 함수는 runtime CSPRNG를 사용하며 고정 난수 시험 hook을 export하지 않는다.

재생성은 Core `v0.6.1@fad307abddd0daa1c880f2e423668f5c58a0e578`에서 `git archive v0.6.1 go.mod go.sum types internal/strictjson x/privacy/amount x/privacy/types x/privacy/crypto`로 임시 디렉터리에 추출한 뒤 그 위치에서 `go run -mod=readonly /absolute/path/to/clairveiljs/tools/generate-fixed-v2-vectors.go`를 실행한다. Core native secret profile이 지원하는 플랫폼이 필요하며 표준 출력은 fixture와 정확히 같아야 한다. Release source 시험은 기록된 source hash 12개를 해당 commit과 대조한다. Go fixed-v2 함수가 기준 byte를 생성하고 암호문을 복호화하며 JS 시험도 이 암호문 byte를 정확히 재현한다.

## V2 감사 설정과 키 snapshot

`clairveiljs/audit-config-v2`와 root/core는 `queryActiveAuditSnapshotV2`, `computeAuditNetworkDigestV2`, `parseAuditKeyRecordV2`, `validateAuditCircuitIdentityV2`, `validateAuditArtifactManifestV2`, `assertAuditSnapshotCurrentV2`를 제공한다. `ClairveilJS.queryActiveAuditSnapshotV2(options)`는 설정된 chain ID와 하나의 REST endpoint를 조회 내내 사용한다. 배포자가 별도로 확보한 완전한 circuit identity, 로컬 artifact manifest 원본 bytes, 독립적으로 고정한 SHA-256 digest가 필수다. 선택적인 `expectedNetworkNonce`·`expectedInitialHeight` pin으로 예상과 다른 genesis namespace를 거부할 수 있다. 체인 출처 인증은 호출자의 책임이다.

설정 응답의 `circuitIdentity` 또는 `circuit_identity`에는 정규 protobuf 바이트나 그 base64 표현, 또는 viem이 반환하는 튜플처럼 디코딩된 회로 식별자 객체를 전달할 수 있다. 두 형식 모두 회로 순서와 키 해시까지 고정된 manifest와 일치해야 한다. viem을 쓰는 provider는 `networkNonce`와 감사 키의 `record`를 hex에서 바이트로 변환한다.

사전 검증은 `/clairveil/privacy/v2/audit/configuration`을 먼저 조회하고 `/clairveil/privacy/v2/audit/key_schedule`과 `/clairveil/privacy/v2/audit/keys/{epoch}`에 설정 응답 높이를 `x-cosmos-block-height`로 보낸다. 세 응답의 높이가 모두 같아야 한다. Halt, 없거나 0인 epoch, 잘못된 pending schedule, pruning되거나 무시된 높이, alias 충돌, circuit/VK/schema 불일치, 로컬 artifact digest 불일치, 잘못된 키 기록은 준비용 snapshot을 반환하기 전에 promise를 거절한다. 최신 높이·V1·다른 endpoint로 fallback하지 않는다. 사용자 provider는 `configuration({})`, `keySchedule({height})`, `key({epoch,height})`를 구현하고 지정된 높이를 지켜야 한다. REST 응답은 canonical base64·십진 문자열, generated 응답은 bytes·bigint를 사용할 수 있다. `halted`는 명시적인 boolean이어야 하며 정수에 JS number를 사용할 수 없다.

정확히 261바이트인 Core 키 기록은 suite 2와 Point64(big-endian x||y)를 사용하며 기존 compressed key와 구분된다. 파서는 metadata, 초기·교체 epoch 규칙, canonical 좌표, identity 거부와 prime-subgroup, 결정적 KeyID, network·epoch·activation height에 결합된 Schnorr PoP를 검증한다. Network digest는 chain ID·32바이트 genesis nonce·audit circuit set을 결합한다. Snapshot의 모든 정수는 전체 uint64 epoch·int64 블록 높이를 포함해 십진 문자열이며 byte identity는 소문자 hex다. 반환값과 내부 객체는 immutable이며 비밀 자료를 포함하지 않는다.

Manifest 검증은 네 audit circuit과 R1CS/PK/VK descriptor 12개의 순서·Core schema·배포 pin을 대조하고 Core CLI처럼 정확한 로컬 원본 bytes를 해시한다. Development marker를 반환하지만 artifact 파일 로딩·proof 검증·setup 신뢰성 검증을 수행하지 않는다. 독립적으로 인증한 체인 상태와 신뢰할 수 있는 로컬 artifact 확보는 호스트 책임이며 RPC 응답의 일치만으로 consensus 인증이 되지 않는다.

증명·브로드캐스트 직전에 다시 조회하고 `assertAuditSnapshotCurrentV2(previous, current)`를 호출한다. Network·epoch·key·artifact namespace가 같은 더 높은 높이는 허용하고 rollback·namespace 변경·복사하거나 역직렬화한 snapshot은 거절한다. 비교 함수 자체는 최신 상태를 조회하지 않는다. 이번 API는 V2 준비 사전 검증이며 기존 V1 wallet/prover/submission 경로는 유지된다. 전체 proof witness 구성과 V2 transaction 제출은 후속 범위다. Audit authorization 생성·prover 연결·로컬 proof 검증은 아래 절에서 설명한다.

`fixtures/clairveil-v0.6.1-audit/vectors.json`은 공개 합성 Core Go 기준값으로 초기·교체·안전 정수 초과·uint64 최대 epoch의 키 기록 네 개, 잘못된 기록 11개, network digest, protobuf identity와 manifest bytes를 담는다. `git archive v0.6.1 go.mod go.sum types internal x/privacy`로 임시 디렉터리에 추출하고 지원되는 Core native profile에서 `go run -mod=readonly /absolute/path/to/clairveiljs/tools/generate-audit-v2-vectors.go`를 실행하면 stdout이 fixture와 정확히 같아야 한다. Release 시험은 source hash 10개를 `fad307abddd0daa1c880f2e423668f5c58a0e578`과 대조하며 집중 시험은 같은 높이 REST header·halt·잘못된 입력·키 교체·artifact 변경을 확인한다.

## V2 감사 authorization과 공개 데이터 결합

`clairveiljs/audit-authorization-v2`는 deposit(1), withdraw(2), transfer2x2(3), batch16x32(4)의 지갑 내부 생성 계층이다. `createAuditOutputEffectV2(kind, index, effect)`는 fixed-v2 복구/disclosure byte를 generated `OutputEffect`로 복사하고 정책·위치·정확한 framing·canonical field/point·공개 disclosure metadata/digest를 검사한다. 실제 note/disclosure 암호 byte는 `protocol-v2`로 생성한다. Deposit과 2x2 change 출력의 disclosure 필드는 생략해야 한다. `encodeAuditAuxV2`는 출력 개수·순서·중복 commitment를 검사하고 Core와 동일한 Aux framing을 사용한다.

`buildAuditPublicInputsV2({kind, snapshot, message})`는 proof 없는 generated V2 메시지 필드로 PI21을 만들고 `message.audit`가 있으면 PI23을 만든다. 인증된 snapshot namespace·만료·root·nullifier·순서가 있는 effect·disclosure vector root·공개 금액/asset/address를 결합한다. Cosmos 주소는 현재 `clair` prefix를 사용하고 deposit은 0을 허용하며 withdraw는 양수여야 한다. 공개 coin 금액은 uint128이다. `parseAuditEnvelopeV2`는 suite/version·예약 byte·개수·크기·canonical field·subgroup point를 엄격히 검사한다. 공개 Poseidon2 cipher root·context hash·owner intent는 Core와 일치한다. `verifyAuditMessageBindingV2`는 PI23을 재구성하며 proof 검증이나 암호문 인증/복호화는 수행하지 않는다. Deposit 이외의 creator는 Core PI23에 포함되지 않으므로 준비 객체가 원래 creator를 별도로 대조한다.

`prepareAuditAuthorizationV2`는 proof 없는 `message`, branded `snapshot`, 비공개 `plaintext` BE32 field, 신뢰하는 로컬 `backend`, 필수 `getCurrentSnapshot`을 받는다. Plaintext는 Core 순서의 정확히 6/2/13/177 field다. Deposit은 `[asset, amount, spendX, spendY, viewX, viewY]`, withdrawal은 `[asset, inputCommitment]`, transfer/batch는 `[asset, inputCommitments..., output(amount, spendX, spendY, viewX, viewY)...]`다. Batch는 입력 16개·출력 32개 slot을 사용하고 비활성 slot은 0으로 채운다. 여기서는 canonical field와 개수를 검사한다. Note 소유권·금액 보존·경로·private field와 전체 witness의 일치는 후속 circuit/proving 단계에서 검증한다. 이 객체는 증명된 거래가 아니다.

Backend는 Core가 지원하는 native secret profile에서 암호 난수와 nonce를 독립적으로 새로 생성한다. 준비 과정은 암호화 전후에 snapshot과 만료를 다시 확인한다. `messageData()`, `publicInputs()`, `ownerIntent()`는 분리된 공개 복사본을 반환한다. 비공개 난수는 명시적인 `exportEncryptionWitness()`로만 꺼내며 신뢰하는 prover coordinator가 복사본을 지워야 한다. `assertCurrent()`는 다시 조회하고 실패하면 객체를 비운다. 사용 시 만료/취소와 `clear()`도 객체를 무효화한다. JSON 직렬화는 금지하고 inspection은 가린다. 삭제는 최선 노력이며 JS/Go GC의 모든 복사본 삭제를 보장하지 않는다. Plaintext·난수·준비 객체를 DApp provider 경계로 전달하거나 JSON으로 저장하지 않는다.

`clairveiljs/audit-native-node`는 Node 전용이다. `node tools/build-audit-native.js /path/to/clairveil /path/to/output/encrypt`로 로컬 binary를 빌드하고 신뢰하는 빌드에서 독립적으로 고정한 SHA256으로 `createAuditNativeBackendV2({executablePath, sha256})`를 호출한다. 빌드는 정확한 Core commit `fad307abddd0daa1c880f2e423668f5c58a0e578`을 추출하고 네 가지 native 기준값 시험이 모두 통과해야 하며 binary 옆에 비밀 없는 provenance를 기록한다. Adapter는 검증한 byte의 비공개 복사본을 실행하고 크기가 제한된 binary stdin/stdout을 사용한다. Secret argument/log/file 없이 timeout·취소를 적용하고 임시 실행 파일을 삭제한다. HTTP·JS/WASM secret crypto·미지원 profile fallback은 없다. Browser 공개 API 번들은 가능하지만 실제 extension/native-host transport는 별도 host 작업이며 여기서 설치하지 않는다.

`npm run verify:audit-native -- /path/to/clairveil`은 지원되는 Core Go/native toolchain에서 빌드와 native 통합 시험을 실행한다. 일반 unit suite는 binary를 요구하지 않으며 native integration case는 binary/hash 환경 pin이 없으면 명시적으로 skip한다. `test/audit-authorization-v2.test.js`는 독립 Go 합성 사례 10개, disclosure 세 모드, 0/최대 uint128, 최대 batch, 잘못된 frame·변조·키 교체·만료·비밀 수명을 검사한다. 추출한 Core module에서 `go run -mod=readonly /path/to/clairveiljs/tools/generate-audit-authorization-v2-vectors.go /path/to/clairveiljs/fixtures/clairveil-v0.6.1-audit/vectors.json`으로 fixture를 재생성한다. Fixture와 bridge에 사용자 데이터는 없다. 전체 note-to-witness 구성·서명·거래 제출은 후속 범위다. Prover coordinator와 로컬 검증은 아래 절에서 설명한다.


## V2 증명 생성과 로컬 검증

`clairveiljs/audit-prover-v2`는 `createAuditProverV2({baseUrl, verifier, fetch?, timeoutMs?, bearerToken?})`를 제공한다. 명시적으로 선택한 prover가 전체 private witness를 받으므로 로컬 또는 독립적으로 관리하는 prover를 사용한다. HTTPS origin 또는 HTTP loopback origin만 허용한다. 현재 Core envelope의 `version: "v1"`, 정확한 circuit/set/artifact identity, canonical base64 PI23과 witness로 `POST /v2/prover/audit-field`를 한 번 호출한다. 이 envelope 값은 현재 V2 규격이다. Redirect·재시도·endpoint 탐색·암묵적 cookie·V1 호출은 없다.

`await prover.prove({prepared, witness, signal?})`는 `prepareAuditAuthorizationV2`가 만든 실제 준비 객체를 소비한다. Witness는 gnark BN254의 전체 binary여야 한다. BE uint32 세 개(public=23, secret>0, total=public+secret) 뒤에 public, secret 순서의 canonical BE32 field가 온다. 최대 4 MiB이며 공개 field 23개가 준비된 PI23과 같아야 하고 후행 byte는 거절한다. 신뢰된 지갑/Core builder가 만든 witness를 받는 API이며 note 비밀·Merkle path·owner signature를 생성하지 않는다. 입력 배열은 첫 await 전에 복사하고 지운다. 준비 객체는 동기적으로 한 시도에 귀속되며 성공·실패·timeout·취소 모두 정리한다. 동시·반복 호출로 재사용할 수 없다. 호출자가 가진 다른 비밀 복사본도 직접 정리해야 한다.

기본 120초 deadline(1..3,600,000 ms 설정 가능)은 snapshot 갱신·HTTP header/body·로컬 검증 전체에 적용된다. 전송 전, 응답 후, 검증 후에 snapshot과 만료를 확인하고 전송·반환 직전에 동기적 abort/preparation 검사를 수행한다. 응답 stream은 16 KiB로 제한하며 중복·미지 JSON key, UTF-8, canonical base64, 정확한 PI23 순서를 검증한다. 164-byte proof framing만으로 성공 처리하지 않으며, 필수 신뢰된 `AuditProofVerifierV2`가 로컬 curve/pairing 검증을 마치고 literal `true`를 반환해야 한다. 이후 proof가 포함된 독립적인 generated V2 메시지를 반환하며 서명·제출하지 않는다. `AuditProverErrorV2.code`는 request/snapshot/transport/response/verification/aborted/timeout을 구분하고 원격 body·bearer token·비밀 abort reason·verifier 진단문은 포함하지 않는다.

Node 전용 `clairveiljs/audit-verifier-node`는 `createAuditNativeVerifierV2({executablePath, sha256, artifactDirectory, expectedArtifactHash, expectedCircuitIdentity, timeoutMs?, executionMode?})`를 제공한다. `node tools/build-audit-native.js /path/to/clairveil /path/to/verify verify`로 빌드한다. 신뢰된 실행 파일 SHA256, 정확한 manifest SHA256과 전체 circuit identity를 독립적으로 고정해야 한다. 생성 시 manifest와 네 VK 해시를 확인하고 이후 같은 복사본과 지정 회로로 검증한다. PK/R1CS·download·artifact 환경 override를 사용하지 않는다. Core registry가 VK/proof의 canonical decode/re-encode와 PI23 기반 BN254 Groth16 검증을 수행한다. Core v0.6.1은 이 audit bundle에 명시적인 development marker를 요구하며 이 API는 production setup 자격을 부여하지 않는다.

`npm run verify:audit-prover -- /path/to/clairveil`은 고정된 Core commit을 추출하고 **실제 Core 회로 네 가지**의 임시 단일 참여자 개발용 artifact를 생성해 각각 증명·검증한다. PI 23개 각각의 변조와 circuit/key/artifact/proof 교체 거절도 검사한다. JavaScript authorization → 실제 Core loopback HTTP prover → 고정된 로컬 verifier → generated V2 deposit 인코딩을 uint64보다 큰 uint128 금액으로 실행한다. Native timeout·취소·출력 제한도 검사한다. 필수 사례가 없거나 skip하면 실패하고 임시 setup을 삭제한다. 선택적 두 번째 인자는 정확한 source/hash가 일치하는 개발용 fixture cache다. 일반 unit suite에서는 fixture/binary pin이 없으면 native 통합 사례 세 개를 명시적으로 skip한다. Test server는 합성 데이터만 사용하며 제품 서비스로 설치하지 않는다.

Browser용 transport와 타입은 V1 실행 모듈 및 Node 전용 binary와 독립적으로 bundle된다. Browser host는 검증된 로컬 verifier bridge를 제공해야 하며 이 변경은 extension native-host transport를 설치하지 않는다. 준비 객체·plaintext·full witness를 DApp provider 경계에 전달하거나 저장·기록하면 안 된다. JavaScript string·호출자 복사본·GC 때문에 완전한 비밀 소거는 보장할 수 없다. Native 설치·origin 접수·일반 지갑 UI·제출 연동은 host 책임이며 이 SDK가 확장이나 native host를 설치하지 않는다.

`preparation-v2`는 fixed-v2 입금 자료를 만들고 선택된 uint128 지출 입력의 소유자·자산·nullifier·합계 금액과 출금 금액의 정확한 일치를 검증한다. `audit-witness-v2`의 `prepareAuditWitnessV2`는 승인된 의도와 예약을 checkpoint에 기록하고 snapshot을 갱신한 뒤 신뢰된 native backend를 호출한다. 반환된 입금·출금·전송의 전체 witness는 승인된 입력과 감사 메시지에 결합된다. `audit-witness-node`는 고정된 Core 내부에서 빌드한 `tools/audit-witness-bridge.go`의 해시 고정 실행 파일을 사용한다. 출력 복구 데이터·공개 데이터·최종 소유자 서명·witness 구성은 Core가 담당한다. Snapshot은 호스트 계정 접두사도 고정한다. 기본값은 `clair`이며 Maroo는 명시적으로 `maroo`를 지정한다. 이전 codec이나 기존 이벤트 경로로 자동 전환하지 않는다.

`createAuditWitnessNativeBackendV2`와 `createAuditNativeVerifierV2` 모두 `executionMode: "staged" | "installed"`를 받으며 기본값은 불변 복사본을 사용하는 staged다. Installed는 운영자가 준비한 native host용이다. 절대 경로·symlink가 아닌 실행 파일, 현재 사용자/root 소유, 파일과 상위 디렉터리의 group/world 쓰기 금지, 일반 실행 파일 여부와 고정 SHA-256을 실행 전에 검증한다. 파일 읽기는 크기를 제한하고 `O_NOFOLLOW`를 사용한다. Browser 프로세스 아래 새 실행 파일을 만들지 않고 설치한 binary를 직접 실행한다. OS 보안 기능을 끄거나 같은 OS 소유자·관리자의 침해를 방어하지는 않는다. Native helper는 신뢰하는 Custody 안에서 선택 노트·파생 spend scalar를 받을 수 있으나 RootSeed는 받지 않는다. 별도로 승인한 prover는 검토한 witness만 받는다. `test/native-installed.test.js`는 pin·변조·symlink·안전하지 않은 권한 거부를 검사한다.

`transactions-v2`는 로컬 검증을 마친 공개 proof 필드로 세 가지 명시적 Cosmos V2 메시지·sign document와 EVM transaction을 만든다. DApp artifact verifier는 `protocol: "audit-field-v2"`를 명시적으로 선택하고 승인한 정확한 actor·효과·금액·transport envelope를 결합한다. Protocol을 생략하면 `note-v1`을 유지한다. 공개 wire·ABI 모듈은 비공개 준비·codec 암호 연산·witness 모듈과 분리한다. 공개 구조 검사가 신뢰 host의 전체 암호 검증을 대체하지 않는다.

공개 wallet API schema는 개별 노트·작업·공개 결과 금액에 canonical uint128을 허용하며 digest는 `33be71b39bfe6a974a8ce1154e5fcf28b25a898deb72eb26a10214587d65313b`다. 높이·epoch·만료·revision은 uint64를 유지한다. Legacy 실행 profile의 금액도 uint64로 제한한다. Host는 지원하는 메서드만 광고하며 V2 거래 감사 데이터 지원이 선택적 페이지 disclosure 조회 지원을 의미하지는 않는다.

`evm-v2`는 Maroo `823f6752e89a8d7157bd90973e7b1f9093e0ec10`(Core v0.6.1)의 `IPrivacy.json`에 맞춰 세 직접 거래 요청을 인코딩한다. 독립 go-ethereum 벡터로 ABI를 검증하며 인코딩 자체가 proof·체인 계정·계약 주소·정확한 입금 value를 검증하지는 않는다. `reserve-v2`는 Core의 부채·담보 산술을 따르며 초과 담보를 허용하고 부족을 별도로 반환한다. `scan-v2`는 공통 페이지 검증 엔진으로 감사 식별자와 fixed-v2 출력 형식을 검증한다. `note-store-v2`는 호스트가 암호화해서 저장해야 하는 비공개 표현이다. nullifier 재조회가 실패하거나 누락되면 저장된 지출 가능 상태를 유지하지 않는다. V2 페이지 연속성·캐시 식별자는 이전 데이터를 거부하며, 알려진 미결 거래의 예약을 버리지 않고 재스캔해야 한다.

## 신뢰된 V2 workflow와 disclosure

`clairveiljs/wallet-kernel-v2`는 `prepareAuditTransactionV2`를 제공한다. 명시적 V2 witness 입력·native backend·`assertAuthority`·영속 `checkpoint`·같은 배포의 `getCurrentSnapshot`, 필수 로컬 검증기를 포함한 prover 설정을 받는다. RootSeed를 복사하고 비동기 경계 전후에 권한을 검사하며 native 소유자 서명 전에 승인·예약을 저장한다. 전체 witness를 V2 prover에 소비하고 proof를 로컬에서 검증한 뒤 snapshot을 다시 확인해 `{kind, message, snapshot}`을 반환한다. 성공·실패 모두 소유한 seed·요청·witness 버퍼를 지우며 원본 seed와 비공개 입력은 호출자가 소유한다. 일반 지갑 서명·자동 재제출·예약 해제를 수행하지 않는다. 최종 host·계정·수수료 사전 검사 후 `transactions-v2`를 사용한다. 페이지 예제 `examples/custody-v2-flow.js`는 공개 DApp 코드만 import하며 privacy material을 파생하거나 받지 않는다.

`clairveiljs/disclosure-v2`는 `decodeUserDisclosureFromScanOutputV2`와 `decodeSelfViewDisclosureFromScanOutputV2`를 제공한다. `scan-v2`가 발급하고 무결성을 확인한 출력만 받는다. 직접 전송 output 0, plane·policy, tx hash, commitment, fixed-v2 평문, 인증 복호화, transfer digest, 선택적 asset-denom 결합이 일치해야 한다. 공개·수신자 암호화 사용자 공개와 self-view 모두 uint128을 지원한다. 신뢰된 결과에는 decoder 메타데이터가 포함되므로 custody host는 페이지 전달 전에 승인된 필드 allowlist만 투영해야 한다. 별도 필수 감사 field를 복호화하거나 batch·원본 event 대체 경로를 활성화하지 않는다.

`verify:release:integration`은 이제 `verify:release:audit`를 필수로 실행한다. `CLAIRVEIL_SOURCE_DIR`와 `CLAIRVEIL_AUDIT_ARTIFACT_CACHE`를 지정하거나 독립 검사 명령에 두 경로를 전달한다. 캐시는 정확한 Core archive·generator 바이트와 회로 4종의 파일 해시가 일치해야 한다. 과거 raw-generator·정규화 generator 출처는 각 선언 해시가 일치할 때만 인정하며 기존 출처를 다시 쓰지 않는다. Native 검증 및 전체 준비·proof·인코딩 6개 경로를 건너뛸 수 없다. 이는 개발 암호 검증이며 실제 일반 지갑·체인 검증은 소비 host에서 별도로 수행한다.

## 신뢰된 RootSeed identity (CC-002)

미출시 `clairveiljs/wallet-kernel` 진입점은 `createPrivacyIdentity({ rootSeed, shieldedPrefix? })`로 CC-002 추출을 시작한다. 신뢰된 지갑 runtime이 이미 보유한 32바이트 `Uint8Array`를 받아 복사한 뒤 기존 protocol 알고리즘으로 spend·view·disclosure key를 파생한다. 새로운 entropy 생성·백업은 custody가 담당하며 이 생성자는 seed 생성·루트 서명 요청·일반 지갑 호출을 하지 않는다. Legacy 서명 자료·chain actor를 포함한 다른 입력 필드는 거절한다.

반환되는 `WalletPrivacyIdentity`에는 복사한 RootSeed와 비공개 key pair가 포함되므로 신뢰된 runtime 안에 유지한다. 동결한 `publicIdentity` projection은 `shieldedAddress`, `spendPubKeyHex`, `viewPubKeyHex`, `disclosurePubKeyHex`만 포함한다. 이는 내부 SDK 타입이며 custody RPC 계정 DTO나 공개 권한이 아니다. Grant·public DTO projection·vault 저장·비밀 수명은 계속 custody가 담당하며 JavaScript는 모든 key 사본의 삭제를 보장하지 않는다.

일반 계정·네트워크 선택은 별도로 유지하며 생성자 입력이 아니다. 같은 RootSeed는 같은 privacy key를 만들고 `shieldedPrefix`는 주소 인코딩만 바꾼다. 새 진입점은 legacy `PrivacyMaterial`을 감싸거나 상속하지 않으며 기존 transaction builder 형식을 맞추기 위한 주소·서명 placeholder를 추가하지 않는다. 일반 chain adapter는 아래처럼 분리했으며 private workflow도 아래처럼 두 독립 입력을 받는다. 기존 legacy 진입점·정확한 파생 vector는 유지하고 새 표면을 broad root나 DApp 진입점에서 재export하지 않는다.

`test/wallet-kernel.test.js`는 skip 경로 없이 고정한 sender/recipient Go vector를 직접 읽는다. 정확한 scalar/public-key/address 일치, 독립 합성 seed 생성, 입력 사본 소유권, public projection과 legacy/잘못된 입력 거절을 검사한다. `test:conformance:required`에도 포함하며 TypeScript 검사로 새 package export와 비공개/actor 필드 거절을 확인한다.

## 일반 chain wallet (CC-002)

미출시 `clairveiljs/chain-wallet` 진입점은 `createKeplrChainWalletAdapter`, `createOfflineSignerChainWalletAdapter`, `createEip1193ChainWalletAdapter`를 export한다. Legacy root-signing adapter와 분리한 일반 지갑 primitive다. Wallet kernel·private workflow·prover 모듈을 import하지 않고 privacy-root·typed-data 서명 메서드를 노출하지 않으며 broad root나 DApp 진입점에서 재export하지 않는다. 기존 legacy adapter와 vector는 유지한다.

모든 생성자는 명시적 `chainId`가 필요하며 지갑을 호출하지 않는다. `connect()`는 명시적으로 Keplr enable 또는 EIP-1193 계정 접근을 요청하고 offline signer는 계정만 읽는다. `getActor()`는 접근 요청 없이 이미 이용 가능한 계정을 읽는다. Cosmos는 `{ namespace: "cosmos", chainId, address, pubKeyHex }`, EVM은 `{ namespace: "eip155", chainId, address }`를 반환한다. 동결한 공개 snapshot은 로컬 SDK 타입이며 custody RPC DTO·CAIP 정규화 계정 ID·grant·인증된 privacy-account 연결이 아니다. Cosmos는 native chain ID·선택적 고정 주소·Bech32 prefix(기본 `clair`)와 20바이트 주소를 사용한다. EVM은 canonical 16진수 chain ID를 요구하고 주소를 소문자로 정규화하며 선택적으로 계정을 고정한다.

`signDirect(signDoc, actor, { signal }?)`와 `sendTransaction(transaction, actor, { signal }?)`는 별도로 확보한 actor가 필요하다. 계정 조회를 await하기 전에 actor를 복사하고 입력의 공개 필드만 추출한다. 호출 직전에 현재 계정·네트워크와 Cosmos 공개키를 해당 actor와 비교하며 EVM은 계정 조회 전후 네트워크도 확인한다. 선택적 `AbortSignal`은 await 전에 캡처하고 마지막 계정 조회 뒤 실제 지갑 호출 직전에 추가 await 없이 다시 검사한다. Custody submission은 이 신호를 항상 전달하며 provider 무효화 시 동기적으로 abort한다. Custom adapter와 wrapper도 같은 호출 경계까지 신호를 전달하고 검사해야 한다. 불일치 또는 abort된 신호는 서명·전송 전에 실패하며 이미 시작한 지갑 호출을 취소하지는 않는다. 메서드 호출당 최대 한 번만 dispatch하며 root 서명·다른 지갑·다른 네트워크로 fallback하지 않는다.

Cosmos는 `bodyBytes`·`authInfoBytes`를 복사하고 설정한 chain ID와 uint64 `bigint` 계정 번호를 요구하며 추가 필드를 제외한다. Keplr에는 고정한 `long` 5.3.2의 실제 unsigned `Long`과 `preferNoSetFee`·`preferNoSetMemo`를 전달한다. 호출자 문서와 offline signer의 `bigint` 계약은 유지한다. Provider 입력 선언은 `KeplrSignDoc`를 사용하고 `test/types.ts`는 자체 mock 대신 고정한 실제 `@keplr-wallet/types` 0.13.41 인터페이스로 컴파일한다(Long 4 의존성 선언에는 `@types/long` 4.0.2 사용). 이 타입 패키지와 Keplr의 Starknet peer는 개발 전용 의존성이다. Direct-sign 응답은 지갑이 제공한 값이므로 호출자가 broadcast 전에 signed bytes·공개키·서명·의도한 effect를 검증해야 한다. 이 adapter는 broadcast하거나 지갑 응답이 검증됐다고 주장하지 않는다.

Keplr의 protobufjs `Long` 응답은 두 32비트 word에서 정확한 uint64 `bigint`로 정규화한다. `2^63`보다 큰 값이 `unsigned:false`로 반환되는 경우도 처리하며 부동소수점 변환이나 지갑 객체의 강제 변환 함수를 사용하지 않는다. 서명된 protobuf 값을 보존하고 submission coordinator의 정확한 문서·서명 검사를 우회하지 않는다. SDK Bech32 decoder에는 유한한 길이 제한(일반 주소 90, shielded 주소 200)을 명시하여 새 `@scure/base`를 선택한 consumer에서 CosmJS encoding의 `Infinity` 기본값이 거절되는 문제를 피한다. 두 문제는 packed SDK를 새로 설치하고 실제 Keplr로 서명한 로컬 custody 통합 harness에서 발견했다.

EVM은 `to`가 필수이며 `from`·`chainId`를 actor에 고정하고 그 외에는 `data`, `value`, `gas`, `gasPrice`, `maxFeePerGas`, `maxPriorityFeePerGas`, `nonce`만 받는다. Data는 16진수 bytes, 수량은 canonical 16진수여야 한다. 추가 metadata는 제외한다. Contract 생성·access list·typed-data 서명은 첫 구현 범위에 없다. `eth_sendTransaction`은 32바이트 transaction hash를 반환해야 하며 dispatch 이후 거절이나 잘못된 응답이 발생해도 자동 재전송하지 않는다. 호출자는 reconciliation으로 결과를 확인할 때까지 제출을 미해결 상태로 유지해야 한다.

이 provider 조회는 외부 지갑 UI가 열린 동안 지갑 상태를 원자적으로 고정할 수 없다. Custody의 grant/epoch 검사·`beginSubmission` journal·signed-artifact 검증·finality/effect reconciliation은 계속 workflow 계층에서 필요하며 이 primitive의 구현 범위가 아니다. 이 adapter와 RootSeed 생성자만으로 기존 DApp client가 custody-ready가 되지 않는다.

`test/chain-wallet.test.js`는 합성 provider로 stale 계정·키·네트워크, 조회 대기 중 입력 변경, 명시적 연결, 공개 필드 추출, 재전송 없는 실패와 독립 identity 유지를 검사한다. Source import-graph 검사는 로컬 chain-wallet 모듈·`@cosmjs/encoding`·`long`만 허용하며 의존성이 바뀔 때 실제 browser bundle도 검사해야 한다. 필수 conformance에 포함하고 TypeScript 검사로 누락·잘못된 actor, 비공개 필드, legacy root-signing 호출을 거절한다. 실제 지갑·chain/prover 검증은 별도 gate다.

## Custody SDK 제공면 (CC-002)

`clairveiljs/wallet-api`의 `src/wallet-api/schema/`가 단일 편집 원본이다. `npm run generate:wallet-api`는 DTO type·registry·Ajv 8.17.1 Draft 2020-12 standalone validator를 생성하고 `npm run check:wallet-api`는 오래된 산출물을 거절한다. 15개 메서드는 닫힌 DTO이며 생성 타입은 형태를 표현하고 조건부 제약은 runtime에서도 검증한다. 엄격한 JSON parser는 중복 키·잘못된 UTF-8/Unicode·accessor·prototype·byte/depth/list 초과를 거절한다. 결과는 복사·동결하고 method/ID·검토한 digest·요청 balance asset과 대조한다. `node tools/sync-wallet-api-mirror.js --check|--write CUSTODY_REPOSITORY`로 custody 생성 mirror 4개를 검사/갱신하며 SDK 원본만 수정한다.

`createWalletKernel({ identity, client, evmClient?, evmChainId?, checkpoint, assertAuthority, reservationManager? })`는 신뢰 runtime 전용이다. `scan`·`proveDeposit`·`prepareDeposit`·`prepareTransfer`·`prepareWithdraw`·공개 identity 조회·dispose를 제공한다. 거래에는 별도 `actor`·`operationId`가 필요하며 scan 소유자는 privacy identity다. 기존 private client도 legacy `material`/`wallet`과 별개로 `privacyIdentity`/`chainActor`를 받는다. Note·intent 서명·audit/self-view·Merkle·nullifier·planner·proof·reservation 알고리즘을 재사용한다. EVM 숫자 wallet chain ID와 protocol chain 문자열은 별도로 고정한다. Own deposit과 native transfer/withdraw는 기존 Cosmos/EVM builder를 사용하며 third-party deposit·relay·batch는 새 facade에 없다.

Host는 authoritative profile/time·암호화 저장소·활성 permission/epoch 검사를 제공한다. `checkpoint`는 정확한 operation/export barrier와 reservation을 원자적으로 영구 기록한 뒤 resolve해야 한다. Kernel은 이를 기다리고 권한을 재확인한 뒤 명시적 prover만 호출하며 checkpoint 실패 시 export하지 않는다. 마지막 비동기 권한 helper가 반환한 뒤 deposit·transfer·withdraw는 prover 호출과 같은 동기 구간에서 dispose 여부를 검사하므로 그 사이 microtask에서 종료되어도 export를 차단한다. Scan·입금 증명·세 가지 준비 작업의 최종 반환에도 같은 동기 검사를 적용하며 마지막 권한 helper와 반환 사이 종료되면 완성된 결과도 거절한다. `proveDeposit`은 실제 `DepositMaterial`과 `prepareDeposit`이 받는 문자열/byte proof union을 선언하고 EVM 응답의 문자열이 아닌 `proofHex`는 거절한다. Scan의 `privacyAccount`는 `PublicPrivacyIdentity`로 선언한다. 엄격한 TypeScript 회귀 검사는 타입 단언 없이 증명을 입금 준비에 연결하고 scan의 공개 identity를 조회한다. Host는 runtime 권한 상실 시 kernel을 dispose해야 하며 비동기 hook만으로 원자적 철회 구독을 대신하지 않는다. 기존 rollback은 proving 시작 뒤 실패한 reservation을 격리한다. Hook은 연동 의무이며 구현된 vault/journal이 아니다. Kernel 결과의 private note/witness는 공개 DTO로 보내면 안 된다. Dispose는 새 작업과 소유 byte 배열을 정리하지만 모든 JavaScript 비밀 사본 소거를 보장하지 않는다.

`clairveiljs/custody-provider`는 `createCustodyProvider`·`createDirectBridgeTransport`를 export한다. Transport·invalidation 구독은 명시적이다. Exchange host가 origin/document 또는 topic을 인증하며 adapter 자체가 확장 인증·grant·WalletConnect responder를 구현하지 않는다. 생성 시 I/O가 없다. 고정 schema와 discovery가 일치해야 다른 메서드를 사용한다. Pending·timeout·polling을 제한하고 무효화 시 capability/revision 상태와 늦은 응답을 버리며 dispose는 영구적이다. 오류는 고정 schema 필드만 포함한다. Discovery 성공 후 capability에 없는 등록 메서드는 `4102 UNSUPPORTED_CAPABILITY`, discovery 부재·무효화된 attachment는 `4103 UNAUTHORIZED`, 알려지지 않은 메서드는 `-32601`로 구분한다. 크기·구조를 제한한 JSON 캡처 후 문자열 `protocolVersion`/`schemaRevision`의 미지원 값은 정확한 params·discovery 접수 검사보다 먼저 `4101 UNSUPPORTED_VERSION`으로 거절하며 누락·문자열이 아닌 버전은 `-32602`를 유지한다. Discovery는 schemaRevision 필드를 받지 않는다. Direct transport와 provider는 getter를 실행하지 않는 공통 검사를 사용한다. Capabilities는 크기·구조가 제한된 JSON 값으로 비교한다. 중첩 객체를 포함한 키 순서 변경만으로 attachment를 무효화하지 않으며 값이나 배열 내용·순서가 바뀌면 무효화한다. 동등한 discovery 응답은 polling·revision guard를 유지한다. `cancelOperation`의 중첩 operation도 요청한 작업 ID와 대조하고 일반 작업 결과와 같은 단조 증가 revision 추적에 포함한다. 오래된 취소 결과나 수락한 취소 결과보다 오래된 지연 조회 응답은 비밀을 제거한 내부 오류로 거절하며 공개 중첩 응답 형태는 유지한다.

`clairveiljs/dapp`의 `createClairveilDappClient({ custodyProvider })`는 15개 논리 메서드를 제공하며 `.cosmos`·private callback·자동 legacy fallback이 없다. `chainWallet`·명시적 `validateArtifact`를 추가하면 `submit`을 제공하며 Cosmos는 `broadcastCosmos`도 필요하다. `createArtifactVerifier`는 chain/asset/profile digest와 EVM contract/protocol chain을 고정하고 허용한 protobuf/ABI를 decode해 공개 effect를 확인한다. Cosmos self-merge/final-transfer도 EVM transfer처럼 메시지의 만료 시각과 공개 summary를 대조하며 누락·불일치 시 begin·서명·broadcast 전에 차단한다. 승인 digest는 모든 bytes·actor·fee를 결속하며 private intent와 최신 chain 상태 확인은 custody 책임이다. 악성 페이지의 digest는 승인이 아니다.

`submit`은 caller의 begin 멱등 key를 유지하고 `clairveil-custody/submission-report/v1` domain·begin key·operation ID·attempt ID·outcome·선택적인 정규 hash를 SHA-256으로 결합하여 각 report key를 파생한다. 동일 보고 intent는 동일 key를 재현하며 submitted·unknown 보고는 begin key나 서로의 key를 공유하지 않는다. 파생은 비동기 경계이므로 보고 직전에 attachment 권한을 다시 확인한다. 보고 응답 유실은 지갑 재호출을 허용하지 않는다.

Submission은 허용된 begin 응답을 provider attachment당 한 번 소비한 뒤 wallet을 호출한다. 여러 client가 in-flight/attempt guard를 공유하고 stale revision/epoch/account를 거절한다. Cosmos는 정확한 signed document·key·secp256k1 서명을 확인한 뒤 한 번 broadcast하며 EVM은 명시적 EIP-1559 artifact만 받는다. Cosmos는 승인 문서와 byte 배열의 독립된 사본을 검증 기준으로 보존하므로 custom adapter가 입력을 수정해도 승인된 bytes를 바꿀 수 없다. 불명확/거절 응답은 unknown으로 보고하고 dispatch를 재시도하지 않는다. 메모리 guard는 host의 durable `beginSubmission` journal을 보완하며 process loss 후 journal을 대신하지 못한다. `clairveiljs/legacy-browser`는 기존 비밀 포함 browser client의 명시적 alias다. 기존 `browser-dapp`도 legacy이며 자동 선택하지 않는다.

Provider의 admission·capability/revision 상태·요청 정리는 `custody-provider/provider.js`, JSON-RPC framing·응답 연결은 `direct-bridge.js`가 담당한다. `chain-wallet/cosmos-signing.js`는 공개 서명 문서 복사와 Keplr 양방향 변환을 담당한다. 두 일반 adapter는 `chain-wallet/actor.js`의 `dispatchToActor`를 사용해 마지막 actor/abort 검사와 실제 지갑 호출을 한 동기 실행 구간에 유지하고 submission coordinator도 같은 actor 비교를 재사용한다. Submission 테스트는 client/profile·합성 서명 fixture를 공유하며 각 실패 주입과 검증은 명시적으로 유지한다. 공개 진입점은 같은 생성자 두 개를 export한다. Submission은 artifact 검증·begin·동기 attempt 소비·dispatch·보고 단계를 구분한다. 제출마다 attachment 무효화를 구독하고 chain adapter에 abort 신호를 전달하며 모든 완료 경로에서 구독을 해제한다. Kernel helper는 actor 캡처·execution 생성·checkpoint payload 구성을 분리한다. `activeResult`는 비동기 경계를 추가하지 않고 최종 결과 검사와 반환을 모으며 prover 직전 검사는 호출과 동기 구간을 유지한다. EVM proof 정규화는 hex와 문자열/byte 분기를 명시한다. Workflow 선언은 필드 배치를 읽기 쉽게 정리하되 토큰은 그대로 유지하며 kernel 테스트는 생성·EVM context·canonical 입금 응답·microtask 예약을 공유하고 각 실패 assertion은 명시적으로 유지한다. 회귀 사례는 control slot 예약·timeout 정리·transport envelope 변경·다른 client에서 반복한 attempt ID·실제 SDK adapter 내부의 각 계정·네트워크 조회 중 attachment 상실·Cosmos 서명 후 attachment 상실·구독 정리·checkpoint 도중 dispose를 검사한다. 선택적 dispatch 신호와 Keplr 입력 선언은 SDK adapter 계약을 보완하며 wire schema·protocol 알고리즘·신뢰 경계는 유지한다.

새 wallet-api/provider/submission/kernel-workflow/public-boundary 테스트는 기본/필수 conformance에 포함한다. 합성 Cosmos/EVM deposit·transfer·withdraw 준비는 기존 private 알고리즘과 mock chain read·형식에 맞는 proof 응답을 사용한다. Checkpoint 실패·actor/epoch 변경·signature/calldata 변조·공개 import graph도 검사한다. 실제 proving·실제 wallet/chain 결제·암호화 host 장애 주입·WalletConnect 검증은 별도다. Browser bundle/CSP·불변 package 측정은 custody CC-002 작업에 기록한다. Package version은 그대로이며 새 export는 미출시다.

## 계약 분류

| 분류 | 의미 | 예시 |
| --- | --- | --- |
| SDK 고정 계약 | ClairveilJS와 Clairveil protocol이 경로·shape·version을 정한다. | `/clairveil/privacy/v1/privacy_scan`, `/v1/prover/transfer`, `/v1/prover/deposit`, Cosmos Msg type URL |
| Profile 고정 endpoint | 제품이 검토한 정확한 URL을 profile에 넣고 SDK가 그 URL만 호출한다. | 선택적 `depositProofUrl` override |
| 주입형 adapter | 호출자가 함수 구현을 제공하며 ClairveilJS는 고정 HTTP route를 가정하지 않는다. | local/WASM prover, `createAsyncJobProverAdapter(...)`의 submit/poll 함수 |
| Product-defined API | 인증·수수료·queue·URL을 제품이 정의한다. ClairveilJS 공통 서버 계약이 아니다. | relay withdraw handoff, DApp proxy route |

`/v1/prover/transfer`, `/v1/prover/withdraw`, `/v1/proofs/batch-transfer`, `/v1/prover/deposit`는 `clairveil.d`의 chain REST endpoint가 아니다. 기본 HTTP prover adapter를 선택한 **브라우저의 ClairveilJS**가 `proverUrl`에 직접 요청한다. `proverUrl`이 DApp proxy를 가리킬 때만 요청이 그 서버를 경유한다.

## Clairveil v0.3.1 고정 계약

이 문서와 SDK의 지원 기준은 현재 Clairveil `v0.3.1` SDK handoff commit
`0ff92839872de26b787a60d8e4d5822cc459855b`이다. 아래 값은
배포 profile이 바꿀 수 있는 설정이 아니라 conformance fixture와 consensus
identity가 고정한 protocol 계약이다.

Cosmos deposit proving은 tag commit
`ca85b02708fdd75259d4d2ee2d671c21198cec69`의 canonical Core `v0.4.0`
prover HTTP 계약을 추가로 따른다. Cosmos protobuf와 on-chain `MsgDeposit`
wire는 바뀌지 않으며 strict off-chain request/response와 proof-frame 경계만 추가된다.

| 계약 | 고정 값 |
| --- | --- |
| Active circuit set | `privacy-note-v1`, BN254, required order `deposit` → `spend` → `joinsplit` → `batch-joinsplit-16x32-v1` |
| Public-input schema SHA-256 | `deposit`: `c3231fb5ae62539d2e4baeb78aa4be8a4c44e3cd8fa325ba60f13b7f563d5a1e`; `spend`: `d0a033aa2f7b6e098873307a815545ee3e83d974026c0e52bf39a038e08f4872`; `joinsplit`: `4946e23db34529c6fce0a95ce69f6df08563a305ddcc70c7b6b786471e03aa82`; batch: `5606327d69dcb06c00811f2135291d39a2ea1cedf554f114f7eb4a178098d333` |
| Canonical binary encoding | `privacy-fixed-v1`; `NotePlaintextV1` 350 bytes, `DisclosurePlaintextV1` 392 bytes, typed envelope header 20 bytes |
| Transfer | prepared payload `v5`; proof/request/response `v2` |
| Withdraw | prover/final payload와 proof/request/response 모두 `v2`; output note field 없음 |
| Relay withdraw | handoff/schema `v2`; relayer `creator`와 owner-bound recipient를 분리 |
| One-Proof batch | payload `batch-transfer-payload-v1`, proof `batch-transfer-proof-v1`, request/response `v1`; Cosmos `MsgBatchTransfer` 또는 EVM `singleProofBatchTransfer` 실행 |

Public input은 이름을 정렬하거나 rename하지 않고 아래 순서를 그대로 사용한다.

- Deposit 3개: `Commitment`, `Amount`, `AssetID`.
- Native transfer / JoinSplit 13개: `MerkleRoot`, `ChainDomainHi`, `ChainDomainLo`, `ExpiresAtUnix`, `Nullifier0`, `Nullifier1`, `Commitment0`, `Commitment1`, `UserPrivacyPolicy`, `UserDisclosureDigest`, `FullDisclosureDigest`, `PayloadDigestHi`, `PayloadDigestLo`.
- Withdraw / Spend 9개: `MerkleRoot`, `ChainDomainHi`, `ChainDomainLo`, `ExpiresAtUnix`, `Nullifier`, `Amount`, `RecipientDigestHi`, `RecipientDigestLo`, `AssetID`.
- BatchJoinSplit16x32 12개: `MerkleRoot`, `ChainDomainHi`, `ChainDomainLo`, `ExpiresAtUnix`, `InputCount`, `OutputCount`, `NullifierRoot`, `CommitmentRoot`, `UserDisclosureRoot`, `FullDisclosureRoot`, `PayloadDigestHi`, `PayloadDigestLo`.

`AssetRegistryV1`만 denom/asset-ID의 authoritative source로 사용하고 missing,
collision 또는 양방향 mapping 불일치에서는 fail-closed한다. Audit disclosure는
필수이고 sender self-view는 기본 포함·명시적 opt-out이다. Native transfer는
정확히 두 개의 2-byte view tag를 사용하며 tag는 untrusted hint이므로 기본
scan은 mismatch에서도 full decrypt를 시도한다. Transfer/withdraw의 `creator`는
replaceable하지만 output, disclosure, recipient, chain과 expiry는 owner
intent/proof에 binding된다.

Raw ciphertext, legacy JSON plaintext, wrong envelope kind, non-zero reserved
byte, trailing byte와 cross-kind decode는 compatibility fallback 없이 거부한다.
Clairveil `v0.3.1`의 상태는 `PUBLICATION_READY_EXPERIMENTAL`이며, 이 계약을
구현했다는 사실만으로 production release gate가 닫히지는 않는다.

## End-to-End 작업 매핑

| 사용자 작업 | 주 SDK API | 준비 중 조회 | proof 계약 | 준비 결과 | 서명·최종 제출 | 완료 판단 |
| --- | --- | --- | --- | --- | --- | --- |
| Deposit | `prepareDeposit(...)` | circuit config, asset mapping; Cosmos sign doc은 account metadata도 조회 | Cosmos: canonical `POST /v1/prover/deposit`, local provider 또는 canonical V1 exact URL override; EVM 동작은 유지 | Cosmos `MsgDeposit` sign doc 또는 EVM `IPrivacy.deposit` transaction | 사용자 Cosmos wallet 또는 EIP-1193 wallet | 두 profile 모두 exact commitment·`encryptedNoteHex`를 보존. Cosmos는 response binding과 164-byte proof frame을 검증한 뒤 `confirmDeposit(...)`, EVM은 `waitForEvmTransaction(...)`으로 확인 |
| Note scan | `scanWalletNotes(...)`, `queryPrivacyScan(...)` | typed privacy scan과 nullifier 상태 | 없음 | 검증된 found note, cursor, nullifier status | 제출 없음 | malformed page나 불명확한 nullifier는 spendable로 취급하지 않음 |
| Native transfer | `prepareTransfer(...)` | scan, circuit/asset/audit/disclosure config, same-root path, nullifier 상태 | `POST /v1/prover/transfer` | Cosmos `MsgTransfer` sign doc 또는 EVM `IPrivacy.transfer` transaction | 사용자 wallet | tx identity, input nullifier, 예상 output/disclosure evidence를 reconcile |
| One-Proof Batch Transfer | `prepareTransferBatch(...)`, `provePreparedBatchTransfer(...)`, `finalizePreparedBatchTransfer(...)` | typed scan, protocol config, same-root path snapshot, 모든 input nullifier | `POST /v1/proofs/batch-transfer` | Cosmos `MsgBatchTransfer` sign doc 또는 EVM `singleProofBatchTransfer` transaction과 선택적 EIP-712 authorization | 사용자 Cosmos/EVM wallet | 같은 operation의 모든 input nullifier, exact transaction binding과 모든 typed output evidence를 원자적으로 reconcile |
| Direct withdraw | `prepareWithdraw(...)` | scan, circuit/asset config, Merkle path, nullifier 상태 | `POST /v1/prover/withdraw` | Cosmos `MsgWithdraw` sign doc 또는 EVM `IPrivacy.withdraw` transaction | 사용자 wallet | tx/receipt와 nullifier 및 withdraw evidence를 확인 |
| Relay withdraw | `prepareRelayWithdraw(...)` | direct withdraw와 동일 | `POST /v1/prover/withdraw` | final relay payload; EVM은 candidate `IPrivacy.withdraw` transaction도 반환 | Product Relayer가 payload에서 transaction을 재구성·검증하고 자기 계정으로 제출 | handoff 전 `recordRelayHandoff(...)`; 이후 tx/nullifier/evidence로 reconcile |
| Disclosure 조회 | `decodeUserDisclosure(...)`, `decodeSelfViewDisclosure(...)`, `decodeAuditDisclosure(...)`, batch decode API | privacy event, scan event 또는 typed privacy scan | 없음 | 로컬에서 검증·복호화한 disclosure report | 제출 없음 | commitment, output index, policy, digest와 대상 key가 모두 일치해야 `verified` |

`prepare*`가 반환됐다는 사실은 transaction 제출이나 성공을 뜻하지 않는다. Cosmos sign doc 또는 EVM transaction은 wallet·relayer 경계를 넘기기 전까지 `ProofReady` artifact이며, 제출 후에는 [상태 전이 문서](./reservation-state-machine.ko.md)의 evidence 규칙으로 처리한다.

## Prover와 Deposit Proof 매핑

| SDK API / adapter | HTTP 대상 | 요청 계약 | 응답 계약 | 호출되는 흐름 |
| --- | --- | --- | --- | --- |
| `createHttpProverAdapter(...).proveDeposit(...)` | `POST {proverUrl}/v1/prover/deposit` | request `v1`, compressed receiver key·amount·asset ID·randomness·commitment를 담은 memo-free payload `v1` | response `v1`, nested proof `v1`, exact commitment, canonical 164-byte proof | Core v0.4.0 기본 Cosmos deposit route |
| `createHttpDepositProofProviderV1({ url })` | `POST <depositProofUrl>` | 동일한 canonical request/payload `v1` | 동일한 canonical response/proof `v1`, exact HTTP 200과 JSON content type | redirect를 허용하지 않는 Cosmos Core v0.4.0 exact endpoint override |
| `createHttpDepositProofProvider({ url })` | `POST <product endpoint>` | legacy flat `{ note_json, note_commitment_hex }` | legacy flat `{ version: "v1", proof_hex, note_commitment_hex }` | 기존 EVM/product-specific endpoint 호환용이며 Cosmos Core v0.4.0 wire가 아님 |
| `createHttpProverAdapter(...).proveTransfer(...)` | `POST {proverUrl}/v1/prover/transfer` | request `v2`, prepared transfer payload `v5` | response `v2`, request payload hash와 proof binding | native transfer와 self-merge |
| `createHttpProverAdapter(...).proveWithdraw(...)` | `POST {proverUrl}/v1/prover/withdraw` | request/prover payload `v2` | response/proof `v2`, request payload hash binding | direct withdraw와 relay withdraw |
| `createHttpProverAdapter(...).proveBatchTransfer(...)` | `POST {proverUrl}/v1/proofs/batch-transfer` | request `v1`, payload `batch-transfer-payload-v1` | response `v1`, proof `batch-transfer-proof-v1`, payload/circuit binding | Cosmos One-Proof Batch Transfer |
| `createAsyncJobProverAdapter(...)` | Product-defined | caller의 submit 함수 | caller의 `getJob` 결과를 위 proof 계약으로 검증 | queue/poll 기반 remote prover |

Cosmos browser client에 `proverUrl`만 제공하고 adapter나 exact deposit URL을
주입하지 않으면 SDK가 기본 HTTP adapter의 canonical deposit route를 사용한다.
Local/WASM prover나 사내 인증·queue contract를 쓰려면 adapter를 직접 주입한다.
Automatic cross-endpoint failover는 계속 비활성화다.

Cosmos profile의 exact `depositProofUrl`은 `createHttpDepositProofProviderV1`로
해석한다. 이름에 version이 없는 `createHttpDepositProofProvider`는 기존
EVM/product-specific integration을 위해 legacy flat wire를 의도적으로
유지하므로 Core v0.4.0 Cosmos prover client로 사용하면 안 된다.

## Clairveil Chain REST 조회 매핑

아래 route는 [Query proto](../proto/clairveil/privacy/v1/query.proto)의 HTTP annotation과 browser/Cosmos public client 구현이 공통으로 사용하는 계약이다.

| SDK 메서드 | HTTP | Clairveil REST route | 용도 |
| --- | --- | --- | --- |
| `fetchPrivacyEvents(...)` | GET | `/clairveil/privacy/v1/events` | raw privacy event 진단 page |
| `fetchScanEvents(...)` | GET | `/clairveil/privacy/v1/scan_events` | 저수준 compatibility/debugging sequence-cursor page; 고수준 wallet/spend scan은 이 endpoint로 fallback하지 않음 |
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

`scanWalletNotes(...)`와 모든 고수준 spend 준비는 event filter 없이 typed `privacy_scan`만 사용한다. Endpoint가 없거나 typed response가 malformed이면 fail-closed하며 wallet cursor를 전진시키거나 다른 source cursor로 교체하지 않는다. `scanNotes({ scanSource: "scan_events" })`와 `fetchScanEvents(...)`는 저수준 진단/호환 surface로 남는다. Wallet은 wire의 `(height, global_sequence, output_index)` 전체 cursor를 사용하고, 해당 cursor까지의 모든 output과 nullifier 상태가 durable하게 반영된 뒤 같은 transaction에서 cursor를 commit해야 한다.

`commitment_paths_at_root`는 요청한 root/height와 정확히 같은 snapshot의 path만 사용한다. Current-root path는 persisted incremental node를 읽으므로 online historical-rebuild budget을 소비하지 않는다. Non-current historical public query는 complete root/count/height metadata를 요구하며 최대 1,024 leaves, keeper process당 동시 rebuild 2개로 제한된다. 한계를 넘으면 `ResourceExhausted`가 반환되며 current root 또는 trusted local historical-path index를 사용해야 한다. 별도 offline recovery/export 상한은 `MaxMerkleRebuildLeaves = 1,048,576`이다. Remote historical root/path 요청은 provider에게 wallet의 시점과 관심 state를 노출한다.

Nullifier와 Merkle path 요청은 spend 대상의 linkage를 query provider에 노출할 수 있다. 기본값에서는 각각 `nullifierFailover: false`, `merklePathFailover: false`로 최초 configured REST endpoint에 고정하며, 여러 endpoint에 노출해도 된다는 제품 결정이 있을 때만 failover를 켠다.

## 공통 Cosmos / EVM 보조 호출

| SDK 기능 | 외부 호출 | 비고 |
| --- | --- | --- |
| Cosmos sign doc 준비 | `GET /cosmos/auth/v1beta1/accounts/{address}` | account number와 sequence 조회 |
| `getBalances(...)` | `GET /cosmos/bank/v1beta1/balances/{address}` | transparent account balance |
| `signDirectAndBroadcast(...)`, `broadcastSignedTx(...)` | CosmJS/Comet RPC broadcast와 tx lookup | ClairveilJS가 별도 product REST broadcast route를 정의하지 않음 |
| EVM prepare preflight | read-only `eth_chainId` | configured `evmRpc`와 연결 wallet network를 각각 확인 |
| `sendEvmTransaction(...)` | wallet `eth_sendTransaction` | transaction 권한은 EIP-1193 wallet 또는 relayer에 있음 |
| `waitForEvmTransaction(...)` | read-only `eth_getTransactionReceipt`, `eth_getTransactionByHash`, `eth_chainId`; 정책에 따라 `eth_blockNumber`, `eth_getBlockByNumber` | prepared request·sender를 받아 receipt, hash/from/to/input/value/network, action별 privacy event와 명시적으로 선택한 finality policy를 검증. Policy가 없으면 fail-closed하며 depth/safe/finalized 정책은 canonical inclusion block hash를 재검증 |
| relay expiry 검증용 chain time | caller가 최신 chain block time 제공 | README의 latest-block REST helper는 예시이며 SDK 고정 relayer API가 아님 |

Privacy scan, circuit, asset, Merkle path, nullifier 같은 Clairveil module 조회는 기본적으로 configured Clairveil REST endpoint를 사용한다. EVM 체인은 완전한 `PrivacyStateAdapter`를 주입해 같은 조회를 contract getter나 indexer로 대체할 수 있다. 이 경우 같은 constructor 호출에 adapter를 함께 전달한 런타임 EVM profile만 Cosmos `rpc`/`rest`를 생략할 수 있다. Adapter read도 `queryTimeoutMs`와 동일 adapter 내부의 bounded `queryRetry`를 적용한다. 직렬화되는 `BrowserWalletProfile`과 `ClairveilWebClientConfig`는 완전한 배포 계약이므로 두 endpoint를 계속 요구하고, Cosmos profile도 항상 `rpc`와 `rest`가 필수다. SDK의 typed scan·circuit·asset·Merkle·reserve 검증은 adapter 경계 뒤에서도 그대로 적용된다. `evmRpc`는 network ID, receipt와 finality/reorg 검증 등 EVM JSON-RPC 조회에 사용한다.

## 온체인 실행 매핑

| 작업 | Cosmos type URL | EVM 실행 | 준비 결과 | 제출 계정 |
| --- | --- | --- | --- | --- |
| Deposit | `/clairveil.privacy.v1.MsgDeposit` | `IPrivacy.deposit(...)` | sign doc 또는 EVM transaction | 사용자 wallet |
| Native transfer | `/clairveil.privacy.v1.MsgTransfer` | `IPrivacy.transfer(...)` | sign doc 또는 EVM transaction | 사용자 wallet |
| One-Proof Batch Transfer | `/clairveil.privacy.v1.MsgBatchTransfer` | `IPrivacy.singleProofBatchTransfer(...)` 또는 authorization variant | Cosmos sign doc 또는 EVM transaction | 사용자 wallet |
| Direct withdraw | `/clairveil.privacy.v1.MsgWithdraw` | `IPrivacy.withdraw(...)` | sign doc 또는 EVM transaction | 사용자 wallet |
| Relay withdraw | `/clairveil.privacy.v1.MsgWithdraw` | `IPrivacy.withdraw(...)` | relay payload와 optional candidate transaction | Product Relayer |

One-Proof Batch Transfer는 동일한 frozen payload/proof와 operation evidence를 Cosmos와 EVM 실행 artifact로 매핑한다. EVM 경로는 precompile의 canonical single-proof selector와 exact calldata를 사용하며 여러 독립 `transfer` 호출로 fallback하지 않는다.

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
| network `txHash` 또는 Cosmos exact signed `txBytesHash` | chain에서 조회 가능한 transaction identity가 존재함 | chain 성공과 원하는 output 생성 |
| EVM `txBytesHash` | prepared EVM transaction request와 reservation의 로컬 binding | network 제출, RPC tx identity 또는 chain 성공. `eth_sendTransaction`이 반환한 `txHash`가 별도로 필요 |
| successful tx result / receipt | 해당 transaction 실행 성공 | 기대한 payment/output과의 일치 |
| input nullifier spent | 입력 note가 소비됨 | payment 또는 payroll item 성공 |
| EVM network `txHash` + prepared `txBytesHash` + successful receipt + verified RPC call/event + verified finality policy + expected output evidence 일치 | EVM operation 성공 판정 가능 | linked input 일부만 확인한 상태 |

Reservation API를 사용하는 직접 제출 흐름은 외부 broadcast 직전에 `markBroadcastAttempting(...)`, 실제 제출 후 `markSubmitted(...)` 또는 불확실한 경우 `markUnknown(...)`에 해당하는 durable evidence를 남겨야 한다. 이미 `recordRelayHandoff(...)`한 payload는 로컬 broadcast를 시작하지 않는다. relayer가 반환한 hash만으로는 `Submitted`를 기록할 수 없으며, authoritative chain 조회로 동일 payload의 transaction 포함을 확인한 뒤 `recordRelayTransactionEvidence(...)`에 payload hash, network tx hash, checked height와 literal inclusion evidence를 전달해야 한다. 고수준 EVM prepare는 `execution_transport: "evm"`과 prepared `txBytesHash`를 `ProofReady`에 기록한다. 이 record의 `markSubmitted(...)`과 `recordRelayTransactionEvidence(...)`은 network `txHash`를 요구하고, `reconcileSpentNotes(...)`는 network hash와 artifact hash가 각각 일치하는지와 `waitForEvmTransaction(...)`이 제공하는 successful receipt·RPC transaction identity·privacy event·finality 검증을 모두 요구한다. 저수준 custom EVM 경로도 `markProofReady(...)`에서 같은 transport tag를 넣어야 한다. SDK broadcast helper는 직접 제출 lifecycle을 대신 관리할 수 있다.

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
