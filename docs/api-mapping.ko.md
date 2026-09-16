# ClairveilJS API 매핑

## 목적과 범위

이 문서는 브라우저 DApp에서 호출하는 ClairveilJS API가 실제로 어떤 **chain REST/RPC**, **prover HTTP 계약**, **Cosmos message**, **EVM privacy precompile**로 이어지는지 추적할 수 있게 한다.

순수 crypto·codec·schema helper의 전체 symbol reference가 아니라, 외부 시스템과 통신하거나 transaction을 만드는 고수준 흐름을 대상으로 한다. 각 메서드의 전체 인자와 반환 타입은 package export map의 TypeScript declaration을 기준으로 한다.

- 시스템 배치와 신뢰 경계: [시스템 아키텍처](./architecture.ko.md)
- note 중복 사용 방지와 제출 후 복구: [Note Reservation 상태 전이](./reservation-state-machine.ko.md)
- endpoint와 client option: [배포·클라이언트 설정](./configuration.ko.md)
- 오류 형태와 재시도 판단: [오류·복구](./errors-and-recovery.ko.md)

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
