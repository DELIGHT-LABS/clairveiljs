# ClairveilJS 배포·클라이언트 설정

## 목적과 기준

이 문서는 브라우저 DApp이 ClairveilJS를 production 환경에 연결할 때 사용하는 chain profile, endpoint, timeout, query failover, prover, EVM, 로컬 저장소 설정을 설명한다.

- 시스템의 컴포넌트와 신뢰 경계: [시스템 아키텍처](./architecture.ko.md)
- SDK API와 외부 endpoint 매핑: [API 매핑](./api-mapping.ko.md)
- 제출 전후 상태와 evidence: [Note Reservation 상태 전이](./reservation-state-machine.ko.md)
- 암호화 wallet DB와 reservation 영속화: [저장소·영속성](./storage-and-persistence.ko.md)
- 실패 처리와 재시도 기준: [오류·복구](./errors-and-recovery.ko.md)

TypeScript에서는 `BrowserWalletProfile`, `ClairveilWebClientConfig`, `ClairveilBrowserClientOptions`가 필드 계약의 기준이다. 런타임에서는 `validateBrowserWalletProfile(...)`과 `validateClairveilWebClientConfig(...)`가 알 수 없는 필드, transport별 필수값, URL 형식과 상호 일관성을 fail-closed로 검증한다.

Production에서는 개별 endpoint를 생성자에 흩어 넣기보다, 완전한 profile을 먼저 검증한 뒤 그 `activeProfile`로 client를 만드는 방식을 권장한다.

> **Release 상태:** 이 SDK가 지원하는 Clairveil v0.3.1 SDK handoff snapshot은
> `PUBLICATION_READY_EXPERIMENTAL`이며 `PRODUCTION_RELEASE_READY`가 아니다.
> 아래 production 설정은 안전한 downstream 통합 기준이지 formal trusted
> setup, 외부 security/circuit audit, signed production artifact 또는 실제
> downstream chain/product 검증을 대신하지 않는다.

```js
import {
  ClairveilBrowserClient,
  validateClairveilWebClientConfig
} from "clairveiljs/browser-dapp";

const validated = validateClairveilWebClientConfig(serverConfig);
const client = new ClairveilBrowserClient({
  profile: validated.activeProfile,
  queryTimeoutMs: 30_000,
  nullifierFailover: false,
  merklePathFailover: false
});

await client.health();
```

`profile`을 넘기면 chain identity, wallet type과 endpoint는 profile만을 source of truth로 사용한다. 같은 생성자에 `rpc`, `rest`, `chainId`, `proverUrl`, `evmRpc` 등을 함께 넘겨도 profile 값이 우선한다. Timeout, retry, failover, injected adapter처럼 profile에 속하지 않는 client 동작 옵션은 별도로 적용된다.

## 배포 설정 문서

`ClairveilWebClientConfig`의 최소 구조는 다음과 같다.

| 필드 | 필수 | 의미 |
| --- | --- | --- |
| `schemaVersion` | 예 | 반드시 `clairveil-web-client-config-v1` |
| `activeChainProfileId` | 예 | `chainProfiles` 중 사용할 profile ID |
| `chainProfiles` | 예 | 중복 ID가 없는 하나 이상의 완전한 profile |
| `serverBacked`, `serverFeatures` | 아니요 | 제품 서버와 UI capability를 나타내는 정책 메타데이터 |
| `modeLabel`, `home`, `localSignerHome`, `localSignerBin`, `localTestMode` | 아니요 | 배포·로컬 도구용 메타데이터. SDK transport 동작을 대신 설정하지 않는다. |

과거 호환을 위한 최상위 `chainId`, `rpc`, `rest`, `proverUrl`, `transport`, denom/prefix, Keplr/EVM 필드도 허용되지만, 존재한다면 선택된 active profile과 정확히 같아야 한다. 새 설정에서는 이 flattened 필드를 생략한다.

`serverFeatures`는 UI 노출과 제품 정책을 위한 flag다. 예를 들어 `batchTransfer: true`만으로 One-Proof 기능이 자동 활성화되지는 않는다. 호출자는 정책을 확인한 뒤 Cosmos/EVM client의 `enableExperimentalBatchTransfer`를 명시적으로 설정해야 한다.

## 공통 Profile 필드

Cosmos와 EVM profile은 아래 필드를 모두 가진다.

| 필드 | 계약 |
| --- | --- |
| `id` | 영문·숫자로 시작하는 1~128자의 ID. `A-Z`, `a-z`, `0-9`, `.`, `_`, `-`만 사용 |
| `label`, `chainName` | 사용자에게 표시할 1~128자 문자열 |
| `transport` / `wallet` | `cosmos` / `keplr` 또는 `evm` / `metamask` 조합 |
| `chainId` | Clairveil protocol domain과 Cosmos sign doc에 사용하는 chain ID |
| `rpc` | Clairveil chain의 Comet RPC base URL |
| `rest` | 주 Clairveil REST base URL |
| `restEndpoints` | 선택적 REST 후보 목록. 비어 있거나 중복될 수 없으며 실제 순서는 `rest`가 먼저다. |
| `accountPrefix`, `shieldedPrefix` | account와 shielded address의 Bech32 prefix |
| `denom`, `displayDenom`, `coinDecimals` | minimal denom, 표시 denom과 decimals |
| `proverUrl` | transfer, withdraw, One-Proof batch용 기본 HTTP prover base URL. Versioned prover route를 붙일 때 path prefix를 보존함 |
| `depositProofUrl` | 선택적 DepositCircuit 전용 exact URL. `proverUrl`에서 파생하지 않음 |

Profile URL은 `http` 또는 `https`이고 query, fragment, embedded credential이 없어야 한다. Runtime validator는 로컬 개발을 위해 HTTP도 허용하지만 production endpoint에는 HTTPS를 사용하고 bearer token이나 private 값을 URL에 넣지 않는다.

## Cosmos Profile

Cosmos profile에는 다음 필드가 추가로 필요하다.

| 필드 | 계약 |
| --- | --- |
| `keplrCoinType` | 0~4,294,967,295 범위의 정수 |
| `gasPriceStep` | 양수인 `low`, `average`, `high` |
| `keplrChainInfo` | Keplr suggest-chain 정보 |

`keplrChainInfo.chainId`, `chainName`, `rpc`, `rest`, coin type, gas price와 denom 표시 정보는 profile의 대응 필드와 정확히 일치해야 한다. `currencies`와 `feeCurrencies`는 각각 하나의 currency만 포함하고 `features`는 빈 배열이어야 한다.

```js
const cosmosProfile = {
  id: "clairveil-mainnet",
  label: "Clairveil",
  chainName: "Clairveil",
  transport: "cosmos",
  wallet: "keplr",
  chainId: "clairveil-1",
  rpc: "https://rpc.example.com",
  rest: "https://rest.example.com",
  restEndpoints: ["https://rest.example.com"],
  accountPrefix: "clair",
  shieldedPrefix: "clairs",
  denom: "uclair",
  displayDenom: "CLAIR",
  coinDecimals: 6,
  proverUrl: "https://prover.example.com",
  depositProofUrl: "https://deposit-proof.example.com/v1/proof",
  keplrCoinType: 118,
  gasPriceStep: { low: 0.01, average: 0.025, high: 0.04 },
  keplrChainInfo: {
    chainId: "clairveil-1",
    chainName: "Clairveil",
    rpc: "https://rpc.example.com",
    rest: "https://rest.example.com",
    bip44: { coinType: 118 },
    bech32Config: {
      bech32PrefixAccAddr: "clair",
      bech32PrefixAccPub: "clairpub",
      bech32PrefixValAddr: "clairvaloper",
      bech32PrefixValPub: "clairvaloperpub",
      bech32PrefixConsAddr: "clairvalcons",
      bech32PrefixConsPub: "clairvalconspub"
    },
    currencies: [{ coinDenom: "CLAIR", coinMinimalDenom: "uclair", coinDecimals: 6 }],
    feeCurrencies: [{
      coinDenom: "CLAIR",
      coinMinimalDenom: "uclair",
      coinDecimals: 6,
      gasPriceStep: { low: 0.01, average: 0.025, high: 0.04 }
    }],
    stakeCurrency: { coinDenom: "CLAIR", coinMinimalDenom: "uclair", coinDecimals: 6 },
    features: []
  }
};
```

위 URL과 network 값은 형식 예시다. 실제 배포에서는 target chain이 배포한 값을 사용한다.

## EVM Profile

EVM profile은 Clairveil REST/RPC 필드와 별도로 다음 값을 요구한다.

| 필드 | 계약 |
| --- | --- |
| `evmRpc` | read-only EVM JSON-RPC URL. wallet provider 대신 chain ID와 receipt 조회에 사용 |
| `evmChainId` | `0x`로 시작하는 EVM quantity 형식의 network ID |
| `evmChainName` | 표시용 network 이름 |
| `evmPrivacyPrecompileAddress` | target/downstream chain이 제공하는 20-byte `IPrivacy` precompile 주소 |
| `evmAuthorizationProfile` | 선택적 JSON-safe chain policy. `typedDataDomain`과 target이 허용하는 `supportedAuthorizationKinds`를 정의 |
| `evmGasLimit` | privacy transaction용 hex quantity |
| `evmSendGasLimit` | native send용 hex quantity |
| `evmDepositMode` | browser EVM profile에서는 canonical `payable-exact-value`가 필수 |
| `evmNativeDenom` | payable deposit에서는 필수이며 `denom`과 정확히 같아야 함 |

공통 `chainId`는 Clairveil payload domain이고 `evmChainId`는 EVM network ID이므로 서로 대체할 수 없다. Proof나 transaction을 준비하기 전에 SDK는 configured `evmRpc`와 연결된 signing wallet이 모두 `evmChainId`와 일치하는지 확인한다.

`payable-exact-value`는 downstream chain이 Clairveil v0.3.1 exact-value deposit ABI와 accounting을 제공할 때만 사용한다. SDK는 minimal-unit amount를 `msg.value`에 정확히 binding하며 `evmNativeDenom !== denom`이면 client 생성 단계에서 거부한다.

```js
const evmProfile = {
  id: "clairveil-evm",
  label: "Clairveil EVM",
  chainName: "Clairveil EVM",
  transport: "evm",
  wallet: "metamask",
  chainId: "clairveil-evm-1",
  rpc: "https://comet.example.com",
  rest: "https://privacy-rest.example.com",
  accountPrefix: "clair",
  shieldedPrefix: "clairs",
  denom: "uclair",
  displayDenom: "CLAIR",
  coinDecimals: 6,
  proverUrl: "https://prover.example.com",
  evmRpc: "https://evm-rpc.example.com",
  evmChainId: "0x539",
  evmChainName: "Clairveil EVM",
  evmPrivacyPrecompileAddress: targetChainPrivacyContractAddress,
  evmDepositMode: "payable-exact-value",
  evmNativeDenom: "uclair",
  evmAuthorizationProfile: {
    typedDataDomain: { name: "Target EVM Privacy", version: "1" },
    supportedAuthorizationKinds: [1, 2, 3]
  },
  evmGasLimit: "0x989680",
  evmSendGasLimit: "0x5208"
};
```

Precompile 주소와 payable 지원 여부는 target/downstream chain의 배포 계약에서 확인해야 한다. ClairveilJS 기본값이나 예시 주소만으로 지원을 가정하지 않는다.

## Client 동작 옵션

Profile 밖에서 조절하는 주요 `ClairveilBrowserClientOptions`는 다음과 같다.

| 옵션 | 기본값 | 운영 기준 |
| --- | --- | --- |
| `queryTimeoutMs` | 30,000ms | REST/RPC 및 `PrivacyStateAdapter` read timeout. `fetchTimeoutMs`는 호환 alias이며 존재하면 우선한다. |
| `queryRetry` | 2회, 250~1,500ms jitter | 기본 retry status는 408, 429, 502, 503, 504. Adapter retry는 동일 adapter만 다시 호출하며 다른 provider로 전환하지 않는다. `false`면 retry하지 않는다. |
| `evmFinalityPolicy` | 없음 | EVM confirmation에는 명시적으로 필요하다. Chain 기준에 맞춰 confirmation depth, `safe`, `finalized`, `custom` 중 하나를 사용한다. `receipt`는 mined block identity만 확인하는 명시적 low-finality opt-in이다. |
| `nullifierFailover` | `false` | 켜면 같은 nullifier를 여러 REST provider에 노출할 수 있다. 제품의 privacy 결정이 있어야 한다. |
| `merklePathFailover` | `false` | 켜면 spend commitment와 exact snapshot 요청이 여러 provider에 노출될 수 있다. |
| `proverAdapter` | 없음 | local/WASM, 사내 인증 또는 async job prover를 주입한다. 있으면 기본 HTTP adapter보다 우선한다. |
| `proverBearerToken` | 없음 | 기본 HTTP prover의 Authorization credential. URL이나 로그에 남기지 않는다. |
| `proverTimeoutMs` | 120,000ms | transfer/withdraw/batch prover timeout |
| `depositProofProvider` | 없음 | local/WASM DepositCircuit provider. 있으면 `depositProofUrl`보다 우선한다. |
| `depositProofTimeoutMs` | 120,000ms | exact deposit proof HTTP timeout |
| `depositProofResponseMaxBytes` | 1MiB | deposit proof 응답 상한 |
| `enableExperimentalBatchTransfer` | `false` | Cosmos/EVM One-Proof batch 명시적 opt-in. EVM에서는 canonical single-proof transaction으로 매핑한다. |

일반 조회는 configured REST endpoint 사이에서 retry/failover할 수 있지만 nullifier와 Merkle witness는 privacy linkage가 크기 때문에 기본 endpoint에 고정된다. Availability를 높이기 위해 두 옵션을 켤 때는 provider 운영 주체가 정말 분리되어 있는지, 같은 사용자를 결합할 수 있는지 먼저 검토한다.

## Prover와 Deposit Proof 경계

`proverUrl`은 다음 기본 route의 base URL이다.

- `POST /v1/prover/transfer`
- `POST /v1/prover/withdraw`
- `POST /v1/proofs/batch-transfer`

Deposit proof는 이 base URL을 사용하지 않는다. 다음 중 하나만 선택한다.

1. `depositProofProvider`: 브라우저 local/WASM 또는 호출자가 검토한 구현
2. `depositProofUrl`: profile에 고정된 정확한 HTTP endpoint

`depositProofUrl`을 `proverUrl`에서 문자열로 조합하거나 fallback하지 않는다. 원격 prover와 deposit proof service는 private payload를 보는 별도 신뢰 주체로 평가한다.

### Remote prover 운영 경계

Clairveil reference prover를 원격으로 운영할 때의 server-side 기본 admission은
회로별 `max_in_flight=1`, `max_queued=4`, positive
`max_request_bytes=8,388,608`(8 MiB)이며 0은 invalid다. 이는
`ClairveilBrowserClientOptions`가 아니라 prover 배포 설정이다. Raw transport
handler를 직접 노출하지 말고 body limit, 인증, TLS, timeout, rate limit과
redacted logging을 적용한 bounded service handler만 노출한다.

Client timeout 또는 `AbortSignal`은 응답 대기만 취소하며 이미 시작한 in-process
solver의 종료나 permit/memory 반환을 보장하지 않는다. 현재 일반
transfer/withdraw prepare helper는 이 오류를 받으면 `rollbackPlanReservation(...)`을
호출한다. Proving 시작 전 `Reserved` operation은 release할 수 있지만 `Proving` 또는
`ProofReady`는 현재 lease가 전이를 허용할 때 `ManualReview`로 격리한다. Opaque job
ID와 checkpoint가 필요한 async 제품은 이를 별도 operation store에서 추적해야 한다.
Hard cancellation과 OOM containment가 필요하면 supervised worker process와 process
isolation을 사용한다.

기본 prover 정책은 명시적으로 선택한 endpoint 하나와 automatic failover
비활성화다. `retryable=true`, timeout 또는 queue saturation은 같은 private
witness를 다른 endpoint로 보낼 권한이 아니다. 같은 endpoint의 bounded retry는
가능하지만 추가 endpoint 전송은 privacy boundary 확대를 설명한 뒤 사용자 또는
제품 정책이 명시적으로 승인한 별도 adapter에서만 구현한다.

## 로컬 저장소 보안

Note Store와 Reservation Store의 보안 계약은 다르다.

| 저장소 | Production | Demo/Test 전용 |
| --- | --- | --- |
| Note Store | 앱 또는 지갑이 제공하는 별도 암호화 wallet DB로 note store contract 구현 | `LocalStorageNoteStore({ allowPlaintext: true })`는 복호화된 note를 평문 JSON으로 저장 |
| Reservation Store | `createBrowserReservationStore(...)` + IndexedDB + Web Locks + `encodeState`/`decodeState` | `unsafeAllowPlaintext`, `unsafeAllowMemoryFallback`, `MemoryReservationStore` |

Reservation `namespace`는 chain과 wallet identity에 대해 안정적으로 정하고, `indexKey`는 privacy root seed처럼 wallet-private material에서 가져온다. 공개 account ID를 lookup key로 쓰는 `unsafeAllowPublicIndexKey`와 memory/plaintext fallback은 production에서 사용하지 않는다. 암호화 키와 private material은 ciphertext와 같은 레코드에 저장하지 않는다.

구체적인 IndexedDB namespace, AEAD envelope, production Note Store adapter와 key rotation/recovery 계약은 [저장소·영속성 구현 가이드](./storage-and-persistence.ko.md)를 따른다.

## 시작 전 확인 순서

1. 서버 설정을 `validateClairveilWebClientConfig(...)`로 검증하고 하나의 active profile을 선택한다.
2. Production URL이 HTTPS인지, credential·query·fragment가 없는지 확인한다.
3. `client.health()`로 Comet chain ID, initialized tree와 audit config를 확인한다. 초기 부트스트랩 화면에서만 `allowUninitializedTree: true`를 고려한다.
4. EVM profile은 `assertEvmNetwork()`로 read-only RPC를 확인한다. Prepare/send API는 signing wallet network도 별도로 확인한다.
5. Circuit, disclosure, audit, asset config가 제품이 기대한 identity와 policy인지 preflight한다.
6. Note Store와 Reservation Store의 암호화·Web Locks 설정을 확인한다.
7. Prover와 deposit proof endpoint/provider를 각각 검토하고 timeout과 credential을 설정한다.
8. Broadcast 전 reservation checkpoint가 영속화되고, 실패 시 [오류·복구 가이드](./errors-and-recovery.ko.md)에 따라 reconcile할 수 있는지 확인한다.
9. Active circuit order, `privacy-fixed-v1` encoding, public-input schema와 wire version이 [API 매핑의 고정 계약](./api-mapping.ko.md#clairveil-v031-고정-계약)과 정확히 일치하는지 확인한다.
10. Formal trusted setup, 외부 audit, signed production artifact와 target chain/product E2E가 완료됐는지 별도 release gate에서 확인한다.

`health()` 성공은 endpoint와 기본 chain 설정이 유효하다는 뜻이지, prover, wallet 서명, EVM payable accounting 또는 실제 transaction 성공을 보장하지 않는다.

## 구현 참조

- Profile 타입과 client 옵션: `src/browser/wallet-client.d.ts`
- Profile/config runtime 검증과 client 구성: `src/browser/wallet-client.js`
- REST retry와 failover: `src/browser/public-client.js`, `src/transport/cosmos-client.js`
- Prover와 deposit proof adapter: `src/privacy/prover.js`
- Note store: `src/privacy/note-store.js`
- Reservation store와 manager: `src/privacy/reservation.js`
