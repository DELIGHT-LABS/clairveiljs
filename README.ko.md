# ClairveilJS

ClairveilJS는 Clairveil privacy 기능을 브라우저와 Node.js 환경에서 사용할 수 있게 해주는 JavaScript SDK입니다.

English documentation: [README.md](./README.md)

시스템 아키텍처: [docs/architecture.ko.md](./docs/architecture.ko.md)

API 매핑: [docs/api-mapping.ko.md](./docs/api-mapping.ko.md)

Note reservation 상태 전이: [docs/reservation-state-machine.ko.md](./docs/reservation-state-machine.ko.md)

저장소·영속성 구현: [docs/storage-and-persistence.ko.md](./docs/storage-and-persistence.ko.md)

배포·클라이언트 설정: [docs/configuration.ko.md](./docs/configuration.ko.md)

오류·복구: [docs/errors-and-recovery.ko.md](./docs/errors-and-recovery.ko.md)

이 패키지는 Clairveil 전용 privacy primitive와 DApp 친화적인 API를 제공합니다.

- Telescope로 생성한 `MsgDeposit`, `MsgTransfer`, `MsgBatchTransfer`, `MsgWithdraw`, privacy query protobuf binding
- Clairveil transaction type URL과 CosmJS `Registry` 생성
- privacy root signing message helper
- 브라우저 친화 crypto primitive (`@noble/hashes`, `@noble/ciphers`)
- root seed, spend/view/disclosure key derivation
- shielded address encode/decode
- note 생성, commitment/nullifier 계산, note encryption
- transfer disclosure MiMC digest 검증
- privacy event, auditable transfer, reserve accounting, balance query
- Keplr/custom signer용 wallet adapter
- memory 및 명시적 plaintext opt-in이 필요한 demo/test용 localStorage note store
- transfer/withdraw planner와 안정적인 `ClairveilError` 코드
- prepared transfer/withdraw/relay withdraw payload builder
- experimental feature gate가 적용된 One-Proof BatchTransfer V1 준비 (`MsgBatchTransfer`, 입력 1~16개, 출력 1~32개)
- `/v1/prover/transfer`, `/v1/prover/withdraw`, `/v1/proofs/batch-transfer` HTTP prover adapter
- Keplr `signDirect`용 sign doc 생성, signed tx 조립, broadcast
- EIP-1193 wallet용 Clairveil-compatible `IPrivacy` EVM precompile calldata adapter
- runtime shape assertion과 TypeScript declaration

## 설치

```bash
npm install clairveiljs@0.3.1
```

[DELIGHT-LABS/clairveiljs](https://github.com/DELIGHT-LABS/clairveiljs)

Node.js는 `>=20`을 요구합니다. 브라우저 번들러에서는 일반 Web API인 `fetch`, `TextEncoder`, `TextDecoder`, `crypto.getRandomValues`가 제공되어야 합니다.

## Entrypoints

```js
import { deriveShieldedAddress } from "clairveiljs/core";
import { createClairveilClient } from "clairveiljs/cosmos";
import { createClairveilBrowserDappClient } from "clairveiljs/browser-dapp";
import { createClairveilEvmClient } from "clairveiljs/evm";
import { createPrivacyStateAdapter } from "clairveiljs/privacy-state";
import { createEvmFinalityPolicy } from "clairveiljs/evm-finality";
import { createNoteReservationManager } from "clairveiljs/reservation";
```

Public consumer는 내부 파일 경로를 직접 import하지 말고 package export map을 사용하세요.

- `clairveiljs`: 현재 Cosmos 중심 client surface와 backward-compatible root entrypoint
- `clairveiljs/core`: key derivation, address, crypto, note, disclosure primitive
- `clairveiljs/cosmos`, `clairveiljs/cosmos-client`: CosmJS 기반 transport/client
- `clairveiljs/evm`: Clairveil-compatible EVM privacy precompile client
- `clairveiljs/privacy-state`: REST, contract getter, indexer용 transport-neutral privacy state adapter
- `clairveiljs/evm-finality`: receipt/depth/safe/finalized/custom EVM finality policy
- `clairveiljs/browser-dapp`: production DApp에서 쓰기 좋은 브라우저 wallet client
- `clairveiljs/browser-public`: public privacy event/read-only query client
- `clairveiljs/reservation`: wallet/DApp note reservation store와 manager
- `clairveiljs/generated/...`: Telescope generated protobuf binding

`clairveiljs/generated/.../tx`와 `clairveiljs/generated/.../tx.js` import 형태를 모두 지원합니다.

## Clairveil 호환성

| ClairveilJS | 검증한 Core source identity | Public Cosmos wire | Downstream EVM deposit |
| --- | --- | --- | --- |
| `0.3.1` | SDK bundle `v0.3.1` / Core `commit_snapshot` (`0ff9283`) | 기존 `MsgDeposit`/query 계약 유지 | opt-in `payable-exact-value` |

`clairveiljs@0.3.1`은 위 표의 고정 SDK handoff를 대상으로 하며 이후 core
변경까지 자동으로 지원하지 않습니다. Exact commit과 release 검증은
[핸드오프 적합성](#handoff-conformance)을 참고하세요.

Reservation은 v0.3.1 전이 표를 따릅니다.
`releaseReservedOrProving(...)`은 `Reserved`만 release하고, proving 시작 후
불명확한 작업은 `ManualReview`로 격리합니다. Evidence 규칙은
[상태 전이](./docs/reservation-state-machine.ko.md)와
[복구 가이드](./docs/errors-and-recovery.ko.md)를 따릅니다.

Clairveil `v0.3.1`의 공개 상태는 `PUBLICATION_READY_EXPERIMENTAL`이며
`PRODUCTION_RELEASE_READY`가 아닙니다. Formal trusted setup, 외부
security/circuit audit, signed production artifact와 downstream chain/product
검증은 별도 production gate입니다. 이 README에서 말하는 production 저장소·배포
권고는 그 gate를 닫았다는 뜻이 아닙니다.

`v0.3.1` release handoff에는 그 시점의 external ClairveilJS가 legacy였다고
기록되어 있습니다. 현재 패키지는 그 handoff 이후 frozen `privacy-note-v1` /
`privacy-fixed-v1` 계약을 port한 downstream 구현이며, 위 exact source와
fixture로 이를 검증합니다. Legacy decode나 compatibility fallback을 추가해
handoff 이전 형식을 다시 허용하지 않습니다.

고정 protocol 기준은 다음과 같다.

- Active circuit set은 `privacy-note-v1`이며 required order는 `deposit`, `spend`, `joinsplit`, `batch-joinsplit-16x32-v1`입니다.
- Canonical encoding은 `privacy-fixed-v1`이며 note plaintext 350 bytes, disclosure plaintext 392 bytes, typed envelope header 20 bytes입니다. Raw ciphertext, legacy JSON, wrong kind, non-zero reserved byte와 trailing byte는 거부합니다.
- Transfer는 prepared payload `v5`와 proof/request/response `v2`, withdraw는 prover/final payload와 proof/request/response `v2`, relay handoff/schema는 `v2`를 사용합니다.
- `AssetRegistryV1`이 denom/asset-ID mapping의 authoritative source이며 audit disclosure는 필수입니다. Transfer의 view tag는 정확히 두 개이고 각각 2 bytes이며, tag mismatch에서도 기본 scan은 full decrypt를 시도합니다.
- Exact public-input 순서와 Batch schema digest는 [API 매핑 문서](./docs/api-mapping.ko.md#clairveil-v031-고정-계약)를 따릅니다.

선택한 Core `0ff9283` commit snapshot의 `Keeper.DepositWithFunder`는 trusted in-process Go
integration API이며 protobuf, gRPC, CLI 또는 client `funder` field가
아닙니다. 따라서 ClairveilJS의 Cosmos message surface는 바꾸지 않고,
새 흐름은 대상 체인의 payable privacy precompile에서 사용합니다. Deposit
ABI는 정확히 `deposit((bytes,bytes,bytes))`이며 amount tuple field는 없고
최소 단위 `msg.value`만 amount source입니다. SDK의 기본 EVM adapter는
direct/authorized transfer·withdraw, multi-proof batch, Clairveil v0.3.1
single-proof batch용 `IPrivacy` ABI surface를 제공합니다. 다른 ABI를 쓰는
downstream chain은 동등한 effect와 receipt 검증을 제공하는 custom adapter를
사용합니다.

## 예제 코드

최소 SDK 사용 예제는 [`examples/`](https://github.com/DELIGHT-LABS/clairveiljs/tree/main/examples)에 있습니다.

- Keplr/Cosmos: [`examples/minimal-keplr-flow.js`](https://github.com/DELIGHT-LABS/clairveiljs/blob/main/examples/minimal-keplr-flow.js)
- MetaMask/EVM: [`examples/minimal-metamask-flow.js`](https://github.com/DELIGHT-LABS/clairveiljs/blob/main/examples/minimal-metamask-flow.js)

두 예제는 wallet privacy material derivation, deposit 준비, note scan, transfer 준비, broadcast 흐름을 SDK surface로 수행합니다. Keplr/Cosmos 예제는 Cosmos `MsgDeposit`에 `DepositCircuit` proof가 포함되기 때문에 `depositProofProvider`가 필요합니다.

## Experimental One-Proof BatchTransfer V1

이 API는 experimental이며 기본값이 비활성화되어 있습니다. Downstream 애플리케이션이 required Go fixture conformance와 5-shape localnet matrix를 독립적으로 통과한 뒤에만 활성화하세요.

```js
const clairveil = createClairveilClient({
  rpc,
  rest,
  chainId,
  enableExperimentalBatchTransfer: true
});
```

`prepareTransferBatch(...)`는 Clairveil v0.3.1에서 공개한 frozen One-Proof `BatchTransfer` V1 계약을 구현합니다. 입력 1~16개를 계획하고 원자적으로 예약하며, 순서가 고정된 payment/change/padding 출력 1~32개를 만들고, 명시적으로 선택한 `proverAdapter.proveBatchTransfer(payload)`를 정확히 한 번 호출합니다. Cosmos profile은 `MsgBatchTransfer` 한 건을, EVM profile은 동일한 proof와 operation evidence에 binding된 `singleProofBatchTransfer` transaction을 반환합니다. Payment를 여러 독립 transfer proof로 확장하지 않고 prover 자동 failover도 하지 않습니다.

browser `prepareTransferBatch(...)`는 Cosmos profile에서는 `MsgBatchTransfer`
sign doc을, EVM profile에서는 같은 proof를 가진
`singleProofBatchTransfer` transaction을 반환합니다. EVM transport의 기본 adapter는
`batchTransfer`, `batchTransferWithAuthorization`,
`singleProofBatchTransfer`, `singleProofBatchTransferWithAuthorization`
calldata builder도 제공합니다. EIP-712 executor와 receipt barrier를 소유한
application은 이를 사용할 수 있으며, broadcast 뒤에는 반드시
`verifyEvmPrivacyReceipt(...)` 또는
명시적인 `evmFinalityPolicy`를 설정한 뒤
`waitForEvmTransaction(..., { privacyTransaction, sender })`로 action별
privacy event를 검증해야 합니다. receipt status만으로는 성공 증거가 아닙니다.

일반 `prepareTransfer(...)`는 공식 native 2×2 `MsgTransfer` 경로로 계속 지원되며 native 2×2는 deprecated가 아닙니다. 두 입력 witness는 검증된 하나의 exact-root `commitment_paths_at_root` snapshot에서 함께 가져옵니다. Clairveil의 기존 multi-message `transfer-batch` orchestration은 별도 protocol 의미를 유지하고 `prepareTransferBatch(...)`의 alias가 아닙니다.

실행 가능한 단건 transfer 준비에는 최신 체인 블록에서 얻은 `chainNowUnix`가 필수입니다. 선택적으로 지정한 `expiresAtUnix`는 prover payload와 signed `MsgTransfer`까지 그대로 유지됩니다. Broadcast 시에는 wallet 서명 이후 `getChainNowUnix`로 체인 시간을 다시 조회하며, provider 누락·오류·잘못된 값 또는 `chainNowUnix >= expiresAtUnix`이면 attempt marker와 RPC 호출 전에 fail-closed합니다.

Merkle witness (`merkle_path`)와 exact snapshot (`commitment_paths_at_root`) 요청은 기본적으로 설정된 REST endpoint에 고정됩니다. 지출하려는 commitment가 여러 endpoint에 노출되어도 되는 경우에만 `merklePathFailover: true`를 설정하세요.

여러 수신자와 출력별 disclosure에는 `payments`를 사용합니다. `outputMode: "compact"`는 payment와 선택적 change만 만들고, `outputMode: "exact32"`는 payment/change 뒤에 명시적인 0-value padding을 추가합니다.

```js
const prepared = await clairveil.prepareTransferBatch({
  material,
  payments: [
    {
      itemId: "invoice-1",
      amount: "5uclair",
      recipient: recipientA,
      userPrivacyPolicy: "all-private",
      userDisclosureMode: "none"
    },
    {
      itemId: "invoice-2",
      amount: "7uclair",
      recipient: recipientB,
      userPrivacyPolicy: "amount",
      userDisclosureMode: "recipient-encrypted",
      userDisclosureTargetPubKeyHex: recipientDisclosurePubKeyHex
    }
  ],
  outputMode: "exact32",
  proverAdapter,
  reservationManager,
  chainNowUnix: latestChainBlockTimeUnix,
  expiresAtUnix: latestChainBlockTimeUnix + 1800,
  async onPreparedPayload(payload) {
    await privateStore.write("batch-payload", payload, { mode: 0o600 });
  },
  async onPreparedProof(proof) {
    await privateStore.write("batch-proof", proof, { mode: 0o600 });
  }
});

// proof 한 건과 MsgBatchTransfer 한 건입니다.
console.log(prepared.prepared.inputCount, prepared.prepared.outputCount);
console.log(prepared.operationEvidence.expected_outputs);
```

실행 가능한 batch에는 `reservationManager`, `onPreparedPayload`,
`onPreparedProof`가 모두 필수입니다. Private checkpoint는 암호화하고 local
file은 mode `0600`으로 저장하세요. Checkpoint가 시작된 뒤 준비가 실패하면
reservation 전체를 `ManualReview`로 격리합니다.

재시작 후 `provePreparedBatchTransfer(...)`는 proof 단계만 복구하며 그
결과는 broadcast 권한이 아닙니다. 원래 operation 입력과 checkpoint를
`finalizePreparedBatchTransfer(...)`에 넘기면 authoritative reservation의 operation,
lease, nullifier 집합을 재검증한 뒤 정확한 집합만 `ProofReady`로 전이합니다.

Signed retry 전에는 저장된 transaction과 모든 input nullifier를 조회하고,
checkpoint한 TxRaw bytes만 재전송하세요. `ProofReady` retry에는 artifact의
현재 lease도 필요합니다. 자세한 절차는
[복구 가이드](./docs/errors-and-recovery.ko.md)를 참고하세요.

Batch 준비는 통합 `privacy-scan-v2`를 요구하며 ciphertext가 없는 legacy event로 fallback하지 않고 fail-closed합니다. SDK는 같은 root의 Merkle snapshot을 검증하고, proving 또는 proof 단계 복구 시 active circuit, authoritative asset mapping, audit identity, disclosure capability를 다시 확인하며, proving 전후 모든 nullifier를 확인하고 proof version/request hash/circuit identity를 검증합니다. 중단 없이 완료된 `prepareTransferBatch(...)`는 reservation 전체를 원자적으로 `ProofReady`로 전환합니다. 반면 proof 단계 복구 결과는 caller가 복원된 operation workflow를 완료할 때까지 `reservationFinalizationRequired: true`를 유지합니다. `operationEvidence`는 payment별 output index, commitment, recipient hash, amount/asset, user/audit/self-view disclosure digest를 기록합니다. Typed output reconcile에는 `fetchAuditableBatchTransfers(...)`, `decodeBatchUserDisclosure(...)`, `decodeBatchSelfViewDisclosure(...)`, `decodeBatchAuditDisclosure(...)`를 사용하고, 연속 audit-query cursor page 사이에는 같은 `createPrivacyScanValidationStateV2()` 객체를 유지하세요.

## 주소와 Prefix

Clairveil reference prefix는 다음처럼 구분됩니다.

- `clair1...`: transparent/public account 주소입니다. Cosmos 계정, prover creator, internal message creator에 사용됩니다.
- `clairs1...`: shielded/private note 주소입니다. shielded transfer recipient에 사용됩니다.
- `0x...`: EVM wallet 주소입니다. EVM chain에서 public recipient나 wallet account를 표현할 때 사용합니다.

Downstream Cosmos chain이 Clairveil privacy module을 embed하면서 prefix가 다르면 `accountPrefix`와 `shieldedPrefix`를 런타임 config로 넘기세요.

## Production Privacy Boundary

Production wallet과 DApp에서는 privacy material을 클라이언트, 또는 wallet-controlled runtime 안에 둬야 합니다.

특히 privacy root signature는 secret material로 다루세요. 같은 transparent address와 pubkey에 대해 root seed를 다시 유도할 수 있기 때문입니다.

Production 서버, relay, analytics endpoint, public proxy로 보내면 안 되는 값:

- privacy root signature 또는 root seed
- spend/view/disclosure private key
- decrypted note plaintext
- unbroadcast prepared payload 중 private witness나 note material이 포함된 값

Production DApp은 다음 역할을 SDK로 브라우저에서 직접 수행하는 것이 기본 모델입니다.

- root material derivation
- note scanning
- deposit preparation
- transfer preparation
- withdraw preparation
- user disclosure decode

로컬 데모나 백오피스 툴이 편의를 위해 helper server를 둘 수는 있습니다. 다만 그 구조를 production wallet boundary로 그대로 가져가면 안 됩니다.

Auditor disclosure decode는 trusted admin/backend/local auditor runtime에서 request-level disclosure private scalar를 제공하는 모델입니다. 일반 사용자 DApp에 audit disclosure private scalar 입력 UI를 두는 것은 production 패턴이 아닙니다.

## Browser DApp Client

Public node를 대상으로 하는 production DApp은 Clairveil application server 없이도 SDK를 직접 사용할 수 있습니다. chain RPC/REST endpoint와 prover URL을 넘기고, wallet privacy material은 브라우저나 wallet-controlled runtime에 보관하세요.

```js
import { createClairveilBrowserDappClient } from "clairveiljs/browser-dapp";

const clairveil = createClairveilBrowserDappClient({
  rpc: "https://rpc.example",
  rest: "https://rest.example",
  chainId: "clairveil-1",
  accountPrefix: "clair",
  shieldedPrefix: "clairs",
  denom: "uclair",
  proverUrl: "https://prover.example",
  evmRpc: "https://evm-rpc.example"
});

const deposit = await clairveil.prepareDeposit({
  address,
  pubKeyHex,
  signatureBase64: privacyRootSignatureBase64,
  amount: "1000000uclair",
  async depositProofProvider({ material }) {
    // local/WASM/trusted deposit prover에서 DepositCircuit proof를 생성합니다.
    return createDepositProof({ material });
  }
});

// 이 Cosmos-style client는 wallet signDirect용 deposit.signDoc을 반환합니다.
// EVM은 profile: { transport: "evm", ... }로 client를 만들면
// prepareDeposit이 EIP-1193 제출용 deposit.transaction을 반환합니다.
```

product-hosted DepositCircuit service를 쓰는 profile 기반 Cosmos DApp은
`profile.depositProofUrl`에 검토된 정확한 endpoint를 설정하세요. SDK는 이
URL을 `proverUrl`에서 만들지 않습니다. `{ note_json, note_commitment_hex }`를
한 번 직접 `POST`하고, redirect·JSON이 아닌 응답·제한을 넘는 응답을 거부하며,
같은 commitment를 담은 `{ version: "v1", proof_hex, note_commitment_hex }`
응답만 받습니다. local/WASM `depositProofProvider`도 계속 사용할 수 있습니다.
활성 profile에서는 `depositProofUrl`도 profile만 source입니다.

EVM profile의 `prepareDeposit`, `prepareTransfer`, `prepareWithdraw`,
`prepareRelayWithdraw`에는 `evmWallet: { getChainId() }`가 필요합니다. SDK는
proof나 prepared transaction을 만들기 전에 연결 지갑과 read-only `evmRpc`의
chain ID가 모두 `profile.evmChainId`와 일치하는지 확인합니다.

Browser-DApp의 `profile`은 생성 시 Web client profile contract에 맞춰
fail-closed 검증됩니다. 공통 필수 필드(`id`, `label`, `chainName`, wallet
metadata, endpoint, denom/display metadata)와 transport별 필드를 모두
제공해야 합니다. EVM profile에는 MetaMask, `evmRpc`, `evmChainId`,
`evmChainName`, precompile address, 두 gas limit이 필수입니다. EVM prepared
transaction은 provider를 직접 호출하지 말고
`sendEvmTransaction({ wallet, transaction, ...reservationOptions })`로
제출하세요. 이 API가 configured network를 다시 확인하고 reserved note의
broadcast lifecycle 상태를 보존합니다.

EVM profile은 `evmDepositMode: "payable-exact-value"`와 profile의
최소단위 `denom`과 같은 `evmNativeDenom`을 반드시 설정해야 합니다. 이 값은
per-request funding input이 아니라 고정 profile 설정입니다.

`waitForEvmTransaction(txHash, { privacyTransaction, sender })`이 일반적인 EVM confirmation API입니다. 원래 SDK가 준비한 transaction과 실제 제출 EOA/executor가 필수이며, receipt·전체 RPC transaction·현재 chain ID를 조회한 뒤 receipt status, hash/from/to/input/value/network identity, action별 privacy event와 선택한 `evmFinalityPolicy`가 모두 일치할 때만 성공합니다. 범용 EVM에는 안전한 기본 finality 값을 정할 수 없으므로 implicit policy가 없습니다. Chain 설정에서 confirmation depth, `safe`, `finalized` 또는 chain-owned `custom` 정책을 명시해야 합니다. `receipt`는 mined block number/hash를 요구하는 명시적 low-finality mode로만 남고 자동 선택되지 않습니다. Depth와 block-tag 정책은 receipt와 canonical inclusion block을 다시 조회해 block hash가 바뀐 reorg를 fail-closed로 거부합니다. 더 높은 수준의 ClairveilJS wrapper가 없는 read-only EVM JSON-RPC method에는 browser client의 `evmJsonRpc<TResult>(method, params)`를 사용할 수 있습니다. 이 API는 설정된 `evmRpc` endpoint와 client query timeout을 사용하며 injected wallet provider를 사용하지 않고 read-only allowlist 밖의 method와 비어 있는 `evmRpc` endpoint를 거부합니다. account 접근, 서명, subscription, transaction 제출에는 사용하면 안 됩니다.

```ts
const receipt = await clairveil.evmJsonRpc<{ blockNumber: string } | null>(
  "eth_getTransactionReceipt",
  [txHash]
);
```

로컬 single-node 데모에서는 faucet, local signer, auditor admin, CORS/proxy convenience를 위해 helper server를 둘 수 있습니다. 그래도 DApp의 핵심 privacy logic은 `clairveiljs/browser-dapp` API를 호출하는 형태를 유지하는 것이 좋습니다.

## EVM Privacy Precompile

EVM Clairveil chain은 state-changing privacy action을 Cosmos SDK tx broadcast가 아니라 EVM privacy precompile로 제출합니다.

ClairveilJS는 브라우저에서 privacy payload를 준비한 뒤, prepared message를
`IPrivacy.deposit`, direct/authorized `transfer`·`withdraw`, multi-proof batch,
single-proof batch calldata로 변환합니다.

지원 범위:

- 대상 EVM chain은 기본 ClairveilJS `IPrivacy` adapter ABI를 구현하거나 동등한 Clairveil v0.3.1 effect와 검증을 제공하는 custom adapter를 사용해야 합니다.
- 기본 adapter는 payable `deposit((bytes,bytes,bytes))`, `transfer((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes,bytes,bytes,uint64))`, `withdraw((bytes,bytes,bytes,string,address,string,uint64))`와 authorization/batch method를 손실 없이 encode합니다.
- privacy precompile address는 대상 chain config가 반드시 제공해야 합니다. ClairveilJS는 특정 chain 주소를 기본값으로 두지 않습니다.
- ABI shape가 다른 EVM chain은 `createEvmContractAdapter(...)`를 제공해야 하며, custom adapter가 contract encoding과 receipt proof를 소유합니다.

지원되는 EVM `IPrivacy.deposit` tuple에는 Cosmos `MsgDeposit`과 같은 필수
`DepositCircuit` proof가 포함됩니다. 다만 tuple은
`{ noteCommitment, encryptedNote, proof }`만 가지며 deposit amount는
transaction `msg.value`로만 bind됩니다. 기본 deposit mode도
`payable-exact-value`입니다.

```js
const evmClairveil = createClairveilEvmClient({
  provider: window.ethereum,
  contractAddress: targetChainPrivacyContractAddress,
  chainId: "evm-privacy-local-1",
  accountPrefix: "clair",
  shieldedPrefix: "clairs",
  defaultDenom: "uclair",
  depositMode: "payable-exact-value",
  nativeDenom: "uclair"
});

const deposit = evmClairveil.buildDepositTransaction({
  rootSeed,
  amount: "10uclair",
  proof: await proveDepositCircuit({ rootSeed, amount: "10uclair" })
});

// transaction.value는 0xa로 자동 계산됩니다.
await evmClairveil.sendTransaction(wallet, deposit.transaction);
```

이 mode에서는 deposit denom이 `nativeDenom`과 정확히 같아야 하고 최소
단위 amount가 EVM transaction value에 그대로 bind됩니다. Zero-value
deposit은 계속 허용됩니다. Caller-selected funder는 SDK surface에
추가하지 않으며 actor derivation과 fixed escrow 선택은 downstream
precompile 책임입니다. Prepared deposit, transfer, withdraw request는
target, calldata, value를 submit 시점까지 bind하며 transfer와 withdraw의
non-zero value는 거부합니다.

지원되는 EVM `IPrivacy.transfer` tuple에는 encrypted output note, `newCommitments`/`cipherTexts` 순서에 맞춘 2-byte `viewTags`, user/audit disclosure, sender `selfViewDisclosureDigest`/`selfViewDisclosurePayload`, absolute `expiresAtUnix`가 들어갑니다. self-view disclosure는 기본 포함되고 명시적 opt-out에서만 빠집니다. `IPrivacy.withdraw` tuple에는 legacy output-note field가 없으므로 dummy `newNoteCommitment`나 `encryptedNote` bytes를 보내면 안 됩니다.

EVM transfer/withdraw도 note scan, planner, disclosure, prover adapter 흐름은 Cosmos와 같습니다. 마지막 submit 단계만 Cosmos sign doc이 아니라 설정된 adapter의 precompile calldata 전송으로 달라집니다. 기본 adapter나 custom adapter 모두 proof, self-view, expiry, exact withdraw tuple을 손실 없이 전달하고 동등한 receipt evidence를 검증해야 합니다.

Privacy 조회는 기본적으로 Clairveil REST를 사용합니다. Clairveil REST가 없는 EVM 체인은 contract getter나 indexer로 구현한 완전한 `PrivacyStateAdapter`를 제공할 수 있습니다. `ClairveilJS`, browser wallet facade, public facade는 typed scan, tree/path, circuit, asset, reserve, disclosure, nullifier 조회를 이 adapter로 보내면서 기존 SDK validator와 planner를 그대로 적용합니다. Adapter read에는 REST와 같은 `queryTimeoutMs`와 동일 adapter 내부의 bounded `queryRetry`가 적용되며 다른 provider로 자동 전환하지 않습니다. Raw event API는 진단용이며 wallet state는 계속 typed `privacy_scan`만 사용하고 실패 시 fail-closed합니다.

직렬화되는 `BrowserWalletProfile`과 `ClairveilWebClientConfig` 문서는 완전한 배포 계약이므로 `rpc`와 `rest`를 계속 요구합니다. Cosmos endpoint를 생략할 수 있는 것은 `ClairveilBrowserClient`에 직접 전달하는 런타임 EVM profile뿐이며, 같은 constructor 호출에 완전한 `PrivacyStateAdapter`도 함께 제공해야 합니다.

### EVM Authorization Profile

`authorizationKind`는 ABI의 `uint8`일 뿐 SDK가 전역 의미를 부여하지
않습니다. 지갑에 authorization 서명을 요청하는 chain은 지원 kind와 EIP-712
domain을 profile로 명시해야 합니다.

```js
import {
  createClairveilEvmClient,
  createEvmAuthorizationProfile
} from "clairveiljs/evm";

const authorizationProfile = createEvmAuthorizationProfile({
  supportedAuthorizationKinds: [1, 2, 3],
  typedDataDomain: { name: "Target EVM Privacy", version: "1" }
});

const evmClairveil = createClairveilEvmClient({
  contractAddress: targetChainPrivacyContractAddress,
  chainId: "target-chain-1",
  evmChainId: "0x539",
  authorizationProfile
});
```

`supportedAuthorizationKinds`를 생략하면 모든 `uint8` 값을 허용합니다.
Profile의 public `buildTypedData(...)`도 transaction 생성과 같은 kind 및 custom
validation 정책을 적용합니다. 다른 EIP-712 형식은 custom `EvmAuthorizationProfile`의
`buildTypedData(...)` callback으로 제공합니다. 이미 서명된 authorization은
typed-data builder 없이도 제출할 수 있습니다.

Browser client에서는 같은 JSON-safe 형식을
`profile.evmAuthorizationProfile`에 넣습니다.

```js
evmAuthorizationProfile: {
  typedDataDomain: { name: "Target EVM Privacy", version: "1" },
  supportedAuthorizationKinds: [1, 2, 3]
}
```

## Prover

JS SDK는 ZK proof generation 자체를 내장하지 않습니다. Browser, local, remote prover 중 하나를 prover adapter로 연결하세요.

```js
import { createHttpProverAdapter } from "clairveiljs";

const proverAdapter = createHttpProverAdapter({
  baseURL: "https://prover.example",
  bearerToken: process.env.CLAIRVEIL_PROVER_TOKEN
});
```

기본 HTTP prover adapter는 다음 route contract를 사용합니다.

- `POST /v1/prover/transfer`
- `POST /v1/prover/withdraw`
- `POST /v1/proofs/batch-transfer`

`baseURL`에 deployment path prefix를 포함할 수 있습니다. Adapter는 각 route를 붙일 때 그 prefix를 보존합니다. 예를 들어 `https://prover.example/tenant-a`는 `https://prover.example/tenant-a/v1/prover/transfer`를 호출합니다.

Remote prover가 job ID를 반환하는 구조라면 `createAsyncJobProverAdapter`로 submit/poll 함수를 감싸세요. one-proof batch 전용 prover는 `submitBatchTransferJob`과 `getJob`만 제공해도 됩니다.

## Disclosure

Disclosure decode report는 handoff-friendly top-level shape를 유지합니다.

```text
plane
policy
output_index
commitment_hex
digest_hex
verified
amount
asset_denom
from
to
```

User disclosure decode는 JS SDK에서 처리합니다. Audit disclosure decode도 JS SDK에서 처리할 수 있지만, disclosure private scalar는 trusted admin/backend/local auditor runtime에서 주입해야 합니다.

아래 expiry-bound transfer와 relay 예제는 최신 체인 블록에서 authoritative time을 조회합니다. REST endpoint는 client 설정과 동일하게 유지하고, 최신 블록에 유효한 timestamp가 없으면 fail-closed하세요.

```js
const chainRestEndpoint = "https://rest.example-chain.invalid";

async function fetchLatestChainBlockTimeUnix() {
  const response = await fetch(
    `${chainRestEndpoint}/cosmos/base/tendermint/v1beta1/blocks/latest`
  );
  if (!response.ok) {
    throw new Error(`latest block time query failed with HTTP ${response.status}`);
  }
  const data = await response.json();
  const value = data?.block?.header?.time ?? data?.sdk_block?.header?.time;
  const milliseconds = Date.parse(String(value || ""));
  if (!Number.isFinite(milliseconds)) {
    throw new Error("latest block response omitted a valid block time");
  }
  return Math.floor(milliseconds / 1000);
}
```

## Withdraw와 Relay Withdraw

Withdraw는 exact-match note 하나가 필요합니다. planner가 `exact_note_required`를 반환하면 먼저 shielded self-transfer로 정확한 금액의 note를 만들어야 합니다.

Direct withdraw는 wallet/DApp이 `MsgWithdraw` sign doc까지 준비합니다.

```js
const withdraw = await clairveil.prepareWithdraw({
  wallet,
  amount: "5uclair",
  recipient: "clair1...",
  proverAdapter
});

if (withdraw.status === "ready") {
  const broadcast = await clairveil.signDirectAndBroadcast({
    wallet,
    signDoc: withdraw.signDoc,
    relayPayload: withdraw.payload,
    getChainNowUnix: fetchLatestChainBlockTimeUnix
  });
  if (!broadcast.ok) throw new Error(broadcast.error || "withdraw 확인에 실패했습니다");
}
```

Relay withdraw는 two-party handoff로 지원합니다. wallet/DApp은 Cosmos와 EVM profile 모두에서 같은 `prepareRelayWithdraw(...)` API로 final withdraw payload를 만들고, product-defined relayer endpoint로 전달합니다. Cosmos profile은 relayer-side `MsgWithdraw` signing에 사용할 payload를 반환합니다. EVM profile은 같은 payload와 `IPrivacy.withdraw` transaction request를 함께 반환합니다. 단, relayer는 client가 보낸 `transaction`을 그대로 신뢰하지 말고 payload에서 transaction을 다시 만들거나 byte-for-byte로 검증해야 합니다. 검증 대상은 `to`, `data`, `chainId`, recipient, expiry, payload hash입니다. 아래 상대 URL은 same-origin local relayer 경계이며, 서로 다른 외부 relayer에는 Note reservation의 handoff 흐름을 사용해야 합니다. 두 예제는 `reservationManager`를 먼저 생성했다고 가정합니다.

```js
const latestChainBlockTimeUnix = await fetchLatestChainBlockTimeUnix();
const prepared = await clairveil.prepareRelayWithdraw({
  wallet,
  amount: "5uclair",
  recipient: "clair1...",
  proverAdapter,
  reservationManager,
  chainNowUnix: latestChainBlockTimeUnix
});
if (prepared.status !== "ready") {
  throw new Error(`relay withdraw 준비 실패: ${prepared.plan?.status || prepared.status}`);
}

await reservationManager.markBroadcastAttempting(prepared.reservation.reservation_ids, {
  leaseToken: prepared.reservation.lease_token,
  reason: "same_origin_local_relayer_submit",
  metadata: { local_relayer: true }
});

const relayResponse = await fetch("/relayer/withdraw", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ payload: prepared.payload })
});
const { txHash } = await relayResponse.json();
await reservationManager.markSubmitted(prepared.reservation.reservation_ids, {
  leaseToken: prepared.reservation.lease_token,
  txHash
});
```

EVM profile에서는 `prepared.transaction`을 user wallet에서 바로 보내지 말고 relayer에 candidate transaction으로 전달하세요. relayer는 payload에서 다시 만든 transaction과 일치할 때만 자기 EVM account로 broadcast해야 합니다.

```js
const latestChainBlockTimeUnix = await fetchLatestChainBlockTimeUnix();
const prepared = await clairveil.prepareRelayWithdraw({
  walletType: "evm",
  evmWallet: { getChainId: () => ethereum.request({ method: "eth_chainId" }) },
  address,
  pubKeyHex,
  signatureBase64,
  amount: "5utest",
  recipient: "0x...",
  chainNowUnix: latestChainBlockTimeUnix,
  reservationManager
});
// Browser EVM client는 ready 결과를 만들 수 없으면 예외를 던집니다.

await reservationManager.markBroadcastAttempting(prepared.reservation.reservation_ids, {
  leaseToken: prepared.reservation.lease_token,
  txBytesHash: prepared.txBytesHash,
  reason: "same_origin_local_relayer_submit",
  metadata: { local_relayer: true }
});

const relayResponse = await fetch("/relayer/evm-withdraw", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    payload: prepared.payload,
    transaction: prepared.transaction
  })
});
const { txHash } = await relayResponse.json();
await reservationManager.markSubmitted(prepared.reservation.reservation_ids, {
  leaseToken: prepared.reservation.lease_token,
  txHash
});
```

```js
const latestChainBlockTimeUnix = await fetchLatestChainBlockTimeUnix();
const relay = await relayerClient.createRelayWithdrawSignDoc({
  payload,
  relayer: relayerAddress,
  pubKeyHex: relayerPubKeyHex,
  chainNowUnix: latestChainBlockTimeUnix,
  expectedChainId: "clairveil-1",
  expectedRecipient: payload.recipient
});

await relayerClient.signDirectAndBroadcast({
  wallet: relayerWallet,
  signDoc: relay.signDoc,
  relayPayload: relay.payload,
  // 서명 지연 뒤 최신 체인 블록 시간을 다시 조회합니다.
  getChainNowUnix: fetchLatestChainBlockTimeUnix
});
```

### Note reservation

동시에 여러 private transaction을 준비할 수 있는 wallet/DApp은 `prepareTransfer(...)`, `prepareWithdraw(...)`, `prepareRelayWithdraw(...)`에 reservation manager를 넘기세요. `prepareTransferBatch(...)`에는 항상 필수입니다. Manager는 이미 예약된 note를 planner 입력에서 제외하고, proof 생성 중 선택된 note를 예약하며, SDK proof/payload 생성 중 lease를 갱신하고, prepared result에 reservation metadata를 돌려줍니다. Prepared result가 wallet UI 또는 relayer flow로 넘어간 뒤에는 caller가 `heartbeatLease(...)`/`renewLease(...)`로 lease를 유지할 수 있습니다.

```js
import {
  createBrowserReservationStore,
  createNoteReservationManager,
  reservationStatuses
} from "clairveiljs/reservation";

const reservationStateText = new TextEncoder();
const reservationStateKeyMaterial = await crypto.subtle.importKey(
  "raw", material.rootSeed, "HKDF", false, ["deriveKey"]
);
const reservationStateKey = await crypto.subtle.deriveKey({
  name: "HKDF",
  hash: "SHA-256",
  salt: reservationStateText.encode(`${chainId}:${address}`),
  info: reservationStateText.encode("clairveil/reservation-state/v1")
}, reservationStateKeyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
const encryptReservationState = async state => {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, reservationStateKey,
    reservationStateText.encode(JSON.stringify(state))
  );
  return { version: 1, iv: [...iv], ciphertext: [...new Uint8Array(ciphertext)] };
};
const decryptReservationState = async value => {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(value.iv) }, reservationStateKey,
    new Uint8Array(value.ciphertext)
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
};

const reservationStore = createBrowserReservationStore({
  namespace: `${chainId}:${address}`,
  requireLocks: true,
  encodeState: encryptReservationState,
  decodeState: decryptReservationState
});

const reservationManager = createNoteReservationManager({
  store: reservationStore,
  ownerKeyId: `${chainId}:${address}`,
  indexKey: material.rootSeed,
  // 선택 사항입니다. 생략하면 SDK가 manager마다 새 worker id를 만듭니다.
  leaseOwner: `browser-tab:${crypto.randomUUID()}`
});

const latestChainBlockTimeUnix = await fetchLatestChainBlockTimeUnix();
const prepared = await clairveil.prepareRelayWithdraw({
  wallet,
  amount: "5uclair",
  recipient: "clair1...",
  proverAdapter,
  reservationManager,
  chainNowUnix: latestChainBlockTimeUnix
});

if (prepared.reservation?.reservation_ids?.length) {
  console.log(prepared.reservation.reservations[0].status === reservationStatuses.ProofReady);
}

```

Namespace는 chain과 wallet identity 기준으로 안정적으로 잡으세요. `indexKey`는 필수이며 privacy root seed처럼 wallet-private material에서 가져와야 합니다. Public account id를 reservation lookup key 기본값으로 쓰지 마세요. `unsafeAllowPublicIndexKey: true`는 약한 privacy boundary를 의도적으로 받아들이는 단일 사용자 데모용 opt-in입니다. Reservation manager는 명시적인 `store`를 항상 요구하며 암묵적으로 memory store를 만들지 않습니다. `createBrowserReservationStore(...)`는 IndexedDB를 사용하고 기본적으로 Web Locks API를 요구해서 두 탭이 같은 note를 동시에 예약하지 못하게 합니다. IndexedDB가 없으면 fail-closed하며, `unsafeAllowMemoryFallback: true`는 데모/테스트 전용 명시 opt-in입니다. Production에서는 전체 reservation state를 at-rest 암호화하는 `encodeState`/`decodeState` callback 쌍을 반드시 제공해야 합니다. `unsafeAllowPlaintext: true`는 amount, tx evidence, timestamp 같은 operational metadata를 평문으로 남기는 데모/테스트 전용 명시 opt-in입니다. 단일 흐름 테스트에서는 `new MemoryReservationStore()`를 명시적으로 넘길 수 있지만 다른 탭이나 프로세스를 보호하지 않고 재시작 후 상태도 보존하지 않습니다.

위 예제는 wallet-private root seed에서 namespace가 분리된 non-extractable AES-GCM key를 파생합니다. 애플리케이션의 secure key-management layer에서 동등한 stable key를 불러와도 되지만, key를 ciphertext와 함께 저장하면 안 됩니다.

Reservation lookup key를 직접 만들 때 32-byte nullifier hex string에는 `nullifierLookupKeyFromHex(indexKey, nullifierHex)`를 사용하세요. `nullifierLookupKey(indexKey, nullifier)`는 string nullifier를 raw UTF-8 label로 취급하며, 실수 방지를 위해 hex 형태의 nullifier string은 거부합니다.

SDK는 reservation을 `Reserved -> Proving -> ProofReady`로 준비합니다. `Proving`과
`ProofReady`는 worker lease를 유지하므로 caller가 지정한 `leaseOwner`는
tab/worker마다 고유해야 합니다. Store는 검증된 생성, CAS, lease,
reconcile API만 노출합니다. Exact 전이·evidence 표는
[상태 전이](./docs/reservation-state-machine.ko.md)를 참고하세요.

- 고수준 제출에는 `reservationManager`와 prepared `reservation`을 함께
  넘기세요. Signed Cosmos transfer에는 `getChainNowUnix`, relay/withdraw에는
  일치하는 payload와 최신 chain time, EVM에는 expected network와 같은
  encoding option이 필요합니다. SDK는 relay transaction을 decode/rebuild하고
  binding되지 않은 sender/gas/fee를 제거한 뒤 payload mismatch를 RPC 전에
  거부합니다.
- Cosmos signing은 exact TxRaw `txHash`를 RPC 전에 영속화하고 broadcast
  또는 indexed hash 불일치를 거부합니다. Caller-owned restart fence는 RPC
  직전의 synchronous `beforeBroadcast(identity)`를 사용할 수 있습니다.
- Custom integration은 외부 경계에서 `markBroadcastAttempting(...)`, 실제
  제출 후에만 `markSubmitted(...)`, 불명확한 결과에 `markUnknown(...)`을
  사용합니다. `signDocHash`만으로는 제출을 증명할 수 없습니다.
- Payroll retry는 `retransmitOneProofPayrollArtifact(...)`로 RPC 경계를 넘으세요.
  Idempotent marker 결과는 retry 권한이 아니며 `ProofReady`에는 artifact의
  현재 lease가 필요합니다.
- Relay payload를 노출하기 전 `recordRelayHandoff(...)`를 영속화하세요.
  Handoff 후에는 TTL이나 cancel로 release하지 말고 chain evidence를 reconcile합니다.

```js
await reservationManager.recordRelayHandoff(
  prepared.reservation.reservation_ids,
  {
    leaseToken: prepared.reservation.lease_token,
    payloadHash: prepared.payload.payload_hash
  }
);

const relayResponse = await sendToExternalRelayer(prepared.payload);
const inclusion = await findIncludedRelayTransaction(relayResponse.txHash);
await reservationManager.recordRelayTransactionEvidence({
  operationId: prepared.reservation.reservations[0].operation_id,
  payloadHash: prepared.payload.payload_hash,
  txHash: inclusion.txHash,
  checkedHeight: inclusion.height,
  transactionIncludedConfirmed: true,
  payloadHashMatched: true
});
```

- `Reserved`만 자동 release할 수 있습니다. `Proving`/`ProofReady` 실패는
  `ManualReview`로 격리하고, 만료된 `ProofReady`는 단순 tx 부재가 아니라
  exact transaction 실패와 모든 input unspent를 증명하는 전용 복구만
  허용합니다.
- `ManualReview`는 operator evidence로만 해결하세요. 실패한 EVM receipt 등
  broadcast 후 실패는 transaction과 nullifier evidence를 모두 요구합니다.
  절차는 [복구 가이드](./docs/errors-and-recovery.ko.md)를 참고하세요.

Reservation은 operation success evidence도 저장할 수 있습니다. Nullifier spent는 입력 note가 소비됐다는 뜻이지만 payroll/payment 성공에는 저장된 tx identity와 output evidence까지 일치해야 합니다. 고수준 `prepareTransfer(...)`는 이제 Cosmos와 EVM 모두 실제 recipient와 canonical coin에서 `expectedRecipientHash`, `expectedAmountHash`를 자동 생성합니다. 호출자가 넘기는 hash는 선택적 assertion이며 실제 값과 다르면 prepare 단계에서 실패합니다. `markProofReady(...)`는 direct item용 `expectedOutputCommitment`, `expectedDisclosureDigest`, `expectedRecipientHash`, `expectedAmount`, `expectedAmountHash`, `expectedDenom`, `batchItemIndex`, `batchItemIndexKnown` 등을 받습니다. One-proof 고수준 batch 경로는 대신 모든 input reservation에 하나의 `expectedOperationEvidenceHash`를 저장하고 전체 `operationEvidence.expected_outputs` 목록을 별도로 반환합니다. 각 entry는 item ID, output index, commitment, recipient hash, amount/asset, user/audit/self-view disclosure digest를 결합합니다. Item 성공을 보고하기 전에 aggregate hash와 모든 per-item entry를 검증해야 합니다. Custom low-level integration은 `clairveiljs/reservation`의 `hashRecipient(recipient, { shieldedPrefix })`, `hashAmount(denom, amount)` helper를 사용할 수 있습니다. 두 helper는 빈 identity field를 거절하며, amount helper는 non-negative uint64 최소 단위 amount만 canonical `denom:amount` 해시로 만듭니다.

Scan migration에서는 최신 nullifier 확인이 명시적으로 `nullifierStatus: "unspent"`인 note만 spendable로 취급하세요. 이전 cache의 `isSpent: false`, 누락·malformed 응답, query 실패는 unverified이므로 다시 검증하기 전에는 planner에서 제외해야 합니다.

## 통합 Privacy Scan과 Merkle Snapshot

고수준 wallet/spend scan은 Clairveil typed `privacy_scan` (`privacy-scan-v2`)만 사용합니다. SDK는 `(height, globalSequence, outputIndex)` 전체 cursor를 저장·재개하고, zero-output withdraw summary까지 포함한 unfiltered scan을 요청합니다. Typed endpoint가 없거나 page가 malformed이면 fail-closed로 중단합니다. 저수준 `scanNotes({ scanSource: "scan_events" })`와 `fetchScanEvents(...)`는 진단/호환 API로 남지만 그 결과를 wallet balance cursor로 저장하지 않습니다.

One-Proof transfer/withdraw에 여러 input을 사용할 때는 개별 `merkle_path` 응답을 섞지 말고, 하나의 검증된 root/height snapshot에서 path를 받아야 합니다.

```js
const pathProvider = await clairveil.createCommitmentPathSnapshotProvider({
  commitmentHexes: selectedNotes.map(note => note.commitment_hex),
  rootHex: verifiedTreeSnapshot.rootHex,
  snapshotHeight: verifiedTreeSnapshot.height
});

const firstPath = await pathProvider.lookupMerklePath(selectedNotes[0].commitment_hex);
```

SDK는 1–16개의 서로 다른 commitment, 요청한 root/height 일치, 각 depth-32 path의 root 재구성을 모두 검증한 뒤 provider를 반환합니다. 원격 path query는 query provider에게 input note 간 linkage를 노출할 수 있으므로, privacy policy에 맞는 endpoint와 네트워크 경로를 사용하세요.

나중에 `reconcileSpentNotes(...)`를 호출할 때 tx/event evidence를 `operationSuccessEvidence` 또는 `successEvidence`에 넣으면 SDK가 expected evidence와 비교합니다. EVM tag가 있는 reservation은 저장된 network `txHash`와 prepared `txBytesHash`가 모두 일치하고, 명시적 successful receipt, `evmTransactionVerified: true`, `evmPrivacyReceiptVerified: true`, `evmFinalityVerified: true`, expected operation/output evidence가 전부 맞아야 `operation_status: "Succeeded"`가 됩니다. `waitForEvmTransaction(...)`의 구조화된 결과에는 이 EVM 필드가 들어 있으므로 `txResult`로 전달할 수 있습니다. Request binding hash나 receipt status만으로는 성공할 수 없습니다. Transport tag가 없는 external reservation은 generic identity matcher를 사용합니다. `signDocHash`는 보조 mismatch guard일 뿐 단독으로 chain 실행을 증명하지 못하며, `txResult: { code: 0 }`만 있는 경우도 identity가 없어 성공이 될 수 없습니다. Nullifier spent만으로는 충분하지 않습니다. 여러 input을 쓰는 operation은 같은 reconcile 호출에 연결된 모든 input의 spent evidence를 넣어야 합니다. 불완전한 evidence는 연결된 operation 전체를 `ManualReview`로 기록하고, tx identity나 expected output이 명시적으로 상충하면 `ConflictSpent`와 `operation_success_evidence_errors`를 기록합니다. 두 경우 모두 spent input은 `ConfirmedSpent`로 격리되며, 나중에 완전한 evidence가 들어오면 연결된 모든 reservation의 operation outcome을 원자적으로 통일합니다. Reservation을 note inventory lock으로만 쓰는 custom low-level caller만 `operationSuccessEvidenceRequired`를 켜지 않고 downstream operation DB에서 별도로 성공 판정을 할 수 있습니다.

Operation 단위 재시도 진단은 구조화되어 있습니다. `OPERATION_STATE_MIXED`는 `error.details.reservations`에 `{ reservation_id, status, operation_status? }`를 제공합니다. `OPERATION_EVIDENCE_CONFLICT`는 `error.details.conflicts`에 `reservation_id`, `tx_hash`·`commitment`·`digest`·`amount` 같은 표준 `field`, 정확한 `source_field`, `reason`, 가능한 경우 `expected`/`actual` 값을 제공합니다. 최초 reconcile에서 발견한 충돌은 반환 전에 먼저 안전하게 저장되며 같은 정보가 `metadata.operation_success_evidence_conflicts`에 남습니다. Reference Payroll에서 manual review가 필요한 경우에는 `reconciliation.error_code`와 `reconciliation.error_details`로도 반환됩니다.

## Handoff Conformance

ClairveilJS는 Clairveil core commit
`0ff92839872de26b787a60d8e4d5822cc459855b`의 exact contract snapshot을 포함하며
note reservation 계약은 v3만 허용합니다. 이것은 ClairveilJS `0.3.1` package용
commit snapshot이고 immutable Clairveil core `v0.3.1` release tag와 같다는
표시가 아닙니다. npm package에도 fixture와 wallet-contract JSON Schema가 포함되므로
runtime conformance helper 사용자는 Clairveil source checkout을 별도로 준비할 필요가
없습니다. 단, release identity gate는 고정 commit object가 들어 있는 checkout을
요구합니다. 기본 fixture 경로는 다음과 같습니다.

```bash
fixtures/clairveil-v0.3.1/x/privacy/client/sdk/conformance/testdata
```

로컬 개발에서는 다음을 실행하세요.

```bash
npm run test:conformance
```

Maintainer가 다른 fixture를 의도적으로 비교할 때만
`CLAIRVEIL_CONFORMANCE_FIXTURE_DIR=/path/to/testdata`로 경로를 덮어씁니다.

Release handoff 또는 CI에서는 bundled fixture만 사용하는 strict command를
사용하세요. fixture가 없으면 실패합니다.

```bash
npm run test:conformance:required
```

`npm run verify:clairveil-source`라는 release script 이름은 호환성을 위해
유지합니다. 고정 metadata와 local SHA-256 manifest를 확인한 뒤 protobuf 4개,
fixture 12개, JSON Schema 1개를 주장한 git commit과 byte-for-byte로 대조합니다.
`CLAIRVEIL_SOURCE_DIR`로 해당 commit을 가진 Clairveil checkout을 지정할 수 있고,
없으면 sibling `../clairveil`을 사용합니다. checkout 또는 commit object가 없으면
fail-closed합니다.

Canonical EVM `IPrivacy` interface는 특정 downstream EVM 구현과 독립적인
SDK 소유 계약입니다. `npm run verify:evm-contract`는 bundled contract version과
ABI digest를 확인하고 모든 function selector와 event signature를 다시 계산하며,
mutability와 SDK adapter의 exact contract 일치를 검사합니다. 이 gate에는
downstream source checkout이 필요하지 않으며 구현 동작은 별도의 EVM integration
test에서 검증합니다.

Reservation conformance test는 fixture의 allowed/rejected 전이를
`canTransitionReservation(...)` 일반 전이 표에 대해 재생합니다. Store release helper도
같은 `Proving → Released` 거부 규칙을 강제합니다.

`prepublishOnly`는 `verify:release:integration`을 실행합니다. Package 검사,
required conformance fixture, 필수 Cosmos localnet·testnet full-flow와 pinned
5-shape one-proof matrix, downstream EVM full-flow evidence gate를 모두 실행하며
owner/relayer wallet, local/testnet node, deposit-proof, prover, EVM driver 설정이
없으면 skip하지 않고 실패합니다.

검증 범위:

- root seed/key/address derivation
- browser signer adapter behavior
- note scan result
- prepared transfer/withdraw payload hash
- prover HTTP contract behavior
- disclosure decode
- relay withdraw message handoff behavior

## Cosmos Node E2E와 Release Gate

Local node E2E는 일반 개발에서는 opt-in이지만 `npm publish`에는 필수입니다. Release 환경은 Clairveil node, 명시적으로 선택한 prover 한 곳, owner와 별도 relayer wallet credential, audit disclosure private scalar, deposit-proof provider를 제공해야 합니다.

현재 local e2e scope:

- deposit
- typed wallet note scan
- shielded transfer
- validated typed scan output 기반 public/self-view/recipient/audit disclosure decode
- direct withdraw
- 별도 relayer가 서명한 relayed withdraw와 reservation/nullifier reconciliation

Relayed withdraw E2E는 owner와 다른 transparent account가 최종 `MsgWithdraw`를 서명·broadcast하고, 포함 tx evidence와 spent nullifier를 reservation의 `ConfirmedSpent` 상태까지 reconcile합니다. Product별 relayer transport 자체는 SDK 범위 밖입니다. One-proof payroll batch는 별도 opt-in E2E로 deposit, typed scan, same-root Merkle path, batch prover, `MsgBatchTransfer`, typed output evidence reconciliation까지 검증합니다.

```bash
CLAIRVEIL_E2E_LOCAL=1 npm run test:e2e:local
```

기본 명령은 circuit identity, 양방향 asset registry, tree state, typed
`privacy_scan`, nullifier batch status, audit/disclosure config, reserve
invariant를 포함하는 Clairveil v0.3.1 query preflight를 수행합니다.

Full flow까지 실행하려면 wallet module과 deposit proof module을 함께 넘기세요. Deposit proof module은 `default`, `createDepositProof`, 또는 `depositProofProvider`를 export하고 `{ proof }`, `{ depositProof }`, `{ proofHex }`, `{ proof_hex }` 같은 proof bytes 또는 proof hex를 반환해야 합니다.

```bash
CLAIRVEIL_E2E_LOCAL=1 \
CLAIRVEIL_E2E_FULL_FLOW=1 \
CLAIRVEIL_E2E_WALLET_MODULE=/absolute/path/to/wallet-adapter.mjs \
CLAIRVEIL_E2E_RELAYER_WALLET_MODULE=/absolute/path/to/relayer-wallet-adapter.mjs \
CLAIRVEIL_E2E_AUDIT_DISCLOSURE_PRIVKEY_HEX=<audit-private-scalar> \
CLAIRVEIL_E2E_DEPOSIT_PROOF_MODULE=/absolute/path/to/deposit-proof-provider.mjs \
CLAIRVEIL_E2E_AUDIT_DISCLOSURE_PRIVKEY_HEX=<auditor-private-scalar-hex> \
npm run test:e2e:local
```

One-proof batch까지 실행하려면 다음을 추가합니다.

```bash
CLAIRVEIL_E2E_LOCAL=1 \
CLAIRVEIL_E2E_FULL_FLOW=1 \
CLAIRVEIL_E2E_ONE_PROOF_BATCH=1 \
CLAIRVEIL_E2E_WALLET_MODULE=/absolute/path/to/wallet-adapter.mjs \
CLAIRVEIL_E2E_RELAYER_WALLET_MODULE=/absolute/path/to/relayer-wallet-adapter.mjs \
CLAIRVEIL_E2E_AUDIT_DISCLOSURE_PRIVKEY_HEX=<audit-private-scalar> \
CLAIRVEIL_E2E_DEPOSIT_PROOF_MODULE=/absolute/path/to/deposit-proof-provider.mjs \
CLAIRVEIL_E2E_AUDIT_DISCLOSURE_PRIVKEY_HEX=<auditor-private-scalar-hex> \
npm run test:e2e:local
```

`CLAIRVEIL_E2E_REQUIRED=1`에서는 `CLAIRVEIL_E2E_AUDIT_DISCLOSURE_PRIVKEY_HEX`가 필수이며 chain audit public key와 일치해야 합니다. Batch input/payment amount, output role, disclosure mode, self-view 설정은 번들된 Clairveil `0ff9283`의 `privacy_batch_transfer_v1_contract.json`에서 직접 읽으며 override할 수 없습니다. Recipient는 typed output evidence를 독립적으로 decrypt·검증할 수 있도록 의도적으로 E2E wallet으로 고정합니다. Batch matrix는 validated typed output에서 public·recipient-encrypted user disclosure, 필수 audit disclosure, 활성화된 sender self-view disclosure를 실제 decode·verify합니다. 기본값에서는 현재 root를 조회하고 `commitment_paths_at_root`가 그 root의 authoritative snapshot height를 반환하게 합니다. 특정 snapshot을 고정하려면 검증된 `CLAIRVEIL_E2E_ONE_PROOF_ROOT_HEX`와 `CLAIRVEIL_E2E_ONE_PROOF_SNAPSHOT_HEIGHT`를 항상 함께 지정하세요.

필수 `test:e2e:local:one-proof-all` 릴리스 명령은 deployment, wallet,
prover, timeout 값을 `CLAIRVEIL_E2E_LOCAL_*` 변수에서 읽습니다. 예를 들어
`CLAIRVEIL_E2E_LOCAL_WALLET_MODULE`과
`CLAIRVEIL_E2E_LOCAL_DEPOSIT_PROOF_MODULE`을 사용합니다. 위의 prefix 없는
변수는 standalone `test:e2e:local` 개발 명령에서 계속 사용할 수 있습니다.

Mnemonic 기반 E2E wallet은 `CLAIRVEIL_E2E_COIN_TYPE` 또는 전체 `CLAIRVEIL_E2E_HD_PATH` 중 하나를 받을 수 있습니다. Clairveil v0.3.1 reference CLI keyring은 coin type `60`을 사용하며, 둘 다 생략하면 CosmJS 기본값 `118`을 사용합니다. Wallet module은 자체 derivation path를 책임집니다.

필수 Cosmos downstream testnet gate는 전체 flow와 pinned 5-shape를 모두
실행합니다. 아래 7개 deployment 값은 전부 필수이며 testnet mode는 local
chain ID와 loopback RPC, REST, prover URL을 거부합니다.

```bash
CLAIRVEIL_E2E_TESTNET_CHAIN_ID=<deployed-testnet-chain-id> \
CLAIRVEIL_E2E_TESTNET_RPC=https://rpc.testnet.example \
CLAIRVEIL_E2E_TESTNET_REST=https://rest.testnet.example \
CLAIRVEIL_E2E_TESTNET_PROVER_URL=https://prover.testnet.example \
CLAIRVEIL_E2E_TESTNET_ACCOUNT_PREFIX=<account-prefix> \
CLAIRVEIL_E2E_TESTNET_SHIELDED_PREFIX=<shielded-prefix> \
CLAIRVEIL_E2E_TESTNET_DENOM=<native-denom> \
CLAIRVEIL_E2E_TESTNET_WALLET_MODULE=/absolute/path/to/wallet-adapter.mjs \
CLAIRVEIL_E2E_TESTNET_RELAYER_WALLET_MODULE=/absolute/path/to/relayer-wallet-adapter.mjs \
CLAIRVEIL_E2E_TESTNET_DEPOSIT_PROOF_MODULE=/absolute/path/to/deposit-proof-provider.mjs \
CLAIRVEIL_E2E_TESTNET_AUDIT_DISCLOSURE_PRIVKEY_HEX=<auditor-private-scalar-hex> \
npm run test:e2e:cosmos:testnet
```

릴리스 환경에서 testnet·wallet·deposit proof credential까지 준비되었다면
`npm run verify:release:integration`을 실행하세요. 이 명령은 wallet-contract
JSON Schema, required Go fixture, Cosmos localnet·testnet full flow, 모든
pinned one-proof shape와 아래의 downstream EVM 동작을 검사하며 필요한 설정이
없으면 skip 대신 실패합니다. 릴리스 runner는 prefix 없는
`CLAIRVEIL_E2E_*` 값을 제거하고 `CLAIRVEIL_E2E_LOCAL_*`과
`CLAIRVEIL_E2E_TESTNET_*`을 서로 다른 child environment로 매핑하므로 한
deployment가 두 gate를 조용히 대신 통과할 수 없습니다.

`CLAIRVEIL_EVM_E2E_DRIVER`에는
`runClairveilEvmE2E(context)`를 export하는 ESM module의 절대
경로를 지정합니다. 배포, wallet, RPC, chain별 query는 driver가 담당하고
`clairveil-evm-e2e-v1` evidence를 반환합니다. 릴리스 검증기는 다음
동작을 독립적으로 확인합니다.

- 각 operation이 receipt status만 신뢰하지 않고 설정된 ClairveilJS EVM
  adapter의 calldata selector와 action별 privacy event를 사용해야 합니다.
- 양수 deposit은 runtime native denom과 privacy asset denom이 같음을 증명하고
  configured precompile에 `amount == msg.value`로 제출되며,
  event actor/funder가 authenticated actor와 fixed escrow이며, escrow/module
  balance와 accounting counter가 정확한 amount만큼 변하고 commitment가
  하나 추가되어야 합니다.
- downstream policy가 거부한 deposit은 추적한 모든 balance, counter, leaf와
  typed-scan cursor/summary/output 변경을 rollback해야 합니다.
- zero-value deposit은 금융 상태를 바꾸지 않고 성공하며 actor/funder를
  유지하고 commitment를 하나 추가해야 합니다.
- deposit note는 `privacy_scan`으로 다시 발견되어야 합니다.
- direct transfer는 prepared/observed transaction identity, 모든 input
  nullifier spent, commitment/recipient/amount evidence와 output note recovery를
  검증하고, prepared audit 및 sender self-view digest가 complete typed-scan
  output과 실제 disclosure decode 결과에 각각 일치해야 합니다. Owner가 준비하고 별도
  relayer가 calldata/proof를 바꾸지 않고 제출하여 canonical creator 교체
  규칙도 증명해야 합니다.
- one-proof batch는 proof와 transaction이 각각 하나여야 하며 모든 input과
  aggregate operation evidence 전체를 다시 hash하고 expected output을 독립
  기록한 최초 payment 요청과 정확히 대조하며, public 및 recipient-encrypted
  user disclosure와 payment/change/padding 모든 output의 mandatory audit,
  all-or-none sender self-view disclosure를 검증해야 합니다. Authorized 경로는
  설정된 EIP-712 signature, effective sender/executor attribution, profile이 허용한
  authorization kind, nonce 소비와 성공 transaction의 exact calldata를 그대로
  재사용해 실제 revert된 nonce replay transaction까지 확인해야 합니다.
- downstream chain에서 v0.3.1의 5개 boundary shape인 1 input/1 payment,
  3 input/4 output, 31 payment+change, 정확히 32 payment, explicit zero
  padding을 모두 실제 실행해야 합니다. Matrix는 pinned
  `privacy_batch_transfer_v1_contract.json` fixture에서 직접 읽으며 input/payment
  amount, output role/amount, disclosure mode, self-view 설정까지 정확히 같아야
  합니다. 각 shape는 proof 1개, transaction 1개, complete typed output, spent
  nullifier, atomic reservation 성공을 증명해야 합니다.
- 성공한 모든 EVM operation은 같은 transaction에 binding된 finality policy
  evidence를 포함해야 하며 release driver는 receipt status만이 아니라 canonical
  inclusion을 다시 검증해야 합니다.
- direct/relay withdraw는 모든 input spent, 정확한 balance/accounting delta,
  exact withdraw tuple을 검증하고 relay payload의 recipient, chain, amount,
  expiry가 바뀌지 않아야 합니다. Relay prepare는 `ProofReady`에서 EVM 후보
  hash를 binding하고, 별도 relayer가 제출 전에 같은 후보를 재구성해야 합니다.
- 실제 revert transaction으로 transfer와 direct withdraw의 block-time expiry,
  cross-chain replay, output/disclosure substitution, duplicate
  nullifier/commitment, relay expiry 연장과 relay recipient 교체가 snapshot된
  privacy state를 바꾸지 않고 거부되는지 증명해야 합니다.
- receipt 부재는 성공 처리할 수 없고 mixed reservation state 및 field별
  evidence 충돌은 `OPERATION_STATE_MIXED`, `OPERATION_EVIDENCE_CONFLICT`와
  상세 reservation/field를 노출해야 합니다.
- 각 deposit 결과 상태는 Clairveil reserve invariant를 만족해야 합니다.

Mandatory audit plane을 복호화하는 EVM integration driver에는 custody key를
별도 경로로 제공해야 합니다. Downstream full-flow driver는
`CLAIRVEIL_EVM_E2E_AUDIT_DISCLOSURE_PRIVKEY_HEX`를 사용하며, 이 secret을
browser profile, evidence JSON, log, repository file에 넣으면 안 됩니다.

일반 로컬 개발에서 driver가 없으면 `npm run test:e2e:evm`은
skip할 수 있습니다. `npm run test:e2e:evm:one-proof-all`은 downstream
5-shape 필수 gate이며 `verify:release:integration`이 이 명령을 호출하므로
publish 릴리스에서는 이 검증을 생략할 수 없습니다.

`npm run test:e2e:evm-payable`은 호환성 alias로만 남아 있으며 동일한
full-flow gate를 실행하므로 deposit-only evidence는 더 이상 통과하지 않습니다.

## 테스트

```bash
npm run check
npm run typecheck
npm test
npm run test:conformance
npm run test:conformance:required
npm pack --dry-run --json
```

## Release Checklist

1. `npm run check`
2. `npm run typecheck`
3. `npm test`
4. `npm run test:conformance:required`
5. `npm pack --dry-run --json`
6. downstream EVM full-flow driver를 설정
7. 실제 downstream Cosmos testnet 설정으로 `npm run verify:release:integration`
8. 최종 EVM ABI/prover contract를 pin한 뒤 EVM support stable 여부를 선언
