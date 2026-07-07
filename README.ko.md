# ClairveilJS

ClairveilJS는 Clairveil privacy 기능을 브라우저와 Node.js 환경에서 사용할 수 있게 해주는 JavaScript SDK입니다.

English documentation: [README.md](./README.md)

이 패키지는 Clairveil 전용 privacy primitive와 DApp 친화적인 API를 제공합니다.

- Telescope로 생성한 `MsgDeposit`, `MsgTransfer`, `MsgWithdraw`, privacy query protobuf binding
- Clairveil transaction type URL과 CosmJS `Registry` 생성
- privacy root signing message helper
- 브라우저 친화 crypto primitive (`@noble/hashes`, `@noble/ciphers`)
- root seed, spend/view/disclosure key derivation
- shielded address encode/decode
- note 생성, commitment/nullifier 계산, note encryption
- transfer disclosure MiMC digest 검증
- privacy event, auditable transfer, reserve accounting, balance query
- Keplr/custom signer용 wallet adapter
- memory/localStorage 기반 note store
- transfer/withdraw planner와 안정적인 `ClairveilError` 코드
- prepared transfer/withdraw/relay withdraw payload builder
- `/v1/prover/transfer`, `/v1/prover/withdraw` HTTP prover adapter
- Keplr `signDirect`용 sign doc 생성, signed tx 조립, broadcast
- EIP-1193 wallet용 Clairveil-compatible `IPrivacy` EVM precompile calldata adapter
- runtime shape assertion과 TypeScript declaration

## 설치

```bash
npm install github:DELIGHT-LABS/clairveiljs
```

[DELIGHT-LABS/clairveiljs](https://github.com/DELIGHT-LABS/clairveiljs)

Node.js는 `>=20`을 요구합니다. 브라우저 번들러에서는 일반 Web API인 `fetch`, `TextEncoder`, `TextDecoder`, `crypto.getRandomValues`가 제공되어야 합니다.

## Entrypoints

```js
import { deriveShieldedAddress } from "clairveiljs/core";
import { createClairveilClient } from "clairveiljs/cosmos";
import { createClairveilBrowserDappClient } from "clairveiljs/browser-dapp";
import { createClairveilEvmClient } from "clairveiljs/evm";
```

Public consumer는 내부 파일 경로를 직접 import하지 말고 package export map을 사용하세요.

- `clairveiljs`: 현재 Cosmos 중심 client surface와 backward-compatible root entrypoint
- `clairveiljs/core`: key derivation, address, crypto, note, disclosure primitive
- `clairveiljs/cosmos`, `clairveiljs/cosmos-client`: CosmJS 기반 transport/client
- `clairveiljs/evm`: Clairveil-compatible EVM privacy precompile client
- `clairveiljs/browser-dapp`: production DApp에서 쓰기 좋은 브라우저 wallet client
- `clairveiljs/browser-public`: public privacy event/read-only query client
- `clairveiljs/generated/...`: Telescope generated protobuf binding

`clairveiljs/generated/.../tx`와 `clairveiljs/generated/.../tx.js` import 형태를 모두 지원합니다.

## 예제 코드

최소 SDK 사용 예제는 [`examples/`](https://github.com/DELIGHT-LABS/clairveiljs/tree/main/examples)에 있습니다.

- Keplr/Cosmos: [`examples/minimal-keplr-flow.js`](https://github.com/DELIGHT-LABS/clairveiljs/blob/main/examples/minimal-keplr-flow.js)
- MetaMask/EVM: [`examples/minimal-metamask-flow.js`](https://github.com/DELIGHT-LABS/clairveiljs/blob/main/examples/minimal-metamask-flow.js)

두 예제는 wallet privacy material derivation, deposit 준비, note scan, transfer 준비, broadcast 흐름을 SDK surface로 수행합니다. Keplr/Cosmos 예제는 Cosmos `MsgDeposit`에 `DepositCircuit` proof가 포함되기 때문에 `depositProofProvider`가 필요합니다.

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
  proverUrl: "https://prover.example"
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

로컬 single-node 데모에서는 faucet, local signer, auditor admin, CORS/proxy convenience를 위해 helper server를 둘 수 있습니다. 그래도 DApp의 핵심 privacy logic은 `clairveiljs/browser-dapp` API를 호출하는 형태를 유지하는 것이 좋습니다.

## EVM Privacy Precompile

EVM Clairveil chain은 state-changing privacy action을 Cosmos SDK tx broadcast가 아니라 EVM privacy precompile로 제출합니다.

ClairveilJS는 브라우저에서 privacy payload를 준비한 뒤, prepared message를 `IPrivacy.deposit`, `IPrivacy.transfer`, `IPrivacy.withdraw` calldata로 변환합니다.

지원 범위:

- 대상 EVM chain은 Clairveil `IPrivacy` precompile ABI와 payload semantic을 제공해야 합니다.
- precompile address는 chain config에서 제공하거나 SDK 기본값 `0x100000000000000000000000000000000000000b`를 사용할 수 있습니다.
- ABI shape가 다른 EVM chain은 현재 SDK의 stable support 범위 밖입니다.

지원되는 EVM ABI에서 `IPrivacy.deposit`은 `{ amount, noteCommitment, encryptedNote }`만 받습니다. Cosmos `MsgDeposit` 경로는 `DepositCircuit` proof가 필요하지만, 현재 EVM precompile deposit calldata에는 proof field가 없습니다.

지원되는 EVM `IPrivacy.transfer` ABI에는 encrypted output note와 `newCommitments`, `cipherTexts` 순서에 맞춘 2개의 2-byte `viewTags`, 그리고 user/audit disclosure field가 들어갑니다. Cosmos `selfViewDisclosure*` field는 없습니다. 그래서 ClairveilJS는 EVM transport에서 self-view disclosure를 기본으로 끄고, self-view disclosure bytes가 들어간 EVM transfer message는 조용히 버리지 않고 에러로 막습니다.

EVM transfer/withdraw도 note scan, planner, disclosure, prover adapter 흐름은 Cosmos와 같습니다. 마지막 submit 단계만 Cosmos sign doc이 아니라 EVM calldata 전송으로 달라집니다.

일부 EVM `IPrivacy.withdraw` 배포는 legacy `newNoteCommitment`, `encryptedNote` ABI field를 아직 포함할 수 있습니다. ClairveilJS는 호환을 위해 기본값으로 이 ABI-only field에 32-byte zero placeholder를 넣습니다. `withdrawOutputMode: "none"`은 이 legacy-compatible ABI에 들어가는 placeholder 값만 비웁니다. downstream precompile이 해당 ABI field 자체를 제거했다면 새 function shape에 맞는 custom contract adapter/encoder를 제공해야 합니다.

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

Remote prover가 job ID를 반환하는 구조라면 `createAsyncJobProverAdapter`로 submit/poll 함수를 감싸세요.

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
```

Relay withdraw는 two-party handoff로 지원합니다. wallet/DApp은 Cosmos와 EVM profile 모두에서 같은 `prepareRelayWithdraw(...)` API로 final withdraw payload를 만들고, product-defined relayer endpoint로 전달합니다. Cosmos profile은 relayer-side `MsgWithdraw` signing에 사용할 payload를 반환합니다. EVM profile은 같은 payload와 `IPrivacy.withdraw` transaction request를 함께 반환합니다. 단, relayer는 client가 보낸 `transaction`을 그대로 신뢰하지 말고 payload에서 transaction을 다시 만들거나 byte-for-byte로 검증해야 합니다. 검증 대상은 `to`, `data`, `chainId`, recipient, expiry, payload hash입니다.

```js
const prepared = await clairveil.prepareRelayWithdraw({
  wallet,
  amount: "5uclair",
  recipient: "clair1...",
  proverAdapter
});

await fetch("/relayer/withdraw", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ payload: prepared.payload })
});
```

EVM profile에서는 `prepared.transaction`을 user wallet에서 바로 보내지 말고 relayer에 candidate transaction으로 전달하세요. relayer는 payload에서 다시 만든 transaction과 일치할 때만 자기 EVM account로 broadcast해야 합니다.

```js
const prepared = await clairveil.prepareRelayWithdraw({
  walletType: "evm",
  address,
  pubKeyHex,
  signatureBase64,
  amount: "5aokrw",
  recipient: "0x..."
});

await fetch("/relayer/evm-withdraw", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    payload: prepared.payload,
    transaction: prepared.transaction
  })
});
```

```js
const relay = await relayerClient.createRelayWithdrawSignDoc({
  payload,
  relayer: relayerAddress,
  pubKeyHex: relayerPubKeyHex,
  expectedChainId: "clairveil-1",
  expectedRecipient: payload.recipient
});
```

## Handoff Conformance

ClairveilJS는 Clairveil Go SDK conformance fixture를 replay하는 handoff test를 포함합니다. 기본 fixture 경로는 sibling Clairveil checkout입니다.

```bash
../clairveil/x/privacy/client/sdk/conformance/testdata
```

로컬 개발에서는 다음을 실행하세요.

```bash
npm run test:conformance
```

fixture directory가 없으면 local command는 명확한 메시지와 함께 skip됩니다.

Release handoff 또는 CI에서는 strict command를 사용하세요. fixture가 없으면 실패합니다.

```bash
npm run test:conformance:required
```

`prepublishOnly`는 strict conformance command를 실행합니다.

검증 범위:

- root seed/key/address derivation
- browser signer adapter behavior
- note scan result
- prepared transfer/withdraw payload hash
- prover HTTP contract behavior
- disclosure decode
- relay withdraw message handoff behavior

## Optional Local Node E2E

Local node e2e는 `prepublishOnly`의 필수 gate가 아닙니다. Clairveil node와 prover를 실행하는 것은 chain repository의 책임이고, SDK는 해당 서비스에 붙었을 때 전체 wallet flow를 수행할 수 있음을 증명합니다.

현재 local e2e scope:

- deposit
- wallet note scan
- shielded transfer
- disclosure decode
- direct withdraw

Relay withdraw payload/signDoc 생성은 SDK test와 Go conformance fixture로 검증합니다. 실제 relayer service e2e는 product-defined relayer transport와 배포 환경에 맞춰 별도로 구성하세요.

```bash
CLAIRVEIL_E2E_LOCAL=1 npm run test:e2e:local
```

Full flow까지 실행하려면 wallet module과 deposit proof module을 함께 넘기세요. Deposit proof module은 `default`, `createDepositProof`, 또는 `depositProofProvider`를 export하고 `{ proof }`, `{ depositProof }`, `{ proofHex }`, `{ proof_hex }` 같은 proof bytes 또는 proof hex를 반환해야 합니다.

```bash
CLAIRVEIL_E2E_LOCAL=1 \
CLAIRVEIL_E2E_FULL_FLOW=1 \
CLAIRVEIL_E2E_WALLET_MODULE=/absolute/path/to/wallet-adapter.mjs \
CLAIRVEIL_E2E_DEPOSIT_PROOF_MODULE=/absolute/path/to/deposit-proof-provider.mjs \
npm run test:e2e:local
```

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
6. 필요하면 `CLAIRVEIL_E2E_LOCAL=1 npm run test:e2e:local`
7. 최종 EVM ABI/prover contract를 pin한 뒤 EVM support stable 여부를 선언
