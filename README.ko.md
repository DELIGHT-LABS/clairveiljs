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
import { createNoteReservationManager } from "clairveiljs/reservation";
```

Public consumer는 내부 파일 경로를 직접 import하지 말고 package export map을 사용하세요.

- `clairveiljs`: 현재 Cosmos 중심 client surface와 backward-compatible root entrypoint
- `clairveiljs/core`: key derivation, address, crypto, note, disclosure primitive
- `clairveiljs/cosmos`, `clairveiljs/cosmos-client`: CosmJS 기반 transport/client
- `clairveiljs/evm`: Clairveil-compatible EVM privacy precompile client
- `clairveiljs/browser-dapp`: production DApp에서 쓰기 좋은 브라우저 wallet client
- `clairveiljs/browser-public`: public privacy event/read-only query client
- `clairveiljs/reservation`: wallet/DApp note reservation store와 manager
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

아래 relay 예제는 최신 체인 블록에서 authoritative time을 조회합니다. REST endpoint는 client 설정과 동일하게 유지하고, 최신 블록에 유효한 timestamp가 없으면 fail-closed하세요.

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

Relay withdraw는 two-party handoff로 지원합니다. wallet/DApp은 Cosmos와 EVM profile 모두에서 같은 `prepareRelayWithdraw(...)` API로 final withdraw payload를 만들고, product-defined relayer endpoint로 전달합니다. Cosmos profile은 relayer-side `MsgWithdraw` signing에 사용할 payload를 반환합니다. EVM profile은 같은 payload와 `IPrivacy.withdraw` transaction request를 함께 반환합니다. 단, relayer는 client가 보낸 `transaction`을 그대로 신뢰하지 말고 payload에서 transaction을 다시 만들거나 byte-for-byte로 검증해야 합니다. 검증 대상은 `to`, `data`, `chainId`, recipient, expiry, payload hash입니다. 아래 두 예제는 [Note reservation](#note-reservation)의 전체 설정으로 `reservationManager`를 먼저 생성했다고 가정합니다.

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

await reservationManager.recordRelayHandoff(prepared.reservation.reservation_ids, {
  leaseToken: prepared.reservation.lease_token,
  payloadHash: prepared.payload.payload_hash
});

await fetch("/relayer/withdraw", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ payload: prepared.payload })
});
```

EVM profile에서는 `prepared.transaction`을 user wallet에서 바로 보내지 말고 relayer에 candidate transaction으로 전달하세요. relayer는 payload에서 다시 만든 transaction과 일치할 때만 자기 EVM account로 broadcast해야 합니다.

```js
const latestChainBlockTimeUnix = await fetchLatestChainBlockTimeUnix();
const prepared = await clairveil.prepareRelayWithdraw({
  walletType: "evm",
  address,
  pubKeyHex,
  signatureBase64,
  amount: "5aokrw",
  recipient: "0x...",
  chainNowUnix: latestChainBlockTimeUnix,
  reservationManager
});
// Browser EVM client는 ready 결과를 만들 수 없으면 예외를 던집니다.

await reservationManager.recordRelayHandoff(prepared.reservation.reservation_ids, {
  leaseToken: prepared.reservation.lease_token,
  payloadHash: prepared.payload.payload_hash
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

동시에 여러 private transaction을 준비할 수 있는 wallet/DApp은 `prepareTransfer(...)`, `prepareWithdraw(...)`, `prepareRelayWithdraw(...)`에 reservation manager를 넘기세요. Manager는 이미 예약된 note를 planner 입력에서 제외하고, proof 생성 중 선택된 note를 예약하며, SDK proof/payload 생성 중 lease를 갱신하고, prepared result에 reservation metadata를 돌려줍니다. Prepared result가 wallet UI 또는 relayer flow로 넘어간 뒤에는 caller가 `heartbeatLease(...)`/`renewLease(...)`로 lease를 유지할 수 있습니다.

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

SDK는 payload 준비 중 reservation을 `Reserved -> Proving -> ProofReady`로 이동합니다. `Reserved`는 durable note inventory lock이고 worker lease를 갖지 않으며, `Proving` 시작 시 batch lease를 원자적으로 claim합니다. Worker lease field는 `Proving`과 `ProofReady`에만 남습니다. SDK는 manager마다 새 `leaseOwner`를 기본 생성하며, 직접 지정할 때는 다른 tab의 만료되지 않은 작업을 recovery가 건드리지 않도록 wallet id가 아니라 browser tab/worker마다 새 값을 사용하세요. Proof heartbeat interval은 60초 고정이 아니라 active lease window에서 계산되므로, timer가 허용하는 한 짧은 lease도 만료 전에 갱신됩니다. 그 뒤 broadcast/reconcile 단계는 wallet 또는 DApp 책임입니다.

- `signDirectAndBroadcast(...)`, `broadcastSignedTx(...)`, EVM `sendTransaction(...)`에는 `reservationManager`와 prepared `reservation`을 함께 넘기세요. 이 메서드들은 외부 RPC 호출 전에 `broadcast_in_flight`를 원자적으로 설정하고 `broadcast_attempt_count`를 증가시킨 뒤, 결과를 `Submitted`, `Unknown`, `ManualReview` 중 하나로 기록합니다. Terminal 저장이 실패하면 durable marker가 남아 reconcile 전 재제출을 막습니다. Withdraw/relay 제출은 실제 transaction과 일치하는 `relayPayload`와 최신 `chainNowUnix`, 또는 권장되는 `getChainNowUnix`도 넘겨야 합니다. EVM request에 `chainId`가 있으면 같은 network ID를 `expectedEvmChainId`로 넘기세요. Binding되지 않은 relay request는 다시 만들고 caller가 넣은 sender, gas, fee 필드를 검증 후 제거합니다. Reservation에 authoritative `txBytesHash`가 이미 있으면 binding에 포함된 지원 sender, gas, fee 필드는 보존될 수 있지만, 지원하지 않는 transaction key는 제출 전에 항상 제거합니다. SDK는 Cosmos body를 decode하거나 EVM calldata를 다시 만들어 payload가 없거나 일치하지 않으면 외부 제출 전에 거부합니다. Custom EVM encoding option을 사용했다면 같은 값을 `relayTransactionOptions`로 넘기세요.
- Custom wallet/provider 연동은 외부 broadcast 경계를 넘기 직전에 `markBroadcastAttempting(ids, { leaseToken, txHash?, txBytesHash?, signDocHash? })`을 호출해 이미 알 수 있는 transaction identity를 영속화한 뒤 아래 결과별 메서드를 사용해야 합니다.
- 실제 transaction이 제출된 뒤에만 `markSubmitted(ids, { leaseToken, txHash | txBytesHash })`를 호출하세요. `signDocHash`만으로는 `Submitted` 근거가 되지 않습니다.
- Transaction이 네트워크에 도달했을 수 있을 때만 `markUnknown(ids, { leaseToken, txHash | txBytesHash, signDocHash?, error })`를 호출하세요. `signDocHash`는 보조 증거일 뿐 단독으로 broadcast 경계를 증명하지 못합니다.
- Wallet 또는 relayer 대기 중에는 `ProofReady` lease를 계속 갱신하세요. `markSubmitted(...)`와 `markUnknown(...)`은 현재의 만료되지 않은 lease token을 요구하며, lease가 만료되면 stale ownership을 전진시키지 말고 reconcile 또는 replan 흐름으로 처리해야 합니다.
- Relay payload를 복사하거나 업로드하기 직전에 `recordRelayHandoff(ids, { leaseToken, payloadHash: prepared.payload.payload_hash })`를 호출하고 영속화가 끝날 때까지 기다리세요. 이 호출이 실패하면 payload를 외부에 노출하지 마세요. 성공한 뒤에는 local proof-discard/release 경로를 쓰지 말고 외부 제출 가능한 payload로 reconcile해야 합니다.
- Wallet rejection 또는 broadcast 전 local proof discard가 발생하면 현재 유효한 lease로 `markReplanRequired(...)`를 호출하세요. 만료된 `ProofReady` lease는 `ManualReview`로 보내야 합니다. 새로고침된 페이지는 이전 proof artifact의 폐기를 증명할 수 없으므로 note를 다시 spendable하게 만들면 안 됩니다.
- Local batch를 직접 폐기할 때 `Reserved`는 바로 release할 수 있고, `Proving`은 현재 batch lease token을 넣어 `releaseReservedOrProving(ids, { leaseToken })`를 호출해야 합니다. `rollbackPlanReservation(...)`은 두 경우를 처리합니다.
- Rollback 시점에 lease가 이미 만료됐다면 note를 release하지 않습니다. 원래 prepare/prover error를 보존하고 note가 조용히 재사용되지 않도록 best-effort로 reservation을 `ManualReview`로 이동합니다.
- `ManualReview`는 chain/payload 이력을 운영자가 검토한 뒤에만 해결하세요. `resolveManualReview(ids, { target: "Released" | "ReplanRequired" | "Failed", operatorId, approvalReference, reason })`는 승인 metadata를 기록하고 승인된 결과 상태로 note를 이동합니다.
- Relay payload를 복사했거나 relayer에게 넘긴 뒤에는 TTL 만료나 local cancel 버튼만으로 reservation을 release하지 마세요. Relayer가 expiry 전까지 proof를 제출할 수 있으므로 nullifier 상태, submitted tx evidence, manual review로 reconcile해야 합니다.
- Relay payload 검증과 relay signing에는 최신 chain block time에서 얻은 `chainNowUnix`가 필수입니다. 브라우저 시간을 대신 쓰지 말고 relay broadcast 직전에 다시 조회하며, 값을 얻지 못하면 제출을 거부하세요.
- Submitted EVM transaction receipt가 실패하면 nullifier 상태를 확인한 뒤 `ConfirmedSpent`, `ReplanRequired`, `ManualReview` 중 하나로 정리하세요. `Submitted` 또는 `Unknown` reservation은 `markReplanRequired(...)`에 `nullifierUnspentConfirmed: true`와 `txAbsentOrFailedConfirmed: true`를 모두 넣어야 `ReplanRequired`로 이동할 수 있습니다. `checkedHeight`와 `txHashChecked`에는 해당 tx 조회의 audit trail을 남기세요.

Reservation은 operation success evidence도 저장할 수 있습니다. Nullifier spent는 입력 note가 소비됐다는 뜻이지만, payroll/payment 성공은 저장된 tx identity와 일치하는 증거 및 expected output commitment, audit disclosure digest, recipient hash, amount hash, denom, 그리고 필요한 경우 item index가 모두 일치해야 합니다. `markProofReady(...)`는 `expectedOutputCommitment`, `expectedDisclosureDigest`, `expectedRecipientHash`, `expectedAmount`, `expectedAmountHash`, `expectedDenom`, `batchItemIndex`, `batchItemIndexKnown`, `operationSuccessEvidenceRequired`를 받습니다. Payroll/batch transfer는 `batchItemIndexKnown: true`로 두고, direct integration은 item position이 success predicate가 아닐 때만 false로 둘 수 있습니다. High-level transfer prepare는 note-lock evidence를 자동으로 채우지만, recipient hash와 amount hash까지 포함한 전체 success predicate가 있을 때만 operation success 판정을 켭니다. Go와 같은 SHA-256 recipient/amount hash는 `clairveiljs/reservation`의 `hashRecipient(recipient, { shieldedPrefix })`, `hashAmount(denom, amount)` helper로 만드세요. 두 helper는 빈 identity field를 거절하며, amount helper는 non-negative uint64 최소 단위 amount만 canonical `denom:amount` 해시로 만듭니다.

Scan migration에서는 최신 nullifier 확인이 명시적으로 `nullifierStatus: "unspent"`인 note만 spendable로 취급하세요. 이전 cache의 `isSpent: false`, 누락·malformed 응답, query 실패는 unverified이므로 다시 검증하기 전에는 planner에서 제외해야 합니다.

나중에 `reconcileSpentNotes(...)`를 호출할 때 tx/event evidence를 `operationSuccessEvidence` 또는 `successEvidence`에 넣으면 SDK가 expected evidence와 비교합니다. `operation_status: "Succeeded"`가 되려면 저장된 submitted `txHash` 또는 `txBytesHash`와 실제 tx identity가 일치해야 합니다. `signDocHash`는 보조 mismatch guard일 뿐 단독으로 chain 실행을 증명하지 못하며, `txResult: { code: 0 }`만 있는 경우도 identity가 없어 성공이 될 수 없습니다. Nullifier spent만으로는 충분하지 않습니다. 여러 input을 쓰는 operation은 같은 reconcile 호출에 연결된 모든 input의 spent evidence를 넣어야 합니다. 불완전한 evidence는 연결된 operation 전체를 `ManualReview`로 기록하고, tx identity나 expected output이 명시적으로 상충하면 `ConflictSpent`와 `operation_success_evidence_errors`를 기록합니다. 두 경우 모두 spent input은 `ConfirmedSpent`로 격리되며, 나중에 완전한 evidence가 들어오면 연결된 모든 reservation의 operation outcome을 원자적으로 통일합니다. Reservation을 note inventory lock으로만 쓴다면 `operationSuccessEvidenceRequired`를 켜지 말고, downstream operation DB에서 별도로 성공 판정을 하세요.

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
