# ClairveilJS 저장소·영속성 구현 가이드

## 목적과 범위

이 문서는 ClairveilJS를 사용하는 브라우저 지갑 또는 DApp이 **복호화된 note와 scan cursor**, **note reservation과 transaction evidence**를 production 환경에서 안전하게 영속화하는 방법을 설명한다.

ClairveilJS는 note 상태를 검증·병합하는 `MemoryNoteStore`, demo/test용 `LocalStorageNoteStore`, 브라우저용 `createBrowserReservationStore(...)`를 제공한다. 그러나 production Note Store의 암호화 키 관리와 wallet DB 구현은 앱 또는 지갑의 책임이다.

- 컴포넌트와 신뢰 경계: [시스템 아키텍처](./architecture.ko.md)
- reservation 상태와 evidence guard: [Note Reservation 상태 전이](./reservation-state-machine.ko.md)
- 배포 profile과 저장소 옵션: [설정 가이드](./configuration.ko.md)
- 재시도와 재시작 복구: [오류·복구](./errors-and-recovery.ko.md)

이 가이드는 Clairveil v0.3.1에서 공개한
`docs/clairveil-js-sdk-handoff-kr.md`,
`docs/clairveil-reference-payroll-wallet-handoff-kr.md`,
`docs/clairveil-client-risk-decisions-kr.md`와
`docs/clairveil-note-reservation-design-kr.md`를 기준으로 ClairveilJS의 현재
공개 API에 맞춰 구체화한 것이다. Clairveil v0.3.1 문서는 wallet DB schema와 encrypted
local storage 방식을 downstream JS SDK·제품의 책임으로 남긴다. 아래 IndexedDB
wrapper와 AES-GCM codec은 **ClairveilJS 권장 구현 구조**이며 v0.3.1 protocol이
고정한 wire contract나 ClairveilJS가 export하는 완성형 wallet DB가 아니다.

## 저장 대상과 책임 분리

| 데이터 | 권장 보관 위치 | 영속화 기준 |
| --- | --- | --- |
| privacy root signature, root seed, spend/view/disclosure private material | Wallet secure store 또는 필요한 동안의 메모리 | 일반 `localStorage`, 평문 IndexedDB, 서버 DB에 저장하지 않는다. |
| 복호화된 note, nullifier 상태, scan cursor | 앱·지갑이 구현한 암호화 Note Store | chain/profile/wallet/account별 namespace로 격리하고 note와 cursor를 원자적으로 저장한다. |
| reservation, lease, payload/proof binding, broadcast evidence | 암호화된 Reservation Store | 브라우저에서는 IndexedDB, Web Locks, 전체-state 암호화를 함께 사용한다. |
| prepared payload 또는 proof checkpoint | 기본적으로 메모리 | 비동기 batch/relay 복구에 꼭 필요한 경우에만 별도 암호화 checkpoint로 영속화한다. |
| 공개 chain config와 비민감 UI 설정 | 일반 설정 저장소 | privacy material과 같은 record나 암호화 키 namespace에 섞지 않는다. |

Note Store와 Reservation Store는 목적과 수명이 다르므로 하나의 상태 객체로 합치지 않는다.

- Note Store는 chain을 다시 scan하면 재구축할 수 있는 wallet inventory다.
- Reservation Store는 note의 중복 사용을 막고, 이미 제출됐을 수 있는 transaction을 재조정하기 위한 안전 상태다.
- Note cache를 잃은 경우에는 full rescan이 가능하지만, `Proving` 이후의 reservation이나 불명확한 broadcast evidence를 잃으면 안전한 자동 복구가 불가능할 수 있다.

### Clairveil wallet projection 대응

Clairveil v0.3.1 문서가 요구하는 최소 wallet projection은 아래처럼 두 저장소와 제품
operation metadata에 나눠 보존한다. 실제 column 이름은 제품이 정할 수 있지만
동등한 정보와 원자성은 유지해야 한다.

| Clairveil projection | ClairveilJS 보관 위치 |
| --- | --- |
| `commitment_hex`, `nullifier_hex`, `amount`, `denom`, `spent` | 암호화 Note Store의 note inventory |
| `last_scan_height`, `last_scan_sequence`와 output 위치 | Note Store의 전체 `(height, global_sequence, output_index)` cursor |
| `nullifier_lookup_key`, `nullifier_lookup_key_id` | 암호화 Reservation Store; 공개 account ID로 lookup key를 대체하지 않음 |
| `reservation_id`, `reservation_status`, `operation_id` | Reservation Store의 CAS·lease·evidence record |
| `tx_hash` | Reservation Store의 network transaction 조회·receipt evidence |
| `tx_bytes_hash` | Cosmos exact signed TxRaw 또는 EVM canonical transaction request의 artifact binding. EVM에서는 network tx 조회 키가 아님 |
| `payroll_id`, `batch_id` | reference payroll 또는 제품 operation DB; reservation `operation_id`와 연결 |

Active reservation에 연결된 note는 일반 transfer, split, merge와 다른 batch의
후보에서 모두 제외한다. Note Store와 Reservation Store를 별도 DB로 구현하더라도
wallet inventory를 표시하거나 plan하기 전에 reservation lookup을 적용해야 한다.

## Production 필수 조건

Production 저장소는 다음 조건을 모두 만족해야 한다.

1. 복호화된 note와 reservation state를 AEAD로 암호화한다.
2. 암호화 키를 ciphertext와 같은 IndexedDB record에 저장하지 않는다.
3. chain, profile, wallet 종류와 account별 namespace를 분리한다.
4. read-modify-write 전체를 동일한 배타 lock 안에서 수행한다.
5. note와 완전한 scan cursor를 하나의 원자적 변경으로 저장한다.
6. 인증 실패, schema 불일치와 손상된 record를 빈 상태로 자동 대체하지 않고 fail-closed 처리한다.
7. `Unknown`, `Submitted`, `ManualReview` reservation을 TTL만으로 해제하지 않는다.
8. 계정 전환과 재시작 후에는 저장된 evidence와 온체인 nullifier/transaction 상태를 reconcile한다.
9. 같은 note namespace의 scan worker는 하나만 활성화하거나, 전체 scan 호출을 별도 single-writer coordinator로 직렬화한다.

다음 옵션과 구현은 demo/test 전용이다.

- `LocalStorageNoteStore({ allowPlaintext: true })`
- `MemoryReservationStore`
- `unsafeAllowPlaintext`
- `unsafeAllowMemoryFallback`
- `unsafeAllowPublicIndexKey`

## Namespace와 계정 격리

저장소 namespace에는 최소한 schema epoch, chain ID, 배포 profile, wallet 종류와 account scope가 포함되어야 한다.

```text
clairveil:wallet-notes:v2:<chain-id>:<profile-scope>:<wallet-kind>:<account-scope>
clairveil:note-reservations:v2:<chain-id>:<profile-scope>:<wallet-kind>:<account-scope>
```

`account-scope`는 공개 주소를 그대로 써도 되는 제품인지 먼저 판단한다. 로컬 DB key만으로 계정 관계가 드러나면 안 되는 환경에서는 namespace 전용 wallet-private key로 만든 안정적인 opaque ID를 사용한다. Reservation의 nullifier lookup용 `indexKey`와 목적을 분리하면 rotation과 migration 경계도 명확해진다.

- namespace가 다른 상태를 읽어 fallback하지 않는다.
- account 또는 chain 전환 시 이전 namespace의 record를 새 namespace로 복사하지 않는다.
- schema/circuit/payload identity가 호환되지 않으면 기존 상태를 억지로 decode하지 않고 새 namespace에서 full rescan한다.
- 동일 계정의 여러 tab만 같은 namespace와 store lock 이름을 공유한다. 현재 SDK는 여러 tab의 전체 network scan을 하나로 직렬화하지 않으므로 scan leader 또는 별도 coordinator도 하나만 둔다.

ClairveilJS의 현재 note cache identity는 `privacy-note-v1-cache-v1`, reservation state identity는 `privacy-note-v1-reservation-v1`이다. 두 state에는 `circuit_set_id: "privacy-note-v1"`, `payload_version: "privacy-fixed-v1"`도 포함된다. DB schema version과 이 protocol identity를 별도 필드로 관리한다.

> **Clairveil v0.3.1 전환 규칙:** 현재 `MemoryNoteStore`는 호환되지 않는
> cache identity를 fresh state로 취급하고, `IndexedDbReservationStore`도
> incompatible state를 fresh state로 정규화한다. 이는 Clairveil v0.3.1의
> 의도적인 compatibility break와 일치한다. `privacy-note-v1` /
> `privacy-fixed-v1`로 전환할 때는 fresh genesis/reset을 사용하고 old
> note/reservation/scan/proof state, queued proof job, cached prepared payload와
> development artifact를 삭제한 뒤 exact artifact set을 다시 만들고 full
> rescan한다. Legacy state를 새 namespace로 import하거나 read-only production
> recovery source로 유지하지 않으며 raw ciphertext와 legacy JSON을 fallback으로
> decode하지 않는다. 전환 직전 구버전 runtime에서 가능한 작업을 먼저
> reconcile할 수는 있지만, 이것이 새 protocol state로의 migration을 허용하지는
> 않는다.

## 암호화 record 계약

### 권장 envelope

하나의 IndexedDB record에 평문 state 대신 다음과 같은 엄격한 envelope를 저장한다.

```js
{
  envelopeVersion: 1,
  kind: "clairveil-note-store",
  namespace: "...",
  keyId: "wallet-db-key-v2",
  algorithm: "AES-GCM",
  iv: "<base64url 12-byte random nonce>",
  ciphertext: "<base64url ciphertext + authentication tag>"
}
```

암호화 구현은 다음 규칙을 지켜야 한다.

- 매 write마다 CSPRNG로 새로운 96-bit AES-GCM IV를 만든다. 같은 key와 IV를 재사용하지 않는다.
- `envelopeVersion`, `kind`, `namespace`, `keyId`를 canonical encoding한 값을 AES-GCM `additionalData`로 인증한다.
- key는 wallet-private material 또는 OS/keychain이 보호하는 secret에서 HKDF 같은 검토된 KDF로 namespace별 유도하고, 가능하면 non-extractable `CryptoKey`로 유지한다.
- root signature나 root seed 원문을 IndexedDB에 저장하지 않는다. key 재유도에 필요한 wallet 승인 절차는 제품에서 정의한다.
- decode 전에 envelope의 허용 필드, 길이, algorithm, namespace와 version을 엄격히 검증한다.
- 인증 실패, 알 수 없는 `keyId`, JSON/schema 오류는 “note 없음”이 아니라 저장소 오류다.

암호화 실패 후 자동으로 빈 DB를 만들면 사용자는 잔액이 사라진 것으로 보거나, unresolved reservation을 무시하고 같은 note를 다시 사용할 수 있다. 초기화는 중단하고 복구 또는 사용자 확인을 거친 reset/full rescan 경로를 제공한다.

## Production Note Store 구현

### SDK가 기대하는 계약

제품 Note Store는 `clairveiljs/note-store`의 `MemoryNoteStore`와 같은 메서드를 구현하면 browser/cosmos client의 `noteStore`로 주입할 수 있다.

| 메서드 | 저장소 구현 요구사항 |
| --- | --- |
| `load()` | 암호화 record를 읽고 인증·decode·state validation을 거친 현재 상태를 반환한다. |
| `save(state)` | SDK 타입상 partial state patch를 받는다. `MemoryNoteStore.save(...)`는 현재 state와 merge하고 identity가 호환되지 않으면 throw 대신 fresh state로 정규화하므로, production wrapper는 전달 전에 patch와 identity를 별도 검증한다. |
| `clear()` | 손상된 record도 지울 수 있도록 기존 ciphertext decode 없이 삭제할 수 있어야 한다. Production UI에서는 명시적 사용자 확인이 필요하다. |
| `mergeScanResult(result, options)` | 기존 note와 cursor를 같은 lock/transaction 안에서 병합·저장한다. |
| `rollbackToHeight(height)` | reorg 기준 높이 이후 note/cursor를 같은 원자적 변경으로 되돌린다. |
| `markSpent(nullifiers)` | 확인된 nullifier의 note 상태를 원자적으로 변경한다. |
| `setNullifierStatuses(statuses)` | batch nullifier 조회 결과를 원자적으로 반영한다. 누락된 응답을 `unspent`로 간주하지 않는다. |

직접 note 병합과 cursor rollback 규칙을 다시 구현하기보다 `MemoryNoteStore`를 note shape와 mutation engine으로 감싸는 방식을 권장한다. 다만 `MemoryNoteStore`는 production용 strict state validator가 아니다. Constructor와 `save(...)`는 호환되지 않는 cache identity를 현재 fresh state로 정규화하며, `save(...)`는 partial patch를 현재 state와 merge한다. 따라서 암호화 envelope와 persisted full state는 `record.read()`에서, 외부에서 들어오는 `save(...)` patch는 `record.validateSavePatch(...)`에서 제품이 fail-closed로 검사해야 한다. Protocol cutover의 의도적인 reset은 별도 새 namespace에서 수행하고 손상된 runtime record를 이 자동 정규화에 맡기지 않는다.

```js
import { MemoryNoteStore } from "clairveiljs/note-store";

// record는 애플리케이션이 구현하는 encrypted IndexedDB abstraction이다.
// exclusive(): namespace별 Web Lock 안에서 callback 실행
// read(): 엄격히 인증·복호화한 NoteStoreState 또는 null 반환
// validateSavePatch(): save용 partial patch와 선택적 identity field를 엄격히 검증
// write(): hydrated NoteStoreState를 canonical encode·암호화해 원자적으로 put
// delete(): ciphertext를 decode하지 않고 해당 namespace record 삭제
export class EncryptedNoteStore {
  #owner;
  #record;

  constructor({ owner = "", record }) {
    this.#owner = owner;
    this.#record = record;
  }

  async #run(mutates, callback) {
    return this.#record.exclusive(async () => {
      const state = await this.#record.read();
      const memory = new MemoryNoteStore({
        owner: this.#owner,
        state: state ?? undefined
      });
      const result = await callback(memory);
      if (mutates) {
        await this.#record.write(await memory.load());
      }
      return result;
    });
  }

  load() {
    return this.#run(false, (store) => store.load());
  }

  save(state) {
    return this.#run(true, async (store) => {
      // SDK가 export하는 validator가 아니라 애플리케이션 record 계약이다.
      // MemoryNoteStore.save()보다 먼저 실행해야 incompatible identity의
      // silent fresh-state normalization을 write하지 않는다.
      await this.#record.validateSavePatch(state);
      return store.save(state);
    });
  }

  mergeScanResult(result, options) {
    return this.#run(true, (store) => store.mergeScanResult(result, options));
  }

  rollbackToHeight(height) {
    return this.#run(true, (store) => store.rollbackToHeight(height));
  }

  markSpent(nullifiers) {
    return this.#run(true, (store) => store.markSpent(nullifiers));
  }

  setNullifierStatuses(statuses) {
    return this.#run(true, (store) => store.setNullifierStatuses(statuses));
  }

  clear() {
    return this.#record.exclusive(async () => {
      await this.#record.delete();
      return new MemoryNoteStore({ owner: this.#owner }).load();
    });
  }
}
```

`record.exclusive(...)`는 read와 write 각각이 아니라 **read → MemoryNoteStore mutation → encrypted write 전체**를 감싸야 한다. 브라우저에서는 namespace별 Web Lock과 IndexedDB transaction을 함께 사용한다. 이 lock은 개별 Note Store method를 직렬화할 뿐 network scan 전체를 직렬화하지 않는다. Web Locks를 지원하지 않는 환경에서 production 기능을 memory fallback으로 계속 실행하지 않는다.

현재 `scanWalletNotes(...)`는 Note Store에서 cursor를 읽고, lock 밖에서 network scan을 기다린 뒤, `mergeScanResult(...)`를 호출한다. `MemoryNoteStore.mergeScanResult(...)`에는 시작 cursor를 비교하는 CAS나 stale-result 거부가 없다. 따라서 같은 namespace에서 두 tab이 동시에 scan하면 늦게 끝난 오래된 결과가 최신 `scanCursor`를 다시 낮출 수 있다. Production 제품은 tab leader/single-writer queue를 두거나, store mutation lock과 이름이 다른 scan-coordinator lock으로 **cursor load부터 network scan과 최종 merge까지의 전체 호출**을 직렬화해야 한다. 현재 SDK가 이 coordinator를 자동 제공한다고 가정하지 않는다.

큰 wallet DB를 note별 record로 정규화해 구현할 수도 있다. 이 경우에도 SDK에 반환하는 `NoteStoreState` snapshot과 cursor update가 하나의 IndexedDB transaction에서 일관되게 만들어져야 하며, 중복 commitment/nullifier와 rollback 규칙을 테스트해야 한다.

### Scan cursor와 reorg

- scan 결과의 note와 wire의 전체 `(height, global_sequence, output_index)` cursor를 함께 commit한다. 해당 cursor까지의 모든 output과 nullifier 상태가 durable하게 반영되기 전에 cursor만 먼저 저장하지 않는다.
- 같은 namespace에서 concurrent scan completion을 허용하지 않는다. 현재 merge는 stale cursor를 자동 거부하거나 monotonic CAS하지 않는다.
- `has_more: true`인 중간 page의 cursor를 scan 완료 cursor로 취급하지 않는다.
- nullifier 조회 응답이 누락되거나 malformed이면 해당 note를 `unspent`로 승격하지 않는다.
- reorg가 감지되면 `rollbackToHeight(...)`를 같은 namespace lock 안에서 실행하고 그 높이부터 다시 scan한다.
- note rollback만으로 linked reservation을 자동 삭제하지 않는다. active reservation은 별도 evidence로 reconcile한다.
- protocol/cache identity가 호환되지 않으면 permissive migration보다 새 namespace와 full rescan을 선택한다.

## Production Reservation Store 구현

브라우저에서는 SDK가 제공하는 IndexedDB adapter를 사용하고, 애플리케이션이 전체 state용 암호화 codec을 주입한다.

```js
import {
  createBrowserReservationStore,
  createNoteReservationManager
} from "clairveiljs/reservation";

const reservationStore = createBrowserReservationStore({
  dbName: "clairveil-reservations",
  namespace: reservationNamespace,
  requireLocks: true,
  encodeState: (state) => reservationCodec.encrypt(state),
  decodeState: (record) => reservationCodec.decryptAndValidate(record)
});

const reservationManager = createNoteReservationManager({
  store: reservationStore,
  ownerKeyId,
  indexKey: rootSeed,
  nullifierLookupKeyId: "privacy-root-v1",
  leaseOwner: `browser-tab:${crypto.randomUUID()}`
});
```

`reservationCodec`은 ClairveilJS export가 아니라 제품이 구현·검토하는 AEAD codec이다. `encodeState`와 `decodeState`는 일부 metadata만이 아니라 `ReservationStoreState` 전체를 인증·암호화해야 한다. `decryptAndValidate(...)`는 인증뿐 아니라 현재 reservation `version`, `circuit_set_id`, `payload_version`도 검사하고 불일치 시 throw해야 한다.

예제의 `reservationNamespace`는 앞 절의 chain/profile/wallet/account scope로 만든 값이고, `ownerKeyId`는 해당 wallet owner를 나타내는 안정적인 opaque ID다. `rootSeed`는 현재 승인된 wallet session의 메모리에서만 사용하고 DB에 저장하지 않는다.

- `requireLocks`는 production에서 `true`로 유지한다.
- `leaseOwner`는 tab/process 시작마다 새 random 값으로 만들고 다른 tab과 lease token을 공유하지 않는다. 생략하면 SDK도 random owner를 생성하지만, 운영 진단을 위해 process 종류를 포함한 opaque prefix를 둘 수 있다.
- `indexKey`는 private nullifier로부터 `nullifier_lookup_key`를 만드는 wallet-private key다. 공개 account ID로 대체하지 않는다.
- `nullifierLookupKeyId`는 index key의 버전을 식별한다. 암호화 envelope의 `keyId`와 목적이 다르다.
- 직접 record를 덮어쓰지 말고 `createNoteReservationManager(...)`의 batch, lease, CAS, broadcast와 reconcile helper를 사용한다.

브라우저가 아닌 backend/desktop adapter를 구현할 때는 `ReservationStore` interface를 구현한다. database transaction 또는 이에 준하는 원자성으로 다음을 보장해야 한다.

- 동일 `owner_key_id + nullifier_lookup_key`의 active reservation은 하나만 존재한다.
- status 변경은 compare-and-set이고 lease token/evidence guard를 우회하지 않는다.
- batch reserve/release/transition은 전부 성공하거나 전부 rollback한다.
- `Submitted`, `Unknown`, `ManualReview`는 단순 만료 cleanup 대상이 아니다.

## Key rotation과 migration

서로 다른 변경을 하나의 “key rotation”으로 처리하지 않는다.

| 변경 | 안전한 처리 |
| --- | --- |
| 저장소 암호화 key 교체 | envelope `keyId`로 이전 key를 식별해 인증·복호화하고, namespace lock 안에서 새 key로 다시 암호화한다. migration 실패 시 기존 ciphertext를 보존한다. |
| `indexKey` 교체 | 모든 reservation lookup key가 달라진다. active reservation과 이전 `nullifier_lookup_key_id`를 보존하는 명시적 migration이 필요하다. 단순 설정 교체로 처리하지 않는다. |
| DB schema 변경 | version별 strict decoder와 단방향 migration을 별도 테스트한다. 원본 backup 또는 rollback 경로 없이 in-place overwrite하지 않는다. |
| 같은 protocol identity 안의 app DB schema/key 변경 | Strict decoder와 검토된 단방향 migration을 사용할 수 있다. Active reservation과 transaction evidence를 보존한다. |
| `privacy-note-v1` / `privacy-fixed-v1`로의 protocol 전환 | Clairveil v0.3.1 계약대로 fresh genesis/reset, incompatible state·job·artifact 삭제와 full rescan을 수행한다. Legacy decode와 in-place migration을 제공하지 않는다. |
| 향후 circuit/payload/cache identity 변경 | 해당 Clairveil release handoff가 migration을 명시적으로 허용하지 않으면 호환되지 않는 것으로 보고 fresh namespace/reset과 full rescan을 사용한다. |

일반적인 사용자 reset에서는 Note Store reset과 Reservation Store reset을 하나의
버튼으로 묶지 않는다. 특히 unresolved reservation 삭제에는 별도의 경고,
export 가능한 진단 evidence와 수동 확인 절차가 필요하다. 단, Clairveil release가
fresh reset을 요구하는 protocol cutover는 예외이며 old note, reservation, scan,
proof state와 artifact를 하나의 배포 절차에서 함께 제거한다.

Protocol cutover 전에는 구버전 runtime에서 non-terminal reservation을 조회하고
가능한 transaction/nullifier evidence를 reconcile한다. Cutover가 시작되면 old
encrypted DB를 새 runtime의 compatibility source로 열거나 reservation을 import하지
않는다. 새 fresh-genesis inventory는 canonical `privacy-scan-v2` full rescan으로만
구축한다.

## 계정 전환과 비동기 작업

wallet account, profile 또는 chain이 바뀌면 다음 순서를 지킨다.

1. 기존 scan, prover poll과 reservation heartbeat를 중단한다.
2. 현재 session generation을 무효화한다.
3. 이전 namespace의 DB handle과 메모리 cache를 닫는다.
4. 새 wallet 승인을 거쳐 namespace와 암호화/index key를 유도한다.
5. 새 namespace 상태를 검증하고 필요한 scan/reconcile을 마친 뒤 spendable inventory를 표시한다.

모든 장기 비동기 작업은 `await` 이후에도 시작할 때의 chain/account/session generation이 현재 값과 같은지 확인해야 한다. 이전 account에서 늦게 완료된 scan이나 prover callback이 새 account의 DB에 write하면 안 된다.

## 재시작과 장애 복구

앱 시작 시에는 저장소를 연 뒤 active reservation을 먼저 확인한다.

1. `Submitted`와 `Unknown`에 network `tx_hash`가 있으면 Cosmos transaction 또는 EVM receipt를 transport별 조회 API로 확인한다.
2. Cosmos의 `tx_bytes_hash`는 exact signed TxRaw의 SHA-256이므로 보존한 signed bytes와 network identity를 검증하는 데 사용할 수 있다. EVM의 `tx_bytes_hash`는 `evmTransactionBindingHash(...)`로 만든 서명 전 canonical request binding이므로 `eth_getTransactionByHash`나 `eth_getTransactionReceipt`의 조회 키로 사용하지 않는다.
3. EVM record에 network `tx_hash`가 없다면 binding hash만으로 transaction 부재를 확정하지 않는다. wallet·relayer operation 기록과 nullifier/output/event evidence를 함께 확인하고, evidence가 부족하면 `Unknown` 또는 `ManualReview`에 유지한다.
4. 연결된 input nullifier를 batch 조회한다.
5. nullifier가 spent이면 `ConfirmedSpent`로 만들되, payment/operation 성공은 output evidence로 별도 판정한다.
6. 올바른 network identity로 tx 실패 또는 부재가 확인되고 nullifier 미사용도 확인된 경우에만 `Failed` 또는 `ReplanRequired`를 검토한다.
7. evidence가 부족하거나 충돌하면 `ManualReview`에 유지한다.

비동기 prover job, relay handoff 또는 batch callback을 재시작 후 이어야 한다면 opaque job ID, request/payload hash, artifact identity와 reservation ID만 별도 encrypted checkpoint에 저장한다. private prover payload 원문은 가능한 한 저장하지 않고, checkpoint는 terminal reconcile 후에만 삭제한다.

## 구현별 권장 형태

| 환경 | Note Store | Reservation Store | Key 보관 |
| --- | --- | --- | --- |
| Browser DApp/extension | 암호화 IndexedDB + store Web Lock + namespace별 single scan leader | `createBrowserReservationStore(...)` + AEAD codec | wallet 재승인으로 유도한 non-extractable Web Crypto key |
| Desktop wallet | SQLite/embedded DB의 암호화 column 또는 encrypted DB | transaction/CAS가 가능한 별도 table | OS Keychain/KeyStore/secure enclave 연동 |
| Backend relayer | 원칙적으로 복호화 note를 보관하지 않음 | 필요한 relay operation/evidence만 transaction DB에 저장 | KMS/HSM, service identity별 key |

Relayer가 wallet Note Store 역할까지 맡도록 확장하면 신뢰 모델이 달라진다. 이 경우 일반 endpoint proxy가 아니라 custody 또는 server-backed wallet 설계로 별도 보안 검토가 필요하다.

## 검증 체크리스트

최소한 다음 테스트를 자동화한다.

- IndexedDB 원문과 로그에 note amount, randomness, nullifier, private material이 나타나지 않는다.
- 같은 state를 두 번 저장해도 IV와 ciphertext가 달라진다.
- 잘못된 key, 변조된 ciphertext/AAD, 알 수 없는 version은 인증 오류로 중단된다.
- 손상된 record가 빈 wallet으로 자동 변환되지 않는다.
- 같은 namespace의 두 tab이 동시에 같은 note를 reserve할 수 없다.
- 다른 chain/account namespace에서는 상대 상태를 읽을 수 없다.
- scan page 저장 중 crash가 나도 note와 cursor가 서로 다른 시점을 가리키지 않는다.
- reorg rollback 후 note/cursor는 복구되지만 unresolved reservation은 자동 삭제되지 않는다.
- 재시작 후 `Submitted`/`Unknown`이 온체인 evidence로 reconcile되기 전에는 input note가 재사용되지 않는다.
- `LocalStorageNoteStore`와 unsafe reservation 옵션이 production build/config에서 거부된다.
- key rotation 실패 시 이전 ciphertext로 rollback할 수 있고 active reservation identity가 유지된다.
- account 전환 전 시작된 비동기 callback이 새 namespace에 write하지 않는다.
- `privacy-note-v1` / `privacy-fixed-v1` cutover에서는 old note/reservation/scan/proof state와 artifact가 삭제되고 legacy decoder나 in-place migration으로 다시 열리지 않는다.
- scan cursor는 `(height, global_sequence, output_index)` 전체가 note/output persistence와 같은 atomic commit에 포함된다.
- 같은 namespace의 concurrent scan을 막고, 의도적으로 순서를 뒤집은 두 scan 결과에서 오래된 cursor가 최신 cursor를 덮지 못한다.

## 구현 참조

- Note Store state와 invariant: `src/privacy/note-store.js`, `src/privacy/note-store.d.ts`
- Reservation Store, Web Locks, lease와 CAS: `src/privacy/reservation.js`, `src/privacy/reservation.d.ts`
- Browser client의 `noteStore`/reservation 연결: `src/browser/wallet-client.js`, `src/browser/wallet-client.d.ts`
- Scan cursor와 nullifier 확인: `src/privacy/scan.js`, `src/privacy/scan.d.ts`
