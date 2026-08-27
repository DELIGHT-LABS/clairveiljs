# ClairveilJS Deployment and Client Configuration

## Purpose and baseline

This document describes the chain profile, endpoint, timeout, query-failover, prover, EVM, and local-store settings used when a browser DApp connects ClairveilJS in a production environment.

- System components and trust boundaries: [System architecture](./architecture.md)
- SDK APIs and external endpoint mapping: [API mapping](./api-mapping.md)
- State and evidence before/after submission: [Note Reservation State Transitions](./reservation-state-machine.md)
- Encrypted wallet DB and reservation persistence: [Storage and persistence](./storage-and-persistence.md)
- Failure handling and retry criteria: [Errors and recovery](./errors-and-recovery.md)

In TypeScript, `BrowserWalletProfile`, `ClairveilWebClientConfig`, and `ClairveilBrowserClientOptions` define the field contract. At runtime, `validateBrowserWalletProfile(...)` and `validateClairveilWebClientConfig(...)` fail closed on unknown fields, transport-specific required values, URL format, and cross-field consistency.

In production, validate a complete profile first and create the client from its `activeProfile`, rather than scattering individual endpoints across the constructor.

> **Release status:** The Clairveil v0.3.1 release supported by this SDK is
> `PUBLICATION_READY_EXPERIMENTAL`, not `PRODUCTION_RELEASE_READY`.
> The production settings below are safe downstream-integration guidance; they do
> not replace formal trusted setup, external security/circuit audit, signed
> production artifacts, or actual downstream chain/product validation.

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

When `profile` is supplied, the profile is the sole source of truth for chain identity, wallet type, and endpoints. Even if `rpc`, `rest`, `chainId`, `proverUrl`, or `evmRpc` are also supplied to the same constructor, the profile values take precedence. Client behavior options outside the profile, such as timeout, retry, failover, and injected adapters, are applied separately.

## Deployment configuration document

The minimum shape of `ClairveilWebClientConfig` is:

| Field | Required | Meaning |
| --- | --- | --- |
| `schemaVersion` | Yes | Must be `clairveil-web-client-config-v1` |
| `activeChainProfileId` | Yes | Profile ID to use from `chainProfiles` |
| `chainProfiles` | Yes | One or more complete profiles with no duplicate IDs |
| `serverBacked`, `serverFeatures` | No | Policy metadata describing product-server and UI capabilities |
| `modeLabel`, `home`, `localSignerHome`, `localSignerBin`, `localTestMode` | No | Deployment/local-tool metadata; does not configure SDK transport behavior |

For backward compatibility, top-level flattened `chainId`, `rpc`, `rest`, `proverUrl`, `transport`, denom/prefix, Keplr, and EVM fields are accepted, but if present they must exactly match the selected active profile. Omit these flattened fields in new configurations.

`serverFeatures` is a flag for UI exposure and product policy. For example, `batchTransfer: true` does not automatically enable One-Proof. After checking policy, the caller must explicitly set `enableExperimentalBatchTransfer` on the client; this feature is currently Cosmos-only.

## Common profile fields

Cosmos and EVM profiles both contain the following fields.

| Field | Contract |
| --- | --- |
| `id` | An ID of 1–128 characters that starts with an English letter or digit and uses only `A-Z`, `a-z`, `0-9`, `.`, `_`, and `-` |
| `label`, `chainName` | 1–128 character strings shown to the user |
| `transport` / `wallet` | `cosmos` / `keplr` or `evm` / `metamask` combination |
| `chainId` | Chain ID used for the Clairveil protocol domain and Cosmos sign docs |
| `rpc` | Comet RPC base URL for the Clairveil chain |
| `rest` | Primary Clairveil REST base URL |
| `restEndpoints` | Optional REST candidate list. It cannot be empty or contain duplicates; `rest` is first in the effective order. |
| `accountPrefix`, `shieldedPrefix` | Bech32 prefixes for account and shielded addresses |
| `denom`, `displayDenom`, `coinDecimals` | Minimal denom, display denom, and decimals |
| `proverUrl` | Default HTTP prover base URL for transfer, withdraw, and One-Proof batch. A path prefix is preserved when versioned prover routes are appended. |
| `depositProofUrl` | Optional exact URL dedicated to DepositCircuit; it is not derived from `proverUrl` |

Profile URLs must use `http` or `https` and must not contain a query, fragment, or embedded credential. The runtime validator allows HTTP for local development, but production endpoints should use HTTPS and must not put bearer tokens or private values in URLs.

## Cosmos profile

A Cosmos profile additionally requires:

| Field | Contract |
| --- | --- |
| `keplrCoinType` | An integer from 0 to 4,294,967,295 |
| `gasPriceStep` | Positive `low`, `average`, and `high` values |
| `keplrChainInfo` | Keplr suggest-chain information |

`keplrChainInfo.chainId`, `chainName`, `rpc`, `rest`, coin type, gas price, and denom-display information must exactly match the corresponding profile fields. `currencies` and `feeCurrencies` each contain one currency, and `features` must be an empty array.

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

The URLs and network values above are format examples. Use values deployed by the target chain in a real deployment.

## EVM profile

An EVM profile additionally requires the following values alongside the Clairveil REST/RPC fields.

| Field | Contract |
| --- | --- |
| `evmRpc` | Read-only EVM JSON-RPC URL used for chain ID and receipt queries instead of the wallet provider |
| `evmChainId` | Network ID in EVM quantity format beginning with `0x` |
| `evmChainName` | Display name for the network |
| `evmPrivacyPrecompileAddress` | 20-byte `IPrivacy` precompile address provided by the target/downstream chain |
| `evmGasLimit` | Hex quantity for privacy transactions |
| `evmSendGasLimit` | Hex quantity for native sends |
| `evmDepositMode` | Browser EVM profiles require the canonical `payable-exact-value` mode |
| `evmNativeDenom` | Required for payable deposits and must exactly equal `denom` |

The common `chainId` is the Clairveil payload domain and `evmChainId` is the EVM network ID; they are not interchangeable. Before preparing a proof or transaction, the SDK verifies that both configured `evmRpc` and the connected signing wallet match `evmChainId`.

Browser EVM profiles target the Clairveil v0.3.1 exact-value deposit ABI and therefore require `payable-exact-value`. The SDK binds the minimal-unit amount exactly to `msg.value` and rejects client creation when `evmNativeDenom !== denom`. A generic EVM client may explicitly select `nonpayable` only as a compatibility setting for a legacy downstream deployment.

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
  evmPrivacyPrecompileAddress: "0x100000000000000000000000000000000000000b",
  evmDepositMode: "payable-exact-value",
  evmNativeDenom: "uclair",
  evmGasLimit: "0x989680",
  evmSendGasLimit: "0x5208"
};
```

Confirm the precompile address and payable support in the target/downstream chain's deployment contract. Do not assume support from the ClairveilJS default or example address alone.

## Client behavior options

The main `ClairveilBrowserClientOptions` controlled outside the profile are:

| Option | Default | Operational guidance |
| --- | --- | --- |
| `queryTimeoutMs` | 30,000ms | REST/RPC query timeout. `fetchTimeoutMs` is a compatibility alias and takes precedence when present. |
| `queryRetry` | 2 attempts, 250–1,500ms jitter | Default retry statuses are 408, 429, 502, 503, 504. `false` disables retry. |
| `nullifierFailover` | `false` | When enabled, the same nullifier may be exposed to multiple REST providers. Requires a product privacy decision. |
| `merklePathFailover` | `false` | When enabled, the spend commitment and exact-snapshot request may be exposed to multiple providers. |
| `proverAdapter` | None | Injects a local/WASM, internally authenticated, or async-job prover. Takes precedence over the default HTTP adapter. |
| `proverBearerToken` | None | Authorization credential for the default HTTP prover. Do not put it in a URL or log it. |
| `proverTimeoutMs` | 120,000ms | Transfer/withdraw/batch prover timeout |
| `depositProofProvider` | None | Local/WASM DepositCircuit provider. Takes precedence over `depositProofUrl`. |
| `depositProofTimeoutMs` | 120,000ms | Exact deposit-proof HTTP timeout |
| `depositProofResponseMaxBytes` | 1MiB | Deposit-proof response limit |
| `enableExperimentalBatchTransfer` | `false` | Explicit opt-in for Cosmos One-Proof batch. Unsupported on EVM. |

General queries may retry/fail over among configured REST endpoints, but nullifier and Merkle-witness requests have high privacy-linkage risk and stay pinned to the default endpoint. Before enabling either option for availability, review whether the provider operators are truly separate and whether they can correlate the same user.

## Prover and deposit-proof boundary

`proverUrl` is the base URL for these routes:

- `POST /v1/prover/transfer`
- `POST /v1/prover/withdraw`
- `POST /v1/proofs/batch-transfer`

Deposit proof does not use this base URL. Choose exactly one of:

1. `depositProofProvider`: a browser-local/WASM or caller-reviewed implementation
2. `depositProofUrl`: an exact HTTP endpoint fixed in the profile

Do not concatenate `depositProofUrl` from `proverUrl` or use a fallback. Evaluate the remote prover and deposit-proof service as separate trust principals that can see private payloads.

### Remote prover operational boundary

When operating the Clairveil reference prover remotely, the server-side default admission is `max_in_flight=1` per circuit, `max_queued=4`, and positive `max_request_bytes=8,388,608` (8 MiB); zero is invalid. These are prover deployment settings, not `ClairveilBrowserClientOptions`. Do not expose a raw transport handler; expose only a bounded service handler with body limits, authentication, TLS, timeouts, rate limits, and redacted logging.

Client timeout or `AbortSignal` cancels waiting for the response only; it does not guarantee that an in-process solver already running has stopped or that its permit/memory was returned. Current general transfer/withdraw prepare helpers call `rollbackPlanReservation(...)` on this error. A `Reserved` operation can be released before proving starts, but `Proving` or `ProofReady` is quarantined in `ManualReview` when the current lease permits that transition. Async products that need opaque job IDs and checkpoints must track them in a separate operation store. Use a supervised worker process and process isolation when hard cancellation and OOM containment are required.

The default prover policy is one explicitly selected endpoint with automatic failover disabled. `retryable=true`, a timeout, or queue saturation does not authorize sending the same private witness to another endpoint. Bounded retries to the same endpoint are possible, but sending to an additional endpoint must be implemented by a separate adapter only after explaining and explicitly approving the expanded privacy boundary in user or product policy.

## Local-store security

The Note Store and Reservation Store have different security contracts.

| Store | Production | Demo/Test only |
| --- | --- | --- |
| Note Store | Implement the Note Store contract using a separate encrypted wallet DB supplied by the app or wallet | `LocalStorageNoteStore({ allowPlaintext: true })` stores decrypted notes as plaintext JSON |
| Reservation Store | `createBrowserReservationStore(...)` + IndexedDB + Web Locks + `encodeState`/`decodeState` | `unsafeAllowPlaintext`, `unsafeAllowMemoryFallback`, `MemoryReservationStore` |

Choose a stable Reservation `namespace` for the chain and wallet identity, and derive `indexKey` from wallet-private material such as the privacy root seed. Do not use the public account ID as the lookup key through `unsafeAllowPublicIndexKey`, and do not use memory/plaintext fallback in production. Never store encryption keys or private material in the same record as the ciphertext.

Follow the [Storage and persistence implementation guide](./storage-and-persistence.md) for the concrete IndexedDB namespace, AEAD envelope, production Note Store adapter, and key-rotation/recovery contract.

## Pre-start checklist

1. Validate the server configuration with `validateClairveilWebClientConfig(...)` and select one active profile.
2. Confirm that production URLs use HTTPS and contain no credentials, query, or fragment.
3. Use `client.health()` to check the Comet chain ID, initialized tree, and audit config. Consider `allowUninitializedTree: true` only on the initial bootstrap screen.
4. For an EVM profile, check read-only RPC with `assertEvmNetwork()`. Prepare/send APIs also check the signing-wallet network separately.
5. Preflight that circuit, disclosure, audit, and asset configuration match the identities and policies expected by the product.
6. Check Note Store and Reservation Store encryption and Web Locks configuration.
7. Review the prover and deposit-proof endpoint/provider separately, and configure timeouts and credentials.
8. Confirm that the reservation checkpoint is durable before broadcast and that it can be reconciled after failure using the [Errors and recovery guide](./errors-and-recovery.md).
9. Confirm that active circuit order, `privacy-fixed-v1` encoding, public-input schema, and wire version exactly match the [fixed contract in API mapping](./api-mapping.md#clairveil-v031-fixed-contract).
10. Confirm in a separate release gate that formal trusted setup, external audit, signed production artifacts, and target chain/product E2E validation are complete.

Successful `health()` means that the endpoint and basic chain configuration are valid; it does not guarantee prover availability, wallet signing, EVM payable accounting, or actual transaction success.

## Implementation references

- Profile types and client options: `src/browser/wallet-client.d.ts`
- Profile/config runtime validation and client construction: `src/browser/wallet-client.js`
- REST retry and failover: `src/browser/public-client.js`, `src/transport/cosmos-client.js`
- Prover and deposit-proof adapters: `src/privacy/prover.js`
- Note Store: `src/privacy/note-store.js`
- Reservation Store and manager: `src/privacy/reservation.js`
