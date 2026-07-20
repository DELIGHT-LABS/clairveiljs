import { deriveShieldedAddress, derivePrivacyMaterial } from "clairveiljs/core";
import { createNoteReservationManager as createRootNoteReservationManager } from "clairveiljs";
import { createClairveilPublicClient } from "clairveiljs/browser-public";
import {
  ClairveilBrowserDappClient,
  createClairveilBrowserDappClient,
  type DecodeAuditDisclosureInput,
  type DecodeSelfViewDisclosureInput,
  type PrepareDepositInput,
  type PreparedCosmosDeposit,
  type PreparedDeposit,
  type PreparedEvmDeposit,
  type PrepareRelayWithdrawInput,
  type PrepareCosmosRelayWithdrawInput,
  type PrepareEvmRelayWithdrawInput,
  type PreparedCosmosRelayWithdraw,
  type PreparedEvmRelayWithdraw,
  type PreparedRelayWithdraw,
  type PreparedRelayWithdrawSignDoc,
  type DirectOperationEvidenceHashes as BrowserDirectOperationEvidenceHashes,
  type PrepareTransferInput,
  type PrepareCosmosTransferInput,
  type PrepareEvmTransferInput,
  type PrepareDefaultEvmProfileTransferInput,
  type PrepareCosmosTransferBatchInput,
  type PrepareExplicitCosmosTransferBatchInput,
  type PreparedCosmosTransfer,
  type PreparedCosmosTransferBatch,
  type PreparedEvmTransfer,
  type PreparedTransfer,
  type PrepareWithdrawInput,
  type PrepareCosmosWithdrawInput,
  type PreparedCosmosWithdraw,
  type PreparedEvmWithdraw,
  type PreparedWithdraw,
  type ScanWalletNotesInput,
  type ScanWalletNotesResult
} from "clairveiljs/browser-dapp";
import type { DisclosureReport } from "clairveiljs/disclosure";
import type { NullifierStatusReader, PreparedWithdrawPayload, WithdrawMessage } from "clairveiljs/payload";
import { scanNotes } from "clairveiljs/scan";
import { runClairveilConformanceFixtures } from "clairveiljs/conformance";
import {
  createClairveilClient,
  type PreparedTransfer as CosmosPreparedTransfer,
  type BatchOperationEvidenceHashes,
  type DirectOperationEvidenceHashes as CosmosDirectOperationEvidenceHashes,
  type ReserveResponse,
  type SignDocBase64
} from "clairveiljs/cosmos";
import { planTransferBatchNotes } from "clairveiljs/planner";
import type { FoundNote } from "clairveiljs/note";
import {
  createNoteReservationManager,
  hashAmount,
  hashRecipient,
  MemoryReservationStore,
  reservationHeartbeatIntervalMs,
  type InitialNoteReservationRecord,
  type ReservationBatch
} from "clairveiljs/reservation";
import {
  bech32AddressToEvm,
  createClairveilEvmClient,
  createEip1193WalletAdapter,
  evmAddressToBech32,
  type Eip1193WalletAdapter,
  functionSelector,
  evmPrivacyPrecompileAddress
} from "clairveiljs/evm";
import type { WalletAdapterLike } from "clairveiljs/wallet-adapter";
import type { MsgDeposit as GeneratedMsgDepositWithExtension } from "clairveiljs/generated/clairveil/privacy/v1/tx.js";

const rootSeed = new Uint8Array(32);
const shielded: string = deriveShieldedAddress(rootSeed, { shieldedPrefix: "demos" });
const material = derivePrivacyMaterial({
  address: "demo1example",
  pubKeyHex: "02".padEnd(66, "0"),
  signatureBase64: "AQID",
  shieldedPrefix: "demos"
});
const prefixedHexRootSigner: WalletAdapterLike = {
  address: "demo1example",
  pubKeyHex: "02".padEnd(66, "0"),
  signPrivacyRoot: () => "0xabc"
};
const explicitBase64RootSigner: WalletAdapterLike = {
  address: "demo1example",
  pubKeyHex: "02".padEnd(66, "0"),
  signPrivacyRoot: async () => ({ signatureBase64: "AQID" })
};
const unprefixedStringRootSigner: WalletAdapterLike = {
  address: "demo1example",
  pubKeyHex: "02".padEnd(66, "0"),
  // @ts-expect-error signPrivacyRoot plain strings are ambiguous; use 0x-prefixed hex or signatureBase64.
  signPrivacyRoot: async () => "ab".repeat(64)
};
const eip1193Wallet = createEip1193WalletAdapter({
  provider: {
    request: async () => "0xabc"
  }
});
const eip1193WalletAdapterLike: WalletAdapterLike = eip1193Wallet;
const eip1193TypedWallet: Eip1193WalletAdapter = eip1193Wallet;
const cosmos = createClairveilClient({
  rpc: "http://127.0.0.1:26657",
  rest: "http://127.0.0.1:1317",
  restEndpoints: ["http://127.0.0.1:1317"],
  chainId: "demo-1",
  accountPrefix: "demo",
  shieldedPrefix: "demos",
  defaultDenom: "udemo",
  queryTimeoutMs: 30000,
  queryRetry: {
    retries: 2,
    baseDelayMs: 250,
    maxDelayMs: 1500,
    jitter: true,
    retryStatuses: [408, 429, 502, 503, 504]
  },
  nullifierFailover: false
});
const publicClient = createClairveilPublicClient({
  rest: "http://127.0.0.1:1317",
  restEndpoints: ["http://127.0.0.1:1317"],
  queryTimeoutMs: 30000,
  queryRetry: false
});
const endpointSetOnlyCosmos = createClairveilClient({
  rpc: "http://127.0.0.1:26657",
  restEndpoints: ["http://127.0.0.1:1317", "http://127.0.0.2:1317"],
  chainId: "demo-1"
});
const endpointSetOnlyPublic = createClairveilPublicClient({
  restEndpoints: ["http://127.0.0.1:1317", "http://127.0.0.2:1317"]
});
publicClient.fetchPrivacyEvents({ limit: 10 });
publicClient.fetchScanEvents({ afterHeight: 1, afterSequence: 2, limit: 10 });
publicClient.fetchScanEvents({
  afterHeight: 9007199254740993n,
  afterSequence: "9007199254740993",
  limit: 10
});
publicClient.fetchAuditableTransfers({ eventTypes: ["shielded_transfer"] });
const publicNullifierBatch: Promise<Map<string, boolean>> = publicClient.checkNullifiers(["00".repeat(32)]);
const publicReserveResult: Promise<{ invariant_holds: boolean }> = publicClient.fetchReserve("udemo");
const publicFetchJsonResult: Promise<{ events?: object[] }> = publicClient.fetchJson<{ events?: object[] }>("/clairveil/privacy/v1/events");
const publicNullifierJsonResult: Promise<{ used?: boolean }> = publicClient.fetchNullifierJson<{ used?: boolean }>("/clairveil/privacy/v1/nullifiers/00");
const cosmosFetchJsonResult: Promise<{ events?: object[] }> = cosmos.fetchJson<{ events?: object[] }>("/clairveil/privacy/v1/events", {
  failover: true,
  retry: false,
  endpoint: "http://127.0.0.1:1317",
  updateActiveEndpoint: false
});
const cosmosNullifierJsonResult: Promise<{ used?: boolean }> = cosmos.fetchNullifierJson<{ used?: boolean }>("/clairveil/privacy/v1/nullifiers/00");
const cosmosScanEventLookup: Promise<object> = cosmos.findPrivacyEventByTxHash("aa", {
  afterSequence: 7,
  scanSource: "scan_events",
  maxPages: 3
});
const cosmosUserDisclosureLookup: Promise<DisclosureReport> = cosmos.decodeUserDisclosure({
  txHash: "aa",
  afterSequence: 7,
  scanSource: "scan_events"
});
const cosmosSelfViewDisclosureLookup: Promise<DisclosureReport> = cosmos.decodeSelfViewDisclosure({
  tx_hash: "aa",
  after_sequence: 7,
  scan_source: "scan_events"
});
const cosmosAuditDisclosureLookup: Promise<DisclosureReport> = cosmos.decodeAuditDisclosure({
  tx_hash: "aa",
  disclosure_privkey_hex: "01".repeat(32),
  after_sequence: 7,
  scan_source: "scan_events"
});
void cosmosScanEventLookup;
void cosmosUserDisclosureLookup;
void cosmosSelfViewDisclosureLookup;
void cosmosAuditDisclosureLookup;
const dappClient = createClairveilBrowserDappClient({
  rpc: "http://127.0.0.1:26657",
  rest: "http://127.0.0.1:1317",
  chainId: "demo-1",
  accountPrefix: "demo",
  shieldedPrefix: "demos",
  denom: "udemo",
  queryTimeoutMs: 30000,
  restEndpoints: ["http://127.0.0.1:1317"],
  queryRetry: { retries: 2 },
  nullifierFailover: false,
  proverUrl: "http://127.0.0.1:8080"
});
const evmProfileDappClient = createClairveilBrowserDappClient({
  profile: {
    transport: "evm",
    wallet: "metamask",
    chainId: "demo-evm-1",
    accountPrefix: "demo",
    shieldedPrefix: "demos",
    denom: "udemo",
    rest: "http://127.0.0.1:1317",
    restEndpoints: ["http://127.0.0.1:1317"],
    evmRpc: "http://127.0.0.1:8545",
    evmChainId: "0x539",
    evmPrivacyPrecompileAddress: "0x0000000000000000000000000000000000000900"
  },
  proverUrl: "http://127.0.0.1:8080"
});
const evmDirectDappClient = new ClairveilBrowserDappClient({
  profile: {
    transport: "evm",
    wallet: "metamask",
    chainId: "demo-evm-direct-1",
    accountPrefix: "demo",
    shieldedPrefix: "demos",
    denom: "udemo",
    rest: "http://127.0.0.1:1317",
    evmRpc: "http://127.0.0.1:8545",
    evmChainId: "0x540",
    evmPrivacyPrecompileAddress: "0x0000000000000000000000000000000000000900"
  },
  proverUrl: "http://127.0.0.1:8080"
});
createClairveilBrowserDappClient({
  profile: {
    // @ts-expect-error profile transport rejects unsupported values.
    transport: "evmm"
  }
});
const walletIdentity = {
  address: "demo1example",
  pubKeyHex: "02".padEnd(66, "0"),
  signatureBase64: "AQID"
};
const reservationManager = createNoteReservationManager({
  store: new MemoryReservationStore(),
  ownerKeyId: "demo-1:demo1example",
  indexKey: rootSeed
});
// @ts-expect-error reservation metadata is JSON-only and cannot persist bigint values.
reservationManager.reserveNotes({ metadata: { requestedAmount: 5n } });
// @ts-expect-error reservation managers require one owner identity alias.
createNoteReservationManager({
  store: new MemoryReservationStore(),
  indexKey: rootSeed
});
const reservationStoreForReplacementType = new MemoryReservationStore();
async function reservationReplacementTypeExample() {
  const reservation = await reservationManager.getReservation("reservation-id");
  return reservationStoreForReplacementType.unsafeReplaceReservation(reservation);
}
void reservationReplacementTypeExample;
// @ts-expect-error unsafeReplaceReservation requires a complete stored record rather than merging a patch.
reservationStoreForReplacementType.unsafeReplaceReservation({ reservation_id: "reservation-id" });
const rootReservationManager = createRootNoteReservationManager({
  store: new MemoryReservationStore(),
  ownerKeyId: "demo-1:demo1example",
  indexKey: rootSeed
});
const expectedRecipientHash: string = hashRecipient(shielded);
const customRecipientHash: string = hashRecipient(shielded, { shieldedPrefix: "demos" });
void customRecipientHash;
const expectedAmountHash: string = hashAmount("uclair", 42n);
// @ts-expect-error direct operation evidence is none-or-both, never one hash alone.
const incompleteBrowserOperationEvidence: BrowserDirectOperationEvidenceHashes = {
  expectedRecipientHash: "recipient-hash"
};
// @ts-expect-error Cosmos direct operation evidence follows the same none-or-both contract.
const incompleteCosmosOperationEvidence: CosmosDirectOperationEvidenceHashes = {
  expected_amount_hash: "amount-hash"
};
// @ts-expect-error batch operation evidence is none-or-complete; recipient hashes require amount hashes.
const incompleteBatchOperationEvidence: BatchOperationEvidenceHashes = {
  expectedRecipientHash: "recipient-hash"
};
void incompleteBrowserOperationEvidence;
void incompleteCosmosOperationEvidence;
void incompleteBatchOperationEvidence;
const unsafeReservationManager = createNoteReservationManager({
  store: new MemoryReservationStore(),
  ownerKeyId: "demo-1:demo1example",
  unsafeAllowPublicIndexKey: true
});
// @ts-expect-error reservation managers require an explicit persistence choice.
createNoteReservationManager({
  ownerKeyId: "demo-1:demo1example",
  indexKey: "private-index-key"
});
// @ts-expect-error reservation managers require indexKey unless unsafeAllowPublicIndexKey is true.
createNoteReservationManager({
  store: new MemoryReservationStore(),
  ownerKeyId: "demo-1:demo1example"
});
const availableNotes = reservationManager.filterAvailableNotes([]);
const rootAvailableNotes = rootReservationManager.filterAvailableNotes([]);
const unsafeAvailableNotes = unsafeReservationManager.filterAvailableNotes([]);
const heartbeatIntervalMs: number = reservationHeartbeatIntervalMs({
  leaseDurationMs: 1000,
  leaseUntil: "2026-01-02T03:04:06.000Z"
});
const renewedReservations = reservationManager.renewLease([], {
  leaseToken: "lease",
  leaseDurationMs: 60000
});
const proofReadyReservations = reservationManager.markProofReady([], {
  leaseToken: "lease",
  payloadHash: "payload-hash",
  expectedOutputCommitment: "output-commitment",
  expectedDisclosureDigest: "audit-disclosure-digest",
  expectedRecipientHash: "recipient-hash",
  expectedAmountHash: "amount-hash",
  expectedAmount: "100",
  expectedDenom: "udemo",
  batchItemIndex: 0,
  batchItemIndexKnown: true,
  operationSuccessEvidenceRequired: true
});
const attemptingReservations = reservationManager.markBroadcastAttempting([], {
  leaseToken: "lease",
  reason: "cosmos_broadcast_tx_sync"
});
const rejectedReservations = reservationManager.markBroadcastRejected([], {
  leaseToken: "lease",
  providerCode: 4001,
  error: "User rejected the request"
});
const submittedReservations = reservationManager.markSubmitted([], {
  leaseToken: "lease",
  txBytesHash: "ab".repeat(32)
});
const submittedAliasReservations = reservationManager.markSubmitted([], {
  leaseToken: "lease",
  submitted_tx_hash: "TX-ALIAS"
});
// @ts-expect-error markSubmitted requires txHash or txBytesHash; signDocHash alone can exist before broadcast.
reservationManager.markSubmitted([], {
  leaseToken: "lease",
  signDocHash: "sign-doc-only"
});
const unknownReservations = reservationManager.markUnknown([], {
  leaseToken: "lease",
  txBytesHash: "tx-bytes-broadcast-attempt",
  signDocHash: "supplemental-sign-doc"
});
const unknownAliasReservations = reservationManager.markUnknown([], {
  leaseToken: "lease",
  submitted_tx_hash: "TX-UNKNOWN-ALIAS"
});
// @ts-expect-error markUnknown requires txHash or txBytesHash evidence.
reservationManager.markUnknown([], {
  leaseToken: "lease",
  signDocHash: "sign-doc-only"
});
const replanReservations = reservationManager.markReplanRequired([], {
  txHash: "aa".repeat(32),
  nullifierUnspentConfirmed: true,
  txAbsentOrFailedConfirmed: true,
  checkedHeight: 123,
  txHashChecked: "aa".repeat(32),
  error: "receipt failed"
});
const manualReviewResolution = reservationManager.resolveManualReview([], {
  target: "ReplanRequired",
  operatorId: "ops@example.test",
  approvalReference: "case-421"
});
const depositInput: PrepareDepositInput = {
  ...walletIdentity,
  amount: "1udemo",
  proofHex: "ab"
};
const transferInput: PrepareCosmosTransferInput = {
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demos1recipient",
  privacyPolicy: "all-private",
  disclosureMode: "none",
  expectedRecipientHash: "recipient-hash",
  expectedAmountHash: "amount-hash",
  scan: {
    afterHeight: 0,
    limit: 200,
    maxPages: 1000
  },
  reservationManager
};
// @ts-expect-error Cosmos transfer evidence requires both recipient and amount hashes.
const invalidCosmosTransferEvidence: PrepareCosmosTransferInput = {
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demos1recipient",
  expectedRecipientHash: "recipient-hash"
};
// @ts-expect-error Explicit EVM transfer evidence requires both recipient and amount hashes.
const invalidEvmTransferEvidence: PrepareEvmTransferInput = {
  ...walletIdentity,
  walletType: "evm",
  amount: "1udemo",
  recipient: "demos1recipient",
  expectedAmountHash: "amount-hash"
};
// @ts-expect-error Default EVM profile transfer evidence requires both hashes.
const invalidDefaultEvmTransferEvidence: PrepareDefaultEvmProfileTransferInput = {
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demos1recipient",
  expectedRecipientHash: "recipient-hash"
};
const withdrawInput: PrepareCosmosWithdrawInput = {
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demo1recipient",
  scan: {
    afterHeight: 0,
    limit: 200,
    maxPages: 1000
  },
  reservationManager
};
const relayWithdrawInput: PrepareRelayWithdrawInput = {
  ...withdrawInput,
  expiresAtUnix: 4102448400,
  chainNowUnix: 4102444800
};
const cosmosRelayWithdrawInput: PrepareCosmosRelayWithdrawInput = {
  ...withdrawInput,
  expiresAtUnix: 4102448400,
  chain_now_unix: 4102444800
};
// @ts-expect-error Cosmos relay preparation requires authoritative chain time.
const missingCosmosRelayChainTime: PrepareCosmosRelayWithdrawInput = {
  ...withdrawInput,
  expiresAtUnix: 4102448400
};
void missingCosmosRelayChainTime;
const scanInput: ScanWalletNotesInput = {
  ...walletIdentity,
  limit: 50,
  maxPages: 3,
  afterHeight: 12,
  page: 2,
  eventTypes: ["deposit", "shielded_transfer"],
  includeFoundNotes: true
};
// @ts-expect-error walletType rejects misspellings.
const invalidWalletType: PrepareDepositInput = { ...walletIdentity, walletType: "evmm", amount: "1udemo" };
// @ts-expect-error Cosmos deposit requires proof/proofHex/depositProofProvider.
const invalidCosmosDepositInput: PrepareDepositInput = { ...walletIdentity, amount: "1udemo" };
const evmCompatibleDepositInput: PrepareDepositInput = { ...walletIdentity, walletType: "evm", amount: "1udemo" };
const evmProfileDepositInput: PrepareDepositInput<"evm"> = { ...walletIdentity, amount: "1udemo" };
const depositResult: Promise<PreparedCosmosDeposit> = dappClient.prepareDeposit(depositInput);
const evmProfileDepositResult: Promise<PreparedEvmDeposit> = evmProfileDappClient.prepareDeposit(evmProfileDepositInput);
const evmProfileInlineDepositResult: Promise<PreparedEvmDeposit> = evmProfileDappClient.prepareDeposit({
  ...walletIdentity,
  amount: "1udemo"
});
const evmProfileInlineDepositWithProofResult: Promise<PreparedEvmDeposit> = evmProfileDappClient.prepareDeposit({
  ...walletIdentity,
  amount: "1udemo",
  proofHex: "ab"
});
const evmDirectInlineDepositResult: Promise<PreparedEvmDeposit> = evmDirectDappClient.prepareDeposit({
  ...walletIdentity,
  amount: "1udemo"
});
const depositUnionResult: Promise<PreparedDeposit> = dappClient.prepareDeposit(depositInput);
const cosmosTransferResult: Promise<PreparedCosmosTransfer> = dappClient.prepareTransfer(transferInput);
const cosmosInlineTransferResult: Promise<PreparedCosmosTransfer> = dappClient.prepareTransfer({
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demos1recipient"
});
const evmProfileTransferResult: Promise<PreparedEvmTransfer> = evmProfileDappClient.prepareTransfer({
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demos1recipient"
});
const evmDirectTransferResult: Promise<PreparedEvmTransfer> = evmDirectDappClient.prepareTransfer({
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demos1recipient"
});
const transferResult: Promise<PreparedTransfer> = dappClient.prepareTransfer(transferInput);
const transferBatchInput: PrepareCosmosTransferBatchInput = {
  ...walletIdentity,
  amounts: ["1udemo", "2udemo"],
  recipient: "demos1recipient",
  expectedRecipientHash: "recipient-hash",
  expectedAmountHashes: ["amount-hash-0", "amount-hash-1"]
};
// @ts-expect-error Cosmos batch evidence requires recipient and amount hash inputs together.
const invalidCosmosBatchEvidence: PrepareCosmosTransferBatchInput = {
  ...walletIdentity,
  amounts: ["1udemo"],
  recipient: "demos1recipient",
  expectedRecipientHash: "recipient-hash"
};
const cosmosTransferBatchResult: Promise<PreparedCosmosTransferBatch> = dappClient.prepareTransferBatch(transferBatchInput);
const explicitCosmosTransferBatchInput: PrepareExplicitCosmosTransferBatchInput = {
  ...walletIdentity,
  walletType: "cosmos",
  amounts: ["1udemo"],
  recipient: "demos1recipient",
  expected_recipient_hash: "recipient-hash",
  expected_amount_hashes: ["amount-hash-0"]
};
// @ts-expect-error Explicit Cosmos batch evidence requires recipient and amount hashes together.
const invalidExplicitCosmosBatchEvidence: PrepareExplicitCosmosTransferBatchInput = {
  ...walletIdentity,
  walletType: "cosmos",
  amounts: ["1udemo"],
  recipient: "demos1recipient",
  expectedAmountHashes: ["amount-hash-0"]
};
const evmProfileExplicitCosmosBatchResult: Promise<PreparedCosmosTransferBatch> = evmProfileDappClient.prepareTransferBatch(explicitCosmosTransferBatchInput);
// @ts-expect-error EVM-default browser clients require explicit walletType: "cosmos" for batch transfer.
evmProfileDappClient.prepareTransferBatch({
  ...walletIdentity,
  amounts: ["1udemo"],
  recipient: "demos1recipient"
});
const cosmosWithdrawResult: Promise<PreparedCosmosWithdraw> = dappClient.prepareWithdraw(withdrawInput);
const cosmosInlineWithdrawResult: Promise<PreparedCosmosWithdraw> = dappClient.prepareWithdraw({
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demo1recipient"
});
const evmProfileWithdrawResult: Promise<PreparedEvmWithdraw> = evmProfileDappClient.prepareWithdraw({
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demo1recipient"
});
const evmDirectWithdrawResult: Promise<PreparedEvmWithdraw> = evmDirectDappClient.prepareWithdraw({
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demo1recipient"
});
const withdrawResult: Promise<PreparedWithdraw> = dappClient.prepareWithdraw(withdrawInput);
const cosmosWithdrawPayload: Promise<PreparedWithdrawPayload> = cosmosWithdrawResult.then(result => result.payload);
const cosmosWithdrawMessage: Promise<WithdrawMessage> = cosmosWithdrawResult.then(result => result.message);
const evmWithdrawPayload: Promise<PreparedWithdrawPayload> = evmDirectWithdrawResult.then(result => result.payload);
void cosmosWithdrawPayload;
void cosmosWithdrawMessage;
void evmWithdrawPayload;
const cosmosRelayWithdrawResult: Promise<PreparedCosmosRelayWithdraw> = dappClient.prepareRelayWithdraw(cosmosRelayWithdrawInput);
const legacyTimeRelayWithdrawResult: Promise<PreparedCosmosRelayWithdraw> = dappClient.prepareRelayWithdraw({
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demo1recipient",
  nowUnix: 4102444800
});
void legacyTimeRelayWithdrawResult;
const evmProfileRelayWithdrawResult: Promise<PreparedEvmRelayWithdraw> = evmProfileDappClient.prepareRelayWithdraw({
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demo1recipient",
  chainNowUnix: 4102444800,
  transactionOptions: { value: "0x0" }
});
const evmDirectRelayWithdrawInput: PrepareEvmRelayWithdrawInput = {
  ...walletIdentity,
  walletType: "evm",
  amount: "1udemo",
  recipient: "demo1recipient",
  chain_now_unix: 4102444800,
  transaction_options: { value: "0x0" }
};
const evmDirectRelayWithdrawResult: Promise<PreparedEvmRelayWithdraw> = evmDirectDappClient.prepareRelayWithdraw(evmDirectRelayWithdrawInput);
const relayWithdrawResult: Promise<PreparedRelayWithdraw> = dappClient.prepareRelayWithdraw(relayWithdrawInput);
const transferReservation: ReservationBatch | null | undefined = (null as unknown as PreparedTransfer).reservation;
const transferPreparedReservation: ReservationBatch | null | undefined = (null as unknown as PreparedTransfer).prepared.reservation;
const withdrawPreparedReservation: ReservationBatch | null | undefined = (null as unknown as PreparedWithdraw).prepared.reservation;
const reservationNotesResult: Promise<object[]> = availableNotes;
const scanResult: Promise<ScanWalletNotesResult> = dappClient.scanWalletNotes(scanInput);
const nullifierResult: Promise<object & { used?: boolean }> = dappClient.checkNullifier("00".repeat(32));
const nullifierBatchResult: Promise<Map<string, boolean>> = dappClient.checkNullifiers(["00".repeat(32)]);
const dappReserveResult: Promise<ReserveResponse> = dappClient.fetchReserve("udemo");
const auditDisclosureInput: DecodeAuditDisclosureInput = {
  txHash: "aa",
  disclosurePrivKeyHex: "01".repeat(32)
};
const auditDisclosureResult: Promise<DisclosureReport> = dappClient.decodeAuditDisclosure(auditDisclosureInput);
const selfViewDisclosureInput: DecodeSelfViewDisclosureInput = {
  txHash: "aa",
  disclosureScalarHex: "01".repeat(32)
};
const selfViewDisclosureResult: Promise<DisclosureReport> = dappClient.decodeSelfViewDisclosure(selfViewDisclosureInput);
const batchPlan = planTransferBatchNotes({ notes: [], amounts: ["1udemo"], denom: "udemo" });
const batchPlanReady: boolean = batchPlan.canBuildTx;
const conformanceResult = runClairveilConformanceFixtures({
  fixtureNames: ["privacy_wallet_golden_vectors.json"]
});
const cosmosReserveResult: Promise<ReserveResponse> = cosmos.fetchReserve("udemo");
const cosmosPreparedTransfer = null as unknown as CosmosPreparedTransfer;
const cosmosPreparedTransferPlanAction: string = cosmosPreparedTransfer.prepared?.planAction ?? "";
// @ts-expect-error Cosmos prepared transfer summary does not expose built payload artifacts.
cosmosPreparedTransfer.prepared?.payload;
const cosmosPreparedTransferBatch = cosmos.prepareTransferBatch({
  material,
  amounts: ["1udemo", "2udemo"],
  recipient: "demos1recipient",
  proverAdapter: undefined as never,
  afterHeight: 10,
  afterSequence: 11,
  expectedRecipientHash: "recipient-hash",
  expectedAmountHashes: ["amount-hash-0", "amount-hash-1"],
  reservationManager
});
cosmos.prepareTransfer({
  material,
  amount: "1udemo",
  recipient: "demos1recipient",
  proverAdapter: undefined as never,
  after_height: 20,
  after_sequence: 21
});
cosmos.prepareWithdraw({
  material,
  amount: "1udemo",
  recipient: "demo1recipient",
  proverAdapter: undefined as never,
  afterHeight: 30,
  afterSequence: 31
});
cosmos.prepareWithdraw({
  material,
  amount: "1udemo",
  recipient: "demo1recipient",
  proverAdapter: undefined as never,
  chainNowUnix: 4102444800
}).then(result => {
  if (result.status === "ready") {
    const readyPayload: PreparedWithdrawPayload = result.payload;
    cosmos.signDirectAndBroadcast({
      wallet: prefixedHexRootSigner,
      signDoc: result.signDoc,
      relayPayload: readyPayload,
      getChainNowUnix: async () => 4102444800
    });
  } else {
    // @ts-expect-error Non-ready withdraw results do not expose a sign doc.
    const signDoc: SignDocBase64 = result.signDoc;
    void signDoc;
  }
});
cosmos.prepareRelayWithdraw({
  material,
  amount: "1udemo",
  recipient: "demo1recipient",
  proverAdapter: undefined as never,
  after_height: 40,
  after_sequence: 41,
  expiresAtUnix: 4102448400,
  chainNowUnix: 4102444800
});
const cosmosPreparedTransferBatchReady: Promise<string> = cosmosPreparedTransferBatch.then(result => result.status);
const nativeSendTx = evmProfileDappClient.evmNativeSendTransaction({
  to: "0x1111111111111111111111111111111111111111",
  amount: "1udemo"
});
const relayBroadcastPayload = {} as PreparedWithdrawPayload;
const nativeSendResult: Promise<string> = createClairveilEvmClient().sendTransaction(null, nativeSendTx);
const reservationBoundEvmSendResult: Promise<string> = createClairveilEvmClient().sendTransaction(
  null,
  nativeSendTx,
  { reservationManager, reservation: {} as ReservationBatch }
);
const reservationBatchBoundEvmSendResult: Promise<string> = createClairveilEvmClient().sendTransaction(
  null,
  nativeSendTx,
  { reservationManager, reservationBatch: {} as ReservationBatch }
);
const snakeReservationBatchBoundEvmSendResult: Promise<string> = createClairveilEvmClient().sendTransaction(
  null,
  nativeSendTx,
  { reservation_manager: reservationManager, reservation_batch: {} as ReservationBatch }
);
createClairveilEvmClient().sendTransaction(null, nativeSendTx, {
  relayPayload: relayBroadcastPayload,
  getChainNowUnix: async () => 4102444800
});
// @ts-expect-error relay EVM broadcasts require authoritative chain time at the submission boundary.
createClairveilEvmClient().sendTransaction(null, nativeSendTx, { relayPayload: relayBroadcastPayload });
const cleanInitialReservation: InitialNoteReservationRecord = {
  reservation_id: "reservation-a",
  owner_key_id: "chain:demo1owner",
  nullifier_lookup_key: "lookup-a",
  note_id: "note-a"
};
void cleanInitialReservation;
const aliasedInitialReservation: InitialNoteReservationRecord = {
  reservationId: "reservation-b",
  ownerKeyId: "chain:demo1owner",
  nullifierLookupKey: "lookup-b"
};
void aliasedInitialReservation;
// @ts-expect-error initial records require reservation, owner, and lookup-key identity.
const incompleteInitialReservation: InitialNoteReservationRecord = { note_id: "note-a" };
void incompleteInitialReservation;
const forgedInitialReservation: InitialNoteReservationRecord = {
  reservation_id: "reservation-a",
  owner_key_id: "chain:demo1owner",
  nullifier_lookup_key: "lookup-a",
  // @ts-expect-error success evidence is written only during the managed ProofReady transition.
  expected_output_commitment: "forged"
};
void forgedInitialReservation;

const legacyFoundNote: FoundNote = {
  note: {
    receiverSpendPubKeyX: 1n,
    receiverSpendPubKeyY: 2n,
    receiverViewPubKeyX: 3n,
    receiverViewPubKeyY: 4n,
    amount: 5n,
    assetID: 7n,
    randomness: 8n,
    memo: ""
  },
  nullifier: "11".repeat(32),
  isSpent: false,
  txHash: "AABB",
  height: 1,
  sequence: 0
};
const preciseFoundNote: FoundNote = {
  ...legacyFoundNote,
  height: "9007199254740993",
  sequence: "9007199254740995"
};
const structuredNullifierStatusReader: NullifierStatusReader = async nullifiers =>
  new Map(nullifiers.map(nullifier => [nullifier, { used: false }]));
const synchronousNullifierStatusReader: NullifierStatusReader = nullifiers =>
  new Map(nullifiers.map(nullifier => [nullifier, { used: false }]));
const publicClientNullifierStatusReader: NullifierStatusReader = publicClient.checkNullifiers.bind(publicClient);
const cosmosClientNullifierStatusReader: NullifierStatusReader = cosmos.checkNullifiers.bind(cosmos);
const dappClientNullifierStatusReader: NullifierStatusReader = dappClient.checkNullifiers.bind(dappClient);
// @ts-expect-error A structured nullifier result must include a literal boolean status.
const missingNullifierUsageReader: NullifierStatusReader = async () => new Map([["00", {}]]);
// @ts-expect-error A status-row result must include a literal boolean status.
const missingStatusRowUsageReader: NullifierStatusReader = async nullifiers => ({ statuses: [{ nullifier: nullifiers[0] }] });
// @ts-expect-error Canonical and alias status fields cannot both be supplied.
const conflictingNullifierAliasReader: NullifierStatusReader = async nullifiers => new Map(nullifiers.map(nullifier => [nullifier, { used: false, Used: false }]));
scanNotes({
  rootSeed,
  checkNullifiers: async nullifiers =>
    new Map(nullifiers.map(nullifier => [nullifier, { Used: false }]))
});
scanNotes({
  rootSeed,
  checkNullifiers: nullifiers =>
    new Map(nullifiers.map(nullifier => [nullifier, { Used: false }]))
});
void structuredNullifierStatusReader;
void synchronousNullifierStatusReader;
void publicClientNullifierStatusReader;
void cosmosClientNullifierStatusReader;
void dappClientNullifierStatusReader;
void preciseFoundNote;
void missingNullifierUsageReader;
void missingStatusRowUsageReader;
void conflictingNullifierAliasReader;
planTransferBatchNotes({ notes: [legacyFoundNote], amounts: ["1udemo"] });
// @ts-expect-error reserved-note broadcasts require both manager and reservation batch.
createClairveilEvmClient().sendTransaction(null, nativeSendTx, { reservationManager });
const reservationBoundCosmosBroadcast = cosmos.broadcastSignedTx(
  { bodyBytes: "" as never, authInfoBytes: "" as never, signature: "" as never },
  { reservationManager, reservation: {} as ReservationBatch }
);
const reservationBatchBoundCosmosBroadcast = cosmos.broadcastSignedTx(
  { bodyBytes: "" as never, authInfoBytes: "" as never, signature: "" as never },
  { reservationManager, reservationBatch: {} as ReservationBatch }
);
const reservationSnakeBatchBoundCosmosBroadcast = cosmos.broadcastSignedTx(
  { bodyBytes: "" as never, authInfoBytes: "" as never, signature: "" as never },
  { reservation_manager: reservationManager, reservation_batch: {} as ReservationBatch }
);
cosmos.broadcastSignedTx(
  { bodyBytes: "" as never, authInfoBytes: "" as never, signature: "" as never },
  { relayPayload: relayBroadcastPayload, chainNowUnix: 4102444800 }
);
cosmos.buildRelayWithdrawMessageFromPayload({
  payload: relayBroadcastPayload,
  relayer: "demo1relayer",
  nowUnix: 4102444800
});
cosmos.createRelayWithdrawSignDoc({
  payload: relayBroadcastPayload,
  relayer: "demo1relayer",
  pubKeyHex: "02".padEnd(66, "0"),
  nowUnix: 4102444800
});
cosmos.broadcastSignedTx(
  { bodyBytes: "" as never, authInfoBytes: "" as never, signature: "" as never },
  // @ts-expect-error relay Cosmos broadcasts require authoritative chain time at the submission boundary.
  { relayPayload: relayBroadcastPayload }
);
cosmos.broadcastSignedTx(
  { bodyBytes: "" as never, authInfoBytes: "" as never, signature: "" as never },
  // @ts-expect-error reserved-note broadcasts require both manager and reservation batch.
  { reservationManager }
);
const generatedMsgDepositWithExtension: GeneratedMsgDepositWithExtension = {
  creator: "demo1example",
  amount: "1udemo",
  noteCommitment: new Uint8Array(32),
  encryptedNote: new Uint8Array(),
  proof: new Uint8Array()
};
void generatedMsgDepositWithExtension;

async function browserDappTypeSmoke() {
  const cosmosDeposit = await depositResult;
  const cosmosDepositAmount: string = cosmosDeposit.prepared.amount;
  const cosmosDepositSignChain: string = cosmosDeposit.signDoc.chainId;
  void cosmosDepositAmount;
  void cosmosDepositSignChain;

  const evmDeposit = await evmProfileDepositResult;
  const evmDepositTo: string = evmDeposit.transaction.to;
  const evmDepositWithProof = await evmProfileInlineDepositWithProofResult;
  const evmDepositWithProofTo: string = evmDepositWithProof.transaction.to;
  void evmDepositTo;
  void evmDepositWithProofTo;

  const deposit = await depositUnionResult;
  const depositAmount: string = deposit.prepared.amount;
  if (deposit.transaction) {
    const depositTo: string = deposit.transaction.to;
    void depositTo;
  } else {
    const depositSignChain: string = deposit.signDoc.chainId;
    void depositSignChain;
  }

  const transfer = await transferResult;
  const transferStatus: string = transfer.plan.status;
  const transferRecipient: string = transfer.prepared.finalRecipient;

  const cosmosTransfer = await cosmosTransferResult;
  const cosmosTransferSignChain: string = cosmosTransfer.signDoc.chainId;
  const cosmosInlineTransfer = await cosmosInlineTransferResult;
  const cosmosInlineTransferSignChain: string = cosmosInlineTransfer.signDoc.chainId;
  const evmProfileTransfer = await evmProfileTransferResult;
  const evmProfileTransferTo: string = evmProfileTransfer.transaction.to;
  const evmDirectTransfer = await evmDirectTransferResult;
  const evmDirectTransferTo: string = evmDirectTransfer.transaction.to;

  const withdraw = await withdrawResult;
  const withdrawRecipient: string = withdraw.prepared.recipient;
  const withdrawExpiry: number = withdraw.prepared.expiresAtUnix;

  const cosmosWithdraw = await cosmosWithdrawResult;
  const cosmosWithdrawSignChain: string = cosmosWithdraw.signDoc.chainId;
  const cosmosInlineWithdraw = await cosmosInlineWithdrawResult;
  const cosmosInlineWithdrawSignChain: string = cosmosInlineWithdraw.signDoc.chainId;
  const evmProfileWithdraw = await evmProfileWithdrawResult;
  const evmProfileWithdrawTo: string = evmProfileWithdraw.transaction.to;
  const evmDirectWithdraw = await evmDirectWithdrawResult;
  const evmDirectWithdrawTo: string = evmDirectWithdraw.transaction.to;

  const relayWithdraw = await relayWithdrawResult;
  const relayWithdrawPayloadHash: string = relayWithdraw.payload.payload_hash;
  const evmRelayWithdraw = await evmProfileRelayWithdrawResult;
  const evmRelayWithdrawTo: string = evmRelayWithdraw.transaction.to;
  const evmRelayWithdrawRecipient: string | undefined = evmRelayWithdraw.prepared.message?.evmRecipient;
  const relaySignDocResult: Promise<PreparedRelayWithdrawSignDoc> = dappClient.createRelayWithdrawSignDoc({
    payload: relayWithdraw.payload,
    address: "demo1relayer",
    pubKeyHex: "02".padEnd(66, "0"),
    chainNowUnix: 4102444800
  });
  dappClient.buildRelayWithdrawMessageFromPayload({
    payload: relayWithdraw.payload,
    address: "demo1relayer",
    pubKeyHex: "02".padEnd(66, "0"),
    now_unix: 4102444800
  });
  const relaySignDoc = await relaySignDocResult;
  const relaySigner: string = relaySignDoc.relayer;

  const scan = await scanResult;
  const spendableTotal: string = scan.summary.total_spendable;
  const nextScanAfterHeight: number | string = scan.nextScanOptions.afterHeight;
  const nullifier = await nullifierResult;
  const nullifierUsed: boolean | undefined = nullifier.used;
  const dappReserve = await dappReserveResult;
  const dappReserveInvariant: boolean = dappReserve.invariant_holds;
  const cosmosReserve = await cosmosReserveResult;
  const cosmosReserveDenom: string = cosmosReserve.denom;
  const publicReserve = await publicReserveResult;
  const publicReserveInvariant: boolean = publicReserve.invariant_holds;
  const auditDisclosure = await auditDisclosureResult;
  const auditVerified: boolean = auditDisclosure.verified;
  const conformance = await conformanceResult;
  const conformanceSkipped: boolean = conformance.skipped;

  void {
    depositAmount,
    transferStatus,
    transferRecipient,
    cosmosTransferSignChain,
    cosmosInlineTransferSignChain,
    evmProfileTransferTo,
    evmDirectTransferTo,
    withdrawRecipient,
    withdrawExpiry,
    cosmosWithdrawSignChain,
    cosmosInlineWithdrawSignChain,
    evmProfileWithdrawTo,
    evmDirectWithdrawTo,
    relayWithdrawPayloadHash,
    evmRelayWithdrawTo,
    evmRelayWithdrawRecipient,
    relaySigner,
    spendableTotal,
    nextScanAfterHeight,
    nullifierUsed,
    dappReserveInvariant,
    cosmosReserveDenom,
    publicReserveInvariant,
    auditVerified,
    conformanceSkipped,
    cosmosPreparedTransferPlanAction
  };
}

const evm = createClairveilEvmClient({
  contractAddress: "0x1111111111111111111111111111111111111111",
  chainId: "0x539",
  shieldedPrefix: "demos",
  defaultDenom: "udemo"
});
evm.buildDepositTransaction({ amount: "1udemo" });
const selector: string = functionSelector("deposit((string,bytes,bytes))");
const evmPrecompileAddress: string = evmPrivacyPrecompileAddress;
const bech32: string = evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo");
const evmAddress: string = bech32AddressToEvm(bech32, "demo");
const evmExistingTransferMessage = {
  creator: "demo1example",
  proof: new Uint8Array([1]),
  root: new Uint8Array(32),
  nullifiers: [new Uint8Array(32), new Uint8Array(32)],
  newCommitments: [new Uint8Array(32), new Uint8Array(32)],
  cipherTexts: [new Uint8Array([1]), new Uint8Array([2])],
  viewTags: [new Uint8Array([3, 4]), new Uint8Array([5, 6])],
  userPrivacyPolicy: 0,
  userDisclosureDigest: new Uint8Array(),
  userDisclosureMode: 0,
  userDisclosureTargetPubkey: new Uint8Array(),
  userDisclosurePayload: new Uint8Array(),
  auditDisclosureDigest: new Uint8Array(),
  auditDisclosureTargetPubkey: new Uint8Array(),
  auditDisclosurePayload: new Uint8Array(),
  selfViewDisclosureDigest: new Uint8Array(),
  selfViewDisclosurePayload: new Uint8Array()
};
const evmExistingWithdrawMessage = {
  creator: "demo1example",
  proof: new Uint8Array([1]),
  root: new Uint8Array(32),
  nullifier: new Uint8Array(32),
  amount: "1udemo",
  recipient: evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo"),
  chainId: "demo-1",
  expiresAtUnix: 4102448400n
};
const evmTransferTransactionResult = evm.buildTransferTransaction({ message: evmExistingTransferMessage });
const evmWithdrawTransactionResult = evm.buildWithdrawTransaction({ message: evmExistingWithdrawMessage });
evm.buildTransferTransaction({
  inputs: [],
  proverAdapter: undefined as never,
  checkNullifiers: async () => new Map()
});
// @ts-expect-error Direct EVM transfer proof generation requires nullifier verification.
evm.buildTransferTransaction({ inputs: [], proverAdapter: undefined as never });
evm.buildWithdrawTransaction({
  notes: [],
  proverAdapter: undefined as never,
  checkNullifiers: async () => new Map()
});
// @ts-expect-error Direct EVM withdraw proof generation requires nullifier verification.
evm.buildWithdrawTransaction({ notes: [], proverAdapter: undefined as never });
const relayPayloadForTypeCheck = {} as PreparedWithdrawPayload;
evm.buildWithdrawTransaction({
  payload: relayPayloadForTypeCheck,
  chainNowUnix: 4102444800
});
evm.buildWithdrawTransaction({
  payload: relayPayloadForTypeCheck,
  nowUnix: 4102444800
});
evm.buildWithdrawTransaction({
  payload: relayPayloadForTypeCheck,
  now_unix: 4102444800
});
evm.buildWithdrawTransaction({
  message: evmExistingWithdrawMessage,
  payload: relayPayloadForTypeCheck
});
// @ts-expect-error Relay payload builds require an explicit chain time.
evm.buildWithdrawTransaction({ payload: relayPayloadForTypeCheck });

async function evmTransactionTypeSmoke() {
  const transfer = await evmTransferTransactionResult;
  const transferMessage = transfer.message;
  const maybeTransferPayload = transfer.payload;
  const maybeTransferProof = transfer.proof;
  const withdraw = await evmWithdrawTransactionResult;
  const withdrawMessage = withdraw.message;
  const maybeWithdrawPayload = withdraw.payload;
  const maybeWithdrawProof = withdraw.proof;
  const maybeWithdrawProverPayload = withdraw.proverPayload;
  const maybeWithdrawSelectedNote = withdraw.selectedNote;

  void {
    transferMessage,
    maybeTransferPayload,
    maybeTransferProof,
    withdrawMessage,
    maybeWithdrawPayload,
    maybeWithdrawProof,
    maybeWithdrawProverPayload,
    maybeWithdrawSelectedNote
  };
}

void {
  shielded,
  material,
  cosmos,
  publicClient,
  dappClient,
  evmProfileDappClient,
  evmDirectDappClient,
  depositInput,
  evmProfileDepositInput,
  transferInput,
  withdrawInput,
  relayWithdrawInput,
  scanInput,
  auditDisclosureInput,
  invalidWalletType,
  invalidCosmosDepositInput,
  evmCompatibleDepositInput,
  depositResult,
  evmProfileDepositResult,
  evmProfileInlineDepositResult,
  evmDirectInlineDepositResult,
  transferResult,
  withdrawResult,
  relayWithdrawResult,
  renewedReservations,
  proofReadyReservations,
  replanReservations,
  manualReviewResolution,
  scanResult,
  dappReserveResult,
  publicFetchJsonResult,
  cosmosFetchJsonResult,
  auditDisclosureResult,
  conformanceResult,
  cosmosReserveResult,
  publicReserveResult,
  endpointSetOnlyCosmos,
  endpointSetOnlyPublic,
  browserDappTypeSmoke,
  evmTransactionTypeSmoke,
  evm,
  selector,
  evmPrecompileAddress,
  bech32,
  evmAddress
};
