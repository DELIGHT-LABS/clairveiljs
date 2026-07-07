import { deriveShieldedAddress, derivePrivacyMaterial } from "clairveiljs/core";
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
  type PrepareTransferInput,
  type PrepareCosmosTransferInput,
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
import { runClairveilConformanceFixtures } from "clairveiljs/conformance";
import {
  createClairveilClient,
  type PreparedTransfer as CosmosPreparedTransfer,
  type ReserveResponse
} from "clairveiljs/cosmos";
import { planTransferBatchNotes } from "clairveiljs/planner";
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
publicClient.fetchAuditableTransfers({ eventTypes: ["shielded_transfer"] });
const publicNullifierBatch: Promise<Map<string, boolean>> = publicClient.checkNullifiers(["00".repeat(32)]);
const publicReserveResult: Promise<{ invariant_holds: boolean }> = publicClient.fetchReserve("udemo");
const publicFetchJsonResult: Promise<{ events?: object[] }> = publicClient.fetchJson<{ events?: object[] }>("/clairveil/privacy/v1/events");
const cosmosFetchJsonResult: Promise<{ events?: object[] }> = cosmos.fetchJson<{ events?: object[] }>("/clairveil/privacy/v1/events", {
  failover: true,
  retry: false
});
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
  scan: {
    afterHeight: 0,
    limit: 200,
    maxPages: 1000
  }
};
const withdrawInput: PrepareCosmosWithdrawInput = {
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demo1recipient",
  scan: {
    afterHeight: 0,
    limit: 200,
    maxPages: 1000
  }
};
const relayWithdrawInput: PrepareRelayWithdrawInput = {
  ...withdrawInput,
  expiresAtUnix: 4102448400
};
const cosmosRelayWithdrawInput: PrepareCosmosRelayWithdrawInput = {
  ...withdrawInput,
  expiresAtUnix: 4102448400
};
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
  recipient: "demos1recipient"
};
const cosmosTransferBatchResult: Promise<PreparedCosmosTransferBatch> = dappClient.prepareTransferBatch(transferBatchInput);
const explicitCosmosTransferBatchInput: PrepareExplicitCosmosTransferBatchInput = {
  ...walletIdentity,
  walletType: "cosmos",
  amounts: ["1udemo"],
  recipient: "demos1recipient"
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
const cosmosRelayWithdrawResult: Promise<PreparedCosmosRelayWithdraw> = dappClient.prepareRelayWithdraw(cosmosRelayWithdrawInput);
const evmProfileRelayWithdrawResult: Promise<PreparedEvmRelayWithdraw> = evmProfileDappClient.prepareRelayWithdraw({
  ...walletIdentity,
  amount: "1udemo",
  recipient: "demo1recipient",
  transactionOptions: { value: "0x0" }
});
const evmDirectRelayWithdrawInput: PrepareEvmRelayWithdrawInput = {
  ...walletIdentity,
  walletType: "evm",
  amount: "1udemo",
  recipient: "demo1recipient",
  transaction_options: { value: "0x0" }
};
const evmDirectRelayWithdrawResult: Promise<PreparedEvmRelayWithdraw> = evmDirectDappClient.prepareRelayWithdraw(evmDirectRelayWithdrawInput);
const relayWithdrawResult: Promise<PreparedRelayWithdraw> = dappClient.prepareRelayWithdraw(relayWithdrawInput);
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
  proverAdapter: undefined as never
});
const cosmosPreparedTransferBatchReady: Promise<string> = cosmosPreparedTransferBatch.then(result => result.status);
const nativeSendTx = evmProfileDappClient.evmNativeSendTransaction({
  to: "0x1111111111111111111111111111111111111111",
  amount: "1udemo"
});
const nativeSendResult: Promise<string> = createClairveilEvmClient().sendTransaction(null, nativeSendTx);
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
    pubKeyHex: "02".padEnd(66, "0")
  });
  const relaySignDoc = await relaySignDocResult;
  const relaySigner: string = relaySignDoc.relayer;

  const scan = await scanResult;
  const spendableTotal: string = scan.summary.total_spendable;
  const nextScanAfterHeight: number = scan.nextScanOptions.afterHeight;
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
