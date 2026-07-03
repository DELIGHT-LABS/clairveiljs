import { deriveShieldedAddress, derivePrivacyMaterial } from "clairveiljs/core";
import { createClairveilPublicClient } from "clairveiljs/browser-public";
import {
  createClairveilBrowserDappClient,
  type DecodeAuditDisclosureInput,
  type PrepareDepositInput,
  type PreparedDeposit,
  type PrepareRelayWithdrawInput,
  type PreparedRelayWithdraw,
  type PreparedRelayWithdrawSignDoc,
  type PrepareTransferInput,
  type PreparedTransfer,
  type PrepareWithdrawInput,
  type PreparedWithdraw,
  type ScanWalletNotesInput,
  type ScanWalletNotesResult
} from "clairveiljs/browser-dapp";
import type { DisclosureReport } from "clairveiljs/disclosure";
import { runClairveilConformanceFixtures } from "clairveiljs/conformance";
import { createClairveilClient } from "clairveiljs/cosmos";
import {
  bech32AddressToEvm,
  createClairveilEvmClient,
  evmAddressToBech32,
  functionSelector,
  evmPrivacyPrecompileAddress
} from "clairveiljs/evm";
import type { MsgDeposit as GeneratedMsgDepositWithExtension } from "clairveiljs/generated/clairveil/privacy/v1/tx.js";

const rootSeed = new Uint8Array(32);
const shielded: string = deriveShieldedAddress(rootSeed, { shieldedPrefix: "demos" });
const material = derivePrivacyMaterial({
  address: "demo1example",
  pubKeyHex: "02".padEnd(66, "0"),
  signatureBase64: "AQID",
  shieldedPrefix: "demos"
});
const cosmos = createClairveilClient({
  rpc: "http://127.0.0.1:26657",
  rest: "http://127.0.0.1:1317",
  chainId: "demo-1",
  accountPrefix: "demo",
  shieldedPrefix: "demos",
  defaultDenom: "udemo"
});
const publicClient = createClairveilPublicClient({
  rest: "http://127.0.0.1:1317"
});
publicClient.fetchPrivacyEvents({ limit: 10 });
publicClient.fetchAuditableTransfers({ eventTypes: ["shielded_transfer"] });
const dappClient = createClairveilBrowserDappClient({
  rpc: "http://127.0.0.1:26657",
  rest: "http://127.0.0.1:1317",
  chainId: "demo-1",
  accountPrefix: "demo",
  shieldedPrefix: "demos",
  denom: "udemo",
  proverUrl: "http://127.0.0.1:8080"
});
const walletIdentity = {
  address: "demo1example",
  pubKeyHex: "02".padEnd(66, "0"),
  signatureBase64: "AQID"
};
const depositInput: PrepareDepositInput = {
  ...walletIdentity,
  amount: "1udemo"
};
const transferInput: PrepareTransferInput = {
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
const withdrawInput: PrepareWithdrawInput = {
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
const depositResult: Promise<PreparedDeposit> = dappClient.prepareDeposit(depositInput);
const transferResult: Promise<PreparedTransfer> = dappClient.prepareTransfer(transferInput);
const withdrawResult: Promise<PreparedWithdraw> = dappClient.prepareWithdraw(withdrawInput);
const relayWithdrawResult: Promise<PreparedRelayWithdraw> = dappClient.prepareRelayWithdraw(relayWithdrawInput);
const scanResult: Promise<ScanWalletNotesResult> = dappClient.scanWalletNotes(scanInput);
const nullifierResult: Promise<object & { used?: boolean }> = dappClient.checkNullifier("00".repeat(32));
const auditDisclosureInput: DecodeAuditDisclosureInput = {
  txHash: "aa",
  disclosurePrivKeyHex: "01".repeat(32)
};
const auditDisclosureResult: Promise<DisclosureReport> = dappClient.decodeAuditDisclosure(auditDisclosureInput);
const conformanceResult = runClairveilConformanceFixtures({
  fixtureNames: ["privacy_wallet_golden_vectors.json"]
});
const generatedMsgDepositWithExtension: GeneratedMsgDepositWithExtension = {
  creator: "demo1example",
  amount: "1udemo",
  noteCommitment: new Uint8Array(32),
  encryptedNote: new Uint8Array()
};
void generatedMsgDepositWithExtension;

async function browserDappTypeSmoke() {
  const deposit = await depositResult;
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

  const withdraw = await withdrawResult;
  const withdrawRecipient: string = withdraw.prepared.recipient;
  const withdrawExpiry: number = withdraw.prepared.expiresAtUnix;
  const relayWithdraw = await relayWithdrawResult;
  const relayWithdrawPayloadHash: string = relayWithdraw.payload.payload_hash;
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
  const auditDisclosure = await auditDisclosureResult;
  const auditVerified: boolean = auditDisclosure.verified;
  const conformance = await conformanceResult;
  const conformanceSkipped: boolean = conformance.skipped;

  void {
    depositAmount,
    transferStatus,
    transferRecipient,
    withdrawRecipient,
    withdrawExpiry,
    relayWithdrawPayloadHash,
    relaySigner,
    spendableTotal,
    nextScanAfterHeight,
    nullifierUsed,
    auditVerified,
    conformanceSkipped
  };
}

const evm = createClairveilEvmClient({
  contractAddress: "0x1111111111111111111111111111111111111111",
  chainId: "0x539",
  shieldedPrefix: "demos",
  defaultDenom: "udemo"
});
const selector: string = functionSelector("deposit((string,bytes,bytes))");
const evmPrecompileAddress: string = evmPrivacyPrecompileAddress;
const bech32: string = evmAddressToBech32("0x1111111111111111111111111111111111111111", "demo");
const evmAddress: string = bech32AddressToEvm(bech32, "demo");

void {
  shielded,
  material,
  cosmos,
  publicClient,
  dappClient,
  depositInput,
  transferInput,
  withdrawInput,
  relayWithdrawInput,
  scanInput,
  auditDisclosureInput,
  invalidWalletType,
  depositResult,
  transferResult,
  withdrawResult,
  relayWithdrawResult,
  scanResult,
  auditDisclosureResult,
  conformanceResult,
  browserDappTypeSmoke,
  evm,
  selector,
  evmPrecompileAddress,
  bech32,
  evmAddress
};
