import type { Base64, ClairAddress, Hex, PrivacyMaterial, ShieldedAddress } from "../core/crypto.js";
import type {
  DerivedPrivacyAccount,
  PrivacyAccountSummary,
  PrivacyEventsQuery,
  PrivacyEventsCursor,
  PrivacyScanOptions,
  PrivacyScanResumeOptions,
  SignedTxBase64,
  SignDocBase64,
  TxSearchResult
} from "../transport/cosmos-client.js";
import type { EvmTransactionRequest } from "../transport/evm.js";
import type { CoinString } from "../core/note.js";
import type { DisclosureReport } from "../core/disclosure.js";
import type {
  PreparedTransferPayload,
  PreparedTransferProof,
  PreparedWithdrawPayload,
  PreparedWithdrawProof,
  TransferMessage,
  TransferPrivacyPolicy,
  TransferUserDisclosureMode,
  WithdrawMessage,
} from "../privacy/payload.js";
import type { TransferPlan, WithdrawPlan } from "../privacy/planner.js";
import type { ScanResult } from "../privacy/scan.js";

export interface BrowserWalletProfile {
  id?: string;
  transport?: "cosmos" | "evm" | string;
  rpc?: string;
  rest?: string;
  chainId?: string;
  accountPrefix?: string;
  shieldedPrefix?: string;
  denom?: string;
  proverUrl?: string;
  evmRpc?: string;
  evmChainId?: string;
  evmPrivacyPrecompileAddress?: string;
  evmGasLimit?: string;
  evmSendGasLimit?: string;
}

export type BrowserWalletType = "cosmos" | "evm";

export interface ClairveilBrowserClientOptions {
  profile?: BrowserWalletProfile;
  rpc?: string;
  rest?: string;
  chainId?: string;
  accountPrefix?: string;
  shieldedPrefix?: string;
  denom?: string;
  proverUrl?: string;
  proverTimeoutMs?: number;
  evmRpc?: string;
  evmChainId?: string;
  evmPrivacyPrecompileAddress?: string;
  evmGasLimit?: string;
  evmSendGasLimit?: string;
}

export interface BrowserHealthResult {
  status: object | null;
  tree: object | null;
  audit: object | null;
  errors: string[];
}

export interface BrowserBlockEventSummary {
  action: string;
  amount: string;
  from: string;
  to: string;
  commitment: string;
  disclosureTarget: string;
  evmFailure: string;
}

export interface BrowserBlockEvent {
  type: string;
  height: string | number;
  tx_hash_hex: Hex;
  code: number;
  gas_used: string;
  gas_wanted: string;
  summary: BrowserBlockEventSummary;
}

export interface BrowserBalancesResponse {
  balances: Array<{ denom: string; amount: string }>;
  pagination?: object | null;
}

export interface BrowserEvmTransactionWaitResult {
  txHash: Hex | string;
  evmTxHash: Hex | string;
  receipt: object | null;
  tx: null;
  ok: boolean;
  error: string;
  errors: string[];
}

export interface BrowserEvmNativeSendTransaction {
  to: string;
  chainId?: string;
  value: Hex | string;
  gas?: Hex | string;
}

export interface BrowserWalletIdentityInput {
  address: ClairAddress | string;
  pubKeyHex?: Hex;
  pub_key_hex?: Hex;
  signatureBase64?: Base64;
  signature_base64?: Base64;
  walletType?: BrowserWalletType;
  wallet_type?: BrowserWalletType;
}

export interface PrepareDepositInput extends BrowserWalletIdentityInput {
  amount: CoinString;
}

export interface PreparedDepositSummary {
  shieldedAddress: ShieldedAddress;
  noteCommitmentHex: Hex;
  amount: CoinString;
}

export interface PreparedCosmosDeposit {
  signDoc: SignDocBase64;
  transaction?: never;
  prepared: PreparedDepositSummary;
}

export interface PreparedEvmDeposit {
  signDoc?: never;
  transaction: EvmTransactionRequest;
  prepared: PreparedDepositSummary;
}

export type PreparedDeposit = PreparedCosmosDeposit | PreparedEvmDeposit;

export interface PrepareTransferInput extends BrowserWalletIdentityInput {
  amount: CoinString;
  recipient: ShieldedAddress;
  allowPlanStep?: boolean;
  allow_plan_step?: boolean;
  limit?: number;
  maxPages?: number;
  max_pages?: number;
  scan?: PrivacyScanOptions;
  privacyPolicy?: TransferPrivacyPolicy;
  privacy_policy?: TransferPrivacyPolicy;
  disclosureMode?: TransferUserDisclosureMode;
  disclosure_mode?: TransferUserDisclosureMode;
  disclosurePubKeyHex?: Hex;
  disclosure_pubkey_hex?: Hex;
}

export interface PreparedTransferSummary {
  shieldedAddress: ShieldedAddress;
  finalAmount: CoinString;
  finalRecipient: ShieldedAddress;
  privacyPolicy: TransferPrivacyPolicy;
  disclosureMode: TransferUserDisclosureMode;
  planStatus: string;
  planAction: string;
  isFinal?: boolean;
  amount?: CoinString;
  recipient?: ShieldedAddress;
  selectedInputTotal?: string;
  payload?: PreparedTransferPayload;
  proof?: PreparedTransferProof;
  message?: TransferMessage;
}

export interface PreparedCosmosTransfer {
  signDoc: SignDocBase64;
  transaction?: never;
  prepared: PreparedTransferSummary;
  plan: TransferPlan;
}

export interface PreparedEvmTransfer {
  signDoc?: never;
  transaction: EvmTransactionRequest;
  prepared: PreparedTransferSummary;
  plan: TransferPlan;
}

export type PreparedTransfer = PreparedCosmosTransfer | PreparedEvmTransfer;

export interface PrepareWithdrawInput extends BrowserWalletIdentityInput {
  amount: CoinString;
  recipient: ClairAddress | string;
  limit?: number;
  maxPages?: number;
  max_pages?: number;
  scan?: PrivacyScanOptions;
}

export interface PreparedWithdrawSummary {
  shieldedAddress: ShieldedAddress;
  amount: CoinString;
  recipient: ClairAddress | string;
  evmRecipient?: string;
  selectedNoteNullifier: Hex;
  expiresAtUnix: number;
  payload?: PreparedWithdrawPayload;
  proof?: PreparedWithdrawProof;
  message?: WithdrawMessage;
}

export interface PreparedCosmosWithdraw {
  signDoc: SignDocBase64;
  transaction?: never;
  prepared: PreparedWithdrawSummary;
  plan: WithdrawPlan;
}

export interface PreparedEvmWithdraw {
  signDoc?: never;
  transaction: EvmTransactionRequest;
  prepared: PreparedWithdrawSummary;
  plan: WithdrawPlan;
}

export type PreparedWithdraw = PreparedCosmosWithdraw | PreparedEvmWithdraw;

export interface ScanWalletNotesInput extends BrowserWalletIdentityInput, PrivacyScanOptions {
  includeFoundNotes?: boolean;
}

export type ScanWalletNotesResult = ScanResult & {
  privacyAccount: PrivacyAccountSummary | DerivedPrivacyAccount;
  scanCursor: PrivacyEventsCursor;
  nextScanOptions: PrivacyScanResumeOptions;
};

export interface DecodeUserDisclosureInput extends Partial<BrowserWalletIdentityInput>, PrivacyScanOptions {
  txHash?: Hex;
  tx_hash?: Hex;
  skipSignerPubKeyCheck?: boolean;
  skip_signer_pubkey_check?: boolean;
}

export interface DecodeAuditDisclosureInput extends PrivacyScanOptions {
  txHash?: Hex;
  tx_hash?: Hex;
  disclosurePrivKeyHex?: Hex;
  disclosure_privkey_hex?: Hex;
}

export class ClairveilBrowserClient {
  constructor(options?: ClairveilBrowserClientOptions);
  health(): Promise<BrowserHealthResult>;
  fetchBlockEvents(limit?: number): Promise<{ events: BrowserBlockEvent[] }>;
  fetchPrivacyEvents(options?: PrivacyEventsQuery): Promise<object & { events?: object[] }>;
  fetchAuditableTransfers(options?: PrivacyEventsQuery): Promise<object & { events: object[] }>;
  buildRootSigningMessage(address: ClairAddress, pubKeyHex: Hex): string;
  verifySignerPubKey(address: ClairAddress, pubKeyHex: Hex): object;
  evmAccountIdentity(address: string): { evmAddress: string; address: ClairAddress; pubKeyHex: Hex };
  derivePrivacyAccount(input: BrowserWalletIdentityInput): DerivedPrivacyAccount;
  getBalances(address: ClairAddress): Promise<BrowserBalancesResponse>;
  waitForTx(txHash: Hex, options?: { attempts?: number; intervalMs?: number }): Promise<TxSearchResult | null>;
  waitForEvmTransaction(txHash: Hex): Promise<BrowserEvmTransactionWaitResult>;
  evmNativeSendTransaction(input: { to: string; amount: CoinString }): BrowserEvmNativeSendTransaction;
  buildBankSendSignDoc(input: { from: ClairAddress; pubKeyHex: Hex; to: ClairAddress; amount: CoinString }): Promise<SignDocBase64>;
  broadcastSignedTx(input: SignedTxBase64, waitOptions?: { attempts?: number; intervalMs?: number }): Promise<object>;
  prepareDeposit(input: PrepareDepositInput): Promise<PreparedDeposit>;
  prepareTransfer(input: PrepareTransferInput): Promise<PreparedTransfer>;
  prepareWithdraw(input: PrepareWithdrawInput): Promise<PreparedWithdraw>;
  scanWalletNotes(input: ScanWalletNotesInput): Promise<ScanWalletNotesResult>;
  checkNullifier(nullifierHex: Hex): Promise<object & { used?: boolean; Used?: boolean }>;
  decodeUserDisclosure(input: DecodeUserDisclosureInput): Promise<DisclosureReport>;
  decodeAuditDisclosure(input: DecodeAuditDisclosureInput): Promise<DisclosureReport>;
  txRawBytesBase64(input: SignedTxBase64): Base64;
}

export function createClairveilBrowserClient(options?: ClairveilBrowserClientOptions): ClairveilBrowserClient;
export function buildRootSigningMessage(address: ClairAddress, pubKeyHex: Hex): string;
export function evmAddressToBech32(address: string, prefix: string): string;
export function verifySignerPubKey(address: ClairAddress, pubKeyHex: Hex): object;

export type BrowserDappProfile = BrowserWalletProfile;
export type ClairveilBrowserDappClientOptions = ClairveilBrowserClientOptions;
export { ClairveilBrowserClient as ClairveilBrowserDappClient };
export function createClairveilBrowserDappClient(options?: ClairveilBrowserClientOptions): ClairveilBrowserClient;
