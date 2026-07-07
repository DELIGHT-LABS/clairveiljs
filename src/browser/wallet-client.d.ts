import type { Base64, ClairAddress, Hex, PrivacyMaterial, ShieldedAddress } from "../core/crypto.js";
import type {
  DerivedPrivacyAccount,
  PrivacyAccountSummary,
  PrivacyEventsQuery,
  PrivacyEventsCursor,
  PrivacyScanOptions,
  PrivacyScanResumeOptions,
  QueryRetryOptions,
  ReserveResponse,
  BroadcastSignedTxResult,
  SignedTxBase64,
  SignDocBase64,
  TxSearchResult
} from "../transport/cosmos-client.js";
import type { EvmPrivacyTransactionOptions, EvmTransactionRequest, EvmWithdrawMessage } from "../transport/evm.js";
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
import type { TransferBatchPlan, TransferPlan, WithdrawPlan } from "../privacy/planner.js";
import type { ScanResult } from "../privacy/scan.js";

export interface BrowserWalletProfile {
  id?: string;
  transport?: BrowserWalletType;
  wallet?: string;
  rpc?: string;
  rest?: string;
  restEndpoints?: string[];
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
  restEndpoints?: string[];
  chainId?: string;
  accountPrefix?: string;
  shieldedPrefix?: string;
  denom?: string;
  proverUrl?: string;
  proverTimeoutMs?: number;
  queryTimeoutMs?: number;
  fetchTimeoutMs?: number;
  queryRetry?: QueryRetryOptions | false;
  nullifierFailover?: boolean;
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

export type DepositProofProvider = (input: object) => Promise<object> | object;

export type PrepareDepositProofInput =
  | { proof: Uint8Array | Hex; proofHex?: Hex; proof_hex?: Hex; depositProofProvider?: DepositProofProvider }
  | { proof?: Uint8Array | Hex; proofHex: Hex; proof_hex?: Hex; depositProofProvider?: DepositProofProvider }
  | { proof?: Uint8Array | Hex; proofHex?: Hex; proof_hex: Hex; depositProofProvider?: DepositProofProvider }
  | { proof?: Uint8Array | Hex; proofHex?: Hex; proof_hex?: Hex; depositProofProvider: DepositProofProvider };

export type PrepareDepositBaseInput = Omit<BrowserWalletIdentityInput, "walletType" | "wallet_type"> & {
  amount: CoinString;
  depositMaterial?: object;
  deposit_material?: object;
};

export type PrepareCosmosDepositInput = PrepareDepositBaseInput & PrepareDepositProofInput & {
  walletType?: "cosmos";
  wallet_type?: "cosmos";
};

export type PrepareEvmDepositInput = PrepareDepositBaseInput & (
  | { walletType: "evm"; wallet_type?: "evm" }
  | { walletType?: "evm"; wallet_type: "evm" }
) & {
  proof?: Uint8Array | Hex;
  proofHex?: Hex;
  proof_hex?: Hex;
  depositProofProvider?: DepositProofProvider;
};

export type PrepareDefaultEvmProfileDepositInput = PrepareDepositBaseInput & {
  walletType?: undefined;
  wallet_type?: undefined;
  proof?: Uint8Array | Hex;
  proofHex?: Hex;
  proof_hex?: Hex;
  depositProofProvider?: DepositProofProvider;
};

export type PrepareDepositInput<TDefaultWalletType extends BrowserWalletType = "cosmos"> =
  | PrepareCosmosDepositInput
  | PrepareEvmDepositInput
  | (TDefaultWalletType extends "evm" ? PrepareDefaultEvmProfileDepositInput : never);

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
export type PreparedDepositForDefault<TDefaultWalletType extends BrowserWalletType> =
  TDefaultWalletType extends "evm" ? PreparedEvmDeposit : PreparedCosmosDeposit;

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

export type PrepareTransferBaseInput = Omit<PrepareTransferInput, "walletType" | "wallet_type">;

export type PrepareCosmosTransferInput = PrepareTransferBaseInput & {
  walletType?: "cosmos";
  wallet_type?: "cosmos";
};

export type PrepareEvmTransferInput = PrepareTransferBaseInput & (
  | { walletType: "evm"; wallet_type?: "evm" }
  | { walletType?: "evm"; wallet_type: "evm" }
);

export type PrepareDefaultEvmProfileTransferInput = PrepareTransferBaseInput & {
  walletType?: undefined;
  wallet_type?: undefined;
};

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

export interface PrepareTransferBatchInput extends BrowserWalletIdentityInput {
  amounts: CoinString[];
  recipient: ShieldedAddress;
  limit?: number;
  maxPages?: number;
  max_pages?: number;
  scan?: PrivacyScanOptions;
  gasLimit?: number;
  gas_limit?: number;
  privacyPolicy?: TransferPrivacyPolicy;
  privacy_policy?: TransferPrivacyPolicy;
  disclosureMode?: TransferUserDisclosureMode;
  disclosure_mode?: TransferUserDisclosureMode;
  disclosurePubKeyHex?: Hex;
  disclosure_pubkey_hex?: Hex;
}

export type PrepareCosmosTransferBatchInput = Omit<PrepareTransferBatchInput, "walletType" | "wallet_type"> & {
  walletType?: "cosmos";
  wallet_type?: "cosmos";
};

export type PrepareExplicitCosmosTransferBatchInput = Omit<PrepareTransferBatchInput, "walletType" | "wallet_type"> & (
  | { walletType: "cosmos"; wallet_type?: "cosmos" }
  | { walletType?: "cosmos"; wallet_type: "cosmos" }
);

export type PrepareTransferBatchInputForDefault<TDefaultWalletType extends BrowserWalletType = "cosmos"> =
  TDefaultWalletType extends "evm" ? PrepareExplicitCosmosTransferBatchInput : PrepareCosmosTransferBatchInput;

export interface PreparedTransferBatchSummary {
  shieldedAddress: ShieldedAddress;
  amounts: CoinString[];
  recipient: ShieldedAddress;
  privacyPolicy: TransferPrivacyPolicy;
  disclosureMode: TransferUserDisclosureMode;
  planStatus: string;
  planAction: string;
  selectedInputTotals?: string[];
  payloads?: PreparedTransferPayload[];
  proofs?: PreparedTransferProof[];
  messages?: TransferMessage[];
}

export interface PreparedCosmosTransferBatch {
  signDoc: SignDocBase64;
  transaction?: never;
  prepared: PreparedTransferBatchSummary;
  plan: TransferBatchPlan;
}

export interface PrepareWithdrawInput extends BrowserWalletIdentityInput {
  amount: CoinString;
  recipient: ClairAddress | string;
  limit?: number;
  maxPages?: number;
  max_pages?: number;
  scan?: PrivacyScanOptions;
  expiresAtUnix?: number;
  expires_at_unix?: number;
}

export type PrepareWithdrawBaseInput = Omit<PrepareWithdrawInput, "walletType" | "wallet_type">;

export type PrepareCosmosWithdrawInput = PrepareWithdrawBaseInput & {
  walletType?: "cosmos";
  wallet_type?: "cosmos";
};

export type PrepareEvmWithdrawInput = PrepareWithdrawBaseInput & (
  | { walletType: "evm"; wallet_type?: "evm" }
  | { walletType?: "evm"; wallet_type: "evm" }
);

export type PrepareDefaultEvmProfileWithdrawInput = PrepareWithdrawBaseInput & {
  walletType?: undefined;
  wallet_type?: undefined;
};

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

export interface PrepareEvmRelayWithdrawTransactionOptionsInput {
  transactionOptions?: EvmPrivacyTransactionOptions;
  transaction_options?: EvmPrivacyTransactionOptions;
}

export type PrepareRelayWithdrawBaseInput = PrepareWithdrawBaseInput;

export type PrepareCosmosRelayWithdrawInput = PrepareRelayWithdrawBaseInput & {
  walletType?: "cosmos";
  wallet_type?: "cosmos";
};

export type PrepareEvmRelayWithdrawInput = PrepareRelayWithdrawBaseInput & PrepareEvmRelayWithdrawTransactionOptionsInput & (
  | { walletType: "evm"; wallet_type?: "evm" }
  | { walletType?: "evm"; wallet_type: "evm" }
);

export type PrepareDefaultEvmProfileRelayWithdrawInput = PrepareRelayWithdrawBaseInput & PrepareEvmRelayWithdrawTransactionOptionsInput & {
  walletType?: undefined;
  wallet_type?: undefined;
};

export type PrepareRelayWithdrawInput<TDefaultWalletType extends BrowserWalletType = "cosmos"> =
  | PrepareCosmosRelayWithdrawInput
  | PrepareEvmRelayWithdrawInput
  | (TDefaultWalletType extends "evm" ? PrepareDefaultEvmProfileRelayWithdrawInput : never);

export interface PreparedRelayWithdrawSummary extends PreparedWithdrawSummary {
  payload: PreparedWithdrawPayload;
  proof?: PreparedWithdrawProof;
}

export interface PreparedEvmRelayWithdrawSummary extends Omit<PreparedRelayWithdrawSummary, "message"> {
  message?: EvmWithdrawMessage;
}

export interface PreparedCosmosRelayWithdraw {
  payload: PreparedWithdrawPayload;
  signDoc?: never;
  transaction?: never;
  prepared: PreparedRelayWithdrawSummary;
  plan: WithdrawPlan;
}

export interface PreparedEvmRelayWithdraw {
  payload: PreparedWithdrawPayload;
  signDoc?: never;
  transaction: EvmTransactionRequest;
  prepared: PreparedEvmRelayWithdrawSummary;
  plan: WithdrawPlan;
}

export type PreparedRelayWithdraw = PreparedCosmosRelayWithdraw | PreparedEvmRelayWithdraw;

export interface CreateRelayWithdrawSignDocInput {
  payload: PreparedWithdrawPayload;
  relayer?: ClairAddress | string;
  creator?: ClairAddress | string;
  address?: ClairAddress | string;
  pubKeyHex?: Hex;
  pub_key_hex?: Hex;
  gasLimit?: number;
  gas_limit?: number;
  feeAmount?: Array<object>;
  fee_amount?: Array<object>;
  memo?: string;
  nowUnix?: number;
  now_unix?: number;
  expectedChainId?: string;
  expected_chain_id?: string;
  expectedRecipient?: ClairAddress | string;
  expected_recipient?: ClairAddress | string;
  accountPrefix?: string;
  account_prefix?: string;
}

export interface PreparedRelayWithdrawSignDoc {
  signDoc: SignDocBase64;
  message: WithdrawMessage;
  payload: PreparedWithdrawPayload;
  relayer: ClairAddress | string;
}

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

export interface DecodeSelfViewDisclosureInput extends DecodeUserDisclosureInput {
  disclosureScalar?: bigint | string | number;
  disclosure_scalar?: bigint | string | number;
  disclosureScalarHex?: Hex;
  disclosure_scalar_hex?: Hex;
}

export interface DecodeAuditDisclosureInput extends PrivacyScanOptions {
  txHash?: Hex;
  tx_hash?: Hex;
  disclosurePrivKeyHex?: Hex;
  disclosure_privkey_hex?: Hex;
}

export class ClairveilBrowserClient<TDefaultWalletType extends BrowserWalletType = "cosmos"> {
  constructor(options: ClairveilBrowserClientOptions & { profile: BrowserWalletProfile & { transport: TDefaultWalletType } });
  constructor(options?: ClairveilBrowserClientOptions);
  health(): Promise<BrowserHealthResult>;
  fetchBlockEvents(limit?: number): Promise<{ events: BrowserBlockEvent[] }>;
  fetchPrivacyEvents(options?: PrivacyEventsQuery): Promise<object & { events?: object[] }>;
  fetchScanEvents(options?: PrivacyEventsQuery): Promise<object & { events?: object[] }>;
  fetchAuditableTransfers(options?: PrivacyEventsQuery): Promise<object & { events: object[] }>;
  fetchReserve(denom: string): Promise<ReserveResponse>;
  buildRootSigningMessage(address: ClairAddress, pubKeyHex: Hex): string;
  verifySignerPubKey(address: ClairAddress, pubKeyHex: Hex): object;
  evmAccountIdentity(address: string): { evmAddress: string; address: ClairAddress; pubKeyHex: Hex };
  derivePrivacyAccount(input: BrowserWalletIdentityInput): DerivedPrivacyAccount;
  getBalances(address: ClairAddress): Promise<BrowserBalancesResponse>;
  waitForTx(txHash: Hex, options?: { attempts?: number; intervalMs?: number }): Promise<TxSearchResult | null>;
  waitForEvmTransaction(txHash: Hex): Promise<BrowserEvmTransactionWaitResult>;
  evmNativeSendTransaction(input: { to: string; amount: CoinString }): BrowserEvmNativeSendTransaction;
  buildBankSendSignDoc(input: { from: ClairAddress; pubKeyHex: Hex; to: ClairAddress; amount: CoinString }): Promise<SignDocBase64>;
  broadcastSignedTx(input: SignedTxBase64, waitOptions?: { attempts?: number; intervalMs?: number }): Promise<BroadcastSignedTxResult>;
  prepareDeposit(input: TDefaultWalletType extends "evm" ? PrepareDefaultEvmProfileDepositInput : never): Promise<PreparedEvmDeposit>;
  prepareDeposit(input: PrepareEvmDepositInput): Promise<PreparedEvmDeposit>;
  prepareDeposit(input: PrepareCosmosDepositInput): Promise<PreparedCosmosDeposit>;
  prepareDeposit(input: PrepareDepositInput<TDefaultWalletType>): Promise<PreparedDeposit>;
  prepareTransfer(input: TDefaultWalletType extends "evm" ? PrepareDefaultEvmProfileTransferInput : never): Promise<PreparedEvmTransfer>;
  prepareTransfer(input: PrepareEvmTransferInput): Promise<PreparedEvmTransfer>;
  prepareTransfer(input: PrepareCosmosTransferInput): Promise<PreparedCosmosTransfer>;
  prepareTransfer(input: PrepareTransferInput): Promise<PreparedTransfer>;
  prepareTransferBatch(input: PrepareTransferBatchInputForDefault<TDefaultWalletType>): Promise<PreparedCosmosTransferBatch>;
  prepareWithdraw(input: TDefaultWalletType extends "evm" ? PrepareDefaultEvmProfileWithdrawInput : never): Promise<PreparedEvmWithdraw>;
  prepareWithdraw(input: PrepareEvmWithdrawInput): Promise<PreparedEvmWithdraw>;
  prepareWithdraw(input: PrepareCosmosWithdrawInput): Promise<PreparedCosmosWithdraw>;
  prepareWithdraw(input: PrepareWithdrawInput): Promise<PreparedWithdraw>;
  prepareRelayWithdraw(input: TDefaultWalletType extends "evm" ? PrepareDefaultEvmProfileRelayWithdrawInput : never): Promise<PreparedEvmRelayWithdraw>;
  prepareRelayWithdraw(input: PrepareEvmRelayWithdrawInput): Promise<PreparedEvmRelayWithdraw>;
  prepareRelayWithdraw(input: PrepareCosmosRelayWithdrawInput): Promise<PreparedCosmosRelayWithdraw>;
  prepareRelayWithdraw(input: PrepareRelayWithdrawInput<TDefaultWalletType>): Promise<PreparedRelayWithdraw>;
  buildRelayWithdrawMessageFromPayload(input: CreateRelayWithdrawSignDocInput): WithdrawMessage;
  createRelayWithdrawSignDoc(input: CreateRelayWithdrawSignDocInput): Promise<PreparedRelayWithdrawSignDoc>;
  scanWalletNotes(input: ScanWalletNotesInput): Promise<ScanWalletNotesResult>;
  checkNullifier(nullifierHex: Hex): Promise<object & { used?: boolean; Used?: boolean }>;
  checkNullifiers(nullifierHexes: Hex[]): Promise<Map<Hex, boolean>>;
  decodeUserDisclosure(input: DecodeUserDisclosureInput): Promise<DisclosureReport>;
  decodeSelfViewDisclosure(input: DecodeSelfViewDisclosureInput): Promise<DisclosureReport>;
  decodeAuditDisclosure(input: DecodeAuditDisclosureInput): Promise<DisclosureReport>;
  txRawBytesBase64(input: SignedTxBase64): Base64;
}

export function createClairveilBrowserClient<TWalletType extends BrowserWalletType>(
  options: ClairveilBrowserClientOptions & { profile: BrowserWalletProfile & { transport: TWalletType } }
): ClairveilBrowserClient<TWalletType>;
export function createClairveilBrowserClient(options?: ClairveilBrowserClientOptions): ClairveilBrowserClient;
export function buildRootSigningMessage(address: ClairAddress, pubKeyHex: Hex): string;
export function evmAddressToBech32(address: string, prefix: string): string;
export function verifySignerPubKey(address: ClairAddress, pubKeyHex: Hex): object;

export type BrowserDappProfile = BrowserWalletProfile;
export type ClairveilBrowserDappClientOptions = ClairveilBrowserClientOptions;
export { ClairveilBrowserClient as ClairveilBrowserDappClient };
export function createClairveilBrowserDappClient<TWalletType extends BrowserWalletType>(
  options: ClairveilBrowserClientOptions & { profile: BrowserWalletProfile & { transport: TWalletType } }
): ClairveilBrowserClient<TWalletType>;
export function createClairveilBrowserDappClient(options?: ClairveilBrowserClientOptions): ClairveilBrowserClient;
