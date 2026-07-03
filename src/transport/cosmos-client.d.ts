export * from "../core/crypto.js";
export * from "../core/disclosure.js";
export * from "../core/errors.js";
export * from "../core/note.js";
export * from "../privacy/payload.js";
export * from "../privacy/planner.js";
export * from "../privacy/prover.js";
export * from "../privacy/scan.js";
export * from "../privacy/note-store.js";
export * from "../core/schemas.js";
export * from "../wallet/adapter.js";
export {
  UserDisclosureMode,
  userDisclosureModeFromJSON,
  userDisclosureModeToJSON
} from "../generated/clairveil/privacy/v1/tx.js";
export type {
  MsgDeposit as MsgDepositMessage,
  MsgTransfer as MsgTransferMessage,
  MsgWithdraw as MsgWithdrawMessage,
  MsgDepositResponse,
  MsgTransferResponse,
  MsgWithdrawResponse
} from "../generated/clairveil/privacy/v1/tx.js";
export type {
  QueryAuditConfigResponse,
  QueryCheckNullifierResponse,
  QueryCircuitConfigResponse,
  QueryCommitmentInfoResponse,
  QueryDisclosureConfigResponse,
  QueryMerklePathResponse,
  QueryPrivacyEvent,
  QueryPrivacyEventAttribute,
  QueryPrivacyEventsResponse,
  QueryReserveResponse,
  QueryTreeStateResponse
} from "../generated/clairveil/privacy/v1/query.js";

import type { Base64, ClairAddress, Hex, PrivacyMaterial, ShieldedAddress } from "../core/crypto.js";
import type { CoinString, DepositMaterial, FoundNote } from "../core/note.js";
import type {
  PreparedTransferPayload,
  PreparedTransferPayloadInput,
  PreparedTransferProof,
  PreparedWithdrawPayload,
  PreparedWithdrawProof,
  PreparedWithdrawProverPayload,
  PreparedWithdrawProverPayloadInput,
  PreparedWithdrawProverPayloadResult,
  RelayWithdrawPayloadBuildResult,
  RelayWithdrawRelayOptions,
  TransferInputSelection,
  TransferMessage,
  TransferMessageBuildResult,
  WithdrawMessage,
  WithdrawMessageBuildResult
} from "../privacy/payload.js";
import type { TransferPlan, WithdrawPlan } from "../privacy/planner.js";
import type { ProverAdapter } from "../privacy/prover.js";
import type { ScanResult } from "../privacy/scan.js";
import type { MemoryNoteStore } from "../privacy/note-store.js";
import type { WalletAdapterLike } from "../wallet/adapter.js";
import type { MsgDeposit as MsgDepositMessage } from "../generated/clairveil/privacy/v1/tx.js";

export const msgDepositTypeUrl: "/clairveil.privacy.v1.MsgDeposit";
export const msgTransferTypeUrl: "/clairveil.privacy.v1.MsgTransfer";
export const msgWithdrawTypeUrl: "/clairveil.privacy.v1.MsgWithdraw";

export interface MsgCodec<T = object> {
  typeUrl: string;
  encode(message: Partial<T>, writer?: object): object;
  decode(input?: Uint8Array): T;
  fromPartial(object: Partial<T>): T;
}

export const MsgDeposit: MsgCodec;
export const MsgTransfer: MsgCodec;
export const MsgWithdraw: MsgCodec;

export interface SignDocBase64 {
  bodyBytes: Base64;
  authInfoBytes: Base64;
  chainId: string;
  accountNumber: string;
}

export interface SignedTxBase64 {
  bodyBytes: Base64;
  authInfoBytes: Base64;
  signature: Base64;
}

export interface PrivacyAccountSummary {
  address: ClairAddress;
  pubKeyHex: Hex;
  signing_message: string;
  shielded_address: ShieldedAddress;
  disclosure_pubkey_hex: Hex;
  root_signature_hash: Hex;
}

export interface DerivedPrivacyAccount {
  signing_message: string;
  shielded_address: ShieldedAddress;
  disclosure_pubkey_hex: Hex;
  root_signature_hash: Hex;
}

export interface TxSearchResult {
  height: string;
  txhash: Hex;
  code?: number;
  raw_log?: string;
  events: object[];
  tx?: object;
}

export interface BroadcastSignedTxResult {
  ok: boolean;
  broadcast: {
    txhash: Hex | string;
    code: number;
    raw_log: string;
  };
  tx: TxSearchResult | null;
  error?: string;
}

export interface ReserveResponse {
  denom: string;
  module_balance: string;
  total_deposited: string;
  total_withdrawn: string;
  expected_module_balance: string;
  invariant_holds: boolean;
}

export interface PrivacyEventsQuery {
  afterHeight?: number;
  after_height?: number;
  page?: number;
  limit?: number;
  eventTypes?: string[];
  event_types?: string[];
}

export interface PrivacyScanOptions extends PrivacyEventsQuery {
  maxPages?: number;
  max_pages?: number;
}

export interface PrivacyEventsCursor {
  after_height: number;
  page: number;
  limit: number;
  event_types: string[];
  has_more: boolean;
  latest_height: number;
  latest_tx_hash: Hex | "";
  next_page?: number;
  pages_scanned?: number;
  completed?: boolean;
}

export interface PrivacyScanResumeOptions {
  afterHeight: number;
  page: number;
  limit: number;
  eventTypes: string[];
  maxPages?: number;
  includeFoundNotes?: boolean;
  hasMore: boolean;
  completed: boolean;
}

export interface WalletScanInput extends PrivacyScanOptions {
  rootSeed: Uint8Array;
  includeFoundNotes?: boolean;
}

export interface ClairveilClientOptions {
  rpc: string;
  rest?: string;
  restEndpoints?: string[];
  chainId: string;
  accountPrefix?: string;
  bech32Prefix?: string;
  shieldedPrefix?: string;
  defaultDenom?: string;
  assetDenom?: string;
  registry?: object;
  queryTimeoutMs?: number;
  fetchTimeoutMs?: number;
  queryRetry?: QueryRetryOptions | false;
  nullifierFailover?: boolean;
}

export interface QueryRetryOptions {
  retries?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  jitter?: boolean;
  retryStatuses?: number[];
}

export interface PreparedDeposit {
  status: "ready";
  signDoc: SignDocBase64;
  message: MsgDepositMessage;
  material: DepositMaterial;
  privacyAccount: PrivacyAccountSummary;
}

export interface PreparedTransferSummary {
  planAction: "final_transfer" | "self_merge" | string;
  isFinal: boolean;
  amount: CoinString;
  recipient: ShieldedAddress;
  finalAmount: CoinString;
  finalRecipient: ShieldedAddress;
  selectedInputTotal: string;
}

export interface PreparedTransfer {
  status: string;
  plan: TransferPlan;
  scan: ScanResult;
  signDoc?: SignDocBase64;
  payload?: PreparedTransferPayload;
  proof?: PreparedTransferProof;
  message?: TransferMessage;
  prepared?: PreparedTransferSummary;
  privacyAccount: PrivacyAccountSummary;
}

export interface PreparedWithdraw {
  status: string;
  plan: WithdrawPlan;
  scan: ScanResult;
  signDoc?: SignDocBase64;
  proverPayload?: PreparedWithdrawProverPayload;
  proof?: PreparedWithdrawProof;
  payload?: PreparedWithdrawPayload;
  message?: WithdrawMessage;
  selectedNote?: FoundNote;
  privacyAccount: PrivacyAccountSummary;
}

export interface PreparedRelayWithdraw {
  status: string;
  plan: WithdrawPlan;
  scan: ScanResult;
  proverPayload?: PreparedWithdrawProverPayload;
  proof?: PreparedWithdrawProof;
  payload?: PreparedWithdrawPayload;
  selectedNote?: FoundNote;
  privacyAccount: PrivacyAccountSummary;
}

export interface PreparedRelayWithdrawSignDoc {
  status: "ready";
  relayer: ClairAddress | string;
  payload: PreparedWithdrawPayload;
  message: WithdrawMessage;
  signDoc: SignDocBase64;
}

export type DepositProofInput =
  | { proof: Uint8Array | Hex; proofHex?: Hex; proof_hex?: Hex }
  | { proof?: Uint8Array | Hex; proofHex: Hex; proof_hex?: Hex }
  | { proof?: Uint8Array | Hex; proofHex?: Hex; proof_hex: Hex };

export type BuildDepositMessageInput = {
  creator: ClairAddress;
  rootSeed: Uint8Array;
  amount: CoinString;
  memo?: string;
  depositMaterial?: object;
  deposit_material?: object;
} & DepositProofInput;

export type PrepareDepositInput = {
  wallet?: WalletAdapterLike;
  material?: PrivacyMaterial;
  depositMaterial?: object;
  deposit_material?: object;
  amount: CoinString;
  memo?: string;
  gasLimit?: number;
  denom?: string;
  assetDenom?: string;
} & DepositProofInput;

export function createClairveilRegistry(extraTypes?: Array<[string, object]>): object;
export function normalizeRpcEndpoint(rpc: string): string;
export function normalizeRestEndpoint(rest: string): string;
export function buildRootSigningMessage(address: ClairAddress, pubKeyHex: Hex): string;
export function cosmosAddressFromPubKey(pubKeyHex: Hex, prefix?: string): ClairAddress;
export function verifySignerPubKey(address: ClairAddress, pubKeyHex: Hex, prefix?: string): {
  address: ClairAddress;
  expectedAddress: ClairAddress;
  matches: boolean;
};
export function assertSignerPubKey(address: ClairAddress, pubKeyHex: Hex, prefix?: string): {
  address: ClairAddress;
  expectedAddress: ClairAddress;
  matches: true;
};
export function eventAttribute(event: object, key: string): string;
export function isAuditableTransfer(event: object): boolean;

export class ClairveilJS {
  constructor(options: ClairveilClientOptions);
  connect(): Promise<object>;
  disconnect(): Promise<void>;
  restEndpoints: string[];
  activeRestEndpoint: string;
  restUrl(path: string, endpoint?: string): string;
  fetchJson<T = object>(pathOrUrl: string, options?: {
    failover?: boolean;
    retry?: QueryRetryOptions | false;
  }): Promise<T>;
  getAccountInfo(address: ClairAddress): Promise<{ accountNumber: bigint; sequence: bigint }>;
  getBalances(address: ClairAddress): Promise<object>;
  getTx(txHash: Hex): Promise<TxSearchResult | null>;
  waitForTx(txHash: Hex, options?: { attempts?: number; intervalMs?: number }): Promise<TxSearchResult | null>;
  fetchPrivacyEvents(options?: PrivacyEventsQuery): Promise<object & { events?: object[] }>;
  fetchTreeState(): Promise<object>;
  fetchCommitmentInfo(commitmentHex: Hex): Promise<object>;
  fetchAuditConfig(): Promise<object>;
  fetchDisclosureConfig(): Promise<object>;
  fetchCircuitConfig(): Promise<object>;
  fetchReserve(denom: string): Promise<ReserveResponse>;
  lookupMerklePath(commitmentHex: Hex): Promise<object>;
  checkNullifier(nullifierHex: Hex): Promise<object>;
  deriveWalletPrivacyMaterial(wallet: WalletAdapterLike): Promise<PrivacyMaterial>;
  scanNotes(input: WalletScanInput): Promise<ScanResult & {
    scanCursor: PrivacyEventsCursor;
    nextScanOptions: PrivacyScanResumeOptions;
  }>;
  fetchAuditableTransfers(options?: PrivacyEventsQuery): Promise<object & { events: object[] }>;
  findPrivacyEventByTxHash(txHash: Hex, options?: PrivacyEventsQuery & {
    maxPages?: number;
    max_pages?: number;
  }): Promise<object>;
  derivePrivacyAccount(input: {
    address: ClairAddress;
    pubKeyHex?: Hex;
    pub_key_hex?: Hex;
    signatureBase64?: Base64;
    signature_base64?: Base64;
  }): DerivedPrivacyAccount;
  buildDepositMaterial(input: {
    creator?: ClairAddress | string;
    rootSeed?: Uint8Array;
    shieldedAddress?: ShieldedAddress;
    amount?: CoinString;
    memo?: string;
    assetDenom?: string;
    denom?: string;
    shieldedPrefix?: string;
  }): DepositMaterial;
  scanWalletNotes(input: PrivacyScanOptions & {
    wallet?: WalletAdapterLike;
    material?: PrivacyMaterial;
    limit?: number;
    maxPages?: number;
    noteStore?: MemoryNoteStore;
    includeFoundNotes?: boolean;
  }): Promise<ScanResult & {
    privacyAccount: object;
    scanCursor: PrivacyEventsCursor;
    nextScanOptions: PrivacyScanResumeOptions;
  }>;
  planWalletTransfer(input: {
    wallet?: WalletAdapterLike;
    material?: PrivacyMaterial;
    amount: CoinString;
    denom?: string;
    limit?: number;
    maxPages?: number;
    scan?: PrivacyScanOptions;
  }): Promise<{ plan: TransferPlan; scan: ScanResult }>;
  planWalletWithdraw(input: {
    wallet?: WalletAdapterLike;
    material?: PrivacyMaterial;
    amount: CoinString;
    denom?: string;
    limit?: number;
    maxPages?: number;
    scan?: PrivacyScanOptions;
  }): Promise<{ plan: WithdrawPlan; scan: ScanResult }>;
  buildDepositMessage(input: BuildDepositMessageInput): object;
  prepareDeposit(input: PrepareDepositInput): Promise<PreparedDeposit>;
  prepareTransfer(input: {
    wallet?: WalletAdapterLike;
    material?: PrivacyMaterial;
    amount: CoinString;
    recipient: ShieldedAddress;
    proverAdapter: ProverAdapter;
    allowPlanStep?: boolean;
    gasLimit?: number;
    userPrivacyPolicy?: string | number;
    userDisclosureMode?: string | number;
    userDisclosureTargetPubKeyHex?: Hex;
    auditDisclosureTargetPubKeyHex?: Hex;
    denom?: string;
    limit?: number;
    maxPages?: number;
    scan?: PrivacyScanOptions;
  }): Promise<PreparedTransfer>;
  prepareWithdraw(input: {
    wallet?: WalletAdapterLike;
    material?: PrivacyMaterial;
    amount: CoinString;
    recipient: ClairAddress;
    proverAdapter: ProverAdapter;
    gasLimit?: number;
    denom?: string;
    assetDenom?: string;
    limit?: number;
    maxPages?: number;
    scan?: PrivacyScanOptions;
    expiresAtUnix?: number;
  }): Promise<PreparedWithdraw>;
  prepareRelayWithdraw(input: {
    wallet?: WalletAdapterLike;
    material?: PrivacyMaterial;
    amount: CoinString;
    recipient: ClairAddress;
    proverAdapter: ProverAdapter;
    denom?: string;
    assetDenom?: string;
    limit?: number;
    maxPages?: number;
    scan?: PrivacyScanOptions;
    expiresAtUnix?: number;
  }): Promise<PreparedRelayWithdraw>;
  createDepositSignDoc(input: Parameters<ClairveilJS["prepareDeposit"]>[0]): Promise<PreparedDeposit>;
  createTransferSignDoc(input: Parameters<ClairveilJS["prepareTransfer"]>[0]): Promise<PreparedTransfer & { status: "ready"; signDoc: SignDocBase64 }>;
  createWithdrawSignDoc(input: Parameters<ClairveilJS["prepareWithdraw"]>[0]): Promise<PreparedWithdraw & { status: "ready"; signDoc: SignDocBase64 }>;
  createRelayWithdrawPayload(input: Parameters<ClairveilJS["prepareRelayWithdraw"]>[0]): Promise<PreparedRelayWithdraw & { status: "ready"; payload: PreparedWithdrawPayload }>;
  buildPreparedTransferPayload(input: PreparedTransferPayloadInput): Promise<PreparedTransferPayload>;
  buildTransferMessage(input: PreparedTransferPayloadInput & {
    proverAdapter?: ProverAdapter;
  }): Promise<TransferMessageBuildResult>;
  buildPreparedWithdrawProverPayload(input: PreparedWithdrawProverPayloadInput): Promise<PreparedWithdrawProverPayloadResult>;
  buildRelayWithdrawPayload(input: PreparedWithdrawProverPayloadInput & {
    proverAdapter?: ProverAdapter;
  }): Promise<RelayWithdrawPayloadBuildResult>;
  buildWithdrawMessage(input: PreparedWithdrawProverPayloadInput & {
    proverAdapter?: ProverAdapter;
    creator?: ClairAddress | string;
  }): Promise<WithdrawMessageBuildResult>;
  buildRelayWithdrawMessageFromPayload(input: {
    payload: PreparedWithdrawPayload;
    relayer?: ClairAddress | string;
    creator?: ClairAddress | string;
  } & RelayWithdrawRelayOptions): WithdrawMessage;
  createRelayWithdrawSignDoc(input: {
    payload: PreparedWithdrawPayload;
    relayer?: ClairAddress | string;
    creator?: ClairAddress | string;
    pubKeyHex?: Hex;
    pub_key_hex?: Hex;
    gasLimit?: number;
    feeAmount?: Array<object>;
    memo?: string;
  } & RelayWithdrawRelayOptions): Promise<PreparedRelayWithdrawSignDoc>;
  decodeUserDisclosure(input: {
    txHash?: Hex;
    tx_hash?: Hex;
    address?: ClairAddress;
    pubKeyHex?: Hex;
    pub_key_hex?: Hex;
    signatureBase64?: Base64;
    signature_base64?: Base64;
    skipSignerPubKeyCheck?: boolean;
    skip_signer_pubkey_check?: boolean;
    afterHeight?: number;
    after_height?: number;
    page?: number;
    limit?: number;
    maxPages?: number;
    max_pages?: number;
    eventTypes?: string[];
    event_types?: string[];
  }): Promise<import("../core/disclosure.js").DisclosureReport>;
  decodeSelfViewDisclosure(input: {
    txHash?: Hex;
    tx_hash?: Hex;
    address?: ClairAddress;
    pubKeyHex?: Hex;
    pub_key_hex?: Hex;
    signatureBase64?: Base64;
    signature_base64?: Base64;
    skipSignerPubKeyCheck?: boolean;
    skip_signer_pubkey_check?: boolean;
    disclosureScalar?: bigint | string | number;
    disclosure_scalar?: bigint | string | number;
    disclosureScalarHex?: Hex;
    disclosure_scalar_hex?: Hex;
    afterHeight?: number;
    after_height?: number;
    page?: number;
    limit?: number;
    maxPages?: number;
    max_pages?: number;
    eventTypes?: string[];
    event_types?: string[];
  }): Promise<import("../core/disclosure.js").DisclosureReport>;
  decodeAuditDisclosure(input: {
    txHash?: Hex;
    tx_hash?: Hex;
    disclosurePrivKeyHex?: Hex;
    disclosure_privkey_hex?: Hex;
    afterHeight?: number;
    after_height?: number;
    page?: number;
    limit?: number;
    maxPages?: number;
    max_pages?: number;
    eventTypes?: string[];
    event_types?: string[];
  }): Promise<import("../core/disclosure.js").DisclosureReport>;
  buildDirectSignDoc(input: {
    signer: ClairAddress;
    pubKeyHex: Hex;
    messages: Array<{ typeUrl: string; value: object }>;
    memo?: string;
    gasLimit?: number;
    feeAmount?: Array<object>;
  }): Promise<SignDocBase64>;
  buildTxRawBytes(signedTx: SignedTxBase64): Uint8Array;
  broadcastSignedTx(signedTx: SignedTxBase64, waitOptions?: object): Promise<BroadcastSignedTxResult>;
  signDirectAndBroadcast(input: { wallet: WalletAdapterLike; signDoc: SignDocBase64; waitOptions?: object }): Promise<BroadcastSignedTxResult>;
}

export function createClairveilClient(options: {
  rpc: string;
  rest?: string;
  restEndpoints?: string[];
  chainId: string;
  accountPrefix?: string;
  bech32Prefix?: string;
  shieldedPrefix?: string;
  defaultDenom?: string;
  assetDenom?: string;
  registry?: object;
  queryTimeoutMs?: number;
  fetchTimeoutMs?: number;
  queryRetry?: QueryRetryOptions | false;
  nullifierFailover?: boolean;
}): ClairveilJS;

export function nextPrivacyScanOptions(scanOrCursor?: object, defaults?: PrivacyScanOptions & {
  includeFoundNotes?: boolean;
}): PrivacyScanResumeOptions;
