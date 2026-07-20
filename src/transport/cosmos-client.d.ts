export * from "../core/crypto.js";
export * from "../core/disclosure.js";
export * from "../core/errors.js";
export * from "../core/note.js";
export * from "../privacy/payload.js";
export * from "../privacy/planner.js";
export * from "../privacy/prover.js";
export * from "../privacy/reservation.js";
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
import type { TransferBatchPlan, TransferPlan, WithdrawPlan } from "../privacy/planner.js";
import type { ProverAdapter } from "../privacy/prover.js";
import type { NoteReservationManager, ReservationBatch } from "../privacy/reservation.js";
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
  txBytesHash: Hex;
  broadcast: {
    txhash: Hex | string;
    code: number | null;
    raw_log: string;
  };
  tx: TxSearchResult | null;
  error?: string;
}

type RequiredReservationManagerBinding =
  | { reservationManager: NoteReservationManager; reservation_manager?: NoteReservationManager | null }
  | { reservationManager?: NoteReservationManager | null; reservation_manager: NoteReservationManager };

type RequiredReservationBatchBinding =
  | { reservation: ReservationBatch; reservationBatch?: ReservationBatch | null; reservation_batch?: ReservationBatch | null }
  | { reservation?: ReservationBatch | null; reservationBatch: ReservationBatch; reservation_batch?: ReservationBatch | null }
  | { reservation?: ReservationBatch | null; reservationBatch?: ReservationBatch | null; reservation_batch: ReservationBatch };

export type ReservationBroadcastBinding =
  | (RequiredReservationManagerBinding & RequiredReservationBatchBinding)
  | {
      reservationManager?: null;
      reservation_manager?: null;
      reservation?: null;
      reservationBatch?: null;
      reservation_batch?: null;
    };

type RelayBroadcastChainTime =
  | {
      chainNowUnix: number;
      chain_now_unix?: number;
      getChainNowUnix?: never;
      get_chain_now_unix?: never;
    }
  | {
      chainNowUnix?: number;
      chain_now_unix: number;
      getChainNowUnix?: never;
      get_chain_now_unix?: never;
    }
  | {
      chainNowUnix?: never;
      chain_now_unix?: never;
      getChainNowUnix: () => number | Promise<number>;
      get_chain_now_unix?: never;
    }
  | {
      chainNowUnix?: never;
      chain_now_unix?: never;
      getChainNowUnix?: never;
      get_chain_now_unix: () => number | Promise<number>;
    };

export type RelayBroadcastValidation =
  | ((
      | { relayPayload: PreparedWithdrawPayload; relay_payload?: never }
      | { relayPayload?: never; relay_payload: PreparedWithdrawPayload }
    ) & RelayBroadcastChainTime & {
      expectedChainId?: string;
      expected_chain_id?: string;
      expectedRecipient?: ClairAddress | string;
      expected_recipient?: ClairAddress | string;
      accountPrefix?: string;
      account_prefix?: string;
    })
  | {
      relayPayload?: never;
      relay_payload?: never;
      chainNowUnix?: never;
      chain_now_unix?: never;
      getChainNowUnix?: never;
      get_chain_now_unix?: never;
      expectedChainId?: never;
      expected_chain_id?: never;
      expectedRecipient?: never;
      expected_recipient?: never;
      accountPrefix?: never;
      account_prefix?: never;
    };

export type ReservationBroadcastOptions = ReservationBroadcastBinding & RelayBroadcastValidation & {
  attempts?: number;
  intervalMs?: number;
};

export interface ReserveResponse {
  denom: string;
  module_balance: string;
  total_deposited: string;
  total_withdrawn: string;
  expected_module_balance: string;
  invariant_holds: boolean;
}

export type Uint64CursorInput = number | bigint | string;
export type Uint64CursorValue = number | string;

export interface PrivacyEventsQuery {
  afterHeight?: Uint64CursorInput;
  after_height?: Uint64CursorInput;
  afterSequence?: Uint64CursorInput;
  after_sequence?: Uint64CursorInput;
  page?: number;
  limit?: number;
  eventTypes?: string[];
  event_types?: string[];
}

export interface PrivacyScanOptions extends PrivacyEventsQuery {
  maxPages?: number;
  max_pages?: number;
  scanSource?: "scan_events" | "privacy_events" | string;
  scan_source?: "scan_events" | "privacy_events" | string;
}

export type RelayChainTimeInput =
  | { chainNowUnix: number; chain_now_unix?: number }
  | { chainNowUnix?: number; chain_now_unix: number };

type CosmosRelayWithdrawRelayOptions = Omit<RelayWithdrawRelayOptions, "chainNowUnix"> & (
  | {
      chainNowUnix: number;
      /** @deprecated Use chainNowUnix with the latest chain block time. */
      nowUnix?: number;
    }
  | {
      chainNowUnix?: number;
      /** @deprecated Use chainNowUnix with the latest chain block time. */
      nowUnix: number;
    }
);

export interface PrivacyEventsCursor {
  source?: "scan_events" | string;
  after_height: Uint64CursorValue;
  after_sequence?: Uint64CursorValue;
  page?: number;
  limit: number;
  event_types: string[];
  has_more: boolean;
  latest_height: Uint64CursorValue;
  latest_sequence?: Uint64CursorValue;
  latest_tx_hash: Hex | "";
  next_height?: Uint64CursorValue;
  next_sequence?: Uint64CursorValue;
  next_page?: number;
  pages_scanned?: number;
  completed?: boolean;
  scan_format_version?: number;
  view_tag_version?: number;
}

export interface PrivacyScanResumeOptions {
  afterHeight: Uint64CursorValue;
  afterSequence?: Uint64CursorValue;
  page?: number;
  limit: number;
  eventTypes: string[];
  scanSource?: "scan_events" | "privacy_events" | string;
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

export interface ReservationReconciliationWarning {
  code: "reservation_heartbeat_failed_after_proof_ready";
  message: string;
  cause?: string;
}

export interface ReservationReconciliationState {
  reservationReconciliationRequired?: true;
  reservationReconciliationWarning?: ReservationReconciliationWarning;
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
  reservation?: ReservationBatch | null;
}

export interface PreparedTransfer extends ReservationReconciliationState {
  status: string;
  plan: TransferPlan;
  scan: ScanResult;
  signDoc?: SignDocBase64;
  payload?: PreparedTransferPayload;
  proof?: PreparedTransferProof;
  message?: TransferMessage;
  reservation?: ReservationBatch | null;
  prepared?: PreparedTransferSummary;
  privacyAccount: PrivacyAccountSummary;
}

export interface PreparedTransferBatchSummary {
  planAction: "batch_transfer";
  amounts: CoinString[];
  recipient: ShieldedAddress;
  selectedInputTotals: string[];
  reservation?: ReservationBatch | null;
}

export interface PreparedTransferBatch extends ReservationReconciliationState {
  status: string;
  plan: TransferBatchPlan;
  scan: ScanResult;
  signDoc?: SignDocBase64;
  payloads?: PreparedTransferPayload[];
  proofs?: PreparedTransferProof[];
  messages?: TransferMessage[];
  reservation?: ReservationBatch | null;
  prepared?: PreparedTransferBatchSummary;
  privacyAccount: PrivacyAccountSummary;
}

interface PreparedWithdrawBase extends ReservationReconciliationState {
  plan: WithdrawPlan;
  scan: ScanResult;
  reservation?: ReservationBatch | null;
  privacyAccount: PrivacyAccountSummary;
}

export interface PreparedWithdrawReady extends PreparedWithdrawBase {
  status: "ready";
  signDoc: SignDocBase64;
  proverPayload: PreparedWithdrawProverPayload;
  proof: PreparedWithdrawProof;
  payload: PreparedWithdrawPayload;
  message: WithdrawMessage;
  selectedNote: FoundNote;
}

export interface PreparedWithdrawNotReady extends PreparedWithdrawBase {
  status: Exclude<WithdrawPlan["status"], "withdraw_ready">;
  signDoc?: never;
  proverPayload?: never;
  proof?: never;
  payload?: never;
  message?: never;
  selectedNote?: never;
}

export type PreparedWithdraw = PreparedWithdrawReady | PreparedWithdrawNotReady;

export interface PreparedRelayWithdraw extends ReservationReconciliationState {
  status: string;
  plan: WithdrawPlan;
  scan: ScanResult;
  proverPayload?: PreparedWithdrawProverPayload;
  proof?: PreparedWithdrawProof;
  payload?: PreparedWithdrawPayload;
  selectedNote?: FoundNote;
  reservation?: ReservationBatch | null;
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
export function cosmosSignDocBindingHash(signDoc: Pick<SignDocBase64, "bodyBytes" | "authInfoBytes">): Hex;

export type DirectOperationEvidenceHashes =
  | {
      expectedRecipientHash?: never;
      expected_recipient_hash?: never;
      expectedAmountHash?: never;
      expected_amount_hash?: never;
    }
  | {
      expectedRecipientHash: string;
      expectedAmountHash: string;
      expected_recipient_hash?: string;
      expected_amount_hash?: string;
    }
  | {
      expected_recipient_hash: string;
      expected_amount_hash: string;
      expectedRecipientHash?: string;
      expectedAmountHash?: string;
    }
  | {
      expectedRecipientHash: string;
      expected_amount_hash: string;
      expected_recipient_hash?: string;
      expectedAmountHash?: string;
    }
  | {
      expected_recipient_hash: string;
      expectedAmountHash: string;
      expectedRecipientHash?: string;
      expected_amount_hash?: string;
    };

type BatchRecipientHashEvidence =
  | {
      expectedRecipientHash: string;
      expected_recipient_hash?: string;
      expectedRecipientHashes?: readonly string[];
      expected_recipient_hashes?: readonly string[];
    }
  | {
      expected_recipient_hash: string;
      expectedRecipientHash?: string;
      expectedRecipientHashes?: readonly string[];
      expected_recipient_hashes?: readonly string[];
    }
  | {
      expectedRecipientHashes: readonly string[];
      expectedRecipientHash?: string;
      expected_recipient_hash?: string;
      expected_recipient_hashes?: readonly string[];
    }
  | {
      expected_recipient_hashes: readonly string[];
      expectedRecipientHash?: string;
      expected_recipient_hash?: string;
      expectedRecipientHashes?: readonly string[];
    };

type BatchAmountHashEvidence =
  | {
      expectedAmountHashes: readonly string[];
      expected_amount_hashes?: readonly string[];
    }
  | {
      expected_amount_hashes: readonly string[];
      expectedAmountHashes?: readonly string[];
    };

export type BatchOperationEvidenceHashes =
  | {
      expectedRecipientHash?: never;
      expected_recipient_hash?: never;
      expectedRecipientHashes?: never;
      expected_recipient_hashes?: never;
      expectedAmountHashes?: never;
      expected_amount_hashes?: never;
    }
  | (BatchRecipientHashEvidence & BatchAmountHashEvidence);

export type PrepareTransferBatchInput = {
  wallet?: WalletAdapterLike;
  material?: PrivacyMaterial;
  amounts: CoinString[];
  recipient: ShieldedAddress;
  proverAdapter: ProverAdapter;
  gasLimit?: number;
  userPrivacyPolicy?: string | number;
  userDisclosureMode?: string | number;
  userDisclosureTargetPubKeyHex?: Hex;
  auditDisclosureTargetPubKeyHex?: Hex;
  denom?: string;
  afterHeight?: Uint64CursorInput;
  after_height?: Uint64CursorInput;
  afterSequence?: Uint64CursorInput;
  after_sequence?: Uint64CursorInput;
  page?: number;
  limit?: number;
  maxPages?: number;
  max_pages?: number;
  eventTypes?: string[];
  event_types?: string[];
  scan?: PrivacyScanOptions;
  scanSource?: "scan_events" | "privacy_events" | string;
  scan_source?: "scan_events" | "privacy_events" | string;
  reservationManager?: NoteReservationManager | null;
  reservation_manager?: NoteReservationManager | null;
} & BatchOperationEvidenceHashes;

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
    method?: string;
    body?: BodyInit | null;
    headers?: Record<string, string>;
    endpoint?: string;
    updateActiveEndpoint?: boolean;
  }): Promise<T>;
  fetchNullifierJson<T = object>(path: string, options?: {
    retry?: QueryRetryOptions | false;
    method?: string;
    body?: BodyInit | null;
    headers?: Record<string, string>;
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
  checkNullifiers(nullifierHexes: readonly Hex[]): Promise<Map<Hex, boolean>>;
  deriveWalletPrivacyMaterial(wallet: WalletAdapterLike): Promise<PrivacyMaterial>;
  scanNotes(input: WalletScanInput): Promise<ScanResult & {
    scanCursor: PrivacyEventsCursor;
    nextScanOptions: PrivacyScanResumeOptions;
  }>;
  fetchScanEvents(options?: PrivacyEventsQuery): Promise<object & {
    events?: object[];
    next_height?: Uint64CursorValue;
    next_sequence?: Uint64CursorValue;
    has_more?: boolean;
    scan_format_version?: number;
    view_tag_version?: number;
  }>;
  fetchAuditableTransfers(options?: PrivacyEventsQuery): Promise<object & { events: object[] }>;
  findPrivacyEventByTxHash(txHash: Hex, options?: PrivacyScanOptions): Promise<object>;
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
    scanSource?: "scan_events" | "privacy_events" | string;
    scan_source?: "scan_events" | "privacy_events" | string;
  }): Promise<{ plan: TransferPlan; scan: ScanResult }>;
  planWalletWithdraw(input: {
    wallet?: WalletAdapterLike;
    material?: PrivacyMaterial;
    amount: CoinString;
    denom?: string;
    limit?: number;
    maxPages?: number;
    scan?: PrivacyScanOptions;
    scanSource?: "scan_events" | "privacy_events" | string;
    scan_source?: "scan_events" | "privacy_events" | string;
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
    afterHeight?: Uint64CursorInput;
    after_height?: Uint64CursorInput;
    afterSequence?: Uint64CursorInput;
    after_sequence?: Uint64CursorInput;
    page?: number;
    limit?: number;
    maxPages?: number;
    max_pages?: number;
    eventTypes?: string[];
    event_types?: string[];
    scan?: PrivacyScanOptions;
    scanSource?: "scan_events" | "privacy_events" | string;
    scan_source?: "scan_events" | "privacy_events" | string;
    reservationManager?: NoteReservationManager | null;
    reservation_manager?: NoteReservationManager | null;
  } & DirectOperationEvidenceHashes): Promise<PreparedTransfer>;
  prepareTransferBatch(input: PrepareTransferBatchInput): Promise<PreparedTransferBatch>;
  prepareWithdraw(input: {
    wallet?: WalletAdapterLike;
    material?: PrivacyMaterial;
    amount: CoinString;
    recipient: ClairAddress;
    proverAdapter: ProverAdapter;
    gasLimit?: number;
    denom?: string;
    assetDenom?: string;
    afterHeight?: Uint64CursorInput;
    after_height?: Uint64CursorInput;
    afterSequence?: Uint64CursorInput;
    after_sequence?: Uint64CursorInput;
    page?: number;
    limit?: number;
    maxPages?: number;
    max_pages?: number;
    eventTypes?: string[];
    event_types?: string[];
    scan?: PrivacyScanOptions;
    scanSource?: "scan_events" | "privacy_events" | string;
    scan_source?: "scan_events" | "privacy_events" | string;
    expiresAtUnix?: number;
    chainNowUnix?: number;
    chain_now_unix?: number;
    reservationManager?: NoteReservationManager | null;
    reservation_manager?: NoteReservationManager | null;
  }): Promise<PreparedWithdraw>;
  prepareRelayWithdraw(input: {
    wallet?: WalletAdapterLike;
    material?: PrivacyMaterial;
    amount: CoinString;
    recipient: ClairAddress;
    proverAdapter: ProverAdapter;
    denom?: string;
    assetDenom?: string;
    afterHeight?: Uint64CursorInput;
    after_height?: Uint64CursorInput;
    afterSequence?: Uint64CursorInput;
    after_sequence?: Uint64CursorInput;
    page?: number;
    limit?: number;
    maxPages?: number;
    max_pages?: number;
    eventTypes?: string[];
    event_types?: string[];
    scan?: PrivacyScanOptions;
    scanSource?: "scan_events" | "privacy_events" | string;
    scan_source?: "scan_events" | "privacy_events" | string;
    expiresAtUnix?: number;
    reservationManager?: NoteReservationManager | null;
    reservation_manager?: NoteReservationManager | null;
  } & RelayChainTimeInput): Promise<PreparedRelayWithdraw>;
  createDepositSignDoc(input: Parameters<ClairveilJS["prepareDeposit"]>[0]): Promise<PreparedDeposit>;
  createTransferSignDoc(input: Parameters<ClairveilJS["prepareTransfer"]>[0]): Promise<PreparedTransfer & { status: "ready"; signDoc: SignDocBase64 }>;
  createTransferBatchSignDoc(input: Parameters<ClairveilJS["prepareTransferBatch"]>[0]): Promise<PreparedTransferBatch & { status: "ready"; signDoc: SignDocBase64 }>;
  createWithdrawSignDoc(input: Parameters<ClairveilJS["prepareWithdraw"]>[0]): Promise<PreparedWithdrawReady>;
  createRelayWithdrawPayload(input: Parameters<ClairveilJS["prepareRelayWithdraw"]>[0]): Promise<PreparedRelayWithdraw & { status: "ready"; payload: PreparedWithdrawPayload }>;
  buildPreparedTransferPayload(input: PreparedTransferPayloadInput): Promise<PreparedTransferPayload>;
  buildTransferMessage(input: PreparedTransferPayloadInput & {
    proverAdapter: ProverAdapter;
    checkNullifiers?: import("../privacy/payload.js").NullifierStatusReader;
  }): Promise<TransferMessageBuildResult>;
  buildPreparedWithdrawProverPayload(input: PreparedWithdrawProverPayloadInput): Promise<PreparedWithdrawProverPayloadResult>;
  buildRelayWithdrawPayload(input: Omit<PreparedWithdrawProverPayloadInput, "chainNowUnix"> & {
    chainNowUnix: number;
    proverAdapter: ProverAdapter;
    checkNullifiers?: import("../privacy/payload.js").NullifierStatusReader;
  }): Promise<RelayWithdrawPayloadBuildResult>;
  buildWithdrawMessage(input: PreparedWithdrawProverPayloadInput & {
    proverAdapter: ProverAdapter;
    creator?: ClairAddress | string;
    checkNullifiers?: import("../privacy/payload.js").NullifierStatusReader;
  }): Promise<WithdrawMessageBuildResult>;
  buildRelayWithdrawMessageFromPayload(input: {
    payload: PreparedWithdrawPayload;
    relayer?: ClairAddress | string;
    creator?: ClairAddress | string;
  } & CosmosRelayWithdrawRelayOptions): WithdrawMessage;
  createRelayWithdrawSignDoc(input: {
    payload: PreparedWithdrawPayload;
    relayer?: ClairAddress | string;
    creator?: ClairAddress | string;
    pubKeyHex?: Hex;
    pub_key_hex?: Hex;
    gasLimit?: number;
    feeAmount?: Array<object>;
    memo?: string;
  } & CosmosRelayWithdrawRelayOptions): Promise<PreparedRelayWithdrawSignDoc>;
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
  } & PrivacyScanOptions): Promise<import("../core/disclosure.js").DisclosureReport>;
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
  } & PrivacyScanOptions): Promise<import("../core/disclosure.js").DisclosureReport>;
  decodeAuditDisclosure(input: {
    txHash?: Hex;
    tx_hash?: Hex;
    disclosurePrivKeyHex?: Hex;
    disclosure_privkey_hex?: Hex;
  } & PrivacyScanOptions): Promise<import("../core/disclosure.js").DisclosureReport>;
  buildDirectSignDoc(input: {
    signer: ClairAddress;
    pubKeyHex: Hex;
    messages: Array<{ typeUrl: string; value: object }>;
    memo?: string;
    gasLimit?: number;
    feeAmount?: Array<object>;
  }): Promise<SignDocBase64>;
  buildTxRawBytes(signedTx: SignedTxBase64): Uint8Array;
  broadcastSignedTx(signedTx: SignedTxBase64, waitOptions?: ReservationBroadcastOptions): Promise<BroadcastSignedTxResult>;
  signDirectAndBroadcast(input: ReservationBroadcastOptions & { wallet: WalletAdapterLike; signDoc: SignDocBase64; waitOptions?: { attempts?: number; intervalMs?: number } }): Promise<BroadcastSignedTxResult>;
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
