import type { PrivacyScanValidationStateSnapshotV2 } from "../privacy/scan.js";

export * from "../core/crypto.js";
export * from "../core/disclosure.js";
export * from "../core/errors.js";
export * from "../core/note.js";
export * from "../privacy/payload.js";
export * from "../privacy/circuit-config.js";
export * from "../privacy/network-config.js";
export * from "../privacy/planner.js";
export * from "../privacy/prover.js";
export * from "../privacy/reservation.js";
export * from "../privacy/scan.js";
export * from "../privacy/merkle-path.js";
export * from "../privacy/note-store.js";
export * from "../core/schemas.js";
export * from "../wallet/adapter.js";
export {
  UserDisclosureMode,
  userDisclosureModeFromJSON,
  userDisclosureModeToJSON
} from "../generated/clairveil/privacy/v1/tx.js";
export type {
  AssetRegistryEntryV1,
  CircuitIdentity,
  CircuitSetIdentity,
  PrivacyScanCursorV1,
  PrivacyScanOutputV2,
  PrivacyScanSummaryV2
} from "../generated/clairveil/privacy/v1/genesis.js";
export type {
  BatchTransferOutput,
  MsgBatchTransfer as MsgBatchTransferMessage,
  MsgDeposit as MsgDepositMessage,
  MsgTransfer as MsgTransferMessage,
  MsgWithdraw as MsgWithdrawMessage,
  MsgBatchTransferResponse,
  MsgDepositResponse,
  MsgTransferResponse,
  MsgWithdrawResponse
} from "../generated/clairveil/privacy/v1/tx.js";
export type {
  QueryAssetByDenomResponse,
  QueryAssetByIDResponse,
  QueryAuditConfigResponse,
  QueryCheckNullifierResponse,
  QueryCircuitConfigResponse,
  QueryCommitmentInfoResponse,
  QueryDisclosureConfigResponse,
  QueryMerklePathResponse,
  QueryPrivacyEvent,
  QueryPrivacyEventAttribute,
  QueryPrivacyEventsResponse,
  QueryPrivacyScanResponse,
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
import type { VerifiedCommitmentPathSnapshot } from "../privacy/merkle-path.js";
import type { MemoryNoteStore } from "../privacy/note-store.js";
import type { WalletAdapterLike } from "../wallet/adapter.js";
import type {
  NormalizedAssetRegistryEntryV1,
  NormalizedAssetRegistryQueryResponseV1
} from "../privacy/asset-registry.js";
import type {
  CircuitSetIdentityV1,
  ValidatedCircuitConfigV1
} from "../privacy/circuit-config.js";
import type {
  MsgBatchTransfer as MsgBatchTransferMessage,
  MsgDeposit as MsgDepositMessage
} from "../generated/clairveil/privacy/v1/tx.js";

export const msgDepositTypeUrl: "/clairveil.privacy.v1.MsgDeposit";
export const msgBatchTransferTypeUrl: "/clairveil.privacy.v1.MsgBatchTransfer";
export const msgTransferTypeUrl: "/clairveil.privacy.v1.MsgTransfer";
export const msgWithdrawTypeUrl: "/clairveil.privacy.v1.MsgWithdraw";

export interface MsgCodec<T = object> {
  typeUrl: string;
  encode(message: Partial<T>, writer?: object): object;
  decode(input?: Uint8Array): T;
  fromPartial(object: Partial<T>): T;
}

export const MsgDeposit: MsgCodec;
export const MsgBatchTransfer: MsgCodec;
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

/** Exact wallet-produced TxRaw bytes, suitable for private durable checkpointing. */
export interface SignedTxRawCheckpoint {
  signedTx: SignedTxBase64;
  txRawBytes: Uint8Array;
  txBytesHash: Hex;
  signDocHash: Hex;
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
  after?: PrivacyScanCursorInput;
  outputLimit?: number;
  output_limit?: number;
  eventLimit?: number;
  event_limit?: number;
  maxEncodedBytes?: Uint64CursorInput;
  max_encoded_bytes?: Uint64CursorInput;
  maxPages?: number;
  max_pages?: number;
  /** Durable typed-page state returned by nextPrivacyScanOptions. */
  validationStateSnapshot?: PrivacyScanValidationStateSnapshotV2;
  validation_state_snapshot?: PrivacyScanValidationStateSnapshotV2;
  scanSource?: "privacy_scan" | "scan_events" | "privacy_events" | string;
  scan_source?: "privacy_scan" | "scan_events" | "privacy_events" | string;
}

export interface PrivacyScanCursorInput {
  height?: Uint64CursorInput;
  globalSequence?: Uint64CursorInput;
  global_sequence?: Uint64CursorInput;
  outputIndex?: number;
  output_index?: number;
}

export interface TypedPrivacyScanQuery {
  after?: PrivacyScanCursorInput;
  outputLimit?: number;
  output_limit?: number;
  eventLimit?: number;
  event_limit?: number;
  maxEncodedBytes?: Uint64CursorInput;
  max_encoded_bytes?: Uint64CursorInput;
  eventTypes?: string[];
  event_types?: string[];
}

export interface CommitmentPathsAtRootQuery {
  commitmentHexes?: readonly Hex[];
  commitment_hexes?: readonly Hex[];
  rootHex?: Hex;
  root_hex?: Hex;
  snapshotHeight?: Uint64CursorInput;
  snapshot_height?: Uint64CursorInput;
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
  source?: "privacy_scan" | "scan_events" | "privacy_events" | string;
  after?: { height?: Uint64CursorValue; globalSequence?: Uint64CursorValue; global_sequence?: Uint64CursorValue; outputIndex?: number; output_index?: number };
  next_cursor?: { height?: Uint64CursorValue; globalSequence?: Uint64CursorValue; global_sequence?: Uint64CursorValue; outputIndex?: number; output_index?: number };
  /** Validated state persisted with a partial privacy_scan cursor. */
  validation_state?: PrivacyScanValidationStateSnapshotV2;
  output_limit?: number;
  event_limit?: number;
  max_encoded_bytes?: Uint64CursorInput;
  latest_output_index?: number;
  after_height?: Uint64CursorValue;
  after_sequence?: Uint64CursorValue;
  page?: number;
  limit?: number;
  event_types: string[];
  has_more: boolean;
  latest_height: Uint64CursorValue;
  latest_sequence?: Uint64CursorValue;
  latest_tx_hash?: Hex | "";
  next_height?: Uint64CursorValue;
  next_sequence?: Uint64CursorValue;
  next_page?: number;
  pages_scanned?: number;
  completed?: boolean;
  scan_format_version?: number;
  view_tag_version?: number;
}

export interface PrivacyScanResumeOptions {
  after?: { height?: Uint64CursorValue; globalSequence?: Uint64CursorValue; global_sequence?: Uint64CursorValue; outputIndex?: number; output_index?: number };
  afterHeight?: Uint64CursorValue;
  afterSequence?: Uint64CursorValue;
  page?: number;
  limit: number;
  eventTypes: string[];
  outputLimit?: number;
  eventLimit?: number | Uint64CursorValue;
  maxEncodedBytes?: Uint64CursorValue;
  scanSource?: "privacy_scan" | "scan_events" | "privacy_events" | string;
  maxPages?: number;
  validationStateSnapshot?: PrivacyScanValidationStateSnapshotV2;
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
  expectedCircuitIdentity?: CircuitSetIdentityV1;
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
  scanSource?: "privacy_scan" | "scan_events" | "privacy_events" | string;
  scan_source?: "privacy_scan" | "scan_events" | "privacy_events" | string;
  reservationManager?: NoteReservationManager | null;
  reservation_manager?: NoteReservationManager | null;
} & PrivacyScanOptions & BatchOperationEvidenceHashes;

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
  fetchPrivacyScan(options?: TypedPrivacyScanQuery): Promise<object>;
  fetchTreeState(): Promise<object>;
  fetchCommitmentInfo(commitmentHex: Hex): Promise<object>;
  fetchAuditConfig(): Promise<object>;
  fetchDisclosureConfig(): Promise<object>;
  queryAuditConfig(): Promise<import("../privacy/network-config.js").ValidatedAuditConfigV1>;
  queryDisclosureConfig(): Promise<import("../privacy/network-config.js").ValidatedDisclosureConfigV1>;
  fetchCircuitConfig(options?: { expectedCircuitIdentity?: ValidatedCircuitConfigV1["circuit_set_identity"] }): Promise<ValidatedCircuitConfigV1>;
  assertCircuitConfig(options?: { expectedCircuitIdentity?: ValidatedCircuitConfigV1["circuit_set_identity"] }): Promise<ValidatedCircuitConfigV1>;
  fetchReserve(denom: string): Promise<ReserveResponse>;
  queryReserve(denom: string): Promise<import("../privacy/network-config.js").ValidatedReserveResponseV1>;
  fetchAssetByDenom(denom: string): Promise<object>;
  fetchAssetByID(assetIdHex: Hex): Promise<object>;
  queryAssetByDenom(denom: string): Promise<NormalizedAssetRegistryQueryResponseV1>;
  queryAssetByID(assetIdHex: Hex): Promise<NormalizedAssetRegistryQueryResponseV1>;
  resolveAsset(denom: string): Promise<NormalizedAssetRegistryEntryV1>;
  resolveAssetByDenom(denom: string): Promise<NormalizedAssetRegistryEntryV1>;
  resolveAssetByID(assetIdHex: Hex): Promise<NormalizedAssetRegistryEntryV1>;
  assertProtocolPreflight(denom: string): Promise<{ circuit_config: ValidatedCircuitConfigV1; asset: NormalizedAssetRegistryEntryV1 }>;
  assertTransferProtocolConfig(denom: string): Promise<{
    circuit_config: ValidatedCircuitConfigV1;
    asset: NormalizedAssetRegistryEntryV1;
    audit_config: import("../privacy/network-config.js").ValidatedAuditConfigV1;
    disclosure_config: import("../privacy/network-config.js").ValidatedDisclosureConfigV1;
  }>;
  fetchCommitmentPathsAtRoot(options: CommitmentPathsAtRootQuery): Promise<object>;
  queryCommitmentPathsAtRoot(options: CommitmentPathsAtRootQuery): Promise<VerifiedCommitmentPathSnapshot>;
  createCommitmentPathSnapshotProvider(options: CommitmentPathsAtRootQuery): Promise<{
    lookupMerklePath(commitmentHex: Hex): Promise<object>;
  }>;
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
    scanSource?: "privacy_scan" | "scan_events" | "privacy_events" | string;
    scan_source?: "privacy_scan" | "scan_events" | "privacy_events" | string;
  }): Promise<{ plan: TransferPlan; scan: ScanResult }>;
  planWalletWithdraw(input: {
    wallet?: WalletAdapterLike;
    material?: PrivacyMaterial;
    amount: CoinString;
    denom?: string;
    limit?: number;
    maxPages?: number;
    scan?: PrivacyScanOptions;
    scanSource?: "privacy_scan" | "scan_events" | "privacy_events" | string;
    scan_source?: "privacy_scan" | "scan_events" | "privacy_events" | string;
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
    scanSource?: "privacy_scan" | "scan_events" | "privacy_events" | string;
    scan_source?: "privacy_scan" | "scan_events" | "privacy_events" | string;
    reservationManager?: NoteReservationManager | null;
    reservation_manager?: NoteReservationManager | null;
  } & PrivacyScanOptions & DirectOperationEvidenceHashes): Promise<PreparedTransfer>;
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
    scanSource?: "privacy_scan" | "scan_events" | "privacy_events" | string;
    scan_source?: "privacy_scan" | "scan_events" | "privacy_events" | string;
    expiresAtUnix?: number;
    chainNowUnix?: number;
    chain_now_unix?: number;
    reservationManager?: NoteReservationManager | null;
    reservation_manager?: NoteReservationManager | null;
  } & PrivacyScanOptions): Promise<PreparedWithdraw>;
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
    scanSource?: "privacy_scan" | "scan_events" | "privacy_events" | string;
    scan_source?: "privacy_scan" | "scan_events" | "privacy_events" | string;
    expiresAtUnix?: number;
    reservationManager?: NoteReservationManager | null;
    reservation_manager?: NoteReservationManager | null;
  } & PrivacyScanOptions & RelayChainTimeInput): Promise<PreparedRelayWithdraw>;
  createDepositSignDoc(input: Parameters<ClairveilJS["prepareDeposit"]>[0]): Promise<PreparedDeposit>;
  createTransferSignDoc(input: Parameters<ClairveilJS["prepareTransfer"]>[0]): Promise<PreparedTransfer & { status: "ready"; signDoc: SignDocBase64 }>;
  createTransferBatchSignDoc(input: Parameters<ClairveilJS["prepareTransferBatch"]>[0]): Promise<PreparedTransferBatch & { status: "ready"; signDoc: SignDocBase64 }>;
  createBatchTransferSignDoc(input: {
    signer: ClairAddress;
    pubKeyHex: Hex;
    gasLimit: number | bigint;
    message: MsgBatchTransferMessage;
    memo?: string;
    expectedCircuitIdentity?: ValidatedCircuitConfigV1["circuit_set_identity"];
  }): Promise<SignDocBase64>;
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
  decodeBatchUserDisclosure(input: {
    /** One output from `validatePrivacyScanPageV2`, never a lossy ABCI event. */
    output?: import("../core/disclosure.js").BatchPrivacyScanDisclosureOutputV2;
    /** Alias for `output`. */
    scanOutput?: import("../core/disclosure.js").BatchPrivacyScanDisclosureOutputV2;
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
    disclosurePubKeyHex?: Hex;
    disclosure_pubkey_hex?: Hex;
    assetDenom?: string;
    asset_denom?: string;
  }): Promise<import("../core/disclosure.js").DisclosureReport>;
  decodeBatchSelfViewDisclosure(input: {
    /** One output from `validatePrivacyScanPageV2`, never a lossy ABCI event. */
    output?: import("../core/disclosure.js").BatchPrivacyScanDisclosureOutputV2;
    /** Alias for `output`. */
    scanOutput?: import("../core/disclosure.js").BatchPrivacyScanDisclosureOutputV2;
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
    assetDenom?: string;
    asset_denom?: string;
  }): Promise<import("../core/disclosure.js").DisclosureReport>;
  decodeBatchAuditDisclosure(input: {
    /** One output from `validatePrivacyScanPageV2`, never a lossy ABCI event. */
    output?: import("../core/disclosure.js").BatchPrivacyScanDisclosureOutputV2;
    /** Alias for `output`. */
    scanOutput?: import("../core/disclosure.js").BatchPrivacyScanDisclosureOutputV2;
    txHash?: Hex;
    tx_hash?: Hex;
    disclosurePrivKeyHex?: Hex;
    disclosure_privkey_hex?: Hex;
    disclosureScalar?: bigint | string | number;
    disclosure_scalar?: bigint | string | number;
    disclosureScalarHex?: Hex;
    disclosure_scalar_hex?: Hex;
    assetDenom?: string;
    asset_denom?: string;
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
  /** Broadcast exact pre-encoded TxRaw bytes without re-encoding them. */
  broadcastTxRawBytes(txRawBytes: Uint8Array, waitOptions?: ReservationBroadcastOptions): Promise<BroadcastSignedTxResult>;
  broadcastSignedTx(signedTx: SignedTxBase64, waitOptions?: ReservationBroadcastOptions): Promise<BroadcastSignedTxResult>;
  /** Sign without broadcasting so callers can durably checkpoint exact TxRaw bytes first. */
  signDirect(input: ReservationBroadcastOptions & { wallet: WalletAdapterLike; signDoc: SignDocBase64; waitOptions?: { attempts?: number; intervalMs?: number } }): Promise<SignedTxRawCheckpoint>;
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
  expectedCircuitIdentity?: CircuitSetIdentityV1;
}): ClairveilJS;

export function nextPrivacyScanOptions(scanOrCursor?: object, defaults?: PrivacyScanOptions & {
  includeFoundNotes?: boolean;
}): PrivacyScanResumeOptions;
