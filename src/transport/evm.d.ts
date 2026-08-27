import type { BytesLike, ClairAddress, Hex, PrivacyMaterial, ShieldedAddress } from "../core/crypto.js";
import type { CoinString, DepositMaterial, FoundNote } from "../core/note.js";
import type { PrefixedHex } from "../wallet/adapter.js";
import type {
  PreparedTransferPayload,
  PreparedTransferPayloadInput,
  PreparedTransferProof,
  PreparedWithdrawPayload,
  PreparedWithdrawProof,
  PreparedWithdrawProverPayload,
  PreparedWithdrawProverPayloadInput,
  PreparedWithdrawProverPayloadResult,
  NullifierStatusReader,
  TransferMessage,
  WithdrawMessage
} from "../privacy/payload.js";
import type { ProverAdapter } from "../privacy/prover.js";
import type { NoteReservationManager, ReservationBatch } from "../privacy/reservation.js";

export * from "./evm-finality.js";

/** @deprecated Resolve the privacy contract address from the active chain configuration. */
export const evmPrivacyPrecompileAddress: "0x100000000000000000000000000000000000000b";
/** @deprecated Use an explicit chain-configured contractAddress. */
export const defaultEvmPrivacyPrecompileAddress: typeof evmPrivacyPrecompileAddress;

export interface Eip1193Provider {
  request(input: { method: string; params?: unknown[] }): Promise<unknown>;
}

export type EvmQuantity = Hex | string;
export type EvmBlockTag = "earliest" | "latest" | "pending" | "safe" | "finalized" | EvmQuantity;
export type EvmDepositMode = "nonpayable" | "payable-exact-value";

export interface EvmTransactionRequest {
  from?: string;
  to: string;
  data?: string;
  value?: EvmQuantity;
  gas?: EvmQuantity;
  gasPrice?: EvmQuantity;
  maxFeePerGas?: EvmQuantity;
  maxPriorityFeePerGas?: EvmQuantity;
  nonce?: EvmQuantity;
  chainId?: EvmQuantity;
}

export interface EvmRpcTransaction extends Partial<EvmTransactionRequest> {
  hash: Hex | string;
  from: string;
  to: string;
  input?: string;
  value: EvmQuantity;
}

export interface EvmTransactionIdentityVerification {
  readonly verified: true;
  readonly operation: string;
  readonly txHash: Hex | string;
  readonly sender: string;
  readonly to: string;
  readonly data: string;
  readonly value: EvmQuantity;
  readonly chainId: EvmQuantity;
  readonly txBytesHash: Hex;
}

export interface EvmPrivacyReceiptVerification {
  readonly verified: true;
  readonly event: string;
  readonly operation: string;
}

export interface EvmPrivacyReceiptVerifierInput {
  transaction: EvmTransactionRequest;
  receipt: { status?: EvmQuantity; logs?: EvmLog[] };
  sender: string;
  contractAddress: string;
  operation: string;
}

export type EvmPrivacyReceiptVerifier = (
  input: Readonly<EvmPrivacyReceiptVerifierInput>
) => EvmPrivacyReceiptVerification;

type EvmReservationManagerBinding =
  | { reservationManager: NoteReservationManager; reservation_manager?: NoteReservationManager | null }
  | { reservationManager?: NoteReservationManager | null; reservation_manager: NoteReservationManager };

type EvmReservationBatchBinding =
  | { reservation: ReservationBatch; reservationBatch?: ReservationBatch | null; reservation_batch?: ReservationBatch | null }
  | { reservation?: ReservationBatch | null; reservationBatch: ReservationBatch; reservation_batch?: ReservationBatch | null }
  | { reservation?: ReservationBatch | null; reservationBatch?: ReservationBatch | null; reservation_batch: ReservationBatch };

type EvmReservationBroadcastBinding =
  | (EvmReservationManagerBinding & EvmReservationBatchBinding)
  | {
      reservationManager?: null;
      reservation_manager?: null;
      reservation?: null;
      reservationBatch?: null;
      reservation_batch?: null;
    };

type EvmRelayBroadcastChainTime =
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

export type EvmRelayBroadcastValidation =
  | ((
      | { relayPayload: PreparedWithdrawPayload; relay_payload?: never }
      | { relayPayload?: never; relay_payload: PreparedWithdrawPayload }
    ) & EvmRelayBroadcastChainTime & {
      expectedChainId?: string;
      expected_chain_id?: string;
      expectedRecipient?: ClairAddress | string;
      expected_recipient?: ClairAddress | string;
      expectedEvmChainId?: EvmQuantity;
      expected_evm_chain_id?: EvmQuantity;
      accountPrefix?: string;
      account_prefix?: string;
      relayTransactionOptions?: EvmPrivacyTransactionOptions;
      relay_transaction_options?: EvmPrivacyTransactionOptions;
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
      expectedEvmChainId?: never;
      expected_evm_chain_id?: never;
      accountPrefix?: never;
      account_prefix?: never;
      relayTransactionOptions?: never;
      relay_transaction_options?: never;
    };

export type EvmReservationBroadcastOptions = EvmReservationBroadcastBinding &
  EvmRelayBroadcastValidation & {
    /** Required for every reserved or relayed spend; re-read immediately before wallet submission. */
    checkNullifiers?: NullifierStatusReader;
    check_nullifiers?: NullifierStatusReader;
  };

export interface EvmCallRequest extends Partial<Omit<EvmTransactionRequest, "to">> {
  to?: string;
}

export interface EvmLogFilter {
  address?: string | string[];
  fromBlock?: EvmBlockTag;
  toBlock?: EvmBlockTag;
  blockHash?: Hex;
  topics?: Array<Hex | Hex[] | null>;
}

export interface EvmLog {
  address: string;
  blockHash?: Hex;
  blockNumber?: EvmQuantity;
  data: Hex;
  logIndex?: EvmQuantity;
  removed?: boolean;
  topics: Hex[];
  transactionHash?: Hex;
  transactionIndex?: EvmQuantity;
}

export interface AbiParameter {
  name?: string;
  type: string;
  components?: AbiParameter[];
  indexed?: boolean;
}

export interface AbiFunction {
  type: "function";
  name: string;
  inputs?: readonly AbiParameter[];
  outputs?: readonly AbiParameter[];
  stateMutability?: "pure" | "view" | "nonpayable" | "payable";
}

export type AbiItem = AbiFunction | AbiParameter | Record<string, unknown>;

export interface EvmDepositMessage {
  amount: CoinString;
  noteCommitment: BytesLike;
  encryptedNote: BytesLike;
  /** DepositCircuit proof binding the transparent amount, asset, and note commitment. */
  proof: BytesLike;
}

export interface EvmWithdrawMessage extends WithdrawMessage {
  evmRecipient?: string;
  evm_recipient?: string;
  recipientAddress?: string;
  recipient_address?: string;
}

export interface EvmPrivacyTransactionOptions {
  /** Must be zero except for an exact amount-derived payable deposit. */
  value?: EvmQuantity;
  signature?: string;
  accountPrefix?: string;
  chainId?: string | number;
}

export type EvmDepositEncoder = (message: EvmDepositMessage, options?: EvmPrivacyTransactionOptions) => Hex;
export type EvmTransferEncoder = (message: TransferMessage, options?: EvmPrivacyTransactionOptions) => Hex;
export type EvmWithdrawEncoder = (message: EvmWithdrawMessage, options?: EvmPrivacyTransactionOptions) => Hex;

/** EIP-712 authorization envelope accepted by an EVM privacy contract. */
export interface EvmPrivacyActionAuthorization {
  effectiveSender: string;
  executor: string;
  nonce: string | number | bigint;
  deadline: string | number | bigint;
  authorizationKind: string | number | bigint;
  signature: BytesLike;
}

export type EvmPrivacyAuthorizationRequest = Omit<EvmPrivacyActionAuthorization, "signature"> & {
  signature?: BytesLike;
};

export interface EvmNormalizedPrivacyAuthorization {
  effectiveSender: string;
  executor: string;
  nonce: bigint;
  deadline: bigint;
  authorizationKind: bigint;
  signature: BytesLike;
}

export type EvmPrivacyAuthorizationAction =
  | "transfer"
  | "withdraw"
  | "batchTransfer"
  | "singleProofBatchTransfer";

export interface EvmPrivacyAuthorizationTypedDataDomain {
  name: string;
  version?: string;
}

export interface EvmPrivacyAuthorizationTypedDataRequest {
  action: EvmPrivacyAuthorizationAction;
  request: TransferMessage | EvmWithdrawMessage | EvmSingleProofBatchTransferMessage;
  authorization: EvmPrivacyAuthorizationRequest;
  cosmosChainId: string;
  evmChainId: EvmQuantity;
  contractAddress: string;
  batchId?: BytesLike;
  batchItemIndex?: string | number | bigint;
}

export type EvmPrivacyAuthorizationTypedDataInput = EvmPrivacyAuthorizationTypedDataRequest & {
  domain: EvmPrivacyAuthorizationTypedDataDomain;
};

export interface EvmPrivacyAuthorizationTypedData {
  types: Readonly<Record<string, readonly { name: string; type: string }[]>>;
  primaryType: "PrivacyActionAuthorization";
  domain: Readonly<{
    name: string;
    version: string;
    chainId: string;
    verifyingContract: string;
  }>;
  message: Readonly<Record<string, string>>;
}

export interface EvmAuthorizationProfile {
  /** Must be pure: validation can run for signing and again for transaction construction. */
  validate?(authorization: EvmNormalizedPrivacyAuthorization): void;
  buildTypedData?(input: EvmPrivacyAuthorizationTypedDataRequest): EvmPrivacyAuthorizationTypedData;
}

export interface EvmAuthorizationProfileOptions {
  /** Optional target-chain allowlist. Omit it to accept every ABI-valid uint8 kind. */
  supportedAuthorizationKinds?: Array<string | number | bigint>;
  /** Canonical EIP-712 domain for contracts using the Clairveil authorization envelope. */
  typedDataDomain?: EvmPrivacyAuthorizationTypedDataDomain;
  /** Optional target-chain policy in addition to supportedAuthorizationKinds. */
  validate?: (authorization: EvmNormalizedPrivacyAuthorization) => void;
}

export interface EvmAuthorizedTransferItem {
  request: TransferMessage;
  authorization: EvmPrivacyActionAuthorization;
}

/** Lossless EVM representation of Clairveil v0.3.1 MsgBatchTransfer. */
export interface EvmSingleProofBatchTransferOutput {
  commitment: BytesLike;
  ciphertext: BytesLike;
  viewTag: BytesLike;
  userPrivacyPolicy: number;
  userDisclosureMode: number;
  userDisclosureDigest?: BytesLike;
  userDisclosureTargetPubkey?: BytesLike;
  userDisclosurePayload?: BytesLike;
  fullDisclosureDigest: BytesLike;
  auditDisclosurePayload: BytesLike;
  selfViewDisclosurePayload?: BytesLike;
}

export interface EvmSingleProofBatchTransferMessage {
  proof: BytesLike;
  root: BytesLike;
  nullifiers: BytesLike[];
  outputs: EvmSingleProofBatchTransferOutput[];
  auditKeyId: string;
  auditKeyEpoch: string | number | bigint;
  auditDisclosureTargetPubkey: BytesLike;
  expiresAtUnix: string | number | bigint;
}

export interface Eip1193WalletAdapter {
  getAddress(): Promise<string>;
  /** Returns the connected wallet's EIP-155 chain ID before transaction submission. */
  getChainId(): Promise<EvmQuantity>;
  signPrivacyRoot(messageBytes: Uint8Array): Promise<PrefixedHex>;
  signTypedData(typedData: EvmPrivacyAuthorizationTypedData): Promise<Hex | string>;
  sendTransaction(transaction: EvmTransactionRequest): Promise<Hex | string>;
  call(transaction: EvmCallRequest, blockTag?: EvmBlockTag): Promise<Hex | string>;
  getLogs(filter: EvmLogFilter): Promise<EvmLog[]>;
}

/** A custom sender may omit getChainId only when no expected evmChainId is configured. */
export type EvmTransactionWallet = Pick<Eip1193WalletAdapter, "sendTransaction"> &
  Partial<Pick<Eip1193WalletAdapter, "getChainId">>;

export interface EvmContractAdapter {
  contractAddress: string;
  abi?: readonly AbiItem[];
  authorizationProfile?: EvmAuthorizationProfile;
  /** Required for strong confirmation when this adapter emits non-canonical calldata/events. */
  verifyPrivacyReceipt?: EvmPrivacyReceiptVerifier;
  buildDepositTransaction(message: EvmDepositMessage, options?: EvmPrivacyTransactionOptions): EvmTransactionRequest;
  buildTransferTransaction(message: TransferMessage, options?: EvmPrivacyTransactionOptions): EvmTransactionRequest;
  buildWithdrawTransaction(message: EvmWithdrawMessage, options?: EvmPrivacyTransactionOptions): EvmTransactionRequest;
  buildTransferWithAuthorizationTransaction?(message: TransferMessage, authorization: EvmPrivacyActionAuthorization, options?: EvmPrivacyTransactionOptions): EvmTransactionRequest;
  buildWithdrawWithAuthorizationTransaction?(message: EvmWithdrawMessage, authorization: EvmPrivacyActionAuthorization, options?: EvmPrivacyTransactionOptions): EvmTransactionRequest;
  buildBatchTransferTransaction?(batchId: BytesLike, requests: TransferMessage[], options?: EvmPrivacyTransactionOptions): EvmTransactionRequest;
  buildBatchTransferWithAuthorizationTransaction?(batchId: BytesLike, items: EvmAuthorizedTransferItem[], options?: EvmPrivacyTransactionOptions): EvmTransactionRequest;
  buildSingleProofBatchTransferTransaction?(message: EvmSingleProofBatchTransferMessage, options?: EvmPrivacyTransactionOptions): EvmTransactionRequest;
  buildSingleProofBatchTransferWithAuthorizationTransaction?(message: EvmSingleProofBatchTransferMessage, authorization: EvmPrivacyActionAuthorization, options?: EvmPrivacyTransactionOptions): EvmTransactionRequest;
}

export interface EvmPublicPrivacyAccount {
  address?: ClairAddress;
  pubKeyHex?: Hex;
  signing_message?: string;
  shielded_address?: ShieldedAddress;
  disclosure_pubkey_hex?: Hex;
  root_signature_hash?: Hex;
}

interface EvmDepositTransactionFields {
  material?: DepositMaterial;
  depositMaterial?: DepositMaterial;
  deposit_material?: DepositMaterial;
  creator?: string;
  rootSeed?: BytesLike;
  shieldedAddress?: ShieldedAddress;
  amount?: CoinString;
  memo?: string;
  denom?: string;
  assetDenom?: string;
  transactionOptions?: EvmPrivacyTransactionOptions;
}

type EvmDepositProofInput =
  | { proof: BytesLike; proofHex?: Hex; proof_hex?: Hex; depositProof?: BytesLike; deposit_proof?: BytesLike }
  | { proof?: undefined; proofHex: Hex; proof_hex?: Hex; depositProof?: BytesLike; deposit_proof?: BytesLike }
  | { proof?: undefined; proofHex?: undefined; proof_hex: Hex; depositProof?: BytesLike; deposit_proof?: BytesLike }
  | { proof?: undefined; proofHex?: undefined; proof_hex?: undefined; depositProof: BytesLike; deposit_proof?: BytesLike }
  | { proof?: undefined; proofHex?: undefined; proof_hex?: undefined; depositProof?: undefined; deposit_proof: BytesLike };

export type EvmDepositTransactionInput =
  | (EvmDepositTransactionFields & {
      message: EvmDepositMessage;
    })
  | (EvmDepositTransactionFields & EvmDepositProofInput & {
      message?: undefined;
    });

export interface EvmDepositTransactionResult {
  status: "ready";
  material?: DepositMaterial;
  message: EvmDepositMessage;
  transaction: EvmTransactionRequest;
}

interface EvmTransferTransactionFields extends PreparedTransferPayloadInput {
  expires_at_unix?: number;
  transactionOptions?: EvmPrivacyTransactionOptions;
}

type EvmAuthoritativeTransferTime =
  | { chainNowUnix: number; chain_now_unix?: number }
  | { chain_now_unix: number; chainNowUnix?: number };

type EvmExistingTransferArtifacts =
  | { payload?: never; proof?: never }
  | { payload: PreparedTransferPayload; proof: PreparedTransferProof };

export type EvmTransferTransactionInput =
  | (EvmTransferTransactionFields & EvmAuthoritativeTransferTime & EvmExistingTransferArtifacts & {
      message: TransferMessage;
      proverAdapter?: ProverAdapter;
      checkNullifiers?: NullifierStatusReader;
    })
  | (EvmTransferTransactionFields & EvmAuthoritativeTransferTime & {
      message?: undefined;
      proverAdapter: ProverAdapter;
      checkNullifiers: NullifierStatusReader;
    });

export interface EvmTransferTransactionResult {
  status: "ready";
  message: TransferMessage;
  payload?: PreparedTransferPayload;
  proof?: PreparedTransferProof;
  transaction: EvmTransactionRequest;
}

interface EvmWithdrawTransactionFields extends Omit<PreparedWithdrawProverPayloadInput, "checkNullifiers"> {
  proof?: PreparedWithdrawProof;
  proverPayload?: PreparedWithdrawProverPayload;
  selectedNote?: FoundNote;
  transactionOptions?: EvmPrivacyTransactionOptions;
  evmRecipient?: string;
  evm_recipient?: string;
  relayer?: string;
  creator?: string;
  address?: string;
  expectedChainId?: string;
  expected_chain_id?: string;
  expectedRecipient?: ClairAddress | string;
  expected_recipient?: ClairAddress | string;
  chain_id?: string;
  nowUnix?: number;
  now_unix?: number;
}

type EvmPayloadRelayChainTime =
  | { chainNowUnix: number; chain_now_unix?: number; nowUnix?: number; now_unix?: number }
  | { chainNowUnix?: number; chain_now_unix: number; nowUnix?: number; now_unix?: number }
  | { chainNowUnix?: number; chain_now_unix?: number; nowUnix: number; now_unix?: number }
  | { chainNowUnix?: number; chain_now_unix?: number; nowUnix?: number; now_unix: number };

export type EvmWithdrawTransactionInput =
  | (EvmWithdrawTransactionFields & {
      message: EvmWithdrawMessage;
      payload?: PreparedWithdrawPayload;
      proverAdapter?: ProverAdapter;
      checkNullifiers?: NullifierStatusReader;
      chainNowUnix?: number;
      chain_now_unix?: number;
    })
  | (EvmWithdrawTransactionFields & {
      message?: undefined;
      payload: PreparedWithdrawPayload;
      proverAdapter?: ProverAdapter;
      checkNullifiers?: NullifierStatusReader;
    } & EvmPayloadRelayChainTime)
  | (EvmWithdrawTransactionFields & {
      message?: undefined;
      payload?: undefined;
      proverAdapter: ProverAdapter;
      checkNullifiers: NullifierStatusReader;
      chainNowUnix?: number;
      chain_now_unix?: number;
    });

export interface EvmWithdrawTransactionResult {
  status: "ready";
  selectedNote?: FoundNote;
  proverPayload?: PreparedWithdrawProverPayload;
  proof?: PreparedWithdrawProof;
  payload?: PreparedWithdrawPayload;
  message: EvmWithdrawMessage;
  transaction: EvmTransactionRequest;
}

export const evmDepositModeNonpayable: "nonpayable";
export const evmDepositModePayableExactValue: "payable-exact-value";
export const defaultEvmDepositMode: "payable-exact-value";
export const evmDepositModes: readonly EvmDepositMode[];
export const evmPrivacyPrecompileAbi: readonly AbiItem[];
export const evmPrivacyPrecompilePayableDepositAbi: readonly AbiItem[];

export function normalizeEvmDepositMode(value?: string | null): EvmDepositMode;
export function evmDepositValueForAmount(amount: CoinString, nativeDenom?: string): Hex;
export function functionSelector(signature: string): string;
export function encodeAbiParameters(types: Array<string | AbiParameter>, values: unknown[]): string;
export function encodeFunctionData(signature: string, types: Array<string | AbiParameter>, values: unknown[]): Hex;
export function normalizeEvmAddress(value: unknown, label?: string): string;
export function isEvmAddress(value: unknown): boolean;
export function evmAddressToBech32(address: string, prefix: string): string;
export function bech32AddressToEvm(address: string, expectedPrefix?: string): string;
export function encodeEvmPrivacyDeposit(message: EvmDepositMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function encodeEvmPrivacyTransfer(message: TransferMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function encodeEvmPrivacyWithdraw(message: EvmWithdrawMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function encodeEvmPrivacyTransferWithAuthorization(message: TransferMessage, authorization: EvmPrivacyActionAuthorization, options?: EvmPrivacyTransactionOptions): Hex;
export function encodeEvmPrivacyWithdrawWithAuthorization(message: EvmWithdrawMessage, authorization: EvmPrivacyActionAuthorization, options?: EvmPrivacyTransactionOptions): Hex;
export function encodeEvmPrivacyBatchTransfer(batchId: BytesLike, requests: TransferMessage[], options?: EvmPrivacyTransactionOptions): Hex;
export function encodeEvmPrivacyBatchTransferWithAuthorization(batchId: BytesLike, items: EvmAuthorizedTransferItem[], options?: EvmPrivacyTransactionOptions): Hex;
export function encodeEvmPrivacySingleProofBatchTransfer(message: EvmSingleProofBatchTransferMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function encodeEvmPrivacySingleProofBatchTransferWithAuthorization(message: EvmSingleProofBatchTransferMessage, authorization: EvmPrivacyActionAuthorization, options?: EvmPrivacyTransactionOptions): Hex;
export function buildEvmPrivacyAuthorizationTypedData(input: EvmPrivacyAuthorizationTypedDataInput): EvmPrivacyAuthorizationTypedData;
export function createEvmAuthorizationProfile(input?: EvmAuthorizationProfileOptions): EvmAuthorizationProfile;
export function defaultEncodeEvmDeposit(message: EvmDepositMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function defaultEncodeEvmTransfer(message: TransferMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function defaultEncodeEvmWithdraw(message: EvmWithdrawMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function evmTransactionBindingHash(transaction: EvmTransactionRequest): Hex;
export function markEvmTransactionReservationRequired<T extends EvmTransactionRequest>(transaction: T): T;
export function verifyEvmTransactionIdentity(input: {
  transaction: EvmTransactionRequest;
  rpcTransaction: EvmRpcTransaction | object;
  txHash: Hex | string;
  sender: string;
  expectedChainId?: EvmQuantity;
  actualChainId: EvmQuantity;
}): Readonly<EvmTransactionIdentityVerification>;
export function verifyEvmPrivacyReceipt(input: {
  transaction: EvmTransactionRequest;
  receipt: { status?: EvmQuantity; logs?: EvmLog[] };
  sender: string;
  contractAddress?: string;
}): Readonly<EvmPrivacyReceiptVerification>;
export function createEip1193WalletAdapter(input?: { provider: Eip1193Provider; account?: string }): Eip1193WalletAdapter;
export function createEvmContractAdapter(input: {
  contractAddress: string;
  accountPrefix?: string;
  chainId?: string | number;
  depositMode?: EvmDepositMode;
  nativeDenom?: string;
  authorizationProfile?: EvmAuthorizationProfile;
  verifyPrivacyReceipt?: EvmPrivacyReceiptVerifier;
  encodeDeposit?: EvmDepositEncoder;
  encodeTransfer?: EvmTransferEncoder;
  encodeWithdraw?: EvmWithdrawEncoder;
  encodeTransferWithAuthorization?: (message: TransferMessage, authorization: EvmPrivacyActionAuthorization, options?: EvmPrivacyTransactionOptions) => Hex;
  encodeWithdrawWithAuthorization?: (message: EvmWithdrawMessage, authorization: EvmPrivacyActionAuthorization, options?: EvmPrivacyTransactionOptions) => Hex;
  encodeBatchTransfer?: (batchId: BytesLike, requests: TransferMessage[], options?: EvmPrivacyTransactionOptions) => Hex;
  encodeBatchTransferWithAuthorization?: (batchId: BytesLike, items: EvmAuthorizedTransferItem[], options?: EvmPrivacyTransactionOptions) => Hex;
  encodeSingleProofBatchTransfer?: (message: EvmSingleProofBatchTransferMessage, options?: EvmPrivacyTransactionOptions) => Hex;
  encodeSingleProofBatchTransferWithAuthorization?: (message: EvmSingleProofBatchTransferMessage, authorization: EvmPrivacyActionAuthorization, options?: EvmPrivacyTransactionOptions) => Hex;
}): EvmContractAdapter;
export function createEvmPrivacyPrecompileAdapter(input: {
  contractAddress: string;
  accountPrefix?: string;
  chainId?: string | number;
  depositMode?: EvmDepositMode;
  nativeDenom?: string;
  authorizationProfile?: EvmAuthorizationProfile;
  verifyPrivacyReceipt?: EvmPrivacyReceiptVerifier;
  encodeDeposit?: EvmDepositEncoder;
  encodeTransfer?: EvmTransferEncoder;
  encodeWithdraw?: EvmWithdrawEncoder;
  encodeTransferWithAuthorization?: (message: TransferMessage, authorization: EvmPrivacyActionAuthorization, options?: EvmPrivacyTransactionOptions) => Hex;
  encodeWithdrawWithAuthorization?: (message: EvmWithdrawMessage, authorization: EvmPrivacyActionAuthorization, options?: EvmPrivacyTransactionOptions) => Hex;
  encodeBatchTransfer?: (batchId: BytesLike, requests: TransferMessage[], options?: EvmPrivacyTransactionOptions) => Hex;
  encodeBatchTransferWithAuthorization?: (batchId: BytesLike, items: EvmAuthorizedTransferItem[], options?: EvmPrivacyTransactionOptions) => Hex;
  encodeSingleProofBatchTransfer?: (message: EvmSingleProofBatchTransferMessage, options?: EvmPrivacyTransactionOptions) => Hex;
  encodeSingleProofBatchTransferWithAuthorization?: (message: EvmSingleProofBatchTransferMessage, authorization: EvmPrivacyActionAuthorization, options?: EvmPrivacyTransactionOptions) => Hex;
}): EvmContractAdapter;

export interface ClairveilEvmClientBaseOptions {
    provider?: Eip1193Provider;
    chainId?: string | number;
    /** Expected EIP-155 network for connected-wallet transaction submission. */
    evmChainId?: string | number;
    accountPrefix?: string;
    bech32Prefix?: string;
    shieldedPrefix?: string;
    defaultDenom?: string;
    /** Clairveil-compatible EVM precompiles use payable exact-value deposits by default. */
    depositMode?: EvmDepositMode;
    /** Runtime-native minimal denom whose amount must equal EVM msg.value. */
    nativeDenom?: string;
    authorizationProfile?: EvmAuthorizationProfile;
}

export type ClairveilEvmClientOptions = ClairveilEvmClientBaseOptions & (
  | { contractAddress: string; contractAdapter?: EvmContractAdapter }
  | { contractAddress?: string; contractAdapter: EvmContractAdapter }
);

export class ClairveilEvmClient {
  constructor(options: ClairveilEvmClientOptions);
  buildDepositMaterial(input?: {
    creator?: string;
    rootSeed?: BytesLike;
    shieldedAddress?: ShieldedAddress;
    amount?: CoinString;
    memo?: string;
    denom?: string;
    assetDenom?: string;
  }): DepositMaterial;
  buildDepositTransaction(input?: EvmDepositTransactionInput): EvmDepositTransactionResult;
  buildPreparedTransferPayload(input?: PreparedTransferPayloadInput): Promise<PreparedTransferPayload>;
  validateAuthorization(authorization: EvmPrivacyAuthorizationRequest, options?: { requireSignature?: boolean }): EvmNormalizedPrivacyAuthorization;
  buildAuthorizationTypedData(input: EvmPrivacyAuthorizationTypedDataRequest): EvmPrivacyAuthorizationTypedData;
  buildTransferTransaction(input?: EvmTransferTransactionInput): Promise<EvmTransferTransactionResult>;
  buildPreparedWithdrawProverPayload(input?: PreparedWithdrawProverPayloadInput): Promise<PreparedWithdrawProverPayloadResult>;
  buildWithdrawTransaction(input?: EvmWithdrawTransactionInput): Promise<EvmWithdrawTransactionResult>;
  buildTransferWithAuthorizationTransaction(input: { message: TransferMessage; authorization: EvmPrivacyActionAuthorization; transactionOptions?: EvmPrivacyTransactionOptions }): { status: "ready"; message: TransferMessage; authorization: EvmPrivacyActionAuthorization; transaction: EvmTransactionRequest };
  buildWithdrawWithAuthorizationTransaction(input: { message: EvmWithdrawMessage; authorization: EvmPrivacyActionAuthorization; transactionOptions?: EvmPrivacyTransactionOptions }): { status: "ready"; message: EvmWithdrawMessage; authorization: EvmPrivacyActionAuthorization; transaction: EvmTransactionRequest };
  buildBatchTransferTransaction(input: { batchId: BytesLike; requests: TransferMessage[]; transactionOptions?: EvmPrivacyTransactionOptions }): { status: "ready"; batchId: BytesLike; requests: TransferMessage[]; transaction: EvmTransactionRequest };
  buildBatchTransferWithAuthorizationTransaction(input: { batchId: BytesLike; items: EvmAuthorizedTransferItem[]; transactionOptions?: EvmPrivacyTransactionOptions }): { status: "ready"; batchId: BytesLike; items: EvmAuthorizedTransferItem[]; transaction: EvmTransactionRequest };
  buildSingleProofBatchTransferTransaction(input: { message: EvmSingleProofBatchTransferMessage; transactionOptions?: EvmPrivacyTransactionOptions }): { status: "ready"; message: EvmSingleProofBatchTransferMessage; transaction: EvmTransactionRequest };
  buildSingleProofBatchTransferWithAuthorizationTransaction(input: { message: EvmSingleProofBatchTransferMessage; authorization: EvmPrivacyActionAuthorization; transactionOptions?: EvmPrivacyTransactionOptions }): { status: "ready"; message: EvmSingleProofBatchTransferMessage; authorization: EvmPrivacyActionAuthorization; transaction: EvmTransactionRequest };
  sendTransaction(wallet: EvmTransactionWallet | null | undefined, transaction: EvmTransactionRequest, reservationOptions?: EvmReservationBroadcastOptions): Promise<Hex | string>;
  verifyTransactionIdentity(input: {
    transaction: EvmTransactionRequest;
    rpcTransaction: EvmRpcTransaction | object;
    txHash: Hex | string;
    sender: string;
    expectedChainId?: EvmQuantity;
    actualChainId: EvmQuantity;
  }): Readonly<EvmTransactionIdentityVerification>;
  verifyPrivacyReceipt(input: { transaction: EvmTransactionRequest; receipt: { status?: EvmQuantity; logs?: EvmLog[] }; sender: string }): Readonly<EvmPrivacyReceiptVerification>;
  privacyAccount(material: PrivacyMaterial): EvmPublicPrivacyAccount;
}

export function createClairveilEvmClient(options: ConstructorParameters<typeof ClairveilEvmClient>[0]): ClairveilEvmClient;
