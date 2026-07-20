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

export interface Eip1193Provider {
  request(input: { method: string; params?: unknown[] }): Promise<unknown>;
}

export type EvmQuantity = Hex | string;
export type EvmBlockTag = "earliest" | "latest" | "pending" | "safe" | "finalized" | EvmQuantity;

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

export type EvmReservationBroadcastOptions = EvmReservationBroadcastBinding & EvmRelayBroadcastValidation;

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
}

export interface EvmWithdrawMessage extends WithdrawMessage {
  evmRecipient?: string;
  evm_recipient?: string;
  recipientAddress?: string;
  recipient_address?: string;
}

export interface EvmPrivacyTransactionOptions {
  value?: EvmQuantity;
  signature?: string;
  accountPrefix?: string;
  chainId?: string | number;
  withdrawOutputMode?: "legacy-zero" | "none" | string;
  legacyOutputMode?: "legacy-zero" | "none" | string;
}

export type EvmDepositEncoder = (message: EvmDepositMessage, options?: EvmPrivacyTransactionOptions) => Hex;
export type EvmTransferEncoder = (message: TransferMessage, options?: EvmPrivacyTransactionOptions) => Hex;
export type EvmWithdrawEncoder = (message: EvmWithdrawMessage, options?: EvmPrivacyTransactionOptions) => Hex;

export interface Eip1193WalletAdapter {
  getAddress(): Promise<string>;
  signPrivacyRoot(messageBytes: Uint8Array): Promise<PrefixedHex>;
  sendTransaction(transaction: EvmTransactionRequest): Promise<Hex | string>;
  call(transaction: EvmCallRequest, blockTag?: EvmBlockTag): Promise<Hex | string>;
  getLogs(filter: EvmLogFilter): Promise<EvmLog[]>;
}

export interface EvmContractAdapter {
  contractAddress: string;
  abi?: readonly AbiItem[];
  buildDepositTransaction(message: EvmDepositMessage, options?: EvmPrivacyTransactionOptions): EvmTransactionRequest;
  buildTransferTransaction(message: TransferMessage, options?: EvmPrivacyTransactionOptions): EvmTransactionRequest;
  buildWithdrawTransaction(message: EvmWithdrawMessage, options?: EvmPrivacyTransactionOptions): EvmTransactionRequest;
}

export interface EvmPublicPrivacyAccount {
  address?: ClairAddress;
  pubKeyHex?: Hex;
  signing_message?: string;
  shielded_address?: ShieldedAddress;
  disclosure_pubkey_hex?: Hex;
  root_signature_hash?: Hex;
}

export type EvmDepositTransactionInput = {
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
  message?: EvmDepositMessage;
};

export interface EvmDepositTransactionResult {
  status: "ready";
  material?: DepositMaterial;
  message: EvmDepositMessage;
  transaction: EvmTransactionRequest;
}

interface EvmTransferTransactionFields extends PreparedTransferPayloadInput {
  payload?: PreparedTransferPayload;
  proof?: PreparedTransferProof;
  transactionOptions?: EvmPrivacyTransactionOptions;
}

export type EvmTransferTransactionInput =
  | (EvmTransferTransactionFields & {
      message: TransferMessage;
      proverAdapter?: ProverAdapter;
      checkNullifiers?: NullifierStatusReader;
    })
  | (EvmTransferTransactionFields & {
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

export const evmPrivacyPrecompileAddress: "0x100000000000000000000000000000000000000b";
export const defaultEvmPrivacyPrecompileAddress: "0x100000000000000000000000000000000000000b";
export const evmPrivacyPrecompileAbi: readonly AbiItem[];

export function functionSelector(signature: string): string;
export function encodeAbiParameters(types: Array<string | AbiParameter>, values: unknown[]): string;
export function encodeFunctionData(signature: string, types: Array<string | AbiParameter>, values: unknown[]): Hex;
export function normalizeEvmAddress(value: unknown, label?: string): string;
export function isEvmAddress(value: unknown): boolean;
export function evmAddressToBech32(address: string, prefix: string): string;
export function bech32AddressToEvm(address: string, expectedPrefix?: string): string;
export function encodeReferenceEvmDeposit(message: EvmDepositMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function encodeReferenceEvmTransfer(message: TransferMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function encodeReferenceEvmWithdraw(message: EvmWithdrawMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function encodeEvmPrivacyDeposit(message: EvmDepositMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function encodeEvmPrivacyTransfer(message: TransferMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function encodeEvmPrivacyWithdraw(message: EvmWithdrawMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function defaultEncodeEvmDeposit(message: EvmDepositMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function defaultEncodeEvmTransfer(message: TransferMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function defaultEncodeEvmWithdraw(message: EvmWithdrawMessage, options?: EvmPrivacyTransactionOptions): Hex;
export function evmTransactionBindingHash(transaction: EvmTransactionRequest): Hex;
export function markEvmTransactionReservationRequired<T extends EvmTransactionRequest>(transaction: T): T;
export function createEip1193WalletAdapter(input?: { provider: Eip1193Provider; account?: string }): Eip1193WalletAdapter;
export function createEvmContractAdapter(input?: {
  contractAddress?: string;
  accountPrefix?: string;
  chainId?: string | number;
  withdrawOutputMode?: "legacy-zero" | "none" | string;
  encodeDeposit?: EvmDepositEncoder;
  encodeTransfer?: EvmTransferEncoder;
  encodeWithdraw?: EvmWithdrawEncoder;
}): EvmContractAdapter;
export function createEvmPrivacyPrecompileAdapter(input?: {
  contractAddress?: string;
  accountPrefix?: string;
  chainId?: string | number;
  withdrawOutputMode?: "legacy-zero" | "none" | string;
  encodeDeposit?: EvmDepositEncoder;
  encodeTransfer?: EvmTransferEncoder;
  encodeWithdraw?: EvmWithdrawEncoder;
}): EvmContractAdapter;

export class ClairveilEvmClient {
  constructor(options?: {
    provider?: Eip1193Provider;
    contractAddress?: string;
    chainId?: string | number;
    accountPrefix?: string;
    bech32Prefix?: string;
    shieldedPrefix?: string;
    defaultDenom?: string;
    withdrawOutputMode?: "legacy-zero" | "none" | string;
    contractAdapter?: EvmContractAdapter;
  });
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
  buildTransferTransaction(input?: EvmTransferTransactionInput): Promise<EvmTransferTransactionResult>;
  buildPreparedWithdrawProverPayload(input?: PreparedWithdrawProverPayloadInput): Promise<PreparedWithdrawProverPayloadResult>;
  buildWithdrawTransaction(input?: EvmWithdrawTransactionInput): Promise<EvmWithdrawTransactionResult>;
  sendTransaction(wallet: Eip1193WalletAdapter | null | undefined, transaction: EvmTransactionRequest, reservationOptions?: EvmReservationBroadcastOptions): Promise<Hex | string>;
  privacyAccount(material: PrivacyMaterial): EvmPublicPrivacyAccount;
}

export function createClairveilEvmClient(options?: ConstructorParameters<typeof ClairveilEvmClient>[0]): ClairveilEvmClient;
