import type { BytesLike, ClairAddress, Hex, Point, ShieldedAddress } from "../core/crypto.js";
import type { CoinString, FoundNote, NoteHashSigner } from "../core/note.js";
import type { ProverAdapter } from "./prover.js";
import type { JoinSplitOwnerIntentSignerV1 } from "./transfer-v5.js";
import type {
  MsgTransfer as TransferMessage,
  MsgWithdraw as WithdrawMessage,
  UserDisclosureMode
} from "../generated/clairveil/privacy/v1/tx.js";

export const preparedTransferPayloadVersion: "v5";
export const preparedTransferProofVersion: "v2";
export const preparedWithdrawProverPayloadVersion: "v2";
export const preparedWithdrawProofVersion: "v2";
export const preparedWithdrawPayloadVersion: "v2";
export const userDisclosureModeValue: Readonly<Record<string, number>>;
export const userDisclosureModeName: Readonly<Record<number, string>>;
export const privacyPolicyValue: Readonly<Record<string, number>>;

export interface TransferInputSelection {
  inputs: FoundNote[];
  total: bigint;
  isFinal: boolean;
  needsZeroDummy: boolean;
}

export interface MerklePathResult {
  root?: Hex;
  Root?: Hex;
  path?: Array<string | number | bigint>;
  Path?: Array<string | number | bigint>;
  path_helper?: Array<string | number | bigint>;
  pathHelper?: Array<string | number | bigint>;
  PathHelper?: Array<string | number | bigint>;
}

export interface MerklePathProvider {
  lookupMerklePath?: (commitmentHex: Hex) => Promise<MerklePathResult> | MerklePathResult;
  LookupMerklePath?: (commitmentHex: Hex) => Promise<MerklePathResult> | MerklePathResult;
}

export type MerklePathProviderLike =
  | MerklePathProvider
  | ((commitmentHex: Hex) => Promise<MerklePathResult> | MerklePathResult);

export type TransferPrivacyPolicy = "all-private" | "amount" | "to" | "amount-to" | "from" | "amount-from" | "from-to" | "to-from" | "amount-from-to" | "amount-to-from" | number;
export type TransferUserDisclosureMode = "none" | "public" | "recipient-encrypted" | UserDisclosureMode | number;

export interface PreparedTransferPayloadInput {
  creator?: ClairAddress | string;
  chainId?: string;
  expiresAtUnix?: number;
  chainNowUnix?: number;
  inputs?: FoundNote[];
  recipient?: ShieldedAddress;
  amount?: CoinString;
  transferAmount?: string | number | bigint;
  transferDenom?: string;
  denom?: string;
  rootSeed?: BytesLike;
  senderSpendPubKey?: Point;
  senderViewPubKey?: Point;
  merklePathProvider?: MerklePathProviderLike;
  ownerIntentSigner?: JoinSplitOwnerIntentSignerV1;
  noteHashSigner?: NoteHashSigner;
  userPrivacyPolicy?: TransferPrivacyPolicy;
  userDisclosureMode?: TransferUserDisclosureMode;
  userDisclosureTargetPubKeyHex?: Hex;
  auditDisclosureTargetPubKeyHex?: Hex;
  disableSelfViewDisclosure?: boolean;
  selfViewDisclosureTargetPubKeyHex?: Hex;
  shieldedPrefix?: string;
}

export interface PreparedTransferPayloadInputNote {
  amount: string;
  randomness_hex: Hex;
  spend_pubkey_hex: Hex;
  view_pubkey_hex: Hex;
  merkle_path: string[];
  merkle_path_helper: number[];
  nullifier_hex: Hex;
}

export interface PreparedTransferPayloadOutputNote {
  amount: string;
  randomness_hex: Hex;
  spend_pubkey_hex: Hex;
  view_pubkey_hex: Hex;
  commitment_hex: Hex;
}

export interface PreparedTransferPayload {
  version: typeof preparedTransferPayloadVersion;
  creator: ClairAddress | string;
  chain_id: string;
  expires_at_unix: number;
  root_hex: Hex;
  asset_id_hex: Hex;
  inputs: [PreparedTransferPayloadInputNote, PreparedTransferPayloadInputNote];
  outputs: [PreparedTransferPayloadOutputNote, PreparedTransferPayloadOutputNote];
  cipher_text_hexes: [Hex, Hex];
  view_tag_hexes: [Hex, Hex];
  user_privacy_policy: number;
  user_disclosure_mode: number;
  user_disclosure_digest_hex: Hex | "";
  user_disclosure_target_pubkey_hex: Hex | "";
  user_disclosure_payload_hex: Hex | "";
  audit_disclosure_digest_hex: Hex;
  audit_disclosure_target_pubkey_hex: Hex;
  audit_disclosure_payload_hex: Hex;
  self_view_disclosure_digest_hex: Hex | "";
  self_view_disclosure_payload_hex: Hex | "";
  user_disclosure_blinding_hex: Hex | "";
  full_disclosure_blinding_hex: Hex;
  owner_signature_hex: Hex;
  payload_hash: Hex;
}

export interface PreparedTransferProof {
  version: typeof preparedTransferProofVersion;
  payload_hash: Hex;
  proof_hex: Hex;
}

export interface TransferMessageBuildResult {
  payload: PreparedTransferPayload;
  proof: PreparedTransferProof;
  message: TransferMessage;
}

export interface TransferMessageBuildOptions {
  nowUnix?: number;
  /** Replaceable Cosmos fee payer/relayer; owner intent remains unchanged. */
  creator?: ClairAddress | string;
  /** Optional target-chain assertion that rejects cross-chain payload reuse. */
  expectedChainId?: string;
  expected_chain_id?: string;
}

export function summarizeSpendableNotesByDenom(notes: FoundNote[], denom?: string): { notes: FoundNote[]; total: bigint };
export function selectTransferInputs(notes: FoundNote[], denom: string, targetAmount: string | number | bigint): TransferInputSelection;
export function selectBatchTransferInputs(notes: FoundNote[], denom: string, targetAmount: string | number | bigint): TransferInputSelection;
export function validatePreparedTransferPayloadMetadata(payload: PreparedTransferPayload): true;
export function computePreparedTransferPayloadHash(payload: PreparedTransferPayload): Hex;
export function buildPreparedTransferPayload(input: PreparedTransferPayloadInput & { chainNowUnix: number }): Promise<PreparedTransferPayload>;
export function validatePreparedTransferProof(payload: PreparedTransferPayload, proof: PreparedTransferProof, options?: { nowUnix?: number }): true;
export function buildTransferMsgFromPayloadAndProof(payload: PreparedTransferPayload, proof: PreparedTransferProof, options?: TransferMessageBuildOptions): TransferMessage;
export type NullifierUsage =
  | boolean
  | { used: boolean; Used?: never }
  | { used?: never; Used: boolean };
export type NullifierStatusEntry =
  ({ nullifier: Hex; Nullifier?: never } | { nullifier?: never; Nullifier: Hex }) &
  Exclude<NullifierUsage, boolean>;
export type NullifierStatusResult =
  | Map<string, NullifierUsage>
  | Record<string, NullifierUsage>
  | { statuses: readonly NullifierStatusEntry[] };
export type NullifierStatusReader = (nullifiers: readonly Hex[]) => NullifierStatusResult | Promise<NullifierStatusResult>;
export type AuthoritativeTransferChainTimeInput =
  | { chainNowUnix: number; chain_now_unix?: number }
  | { chain_now_unix: number; chainNowUnix?: number };
export function buildTransferMessage(input: PreparedTransferPayloadInput & AuthoritativeTransferChainTimeInput & { expires_at_unix?: number; proverAdapter: ProverAdapter; checkNullifiers: NullifierStatusReader; signal?: AbortSignal }): Promise<TransferMessageBuildResult>;
export function computePreparedWithdrawProverPayloadHash(payload: PreparedWithdrawProverPayload): Hex;
export interface PreparedWithdrawProverPayloadInput {
  notes?: FoundNote[];
  amount?: CoinString;
  denom?: string;
  assetDenom?: string;
  recipient?: ClairAddress | string;
  chainId?: string;
  expiresAtUnix?: number;
  chainNowUnix?: number;
  rootSeed?: BytesLike;
  merklePathProvider?: MerklePathProviderLike;
  spendNoteHashSigner?: NoteHashSigner;
  accountPrefix?: string;
  checkNullifiers?: NullifierStatusReader;
}

export interface PreparedWithdrawProverPayload {
  version: typeof preparedWithdrawProverPayloadVersion;
  root_hex: Hex;
  nullifier_hex: Hex;
  amount: string;
  asset_denom: string;
  asset_id_hex: Hex;
  recipient: ClairAddress | string;
  recipient_bytes_hex: Hex;
  chain_id: string;
  expires_at_unix: number;
  note_randomness_hex: Hex;
  spend_pubkey_hex: Hex;
  view_pubkey_hex: Hex;
  merkle_path: string[];
  merkle_path_helper: number[];
  spend_intent_signature_hex: Hex;
  payload_hash: Hex;
}

export interface PreparedWithdrawProverPayloadResult {
  selectedNote: FoundNote;
  payload: PreparedWithdrawProverPayload;
}

export interface PreparedWithdrawProof {
  version: typeof preparedWithdrawProofVersion;
  payload_hash: Hex;
  proof_hex: Hex;
}

export interface PreparedWithdrawPayload {
  version: typeof preparedWithdrawPayloadVersion;
  proof_hex: Hex;
  root_hex: Hex;
  nullifier_hex: Hex;
  amount: CoinString;
  recipient: ClairAddress | string;
  chain_id: string;
  expires_at_unix: number;
  payload_hash: Hex;
}

export interface WithdrawMessageBuildResult {
  selectedNote: FoundNote;
  proverPayload: PreparedWithdrawProverPayload;
  proof: PreparedWithdrawProof;
  payload: PreparedWithdrawPayload;
  message: WithdrawMessage;
}

export interface RelayWithdrawPayloadBuildResult {
  selectedNote: FoundNote;
  proverPayload: PreparedWithdrawProverPayload;
  proof: PreparedWithdrawProof;
  payload: PreparedWithdrawPayload;
}

export interface RelayWithdrawRelayOptions {
  /** Latest chain block time in whole Unix seconds. Local wall-clock time is not accepted. */
  chainNowUnix: number;
  expectedChainId?: string;
  expectedRecipient?: ClairAddress | string;
  accountPrefix?: string;
}

export function buildPreparedWithdrawProverPayload(input: PreparedWithdrawProverPayloadInput): Promise<PreparedWithdrawProverPayloadResult>;
export function computePreparedWithdrawPayloadHash(payload: PreparedWithdrawPayload): Hex;
export function validatePreparedWithdrawProverPayloadMetadata(payload: PreparedWithdrawProverPayload, nowUnix?: number): true;
export function validatePreparedWithdrawProof(proverPayload: PreparedWithdrawProverPayload, proof: PreparedWithdrawProof, nowUnix?: number): true;
export function buildPreparedWithdrawPayloadFromProof(proverPayload: PreparedWithdrawProverPayload, proof: PreparedWithdrawProof, nowUnix?: number): PreparedWithdrawPayload;
export function validatePreparedWithdrawPayload(payload: PreparedWithdrawPayload, nowUnix?: number): true;
export function validateRelayWithdrawPayload(payload: PreparedWithdrawPayload, options: RelayWithdrawRelayOptions): true;
export function buildWithdrawMsgFromPayload(payload: PreparedWithdrawPayload, creator: ClairAddress | string, nowUnix?: number): WithdrawMessage;
export function buildRelayWithdrawMsgFromPayload(payload: PreparedWithdrawPayload, relayer: ClairAddress | string, options: RelayWithdrawRelayOptions): WithdrawMessage;
export function buildRelayWithdrawPayload(input: Omit<PreparedWithdrawProverPayloadInput, "chainNowUnix"> & {
  /** Latest chain block time in whole Unix seconds. */
  chainNowUnix: number;
  proverAdapter: ProverAdapter;
  checkNullifiers: NullifierStatusReader;
  signal?: AbortSignal;
}): Promise<RelayWithdrawPayloadBuildResult>;
export function buildWithdrawMessage(input: PreparedWithdrawProverPayloadInput & {
  proverAdapter: ProverAdapter;
  checkNullifiers: NullifierStatusReader;
  creator?: ClairAddress | string;
  signal?: AbortSignal;
}): Promise<WithdrawMessageBuildResult>;
export function createRestMerklePathProvider(input?: { rest: string; fetchImpl?: typeof fetch; timeoutMs?: number }): { lookupMerklePath(commitmentHex: Hex): Promise<MerklePathResult> };

export type { TransferMessage, WithdrawMessage };
