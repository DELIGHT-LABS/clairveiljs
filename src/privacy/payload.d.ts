import type { BytesLike, ClairAddress, Hex, Point, ShieldedAddress } from "../core/crypto.js";
import type { CoinString, FoundNote, Note, NoteHashSigner } from "../core/note.js";
import type { ProverAdapter } from "./prover.js";
import type {
  MsgTransfer as TransferMessage,
  MsgWithdraw as WithdrawMessage,
  UserDisclosureMode
} from "../generated/clairveil/privacy/v1/tx.js";

export const preparedTransferPayloadVersion: "v1";
export const preparedTransferProofVersion: "v1";
export const preparedWithdrawProverPayloadVersion: "v1";
export const preparedWithdrawProofVersion: "v1";
export const preparedWithdrawPayloadVersion: "v1";
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

export type TransferPrivacyPolicy = "all-private" | "amount" | "recipient" | "sender" | "amount+recipient" | "amount+sender" | "recipient+sender" | "all" | number;
export type TransferUserDisclosureMode = "none" | "public" | "recipient-encrypted" | UserDisclosureMode | number;

export interface TransferDisclosurePayload {
  version: "v1";
  plane: "user" | "audit" | string;
  policy: number;
  output_index: number;
  commitment_hex: Hex;
  disclosure_digest_hex: Hex;
  amount?: string;
  asset_id_hex?: Hex;
  asset_denom?: string;
  from_shielded_address?: ShieldedAddress;
  to_shielded_address?: ShieldedAddress;
}

export interface TransferDisclosureData {
  payload: TransferDisclosurePayload;
  digest_hex: Hex;
  target_pubkey_hex: Hex | "";
  payload_hex: Hex;
  mode: number;
}

export interface PreparedTransferPayloadInput {
  creator?: ClairAddress | string;
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
  noteHashSigner?: NoteHashSigner;
  userPrivacyPolicy?: TransferPrivacyPolicy;
  userDisclosureMode?: TransferUserDisclosureMode;
  userDisclosureTargetPubKeyHex?: Hex;
  auditDisclosureTargetPubKeyHex?: Hex;
  shieldedPrefix?: string;
}

export interface PreparedTransferPayloadInputNote {
  amount: string;
  randomness_hex: Hex;
  spend_pubkey_hex: Hex;
  view_pubkey_hex: Hex;
  merkle_path: string[];
  merkle_path_helper: number[];
  note_hash_signature_hex: Hex;
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
  root_hex: Hex;
  asset_id_hex: Hex;
  inputs: [PreparedTransferPayloadInputNote, PreparedTransferPayloadInputNote];
  outputs: [PreparedTransferPayloadOutputNote, PreparedTransferPayloadOutputNote];
  cipher_text_hexes: [Hex, Hex];
  user_privacy_policy: number;
  user_disclosure_mode: number;
  user_disclosure_digest_hex: Hex | "";
  user_disclosure_target_pubkey_hex: Hex | "";
  user_disclosure_payload_hex: Hex | "";
  audit_disclosure_digest_hex: Hex;
  audit_disclosure_target_pubkey_hex: Hex;
  audit_disclosure_payload_hex: Hex;
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

export function summarizeSpendableNotesByDenom(notes: FoundNote[], denom?: string): { notes: FoundNote[]; total: bigint };
export function selectTransferInputs(notes: FoundNote[], denom: string, targetAmount: string | number | bigint): TransferInputSelection;
export function buildUserDisclosureData(input: {
  policy?: TransferPrivacyPolicy;
  mode?: TransferUserDisclosureMode;
  outputCommitmentHex: Hex;
  transferDenom?: string;
  fromNote: Note;
  recipientNote: Note;
  targetPubKeyHex?: Hex;
  shieldedPrefix?: string;
}): TransferDisclosureData | null;
export function buildAuditDisclosureData(input: {
  outputCommitmentHex: Hex;
  transferDenom?: string;
  fromNote: Note;
  recipientNote: Note;
  auditPubKeyHex?: Hex;
  shieldedPrefix?: string;
}): TransferDisclosureData;
export function computePreparedTransferPayloadHash(payload: PreparedTransferPayload): Hex;
export function buildPreparedTransferPayload(input: PreparedTransferPayloadInput): Promise<PreparedTransferPayload>;
export function validatePreparedTransferProof(payload: PreparedTransferPayload, proof: PreparedTransferProof): true;
export function buildTransferMsgFromPayloadAndProof(payload: PreparedTransferPayload, proof: PreparedTransferProof): TransferMessage;
export function buildTransferMessage(input?: PreparedTransferPayloadInput & { proverAdapter?: ProverAdapter }): Promise<TransferMessageBuildResult>;
export function computePreparedWithdrawProverPayloadHash(payload: PreparedWithdrawProverPayload): Hex;
export interface PreparedWithdrawProverPayloadInput {
  notes?: FoundNote[];
  amount?: CoinString;
  denom?: string;
  assetDenom?: string;
  recipient?: ClairAddress | string;
  chainId?: string;
  expiresAtUnix?: number;
  rootSeed?: BytesLike;
  merklePathProvider?: MerklePathProviderLike;
  spendNoteHashSigner?: NoteHashSigner;
  accountPrefix?: string;
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
  spend_note_hash_signature_hex: Hex;
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

export function buildPreparedWithdrawProverPayload(input: PreparedWithdrawProverPayloadInput): Promise<PreparedWithdrawProverPayloadResult>;
export function computePreparedWithdrawPayloadHash(payload: PreparedWithdrawPayload): Hex;
export function validatePreparedWithdrawProof(proverPayload: PreparedWithdrawProverPayload, proof: PreparedWithdrawProof, nowUnix?: number): true;
export function buildPreparedWithdrawPayloadFromProof(proverPayload: PreparedWithdrawProverPayload, proof: PreparedWithdrawProof, nowUnix?: number): PreparedWithdrawPayload;
export function validatePreparedWithdrawPayload(payload: PreparedWithdrawPayload, nowUnix?: number): true;
export function buildWithdrawMsgFromPayload(payload: PreparedWithdrawPayload, creator: ClairAddress | string): WithdrawMessage;
export function buildWithdrawMessage(input?: PreparedWithdrawProverPayloadInput & {
  proverAdapter?: ProverAdapter;
  creator?: ClairAddress | string;
}): Promise<WithdrawMessageBuildResult>;
export function createRestMerklePathProvider(input?: { rest: string; fetchImpl?: typeof fetch }): { lookupMerklePath(commitmentHex: Hex): Promise<MerklePathResult> };

export type { TransferMessage, WithdrawMessage };
