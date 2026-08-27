import type { BytesLike, ClairAddress, Hex, Point, ShieldedAddress } from "../core/crypto.js";
import type { CoinString, FoundNote, Note, NoteHashSigner } from "../core/note.js";
import type { MsgTransfer } from "../generated/clairveil/privacy/v1/tx.js";
import type {
  MerklePathProviderLike,
  TransferPrivacyPolicy,
  TransferUserDisclosureMode
} from "./payload.js";

export const preparedTransferV5PayloadVersion: "v5";
export const preparedTransferV5ProofVersion: "v2";
export const transferV5ProofRequestVersion: "v2";
export const transferV5ProofResponseVersion: "v2";
export const joinSplitOwnerIntentSigningRequestV1Version: "joinsplit-owner-intent-signing-request-v1";

export interface DisclosureBlindingSeparationInputV1 {
  enabled?: boolean;
  privacyPolicy?: number;
  privacy_policy?: number;
  outputRandomness?: bigint | number | string;
  output_randomness?: bigint | number | string;
  userDisclosureBlinding?: bigint | number | string;
  user_disclosure_blinding?: bigint | number | string;
  fullDisclosureBlinding?: bigint | number | string;
  full_disclosure_blinding?: bigint | number | string;
}

export interface PreparedTransferV5Input {
  amount: string;
  randomness_hex: Hex;
  spend_pubkey_hex: Hex;
  view_pubkey_hex: Hex;
  merkle_path: string[];
  merkle_path_helper: number[];
  nullifier_hex: Hex;
}

export interface PreparedTransferV5Output {
  amount: string;
  randomness_hex: Hex;
  spend_pubkey_hex: Hex;
  view_pubkey_hex: Hex;
  commitment_hex: Hex;
}

export interface PreparedTransferV5Payload {
  version: typeof preparedTransferV5PayloadVersion;
  creator: string;
  chain_id: string;
  expires_at_unix: number;
  root_hex: Hex;
  asset_id_hex: Hex;
  inputs: [PreparedTransferV5Input, PreparedTransferV5Input];
  outputs: [PreparedTransferV5Output, PreparedTransferV5Output];
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

export interface PreparedTransferV5Proof {
  version: typeof preparedTransferV5ProofVersion;
  payload_hash: Hex;
  proof_hex: Hex;
}

export interface JoinSplitOwnerIntentSigningRequestV1 {
  version: typeof joinSplitOwnerIntentSigningRequestV1Version;
  circuit_set_id: "privacy-note-v1";
  chain_id: string;
  expires_at_unix: number;
  input_notes: readonly [Note, Note];
  output_notes: readonly [Note, Note];
  sender_spend_pubkey_hex: Hex;
  recipient_output_randomness_hex: Hex;
  user_disclosure_blinding_hex: Hex | "";
  full_disclosure_blinding_hex: Hex;
  payload: Omit<PreparedTransferV5Payload, "owner_signature_hex" | "payload_hash"> & Partial<Pick<PreparedTransferV5Payload, "owner_signature_hex" | "payload_hash">>;
  final_effect: {
    root_hex: Hex;
    asset_id_hex: Hex;
    nullifier_hexes: readonly [Hex, Hex];
    commitment_hexes: readonly [Hex, Hex];
    user_disclosure_digest_hex: Hex | "";
    full_disclosure_digest_hex: Hex;
    expires_at_unix: number;
    payload_digest_hex: Hex;
    intent_hex: Hex;
  };
  expected_intent_hex: Hex;
}

export interface JoinSplitOwnerIntentSignerV1 {
  signJoinSplitOwnerIntent?(request: JoinSplitOwnerIntentSigningRequestV1): Promise<Uint8Array> | Uint8Array;
  signOwnerIntent?(request: JoinSplitOwnerIntentSigningRequestV1): Promise<Uint8Array> | Uint8Array;
}

/** Required value inputs for a V5 2-in/2-out transfer payload. */
export type BuildPreparedTransferV5PayloadInput = {
  creator: ClairAddress | string;
  chainId: string;
  expiresAtUnix?: number;
  chainNowUnix: number;
  /** V5 is a fixed 2-in/2-out circuit. */
  inputs: readonly [FoundNote, FoundNote];
  recipient: ShieldedAddress;
  transferDenom?: string;
  denom?: string;
  merklePathProvider: MerklePathProviderLike;
  auditDisclosureTargetPubKeyHex: Hex;
  senderSpendPubKey?: Point;
  senderViewPubKey?: Point;
  rootSeed?: BytesLike;
  ownerIntentSigner?: JoinSplitOwnerIntentSignerV1;
  noteHashSigner?: NoteHashSigner;
  userPrivacyPolicy?: TransferPrivacyPolicy;
  userDisclosureMode?: TransferUserDisclosureMode;
  userDisclosureTargetPubKeyHex?: Hex;
  disableSelfViewDisclosure?: boolean;
  selfViewDisclosureTargetPubKeyHex?: Hex;
  shieldedPrefix?: string;
} & (
  | { amount: CoinString; transferAmount?: string | number | bigint }
  | { amount?: never; transferAmount: string | number | bigint }
);

export function buildPreparedTransferV5Payload(input: BuildPreparedTransferV5PayloadInput): Promise<PreparedTransferV5Payload>;
export function buildJoinSplitOwnerIntentSigningRequestV1(input: {
  payload: JoinSplitOwnerIntentSigningRequestV1["payload"];
  inputNotes: [Note, Note];
  outputNotes: [Note, Note];
  intent: bigint;
  payloadDigest: { hex: Hex; hi: bigint; lo: bigint };
}): JoinSplitOwnerIntentSigningRequestV1;
export function validateJoinSplitOwnerIntentSigningRequestV1(request: JoinSplitOwnerIntentSigningRequestV1): { expected_intent: bigint; final_effect: JoinSplitOwnerIntentSigningRequestV1["final_effect"] };
export function signValidatedJoinSplitOwnerIntentV1(signer: JoinSplitOwnerIntentSignerV1 | NoteHashSigner, request: JoinSplitOwnerIntentSigningRequestV1, options?: { allowLegacyNoteHashSigner?: boolean }): Promise<Hex>;
export function computePreparedTransferV5PayloadHash(payload: Partial<PreparedTransferV5Payload>): Hex;
export function validatePreparedTransferV5PayloadMetadata(payload: PreparedTransferV5Payload): true;
export function validatePreparedTransferV5PayloadAt(payload: PreparedTransferV5Payload, nowUnix?: number): true;
export function validatePreparedTransferV5Proof(payload: PreparedTransferV5Payload, proof: PreparedTransferV5Proof, options?: { nowUnix?: number }): true;
export function buildTransferV5MsgFromPayloadAndProof(payload: PreparedTransferV5Payload, proof: PreparedTransferV5Proof, options?: {
  nowUnix?: number;
  /** Replaceable Cosmos fee payer/relayer; owner intent remains unchanged. */
  creator?: ClairAddress | string;
  /** Optional target-chain assertion that rejects cross-chain payload reuse. */
  expectedChainId?: string;
  expected_chain_id?: string;
}): MsgTransfer;
export function validateDisclosureBlindingSeparationV1(input?: DisclosureBlindingSeparationInputV1): true;
