import type { Base64, ClairAddress, Hex, PrivacyMaterial, ShieldedAddress } from "../core/crypto.js";
import type {
  DerivedPrivacyAccount,
  ClairveilJS,
  CosmosFeeCoin,
  PrivacyAccountSummary,
  PrivacyEventsQuery,
  PrivacyEventsCursor,
  PrivacyScanOptions,
  PrivacyScanResumeOptions,
  TypedWalletScanOptions,
  QueryRetryOptions,
  ReservationReconciliationState,
  ReserveResponse,
  BatchOperationEvidenceHashes,
  BatchTransferOperationEvidence,
  PreparedBatchTransferPayloadCheckpoint,
  PreparedBatchTransferProofCheckpoint,
  FinalizedPreparedBatchTransfer as FinalizedTransportPreparedBatchTransfer,
  TransferBatchPaymentInput,
  BroadcastSignedTxResult,
  ReservationBroadcastOptions,
  SignedTxBase64,
  SignedTxRawCheckpoint,
  SignDocBase64,
  TxSearchResult
} from "../transport/cosmos-client.js";
import type {
  ValidatedAuditConfigV1,
  ValidatedDisclosureConfigV1,
  ValidatedReserveResponseV1
} from "../privacy/network-config.js";
import type { ValidatedCircuitConfigV1 } from "../privacy/circuit-config.js";
import type {
  NormalizedAssetRegistryEntryV1,
  NormalizedAssetRegistryQueryResponseV1
} from "../privacy/asset-registry.js";
import type {
  EvmDepositMode,
  EvmPrivacyAuthorizationTypedDataDomain,
  Eip1193WalletAdapter,
  EvmPrivacyActionAuthorization,
  EvmPrivacyAuthorizationRequest,
  EvmPrivacyAuthorizationTypedData,
  EvmPrivacyTransactionOptions,
  EvmReservationBroadcastOptions,
  EvmRpcTransaction,
  EvmTransactionRequest,
  EvmTransactionIdentityVerification,
  EvmTransactionWallet,
  EvmWithdrawMessage
} from "../transport/evm.js";
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
import type { PreparedBatchTransferPayload, PreparedBatchTransferProof } from "../privacy/batch-transfer.js";
import type {
  BatchTransferProverAdapter,
  DepositProofProvider as DepositProofProviderContract,
  ProverAdapter
} from "../privacy/prover.js";
import type { MsgBatchTransfer as MsgBatchTransferMessage } from "../generated/clairveil/privacy/v1/tx.js";
import type { TransferBatchPlan, TransferPlan, WithdrawPlan } from "../privacy/planner.js";
import type { NoteReservationManager, ReservationBatch } from "../privacy/reservation.js";
import type { ScanResult } from "../privacy/scan.js";
import type { MemoryNoteStore } from "../privacy/note-store.js";
import type { WalletAdapterLike } from "../wallet/adapter.js";

export interface BrowserGasPriceStep {
  low: number;
  average: number;
  high: number;
}

export interface BrowserKeplrCurrency {
  coinDenom: string;
  coinMinimalDenom: string;
  coinDecimals: number;
}

export interface BrowserKeplrFeeCurrency extends BrowserKeplrCurrency {
  gasPriceStep: BrowserGasPriceStep;
}

export interface BrowserKeplrChainInfo {
  chainId: string;
  chainName: string;
  rpc: string;
  rest: string;
  bip44: { coinType: number };
  bech32Config: {
    bech32PrefixAccAddr: string;
    bech32PrefixAccPub: string;
    bech32PrefixValAddr: string;
    bech32PrefixValPub: string;
    bech32PrefixConsAddr: string;
    bech32PrefixConsPub: string;
  };
  currencies: [BrowserKeplrCurrency];
  feeCurrencies: [BrowserKeplrFeeCurrency];
  stakeCurrency: BrowserKeplrCurrency;
  features: [];
}

interface BrowserWalletProfileBase {
  /** Profile identity and UI metadata required by clairveil-web-client-config-v1. */
  id: string;
  label: string;
  chainName: string;
  chainId: string;
  rpc: string;
  rest: string;
  restEndpoints?: string[];
  accountPrefix: string;
  shieldedPrefix: string;
  denom: string;
  displayDenom: string;
  coinDecimals: number;
  proverUrl: string;
  /** Exact product-reviewed DepositCircuit proof endpoint; never derived from proverUrl. */
  depositProofUrl?: string;
}

export interface BrowserCosmosWalletProfile extends BrowserWalletProfileBase {
  transport: "cosmos";
  wallet: "keplr";
  keplrCoinType: number;
  gasPriceStep: BrowserGasPriceStep;
  keplrChainInfo: BrowserKeplrChainInfo;
}

interface BrowserEvmWalletProfileBase extends BrowserWalletProfileBase {
  transport: "evm";
  wallet: "metamask";
  evmRpc: string;
  evmChainId: string;
  evmChainName: string;
  evmPrivacyPrecompileAddress: string;
  evmGasLimit: string;
  evmSendGasLimit: string;
}

export interface BrowserEvmAuthorizationProfile {
  /** EIP-712 domain selected by the target EVM privacy contract. */
  typedDataDomain?: EvmPrivacyAuthorizationTypedDataDomain;
  /** Target-chain authorization-kind allowlist. Omit to permit every uint8 kind. */
  supportedAuthorizationKinds?: Array<string | number>;
}

/** The canonical EVM precompile has no amount tuple field: msg.value is mandatory. */
export type BrowserEvmWalletProfile = BrowserEvmWalletProfileBase & {
  evmDepositMode?: "payable-exact-value";
  /** Must equal denom so the minimal-unit amount can bind exactly to msg.value. */
  evmNativeDenom: string;
  evmAuthorizationProfile?: BrowserEvmAuthorizationProfile;
};

/** A complete, document-validated browser DApp profile. */
export type BrowserWalletProfile = BrowserCosmosWalletProfile | BrowserEvmWalletProfile;

export type BrowserWalletType = "cosmos" | "evm";

/** Server-provided feature visibility flags from clairveil-web-client-config-v1. */
export interface BrowserServerFeatures {
  localTestMode?: boolean;
  localSigners?: boolean;
  faucet?: boolean;
  depositProof?: boolean;
  auditorAdmin?: boolean;
  localSignerAdmin?: boolean;
  localSignerSetup?: boolean;
  relayer?: boolean;
  proverProxy?: boolean;
  batchTransfer?: boolean;
}

/**
 * Complete browser deployment configuration. Validate this document before
 * selecting `activeProfile` and passing it to the browser client.
 */
export interface ClairveilWebClientConfig {
  schemaVersion: "clairveil-web-client-config-v1";
  activeChainProfileId: string;
  chainProfiles: BrowserWalletProfile[];
  serverBacked?: boolean;
  modeLabel?: string;
  home?: string;
  localSignerHome?: string;
  localSignerBin?: string;
  localTestMode?: boolean;
  serverFeatures?: BrowserServerFeatures;
  /** Deprecated flattened fields; when present they must equal activeProfile. */
  chainId?: string;
  rpc?: string;
  rest?: string;
  proverUrl?: string;
  transport?: BrowserWalletType;
  denom?: string;
  displayDenom?: string;
  coinDecimals?: number;
  accountPrefix?: string;
  shieldedPrefix?: string;
  keplrChainInfo?: BrowserKeplrChainInfo;
  evmRpc?: string;
  evmChainId?: string;
  evmChainName?: string;
  evmPrivacyPrecompileAddress?: string;
  evmDepositMode?: EvmDepositMode;
  evmNativeDenom?: string;
  evmAuthorizationProfile?: BrowserEvmAuthorizationProfile;
  evmGasLimit?: string;
  evmSendGasLimit?: string;
}

export type ValidatedClairveilWebClientConfig = Omit<ClairveilWebClientConfig, "chainProfiles" | "serverFeatures"> & {
  chainProfiles: readonly BrowserWalletProfile[];
  serverFeatures?: Readonly<BrowserServerFeatures>;
  activeProfile: BrowserWalletProfile;
};

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
  /** Inject a browser, local, WASM, or async-job prover implementation. */
  proverAdapter?: BrowserProverAdapter;
  /** Optional bearer credential for the default HTTP prover adapter. */
  proverBearerToken?: string;
  proverTimeoutMs?: number;
  /** Optional local/WASM DepositCircuit provider; profile endpoint remains separate from proverUrl. */
  depositProofProvider?: DepositProofProvider;
  depositProofUrl?: string;
  depositProofTimeoutMs?: number;
  depositProofResponseMaxBytes?: number;
  queryTimeoutMs?: number;
  fetchTimeoutMs?: number;
  queryRetry?: QueryRetryOptions | false;
  nullifierFailover?: boolean;
  /** Allow Merkle witness and exact-snapshot queries to fail over across REST endpoints. */
  merklePathFailover?: boolean;
  evmRpc?: string;
  evmChainId?: string;
  evmPrivacyPrecompileAddress?: string;
  evmDepositMode?: EvmDepositMode;
  evmNativeDenom?: string;
  evmAuthorizationProfile?: BrowserEvmAuthorizationProfile;
  evmGasLimit?: string;
  evmSendGasLimit?: string;
  enableExperimentalBatchTransfer?: boolean;
  enable_experimental_batch_transfer?: boolean;
}

/**
 * Runtime prover injection accepted by the browser facade. Individual
 * operations still require the method for that operation (transfer,
 * withdraw, or one-proof batch transfer).
 */
export type BrowserProverAdapter = Partial<ProverAdapter> & Partial<BatchTransferProverAdapter>;

export interface BrowserHealthResult {
  /** `health()` resolves only after the configured chain, tree, and audit config validate. */
  status: object;
  tree: object;
  audit: ValidatedAuditConfigV1;
  errors: [];
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
  executionTransport: "evm";
  txHash: Hex | string;
  evmTxHash: Hex | string;
  /** Binding of the original prepared request; not a network transaction hash. */
  txBytesHash: Hex | string;
  receipt: object | null;
  /** Exact hash/from/to/input/value/chain verification against RPC transaction data. */
  transactionVerification: Readonly<EvmTransactionIdentityVerification> | null;
  /** Action-specific EVM privacy-event verification. */
  privacyReceipt: Readonly<{ verified: true; event: string; operation: string }> | null;
  tx: EvmRpcTransaction | object | null;
  evmTransactionVerified: boolean;
  evmPrivacyReceiptVerified: boolean;
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

export type DepositProofProvider = DepositProofProviderContract;

/** The connected EVM signing wallet required before an EVM prepare request. */
export type EvmNetworkWallet = Pick<Eip1193WalletAdapter, "getChainId">;

/** Optional signer for an EIP-712 batch-executor authorization without a pre-supplied signature. */
export type EvmBatchAuthorizationSigner = Pick<Eip1193WalletAdapter, "signTypedData">;

/** Connected EVM wallet required for browser-facade transaction submission. */
export type BrowserEvmTransactionWallet = EvmNetworkWallet & EvmTransactionWallet;

/**
 * Reservation-aware EVM submission input. Relay fields are the same as the
 * low-level client; when supplied, active-profile chain and prefix bindings
 * are enforced by the browser facade.
 */
export type BrowserEvmTransactionBroadcastInput = {
  wallet: BrowserEvmTransactionWallet;
  transaction: EvmTransactionRequest;
} & EvmReservationBroadcastOptions;

type EvmNetworkWalletBinding =
  | { evmWallet: EvmNetworkWallet; evm_wallet?: EvmNetworkWallet }
  | { evmWallet?: EvmNetworkWallet; evm_wallet: EvmNetworkWallet };

type DepositProofProviderBinding = {
  depositProofProvider?: DepositProofProvider;
  deposit_proof_provider?: DepositProofProvider;
};

export type PrepareDepositProofInput =
  | ({ proof: Uint8Array | Hex; proofHex?: Hex; proof_hex?: Hex } & DepositProofProviderBinding)
  | ({ proof?: Uint8Array | Hex; proofHex: Hex; proof_hex?: Hex } & DepositProofProviderBinding)
  | ({ proof?: Uint8Array | Hex; proofHex?: Hex; proof_hex: Hex } & DepositProofProviderBinding)
  | ({ proof?: Uint8Array | Hex; proofHex?: Hex; proof_hex?: Hex; depositProofProvider: DepositProofProvider } & DepositProofProviderBinding)
  | ({ proof?: Uint8Array | Hex; proofHex?: Hex; proof_hex?: Hex; deposit_proof_provider: DepositProofProvider } & DepositProofProviderBinding);

export type PrepareDepositBaseInput = Omit<BrowserWalletIdentityInput, "walletType" | "wallet_type"> & {
  amount: CoinString;
  depositMaterial?: object;
  deposit_material?: object;
  signal?: AbortSignal;
};

export type PrepareCosmosDepositInput = PrepareDepositBaseInput & PrepareDepositProofInput & {
  walletType?: "cosmos";
  wallet_type?: "cosmos";
  gasLimit?: number;
  gas_limit?: number;
  /** Exact profile/caller-selected fee coins embedded in the sign doc. */
  feeAmount?: readonly CosmosFeeCoin[];
  fee_amount?: readonly CosmosFeeCoin[];
};

export type PrepareEvmDepositInput = PrepareDepositBaseInput & EvmNetworkWalletBinding & (
  | { walletType: "evm"; wallet_type?: "evm" }
  | { walletType?: "evm"; wallet_type: "evm" }
) & DepositProofProviderBinding & {
  proof?: Uint8Array | Hex;
  proofHex?: Hex;
  proof_hex?: Hex;
};

export type PrepareDefaultEvmProfileDepositInput = PrepareDepositBaseInput & EvmNetworkWalletBinding & DepositProofProviderBinding & {
  walletType?: undefined;
  wallet_type?: undefined;
  proof?: Uint8Array | Hex;
  proofHex?: Hex;
  proof_hex?: Hex;
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
  prepared: PreparedDepositSummary & {
    /** Exact encrypted deposit output required by confirmDeposit. */
    encryptedNoteHex: Hex;
  };
}

export interface PreparedEvmDeposit {
  signDoc?: never;
  transaction: EvmTransactionRequest;
  prepared: PreparedDepositSummary & {
    /** Exact encrypted deposit output required for receipt/state recovery. */
    encryptedNoteHex: Hex;
  };
}

export type PreparedDeposit = PreparedCosmosDeposit | PreparedEvmDeposit;
export type PreparedDepositForDefault<TDefaultWalletType extends BrowserWalletType> =
  TDefaultWalletType extends "evm" ? PreparedEvmDeposit : PreparedCosmosDeposit;

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

type AuthoritativeBrowserTransferPreparationTime =
  | { chainNowUnix: number; chain_now_unix?: number }
  | { chain_now_unix: number; chainNowUnix?: number };

export type PrepareTransferInput = BrowserWalletIdentityInput & DirectOperationEvidenceHashes & {
  amount: CoinString;
  recipient: ShieldedAddress;
  proverAdapter?: ProverAdapter;
  prover_adapter?: ProverAdapter;
  signal?: AbortSignal;
  allowPlanStep?: boolean;
  allow_plan_step?: boolean;
  limit?: number;
  maxPages?: number;
  max_pages?: number;
  scan?: TypedWalletScanOptions;
  privacyPolicy?: TransferPrivacyPolicy;
  privacy_policy?: TransferPrivacyPolicy;
  disclosureMode?: TransferUserDisclosureMode;
  disclosure_mode?: TransferUserDisclosureMode;
  disclosurePubKeyHex?: Hex;
  disclosure_pubkey_hex?: Hex;
  /** Optional explicit expiry; defaults to authoritative chain time + 1800 seconds. */
  expiresAtUnix?: number;
  expires_at_unix?: number;
  /** Authoritative chain time is required before an executable transfer proof is prepared. */
  chainNowUnix?: number;
  chain_now_unix?: number;
  /** Sender self-view is enabled by default; set true only for an explicit opt-out. */
  disableSelfViewDisclosure?: boolean;
  disable_self_view_disclosure?: boolean;
  selfViewDisclosureTargetPubKeyHex?: Hex;
  self_view_disclosure_target_pubkey?: Hex;
  reservationManager?: NoteReservationManager | null;
  reservation_manager?: NoteReservationManager | null;
  /** Cosmos only: exact gas limit embedded in the ProofReady sign doc. */
  gasLimit?: number;
  gas_limit?: number;
  /** Cosmos only: exact minimal-denom fee coins embedded in the ProofReady sign doc. */
  feeAmount?: readonly CosmosFeeCoin[];
  fee_amount?: readonly CosmosFeeCoin[];
} & AuthoritativeBrowserTransferPreparationTime;

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

export type PrepareTransferBaseInput = DistributiveOmit<PrepareTransferInput, "walletType" | "wallet_type">;

export type PrepareCosmosTransferInput = PrepareTransferBaseInput & {
  walletType?: "cosmos";
  wallet_type?: "cosmos";
};

export type PrepareEvmTransferInput = PrepareTransferBaseInput & EvmNetworkWalletBinding & (
  | { walletType: "evm"; wallet_type?: "evm" }
  | { walletType?: "evm"; wallet_type: "evm" }
);

export type PrepareDefaultEvmProfileTransferInput = PrepareTransferBaseInput & EvmNetworkWalletBinding & {
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
  expiresAtUnix: number;
  chainNowUnix: number;
  payload?: PreparedTransferPayload;
  proof?: PreparedTransferProof;
  message?: TransferMessage;
  reservation?: ReservationBatch | null;
}

export interface PreparedCosmosTransfer extends ReservationReconciliationState {
  signDoc: SignDocBase64;
  transaction?: never;
  reservation?: ReservationBatch | null;
  prepared: PreparedTransferSummary;
  plan: TransferPlan;
}

export interface PreparedEvmTransfer extends ReservationReconciliationState {
  signDoc?: never;
  transaction: EvmTransactionRequest;
  txBytesHash: string;
  reservation?: ReservationBatch | null;
  prepared: PreparedTransferSummary;
  plan: TransferPlan;
}

export type PreparedTransfer = PreparedCosmosTransfer | PreparedEvmTransfer;

type BrowserPrepareTransferBatchPaymentShape =
  | { payments: readonly TransferBatchPaymentInput[]; amounts?: never; recipient?: never }
  | { payments?: never; amounts: CoinString[]; recipient: ShieldedAddress };

type BrowserBatchReservationManagerBinding =
  | { reservationManager: NoteReservationManager; reservation_manager?: NoteReservationManager | null }
  | { reservationManager?: NoteReservationManager | null; reservation_manager: NoteReservationManager };

type BrowserBatchPayloadCheckpointBinding =
  | {
      onPreparedPayload: PreparedBatchTransferPayloadCheckpoint;
      on_prepared_payload?: PreparedBatchTransferPayloadCheckpoint;
    }
  | {
      onPreparedPayload?: PreparedBatchTransferPayloadCheckpoint;
      on_prepared_payload: PreparedBatchTransferPayloadCheckpoint;
    };

type BrowserBatchProofCheckpointBinding =
  | {
      onPreparedProof: PreparedBatchTransferProofCheckpoint;
      on_prepared_proof?: PreparedBatchTransferProofCheckpoint;
    }
  | {
      onPreparedProof?: PreparedBatchTransferProofCheckpoint;
      on_prepared_proof: PreparedBatchTransferProofCheckpoint;
    };

export type PrepareTransferBatchInput = BrowserWalletIdentityInput &
  BatchOperationEvidenceHashes &
  BrowserPrepareTransferBatchPaymentShape &
  BrowserBatchReservationManagerBinding &
  BrowserBatchPayloadCheckpointBinding &
  BrowserBatchProofCheckpointBinding & {
  outputMode?: "compact" | "exact32" | "exact-32";
  output_mode?: "compact" | "exact32" | "exact-32";
  proverAdapter?: BatchTransferProverAdapter;
  prover_adapter?: BatchTransferProverAdapter;
  signal?: AbortSignal;
  limit?: number;
  maxPages?: number;
  max_pages?: number;
  scan?: TypedWalletScanOptions;
  gasLimit?: number;
  gas_limit?: number;
  /** Exact profile/caller-selected fee coins, snapshotted before scan/proving. */
  feeAmount?: readonly CosmosFeeCoin[];
  fee_amount?: readonly CosmosFeeCoin[];
  expiresAtUnix?: number;
  expires_at_unix?: number;
  chainNowUnix?: number;
  chain_now_unix?: number;
  rootHex?: Hex;
  root_hex?: Hex;
  snapshotHeight?: number | bigint | string;
  snapshot_height?: number | bigint | string;
  disableSelfViewDisclosure?: boolean;
  disable_self_view_disclosure?: boolean;
  selfViewDisclosureTargetPubKeyHex?: Hex;
  self_view_disclosure_target_pubkey?: Hex;
  privacyPolicy?: TransferPrivacyPolicy;
  privacy_policy?: TransferPrivacyPolicy;
  disclosureMode?: TransferUserDisclosureMode;
  disclosure_mode?: TransferUserDisclosureMode;
  disclosurePubKeyHex?: Hex;
  disclosure_pubkey_hex?: Hex;
  auditDisclosureTargetPubKeyHex?: Hex;
  audit_disclosure_target_pubkey_hex?: Hex;
};

export type PrepareCosmosTransferBatchInput = DistributiveOmit<PrepareTransferBatchInput, "walletType" | "wallet_type"> & {
  walletType?: "cosmos";
  wallet_type?: "cosmos";
};

export type PrepareEvmTransferBatchInput = DistributiveOmit<PrepareTransferBatchInput, "walletType" | "wallet_type"> &
  EvmNetworkWalletBinding & (
    | { walletType: "evm"; wallet_type?: "evm" }
    | { walletType?: "evm"; wallet_type: "evm" }
  ) & {
    transactionOptions?: EvmPrivacyTransactionOptions;
    transaction_options?: EvmPrivacyTransactionOptions;
    authorization?: EvmPrivacyAuthorizationRequest;
    privacy_authorization?: EvmPrivacyAuthorizationRequest;
    authorizationSigner?: EvmBatchAuthorizationSigner;
    authorization_signer?: EvmBatchAuthorizationSigner;
  };

export type PrepareDefaultEvmProfileTransferBatchInput = DistributiveOmit<PrepareTransferBatchInput, "walletType" | "wallet_type"> &
  EvmNetworkWalletBinding & {
    walletType?: undefined;
    wallet_type?: undefined;
    transactionOptions?: EvmPrivacyTransactionOptions;
    transaction_options?: EvmPrivacyTransactionOptions;
    authorization?: EvmPrivacyAuthorizationRequest;
    privacy_authorization?: EvmPrivacyAuthorizationRequest;
    authorizationSigner?: EvmBatchAuthorizationSigner;
    authorization_signer?: EvmBatchAuthorizationSigner;
  };

export type PrepareExplicitCosmosTransferBatchInput = DistributiveOmit<PrepareTransferBatchInput, "walletType" | "wallet_type"> & (
  | { walletType: "cosmos"; wallet_type?: "cosmos" }
  | { walletType?: "cosmos"; wallet_type: "cosmos" }
);

export type PrepareTransferBatchInputForDefault<TDefaultWalletType extends BrowserWalletType = "cosmos"> =
  TDefaultWalletType extends "evm" ? PrepareDefaultEvmProfileTransferBatchInput : PrepareCosmosTransferBatchInput;

type FinalizePreparedBatchTransferBaseInput = DistributiveOmit<
  Parameters<ClairveilJS["finalizePreparedBatchTransfer"]>[0],
  "signer" | "pubKeyHex" | "gasLimit" | "denom" | "userPrivacyPolicy" | "userDisclosureMode" | "userDisclosureTargetPubKeyHex" | "executionBuilder"
> & {
  signer?: ClairAddress | string;
  address?: ClairAddress | string;
  pubKeyHex?: Hex;
  pub_key_hex?: Hex;
  gasLimit?: number | bigint;
  gas_limit?: number | bigint;
  denom?: string;
  privacyPolicy?: TransferPrivacyPolicy;
  privacy_policy?: TransferPrivacyPolicy;
  disclosureMode?: TransferUserDisclosureMode;
  disclosure_mode?: TransferUserDisclosureMode;
  disclosurePubKeyHex?: Hex;
  disclosure_pubkey_hex?: Hex;
};

export type FinalizePreparedBatchTransferInput = FinalizePreparedBatchTransferBaseInput & {
  walletType?: "cosmos";
  wallet_type?: "cosmos";
};

export type FinalizeEvmPreparedBatchTransferInput = FinalizePreparedBatchTransferBaseInput &
  EvmNetworkWalletBinding & (
    | { walletType: "evm"; wallet_type?: "evm" }
    | { walletType?: "evm"; wallet_type: "evm" }
  ) & {
    transactionOptions?: EvmPrivacyTransactionOptions;
    transaction_options?: EvmPrivacyTransactionOptions;
    authorization?: EvmPrivacyAuthorizationRequest;
    privacy_authorization?: EvmPrivacyAuthorizationRequest;
    authorizationSigner?: EvmBatchAuthorizationSigner;
    authorization_signer?: EvmBatchAuthorizationSigner;
  };

export type FinalizeDefaultEvmProfilePreparedBatchTransferInput = FinalizePreparedBatchTransferBaseInput &
  EvmNetworkWalletBinding & {
    walletType?: undefined;
    wallet_type?: undefined;
    transactionOptions?: EvmPrivacyTransactionOptions;
    transaction_options?: EvmPrivacyTransactionOptions;
    authorization?: EvmPrivacyAuthorizationRequest;
    privacy_authorization?: EvmPrivacyAuthorizationRequest;
    authorizationSigner?: EvmBatchAuthorizationSigner;
    authorization_signer?: EvmBatchAuthorizationSigner;
  };

export type FinalizePreparedBatchTransferInputForDefault<TDefaultWalletType extends BrowserWalletType = "cosmos"> =
  TDefaultWalletType extends "evm"
    ? FinalizeDefaultEvmProfilePreparedBatchTransferInput
    : FinalizePreparedBatchTransferInput;

export interface PreparedTransferBatchSummary {
  shieldedAddress: ShieldedAddress;
  payments: Array<{
    itemId: string;
    amount: CoinString;
    recipient: ShieldedAddress;
    privacyPolicy: string;
    disclosureMode: string;
  }>;
  amounts: CoinString[];
  recipient?: ShieldedAddress;
  privacyPolicy?: TransferPrivacyPolicy;
  disclosureMode?: TransferUserDisclosureMode;
  outputMode: "compact" | "exact32";
  planStatus: string;
  planAction: string;
  selectedInputTotal?: string;
  inputCount?: number;
  outputCount?: number;
  payload?: PreparedBatchTransferPayload;
  proof?: PreparedBatchTransferProof;
  message?: MsgBatchTransferMessage;
  operationEvidence?: BatchTransferOperationEvidence;
  operationEvidenceHash?: Hex;
  reservation?: ReservationBatch | null;
}

export interface PreparedCosmosTransferBatch extends ReservationReconciliationState {
  signDoc: SignDocBase64;
  transaction?: never;
  reservation?: ReservationBatch | null;
  prepared: PreparedTransferBatchSummary;
  plan: TransferBatchPlan;
}

export interface PreparedEvmTransferBatch extends ReservationReconciliationState {
  signDoc?: never;
  transaction: EvmTransactionRequest;
  /** SHA-256 binding of the exact canonical transaction fields persisted with every input reservation. */
  txBytesHash: string;
  /** The resolved executor authorization, including a signature if the SDK requested one. */
  authorization?: EvmPrivacyActionAuthorization;
  /** The exact EIP-712 payload signed during preparation, when authorizationSigner was used. */
  authorizationTypedData?: EvmPrivacyAuthorizationTypedData;
  reservation?: ReservationBatch | null;
  prepared: PreparedTransferBatchSummary;
  plan: TransferBatchPlan;
}

export type PreparedTransferBatch = PreparedCosmosTransferBatch | PreparedEvmTransferBatch;

export type FinalizedCosmosPreparedBatchTransfer = Extract<
  FinalizedTransportPreparedBatchTransfer,
  { signDoc: SignDocBase64 }
>;

export type FinalizedEvmPreparedBatchTransfer = Extract<
  FinalizedTransportPreparedBatchTransfer,
  { execution: object }
> & {
  transaction: EvmTransactionRequest;
  /** Same transaction binding persisted during checkpoint recovery. */
  txBytesHash: string;
  authorization?: EvmPrivacyActionAuthorization;
  authorizationTypedData?: EvmPrivacyAuthorizationTypedData;
};

export type FinalizedPreparedBatchTransfer =
  | FinalizedCosmosPreparedBatchTransfer
  | FinalizedEvmPreparedBatchTransfer;

export interface PrepareWithdrawInput extends BrowserWalletIdentityInput {
  amount: CoinString;
  recipient: ClairAddress | string;
  proverAdapter?: ProverAdapter;
  prover_adapter?: ProverAdapter;
  signal?: AbortSignal;
  limit?: number;
  maxPages?: number;
  max_pages?: number;
  scan?: TypedWalletScanOptions;
  expiresAtUnix?: number;
  expires_at_unix?: number;
  chainNowUnix?: number;
  chain_now_unix?: number;
  reservationManager?: NoteReservationManager | null;
  reservation_manager?: NoteReservationManager | null;
  /** Cosmos only: exact gas limit embedded in the ProofReady sign doc. */
  gasLimit?: number;
  gas_limit?: number;
  /** Cosmos only: exact minimal-denom fee coins embedded in the ProofReady sign doc. */
  feeAmount?: readonly CosmosFeeCoin[];
  fee_amount?: readonly CosmosFeeCoin[];
}

export type PrepareWithdrawBaseInput = Omit<PrepareWithdrawInput, "walletType" | "wallet_type">;

export type PrepareCosmosWithdrawInput = PrepareWithdrawBaseInput & {
  walletType?: "cosmos";
  wallet_type?: "cosmos";
};

export type PrepareEvmWithdrawInput = PrepareWithdrawBaseInput & EvmNetworkWalletBinding & (
  | { walletType: "evm"; wallet_type?: "evm" }
  | { walletType?: "evm"; wallet_type: "evm" }
);

export type PrepareDefaultEvmProfileWithdrawInput = PrepareWithdrawBaseInput & EvmNetworkWalletBinding & {
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
  reservation?: ReservationBatch | null;
}

export interface PreparedCosmosWithdraw extends ReservationReconciliationState {
  signDoc: SignDocBase64;
  transaction?: never;
  payload: PreparedWithdrawPayload;
  proof: PreparedWithdrawProof;
  message: WithdrawMessage;
  reservation?: ReservationBatch | null;
  prepared: PreparedWithdrawSummary;
  plan: WithdrawPlan;
}

export interface PreparedEvmWithdraw extends ReservationReconciliationState {
  signDoc?: never;
  transaction: EvmTransactionRequest;
  txBytesHash: string;
  payload: PreparedWithdrawPayload;
  proof: PreparedWithdrawProof;
  message: WithdrawMessage;
  reservation?: ReservationBatch | null;
  prepared: PreparedWithdrawSummary;
  plan: WithdrawPlan;
}

export type PreparedWithdraw = PreparedCosmosWithdraw | PreparedEvmWithdraw;

type RelayChainTimeInput = {
  chainNowUnix?: number;
  chain_now_unix?: number;
  /** @deprecated Use chainNowUnix with the latest chain block time. */
  nowUnix?: number;
  /** @deprecated Use chain_now_unix with the latest chain block time. */
  now_unix?: number;
} & (
  | { chainNowUnix: number }
  | { chain_now_unix: number }
  | { nowUnix: number }
  | { now_unix: number }
);

export type PrepareEvmRelayWithdrawTransactionOptionsInput = {
  transactionOptions?: EvmPrivacyTransactionOptions;
  transaction_options?: EvmPrivacyTransactionOptions;
} & RelayChainTimeInput;

export type PrepareRelayWithdrawBaseInput = PrepareWithdrawBaseInput;

export type PrepareCosmosRelayWithdrawInput = PrepareRelayWithdrawBaseInput & RelayChainTimeInput & {
  walletType?: "cosmos";
  wallet_type?: "cosmos";
};

export type PrepareEvmRelayWithdrawInput = PrepareRelayWithdrawBaseInput & EvmNetworkWalletBinding & PrepareEvmRelayWithdrawTransactionOptionsInput & (
  | { walletType: "evm"; wallet_type?: "evm" }
  | { walletType?: "evm"; wallet_type: "evm" }
);

export type PrepareDefaultEvmProfileRelayWithdrawInput = PrepareRelayWithdrawBaseInput & EvmNetworkWalletBinding & PrepareEvmRelayWithdrawTransactionOptionsInput & {
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

export interface PreparedCosmosRelayWithdraw extends ReservationReconciliationState {
  payload: PreparedWithdrawPayload;
  signDoc?: never;
  transaction?: never;
  reservation?: ReservationBatch | null;
  prepared: PreparedRelayWithdrawSummary;
  plan: WithdrawPlan;
}

export interface PreparedEvmRelayWithdraw extends ReservationReconciliationState {
  payload: PreparedWithdrawPayload;
  signDoc?: never;
  transaction: EvmTransactionRequest;
  reservation?: ReservationBatch | null;
  prepared: PreparedEvmRelayWithdrawSummary;
  plan: WithdrawPlan;
}

export type PreparedRelayWithdraw = PreparedCosmosRelayWithdraw | PreparedEvmRelayWithdraw;

export type CreateRelayWithdrawSignDocInput = {
  payload: PreparedWithdrawPayload;
  relayer?: ClairAddress | string;
  creator?: ClairAddress | string;
  address?: ClairAddress | string;
  pubKeyHex?: Hex;
  pub_key_hex?: Hex;
  gasLimit?: number;
  gas_limit?: number;
  feeAmount?: readonly CosmosFeeCoin[];
  fee_amount?: readonly CosmosFeeCoin[];
  memo?: string;
  expectedChainId?: string;
  expected_chain_id?: string;
  expectedRecipient?: ClairAddress | string;
  expected_recipient?: ClairAddress | string;
  accountPrefix?: string;
  account_prefix?: string;
} & RelayChainTimeInput;

export interface PreparedRelayWithdrawSignDoc {
  signDoc: SignDocBase64;
  message: WithdrawMessage;
  payload: PreparedWithdrawPayload;
  relayer: ClairAddress | string;
}

export interface ScanWalletNotesInput extends BrowserWalletIdentityInput, TypedWalletScanOptions {
  includeFoundNotes?: boolean;
  noteStore?: MemoryNoteStore;
  note_store?: MemoryNoteStore;
}

export type ScanWalletNotesResult = ScanResult & {
  privacyAccount: PrivacyAccountSummary | DerivedPrivacyAccount;
  scanCursor: PrivacyEventsCursor;
  nextScanOptions: PrivacyScanResumeOptions;
};

export interface DecodeUserDisclosureInput extends Partial<BrowserWalletIdentityInput>, PrivacyScanOptions {
  /** Validator-issued shielded-transfer recipient output; avoids raw event lookup. */
  output?: import("../core/disclosure.js").TransferPrivacyScanDisclosureOutputV2;
  scanOutput?: import("../core/disclosure.js").TransferPrivacyScanDisclosureOutputV2;
  txHash?: Hex;
  tx_hash?: Hex;
  assetDenom?: string;
  asset_denom?: string;
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
  /** Validator-issued shielded-transfer recipient output; avoids raw event lookup. */
  output?: import("../core/disclosure.js").TransferPrivacyScanDisclosureOutputV2;
  scanOutput?: import("../core/disclosure.js").TransferPrivacyScanDisclosureOutputV2;
  txHash?: Hex;
  tx_hash?: Hex;
  assetDenom?: string;
  asset_denom?: string;
  disclosurePrivKeyHex?: Hex;
  disclosure_privkey_hex?: Hex;
}

type BrowserProfileTransport = BrowserWalletType | null;

type PrepareDepositInputForProfile<
  TDefaultWalletType extends BrowserWalletType,
  TProfileTransport extends BrowserProfileTransport
> = TProfileTransport extends "evm"
  ? PrepareEvmDepositInput | PrepareDefaultEvmProfileDepositInput
  : TProfileTransport extends "cosmos"
    ? PrepareCosmosDepositInput
    : PrepareDepositInput<TDefaultWalletType>;

type PreparedDepositForProfile<TProfileTransport extends BrowserProfileTransport> =
  TProfileTransport extends "evm" ? PreparedEvmDeposit
    : TProfileTransport extends "cosmos" ? PreparedCosmosDeposit
      : PreparedDeposit;

type PrepareTransferInputForProfile<TProfileTransport extends BrowserProfileTransport> =
  TProfileTransport extends "evm"
    ? PrepareEvmTransferInput | PrepareDefaultEvmProfileTransferInput
    : TProfileTransport extends "cosmos"
      ? PrepareCosmosTransferInput
      : PrepareTransferInput;

type PreparedTransferForProfile<TProfileTransport extends BrowserProfileTransport> =
  TProfileTransport extends "evm" ? PreparedEvmTransfer
    : TProfileTransport extends "cosmos" ? PreparedCosmosTransfer
      : PreparedTransfer;

type PrepareTransferBatchInputForProfile<
  TDefaultWalletType extends BrowserWalletType,
  TProfileTransport extends BrowserProfileTransport
> = TProfileTransport extends "evm"
  ? PrepareEvmTransferBatchInput | PrepareDefaultEvmProfileTransferBatchInput
  : TProfileTransport extends "cosmos"
    ? PrepareCosmosTransferBatchInput
    : PrepareTransferBatchInputForDefault<TDefaultWalletType>;

type PreparedTransferBatchForProfile<TProfileTransport extends BrowserProfileTransport> =
  TProfileTransport extends "evm" ? PreparedEvmTransferBatch
    : TProfileTransport extends "cosmos" ? PreparedCosmosTransferBatch
      : PreparedTransferBatch;

type FinalizePreparedBatchTransferInputForProfile<
  TDefaultWalletType extends BrowserWalletType,
  TProfileTransport extends BrowserProfileTransport
> = TProfileTransport extends "evm"
  ? FinalizeEvmPreparedBatchTransferInput | FinalizeDefaultEvmProfilePreparedBatchTransferInput
  : TProfileTransport extends "cosmos"
    ? FinalizePreparedBatchTransferInput
    : FinalizePreparedBatchTransferInputForDefault<TDefaultWalletType>;

type FinalizedPreparedBatchTransferForProfile<TProfileTransport extends BrowserProfileTransport> =
  TProfileTransport extends "evm" ? FinalizedEvmPreparedBatchTransfer
    : TProfileTransport extends "cosmos" ? FinalizedCosmosPreparedBatchTransfer
      : FinalizedPreparedBatchTransfer;

type PrepareWithdrawInputForProfile<TProfileTransport extends BrowserProfileTransport> =
  TProfileTransport extends "evm"
    ? PrepareEvmWithdrawInput | PrepareDefaultEvmProfileWithdrawInput
    : TProfileTransport extends "cosmos"
      ? PrepareCosmosWithdrawInput
      : PrepareWithdrawInput;

type PreparedWithdrawForProfile<TProfileTransport extends BrowserProfileTransport> =
  TProfileTransport extends "evm" ? PreparedEvmWithdraw
    : TProfileTransport extends "cosmos" ? PreparedCosmosWithdraw
      : PreparedWithdraw;

type PrepareRelayWithdrawInputForProfile<
  TDefaultWalletType extends BrowserWalletType,
  TProfileTransport extends BrowserProfileTransport
> = TProfileTransport extends "evm"
  ? PrepareEvmRelayWithdrawInput | PrepareDefaultEvmProfileRelayWithdrawInput
  : TProfileTransport extends "cosmos"
    ? PrepareCosmosRelayWithdrawInput
    : PrepareRelayWithdrawInput<TDefaultWalletType>;

type PreparedRelayWithdrawForProfile<TProfileTransport extends BrowserProfileTransport> =
  TProfileTransport extends "evm" ? PreparedEvmRelayWithdraw
    : TProfileTransport extends "cosmos" ? PreparedCosmosRelayWithdraw
      : PreparedRelayWithdraw;

export class ClairveilBrowserClient<
  TDefaultWalletType extends BrowserWalletType = "cosmos",
  TProfileTransport extends BrowserProfileTransport = null
> {
  constructor(options: ClairveilBrowserClientOptions & { profile: BrowserWalletProfile & { transport: TProfileTransport } });
  constructor(options?: ClairveilBrowserClientOptions);
  /**
   * Verify the configured chain, tree, and audit configuration.
   *
   * By default the tree must already be initialized. Set
   * `allowUninitializedTree` only for bootstrap surfaces that need to accept
   * an empty, otherwise structurally valid tree before the first deposit.
   */
  health(options?: { allowUninitializedTree?: boolean }): Promise<BrowserHealthResult>;
  fetchBlockEvents(limit?: number): Promise<{ events: BrowserBlockEvent[] }>;
  fetchPrivacyEvents(options?: PrivacyEventsQuery): Promise<object & { events?: object[] }>;
  fetchScanEvents(options?: PrivacyEventsQuery): Promise<object & { events?: object[] }>;
  queryPrivacyScan(options?: Parameters<ClairveilJS["queryPrivacyScan"]>[0]): ReturnType<ClairveilJS["queryPrivacyScan"]>;
  fetchAuditableTransfers(options?: PrivacyEventsQuery): Promise<object & { events: object[] }>;
  fetchAuditableBatchTransfers(options?: Parameters<ClairveilJS["fetchAuditableBatchTransfers"]>[0]): ReturnType<ClairveilJS["fetchAuditableBatchTransfers"]>;
  fetchAuditConfig(): Promise<object>;
  fetchDisclosureConfig(): Promise<object>;
  queryAuditConfig(): Promise<ValidatedAuditConfigV1>;
  queryDisclosureConfig(): Promise<ValidatedDisclosureConfigV1>;
  fetchCircuitConfig(options?: { expectedCircuitIdentity?: ValidatedCircuitConfigV1["circuit_set_identity"] }): Promise<ValidatedCircuitConfigV1>;
  assertCircuitConfig(options?: { expectedCircuitIdentity?: ValidatedCircuitConfigV1["circuit_set_identity"] }): Promise<ValidatedCircuitConfigV1>;
  fetchReserve(denom: string): Promise<ReserveResponse>;
  queryReserve(denom: string): Promise<ValidatedReserveResponseV1>;
  fetchAssetByDenom(denom: string): Promise<object>;
  fetchAssetByID(assetIdHex: Hex): Promise<object>;
  queryAssetByDenom(denom: string): Promise<NormalizedAssetRegistryQueryResponseV1>;
  queryAssetByID(assetIdHex: Hex): Promise<NormalizedAssetRegistryQueryResponseV1>;
  resolveAsset(denom: string): Promise<NormalizedAssetRegistryEntryV1>;
  resolveAssetByDenom(denom: string): Promise<NormalizedAssetRegistryEntryV1>;
  resolveAssetByID(assetIdHex: Hex): Promise<NormalizedAssetRegistryEntryV1>;
  assertProtocolPreflight(denom: string): Promise<{
    circuit_config: ValidatedCircuitConfigV1;
    asset: NormalizedAssetRegistryEntryV1;
  }>;
  assertTransferProtocolConfig(denom: string): Promise<{
    circuit_config: ValidatedCircuitConfigV1;
    asset: NormalizedAssetRegistryEntryV1;
    audit_config: ValidatedAuditConfigV1;
    disclosure_config: ValidatedDisclosureConfigV1;
  }>;
  fetchTreeState(): Promise<object>;
  fetchCommitmentInfo(commitmentHex: Hex): Promise<object>;
  lookupMerklePath(commitmentHex: Hex): Promise<object>;
  fetchCommitmentPathsAtRoot(options: Parameters<ClairveilJS["fetchCommitmentPathsAtRoot"]>[0]): ReturnType<ClairveilJS["fetchCommitmentPathsAtRoot"]>;
  queryCommitmentPathsAtRoot(options: Parameters<ClairveilJS["queryCommitmentPathsAtRoot"]>[0]): ReturnType<ClairveilJS["queryCommitmentPathsAtRoot"]>;
  createCommitmentPathSnapshotProvider(options: Parameters<ClairveilJS["createCommitmentPathSnapshotProvider"]>[0]): ReturnType<ClairveilJS["createCommitmentPathSnapshotProvider"]>;
  buildRootSigningMessage(address: ClairAddress, pubKeyHex: Hex): string;
  verifySignerPubKey(address: ClairAddress, pubKeyHex: Hex): object;
  evmAccountIdentity(address: string): { evmAddress: string; address: ClairAddress; pubKeyHex: Hex };
  derivePrivacyAccount(input: BrowserWalletIdentityInput): DerivedPrivacyAccount;
  getBalances(address: ClairAddress): Promise<BrowserBalancesResponse>;
  waitForTx(txHash: Hex, options?: { attempts?: number; intervalMs?: number }): Promise<TxSearchResult | null>;
  waitForEvmTransaction(txHash: Hex, options: {
    /** Original SDK-prepared transaction; required for exact RPC identity and event verification. */
    privacyTransaction: EvmTransactionRequest;
    /** Actual EOA/executor that submitted the transaction. */
    sender: string;
    attempts?: number;
    intervalMs?: number;
  }): Promise<BrowserEvmTransactionWaitResult>;
  /**
   * Executes an allowlisted read request against the configured EVM JSON-RPC endpoint.
   * Prefer a higher-level browser-client method when one is available; this
   * method requires evmRpc, does not use the injected wallet provider, and must not be used to
   * request accounts, signatures, subscriptions, or transaction submission.
   */
  evmJsonRpc<TResult = unknown>(method: string, params?: readonly unknown[]): Promise<TResult>;
  /**
   * Confirms that the profile's configured read-only EVM RPC reports the
   * exact configured `evmChainId`. EVM profile prepare methods also validate
   * the connected signing wallet before they construct any prepared artifact.
   */
  assertEvmNetwork(): Promise<string | null>;
  /** Validate the connected EIP-1193 wallet against the active EVM profile. */
  assertEvmWalletNetwork(wallet: EvmNetworkWallet): Promise<string | null>;
  /** Resolve an injected local/WASM provider or the active profile's pinned endpoint. */
  depositProofProvider(provider?: DepositProofProvider | null): DepositProofProvider | null;
  evmNativeSendTransaction(input: { to: string; amount: CoinString }): BrowserEvmNativeSendTransaction;
  /** Submit an EVM transaction while preserving prepared reservation lifecycle state. */
  sendEvmTransaction(input: BrowserEvmTransactionBroadcastInput): Promise<Hex | string>;
  buildBankSendSignDoc(input: {
    from: ClairAddress;
    pubKeyHex: Hex;
    to: ClairAddress;
    amount: CoinString;
    gasLimit?: number;
    gas_limit?: number;
    feeAmount?: readonly CosmosFeeCoin[];
    fee_amount?: readonly CosmosFeeCoin[];
  }): Promise<SignDocBase64>;
  broadcastTxRawBytes(txRawBytes: Uint8Array, waitOptions?: ReservationBroadcastOptions): Promise<BroadcastSignedTxResult>;
  broadcastSignedTx(input: SignedTxBase64, waitOptions?: ReservationBroadcastOptions): Promise<BroadcastSignedTxResult>;
  signDirect(input: ReservationBroadcastOptions & {
    wallet: WalletAdapterLike;
    signDoc: SignDocBase64;
    waitOptions?: { attempts?: number; intervalMs?: number };
  }): Promise<SignedTxRawCheckpoint>;
  signDirectAndBroadcast(input: ReservationBroadcastOptions & {
    wallet: WalletAdapterLike;
    signDoc: SignDocBase64;
    waitOptions?: { attempts?: number; intervalMs?: number };
  }): Promise<BroadcastSignedTxResult>;
  prepareDeposit(input: TProfileTransport extends "evm" ? PrepareDefaultEvmProfileDepositInput : never): Promise<PreparedEvmDeposit>;
  prepareDeposit(input: TProfileTransport extends "evm" ? PrepareEvmDepositInput : TProfileTransport extends "cosmos" ? never : PrepareEvmDepositInput): Promise<PreparedEvmDeposit>;
  prepareDeposit(input: TProfileTransport extends "evm" ? never : PrepareCosmosDepositInput): Promise<PreparedCosmosDeposit>;
  prepareDeposit(input: PrepareDepositInputForProfile<TDefaultWalletType, TProfileTransport>): Promise<PreparedDepositForProfile<TProfileTransport>>;
  confirmDeposit(input: Parameters<ClairveilJS["confirmDeposit"]>[0]): ReturnType<ClairveilJS["confirmDeposit"]>;
  prepareTransfer(input: TProfileTransport extends "evm" ? PrepareDefaultEvmProfileTransferInput : never): Promise<PreparedEvmTransfer>;
  prepareTransfer(input: TProfileTransport extends "evm" ? PrepareEvmTransferInput : TProfileTransport extends "cosmos" ? never : PrepareEvmTransferInput): Promise<PreparedEvmTransfer>;
  prepareTransfer(input: TProfileTransport extends "evm" ? never : PrepareCosmosTransferInput): Promise<PreparedCosmosTransfer>;
  prepareTransfer(input: PrepareTransferInputForProfile<TProfileTransport>): Promise<PreparedTransferForProfile<TProfileTransport>>;
  prepareTransferBatch(input: TProfileTransport extends "evm"
    ? PrepareEvmTransferBatchInput | PrepareDefaultEvmProfileTransferBatchInput
    : TProfileTransport extends "cosmos" ? never : PrepareEvmTransferBatchInput): Promise<PreparedEvmTransferBatch>;
  prepareTransferBatch(input: TProfileTransport extends "evm" ? never : PrepareCosmosTransferBatchInput): Promise<PreparedCosmosTransferBatch>;
  prepareTransferBatch(input: PrepareTransferBatchInputForProfile<TDefaultWalletType, TProfileTransport>): Promise<PreparedTransferBatchForProfile<TProfileTransport>>;
  provePreparedBatchTransfer(input: Omit<Parameters<ClairveilJS["provePreparedBatchTransfer"]>[0], "proverAdapter"> & {
    proverAdapter?: Parameters<ClairveilJS["provePreparedBatchTransfer"]>[0]["proverAdapter"];
    prover_adapter?: Parameters<ClairveilJS["provePreparedBatchTransfer"]>[0]["proverAdapter"];
    address?: ClairAddress | string;
  }): ReturnType<ClairveilJS["provePreparedBatchTransfer"]>;
  finalizePreparedBatchTransfer(input: TProfileTransport extends "evm"
    ? FinalizeEvmPreparedBatchTransferInput | FinalizeDefaultEvmProfilePreparedBatchTransferInput
    : TProfileTransport extends "cosmos" ? never : FinalizeEvmPreparedBatchTransferInput): Promise<FinalizedEvmPreparedBatchTransfer>;
  finalizePreparedBatchTransfer(input: TProfileTransport extends "evm" ? never : FinalizePreparedBatchTransferInput): Promise<FinalizedCosmosPreparedBatchTransfer>;
  finalizePreparedBatchTransfer(
    input: FinalizePreparedBatchTransferInputForProfile<TDefaultWalletType, TProfileTransport>
  ): Promise<FinalizedPreparedBatchTransferForProfile<TProfileTransport>>;
  prepareWithdraw(input: TProfileTransport extends "evm" ? PrepareDefaultEvmProfileWithdrawInput : never): Promise<PreparedEvmWithdraw>;
  prepareWithdraw(input: TProfileTransport extends "evm" ? PrepareEvmWithdrawInput : TProfileTransport extends "cosmos" ? never : PrepareEvmWithdrawInput): Promise<PreparedEvmWithdraw>;
  prepareWithdraw(input: TProfileTransport extends "evm" ? never : PrepareCosmosWithdrawInput): Promise<PreparedCosmosWithdraw>;
  prepareWithdraw(input: PrepareWithdrawInputForProfile<TProfileTransport>): Promise<PreparedWithdrawForProfile<TProfileTransport>>;
  prepareRelayWithdraw(input: TProfileTransport extends "evm" ? PrepareDefaultEvmProfileRelayWithdrawInput : never): Promise<PreparedEvmRelayWithdraw>;
  prepareRelayWithdraw(input: TProfileTransport extends "evm" ? PrepareEvmRelayWithdrawInput : TProfileTransport extends "cosmos" ? never : PrepareEvmRelayWithdrawInput): Promise<PreparedEvmRelayWithdraw>;
  prepareRelayWithdraw(input: TProfileTransport extends "evm" ? never : PrepareCosmosRelayWithdrawInput): Promise<PreparedCosmosRelayWithdraw>;
  prepareRelayWithdraw(input: PrepareRelayWithdrawInputForProfile<TDefaultWalletType, TProfileTransport>): Promise<PreparedRelayWithdrawForProfile<TProfileTransport>>;
  buildRelayWithdrawMessageFromPayload(input: CreateRelayWithdrawSignDocInput): WithdrawMessage;
  createRelayWithdrawSignDoc(input: CreateRelayWithdrawSignDocInput): Promise<PreparedRelayWithdrawSignDoc>;
  scanWalletNotes(input: ScanWalletNotesInput): Promise<ScanWalletNotesResult>;
  checkNullifier(nullifierHex: Hex): Promise<object & { used?: boolean; Used?: boolean }>;
  checkNullifiers(nullifierHexes: readonly Hex[]): Promise<Map<Hex, boolean>>;
  decodeUserDisclosure(input: DecodeUserDisclosureInput): Promise<DisclosureReport>;
  decodeSelfViewDisclosure(input: DecodeSelfViewDisclosureInput): Promise<DisclosureReport>;
  decodeAuditDisclosure(input: DecodeAuditDisclosureInput): Promise<DisclosureReport>;
  decodeBatchUserDisclosure(input: Parameters<ClairveilJS["decodeBatchUserDisclosure"]>[0] & {
    walletType?: BrowserWalletType;
    wallet_type?: BrowserWalletType;
  }): ReturnType<ClairveilJS["decodeBatchUserDisclosure"]>;
  decodeBatchSelfViewDisclosure(input: Parameters<ClairveilJS["decodeBatchSelfViewDisclosure"]>[0] & {
    walletType?: BrowserWalletType;
    wallet_type?: BrowserWalletType;
  }): ReturnType<ClairveilJS["decodeBatchSelfViewDisclosure"]>;
  decodeBatchAuditDisclosure(input: Parameters<ClairveilJS["decodeBatchAuditDisclosure"]>[0]): ReturnType<ClairveilJS["decodeBatchAuditDisclosure"]>;
  txRawBytesBase64(input: SignedTxBase64): Base64;
}

export function createClairveilBrowserClient<TWalletType extends BrowserWalletType>(
  options: ClairveilBrowserClientOptions & { profile: BrowserWalletProfile & { transport: TWalletType } }
): ClairveilBrowserClient<TWalletType, TWalletType>;
export function createClairveilBrowserClient(options?: ClairveilBrowserClientOptions): ClairveilBrowserClient;
export function validateBrowserWalletProfile<TProfile extends BrowserWalletProfile>(profile: TProfile): TProfile;
export function validateClairveilWebClientConfig(config: ClairveilWebClientConfig | object): ValidatedClairveilWebClientConfig;
export function resolveActiveClairveilWebClientProfile(config: ClairveilWebClientConfig | object): BrowserWalletProfile;
export function buildRootSigningMessage(address: ClairAddress, pubKeyHex: Hex): string;
export function evmAddressToBech32(address: string, prefix: string): string;
export function verifySignerPubKey(address: ClairAddress, pubKeyHex: Hex): object;

export type BrowserDappProfile = BrowserWalletProfile;
export type ClairveilBrowserDappClientOptions = ClairveilBrowserClientOptions;
export { ClairveilBrowserClient as ClairveilBrowserDappClient };
export function createClairveilBrowserDappClient<TWalletType extends BrowserWalletType>(
  options: ClairveilBrowserClientOptions & { profile: BrowserWalletProfile & { transport: TWalletType } }
): ClairveilBrowserClient<TWalletType, TWalletType>;
export function createClairveilBrowserDappClient(options?: ClairveilBrowserClientOptions): ClairveilBrowserClient;
