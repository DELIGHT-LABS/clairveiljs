import type { WalletPrivacyIdentity, PublicPrivacyIdentity } from './identity.js';
import type { ChainActor } from '../chain-wallet/index.js';
import type {
  ClairveilJS, PreparedDeposit, PreparedTransfer, PreparedWithdraw,
  PreparedWithdrawWithExecution, SignDocBase64
} from '../transport/cosmos-client.js';
import type { ClairveilEvmClient } from '../transport/evm.js';
import type { DepositMaterial } from '../core/note.js';
type StripLegacy<T> = Omit<T,
  'wallet' | 'material' | 'privacyIdentity' | 'chainActor' | 'executionBuilder'
  | 'proverAdapter' | 'reservationManager' | 'reservation_manager'
>;
type KernelOperation<T> = StripLegacy<T> & {
  operationId: string;
  actor: ChainActor;
  transactionOptions?: Record<string, string>;
  prover?: unknown
};
export type KernelPrepared<T> = T extends unknown
  ? Omit<T, 'privacyAccount' | 'signDoc'> & {
    privacyAccount: PublicPrivacyIdentity;
    signDoc?: SignDocBase64;
    execution?: object
  }
  : never;

export interface WalletKernel {
  getPublicIdentity(): PublicPrivacyIdentity;

  scan(input: StripLegacy<Parameters<ClairveilJS['scanWalletNotes']>[0]> & {
    operationId: string
  }): Promise<
    Omit<Awaited<ReturnType<ClairveilJS['scanWalletNotes']>>, 'privacyAccount'>
    & { privacyAccount: PublicPrivacyIdentity }
  >;

  proveDeposit(input: {
    operationId: string;
    actor: ChainActor;
    amount: string;
    assetDenom?: string;
    signal?: AbortSignal;
    prover: (payload: any, options?: { signal?: AbortSignal }) => Promise<any>
  }): Promise<{ depositMaterial: DepositMaterial } & (
    { proofHex: string; proof?: never }
    | { proof: Uint8Array | string; proofHex?: never }
  )>;

  prepareDeposit(
    input: KernelOperation<Parameters<ClairveilJS['prepareDeposit']>[0]>
  ): Promise<KernelPrepared<PreparedDeposit>>;
  prepareTransfer(
    input: KernelOperation<Parameters<ClairveilJS['prepareTransfer']>[0]>
  ): Promise<KernelPrepared<PreparedTransfer>>;
  prepareWithdraw(
    input: KernelOperation<Parameters<ClairveilJS['prepareWithdraw']>[0]>
  ): Promise<KernelPrepared<PreparedWithdraw | PreparedWithdrawWithExecution>>;

  dispose(): void;
}

export function createWalletKernel(input: {
  identity: WalletPrivacyIdentity;
  client: ClairveilJS;
  evmClient?: ClairveilEvmClient;
  evmChainId?: string;
  reservationManager?: object;
  checkpoint: (record: {
    operationId: string;
    kind: string;
    payload: unknown
  }) => Promise<void>;
  assertAuthority: (context: { operationId: string }) => void | Promise<void>
}): WalletKernel;
