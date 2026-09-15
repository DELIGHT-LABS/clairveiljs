import { assertSignerPubKey } from '../transport/cosmos-client.js';
import { evmTransactionBindingHash } from '../transport/evm.js';
import { createPrivacyIdentity } from './identity.js';
import { buildDepositProofRequestV1, validateDepositProofResponseV1 } from '../privacy/prover.js';
import { toBech32, fromHex } from '@cosmjs/encoding';

const forbiddenOverrides = new Set([
  'wallet', 'material', 'privacyIdentity', 'chainActor', 'rootSeed',
  'signatureBase64', 'executionBuilder', 'proverAdapter', 'reservation_manager'
]);
const spendProverMethods = ['proveTransfer', 'proveWithdraw'];
const evmAddressPattern = /^0x[0-9a-f]{40}$/;
const evmChainPattern = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;

function snapshotActor(proposed) {
  if (!proposed) return proposed;
  return Object.freeze({
    namespace: proposed.namespace,
    chainId: proposed.chainId,
    address: proposed.address,
    ...(proposed.namespace === 'cosmos' ? { pubKeyHex: proposed.pubKeyHex } : {})
  });
}

function creatorAddress(actor, prefix) {
  return actor.namespace === 'eip155' ? toBech32(prefix, fromHex(actor.address.slice(2))) : actor.address;
}

function depositRequest(actor, material, signal) {
  // Preserve the two existing provider contracts; do not silently switch profiles.
  if (actor.namespace === 'cosmos') return buildDepositProofRequestV1({ material });
  return {
    material,
    amount: material.amount,
    note: material.note,
    noteJson: material.note_json,
    note_json: material.note_json,
    noteCommitmentHex: material.note_commitment_hex,
    note_commitment_hex: material.note_commitment_hex,
    signal
  };
}

function depositProof(actor, material, response) {
  if (actor.namespace === 'cosmos') {
    const request = buildDepositProofRequestV1({ material });
    return { proofHex: validateDepositProofResponseV1(request, response).proof.proof_hex };
  }
  const proofHex = response?.proofHex ?? response?.proof_hex ?? response?.proof?.proof_hex;
  const proof = response?.depositProof ?? response?.deposit_proof ?? response?.proof;
  if (proofHex) {
    if (typeof proofHex !== 'string') throw new Error('invalid EVM deposit proof response');
    return { proofHex };
  }
  if (!(proof instanceof Uint8Array) && typeof proof !== 'string') {
    throw new Error('invalid EVM deposit proof response');
  }
  return { proof };
}

/** Trusted host hooks run here, never in the public provider/client graph. */
export function createWalletKernel({ identity: inputIdentity, client, evmClient, evmChainId, checkpoint, assertAuthority, reservationManager } = {}) {
  if (!inputIdentity || !client || typeof checkpoint !== 'function' || typeof assertAuthority !== 'function') {
    throw new TypeError('identity, private client, checkpoint and authority hooks are required');
  }
  const identity = createPrivacyIdentity({ rootSeed: inputIdentity.rootSeed, shieldedPrefix: client.shieldedPrefix });
  if (Object.keys(identity.publicIdentity).some(key => identity.publicIdentity[key] !== inputIdentity.publicIdentity?.[key])) {
    throw new Error('identity mismatch');
  }
  let disposed = false;

  function assertActive() {
    if (disposed) throw new Error('wallet kernel is disposed');
  }

  // Stay synchronous: disposal can run after authorize() and before result return.
  function activeResult(result) {
    assertActive();
    return result;
  }

  function assertActor(actor, transactionOptions) {
    if (!actor) return;
    if (actor.namespace === 'cosmos') {
      if (actor.chainId !== client.chainId) throw new Error('Cosmos actor/profile mismatch');
      assertSignerPubKey(actor.address, actor.pubKeyHex, client.accountPrefix);
      return;
    }
    if (actor.namespace !== 'eip155') throw new Error('unsupported actor namespace');
    if (!evmAddressPattern.test(actor.address) || !evmChainPattern.test(actor.chainId)
      || !evmClient || evmChainId === undefined || BigInt(actor.chainId) !== BigInt(evmChainId)) {
      throw new Error('EVM actor/profile mismatch');
    }
    if ((transactionOptions?.from !== undefined && transactionOptions.from !== actor.address)
      || (transactionOptions?.chainId !== undefined && BigInt(transactionOptions.chainId) !== BigInt(actor.chainId))) {
      throw new Error('EVM transaction options/actor mismatch');
    }
  }

  function captureOperation(input, requiresActor = true) {
    assertActive();
    if (!input || typeof input !== 'object' || typeof input.operationId !== 'string' || !input.operationId) {
      throw new Error('operationId is required');
    }
    for (const name of forbiddenOverrides) {
      if (Object.hasOwn(input, name)) throw new Error(`kernel input cannot override ${name}`);
    }
    const { actor: proposed, operationId, prover, transactionOptions, ...options } = input;
    const actor = snapshotActor(proposed);
    if (requiresActor && !actor) throw new Error('transaction actor is required');
    assertActor(actor, transactionOptions);
    return { operationId, actor, prover, transactionOptions: transactionOptions && { ...transactionOptions }, options };
  }

  async function authorize(operationId) {
    assertActive();
    await assertAuthority({ operationId });
    assertActive();
  }

  function checkpointRequest(operationId, kind, payload) {
    return checkpoint({ operationId, kind, payload });
  }

  function checkedProver(prover, operationId) {
    const guarded = {};
    for (const method of spendProverMethods) {
      if (typeof prover?.[method] !== 'function') continue;
      guarded[method] = async (payload, options) => {
        await authorize(operationId);
        await checkpointRequest(operationId, method, payload);
        await authorize(operationId);
        // authorize() adds an await boundary; disposal can run before we resume.
        // Keep this final check and the actual prover invocation synchronous.
        assertActive();
        return prover[method](payload, options);
      };
    }
    return guarded;
  }

  function createExecutionBuilder(kind, actor, transactionOptions, options) {
    if (actor?.namespace !== 'eip155') return undefined;
    return async input => {
      assertActive();
      const built = await evmClient[`build${kind}Transaction`]({
        ...input,
        accountPrefix: client.accountPrefix,
        chainNowUnix: options.chainNowUnix ?? options.chain_now_unix,
        expiresAtUnix: options.expiresAtUnix ?? options.expires_at_unix,
        transactionOptions: { ...transactionOptions, from: actor.address, chainId: actor.chainId },
        ...(kind === 'Withdraw' ? { evmRecipient: options.recipient } : {})
      });
      if ((built.transaction.from !== undefined && built.transaction.from !== actor.address)
        || (built.transaction.chainId !== undefined && BigInt(built.transaction.chainId) !== BigInt(actor.chainId))) {
        throw new Error('EVM builder returned a different actor or chain');
      }
      const transaction = { ...built.transaction, from: actor.address, chainId: actor.chainId };
      return { ...built, transaction, txBytesHash: evmTransactionBindingHash(transaction), executionTransport: 'evm' };
    };
  }

  async function prepare(kind, input) {
    const { operationId, actor, prover, transactionOptions, options } = captureOperation(input);
    await authorize(operationId);
    if (kind !== 'Deposit' && !reservationManager) throw new Error('spend preparation requires a reservation manager');
    const executionBuilder = createExecutionBuilder(kind, actor, transactionOptions, { ...options });
    if (kind === 'Withdraw' && actor.namespace === 'eip155' && evmAddressPattern.test(options.recipient)) {
      options.recipient = toBech32(client.accountPrefix, fromHex(options.recipient.slice(2)));
    }
    const result = await client[`prepare${kind}`]({
      ...options,
      privacyIdentity: identity,
      chainActor: actor,
      executionBuilder,
      reservationManager,
      proverAdapter: checkedProver(prover, operationId)
    });
    await authorize(operationId);
    return activeResult(result);
  }

  async function scan(input) {
    const { operationId, options } = captureOperation(input, false);
    await authorize(operationId);
    const result = await client.scanWalletNotes({ ...options, privacyIdentity: identity });
    await authorize(operationId);
    return activeResult(result);
  }

  async function proveDeposit(input) {
    const { operationId, actor, prover, options } = captureOperation(input);
    await authorize(operationId);
    const depositInput = {
      rootSeed: identity.rootSeed,
      creator: creatorAddress(actor, client.accountPrefix),
      amount: options.amount,
      assetDenom: options.assetDenom
    };
    await client.assertProtocolPreflight(options.assetDenom ?? client.defaultDenom);
    const material = client.buildDepositMaterial(depositInput);
    client.validateDepositMaterial({ depositMaterial: material, ...depositInput });
    if (typeof prover !== 'function') throw new Error('explicit deposit prover is required');

    const payload = depositRequest(actor, material, options.signal);
    const { signal: _signal, ...checkpointPayload } = payload;
    await checkpointRequest(operationId, 'proveDeposit', checkpointPayload);
    await authorize(operationId);
    assertActive(); // No await between the final disposal check and witness export.
    const response = await prover(payload, { signal: options.signal });
    const result = { depositMaterial: material, ...depositProof(actor, material, response) };
    await authorize(operationId);
    return activeResult(result);
  }

  return Object.freeze({
    getPublicIdentity() { assertActive(); return identity.publicIdentity; },
    scan,
    proveDeposit,
    prepareDeposit: input => prepare('Deposit', input),
    prepareTransfer: input => prepare('Transfer', input),
    prepareWithdraw: input => prepare('Withdraw', input),
    dispose() {
      disposed = true;
      identity.rootSeed.fill(0);
      for (const keys of [identity.spend, identity.view, identity.disclosure]) keys.seed?.fill(0);
    }
  });
}
