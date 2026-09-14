import { assertSignerPubKey } from '../transport/cosmos-client.js';
import { evmTransactionBindingHash } from '../transport/evm.js';
import { createPrivacyIdentity } from './identity.js';
import { buildDepositProofRequestV1, validateDepositProofResponseV1 } from '../privacy/prover.js';
import { toBech32, fromHex } from '@cosmjs/encoding';

/** Trusted host hooks run here, never in the public provider/client graph. */
export function createWalletKernel({ identity: inputIdentity, client, evmClient, evmChainId, checkpoint, assertAuthority, reservationManager } = {}) {
  if (!inputIdentity || !client || typeof checkpoint !== 'function' || typeof assertAuthority !== 'function') throw new TypeError('identity, private client, checkpoint and authority hooks are required');
  const identity = createPrivacyIdentity({ rootSeed: inputIdentity.rootSeed, shieldedPrefix: client.shieldedPrefix });
  if (Object.keys(identity.publicIdentity).some(key => identity.publicIdentity[key] !== inputIdentity.publicIdentity?.[key])) throw new Error('identity mismatch');
  let disposed = false;
  function active() { if (disposed) throw new Error('wallet kernel is disposed'); }
  function capture(input, transaction = true) {
    active();
    if (!input || typeof input !== 'object' || typeof input.operationId !== 'string' || !input.operationId) throw new Error('operationId is required');
    for (const name of ['wallet', 'material', 'privacyIdentity', 'chainActor', 'rootSeed', 'signatureBase64', 'executionBuilder', 'proverAdapter', 'reservation_manager']) {
      if (Object.hasOwn(input, name)) throw new Error(`kernel input cannot override ${name}`);
    }
    const { actor: proposed, operationId, prover, transactionOptions, ...options } = input;
    const actor = proposed && Object.freeze({ namespace: proposed.namespace, chainId: proposed.chainId, address: proposed.address, ...(proposed.namespace === 'cosmos' ? { pubKeyHex: proposed.pubKeyHex } : {}) });
    if (transaction && !actor) throw new Error('transaction actor is required');
    if (actor?.namespace === 'cosmos') {
      if (actor.chainId !== client.chainId) throw new Error('Cosmos actor/profile mismatch');
      assertSignerPubKey(actor.address, actor.pubKeyHex, client.accountPrefix);
    } else if (actor && actor.namespace !== 'eip155') throw new Error('unsupported actor namespace');
    if (actor?.namespace === 'eip155') {
      if (!/^0x[0-9a-f]{40}$/.test(actor.address) || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(actor.chainId) || !evmClient || evmChainId === undefined || BigInt(actor.chainId) !== BigInt(evmChainId)) throw new Error('EVM actor/profile mismatch');
      if ((transactionOptions?.from !== undefined && transactionOptions.from !== actor.address) || (transactionOptions?.chainId !== undefined && BigInt(transactionOptions.chainId) !== BigInt(actor.chainId))) throw new Error('EVM transaction options/actor mismatch');
    }
    return { operationId, actor, prover, transactionOptions: transactionOptions && { ...transactionOptions }, options };
  }
  async function authorize(operationId) { active(); await assertAuthority({ operationId }); active(); }
  function checkedProver(prover, operationId) {
    const result = {};
    for (const method of ['proveTransfer', 'proveWithdraw']) {
      if (typeof prover?.[method] === 'function') result[method] = async (payload, options) => {
        await authorize(operationId);
        await checkpoint({ operationId, kind: method, payload });
        await authorize(operationId);
        return prover[method](payload, options);
      };
    }
    return result;
  }
  function builder(kind, actor, transactionOptions, options) {
    if (actor?.namespace !== 'eip155') return undefined;
    return async input => {
      active();
      const build = evmClient[`build${kind}Transaction`].bind(evmClient);
      const built = await build({ ...input, accountPrefix: client.accountPrefix, chainNowUnix: options.chainNowUnix ?? options.chain_now_unix, expiresAtUnix: options.expiresAtUnix ?? options.expires_at_unix, transactionOptions: { ...transactionOptions, from: actor.address, chainId: actor.chainId }, ...(kind === 'Withdraw' ? { evmRecipient: options.recipient } : {}) });
      if ((built.transaction.from !== undefined && built.transaction.from !== actor.address) || (built.transaction.chainId !== undefined && BigInt(built.transaction.chainId) !== BigInt(actor.chainId))) throw new Error('EVM builder returned a different actor or chain');
      const transaction = { ...built.transaction, from: actor.address, chainId: actor.chainId };
      return { ...built, transaction, txBytesHash: evmTransactionBindingHash(transaction), executionTransport: 'evm' };
    };
  }
  async function prepare(kind, input) {
    const { operationId, actor, prover, transactionOptions, options } = capture(input);
    await authorize(operationId);
    if (kind !== 'Deposit' && !reservationManager) throw new Error('spend preparation requires a reservation manager');
    const executionBuilder = builder(kind, actor, transactionOptions, { ...options });
    if (kind === 'Withdraw' && actor.namespace === 'eip155' && /^0x[0-9a-f]{40}$/.test(options.recipient)) options.recipient = toBech32(client.accountPrefix, fromHex(options.recipient.slice(2)));
    const result = await client[`prepare${kind}`]({ ...options, privacyIdentity: identity, chainActor: actor, executionBuilder, reservationManager, proverAdapter: checkedProver(prover, operationId) });
    await authorize(operationId);
    return result;
  }
  return Object.freeze({
    getPublicIdentity() { active(); return identity.publicIdentity; },
    async scan(input) {
      const { operationId, options } = capture(input, false);
      await authorize(operationId);
      const result = await client.scanWalletNotes({ ...options, privacyIdentity: identity });
      await authorize(operationId);
      return result;
    },
    async proveDeposit(input) {
      const { operationId, actor, prover, options } = capture(input);
      await authorize(operationId);
      const creator = actor.namespace === 'eip155' ? toBech32(client.accountPrefix, fromHex(actor.address.slice(2))) : actor.address;
      await client.assertProtocolPreflight(options.assetDenom ?? client.defaultDenom);
      const material = client.buildDepositMaterial({ rootSeed: identity.rootSeed, creator, amount: options.amount, assetDenom: options.assetDenom });
      client.validateDepositMaterial({ depositMaterial: material, rootSeed: identity.rootSeed, creator, amount: options.amount, assetDenom: options.assetDenom });
      if (typeof prover !== 'function') throw new Error('explicit deposit prover is required');
      // Preserve the two existing provider contracts; do not silently switch profiles.
      const payload = actor.namespace === 'cosmos' ? buildDepositProofRequestV1({ material }) : {
        material, amount: material.amount, note: material.note, noteJson: material.note_json, note_json: material.note_json,
        noteCommitmentHex: material.note_commitment_hex, note_commitment_hex: material.note_commitment_hex, signal: options.signal
      };
      const { signal: _signal, ...checkpointPayload } = payload;
      await checkpoint({ operationId, kind: 'proveDeposit', payload: checkpointPayload });
      await authorize(operationId);
      const response = await prover(payload, { signal: options.signal });
      await authorize(operationId);
      if (actor.namespace === 'cosmos') return { depositMaterial: material, proofHex: validateDepositProofResponseV1(buildDepositProofRequestV1({ material }), response).proof.proof_hex };
      const proofHex = response?.proofHex ?? response?.proof_hex ?? response?.proof?.proof_hex;
      const proof = response?.depositProof ?? response?.deposit_proof ?? response?.proof;
      if (!proofHex && !(proof instanceof Uint8Array) && typeof proof !== 'string') throw new Error('invalid EVM deposit proof response');
      return { depositMaterial: material, ...(proofHex ? { proofHex } : { proof }) };
    },
    prepareDeposit: input => prepare('Deposit', input),
    prepareTransfer: input => prepare('Transfer', input),
    prepareWithdraw: input => prepare('Withdraw', input),
    dispose() { disposed = true; identity.rootSeed.fill(0); for (const keys of [identity.spend, identity.view, identity.disclosure]) keys.seed?.fill(0); }
  });
}
