import { validateWalletValue, validateWalletResult, snapshotJson } from '../wallet-api/index.js';
import { signDocFromArtifact, verifyCosmosSignResponse } from '../chain-wallet/verification.js';
import { assertSameActor } from '../chain-wallet/actor.js';
import { validateSubmissionArtifact } from './artifact.js';

const attachmentState = new WeakMap();
const maximumConsumedAttempts = 4096;

function stateFor(provider) {
  if (!attachmentState.has(provider)) {
    attachmentState.set(provider, { consumed: new Set(), inFlight: new Set() });
  }
  return attachmentState.get(provider);
}

function assertWalletAvailable(artifact, chainWallet, broadcastCosmos) {
  if (artifact.transport === 'cosmos') {
    if (typeof chainWallet.signDirect !== 'function' || typeof broadcastCosmos !== 'function') {
      throw new Error('Cosmos signing/broadcast unavailable');
    }
  } else if (typeof chainWallet.sendTransaction !== 'function') {
    throw new Error('EVM submission unavailable');
  }
}

function transactionHash(transport, hash) {
  const pattern = transport === 'evm' ? /^0x[0-9a-fA-F]{64}$/ : /^[0-9a-fA-F]{64}$/;
  if (typeof hash !== 'string' || !pattern.test(hash)) throw new Error('invalid broadcast hash');
  return hash.toLowerCase();
}

export function createSubmissionCoordinator({ custodyProvider, chainWallet, validateArtifact, broadcastCosmos }) {
  if (typeof chainWallet.getActor !== 'function' || typeof validateArtifact !== 'function') {
    throw new TypeError('chain wallet and profile artifact verifier are required');
  }
  const { consumed, inFlight } = stateFor(custodyProvider);

  return async function submit(input) {
    const { operation, actor, context, idempotencyKey, networkProfileDigest, chainActorAccountId } = snapshotJson(input, { response: true });
    const checked = validateWalletValue('ClairveilOperation', operation, { response: true });
    if (checked.state !== 'awaiting_chain_signature' || !checked.publicArtifact || checked.accessMode === 'recovery-only') {
      throw new Error('operation is not ready for wallet invocation');
    }
    const epoch = custodyProvider.generation;
    const requestKey = `${epoch}:${context.sessionHandle}:${checked.operationId}`;
    if (inFlight.has(requestKey)) throw new Error('submission already in progress');
    inFlight.add(requestKey);

    let attempt;
    let invoked = false;
    const dispatchController = new AbortController();
    let unsubscribe;

    function assertCurrent() {
      if (custodyProvider.generation !== epoch) throw new Error('custody attachment changed');
    }

    async function assertWalletMatches() {
      const actual = await chainWallet.getActor();
      assertCurrent();
      assertSameActor(actor, actual);
    }

    function params(fields) {
      return {
        ...context,
        protocolVersion: '1',
        schemaRevision: 'draft',
        binding: 'clairveil-draft',
        idempotencyKey,
        operationId: checked.operationId,
        ...fields
      };
    }

    async function begin(artifact) {
      const request = params({
        chainActorHandle: artifact.chainActorHandle,
        expectedStatusRevision: checked.statusRevision,
        artifactBindingHash: artifact.artifactBindingHash
      });
      const response = await custodyProvider.request({ method: 'clairveil_beginSubmission', params: request });
      return validateWalletResult('clairveil_beginSubmission', response, request);
    }

    function consumeAttempt() {
      if (!attempt.invokeWallet) return false;
      const key = `${epoch}:${attempt.attemptId}`;
      if (consumed.has(key)) return false;
      if (consumed.size >= maximumConsumedAttempts) throw new Error('submission attachment limit reached');
      consumed.add(key); // Consume synchronously, before wallet discovery or dispatch can await.
      return true;
    }

    async function report(outcome, hash) {
      assertCurrent();
      return custodyProvider.request({
        method: 'clairveil_recordSubmission',
        params: params({ attemptId: attempt.attemptId, outcome, ...(hash ? { transactionHash: hash } : {}) })
      });
    }

    async function dispatch(artifact) {
      invoked = true;
      const options = { signal: dispatchController.signal };
      if (artifact.transport === 'evm') return chainWallet.sendTransaction(artifact.transaction, actor, options);

      // Keep the verification baseline private: custom adapters may mutate
      // their input object or its byte arrays while obtaining a signature.
      const expectedDocument = signDocFromArtifact(artifact);
      const response = await chainWallet.signDirect(signDocFromArtifact(artifact), actor, options);
      const bytes = verifyCosmosSignResponse(expectedDocument, response, actor);
      assertCurrent();
      await assertWalletMatches();
      assertCurrent();
      return broadcastCosmos(bytes, actor);
    }

    try {
      unsubscribe = custodyProvider.onInvalidation(() => dispatchController.abort());
      assertCurrent();
      const artifact = await validateSubmissionArtifact({
        operation: checked, actor, networkProfileDigest, chainActorAccountId, validateEffect: validateArtifact
      });
      assertCurrent();
      await assertWalletMatches();
      assertWalletAvailable(artifact, chainWallet, broadcastCosmos);

      attempt = await begin(artifact);
      assertCurrent();
      if (!consumeAttempt()) return { attempt, invoked: false };
      await assertWalletMatches();
      assertCurrent();

      const hash = transactionHash(artifact.transport, await dispatch(artifact));
      const result = await report('reported_submitted', hash);
      return { attempt, invoked, result };
    } catch {
      // A rejected or lost wallet response is not proof of non-submission.
      if (attempt && custodyProvider.generation === epoch) {
        try { await report('unknown'); } catch { /* Reconciliation owns unresolved reporting. */ }
      }
      throw new Error('Submission unresolved; reconcile before another attempt');
    } finally {
      unsubscribe?.();
      inFlight.delete(requestKey);
    }
  };
}
