import { validateWalletValue, validateWalletResult, snapshotJson } from '../wallet-api/index.js';
import { signDocFromArtifact, verifyCosmosSignResponse } from '../chain-wallet/verification.js';
import { validateSubmissionArtifact } from './artifact.js';

const attachmentState = new WeakMap();
export function createSubmissionCoordinator({ custodyProvider, chainWallet, validateArtifact, broadcastCosmos }) {
  if (typeof chainWallet.getActor !== 'function' || typeof validateArtifact !== 'function') throw new TypeError('chain wallet and profile artifact verifier are required');
  if (!attachmentState.has(custodyProvider)) attachmentState.set(custodyProvider, { consumed: new Set(), inFlight: new Set() });
  const { consumed, inFlight } = attachmentState.get(custodyProvider);
  return async function submit(input) {
    const { operation, actor, context, idempotencyKey, networkProfileDigest, chainActorAccountId } = snapshotJson(input, { response: true });
    const checked = validateWalletValue('ClairveilOperation', operation, { response: true });
    if (checked.state !== 'awaiting_chain_signature' || !checked.publicArtifact || checked.accessMode === 'recovery-only') throw new Error('operation is not ready for wallet invocation');
    const epoch = custodyProvider.generation;
    const requestKey = `${epoch}:${context.sessionHandle}:${checked.operationId}`;
    if (inFlight.has(requestKey)) throw new Error('submission already in progress');
    inFlight.add(requestKey);
    let attempt;
    let invoked = false;
    const current = () => { if (custodyProvider.generation !== epoch) throw new Error('custody attachment changed'); };
    async function walletMatches() {
      const actual = await chainWallet.getActor(); current();
      if (['namespace','chainId','address','pubKeyHex'].some(key => actual[key] !== actor[key])) throw new Error('ordinary wallet actor changed');
    }
    async function report(outcome, transactionHash) {
      current();
      return custodyProvider.request({ method: 'clairveil_recordSubmission', params: {
        ...context, protocolVersion: '1', schemaRevision: 'draft', binding: 'clairveil-draft',
        idempotencyKey, operationId: checked.operationId, attemptId: attempt.attemptId, outcome,
        ...(transactionHash ? { transactionHash } : {})
      } });
    }
    try {
      current();
      const artifact = await validateSubmissionArtifact({ operation: checked, actor, networkProfileDigest, chainActorAccountId, validateEffect: validateArtifact });
      current(); await walletMatches();
      if (artifact.transport === 'cosmos' && (typeof chainWallet.signDirect !== 'function' || typeof broadcastCosmos !== 'function')) throw new Error('Cosmos signing/broadcast unavailable');
      if (artifact.transport === 'evm' && typeof chainWallet.sendTransaction !== 'function') throw new Error('EVM submission unavailable');
      const beginParams = {
        ...context, protocolVersion: '1', schemaRevision: 'draft', binding: 'clairveil-draft',
        idempotencyKey, operationId: checked.operationId, chainActorHandle: artifact.chainActorHandle,
        expectedStatusRevision: checked.statusRevision, artifactBindingHash: artifact.artifactBindingHash
      };
      attempt = validateWalletResult('clairveil_beginSubmission', await custodyProvider.request({ method: 'clairveil_beginSubmission', params: beginParams }), beginParams);
      current();
      if (!attempt.invokeWallet) return { attempt, invoked: false };
      const key = `${epoch}:${attempt.attemptId}`;
      if (consumed.has(key)) return { attempt, invoked: false };
      if (consumed.size >= 4096) throw new Error('submission attachment limit reached');
      consumed.add(key); // Consumed before another await, including account discovery.
      await walletMatches(); current();
      let hash;
      invoked = true;
      if (artifact.transport === 'evm') hash = await chainWallet.sendTransaction(artifact.transaction, actor);
      else {
        const document = signDocFromArtifact(artifact);
        const response = await chainWallet.signDirect(document, actor);
        const bytes = verifyCosmosSignResponse(document, response, actor);
        current(); await walletMatches();
        hash = await broadcastCosmos(bytes, actor);
      }
      if (typeof hash !== 'string' || !(artifact.transport === 'evm' ? /^0x[0-9a-fA-F]{64}$/ : /^[0-9a-fA-F]{64}$/).test(hash)) throw new Error('invalid broadcast hash');
      const result = await report('reported_submitted', hash.toLowerCase());
      return { attempt, invoked, result };
    } catch {
      // A rejected or lost wallet response is not proof of non-submission.
      if (attempt && custodyProvider.generation === epoch) { try { await report('unknown'); } catch {} }
      throw new Error('Submission unresolved; reconcile before another attempt');
    } finally { inFlight.delete(requestKey); }
  };
}
