import { validateWalletValue, snapshotJson } from '../wallet-api/index.js';
import { validateCosmosArtifact } from '../chain-wallet/verification.js';
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
export async function computeArtifactBinding({ operationId, networkProfileDigest, chainActorAccountId, artifact }) {
  const checked = validateWalletValue('ClairveilHandoffArtifact', artifact, { response: true });
  validateWalletValue('Handle', operationId);
  validateWalletValue('Hex32', networkProfileDigest);
  const { artifactBindingHash: _hash, chainActorHandle: _handle, ...publicArtifact } = checked;
  const value = snapshotJson({ schemaRevision: 'draft', operationId, networkProfileDigest, chainActorAccountId, artifact: publicArtifact }, { response: true });
  const bytes = new TextEncoder().encode('clairveil-custody/artifact/v1\n' + canonical(value));
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(byte => byte.toString(16).padStart(2, '0')).join('');
}
export async function validateSubmissionArtifact({ operation, actor, networkProfileDigest, chainActorAccountId, validateEffect }) {
  const artifact = validateWalletValue('ClairveilHandoffArtifact', operation.publicArtifact, { response: true });
  const expectedAccount = actor.namespace === 'cosmos' ? `cosmos:${actor.chainId}:${actor.address}` : `eip155:${BigInt(actor.chainId)}:${actor.address}`;
  if (chainActorAccountId !== expectedAccount) throw new Error('artifact actor account mismatch');
  if (await computeArtifactBinding({ operationId: operation.operationId, networkProfileDigest, chainActorAccountId, artifact }) !== artifact.artifactBindingHash) throw new Error('artifact binding mismatch');
  if (artifact.transport === 'cosmos') {
    if (actor.namespace !== 'cosmos') throw new Error('artifact actor namespace mismatch');
    validateCosmosArtifact(artifact, actor, operation.kind);
  } else {
    if (actor.namespace !== 'eip155') throw new Error('artifact actor namespace mismatch');
    const tx = artifact.transaction;
    if (artifact.chainId !== `eip155:${BigInt(actor.chainId)}` || tx.from !== actor.address || BigInt(tx.chainId) !== BigInt(actor.chainId) || BigInt(tx.gas) === 0n || BigInt(tx.maxPriorityFeePerGas) > BigInt(tx.maxFeePerGas)) throw new Error('EVM actor, network or fee mismatch');
  }
  // The selected profile must decode its chain ABI/messages and compare the approved effect.
  // No generic signature/selector-only fallback admits an unknown network or action.
  if (typeof validateEffect !== 'function' || await validateEffect({ operation, artifact, actor, networkProfileDigest }) !== true) throw new Error('artifact effect is not verified');
  return artifact;
}
