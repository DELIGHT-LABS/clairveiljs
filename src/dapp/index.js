import { methodRegistry } from '../wallet-api/index.js';
import { createSubmissionCoordinator } from './submission.js';
export function createClairveilDappClient({ custodyProvider, chainWallet, validateArtifact, broadcastCosmos } = {}) {
  if (typeof custodyProvider?.request !== 'function') throw new TypeError('custody provider is required');
  const methods = Object.fromEntries(Object.keys(methodRegistry).map(method => [method.slice('clairveil_'.length), params => custodyProvider.request({ method, params })]));
  if (chainWallet) methods.submit = createSubmissionCoordinator({ custodyProvider, chainWallet, validateArtifact, broadcastCosmos });
  return Object.freeze(methods);
}
export { computeArtifactBinding } from "./artifact.js";
export { createArtifactVerifier } from "./profile.js";
