import {
  invalidWalletData,
  mapWalletError,
  snapshotJson,
  validateWalletParams,
  validateWalletResult,
  WalletRpcError
} from '../wallet-api/index.js';

const discoveryMethod = 'clairveil_getCapabilities';
const controlMethods = new Set(['clairveil_disconnect', 'clairveil_cancelOperation']);
const limits = Object.freeze({ pending: 16, controlPending: 18, trackedOperations: 256, pollIntervalMs: 1000 });

function unavailable() {
  return new WalletRpcError({
    code: 4103,
    message: 'UNAUTHORIZED',
    data: { label: 'UNAUTHORIZED', retryable: false }
  });
}

function unsupported() {
  return new WalletRpcError({
    code: 4102,
    message: 'UNSUPPORTED_CAPABILITY',
    data: { label: 'UNSUPPORTED_CAPABILITY', retryable: false }
  });
}

function limited() {
  return new WalletRpcError({
    code: 4112,
    message: 'RESOURCE_LIMIT',
    data: { label: 'RESOURCE_LIMIT', retryable: true, retryAfterMs: 1000 }
  });
}

function captureRequest(input) {
  let request;
  try {
    request = snapshotJson(input);
    if (Object.keys(request).length !== 2 || !Object.hasOwn(request, 'method') || !Object.hasOwn(request, 'params')) {
      throw new Error('invalid provider request');
    }
  } catch {
    throw invalidWalletData();
  }
  return { method: request.method, params: validateWalletParams(request.method, request.params) };
}

function operationKey(params, operationId = params.operationId ?? '') {
  return `${params.sessionHandle ?? 'bootstrap'}:${operationId}`;
}

export function createCustodyProvider({ transport, subscribeInvalidation, timeoutMs = 30000, clock = Date.now } = {}) {
  if (typeof transport?.request !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000) {
    throw new TypeError('explicit transport and bounded timeout are required');
  }

  let generation = 0;
  let pending = 0;
  let capabilities;
  let disposed = false;
  const revisions = new Map();
  const polls = new Map();
  const listeners = new Set();

  function invalidate() {
    generation++;
    capabilities = undefined;
    revisions.clear();
    polls.clear();
    for (const listener of listeners) {
      try { listener(); } catch { /* One observer cannot prevent revocation. */ }
    }
  }

  function assertCurrent(epoch) {
    if (epoch !== generation) throw unavailable();
  }

  function admit({ method, params }) {
    if (method !== discoveryMethod) {
      if (!capabilities) throw unavailable();
      if (!capabilities.methods.includes(method)) throw unsupported();
    }
    const pendingLimit = controlMethods.has(method) ? limits.controlPending : limits.pending;
    if (pending >= pendingLimit) throw limited();
    if (method !== 'clairveil_getOperation') return;

    const key = operationKey(params);
    const now = clock();
    if (polls.has(key) && now - polls.get(key) < limits.pollIntervalMs) throw limited();
    if (!polls.has(key) && polls.size >= limits.trackedOperations) throw limited();
    polls.set(key, now);
  }

  function acceptResult({ method, params }, raw) {
    const result = validateWalletResult(method, raw, params);
    if (method === discoveryMethod) {
      if (capabilities && JSON.stringify(capabilities) !== JSON.stringify(result)) invalidate();
      capabilities = result;
    }
    if (result.operationId && result.statusRevision !== undefined) {
      const key = operationKey(params, result.operationId);
      const revision = BigInt(result.statusRevision);
      const previous = revisions.get(key);
      if (previous !== undefined && revision < previous) throw invalidWalletData(true);
      if (!revisions.has(key) && revisions.size >= limits.trackedOperations) throw limited();
      revisions.set(key, revision);
    }
    if (method === 'clairveil_disconnect') invalidate();
    return result;
  }

  const unsubscribe = subscribeInvalidation?.(invalidate);
  return Object.freeze({
    get generation() { return generation; },
    invalidate,
    onInvalidation(listener) {
      if (typeof listener !== 'function') throw new TypeError('listener required');
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    dispose() {
      disposed = true;
      invalidate();
      unsubscribe?.();
      listeners.clear();
    },
    async request(input) {
      if (disposed) throw unavailable();
      const request = captureRequest(input);
      admit(request);
      const epoch = generation;
      pending++;
      let timer;
      try {
        const raw = await Promise.race([
          Promise.resolve().then(() => {
            assertCurrent(epoch);
            // Keep response correlation independent of transport-side envelope changes.
            return transport.request({ ...request });
          }),
          new Promise((_, reject) => { timer = setTimeout(() => reject(limited()), timeoutMs); })
        ]);
        assertCurrent(epoch);
        return acceptResult(request, raw);
      } catch (error) {
        throw mapWalletError(request.method, error);
      } finally {
        clearTimeout(timer);
        pending--;
      }
    }
  });
}
