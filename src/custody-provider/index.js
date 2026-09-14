import { validateWalletParams, validateWalletResult, validateWalletValue, mapWalletError, invalidWalletData, WalletRpcError, methodRegistry, snapshotJson, parseWalletJson } from '../wallet-api/index.js';

function unavailable() { return new WalletRpcError({ code: 4103, message: 'UNAUTHORIZED', data: { label: 'UNAUTHORIZED', retryable: false } }); }
function limited() { return new WalletRpcError({ code: 4112, message: 'RESOURCE_LIMIT', data: { label: 'RESOURCE_LIMIT', retryable: true, retryAfterMs: 1000 } }); }
export function createCustodyProvider({ transport, subscribeInvalidation, timeoutMs = 30000, clock = Date.now } = {}) {
  if (typeof transport?.request !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000) throw new TypeError('explicit transport and bounded timeout are required');
  let generation = 0, pending = 0, capabilities, disposed = false;
  const revisions = new Map(), polls = new Map();
  const listeners = new Set();
  function invalidate() {
    generation++; capabilities = undefined; revisions.clear(); polls.clear();
    for (const listener of listeners) { try { listener(); } catch {} }
  }
  const unsubscribe = subscribeInvalidation?.(invalidate);
  return Object.freeze({
    get generation() { return generation; },
    invalidate,
    onInvalidation(listener) { if (typeof listener !== 'function') throw new TypeError('listener required'); listeners.add(listener); return () => listeners.delete(listener); },
    dispose() { disposed = true; invalidate(); unsubscribe?.(); listeners.clear(); },
    async request(input) {
      if (disposed) throw unavailable();
      let method, params;
      try {
        const value = snapshotJson(input);
        if (Object.keys(value).length !== 2 || !Object.hasOwn(value, 'method') || !Object.hasOwn(value, 'params')) throw new Error('invalid provider request');
        ({ method, params } = value);
      } catch { throw invalidWalletData(); }
      const captured = validateWalletParams(method, params);
      if (method !== 'clairveil_getCapabilities' && (!capabilities || !capabilities.methods.includes(method))) throw unavailable();
      const control = ['clairveil_disconnect', 'clairveil_cancelOperation'].includes(method);
      if (pending >= (control ? 18 : 16)) throw limited();
      const pollKey = `${captured.sessionHandle ?? 'bootstrap'}:${captured.operationId ?? ''}`;
      if (method === 'clairveil_getOperation') {
        const now = clock();
        if (polls.has(pollKey) && now - polls.get(pollKey) < 1000) throw limited();
        if (!polls.has(pollKey) && polls.size >= 256) throw limited();
        polls.set(pollKey, now);
      }
      const epoch = generation; pending++;
      let timer;
      try {
        const raw = await Promise.race([
          Promise.resolve().then(() => { if (epoch !== generation) throw unavailable(); return transport.request({ method, params: captured }); }),
          new Promise((_, reject) => { timer = setTimeout(() => reject(limited()), timeoutMs); })
        ]);
        if (epoch !== generation) throw unavailable();
        const result = validateWalletResult(method, raw, captured);
        if (method === 'clairveil_getCapabilities') {
          if (capabilities && JSON.stringify(capabilities) !== JSON.stringify(result)) invalidate();
          capabilities = result;
        }
        if (result.operationId && result.statusRevision !== undefined) {
          const key = `${captured.sessionHandle ?? 'bootstrap'}:${result.operationId}`;
          const previous = revisions.get(key);
          if (previous !== undefined && BigInt(result.statusRevision) < previous) throw invalidWalletData(true);
          if (!revisions.has(key) && revisions.size >= 256) throw limited();
          revisions.set(key, BigInt(result.statusRevision));
        }
        if (method === 'clairveil_disconnect') invalidate();
        return result;
      } catch (error) { throw mapWalletError(method, error); }
      finally { clearTimeout(timer); pending--; }
    }
  });
}

/** The host-supplied exchange owns origin/document authentication; this is only framing. */
export function createDirectBridgeTransport({ exchange } = {}) {
  if (typeof exchange !== 'function') throw new TypeError('bridge exchange is required');
  return Object.freeze({ async request({ method, params }) {
    const captured = validateWalletParams(method, params);
    const id = [...crypto.getRandomValues(new Uint8Array(16))].map(byte => byte.toString(16).padStart(2, '0')).join('');
    const request = snapshotJson({ jsonrpc: '2.0', id, method, params: captured });
    const raw = await exchange(request);
    const response = validateWalletValue(methodRegistry[method].response, (typeof raw === 'string' || raw instanceof Uint8Array) ? parseWalletJson(raw, { response: true }) : raw, { response: true });
    if (response.id !== id) throw invalidWalletData(true);
    if (response.error) throw mapWalletError(method, response.error);
    return validateWalletResult(method, response.result, captured);
  } });
}
