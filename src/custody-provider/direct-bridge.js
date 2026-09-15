import {
  invalidWalletData,
  mapWalletError,
  methodRegistry,
  parseWalletJson,
  snapshotJson,
  validateWalletParams,
  validateWalletResult,
  validateWalletValue
} from '../wallet-api/index.js';

function requestId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

/** The host-supplied exchange owns origin/document authentication; this is only framing. */
export function createDirectBridgeTransport({ exchange } = {}) {
  if (typeof exchange !== 'function') throw new TypeError('bridge exchange is required');

  return Object.freeze({
    async request({ method, params }) {
      const captured = validateWalletParams(method, params);
      const id = requestId();
      const request = snapshotJson({ jsonrpc: '2.0', id, method, params: captured });
      const raw = await exchange(request);
      const decoded = typeof raw === 'string' || raw instanceof Uint8Array
        ? parseWalletJson(raw, { response: true })
        : raw;
      const response = validateWalletValue(methodRegistry[method].response, decoded, { response: true });

      if (response.id !== id) throw invalidWalletData(true);
      if (response.error) throw mapWalletError(method, response.error);
      return validateWalletResult(method, response.result, captured);
    }
  });
}
