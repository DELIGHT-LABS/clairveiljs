import * as validators from './generated/validators.js';
import { schemaDigest, methodRegistry, contractRegistry } from './generated/registry.js';
import { snapshotJson, parseWalletJson, freezeJson } from './json.js';
freezeJson(methodRegistry); freezeJson(contractRegistry);
export { schemaDigest, methodRegistry, contractRegistry, snapshotJson, parseWalletJson };
export class WalletRpcError extends Error {
  constructor(error) {
    super(error.message);
    this.name = 'WalletRpcError';
    this.code = error.code;
    this.rpcError = freezeJson(error);
  }
}
export function invalidWalletData(response = false) {
  return new WalletRpcError({ code: response ? -32603 : -32602, message: response ? 'Internal error' : 'Invalid params' });
}
export function validateWalletValue(definition, input, { response = false } = {}) {
  let value;
  try {
    value = snapshotJson(input, { response });
    const name = definition.replace(/^#\/\$defs\//, '').replaceAll('-', 'Minus');
    if (!Object.hasOwn(validators, name) || !validators[name](value)) throw new Error('Invalid wallet DTO');
  } catch { throw invalidWalletData(response); }
  return value;
}
export function validateWalletParams(method, params) {
  if (!Object.hasOwn(methodRegistry, method)) throw new WalletRpcError({ code: -32601, message: 'Method not found' });
  let value;
  // Bound and copy the input before inspecting versions; never invoke accessors.
  try { value = snapshotJson(params); } catch { throw invalidWalletData(); }
  if ((typeof value?.protocolVersion === 'string' && value.protocolVersion !== '1')
    || (method !== 'clairveil_getCapabilities' && typeof value?.schemaRevision === 'string' && value.schemaRevision !== 'draft')) {
    throw new WalletRpcError({
      code: 4101,
      message: 'UNSUPPORTED_VERSION',
      data: { label: 'UNSUPPORTED_VERSION', retryable: false }
    });
  }
  return validateWalletValue(methodRegistry[method].params, value);
}
export function validateWalletResult(method, result, params) {
  if (!Object.hasOwn(methodRegistry, method)) throw invalidWalletData(true);
  const value = validateWalletValue(methodRegistry[method].result, result, { response: true });
  if (method === 'clairveil_getCapabilities' && value.schemaDigest !== schemaDigest) throw invalidWalletData(true);
  for (const key of ['operationId', 'accountHandle', 'networkHandle', 'attemptId']) {
    if (params?.[key] !== undefined && value[key] !== undefined && params[key] !== value[key]) throw invalidWalletData(true);
  }
  if (method === 'clairveil_getBalances' && params?.protocol?.assets) {
    const requested = new Set(params.protocol.assets);
    const balances = value.rows;
    if (Array.isArray(balances) && (balances.length !== requested.size || new Set(balances.map(row => row.assetDenom)).size !== requested.size || balances.some(row => !requested.has(row.assetDenom)))) throw invalidWalletData(true);
  }
  return value;
}
export function mapWalletError(method, input) {
  try {
    const value = input instanceof WalletRpcError ? input.rpcError : input;
    return new WalletRpcError(validateWalletValue(methodRegistry[method].error, value, { response: true }));
  } catch { return invalidWalletData(true); }
}
