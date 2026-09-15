import Long from "long";

export function snapshotSignDoc(value, chainId) {
  const { chainId: documentChainId, bodyBytes, authInfoBytes, accountNumber } = value ?? {};
  if (documentChainId !== chainId) throw new Error("signDoc chain ID mismatch");
  if (!(bodyBytes instanceof Uint8Array) || !(authInfoBytes instanceof Uint8Array)
    || typeof accountNumber !== "bigint" || accountNumber < 0n || accountNumber > 0xffffffffffffffffn) {
    throw new TypeError("invalid Cosmos direct sign document");
  }
  return {
    bodyBytes: Uint8Array.from(bodyBytes),
    authInfoBytes: Uint8Array.from(authInfoBytes),
    chainId,
    accountNumber
  };
}

// Keplr's injected API uses protobufjs Long; the SDK's public sign document
// uses bigint. Decode its 64-bit words without a lossy Number conversion or
// calling an arbitrary wallet-returned toString implementation.
function keplrAccountNumber(value) {
  if (typeof value === 'bigint' && value >= 0n && value <= 0xffffffffffffffffn) return value;
  if (!value || typeof value !== 'object') throw new TypeError('invalid Keplr account number');
  const { low, high, unsigned } = value;
  if (!Number.isInteger(low) || low < -0x80000000 || low > 0x7fffffff
    || !Number.isInteger(high) || high < -0x80000000 || high > 0x7fffffff
    || typeof unsigned !== 'boolean') {
    throw new TypeError('invalid Keplr account number');
  }
  // Keplr constructs Long.fromString without the unsigned flag, including for
  // uint64 account numbers above 2^63. Interpret the protobuf words as unsigned;
  // submission still compares this exact number with the approved document.
  return (BigInt(high >>> 0) << 32n) | BigInt(low >>> 0);
}

export function toKeplrSignDoc(document) {
  return { ...document, accountNumber: Long.fromString(document.accountNumber.toString(), true) };
}

export function fromKeplrSignResponse(response) {
  return { ...response, signed: { ...response?.signed, accountNumber: keplrAccountNumber(response?.signed?.accountNumber) } };
}
