import { dispatchToActor, expectedActor } from "./actor.js";

function address(value) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value)) throw new TypeError("invalid EVM address");
  return value.toLowerCase();
}

function quantity(value) {
  if (typeof value !== "string" || !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(value)) {
    throw new TypeError("EVM quantities must be canonical 0x-prefixed strings");
  }
  return value.toLowerCase();
}

function snapshotTransaction(value, actor) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("EVM transaction is required");
  const { from, to, chainId, data } = value;
  if (from !== undefined && address(from) !== actor.address) throw new Error("transaction sender mismatch");
  if (chainId !== undefined && quantity(chainId) !== actor.chainId) throw new Error("transaction chain ID mismatch");
  const transaction = { from: actor.address, to: address(to), chainId: actor.chainId };
  if (data !== undefined) {
    if (typeof data !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(data)) throw new TypeError("invalid EVM transaction data");
    transaction.data = data;
  }
  for (const field of ["value", "gas", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas", "nonce"]) {
    const fieldValue = value[field];
    if (fieldValue !== undefined) transaction[field] = quantity(fieldValue);
  }
  return transaction;
}

export function createEip1193ChainWalletAdapter({ provider, chainId, account } = {}) {
  if (typeof provider?.request !== "function") throw new TypeError("EIP-1193 provider request is required");
  chainId = quantity(chainId);
  const selectedAccount = account === undefined ? undefined : address(account);
  const getActor = async () => {
    const before = quantity(await provider.request({ method: "eth_chainId", params: [] }));
    if (before !== chainId) throw new Error("chain wallet network mismatch");
    const accounts = await provider.request({ method: "eth_accounts", params: [] });
    if (!Array.isArray(accounts) || !accounts.length) throw new Error("chain wallet returned no connected accounts");
    const addresses = accounts.map(address);
    const resolved = selectedAccount ?? addresses[0];
    if (!addresses.includes(resolved)) throw new Error("chain wallet account mismatch");
    if (quantity(await provider.request({ method: "eth_chainId", params: [] })) !== chainId) {
      throw new Error("chain wallet network changed");
    }
    return Object.freeze({ namespace: "eip155", chainId, address: resolved });
  };
  return Object.freeze({
    async connect() {
      await provider.request({ method: "eth_requestAccounts", params: [] });
      return getActor();
    },
    getActor,
    async sendTransaction(transaction, actor, { signal } = {}) {
      const expected = expectedActor(actor, "eip155", chainId);
      const external = snapshotTransaction(transaction, expected);
      const hash = await dispatchToActor(expected, getActor, signal,
        () => provider.request({ method: "eth_sendTransaction", params: [external] }));
      if (typeof hash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error("chain wallet returned an invalid transaction hash");
      return hash;
    }
  });
}
