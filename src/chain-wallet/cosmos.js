import { fromBech32, toHex } from "@cosmjs/encoding";
import { assertSameActor, expectedActor, requireString } from "./actor.js";

function snapshotSignDoc(value, chainId) {
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

function cosmosAdapter({ chainId, address, accountPrefix, readAccount, connect, sign }) {
  chainId = requireString(chainId, "chainId");
  accountPrefix = requireString(accountPrefix, "accountPrefix");
  if (address !== undefined) address = requireString(address, "address");
  const getActor = async () => {
    const { address: currentAddress, pubkey } = await readAccount() ?? {};
    if (typeof currentAddress !== "string" || (address !== undefined && currentAddress !== address)) {
      throw new Error("chain wallet account mismatch");
    }
    const decoded = fromBech32(currentAddress);
    if (decoded.prefix !== accountPrefix || decoded.data.length !== 20) throw new Error("chain wallet address prefix or length mismatch");
    if (!(pubkey instanceof Uint8Array) || !pubkey.length) throw new Error("chain wallet public key is required");
    return Object.freeze({ namespace: "cosmos", chainId, address: currentAddress, pubKeyHex: toHex(pubkey) });
  };
  return Object.freeze({
    async connect() { await connect(); return getActor(); },
    getActor,
    async signDirect(signDoc, actor) {
      const expected = expectedActor(actor, "cosmos", chainId);
      const document = snapshotSignDoc(signDoc, chainId);
      assertSameActor(expected, await getActor());
      // Dispatch once with the captured public document and actor. No root signing or retries.
      return sign(expected.address, document);
    }
  });
}

export function createKeplrChainWalletAdapter({ keplr, chainId, address, accountPrefix = "clair" } = {}) {
  if (typeof keplr?.enable !== "function" || typeof keplr?.getKey !== "function" || typeof keplr?.signDirect !== "function") {
    throw new TypeError("Keplr enable, getKey and signDirect are required");
  }
  const selectedChainId = requireString(chainId, "chainId");
  return cosmosAdapter({
    chainId: selectedChainId, address, accountPrefix,
    connect: () => keplr.enable(selectedChainId),
    async readAccount() {
      const key = await keplr.getKey(selectedChainId);
      return { address: key?.bech32Address, pubkey: key?.pubKey };
    },
    sign: (signer, document) => keplr.signDirect(selectedChainId, signer, document, { preferNoSetFee: true, preferNoSetMemo: true })
  });
}

export function createOfflineSignerChainWalletAdapter({ signer, chainId, address, accountPrefix = "clair" } = {}) {
  if (typeof signer?.getAccounts !== "function" || typeof signer?.signDirect !== "function") {
    throw new TypeError("offline signer getAccounts and signDirect are required");
  }
  const selectedAddress = address === undefined ? undefined : requireString(address, "address");
  return cosmosAdapter({
    chainId, address: selectedAddress, accountPrefix,
    connect: async () => {},
    async readAccount() {
      const accounts = await signer.getAccounts();
      if (!Array.isArray(accounts) || !accounts.length) throw new Error("offline signer returned no accounts");
      return selectedAddress === undefined ? accounts[0] : accounts.find(account => account.address === selectedAddress);
    },
    sign: (account, document) => signer.signDirect(account, document)
  });
}
