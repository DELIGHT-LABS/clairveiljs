import { createClairveilBrowserDappClient } from "clairveiljs/browser-dapp";

function hexToBytes(value) {
  const hex = String(value || "").replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error("hex value must contain an even number of hex characters");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.slice(i, i + 0x8000));
  }
  return btoa(binary);
}

async function ensureMetaMaskChain(provider, {
  evmChainId,
  evmRpc,
  chainName = "Clairveil EVM",
  nativeCurrency = { name: "CLAIR", symbol: "CLAIR", decimals: 18 }
}) {
  if (!evmChainId) return;
  try {
    await provider.request({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: evmChainId }]
    });
    return;
  } catch (error) {
    if (error?.code !== 4902 || !evmRpc) throw error;
  }

  await provider.request({
    method: "wallet_addEthereumChain",
    params: [{
      chainId: evmChainId,
      chainName,
      rpcUrls: [evmRpc],
      nativeCurrency
    }]
  });
}

export async function runMinimalMetaMaskFlow({
  provider = window.ethereum,
  chainId = "evm-local",
  rest = "http://127.0.0.1:1317",
  rpc = "http://127.0.0.1:26657",
  proverUrl = "http://127.0.0.1:8080",
  evmRpc = "http://127.0.0.1:8545",
  evmChainId = "0x32f",
  evmPrivacyPrecompileAddress = "0x100000000000000000000000000000000000000b",
  accountPrefix = "clair",
  shieldedPrefix = "clairs",
  denom = "uclair",
  depositAmount = "10uclair",
  transferAmount = "1uclair",
  recipientShieldedAddress,
  chainName,
  nativeCurrency,
  waitForDeposit = false,
  waitForTransfer = false
}) {
  if (!provider) {
    throw new Error("MetaMask provider is required");
  }

  const clairveil = createClairveilBrowserDappClient({
    profile: {
      transport: "evm",
      wallet: "metamask",
      chainId,
      rest,
      rpc,
      proverUrl,
      evmRpc,
      evmChainId,
      evmPrivacyPrecompileAddress,
      accountPrefix,
      shieldedPrefix,
      denom
    }
  });

  await ensureMetaMaskChain(provider, {
    evmChainId,
    evmRpc,
    chainName,
    nativeCurrency
  });

  const [evmAccount] = await provider.request({ method: "eth_requestAccounts" });
  const identity = clairveil.evmAccountIdentity(evmAccount);
  const rootMessage = clairveil.buildRootSigningMessage(identity.address, identity.pubKeyHex);
  const signatureHex = await provider.request({
    method: "personal_sign",
    params: [rootMessage, evmAccount]
  });
  const signatureBase64 = bytesToBase64(hexToBytes(signatureHex));

  const privacyRequest = {
    walletType: "evm",
    address: identity.address,
    pubKeyHex: identity.pubKeyHex,
    signatureBase64
  };

  const deposit = await clairveil.prepareDeposit({
    ...privacyRequest,
    amount: depositAmount
  });
  const depositTxHash = await provider.request({
    method: "eth_sendTransaction",
    params: [{ from: evmAccount, ...deposit.transaction }]
  });
  const depositReceipt = waitForDeposit
    ? await clairveil.waitForEvmTransaction(depositTxHash)
    : null;

  const scan = await clairveil.scanWalletNotes({
    ...privacyRequest,
    includeFoundNotes: true
  });

  let transfer = null;
  let transferTxHash = "";
  let transferReceipt = null;
  if (recipientShieldedAddress) {
    transfer = await clairveil.prepareTransfer({
      ...privacyRequest,
      amount: transferAmount,
      recipient: recipientShieldedAddress,
      allowPlanStep: false
    });
    transferTxHash = await provider.request({
      method: "eth_sendTransaction",
      params: [{ from: evmAccount, ...transfer.transaction }]
    });
    transferReceipt = waitForTransfer
      ? await clairveil.waitForEvmTransaction(transferTxHash)
      : null;
  }

  return {
    evmAccount,
    identity,
    deposit,
    depositTxHash,
    depositReceipt,
    scan,
    transfer,
    transferTxHash,
    transferReceipt
  };
}
