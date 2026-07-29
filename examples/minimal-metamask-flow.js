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

function bytesToHex(bytes) {
  return [...bytes].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function utf8ToHex(value) {
  return bytesToHex(new TextEncoder().encode(String(value)));
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
  depositAmount = `10${denom}`,
  transferAmount = `1${denom}`,
  recipientShieldedAddress,
  chainName = "Clairveil EVM",
  nativeCurrency,
  profileId = "clairveil-evm",
  profileLabel = "Clairveil EVM",
  displayDenom = "CLAIR",
  coinDecimals = 6,
  evmGasLimit = "0x989680",
  evmSendGasLimit = "0x5208",
  depositProofProvider,
  waitForDeposit = true,
  waitForTransfer = false
}) {
  if (!provider) {
    throw new Error("MetaMask provider is required");
  }
  if (typeof depositProofProvider !== "function") {
    throw new Error("depositProofProvider is required to build the canonical EVM DepositCircuit proof");
  }

  const clairveil = createClairveilBrowserDappClient({
    profile: {
      id: profileId,
      label: profileLabel,
      chainName,
      transport: "evm",
      wallet: "metamask",
      chainId,
      rest,
      rpc,
      proverUrl,
      evmRpc,
      evmChainId,
      evmChainName: chainName,
      evmPrivacyPrecompileAddress,
      evmGasLimit,
      evmSendGasLimit,
      accountPrefix,
      shieldedPrefix,
      denom,
      displayDenom,
      coinDecimals
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
    params: [`0x${utf8ToHex(rootMessage)}`, evmAccount]
  });
  const signatureBase64 = bytesToBase64(hexToBytes(signatureHex));

  const privacyRequest = {
    address: identity.address,
    pubKeyHex: identity.pubKeyHex,
    signatureBase64
  };
  // Browser EVM profiles verify this connected wallet network before every
  // privacy prepare call, independently of the read-only evmRpc endpoint.
  const evmWallet = {
    getChainId: () => provider.request({ method: "eth_chainId" }),
    sendTransaction: transaction => provider.request({
      method: "eth_sendTransaction",
      params: [{ from: evmAccount, ...transaction }]
    })
  };

  const deposit = await clairveil.prepareDeposit({
    ...privacyRequest,
    evmWallet,
    amount: depositAmount,
    depositProofProvider
  });
  const depositTxHash = await clairveil.sendEvmTransaction({
    wallet: evmWallet,
    transaction: deposit.transaction
  });
  const depositReceipt = waitForDeposit
    ? await clairveil.waitForEvmTransaction(depositTxHash)
    : null;
  if (waitForDeposit && !depositReceipt?.ok) {
    throw new Error(depositReceipt?.error || depositReceipt?.errors?.[0] || "EVM deposit was not confirmed");
  }

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
      evmWallet,
      amount: transferAmount,
      recipient: recipientShieldedAddress,
      allowPlanStep: false
    });
    transferTxHash = await clairveil.sendEvmTransaction({
      wallet: evmWallet,
      transaction: transfer.transaction
    });
    transferReceipt = waitForTransfer
      ? await clairveil.waitForEvmTransaction(transferTxHash)
      : null;
    if (waitForTransfer && !transferReceipt?.ok) {
      throw new Error(transferReceipt?.error || transferReceipt?.errors?.[0] || "EVM transfer was not confirmed");
    }
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
