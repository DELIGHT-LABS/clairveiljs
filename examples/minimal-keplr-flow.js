import {
  buildDepositProofRequestV1,
  createClairveilClient,
  createHttpProverAdapter,
  createKeplrWalletAdapter,
  LocalStorageNoteStore,
  normalizeDepositProofProviderResultV1,
  parseCoin
} from "clairveiljs";

export async function runMinimalClairveilFlow({
  keplr = window.keplr,
  chainId = "clairveil-local-1",
  rest = "http://127.0.0.1:1317",
  rpc = "tcp://127.0.0.1:26657",
  proverUrl = "http://127.0.0.1:8080",
  accountPrefix = "clair",
  shieldedPrefix = "clairs",
  defaultDenom = "uclair",
  depositAmount = `10${defaultDenom}`,
  transferAmount = `1${defaultDenom}`,
  depositProofProvider,
  recipientShieldedAddress
}) {
  const clairveil = createClairveilClient({
    chainId,
    rest,
    rpc,
    accountPrefix,
    shieldedPrefix,
    defaultDenom
  });
  const wallet = createKeplrWalletAdapter({ keplr, chainId, accountPrefix });
  const proverAdapter = createHttpProverAdapter({ baseURL: proverUrl });
  const noteStore = new LocalStorageNoteStore({
    key: `clairveil:${chainId}:notes`,
    allowPlaintext: true
  });

  await keplr.enable(chainId);

  const fetchLatestChainBlockTimeUnix = async () => {
    const response = await fetch(`${rest.replace(/\/$/, "")}/cosmos/base/tendermint/v1beta1/blocks/latest`);
    if (!response.ok) throw new Error(`latest block time query failed with HTTP ${response.status}`);
    const data = await response.json();
    const value = data?.block?.header?.time ?? data?.sdk_block?.header?.time;
    const milliseconds = Date.parse(String(value || ""));
    if (!Number.isFinite(milliseconds)) throw new Error("latest block response omitted a valid block time");
    return Math.floor(milliseconds / 1000);
  };

  const material = await clairveil.deriveWalletPrivacyMaterial(wallet);
  // The remote deposit prover sees receiver keys, amount, asset ID, and
  // randomness. Verify the active circuit and denom mapping before exposing
  // that witness; prepareDeposit repeats the check before signing.
  const depositCoin = parseCoin(depositAmount, defaultDenom);
  await clairveil.assertProtocolPreflight(depositCoin.denom);
  const depositMaterial = clairveil.buildDepositMaterial({
    creator: material.address,
    rootSeed: material.rootSeed,
    amount: depositCoin.raw,
    assetDenom: depositCoin.denom
  });
  const validatedDepositMaterial = clairveil.validateDepositMaterial({
    depositMaterial,
    creator: material.address,
    rootSeed: material.rootSeed,
    amount: depositCoin.raw,
    assetDenom: depositCoin.denom
  }).material;
  const depositRequest = buildDepositProofRequestV1({ material: validatedDepositMaterial });
  const provider = typeof depositProofProvider === "function"
    ? depositProofProvider
    : proverAdapter.proveDeposit.bind(proverAdapter);
  const depositResponse = normalizeDepositProofProviderResultV1(
    depositRequest,
    await provider(depositRequest)
  );

  const deposit = await clairveil.prepareDeposit({
    wallet,
    material,
    depositMaterial: validatedDepositMaterial,
    amount: depositCoin.raw,
    assetDenom: depositCoin.denom,
    proofHex: depositResponse.proof.proof_hex
  });
  const depositBroadcast = await clairveil.signDirectAndBroadcast({ wallet, signDoc: deposit.signDoc });
  if (!depositBroadcast.ok) {
    throw new Error(depositBroadcast.error || "Clairveil deposit was broadcast but not confirmed");
  }
  await clairveil.confirmDeposit({
    txHash: depositBroadcast.txHash,
    prepared: deposit
  });

  const scan = await clairveil.scanWalletNotes({
    wallet,
    material,
    noteStore,
    includeFoundNotes: true
  });

  const chainNowUnix = await fetchLatestChainBlockTimeUnix();
  const transfer = await clairveil.prepareTransfer({
    wallet,
    material,
    amount: transferAmount,
    recipient: recipientShieldedAddress,
    proverAdapter,
    allowPlanStep: false,
    chainNowUnix,
    expiresAtUnix: chainNowUnix + 1800
  });

  if (transfer.status !== "ready") {
    return { material, scan, transfer };
  }

  const broadcast = await clairveil.signDirectAndBroadcast({
    wallet,
    signDoc: transfer.signDoc,
    getChainNowUnix: fetchLatestChainBlockTimeUnix
  });
  if (!broadcast.ok) {
    throw new Error(broadcast.error || "Clairveil transfer was broadcast but not confirmed");
  }

  return { material, scan, depositBroadcast, transfer, broadcast };
}
