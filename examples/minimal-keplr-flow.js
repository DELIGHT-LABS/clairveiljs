import {
  createClairveilClient,
  createHttpProverAdapter,
  createKeplrWalletAdapter,
  LocalStorageNoteStore
} from "clairveiljs";

export async function runMinimalClairveilFlow({
  keplr = window.keplr,
  chainId = "clairveil-local-3",
  rest = "http://127.0.0.1:1317",
  rpc = "tcp://127.0.0.1:26657",
  proverUrl = "http://127.0.0.1:8080",
  accountPrefix = "clair",
  shieldedPrefix = "clairs",
  defaultDenom = "uclair",
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

  const material = await clairveil.deriveWalletPrivacyMaterial(wallet);

  const deposit = await clairveil.prepareDeposit({
    wallet,
    material,
    amount: "10uclair"
  });
  await clairveil.signDirectAndBroadcast({ wallet, signDoc: deposit.signDoc });

  const scan = await clairveil.scanWalletNotes({
    wallet,
    material,
    noteStore,
    includeFoundNotes: true
  });

  const transfer = await clairveil.prepareTransfer({
    wallet,
    material,
    amount: "1uclair",
    recipient: recipientShieldedAddress,
    proverAdapter,
    allowPlanStep: false
  });

  if (transfer.status !== "ready") {
    return { material, scan, transfer };
  }

  const broadcast = await clairveil.signDirectAndBroadcast({
    wallet,
    signDoc: transfer.signDoc
  });

  return { material, scan, transfer, broadcast };
}
