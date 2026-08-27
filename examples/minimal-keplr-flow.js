import {
  createClairveilClient,
  createHttpProverAdapter,
  createKeplrWalletAdapter,
  LocalStorageNoteStore
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
  if (typeof depositProofProvider !== "function") {
    throw new Error("depositProofProvider is required for Cosmos deposits");
  }
  const depositMaterial = clairveil.buildDepositMaterial({
    creator: material.address,
    rootSeed: material.rootSeed,
    amount: depositAmount
  });
  const proof = await depositProofProvider({
    material: depositMaterial,
    amount: depositMaterial.amount,
    note: depositMaterial.note,
    noteJson: depositMaterial.note_json,
    note_json: depositMaterial.note_json,
    noteCommitmentHex: depositMaterial.note_commitment_hex,
    note_commitment_hex: depositMaterial.note_commitment_hex
  });
  const proofBytes = proof?.proof ?? proof?.depositProof ?? proof?.deposit_proof ?? null;
  const proofHex = proof?.proofHex ?? proof?.proof_hex ?? proof?.depositProofHex ?? proof?.deposit_proof_hex;

  const deposit = await clairveil.prepareDeposit({
    wallet,
    material,
    depositMaterial,
    amount: depositAmount,
    proof: proofBytes,
    proofHex
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
