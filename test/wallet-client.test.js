import test from "node:test";
import assert from "node:assert/strict";
import { ClairveilBrowserClient } from "clairveiljs/browser-dapp";

function browserClient() {
  return new ClairveilBrowserClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-3",
    accountPrefix: "clair",
    shieldedPrefix: "clairs",
    denom: "uclair",
  });
}

test("waitForEvmTransaction treats padded success status as successful", async () => {
  const client = browserClient();
  client.waitForEvmReceipt = async () => ({ status: "0x01" });

  const result = await client.waitForEvmTransaction("0xabc");

  assert.equal(result.ok, true);
  assert.equal(result.error, "");
});

test("waitForEvmTransaction keeps missing receipt status ambiguous", async () => {
  const client = browserClient();
  client.waitForEvmReceipt = async () => ({});

  const result = await client.waitForEvmTransaction("0xabc");

  assert.equal(result.ok, false);
  assert.match(result.error, /explicit successful receipt status/);
  assert.doesNotMatch(result.error, /failed with receipt status/);
});

test("browser preparation rejects conflicting operation-evidence aliases", async () => {
  const client = browserClient();
  client.privacyMaterial = () => ({});
  client.proverAdapter = () => ({});

  await assert.rejects(
    () => client.prepareTransfer({
      amount: "1uclair",
      recipient: "clairs1recipient",
      expectedRecipientHash: "recipient-a",
      expected_recipient_hash: "recipient-b",
      expectedAmountHash: "amount-a",
      expected_amount_hash: "amount-a"
    }),
    /expectedRecipientHash aliases conflict/
  );
  await assert.rejects(
    () => client.prepareTransferBatch({
      amounts: ["1uclair"],
      recipient: "clairs1recipient",
      expectedRecipientHashes: ["recipient-a"],
      expected_recipient_hashes: ["recipient-b"],
      expectedAmountHashes: ["amount-a"],
      expected_amount_hashes: ["amount-a"]
    }),
    /expectedRecipientHashes aliases conflict/
  );
  await assert.rejects(
    () => client.prepareTransfer({
      amount: "1uclair",
      recipient: "clairs1recipient",
      expectedRecipientHash: "",
      expectedAmountHash: ""
    }),
    /expectedRecipientHash must not be empty/
  );
});

test("browser client delegates signDirectAndBroadcast to the Cosmos client", async () => {
  const client = browserClient();
  const input = { wallet: {}, signDoc: {} };
  client.cosmos.signDirectAndBroadcast = async received => {
    assert.equal(received, input);
    return { ok: true };
  };

  assert.deepEqual(await client.signDirectAndBroadcast(input), { ok: true });
});

test("browser relay cleanup preserves a frozen transaction build error", async () => {
  const client = browserClient();
  client.privacyMaterial = () => ({});
  client.proverAdapter = () => ({});
  const reservation = {
    reservation_ids: ["reservation-1"],
    lease_token: "lease-token"
  };
  client.cosmos.prepareRelayWithdraw = async () => ({
    status: "ready",
    payload: {},
    proof: {},
    proverPayload: {},
    selectedNote: {},
    reservation,
    privacyAccount: { shielded_address: "clairs1sender" }
  });
  const original = Object.freeze(new Error("frozen EVM transaction build failure"));
  client.evm.buildWithdrawTransaction = async () => {
    throw original;
  };
  const reservationManager = {
    async markReplanRequired() {
      throw new Error("reservation cleanup failed");
    }
  };

  await assert.rejects(
    () => client.prepareRelayWithdraw({
      walletType: "evm",
      amount: "1uclair",
      recipient: "clair1recipient",
      chainNowUnix: 4102444800,
      reservationManager
    }),
    error => error === original
  );
});

test("browser relay helpers preserve legacy chain-time aliases", async () => {
  const client = browserClient();
  client.privacyMaterial = () => ({});
  client.proverAdapter = () => ({});

  let preparedInput = null;
  client.cosmos.prepareRelayWithdraw = async input => {
    preparedInput = input;
    return { status: "insufficient_funds", plan: { message: "not ready" } };
  };
  await assert.rejects(
    () => client.prepareRelayWithdraw({
      amount: "1uclair",
      recipient: "clair1recipient",
      nowUnix: 4102444800
    }),
    /not ready/
  );
  assert.equal(preparedInput.chainNowUnix, 4102444800);

  client.cosmos.buildRelayWithdrawMessageFromPayload = input => input;
  const messageInput = client.buildRelayWithdrawMessageFromPayload({
    payload: {},
    address: "clair1relayer",
    now_unix: 4102444801
  });
  assert.equal(messageInput.chainNowUnix, 4102444801);

  let signDocInput = null;
  client.cosmos.createRelayWithdrawSignDoc = async input => {
    signDocInput = input;
    return { signDoc: {}, message: {}, payload: input.payload, relayer: input.relayer };
  };
  await client.createRelayWithdrawSignDoc({
    payload: {},
    address: "clair1relayer",
    pubKeyHex: "02".padEnd(66, "0"),
    nowUnix: 4102444802
  });
  assert.equal(signDocInput.chainNowUnix, 4102444802);
});
