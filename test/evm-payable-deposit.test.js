import test from "node:test";
import assert from "node:assert/strict";
import {
  createClairveilEvmClient,
  createEvmContractAdapter,
  evmDepositModePayableExactValue,
  evmDepositValueForAmount,
  evmPrivacyPrecompilePayableDepositAbi
} from "clairveiljs/evm";

function depositMessage(amount = "3udemo") {
  return {
    amount,
    noteCommitment: new Uint8Array(32).fill(1),
    encryptedNote: new Uint8Array([2, 3]),
    proof: new Uint8Array([4, 5])
  };
}

test("payable EVM deposits derive exact msg.value from the native minimal denom", () => {
  assert.equal(evmDepositValueForAmount("3udemo", "udemo"), "0x3");
  assert.equal(evmDepositValueForAmount("0udemo", "udemo"), "0x0");
  assert.equal(
    evmDepositValueForAmount("18446744073709551615udemo", "udemo"),
    "0xffffffffffffffff"
  );
  assert.throws(
    () => evmDepositValueForAmount("18446744073709551616udemo", "udemo"),
    /uint64 amount range/
  );
  assert.throws(
    () => evmDepositValueForAmount("3uother", "udemo"),
    /does not match native denom/
  );

  const client = createClairveilEvmClient({
    accountPrefix: "demo",
    shieldedPrefix: "demos",
    defaultDenom: "udemo",
    depositMode: evmDepositModePayableExactValue,
    nativeDenom: "udemo"
  });
  const prepared = client.buildDepositTransaction({ message: depositMessage() });
  assert.equal(prepared.transaction.value, "0x3");
  assert.equal(client.contract.abi[0].stateMutability, "payable");
  assert.equal(evmPrivacyPrecompilePayableDepositAbi[0].stateMutability, "payable");

  assert.throws(
    () => client.buildDepositTransaction({
      message: depositMessage(),
      transactionOptions: { value: "0x4" }
    }),
    /does not match required value/
  );
  assert.throws(
    () => client.buildDepositTransaction({ message: depositMessage("3uother") }),
    /does not match native denom/
  );
});

test("nonpayable operations reject value and payable deposit bindings survive serialization", async () => {
  const nonpayable = createEvmContractAdapter({
    encodeDeposit: () => "0x01",
    encodeTransfer: () => "0x02",
    encodeWithdraw: () => "0x03"
  });
  assert.throws(
    () => nonpayable.buildDepositTransaction(depositMessage(), { value: "0x1" }),
    /does not match required value 0x0/
  );
  assert.throws(
    () => nonpayable.buildTransferTransaction({}, { value: "0x1" }),
    /transfer transaction value must be zero/
  );
  assert.throws(
    () => nonpayable.buildWithdrawTransaction({}, { value: "0x1" }),
    /withdraw transaction value must be zero/
  );

  const client = createClairveilEvmClient({
    defaultDenom: "udemo",
    depositMode: "payable-exact-value",
    nativeDenom: "udemo"
  });
  const prepared = client.buildDepositTransaction({ message: depositMessage() });
  const serialized = JSON.parse(JSON.stringify(prepared.transaction));
  let submitted = null;
  const wallet = {
    async sendTransaction(transaction) {
      submitted = transaction;
      return `0x${"ab".repeat(32)}`;
    }
  };
  await client.sendTransaction(wallet, serialized);
  assert.equal(submitted.value, "0x3");
  assert.equal(Object.hasOwn(submitted, "__clairveilEvmTransaction"), false);

  await assert.rejects(
    () => client.sendTransaction(wallet, { ...serialized, value: "0x4" }),
    /binding was modified/
  );
  await assert.rejects(
    () => client.sendTransaction(wallet, { ...serialized, data: "0x1234" }),
    /binding was modified/
  );
  await assert.rejects(
    () => client.sendTransaction(wallet, {
      ...serialized,
      to: "0x1111111111111111111111111111111111111111"
    }),
    /target does not match/
  );

  const transferClient = createClairveilEvmClient({
    contractAdapter: nonpayable
  });
  const transfer = await transferClient.buildTransferTransaction({
    message: { expiresAtUnix: 2_000n },
    chainNowUnix: 1_000
  });
  await transferClient.sendTransaction(wallet, JSON.parse(JSON.stringify(transfer.transaction)));
  await assert.rejects(
    () => transferClient.sendTransaction(wallet, { ...transfer.transaction, value: "0x5" }),
    /binding was modified/
  );
  await assert.rejects(
    () => transferClient.sendTransaction(wallet, { ...transfer.transaction, data: "0x04" }),
    /binding was modified/
  );
  await assert.rejects(
    () => transferClient.sendTransaction(wallet, {
      ...transfer.transaction,
      to: "0x2222222222222222222222222222222222222222"
    }),
    /target does not match/
  );

  const withdraw = await transferClient.buildWithdrawTransaction({ message: {} });
  await assert.rejects(
    () => transferClient.sendTransaction(wallet, { ...withdraw.transaction, value: "0x5" }),
    /binding was modified/
  );
});
