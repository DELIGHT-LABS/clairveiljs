import test from "node:test";
import assert from "node:assert/strict";
import { createClairveilClient } from "clairveiljs/cosmos";

function clientWithMaterial() {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-test-1",
    defaultDenom: "uclair"
  });
  const material = client.buildDepositMaterial({
    creator: "clair1deposit",
    rootSeed: new Uint8Array(32).fill(7),
    amount: "7uclair"
  });
  return { client, material };
}

function successfulDepositTx(material) {
  return {
    txhash: "AABBCC",
    code: 0,
    events: [{
      type: "deposit",
      attributes: [
        { key: "commitment", value: material.note_commitment_hex },
        { key: "encrypted_note", value: material.encrypted_note_hex }
      ]
    }]
  };
}

test("confirmDeposit verifies the prepared commitment and encrypted note in the tx result", async () => {
  const { client, material } = clientWithMaterial();
  const tx = successfulDepositTx(material);
  client.waitForTx = async () => tx;

  const confirmed = await client.confirmDeposit({ txHash: "aabbcc", material });

  assert.equal(confirmed.status, "confirmed");
  assert.equal(confirmed.txHash, "AABBCC");
  assert.equal(confirmed.commitment, material.note_commitment_hex);
  assert.equal(confirmed.encryptedNote, material.encrypted_note_hex);
  assert.equal(confirmed.event.type, "deposit");
});

test("confirmDeposit rejects a failed tx and mismatched deposit event", async () => {
  const { client, material } = clientWithMaterial();
  client.waitForTx = async () => ({ ...successfulDepositTx(material), code: 7 });
  await assert.rejects(
    () => client.confirmDeposit({ txHash: "aabbcc", material }),
    /deposit transaction did not succeed: code 7/
  );

  client.waitForTx = async () => ({
    ...successfulDepositTx(material),
    events: [{
      type: "deposit",
      attributes: [
        { key: "commitment", value: "00".repeat(32) },
        { key: "encrypted_note", value: material.encrypted_note_hex }
      ]
    }]
  });
  await assert.rejects(
    () => client.confirmDeposit({ txHash: "aabbcc", prepared: { material } }),
    /does not contain the prepared commitment and encrypted note/
  );
});
