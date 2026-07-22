import test from "node:test";
import assert from "node:assert/strict";
import { createClairveilClient } from "clairveiljs/cosmos";

test("Cosmos client reads sign-doc account metadata from the standard auth account route", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-1"
  });
  const address = "clair1vd3rcrmuutg5thjg62d5pn7nf6c2sjf65pvqp9";
  const calls = [];
  client.fetchJson = async path => {
    calls.push(path);
    return {
      account: {
        account_number: 0,
        sequence: "7"
      }
    };
  };

  assert.deepEqual(await client.getAccountInfo(address), {
    accountNumber: 0n,
    sequence: 7n
  });
  assert.deepEqual(calls, [`/cosmos/auth/v1beta1/accounts/${address}`]);
});
