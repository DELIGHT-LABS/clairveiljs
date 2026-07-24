import test from "node:test";
import assert from "node:assert/strict";
import {
  createClairveilClient,
  normalizeAuditConfigV1,
  normalizeDisclosureConfigV1,
  normalizeReserveResponseV1,
  validateCircuitConfigV1
} from "clairveiljs/cosmos-client";

test("Cosmos client runtime exports match its declared config validators", () => {
  assert.equal(typeof validateCircuitConfigV1, "function");
  assert.equal(typeof normalizeAuditConfigV1, "function");
  assert.equal(typeof normalizeDisclosureConfigV1, "function");
  assert.equal(typeof normalizeReserveResponseV1, "function");
});

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

test("Cosmos client unwraps standard vesting account metadata for direct signing", async () => {
  const client = createClairveilClient({
    rpc: "http://127.0.0.1:26657",
    rest: "http://127.0.0.1:1317",
    chainId: "clairveil-local-1"
  });
  client.fetchJson = async () => ({
    account: {
      "@type": "/cosmos.vesting.v1beta1.ContinuousVestingAccount",
      base_vesting_account: {
        base_account: {
          account_number: "42",
          sequence: "9"
        }
      }
    }
  });

  assert.deepEqual(await client.getAccountInfo("clair1vesting"), {
    accountNumber: 42n,
    sequence: 9n
  });
});
