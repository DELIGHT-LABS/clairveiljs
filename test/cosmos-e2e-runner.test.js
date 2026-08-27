import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { cosmosE2eChildEnvironment } from "../tools/run-cosmos-e2e.js";

const e2eSource = readFileSync(new URL("./e2e-local.e2e.js", import.meta.url), "utf8");

test("Cosmos release E2E isolates local and testnet deployment settings", () => {
  const sourceEnv = {
    PATH: "/usr/bin",
    CLAIRVEIL_E2E_CHAIN_ID: "generic-must-not-leak",
    CLAIRVEIL_E2E_RPC: "https://generic.invalid",
    CLAIRVEIL_E2E_LOCAL_CHAIN_ID: "clairveil-local-1",
    CLAIRVEIL_E2E_LOCAL_RPC: "http://127.0.0.1:26657",
    CLAIRVEIL_E2E_LOCAL_MNEMONIC: "local secret",
    CLAIRVEIL_E2E_TESTNET_CHAIN_ID: "clairveil-testnet-1",
    CLAIRVEIL_E2E_TESTNET_RPC: "https://rpc.testnet.example",
    CLAIRVEIL_E2E_TESTNET_MNEMONIC: "testnet secret"
  };

  const local = cosmosE2eChildEnvironment("local", sourceEnv);
  assert.equal(local.PATH, "/usr/bin");
  assert.equal(local.CLAIRVEIL_E2E_CHAIN_ID, "clairveil-local-1");
  assert.equal(local.CLAIRVEIL_E2E_RPC, "http://127.0.0.1:26657");
  assert.equal(local.CLAIRVEIL_E2E_MNEMONIC, "local secret");
  assert.equal(local.CLAIRVEIL_E2E_LOCAL, "1");
  assert.equal(local.CLAIRVEIL_E2E_TESTNET, undefined);
  assert.equal(local.CLAIRVEIL_E2E_TESTNET_CHAIN_ID, undefined);

  const testnet = cosmosE2eChildEnvironment("testnet", sourceEnv);
  assert.equal(testnet.CLAIRVEIL_E2E_CHAIN_ID, "clairveil-testnet-1");
  assert.equal(testnet.CLAIRVEIL_E2E_RPC, "https://rpc.testnet.example");
  assert.equal(testnet.CLAIRVEIL_E2E_MNEMONIC, "testnet secret");
  assert.equal(testnet.CLAIRVEIL_E2E_TESTNET, "1");
  assert.equal(testnet.CLAIRVEIL_E2E_LOCAL, undefined);
  assert.equal(testnet.CLAIRVEIL_E2E_LOCAL_CHAIN_ID, undefined);

  for (const child of [local, testnet]) {
    assert.equal(child.CLAIRVEIL_E2E_FULL_FLOW, "1");
    assert.equal(child.CLAIRVEIL_E2E_ONE_PROOF_BATCH, "1");
    assert.equal(child.CLAIRVEIL_E2E_ONE_PROOF_BATCH_SHAPE, "all");
    assert.equal(child.CLAIRVEIL_E2E_REQUIRED, "1");
  }
});

test("Cosmos release E2E rejects an unknown deployment mode", () => {
  assert.throws(
    () => cosmosE2eChildEnvironment("staging", {}),
    /must be local or testnet/
  );
});

test("Cosmos release E2E exercises final privacy broadcast fences", () => {
  assert.match(
    e2eSource,
    /async function broadcastPrepared[\s\S]*?getChainNowUnix:\s*\(\) => latestChainBlockTimeUnix\(config\)/
  );
  assert.match(
    e2eSource,
    /await client\.confirmDeposit\(\{[\s\S]*?txHash,[\s\S]*?prepared,[\s\S]*?depositMaterial/
  );
  assert.match(
    e2eSource,
    /signDirectAndBroadcast\(\{[\s\S]*?signDoc: signDoc\.sign_doc,[\s\S]*?reservationManager,[\s\S]*?reservation: reservationBatch,[\s\S]*?getChainNowUnix:/
  );
  assert.doesNotMatch(e2eSource, /markOneProofPayrollReservationBroadcastAttempting/);
  assert.doesNotMatch(e2eSource, /markOneProofPayrollReservationSubmitted/);
});
