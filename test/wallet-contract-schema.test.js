import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { assertJsonSchema, validateJsonSchema } from "../tools/json-schema-validator.js";
import { fixtureDir, fixtureTestOptions, readFixture } from "./helpers.js";

const schemaPath = process.env.CLAIRVEIL_WALLET_CONTRACT_SCHEMA
  ? resolve(process.env.CLAIRVEIL_WALLET_CONTRACT_SCHEMA)
  : resolve(fixtureDir, "../../../../../../docs/schemas/clairveil-js-wallet-contract.schema.json");

function walletContractSchema() {
  return JSON.parse(readFileSync(schemaPath, "utf8"));
}

const fixtureSchemaContracts = Object.freeze([
  ["privacy_browser_signer_provider_contract.json", "browserSignerProviderContract"],
  ["privacy_prover_example_bundle.json", "proverExampleBundle"],
  ["privacy_prover_http_api_contract.json", "proverHttpApiContract"],
  ["privacy_note_reservation_contract.json", "noteReservationContract"],
  ["privacy_relay_withdraw_contract.json", "relayWithdrawContract"],
  ["privacy_send_capable_reference_flow.json", "sendCapableReferenceFlow"],
  ["privacy_wallet_golden_vectors.json", "walletGoldenVectors"],
  ["privacy_wallet_readonly_reference_bundle.json", "walletReadonlyReferenceBundle"]
]);

for (const [fixtureName, schemaName] of fixtureSchemaContracts) {
  test(`published ${fixtureName} satisfies Clairveil's ${schemaName} JSON Schema contract`, fixtureTestOptions, () => {
    const schema = walletContractSchema();
    const fixture = readFixture(fixtureName);
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    if (fixtureName === "privacy_note_reservation_contract.json") {
      assert.equal(fixture.version, 3);
    }
    assertJsonSchema(schema, fixture, schema.$defs[schemaName]);
  });
}

test("wallet contract release gate catches a schema-breaking audit config", fixtureTestOptions, () => {
  const schema = walletContractSchema();
  const fixture = structuredClone(readFixture("privacy_browser_signer_provider_contract.json"));
  fixture.send_provider.audit_config_response.audit_key_epoch = "0";
  const errors = validateJsonSchema(schema, fixture, schema.$defs.browserSignerProviderContract);
  assert.ok(errors.some(error => error.includes("audit_key_epoch")));
});

test("wallet contract release gate rejects downgraded or incomplete reservation contracts", fixtureTestOptions, () => {
  const schema = walletContractSchema();
  const fixture = readFixture("privacy_note_reservation_contract.json");

  const downgraded = structuredClone(fixture);
  downgraded.version = 1;
  const downgradeErrors = validateJsonSchema(schema, downgraded, schema.$defs.noteReservationContract);
  assert.ok(downgradeErrors.some(error => error.includes("$.version")));

  const incomplete = structuredClone(fixture);
  delete incomplete.fail_closed_runtime_policy;
  const incompleteErrors = validateJsonSchema(schema, incomplete, schema.$defs.noteReservationContract);
  assert.ok(incompleteErrors.some(error => error.includes("fail_closed_runtime_policy")));
});
