import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assertJsonSchema, validateJsonSchema } from "../tools/json-schema-validator.js";
import { fixtureDir, fixtureTestOptions, readFixture } from "./helpers.js";

const fixtureSchemaPath = resolve(
  fixtureDir,
  "../../../../../../docs/schemas/clairveil-js-wallet-contract.schema.json"
);
const bundledSchemaPath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../fixtures/clairveil-v0.3.1/docs/schemas/clairveil-js-wallet-contract.schema.json"
);
const schemaPath = process.env.CLAIRVEIL_WALLET_CONTRACT_SCHEMA
  ? resolve(process.env.CLAIRVEIL_WALLET_CONTRACT_SCHEMA)
  : existsSync(fixtureSchemaPath) ? fixtureSchemaPath : bundledSchemaPath;

function walletContractSchema() {
  return JSON.parse(readFileSync(schemaPath, "utf8"));
}

function schemaDefinition(schema, name) {
  if (!Object.hasOwn(schema.$defs || {}, name)) {
    throw new Error(`wallet contract JSON Schema is missing $defs.${name}`);
  }
  return schema.$defs[name];
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
    assertJsonSchema(schema, fixture, schemaDefinition(schema, schemaName));
  });
}

test("wallet contract release gate catches a schema-breaking audit config", fixtureTestOptions, () => {
  const schema = walletContractSchema();
  const fixture = structuredClone(readFixture("privacy_browser_signer_provider_contract.json"));
  fixture.send_provider.audit_config_response.audit_key_epoch = "0";
  const errors = validateJsonSchema(
    schema,
    fixture,
    schemaDefinition(schema, "browserSignerProviderContract")
  );
  assert.ok(errors.some(error => error.includes("audit_key_epoch")));
});

test("wallet contract release gate rejects downgraded or incomplete reservation contracts", fixtureTestOptions, () => {
  const schema = walletContractSchema();
  const fixture = readFixture("privacy_note_reservation_contract.json");

  const downgraded = structuredClone(fixture);
  downgraded.version = 1;
  const reservationSchema = schemaDefinition(schema, "noteReservationContract");
  const downgradeErrors = validateJsonSchema(schema, downgraded, reservationSchema);
  assert.ok(downgradeErrors.some(error => error.includes("$.version")));

  const incomplete = structuredClone(fixture);
  delete incomplete.fail_closed_runtime_policy;
  const incompleteErrors = validateJsonSchema(schema, incomplete, reservationSchema);
  assert.ok(incompleteErrors.some(error => error.includes("fail_closed_runtime_policy")));
});

test("wallet contract release gate fails closed when a selected $defs entry is missing", () => {
  const schema = walletContractSchema();
  assert.throws(
    () => schemaDefinition(schema, "missingContract"),
    /missing \$defs\.missingContract/
  );
  assert.throws(
    () => validateJsonSchema(schema, {}, schema.$defs.missingContract),
    /JSON Schema selection is undefined/
  );
});
