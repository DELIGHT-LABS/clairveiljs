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

test("published browser wallet fixture satisfies Clairveil's JSON Schema contract", fixtureTestOptions, () => {
  const schema = walletContractSchema();
  const fixture = readFixture("privacy_browser_signer_provider_contract.json");
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assertJsonSchema(schema, fixture, schema.$defs.browserSignerProviderContract);
});

test("wallet contract release gate catches a schema-breaking audit config", fixtureTestOptions, () => {
  const schema = walletContractSchema();
  const fixture = structuredClone(readFixture("privacy_browser_signer_provider_contract.json"));
  fixture.send_provider.audit_config_response.audit_key_epoch = "0";
  const errors = validateJsonSchema(schema, fixture, schema.$defs.browserSignerProviderContract);
  assert.ok(errors.some(error => error.includes("audit_key_epoch")));
});
