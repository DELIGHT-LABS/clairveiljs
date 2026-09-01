import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  clairveilProverConformanceBundleVersion,
  defaultProverHttpApiSchemaPath,
  depositProverConformanceFixtureName,
  proverHttpApiConformanceFixtureName,
  readClairveilProverConformanceFixture,
  supportedClairveilProverCommit,
  supportedClairveilProverRelease,
  supportedClairveilProverSourceKind
} from "clairveiljs/conformance";
import { assertJsonSchema, validateJsonSchema } from "../tools/json-schema-validator.js";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const schemaPath = process.env.CLAIRVEIL_PROVER_HTTP_API_SCHEMA
  ? resolve(process.env.CLAIRVEIL_PROVER_HTTP_API_SCHEMA)
  : resolve(packageRoot, defaultProverHttpApiSchemaPath);

function proverHttpApiSchema() {
  return JSON.parse(readFileSync(schemaPath, "utf8"));
}

function schemaDefinition(schema, name) {
  if (!Object.hasOwn(schema.$defs || {}, name)) {
    throw new Error(`prover HTTP API JSON Schema is missing $defs.${name}`);
  }
  return schema.$defs[name];
}

test("v0.4.0 prover conformance has an independent exact release identity", () => {
  assert.equal(clairveilProverConformanceBundleVersion, "v0.4.0");
  assert.equal(supportedClairveilProverRelease, "v0.4.0");
  assert.equal(supportedClairveilProverSourceKind, "release_tag");
  assert.equal(supportedClairveilProverCommit, "ca85b02708fdd75259d4d2ee2d671c21198cec69");
});

for (const [fixtureName, definitionName] of [
  [proverHttpApiConformanceFixtureName, "fullRouteInventory"],
  [depositProverConformanceFixtureName, "depositConformanceFixture"]
]) {
  test(`published ${fixtureName} satisfies Clairveil v0.4.0's dedicated prover schema`, () => {
    const schema = proverHttpApiSchema();
    const fixture = readClairveilProverConformanceFixture(fixtureName);
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assertJsonSchema(schema, fixture);
    assertJsonSchema(schema, fixture, schemaDefinition(schema, definitionName));
  });
}

test("prover schema enforces prefixItems order and items:false tuple closure", () => {
  const schema = proverHttpApiSchema();
  const definition = schemaDefinition(schema, "fullRouteInventory");
  const fixture = readClairveilProverConformanceFixture(proverHttpApiConformanceFixtureName);

  const reordered = structuredClone(fixture);
  reordered.common_policy.request.content_encodings.reverse();
  const reorderErrors = validateJsonSchema(schema, reordered, definition);
  assert.ok(reorderErrors.some(error => error.includes("content_encodings[0]")));

  const extended = structuredClone(fixture);
  extended.common_policy.request.content_encodings.push("br");
  const extendedErrors = validateJsonSchema(schema, extended, definition);
  assert.ok(extendedErrors.some(error => error.includes("content_encodings[2] is not allowed")));
});

test("prover schema rejects changed route failure and uint64 boundary contracts", () => {
  const schema = proverHttpApiSchema();
  const routeFixture = readClairveilProverConformanceFixture(proverHttpApiConformanceFixtureName);
  const changedFailure = structuredClone(routeFixture);
  changedFailure.common_policy.route_failure_status.deposit.prover_failure = 400;
  const failureErrors = validateJsonSchema(
    schema,
    changedFailure,
    schemaDefinition(schema, "fullRouteInventory")
  );
  assert.ok(failureErrors.some(error => error.includes("prover_failure")));

  const depositFixture = readClairveilProverConformanceFixture(depositProverConformanceFixtureName);
  const overflow = structuredClone(depositFixture.canonical_positive_request);
  overflow.payload.amount = "18446744073709551616";
  const overflowErrors = validateJsonSchema(
    schema,
    overflow,
    schemaDefinition(schema, "canonicalDepositRequest")
  );
  assert.ok(overflowErrors.some(error => error.includes("amount")));

  const nonCanonical = structuredClone(depositFixture.canonical_positive_request);
  nonCanonical.payload.amount = "04242";
  const canonicalErrors = validateJsonSchema(
    schema,
    nonCanonical,
    schemaDefinition(schema, "canonicalDepositRequest")
  );
  assert.ok(canonicalErrors.some(error => error.includes("amount")));
});

test("schema validator implements boolean schemas and rejects missing selections", () => {
  const schema = proverHttpApiSchema();
  assert.deepEqual(validateJsonSchema(schema, "anything", true), []);
  assert.deepEqual(validateJsonSchema(schema, "anything", false), ["$ is not allowed"]);
  assert.deepEqual(
    validateJsonSchema({ $defs: { never: false }, $ref: "#/$defs/never" }, "anything"),
    ["$ is not allowed"]
  );
  assert.throws(
    () => validateJsonSchema(schema, {}, schema.$defs.missingContract),
    /JSON Schema selection is undefined/
  );
});
