/** Consensus identity schema used by Clairveil's `privacy-note-v1` active set. */
export const circuitSetIdentitySchemaVersionV1 = "v1";
export const privacyNoteV1CircuitSetId = "privacy-note-v1";
export const privacyNoteV1CircuitCurve = "BN254";
export const privacyNoteV1CircuitOrder = Object.freeze([
  "deposit",
  "spend",
  "joinsplit",
  "batch-joinsplit-16x32-v1"
]);

/** Public-input schemas are protocol constants, not node-local artifact metadata. */
export const privacyNoteV1PublicInputSchemaSHA256 = Object.freeze({
  deposit: "c3231fb5ae62539d2e4baeb78aa4be8a4c44e3cd8fa325ba60f13b7f563d5a1e",
  spend: "d0a033aa2f7b6e098873307a815545ee3e83d974026c0e52bf39a038e08f4872",
  joinsplit: "4946e23db34529c6fce0a95ce69f6df08563a305ddcc70c7b6b786471e03aa82",
  "batch-joinsplit-16x32-v1": "5606327d69dcb06c00811f2135291d39a2ea1cedf554f114f7eb4a178098d333"
});

function object(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value;
}

function text(value, label) {
  if (typeof value !== "string" || value !== value.trim() || !value) throw new Error(`${label} is required`);
  return value;
}

function aliasValue(source, names, label, normalize = value => value) {
  const values = names
    .filter(name => source?.[name] !== undefined && source?.[name] !== null)
    .map(name => normalize(source[name]));
  if (!values.length) throw new Error(`${label} is required`);
  if (values.some(value => value !== values[0])) throw new Error(`${label} aliases disagree`);
  return values[0];
}

function sha256(value, label) {
  const digest = text(value, label);
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error(`${label} must be lowercase SHA-256 hex`);
  return digest;
}

function circuitIdentity(raw, index, { allowMissingVerifyingKey = false } = {}) {
  const value = object(raw, `circuit identity ${index}`);
  const circuitId = aliasValue(value, ["circuit_id", "circuitId"], `circuit identity ${index}.circuit_id`, entry => text(entry, `circuit identity ${index}.circuit_id`));
  const verifyingKey = ["verifying_key_sha256", "verifyingKeySha256"]
    .filter(name => value[name] !== undefined && value[name] !== null);
  if (!verifyingKey.length && allowMissingVerifyingKey) {
    return Object.freeze({
      circuit_id: circuitId,
      public_input_schema_sha256: aliasValue(value, ["public_input_schema_sha256", "publicInputSchemaSha256"], `circuit identity ${index}.public_input_schema_sha256`, entry => sha256(entry, `circuit identity ${index}.public_input_schema_sha256`))
    });
  }
  return Object.freeze({
    circuit_id: circuitId,
    verifying_key_sha256: aliasValue(value, ["verifying_key_sha256", "verifyingKeySha256"], `circuit identity ${index}.verifying_key_sha256`, entry => sha256(entry, `circuit identity ${index}.verifying_key_sha256`)),
    public_input_schema_sha256: aliasValue(value, ["public_input_schema_sha256", "publicInputSchemaSha256"], `circuit identity ${index}.public_input_schema_sha256`, entry => sha256(entry, `circuit identity ${index}.public_input_schema_sha256`))
  });
}

function normalizeCircuitSetIdentity(raw, label, options) {
  const value = object(raw, label);
  const circuits = value.circuits;
  if (!Array.isArray(circuits)) throw new Error(`${label}.circuits must be an array`);
  const identity = {
    schema_version: aliasValue(value, ["schema_version", "schemaVersion"], `${label}.schema_version`, entry => text(entry, `${label}.schema_version`)),
    circuit_set_id: aliasValue(value, ["circuit_set_id", "circuitSetId"], `${label}.circuit_set_id`, entry => text(entry, `${label}.circuit_set_id`)),
    curve: text(value.curve, `${label}.curve`),
    circuits: Object.freeze(circuits.map((entry, index) => circuitIdentity(entry, index, options)))
  };
  return Object.freeze(identity);
}

function validatePinnedIdentity(identity, label) {
  if (identity.schema_version !== circuitSetIdentitySchemaVersionV1) throw new Error(`${label}.schema_version must be ${circuitSetIdentitySchemaVersionV1}`);
  if (identity.circuit_set_id !== privacyNoteV1CircuitSetId) throw new Error(`${label}.circuit_set_id must be ${privacyNoteV1CircuitSetId}`);
  if (identity.curve !== privacyNoteV1CircuitCurve) throw new Error(`${label}.curve must be ${privacyNoteV1CircuitCurve}`);
  if (identity.circuits.length !== privacyNoteV1CircuitOrder.length) throw new Error(`${label}.circuits must contain exactly ${privacyNoteV1CircuitOrder.length} entries`);
  identity.circuits.forEach((circuit, index) => {
    const expectedId = privacyNoteV1CircuitOrder[index];
    if (circuit.circuit_id !== expectedId) throw new Error(`${label}.circuits[${index}].circuit_id must be ${expectedId}`);
    const expectedSchema = privacyNoteV1PublicInputSchemaSHA256[expectedId];
    if (circuit.public_input_schema_sha256 !== expectedSchema) {
      throw new Error(`${label}.circuits[${index}].public_input_schema_sha256 does not match ${expectedId}`);
    }
  });
  return true;
}

function sameCircuitIdentity(expected, actual) {
  if (expected.schema_version !== actual.schema_version || expected.circuit_set_id !== actual.circuit_set_id || expected.curve !== actual.curve || expected.circuits.length !== actual.circuits.length) return false;
  return expected.circuits.every((circuit, index) => (
    circuit.circuit_id === actual.circuits[index].circuit_id &&
    circuit.public_input_schema_sha256 === actual.circuits[index].public_input_schema_sha256 &&
    (circuit.verifying_key_sha256 === undefined || circuit.verifying_key_sha256 === actual.circuits[index].verifying_key_sha256)
  ));
}

function validateArtifacts(raw, identity) {
  if (!Array.isArray(raw)) throw new Error("CircuitConfig.artifacts must be an array");
  if (raw.length !== identity.circuits.length) throw new Error("CircuitConfig.artifacts must match the consensus circuit identity");
  return Object.freeze(raw.map((entry, index) => {
    const value = object(entry, `CircuitConfig.artifacts[${index}]`);
    const circuitId = aliasValue(value, ["circuit_id", "circuitId"], `CircuitConfig.artifacts[${index}].circuit_id`, item => text(item, `CircuitConfig.artifacts[${index}].circuit_id`));
    const artifactType = aliasValue(value, ["artifact_type", "artifactType"], `CircuitConfig.artifacts[${index}].artifact_type`, item => text(item, `CircuitConfig.artifacts[${index}].artifact_type`));
    const digest = aliasValue(value, ["sha256", "SHA256"], `CircuitConfig.artifacts[${index}].sha256`, item => sha256(item, `CircuitConfig.artifacts[${index}].sha256`));
    if (circuitId !== identity.circuits[index].circuit_id) throw new Error(`CircuitConfig.artifacts[${index}].circuit_id does not match the consensus identity`);
    if (artifactType !== "verifying_key") throw new Error(`CircuitConfig.artifacts[${index}].artifact_type must be verifying_key`);
    if (digest !== identity.circuits[index].verifying_key_sha256) throw new Error(`CircuitConfig.artifacts[${index}].sha256 does not match the consensus verifying key`);
    return Object.freeze({ circuit_id: circuitId, artifact_type: artifactType, sha256: digest });
  }));
}

/**
 * Validate the consensus `CircuitConfig` response before preparing any proof.
 * `expectedCircuitIdentity` is an optional deployment pin; when supplied it
 * additionally binds every verifying-key hash to the caller's trusted value.
 */
export function validateCircuitConfigV1(response, { expectedCircuitIdentity } = {}) {
  const value = object(response, "CircuitConfig response");
  const identity = normalizeCircuitSetIdentity(
    value.circuit_set_identity ?? value.circuitSetIdentity,
    "CircuitConfig.circuit_set_identity"
  );
  validatePinnedIdentity(identity, "CircuitConfig.circuit_set_identity");
  const schemaVersion = aliasValue(value, ["schema_version", "schemaVersion"], "CircuitConfig.schema_version", entry => text(entry, "CircuitConfig.schema_version"));
  const activeSetId = aliasValue(value, ["active_set_id", "activeSetId"], "CircuitConfig.active_set_id", entry => text(entry, "CircuitConfig.active_set_id"));
  const curve = text(value.curve, "CircuitConfig.curve");
  const checksumSource = aliasValue(value, ["checksum_source", "checksumSource"], "CircuitConfig.checksum_source", entry => text(entry, "CircuitConfig.checksum_source"));
  if (schemaVersion !== identity.schema_version || activeSetId !== identity.circuit_set_id || curve !== identity.curve) {
    throw new Error("CircuitConfig top-level identity does not match circuit_set_identity");
  }
  if (checksumSource !== "consensus") throw new Error("CircuitConfig.checksum_source must be consensus");
  const artifacts = validateArtifacts(value.artifacts, identity);
  if (expectedCircuitIdentity !== undefined) {
    const expected = normalizeCircuitSetIdentity(expectedCircuitIdentity, "expectedCircuitIdentity", { allowMissingVerifyingKey: false });
    validatePinnedIdentity(expected, "expectedCircuitIdentity");
    if (!sameCircuitIdentity(expected, identity)) throw new Error("CircuitConfig consensus identity does not match expectedCircuitIdentity");
  }
  return Object.freeze({
    schema_version: schemaVersion,
    active_set_id: activeSetId,
    curve,
    checksum_source: checksumSource,
    circuit_set_identity: identity,
    artifacts
  });
}

/** Validate a deployment-owned full CircuitSetIdentity pin without a query response. */
export function validateExpectedCircuitIdentityV1(identity) {
  const normalized = normalizeCircuitSetIdentity(identity, "expectedCircuitIdentity", { allowMissingVerifyingKey: false });
  validatePinnedIdentity(normalized, "expectedCircuitIdentity");
  return normalized;
}
