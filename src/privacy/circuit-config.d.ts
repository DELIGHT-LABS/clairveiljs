export const circuitSetIdentitySchemaVersionV1: "v1";
export const privacyNoteV1CircuitSetId: "privacy-note-v1";
export const privacyNoteV1CircuitCurve: "BN254";
export const privacyNoteV1CircuitOrder: readonly ["deposit", "spend", "joinsplit", "batch-joinsplit-16x32-v1"];
export const privacyNoteV1PublicInputSchemaSHA256: Readonly<Record<(typeof privacyNoteV1CircuitOrder)[number], string>>;

export interface CircuitIdentityV1 {
  circuit_id?: string;
  circuitId?: string;
  verifying_key_sha256?: string;
  verifyingKeySha256?: string;
  public_input_schema_sha256?: string;
  publicInputSchemaSha256?: string;
}

export interface CircuitSetIdentityV1 {
  schema_version?: string;
  schemaVersion?: string;
  circuit_set_id?: string;
  circuitSetId?: string;
  curve: string;
  circuits: CircuitIdentityV1[];
}

export interface CircuitConfigV1 {
  schema_version?: string;
  schemaVersion?: string;
  active_set_id?: string;
  activeSetId?: string;
  curve: string;
  checksum_source?: string;
  checksumSource?: string;
  circuit_set_identity?: CircuitSetIdentityV1;
  circuitSetIdentity?: CircuitSetIdentityV1;
  artifacts: Array<{
    circuit_id?: string;
    circuitId?: string;
    artifact_type?: string;
    artifactType?: string;
    sha256?: string;
    SHA256?: string;
  }>;
}

export interface ValidatedCircuitConfigV1 {
  schema_version: "v1";
  active_set_id: "privacy-note-v1";
  curve: "BN254";
  checksum_source: "consensus";
  circuit_set_identity: {
    schema_version: "v1";
    circuit_set_id: "privacy-note-v1";
    curve: "BN254";
    circuits: ReadonlyArray<{
      circuit_id: (typeof privacyNoteV1CircuitOrder)[number];
      verifying_key_sha256: string;
      public_input_schema_sha256: string;
    }>;
  };
  artifacts: ReadonlyArray<{ circuit_id: string; artifact_type: "verifying_key"; sha256: string }>;
}

export function validateCircuitConfigV1(response: CircuitConfigV1 | object, options?: { expectedCircuitIdentity?: CircuitSetIdentityV1 }): ValidatedCircuitConfigV1;
export function validateExpectedCircuitIdentityV1(identity: CircuitSetIdentityV1): ValidatedCircuitConfigV1["circuit_set_identity"];
