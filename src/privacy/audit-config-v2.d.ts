export const auditCircuitSetIdV2: "privacy-note-v1-u128-audit-field-v1";
export const auditCircuitOrderV2: readonly ["deposit-audit-field-u128-v1", "spend-audit-field-u128-v1", "joinsplit-2x2-audit-field-u128-v1", "batch-joinsplit-16x32-audit-field-u128-v1"];
export const auditPublicInputSchemaSHA256V2: Readonly<Record<(typeof auditCircuitOrderV2)[number], string>>;
export interface AuditCircuitIdentityV2 {
  readonly schema_version: "v1";
  readonly circuit_set_id: typeof auditCircuitSetIdV2;
  readonly curve: "BN254";
  readonly circuits: ReadonlyArray<{
    readonly circuit_id: (typeof auditCircuitOrderV2)[number];
    readonly verifying_key_sha256: string;
    readonly public_input_schema_sha256: string;
  }>;
}
/** Snake/camel case deployment pin input; runtime requires all hashes and detects alias conflicts. */
export interface AuditCircuitIdentityInputV2 {
  readonly schema_version?: string; readonly schemaVersion?: string;
  readonly circuit_set_id?: string; readonly circuitSetId?: string;
  readonly curve: string;
  readonly circuits: ReadonlyArray<{
    readonly circuit_id?: string; readonly circuitId?: string;
    readonly verifying_key_sha256?: string; readonly verifyingKeySha256?: string;
    readonly public_input_schema_sha256?: string; readonly publicInputSchemaSha256?: string;
  }>;
}
export interface AuditKeyRecordV2 {
  readonly epoch: string;
  /** Lowercase SHA256 hex. */
  readonly keyId: string;
  /** Canonical Point64, x||y big-endian, lowercase hex. */
  readonly publicKey: string;
  readonly activationHeight: string;
  readonly registeredHeight: string;
  readonly origin: Readonly<{ kind: 1 | 2 | 3; anchor: string; height: string }>;
  /** Validated PoP96 bytes as lowercase hex. */
  readonly possessionProof: string;
}
declare const auditSnapshotBrand: unique symbol;
/** Immutable public state; no private keys/witnesses. Integers remain decimal strings. */
export interface AuditSnapshotV2 {
  readonly [auditSnapshotBrand]: true;
  readonly chainId: string;
  readonly accountPrefix: string;
  readonly networkDigest: string;
  readonly networkNonce: string;
  readonly initialHeight: string;
  readonly circuitIdentity: AuditCircuitIdentityV2;
  readonly epoch: string;
  readonly keyId: string;
  readonly publicKey: string;
  readonly stateHeight: string;
  readonly artifactHash: string;
  readonly developmentOnly: boolean;
  readonly keyRecord: AuditKeyRecordV2;
  readonly nextEpoch: string;
  readonly nextActivationHeight: string;
}
/** Implementations must honor height; results may be REST snake_case/base64 or generated camelCase/bytes/bigint. */
export interface AuditQueryProviderV2 {
  configuration(options: Record<string, never>): Promise<object>;
  keySchedule(options: { height: string }): Promise<object>;
  key(options: { epoch: string; height: string }): Promise<object>;
}
export interface AuditSnapshotOptionsV2 {
  /** Host SDK address codec prefix; defaults to clair. Explicitly pin maroo for Maroo. */
  accountPrefix?: string;
  expectedCircuitIdentity: AuditCircuitIdentityInputV2;
  /** Exact local manifest bytes, never a server-provided label. */
  artifactManifestBytes: Uint8Array;
  /** Independently pinned SHA256 of the exact local manifest bytes. */
  expectedArtifactHash: string;
  expectedNetworkNonce?: Uint8Array;
  expectedInitialHeight?: string | bigint;
}
export function computeAuditNetworkDigestV2(chainId: string, networkNonce: Uint8Array): Uint8Array;
export function validateAuditCircuitIdentityV2(identity: AuditCircuitIdentityInputV2): AuditCircuitIdentityV2;
/** Metadata validation only: does not load artifact files or qualify their setup. */
export function validateAuditArtifactManifestV2(bytes: Uint8Array, options: Pick<AuditSnapshotOptionsV2, "expectedCircuitIdentity" | "expectedArtifactHash">): Readonly<{artifactHash: string; circuitIdentity: AuditCircuitIdentityV2; developmentOnly: boolean}>;
export function parseAuditKeyRecordV2(bytes: Uint8Array, options: {networkDigest: Uint8Array; initialHeight: string | bigint}): AuditKeyRecordV2;
/** Validated RPC consistency is not authenticated chain provenance. No transaction/proof is created. */
export function queryActiveAuditSnapshotV2(options: AuditSnapshotOptionsV2 & {query: AuditQueryProviderV2; chainId: string}): Promise<AuditSnapshotV2>;
/** Re-query before each sensitive step; copied/deserialized snapshots are rejected. */
export function assertAuditSnapshotCurrentV2(prepared: AuditSnapshotV2, current: AuditSnapshotV2): AuditSnapshotV2;
export function normalizeDisclosureConfigV2(response:object):Readonly<{payload_version:"privacy-fixed-v2";audit_disclosure_required:true;supported_user_policies:readonly string[];supported_user_modes:readonly string[]}>;
