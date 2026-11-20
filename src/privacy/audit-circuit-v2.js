import { sha256Hex } from "../core/browser-crypto.js";
import { object, bytes, hexDigest, text, alias } from "./audit-encoding.js";

export const auditCircuitSetIdV2 = "privacy-note-v1-u128-audit-field-v1";
export const auditCircuitOrderV2 = Object.freeze([
  "deposit-audit-field-u128-v1", "spend-audit-field-u128-v1",
  "joinsplit-2x2-audit-field-u128-v1", "batch-joinsplit-16x32-audit-field-u128-v1"
]);
export const auditPublicInputSchemaSHA256V2 = Object.freeze(Object.fromEntries(auditCircuitOrderV2.map((id, i) => [id, [
  "80b74ba0aa18f13e9379bf18df7a7828f1d0ae997da8339dc47dc88a5306ca9c",
  "6e7576dea2a86f54d8606f0c88d64b5b814b5f4c36c0889dcc54af4a63546ce7",
  "1a2108c9101745f83aca90d0aca2f90cca143243c58364732c879329883518b7",
  "e405f7e1c0bbed8168a93d9853ec6da3cb7acd5c35bb593e597a2839cebfd724"
][i]])));
/** Full, deployment-owned verifier pin. No missing VK hashes or V1 fallback. */
export function validateAuditCircuitIdentityV2(raw) {
  const value = object(raw, "audit circuit identity");
  const identity = {
    schema_version: alias(value, "schema_version", "schemaVersion"),
    circuit_set_id: alias(value, "circuit_set_id", "circuitSetId"),
    curve: text(value.curve, "curve")
  };
  if (identity.schema_version !== "v1" || identity.circuit_set_id !== auditCircuitSetIdV2 || identity.curve !== "BN254") {
    throw new Error("audit circuit identity version, set or curve mismatch");
  }
  if (!Array.isArray(value.circuits) || value.circuits.length !== 4) throw new Error("audit circuit identity requires four circuits");
  identity.circuits = Object.freeze(value.circuits.map((rawCircuit, index) => {
    const c = object(rawCircuit, "audit circuit");
    const result = {
      circuit_id: alias(c, "circuit_id", "circuitId"),
      verifying_key_sha256: alias(c, "verifying_key_sha256", "verifyingKeySha256", hexDigest),
      public_input_schema_sha256: alias(c, "public_input_schema_sha256", "publicInputSchemaSha256", hexDigest)
    };
    if (result.circuit_id !== auditCircuitOrderV2[index] || result.public_input_schema_sha256 !== auditPublicInputSchemaSHA256V2[result.circuit_id]) {
      throw new Error("audit circuit identity order or public input schema mismatch");
    }
    return Object.freeze(result);
  }));
  return Object.freeze(identity);
}
export function sameIdentity(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

/** Validate manifest metadata and hash its exact local bytes, as Core's CLI does.
 * This does not load R1CS/PK/VK files or verify a trusted setup/proof. */
export function validateAuditArtifactManifestV2(raw, { expectedCircuitIdentity, expectedArtifactHash } = {}) {
  const identity = validateAuditCircuitIdentityV2(expectedCircuitIdentity);
  const hash = hexDigest(expectedArtifactHash, "expectedArtifactHash");
  if (/^0+$/.test(hash)) throw new Error("artifact hash must be nonzero");
  const manifestBytes = bytes(raw, "artifactManifestBytes");
  const artifactHash = sha256Hex(manifestBytes);
  if (artifactHash !== hash) throw new Error("local artifact manifest digest mismatch");
  const m = object(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes)), "artifact manifest");
  const allowed = ["development_only", "schema_version", "generated_at", "curve", "active_set_id", "artifact_dir", "artifacts", "circuit_set_identity"];
  if (Object.keys(m).some(key => !allowed.includes(key))) throw new Error("unknown artifact manifest field");
  if (m.schema_version !== "v2" || m.curve !== "BN254" || m.active_set_id !== auditCircuitSetIdV2) throw new Error("audit artifact manifest version, set or curve mismatch");
  if (m.development_only !== undefined && typeof m.development_only !== "boolean") throw new Error("invalid development_only marker");
  for (const key of ["generated_at", "artifact_dir"]) if (m[key] !== undefined && typeof m[key] !== "string") throw new Error(`invalid manifest ${key}`);
  if (!sameIdentity(validateAuditCircuitIdentityV2(m.circuit_set_identity), identity)) throw new Error("artifact circuit identity mismatch");
  if (!Array.isArray(m.artifacts) || m.artifacts.length !== 12) throw new Error("audit artifact manifest requires exactly 12 descriptors");
  m.artifacts.forEach((rawDescriptor, index) => {
    const d = object(rawDescriptor, "artifact descriptor"), circuit = identity.circuits[Math.floor(index / 3)];
    const stem = circuit.circuit_id.replaceAll("-", "_");
    const [kind, suffix] = [["r1cs", "r1cs"], ["proving_key", "pk"], ["verifying_key", "vk"]][index % 3];
    if (Object.keys(d).some(key => !["circuit_id", "artifact_type", "filename", "checksum_env", "sha256"].includes(key)) ||
        d.circuit_id !== circuit.circuit_id || d.artifact_type !== kind || d.filename !== `privacy_${stem}_${suffix}.bin` ||
        d.checksum_env !== `CLAIRVEIL_${stem.toUpperCase()}_${suffix.toUpperCase()}_SHA256`) throw new Error("audit artifact descriptor mismatch");
    hexDigest(d.sha256, "artifact SHA256");
    if (kind === "verifying_key" && d.sha256 !== circuit.verifying_key_sha256) throw new Error("artifact verifying key mismatch");
  });
  return Object.freeze({ artifactHash, circuitIdentity: identity, developmentOnly: m.development_only ?? false });
}
