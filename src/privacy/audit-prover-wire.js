import { base64FromBytes, bytesFromHex } from "../core/browser-crypto.js";
import { integerBytes, equalBytes } from "../core/encoding.js";
import { canonicalField } from "../core/curve-validation.js";
import { exactBytes, shape } from "./audit-field-v2.js";
import { FIELD_MODULUS } from "../core/crypto.js";
import { wireBytes } from "./audit-encoding.js";
import {
  auditCircuitSetIdV2,
  auditCircuitOrderV2,
} from "./audit-circuit-v2.js";
import { parseWalletJson } from "../wallet-api/json.js";

export const maxAuditWitnessBytes = 4 * 1024 * 1024;
export const maxAuditResponseBytes = 16 * 1024;
const fieldModulus = integerBytes(FIELD_MODULUS, 32);
export function auditPublicInputBytes(publicInputs) {
  if (!Array.isArray(publicInputs) || publicInputs.length !== 23)
    throw new Error("audit proof requires PI23");
  return publicInputs.map((v) =>
    integerBytes(canonicalField(v, "public input"), 32),
  );
}
export function validateFullAuditWitness(witness, publicInputs) {
  const pi = auditPublicInputBytes(publicInputs);
  if (
    !(witness instanceof Uint8Array) ||
    witness.length < 12 ||
    witness.length > maxAuditWitnessBytes
  )
    throw new Error("invalid full witness length");
  const view = new DataView(
    witness.buffer,
    witness.byteOffset,
    witness.byteLength,
  );
  const publicCount = view.getUint32(0),
    secretCount = view.getUint32(4),
    count = view.getUint32(8);
  if (
    publicCount !== 23 ||
    secretCount === 0 ||
    count !== publicCount + secretCount ||
    witness.length !== 12 + count * 32
  )
    throw new Error("full witness header or length mismatch");
  for (let i = 0; i < count; i++) {
    const field = witness.subarray(12 + i * 32, 44 + i * 32);
    // Check canonical bytes without creating extra private BigInt/field copies.
    let order = 0;
    for (let j = 0; j < 32; j++)
      if (order === 0) order = Math.sign(field[j] - fieldModulus[j]);
    if (order >= 0) throw new Error("noncanonical witness field");
    if (i < 23 && !equalBytes(field, pi[i]))
      throw new Error("witness public input mismatch");
  }
}
export function auditProofRequest(kind, snapshot, publicInputs, witness) {
  shape(kind);
  validateFullAuditWitness(witness, publicInputs);
  return {
    version: "v1",
    circuit_set_id: auditCircuitSetIdV2,
    circuit_id: auditCircuitOrderV2[kind - 1],
    artifact_hash: base64FromBytes(bytesFromHex(snapshot.artifactHash)),
    public_inputs: auditPublicInputBytes(publicInputs).map(base64FromBytes),
    witness: base64FromBytes(witness),
  };
}
// Framing only. Curve decoding and the pairing check are mandatory in the local verifier.
export function auditProofFrame(value) {
  const proof = exactBytes(value, 164, "BN254 proof");
  for (const offset of [0, 32, 96, 132])
    if ((proof[offset] & 0xc0) === 0)
      throw new Error("uncompressed proof point");
  if (new DataView(proof.buffer).getUint32(128) !== 0)
    throw new Error("proof commitments unsupported");
  return proof;
}
export function auditProofResponse(raw, request) {
  if (!(raw instanceof Uint8Array) || raw.length > maxAuditResponseBytes)
    throw new Error("prover response bound");
  const response = parseWalletJson(raw);
  const fields = [
    "version",
    "circuit_set_id",
    "circuit_id",
    "artifact_hash",
    "public_inputs",
    "proof",
  ];
  if (
    !response ||
    Array.isArray(response) ||
    Object.keys(response).length !== fields.length ||
    Object.keys(response).some((k) => !fields.includes(k))
  )
    throw new Error("prover response fields mismatch");
  for (const key of fields.slice(0, 4))
    if (response[key] !== request[key])
      throw new Error("prover response binding mismatch");
  if (
    !Array.isArray(response.public_inputs) ||
    response.public_inputs.length !== 23 ||
    response.public_inputs.some((v, i) => v !== request.public_inputs[i])
  )
    throw new Error("prover public input binding mismatch");
  if (typeof response.proof !== "string")
    throw new Error("proof must be canonical base64");
  return auditProofFrame(wireBytes(response.proof, "proof"));
}
