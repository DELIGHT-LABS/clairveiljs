import { hexFromBytes } from "../core/browser-crypto.js";
import { normalizeBech32Prefix } from "../core/crypto.js";
import { CircuitSetIdentity } from "../generated/clairveil/privacy/v1/genesis.js";
import { object, bytes, wireBytes, integer, alias, equal, maxHeight, maxUint64 } from "./audit-encoding.js";
import { validateAuditArtifactManifestV2, validateAuditCircuitIdentityV2, sameIdentity } from "./audit-circuit-v2.js";
import { computeAuditNetworkDigestV2, parseAuditKeyRecordV2 } from "./audit-key-v2.js";

export { auditCircuitSetIdV2, auditCircuitOrderV2, auditPublicInputSchemaSHA256V2,
  validateAuditArtifactManifestV2, validateAuditCircuitIdentityV2 } from "./audit-circuit-v2.js";
export { computeAuditNetworkDigestV2, parseAuditKeyRecordV2 } from "./audit-key-v2.js";

const snapshots = new WeakSet();

export function normalizeDisclosureConfigV2(response) {
  const value = object(response, "V2 disclosure configuration");
  const version = alias(value,"payload_version","payloadVersion");
  const required = alias(value,"audit_disclosure_required","auditDisclosureRequired",v=>{if(typeof v!=="boolean")throw new Error("audit requirement must be boolean");return v;});
  if(version!=="privacy-fixed-v2" || !required)throw new Error("V2 disclosure configuration required");
  const list = allowed => input => {
    if(!Array.isArray(input) || !input.includes(allowed[0]) || input.some(v=>typeof v!=="string" || !allowed.includes(v)) || new Set(input).size!==input.length)throw new Error("unsupported V2 disclosure configuration");
    return Object.freeze([...input].sort());
  };
  return Object.freeze({payload_version:version,audit_disclosure_required:required,
    supported_user_policies:alias(value,"supported_user_policies","supportedUserPolicies",list(["all-private","amount","to","amount-to","from","amount-from","from-to","amount-from-to"])),
    supported_user_modes:alias(value,"supported_user_modes","supportedUserModes",list(["none","public","recipient-encrypted"]))});
}

/** Fail-closed V2 preparation preflight. Providers must honor the height argument.
 * A consistent RPC response is not authenticated consensus provenance. */
export async function queryActiveAuditSnapshotV2({ query, chainId, accountPrefix = "clair", expectedCircuitIdentity, artifactManifestBytes,
  expectedArtifactHash, expectedNetworkNonce, expectedInitialHeight } = {}) {
  for (const method of ["configuration", "keySchedule", "key"]) {
    if (typeof query?.[method] !== "function") throw new Error(`audit query.${method} is required`);
  }
  if (typeof accountPrefix !== "string" || accountPrefix.length > 83 || normalizeBech32Prefix(accountPrefix) !== accountPrefix) throw new Error("canonical account prefix required");
  const artifact = validateAuditArtifactManifestV2(artifactManifestBytes, { expectedCircuitIdentity, expectedArtifactHash });
  // Validate and copy caller pins before awaiting an untrusted provider.
  computeAuditNetworkDigestV2(chainId, new Uint8Array(32));
  const pinnedNonce = expectedNetworkNonce === undefined ? undefined : bytes(expectedNetworkNonce, "expectedNetworkNonce", 32);
  const pinnedInitial = expectedInitialHeight === undefined ? undefined : integer(expectedInitialHeight, "expectedInitialHeight", maxHeight, 1n);
  const c = object(await query.configuration({}), "audit configuration");
  const nonce = alias(c, "network_nonce", "networkNonce", wireBytes);
  const network = computeAuditNetworkDigestV2(chainId, nonce);
  const initial = alias(c, "initial_height", "initialHeight", (v, l) => integer(v, l, maxHeight, 1n));
  const height = alias(c, "state_height", "stateHeight", (v, l) => integer(v, l, maxHeight, 1n));
  if (BigInt(height) < BigInt(initial)) throw new Error("configuration height precedes initial height");
  if (pinnedNonce && !equal(pinnedNonce, nonce)) throw new Error("audit network nonce mismatch");
  if (pinnedInitial !== undefined && pinnedInitial !== initial) throw new Error("audit initial height mismatch");
  const encodedIdentity = alias(c, "circuit_identity", "circuitIdentity", wireBytes);
  if (encodedIdentity.length > 16384) throw new Error("audit circuit identity is too large");
  const decoded = CircuitSetIdentity.decode(encodedIdentity);
  if (!equal(CircuitSetIdentity.encode(decoded).finish(), encodedIdentity)) throw new Error("audit circuit identity is not canonical protobuf");
  const identity = validateAuditCircuitIdentityV2(decoded);
  if (!sameIdentity(identity, artifact.circuitIdentity)) throw new Error("audit verifier identity does not match on-chain configuration");

  const s = object(await query.keySchedule({ height }), "audit key schedule");
  const stateHeight = alias(s, "state_height", "stateHeight", (v, l) => integer(v, l, maxHeight, 1n));
  const epoch = alias(s, "active_epoch", "activeEpoch", (v, l) => integer(v, l, maxUint64, 1n));
  if (stateHeight !== height || s.halted !== false) throw new Error("no active audit key at configuration height: halted or height mismatch");
  const nextEpoch = alias(s, "next_epoch", "nextEpoch", (v, l) => integer(v ?? "0", l));
  const nextHeight = alias(s, "next_activation_height", "nextActivationHeight", (v, l) => integer(v ?? "0", l, maxHeight));
  if ((nextEpoch === "0") !== (nextHeight === "0") || (nextEpoch !== "0" && (BigInt(nextEpoch) <= BigInt(epoch) || BigInt(nextHeight) <= BigInt(height)))) {
    throw new Error("invalid pending audit key schedule");
  }
  const response = object(await query.key({ epoch, height }), "audit key response");
  if (alias(response, "state_height", "stateHeight", (v, l) => integer(v, l, maxHeight, 1n)) !== height) throw new Error("audit key query height mismatch");
  const record = parseAuditKeyRecordV2(wireBytes(response.record, "audit key record"), { networkDigest: network, initialHeight: initial });
  if (record.epoch !== epoch || BigInt(record.activationHeight) > BigInt(height)) throw new Error("audit key schedule mismatch");
  const snapshot = Object.freeze({ chainId, accountPrefix, networkDigest: hexFromBytes(network), networkNonce: hexFromBytes(nonce), initialHeight: initial,
    circuitIdentity: identity, epoch, keyId: record.keyId, publicKey: record.publicKey, stateHeight: height,
    artifactHash: artifact.artifactHash, developmentOnly: artifact.developmentOnly, keyRecord: record,
    nextEpoch, nextActivationHeight: nextHeight });
  snapshots.add(snapshot);
  return snapshot;
}

/** Compare freshly queried snapshots before proving/broadcasting. Height may
 * advance, but a rollback or namespace change requires discarding preparation.
 * Deserialized/copied objects must be re-queried, not treated as validated. */
export function assertAuditSnapshotCurrentV2(prepared, current) {
  if (!snapshots.has(prepared) || !snapshots.has(current)) throw new Error("validated audit snapshots are required");
  if (["accountPrefix", "networkDigest", "initialHeight", "epoch", "keyId", "artifactHash"].some(key => prepared[key] !== current[key]) ||
      !sameIdentity(prepared.circuitIdentity, current.circuitIdentity)) throw new Error("prepared audit namespace changed; prepare again");
  if (BigInt(current.stateHeight) < BigInt(prepared.stateHeight)) throw new Error("audit snapshot height is stale");
  return current;
}
