import { readFileSync } from "node:fs";
import { queryActiveAuditSnapshotV2 } from "clairveiljs/audit-config-v2";
import { prepareAuditAuthorizationV2 } from "clairveiljs/audit-authorization-v2";
import { bytesFromHex } from "clairveiljs/browser-crypto";
export const vectors = JSON.parse(
  readFileSync(
    new URL(
      "../../fixtures/clairveil-v0.6.1-audit-authorization/vectors.json",
      import.meta.url,
    ),
  ),
);
export const config = JSON.parse(
  readFileSync(
    new URL(
      "../../fixtures/clairveil-v0.6.1-audit/vectors.json",
      import.meta.url,
    ),
  ),
);
const bytes = (s) => (s ? bytesFromHex(s) : new Uint8Array());
export async function snapshot(index = 1) {
  const row = config.records[index];
  return queryActiveAuditSnapshotV2({
    chainId: config.chain_id,
    expectedCircuitIdentity: config.identity,
    artifactManifestBytes: Buffer.from(config.manifest_base64, "base64"),
    expectedArtifactHash: config.artifact_hash,
    query: {
      configuration: async () => ({
        networkNonce: bytes(config.network_nonce_hex),
        initialHeight: "10",
        circuitIdentity: Buffer.from(config.identity_base64, "base64"),
        stateHeight: row.state_height,
      }),
      keySchedule: async () => ({
        activeEpoch: row.epoch,
        nextEpoch: "0",
        nextActivationHeight: "0",
        halted: false,
        stateHeight: row.state_height,
      }),
      key: async () => ({
        record: bytes(row.record_hex),
        stateHeight: row.state_height,
      }),
    },
  });
}
export function data(row) {
  const common = {
    creator: row.creator,
    expiresAtUnix: BigInt(row.expiresAtUnix),
  };
  const outputs = row.outputs.map((o) =>
    Object.fromEntries(
      Object.entries(o).map(([k, v]) => [
        k,
        typeof v === "number" ? v : bytes(v),
      ]),
    ),
  );
  if (row.kind === 1)
    return { ...common, amount: row.amount, output: outputs[0] };
  if (row.kind === 2)
    return {
      ...common,
      amount: row.amount,
      recipient: row.recipient,
      root: bytes(row.root),
      nullifier: bytes(row.nullifiers[0]),
    };
  return {
    ...common,
    root: bytes(row.root),
    nullifiers: row.nullifiers.map(bytes),
    outputs,
  };
}
const options = async (row) => ({
  kind: row.kind,
  snapshot: await snapshot(),
  message: data(row),
});

export async function preparedCase(row = vectors.cases[0], overrides = {}) {
  const o = await options(row);
  const prepared = await prepareAuditAuthorizationV2({
    ...o,
    plaintext: row.plaintext.map(bytes),
    backend: {
      encrypt: async () => ({
        envelope: bytes(row.envelope),
        witness: bytes(row.syntheticWitness),
      }),
    },
    getCurrentSnapshot: async () => o.snapshot,
    now: () => 1n,
    ...overrides,
  });
  return { prepared, snapshot: o.snapshot, row };
}
export function fullWitness(pi, secretCount = 1) {
  const b = Buffer.alloc(12 + (23 + secretCount) * 32);
  b.writeUInt32BE(23, 0);
  b.writeUInt32BE(secretCount, 4);
  b.writeUInt32BE(23 + secretCount, 8);
  pi.forEach((v, i) =>
    b.set(bytesFromHex(BigInt(v).toString(16).padStart(64, "0")), 12 + i * 32),
  );
  return b;
}
export function framedProof() {
  const b = Buffer.alloc(164);
  for (const i of [0, 32, 96, 132]) b[i] = 0x40;
  return b;
}
export function reply(request, proof = framedProof()) {
  const { witness, ...rest } = request;
  return { ...rest, proof: proof.toString("base64") };
}
