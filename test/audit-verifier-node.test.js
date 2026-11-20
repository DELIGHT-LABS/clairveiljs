import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createAuditNativeVerifierV2 } from "clairveiljs/audit-verifier-node";
import { createAuditProverV2 } from "clairveiljs/audit-prover-v2";
import { prepareAuditAuthorizationV2 } from "clairveiljs/audit-authorization-v2";
import { queryActiveAuditSnapshotV2 } from "clairveiljs/audit-config-v2";
import { MsgDeposit } from "clairveiljs/generated/clairveil/privacy/v2/tx.js";
import { config, framedProof } from "./helpers/audit-prover.js";
const directory = process.env.CLAIRVEIL_AUDIT_PROOF_FIXTURES;
const sha = (b) => createHash("sha256").update(b).digest("hex");
test("native verifier fails closed on executable and artifact pins before accepting proof work", async () => {
  const dir = mkdtempSync(join(tmpdir(), "audit-verifier-negative-"));
  try {
    const path = join(dir, "verify");
    writeFileSync(path, "#!/bin/sh\necho CVV2\n", { mode: 0o700 });
    const options = {
      executablePath: path,
      sha256: sha(readFileSync(path)),
      artifactDirectory: dir,
      expectedArtifactHash: config.artifact_hash,
      expectedCircuitIdentity: config.identity,
    };
    await assert.rejects(
      createAuditNativeVerifierV2({ ...options, sha256: "0".repeat(64) }),
      /hash/,
    );
    await assert.rejects(createAuditNativeVerifierV2(options), /artifact/);
    writeFileSync(
      join(dir, "privacy_zk_manifest.json"),
      Buffer.from(config.manifest_base64, "base64"),
    );
    await assert.rejects(createAuditNativeVerifierV2(options), /artifact|key/);
    await assert.rejects(
      createAuditNativeVerifierV2({
        ...options,
        expectedArtifactHash: "0".repeat(64),
      }),
      /hash|digest/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test(
  "native process deadline, in-flight abort, output bounds and stderr are enforced",
  { skip: !directory },
  async () => {
    const manifest = readFileSync(join(directory, "privacy_zk_manifest.json"));
    const identity = JSON.parse(manifest).circuit_set_identity;
    const row = JSON.parse(readFileSync(join(directory, "proof-1.json")));
    const input = {
      kind: 1,
      artifactHash: sha(manifest),
      circuitIdentity: identity,
      publicInputs: row.publicInputs.map(BigInt),
      proof: Buffer.from(row.proof, "base64"),
    };
    const temp = mkdtempSync(join(tmpdir(), "audit-verifier-process-"));
    try {
      for (const [name, script, pattern] of [
        ["timeout", "while :; do :; done", /timed out/],
        ["stderr", "echo private-diagnostic >&2; exit 1", /verification/],
        ["overflow", "while :; do echo too-long; done", /bound/],
        ["truncated", "printf CVV", /verification/],
      ]) {
        const executable = join(temp, name);
        writeFileSync(executable, "#!/bin/sh\n" + script + "\n", {
          mode: 0o700,
        });
        const verifier = await createAuditNativeVerifierV2({
          executablePath: executable,
          sha256: sha(readFileSync(executable)),
          artifactDirectory: directory,
          expectedArtifactHash: sha(manifest),
          expectedCircuitIdentity: identity,
          timeoutMs: name === "timeout" ? 100 : 5000,
        });
        await assert.rejects(
          verifier.verify(input),
          (e) =>
            pattern.test(e.message) &&
            !e.message.includes("private-diagnostic"),
        );
        if (name === "timeout") {
          const c = new AbortController();
          const pending = verifier.verify({ ...input, signal: c.signal });
          setTimeout(() => c.abort(), 20);
          await assert.rejects(pending, /aborted/);
        }
      }
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  },
);

test(
  "JS authorization → actual Core HTTP prover → pinned local verification → V2 message",
  { skip: !directory },
  async () => {
    const fixture = JSON.parse(readFileSync(join(directory, "deposit.json")));
    const manifest = readFileSync(join(directory, "privacy_zk_manifest.json"));
    const identity = JSON.parse(manifest).circuit_set_identity;
    const row = config.records[1];
    const query = () =>
      queryActiveAuditSnapshotV2({
        chainId: config.chain_id,
        expectedCircuitIdentity: identity,
        artifactManifestBytes: manifest,
        expectedArtifactHash: sha(manifest),
        query: {
          configuration: async () => ({
            networkNonce: Buffer.from(config.network_nonce_hex, "hex"),
            initialHeight: "10",
            circuitIdentity: Buffer.from(fixture.identityBytes, "base64"),
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
            record: Buffer.from(row.record_hex, "hex"),
            stateHeight: row.state_height,
          }),
        },
      });
    const snapshot = await query();
    const verifier = await createAuditNativeVerifierV2({
      executablePath: process.env.CLAIRVEIL_AUDIT_VERIFIER_BINARY,
      sha256: process.env.CLAIRVEIL_AUDIT_VERIFIER_SHA256,
      artifactDirectory: directory,
      expectedArtifactHash: snapshot.artifactHash,
      expectedCircuitIdentity: snapshot.circuitIdentity,
    });
    const {
      proof: unused,
      audit: unusedAudit,
      ...message
    } = MsgDeposit.fromPartial({
      ...fixture.message,
      expiresAtUnix: BigInt(fixture.message.expiresAtUnix),
      output: {
        commitment: Buffer.from(fixture.message.output.commitment, "base64"),
        ciphertext: Buffer.from(fixture.message.output.ciphertext, "base64"),
      },
    });
    const prepared = await prepareAuditAuthorizationV2({
      kind: 1,
      snapshot,
      message,
      plaintext: fixture.plaintext.map((s) => Buffer.from(s, "base64")),
      backend: {
        encrypt: async () => ({
          envelope: Buffer.from(fixture.envelope, "base64"),
          witness: Buffer.from(fixture.syntheticWitness, "base64"),
        }),
      },
      getCurrentSnapshot: query,
    });
    const witness = Buffer.from(fixture.request.witness, "base64");
    const prover = createAuditProverV2({
      baseUrl: fixture.baseUrl,
      verifier,
      timeoutMs: 120000,
    });
    const result = await prover.prove({ prepared, witness });
    assert(witness.every((v) => v === 0));
    assert.throws(() => prepared.exportEncryptionWitness(), /cleared/);
    assert.equal(result.proof.length, 164);
    assert.equal(result.amount, "100000000000000000000uclair");
    assert.equal(result.audit.epoch, BigInt(row.epoch));
    assert.deepEqual(
      MsgDeposit.decode(MsgDeposit.encode(result).finish()),
      result,
    );
  },
);
test(
  "actual Core four-circuit proofs pass native verification; PI, key, circuit and proof swaps fail",
  { skip: !directory },
  async () => {
    const manifest = readFileSync(join(directory, "privacy_zk_manifest.json"));
    const identity = JSON.parse(manifest).circuit_set_identity;
    const options = {
      executablePath: process.env.CLAIRVEIL_AUDIT_VERIFIER_BINARY,
      sha256: process.env.CLAIRVEIL_AUDIT_VERIFIER_SHA256,
      artifactDirectory: directory,
      expectedArtifactHash: sha(manifest),
      expectedCircuitIdentity: identity,
    };
    const verifier = await createAuditNativeVerifierV2(options);
    for (const kind of [1, 2, 3, 4]) {
      const row = JSON.parse(
        readFileSync(join(directory, `proof-${kind}.json`)),
      );
      const input = {
        kind,
        artifactHash: sha(manifest),
        circuitIdentity: identity,
        publicInputs: row.publicInputs.map(BigInt),
        proof: Buffer.from(row.proof, "base64"),
      };
      assert.equal(await verifier.verify(input), true);
      for (const mutate of [
        (x) => ({ ...x, kind: (kind % 4) + 1 }),
        (x) => ({ ...x, artifactHash: "1".repeat(64) }),
        (x) => ({ ...x, proof: framedProof() }),
        (x) => ({ ...x, proof: x.proof.subarray(1) }),
        (x) => {
          const b = Uint8Array.from(x.proof);
          b[31] ^= 1;
          return { ...x, proof: b };
        },
      ])
        await assert.rejects(verifier.verify(mutate(input)));
      for (let i = 0; i < 23; i++) {
        const publicInputs = input.publicInputs.slice();
        publicInputs[i]++;
        await assert.rejects(verifier.verify({ ...input, publicInputs }));
      }
      const changed = structuredClone(identity);
      changed.circuits[kind - 1].verifying_key_sha256 = "1".repeat(64);
      await assert.rejects(
        verifier.verify({ ...input, circuitIdentity: changed }),
      );
      const c = new AbortController();
      c.abort();
      await assert.rejects(
        verifier.verify({ ...input, signal: c.signal }),
        /abort/,
      );
    }
    const temp = mkdtempSync(join(tmpdir(), "audit-verifier-artifacts-"));
    try {
      writeFileSync(join(temp, "privacy_zk_manifest.json"), manifest);
      for (const descriptor of JSON.parse(manifest).artifacts.filter(
        (d) => d.artifact_type === "verifying_key",
      )) {
        const vk = readFileSync(join(directory, descriptor.filename));
        vk[0] ^= 1;
        writeFileSync(join(temp, descriptor.filename), vk);
      }
      await assert.rejects(
        createAuditNativeVerifierV2({ ...options, artifactDirectory: temp }),
        /key|hash/,
      );
      writeFileSync(
        join(temp, "privacy_zk_manifest.json"),
        Buffer.concat([manifest, Buffer.from(" ")]),
      );
      await assert.rejects(
        createAuditNativeVerifierV2({ ...options, artifactDirectory: temp }),
        /digest/,
      );
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  },
);
