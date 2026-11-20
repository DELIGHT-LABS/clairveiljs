import test from "node:test";
import { fromBech32, toBech32 } from "@cosmjs/encoding";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { inspect } from "node:util";
import { queryActiveAuditSnapshotV2 } from "clairveiljs/audit-config-v2";
import {
  createAuditOutputEffectV2,
  encodeAuditAuxV2,
  buildAuditPublicInputsV2,
  parseAuditEnvelopeV2,
  computeAuditContextHashV2,
  computeAuditOwnerIntentV2,
  prepareAuditAuthorizationV2,
  verifyAuditMessageBindingV2,
} from "clairveiljs/audit-authorization-v2";
import { bytesFromHex, hexFromBytes } from "clairveiljs/browser-crypto";
import { FIELD_MODULUS } from "clairveiljs/crypto";
const vectors = JSON.parse(
  readFileSync(
    new URL(
      "../fixtures/clairveil-v0.6.1-audit-authorization/vectors.json",
      import.meta.url,
    ),
  ),
);
const config = JSON.parse(
  readFileSync(
    new URL("../fixtures/clairveil-v0.6.1-audit/vectors.json", import.meta.url),
  ),
);
const bytes = (s) => (s ? bytesFromHex(s) : new Uint8Array());
async function snapshot(index = 1, accountPrefix = "clair") {
  const row = config.records[index];
  return queryActiveAuditSnapshotV2({
    chainId: config.chain_id, accountPrefix,
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
function data(row) {
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
for (const row of vectors.cases)
  test(`Core semantic vector: ${row.name}`, async () => {
    const o = await options(row);
    const outputs =
      row.kind === 1 ? [o.message.output] : (o.message.outputs ?? []);
    assert.equal(hexFromBytes(encodeAuditAuxV2(row.kind, outputs)), row.aux);
    for (let i = 0; i < outputs.length; i++)
      assert.deepEqual(
        createAuditOutputEffectV2(row.kind, i, outputs[i]),
        outputs[i],
      );
    const pi = buildAuditPublicInputsV2(o);
    assert.deepEqual(pi.map(String), row.publicInputs.slice(0, 21));
    const message = {
      ...o.message,
      audit: {
        keyId: bytes(o.snapshot.keyId),
        epoch: BigInt(o.snapshot.epoch),
        envelope: bytes(row.envelope),
      },
    };
    const final = buildAuditPublicInputsV2({ ...o, message });
    assert.deepEqual(final.map(String), row.publicInputs);
    assert.equal(
      hexFromBytes(
        computeAuditContextHashV2(row.kind, pi, bytes(row.envelope)),
      ),
      row.contextHash,
    );
    assert.equal(
      hexFromBytes(
        computeAuditOwnerIntentV2(row.kind, final, bytes(row.envelope)),
      ),
      row.ownerIntent,
    );
    assert.equal(
      verifyAuditMessageBindingV2({ ...o, message, publicInputs: final }),
      true,
    );
    for (const mutate of [
      (m) => m.expiresAtUnix++,
      (m) => (m.audit.envelope[m.audit.envelope.length - 1] ^= 1),
      (m) => (m.audit.keyId[0] ^= 1),
      (m) => m.audit.epoch++,
      ...(row.kind < 3
        ? [(m) => (m.amount = "8uclair")]
        : [(m) => m.outputs.reverse(), (m) => m.nullifiers.reverse()]),
    ]) {
      const altered = structuredClone(message);
      mutate(altered);
      if (
        JSON.stringify(altered, (_, v) =>
          typeof v === "bigint" ? String(v) : v,
        ) ===
        JSON.stringify(message, (_, v) =>
          typeof v === "bigint" ? String(v) : v,
        )
      )
        continue;
      assert.throws(() =>
        verifyAuditMessageBindingV2({
          ...o,
          message: altered,
          publicInputs: final,
        }),
      );
    }
  });
test("strict framing rejects noncanonical fields, points, kind, count, padding and length", () => {
  for (const row of vectors.cases) {
    const pi = row.publicInputs.map(BigInt);
    const check = (wire) =>
      parseAuditEnvelopeV2(row.kind, Number(pi[9]), Number(pi[10]), wire);
    const wire = bytes(row.envelope);
    assert.throws(() => check(wire.subarray(1)));
    assert.throws(() => check(new Uint8Array([...wire, 0])));
    for (const offset of [0, 16, 18, 20, 21, 22, 23, 31]) {
      const bad = wire.slice();
      bad[offset] ^= 1;
      assert.throws(() => check(bad));
    }
    const bad = wire.slice();
    bad.set(bytes(FIELD_MODULUS.toString(16).padStart(64, "0")), 112);
    assert.throws(() => check(bad));
    bad.set(wire);
    bad.fill(0, 48, 112);
    bad[111] = 1;
    assert.throws(() => check(bad));
  }
});
test("effect validation rejects disclosure mismatches, duplicates and ignored aliases", async () => {
  const row = vectors.cases.find((x) => x.name === "transfer-public");
  const o = await options(row);
  for (const change of [
    (m) => (m.outputs[0].userPrivacyPolicy = 2),
    (m) => (m.outputs[0].userDisclosureDigest[31] ^= 1),
    (m) => (m.outputs[0].commitment[31] ^= 1),
    (m) => (m.outputs[0].userDisclosurePayload[10] ^= 1),
    (m) => (m.outputs[1].selfFullDisclosureDigest = new Uint8Array(32)),
    (m) => (m.outputs[0].auditCiphertext = new Uint8Array(32)),
    (m) => (m.outputs[1] = structuredClone(m.outputs[0])),
    (m) => (m.nullifiers[1] = m.nullifiers[0]),
  ]) {
    const message = structuredClone(o.message);
    change(message);
    assert.throws(() => buildAuditPublicInputsV2({ ...o, message }));
  }
  for (const amount of [
    "00uclair",
    "-1uclair",
    "1.0uclair",
    "340282366920938463463374607431768211456uclair",
  ]) {
    const dep = await options(vectors.cases[0]);
    assert.throws(() =>
      buildAuditPublicInputsV2({ ...dep, message: { ...dep.message, amount } }),
    );
  }
  const dep = await options(vectors.cases[0]);
  assert.throws(() =>
    buildAuditPublicInputsV2({ ...dep, snapshot: { ...dep.snapshot } }),
  );
  assert.throws(() =>
    buildAuditPublicInputsV2({
      ...dep,
      message: { ...dep.message, creator: dep.message.creator.toUpperCase() },
    }),
  );
  const wd = await options(vectors.cases[2]);
  assert.throws(() =>
    buildAuditPublicInputsV2({
      ...wd,
      message: { ...wd.message, amount: "0uclair" },
    }),
  );
});
test("preparation owns detached bytes, keeps witness private, rechecks snapshot and expires/clears", async () => {
  const row = vectors.cases[3];
  const o = await options(row);
  const plain = row.plaintext.map(bytes);
  let calls = 0;
  let request;
  const backend = {
    encrypt: async (r) => {
      request = r;
      calls++;
      return {
        envelope: bytes(row.envelope),
        witness: bytes(row.syntheticWitness),
      };
    },
  };
  const p = await prepareAuditAuthorizationV2({
    ...o,
    plaintext: plain,
    backend,
    getCurrentSnapshot: async () => o.snapshot,
    now: () => 1900000000n,
  });
  assert.equal(calls, 1);
  assert(request.plaintext.every((v) => v === 0));
  assert(plain[0].some((v) => v !== 0));
  assert.throws(() => JSON.stringify(p), /serializ/);
  assert(!inspect(p).includes(row.syntheticWitness));
  const msg = p.messageData();
  const pi = p.publicInputs();
  assert.deepEqual(pi.map(String), row.publicInputs);
  assert.equal(hexFromBytes(p.exportEncryptionWitness()), row.syntheticWitness);
  msg.root[0] ^= 1;
  pi[0] = 0n;
  o.message.root[0] ^= 1;
  assert.equal(hexFromBytes(p.messageData().root), row.root);
  assert.throws(() => p.assertMessageBinding(msg), /binding/);
  const relayed = p.messageData();
  relayed.creator = vectors.cases[2].recipient;
  assert.throws(() => p.assertMessageBinding(relayed), /creator|binding/);
  p.clear();
  assert.throws(() => p.exportEncryptionWitness(), /clear/);
  assert.throws(() => p.messageData(), /clear/);
  p.clear();
  await assert.rejects(
    prepareAuditAuthorizationV2({
      ...(await options(row)),
      plaintext: plain,
      backend,
      getCurrentSnapshot: async () => await snapshot(0),
      now: () => 1900000000n,
    }),
    /snapshot|changed|mismatch/,
  );
  await assert.rejects(
    prepareAuditAuthorizationV2({
      ...(await options(row)),
      plaintext: plain,
      backend,
      getCurrentSnapshot: async () => o.snapshot,
      now: () => 2000000000n,
    }),
    /expir/,
  );
});
test("abort and backend failures cannot return preparation or retain owned plaintext", async () => {
  const row = vectors.cases[0];
  const o = await options(row);
  const c = new AbortController();
  let request;
  await assert.rejects(
    prepareAuditAuthorizationV2({
      ...o,
      plaintext: row.plaintext.map(bytes),
      getCurrentSnapshot: async () => o.snapshot,
      now: () => 1900000000n,
      signal: c.signal,
      backend: {
        encrypt: async (r) => {
          request = r;
          c.abort();
          return {
            envelope: bytes(row.envelope),
            witness: bytes(row.syntheticWitness),
          };
        },
      },
    }),
    /abort/i,
  );
  assert(request.plaintext.every((v) => v === 0));
  await assert.rejects(
    prepareAuditAuthorizationV2({
      ...o,
      plaintext: row.plaintext.map(bytes),
      getCurrentSnapshot: async () => o.snapshot,
      now: () => 1900000000n,
      backend: {
        encrypt: async (r) => {
          request = r;
          throw new Error("synthetic backend failure");
        },
      },
    }),
  );
  assert(request.plaintext.every((v) => v === 0));
});
test("Aux rejects incomplete deposit/transfer and empty batch shapes", () => {
  for (const kind of [1, 3, 4])
    assert.throws(() => encodeAuditAuxV2(kind, []), /count|capacity/);
  const transfer = data(vectors.cases[3]);
  assert.throws(
    () => encodeAuditAuxV2(3, transfer.outputs.slice(0, 1)),
    /count|capacity/,
  );
});
test("rotation after encryption discards witness and expiry or refresh failure clears preparation", async () => {
  const row = vectors.cases[0];
  const o = await options(row);
  let returned;
  const backend = {
    encrypt: async () =>
      (returned = {
        envelope: bytes(row.envelope),
        witness: bytes(row.syntheticWitness),
      }),
  };
  let queries = 0;
  await assert.rejects(
    prepareAuditAuthorizationV2({
      ...o,
      plaintext: row.plaintext.map(bytes),
      backend,
      getCurrentSnapshot: async () =>
        ++queries === 1 ? o.snapshot : await snapshot(0),
      now: () => 1900000000n,
    }),
  );
  assert(returned.witness.every((v) => v === 0));
  let time = 1900000000n;
  const p = await prepareAuditAuthorizationV2({
    ...o,
    plaintext: row.plaintext.map(bytes),
    backend,
    getCurrentSnapshot: async () => o.snapshot,
    now: () => time,
  });
  time = 2000000000n;
  assert.throws(() => p.publicInputs(), /expired/);
  time = 1900000000n;
  assert.throws(() => p.exportEncryptionWitness(), /cleared/);
  let fail = false;
  const q = await prepareAuditAuthorizationV2({
    ...o,
    plaintext: row.plaintext.map(bytes),
    backend,
    getCurrentSnapshot: async () => {
      if (fail) throw new Error("fresh chain unavailable");
      return o.snapshot;
    },
    now: () => 1900000000n,
  });
  fail = true;
  await assert.rejects(q.assertCurrent());
  assert.throws(() => q.messageData(), /cleared/);
});
test("Core-sized Cosmos addresses use a finite explicit Bech32 length bound", async () => {
  const { toBech32 } = await import("@cosmjs/encoding");
  const o = await options(vectors.cases[0]);
  const creator = toBech32("clair", new Uint8Array(255).fill(7), 420);
  assert.equal(
    buildAuditPublicInputsV2({ ...o, message: { ...o.message, creator } })
      .length,
    21,
  );
  const overlong = toBech32("clair", new Uint8Array(256).fill(7), 1024);
  assert.throws(() =>
    buildAuditPublicInputsV2({
      ...o,
      message: { ...o.message, creator: overlong },
    }),
  );
});


test("audit addresses use the pinned host prefix for Cosmos and Maroo EVM", async () => {
  const core = await snapshot(), maroo = await snapshot(1, "maroo");
  for (const row of vectors.cases.filter(row => row.kind <= 3)) {
    const message = data(row), mapped = { ...message, creator: toBech32("maroo", fromBech32(message.creator).data) };
    if (message.recipient) mapped.recipient = toBech32("maroo", fromBech32(message.recipient).data);
    assert.deepEqual(buildAuditPublicInputsV2({kind:row.kind,snapshot:maroo,message:mapped}), buildAuditPublicInputsV2({kind:row.kind,snapshot:core,message}));
    assert.throws(()=>buildAuditPublicInputsV2({kind:row.kind,snapshot:core,message:mapped}), /address/);
    assert.throws(()=>buildAuditPublicInputsV2({kind:row.kind,snapshot:maroo,message}), /address/);
  }
});
