import test from "node:test";
import assert from "node:assert/strict";
import { createAuditProverV2 } from "clairveiljs/audit-prover-v2";
import {
  vectors,
  preparedCase,
  fullWitness,
  reply,
  framedProof,
  snapshot,
} from "./helpers/audit-prover.js";

const url = "http://127.0.0.1:8181";
const response = (value) =>
  new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
  });
const stubVerifier = { verify: async () => true }; // Transport/lifecycle tests only; real crypto runs separately.
for (const kind of [1, 2, 3, 4])
  test(`V2 kind ${kind}: exact route/wire, local verification and single use`, async () => {
    const row = vectors.cases.find((r) => r.kind === kind);
    const { prepared } = await preparedCase(row);
    const witness = fullWitness(prepared.publicInputs());
    let calls = 0,
      verified = 0;
    const prover = createAuditProverV2({
      baseUrl: url,
      verifier: {
        verify: async (r) => {
          verified++;
          assert.equal(r.kind, kind);
          assert.equal(r.publicInputs.length, 23);
          assert.equal(r.proof.length, 164);
          return true;
        },
      },
      fetch: async (target, init) => {
        calls++;
        assert.equal(target, url + "/v2/prover/audit-field");
        assert.equal(init.redirect, "error");
        assert.equal(init.credentials, "omit");
        const req = JSON.parse(init.body);
        assert.equal(req.version, "v1");
        assert.equal(req.public_inputs.length, 23);
        assert.equal(Buffer.from(req.witness, "base64").readUInt32BE(), 23);
        assert.deepEqual(
          Object.keys(req).sort(),
          [
            "version",
            "circuit_set_id",
            "circuit_id",
            "artifact_hash",
            "public_inputs",
            "witness",
          ].sort(),
        );
        return response(reply(req));
      },
    });
    const message = await prover.prove({ prepared, witness });
    assert.equal(calls, 1);
    assert.equal(verified, 1);
    assert.deepEqual(message.proof, Uint8Array.from(framedProof()));
    assert.equal(message.creator, row.creator);
    assert(witness.every((x) => x === 0));
    assert.throws(() => prepared.publicInputs(), /cleared/);
    await assert.rejects(prover.prove({ prepared, witness }), /consumed|used/);
    assert.equal(calls, 1);
  });

test("full witness rejects malformed headers, PI mismatch, noncanonical fields and trailing data before HTTP", async () => {
  for (const mutate of [
    (b) => b.subarray(1),
    (b) => Buffer.concat([b, Buffer.alloc(1)]),
    (b) => {
      b.writeUInt32BE(22, 0);
      return b;
    },
    (b) => {
      b.writeUInt32BE(25, 8);
      return b;
    },
    (b) => {
      b[43] ^= 1;
      return b;
    },
    (b) => {
      b.fill(255, b.length - 32);
      return b;
    },
    (b) => b.subarray(0, 12 + 23 * 32),
  ]) {
    const { prepared } = await preparedCase();
    let calls = 0;
    const witness = mutate(fullWitness(prepared.publicInputs()));
    const p = createAuditProverV2({
      baseUrl: url,
      verifier: stubVerifier,
      fetch: async () => {
        calls++;
        throw Error("unexpected");
      },
    });
    await assert.rejects(p.prove({ prepared, witness }));
    assert.equal(calls, 0);
    assert(witness.every((x) => x === 0));
    assert.throws(() => prepared.publicInputs(), /cleared/);
  }
});

test("every response binding and strict JSON/base64/proof frame is checked before verification", async () => {
  const attacks = [
    (r) => ({ ...r, version: "v2" }),
    (r) => ({ ...r, circuit_set_id: "privacy-note-v1" }),
    (r) => ({ ...r, circuit_id: "spend-audit-field-u128-v1" }),
    (r) => ({ ...r, artifact_hash: Buffer.alloc(32, 2).toString("base64") }),
    (r) => ({ ...r, public_inputs: r.public_inputs.slice(1) }),
    (r) => ({
      ...r,
      public_inputs: [r.public_inputs[1], ...r.public_inputs.slice(1)],
    }),
    (r) => ({ ...r, proof: r.proof + "\n" }),
    (r) => ({ ...r, proof: Buffer.alloc(164).toString("base64") }),
    (r) => ({ ...r, unknown: true }),
    (r) =>
      JSON.stringify(r).replace(
        '"version":"v1"',
        '"version":"v1","version":"v1"',
      ),
    (r) => JSON.stringify(r) + " {}",
    (r) => ({ ...r, proof: framedProof().subarray(1).toString("base64") }),
  ];
  for (const attack of attacks) {
    const { prepared } = await preparedCase();
    let verified = 0,
      calls = 0;
    const p = createAuditProverV2({
      baseUrl: url,
      verifier: {
        verify: async () => {
          verified++;
          return true;
        },
      },
      fetch: async (_, init) => {
        calls++;
        const bad = attack(reply(JSON.parse(init.body)));
        return typeof bad === "string"
          ? new Response(bad, {
              headers: { "content-type": "application/json" },
            })
          : response(bad);
      },
    });
    await assert.rejects(
      p.prove({ prepared, witness: fullWitness(prepared.publicInputs()) }),
    );
    assert.equal(verified, 0);
    assert.equal(calls, 1);
  }
});

test("mandatory local verifier rejects a mathematically invalid but correctly framed proof", async () => {
  assert.throws(() => createAuditProverV2({ baseUrl: url }), /verifier/);
  for (const value of [false, undefined, "true"]) {
    const { prepared } = await preparedCase();
    const p = createAuditProverV2({
      baseUrl: url,
      verifier: { verify: async () => value },
      fetch: async (_, init) => response(reply(JSON.parse(init.body))),
    });
    await assert.rejects(
      p.prove({ prepared, witness: fullWitness(prepared.publicInputs()) }),
      /verification/,
    );
  }
});

test("finite deadline covers hanging HTTP, body, snapshot and verifier; cancellation clears single-use state", async () => {
  for (const stage of ["fetch", "body", "snapshot", "verify", "abort"]) {
    let queried = 0;
    const base = await preparedCase();
    base.prepared.clear();
    const { prepared } = await preparedCase(undefined, {
      getCurrentSnapshot: async () => {
        if (++queried > 2 && stage === "snapshot") return new Promise(() => {});
        return base.snapshot;
      },
    });
    const witness = fullWitness(prepared.publicInputs());
    const controller = new AbortController();
    let calls = 0;
    const p = createAuditProverV2({
      baseUrl: url,
      timeoutMs: 100,
      verifier: {
        verify: async () => (stage === "verify" ? new Promise(() => {}) : true),
      },
      fetch: async (_, init) => {
        calls++;
        if (stage === "fetch" || stage === "abort")
          return new Promise(() => {});
        if (stage === "body")
          return new Response(new ReadableStream({ start() {} }), {
            headers: { "content-type": "application/json" },
          });
        return response(reply(JSON.parse(init.body)));
      },
    });
    const pending = p.prove({ prepared, witness, signal: controller.signal });
    if (stage === "abort")
      setTimeout(() => controller.abort(Error("private-abort-reason")), 10);
    await assert.rejects(
      pending,
      (e) =>
        /timed out|aborted/.test(e.message) &&
        !e.message.includes("private-abort-reason"),
    );
    assert(witness.every((x) => x === 0));
    assert.throws(() => prepared.publicInputs(), /cleared/);
    assert(calls <= 1);
  }
});

test("remote errors, redirects and oversized streamed bodies are bounded and redacted without retry", async () => {
  for (const make of [
    () => new Response("secret-witness", { status: 500 }),
    () =>
      new Response("", {
        status: 302,
        headers: { location: "https://other.invalid" },
      }),
    () => new Response("{}", { headers: { "content-type": "text/plain" } }),
    () =>
      new Response("x".repeat(16385), {
        headers: { "content-type": "application/json" },
      }),
    () => {
      throw Error("secret-witness");
    },
  ]) {
    const { prepared } = await preparedCase();
    let calls = 0;
    const p = createAuditProverV2({
      baseUrl: url,
      verifier: stubVerifier,
      fetch: async () => {
        calls++;
        return make();
      },
    });
    await assert.rejects(
      p.prove({ prepared, witness: fullWitness(prepared.publicInputs()) }),
      (e) => !e.message.includes("secret-witness"),
    );
    assert.equal(calls, 1);
  }
});

test("prover construction rejects ambiguous endpoints, credentials and unbounded deadlines", () => {
  for (const baseUrl of [
    "ftp://localhost",
    "http://example.com",
    "https://name:password@host.invalid",
    "https://host.invalid/v1",
    "https://host.invalid/?secret=1",
    "https://host.invalid/#fragment",
  ])
    assert.throws(() =>
      createAuditProverV2({ baseUrl, verifier: stubVerifier }),
    );
  for (const timeoutMs of [0, Infinity, NaN, -1, 1.5, 3600001])
    assert.throws(() =>
      createAuditProverV2({ baseUrl: url, timeoutMs, verifier: stubVerifier }),
    );
  assert.throws(() =>
    createAuditProverV2({
      baseUrl: url,
      bearerToken: "token\r\nheader",
      verifier: stubVerifier,
    }),
  );
});

test("a second concurrent attempt cannot reuse or clear the preparation owned by the first", async () => {
  const { prepared } = await preparedCase();
  let resume,
    calls = 0;
  const ready = new Promise((resolve) => {
    resume = resolve;
  });
  const p = createAuditProverV2({
    baseUrl: url,
    verifier: stubVerifier,
    fetch: async (_, init) => {
      calls++;
      await ready;
      return response(reply(JSON.parse(init.body)));
    },
  });
  const witness = fullWitness(prepared.publicInputs()),
    duplicate = witness.slice();
  const first = p.prove({ prepared, witness });
  await assert.rejects(p.prove({ prepared, witness: duplicate }), /consumed/);
  assert.equal(prepared.publicInputs().length, 23);
  resume();
  await first;
  assert.equal(calls, 1);
  duplicate.fill(0);
});

test("snapshot change before export, after response or after local verification rejects the result", async () => {
  const current = await snapshot(),
    old = await snapshot(0);
  for (const at of [3, 4, 5]) {
    let queries = 0,
      calls = 0,
      verifications = 0;
    const { prepared } = await preparedCase(undefined, {
      getCurrentSnapshot: async () => (++queries >= at ? old : current),
    });
    const p = createAuditProverV2({
      baseUrl: url,
      verifier: {
        verify: async () => {
          verifications++;
          return true;
        },
      },
      fetch: async (_, init) => {
        calls++;
        return response(reply(JSON.parse(init.body)));
      },
    });
    await assert.rejects(
      p.prove({ prepared, witness: fullWitness(prepared.publicInputs()) }),
      /snapshot/,
    );
    assert.equal(calls, at === 3 ? 0 : 1);
    assert.equal(verifications, at === 5 ? 1 : 0);
    assert.throws(() => prepared.publicInputs(), /cleared/);
  }
});

test("abort at the final dispatch fence prevents witness export and all external error details are redacted", async () => {
  const controller = new AbortController();
  let queries = 0,
    calls = 0;
  const s = await snapshot();
  const { prepared } = await preparedCase(undefined, {
    getCurrentSnapshot: async () => {
      if (++queries === 3) queueMicrotask(() => controller.abort());
      return s;
    },
  });
  const p = createAuditProverV2({
    baseUrl: url,
    verifier: stubVerifier,
    fetch: async () => {
      calls++;
      throw Error("private-body");
    },
  });
  await assert.rejects(
    p.prove({
      prepared,
      witness: fullWitness(prepared.publicInputs()),
      signal: controller.signal,
    }),
    /aborted/,
  );
  assert.equal(calls, 0);
  const next = await preparedCase();
  const bad = createAuditProverV2({
    baseUrl: url,
    verifier: {
      verify: async () => {
        throw Error("private verifier details");
      },
    },
    fetch: async (_, init) => response(reply(JSON.parse(init.body))),
  });
  await assert.rejects(
    bad.prove({
      prepared: next.prepared,
      witness: fullWitness(next.prepared.publicInputs()),
    }),
    (e) => e.code === "verification" && !e.message.includes("private verifier"),
  );
});
