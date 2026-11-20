import test from "node:test";
import assert from "node:assert/strict";
import {
  readFileSync,
  writeFileSync,
  mkdtempSync,
  rmSync,
  readdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createAuditNativeBackendV2 } from "clairveiljs/audit-native-node";
import {
  computeAuditCipherRootV2,
  parseAuditEnvelopeV2,
} from "clairveiljs/audit-authorization-v2";
import { bytesFromHex, concatBytes } from "clairveiljs/browser-crypto";
const vectors = JSON.parse(
  readFileSync(
    new URL(
      "../fixtures/clairveil-v0.6.1-audit-authorization/vectors.json",
      import.meta.url,
    ),
  ),
);
const sha = (b) => createHash("sha256").update(b).digest("hex");
const field = (x) => bytesFromHex(BigInt(x).toString(16).padStart(64, "0"));
const request = (row) => ({
  kind: row.kind,
  publicInputs: concatBytes(...row.publicInputs.slice(0, 21).map(field)),
  plaintext: concatBytes(...row.plaintext.map(bytesFromHex)),
});
test("native adapter enforces pin, timeout, abort, response size and redacted errors", async () => {
  const dir = mkdtempSync(join(tmpdir(), "audit-adapter-test-"));
  const stageBefore = new Set(
    readdirSync(tmpdir()).filter((n) => n.startsWith("clairveil-audit-run-")),
  );
  try {
    for (const [name, script, pattern] of [
      [
        "failure",
        "echo synthetic-private-data >&2; exit 1",
        "native encryption failed",
      ],
      ["timeout", "while :; do :; done", "timed out"],
      ["overflow", "while :; do echo excessive-output; done", "exceeds bound"],
      ["truncated", "echo CVA2", "invalid native"],
    ]) {
      const path = join(dir, name);
      writeFileSync(path, "#!/bin/sh\n" + script + "\n", { mode: 0o700 });
      await assert.rejects(
        createAuditNativeBackendV2({
          executablePath: path,
          sha256: "0".repeat(64),
        }),
        /hash mismatch/,
      );
      const backend = await createAuditNativeBackendV2({
        executablePath: path,
        sha256: sha(readFileSync(path)),
        timeoutMs: name === "timeout" ? 200 : 5000,
      });
      await assert.rejects(
        backend.encrypt(request(vectors.cases[0])),
        (e) =>
          e.message.includes(pattern) &&
          !e.message.includes("synthetic-private-data"),
      );
      const c = new AbortController();
      c.abort();
      await assert.rejects(
        backend.encrypt({ ...request(vectors.cases[0]), signal: c.signal }),
        /abort/i,
      );
      await assert.rejects(
        backend.encrypt({
          ...request(vectors.cases[0]),
          plaintext: new Uint8Array(1),
        }),
        /length/,
      );
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  assert.deepEqual(
    new Set(
      readdirSync(tmpdir()).filter((n) => n.startsWith("clairveil-audit-run-")),
    ),
    stageBefore,
  );
});
const nativePath = process.env.CLAIRVEIL_AUDIT_NATIVE_BINARY;
test(
  "pinned native Core encrypts all four shapes with fresh entropy and fails closed without hardware profile",
  { skip: !nativePath },
  async () => {
    const backend = await createAuditNativeBackendV2({
      executablePath: nativePath,
      sha256: process.env.CLAIRVEIL_AUDIT_NATIVE_SHA256,
    });
    for (const row of vectors.cases) {
      const r = request(row),
        a = await backend.encrypt(r),
        b = await backend.encrypt(r);
      try {
        assert(!Buffer.from(a.envelope).equals(Buffer.from(b.envelope)));
        assert(!Buffer.from(a.witness).equals(Buffer.from(b.witness)));
        const pi = row.publicInputs.slice(0, 21).map(BigInt);
        const frame = parseAuditEnvelopeV2(
          row.kind,
          Number(pi[9]),
          Number(pi[10]),
          a.envelope,
        );
        assert.equal(frame.ciphertext.length, row.plaintext.length);
        assert.equal(
          computeAuditCipherRootV2(row.kind, pi, a.envelope).length,
          2,
        );
        const bad = r.publicInputs.slice();
        bad[0] = 255;
        await assert.rejects(
          backend.encrypt({ ...r, publicInputs: bad }),
          /native encryption failed/,
        );
      } finally {
        a.witness.fill(0);
        b.witness.fill(0);
        r.plaintext.fill(0);
      }
    }
    const saved = process.env.GODEBUG;
    try {
      process.env.GODEBUG = "cpu.all=off";
      await assert.rejects(
        backend.encrypt(request(vectors.cases[0])),
        /native encryption failed/,
      );
    } finally {
      if (saved === undefined) delete process.env.GODEBUG;
      else process.env.GODEBUG = saved;
    }
  },
);
