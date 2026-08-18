import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFileSync, cpSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyVendoredClairveilRelease
} from "../tools/verify-clairveil-source.js";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));

test("vendored Clairveil v0.3.1 release contracts verify without a source checkout", () => {
  const result = verifyVendoredClairveilRelease({ packageRoot });

  assert.equal(result.release, "v0.3.1");
  assert.equal(result.commit, "1a6ce6a0a0e10b765c025072b44c2364e9711b48");
  assert.equal(result.protobufCount, 4);
  assert.equal(result.fixtureCount, 12);
  assert.equal(result.schemaCount, 1);
  assert.equal(result.fileCount, 17);
});

test("release verifier CLI does not require CLAIRVEIL_SOURCE_DIR", () => {
  const result = spawnSync(
    process.execPath,
    [join(packageRoot, "tools/verify-clairveil-source.js")],
    {
      cwd: packageRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        CLAIRVEIL_SOURCE_DIR: join(packageRoot, "does-not-exist")
      }
    }
  );

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /verified bundled Clairveil v0\.3\.1/);
});

test("release verifier rejects a modified vendored fixture", () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "clairveiljs-release-contract-"));

  try {
    mkdirSync(join(temporaryRoot, "fixtures"), { recursive: true });
    cpSync(
      join(packageRoot, "fixtures", "clairveil-v0.3.1"),
      join(temporaryRoot, "fixtures", "clairveil-v0.3.1"),
      { recursive: true }
    );
    cpSync(join(packageRoot, "proto"), join(temporaryRoot, "proto"), {
      recursive: true
    });

    appendFileSync(
      join(
        temporaryRoot,
        "fixtures",
        "clairveil-v0.3.1",
        "x",
        "privacy",
        "client",
        "sdk",
        "conformance",
        "testdata",
        "privacy_wallet_golden_vectors.json"
      ),
      "\n"
    );

    assert.throws(
      () => verifyVendoredClairveilRelease({ packageRoot: temporaryRoot }),
      /privacy_wallet_golden_vectors\.json SHA-256 is/
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
