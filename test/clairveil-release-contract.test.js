import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyBundledClairveilContractSnapshot,
  verifyVendoredClairveilContractSnapshot
} from "../tools/verify-clairveil-source.js";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const releaseSourceTestsEnabled = process.env.CLAIRVEIL_RELEASE_SOURCE_TESTS === "1";
const clairveilSourceRoot = resolve(
  process.env.CLAIRVEIL_SOURCE_DIR || resolve(packageRoot, "..", "clairveil")
);

test("bundled Clairveil handoff contracts validate without a core checkout", () => {
  const result = verifyBundledClairveilContractSnapshot({ packageRoot });

  assert.equal(result.bundleVersion, "v0.3.1");
  assert.equal(result.sourceKind, "commit_snapshot");
  assert.equal(result.commit, "621c24a3ef1118b6ab2b8b780ab00da6fbc00e1b");
  assert.equal(result.protobufCount, 4);
  assert.equal(result.fixtureCount, 12);
  assert.equal(result.schemaCount, 1);
  assert.equal(result.fileCount, 17);
});

test("vendored Clairveil handoff contracts match the configured core commit object", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const result = verifyVendoredClairveilContractSnapshot({ packageRoot, clairveilSourceRoot });

  assert.equal(result.bundleVersion, "v0.3.1");
  assert.equal(result.sourceKind, "commit_snapshot");
  assert.equal(result.commit, "621c24a3ef1118b6ab2b8b780ab00da6fbc00e1b");
  assert.equal(result.protobufCount, 4);
  assert.equal(result.fixtureCount, 12);
  assert.equal(result.schemaCount, 1);
  assert.equal(result.fileCount, 17);
  assert.equal(result.clairveilSourceRoot, clairveilSourceRoot);
});

test("release verifier CLI checks the configured Clairveil source checkout", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const result = spawnSync(
    process.execPath,
    [join(packageRoot, "tools/verify-clairveil-source.js")],
    {
      cwd: packageRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        CLAIRVEIL_SOURCE_DIR: clairveilSourceRoot
      }
    }
  );

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /verified bundled Clairveil commit_snapshot 621c24a3/);
});

test("release verifier fails closed when the Clairveil source checkout is unavailable", () => {
  assert.throws(
    () => verifyVendoredClairveilContractSnapshot({
      packageRoot,
      clairveilSourceRoot: join(packageRoot, "does-not-exist")
    }),
    /Clairveil source checkout/
  );
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
      () => verifyBundledClairveilContractSnapshot({ packageRoot: temporaryRoot }),
      /privacy_wallet_golden_vectors\.json SHA-256 is/
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("release verifier rejects a self-consistent manifest that diverges from the claimed commit", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "clairveiljs-upstream-contract-"));

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
    const relativeFixturePath =
      "fixtures/clairveil-v0.3.1/x/privacy/client/sdk/conformance/testdata/privacy_wallet_golden_vectors.json";
    const fixturePath = join(temporaryRoot, relativeFixturePath);
    appendFileSync(fixturePath, "\n");
    const manifestPath = join(temporaryRoot, "fixtures", "clairveil-v0.3.1", "manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    manifest.files.find(entry => entry.local_path === relativeFixturePath).sha256 =
      createHash("sha256").update(readFileSync(fixturePath)).digest("hex");
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    assert.throws(
      () => verifyVendoredClairveilContractSnapshot({ packageRoot: temporaryRoot, clairveilSourceRoot }),
      /does not match .* at Clairveil commit/
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("release verifier rejects labeling a commit snapshot as a release tag", () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "clairveiljs-source-identity-"));

  try {
    mkdirSync(join(temporaryRoot, "fixtures"), { recursive: true });
    cpSync(
      join(packageRoot, "fixtures", "clairveil-v0.3.1"),
      join(temporaryRoot, "fixtures", "clairveil-v0.3.1"),
      { recursive: true }
    );
    const manifestPath = join(
      temporaryRoot,
      "fixtures",
      "clairveil-v0.3.1",
      "manifest.json"
    );
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    manifest.source.release = "v0.3.1";
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    assert.throws(
      () => verifyBundledClairveilContractSnapshot({ packageRoot: temporaryRoot }),
      /source must identify only an exact commit snapshot/
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("required conformance refuses external fixture and schema overrides", () => {
  for (const name of ["CLAIRVEIL_CONFORMANCE_FIXTURE_DIR", "CLAIRVEIL_WALLET_CONTRACT_SCHEMA"]) {
    const env = { ...process.env };
    delete env.CLAIRVEIL_CONFORMANCE_FIXTURE_DIR;
    delete env.CLAIRVEIL_WALLET_CONTRACT_SCHEMA;
    env[name] = join(packageRoot, "external-contract");
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        join(packageRoot, "tools/require-conformance-fixtures.js"),
        "--eval",
        "process.stdout.write('unreachable')"
      ],
      {
        cwd: packageRoot,
        encoding: "utf8",
        env
      }
    );

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, new RegExp(name));
    assert.equal(result.stdout, "");
  }
});
