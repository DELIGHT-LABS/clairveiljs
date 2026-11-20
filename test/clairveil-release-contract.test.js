import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyBundledClairveilProtoContractSnapshot,
  verifyVendoredClairveilProtoContractSnapshot,
  verifyBundledClairveilContractSnapshot,
  verifyBundledClairveilProverContractSnapshot,
  verifyVendoredClairveilContractSnapshot,
  verifyVendoredClairveilProverContractSnapshot
} from "../tools/verify-clairveil-source.js";
import {
  supportedEvmCanonicalAbiSha256,
  verifyBundledEvmContract
} from "../tools/verify-evm-contract.js";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const releaseSourceTestsEnabled = process.env.CLAIRVEIL_RELEASE_SOURCE_TESTS === "1";
const clairveilSourceRoot = resolve(
  process.env.CLAIRVEIL_SOURCE_DIR || resolve(packageRoot, "..", "clairveil")
);

function temporaryClairveilCheckout(prefix) {
  const temporaryRoot = mkdtempSync(join(tmpdir(), prefix));
  const temporaryCheckout = join(temporaryRoot, "clairveil");
  const clone = spawnSync(
    "git",
    ["clone", "--shared", "--no-checkout", clairveilSourceRoot, temporaryCheckout],
    { encoding: "utf8" }
  );
  assert.equal(clone.status, 0, clone.stderr || clone.stdout);
  return { temporaryRoot, temporaryCheckout };
}

function gitInCheckout(temporaryCheckout, args) {
  const result = spawnSync(
    "git",
    ["-C", temporaryCheckout, ...args],
    { encoding: "utf8" }
  );
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout.trim();
}

test("bundled Clairveil handoff contracts validate without a core checkout", () => {
  const result = verifyBundledClairveilContractSnapshot({ packageRoot });

  assert.equal(result.bundleVersion, "v0.3.1");
  assert.equal(result.sourceKind, "commit_snapshot");
  assert.equal(result.commit, "0ff92839872de26b787a60d8e4d5822cc459855b");
  assert.equal(result.protobufCount, 4);
  assert.equal(result.fixtureCount, 12);
  assert.equal(result.schemaCount, 1);
  assert.equal(result.fileCount, 17);
  assert.equal(result.prover.bundleVersion, "v0.4.0");
  assert.equal(result.prover.sourceKind, "release_tag");
  assert.equal(result.prover.release, "v0.4.0");
  assert.equal(result.prover.commit, "ca85b02708fdd75259d4d2ee2d671c21198cec69");
  assert.equal(result.prover.fixtureCount, 2);
  assert.equal(result.prover.schemaCount, 1);
  assert.equal(result.prover.fileCount, 3);
  assert.equal(result.proto.release, "v0.6.1");
  assert.equal(result.proto.commit, "fad307abddd0daa1c880f2e423668f5c58a0e578");
  assert.equal(result.proto.protobufCount, 6);
  assert.equal(result.totalFileCount, 26);
  assert.equal(result.totalFixtureCount, 14);
  assert.equal(result.totalSchemaCount, 2);
});

test("bundled Clairveil v0.4.0 prover contract validates independently", () => {
  const result = verifyBundledClairveilProverContractSnapshot({ packageRoot });

  assert.equal(result.bundleVersion, "v0.4.0");
  assert.equal(result.sourceKind, "release_tag");
  assert.equal(result.release, "v0.4.0");
  assert.equal(result.commit, "ca85b02708fdd75259d4d2ee2d671c21198cec69");
  assert.equal(result.fixtureCount, 2);
  assert.equal(result.schemaCount, 1);
  assert.equal(result.fileCount, 3);
});

test("Core v0.6.1 proto identity and hashes validate independently", () => {
  const result = verifyBundledClairveilProtoContractSnapshot({ packageRoot });
  assert.equal(result.release, "v0.6.1");
  assert.equal(result.commit, "fad307abddd0daa1c880f2e423668f5c58a0e578");
  assert.equal(result.protobufCount, 6);
});

test("uint128 reference vectors identify the exact Core v0.6.1 amount implementation", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const fixture = JSON.parse(readFileSync(join(packageRoot, "fixtures/clairveil-v0.6.1-amount/vectors.json"), "utf8"));
  assert.equal(fixture.source.commit, "fad307abddd0daa1c880f2e423668f5c58a0e578");
  assert.equal(fixture.source.path, "x/privacy/amount/amount.go");
  const source = spawnSync("git", ["-C", clairveilSourceRoot, "cat-file", "blob", `${fixture.source.commit}:${fixture.source.path}`]);
  assert.equal(source.status, 0);
  assert.equal(createHash("sha256").update(source.stdout).digest("hex"), fixture.source.sha256);
});

test("fixed-v2 codec vectors identify exact Core v0.6.1 serialization and crypto sources", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const fixture = JSON.parse(readFileSync(join(packageRoot, "fixtures/clairveil-v0.6.1-fixed/vectors.json"), "utf8"));
  assert.equal(fixture.source.release, "v0.6.1");
  assert.equal(fixture.source.commit, "fad307abddd0daa1c880f2e423668f5c58a0e578");
  assert.equal(Object.keys(fixture.source.files).length, 12);
  for (const [path, digest] of Object.entries(fixture.source.files)) {
    const source = spawnSync("git", ["-C", clairveilSourceRoot, "cat-file", "blob", `${fixture.source.commit}:${path}`]);
    assert.equal(source.status, 0);
    assert.equal(createHash("sha256").update(source.stdout).digest("hex"), digest, path);
  }
});

test("audit-v2 snapshot vectors identify exact Core v0.6.1 query, key, PoP and artifact sources", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const fixture = JSON.parse(readFileSync(join(packageRoot, "fixtures/clairveil-v0.6.1-audit/vectors.json"), "utf8"));
  assert.equal(fixture.source.release, "v0.6.1");
  assert.equal(fixture.source.commit, "fad307abddd0daa1c880f2e423668f5c58a0e578");
  assert.equal(Object.keys(fixture.source.files).length, 10);
  for (const [path, digest] of Object.entries(fixture.source.files)) {
    const source = spawnSync("git", ["-C", clairveilSourceRoot, "cat-file", "blob", `${fixture.source.commit}:${path}`]);
    assert.equal(source.status, 0);
    assert.equal(createHash("sha256").update(source.stdout).digest("hex"), digest, path);
  }
});

test("proto verifier rejects tampering even after the local manifest hash is updated", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "clairveiljs-proto-tamper-"));
  try {
    cpSync(join(packageRoot, "fixtures/clairveil-v0.6.1-proto"),
      join(temporaryRoot, "fixtures/clairveil-v0.6.1-proto"), { recursive: true });
    cpSync(join(packageRoot, "proto"), join(temporaryRoot, "proto"), { recursive: true });
    const relativePath = "proto/clairveil/privacy/v2/tx.proto";
    const protoPath = join(temporaryRoot, relativePath);
    appendFileSync(protoPath, "\n// tampered\n");
    assert.throws(() => verifyBundledClairveilProtoContractSnapshot({ packageRoot: temporaryRoot }), /tx\.proto SHA-256 is/);
    const manifestPath = join(temporaryRoot, "fixtures/clairveil-v0.6.1-proto/manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    manifest.files.find(entry => entry.local_path === relativePath).sha256 =
      createHash("sha256").update(readFileSync(protoPath)).digest("hex");
    writeFileSync(manifestPath, JSON.stringify(manifest));
    assert.throws(() => verifyVendoredClairveilProtoContractSnapshot({
      packageRoot: temporaryRoot, clairveilSourceRoot
    }), /does not match .* at Clairveil v0\.6\.1 commit/);
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("proto verifier rejects a lightweight v0.6.1 tag", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const { temporaryRoot, temporaryCheckout } = temporaryClairveilCheckout("clairveiljs-proto-tag-");
  try {
    gitInCheckout(temporaryCheckout, ["tag", "--force", "v0.6.1", "fad307abddd0daa1c880f2e423668f5c58a0e578"]);
    assert.throws(() => verifyVendoredClairveilProtoContractSnapshot({
      packageRoot, clairveilSourceRoot: temporaryCheckout
    }), /tag v0\.6\.1 must be annotated; got commit/);
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("bundled generic Clairveil EVM contract validates without a downstream checkout", () => {
  const result = verifyBundledEvmContract({ packageRoot });

  assert.equal(result.contractVersion, "0.3.1");
  assert.equal(result.abiSha256, supportedEvmCanonicalAbiSha256);
});

test("vendored Clairveil handoff contracts match the configured core commit object", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const result = verifyVendoredClairveilContractSnapshot({ packageRoot, clairveilSourceRoot });

  assert.equal(result.bundleVersion, "v0.3.1");
  assert.equal(result.sourceKind, "commit_snapshot");
  assert.equal(result.commit, "0ff92839872de26b787a60d8e4d5822cc459855b");
  assert.equal(result.protobufCount, 4);
  assert.equal(result.fixtureCount, 12);
  assert.equal(result.schemaCount, 1);
  assert.equal(result.fileCount, 17);
  assert.equal(result.prover.release, "v0.4.0");
  assert.equal(result.prover.commit, "ca85b02708fdd75259d4d2ee2d671c21198cec69");
  assert.equal(result.clairveilSourceRoot, clairveilSourceRoot);
});

test("vendored v0.4.0 prover contracts match the exact Core release tag", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const result = verifyVendoredClairveilProverContractSnapshot({
    packageRoot,
    clairveilSourceRoot
  });

  assert.equal(result.release, "v0.4.0");
  assert.equal(result.commit, "ca85b02708fdd75259d4d2ee2d671c21198cec69");
  assert.equal(result.clairveilSourceRoot, clairveilSourceRoot);
});

test("release verifier rejects a lightweight v0.4.0 tag", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const { temporaryRoot, temporaryCheckout } = temporaryClairveilCheckout(
    "clairveiljs-lightweight-tag-"
  );

  try {
    gitInCheckout(temporaryCheckout, [
      "tag",
      "--force",
      "v0.4.0",
      "ca85b02708fdd75259d4d2ee2d671c21198cec69"
    ]);

    assert.throws(
      () => verifyVendoredClairveilProverContractSnapshot({
        packageRoot,
        clairveilSourceRoot: temporaryCheckout
      }),
      /tag v0\.4\.0 must be annotated; got commit/
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("release verifier rejects a nested annotated v0.4.0 tag", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const { temporaryRoot, temporaryCheckout } = temporaryClairveilCheckout(
    "clairveiljs-nested-tag-"
  );

  try {
    const tagIdentity = [
      "-c", "user.name=ClairveilJS Tests",
      "-c", "user.email=clairveiljs@example.invalid"
    ];
    gitInCheckout(temporaryCheckout, [
      ...tagIdentity,
      "tag", "--annotate", "--force", "--message", "inner release tag",
      "nested-v0.4.0", "ca85b02708fdd75259d4d2ee2d671c21198cec69"
    ]);
    gitInCheckout(temporaryCheckout, [
      ...tagIdentity,
      "tag", "--annotate", "--force", "--message", "outer release tag",
      "v0.4.0", "nested-v0.4.0"
    ]);

    assert.throws(
      () => verifyVendoredClairveilProverContractSnapshot({
        packageRoot,
        clairveilSourceRoot: temporaryCheckout
      }),
      /tag v0\.4\.0 must directly target a commit; got tag/
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("release verifier rejects a v0.4.0 tag that directly targets the wrong commit", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const { temporaryRoot, temporaryCheckout } = temporaryClairveilCheckout(
    "clairveiljs-wrong-tag-target-"
  );

  try {
    gitInCheckout(temporaryCheckout, [
      "-c", "user.name=ClairveilJS Tests",
      "-c", "user.email=clairveiljs@example.invalid",
      "tag", "--annotate", "--force", "--message", "wrong release target",
      "v0.4.0", "0ff92839872de26b787a60d8e4d5822cc459855b"
    ]);

    assert.throws(
      () => verifyVendoredClairveilProverContractSnapshot({
        packageRoot,
        clairveilSourceRoot: temporaryCheckout
      }),
      /tag v0\.4\.0 directly targets 0ff9283.*expected ca85b027/
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("release verifier rejects an annotated v0.4.0 ref with a different embedded tag name", {
  skip: !releaseSourceTestsEnabled
}, () => {
  const { temporaryRoot, temporaryCheckout } = temporaryClairveilCheckout(
    "clairveiljs-wrong-tag-name-"
  );

  try {
    const tagIdentity = [
      "-c", "user.name=ClairveilJS Tests",
      "-c", "user.email=clairveiljs@example.invalid"
    ];
    gitInCheckout(temporaryCheckout, [
      ...tagIdentity,
      "tag", "--annotate", "--message", "wrong embedded release name",
      "wrong-name", "ca85b02708fdd75259d4d2ee2d671c21198cec69"
    ]);
    const wrongTagObject = gitInCheckout(temporaryCheckout, [
      "rev-parse", "wrong-name^{tag}"
    ]);
    gitInCheckout(temporaryCheckout, [
      "update-ref", "refs/tags/v0.4.0", wrongTagObject
    ]);

    assert.throws(
      () => verifyVendoredClairveilProverContractSnapshot({
        packageRoot,
        clairveilSourceRoot: temporaryCheckout
      }),
      /tag v0\.4\.0 declares embedded tag name wrong-name; expected v0\.4\.0/
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
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
  assert.match(result.stdout, /verified bundled Clairveil commit_snapshot 0ff92839/);
  assert.match(result.stdout, /verified Clairveil v0\.4\.0 prover contract at ca85b027/);
});

test("EVM contract verifier CLI checks the SDK-owned generic interface", () => {
  const result = spawnSync(
    process.execPath,
    [join(packageRoot, "tools/verify-evm-contract.js")],
    {
      cwd: packageRoot,
      encoding: "utf8"
    }
  );

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /verified Clairveil EVM contract 0\.3\.1/);
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

test("EVM contract verifier rejects a modified SDK-owned interface fixture", () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "clairveiljs-evm-contract-"));

  try {
    mkdirSync(join(temporaryRoot, "fixtures"), { recursive: true });
    cpSync(
      join(packageRoot, "fixtures", "evm-privacy-precompile-v0.3.1.json"),
      join(temporaryRoot, "fixtures", "evm-privacy-precompile-v0.3.1.json")
    );
    const fixturePath = join(temporaryRoot, "fixtures", "evm-privacy-precompile-v0.3.1.json");
    const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
    fixture.selectors.deposit = "00000000";
    writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`);

    assert.throws(
      () => verifyBundledEvmContract({ packageRoot: temporaryRoot }),
      /selector for deposit/
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
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
    cpSync(
      join(packageRoot, "fixtures", "clairveil-v0.4.0-prover"),
      join(temporaryRoot, "fixtures", "clairveil-v0.4.0-prover"),
      { recursive: true }
    );
    cpSync(join(packageRoot, "fixtures/clairveil-v0.6.1-proto"),
      join(temporaryRoot, "fixtures/clairveil-v0.6.1-proto"), { recursive: true });
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
    cpSync(
      join(packageRoot, "fixtures", "clairveil-v0.4.0-prover"),
      join(temporaryRoot, "fixtures", "clairveil-v0.4.0-prover"),
      { recursive: true }
    );
    cpSync(join(packageRoot, "fixtures/clairveil-v0.6.1-proto"),
      join(temporaryRoot, "fixtures/clairveil-v0.6.1-proto"), { recursive: true });
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

test("release verifier rejects a modified v0.4.0 prover fixture", () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "clairveiljs-prover-contract-"));

  try {
    mkdirSync(join(temporaryRoot, "fixtures"), { recursive: true });
    cpSync(
      join(packageRoot, "fixtures", "clairveil-v0.4.0-prover"),
      join(temporaryRoot, "fixtures", "clairveil-v0.4.0-prover"),
      { recursive: true }
    );
    appendFileSync(
      join(
        temporaryRoot,
        "fixtures",
        "clairveil-v0.4.0-prover",
        "x",
        "privacy",
        "client",
        "sdk",
        "conformance",
        "testdata",
        "privacy_deposit_prover_contract.json"
      ),
      "\n"
    );

    assert.throws(
      () => verifyBundledClairveilProverContractSnapshot({ packageRoot: temporaryRoot }),
      /privacy_deposit_prover_contract\.json SHA-256 is/
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("release verifier rejects a false v0.4.0 prover release identity", () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "clairveiljs-prover-source-"));

  try {
    mkdirSync(join(temporaryRoot, "fixtures"), { recursive: true });
    cpSync(
      join(packageRoot, "fixtures", "clairveil-v0.4.0-prover"),
      join(temporaryRoot, "fixtures", "clairveil-v0.4.0-prover"),
      { recursive: true }
    );
    const manifestPath = join(
      temporaryRoot,
      "fixtures",
      "clairveil-v0.4.0-prover",
      "manifest.json"
    );
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    manifest.source.release = "v0.3.1";
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    assert.throws(
      () => verifyBundledClairveilProverContractSnapshot({ packageRoot: temporaryRoot }),
      /prover manifest release is v0\.3\.1; expected v0\.4\.0/
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("required conformance refuses external fixture and schema overrides", () => {
  const overrideNames = [
    "CLAIRVEIL_CONFORMANCE_FIXTURE_DIR",
    "CLAIRVEIL_WALLET_CONTRACT_SCHEMA",
    "CLAIRVEIL_PROVER_CONFORMANCE_FIXTURE_DIR",
    "CLAIRVEIL_PROVER_HTTP_API_SCHEMA"
  ];
  for (const name of overrideNames) {
    const env = { ...process.env };
    for (const overrideName of overrideNames) delete env[overrideName];
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


test("audit authorization vectors identify exact Core v0.6.1 public binding and cipher sources", {skip: !releaseSourceTestsEnabled}, () => {
  const fixture = JSON.parse(readFileSync(join(packageRoot, "fixtures/clairveil-v0.6.1-audit-authorization/vectors.json"), "utf8"));
  assert.equal(fixture.source.commit, "fad307abddd0daa1c880f2e423668f5c58a0e578");
  assert.equal(Object.keys(fixture.source.files).length, 14);
  for (const [path, digest] of Object.entries(fixture.source.files)) {
    const source = spawnSync("git", ["-C", clairveilSourceRoot, "cat-file", "blob", `${fixture.source.commit}:${path}`]);
    assert.equal(source.status, 0);
    assert.equal(createHash("sha256").update(source.stdout).digest("hex"), digest, path);
  }
});
