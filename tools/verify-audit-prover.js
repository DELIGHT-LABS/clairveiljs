// Explicit real-crypto gate. Development setup only; never supplies production trust pins.
import { execFileSync, spawn } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  rmSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { matchesAuditProofSource } from './audit-artifact-provenance.js';
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const core = resolve(process.argv[2] ?? join(root, "../clairveil"));
const cache = process.argv[3] ? resolve(process.argv[3]) : undefined;
const commit = "fad307abddd0daa1c880f2e423668f5c58a0e578";
const stage = mkdtempSync(join(tmpdir(), "clairveil-audit-prover-check-"));
const sha = (b) => createHash("sha256").update(b).digest("hex");
let server;
try {
  const archive = execFileSync(
    "git",
    ["archive", commit, "go.mod", "go.sum", "types", "internal", "x/privacy"],
    { cwd: core, maxBuffer: 128 * 1024 * 1024 },
  );
  execFileSync("tar", ["-x", "-C", stage], { input: archive });
  const generator = readFileSync(
    join(root, "tools/generate-audit-prover-vectors_test.go"),
  );
  const generatorHash = sha(execFileSync("gofmt", [], { input: generator }));
  const fixtures = cache ?? join(stage, "proof-fixtures");
  if (cache) {
    const provenance = JSON.parse(readFileSync(join(fixtures, "source.json")));
    if (!matchesAuditProofSource(provenance, { coreCommit: commit, archiveSHA256: sha(archive),
      generatorSHA256: sha(generator), generatorGofmtSHA256: generatorHash }))
      throw new Error("cached development proof source mismatch");
    const manifest = JSON.parse(
      readFileSync(join(fixtures, "privacy_zk_manifest.json")),
    );
    const required = [
      "privacy_zk_manifest.json",
      ...manifest.artifacts.map((d) => d.filename),
      ...[1, 2, 3, 4].map((k) => `proof-${k}.json`),
    ];
    for (const file of required)
      if (sha(readFileSync(join(fixtures, file))) !== provenance.files[file])
        throw new Error("cached development fixture hash mismatch");
  } else {
    writeFileSync(
      join(stage, "x/privacy/circuit/clairveiljs_proof_fixture_test.go"),
      generator,
    );
    process.stdout.write(
      "Generating and proving all four actual Core circuits with temporary development-only setup...\n",
    );
    const log = execFileSync(
      "go",
      [
        "test",
        "-mod=readonly",
        "./x/privacy/circuit",
        "-run",
        "^TestClairveilJSAuditProofFixtures$",
        "-count=1",
        "-timeout=20m",
        "-json",
      ],
      {
        cwd: stage,
        env: { ...process.env, CLAIRVEIL_AUDIT_PROOF_FIXTURES: fixtures },
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    const events = log
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const passed = events.filter(
      (e) =>
        e.Action === "pass" &&
        e.Test?.startsWith("TestClairveilJSAuditProofFixtures/"),
    );
    if (
      passed.length !== 4 ||
      events.some((e) => e.Action === "skip") ||
      !events.some(
        (e) =>
          e.Test === "TestClairveilJSAuditProofFixtures" && e.Action === "pass",
      )
    )
      throw new Error("required actual-circuit proof generation incomplete");
    process.stdout.write(
      "Four actual Core circuit proofs generated and verified.\n",
    );
  }
  const binary = join(stage, "verify");
  execFileSync(
    process.execPath,
    [join(root, "tools/build-audit-native.js"), core, binary, "verify"],
    { cwd: root, stdio: "inherit" },
  );
  const metadata = JSON.parse(readFileSync(`${binary}.json`));
  const serverSource = join(
    stage,
    "x/privacy/crypto/cmd/clairveiljs-prover-test",
  );
  mkdirSync(serverSource, { recursive: true });
  writeFileSync(
    join(serverSource, "main.go"),
    readFileSync(join(root, "tools/audit-prover-test-server.go")),
  );
  execFileSync(
    "go",
    [
      "build",
      "-mod=readonly",
      "-trimpath",
      "-buildvcs=false",
      "-o",
      join(stage, "prover-test"),
      "./x/privacy/crypto/cmd/clairveiljs-prover-test",
    ],
    { cwd: stage, stdio: ["ignore", "pipe", "pipe"] },
  );
  rmSync(join(fixtures, "deposit.json"), { force: true });
  server = spawn(
    join(stage, "prover-test"),
    [fixtures, join(root, "fixtures/clairveil-v0.6.1-audit/vectors.json")],
    { stdio: "ignore" },
  );
  let failed = false;
  server.on("error", () => {
    failed = true;
  });
  for (let i = 0; !existsSync(join(fixtures, "deposit.json")); i++) {
    if (i >= 600 || failed || server.exitCode !== null)
      throw new Error("local Core test prover did not start");
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  const result = execFileSync(
    process.execPath,
    [
      "--test",
      "test/audit-prover-v2.test.js",
      "test/audit-verifier-node.test.js",
    ],
    {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
      env: {
        ...process.env,
        CLAIRVEIL_AUDIT_PROOF_FIXTURES: fixtures,
        CLAIRVEIL_AUDIT_VERIFIER_BINARY: binary,
        CLAIRVEIL_AUDIT_VERIFIER_SHA256: metadata.binarySHA256,
      },
    },
  );
  process.stdout.write(result);
  if (!/^# fail 0$/m.test(result) || !/^# skipped 0$/m.test(result))
    throw new Error("native proof gate must pass without skips");
  process.stdout.write(
    JSON.stringify({
      coreCommit: commit,
      developmentOnly: true,
      actualCircuits: 4,
      actualHttpRoundTrip: true,
      fixtureReuse: Boolean(cache),
      manifestSHA256: sha(
        readFileSync(join(fixtures, "privacy_zk_manifest.json")),
      ),
    }) + "\n",
  );
} finally {
  if (server && server.exitCode === null) {
    server.kill("SIGKILL");
    await new Promise((resolve) => server.once("close", resolve));
  }
  rmSync(stage, { recursive: true, force: true });
  if (cache) rmSync(join(cache, "deposit.json"), { force: true });
}
