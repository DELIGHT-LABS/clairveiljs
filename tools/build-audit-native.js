import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  mkdirSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { verifyVendoredClairveilProtoContractSnapshot } from './verify-clairveil-source.js';
const commit = "fad307abddd0daa1c880f2e423668f5c58a0e578";
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [sourceArg, outputArg, mode = "encrypt"] = process.argv.slice(2);
if (!sourceArg || !outputArg)
  throw new Error(
    "usage: node tools/build-audit-native.js CORE_GIT_DIRECTORY OUTPUT_BINARY [encrypt|verify|witness|fixture-server]",
  );
const bridges = { encrypt: 'audit-native-bridge.go', verify: 'audit-verifier-bridge.go', witness: 'audit-witness-bridge.go', 'fixture-server': 'audit-prover-test-server.go' };
if (!Object.hasOwn(bridges, mode))
  throw new Error("unsupported native bridge mode");
const source = resolve(sourceArg),
  output = resolve(outputArg);
if (existsSync(output) || existsSync(`${output}.json`)) throw new Error('Native output already exists; choose a new build directory');
verifyVendoredClairveilProtoContractSnapshot({ clairveilSourceRoot: source });
const stage = mkdtempSync(join(tmpdir(), "clairveil-audit-native-build-"));
const sha = (b) => createHash("sha256").update(b).digest("hex");
try {
  const resolved = execFileSync("git", ["rev-parse", `${commit}^{commit}`], {
    cwd: source,
    encoding: "utf8",
  }).trim();
  if (resolved !== commit) throw new Error("Core commit mismatch");
  const archive = execFileSync(
    "git",
    ["archive", commit, "go.mod", "go.sum", "types", "internal", "x/privacy"],
    { cwd: source, maxBuffer: 128 * 1024 * 1024 },
  );
  execFileSync("tar", ["-x", "-C", stage], { input: archive });
  const bridge = readFileSync(
    join(
      packageRoot,
      `tools/${bridges[mode]}`,
    ),
  );
  const command = join(stage, "x/privacy/crypto/cmd/clairveiljs-audit");
  mkdirSync(command, { recursive: true });
  writeFileSync(join(command, "main.go"), bridge);
  const kat = execFileSync(
    "go",
    [
      "test",
      "-mod=readonly",
      "./x/privacy/crypto/auditfield",
      "-run",
      "^TestFourKindNativeKAT$",
      "-count=1",
      "-json",
    ],
    { cwd: stage, encoding: "utf8" },
  );
  const events = kat
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  for (const name of [
    "TestFourKindNativeKAT",
    ...["final_deposit", "final_spend", "final_join", "final_batch"].map(
      (n) => `TestFourKindNativeKAT/${n}`,
    ),
  ])
    if (!events.some((e) => e.Test === name && e.Action === "pass"))
      throw new Error("required native KAT missing, failed or skipped");
  mkdirSync(dirname(output), { recursive: true });
  execFileSync(
    "go",
    [
      "build",
      "-mod=readonly",
      "-trimpath",
      "-buildvcs=false",
      "-o",
      output,
      "./x/privacy/crypto/cmd/clairveiljs-audit",
    ],
    { cwd: stage, stdio: ["ignore", "pipe", "pipe"] },
  );
  const metadata = {
    mode,
    coreCommit: commit,
    bridgeSHA256: sha(bridge),
    archiveSHA256: sha(archive),
    binarySHA256: sha(readFileSync(output)),
    platform: process.platform,
    arch: process.arch,
    goVersion: execFileSync("go", ["version"], {
      cwd: stage,
      encoding: "utf8",
    }).trim(),
    nativeKnownAnswerTests: "passed",
  };
  writeFileSync(`${output}.json`, JSON.stringify(metadata, null, 2) + "\n");
  process.stdout.write(JSON.stringify(metadata, null, 2) + "\n");
} finally {
  rmSync(stage, { recursive: true, force: true });
}
