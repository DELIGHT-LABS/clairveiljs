import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  clairveilConformanceBundleVersion,
  conformanceFixtureRelativePath,
  defaultConformanceFixtureNames,
  supportedClairveilCommit,
  supportedClairveilSourceKind
} from "../src/conformance.js";

const defaultPackageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const defaultClairveilSourceRoot = resolve(defaultPackageRoot, "..", "clairveil");

export const clairveilContractManifestRelativePath =
  `fixtures/clairveil-${clairveilConformanceBundleVersion}/manifest.json`;

export const clairveilProtoContractRelativePaths = Object.freeze([
  "clairveil/privacy/v1/batch_feasibility.proto",
  "clairveil/privacy/v1/genesis.proto",
  "clairveil/privacy/v1/query.proto",
  "clairveil/privacy/v1/tx.proto"
]);

const walletContractSchemaRelativePath =
  "docs/schemas/clairveil-js-wallet-contract.schema.json";

function expectedManifestFiles() {
  return [
    ...clairveilProtoContractRelativePaths.map(relativePath => ({
      kind: "protobuf",
      local_path: `proto/${relativePath}`,
      upstream_path: `proto/${relativePath}`
    })),
    ...defaultConformanceFixtureNames.map(name => ({
      kind: "conformance_fixture",
      local_path:
        `fixtures/clairveil-${clairveilConformanceBundleVersion}/${conformanceFixtureRelativePath}/${name}`,
      upstream_path: `${conformanceFixtureRelativePath}/${name}`
    })),
    {
      kind: "json_schema",
      local_path:
        `fixtures/clairveil-${clairveilConformanceBundleVersion}/${walletContractSchemaRelativePath}`,
      upstream_path: walletContractSchemaRelativePath
    }
  ];
}

function fail(message) {
  throw new Error(`Clairveil contract snapshot verification failed: ${message}`);
}

function fileSha256(filePath) {
  try {
    return createHash("sha256").update(readFileSync(filePath)).digest("hex");
  } catch (error) {
    fail(`cannot read ${filePath}: ${error.message}`);
  }
}

function gitOutput(sourceRoot, args, { encoding = "utf8" } = {}) {
  try {
    return execFileSync("git", ["-C", sourceRoot, ...args], {
      encoding,
      maxBuffer: 32 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"]
    });
  } catch (error) {
    const detail = Buffer.isBuffer(error?.stderr)
      ? error.stderr.toString("utf8").trim()
      : String(error?.stderr || error?.message || "git command failed").trim();
    fail(`${detail} (Clairveil source checkout: ${sourceRoot})`);
  }
}

function verifyClairveilCommitObject(sourceRoot) {
  const insideWorkTree = gitOutput(sourceRoot, ["rev-parse", "--is-inside-work-tree"]).trim();
  if (insideWorkTree !== "true") {
    fail(`${sourceRoot} is not a Clairveil git checkout`);
  }
  const objectType = gitOutput(sourceRoot, ["cat-file", "-t", supportedClairveilCommit]).trim();
  if (objectType !== "commit") {
    fail(`${supportedClairveilCommit} is not a commit object in ${sourceRoot}`);
  }
}

function clairveilCommitFile(sourceRoot, upstreamPath) {
  return gitOutput(
    sourceRoot,
    ["cat-file", "blob", `${supportedClairveilCommit}:${upstreamPath}`],
    { encoding: null }
  );
}

function readManifest(manifestPath) {
  try {
    return JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (error) {
    fail(`cannot read ${manifestPath}: ${error.message}`);
  }
}

function inspectBundledClairveilContractSnapshot({
  packageRoot = defaultPackageRoot
} = {}) {
  const resolvedPackageRoot = resolve(packageRoot);
  const manifestPath = join(
    resolvedPackageRoot,
    clairveilContractManifestRelativePath
  );
  const manifest = readManifest(manifestPath);

  if (manifest.manifest_version !== 2) {
    fail(`manifest_version is ${manifest.manifest_version}; expected 2`);
  }
  if (manifest.source?.repository !== "https://github.com/DELIGHT-LABS/clairveil") {
    fail("manifest source repository is not the Clairveil repository");
  }
  const sourceKeys = Object.keys(manifest.source || {}).sort();
  const expectedSourceKeys = ["commit", "kind", "repository"];
  if (
    sourceKeys.length !== expectedSourceKeys.length ||
    sourceKeys.some((key, index) => key !== expectedSourceKeys[index])
  ) {
    fail("manifest source must identify only an exact commit snapshot");
  }
  if (manifest.source?.kind !== supportedClairveilSourceKind) {
    fail(
      `manifest source kind is ${manifest.source?.kind}; expected ${supportedClairveilSourceKind}`
    );
  }
  if (manifest.source?.commit !== supportedClairveilCommit) {
    fail(
      `manifest commit is ${manifest.source?.commit}; expected ${supportedClairveilCommit}`
    );
  }
  if (!Array.isArray(manifest.files)) {
    fail("manifest files must be an array");
  }

  const filesByLocalPath = new Map();
  for (const entry of manifest.files) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      fail("manifest contains a non-object file entry");
    }
    const entryKeys = Object.keys(entry).sort();
    const expectedKeys = ["kind", "local_path", "sha256", "upstream_path"];
    if (
      entryKeys.length !== expectedKeys.length ||
      entryKeys.some((key, index) => key !== expectedKeys[index])
    ) {
      fail(`manifest entry ${entry.local_path || "<unknown>"} has unexpected fields`);
    }
    if (filesByLocalPath.has(entry.local_path)) {
      fail(`manifest contains duplicate local_path ${entry.local_path}`);
    }
    filesByLocalPath.set(entry.local_path, entry);
  }

  const expectedFiles = expectedManifestFiles();
  if (filesByLocalPath.size !== expectedFiles.length) {
    fail(
      `manifest contains ${filesByLocalPath.size} files; expected ${expectedFiles.length}`
    );
  }

  const files = [];
  for (const expected of expectedFiles) {
    const entry = filesByLocalPath.get(expected.local_path);
    if (!entry) {
      fail(`manifest is missing ${expected.local_path}`);
    }
    if (entry.kind !== expected.kind) {
      fail(
        `${expected.local_path} kind is ${entry.kind}; expected ${expected.kind}`
      );
    }
    if (entry.upstream_path !== expected.upstream_path) {
      fail(
        `${expected.local_path} upstream_path is ${entry.upstream_path}; expected ${expected.upstream_path}`
      );
    }
    if (!/^[0-9a-f]{64}$/.test(entry.sha256)) {
      fail(`${expected.local_path} has an invalid SHA-256 digest`);
    }

    const localFilePath = join(resolvedPackageRoot, entry.local_path);
    const actualSha256 = fileSha256(localFilePath);
    if (actualSha256 !== entry.sha256) {
      fail(
        `${entry.local_path} SHA-256 is ${actualSha256}; expected ${entry.sha256}`
      );
    }
    files.push({ entry, localFilePath });
  }

  return {
    result: {
      bundleVersion: clairveilConformanceBundleVersion,
      sourceKind: supportedClairveilSourceKind,
      commit: supportedClairveilCommit,
      manifestPath,
      fileCount: expectedFiles.length,
      protobufCount: clairveilProtoContractRelativePaths.length,
      fixtureCount: defaultConformanceFixtureNames.length,
      schemaCount: 1
    },
    files
  };
}

export function verifyBundledClairveilContractSnapshot(options = {}) {
  return inspectBundledClairveilContractSnapshot(options).result;
}

export function verifyVendoredClairveilContractSnapshot({
  packageRoot = defaultPackageRoot,
  clairveilSourceRoot = process.env.CLAIRVEIL_SOURCE_DIR || defaultClairveilSourceRoot
} = {}) {
  const { result, files } = inspectBundledClairveilContractSnapshot({ packageRoot });
  const resolvedClairveilSourceRoot = resolve(clairveilSourceRoot);
  verifyClairveilCommitObject(resolvedClairveilSourceRoot);

  for (const { entry, localFilePath } of files) {
    const localBytes = readFileSync(localFilePath);
    const upstreamBytes = clairveilCommitFile(
      resolvedClairveilSourceRoot,
      entry.upstream_path
    );
    if (!localBytes.equals(upstreamBytes)) {
      fail(
        `${entry.local_path} does not match ${entry.upstream_path} at ` +
        `Clairveil commit ${supportedClairveilCommit}`
      );
    }
  }

  return {
    ...result,
    clairveilSourceRoot: resolvedClairveilSourceRoot
  };
}

function isDirectInvocation() {
  return Boolean(
    process.argv[1] &&
    pathToFileURL(resolve(process.argv[1])).href === import.meta.url
  );
}

if (isDirectInvocation()) {
  try {
    const result = verifyVendoredClairveilContractSnapshot();
    console.log(
      `verified bundled Clairveil ${result.sourceKind} ${result.commit} ` +
      `for ClairveilJS ${result.bundleVersion}: ` +
      `${result.protobufCount} protobufs, ${result.fixtureCount} conformance fixtures, ` +
      `${result.schemaCount} JSON Schema`
    );
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
