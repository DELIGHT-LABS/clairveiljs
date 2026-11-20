import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  clairveilConformanceBundleVersion,
  clairveilProverConformanceBundleVersion,
  clairveilProtoBundleVersion,
  supportedClairveilProtoCommit,
  supportedClairveilProtoRelease,
  supportedClairveilProtoSourceKind,
  conformanceFixtureRelativePath,
  defaultConformanceFixtureNames,
  defaultProverConformanceFixtureNames,
  proverHttpApiSchemaRelativePath,
  supportedClairveilCommit,
  supportedClairveilProverCommit,
  supportedClairveilProverRelease,
  supportedClairveilProverSourceKind,
  supportedClairveilSourceKind
} from "../src/conformance.js";

const defaultPackageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const defaultClairveilSourceRoot = resolve(defaultPackageRoot, "..", "clairveil");

export const clairveilContractManifestRelativePath =
  `fixtures/clairveil-${clairveilConformanceBundleVersion}/manifest.json`;
export const clairveilProverContractManifestRelativePath =
  `fixtures/clairveil-${clairveilProverConformanceBundleVersion}-prover/manifest.json`;

export const clairveilProtoContractManifestRelativePath =
  `fixtures/clairveil-${clairveilProtoBundleVersion}-proto/manifest.json`;

export const clairveilProtoContractRelativePaths = Object.freeze([
  "clairveil/privacy/v1/batch_feasibility.proto",
  "clairveil/privacy/v1/genesis.proto",
  "clairveil/privacy/v1/query.proto",
  "clairveil/privacy/v1/tx.proto"
]);

export const currentClairveilProtoContractRelativePaths = Object.freeze([
  ...clairveilProtoContractRelativePaths,
  "clairveil/privacy/v2/query.proto",
  "clairveil/privacy/v2/tx.proto"
]);

const walletContractSchemaRelativePath =
  "docs/schemas/clairveil-js-wallet-contract.schema.json";

function expectedManifestFiles() {
  return [
    ...clairveilProtoContractRelativePaths.map(relativePath => ({
      kind: "protobuf",
      local_path: `fixtures/clairveil-${clairveilConformanceBundleVersion}/proto/${relativePath}`,
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

function expectedProverManifestFiles() {
  const bundleRoot = `fixtures/clairveil-${clairveilProverConformanceBundleVersion}-prover`;
  return [
    ...defaultProverConformanceFixtureNames.map(name => ({
      kind: "conformance_fixture",
      local_path: `${bundleRoot}/${conformanceFixtureRelativePath}/${name}`,
      upstream_path: `${conformanceFixtureRelativePath}/${name}`
    })),
    {
      kind: "json_schema",
      local_path: `${bundleRoot}/${proverHttpApiSchemaRelativePath}`,
      upstream_path: proverHttpApiSchemaRelativePath
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

function verifyClairveilCommitObject(sourceRoot, commit = supportedClairveilCommit) {
  const insideWorkTree = gitOutput(sourceRoot, ["rev-parse", "--is-inside-work-tree"]).trim();
  if (insideWorkTree !== "true") {
    fail(`${sourceRoot} is not a Clairveil git checkout`);
  }
  const objectType = gitOutput(sourceRoot, ["cat-file", "-t", commit]).trim();
  if (objectType !== "commit") {
    fail(`${commit} is not a commit object in ${sourceRoot}`);
  }
}

function verifyClairveilReleaseTag(
  sourceRoot,
  release = supportedClairveilProverRelease,
  commit = supportedClairveilProverCommit
) {
  verifyClairveilCommitObject(sourceRoot, commit);
  const tagRef = `refs/tags/${release}`;
  const tagObjectType = gitOutput(sourceRoot, ["cat-file", "-t", tagRef]).trim();
  if (tagObjectType !== "tag") {
    fail(
      `Clairveil tag ${release} must be annotated; ` +
      `got ${tagObjectType || "an unknown object type"}`
    );
  }
  const tagHeader = gitOutput(sourceRoot, ["cat-file", "-p", tagRef])
    .split(/\r?\n\r?\n/, 1)[0];
  const headerLines = tagHeader.split(/\r?\n/);
  const headerValues = name => headerLines
    .filter(line => line.startsWith(`${name} `))
    .map(line => line.slice(name.length + 1));
  const targetObjects = headerValues("object");
  const targetTypes = headerValues("type");
  const tagNames = headerValues("tag");
  if (targetObjects.length !== 1 || targetTypes.length !== 1 || tagNames.length !== 1 ||
      !/^[0-9a-f]+$/.test(targetObjects[0]) || !/^\S+$/.test(targetTypes[0]) ||
      !/^\S+$/.test(tagNames[0])) {
    fail(`Clairveil tag ${release} has malformed tag headers`);
  }
  const [targetObject] = targetObjects;
  const [targetType] = targetTypes;
  const [tagName] = tagNames;
  if (tagName !== release) {
    fail(
      `Clairveil tag ${release} declares embedded tag name ${tagName}; ` +
      `expected ${release}`
    );
  }
  if (targetType !== "commit") {
    fail(
      `Clairveil tag ${release} must directly target a commit; ` +
      `got ${targetType}`
    );
  }
  if (targetObject !== commit) {
    fail(
      `Clairveil tag ${release} directly targets ${targetObject}; ` +
      `expected ${commit}`
    );
  }
}

function clairveilCommitFile(sourceRoot, upstreamPath, commit = supportedClairveilCommit) {
  return gitOutput(
    sourceRoot,
    ["cat-file", "blob", `${commit}:${upstreamPath}`],
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

function inspectContractBundle({
  packageRoot,
  manifestRelativePath,
  expectedFiles,
  expectedSource,
  sourceIdentityDescription,
  resultMetadata,
  label = ""
}) {
  const resolvedPackageRoot = resolve(packageRoot);
  const manifestPath = join(resolvedPackageRoot, manifestRelativePath);
  const manifest = readManifest(manifestPath);
  const prefix = label ? `${label} ` : "";

  if (manifest.manifest_version !== 2) {
    fail(`${prefix}manifest_version is ${manifest.manifest_version}; expected 2`);
  }
  if (manifest.source?.repository !== "https://github.com/DELIGHT-LABS/clairveil") {
    fail(`${prefix}manifest source repository is not the Clairveil repository`);
  }
  const sourceKeys = Object.keys(manifest.source || {}).sort();
  const expectedSourceKeys = Object.keys(expectedSource).sort();
  if (
    sourceKeys.length !== expectedSourceKeys.length ||
    sourceKeys.some((key, index) => key !== expectedSourceKeys[index])
  ) {
    fail(`${prefix}manifest source must identify only ${sourceIdentityDescription}`);
  }
  for (const [field, expected] of Object.entries(expectedSource)) {
    if (manifest.source?.[field] !== expected) {
      const fieldLabel = field === "kind" ? "source kind" : field;
      fail(
        `${prefix}manifest ${fieldLabel} is ${manifest.source?.[field]}; expected ${expected}`
      );
    }
  }
  if (!Array.isArray(manifest.files)) {
    fail(`${prefix}manifest files must be an array`);
  }

  const filesByLocalPath = new Map();
  for (const entry of manifest.files) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      fail(`${prefix}manifest contains a non-object file entry`);
    }
    const entryKeys = Object.keys(entry).sort();
    const expectedKeys = ["kind", "local_path", "sha256", "upstream_path"];
    if (
      entryKeys.length !== expectedKeys.length ||
      entryKeys.some((key, index) => key !== expectedKeys[index])
    ) {
      fail(`${prefix}manifest entry ${entry.local_path || "<unknown>"} has unexpected fields`);
    }
    if (filesByLocalPath.has(entry.local_path)) {
      fail(`${prefix}manifest contains duplicate local_path ${entry.local_path}`);
    }
    filesByLocalPath.set(entry.local_path, entry);
  }

  if (filesByLocalPath.size !== expectedFiles.length) {
    fail(
      `${prefix}manifest contains ${filesByLocalPath.size} files; expected ${expectedFiles.length}`
    );
  }

  const files = [];
  for (const expected of expectedFiles) {
    const entry = filesByLocalPath.get(expected.local_path);
    if (!entry) {
      fail(`${prefix}manifest is missing ${expected.local_path}`);
    }
    if (entry.kind !== expected.kind) {
      fail(
        `${expected.local_path} kind is ${entry.kind}; expected ${expected.kind}`
      );
    }
    if (entry.upstream_path !== expected.upstream_path) {
      fail(
        `${expected.local_path} upstream_path is ${entry.upstream_path}; ` +
        `expected ${expected.upstream_path}`
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
      ...resultMetadata,
      manifestPath,
      fileCount: expectedFiles.length
    },
    files
  };
}

function inspectBundledClairveilContractSnapshot({ packageRoot = defaultPackageRoot } = {}) {
  return inspectContractBundle({
    packageRoot,
    manifestRelativePath: clairveilContractManifestRelativePath,
    expectedFiles: expectedManifestFiles(),
    expectedSource: {
      repository: "https://github.com/DELIGHT-LABS/clairveil",
      kind: supportedClairveilSourceKind,
      commit: supportedClairveilCommit
    },
    sourceIdentityDescription: "an exact commit snapshot",
    resultMetadata: {
      bundleVersion: clairveilConformanceBundleVersion,
      sourceKind: supportedClairveilSourceKind,
      commit: supportedClairveilCommit,
      protobufCount: clairveilProtoContractRelativePaths.length,
      fixtureCount: defaultConformanceFixtureNames.length,
      schemaCount: 1
    }
  });
}

function inspectBundledClairveilProverContractSnapshot({ packageRoot = defaultPackageRoot } = {}) {
  return inspectContractBundle({
    packageRoot,
    manifestRelativePath: clairveilProverContractManifestRelativePath,
    expectedFiles: expectedProverManifestFiles(),
    expectedSource: {
      repository: "https://github.com/DELIGHT-LABS/clairveil",
      kind: supportedClairveilProverSourceKind,
      release: supportedClairveilProverRelease,
      commit: supportedClairveilProverCommit
    },
    sourceIdentityDescription: "an exact release tag and commit",
    resultMetadata: {
      bundleVersion: clairveilProverConformanceBundleVersion,
      sourceKind: supportedClairveilProverSourceKind,
      release: supportedClairveilProverRelease,
      commit: supportedClairveilProverCommit,
      protobufCount: 0,
      fixtureCount: defaultProverConformanceFixtureNames.length,
      schemaCount: 1
    },
    label: "prover"
  });
}

function inspectBundledClairveilProtoContractSnapshot({ packageRoot = defaultPackageRoot } = {}) {
  return inspectContractBundle({
    packageRoot,
    manifestRelativePath: clairveilProtoContractManifestRelativePath,
    expectedFiles: currentClairveilProtoContractRelativePaths.map(relativePath => ({
      kind: "protobuf",
      local_path: `proto/${relativePath}`,
      upstream_path: `proto/${relativePath}`
    })),
    expectedSource: {
      repository: "https://github.com/DELIGHT-LABS/clairveil",
      kind: supportedClairveilProtoSourceKind,
      release: supportedClairveilProtoRelease,
      commit: supportedClairveilProtoCommit
    },
    sourceIdentityDescription: "an exact release tag and commit",
    resultMetadata: {
      bundleVersion: clairveilProtoBundleVersion,
      sourceKind: supportedClairveilProtoSourceKind,
      release: supportedClairveilProtoRelease,
      commit: supportedClairveilProtoCommit,
      protobufCount: currentClairveilProtoContractRelativePaths.length,
      fixtureCount: 0,
      schemaCount: 0
    },
    label: "proto"
  });
}

export function verifyBundledClairveilProtoContractSnapshot(options = {}) {
  return inspectBundledClairveilProtoContractSnapshot(options).result;
}

export function verifyVendoredClairveilProtoContractSnapshot({
  packageRoot = defaultPackageRoot,
  clairveilSourceRoot = process.env.CLAIRVEIL_SOURCE_DIR || defaultClairveilSourceRoot
} = {}) {
  const { result, files } = inspectBundledClairveilProtoContractSnapshot({ packageRoot });
  const resolvedClairveilSourceRoot = resolve(clairveilSourceRoot);
  verifyClairveilReleaseTag(
    resolvedClairveilSourceRoot, supportedClairveilProtoRelease, supportedClairveilProtoCommit
  );
  for (const { entry, localFilePath } of files) {
    if (!readFileSync(localFilePath).equals(clairveilCommitFile(
      resolvedClairveilSourceRoot, entry.upstream_path, supportedClairveilProtoCommit
    ))) {
      fail(
        `${entry.local_path} does not match ${entry.upstream_path} at ` +
        `Clairveil ${supportedClairveilProtoRelease} commit ${supportedClairveilProtoCommit}`
      );
    }
  }
  return { ...result, clairveilSourceRoot: resolvedClairveilSourceRoot };
}

export function verifyBundledClairveilContractSnapshot(options = {}) {
  const lifecycle = inspectBundledClairveilContractSnapshot(options).result;
  const prover = inspectBundledClairveilProverContractSnapshot(options).result;
  const proto = inspectBundledClairveilProtoContractSnapshot(options).result;
  return {
    ...lifecycle,
    prover,
    proto,
    totalFileCount: lifecycle.fileCount + prover.fileCount + proto.fileCount,
    totalFixtureCount: lifecycle.fixtureCount + prover.fixtureCount,
    totalSchemaCount: lifecycle.schemaCount + prover.schemaCount
  };
}

export function verifyBundledClairveilProverContractSnapshot(options = {}) {
  return inspectBundledClairveilProverContractSnapshot(options).result;
}

export function verifyVendoredClairveilContractSnapshot({
  packageRoot = defaultPackageRoot,
  clairveilSourceRoot = process.env.CLAIRVEIL_SOURCE_DIR || defaultClairveilSourceRoot
} = {}) {
  const { result, files } = inspectBundledClairveilContractSnapshot({ packageRoot });
  const prover = inspectBundledClairveilProverContractSnapshot({ packageRoot });
  const resolvedClairveilSourceRoot = resolve(clairveilSourceRoot);
  verifyClairveilCommitObject(resolvedClairveilSourceRoot);
  verifyClairveilReleaseTag(resolvedClairveilSourceRoot);

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

  for (const { entry, localFilePath } of prover.files) {
    const localBytes = readFileSync(localFilePath);
    const upstreamBytes = clairveilCommitFile(
      resolvedClairveilSourceRoot,
      entry.upstream_path,
      supportedClairveilProverCommit
    );
    if (!localBytes.equals(upstreamBytes)) {
      fail(
        `${entry.local_path} does not match ${entry.upstream_path} at ` +
        `Clairveil ${supportedClairveilProverRelease} commit ${supportedClairveilProverCommit}`
      );
    }
  }

  const proto = verifyVendoredClairveilProtoContractSnapshot({ packageRoot, clairveilSourceRoot });
  return {
    ...result,
    prover: prover.result,
    proto,
    totalFileCount: result.fileCount + prover.result.fileCount + proto.fileCount,
    totalFixtureCount: result.fixtureCount + prover.result.fixtureCount,
    totalSchemaCount: result.schemaCount + prover.result.schemaCount,
    clairveilSourceRoot: resolvedClairveilSourceRoot
  };
}

export function verifyVendoredClairveilProverContractSnapshot({
  packageRoot = defaultPackageRoot,
  clairveilSourceRoot = process.env.CLAIRVEIL_SOURCE_DIR || defaultClairveilSourceRoot
} = {}) {
  const { result, files } = inspectBundledClairveilProverContractSnapshot({ packageRoot });
  const resolvedClairveilSourceRoot = resolve(clairveilSourceRoot);
  verifyClairveilReleaseTag(resolvedClairveilSourceRoot);
  for (const { entry, localFilePath } of files) {
    const localBytes = readFileSync(localFilePath);
    const upstreamBytes = clairveilCommitFile(
      resolvedClairveilSourceRoot,
      entry.upstream_path,
      supportedClairveilProverCommit
    );
    if (!localBytes.equals(upstreamBytes)) {
      fail(
        `${entry.local_path} does not match ${entry.upstream_path} at ` +
        `Clairveil ${supportedClairveilProverRelease} commit ${supportedClairveilProverCommit}`
      );
    }
  }
  return { ...result, clairveilSourceRoot: resolvedClairveilSourceRoot };
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
      `${result.schemaCount} JSON Schema; ` +
      `verified Clairveil ${result.prover.release} prover contract at ` +
      `${result.prover.commit}: ${result.prover.fixtureCount} conformance fixtures, ` +
      `${result.prover.schemaCount} JSON Schema; ` +
      `verified Clairveil ${result.proto.release} protobuf contract at ` +
      `${result.proto.commit}: ${result.proto.protobufCount} protobufs`
    );
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
