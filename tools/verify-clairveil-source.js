import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  conformanceFixtureRelativePath,
  defaultConformanceFixtureNames,
  supportedClairveilCommit,
  supportedClairveilRelease
} from "../src/conformance.js";

const defaultPackageRoot = dirname(dirname(fileURLToPath(import.meta.url)));

export const clairveilReleaseManifestRelativePath =
  `fixtures/clairveil-${supportedClairveilRelease}/manifest.json`;

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
        `fixtures/clairveil-${supportedClairveilRelease}/${conformanceFixtureRelativePath}/${name}`,
      upstream_path: `${conformanceFixtureRelativePath}/${name}`
    })),
    {
      kind: "json_schema",
      local_path:
        `fixtures/clairveil-${supportedClairveilRelease}/${walletContractSchemaRelativePath}`,
      upstream_path: walletContractSchemaRelativePath
    }
  ];
}

function fail(message) {
  throw new Error(`Clairveil release contract verification failed: ${message}`);
}

function fileSha256(filePath) {
  try {
    return createHash("sha256").update(readFileSync(filePath)).digest("hex");
  } catch (error) {
    fail(`cannot read ${filePath}: ${error.message}`);
  }
}

function readManifest(manifestPath) {
  try {
    return JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch (error) {
    fail(`cannot read ${manifestPath}: ${error.message}`);
  }
}

export function verifyVendoredClairveilRelease({
  packageRoot = defaultPackageRoot
} = {}) {
  const resolvedPackageRoot = resolve(packageRoot);
  const manifestPath = join(
    resolvedPackageRoot,
    clairveilReleaseManifestRelativePath
  );
  const manifest = readManifest(manifestPath);

  if (manifest.manifest_version !== 1) {
    fail(`manifest_version is ${manifest.manifest_version}; expected 1`);
  }
  if (manifest.source?.repository !== "https://github.com/DELIGHT-LABS/clairveil") {
    fail("manifest source repository is not the Clairveil repository");
  }
  if (manifest.source?.release !== supportedClairveilRelease) {
    fail(
      `manifest release is ${manifest.source?.release}; expected ${supportedClairveilRelease}`
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

    const actualSha256 = fileSha256(join(resolvedPackageRoot, entry.local_path));
    if (actualSha256 !== entry.sha256) {
      fail(
        `${entry.local_path} SHA-256 is ${actualSha256}; expected ${entry.sha256}`
      );
    }
  }

  return {
    release: supportedClairveilRelease,
    commit: supportedClairveilCommit,
    manifestPath,
    fileCount: expectedFiles.length,
    protobufCount: clairveilProtoContractRelativePaths.length,
    fixtureCount: defaultConformanceFixtureNames.length,
    schemaCount: 1
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
    const result = verifyVendoredClairveilRelease();
    console.log(
      `verified bundled Clairveil ${result.release} (${result.commit}): ` +
      `${result.protobufCount} protobufs, ${result.fixtureCount} conformance fixtures, ` +
      `${result.schemaCount} JSON Schema`
    );
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
