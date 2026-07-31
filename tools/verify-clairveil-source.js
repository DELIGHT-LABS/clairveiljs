import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  supportedClairveilCommit,
  supportedClairveilRelease
} from "../src/conformance.js";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const sourceDir = resolve(
  process.env.CLAIRVEIL_SOURCE_DIR || join(packageRoot, "..", "clairveil")
);

function git(...args) {
  const result = spawnSync("git", ["-C", sourceDir, ...args], {
    encoding: "utf8"
  });
  if (result.status !== 0) {
    const detail = String(result.stderr || result.stdout || "").trim();
    throw new Error(`failed to inspect Clairveil source at ${sourceDir}: ${detail}`);
  }
  return String(result.stdout || "").trim();
}

const tagCommit = git("rev-parse", `${supportedClairveilRelease}^{}`);
if (tagCommit !== supportedClairveilCommit) {
  throw new Error(
    `${supportedClairveilRelease} resolves to ${tagCommit}, expected ${supportedClairveilCommit}`
  );
}
const sourceCommit = git("rev-parse", "HEAD");
if (sourceCommit !== supportedClairveilCommit) {
  throw new Error(
    `Clairveil source HEAD is ${sourceCommit}; check out ${supportedClairveilRelease} (${supportedClairveilCommit}) for release verification`
  );
}
const trackedChanges = git("status", "--porcelain", "--untracked-files=no");
if (trackedChanges) {
  throw new Error(
    `Clairveil source at ${sourceDir} has tracked worktree changes; release verification requires the immutable ${supportedClairveilRelease} tree`
  );
}

const protoFiles = [
  "clairveil/privacy/v1/batch_feasibility.proto",
  "clairveil/privacy/v1/genesis.proto",
  "clairveil/privacy/v1/query.proto",
  "clairveil/privacy/v1/tx.proto"
];
for (const relativePath of protoFiles) {
  const upstream = readFileSync(join(sourceDir, "proto", relativePath));
  const local = readFileSync(join(packageRoot, "proto", relativePath));
  if (!upstream.equals(local)) {
    throw new Error(
      `local proto/${relativePath} does not match ${supportedClairveilRelease}`
    );
  }
}

console.log(
  `verified Clairveil ${supportedClairveilRelease} source ${supportedClairveilCommit} and ${protoFiles.length} protobuf contracts`
);
