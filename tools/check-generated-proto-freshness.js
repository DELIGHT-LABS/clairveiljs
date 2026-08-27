import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const generatedRoots = ["codegen/generated", "src/generated"];

function filesBelow(packageRoot, root) {
  const absoluteRoot = resolve(packageRoot, root);
  const files = [];
  const visit = directory => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile()) files.push(path);
    }
  };
  if (existsSync(absoluteRoot)) visit(absoluteRoot);
  return files.sort();
}

function generatedSnapshot(packageRoot) {
  const snapshot = new Map();
  for (const root of generatedRoots) {
    for (const path of filesBelow(packageRoot, root)) {
      snapshot.set(
        relative(packageRoot, path),
        createHash("sha256").update(readFileSync(path)).digest("hex")
      );
    }
  }
  return snapshot;
}

function changedGeneratedFiles(before, after) {
  const paths = new Set([...before.keys(), ...after.keys()]);
  return [...paths]
    .filter(path => before.get(path) !== after.get(path))
    .sort();
}

function freshGeneratedSnapshot() {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "clairveiljs-proto-freshness-"));
  try {
    for (const file of ["package.json", "telescope.config.json", "tsconfig.codegen.json"]) {
      cpSync(join(repositoryRoot, file), join(temporaryRoot, file));
    }
    cpSync(join(repositoryRoot, "proto"), join(temporaryRoot, "proto"), {
      recursive: true
    });
    mkdirSync(join(temporaryRoot, "tools"), { recursive: true });
    cpSync(
      join(repositoryRoot, "tools", "patch-generated-helpers.js"),
      join(temporaryRoot, "tools", "patch-generated-helpers.js")
    );
    symlinkSync(join(repositoryRoot, "node_modules"), join(temporaryRoot, "node_modules"), "dir");

    const codegen = spawnSync("npm", ["run", "codegen:proto"], {
      cwd: temporaryRoot,
      env: process.env,
      encoding: "utf8"
    });
    if (codegen.error) throw codegen.error;
    if (codegen.status !== 0) {
      throw new Error(
        `isolated protobuf codegen failed with exit ${codegen.status || 1}:\n` +
        `${codegen.stderr || codegen.stdout || "no output"}`
      );
    }
    return generatedSnapshot(temporaryRoot);
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

const changed = changedGeneratedFiles(
  generatedSnapshot(repositoryRoot),
  freshGeneratedSnapshot()
);
if (changed.length) {
  const listed = changed.slice(0, 25).map(path => `  - ${path}`).join("\n");
  const remainder = changed.length > 25 ? `\n  - ... and ${changed.length - 25} more` : "";
  throw new Error(
    `generated protobuf bindings do not exactly match clean codegen output:\n${listed}${remainder}\n` +
    "Run npm run codegen:proto after removing stale generated files, then commit every generated change."
  );
}
