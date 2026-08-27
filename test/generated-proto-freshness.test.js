import test from "node:test";
import assert from "node:assert/strict";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));

test("proto freshness gate rejects an orphan generated binding", () => {
  const temporaryRoot = mkdtempSync(join(tmpdir(), "clairveiljs-orphan-proto-"));
  try {
    for (const file of ["package.json", "telescope.config.json", "tsconfig.codegen.json"]) {
      cpSync(join(packageRoot, file), join(temporaryRoot, file));
    }
    cpSync(join(packageRoot, "proto"), join(temporaryRoot, "proto"), { recursive: true });
    cpSync(join(packageRoot, "codegen"), join(temporaryRoot, "codegen"), { recursive: true });
    mkdirSync(join(temporaryRoot, "src"), { recursive: true });
    cpSync(join(packageRoot, "src", "generated"), join(temporaryRoot, "src", "generated"), {
      recursive: true
    });
    mkdirSync(join(temporaryRoot, "tools"), { recursive: true });
    for (const file of ["check-generated-proto-freshness.js", "patch-generated-helpers.js"]) {
      cpSync(join(packageRoot, "tools", file), join(temporaryRoot, "tools", file));
    }
    symlinkSync(join(packageRoot, "node_modules"), join(temporaryRoot, "node_modules"), "dir");

    const orphan = join(
      temporaryRoot,
      "src",
      "generated",
      "clairveil",
      "privacy",
      "v1",
      "removed_contract.js"
    );
    writeFileSync(orphan, "export const stale = true;\n");

    const result = spawnSync(
      process.execPath,
      [join(temporaryRoot, "tools", "check-generated-proto-freshness.js")],
      { cwd: temporaryRoot, encoding: "utf8" }
    );
    assert.notEqual(result.status, 0);
    assert.match(`${result.stderr}\n${result.stdout}`, /removed_contract\.js/);
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
