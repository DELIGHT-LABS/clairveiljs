import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(process.argv[2] ?? join(root, "../clairveil"));
const directory = mkdtempSync(
  join(tmpdir(), "clairveil-audit-native-verification-"),
);
try {
  const binary = join(directory, "encrypt");
  execFileSync(
    process.execPath,
    [join(root, "tools/build-audit-native.js"), source, binary],
    { cwd: root, stdio: "inherit" },
  );
  const metadata = JSON.parse(readFileSync(`${binary}.json`, "utf8"));
  execFileSync(process.execPath, ["--test", "test/audit-native-node.test.js"], {
    cwd: root,
    stdio: "inherit",
    env: {
      ...process.env,
      CLAIRVEIL_AUDIT_NATIVE_BINARY: binary,
      CLAIRVEIL_AUDIT_NATIVE_SHA256: metadata.binarySHA256,
    },
  });
} finally {
  rmSync(directory, { recursive: true, force: true });
}
