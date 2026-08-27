import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const supportedModes = new Set(["local", "testnet"]);
const genericPrefix = "CLAIRVEIL_E2E_";

export function cosmosE2eChildEnvironment(mode, sourceEnv = process.env) {
  const normalizedMode = String(mode || "").trim().toLowerCase();
  if (!supportedModes.has(normalizedMode)) {
    throw new Error("Cosmos E2E mode must be local or testnet");
  }

  const scopedPrefix = `${genericPrefix}${normalizedMode.toUpperCase()}_`;
  const childEnv = {};
  for (const [name, value] of Object.entries(sourceEnv || {})) {
    if (!name.startsWith(genericPrefix) && value != null) {
      childEnv[name] = String(value);
    }
  }
  for (const [name, value] of Object.entries(sourceEnv || {})) {
    if (!name.startsWith(scopedPrefix) || value == null) continue;
    const suffix = name.slice(scopedPrefix.length);
    if (suffix) childEnv[`${genericPrefix}${suffix}`] = String(value);
  }

  childEnv.CLAIRVEIL_E2E_FULL_FLOW = "1";
  childEnv.CLAIRVEIL_E2E_ONE_PROOF_BATCH = "1";
  childEnv.CLAIRVEIL_E2E_ONE_PROOF_BATCH_SHAPE = "all";
  childEnv.CLAIRVEIL_E2E_REQUIRED = "1";
  if (normalizedMode === "local") {
    childEnv.CLAIRVEIL_E2E_LOCAL = "1";
  } else {
    childEnv.CLAIRVEIL_E2E_TESTNET = "1";
  }
  return childEnv;
}

export function runCosmosE2E(mode, sourceEnv = process.env) {
  const testFile = fileURLToPath(new URL("../test/e2e-local.e2e.js", import.meta.url));
  const packageRoot = fileURLToPath(new URL("..", import.meta.url));
  const result = spawnSync(process.execPath, ["--test", testFile], {
    cwd: packageRoot,
    env: cosmosE2eChildEnvironment(mode, sourceEnv),
    stdio: "inherit"
  });
  if (result.error) throw result.error;
  if (result.signal) {
    throw new Error(`Cosmos ${mode} E2E terminated by ${result.signal}`);
  }
  return result.status ?? 1;
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  process.exitCode = runCosmosE2E(process.argv[2]);
}
