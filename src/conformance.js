import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const conformanceFixtureRelativePath = "x/privacy/client/sdk/conformance/testdata";
export const supportedClairveilRelease = "v0.3.1";
export const supportedClairveilCommit = "1a6ce6a0a0e10b765c025072b44c2364e9711b48";
export const defaultConformanceFixtureDir = `fixtures/clairveil-${supportedClairveilRelease}/${conformanceFixtureRelativePath}`;

export const batchTransferConformanceFixtureName = "privacy_batch_transfer_v1_contract.json";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));

export const defaultConformanceFixtureNames = Object.freeze([
  "privacy_wallet_golden_vectors.json",
  "privacy_browser_signer_provider_contract.json",
  "privacy_wallet_readonly_reference_bundle.json",
  "privacy_prover_example_bundle.json",
  "privacy_prover_http_api_contract.json",
  "privacy_send_capable_reference_flow.json",
  "privacy_batch_joinsplit_v1_contract.json",
  "privacy_note_v1_contract.json",
  "privacy_disclosure_blinding_v1_contract.json",
  batchTransferConformanceFixtureName,
  "privacy_note_reservation_contract.json",
  "privacy_relay_withdraw_contract.json"
]);

function resolveConformanceFixturePath(fixtureDir, name) {
  return join(fixtureDir, name);
}

export function suggestClairveilConformanceFixtureDirs({ cwd = process.cwd() } = {}) {
  return [
    resolve(packageRoot, defaultConformanceFixtureDir),
    resolve(cwd, defaultConformanceFixtureDir),
    resolve(cwd, conformanceFixtureRelativePath)
  ];
}

export function resolveClairveilConformanceFixtureDir({ fixtureDir } = {}) {
  if (fixtureDir) return fixtureDir;
  if (process.env.CLAIRVEIL_CONFORMANCE_FIXTURE_DIR) {
    return process.env.CLAIRVEIL_CONFORMANCE_FIXTURE_DIR;
  }
  const candidates = suggestClairveilConformanceFixtureDirs();
  return candidates.find(candidate => existsSync(candidate)) || candidates[0];
}

export function clairveilConformanceFixturesAvailable(options = {}) {
  return existsSync(resolveClairveilConformanceFixtureDir(options));
}

export function clairveilConformanceFixtureSkipReason(options = {}) {
  const fixtureDir = resolveClairveilConformanceFixtureDir(options);
  if (existsSync(fixtureDir)) return "";
  return `Bundled Clairveil ${supportedClairveilRelease} conformance fixtures not found at ${fixtureDir}. Set CLAIRVEIL_CONFORMANCE_FIXTURE_DIR only when intentionally testing another fixture directory.`;
}

export function readClairveilConformanceFixture(name, options = {}) {
  const fixtureDir = resolveClairveilConformanceFixtureDir(options);
  if (!existsSync(fixtureDir)) {
    throw new Error(clairveilConformanceFixtureSkipReason({ ...options, fixtureDir }));
  }
  return JSON.parse(readFileSync(resolveConformanceFixturePath(fixtureDir, name), "utf8"));
}

export function loadClairveilConformanceFixtures(options = {}) {
  const fixtureNames = options.fixtureNames || options.fixtures || defaultConformanceFixtureNames;
  const loaded = {};
  for (const name of fixtureNames) {
    loaded[name] = readClairveilConformanceFixture(name, options);
  }
  return loaded;
}

export async function runClairveilConformanceFixtures(options = {}, runner) {
  const required = Boolean(options.required ?? process.env.CLAIRVEIL_CONFORMANCE_REQUIRED === "1");
  const fixtureDir = resolveClairveilConformanceFixtureDir(options);
  const reason = clairveilConformanceFixtureSkipReason({ ...options, fixtureDir });
  if (reason) {
    if (required) throw new Error(reason);
    return {
      skipped: true,
      reason,
      fixtureDir,
      fixtures: {}
    };
  }

  const fixtures = loadClairveilConformanceFixtures({ ...options, fixtureDir });
  const callback = runner || options.runner || options.test;
  const result = typeof callback === "function"
    ? await callback(fixtures, { fixtureDir })
    : undefined;
  return {
    skipped: false,
    reason: "",
    fixtureDir,
    fixtures,
    result
  };
}
