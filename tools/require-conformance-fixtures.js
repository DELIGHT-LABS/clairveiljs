const forbiddenReleaseOverrides = [
  "CLAIRVEIL_CONFORMANCE_FIXTURE_DIR",
  "CLAIRVEIL_WALLET_CONTRACT_SCHEMA"
];

for (const name of forbiddenReleaseOverrides) {
  if (String(process.env[name] ?? "").trim()) {
    throw new Error(
      `${name} cannot override the ClairveilJS bundled fixtures in the required release gate`
    );
  }
}

process.env.CLAIRVEIL_CONFORMANCE_REQUIRED = "1";
process.env.CLAIRVEIL_CONFORMANCE_RELEASE_PINNED = "1";
