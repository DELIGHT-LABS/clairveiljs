if (process.env.CLAIRVEIL_CONFORMANCE_FIXTURE_DIR) {
  throw new Error(
    "test:conformance:required uses ClairveilJS bundled fixtures; " +
    "use test:conformance for an explicit diagnostic fixture directory"
  );
}

process.env.CLAIRVEIL_CONFORMANCE_REQUIRED = "1";
process.env.CLAIRVEIL_CONFORMANCE_RELEASE_PINNED = "1";
