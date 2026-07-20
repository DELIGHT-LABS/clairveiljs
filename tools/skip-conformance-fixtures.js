import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Package checks must not depend on a sibling Clairveil checkout. Release
// verification enables the fixtures explicitly through test:conformance:required.
process.env.CLAIRVEIL_CONFORMANCE_FIXTURE_DIR = join(
  tmpdir(),
  `clairveil-unit-fixtures-${process.pid}-${randomUUID()}`
);
