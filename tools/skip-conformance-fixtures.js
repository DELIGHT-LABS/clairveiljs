import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Keep the fast unit suite independent of conformance replay. The strict
// release command runs the bundled fixtures through test:conformance:required.
process.env.CLAIRVEIL_CONFORMANCE_FIXTURE_DIR = join(
  tmpdir(),
  `clairveil-unit-fixtures-${process.pid}-${randomUUID()}`
);
