import {
  clairveilConformanceFixtureSkipReason,
  clairveilConformanceFixturesAvailable,
  defaultConformanceFixtureDir,
  readClairveilConformanceFixture,
  resolveClairveilConformanceFixtureDir
} from "clairveiljs/conformance";

export const defaultFixtureDir = defaultConformanceFixtureDir;
export const fixtureDir = resolveClairveilConformanceFixtureDir();
export const fixturesRequired = process.env.CLAIRVEIL_CONFORMANCE_REQUIRED === "1";
export const fixturesAvailable = clairveilConformanceFixturesAvailable({ fixtureDir });

if (!fixturesAvailable && fixturesRequired) {
  throw new Error(clairveilConformanceFixtureSkipReason({ fixtureDir }));
}

export const fixtureSkipReason = fixturesAvailable
  ? ""
  : `${clairveilConformanceFixtureSkipReason({ fixtureDir })} Set CLAIRVEIL_CONFORMANCE_REQUIRED=1 to fail instead of skipping.`;

export const fixtureTestOptions = fixtureSkipReason ? { skip: fixtureSkipReason } : {};

export function readFixture(name) {
  return readClairveilConformanceFixture(name, { fixtureDir });
}

export function hexToBase64(hex) {
  return Buffer.from(hex, "hex").toString("base64");
}

export function utf8ToHex(text) {
  return Buffer.from(text, "utf8").toString("hex");
}
