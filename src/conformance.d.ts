export const conformanceFixtureRelativePath: string;
export const defaultConformanceFixtureDir: string;
export const defaultConformanceFixtureNames: readonly string[];

export interface ClairveilConformanceFixtureOptions {
  fixtureDir?: string;
  fixtureNames?: string[];
  fixtures?: string[];
  required?: boolean;
  runner?: ClairveilConformanceFixtureRunner;
  test?: ClairveilConformanceFixtureRunner;
}

export type ClairveilConformanceFixtureMap = Record<string, object>;

export type ClairveilConformanceFixtureRunner = (
  fixtures: ClairveilConformanceFixtureMap,
  context: { fixtureDir: string }
) => unknown | Promise<unknown>;

export interface ClairveilConformanceRunResult {
  skipped: boolean;
  reason: string;
  fixtureDir: string;
  fixtures: ClairveilConformanceFixtureMap;
  result?: unknown;
}

export function resolveClairveilConformanceFixtureDir(options?: ClairveilConformanceFixtureOptions): string;
export function suggestClairveilConformanceFixtureDirs(options?: { cwd?: string }): string[];
export function clairveilConformanceFixturesAvailable(options?: ClairveilConformanceFixtureOptions): boolean;
export function clairveilConformanceFixtureSkipReason(options?: ClairveilConformanceFixtureOptions): string;
export function readClairveilConformanceFixture(name: string, options?: ClairveilConformanceFixtureOptions): object;
export function loadClairveilConformanceFixtures(options?: ClairveilConformanceFixtureOptions): ClairveilConformanceFixtureMap;
export function runClairveilConformanceFixtures(
  options?: ClairveilConformanceFixtureOptions,
  runner?: ClairveilConformanceFixtureRunner
): Promise<ClairveilConformanceRunResult>;
