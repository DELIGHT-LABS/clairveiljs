import test from 'node:test';
import assert from 'node:assert/strict';
import { auditReleaseInputs } from '../tools/verify-audit-release.js';
import { readFileSync } from 'node:fs';
import { matchesAuditProofSource } from '../tools/audit-artifact-provenance.js';
test('V2 release cannot silently skip native proofs when Core or artifacts are missing', () => {
  for (const args of [[], ['/core'], ['/core','/cache','extra']]) assert.throws(() => auditReleaseInputs(args, {}), /requires explicit/);
  assert.deepEqual(auditReleaseInputs([], { CLAIRVEIL_SOURCE_DIR: '/core', CLAIRVEIL_AUDIT_ARTIFACT_CACHE: '/cache' }), { core: '/core', cache: '/cache' });
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url)));
  assert.match(pkg.scripts['verify:release:integration'], /npm run verify:release:audit/);
  assert.equal(pkg.scripts['verify:release:audit'], 'node tools/verify-audit-release.js');
});
test('historical raw-byte and gofmt cache identities both require the exact generator and all four circuits', () => {
  const expected = { coreCommit: 'core', archiveSHA256: 'archive', generatorSHA256: 'raw', generatorGofmtSHA256: 'formatted' };
  const base = { coreCommit: 'core', archiveSHA256: 'archive', actualCoreCircuitsPassed: 4 };
  for (const fields of [{ generatorSHA256: 'raw' }, { generatorGofmtSHA256: 'formatted' }, { generatorSHA256: 'raw', generatorGofmtSHA256: 'formatted' }]) {
    assert.equal(matchesAuditProofSource({ ...base, ...fields }, expected), true);
    for (const edit of [{ coreCommit: 'other' }, { archiveSHA256: 'other' }, { actualCoreCircuitsPassed: 3 }, { generatorSHA256: 'other' }, { generatorGofmtSHA256: 'other' }]) {
      assert.equal(matchesAuditProofSource({ ...base, ...fields, ...edit }, expected), false);
    }
  }
  assert.equal(matchesAuditProofSource(base, expected), false);
});
