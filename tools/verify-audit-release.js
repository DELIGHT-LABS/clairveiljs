// Required V2 release gate. All cryptography is exercised against exact Core.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export function auditReleaseInputs(args = [], env = process.env) {
  const core = args[0] || env.CLAIRVEIL_SOURCE_DIR;
  const cache = args[1] || env.CLAIRVEIL_AUDIT_ARTIFACT_CACHE;
  if (!core || !cache || args.length > 2) throw new Error('V2 release requires explicit Core Git source and verified development proof cache');
  return { core: resolve(core), cache: resolve(cache) };
}
export function verifyAuditRelease(args = [], env = process.env) {
  const { core, cache } = auditReleaseInputs(args, env);
  const stage = mkdtempSync(join(tmpdir(), 'clairveil-v2-release-'));
  const run = (file, ...options) => execFileSync(process.execPath, [join(root, file), ...options], { cwd: root, env, stdio: 'inherit' });
  try {
    run('tools/verify-audit-native.js', core);
    run('tools/verify-audit-prover.js', core, cache);
    for (const mode of ['witness', 'verify', 'fixture-server']) run('tools/build-audit-native.js', core, join(stage, mode), mode);
    const reportPath = join(stage, 'witness-report.json');
    run('tools/check-audit-witness-v2.js', '--native', join(stage, 'witness'), '--verifier', join(stage, 'verify'),
      '--server', join(stage, 'fixture-server'), '--artifacts', cache, '--report', reportPath);
    const report = JSON.parse(readFileSync(reportPath, 'utf8'));
    const shapes = new Set(report.results?.map(r => `${r.accountPrefix}:${r.kind}`));
    if (report.status !== 'passed' || report.checkpoints !== 6 || shapes.size !== 6
      || ['clair','maroo'].some(prefix => ['deposit','transfer','withdraw'].some(kind => !shapes.has(`${prefix}:${kind}`)))
      || report.results.some(r => r.proofBytes !== 164 || r.changedProofRejected !== true || r.witnessBytes <= 12 + 23 * 32)) throw new Error('V2 native workflow evidence incomplete');
    if (env.CLAIRVEIL_AUDIT_REPORT) writeFileSync(resolve(env.CLAIRVEIL_AUDIT_REPORT), JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    return report;
  } finally { rmSync(stage, { recursive: true, force: true }); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  verifyAuditRelease(process.argv.slice(2));
}
