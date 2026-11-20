/** Historical custody caches stored the exact generator bytes under SHA256;
 * newer SDK caches identify gofmt-normalized bytes. Both must match when present. */
export function matchesAuditProofSource(provenance, expected) {
  const raw = provenance.generatorSHA256, formatted = provenance.generatorGofmtSHA256;
  return provenance.coreCommit === expected.coreCommit && provenance.archiveSHA256 === expected.archiveSHA256
    && provenance.actualCoreCircuitsPassed === 4 && (raw !== undefined || formatted !== undefined)
    && (raw === undefined || raw === expected.generatorSHA256)
    && (formatted === undefined || formatted === expected.generatorGofmtSHA256);
}
