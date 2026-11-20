import type { AuditWitnessInputV2 } from '../privacy/audit-witness-v2.js';
import type { AuditSnapshotV2 } from '../privacy/audit-config-v2.js';
import type { createAuditProverV2 } from '../privacy/audit-prover-v2.js';
import type { DirectAuditMessageV2 } from '../transport/transactions-v2.js';
export interface AuditTransactionInputV2 extends AuditWitnessInputV2 {
  assertAuthority(): void | Promise<void>;
  prover: Parameters<typeof createAuditProverV2>[0];
}
/** Trusted wallet only. Copies/clears its seed; caller retains ownership of the original.
 * Durable approval precedes native signing. Every proof needs local verification.
 * No ordinary signing/broadcast or automatic reservation release. */
export function prepareAuditTransactionV2(input: AuditTransactionInputV2): Promise<Readonly<{
  kind: AuditWitnessInputV2['kind']; message: DirectAuditMessageV2; snapshot: AuditSnapshotV2;
}>>;
