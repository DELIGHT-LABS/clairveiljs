import { prepareAuditWitnessV2 } from '../privacy/audit-witness-v2.js';
import { createAuditProverV2 } from '../privacy/audit-prover-v2.js';
import { assertAuditSnapshotCurrentV2 } from '../privacy/audit-config-v2.js';

/** Trusted wallet only. Returns a locally verified public V2 message; never signs
 * an ordinary transaction or decides whether a reservation may be released. */
export async function prepareAuditTransactionV2(input) {
  const { kind, assertAuthority, getCurrentSnapshot, checkpoint, signal, snapshot } = input;
  if (typeof assertAuthority !== 'function' || typeof getCurrentSnapshot !== 'function' || typeof checkpoint !== 'function') {
    throw new Error('V2 authority, snapshot and durable checkpoint hooks required');
  }
  if (!(input.rootSeed instanceof Uint8Array) || input.rootSeed.length !== 32) throw new Error('32-byte RootSeed required');
  const prover = createAuditProverV2(input.prover);
  const seed = input.rootSeed.slice();
  const request = { ...input, rootSeed: seed };
  let prepared;
  const check = async () => {
    signal?.throwIfAborted();
    await assertAuthority();
    signal?.throwIfAborted();
  };
  const refresh = async () => {
    await check();
    const current = await getCurrentSnapshot();
    await check();
    return assertAuditSnapshotCurrentV2(snapshot, current);
  };
  try {
    await check();
    prepared = await prepareAuditWitnessV2({ ...request,
      getCurrentSnapshot: refresh,
      checkpoint: async record => { await check(); await checkpoint(record); await check(); }
    });
    seed.fill(0);
    await check();
    const message = await prover.prove({ prepared: prepared.prepared, witness: prepared.witness, signal });
    await refresh();
    return Object.freeze({ kind, message, snapshot });
  } finally {
    seed.fill(0);
    prepared?.clear();
  }
}
