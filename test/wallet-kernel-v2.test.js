import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareAuditTransactionV2 } from 'clairveiljs/wallet-kernel-v2';
import { snapshot, vectors, config } from './helpers/audit-prover.js';

async function fixture() {
  const current = await snapshot();
  const events = [], requests = [];
  const rootSeed = Uint8Array.from({ length: 32 }, (_, i) => i);
  return { events, requests, input: {
    kind: 'deposit', rootSeed, snapshot: current, creator: vectors.cases[0].creator,
    chainId: config.chain_id, amount: 1n << 64n, denom: 'uclair',
    expiresAtUnix: String(Math.floor(Date.now() / 1000) + 600),
    assertAuthority() { events.push('authority'); },
    getCurrentSnapshot: async () => { events.push('snapshot'); return current; },
    checkpoint: async () => { events.push('checkpoint'); },
    backend: { prepare: async ({ request }) => { events.push('native'); requests.push(request); throw new Error('native unavailable'); } },
    prover: { baseUrl: 'http://127.0.0.1:8080', verifier: { verify: async () => true },
      fetch: async () => { events.push('prover'); throw new Error('unexpected witness export'); } }
  } };
}

test('V2 kernel refuses revoked authority before checkpoint, native signing or witness export', async () => {
  const f = await fixture();
  f.input.assertAuthority = () => { throw new Error('revoked'); };
  await assert.rejects(prepareAuditTransactionV2(f.input), /revoked/);
  assert.deepEqual(f.events, []);
});
test('V2 kernel requires explicit authority and a qualified verifier before preparing secrets', async () => {
  for (const change of [{ assertAuthority: undefined }, { prover: { baseUrl: 'http://127.0.0.1:8080' } }]) {
    const f = await fixture();
    await assert.rejects(prepareAuditTransactionV2({ ...f.input, ...change }));
    assert.ok(!f.events.includes('checkpoint')); assert.ok(!f.events.includes('native'));
  }
});
test('V2 kernel abort after durable approval cannot reach the native owner signer', async () => {
  const f = await fixture(), controller = new AbortController();
  f.input.signal = controller.signal;
  f.input.checkpoint = async () => { f.events.push('checkpoint'); controller.abort(); };
  await assert.rejects(prepareAuditTransactionV2(f.input));
  assert.ok(f.events.includes('checkpoint')); assert.ok(!f.events.includes('native'));
});
test('V2 kernel clears its native request on failure without changing caller-owned RootSeed', async () => {
  const f = await fixture(), before = f.input.rootSeed.slice();
  await assert.rejects(prepareAuditTransactionV2(f.input), /native unavailable/);
  assert.ok(f.events.indexOf('checkpoint') < f.events.indexOf('native'));
  assert.equal(f.events.includes('prover'), false);
  assert.equal(f.requests.length, 1); assert.ok(f.requests[0].every(byte => byte === 0));
  assert.deepEqual(f.input.rootSeed, before);
});
test('V2 kernel rejects a stale snapshot after approval and never falls back to V1', async () => {
  const f = await fixture();
  f.input.getCurrentSnapshot = async () => ({ ...f.input.snapshot });
  await assert.rejects(prepareAuditTransactionV2(f.input), /validated/);
  assert.equal(f.events.includes('native'), false); assert.equal(f.events.includes('prover'), false);
});
