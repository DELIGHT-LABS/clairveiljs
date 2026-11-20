// Shared only by the authorization builder and prover coordinator.
const preparations = new WeakMap();
export function registerAuditPreparation(prepared, kind, snapshot) {
  preparations.set(prepared, { kind, snapshot, consumed: false });
}
export function consumeAuditPreparation(prepared) {
  const state = preparations.get(prepared);
  if (!state) throw new Error("genuine V2 audit preparation required");
  if (state.consumed) throw new Error("audit preparation already consumed");
  state.consumed = true; // Claim before the first await, including on failure.
  return { kind: state.kind, snapshot: state.snapshot };
}
