export function requireString(value, label) {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(`${label} is required`);
  return value.trim();
}

export function expectedActor(value, namespace, chainId) {
  if (!value || value.namespace !== namespace || value.chainId !== chainId) {
    throw new Error("chain actor network mismatch");
  }
  const actor = { namespace, chainId, address: requireString(value.address, "chain actor address") };
  if (namespace === "cosmos") actor.pubKeyHex = requireString(value.pubKeyHex, "chain actor public key");
  return Object.freeze(actor);
}

export function assertSameActor(expected, current) {
  if (expected.namespace !== current.namespace || expected.chainId !== current.chainId
    || expected.address !== current.address || expected.pubKeyHex !== current.pubKeyHex) {
    throw new Error("chain wallet account or network changed");
  }
}

export async function dispatchToActor(expected, getActor, signal, dispatch) {
  signal?.throwIfAborted();
  assertSameActor(expected, await getActor());
  // Account lookup can outlive custody authority. Keep the final check and
  // actual wallet invocation in the same synchronous continuation.
  signal?.throwIfAborted();
  return dispatch();
}
