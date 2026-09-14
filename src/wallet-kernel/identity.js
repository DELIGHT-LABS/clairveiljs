import {
  defaultShieldedPrefix,
  deriveDisclosureKeys,
  deriveSpendKeys,
  deriveViewKeys,
  encodeShieldedAddress,
  normalizeBech32Prefix
} from "../core/crypto.js";

/** Trusted-runtime constructor. It neither generates entropy nor calls a chain wallet. */
export function createPrivacyIdentity(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || Reflect.ownKeys(input).some(key => key !== "rootSeed" && key !== "shieldedPrefix")) {
    throw new TypeError("privacy identity input accepts only rootSeed and shieldedPrefix");
  }
  const { rootSeed: sourceSeed, shieldedPrefix: selectedPrefix } = input;
  if (!(sourceSeed instanceof Uint8Array) || sourceSeed.byteLength !== 32) {
    throw new TypeError("rootSeed must be a 32-byte Uint8Array");
  }
  if (selectedPrefix !== undefined && typeof selectedPrefix !== "string") {
    throw new TypeError("shieldedPrefix must be a string");
  }
  const shieldedPrefix = normalizeBech32Prefix(selectedPrefix ?? defaultShieldedPrefix, "shielded prefix");
  const rootSeed = Uint8Array.from(sourceSeed);
  const spend = deriveSpendKeys(rootSeed);
  const view = deriveViewKeys(rootSeed);
  const disclosure = deriveDisclosureKeys(rootSeed);
  // Build an explicit public projection; never spread the private identity or key pairs.
  const publicIdentity = Object.freeze({
    shieldedAddress: encodeShieldedAddress(spend.pubKey, view.pubKey, { shieldedPrefix }),
    spendPubKeyHex: spend.pubKeyHex,
    viewPubKeyHex: view.pubKeyHex,
    disclosurePubKeyHex: disclosure.pubKeyHex
  });
  return { rootSeed, spend, view, disclosure, publicIdentity };
}
