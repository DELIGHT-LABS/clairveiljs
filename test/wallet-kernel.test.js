import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import * as kernel from "clairveiljs/wallet-kernel";
import { deriveShieldedAddress, hexFromBytes } from "clairveiljs/core";

// These checked-in protocol fixtures are mandatory, including in the ordinary unit run.
const vectors = JSON.parse(readFileSync(new URL(
  "../fixtures/clairveil-v0.3.1/x/privacy/client/sdk/conformance/testdata/privacy_wallet_golden_vectors.json",
  import.meta.url
), "utf8"));
const fixtureSeed = name => Uint8Array.from(Buffer.from(vectors[`${name}_root_seed`].root_seed_hex, "hex"));

for (const name of ["sender", "recipient"]) {
  test(`wallet-kernel preserves the ${name} Go identity vector from RootSeed alone`, () => {
    const identity = kernel.createPrivacyIdentity({ rootSeed: fixtureSeed(name) });
    const expected = vectors[name];
    assert.equal(hexFromBytes(identity.rootSeed), vectors[`${name}_root_seed`].root_seed_hex);
    for (const domain of ["spend", "view", "disclosure"]) {
      assert.equal(identity[domain].scalarHex, expected[`${domain}_scalar_hex`]);
      assert.equal(identity[domain].pubKeyHex, expected[`${domain}_pubkey_hex`]);
    }
    assert.equal(identity.publicIdentity.shieldedAddress, expected.shielded_address);
  });
}

test("wallet-kernel accepts independent synthetic entropy and preserves caller ownership", () => {
  const seed = Uint8Array.from({ length: 32 }, (_, index) => index);
  const expected = deriveShieldedAddress(seed);
  const first = kernel.createPrivacyIdentity({ rootSeed: seed });
  const second = kernel.createPrivacyIdentity({ rootSeed: seed });
  seed.fill(0);
  assert.deepEqual(first.publicIdentity, second.publicIdentity);
  assert.equal(first.publicIdentity.shieldedAddress, expected);
  assert.equal(first.rootSeed[31], 31);
  first.rootSeed.fill(0);
  first.spend.seed.fill(0);
  assert.equal(second.rootSeed[31], 31);
  assert.notDeepEqual(first.spend.seed, second.spend.seed);
});

test("wallet-kernel public projection contains only independent public identity fields", () => {
  const identity = kernel.createPrivacyIdentity({ rootSeed: fixtureSeed("sender") });
  assert.deepEqual(JSON.parse(JSON.stringify(identity.publicIdentity)), {
    shieldedAddress: vectors.sender.shielded_address,
    spendPubKeyHex: vectors.sender.spend_pubkey_hex,
    viewPubKeyHex: vectors.sender.view_pubkey_hex,
    disclosurePubKeyHex: vectors.sender.disclosure_pubkey_hex
  });
  assert.equal(Object.isFrozen(identity.publicIdentity), true);
  assert.equal("address" in identity, false);
  assert.equal("signatureBase64" in identity, false);
  assert.equal("signingMessage" in identity, false);
});

test("wallet-kernel rejects absent, wrongly sized and coerced seeds without fallback", () => {
  for (const rootSeed of [undefined, null, "42".repeat(32), Array(32).fill(42), new ArrayBuffer(32),
    new Uint8Array(31), new Uint8Array(33), new Uint16Array(16)]) {
    assert.throws(() => kernel.createPrivacyIdentity({ rootSeed }), /32-byte Uint8Array/);
  }
  for (const input of [undefined, null, [], "fixture"]) {
    assert.throws(() => kernel.createPrivacyIdentity(input), /accepts only/);
  }
});

test("wallet-kernel rejects mixing ordinary actors or legacy root signatures into identity input", () => {
  const rootSeed = fixtureSeed("sender");
  for (const extra of [
    { address: "0x" + "11".repeat(20) },
    { chainActor: { namespace: "cosmos", network: "synthetic-1", address: "fixture-actor" } },
    { pubKeyHex: "02".repeat(33) },
    { signatureBase64: "cHVibGljLWZpeHR1cmU=" },
    { signPrivacyRoot() { throw new Error("MUST_NOT_SIGN"); } }
  ]) {
    assert.throws(() => kernel.createPrivacyIdentity({ rootSeed, ...extra }), /accepts only/);
  }
});

test("wallet-kernel prefix selection changes only address encoding and rejects invalid prefixes", () => {
  const rootSeed = fixtureSeed("sender");
  const original = kernel.createPrivacyIdentity({ rootSeed });
  const alternate = kernel.createPrivacyIdentity({ rootSeed, shieldedPrefix: "testprivacy" });
  assert.match(alternate.publicIdentity.shieldedAddress, /^testprivacy1/);
  for (const domain of ["spend", "view", "disclosure"]) assert.deepEqual(alternate[domain], original[domain]);
  assert.deepEqual(rootSeed, fixtureSeed("sender"));
  for (const shieldedPrefix of ["", "bad1prefix", null, 42]) {
    assert.throws(() => kernel.createPrivacyIdentity({ rootSeed, shieldedPrefix }), /prefix|Prefix/);
  }
});

test("wallet-kernel entrypoint exposes no legacy root setup, wallet adapter or broad core facade", () => {
  assert.deepEqual(Object.keys(kernel).sort(), ["createPrivacyIdentity", "createWalletKernel"]);
});
