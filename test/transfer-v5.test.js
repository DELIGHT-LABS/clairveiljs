import test from "node:test";
import assert from "node:assert/strict";
import {
  derivePubKeyFromScalar,
  deriveSpendKeys,
  deriveViewKeys,
  encodeShieldedAddress,
  packPoint
} from "clairveiljs/core";
import { createNote } from "clairveiljs/note";
import {
  computeAssetIdV1,
  encryptedEnvelopeKindV1,
  wrapEncryptedEnvelopeV1
} from "clairveiljs/protocol-v1";
import {
  buildTransferV5MsgFromPayloadAndProof,
  computePreparedTransferV5PayloadHash,
  validatePreparedTransferV5PayloadAt,
  validatePreparedTransferV5PayloadMetadata
} from "clairveiljs/transfer-v5";
import { buildPreparedTransferPayload } from "clairveiljs/payload";

function field(value) {
  return BigInt(value).toString(16).padStart(64, "0");
}

function signature(point) {
  return `${Buffer.from(packPoint(point)).toString("hex")}${field(1n)}`;
}

function validPayload() {
  const spend = derivePubKeyFromScalar(17n);
  const view = derivePubKeyFromScalar(19n);
  const recipientSpend = derivePubKeyFromScalar(23n);
  const recipientView = derivePubKeyFromScalar(29n);
  const audit = derivePubKeyFromScalar(31n);
  const transferCiphertext = wrapEncryptedEnvelopeV1(encryptedEnvelopeKindV1.transferNote, new Uint8Array(410));
  const auditPayload = wrapEncryptedEnvelopeV1(encryptedEnvelopeKindV1.auditDisclosure, new Uint8Array(452));
  const payload = {
    version: "v5",
    creator: "clair1creator",
    chain_id: "clairveil-test-1",
    expires_at_unix: 4_102_448_400,
    root_hex: field(1n),
    asset_id_hex: field(2n),
    inputs: [
      { amount: "7", randomness_hex: field(3n), spend_pubkey_hex: Buffer.from(packPoint(spend)).toString("hex"), view_pubkey_hex: Buffer.from(packPoint(view)).toString("hex"), merkle_path: ["01"], merkle_path_helper: [0], nullifier_hex: field(4n) },
      { amount: "5", randomness_hex: field(5n), spend_pubkey_hex: Buffer.from(packPoint(spend)).toString("hex"), view_pubkey_hex: Buffer.from(packPoint(view)).toString("hex"), merkle_path: ["02"], merkle_path_helper: [1], nullifier_hex: field(6n) }
    ],
    outputs: [
      { amount: "7", randomness_hex: field(7n), spend_pubkey_hex: Buffer.from(packPoint(recipientSpend)).toString("hex"), view_pubkey_hex: Buffer.from(packPoint(recipientView)).toString("hex"), commitment_hex: field(8n) },
      { amount: "5", randomness_hex: field(10n), spend_pubkey_hex: Buffer.from(packPoint(spend)).toString("hex"), view_pubkey_hex: Buffer.from(packPoint(view)).toString("hex"), commitment_hex: field(11n) }
    ],
    cipher_text_hexes: [Buffer.from(transferCiphertext).toString("hex"), Buffer.from(transferCiphertext).toString("hex")],
    view_tag_hexes: ["1234", "5678"],
    user_privacy_policy: 0,
    user_disclosure_mode: 0,
    user_disclosure_digest_hex: "",
    user_disclosure_target_pubkey_hex: "",
    user_disclosure_payload_hex: "",
    audit_disclosure_digest_hex: field(12n),
    audit_disclosure_target_pubkey_hex: Buffer.from(packPoint(audit)).toString("hex"),
    audit_disclosure_payload_hex: Buffer.from(auditPayload).toString("hex"),
    self_view_disclosure_digest_hex: "",
    self_view_disclosure_payload_hex: "",
    user_disclosure_blinding_hex: "",
    full_disclosure_blinding_hex: field(13n),
    owner_signature_hex: signature(spend)
  };
  payload.payload_hash = computePreparedTransferV5PayloadHash(payload);
  return payload;
}

test("transfer v5 prepared payload hash matches the Clairveil main line contract", () => {
  const payload = {
    version: "v5", creator: "clair1creator", chain_id: "clairveil-test-1", expires_at_unix: 4102448400,
    root_hex: field(1n), asset_id_hex: field(2n), user_privacy_policy: 0, user_disclosure_mode: 0,
    user_disclosure_digest_hex: "", user_disclosure_target_pubkey_hex: "", user_disclosure_payload_hex: "",
    audit_disclosure_digest_hex: field(3n), audit_disclosure_target_pubkey_hex: "04", audit_disclosure_payload_hex: "05",
    self_view_disclosure_digest_hex: "", self_view_disclosure_payload_hex: "", user_disclosure_blinding_hex: "", full_disclosure_blinding_hex: field(6n), owner_signature_hex: "07",
    inputs: [
      { amount: "7", randomness_hex: field(8n), spend_pubkey_hex: "09", view_pubkey_hex: "0a", merkle_path: ["01", "02"], merkle_path_helper: [0, 1], nullifier_hex: field(11n) },
      { amount: "5", randomness_hex: field(12n), spend_pubkey_hex: "0d", view_pubkey_hex: "0e", merkle_path: ["03"], merkle_path_helper: [1], nullifier_hex: field(15n) }
    ],
    outputs: [
      { amount: "7", randomness_hex: field(16n), spend_pubkey_hex: "11", view_pubkey_hex: "12", commitment_hex: field(19n) },
      { amount: "5", randomness_hex: field(20n), spend_pubkey_hex: "15", view_pubkey_hex: "16", commitment_hex: field(23n) }
    ],
    cipher_text_hexes: ["ab", "cd"], view_tag_hexes: ["1234", "5678"]
  };
  assert.equal(computePreparedTransferV5PayloadHash(payload), "eb71bb985eb351a750696347cc156d9a1fe535daa20d27c6e758df45ad49e62e");
});

test("transfer v5 rejects stale or tampered prepared effects before MsgTransfer construction", () => {
  const payload = validPayload();
  assert.equal(validatePreparedTransferV5PayloadMetadata(payload), true);
  assert.equal(validatePreparedTransferV5PayloadAt(payload, 1_700_000_000), true);
  const proof = { version: "v2", payload_hash: payload.payload_hash, proof_hex: `${"c0"}${"00".repeat(31)}${"c0"}${"00".repeat(63)}${"c0"}${"00".repeat(35)}${"c0"}${"00".repeat(31)}` };
  const message = buildTransferV5MsgFromPayloadAndProof(payload, proof, { nowUnix: 1_700_000_000 });
  assert.equal(message.expiresAtUnix, 4102448400n);
  assert.equal(message.viewTags.length, 2);
  assert.throws(() => validatePreparedTransferV5PayloadAt(payload, payload.expires_at_unix));
  assert.throws(() => validatePreparedTransferV5PayloadMetadata({ ...payload, creator: "clair1altered" }));
});

test("standard transfer builder emits the Clairveil 0.2 V5 fixed-envelope contract", async () => {
  const rootSeed = new Uint8Array(32).fill(7);
  const senderSpend = deriveSpendKeys(rootSeed).pubKey;
  const senderView = deriveViewKeys(rootSeed).pubKey;
  const recipientSpend = derivePubKeyFromScalar(37n);
  const recipientView = derivePubKeyFromScalar(41n);
  const audit = derivePubKeyFromScalar(43n);
  const assetId = computeAssetIdV1("uclair");
  const inputs = [3n, 5n].map((randomness, index) => ({
    note: createNote({
      spendPubKey: senderSpend,
      viewPubKey: senderView,
      amount: index === 0 ? 7n : 5n,
      assetId,
      randomness
    }),
    nullifier: field(BigInt(100 + index)),
    isSpent: false,
    nullifierStatus: "unspent",
    txHash: field(BigInt(200 + index)),
    height: 1,
    sequence: index
  }));
  const payload = await buildPreparedTransferPayload({
    creator: "clair1creator",
    chainId: "clairveil-test-1",
    chainNowUnix: 1_700_000_000,
    inputs,
    recipient: encodeShieldedAddress(recipientSpend, recipientView, { prefix: "clairs" }),
    amount: "7uclair",
    rootSeed,
    merklePathProvider: () => ({ root: field(1n), path: [], path_helper: [] }),
    auditDisclosureTargetPubKeyHex: Buffer.from(packPoint(audit)).toString("hex")
  });

  assert.equal(payload.version, "v5");
  assert.equal(payload.expires_at_unix, 1_700_001_800);
  assert.equal(payload.asset_id_hex, field(assetId));
  assert.equal(payload.cipher_text_hexes[0].length, 860);
  assert.equal(payload.cipher_text_hexes[1].length, 860);
  assert.equal(payload.audit_disclosure_payload_hex.length, 944);
  assert.equal(payload.self_view_disclosure_payload_hex.length, 944);
  assert.equal(payload.owner_signature_hex.length, 128);
  assert.equal(validatePreparedTransferV5PayloadMetadata(payload), true);
});
