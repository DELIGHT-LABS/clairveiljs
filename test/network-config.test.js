import test from "node:test";
import assert from "node:assert/strict";
import { derivePubKeyFromScalar, packPointHex } from "clairveiljs/core";
import {
  normalizeAuditConfigV1,
  normalizeDisclosureConfigV1,
  normalizeReserveResponseV1
} from "clairveiljs/network-config";
import { createClairveilClient } from "clairveiljs/cosmos-client";

function auditConfig() {
  return {
    audit_master_pubkey_hex: packPointHex(derivePubKeyFromScalar(101n)),
    audit_key_id: "master",
    audit_key_epoch: "1"
  };
}

function disclosureConfig() {
  return {
    payload_version: "privacy-fixed-v1",
    audit_disclosure_required: true,
    supported_user_policies: ["all-private", "amount", "to"],
    supported_user_modes: ["none", "public", "recipient-encrypted"]
  };
}

function reserve() {
  return {
    denom: "uclair",
    module_balance: "7",
    total_deposited: "10",
    total_withdrawn: "3",
    expected_module_balance: "7",
    invariant_holds: true
  };
}

test("network config validators normalize canonical Query responses", () => {
  const audit = normalizeAuditConfigV1({
    ...auditConfig(),
    auditMasterPubkeyHex: auditConfig().audit_master_pubkey_hex,
    auditKeyId: "master",
    auditKeyEpoch: 1
  });
  assert.equal(audit.audit_key_id, "master");
  assert.equal(audit.audit_key_epoch, "1");
  assert.equal(audit.audit_master_pubkey_hex, packPointHex(derivePubKeyFromScalar(101n)));

  assert.deepEqual(normalizeDisclosureConfigV1(disclosureConfig()), disclosureConfig());
  assert.deepEqual(normalizeReserveResponseV1(reserve(), "uclair"), reserve());
});

test("network config validators reject malformed, incompatible, and non-conserving responses", () => {
  assert.throws(
    () => normalizeAuditConfigV1({ ...auditConfig(), audit_key_id: "Master" }),
    /audit config key ID/
  );
  assert.throws(
    () => normalizeAuditConfigV1({ ...auditConfig(), audit_key_epoch: "0" }),
    /positive/
  );
  assert.throws(
    () => normalizeDisclosureConfigV1({ ...disclosureConfig(), audit_disclosure_required: false }),
    /requires audit disclosure/
  );
  assert.throws(
    () => normalizeDisclosureConfigV1({ ...disclosureConfig(), supported_user_modes: ["none", "opaque"] }),
    /unsupported/
  );
  assert.throws(
    () => normalizeReserveResponseV1({ ...reserve(), module_balance: "6" }, "uclair"),
    /accounting invariant/
  );
  assert.throws(
    () => normalizeReserveResponseV1({ ...reserve(), invariant_holds: false }, "uclair"),
    /does not hold/
  );
});

test("Cosmos typed configuration queries fail closed before returning network data", async () => {
  const client = createClairveilClient({
    rpc: "http://rpc.example",
    rest: "http://rest.example",
    chainId: "clairveil-test-1"
  });
  client.fetchJson = async path => {
    if (path.endsWith("/audit_config")) return auditConfig();
    if (path.endsWith("/disclosure_config")) return disclosureConfig();
    if (path.endsWith("/reserve/uclair")) return reserve();
    throw new Error(`unexpected path ${path}`);
  };
  const [audit, disclosure, balance] = await Promise.all([
    client.queryAuditConfig(),
    client.queryDisclosureConfig(),
    client.queryReserve("uclair")
  ]);
  assert.equal(audit.audit_key_epoch, "1");
  assert.equal(disclosure.payload_version, "privacy-fixed-v1");
  assert.equal(balance.invariant_holds, true);
});
