import test from "node:test";
import assert from "node:assert/strict";
import {
  payableEvmEvidenceSchema,
  runPayableEvmIntegrationVerification,
  validatePayableEvmIntegrationEvidence,
  verifiedClairveilCommit,
  verifiedClairveilRelease,
  verifiedSdkVersion
} from "../tools/verify-evm-payable-integration.js";

function snapshot({
  fixedEscrowBalance = "100",
  privacyModuleBalance = "60",
  totalDeposited = "80",
  totalWithdrawn = "20",
  leafCount = "7"
} = {}) {
  return {
    fixedEscrowBalance,
    privacyModuleBalance,
    totalDeposited,
    totalWithdrawn,
    leafCount
  };
}

function validEvidence() {
  const precompileAddress = "0x100000000000000000000000000000000000000b";
  const actor = "0x1111111111111111111111111111111111111111";
  const fixedEscrowFunder = "clair1fixedescrow";
  return {
    schemaVersion: payableEvmEvidenceSchema,
    clairveilRelease: verifiedClairveilRelease,
    clairveilCommit: verifiedClairveilCommit,
    sdkVersion: verifiedSdkVersion,
    chainId: "clairveil-downstream-1",
    evmChainId: "0x539",
    denom: "uclair",
    precompileAddress,
    actor,
    fixedEscrowFunder,
    success: {
      amount: "5",
      value: "0x5",
      to: precompileAddress,
      txHash: `0x${"11".repeat(32)}`,
      status: "success",
      eventCreator: actor,
      eventFunder: fixedEscrowFunder,
      before: snapshot(),
      after: snapshot({
        fixedEscrowBalance: "95",
        privacyModuleBalance: "65",
        totalDeposited: "85",
        leafCount: "8"
      }),
      reserveInvariantHolds: true
    },
    rollback: {
      amount: "5",
      value: "0x5",
      to: precompileAddress,
      txHash: `0x${"22".repeat(32)}`,
      status: "reverted",
      failureKind: "downstream-policy",
      before: snapshot(),
      after: snapshot(),
      reserveInvariantHolds: true
    },
    zeroValue: {
      amount: "0",
      value: "0x0",
      to: precompileAddress,
      txHash: `0x${"33".repeat(32)}`,
      status: "success",
      eventCreator: actor,
      eventFunder: fixedEscrowFunder,
      before: snapshot(),
      after: snapshot({ leafCount: "8" }),
      reserveInvariantHolds: true
    }
  };
}

test("payable EVM integration evidence validates success, rollback, and zero-value behavior", () => {
  const evidence = validEvidence();
  assert.equal(validatePayableEvmIntegrationEvidence(evidence), evidence);
});

test("payable EVM integration evidence rejects incomplete downstream semantics", () => {
  const cases = [
    ["success target", evidence => {
      evidence.success.to = "0x2222222222222222222222222222222222222222";
    }, /does not match precompileAddress/],
    ["success value", evidence => {
      evidence.success.value = "0x4";
    }, /value does not match amount/],
    ["event actor", evidence => {
      evidence.success.eventCreator = "0x2222222222222222222222222222222222222222";
    }, /eventCreator does not match actor/],
    ["escrow movement", evidence => {
      evidence.success.after.fixedEscrowBalance = "96";
    }, /fixedEscrowBalance delta/],
    ["rollback", evidence => {
      evidence.rollback.after.leafCount = "8";
    }, /rollback.leafCount changed/],
    ["zero-value mutation", evidence => {
      evidence.zeroValue.after.totalDeposited = "81";
    }, /changed for zero-value deposit/]
  ];
  for (const [name, mutate, expected] of cases) {
    const evidence = validEvidence();
    mutate(evidence);
    assert.throws(
      () => validatePayableEvmIntegrationEvidence(evidence),
      expected,
      name
    );
  }
});

test("payable EVM integration verification skips locally but fails closed when required", async () => {
  assert.deepEqual(
    await runPayableEvmIntegrationVerification({ driverPath: "", required: false }),
    {
      status: "skipped",
      reason: "CLAIRVEIL_EVM_PAYABLE_E2E_DRIVER is not configured"
    }
  );
  await assert.rejects(
    () => runPayableEvmIntegrationVerification({ driverPath: "", required: true }),
    /CLAIRVEIL_EVM_PAYABLE_E2E_DRIVER is required/
  );
});
