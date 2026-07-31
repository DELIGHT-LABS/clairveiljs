import { fileURLToPath, pathToFileURL } from "node:url";
import { resolve } from "node:path";

export const payableEvmEvidenceSchema = "clairveil-payable-evm-e2e-v1";
export const verifiedClairveilRelease = "v0.3.1";
export const verifiedClairveilCommit = "1a6ce6a0a0e10b765c025072b44c2364e9711b48";
export const verifiedSdkVersion = "0.3.1";

const stateFields = [
  "fixedEscrowBalance",
  "privacyModuleBalance",
  "totalDeposited",
  "totalWithdrawn",
  "leafCount"
];

function fail(message) {
  throw new Error(`payable EVM integration evidence: ${message}`);
}

function requiredString(value, label) {
  const text = String(value ?? "").trim();
  if (!text) fail(`${label} is required`);
  return text;
}

function uint(value, label) {
  const text = requiredString(value, label);
  if (!/^(0|[1-9][0-9]*)$/.test(text)) {
    fail(`${label} must be a canonical unsigned decimal string`);
  }
  return BigInt(text);
}

function quantity(value, label) {
  const text = requiredString(value, label);
  if (!/^(?:0x[0-9a-fA-F]+|0|[1-9][0-9]*)$/.test(text)) {
    fail(`${label} must be an EVM quantity`);
  }
  const parsed = BigInt(text);
  if (parsed < 0n) fail(`${label} must be non-negative`);
  return parsed;
}

function evmAddress(value, label) {
  const address = requiredString(value, label).toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(address)) {
    fail(`${label} must be a 20-byte EVM address`);
  }
  return address;
}

function transactionHash(value, label) {
  const hash = requiredString(value, label).toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(hash)) {
    fail(`${label} must be a 32-byte EVM transaction hash`);
  }
  return hash;
}

function identity(value, label) {
  const text = requiredString(value, label);
  return /^0x[0-9a-fA-F]{40}$/.test(text) ? text.toLowerCase() : text;
}

function state(snapshot, label) {
  if (!snapshot || typeof snapshot !== "object") fail(`${label} is required`);
  return Object.fromEntries(
    stateFields.map(field => [field, uint(snapshot[field], `${label}.${field}`)])
  );
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) fail(message);
}

function assertStateEqual(actual, expected, label) {
  for (const field of stateFields) {
    assertEqual(actual[field], expected[field], `${label}.${field} changed`);
  }
}

function assertReserveInvariant(snapshot, reported, label) {
  if (reported !== true) fail(`${label}.reserveInvariantHolds must be true`);
  const outstanding = snapshot.totalDeposited - snapshot.totalWithdrawn;
  if (outstanding < 0n) fail(`${label} totalWithdrawn exceeds totalDeposited`);
  if (snapshot.privacyModuleBalance < outstanding) {
    fail(`${label} privacy module balance does not cover outstanding deposits`);
  }
}

function transactionEvidence(entry, label, precompileAddress, expectedValue) {
  if (!entry || typeof entry !== "object") fail(`${label} is required`);
  assertEqual(
    evmAddress(entry.to, `${label}.to`),
    precompileAddress,
    `${label}.to does not match precompileAddress`
  );
  assertEqual(
    quantity(entry.value, `${label}.value`),
    expectedValue,
    `${label}.value does not match amount`
  );
  transactionHash(entry.txHash, `${label}.txHash`);
}

function successfulDeposit(
  entry,
  label,
  precompileAddress,
  actor,
  fixedEscrowFunder,
  { zeroValue = false } = {}
) {
  const amount = uint(entry?.amount, `${label}.amount`);
  if (zeroValue ? amount !== 0n : amount === 0n) {
    fail(`${label}.amount must be ${zeroValue ? "zero" : "positive"}`);
  }
  transactionEvidence(entry, label, precompileAddress, amount);
  assertEqual(requiredString(entry.status, `${label}.status`), "success", `${label}.status must be success`);
  assertEqual(
    identity(entry.eventCreator, `${label}.eventCreator`),
    actor,
    `${label}.eventCreator does not match actor`
  );
  assertEqual(
    identity(entry.eventFunder, `${label}.eventFunder`),
    fixedEscrowFunder,
    `${label}.eventFunder does not match fixedEscrowFunder`
  );

  const before = state(entry.before, `${label}.before`);
  const after = state(entry.after, `${label}.after`);
  if (zeroValue) {
    for (const field of stateFields.slice(0, 4)) {
      assertEqual(after[field], before[field], `${label}.${field} changed for zero-value deposit`);
    }
  } else {
    if (before.fixedEscrowBalance < amount) {
      fail(`${label}.before.fixedEscrowBalance is smaller than amount`);
    }
    assertEqual(
      after.fixedEscrowBalance,
      before.fixedEscrowBalance - amount,
      `${label}.fixedEscrowBalance delta does not equal -amount`
    );
    assertEqual(
      after.privacyModuleBalance,
      before.privacyModuleBalance + amount,
      `${label}.privacyModuleBalance delta does not equal amount`
    );
    assertEqual(
      after.totalDeposited,
      before.totalDeposited + amount,
      `${label}.totalDeposited delta does not equal amount`
    );
    assertEqual(
      after.totalWithdrawn,
      before.totalWithdrawn,
      `${label}.totalWithdrawn changed`
    );
  }
  assertEqual(after.leafCount, before.leafCount + 1n, `${label}.leafCount delta does not equal one`);
  assertReserveInvariant(after, entry.reserveInvariantHolds, label);
}

function rolledBackDeposit(entry, precompileAddress) {
  const label = "rollback";
  const amount = uint(entry?.amount, `${label}.amount`);
  if (amount === 0n) fail(`${label}.amount must be positive`);
  transactionEvidence(entry, label, precompileAddress, amount);
  assertEqual(requiredString(entry.status, `${label}.status`), "reverted", `${label}.status must be reverted`);
  assertEqual(
    requiredString(entry.failureKind, `${label}.failureKind`),
    "downstream-policy",
    `${label}.failureKind must be downstream-policy`
  );
  const before = state(entry.before, `${label}.before`);
  const after = state(entry.after, `${label}.after`);
  assertStateEqual(after, before, label);
  assertReserveInvariant(after, entry.reserveInvariantHolds, label);
}

export function validatePayableEvmIntegrationEvidence(evidence) {
  if (!evidence || typeof evidence !== "object") fail("driver must return an evidence object");
  assertEqual(
    requiredString(evidence.schemaVersion, "schemaVersion"),
    payableEvmEvidenceSchema,
    `schemaVersion must be ${payableEvmEvidenceSchema}`
  );
  assertEqual(
    requiredString(evidence.clairveilRelease, "clairveilRelease"),
    verifiedClairveilRelease,
    `clairveilRelease must be ${verifiedClairveilRelease}`
  );
  assertEqual(
    requiredString(evidence.clairveilCommit, "clairveilCommit"),
    verifiedClairveilCommit,
    `clairveilCommit must be ${verifiedClairveilCommit}`
  );
  assertEqual(
    requiredString(evidence.sdkVersion, "sdkVersion"),
    verifiedSdkVersion,
    `sdkVersion must be ${verifiedSdkVersion}`
  );
  requiredString(evidence.chainId, "chainId");
  quantity(evidence.evmChainId, "evmChainId");
  requiredString(evidence.denom, "denom");

  const precompileAddress = evmAddress(evidence.precompileAddress, "precompileAddress");
  const actor = identity(evidence.actor, "actor");
  const fixedEscrowFunder = identity(evidence.fixedEscrowFunder, "fixedEscrowFunder");
  successfulDeposit(
    evidence.success,
    "success",
    precompileAddress,
    actor,
    fixedEscrowFunder
  );
  rolledBackDeposit(evidence.rollback, precompileAddress);
  successfulDeposit(
    evidence.zeroValue,
    "zeroValue",
    precompileAddress,
    actor,
    fixedEscrowFunder,
    { zeroValue: true }
  );
  return evidence;
}

export async function runPayableEvmIntegrationVerification({
  driverPath = process.env.CLAIRVEIL_EVM_PAYABLE_E2E_DRIVER,
  required = process.env.CLAIRVEIL_EVM_PAYABLE_E2E_REQUIRED === "1"
} = {}) {
  if (!String(driverPath ?? "").trim()) {
    if (required) {
      fail("CLAIRVEIL_EVM_PAYABLE_E2E_DRIVER is required");
    }
    return { status: "skipped", reason: "CLAIRVEIL_EVM_PAYABLE_E2E_DRIVER is not configured" };
  }

  const resolvedDriver = resolve(String(driverPath));
  const driver = await import(pathToFileURL(resolvedDriver).href);
  if (typeof driver.runClairveilPayableDepositE2E !== "function") {
    fail("driver must export runClairveilPayableDepositE2E(context)");
  }
  const evidence = await driver.runClairveilPayableDepositE2E(Object.freeze({
    evidenceSchema: payableEvmEvidenceSchema,
    clairveilRelease: verifiedClairveilRelease,
    clairveilCommit: verifiedClairveilCommit,
    sdkVersion: verifiedSdkVersion
  }));
  validatePayableEvmIntegrationEvidence(evidence);
  return { status: "passed", evidence };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runPayableEvmIntegrationVerification()
    .then(result => {
      if (result.status === "skipped") {
        console.log(`SKIP payable EVM integration: ${result.reason}`);
      } else {
        console.log("PASS payable EVM integration evidence");
      }
    })
    .catch(error => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    });
}
