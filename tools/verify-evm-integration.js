import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, resolve } from "node:path";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { hashAmount, hashRecipient } from "../src/privacy/reservation.js";
import { verifyVendoredClairveilContractSnapshot } from "./verify-clairveil-source.js";

export const evmEvidenceSchema = "clairveil-evm-e2e-v1";
export const verifiedClairveilBundleVersion = "v0.3.1";
export const verifiedClairveilSourceKind = "commit_snapshot";
export const verifiedClairveilCommit = "0ff92839872de26b787a60d8e4d5822cc459855b";
export const verifiedSdkVersion = "0.3.1";
export const evmOneProofBatchMatrixSchema = "clairveil-evm-one-proof-batch-matrix-v1";
export const evmPostCoreRollbackSuccessMarker = `0x${"a5".repeat(32)}`;
export const evmPostCoreRollbackFailureMarker = `0x${"f1".repeat(32)}`;
const sdkRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const batchTransferContractFixturePath = resolve(
  sdkRoot,
  `fixtures/clairveil-${verifiedClairveilBundleVersion}/x/privacy/client/sdk/conformance/testdata/privacy_batch_transfer_v1_contract.json`
);
const fixtureDisclosureModeValues = Object.freeze({
  none: 0,
  public: 1,
  "recipient-encrypted": 2
});

function fixtureAmount(value, label) {
  const text = String(value ?? "").trim();
  if (!/^[1-9][0-9]*$/.test(text)) {
    throw new Error(`Clairveil v0.3.1 batch fixture ${label} must be a positive canonical integer`);
  }
  return text;
}

function loadEvmOneProofBatchReleaseShapes() {
  let fixture;
  try {
    fixture = JSON.parse(readFileSync(batchTransferContractFixturePath, "utf8"));
  } catch (error) {
    throw new Error(`cannot load pinned Clairveil v0.3.1 batch fixture: ${error.message}`);
  }
  if (fixture?.schema_version !== "clairveil.batch-transfer.contract.v1" ||
      fixture?.max_inputs !== 16 || fixture?.max_outputs !== 32 ||
      !Array.isArray(fixture?.cases) || fixture.cases.length !== 5) {
    throw new Error("pinned Clairveil v0.3.1 batch fixture has an unexpected contract shape");
  }
  const ids = new Set();
  return Object.freeze(fixture.cases.map((entry, caseIndex) => {
    const label = `case ${caseIndex}`;
    const id = String(entry?.id ?? "").trim();
    if (!id || ids.has(id)) {
      throw new Error(`pinned Clairveil v0.3.1 batch fixture ${label} has an invalid or duplicate id`);
    }
    ids.add(id);
    if (!Array.isArray(entry.input_amounts) || !entry.input_amounts.length ||
        entry.input_amounts.length > fixture.max_inputs) {
      throw new Error(`pinned Clairveil v0.3.1 batch fixture ${id} has invalid input_amounts`);
    }
    if (!Array.isArray(entry.payment_amounts) || !entry.payment_amounts.length ||
        entry.payment_amounts.length > fixture.max_outputs) {
      throw new Error(`pinned Clairveil v0.3.1 batch fixture ${id} has invalid payment_amounts`);
    }
    const inputAmounts = entry.input_amounts.map((value, index) =>
      fixtureAmount(value, `${id}.input_amounts[${index}]`));
    const paymentAmounts = entry.payment_amounts.map((value, index) =>
      fixtureAmount(value, `${id}.payment_amounts[${index}]`));
    const outputRoles = Array.isArray(entry.expected_output_roles)
      ? entry.expected_output_roles.map(value => String(value ?? "").trim())
      : [];
    const disclosureModes = Array.isArray(entry.disclosure_modes)
      ? entry.disclosure_modes.map(value => String(value ?? "").trim())
      : [];
    if (!outputRoles.length || outputRoles.length > fixture.max_outputs ||
        disclosureModes.length !== outputRoles.length ||
        outputRoles.some(role => !["payment", "change", "padding"].includes(role)) ||
        disclosureModes.some(mode => fixtureDisclosureModeValues[mode] == null)) {
      throw new Error(`pinned Clairveil v0.3.1 batch fixture ${id} has invalid output metadata`);
    }
    const canonicalRoles = [
      ...Array(paymentAmounts.length).fill("payment"),
      ...(outputRoles.includes("change") ? ["change"] : []),
      ...Array(outputRoles.filter(role => role === "padding").length).fill("padding")
    ];
    if (canonicalRoles.length !== outputRoles.length ||
        canonicalRoles.some((role, index) => role !== outputRoles[index])) {
      throw new Error(`pinned Clairveil v0.3.1 batch fixture ${id} has non-canonical output roles`);
    }
    const inputTotal = inputAmounts.reduce((sum, amount) => sum + BigInt(amount), 0n);
    const paymentTotal = paymentAmounts.reduce((sum, amount) => sum + BigInt(amount), 0n);
    const changeAmount = inputTotal - paymentTotal;
    const changeCount = outputRoles.filter(role => role === "change").length;
    if (changeAmount < 0n || (changeCount === 1) !== (changeAmount > 0n)) {
      throw new Error(`pinned Clairveil v0.3.1 batch fixture ${id} has inconsistent change`);
    }
    const outputAmounts = [];
    let paymentIndex = 0;
    for (const role of outputRoles) {
      if (role === "payment") outputAmounts.push(paymentAmounts[paymentIndex++]);
      else if (role === "change") outputAmounts.push(changeAmount.toString());
      else outputAmounts.push("0");
    }
    const outputMode = String(entry.output_mode ?? "").trim();
    if (!["compact", "exact32"].includes(outputMode) ||
        (outputMode === "exact32" && outputRoles.length !== fixture.max_outputs)) {
      throw new Error(`pinned Clairveil v0.3.1 batch fixture ${id} has an invalid output_mode`);
    }
    if (entry.self_view !== "enabled" && entry.self_view !== "disabled") {
      throw new Error(`pinned Clairveil v0.3.1 batch fixture ${id} has an invalid self_view mode`);
    }
    return Object.freeze({
      id,
      inputAmounts: Object.freeze(inputAmounts),
      paymentAmounts: Object.freeze(paymentAmounts),
      outputRoles: Object.freeze(outputRoles),
      outputAmounts: Object.freeze(outputAmounts),
      disclosureModes: Object.freeze(disclosureModes),
      inputCount: inputAmounts.length,
      paymentCount: paymentAmounts.length,
      outputCount: outputRoles.length,
      changeCount,
      paddingCount: outputRoles.filter(role => role === "padding").length,
      outputMode,
      selfViewEnabled: entry.self_view === "enabled"
    });
  }));
}

/**
 * Deterministic downstream test policy used by release E2E. It forwards the
 * exact calldata and msg.value to the configured privacy contract, then
 * reverts with a distinct marker only when the inner privacy call succeeded.
 * The outer revert must roll back every inner privacy state write and event.
 */
export function createEvmPostCoreRollbackHarness(contractAddress) {
  const target = evmAddress(contractAddress, "post-core rollback privacy contract").slice(2);
  const successMarker = evmPostCoreRollbackSuccessMarker.slice(2);
  const failureMarker = evmPostCoreRollbackFailureMarker.slice(2);
  const runtimeCode = `0x366000600037600060003660003473${target}5af16051577f${failureMarker}60005260206000fd5b7f${successMarker}60005260206000fd`;
  const runtimeLength = (runtimeCode.length - 2) / 2;
  if (runtimeLength !== 0x7b) {
    throw new Error("post-core rollback harness runtime length is invalid");
  }
  const initCode = `0x607b600c600039607b6000f3${runtimeCode.slice(2)}`;
  return Object.freeze({
    contractAddress: `0x${target}`,
    runtimeCode,
    initCode,
    successMarker: evmPostCoreRollbackSuccessMarker,
    failureMarker: evmPostCoreRollbackFailureMarker
  });
}

export const evmOneProofBatchReleaseShapes = loadEvmOneProofBatchReleaseShapes();

export const defaultEvmPrivacyActions = Object.freeze({
  deposit: Object.freeze({ selector: "e6eb7771", event: "PrivacyDeposit" }),
  transfer: Object.freeze({ selector: "43fd6967", event: "PrivacyTransfer" }),
  singleProofBatchTransfer: Object.freeze({
    selector: "3bbb329b",
    event: "PrivacySingleProofBatchTransfer"
  }),
  singleProofBatchTransferWithAuthorization: Object.freeze({
    selector: "0272cf35",
    event: "PrivacySingleProofBatchTransfer"
  }),
  withdraw: Object.freeze({ selector: "ce4f349c", event: "PrivacyWithdraw" })
});

const stateFields = [
  "fixedEscrowBalance",
  "privacyModuleBalance",
  "totalDeposited",
  "totalWithdrawn",
  "leafCount",
  "privacyScanHeight",
  "privacyScanGlobalSequence",
  "privacyScanOutputIndex",
  "privacyScanSummaryCount",
  "privacyScanOutputCount"
];

const conflictFields = new Set([
  "tx_hash",
  "commitment",
  "digest",
  "amount",
  "recipient_hash",
  "amount_hash",
  "denom"
]);

function fail(message) {
  throw new Error(`EVM integration evidence: ${message}`);
}

function requiredObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} is required`);
  return value;
}

function requiredString(value, label) {
  const text = String(value ?? "").trim();
  if (!text) fail(`${label} is required`);
  return text;
}

function literalTrue(value, label) {
  if (value !== true) fail(`${label} must be true`);
}

function literalFalse(value, label) {
  if (value !== false) fail(`${label} must be false`);
}

function uint(value, label) {
  const text = requiredString(value, label);
  if (!/^(0|[1-9][0-9]*)$/.test(text)) {
    fail(`${label} must be a canonical unsigned decimal string`);
  }
  return BigInt(text);
}

function boundedCount(value, label, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    fail(`${label} must be an integer in ${min}..${max}`);
  }
  return value;
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

function hex32(value, label) {
  const digest = requiredString(value, label).toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(digest)) fail(`${label} must be exactly 32 bytes of hex`);
  return digest;
}

function optionalHex32(value, label) {
  const digest = String(value ?? "").trim().toLowerCase().replace(/^0x/, "");
  return digest ? hex32(digest, label) : "";
}

function calldata(value, label) {
  const data = requiredString(value, label).toLowerCase();
  if (!/^0x(?:[0-9a-f]{2})+$/.test(data)) fail(`${label} must be non-empty canonical hex bytes`);
  return data;
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) fail(message);
}

function validateExactAmounts(values, label, expected) {
  if (!Array.isArray(values) || values.length !== expected.length) {
    fail(`${label} must contain exactly ${expected.length} amounts from the pinned v0.3.1 fixture`);
  }
  values.forEach((value, index) => {
    assertEqual(
      uint(value, `${label}[${index}]`).toString(),
      expected[index],
      `${label}[${index}] differs from the pinned v0.3.1 fixture`
    );
  });
}

function validateExactDisclosureModes(values, label, expected) {
  if (!Array.isArray(values) || values.length !== expected.length) {
    fail(`${label} must contain exactly ${expected.length} modes from the pinned v0.3.1 fixture`);
  }
  values.forEach((value, index) => {
    assertEqual(
      requiredString(value, `${label}[${index}]`),
      expected[index],
      `${label}[${index}] differs from the pinned v0.3.1 fixture`
    );
  });
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function state(snapshot, label) {
  requiredObject(snapshot, label);
  return Object.fromEntries(
    stateFields.map(field => [field, uint(snapshot[field], `${label}.${field}`)])
  );
}

function assertStateEqual(actual, expected, label) {
  for (const field of stateFields) {
    assertEqual(actual[field], expected[field], `${label}.${field} changed`);
  }
}

function comparePrivacyScanCursor(left, right) {
  for (const field of [
    "privacyScanHeight",
    "privacyScanGlobalSequence",
    "privacyScanOutputIndex"
  ]) {
    if (left[field] < right[field]) return -1;
    if (left[field] > right[field]) return 1;
  }
  return 0;
}

function assertDepositScanDelta(actual, expected, label) {
  assertEqual(
    actual.privacyScanSummaryCount,
    expected.privacyScanSummaryCount + 1n,
    `${label}.privacyScanSummaryCount delta does not equal one`
  );
  assertEqual(
    actual.privacyScanOutputCount,
    expected.privacyScanOutputCount + 1n,
    `${label}.privacyScanOutputCount delta does not equal one`
  );
  if (comparePrivacyScanCursor(actual, expected) <= 0) {
    fail(`${label} typed privacy scan cursor did not advance`);
  }
}

function assertReserveInvariant(snapshot, reported, label) {
  literalTrue(reported, `${label}.reserveInvariantHolds`);
  const outstanding = snapshot.totalDeposited - snapshot.totalWithdrawn;
  if (outstanding < 0n) fail(`${label} totalWithdrawn exceeds totalDeposited`);
  if (snapshot.privacyModuleBalance !== outstanding) {
    fail(`${label} privacy module balance differs from outstanding deposits`);
  }
}

function transactionIdentity(entry, label, {
  precompileAddress,
  expectedTarget = precompileAddress,
  sender,
  evmChainId,
  expectedValue,
  expectedOperation,
  expectedEvent,
  receiptStatus,
  privacyEventVerified
}) {
  requiredObject(entry, label);
  const prepared = requiredObject(entry.prepared, `${label}.prepared`);
  const observed = requiredObject(entry.observed, `${label}.observed`);
  const receipt = requiredObject(entry.receipt, `${label}.receipt`);
  const preparedTo = evmAddress(prepared.to, `${label}.prepared.to`);
  const preparedSender = evmAddress(prepared.sender, `${label}.prepared.sender`);
  const preparedData = calldata(prepared.data, `${label}.prepared.data`);
  const preparedValue = quantity(prepared.value, `${label}.prepared.value`);
  const preparedChainId = quantity(prepared.chainId, `${label}.prepared.chainId`);
  const observedHash = transactionHash(observed.hash, `${label}.observed.hash`);
  const action = defaultEvmPrivacyActions[expectedOperation];
  if (!action || action.event !== expectedEvent) {
    fail(`${label} verifier has an unsupported default-adapter privacy action`);
  }

  assertEqual(preparedTo, expectedTarget, `${label}.prepared.to does not match the expected target`);
  assertEqual(preparedSender, sender, `${label}.prepared.sender does not match the expected sender`);
  assertEqual(requiredString(prepared.operation, `${label}.prepared.operation`), expectedOperation, `${label}.prepared.operation must be ${expectedOperation}`);
  assertEqual(preparedData.slice(2, 10), action.selector, `${label}.prepared.data selector must match the default adapter ${expectedOperation}`);
  assertEqual(preparedValue, expectedValue, `${label}.prepared.value does not match the expected value`);
  assertEqual(preparedChainId, evmChainId, `${label}.prepared.chainId does not match evmChainId`);
  assertEqual(evmAddress(observed.from, `${label}.observed.from`), preparedSender, `${label}.observed.from differs from prepared.sender`);
  assertEqual(evmAddress(observed.to, `${label}.observed.to`), preparedTo, `${label}.observed.to differs from prepared.to`);
  assertEqual(calldata(observed.input, `${label}.observed.input`), preparedData, `${label}.observed.input differs from prepared.data`);
  assertEqual(quantity(observed.value, `${label}.observed.value`), preparedValue, `${label}.observed.value differs from prepared.value`);
  assertEqual(quantity(observed.chainId, `${label}.observed.chainId`), preparedChainId, `${label}.observed.chainId differs from prepared.chainId`);
  assertEqual(transactionHash(receipt.transactionHash, `${label}.receipt.transactionHash`), observedHash, `${label}.receipt.transactionHash differs from observed.hash`);
  assertEqual(requiredString(receipt.status, `${label}.receipt.status`).toLowerCase(), receiptStatus, `${label}.receipt.status must be ${receiptStatus}`);
  const receiptBlockNumber = receiptStatus === "0x1"
    ? quantity(receipt.blockNumber, `${label}.receipt.blockNumber`)
    : null;
  const receiptBlockHash = receiptStatus === "0x1"
    ? hex32(receipt.blockHash, `${label}.receipt.blockHash`)
    : "";
  if (privacyEventVerified) {
    literalTrue(receipt.privacyEventVerified, `${label}.receipt.privacyEventVerified`);
    assertEqual(requiredString(receipt.privacyOperation, `${label}.receipt.privacyOperation`), expectedOperation, `${label}.receipt.privacyOperation must be ${expectedOperation}`);
    assertEqual(requiredString(receipt.privacyEvent, `${label}.receipt.privacyEvent`), expectedEvent, `${label}.receipt.privacyEvent must be ${expectedEvent}`);
  } else {
    literalFalse(receipt.privacyEventVerified, `${label}.receipt.privacyEventVerified`);
  }
  if (receiptStatus === "0x1") {
    const finality = requiredObject(entry.finality, `${label}.finality`);
    literalTrue(finality.verified, `${label}.finality.verified`);
    assertEqual(
      transactionHash(finality.txHash, `${label}.finality.txHash`),
      observedHash,
      `${label}.finality.txHash differs from observed.hash`
    );
    const mode = requiredString(finality.mode, `${label}.finality.mode`);
    if (!new Set(["receipt", "confirmations", "safe", "finalized", "custom"]).has(mode)) {
      fail(`${label}.finality.mode is unsupported`);
    }
    if (mode === "receipt") {
      fail(`${label}.finality.mode must revalidate canonical inclusion for the release gate`);
    }
    const inclusionBlockNumber = quantity(finality.blockNumber, `${label}.finality.blockNumber`);
    const inclusionBlockHash = hex32(finality.blockHash, `${label}.finality.blockHash`);
    assertEqual(
      inclusionBlockNumber,
      receiptBlockNumber,
      `${label}.finality.blockNumber differs from receipt.blockNumber`
    );
    assertEqual(
      inclusionBlockHash,
      receiptBlockHash,
      `${label}.finality.blockHash differs from receipt.blockHash`
    );
    if (mode === "confirmations") {
      const confirmations = boundedCount(
        finality.confirmations,
        `${label}.finality.confirmations`,
        2,
        Number.MAX_SAFE_INTEGER
      );
      const finalityBlockNumber = quantity(
        finality.finalityBlockNumber,
        `${label}.finality.finalityBlockNumber`
      );
      const requiredBlockNumber = inclusionBlockNumber + BigInt(confirmations - 1);
      if (finalityBlockNumber < requiredBlockNumber) {
        fail(`${label}.finality.finalityBlockNumber does not reach the required confirmation depth`);
      }
    } else if (mode === "safe" || mode === "finalized") {
      assertEqual(
        requiredString(finality.blockTag, `${label}.finality.blockTag`),
        mode,
        `${label}.finality.blockTag must match its finality mode`
      );
      const finalityBlockNumber = quantity(
        finality.finalityBlockNumber,
        `${label}.finality.finalityBlockNumber`
      );
      if (finalityBlockNumber < inclusionBlockNumber) {
        fail(`${label}.finality.finalityBlockNumber predates the inclusion block`);
      }
    }
  }
  return observedHash;
}

function successfulTransaction(entry, label, options) {
  return transactionIdentity(entry, label, {
    ...options,
    receiptStatus: "0x1",
    privacyEventVerified: true
  });
}

function revertedTransaction(entry, label, options) {
  return transactionIdentity(entry, label, {
    ...options,
    receiptStatus: "0x0",
    privacyEventVerified: false
  });
}

function validateScanTransactionLink(link, label, evmTxHash) {
  requiredObject(link, label);
  const scanTxHash = transactionHash(link.scanTxHash, `${label}.scanTxHash`);
  assertEqual(
    transactionHash(link.evmTxHash, `${label}.evmTxHash`),
    evmTxHash,
    `${label}.evmTxHash differs from the submitted EVM transaction`
  );
  if (uint(link.cometHeight, `${label}.cometHeight`) === 0n) {
    fail(`${label}.cometHeight must be positive`);
  }
  literalTrue(link.cosmosTxSucceeded, `${label}.cosmosTxSucceeded`);
  literalTrue(link.ethereumTxHashEventMatched, `${label}.ethereumTxHashEventMatched`);
  return scanTxHash;
}

function validateDepositFlow(flow, context) {
  requiredObject(flow, "deposit");
  const validateSuccess = (entry, label, { zeroValue = false } = {}) => {
    const amount = uint(entry?.amount, `${label}.amount`);
    if (zeroValue ? amount !== 0n : amount === 0n) {
      fail(`${label}.amount must be ${zeroValue ? "zero" : "positive"}`);
    }
    const txHash = successfulTransaction(entry.transaction, `${label}.transaction`, {
      ...context,
      sender: context.actor,
      expectedValue: amount,
      expectedOperation: "deposit",
      expectedEvent: "PrivacyDeposit"
    });
    assertEqual(evmAddress(entry.eventEffectiveSender, `${label}.eventEffectiveSender`), context.actor, `${label}.eventEffectiveSender does not match actor`);
    assertEqual(evmAddress(entry.eventOperator, `${label}.eventOperator`), context.actor, `${label}.eventOperator does not match actor`);
    const commitment = hex32(entry.commitment, `${label}.commitment`);
    assertEqual(
      hex32(entry.receiptCommitment, `${label}.receiptCommitment`),
      commitment,
      `${label}.receiptCommitment differs from the prepared deposit commitment`
    );
    assertEqual(
      hex32(entry.typedScanCommitment, `${label}.typedScanCommitment`),
      commitment,
      `${label}.typedScanCommitment differs from the receipt deposit commitment`
    );
    validateScanTransactionLink(
      entry.scanTransactionLink,
      `${label}.scanTransactionLink`,
      txHash
    );
    const before = state(entry.before, `${label}.before`);
    const after = state(entry.after, `${label}.after`);
    if (zeroValue) {
      for (const field of stateFields.slice(0, 4)) {
        assertEqual(after[field], before[field], `${label}.${field} changed for zero-value deposit`);
      }
    } else {
      // msg.value is credited to the fixed precompile escrow and consumed by
      // DepositWithFunder inside one atomic EVM transaction. At an observable
      // block boundary the escrow must therefore retain no part of the deposit.
      assertEqual(after.fixedEscrowBalance, before.fixedEscrowBalance, `${label}.fixedEscrowBalance retained deposit value`);
      assertEqual(after.privacyModuleBalance, before.privacyModuleBalance + amount, `${label}.privacyModuleBalance delta does not equal amount`);
      assertEqual(after.totalDeposited, before.totalDeposited + amount, `${label}.totalDeposited delta does not equal amount`);
      assertEqual(after.totalWithdrawn, before.totalWithdrawn, `${label}.totalWithdrawn changed`);
    }
    assertEqual(after.leafCount, before.leafCount + 1n, `${label}.leafCount delta does not equal one`);
    assertDepositScanDelta(after, before, label);
    assertReserveInvariant(after, entry.reserveInvariantHolds, label);
  };

  validateSuccess(flow.success, "deposit.success");
  validateSuccess(flow.zeroValue, "deposit.zeroValue", { zeroValue: true });

  const rollback = requiredObject(flow.rollback, "deposit.rollback");
  const rollbackAmount = uint(rollback.amount, "deposit.rollback.amount");
  if (rollbackAmount === 0n) fail("deposit.rollback.amount must be positive");
  assertEqual(
    requiredString(rollback.failureKind, "deposit.rollback.failureKind"),
    "downstream-policy-after-execution",
    "deposit.rollback.failureKind must be downstream-policy-after-execution"
  );
  assertEqual(
    requiredString(rollback.failureStage, "deposit.rollback.failureStage"),
    "post-core",
    "deposit.rollback.failureStage must be post-core"
  );
  requiredString(rollback.failureReason, "deposit.rollback.failureReason");
  const postCore = requiredObject(rollback.postCoreProof, "deposit.rollback.postCoreProof");
  literalTrue(postCore.innerCallSucceeded, "deposit.rollback.postCoreProof.innerCallSucceeded");
  const harnessAddress = evmAddress(
    postCore.harnessAddress,
    "deposit.rollback.postCoreProof.harnessAddress"
  );
  if (harnessAddress === context.precompileAddress) {
    fail("deposit.rollback.postCoreProof.harnessAddress must differ from precompileAddress");
  }
  const expectedHarness = createEvmPostCoreRollbackHarness(context.precompileAddress);
  assertEqual(
    calldata(postCore.runtimeCode, "deposit.rollback.postCoreProof.runtimeCode"),
    expectedHarness.runtimeCode,
    "deposit.rollback.postCoreProof.runtimeCode is not the canonical post-core rollback harness"
  );
  assertEqual(
    `0x${hex32(postCore.successMarker, "deposit.rollback.postCoreProof.successMarker")}`,
    expectedHarness.successMarker,
    "deposit.rollback.postCoreProof.successMarker is invalid"
  );
  assertEqual(
    `0x${hex32(postCore.simulationRevertData, "deposit.rollback.postCoreProof.simulationRevertData")}`,
    expectedHarness.successMarker,
    "deposit.rollback.postCoreProof.simulationRevertData does not prove inner-call success"
  );
  assertEqual(
    evmAddress(postCore.innerTarget, "deposit.rollback.postCoreProof.innerTarget"),
    context.precompileAddress,
    "deposit.rollback.postCoreProof.innerTarget differs from precompileAddress"
  );
  const rollbackCalldata = calldata(
    rollback.transaction?.prepared?.data,
    "deposit.rollback.transaction.prepared.data"
  );
  assertEqual(
    calldata(postCore.innerCalldata, "deposit.rollback.postCoreProof.innerCalldata"),
    rollbackCalldata,
    "deposit.rollback.postCoreProof.innerCalldata differs from the reverted outer call"
  );
  assertEqual(
    quantity(postCore.innerValue, "deposit.rollback.postCoreProof.innerValue"),
    rollbackAmount,
    "deposit.rollback.postCoreProof.innerValue differs from rollback amount"
  );
  const deploymentTxHash = transactionHash(
    postCore.deploymentTransactionHash,
    "deposit.rollback.postCoreProof.deploymentTransactionHash"
  );
  const attestationTxHash = transactionHash(
    postCore.attestationTransactionHash,
    "deposit.rollback.postCoreProof.attestationTransactionHash"
  );
  if (deploymentTxHash === attestationTxHash) {
    fail("deposit.rollback post-core deployment and attestation transactions must differ");
  }
  const rollbackTxHash = revertedTransaction(rollback.transaction, "deposit.rollback.transaction", {
    ...context,
    sender: context.rollbackActor,
    expectedTarget: harnessAddress,
    expectedValue: rollbackAmount,
    expectedOperation: "deposit",
    expectedEvent: "PrivacyDeposit"
  });
  if (rollbackTxHash === deploymentTxHash || rollbackTxHash === attestationTxHash) {
    fail("deposit.rollback post-core setup transactions must differ from the reverted transaction");
  }
  const rollbackBefore = state(rollback.before, "deposit.rollback.before");
  const rollbackAfter = state(rollback.after, "deposit.rollback.after");
  assertStateEqual(rollbackAfter, rollbackBefore, "deposit.rollback");
  assertReserveInvariant(rollbackAfter, rollback.reserveInvariantHolds, "deposit.rollback");

  const recovered = requiredObject(flow.recoveredNote, "deposit.recoveredNote");
  assertEqual(requiredString(recovered.scanSource, "deposit.recoveredNote.scanSource"), "privacy_scan", "deposit.recoveredNote.scanSource must be privacy_scan");
  assertEqual(hex32(recovered.commitment, "deposit.recoveredNote.commitment"), hex32(flow.success.commitment, "deposit.success.commitment"), "deposit recovered commitment differs from the successful deposit");
  assertEqual(uint(recovered.amount, "deposit.recoveredNote.amount"), uint(flow.success.amount, "deposit.success.amount"), "deposit recovered amount differs from the successful deposit");
  assertEqual(requiredString(recovered.denom, "deposit.recoveredNote.denom"), context.denom, "deposit recovered denom differs from denom");
  literalTrue(recovered.spendable, "deposit.recoveredNote.spendable");
}

function validateNullifiers(entries, label, expectedCount) {
  if (!Array.isArray(entries) || entries.length !== expectedCount) {
    fail(`${label} must contain exactly ${expectedCount} items`);
  }
  const values = entries.map((entry, index) => {
    requiredObject(entry, `${label}[${index}]`);
    literalTrue(entry.spent, `${label}[${index}].spent`);
    return hex32(entry.nullifier, `${label}[${index}].nullifier`);
  });
  if (new Set(values).size !== values.length) fail(`${label} contains duplicate nullifiers`);
}

function validateTransfer(flow, context) {
  requiredObject(flow, "transfer");
  assertEqual(requiredString(flow.sdkMethod, "transfer.sdkMethod"), "prepareTransfer", "transfer.sdkMethod must be prepareTransfer");
  const amount = uint(flow.amount, "transfer.amount");
  if (amount === 0n) fail("transfer.amount must be positive");
  assertEqual(requiredString(flow.denom, "transfer.denom"), context.denom, "transfer.denom differs from denom");
  const recipient = requiredString(flow.recipient, "transfer.recipient");
  const creatorReplacement = requiredObject(flow.creatorReplacement, "transfer.creatorReplacement");
  assertEqual(evmAddress(creatorReplacement.preparedBy, "transfer.creatorReplacement.preparedBy"), context.actor, "transfer creator replacement was not prepared by actor");
  assertEqual(evmAddress(creatorReplacement.submittedBy, "transfer.creatorReplacement.submittedBy"), context.relayer, "transfer creator replacement was not submitted by relayer");
  literalTrue(creatorReplacement.calldataUnchanged, "transfer.creatorReplacement.calldataUnchanged");
  literalTrue(creatorReplacement.proofUnchanged, "transfer.creatorReplacement.proofUnchanged");
  literalTrue(creatorReplacement.effectsMatched, "transfer.creatorReplacement.effectsMatched");
  const txHash = successfulTransaction(flow.transaction, "transfer.transaction", {
    ...context,
    sender: context.relayer,
    expectedValue: 0n,
    expectedOperation: "transfer",
    expectedEvent: "PrivacyTransfer"
  });
  const inputCount = boundedCount(flow.inputCount, "transfer.inputCount", 1, 2);
  validateNullifiers(flow.inputNullifiers, "transfer.inputNullifiers", inputCount);

  // The EVM receipt binds the prepared transfer root. Per-output payment
  // evidence is observed through typed privacy_scan, not a Solidity output
  // event. Keep those evidence sources distinct in the integration contract.
  const observed = requiredObject(flow.observedOutput, "transfer.observedOutput");
  const commitment = hex32(observed.outputCommitment, "transfer.observedOutput.outputCommitment");
  hex32(observed.auditDisclosureDigest, "transfer.observedOutput.auditDisclosureDigest");
  assertEqual(uint(observed.amount, "transfer.observedOutput.amount"), amount, "transfer.observedOutput.amount differs from transfer.amount");
  assertEqual(requiredString(observed.denom, "transfer.observedOutput.denom"), context.denom, "transfer.observedOutput.denom differs from denom");
  assertEqual(hex32(observed.recipientHash, "transfer.observedOutput.recipientHash"), hashRecipient(recipient, { shieldedPrefix: context.shieldedPrefix }), "transfer.observedOutput.recipientHash differs from the recipient hash");
  assertEqual(hex32(observed.amountHash, "transfer.observedOutput.amountHash"), hashAmount(context.denom, amount), "transfer.observedOutput.amountHash differs from the amount hash");
  literalTrue(flow.operationEvidenceMatched, "transfer.operationEvidenceMatched");

  const recovered = requiredObject(flow.recoveredOutput, "transfer.recoveredOutput");
  assertEqual(hex32(recovered.commitment, "transfer.recoveredOutput.commitment"), commitment, "transfer recovered commitment differs from the event");
  assertEqual(uint(recovered.amount, "transfer.recoveredOutput.amount"), amount, "transfer recovered amount differs from transfer.amount");
  assertEqual(requiredString(recovered.denom, "transfer.recoveredOutput.denom"), context.denom, "transfer recovered denom differs from denom");
  literalTrue(recovered.spendable, "transfer.recoveredOutput.spendable");
  const disclosure = requiredObject(flow.disclosure, "transfer.disclosure");
  literalTrue(disclosure.verified, "transfer.disclosure.verified");
  literalTrue(disclosure.typedScanOutput, "transfer.disclosure.typedScanOutput");
  validateScanTransactionLink(
    disclosure.scanTransactionLink,
    "transfer.disclosure.scanTransactionLink",
    txHash
  );
  assertEqual(hex32(disclosure.outputCommitment, "transfer.disclosure.outputCommitment"), commitment, "transfer disclosure commitment differs from the observed output");
  assertEqual(hex32(disclosure.digest, "transfer.disclosure.digest"), hex32(disclosure.preparedDigest, "transfer.disclosure.preparedDigest"), "transfer disclosure digest differs from the prepared transfer");

  const auditDisclosure = requiredObject(flow.auditDisclosure, "transfer.auditDisclosure");
  literalTrue(auditDisclosure.verified, "transfer.auditDisclosure.verified");
  literalTrue(auditDisclosure.typedScanOutput, "transfer.auditDisclosure.typedScanOutput");
  const auditScanTxHash = validateScanTransactionLink(
    auditDisclosure.scanTransactionLink,
    "transfer.auditDisclosure.scanTransactionLink",
    txHash
  );
  assertEqual(
    auditScanTxHash,
    transactionHash(disclosure.scanTransactionLink.scanTxHash, "transfer.disclosure.scanTransactionLink.scanTxHash"),
    "transfer user and audit disclosures were not decoded from the same typed scan transaction"
  );
  assertEqual(hex32(auditDisclosure.outputCommitment, "transfer.auditDisclosure.outputCommitment"), commitment, "transfer audit disclosure commitment differs from the observed output");
  const preparedAuditDigest = hex32(auditDisclosure.preparedDigest, "transfer.auditDisclosure.preparedDigest");
  assertEqual(hex32(auditDisclosure.typedScanDigest, "transfer.auditDisclosure.typedScanDigest"), preparedAuditDigest, "transfer typed scan audit digest differs from the prepared reservation evidence");
  assertEqual(hex32(auditDisclosure.decodedDigest, "transfer.auditDisclosure.decodedDigest"), preparedAuditDigest, "transfer decoded audit digest differs from the prepared reservation evidence");
  assertEqual(hex32(observed.auditDisclosureDigest, "transfer.observedOutput.auditDisclosureDigest"), preparedAuditDigest, "transfer observed audit digest differs from the prepared reservation evidence");

  const selfViewDisclosure = requiredObject(flow.selfViewDisclosure, "transfer.selfViewDisclosure");
  literalTrue(selfViewDisclosure.verified, "transfer.selfViewDisclosure.verified");
  literalTrue(selfViewDisclosure.typedScanOutput, "transfer.selfViewDisclosure.typedScanOutput");
  const selfViewScanTxHash = validateScanTransactionLink(
    selfViewDisclosure.scanTransactionLink,
    "transfer.selfViewDisclosure.scanTransactionLink",
    txHash
  );
  assertEqual(
    selfViewScanTxHash,
    auditScanTxHash,
    "transfer user, self-view, and audit disclosures were not decoded from the same typed scan transaction"
  );
  assertEqual(
    hex32(selfViewDisclosure.outputCommitment, "transfer.selfViewDisclosure.outputCommitment"),
    commitment,
    "transfer self-view disclosure commitment differs from the observed output"
  );
  const preparedSelfViewDigest = hex32(
    selfViewDisclosure.preparedDigest,
    "transfer.selfViewDisclosure.preparedDigest"
  );
  assertEqual(
    hex32(selfViewDisclosure.typedScanDigest, "transfer.selfViewDisclosure.typedScanDigest"),
    preparedSelfViewDigest,
    "transfer typed scan self-view digest differs from the prepared transfer"
  );
  assertEqual(
    hex32(selfViewDisclosure.decodedDigest, "transfer.selfViewDisclosure.decodedDigest"),
    preparedSelfViewDigest,
    "transfer decoded self-view digest differs from the prepared transfer"
  );
  return txHash;
}

function validateBatch(flow, context) {
  requiredObject(flow, "batch");
  assertEqual(requiredString(flow.sdkMethod, "batch.sdkMethod"), "prepareTransferBatch", "batch.sdkMethod must be prepareTransferBatch");
  const authorization = requiredObject(flow.authorization, "batch.authorization");
  const authorizationKind = boundedCount(authorization.kind, "batch.authorization.kind", 0, 255);
  assertEqual(evmAddress(authorization.effectiveSender, "batch.authorization.effectiveSender"), context.actor, "batch authorization effective sender differs from actor");
  assertEqual(evmAddress(authorization.executor, "batch.authorization.executor"), context.relayer, "batch authorization executor differs from relayer");
  literalTrue(authorization.signatureVerified, "batch.authorization.signatureVerified");
  literalTrue(authorization.nonceConsumed, "batch.authorization.nonceConsumed");
  if (!Array.isArray(authorization.profileSupportedKinds) || authorization.profileSupportedKinds.length === 0) {
    fail("batch.authorization.profileSupportedKinds must be a non-empty target-profile allowlist");
  }
  const supportedKinds = authorization.profileSupportedKinds.map((kind, index) =>
    boundedCount(kind, `batch.authorization.profileSupportedKinds[${index}]`, 0, 255));
  if (new Set(supportedKinds).size !== supportedKinds.length) {
    fail("batch.authorization.profileSupportedKinds contains duplicates");
  }
  if (!supportedKinds.includes(authorizationKind)) {
    fail("batch.authorization.profileSupportedKinds does not include the exercised kind");
  }
  const txHash = successfulTransaction(flow.transaction, "batch.transaction", {
    ...context,
    sender: context.relayer,
    expectedValue: 0n,
    expectedOperation: "singleProofBatchTransferWithAuthorization",
    expectedEvent: "PrivacySingleProofBatchTransfer"
  });
  literalTrue(authorization.replayRejected, "batch.authorization.replayRejected");
  const replayFailureReason = requiredString(
    authorization.replayFailureReason,
    "batch.authorization.replayFailureReason"
  );
  if (!/nonce/i.test(replayFailureReason)) {
    fail("batch.authorization.replayFailureReason must prove nonce-based rejection");
  }
  const replayTxHash = revertedTransaction(
    authorization.replayTransaction,
    "batch.authorization.replayTransaction",
    {
      ...context,
      sender: context.relayer,
      expectedValue: 0n,
      expectedOperation: "singleProofBatchTransferWithAuthorization",
      expectedEvent: "PrivacySingleProofBatchTransfer"
    }
  );
  if (replayTxHash === txHash) fail("batch authorization replay must be a distinct submitted transaction");
  assertEqual(
    calldata(
      authorization.replayTransaction.prepared.data,
      "batch.authorization.replayTransaction.prepared.data"
    ),
    calldata(flow.transaction.prepared.data, "batch.transaction.prepared.data"),
    "batch authorization replay must reuse the exact authorized calldata and nonce"
  );
  assertEqual(boundedCount(flow.proofCount, "batch.proofCount", 1, 1), 1, "batch.proofCount must be one");
  assertEqual(boundedCount(flow.transactionCount, "batch.transactionCount", 1, 1), 1, "batch.transactionCount must be one");
  const inputCount = boundedCount(flow.inputCount, "batch.inputCount", 1, 16);
  const outputCount = boundedCount(flow.outputCount, "batch.outputCount", 1, 32);
  validateNullifiers(flow.inputNullifiers, "batch.inputNullifiers", inputCount);
  literalTrue(flow.atomic, "batch.atomic");
  literalTrue(flow.operationEvidenceMatched, "batch.operationEvidenceMatched");
  const scanTxHash = validateScanTransactionLink(
    flow.scanTransactionLink,
    "batch.scanTransactionLink",
    txHash
  );
  if (!Array.isArray(flow.requestedPayments) ||
      flow.requestedPayments.length < 1 || flow.requestedPayments.length > 32) {
    fail("batch.requestedPayments must contain the complete 1..32 item request");
  }
  const requestedItemIds = new Set();
  const requestedPayments = flow.requestedPayments.map((payment, index) => {
    requiredObject(payment, `batch.requestedPayments[${index}]`);
    const itemId = requiredString(payment.itemId, `batch.requestedPayments[${index}].itemId`);
    if (requestedItemIds.has(itemId)) fail("batch.requestedPayments contains duplicate item IDs");
    requestedItemIds.add(itemId);
    const recipient = requiredString(payment.recipient, `batch.requestedPayments[${index}].recipient`);
    const amount = uint(payment.amount, `batch.requestedPayments[${index}].amount`);
    if (amount === 0n) fail(`batch.requestedPayments[${index}].amount must be positive`);
    const paymentDenom = requiredString(payment.denom, `batch.requestedPayments[${index}].denom`);
    assertEqual(paymentDenom, context.denom, `batch.requestedPayments[${index}].denom differs from denom`);
    const policy = boundedCount(
      payment.userPrivacyPolicy,
      `batch.requestedPayments[${index}].userPrivacyPolicy`,
      0,
      7
    );
    const mode = boundedCount(
      payment.userDisclosureMode,
      `batch.requestedPayments[${index}].userDisclosureMode`,
      0,
      2
    );
    if ((policy === 0 && mode !== 0) || (policy !== 0 && mode === 0)) {
      fail(`batch.requestedPayments[${index}] has an incompatible privacy policy and disclosure mode`);
    }
    return {
      itemId,
      recipient,
      amount: amount.toString(),
      denom: paymentDenom,
      recipientHash: hashRecipient(recipient, { shieldedPrefix: context.shieldedPrefix }),
      amountHash: hashAmount(paymentDenom, amount),
      userPrivacyPolicy: policy,
      userDisclosureMode: mode
    };
  });
  const disclosureModes = new Set(requestedPayments.map(payment => payment.userDisclosureMode));
  if (!disclosureModes.has(1) || !disclosureModes.has(2)) {
    fail("batch.requestedPayments must exercise public and recipient-encrypted disclosure modes");
  }
  if (!Array.isArray(flow.payments) || flow.payments.length < 1 || flow.payments.length > 32) {
    fail("batch.payments must contain 1..32 items");
  }
  if (flow.payments.length !== requestedPayments.length) {
    fail("batch.payments must exactly match the complete requested payment list");
  }
  if (outputCount < flow.payments.length) fail("batch.outputCount is smaller than the payment count");
  const operationEvidence = requiredObject(flow.operationEvidence, "batch.operationEvidence");
  assertEqual(requiredString(operationEvidence.version, "batch.operationEvidence.version"), "batch-transfer-operation-evidence-v1", "batch.operationEvidence.version is unsupported");
  const operationId = requiredString(operationEvidence.operation_id, "batch.operationEvidence.operation_id");
  assertEqual(requiredString(operationEvidence.circuit_set_id, "batch.operationEvidence.circuit_set_id"), "privacy-note-v1", "batch.operationEvidence.circuit_set_id must be privacy-note-v1");
  const payloadHash = hex32(operationEvidence.payload_hash, "batch.operationEvidence.payload_hash");
  const proofPayloadHash = hex32(operationEvidence.proof_payload_hash, "batch.operationEvidence.proof_payload_hash");
  const proofHash = hex32(operationEvidence.proof_hash, "batch.operationEvidence.proof_hash");
  assertEqual(proofPayloadHash, payloadHash, "batch operation proof payload hash differs from its payload hash");
  if (!Array.isArray(operationEvidence.input_nullifier_hexes) ||
      operationEvidence.input_nullifier_hexes.length !== inputCount) {
    fail(`batch.operationEvidence.input_nullifier_hexes must contain exactly ${inputCount} items`);
  }
  const canonicalNullifiers = operationEvidence.input_nullifier_hexes.map((value, index) => {
    const nullifier = hex32(value, `batch.operationEvidence.input_nullifier_hexes[${index}]`);
    assertEqual(nullifier, hex32(flow.inputNullifiers[index].nullifier, `batch.inputNullifiers[${index}].nullifier`), `batch operation evidence nullifier ${index} differs from the spent input`);
    return nullifier;
  });
  if (!Array.isArray(operationEvidence.expected_outputs) ||
      operationEvidence.expected_outputs.length !== flow.payments.length) {
    fail("batch.operationEvidence.expected_outputs must exactly match the complete payment list");
  }
  const itemIds = new Set();
  const canonicalExpectedOutputs = operationEvidence.expected_outputs.map((expected, index) => {
    requiredObject(expected, `batch.operationEvidence.expected_outputs[${index}]`);
    assertEqual(requiredString(expected.operation_id, `batch.operationEvidence.expected_outputs[${index}].operation_id`), operationId, `batch expected output ${index} operation ID differs`);
    const itemId = requiredString(expected.item_id, `batch.operationEvidence.expected_outputs[${index}].item_id`);
    if (itemIds.has(itemId)) fail("batch.operationEvidence.expected_outputs contains duplicate item IDs");
    itemIds.add(itemId);
    assertEqual(expected.batch_item_index, index, `batch.operationEvidence.expected_outputs[${index}].batch_item_index must equal ${index}`);
    assertEqual(requiredString(expected.role, `batch.operationEvidence.expected_outputs[${index}].role`), "payment", `batch expected output ${index} role must be payment`);
    const userDigest = optionalHex32(expected.expected_user_disclosure_digest, `batch.operationEvidence.expected_outputs[${index}].expected_user_disclosure_digest`);
    const selfViewDigest = optionalHex32(expected.expected_self_view_disclosure_digest, `batch.operationEvidence.expected_outputs[${index}].expected_self_view_disclosure_digest`);
    const amount = uint(expected.expected_amount, `batch.operationEvidence.expected_outputs[${index}].expected_amount`);
    if (amount === 0n) fail(`batch.operationEvidence.expected_outputs[${index}].expected_amount must be positive`);
    const auditKeyEpoch = uint(expected.audit_key_epoch, `batch.operationEvidence.expected_outputs[${index}].audit_key_epoch`);
    if (auditKeyEpoch === 0n) fail(`batch.operationEvidence.expected_outputs[${index}].audit_key_epoch must be positive`);
    return {
      operation_id: operationId,
      item_id: itemId,
      batch_item_index: index,
      role: "payment",
      expected_output_commitment: hex32(expected.expected_output_commitment, `batch.operationEvidence.expected_outputs[${index}].expected_output_commitment`),
      expected_user_disclosure_digest: userDigest,
      expected_audit_disclosure_digest: hex32(expected.expected_audit_disclosure_digest, `batch.operationEvidence.expected_outputs[${index}].expected_audit_disclosure_digest`),
      expected_self_view_disclosure_digest: selfViewDigest,
      expected_recipient_hash: hex32(expected.expected_recipient_hash, `batch.operationEvidence.expected_outputs[${index}].expected_recipient_hash`),
      expected_amount: amount.toString(),
      expected_amount_hash: hex32(expected.expected_amount_hash, `batch.operationEvidence.expected_outputs[${index}].expected_amount_hash`),
      expected_denom: requiredString(expected.expected_denom, `batch.operationEvidence.expected_outputs[${index}].expected_denom`),
      asset_id_hex: hex32(expected.asset_id_hex, `batch.operationEvidence.expected_outputs[${index}].asset_id_hex`),
      user_privacy_policy: boundedCount(expected.user_privacy_policy, `batch.operationEvidence.expected_outputs[${index}].user_privacy_policy`, 0, 7),
      user_disclosure_mode: boundedCount(expected.user_disclosure_mode, `batch.operationEvidence.expected_outputs[${index}].user_disclosure_mode`, 0, 2),
      audit_key_id: requiredString(expected.audit_key_id, `batch.operationEvidence.expected_outputs[${index}].audit_key_id`),
      audit_key_epoch: auditKeyEpoch.toString()
    };
  });
  canonicalExpectedOutputs.forEach((expected, index) => {
    const requested = requestedPayments[index];
    assertEqual(expected.item_id, requested.itemId, `batch expected output ${index} item ID differs from the request`);
    assertEqual(expected.expected_recipient_hash, requested.recipientHash, `batch expected output ${index} recipient hash differs from the request`);
    assertEqual(expected.expected_amount, requested.amount, `batch expected output ${index} amount differs from the request`);
    assertEqual(expected.expected_amount_hash, requested.amountHash, `batch expected output ${index} amount hash differs from the request`);
    assertEqual(expected.expected_denom, requested.denom, `batch expected output ${index} denom differs from the request`);
    assertEqual(expected.user_privacy_policy, requested.userPrivacyPolicy, `batch expected output ${index} privacy policy differs from the request`);
    assertEqual(expected.user_disclosure_mode, requested.userDisclosureMode, `batch expected output ${index} disclosure mode differs from the request`);
  });
  const canonicalOperationEvidence = {
    version: "batch-transfer-operation-evidence-v1",
    operation_id: operationId,
    circuit_set_id: "privacy-note-v1",
    payload_hash: payloadHash,
    proof_payload_hash: proofPayloadHash,
    proof_hash: proofHash,
    input_nullifier_hexes: canonicalNullifiers,
    expected_outputs: canonicalExpectedOutputs
  };
  assertEqual(
    hex32(flow.operationEvidenceHash, "batch.operationEvidenceHash"),
    sha256Hex(JSON.stringify(canonicalOperationEvidence)),
    "batch.operationEvidenceHash does not bind the canonical aggregate operation evidence"
  );

  const auditKeyId = requiredString(flow.auditKeyId, "batch.auditKeyId");
  const auditKeyEpoch = uint(flow.auditKeyEpoch, "batch.auditKeyEpoch");
  if (auditKeyEpoch === 0n) fail("batch.auditKeyEpoch must be positive");
  if (typeof flow.selfViewEnabled !== "boolean") fail("batch.selfViewEnabled must be boolean");
  const commitments = [];
  flow.payments.forEach((payment, index) => {
    requiredObject(payment, `batch.payments[${index}]`);
    const requested = requestedPayments[index];
    assertEqual(payment.index, index, `batch.payments[${index}].index must equal its canonical output index`);
    const recipient = requiredString(payment.recipient, `batch.payments[${index}].recipient`);
    assertEqual(requiredString(payment.itemId, `batch.payments[${index}].itemId`), requested.itemId, `batch.payments[${index}].itemId differs from the request`);
    assertEqual(recipient, requested.recipient, `batch.payments[${index}].recipient differs from the request`);
    const amount = uint(payment.amount, `batch.payments[${index}].amount`);
    if (amount === 0n) fail(`batch.payments[${index}].amount must be positive`);
    assertEqual(amount.toString(), requested.amount, `batch.payments[${index}].amount differs from the request`);
    assertEqual(requiredString(payment.denom, `batch.payments[${index}].denom`), context.denom, `batch.payments[${index}].denom differs from denom`);
    const commitment = hex32(payment.outputCommitment, `batch.payments[${index}].outputCommitment`);
    commitments.push(commitment);
    const recipientHash = hex32(payment.recipientHash, `batch.payments[${index}].recipientHash`);
    const amountHash = hex32(payment.amountHash, `batch.payments[${index}].amountHash`);
    assertEqual(recipientHash, hashRecipient(recipient, { shieldedPrefix: context.shieldedPrefix }), `batch.payments[${index}].recipientHash differs from the recipient hash`);
    assertEqual(amountHash, hashAmount(context.denom, amount), `batch.payments[${index}].amountHash differs from the amount hash`);
    const policy = boundedCount(payment.userPrivacyPolicy, `batch.payments[${index}].userPrivacyPolicy`, 0, 7);
    const mode = boundedCount(payment.userDisclosureMode, `batch.payments[${index}].userDisclosureMode`, 0, 2);
    assertEqual(policy, requested.userPrivacyPolicy, `batch.payments[${index}].privacy policy differs from the request`);
    assertEqual(mode, requested.userDisclosureMode, `batch.payments[${index}].disclosure mode differs from the request`);
    const userDigest = optionalHex32(payment.userDisclosureDigest, `batch.payments[${index}].userDisclosureDigest`);
    if (policy === 0) {
      if (mode !== 0 || userDigest) fail(`batch.payments[${index}] all-private disclosure evidence is invalid`);
    } else if ((mode !== 1 && mode !== 2) || !userDigest) {
      fail(`batch.payments[${index}] disclosed output evidence is invalid`);
    }
    const auditDigest = hex32(payment.auditDisclosureDigest, `batch.payments[${index}].auditDisclosureDigest`);
    const selfViewDigest = optionalHex32(payment.selfViewDisclosureDigest, `batch.payments[${index}].selfViewDisclosureDigest`);
    if (flow.selfViewEnabled) {
      assertEqual(selfViewDigest, auditDigest, `batch.payments[${index}] self-view digest differs from its full disclosure digest`);
    } else if (selfViewDigest) {
      fail(`batch.payments[${index}] has self-view evidence while batch self-view is disabled`);
    }
    if (mode === 0) literalFalse(payment.userDisclosureVerified, `batch.payments[${index}].userDisclosureVerified`);
    else literalTrue(payment.userDisclosureVerified, `batch.payments[${index}].userDisclosureVerified`);
    assertEqual(transactionHash(payment.typedScanTxHash, `batch.payments[${index}].typedScanTxHash`), scanTxHash, `batch.payments[${index}] typed scan tx hash differs from the linked Cosmos transaction`);
    literalTrue(payment.typedScanMatched, `batch.payments[${index}].typedScanMatched`);
    literalTrue(payment.recovered, `batch.payments[${index}].recovered`);

    const expected = canonicalExpectedOutputs[index];
    assertEqual(commitment, expected.expected_output_commitment, `batch payment ${index} commitment differs from operation evidence`);
    assertEqual(userDigest, expected.expected_user_disclosure_digest, `batch payment ${index} user disclosure digest differs from operation evidence`);
    assertEqual(auditDigest, expected.expected_audit_disclosure_digest, `batch payment ${index} audit disclosure digest differs from operation evidence`);
    assertEqual(selfViewDigest, expected.expected_self_view_disclosure_digest, `batch payment ${index} self-view disclosure digest differs from operation evidence`);
    assertEqual(recipientHash, expected.expected_recipient_hash, `batch payment ${index} recipient hash differs from operation evidence`);
    assertEqual(amount.toString(), expected.expected_amount, `batch payment ${index} amount differs from operation evidence`);
    assertEqual(amountHash, expected.expected_amount_hash, `batch payment ${index} amount hash differs from operation evidence`);
    assertEqual(context.denom, expected.expected_denom, `batch payment ${index} denom differs from operation evidence`);
    assertEqual(policy, expected.user_privacy_policy, `batch payment ${index} privacy policy differs from operation evidence`);
    assertEqual(mode, expected.user_disclosure_mode, `batch payment ${index} disclosure mode differs from operation evidence`);
    assertEqual(auditKeyId, expected.audit_key_id, `batch payment ${index} audit key ID differs from operation evidence`);
    assertEqual(auditKeyEpoch.toString(), expected.audit_key_epoch, `batch payment ${index} audit key epoch differs from operation evidence`);
  });
  if (new Set(commitments).size !== commitments.length) fail("batch.payments contains duplicate output commitments");

  if (!Array.isArray(flow.outputs) || flow.outputs.length !== outputCount) {
    fail("batch.outputs must contain the complete payment/change/padding output set");
  }
  let sawChange = false;
  let sawPadding = false;
  const allCommitments = [];
  flow.outputs.forEach((output, index) => {
    requiredObject(output, `batch.outputs[${index}]`);
    assertEqual(output.index, index, `batch.outputs[${index}].index must form a contiguous prefix`);
    const role = requiredString(output.role, `batch.outputs[${index}].role`);
    if (index < flow.payments.length) {
      assertEqual(role, "payment", `batch.outputs[${index}].role must be payment`);
    } else if (role === "change") {
      if (sawChange || sawPadding || index !== flow.payments.length) {
        fail(`batch.outputs[${index}] change output is not in canonical order`);
      }
      sawChange = true;
    } else if (role === "padding") {
      sawPadding = true;
    } else {
      fail(`batch.outputs[${index}].role must be payment, change, or padding`);
    }
    const amount = uint(output.amount, `batch.outputs[${index}].amount`);
    if ((role === "payment" || role === "change") && amount === 0n) {
      fail(`batch.outputs[${index}].amount must be positive for ${role}`);
    }
    if (role === "padding" && amount !== 0n) {
      fail(`batch.outputs[${index}].amount must be zero for padding`);
    }
    assertEqual(requiredString(output.denom, `batch.outputs[${index}].denom`), context.denom, `batch.outputs[${index}].denom differs from denom`);
    const commitment = hex32(output.outputCommitment, `batch.outputs[${index}].outputCommitment`);
    allCommitments.push(commitment);
    const policy = boundedCount(output.userPrivacyPolicy, `batch.outputs[${index}].userPrivacyPolicy`, 0, 7);
    const mode = boundedCount(output.userDisclosureMode, `batch.outputs[${index}].userDisclosureMode`, 0, 2);
    const userDigest = optionalHex32(output.userDisclosureDigest, `batch.outputs[${index}].userDisclosureDigest`);
    const auditDigest = hex32(output.auditDisclosureDigest, `batch.outputs[${index}].auditDisclosureDigest`);
    const selfViewDigest = optionalHex32(output.selfViewDisclosureDigest, `batch.outputs[${index}].selfViewDisclosureDigest`);
    assertEqual(requiredString(output.auditKeyId, `batch.outputs[${index}].auditKeyId`), auditKeyId, `batch.outputs[${index}].auditKeyId differs from batch audit identity`);
    assertEqual(uint(output.auditKeyEpoch, `batch.outputs[${index}].auditKeyEpoch`), auditKeyEpoch, `batch.outputs[${index}].auditKeyEpoch differs from batch audit identity`);
    assertEqual(transactionHash(output.typedScanTxHash, `batch.outputs[${index}].typedScanTxHash`), scanTxHash, `batch.outputs[${index}] typed scan tx hash differs from the linked Cosmos transaction`);
    literalTrue(output.typedScanMatched, `batch.outputs[${index}].typedScanMatched`);
    literalTrue(output.auditVerified, `batch.outputs[${index}].auditVerified`);
    literalTrue(output.recovered, `batch.outputs[${index}].recovered`);
    if (flow.selfViewEnabled) {
      assertEqual(selfViewDigest, auditDigest, `batch.outputs[${index}] self-view digest differs from its full disclosure digest`);
      literalTrue(output.selfViewVerified, `batch.outputs[${index}].selfViewVerified`);
    } else {
      if (selfViewDigest) fail(`batch.outputs[${index}] has self-view evidence while batch self-view is disabled`);
      literalFalse(output.selfViewVerified, `batch.outputs[${index}].selfViewVerified`);
    }
    if (mode === 0) {
      if (policy !== 0 || userDigest) fail(`batch.outputs[${index}] all-private user disclosure evidence is invalid`);
      literalFalse(output.userDisclosureVerified, `batch.outputs[${index}].userDisclosureVerified`);
    } else {
      if (policy === 0 || !userDigest) fail(`batch.outputs[${index}] enabled user disclosure evidence is invalid`);
      literalTrue(output.userDisclosureVerified, `batch.outputs[${index}].userDisclosureVerified`);
    }
    if (role !== "payment" && (policy !== 0 || mode !== 0 || userDigest)) {
      fail(`batch.outputs[${index}] ${role} output must be all-private`);
    }
    if (role === "padding") literalFalse(output.spendable, `batch.outputs[${index}].spendable`);
    else literalTrue(output.spendable, `batch.outputs[${index}].spendable`);
    if (role === "payment") {
      const payment = flow.payments[index];
      assertEqual(commitment, hex32(payment.outputCommitment, `batch.payments[${index}].outputCommitment`), `batch.outputs[${index}] commitment differs from its payment evidence`);
      assertEqual(amount.toString(), uint(payment.amount, `batch.payments[${index}].amount`).toString(), `batch.outputs[${index}] amount differs from its payment evidence`);
      assertEqual(userDigest, optionalHex32(payment.userDisclosureDigest, `batch.payments[${index}].userDisclosureDigest`), `batch.outputs[${index}] user disclosure digest differs from its payment evidence`);
      assertEqual(auditDigest, hex32(payment.auditDisclosureDigest, `batch.payments[${index}].auditDisclosureDigest`), `batch.outputs[${index}] audit disclosure digest differs from its payment evidence`);
      assertEqual(selfViewDigest, optionalHex32(payment.selfViewDisclosureDigest, `batch.payments[${index}].selfViewDisclosureDigest`), `batch.outputs[${index}] self-view disclosure digest differs from its payment evidence`);
    }
  });
  if (new Set(allCommitments).size !== allCommitments.length) {
    fail("batch.outputs contains duplicate output commitments");
  }
  return txHash;
}

function validateBatchShapeMatrix(matrix, context) {
  requiredObject(matrix, "batchShapeMatrix");
  assertEqual(
    requiredString(matrix.schemaVersion, "batchShapeMatrix.schemaVersion"),
    evmOneProofBatchMatrixSchema,
    `batchShapeMatrix.schemaVersion must be ${evmOneProofBatchMatrixSchema}`
  );
  if (!Array.isArray(matrix.shapes) || matrix.shapes.length !== evmOneProofBatchReleaseShapes.length) {
    fail(`batchShapeMatrix.shapes must contain exactly ${evmOneProofBatchReleaseShapes.length} shapes`);
  }
  const expectedById = new Map(evmOneProofBatchReleaseShapes.map(shape => [shape.id, shape]));
  const observedById = new Map();
  const transactionHashes = new Set();
  const scanTransactionHashes = new Set();
  const executionModes = new Set();

  matrix.shapes.forEach((shape, shapeIndex) => {
    const label = `batchShapeMatrix.shapes[${shapeIndex}]`;
    requiredObject(shape, label);
    const id = requiredString(shape.id, `${label}.id`);
    const expected = expectedById.get(id);
    if (!expected) fail(`${label}.id is not a required Clairveil v0.3.1 boundary shape`);
    if (observedById.has(id)) fail(`batchShapeMatrix.shapes contains duplicate shape ${id}`);
    observedById.set(id, shape);

    const executionMode = requiredString(shape.executionMode, `${label}.executionMode`);
    if (executionMode !== "direct" && executionMode !== "authorized") {
      fail(`${label}.executionMode must be direct or authorized`);
    }
    executionModes.add(executionMode);
    const operation = executionMode === "authorized"
      ? "singleProofBatchTransferWithAuthorization"
      : "singleProofBatchTransfer";
    const sender = executionMode === "authorized" ? context.relayer : context.actor;
    const txHash = successfulTransaction(shape.transaction, `${label}.transaction`, {
      ...context,
      sender,
      expectedValue: 0n,
      expectedOperation: operation,
      expectedEvent: "PrivacySingleProofBatchTransfer"
    });
    if (transactionHashes.has(txHash)) fail(`${label}.transaction reuses another shape transaction`);
    transactionHashes.add(txHash);

    assertEqual(boundedCount(shape.proofCount, `${label}.proofCount`, 1, 1), 1, `${label}.proofCount must be one`);
    assertEqual(boundedCount(shape.transactionCount, `${label}.transactionCount`, 1, 1), 1, `${label}.transactionCount must be one`);
    assertEqual(boundedCount(shape.inputCount, `${label}.inputCount`, 1, 16), expected.inputCount, `${label}.inputCount differs from the release shape`);
    assertEqual(boundedCount(shape.paymentCount, `${label}.paymentCount`, 1, 32), expected.paymentCount, `${label}.paymentCount differs from the release shape`);
    assertEqual(boundedCount(shape.outputCount, `${label}.outputCount`, 1, 32), expected.outputCount, `${label}.outputCount differs from the release shape`);
    assertEqual(boundedCount(shape.changeCount, `${label}.changeCount`, 0, 1), expected.changeCount, `${label}.changeCount differs from the release shape`);
    assertEqual(boundedCount(shape.paddingCount, `${label}.paddingCount`, 0, 31), expected.paddingCount, `${label}.paddingCount differs from the release shape`);
    assertEqual(requiredString(shape.outputMode, `${label}.outputMode`), expected.outputMode, `${label}.outputMode differs from the release shape`);
    if (shape.selfViewEnabled !== expected.selfViewEnabled) {
      fail(`${label}.selfViewEnabled differs from the release shape`);
    }
    validateExactAmounts(shape.inputAmounts, `${label}.inputAmounts`, expected.inputAmounts);
    validateExactAmounts(shape.paymentAmounts, `${label}.paymentAmounts`, expected.paymentAmounts);
    validateExactDisclosureModes(
      shape.disclosureModes,
      `${label}.disclosureModes`,
      expected.disclosureModes
    );
    validateNullifiers(shape.inputNullifiers, `${label}.inputNullifiers`, expected.inputCount);
    literalTrue(shape.atomic, `${label}.atomic`);
    literalTrue(shape.operationEvidenceMatched, `${label}.operationEvidenceMatched`);
    literalTrue(shape.reservationsSucceeded, `${label}.reservationsSucceeded`);

    const scanTxHash = validateScanTransactionLink(
      shape.scanTransactionLink,
      `${label}.scanTransactionLink`,
      txHash
    );
    if (scanTransactionHashes.has(scanTxHash)) fail(`${label}.scanTransactionLink reuses another shape transaction`);
    scanTransactionHashes.add(scanTxHash);

    if (!Array.isArray(shape.outputs) || shape.outputs.length !== expected.outputCount) {
      fail(`${label}.outputs must contain exactly ${expected.outputCount} typed outputs`);
    }
    let changeCount = 0;
    let paddingCount = 0;
    const outputCommitments = new Set();
    shape.outputs.forEach((output, outputIndex) => {
      const outputLabel = `${label}.outputs[${outputIndex}]`;
      requiredObject(output, outputLabel);
      assertEqual(output.index, outputIndex, `${outputLabel}.index must be contiguous`);
      const role = requiredString(output.role, `${outputLabel}.role`);
      const expectedRole = expected.outputRoles[outputIndex];
      assertEqual(role, expectedRole, `${outputLabel}.role differs from the canonical shape`);
      if (role === "change") changeCount += 1;
      if (role === "padding") paddingCount += 1;
      const amount = uint(output.amount, `${outputLabel}.amount`);
      assertEqual(
        amount.toString(),
        expected.outputAmounts[outputIndex],
        `${outputLabel}.amount differs from the pinned v0.3.1 fixture`
      );
      assertEqual(
        boundedCount(output.userDisclosureMode, `${outputLabel}.userDisclosureMode`, 0, 2),
        fixtureDisclosureModeValues[expected.disclosureModes[outputIndex]],
        `${outputLabel}.userDisclosureMode differs from the pinned v0.3.1 fixture`
      );
      const outputCommitment = hex32(output.outputCommitment, `${outputLabel}.outputCommitment`);
      if (outputCommitments.has(outputCommitment)) {
        fail(`${label}.outputs contains duplicate output commitments`);
      }
      outputCommitments.add(outputCommitment);
      assertEqual(transactionHash(output.typedScanTxHash, `${outputLabel}.typedScanTxHash`), scanTxHash, `${outputLabel}.typedScanTxHash differs from the shape scan transaction`);
      literalTrue(output.typedScanMatched, `${outputLabel}.typedScanMatched`);
      literalTrue(output.auditVerified, `${outputLabel}.auditVerified`);
      if (role === "padding") literalFalse(output.recovered, `${outputLabel}.recovered`);
      else literalTrue(output.recovered, `${outputLabel}.recovered`);
      if (expected.selfViewEnabled) literalTrue(output.selfViewVerified, `${outputLabel}.selfViewVerified`);
      else literalFalse(output.selfViewVerified, `${outputLabel}.selfViewVerified`);
      if (role === "padding") literalFalse(output.spendable, `${outputLabel}.spendable`);
      else literalTrue(output.spendable, `${outputLabel}.spendable`);
    });
    assertEqual(changeCount, expected.changeCount, `${label} observed change count differs`);
    assertEqual(paddingCount, expected.paddingCount, `${label} observed padding count differs`);
  });

  for (const expected of evmOneProofBatchReleaseShapes) {
    if (!observedById.has(expected.id)) fail(`batchShapeMatrix.shapes is missing ${expected.id}`);
  }
  if (!executionModes.has("direct")) {
    fail("batchShapeMatrix must execute at least one shape through direct singleProofBatchTransfer");
  }
  return observedById;
}

function validateWithdrawal(entry, label, context, sender, expectedMethod) {
  requiredObject(entry, label);
  assertEqual(requiredString(entry.sdkMethod, `${label}.sdkMethod`), expectedMethod, `${label}.sdkMethod must be ${expectedMethod}`);
  const amount = uint(entry.amount, `${label}.amount`);
  if (amount === 0n) fail(`${label}.amount must be positive`);
  assertEqual(requiredString(entry.denom, `${label}.denom`), context.denom, `${label}.denom differs from denom`);
  requiredString(entry.recipient, `${label}.recipient`);
  const txHash = successfulTransaction(entry.transaction, `${label}.transaction`, {
    ...context,
    sender,
    expectedValue: 0n,
    expectedOperation: "withdraw",
    expectedEvent: "PrivacyWithdraw"
  });
  const inputCount = boundedCount(entry.inputCount, `${label}.inputCount`, 1, 1);
  validateNullifiers(entry.inputNullifiers, `${label}.inputNullifiers`, inputCount);
  literalTrue(entry.legacyOutputFieldsAbsent, `${label}.legacyOutputFieldsAbsent`);
  const recipientBefore = uint(entry.recipientBalanceBefore, `${label}.recipientBalanceBefore`);
  const recipientAfter = uint(entry.recipientBalanceAfter, `${label}.recipientBalanceAfter`);
  assertEqual(recipientAfter, recipientBefore + amount, `${label} recipient balance delta does not equal amount`);
  const moduleBefore = uint(entry.privacyModuleBalanceBefore, `${label}.privacyModuleBalanceBefore`);
  const moduleAfter = uint(entry.privacyModuleBalanceAfter, `${label}.privacyModuleBalanceAfter`);
  if (moduleBefore < amount) fail(`${label} privacy module balance before withdrawal is smaller than amount`);
  assertEqual(moduleAfter, moduleBefore - amount, `${label} privacy module balance delta does not equal -amount`);
  const depositedBefore = uint(entry.totalDepositedBefore, `${label}.totalDepositedBefore`);
  const depositedAfter = uint(entry.totalDepositedAfter, `${label}.totalDepositedAfter`);
  assertEqual(depositedAfter, depositedBefore, `${label} totalDeposited changed`);
  const withdrawnBefore = uint(entry.totalWithdrawnBefore, `${label}.totalWithdrawnBefore`);
  const withdrawnAfter = uint(entry.totalWithdrawnAfter, `${label}.totalWithdrawnAfter`);
  assertEqual(withdrawnAfter, withdrawnBefore + amount, `${label} totalWithdrawn delta does not equal amount`);
  assertReserveInvariant({
    privacyModuleBalance: moduleAfter,
    totalDeposited: depositedAfter,
    totalWithdrawn: withdrawnAfter
  }, entry.reserveInvariantHolds, label);
  return { amount, txHash };
}

function validateWithdraw(flow, context) {
  requiredObject(flow, "withdraw");
  validateWithdrawal(flow.direct, "withdraw.direct", context, context.actor, "prepareWithdraw");
  const { amount: relayAmount, txHash: relayTxHash } = validateWithdrawal(
    flow.relay,
    "withdraw.relay",
    context,
    context.relayer,
    "prepareRelayWithdraw"
  );
  const relay = flow.relay;
  assertEqual(evmAddress(relay.owner, "withdraw.relay.owner"), context.actor, "withdraw.relay.owner does not match actor");
  assertEqual(evmAddress(relay.relayer, "withdraw.relay.relayer"), context.relayer, "withdraw.relay.relayer does not match relayer");
  if (context.actor === context.relayer) fail("withdraw.relay owner and relayer must differ");
  literalTrue(relay.candidateMatchedRelayerRebuild, "withdraw.relay.candidateMatchedRelayerRebuild");
  hex32(relay.proofReadyTxBytesHash, "withdraw.relay.proofReadyTxBytesHash");
  const payload = requiredObject(relay.payload, "withdraw.relay.payload");
  assertEqual(hex32(payload.preparedHash, "withdraw.relay.payload.preparedHash"), hex32(payload.submittedHash, "withdraw.relay.payload.submittedHash"), "withdraw relay payload hash changed before submission");
  const relayRecipient = requiredString(relay.recipient, "withdraw.relay.recipient");
  const preparedRecipient = requiredString(payload.recipient, "withdraw.relay.payload.recipient");
  const submittedRecipient = requiredString(payload.submittedRecipient, "withdraw.relay.payload.submittedRecipient");
  assertEqual(preparedRecipient, relayRecipient, "withdraw relay payload recipient differs from withdraw.relay.recipient");
  assertEqual(submittedRecipient, relayRecipient, "withdraw relay submitted recipient differs from withdraw.relay.recipient");
  assertEqual(requiredString(payload.chainId, "withdraw.relay.payload.chainId"), context.chainId, "withdraw relay chainId differs from chainId");
  assertEqual(requiredString(payload.submittedChainId, "withdraw.relay.payload.submittedChainId"), context.chainId, "withdraw relay submittedChainId differs from chainId");
  assertEqual(uint(payload.amount, "withdraw.relay.payload.amount"), relayAmount, "withdraw relay payload amount differs from relay amount");
  assertEqual(uint(payload.submittedAmount, "withdraw.relay.payload.submittedAmount"), relayAmount, "withdraw relay submitted amount differs from relay amount");
  assertEqual(uint(payload.expiresAtUnix, "withdraw.relay.payload.expiresAtUnix"), uint(payload.submittedExpiresAtUnix, "withdraw.relay.payload.submittedExpiresAtUnix"), "withdraw relay expiry changed before submission");

  const lifecycle = requiredObject(
    relay.reservationLifecycle,
    "withdraw.relay.reservationLifecycle"
  );
  requiredString(
    lifecycle.reservationId,
    "withdraw.relay.reservationLifecycle.reservationId"
  );
  const proofReadyTxBytesHash = hex32(
    relay.proofReadyTxBytesHash,
    "withdraw.relay.proofReadyTxBytesHash"
  );
  const preparedPayloadHash = hex32(
    payload.preparedHash,
    "withdraw.relay.payload.preparedHash"
  );
  const validateStage = (stageName, expectedStatus, { requireSubmittedTx = false } = {}) => {
    const stage = requiredObject(
      lifecycle[stageName],
      `withdraw.relay.reservationLifecycle.${stageName}`
    );
    assertEqual(
      requiredString(stage.status, `withdraw.relay.reservationLifecycle.${stageName}.status`),
      expectedStatus,
      `withdraw.relay.reservationLifecycle.${stageName}.status must be ${expectedStatus}`
    );
    literalTrue(
      stage.relayHandedOff,
      `withdraw.relay.reservationLifecycle.${stageName}.relayHandedOff`
    );
    assertEqual(
      hex32(stage.payloadHash, `withdraw.relay.reservationLifecycle.${stageName}.payloadHash`),
      preparedPayloadHash,
      `withdraw.relay.reservationLifecycle.${stageName}.payloadHash differs from the handed-off payload`
    );
    assertEqual(
      hex32(stage.txBytesHash, `withdraw.relay.reservationLifecycle.${stageName}.txBytesHash`),
      proofReadyTxBytesHash,
      `withdraw.relay.reservationLifecycle.${stageName}.txBytesHash differs from ProofReady`
    );
    if (requireSubmittedTx) {
      assertEqual(
        transactionHash(
          stage.submittedTxHash,
          `withdraw.relay.reservationLifecycle.${stageName}.submittedTxHash`
        ),
        relayTxHash,
        `withdraw.relay.reservationLifecycle.${stageName}.submittedTxHash differs from the relayer transaction`
      );
    }
  };
  validateStage("handoff", "ProofReady");
  validateStage("submitted", "Submitted", { requireSubmittedTx: true });
  validateStage("reconciled", "ConfirmedSpent", { requireSubmittedTx: true });
}

function validateRecovery(flow, transferTxHash) {
  requiredObject(flow, "recovery");
  const missing = requiredObject(flow.missingReceipt, "recovery.missingReceipt");
  transactionHash(missing.txHash, "recovery.missingReceipt.txHash");
  assertEqual(requiredString(missing.confirmation, "recovery.missingReceipt.confirmation"), "ambiguous", "recovery.missingReceipt.confirmation must be ambiguous");
  literalFalse(missing.markedSucceeded, "recovery.missingReceipt.markedSucceeded");
  assertEqual(requiredString(missing.operationStatus, "recovery.missingReceipt.operationStatus"), "Unknown", "recovery.missingReceipt.operationStatus must be Unknown");

  const mixed = requiredObject(flow.mixedState, "recovery.mixedState");
  assertEqual(requiredString(mixed.errorCode, "recovery.mixedState.errorCode"), "OPERATION_STATE_MIXED", "recovery.mixedState.errorCode must be OPERATION_STATE_MIXED");
  literalFalse(mixed.markedSucceeded, "recovery.mixedState.markedSucceeded");
  if (!Array.isArray(mixed.reservations) || mixed.reservations.length < 2) {
    fail("recovery.mixedState.reservations must contain at least two reservations");
  }
  const reservationIds = new Set();
  const reservationStatuses = new Set();
  mixed.reservations.forEach((reservation, index) => {
    requiredObject(reservation, `recovery.mixedState.reservations[${index}]`);
    reservationIds.add(requiredString(reservation.reservationId, `recovery.mixedState.reservations[${index}].reservationId`));
    reservationStatuses.add(requiredString(reservation.status, `recovery.mixedState.reservations[${index}].status`));
  });
  if (reservationIds.size !== mixed.reservations.length) fail("recovery.mixedState.reservations contains duplicate reservation IDs");
  if (reservationStatuses.size < 2) fail("recovery.mixedState.reservations must expose the mixed statuses");

  const conflict = requiredObject(flow.evidenceConflict, "recovery.evidenceConflict");
  assertEqual(requiredString(conflict.errorCode, "recovery.evidenceConflict.errorCode"), "OPERATION_EVIDENCE_CONFLICT", "recovery.evidenceConflict.errorCode must be OPERATION_EVIDENCE_CONFLICT");
  literalFalse(conflict.markedSucceeded, "recovery.evidenceConflict.markedSucceeded");
  literalTrue(conflict.priorSucceededPreserved, "recovery.evidenceConflict.priorSucceededPreserved");
  assertEqual(requiredString(conflict.operationStatus, "recovery.evidenceConflict.operationStatus"), "Succeeded", "recovery.evidenceConflict.operationStatus must preserve the prior Succeeded result");
  if (!Array.isArray(conflict.conflicts) || conflict.conflicts.length < 1) {
    fail("recovery.evidenceConflict.conflicts must identify at least one conflicting field");
  }
  conflict.conflicts.forEach((entry, index) => {
    requiredObject(entry, `recovery.evidenceConflict.conflicts[${index}]`);
    requiredString(entry.reservation_id, `recovery.evidenceConflict.conflicts[${index}].reservation_id`);
    const field = requiredString(entry.field, `recovery.evidenceConflict.conflicts[${index}].field`);
    if (!conflictFields.has(field)) fail(`recovery.evidenceConflict.conflicts[${index}].field is unsupported`);
    requiredString(entry.source_field, `recovery.evidenceConflict.conflicts[${index}].source_field`);
    requiredString(entry.reason, `recovery.evidenceConflict.conflicts[${index}].reason`);
    const expected = requiredString(entry.expected, `recovery.evidenceConflict.conflicts[${index}].expected`);
    const actual = requiredString(entry.actual, `recovery.evidenceConflict.conflicts[${index}].actual`);
    if (expected === actual) fail(`recovery.evidenceConflict.conflicts[${index}] does not contain a conflict`);
  });
  const reportedConflictFields = new Set(conflict.conflicts.map(entry => String(entry.field)));
  for (const field of ["tx_hash", "commitment", "digest", "amount"]) {
    if (!reportedConflictFields.has(field)) {
      fail(`recovery.evidenceConflict.conflicts must include ${field}`);
    }
  }

  const matched = requiredObject(flow.matchingEvidence, "recovery.matchingEvidence");
  assertEqual(transactionHash(matched.txHash, "recovery.matchingEvidence.txHash"), transferTxHash, "recovery.matchingEvidence.txHash differs from the transfer transaction");
  literalTrue(matched.markedSucceeded, "recovery.matchingEvidence.markedSucceeded");
  assertEqual(requiredString(matched.operationStatus, "recovery.matchingEvidence.operationStatus"), "Succeeded", "recovery.matchingEvidence.operationStatus must be Succeeded");
  assertEqual(requiredString(matched.reservationStatus, "recovery.matchingEvidence.reservationStatus"), "ConfirmedSpent", "recovery.matchingEvidence.reservationStatus must be ConfirmedSpent");
}

function validateSafety(flow, context, evidence) {
  requiredObject(flow, "safety");
  const scenarios = [
    ["expiredAtBlockTime", "expired-at-block-time", "transfer", context.actor, evidence.transfer.transaction, "expiry", "expiresAtUnix"],
    ["crossChainReplay", "cross-chain-replay", "transfer", context.actor, evidence.transfer.transaction, "chain", "chainId"],
    ["outputSubstitution", "output-substitution", "transfer", context.actor, evidence.transfer.transaction, "hex", "newCommitments[0]"],
    ["disclosureSubstitution", "disclosure-substitution", "transfer", context.actor, evidence.transfer.transaction, "hex", "auditDisclosureDigest"],
    ["duplicateNullifier", "duplicate-nullifier", "transfer", context.actor, evidence.transfer.transaction, "duplicateHex", "nullifiers[1]"],
    ["duplicateCommitment", "duplicate-commitment", "transfer", context.actor, evidence.transfer.transaction, "duplicateHex", "newCommitments[1]"],
    ["withdrawExpiredAtBlockTime", "withdraw-expired-at-block-time", "withdraw", context.actor, evidence.withdraw.direct.transaction, "expiry", "expiresAtUnix"],
    ["relayExpiryExtension", "relay-expiry-extension", "withdraw", context.relayer, evidence.withdraw.relay.transaction, "increasedUint", "expiresAtUnix"],
    ["relayRecipientReplacement", "relay-recipient-replacement", "withdraw", context.relayer, evidence.withdraw.relay.transaction, "recipient", "recipient"]
  ];
  const transactionHashes = new Set();
  for (const [field, scenario, operation, sender, referenceTransaction, mutationKind, mutationField] of scenarios) {
    const entry = requiredObject(flow[field], `safety.${field}`);
    assertEqual(requiredString(entry.scenario, `safety.${field}.scenario`), scenario, `safety.${field}.scenario must be ${scenario}`);
    assertEqual(requiredString(entry.rejectionLayer, `safety.${field}.rejectionLayer`), "chain", `safety.${field}.rejectionLayer must be chain`);
    literalTrue(entry.rejected, `safety.${field}.rejected`);
    literalTrue(entry.stateUnchanged, `safety.${field}.stateUnchanged`);
    requiredString(entry.failureReason, `safety.${field}.failureReason`);
    if (operation === "withdraw") {
      literalTrue(entry.sdkPreflightRejected, `safety.${field}.sdkPreflightRejected`);
      requiredString(
        entry.sdkPreflightFailureReason,
        `safety.${field}.sdkPreflightFailureReason`
      );
    }
    const txHash = revertedTransaction(entry.transaction, `safety.${field}.transaction`, {
      ...context,
      sender,
      expectedValue: 0n,
      expectedOperation: operation,
      expectedEvent: defaultEvmPrivacyActions[operation].event
    });
    if (transactionHashes.has(txHash)) fail(`safety.${field}.transaction reuses another rejection transaction`);
    transactionHashes.add(txHash);

    const before = state(entry.before, `safety.${field}.before`);
    const after = state(entry.after, `safety.${field}.after`);
    assertStateEqual(after, before, `safety.${field}`);
    literalTrue(entry.reserveInvariantHeldBefore, `safety.${field}.reserveInvariantHeldBefore`);
    literalTrue(entry.reserveInvariantHeldAfter, `safety.${field}.reserveInvariantHeldAfter`);
    assertReserveInvariant(before, entry.reserveInvariantHeldBefore, `safety.${field}.before`);
    assertReserveInvariant(after, entry.reserveInvariantHeldAfter, `safety.${field}.after`);

    const mutation = requiredObject(entry.mutation, `safety.${field}.mutation`);
    assertEqual(
      requiredString(mutation.field, `safety.${field}.mutation.field`),
      mutationField,
      `safety.${field}.mutation.field must be ${mutationField}`
    );
    const referenceData = calldata(
      referenceTransaction?.prepared?.data,
      `safety.${field}.referenceTransaction.prepared.data`
    );
    const attemptedData = calldata(
      entry.transaction.prepared.data,
      `safety.${field}.transaction.prepared.data`
    );
    assertEqual(
      calldata(mutation.referenceCalldata, `safety.${field}.mutation.referenceCalldata`),
      referenceData,
      `safety.${field}.mutation.referenceCalldata does not bind the successful reference call`
    );
    assertEqual(
      calldata(mutation.attemptedCalldata, `safety.${field}.mutation.attemptedCalldata`),
      attemptedData,
      `safety.${field}.mutation.attemptedCalldata does not bind the rejected call`
    );
    if (attemptedData === referenceData) {
      fail(`safety.${field}.transaction does not mutate the successful reference call`);
    }

    if (mutationKind === "expiry") {
      const proofBoundValue = uint(mutation.proofBoundValue, `safety.${field}.mutation.proofBoundValue`);
      const executionBlockTimeUnix = uint(
        mutation.executionBlockTimeUnix,
        `safety.${field}.mutation.executionBlockTimeUnix`
      );
      if (executionBlockTimeUnix < proofBoundValue) {
        fail(`safety.${field} was not submitted at or after its proof-bound expiry`);
      }
    } else if (mutationKind === "chain") {
      const proofBoundValue = requiredString(
        mutation.proofBoundValue,
        `safety.${field}.mutation.proofBoundValue`
      );
      const executionValue = requiredString(
        mutation.executionValue,
        `safety.${field}.mutation.executionValue`
      );
      assertEqual(executionValue, context.chainId, `safety.${field}.mutation.executionValue differs from chainId`);
      if (proofBoundValue === executionValue) fail(`safety.${field} does not bind a different proof chain`);
    } else if (mutationKind === "hex") {
      const original = hex32(mutation.original, `safety.${field}.mutation.original`);
      const attempted = hex32(mutation.attempted, `safety.${field}.mutation.attempted`);
      if (original === attempted) fail(`safety.${field}.mutation does not change ${mutationField}`);
    } else if (mutationKind === "duplicateHex") {
      const original = hex32(mutation.original, `safety.${field}.mutation.original`);
      const attempted = hex32(mutation.attempted, `safety.${field}.mutation.attempted`);
      const duplicateOf = hex32(mutation.duplicateOf, `safety.${field}.mutation.duplicateOf`);
      assertEqual(attempted, duplicateOf, `safety.${field}.mutation attempted value is not the declared duplicate`);
      if (original === attempted) fail(`safety.${field}.mutation did not replace a distinct original value`);
    } else if (mutationKind === "increasedUint") {
      const original = uint(mutation.original, `safety.${field}.mutation.original`);
      const attempted = uint(mutation.attempted, `safety.${field}.mutation.attempted`);
      if (attempted <= original) fail(`safety.${field}.mutation did not extend the expiry`);
    } else if (mutationKind === "recipient") {
      const original = requiredString(mutation.original, `safety.${field}.mutation.original`);
      const attempted = requiredString(mutation.attempted, `safety.${field}.mutation.attempted`);
      if (original === attempted) fail(`safety.${field}.mutation did not replace the recipient`);
      const evmOriginal = evmAddress(mutation.evmOriginal, `safety.${field}.mutation.evmOriginal`);
      const evmAttempted = evmAddress(mutation.evmAttempted, `safety.${field}.mutation.evmAttempted`);
      if (evmOriginal === evmAttempted) fail(`safety.${field}.mutation did not replace the EVM recipient`);
    }
  }
}

export function validateEvmIntegrationEvidence(evidence) {
  requiredObject(evidence, "driver evidence");
  assertEqual(requiredString(evidence.schemaVersion, "schemaVersion"), evmEvidenceSchema, `schemaVersion must be ${evmEvidenceSchema}`);
  assertEqual(requiredString(evidence.clairveilBundleVersion, "clairveilBundleVersion"), verifiedClairveilBundleVersion, `clairveilBundleVersion must be ${verifiedClairveilBundleVersion}`);
  assertEqual(requiredString(evidence.clairveilSourceKind, "clairveilSourceKind"), verifiedClairveilSourceKind, `clairveilSourceKind must be ${verifiedClairveilSourceKind}`);
  assertEqual(requiredString(evidence.clairveilCommit, "clairveilCommit"), verifiedClairveilCommit, `clairveilCommit must be ${verifiedClairveilCommit}`);
  assertEqual(requiredString(evidence.sdkVersion, "sdkVersion"), verifiedSdkVersion, `sdkVersion must be ${verifiedSdkVersion}`);

  const context = {
    chainId: requiredString(evidence.chainId, "chainId"),
    evmChainId: quantity(evidence.evmChainId, "evmChainId"),
    denom: requiredString(evidence.denom, "denom"),
    nativeDenom: requiredString(evidence.nativeDenom, "nativeDenom"),
    shieldedPrefix: requiredString(evidence.shieldedPrefix, "shieldedPrefix"),
    precompileAddress: evmAddress(evidence.precompileAddress, "precompileAddress"),
    actor: evmAddress(evidence.actor, "actor"),
    relayer: evmAddress(evidence.relayer, "relayer"),
    rollbackActor: evmAddress(evidence.rollbackActor, "rollbackActor"),
    fixedEscrowFunder: evmAddress(evidence.fixedEscrowFunder, "fixedEscrowFunder")
  };
  assertEqual(context.nativeDenom, context.denom, "nativeDenom must equal denom");
  if (context.actor === context.relayer) fail("actor and relayer must differ");
  if (context.rollbackActor === context.actor || context.rollbackActor === context.relayer) {
    fail("rollbackActor must differ from actor and relayer");
  }
  assertEqual(context.fixedEscrowFunder, context.precompileAddress, "fixedEscrowFunder must equal precompileAddress");

  validateDepositFlow(evidence.deposit, context);
  const transferTxHash = validateTransfer(evidence.transfer, context);
  validateBatch(evidence.batch, context);
  validateBatchShapeMatrix(evidence.batchShapeMatrix, context);
  validateWithdraw(evidence.withdraw, context);
  validateSafety(evidence.safety, context, evidence);
  validateRecovery(evidence.recovery, transferTxHash);
  return evidence;
}

export async function runEvmIntegrationVerification({
  driverPath = process.env.CLAIRVEIL_EVM_E2E_DRIVER,
  required = process.env.CLAIRVEIL_EVM_E2E_REQUIRED === "1"
} = {}) {
  const configuredDriverPath = String(driverPath ?? "").trim();
  if (!configuredDriverPath) {
    if (required) fail("CLAIRVEIL_EVM_E2E_DRIVER is required");
    return { status: "skipped", reason: "CLAIRVEIL_EVM_E2E_DRIVER is not configured" };
  }

  verifyVendoredClairveilContractSnapshot({ packageRoot: sdkRoot });
  const resolvedDriver = resolve(configuredDriverPath);
  const driver = await import(pathToFileURL(resolvedDriver).href);
  if (typeof driver.runClairveilEvmE2E !== "function") {
    fail("driver must export runClairveilEvmE2E(context)");
  }
  const evidence = await driver.runClairveilEvmE2E(Object.freeze({
    evidenceSchema: evmEvidenceSchema,
    oneProofBatchMatrixSchema: evmOneProofBatchMatrixSchema,
    oneProofBatchReleaseShapes: evmOneProofBatchReleaseShapes,
    clairveilBundleVersion: verifiedClairveilBundleVersion,
    clairveilSourceKind: verifiedClairveilSourceKind,
    clairveilCommit: verifiedClairveilCommit,
    sdkVersion: verifiedSdkVersion,
    createPostCoreRollbackHarness: createEvmPostCoreRollbackHarness,
    sdkRoot
  }));
  validateEvmIntegrationEvidence(evidence);
  return { status: "passed", evidence };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runEvmIntegrationVerification()
    .then(result => {
      if (result.status === "skipped") {
        console.log(`SKIP EVM integration: ${result.reason}`);
      } else {
        console.log("PASS EVM full-flow integration evidence");
      }
    })
    .catch(error => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    });
}
