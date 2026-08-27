import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { CURVE_BASE, encodeShieldedAddress } from "clairveiljs/core";
import { hashAmount, hashRecipient } from "clairveiljs/reservation";
import {
  createEvmPostCoreRollbackHarness,
  defaultEvmPrivacyActions,
  evmEvidenceSchema,
  evmOneProofBatchMatrixSchema,
  evmOneProofBatchReleaseShapes,
  runEvmIntegrationVerification,
  validateEvmIntegrationEvidence,
  verifiedClairveilCommit,
  verifiedClairveilRelease,
  verifiedSdkVersion
} from "../tools/verify-evm-integration.js";

const precompileAddress = "0x0000000000000000000000000000000000000900";
const actor = "0x1111111111111111111111111111111111111111";
const relayer = "0x2222222222222222222222222222222222222222";
const rollbackActor = "0x3333333333333333333333333333333333333333";
const fixedEscrowFunder = precompileAddress;
const recipient = encodeShieldedAddress(CURVE_BASE, CURVE_BASE, {
  shieldedPrefix: "demos"
});

function digest(byte) {
  return byte.repeat(64 / byte.length);
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function snapshot({
  fixedEscrowBalance = "100",
  privacyModuleBalance = "60",
  totalDeposited = "80",
  totalWithdrawn = "20",
  leafCount = "7",
  privacyScanHeight = "10",
  privacyScanGlobalSequence = "3",
  privacyScanOutputIndex = "0",
  privacyScanSummaryCount = "7",
  privacyScanOutputCount = "7"
} = {}) {
  return {
    fixedEscrowBalance,
    privacyModuleBalance,
    totalDeposited,
    totalWithdrawn,
    leafCount,
    privacyScanHeight,
    privacyScanGlobalSequence,
    privacyScanOutputIndex,
    privacyScanSummaryCount,
    privacyScanOutputCount
  };
}

function transaction(seed, {
  sender = actor,
  to = precompileAddress,
  value = "0x0",
  status = "0x1",
  operation = "transfer"
} = {}) {
  const action = defaultEvmPrivacyActions[operation];
  if (!action) throw new Error(`unsupported test operation ${operation}`);
  const data = `0x${action.selector}${seed.repeat(4)}`;
  const hash = `0x${seed.repeat(32)}`;
  return {
    prepared: {
      to,
      sender,
      operation,
      data,
      value,
      chainId: "0x539"
    },
    observed: {
      hash,
      from: sender,
      to,
      input: data,
      value,
      chainId: "0x539"
    },
    receipt: {
      transactionHash: hash,
      status,
      privacyEventVerified: status === "0x1",
      ...(status === "0x1" ? {
        blockNumber: "0xa",
        blockHash: `0x${sha256Hex(`block:${hash}`)}`,
        privacyOperation: operation,
        privacyEvent: action.event
      } : {})
    },
    ...(status === "0x1" ? {
      finality: {
        verified: true,
        mode: "confirmations",
        txHash: hash,
        blockNumber: "0xa",
        blockHash: `0x${sha256Hex(`block:${hash}`)}`,
        finalityBlockNumber: "0xb",
        confirmations: 2
      }
    } : {})
  };
}

function spentNullifier(byte) {
  return { nullifier: digest(byte), spent: true };
}

function matrixDigest(value) {
  return sha256Hex(`evm-one-proof-matrix:${value}`);
}

function validBatchShapeMatrix() {
  let outputSeed = 160;
  return {
    schemaVersion: evmOneProofBatchMatrixSchema,
    shapes: evmOneProofBatchReleaseShapes.map((expected, shapeIndex) => {
      const shapeTransaction = transaction((144 + shapeIndex).toString(16), {
        operation: "singleProofBatchTransfer"
      });
      const scanTxHash = `0x${digest((224 + shapeIndex).toString(16))}`;
      return {
        id: expected.id,
        executionMode: "direct",
        transaction: shapeTransaction,
        proofCount: 1,
        transactionCount: 1,
        inputCount: expected.inputCount,
        paymentCount: expected.paymentCount,
        outputCount: expected.outputCount,
        changeCount: expected.changeCount,
        paddingCount: expected.paddingCount,
        outputMode: expected.outputMode,
        selfViewEnabled: expected.selfViewEnabled,
        inputAmounts: [...expected.inputAmounts],
        paymentAmounts: [...expected.paymentAmounts],
        disclosureModes: [...expected.disclosureModes],
        inputNullifiers: Array.from({ length: expected.inputCount }, () => {
          const value = outputSeed++;
          return { nullifier: matrixDigest(value), spent: true };
        }),
        atomic: true,
        operationEvidenceMatched: true,
        reservationsSucceeded: true,
        scanTransactionLink: {
          scanTxHash,
          evmTxHash: shapeTransaction.observed.hash,
          cometHeight: String(30 + shapeIndex),
          cosmosTxSucceeded: true,
          ethereumTxHashEventMatched: true
        },
        outputs: Array.from({ length: expected.outputCount }, (_unused, outputIndex) => {
          const role = expected.outputRoles[outputIndex];
          const value = outputSeed++;
          return {
            index: outputIndex,
            role,
            amount: expected.outputAmounts[outputIndex],
            userDisclosureMode: ({
              none: 0,
              public: 1,
              "recipient-encrypted": 2
            })[expected.disclosureModes[outputIndex]],
            outputCommitment: matrixDigest(value),
            typedScanTxHash: scanTxHash,
            typedScanMatched: true,
            auditVerified: true,
            selfViewVerified: expected.selfViewEnabled,
            recovered: role !== "padding",
            spendable: role !== "padding"
          };
        })
      };
    })
  };
}

function validEvidence() {
  const transferCommitment = digest("66");
  const transferDigest = digest("77");
  const batchCommitment = digest("88");
  const batchUserDigest = digest("87");
  const batchAuditDigest = digest("89");
  const batchEncryptedCommitment = digest("8a");
  const batchEncryptedUserDigest = digest("8b");
  const batchEncryptedAuditDigest = digest("8c");
  const batchChangeCommitment = digest("8d");
  const batchChangeAuditDigest = digest("8e");
  const batchScanTxHash = `0x${digest("56")}`;
  const batchOperationEvidence = {
    version: "batch-transfer-operation-evidence-v1",
    operation_id: "batch-operation-1",
    circuit_set_id: "privacy-note-v1",
    payload_hash: digest("81"),
    proof_payload_hash: digest("81"),
    proof_hash: digest("82"),
    input_nullifier_hexes: [digest("50")],
    expected_outputs: [{
      operation_id: "batch-operation-1",
      item_id: "batch-payment-0",
      batch_item_index: 0,
      role: "payment",
      expected_output_commitment: batchCommitment,
      expected_user_disclosure_digest: batchUserDigest,
      expected_audit_disclosure_digest: batchAuditDigest,
      expected_self_view_disclosure_digest: batchAuditDigest,
      expected_recipient_hash: hashRecipient(recipient, { shieldedPrefix: "demos" }),
      expected_amount: "2",
      expected_amount_hash: hashAmount("udemo", "2"),
      expected_denom: "udemo",
      asset_id_hex: digest("83"),
      user_privacy_policy: 7,
      user_disclosure_mode: 1,
      audit_key_id: "master",
      audit_key_epoch: "1"
    }, {
      operation_id: "batch-operation-1",
      item_id: "batch-payment-1",
      batch_item_index: 1,
      role: "payment",
      expected_output_commitment: batchEncryptedCommitment,
      expected_user_disclosure_digest: batchEncryptedUserDigest,
      expected_audit_disclosure_digest: batchEncryptedAuditDigest,
      expected_self_view_disclosure_digest: batchEncryptedAuditDigest,
      expected_recipient_hash: hashRecipient(recipient, { shieldedPrefix: "demos" }),
      expected_amount: "1",
      expected_amount_hash: hashAmount("udemo", "1"),
      expected_denom: "udemo",
      asset_id_hex: digest("84"),
      user_privacy_policy: 7,
      user_disclosure_mode: 2,
      audit_key_id: "master",
      audit_key_epoch: "1"
    }]
  };
  const transferTx = transaction("44", { sender: relayer });
  const authorizedBatchTx = transaction("55", {
    sender: relayer,
    operation: "singleProofBatchTransferWithAuthorization"
  });
  const replayBatchTx = transaction("57", {
    sender: relayer,
    status: "0x0",
    operation: "singleProofBatchTransferWithAuthorization"
  });
  replayBatchTx.prepared.data = authorizedBatchTx.prepared.data;
  replayBatchTx.observed.input = authorizedBatchTx.observed.input;
  const directWithdrawTx = transaction("66", { operation: "withdraw" });
  const relayWithdrawTx = transaction("77", { sender: relayer, operation: "withdraw" });
  const rollbackHarnessAddress = "0x4444444444444444444444444444444444444444";
  const rollbackHarness = createEvmPostCoreRollbackHarness(precompileAddress);
  const rejected = (
    seed,
    scenario,
    operation = "transfer",
    sender = actor,
    mutation = {},
    referenceTransaction = transferTx
  ) => {
    const rejectedTransaction = transaction(seed, { sender, status: "0x0", operation });
    return {
      scenario,
      rejectionLayer: "chain",
      rejected: true,
      stateUnchanged: true,
      failureReason: `${scenario} rejected by downstream execution`,
      ...(operation === "withdraw" ? {
        sdkPreflightRejected: true,
        sdkPreflightFailureReason: `${scenario} rejected before the wallet boundary`
      } : {}),
      before: snapshot(),
      after: snapshot(),
      reserveInvariantHeldBefore: true,
      reserveInvariantHeldAfter: true,
      mutation: {
        ...mutation,
        referenceCalldata: referenceTransaction.prepared.data,
        attemptedCalldata: rejectedTransaction.prepared.data
      },
      transaction: rejectedTransaction
    };
  };
  return {
    schemaVersion: evmEvidenceSchema,
    clairveilRelease: verifiedClairveilRelease,
    clairveilCommit: verifiedClairveilCommit,
    sdkVersion: verifiedSdkVersion,
    chainId: "downstream-1",
    evmChainId: "0x539",
    denom: "udemo",
    nativeDenom: "udemo",
    shieldedPrefix: "demos",
    precompileAddress,
    actor,
    relayer,
    rollbackActor,
    fixedEscrowFunder,
    deposit: {
      success: {
        amount: "5",
        commitment: digest("10"),
        receiptCommitment: digest("10"),
        typedScanCommitment: digest("10"),
        scanTransactionLink: {
          scanTxHash: `0x${digest("12")}`,
          evmTxHash: `0x${digest("11")}`,
          cometHeight: "11",
          cosmosTxSucceeded: true,
          ethereumTxHashEventMatched: true
        },
        eventEffectiveSender: actor,
        eventOperator: actor,
        transaction: transaction("11", { value: "0x5", operation: "deposit" }),
        before: snapshot(),
        after: snapshot({
          fixedEscrowBalance: "100",
          privacyModuleBalance: "65",
          totalDeposited: "85",
          leafCount: "8",
          privacyScanGlobalSequence: "4",
          privacyScanSummaryCount: "8",
          privacyScanOutputCount: "8"
        }),
        reserveInvariantHolds: true
      },
      rollback: {
        amount: "5",
        failureKind: "downstream-policy-after-execution",
        failureStage: "post-core",
        failureReason: "downstream post-call policy rejected the successful privacy execution",
        transaction: transaction("22", {
          sender: rollbackActor,
          to: rollbackHarnessAddress,
          value: "0x5",
          status: "0x0",
          operation: "deposit"
        }),
        postCoreProof: {
          harnessAddress: rollbackHarnessAddress,
          runtimeCode: rollbackHarness.runtimeCode,
          successMarker: rollbackHarness.successMarker,
          simulationRevertData: rollbackHarness.successMarker,
          innerCallSucceeded: true,
          innerTarget: precompileAddress,
          innerCalldata: `0x${defaultEvmPrivacyActions.deposit.selector}${"22".repeat(4)}`,
          innerValue: "0x5",
          deploymentTransactionHash: `0x${"20".repeat(32)}`,
          attestationTransactionHash: `0x${"21".repeat(32)}`
        },
        before: snapshot(),
        after: snapshot(),
        reserveInvariantHolds: true
      },
      zeroValue: {
        amount: "0",
        commitment: digest("30"),
        receiptCommitment: digest("30"),
        typedScanCommitment: digest("30"),
        scanTransactionLink: {
          scanTxHash: `0x${digest("34")}`,
          evmTxHash: `0x${digest("33")}`,
          cometHeight: "12",
          cosmosTxSucceeded: true,
          ethereumTxHashEventMatched: true
        },
        eventEffectiveSender: actor,
        eventOperator: actor,
        transaction: transaction("33", { operation: "deposit" }),
        before: snapshot(),
        after: snapshot({
          leafCount: "8",
          privacyScanGlobalSequence: "4",
          privacyScanSummaryCount: "8",
          privacyScanOutputCount: "8"
        }),
        reserveInvariantHolds: true
      },
      recoveredNote: {
        scanSource: "privacy_scan",
        commitment: digest("10"),
        amount: "5",
        denom: "udemo",
        spendable: true
      }
    },
    transfer: {
      sdkMethod: "prepareTransfer",
      amount: "5",
      denom: "udemo",
      recipient,
      transaction: transferTx,
      creatorReplacement: {
        preparedBy: actor,
        submittedBy: relayer,
        calldataUnchanged: true,
        proofUnchanged: true,
        effectsMatched: true
      },
      inputCount: 1,
      inputNullifiers: [spentNullifier("40")],
      observedOutput: {
        outputCommitment: transferCommitment,
        auditDisclosureDigest: transferDigest,
        recipientHash: hashRecipient(recipient, { shieldedPrefix: "demos" }),
        amount: "5",
        amountHash: hashAmount("udemo", "5"),
        denom: "udemo"
      },
      recoveredOutput: {
        commitment: transferCommitment,
        amount: "5",
        denom: "udemo",
        spendable: true
      },
      disclosure: {
        verified: true,
        typedScanOutput: true,
        scanTransactionLink: {
          scanTxHash: `0x${digest("45")}`,
          evmTxHash: transferTx.observed.hash,
          cometHeight: "17",
          cosmosTxSucceeded: true,
          ethereumTxHashEventMatched: true
        },
        outputCommitment: transferCommitment,
        digest: transferDigest,
        preparedDigest: transferDigest
      },
      auditDisclosure: {
        verified: true,
        typedScanOutput: true,
        scanTransactionLink: {
          scanTxHash: `0x${digest("45")}`,
          evmTxHash: transferTx.observed.hash,
          cometHeight: "17",
          cosmosTxSucceeded: true,
          ethereumTxHashEventMatched: true
        },
        outputCommitment: transferCommitment,
        preparedDigest: transferDigest,
        typedScanDigest: transferDigest,
        decodedDigest: transferDigest
      },
      selfViewDisclosure: {
        verified: true,
        typedScanOutput: true,
        scanTransactionLink: {
          scanTxHash: `0x${digest("45")}`,
          evmTxHash: transferTx.observed.hash,
          cometHeight: "17",
          cosmosTxSucceeded: true,
          ethereumTxHashEventMatched: true
        },
        outputCommitment: transferCommitment,
        preparedDigest: transferDigest,
        typedScanDigest: transferDigest,
        decodedDigest: transferDigest
      },
      operationEvidenceMatched: true
    },
    batch: {
      sdkMethod: "prepareTransferBatch",
      transaction: authorizedBatchTx,
      authorization: {
        kind: 17,
        effectiveSender: actor,
        executor: relayer,
        profileSupportedKinds: [17],
        signatureVerified: true,
        nonceConsumed: true,
        replayRejected: true,
        replayFailureReason: "authorization nonce already used",
        replayTransaction: replayBatchTx
      },
      proofCount: 1,
      transactionCount: 1,
      inputCount: 1,
      outputCount: 3,
      inputNullifiers: [spentNullifier("50")],
      atomic: true,
      operationEvidenceMatched: true,
      operationEvidence: batchOperationEvidence,
      operationEvidenceHash: sha256Hex(JSON.stringify(batchOperationEvidence)),
      auditKeyId: "master",
      auditKeyEpoch: "1",
      selfViewEnabled: true,
      scanTransactionLink: {
        scanTxHash: batchScanTxHash,
        evmTxHash: authorizedBatchTx.observed.hash,
        cometHeight: "21",
        cosmosTxSucceeded: true,
        ethereumTxHashEventMatched: true
      },
      requestedPayments: [{
        itemId: "batch-payment-0",
        recipient,
        amount: "2",
        denom: "udemo",
        userPrivacyPolicy: 7,
        userDisclosureMode: 1
      }, {
        itemId: "batch-payment-1",
        recipient,
        amount: "1",
        denom: "udemo",
        userPrivacyPolicy: 7,
        userDisclosureMode: 2
      }],
      payments: [{
        index: 0,
        itemId: "batch-payment-0",
        recipient,
        amount: "2",
        denom: "udemo",
        outputCommitment: batchCommitment,
        recipientHash: hashRecipient(recipient, { shieldedPrefix: "demos" }),
        amountHash: hashAmount("udemo", "2"),
        userPrivacyPolicy: 7,
        userDisclosureMode: 1,
        userDisclosureDigest: batchUserDigest,
        auditDisclosureDigest: batchAuditDigest,
        selfViewDisclosureDigest: batchAuditDigest,
        userDisclosureVerified: true,
        typedScanTxHash: batchScanTxHash,
        typedScanMatched: true,
        recovered: true
      }, {
        index: 1,
        itemId: "batch-payment-1",
        recipient,
        amount: "1",
        denom: "udemo",
        outputCommitment: batchEncryptedCommitment,
        recipientHash: hashRecipient(recipient, { shieldedPrefix: "demos" }),
        amountHash: hashAmount("udemo", "1"),
        userPrivacyPolicy: 7,
        userDisclosureMode: 2,
        userDisclosureDigest: batchEncryptedUserDigest,
        auditDisclosureDigest: batchEncryptedAuditDigest,
        selfViewDisclosureDigest: batchEncryptedAuditDigest,
        userDisclosureVerified: true,
        typedScanTxHash: batchScanTxHash,
        typedScanMatched: true,
        recovered: true
      }],
      outputs: [{
        index: 0,
        role: "payment",
        amount: "2",
        denom: "udemo",
        outputCommitment: batchCommitment,
        userPrivacyPolicy: 7,
        userDisclosureMode: 1,
        userDisclosureDigest: batchUserDigest,
        auditDisclosureDigest: batchAuditDigest,
        selfViewDisclosureDigest: batchAuditDigest,
        auditKeyId: "master",
        auditKeyEpoch: "1",
        typedScanTxHash: batchScanTxHash,
        typedScanMatched: true,
        userDisclosureVerified: true,
        auditVerified: true,
        selfViewVerified: true,
        recovered: true,
        spendable: true
      }, {
        index: 1,
        role: "payment",
        amount: "1",
        denom: "udemo",
        outputCommitment: batchEncryptedCommitment,
        userPrivacyPolicy: 7,
        userDisclosureMode: 2,
        userDisclosureDigest: batchEncryptedUserDigest,
        auditDisclosureDigest: batchEncryptedAuditDigest,
        selfViewDisclosureDigest: batchEncryptedAuditDigest,
        auditKeyId: "master",
        auditKeyEpoch: "1",
        typedScanTxHash: batchScanTxHash,
        typedScanMatched: true,
        userDisclosureVerified: true,
        auditVerified: true,
        selfViewVerified: true,
        recovered: true,
        spendable: true
      }, {
        index: 2,
        role: "change",
        amount: "3",
        denom: "udemo",
        outputCommitment: batchChangeCommitment,
        userPrivacyPolicy: 0,
        userDisclosureMode: 0,
        userDisclosureDigest: "",
        auditDisclosureDigest: batchChangeAuditDigest,
        selfViewDisclosureDigest: batchChangeAuditDigest,
        auditKeyId: "master",
        auditKeyEpoch: "1",
        typedScanTxHash: batchScanTxHash,
        typedScanMatched: true,
        userDisclosureVerified: false,
        auditVerified: true,
        selfViewVerified: true,
        recovered: true,
        spendable: true
      }]
    },
    batchShapeMatrix: validBatchShapeMatrix(),
    withdraw: {
      direct: {
        sdkMethod: "prepareWithdraw",
        amount: "3",
        denom: "udemo",
        recipient: "demo1recipient",
        transaction: directWithdrawTx,
        inputCount: 1,
        inputNullifiers: [spentNullifier("60")],
        legacyOutputFieldsAbsent: true,
        recipientBalanceBefore: "10",
        recipientBalanceAfter: "13",
        privacyModuleBalanceBefore: "60",
        privacyModuleBalanceAfter: "57",
        totalDepositedBefore: "80",
        totalDepositedAfter: "80",
        totalWithdrawnBefore: "20",
        totalWithdrawnAfter: "23",
        reserveInvariantHolds: true
      },
      relay: {
        sdkMethod: "prepareRelayWithdraw",
        amount: "4",
        denom: "udemo",
        recipient: "demo1recipient",
        transaction: relayWithdrawTx,
        inputCount: 1,
        inputNullifiers: [spentNullifier("70")],
        legacyOutputFieldsAbsent: true,
        recipientBalanceBefore: "13",
        recipientBalanceAfter: "17",
        privacyModuleBalanceBefore: "57",
        privacyModuleBalanceAfter: "53",
        totalDepositedBefore: "80",
        totalDepositedAfter: "80",
        totalWithdrawnBefore: "23",
        totalWithdrawnAfter: "27",
        reserveInvariantHolds: true,
        owner: actor,
        relayer,
        candidateMatchedRelayerRebuild: true,
        proofReadyTxBytesHash: digest("91"),
        reservationLifecycle: {
          reservationId: "relay-reservation-1",
          handoff: {
            status: "ProofReady",
            relayHandedOff: true,
            payloadHash: digest("90"),
            txBytesHash: digest("91")
          },
          submitted: {
            status: "Submitted",
            relayHandedOff: true,
            payloadHash: digest("90"),
            txBytesHash: digest("91"),
            submittedTxHash: relayWithdrawTx.observed.hash
          },
          reconciled: {
            status: "ConfirmedSpent",
            relayHandedOff: true,
            payloadHash: digest("90"),
            txBytesHash: digest("91"),
            submittedTxHash: relayWithdrawTx.observed.hash
          }
        },
        payload: {
          preparedHash: digest("90"),
          submittedHash: digest("90"),
          recipient: "demo1recipient",
          submittedRecipient: "demo1recipient",
          chainId: "downstream-1",
          submittedChainId: "downstream-1",
          amount: "4",
          submittedAmount: "4",
          expiresAtUnix: "4102448400",
          submittedExpiresAtUnix: "4102448400"
        }
      }
    },
    safety: {
      expiredAtBlockTime: rejected("a1", "expired-at-block-time", "transfer", actor, {
        field: "expiresAtUnix",
        proofBoundValue: "100",
        executionBlockTimeUnix: "100"
      }),
      crossChainReplay: rejected("a2", "cross-chain-replay", "transfer", actor, {
        field: "chainId",
        proofBoundValue: "other-chain",
        executionValue: "downstream-1"
      }),
      outputSubstitution: rejected("a3", "output-substitution", "transfer", actor, {
        field: "newCommitments[0]",
        original: digest("01"),
        attempted: digest("02")
      }),
      disclosureSubstitution: rejected("a4", "disclosure-substitution", "transfer", actor, {
        field: "auditDisclosureDigest",
        original: digest("03"),
        attempted: digest("04")
      }),
      duplicateNullifier: rejected("a5", "duplicate-nullifier", "transfer", actor, {
        field: "nullifiers[1]",
        original: digest("05"),
        attempted: digest("06"),
        duplicateOf: digest("06")
      }),
      duplicateCommitment: rejected("a6", "duplicate-commitment", "transfer", actor, {
        field: "newCommitments[1]",
        original: digest("07"),
        attempted: digest("08"),
        duplicateOf: digest("08")
      }),
      withdrawExpiredAtBlockTime: rejected(
        "a9",
        "withdraw-expired-at-block-time",
        "withdraw",
        actor,
        {
          field: "expiresAtUnix",
          proofBoundValue: "200",
          executionBlockTimeUnix: "200"
        },
        directWithdrawTx
      ),
      relayExpiryExtension: rejected(
        "a7",
        "relay-expiry-extension",
        "withdraw",
        relayer,
        {
          field: "expiresAtUnix",
          original: "300",
          attempted: "301"
        },
        relayWithdrawTx
      ),
      relayRecipientReplacement: rejected(
        "a8",
        "relay-recipient-replacement",
        "withdraw",
        relayer,
        {
          field: "recipient",
          original: "demo1recipient",
          attempted: "demo1actor",
          evmOriginal: "0x4444444444444444444444444444444444444444",
          evmAttempted: actor
        },
        relayWithdrawTx
      )
    },
    recovery: {
      missingReceipt: {
        txHash: `0x${digest("aa")}`,
        confirmation: "ambiguous",
        markedSucceeded: false,
        operationStatus: "Unknown"
      },
      mixedState: {
        errorCode: "OPERATION_STATE_MIXED",
        markedSucceeded: false,
        reservations: [
          { reservationId: "reservation-a", status: "Submitted" },
          { reservationId: "reservation-b", status: "ConfirmedSpent" }
        ]
      },
      evidenceConflict: {
        errorCode: "OPERATION_EVIDENCE_CONFLICT",
        markedSucceeded: false,
        priorSucceededPreserved: true,
        operationStatus: "Succeeded",
        conflicts: [
          {
            reservation_id: "reservation-a",
            field: "tx_hash",
            source_field: "tx_hash",
            reason: "mismatch",
            expected: digest("01"),
            actual: digest("02")
          },
          {
            reservation_id: "reservation-a",
            field: "commitment",
            source_field: "expected_output_commitment",
            reason: "mismatch",
            expected: digest("03"),
            actual: digest("04")
          },
          {
            reservation_id: "reservation-a",
            field: "digest",
            source_field: "expected_disclosure_digest",
            reason: "mismatch",
            expected: digest("05"),
            actual: digest("06")
          },
          {
            reservation_id: "reservation-a",
            field: "amount",
            source_field: "expected_amount",
            reason: "mismatch",
            expected: "5",
            actual: "6"
          }
        ]
      },
      matchingEvidence: {
        txHash: transferTx.observed.hash,
        markedSucceeded: true,
        operationStatus: "Succeeded",
        reservationStatus: "ConfirmedSpent"
      }
    }
  };
}

test("EVM integration evidence validates every v0.3.1 privacy rail", () => {
  const evidence = validEvidence();
  assert.equal(validateEvmIntegrationEvidence(evidence), evidence);
});

test("EVM integration evidence rejects missing or contradictory full-flow semantics", () => {
  const cases = [
    ["native denom binding", evidence => {
      evidence.nativeDenom = "uother";
    }, /nativeDenom must equal denom/],
    ["transaction identity", evidence => {
      evidence.transfer.transaction.observed.input = "0x9999";
    }, /observed.input differs/],
    ["prepared action selector", evidence => {
      const replacement = transaction("55", { operation: "transfer" });
      evidence.batch.transaction.prepared.data = replacement.prepared.data;
      evidence.batch.transaction.observed.input = replacement.observed.input;
    }, /selector must match the default adapter singleProofBatchTransfer/],
    ["prepared action name", evidence => {
      evidence.batch.transaction.prepared.operation = "transfer";
    }, /prepared\.operation must be singleProofBatchTransfer/],
    ["receipt action event", evidence => {
      evidence.batch.transaction.receipt.privacyEvent = "PrivacyTransfer";
    }, /receipt\.privacyEvent must be PrivacySingleProofBatchTransfer/],
    ["successful transaction finality", evidence => {
      evidence.transfer.transaction.finality.verified = false;
    }, /finality\.verified must be true/],
    ["receipt/finality block number binding", evidence => {
      evidence.transfer.transaction.finality.blockNumber = "0x9";
    }, /finality\.blockNumber differs from receipt\.blockNumber/],
    ["receipt/finality block hash binding", evidence => {
      evidence.transfer.transaction.finality.blockHash = `0x${digest("ff")}`;
    }, /finality\.blockHash differs from receipt\.blockHash/],
    ["receipt-only release finality", evidence => {
      evidence.transfer.transaction.finality.mode = "receipt";
    }, /must revalidate canonical inclusion/],
    ["single-confirmation release finality", evidence => {
      evidence.transfer.transaction.finality.confirmations = 1;
    }, /finality\.confirmations must be an integer in 2/],
    ["insufficient confirmation depth", evidence => {
      evidence.transfer.transaction.finality.confirmations = 3;
      evidence.transfer.transaction.finality.finalityBlockNumber = "0xb";
    }, /does not reach the required confirmation depth/],
    ["deposit rollback", evidence => {
      evidence.deposit.rollback.after.leafCount = "8";
    }, /deposit.rollback.leafCount changed/],
    ["deposit rollback typed scan state", evidence => {
      evidence.deposit.rollback.after.privacyScanSummaryCount = "8";
    }, /deposit.rollback.privacyScanSummaryCount changed/],
    ["deposit rollback must be post-core", evidence => {
      evidence.deposit.rollback.failureStage = "pre-core";
    }, /failureStage must be post-core/],
    ["deposit rollback inner success marker", evidence => {
      evidence.deposit.rollback.postCoreProof.simulationRevertData = `0x${"f1".repeat(32)}`;
    }, /does not prove inner-call success/],
    ["deposit rollback canonical harness", evidence => {
      evidence.deposit.rollback.postCoreProof.runtimeCode += "00";
    }, /is not the canonical post-core rollback harness/],
    ["deposit rollback outer target", evidence => {
      evidence.deposit.rollback.transaction.prepared.to = precompileAddress;
      evidence.deposit.rollback.transaction.observed.to = precompileAddress;
    }, /prepared.to does not match the expected target/],
    ["deposit typed scan output", evidence => {
      evidence.deposit.success.after.privacyScanOutputCount = "7";
    }, /privacyScanOutputCount delta does not equal one/],
    ["deposit recovery", evidence => {
      evidence.deposit.recoveredNote.commitment = digest("ff");
    }, /recovered commitment differs/],
    ["deposit receipt commitment binding", evidence => {
      evidence.deposit.success.commitment = digest("fe");
      evidence.deposit.recoveredNote.commitment = digest("fe");
    }, /receiptCommitment differs from the prepared deposit commitment/],
    ["deposit typed scan commitment binding", evidence => {
      evidence.deposit.success.typedScanCommitment = digest("fd");
    }, /typedScanCommitment differs from the receipt deposit commitment/],
    ["deposit typed scan transaction link", evidence => {
      evidence.deposit.success.scanTransactionLink.evmTxHash = `0x${digest("fc")}`;
    }, /evmTxHash differs from the submitted EVM transaction/],
    ["transfer nullifier", evidence => {
      evidence.transfer.inputNullifiers[0].spent = false;
    }, /inputNullifiers\[0\]\.spent must be true/],
    ["transfer operation evidence", evidence => {
      evidence.transfer.observedOutput.amountHash = digest("ff");
    }, /amountHash differs/],
    ["creator replacement", evidence => {
      evidence.transfer.creatorReplacement.calldataUnchanged = false;
    }, /creatorReplacement\.calldataUnchanged must be true/],
    ["transfer disclosure", evidence => {
      evidence.transfer.disclosure.digest = "ff";
    }, /must be exactly 32 bytes/],
    ["transfer typed audit digest", evidence => {
      evidence.transfer.auditDisclosure.typedScanDigest = digest("ff");
    }, /typed scan audit digest differs/],
    ["transfer decoded audit digest", evidence => {
      evidence.transfer.auditDisclosure.decodedDigest = digest("ff");
    }, /decoded audit digest differs/],
    ["transfer decoded self-view digest", evidence => {
      evidence.transfer.selfViewDisclosure.decodedDigest = digest("ff");
    }, /decoded self-view digest differs/],
    ["transfer audit plane separation", evidence => {
      evidence.transfer.auditDisclosure.scanTransactionLink.scanTxHash = `0x${digest("46")}`;
    }, /user and audit disclosures were not decoded from the same typed scan transaction/],
    ["transfer scan/EVM transaction link", evidence => {
      evidence.transfer.disclosure.scanTransactionLink.evmTxHash = `0x${digest("ff")}`;
    }, /differs from the submitted EVM transaction/],
    ["one proof", evidence => {
      evidence.batch.proofCount = 2;
    }, /batch.proofCount must be an integer in 1\.\.1/],
    ["authorization kind", evidence => {
      evidence.batch.authorization.kind = 18;
    }, /profileSupportedKinds does not include the exercised kind/],
    ["authorization replay", evidence => {
      evidence.batch.authorization.replayTransaction.receipt.status = "0x1";
    }, /receipt\.status must be 0x0/],
    ["authorization replay calldata", evidence => {
      evidence.batch.authorization.replayTransaction.prepared.data += "00";
      evidence.batch.authorization.replayTransaction.observed.input += "00";
    }, /must reuse the exact authorized calldata and nonce/],
    ["batch recovery", evidence => {
      evidence.batch.payments[0].recovered = false;
    }, /payments\[0\]\.recovered must be true/],
    ["batch aggregate operation hash", evidence => {
      evidence.batch.operationEvidence.proof_hash = digest("ff");
    }, /operationEvidenceHash does not bind/],
    ["batch truncated payment evidence", evidence => {
      evidence.batch.operationEvidence.expected_outputs = [];
    }, /must exactly match the complete payment list/],
    ["batch request amount substitution", evidence => {
      evidence.batch.requestedPayments[0].amount = "3";
    }, /expected output 0 amount differs from the request/],
    ["batch request policy substitution", evidence => {
      evidence.batch.requestedPayments[0].userPrivacyPolicy = 1;
      evidence.batch.requestedPayments[0].userDisclosureMode = 1;
    }, /expected output 0 privacy policy differs from the request/],
    ["batch missing requested payment", evidence => {
      evidence.batch.requestedPayments = [];
    }, /requestedPayments must contain the complete 1\.\.32 item request/],
    ["batch missing recipient-encrypted disclosure coverage", evidence => {
      evidence.batch.requestedPayments[1].userDisclosureMode = 1;
    }, /must exercise public and recipient-encrypted disclosure modes/],
    ["batch incomplete typed output set", evidence => {
      evidence.batch.outputs.pop();
    }, /must contain the complete payment\/change\/padding output set/],
    ["batch noncanonical output role", evidence => {
      evidence.batch.outputs[2].role = "payment";
    }, /role must be payment, change, or padding/],
    ["batch mixed self-view evidence", evidence => {
      evidence.batch.outputs[1].selfViewDisclosureDigest = "";
    }, /self-view digest differs/],
    ["batch missing audit decode", evidence => {
      evidence.batch.outputs[1].auditVerified = false;
    }, /outputs\[1\]\.auditVerified must be true/],
    ["batch typed digest", evidence => {
      evidence.batch.payments[0].selfViewDisclosureDigest = digest("ff");
    }, /self-view digest differs/],
    ["batch scan/EVM transaction link", evidence => {
      evidence.batch.scanTransactionLink.ethereumTxHashEventMatched = false;
    }, /ethereumTxHashEventMatched must be true/],
    ["batch matrix completeness", evidence => {
      evidence.batchShapeMatrix.shapes.pop();
    }, /must contain exactly 5 shapes/],
    ["batch matrix exact boundary", evidence => {
      evidence.batchShapeMatrix.shapes[2].paymentCount = 30;
    }, /paymentCount differs from the release shape/],
    ["batch matrix exact input amounts", evidence => {
      evidence.batchShapeMatrix.shapes[1].inputAmounts[0] = "4";
    }, /inputAmounts\[0\] differs from the pinned v0\.3\.1 fixture/],
    ["batch matrix exact payment amounts", evidence => {
      evidence.batchShapeMatrix.shapes[0].paymentAmounts[0] = "8";
    }, /paymentAmounts\[0\] differs from the pinned v0\.3\.1 fixture/],
    ["batch matrix exact output amounts", evidence => {
      evidence.batchShapeMatrix.shapes[1].outputs[3].amount = "5";
    }, /outputs\[3\]\.amount differs from the pinned v0\.3\.1 fixture/],
    ["batch matrix exact disclosure modes", evidence => {
      evidence.batchShapeMatrix.shapes[1].disclosureModes[1] = "none";
    }, /disclosureModes\[1\] differs from the pinned v0\.3\.1 fixture/],
    ["batch matrix typed disclosure modes", evidence => {
      evidence.batchShapeMatrix.shapes[1].outputs[2].userDisclosureMode = 1;
    }, /outputs\[2\]\.userDisclosureMode differs from the pinned v0\.3\.1 fixture/],
    ["batch matrix one proof", evidence => {
      evidence.batchShapeMatrix.shapes[3].proofCount = 2;
    }, /proofCount must be an integer in 1\.\.1/],
    ["batch matrix padding semantics", evidence => {
      const paddingShape = evidence.batchShapeMatrix.shapes[4];
      paddingShape.outputs[1].recovered = true;
    }, /outputs\[1\]\.recovered must be false/],
    ["batch matrix transaction uniqueness", evidence => {
      evidence.batchShapeMatrix.shapes[1].transaction = evidence.batchShapeMatrix.shapes[0].transaction;
    }, /reuses another shape transaction/],
    ["batch matrix direct execution coverage", evidence => {
      evidence.batchShapeMatrix.shapes.forEach((shape, index) => {
        const authorized = transaction((190 + index).toString(16), {
          sender: relayer,
          operation: "singleProofBatchTransferWithAuthorization"
        });
        shape.executionMode = "authorized";
        shape.transaction = authorized;
        shape.scanTransactionLink.evmTxHash = authorized.observed.hash;
      });
    }, /must execute at least one shape through direct singleProofBatchTransfer/],
    ["batch matrix duplicate output commitment", evidence => {
      const shape = evidence.batchShapeMatrix.shapes[1];
      shape.outputs[1].outputCommitment = shape.outputs[0].outputCommitment;
    }, /outputs contains duplicate output commitments/],
    ["direct withdrawal", evidence => {
      evidence.withdraw.direct.recipientBalanceAfter = "12";
    }, /recipient balance delta/],
    ["withdraw reserve debit", evidence => {
      evidence.withdraw.direct.privacyModuleBalanceAfter = "58";
    }, /privacy module balance delta/],
    ["withdraw reserve invariant", evidence => {
      evidence.withdraw.relay.reserveInvariantHolds = false;
    }, /reserveInvariantHolds must be true/],
    ["withdraw input cardinality", evidence => {
      evidence.withdraw.direct.inputCount = 2;
      evidence.withdraw.direct.inputNullifiers.push(spentNullifier("61"));
    }, /withdraw\.direct\.inputCount must be an integer in 1\.\.1/],
    ["relay immutability", evidence => {
      evidence.withdraw.relay.payload.submittedHash = digest("ff");
    }, /payload hash changed/],
    ["relay recipient binding", evidence => {
      evidence.withdraw.relay.payload.recipient = "demo1other";
      evidence.withdraw.relay.payload.submittedRecipient = "demo1other";
    }, /payload recipient differs from withdraw\.relay\.recipient/],
    ["relay rebuild", evidence => {
      evidence.withdraw.relay.candidateMatchedRelayerRebuild = false;
    }, /candidateMatchedRelayerRebuild must be true/],
    ["relay handoff reservation stage", evidence => {
      evidence.withdraw.relay.reservationLifecycle.handoff.status = "Reserved";
    }, /handoff.status must be ProofReady/],
    ["relay submitted reservation tx", evidence => {
      evidence.withdraw.relay.reservationLifecycle.submitted.submittedTxHash = `0x${digest("ff")}`;
    }, /submittedTxHash differs from the relayer transaction/],
    ["relay final reservation reconciliation", evidence => {
      evidence.withdraw.relay.reservationLifecycle.reconciled.status = "Submitted";
    }, /reconciled.status must be ConfirmedSpent/],
    ["expiry rejection", evidence => {
      evidence.safety.expiredAtBlockTime.transaction.receipt.status = "0x1";
    }, /receipt\.status must be 0x0/],
    ["rejection layer", evidence => {
      evidence.safety.crossChainReplay.rejectionLayer = "sdk";
    }, /rejectionLayer must be chain/],
    ["direct withdraw expiry rejection", evidence => {
      delete evidence.safety.withdrawExpiredAtBlockTime;
    }, /safety\.withdrawExpiredAtBlockTime is required/],
    ["withdraw SDK preflight rejection", evidence => {
      delete evidence.safety.relayExpiryExtension.sdkPreflightRejected;
    }, /relayExpiryExtension\.sdkPreflightRejected must be true/],
    ["rejection mutation identity", evidence => {
      evidence.safety.outputSubstitution.mutation.field = "auditDisclosureDigest";
    }, /mutation\.field must be newCommitments\[0\]/],
    ["rejection calldata binding", evidence => {
      evidence.safety.disclosureSubstitution.mutation.attemptedCalldata =
        evidence.safety.disclosureSubstitution.mutation.referenceCalldata;
    }, /attemptedCalldata does not bind the rejected call/],
    ["rejection state snapshot", evidence => {
      evidence.safety.duplicateNullifier.after.leafCount = "8";
    }, /safety\.duplicateNullifier\.leafCount changed/],
    ["duplicate rejection transaction", evidence => {
      evidence.safety.duplicateCommitment.transaction = evidence.safety.duplicateNullifier.transaction;
    }, /reuses another rejection transaction/],
    ["missing receipt", evidence => {
      evidence.recovery.missingReceipt.markedSucceeded = true;
    }, /missingReceipt.markedSucceeded must be false/],
    ["mixed reservation details", evidence => {
      evidence.recovery.mixedState.reservations[1].status = "Submitted";
    }, /must expose the mixed statuses/],
    ["field-level conflict", evidence => {
      evidence.recovery.evidenceConflict.conflicts[0].actual = digest("01");
    }, /does not contain a conflict/],
    ["conflict reservation ID", evidence => {
      delete evidence.recovery.evidenceConflict.conflicts[0].reservation_id;
    }, /conflicts\[0\]\.reservation_id is required/],
    ["conflict source field", evidence => {
      delete evidence.recovery.evidenceConflict.conflicts[0].source_field;
    }, /conflicts\[0\]\.source_field is required/],
    ["conflict reason", evidence => {
      delete evidence.recovery.evidenceConflict.conflicts[0].reason;
    }, /conflicts\[0\]\.reason is required/],
    ["missing conflict field", evidence => {
      evidence.recovery.evidenceConflict.conflicts = evidence.recovery.evidenceConflict.conflicts.filter(entry => entry.field !== "digest");
    }, /must include digest/],
    ["matching evidence", evidence => {
      evidence.recovery.matchingEvidence.txHash = `0x${digest("ff")}`;
    }, /differs from the transfer transaction/]
  ];

  for (const [name, mutate, expected] of cases) {
    const evidence = validEvidence();
    mutate(evidence);
    assert.throws(() => validateEvmIntegrationEvidence(evidence), expected, name);
  }
});

test("EVM integration verification skips locally but fails closed when required", async () => {
  assert.deepEqual(
    await runEvmIntegrationVerification({ driverPath: "", required: false }),
    {
      status: "skipped",
      reason: "CLAIRVEIL_EVM_E2E_DRIVER is not configured"
    }
  );
  await assert.rejects(
    () => runEvmIntegrationVerification({ driverPath: "", required: true }),
    /CLAIRVEIL_EVM_E2E_DRIVER is required/
  );
});

test("optional EVM integration CLI skips without an external Clairveil checkout", () => {
  const env = { ...process.env };
  delete env.CLAIRVEIL_EVM_E2E_DRIVER;
  delete env.CLAIRVEIL_EVM_E2E_REQUIRED;
  env.CLAIRVEIL_SOURCE_DIR = fileURLToPath(
    new URL("./does-not-exist-clairveil-source", import.meta.url)
  );
  const result = spawnSync(process.execPath, [
    fileURLToPath(new URL("../tools/verify-evm-integration.js", import.meta.url))
  ], {
    env,
    encoding: "utf8"
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(
    result.stdout,
    /SKIP EVM integration: CLAIRVEIL_EVM_E2E_DRIVER is not configured/
  );
});

test("configured EVM integration still verifies the Clairveil snapshot", () => {
  const sourcePath = fileURLToPath(
    new URL("./does-not-exist-clairveil-source", import.meta.url)
  );
  const driverPath = fileURLToPath(
    new URL("./does-not-exist-evm-driver.mjs", import.meta.url)
  );
  const cliPath = fileURLToPath(
    new URL("../tools/verify-evm-integration.js", import.meta.url)
  );
  const env = {
    ...process.env,
    CLAIRVEIL_SOURCE_DIR: sourcePath,
    CLAIRVEIL_EVM_E2E_DRIVER: driverPath
  };
  delete env.CLAIRVEIL_EVM_E2E_REQUIRED;
  const result = spawnSync(process.execPath, [cliPath], {
    env,
    encoding: "utf8"
  });
  assert.equal(result.status, 1, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stderr, /Clairveil contract snapshot verification failed/);
});

test("deprecated EVM payable CLI preserves the legacy required gate", () => {
  const env = { ...process.env };
  for (const name of [
    "CLAIRVEIL_EVM_E2E_DRIVER",
    "CLAIRVEIL_EVM_E2E_REQUIRED",
    "CLAIRVEIL_EVM_PAYABLE_E2E_DRIVER",
    "CLAIRVEIL_EVM_PAYABLE_E2E_REQUIRED"
  ]) {
    delete env[name];
  }
  env.CLAIRVEIL_EVM_PAYABLE_E2E_REQUIRED = "1";
  const result = spawnSync(process.execPath, [
    fileURLToPath(new URL("../tools/verify-evm-payable-integration.js", import.meta.url))
  ], {
    env,
    encoding: "utf8"
  });
  assert.equal(result.status, 1, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stderr, /CLAIRVEIL_EVM_E2E_DRIVER is required/);
});
