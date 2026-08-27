import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import sha3 from "js-sha3";
import {
  createClairveilEvmClient,
  createEvmAuthorizationProfile,
  createEvmContractAdapter,
  encodeAbiParameters,
  encodeEvmPrivacyBatchTransfer,
  encodeEvmPrivacyBatchTransferWithAuthorization,
  encodeEvmPrivacyDeposit,
  encodeEvmPrivacySingleProofBatchTransfer,
  encodeEvmPrivacySingleProofBatchTransferWithAuthorization,
  encodeEvmPrivacyTransferWithAuthorization,
  encodeEvmPrivacyWithdrawWithAuthorization,
  evmPrivacyPrecompileAbi,
  evmPrivacyPrecompileAddress,
  functionSelector,
  defaultEvmPrivacyPrecompileAddress,
  defaultEncodeEvmTransfer
} from "clairveiljs/evm";

const { keccak_256: keccak256 } = sha3;
const fixture = JSON.parse(await readFile(
  fileURLToPath(new URL("../fixtures/evm-privacy-precompile-v0.3.1.json", import.meta.url)),
  "utf8"
));

const sender = "0x1111111111111111111111111111111111111111";
const executor = "0x2222222222222222222222222222222222222222";
const testPrivacyContractAddress = "0x0000000000000000000000000000000000000900";

test("generic ABI encoding supports canonical boolean words", () => {
  assert.equal(
    encodeAbiParameters(["bool", "bool"], [false, true]),
    `${"00".repeat(32)}${"00".repeat(31)}01`
  );
  assert.throws(
    () => encodeAbiParameters(["bool"], [1]),
    /bool ABI value must be a boolean/
  );
});

test("generic EVM clients require the target chain privacy contract address", () => {
  assert.equal(defaultEvmPrivacyPrecompileAddress, evmPrivacyPrecompileAddress);
  assert.throws(
    () => createClairveilEvmClient(),
    /requires contractAddress or contractAdapter\.contractAddress/
  );
  assert.throws(
    () => createEvmContractAdapter(),
    /requires contractAddress/
  );
  assert.throws(
    () => createClairveilEvmClient({
      contractAdapter: {
        buildDepositTransaction() {},
        buildTransferTransaction() {},
        buildWithdrawTransaction() {}
      }
    }),
    /contractAdapter\.contractAddress is required/
  );
});

function bytes(length, fill) {
  return new Uint8Array(length).fill(fill);
}

function transferMessage() {
  return {
    proof: bytes(96, 1),
    root: bytes(32, 2),
    nullifiers: [bytes(32, 3)],
    newCommitments: [bytes(32, 4), bytes(32, 5)],
    cipherTexts: [bytes(48, 6), bytes(48, 7)],
    viewTags: [bytes(2, 8), bytes(2, 9)],
    userPrivacyPolicy: 3,
    userDisclosureDigest: bytes(32, 10),
    userDisclosureMode: 2,
    userDisclosureTargetPubkey: bytes(33, 11),
    userDisclosurePayload: bytes(64, 12),
    auditDisclosureDigest: bytes(32, 13),
    auditDisclosureTargetPubkey: bytes(33, 14),
    auditDisclosurePayload: bytes(472, 15),
    selfViewDisclosureDigest: bytes(32, 16),
    selfViewDisclosurePayload: bytes(64, 17),
    expiresAtUnix: 1_900_000_000n
  };
}

function authorization() {
  return {
    effectiveSender: sender,
    executor,
    nonce: 7n,
    deadline: 1_900_000_100n,
    authorizationKind: 1,
    signature: bytes(65, 18)
  };
}

function singleProofBatchMessage() {
  return {
    proof: bytes(128, 19),
    root: bytes(32, 20),
    nullifiers: [bytes(32, 21)],
    outputs: [{
      commitment: bytes(32, 22),
      ciphertext: bytes(430, 23),
      viewTag: bytes(2, 24),
      userPrivacyPolicy: 0,
      userDisclosureMode: 0,
      // Go's JSON vectors spell omitted Solidity `bytes` as `0x`.
      userDisclosureDigest: "0x",
      userDisclosureTargetPubkey: "0x",
      userDisclosurePayload: "0x",
      fullDisclosureDigest: bytes(32, 25),
      auditDisclosurePayload: bytes(472, 26),
      selfViewDisclosurePayload: "0x"
    }],
    auditKeyId: "audit-key-1",
    auditKeyEpoch: 1n,
    auditDisclosureTargetPubkey: bytes(33, 27),
    expiresAtUnix: 1_900_000_000n
  };
}

function eventTopic(signature) {
  return `0x${keccak256(signature)}`;
}

function addressTopic(address) {
  return `0x${address.slice(2).toLowerCase().padStart(64, "0")}`;
}

function canonicalAbiParameter({ name = "", type, indexed = false, components } = {}) {
  return {
    name,
    type,
    ...(components ? { components: components.map(canonicalAbiParameter) } : {}),
    ...(indexed ? { indexed } : {})
  };
}

function canonicalAbiItem({ type, name, stateMutability, inputs = [], outputs = [], anonymous = false }) {
  return {
    type,
    name,
    ...(stateMutability ? { stateMutability } : {}),
    inputs: inputs.map(canonicalAbiParameter),
    ...(type === "function" ? { outputs: outputs.map(canonicalAbiParameter) } : {}),
    ...(type === "event" ? { anonymous } : {})
  };
}

function canonicalAbiDigest(abi) {
  const normalized = abi.map(canonicalAbiItem).sort((a, b) => (
    `${a.type}:${a.name}`.localeCompare(`${b.type}:${b.name}`)
  ));
  return createHash("sha256").update(JSON.stringify(normalized)).digest("hex");
}

test("default ClairveilJS EVM adapter selectors and event surface are represented exactly", () => {
  assert.equal(fixture.schema_version, "clairveil-evm-privacy-contract-v1");
  const signatures = {
    deposit: "deposit((bytes,bytes,bytes))",
    transfer: "transfer((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes,bytes,bytes,uint64))",
    withdraw: "withdraw((bytes,bytes,bytes,string,address,string,uint64))",
    transferWithAuthorization: "transferWithAuthorization((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes,bytes,bytes,uint64),(address,address,uint256,uint64,uint8,bytes))",
    withdrawWithAuthorization: "withdrawWithAuthorization((bytes,bytes,bytes,string,address,string,uint64),(address,address,uint256,uint64,uint8,bytes))",
    batchTransfer: "batchTransfer(bytes32,(bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes,bytes,bytes,uint64)[])",
    batchTransferWithAuthorization: "batchTransferWithAuthorization(bytes32,((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes,bytes,bytes,uint64),(address,address,uint256,uint64,uint8,bytes))[])",
    singleProofBatchTransfer: "singleProofBatchTransfer((bytes,bytes,bytes[],(bytes,bytes,bytes,uint32,uint8,bytes,bytes,bytes,bytes,bytes,bytes)[],string,uint64,bytes,uint64))",
    singleProofBatchTransferWithAuthorization: "singleProofBatchTransferWithAuthorization((bytes,bytes,bytes[],(bytes,bytes,bytes,uint32,uint8,bytes,bytes,bytes,bytes,bytes,bytes)[],string,uint64,bytes,uint64),(address,address,uint256,uint64,uint8,bytes))"
  };
  for (const [name, signature] of Object.entries(signatures)) {
    assert.equal(functionSelector(signature), fixture.selectors[name], name);
  }
  assert.deepEqual(
    evmPrivacyPrecompileAbi.filter(item => item.type === "function").map(item => item.name).sort(),
    Object.keys(fixture.selectors).sort()
  );
  assert.deepEqual(
    evmPrivacyPrecompileAbi.filter(item => item.type === "event").map(item => item.name).sort(),
    Object.keys(fixture.events).sort()
  );
  assert.equal(evmPrivacyPrecompileAbi.find(item => item.name === "deposit").stateMutability, "payable");
  assert.equal(canonicalAbiDigest(evmPrivacyPrecompileAbi), fixture.canonical_abi_sha256);
});

test("EVM payable deposit removes the legacy amount tuple field", () => {
  const calldata = encodeEvmPrivacyDeposit({
    amount: "3aokrw",
    noteCommitment: bytes(32, 1),
    encryptedNote: bytes(4, 2),
    proof: bytes(8, 3)
  });
  assert.equal(calldata.slice(0, 10), `0x${fixture.selectors.deposit}`);
  // The first top-level word is the tuple offset. Its body has only the three
  // dynamic byte fields defined by IPrivacy.deposit(request).
  assert.equal(calldata.slice(10, 74), "20".padStart(64, "0"));
  assert.equal(calldata.slice(74, 138), "60".padStart(64, "0"));
});

test("EVM authorization and both batch rails encode without field loss", () => {
  const transfer = transferMessage();
  const auth = authorization();
  assert.equal(encodeEvmPrivacyTransferWithAuthorization(transfer, auth).slice(0, 10), `0x${fixture.selectors.transferWithAuthorization}`);
  assert.equal(encodeEvmPrivacyWithdrawWithAuthorization({
    proof: bytes(96, 1), root: bytes(32, 2), nullifier: bytes(32, 3), amount: "1aokrw",
    recipient: sender, chainId: "evm-privacy-local-1", expiresAtUnix: 1_900_000_000n
  }, auth).slice(0, 10), `0x${fixture.selectors.withdrawWithAuthorization}`);
  assert.equal(encodeEvmPrivacyBatchTransfer(bytes(32, 1), [transfer]).slice(0, 10), `0x${fixture.selectors.batchTransfer}`);
  assert.equal(encodeEvmPrivacyBatchTransferWithAuthorization(bytes(32, 1), [{ request: transfer, authorization: auth }]).slice(0, 10), `0x${fixture.selectors.batchTransferWithAuthorization}`);
  const single = singleProofBatchMessage();
  assert.equal(encodeEvmPrivacySingleProofBatchTransfer(single).slice(0, 10), `0x${fixture.selectors.singleProofBatchTransfer}`);
  assert.equal(encodeEvmPrivacySingleProofBatchTransferWithAuthorization(single, auth).slice(0, 10), `0x${fixture.selectors.singleProofBatchTransferWithAuthorization}`);
});

test("EVM authorization encoders accept every ABI-valid kind and target profiles enforce their own allowlist", () => {
  const transfer = transferMessage();
  for (const authorizationKind of [0, 1, 2, 3, 42, 255]) {
    assert.equal(
      encodeEvmPrivacyTransferWithAuthorization(transfer, { ...authorization(), authorizationKind }).slice(0, 10),
      `0x${fixture.selectors.transferWithAuthorization}`
    );
  }
  assert.throws(
    () => encodeEvmPrivacyTransferWithAuthorization(transfer, { ...authorization(), authorizationKind: 256 }),
    /authorization kind must be a uint8/
  );
  assert.equal(
    createClairveilEvmClient({ contractAddress: testPrivacyContractAddress }).buildTransferWithAuthorizationTransaction({
      message: transfer,
      authorization: { ...authorization(), authorizationKind: 42 }
    }).status,
    "ready"
  );
  const profile = createEvmAuthorizationProfile({
    supportedAuthorizationKinds: [1, 2, 3]
  });
  const client = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
    authorizationProfile: profile
  });
  for (const authorizationKind of [1, 2, 3]) {
    assert.equal(
      client.buildTransferWithAuthorizationTransaction({
        message: transfer,
        authorization: { ...authorization(), authorizationKind }
      }).status,
      "ready"
    );
  }
  assert.throws(
    () => client.buildTransferWithAuthorizationTransaction({
      message: transfer,
      authorization: { ...authorization(), authorizationKind: 42 }
    }),
    /unsupported EVM privacy authorization kind 42/
  );
  const extendedProfile = createEvmAuthorizationProfile({
    supportedAuthorizationKinds: [42]
  });
  assert.equal(
    createClairveilEvmClient({
      contractAddress: testPrivacyContractAddress,
      authorizationProfile: extendedProfile
    })
      .buildTransferWithAuthorizationTransaction({
        message: transfer,
        authorization: { ...authorization(), authorizationKind: 42 }
      }).status,
    "ready"
  );
});

test("equivalent independently-created authorization profiles compose with custom EVM adapters", () => {
  const options = {
    supportedAuthorizationKinds: [3, 1, 2],
    typedDataDomain: { name: "Generic EVM Privacy", version: "1" }
  };
  const adapterProfile = createEvmAuthorizationProfile(options);
  const clientProfile = createEvmAuthorizationProfile({
    ...options,
    supportedAuthorizationKinds: [1, 2, 3]
  });
  const adapter = createEvmContractAdapter({
    contractAddress: testPrivacyContractAddress,
    authorizationProfile: adapterProfile
  });

  assert.doesNotThrow(() => createClairveilEvmClient({
    contractAdapter: adapter,
    authorizationProfile: clientProfile
  }));
  assert.throws(
    () => createClairveilEvmClient({
      contractAdapter: adapter,
      authorizationProfile: createEvmAuthorizationProfile({
        ...options,
        supportedAuthorizationKinds: [1, 2]
      })
    }),
    /authorizationProfile conflicts/
  );
});

test("EVM authorization typed data binds the configured domain and exact envelope", () => {
  const transfer = transferMessage();
  const unsignedAuthorization = { ...authorization() };
  delete unsignedAuthorization.signature;
  const typedDataRequest = {
    action: "batchTransfer",
    request: transfer,
    authorization: unsignedAuthorization,
    cosmosChainId: "evm-privacy-local-1",
    evmChainId: "0x40000",
    batchId: bytes(32, 29),
    batchItemIndex: 3
  };
  assert.throws(
    () => createClairveilEvmClient({ contractAddress: testPrivacyContractAddress }).buildAuthorizationTypedData(typedDataRequest),
    /configured EVM authorization profile does not provide buildTypedData/
  );
  const profile = createEvmAuthorizationProfile({
    supportedAuthorizationKinds: [1, 2, 3],
    typedDataDomain: { name: "Example EVM Privacy", version: "2" }
  });
  const typed = profile.buildTypedData({
    ...typedDataRequest,
    contractAddress: testPrivacyContractAddress
  });
  assert.equal(typed.primaryType, "PrivacyActionAuthorization");
  assert.equal(typed.domain.name, "Example EVM Privacy");
  assert.equal(typed.domain.version, "2");
  assert.equal(typed.domain.chainId, "262144");
  assert.equal(typed.domain.verifyingContract, testPrivacyContractAddress);
  assert.equal(typed.message.authorizationEnvelopeSelector, `0x${fixture.selectors.batchTransferWithAuthorization}`);
  assert.equal(typed.message.authorizationActionSelector, `0x${fixture.selectors.transfer}`);
  assert.equal(typed.message.cosmosChainIdHash, `0x${keccak256("evm-privacy-local-1")}`);
  assert.equal(typed.message.batchId, `0x${"1d".repeat(32)}`);
  assert.equal(typed.message.batchItemIndex, "3");
  assert.throws(
    () => profile.buildTypedData({
      ...typedDataRequest,
      authorization: { ...unsignedAuthorization, authorizationKind: 42 }
    }),
    /unsupported EVM privacy authorization kind 42/
  );
  const extendedProfile = createEvmAuthorizationProfile({
    supportedAuthorizationKinds: [42],
    typedDataDomain: { name: "Example EVM Privacy", version: "2" }
  });
  assert.equal(
    extendedProfile.buildTypedData({
      ...typedDataRequest,
      contractAddress: testPrivacyContractAddress,
      authorization: { ...unsignedAuthorization, authorizationKind: 42 }
    }).message.authorizationKind,
    "42"
  );
});

test("EVM receipt verification requires the exact PrivacyDeposit event, not only status", () => {
  const client = createClairveilEvmClient({
    defaultDenom: "aokrw",
    nativeDenom: "aokrw",
    contractAddress: testPrivacyContractAddress
  });
  const prepared = client.buildDepositTransaction({ message: {
    amount: "3aokrw",
    noteCommitment: bytes(32, 31),
    encryptedNote: bytes(4, 32),
    proof: bytes(8, 33)
  } });
  const data = `0x${encodeAbiParameters(
    ["string", "bytes"],
    ["3aokrw", bytes(32, 31)]
  )}`;
  const receipt = {
    status: "0x1",
    logs: [{
      address: testPrivacyContractAddress,
      topics: [
        eventTopic(fixture.events.PrivacyDeposit),
        addressTopic(sender),
        addressTopic(sender)
      ],
      data
    }]
  };
  assert.deepEqual(client.verifyPrivacyReceipt({ transaction: prepared.transaction, receipt, sender }), {
    verified: true,
    event: "PrivacyDeposit",
    operation: "deposit"
  });

  assert.throws(
    () => client.verifyPrivacyReceipt({
      transaction: prepared.transaction,
      sender,
      receipt: { ...receipt, logs: [{ ...receipt.logs[0], data: `0x${encodeAbiParameters(["string", "bytes"], ["4aokrw", bytes(32, 31)])}` }] }
    }),
    /amount or note commitment/
  );
});

test("EVM transaction identity verification binds hash, sender, call, value, and network", async () => {
  const client = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
    evmChainId: "0x539"
  });
  const built = await client.buildTransferTransaction({ message: transferMessage() });
  const transaction = { ...built.transaction, chainId: "0x539" };
  const txHash = `0x${"ab".repeat(32)}`;
  const rpcTransaction = {
    hash: txHash,
    from: sender,
    to: transaction.to,
    input: transaction.data,
    value: transaction.value,
    chainId: "0x539"
  };
  const input = {
    transaction,
    rpcTransaction,
    txHash,
    sender,
    expectedChainId: "0x539",
    actualChainId: "0x539"
  };

  const verified = client.verifyTransactionIdentity(input);
  assert.equal(verified.verified, true);
  assert.equal(verified.operation, "transfer");
  assert.equal(verified.txHash, txHash);
  assert.equal(verified.sender, sender);
  assert.equal(verified.chainId, "0x539");
  assert.match(verified.txBytesHash, /^[0-9a-f]{64}$/);

  for (const [label, changed, expectedError] of [
    ["hash", { rpcTransaction: { ...rpcTransaction, hash: `0x${"ac".repeat(32)}` } }, /hash does not match/],
    ["sender", { rpcTransaction: { ...rpcTransaction, from: executor } }, /sender does not match/],
    ["target", { rpcTransaction: { ...rpcTransaction, to: executor } }, /target does not match/],
    ["calldata", { rpcTransaction: { ...rpcTransaction, input: `${transaction.data.slice(0, -2)}ff` } }, /calldata does not match/],
    ["value", { rpcTransaction: { ...rpcTransaction, value: "0x1" } }, /value does not match/],
    ["network", { actualChainId: "0x1" }, /RPC chain ID does not match/]
  ]) {
    assert.throws(
      () => client.verifyTransactionIdentity({ ...input, ...changed }),
      expectedError,
      label
    );
  }
});

test("EVM receipt verification binds direct, authorized, and batch event evidence", async () => {
  const client = createClairveilEvmClient({
    defaultDenom: "aokrw",
    nativeDenom: "aokrw",
    chainId: "evm-privacy-local-1",
    accountPrefix: "evm",
    contractAddress: testPrivacyContractAddress
  });
  const transfer = transferMessage();
  const transferBuilt = await client.buildTransferTransaction({ message: transfer });
  const transferReceipt = {
    status: "0x1",
    logs: [{
      address: testPrivacyContractAddress,
      topics: [eventTopic(fixture.events.PrivacyTransfer), addressTopic(sender), addressTopic(sender)],
      data: `0x${encodeAbiParameters(["bytes"], [transfer.root])}`
    }]
  };
  assert.equal(client.verifyPrivacyReceipt({ transaction: transferBuilt.transaction, receipt: transferReceipt, sender }).event, "PrivacyTransfer");

  const authorized = client.buildTransferWithAuthorizationTransaction({
    message: transfer,
    authorization: authorization()
  });
  assert.equal(client.verifyPrivacyReceipt({
    transaction: authorized.transaction,
    receipt: {
      status: "0x1",
      logs: [{
        address: testPrivacyContractAddress,
        topics: [eventTopic(fixture.events.PrivacyTransfer), addressTopic(sender), addressTopic(executor)],
        data: `0x${encodeAbiParameters(["bytes"], [transfer.root])}`
      }]
    },
    sender: executor
  }).event, "PrivacyTransfer");

  const withdrawBuilt = await client.buildWithdrawTransaction({ message: {
    proof: bytes(96, 41), root: bytes(32, 42), nullifier: bytes(32, 43), amount: "4aokrw",
    recipient: sender, chainId: "evm-privacy-local-1", expiresAtUnix: 1_900_000_000n
  } });
  assert.equal(client.verifyPrivacyReceipt({
    transaction: withdrawBuilt.transaction,
    receipt: {
      status: "0x1",
      logs: [{
        address: testPrivacyContractAddress,
        topics: [eventTopic(fixture.events.PrivacyWithdraw), addressTopic(sender), addressTopic(sender), addressTopic(sender)],
        data: `0x${encodeAbiParameters(["string"], ["4aokrw"])}`
      }]
    },
    sender
  }).event, "PrivacyWithdraw");

  const batchBuilt = client.buildBatchTransferTransaction({ batchId: bytes(32, 44), requests: [transfer] });
  const batchExpectation = batchBuilt.transaction.__clairveilEvmTransaction.receiptExpectation;
  assert.equal(client.verifyPrivacyReceipt({
    transaction: batchBuilt.transaction,
    receipt: {
      status: "0x1",
      logs: [{
        address: testPrivacyContractAddress,
        topics: [
          eventTopic(fixture.events.PrivacyBatchTransferItem),
          addressTopic(sender),
          addressTopic(sender),
          `0x${"2c".repeat(32)}`
        ],
        data: `0x${encodeAbiParameters(
          ["uint64", "bytes32", "bytes"],
          [0, batchExpectation.entries[0].requestHash, transfer.root]
        )}`
      }]
    },
    sender
  }).event, "PrivacyBatchTransferItem");

  const single = singleProofBatchMessage();
  const singleBuilt = client.buildSingleProofBatchTransferTransaction({ message: single });
  const singleExpectation = singleBuilt.transaction.__clairveilEvmTransaction.receiptExpectation;
  assert.equal(client.verifyPrivacyReceipt({
    transaction: singleBuilt.transaction,
    receipt: {
      status: "0x1",
      logs: [{
        address: testPrivacyContractAddress,
        topics: [
          eventTopic(fixture.events.PrivacySingleProofBatchTransfer),
          addressTopic(sender),
          addressTopic(sender),
          singleExpectation.requestHash
        ],
        data: `0x${encodeAbiParameters(["bytes", "uint8", "uint8"], [single.root, 1, 1])}`
      }]
    },
    sender
  }).event, "PrivacySingleProofBatchTransfer");
});

test("receipt verification refuses a custom adapter calldata mismatch even with a known selector", async () => {
  const transfer = transferMessage();
  const canonical = defaultEncodeEvmTransfer(transfer);
  const altered = `${canonical.slice(0, -2)}ff`;
  const client = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
    contractAdapter: {
      contractAddress: testPrivacyContractAddress,
      buildTransferTransaction: () => ({
        to: testPrivacyContractAddress,
        data: altered,
        value: "0x0"
      })
    }
  });
  const prepared = await client.buildTransferTransaction({ message: transfer });
  assert.equal(prepared.transaction.__clairveilEvmTransaction.receiptExpectation, null);
  const txHash = `0x${"ab".repeat(32)}`;
  assert.equal(client.verifyTransactionIdentity({
    transaction: prepared.transaction,
    rpcTransaction: {
      hash: txHash,
      from: sender,
      to: prepared.transaction.to,
      input: prepared.transaction.data,
      value: prepared.transaction.value
    },
    txHash,
    sender,
    expectedChainId: "0x539",
    actualChainId: "0x539"
  }).verified, true);
  assert.throws(
    () => client.verifyPrivacyReceipt({
      transaction: prepared.transaction,
      sender,
      receipt: { status: "0x1", logs: [] }
    }),
    /requires an SDK-prepared transaction/
  );
});

test("custom EVM adapters can provide fail-closed receipt evidence for custom calldata", async () => {
  const transfer = transferMessage();
  const altered = `${defaultEncodeEvmTransfer(transfer).slice(0, -2)}ff`;
  let verifierInput = null;
  const client = createClairveilEvmClient({
    contractAddress: testPrivacyContractAddress,
    contractAdapter: {
      contractAddress: testPrivacyContractAddress,
      buildTransferTransaction: () => ({
        to: testPrivacyContractAddress,
        data: altered,
        value: "0x0"
      }),
      verifyPrivacyReceipt(input) {
        verifierInput = input;
        return {
          verified: true,
          operation: input.operation,
          event: "CustomPrivacyTransfer"
        };
      }
    }
  });
  const prepared = await client.buildTransferTransaction({ message: transfer });
  const verified = client.verifyPrivacyReceipt({
    transaction: prepared.transaction,
    sender,
    receipt: { status: "0x1", logs: [] }
  });

  assert.deepEqual(verified, {
    verified: true,
    operation: "transfer",
    event: "CustomPrivacyTransfer"
  });
  assert.equal(verifierInput.operation, "transfer");
  assert.equal(verifierInput.transaction, prepared.transaction);
  assert.throws(
    () => client.verifyPrivacyReceipt({
      transaction: prepared.transaction,
      sender,
      receipt: { status: "0x0", logs: [] }
    }),
    /explicit successful status/
  );
  assert.throws(
    () => createClairveilEvmClient({
      contractAddress: testPrivacyContractAddress,
      contractAdapter: {
        ...client.contract,
        verifyPrivacyReceipt: () => ({
          verified: true,
          operation: "withdraw",
          event: "CustomPrivacyTransfer"
        })
      }
    }).verifyPrivacyReceipt({
      transaction: prepared.transaction,
      sender,
      receipt: { status: "0x1", logs: [] }
    }),
    /operation does not match/
  );
});
