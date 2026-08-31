import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import sha3 from "js-sha3";
import { evmPrivacyPrecompileAbi } from "../src/transport/evm.js";

const { keccak_256: keccak256 } = sha3;
const defaultPackageRoot = dirname(dirname(fileURLToPath(import.meta.url)));

export const evmContractFixtureRelativePath =
  "fixtures/evm-privacy-precompile-v0.3.1.json";
export const supportedEvmContractVersion = "0.3.1";
export const supportedEvmCanonicalAbiSha256 =
  "ee29aa6ab3e0ddca3c43e6457a51d05b15f405bbf192a6076d01894aecfcb31b";

function fail(message) {
  throw new Error(`Clairveil EVM contract verification failed: ${message}`);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${label} fields are ${actual.join(",")}; expected ${wanted.join(",")}`);
  }
}

function readFixture(packageRoot) {
  const fixturePath = join(packageRoot, evmContractFixtureRelativePath);
  let fixture;
  try {
    fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  } catch (error) {
    fail(`cannot read ${fixturePath}: ${error.message}`);
  }
  return { fixture, fixturePath };
}

function canonicalAbiParameter({ name = "", type, indexed = false, components } = {}) {
  return {
    name,
    type,
    ...(components ? { components: components.map(canonicalAbiParameter) } : {}),
    ...(indexed ? { indexed } : {})
  };
}

function canonicalAbiItem({
  type,
  name,
  stateMutability,
  inputs = [],
  outputs = [],
  anonymous = false
}) {
  return {
    type,
    name,
    ...(stateMutability ? { stateMutability } : {}),
    inputs: inputs.map(canonicalAbiParameter),
    ...(type === "function" ? { outputs: outputs.map(canonicalAbiParameter) } : {}),
    ...(type === "event" ? { anonymous } : {})
  };
}

function canonicalAbi(abi) {
  if (!Array.isArray(abi)) fail("canonical ABI must be an array");
  return abi.map(canonicalAbiItem).sort((left, right) =>
    `${left.type}:${left.name}`.localeCompare(`${right.type}:${right.name}`));
}

function canonicalAbiDigest(abi) {
  return sha256(JSON.stringify(canonicalAbi(abi)));
}

function signatureType(parameter) {
  const type = String(parameter?.type || "");
  if (!type.startsWith("tuple")) return type;
  if (!Array.isArray(parameter.components)) fail("tuple ABI parameter is missing components");
  return `(${parameter.components.map(signatureType).join(",")})${type.slice("tuple".length)}`;
}

function abiSignature(item) {
  return `${item.name}(${item.inputs.map(signatureType).join(",")})`;
}

function verifyFixtureShape(fixture) {
  exactKeys(
    fixture,
    ["schema_version", "contract_version", "canonical_abi_sha256", "selectors", "events"],
    "fixture"
  );
  if (fixture.schema_version !== "clairveil-evm-privacy-contract-v1") {
    fail(`schema_version is ${fixture.schema_version}`);
  }
  if (fixture.contract_version !== supportedEvmContractVersion) {
    fail(`contract_version is ${fixture.contract_version}`);
  }
  if (fixture.canonical_abi_sha256 !== supportedEvmCanonicalAbiSha256) {
    fail(`canonical_abi_sha256 is ${fixture.canonical_abi_sha256}`);
  }
  exactKeys(fixture.selectors, [
    "deposit",
    "transfer",
    "withdraw",
    "transferWithAuthorization",
    "withdrawWithAuthorization",
    "batchTransfer",
    "batchTransferWithAuthorization",
    "singleProofBatchTransfer",
    "singleProofBatchTransferWithAuthorization"
  ], "fixture.selectors");
  exactKeys(fixture.events, [
    "PrivacyDeposit",
    "PrivacyTransfer",
    "PrivacyWithdraw",
    "PrivacyBatchTransferItem",
    "PrivacySingleProofBatchTransfer"
  ], "fixture.events");
}

function verifyAbiAgainstFixture(abi, fixture, label) {
  const normalized = canonicalAbi(abi);
  if (normalized.length !== 14) fail(`${label} contains ${normalized.length} ABI items; expected 14`);
  const digest = canonicalAbiDigest(abi);
  if (digest !== fixture.canonical_abi_sha256) {
    fail(`${label} canonical ABI SHA-256 is ${digest}; expected ${fixture.canonical_abi_sha256}`);
  }
  const functions = normalized.filter(item => item.type === "function");
  const events = normalized.filter(item => item.type === "event");
  if (functions.length !== 9 || events.length !== 5) {
    fail(`${label} contains ${functions.length} functions and ${events.length} events`);
  }
  for (const item of functions) {
    const signature = abiSignature(item);
    const selector = keccak256(signature).slice(0, 8);
    if (fixture.selectors[item.name] !== selector) {
      fail(`${label} selector for ${item.name} is ${selector}; expected ${fixture.selectors[item.name]}`);
    }
    const expectedMutability = item.name === "deposit" ? "payable" : "nonpayable";
    if (item.stateMutability !== expectedMutability) {
      fail(`${label} ${item.name} mutability is ${item.stateMutability}; expected ${expectedMutability}`);
    }
  }
  for (const item of events) {
    const signature = abiSignature(item);
    if (fixture.events[item.name] !== signature) {
      fail(`${label} event ${item.name} is ${signature}; expected ${fixture.events[item.name]}`);
    }
  }
}

export function verifyBundledEvmContract({ packageRoot = defaultPackageRoot } = {}) {
  const resolvedPackageRoot = resolve(packageRoot);
  const { fixture, fixturePath } = readFixture(resolvedPackageRoot);
  verifyFixtureShape(fixture);
  verifyAbiAgainstFixture(evmPrivacyPrecompileAbi, fixture, "ClairveilJS EVM adapter");
  return {
    contractVersion: supportedEvmContractVersion,
    fixturePath,
    abiSha256: supportedEvmCanonicalAbiSha256
  };
}

function isDirectInvocation() {
  return Boolean(
    process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
  );
}

if (isDirectInvocation()) {
  try {
    const result = verifyBundledEvmContract();
    console.log(
      `verified Clairveil EVM contract ${result.contractVersion} (${result.abiSha256})`
    );
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
