import { fromBech32, toBech32 } from "@cosmjs/encoding";
import sha3 from "js-sha3";
import {
  buildDepositMaterial,
  parseCoin
} from "../core/note.js";
import {
  buildPreparedTransferPayload,
  buildTransferMessage,
  buildPreparedWithdrawProverPayload,
  buildWithdrawMsgFromPayload,
  buildWithdrawMessage,
  validateRelayWithdrawPayload
} from "../privacy/payload.js";
import {
  defaultShieldedPrefix,
  bytesFromHex,
  hexFromBytes,
  normalizeBech32Prefix,
  normalizeHex
} from "../core/crypto.js";

const { keccak_256: keccak256 } = sha3;
const zeroWord = "0".repeat(64);
const emptyBytes = new Uint8Array();
const zeroBytes32 = new Uint8Array(32);
const referenceDepositSignature = "deposit(uint256,bytes32,bytes)";
const referenceTransferSignature = "shieldedTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],bytes[],uint8,uint8,bytes32,bytes32,bytes,bytes32,bytes32,bytes)";
const referenceWithdrawSignature = "withdraw(bytes,bytes32,bytes32,uint256,address,string,uint64)";
const evmPrivacyDepositSignature = "deposit((string,bytes,bytes))";
const evmPrivacyTransferSignature = "transfer((bytes,bytes,bytes[],bytes[],bytes[],bytes[],uint32,bytes,uint8,bytes,bytes,bytes,bytes,bytes))";
const evmPrivacyWithdrawSignature = "withdraw((bytes,bytes,bytes,bytes,bytes,string,address,string,uint64))";

export const evmPrivacyPrecompileAddress = "0x100000000000000000000000000000000000000b";
export const defaultEvmPrivacyPrecompileAddress = evmPrivacyPrecompileAddress;
export const evmPrivacyPrecompileAbi = Object.freeze([
  {
    type: "function",
    name: "deposit",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "amount", type: "string" },
          { name: "noteCommitment", type: "bytes" },
          { name: "encryptedNote", type: "bytes" }
        ]
      }
    ],
    outputs: [{ name: "success", type: "bool" }]
  },
  {
    type: "function",
    name: "transfer",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "proof", type: "bytes" },
          { name: "root", type: "bytes" },
          { name: "nullifiers", type: "bytes[]" },
          { name: "newCommitments", type: "bytes[]" },
          { name: "cipherTexts", type: "bytes[]" },
          { name: "viewTags", type: "bytes[]" },
          { name: "userPrivacyPolicy", type: "uint32" },
          { name: "userDisclosureDigest", type: "bytes" },
          { name: "userDisclosureMode", type: "uint8" },
          { name: "userDisclosureTargetPubkey", type: "bytes" },
          { name: "userDisclosurePayload", type: "bytes" },
          { name: "auditDisclosureDigest", type: "bytes" },
          { name: "auditDisclosureTargetPubkey", type: "bytes" },
          { name: "auditDisclosurePayload", type: "bytes" }
        ]
      }
    ],
    outputs: [{ name: "success", type: "bool" }]
  },
  {
    type: "function",
    name: "withdraw",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "request",
        type: "tuple",
        components: [
          { name: "proof", type: "bytes" },
          { name: "root", type: "bytes" },
          { name: "nullifier", type: "bytes" },
          { name: "newNoteCommitment", type: "bytes" },
          { name: "encryptedNote", type: "bytes" },
          { name: "amount", type: "string" },
          { name: "recipient", type: "address" },
          { name: "chainId", type: "string" },
          { name: "expiresAtUnix", type: "uint64" }
        ]
      }
    ],
    outputs: [{ name: "success", type: "bool" }]
  },
  {
    type: "event",
    name: "PrivacyDeposit",
    inputs: [
      { name: "caller", type: "address", indexed: true },
      { name: "amount", type: "string", indexed: false },
      { name: "noteCommitment", type: "bytes", indexed: false }
    ],
    anonymous: false
  },
  {
    type: "event",
    name: "PrivacyTransfer",
    inputs: [
      { name: "caller", type: "address", indexed: true },
      { name: "root", type: "bytes", indexed: false }
    ],
    anonymous: false
  },
  {
    type: "event",
    name: "PrivacyWithdraw",
    inputs: [
      { name: "caller", type: "address", indexed: true },
      { name: "recipient", type: "address", indexed: true },
      { name: "amount", type: "string", indexed: false }
    ],
    anonymous: false
  }
]);

const evmPrivacyDepositTuple = evmPrivacyPrecompileAbi[0].inputs[0];
const evmPrivacyTransferTuple = evmPrivacyPrecompileAbi[1].inputs[0];
const evmPrivacyWithdrawTuple = evmPrivacyPrecompileAbi[2].inputs[0];

function strip0x(value) {
  return String(value || "").trim().replace(/^0x/i, "");
}

function with0x(hex) {
  return `0x${strip0x(hex).toLowerCase()}`;
}

function bytesLikeToHex(value, label = "bytes") {
  if (value == null) return "";
  if (typeof value === "string") {
    return normalizeHex(value, label);
  }
  return hexFromBytes(Uint8Array.from(value));
}

function padRightWord(hex) {
  const clean = strip0x(hex);
  const remainder = clean.length % 64;
  return remainder === 0 ? clean : clean.padEnd(clean.length + (64 - remainder), "0");
}

function uintWord(value, bits = 256) {
  const n = BigInt(value);
  if (n < 0n) throw new Error("uint value must be non-negative");
  if (bits < 256 && n >= (1n << BigInt(bits))) {
    throw new Error(`uint${bits} value overflow`);
  }
  const hex = n.toString(16);
  if (hex.length > 64) throw new Error("uint value does not fit in 32 bytes");
  return hex.padStart(64, "0");
}

function addressWord(value) {
  const hex = strip0x(value).toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(hex)) {
    throw new Error("EVM address must be 20-byte hex");
  }
  return hex.padStart(64, "0");
}

function bytes32Word(value, label = "bytes32") {
  const hex = bytesLikeToHex(value, label);
  if (hex.length !== 64) {
    throw new Error(`${label} must be 32 bytes`);
  }
  return hex;
}

function utf8Hex(value) {
  return hexFromBytes(new TextEncoder().encode(String(value)));
}

function abiTypeName(type) {
  return typeof type === "string" ? type : type?.type;
}

function abiComponents(type) {
  return type?.components || [];
}

function isDynamicAbiType(type) {
  const name = abiTypeName(type);
  if (name === "tuple") {
    return abiComponents(type).some(component => isDynamicAbiType(component));
  }
  return name === "bytes" || name === "string" || name.endsWith("[]");
}

function encodeStaticAbi(type, value) {
  const name = abiTypeName(type);
  if (name === "tuple") return encodeTupleAbi(type, value);
  if (/^uint(8|16|32|64|128|256)?$/.test(name)) {
    const bits = Number(name.slice(4) || "256");
    return uintWord(value, bits);
  }
  if (name === "address") return addressWord(value);
  if (name === "bytes32") return bytes32Word(value);
  throw new Error(`unsupported static ABI type ${name}`);
}

function encodeBytes(hex) {
  const clean = strip0x(hex);
  return `${uintWord(clean.length / 2)}${padRightWord(clean)}`;
}

function encodeDynamicAbi(type, value) {
  const name = abiTypeName(type);
  if (name === "tuple") return encodeTupleAbi(type, value);
  if (name === "bytes") return encodeBytes(bytesLikeToHex(value));
  if (name === "string") return encodeBytes(utf8Hex(value));
  if (name === "bytes32[]") {
    return `${uintWord(value.length)}${value.map((item, index) => bytes32Word(item, `bytes32[${index}]`)).join("")}`;
  }
  if (name === "bytes[]") {
    const values = [...value];
    const heads = [];
    const tails = [];
    let offset = 32 * values.length;
    for (const item of values) {
      const encoded = encodeBytes(bytesLikeToHex(item));
      heads.push(uintWord(offset));
      tails.push(encoded);
      offset += encoded.length / 2;
    }
    return `${uintWord(values.length)}${heads.join("")}${tails.join("")}`;
  }
  throw new Error(`unsupported dynamic ABI type ${name}`);
}

function tupleComponentValue(component, value, index) {
  if (Array.isArray(value)) return value[index];
  if (value && typeof value === "object" && component.name) return value[component.name];
  throw new Error(`tuple component ${component.name || index} is missing`);
}

function encodeTupleAbi(type, value) {
  const components = abiComponents(type);
  return encodeAbiParameters(
    components,
    components.map((component, index) => tupleComponentValue(component, value, index))
  );
}

export function functionSelector(signature) {
  return keccak256(String(signature)).slice(0, 8);
}

export function encodeAbiParameters(types, values) {
  if (types.length !== values.length) {
    throw new Error(`ABI parameter count mismatch: ${types.length} types, ${values.length} values`);
  }
  const heads = [];
  const tails = [];
  let tailOffset = types.length * 32;
  for (let i = 0; i < types.length; i += 1) {
    const type = types[i];
    const value = values[i];
    if (isDynamicAbiType(type)) {
      const encoded = encodeDynamicAbi(type, value);
      heads.push(uintWord(tailOffset));
      tails.push(encoded);
      tailOffset += encoded.length / 2;
    } else {
      heads.push(encodeStaticAbi(type, value));
    }
  }
  return `${heads.join("")}${tails.join("")}`;
}

export function encodeFunctionData(signature, types, values) {
  return with0x(`${functionSelector(signature)}${encodeAbiParameters(types, values)}`);
}

function optionalBytes32(value) {
  const hex = bytesLikeToHex(value);
  return hex ? bytes32Word(hex) : zeroWord;
}

export function normalizeEvmAddress(value, label = "EVM address") {
  const hex = strip0x(value).toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(hex)) {
    throw new Error(`${label} must be 20-byte hex`);
  }
  return `0x${hex}`;
}

export function isEvmAddress(value) {
  return typeof value === "string" && /^[0-9a-f]{40}$/i.test(strip0x(value));
}

export function evmAddressToBech32(address, prefix) {
  const normalizedPrefix = normalizeBech32Prefix(prefix, "accountPrefix");
  return toBech32(normalizedPrefix, bytesFromHex(strip0x(normalizeEvmAddress(address)), "EVM address"));
}

export function bech32AddressToEvm(address, expectedPrefix) {
  const decoded = fromBech32(String(address || "").trim());
  if (expectedPrefix) {
    const normalizedPrefix = normalizeBech32Prefix(expectedPrefix, "accountPrefix");
    if (decoded.prefix !== normalizedPrefix) {
      throw new Error(`bech32 address prefix mismatch: expected ${normalizedPrefix}, got ${decoded.prefix}`);
    }
  }
  const bytes = Uint8Array.from(decoded.data);
  if (bytes.length !== 20) {
    throw new Error(`bech32 address must decode to 20 bytes for EVM precompile calls, got ${bytes.length}`);
  }
  return `0x${hexFromBytes(bytes)}`;
}

function evmAmount(coinString) {
  return parseCoin(coinString).amount;
}

function valueFrom(object, names, fallback) {
  for (const name of names) {
    if (object?.[name] != null) return object[name];
  }
  return fallback;
}

function requiredBytes(value, label, byteLength) {
  const hex = bytesLikeToHex(value, label);
  if (!hex) throw new Error(`${label} is required`);
  if (byteLength != null && hex.length !== byteLength * 2) {
    throw new Error(`${label} must be ${byteLength} bytes`);
  }
  return value;
}

function optionalBytes(value) {
  return value == null ? emptyBytes : value;
}

function bytesArray(value, label, byteLength) {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value.map((item, index) => requiredBytes(item, `${label}[${index}]`, byteLength));
}

function explicitWithdrawEvmRecipient(message) {
  const recipient = valueFrom(message, ["evmRecipient", "evm_recipient", "recipientAddress", "recipient_address"], null);
  return recipient ? normalizeEvmAddress(recipient, "withdraw recipient") : "";
}

function assertWithdrawEvmRecipientMatchesMessage(evmRecipient, messageRecipient, accountPrefix) {
  if (!evmRecipient || messageRecipient == null) return;
  const recipient = String(messageRecipient).trim();
  if (!recipient) return;
  if (isEvmAddress(recipient)) {
    const normalizedRecipient = normalizeEvmAddress(recipient, "withdraw recipient");
    if (normalizedRecipient.toLowerCase() !== evmRecipient.toLowerCase()) {
      throw new Error(`withdraw evmRecipient does not match message recipient: ${evmRecipient} does not match ${normalizedRecipient}`);
    }
    return;
  }
  const decodedRecipient = bech32AddressToEvm(recipient, accountPrefix);
  if (decodedRecipient.toLowerCase() !== evmRecipient.toLowerCase()) {
    throw new Error(`withdraw evmRecipient does not match message recipient: ${evmRecipient} does not match ${decodedRecipient}`);
  }
}

function withdrawRecipientToEvmAddress(message, options = {}) {
  const recipient = explicitWithdrawEvmRecipient(message);
  if (recipient) {
    assertWithdrawEvmRecipientMatchesMessage(recipient, valueFrom(message, ["recipient"], null), options.accountPrefix);
    return recipient;
  }
  const fallback = valueFrom(message, ["recipient"], null);
  if (isEvmAddress(fallback)) return normalizeEvmAddress(fallback, "withdraw recipient");
  return bech32AddressToEvm(fallback, options.accountPrefix);
}

function legacyWithdrawOutput(message, options = {}) {
  if (options.withdrawOutputMode === "none" || options.legacyOutputMode === "none") {
    return {
      newNoteCommitment: optionalBytes(valueFrom(message, ["newNoteCommitment", "new_note_commitment"], emptyBytes)),
      encryptedNote: optionalBytes(valueFrom(message, ["encryptedNote", "encrypted_note"], emptyBytes))
    };
  }
  return {
    newNoteCommitment: valueFrom(message, ["newNoteCommitment", "new_note_commitment"], zeroBytes32),
    encryptedNote: valueFrom(message, ["encryptedNote", "encrypted_note"], zeroBytes32)
  };
}

export function encodeReferenceEvmDeposit(message, options = {}) {
  return encodeFunctionData(
    options.signature || referenceDepositSignature,
    ["uint256", "bytes32", "bytes"],
    [
      evmAmount(message.amount),
      bytes32Word(message.noteCommitment, "note commitment"),
      message.encryptedNote
    ]
  );
}

export function encodeReferenceEvmTransfer(message, options = {}) {
  return encodeFunctionData(
    options.signature || referenceTransferSignature,
    ["bytes", "bytes32", "bytes32[]", "bytes32[]", "bytes[]", "bytes[]", "uint8", "uint8", "bytes32", "bytes32", "bytes", "bytes32", "bytes32", "bytes"],
    [
      message.proof,
      bytes32Word(message.root, "transfer root"),
      message.nullifiers,
      message.newCommitments,
      message.cipherTexts,
      bytesArray(message.viewTags, "transfer view tags", 2),
      message.userPrivacyPolicy ?? 0,
      message.userDisclosureMode ?? 0,
      optionalBytes32(message.userDisclosureDigest),
      optionalBytes32(message.userDisclosureTargetPubkey),
      message.userDisclosurePayload || new Uint8Array(),
      bytes32Word(message.auditDisclosureDigest, "audit disclosure digest"),
      bytes32Word(message.auditDisclosureTargetPubkey, "audit disclosure target pubkey"),
      message.auditDisclosurePayload
    ]
  );
}

export function encodeReferenceEvmWithdraw(message, options = {}) {
  const coin = parseCoin(message.amount);
  return encodeFunctionData(
    options.signature || referenceWithdrawSignature,
    ["bytes", "bytes32", "bytes32", "uint256", "address", "string", "uint64"],
    [
      message.proof,
      bytes32Word(message.root, "withdraw root"),
      bytes32Word(message.nullifier, "withdraw nullifier"),
      coin.amount,
      withdrawRecipientToEvmAddress(message, options),
      coin.denom,
      message.expiresAtUnix ?? 0
    ]
  );
}

export function encodeEvmPrivacyDeposit(message, options = {}) {
  const request = {
    amount: String(valueFrom(message, ["amount"], "")),
    noteCommitment: requiredBytes(valueFrom(message, ["noteCommitment", "note_commitment"], null), "note commitment", 32),
    encryptedNote: requiredBytes(valueFrom(message, ["encryptedNote", "encrypted_note"], null), "encrypted note")
  };
  return encodeFunctionData(
    options.signature || evmPrivacyDepositSignature,
    [evmPrivacyDepositTuple],
    [request]
  );
}

export function encodeEvmPrivacyTransfer(message, options = {}) {
  const hasSelfViewDisclosure = (value) => {
    if (value == null) return false;
    if (typeof value === "string") return strip0x(value).length > 0;
    return value.length > 0;
  };
  if (
    hasSelfViewDisclosure(message.selfViewDisclosureDigest ?? message.self_view_disclosure_digest)
    || hasSelfViewDisclosure(message.selfViewDisclosurePayload ?? message.self_view_disclosure_payload)
  ) {
    throw new Error("EVM privacy transfer ABI does not support self-view disclosure fields");
  }
  const request = {
    proof: requiredBytes(message.proof, "transfer proof"),
    root: requiredBytes(message.root, "transfer root", 32),
    nullifiers: bytesArray(message.nullifiers, "transfer nullifiers", 32),
    newCommitments: bytesArray(message.newCommitments, "transfer new commitments", 32),
    cipherTexts: bytesArray(message.cipherTexts, "transfer cipher texts"),
    viewTags: bytesArray(message.viewTags, "transfer view tags", 2),
    userPrivacyPolicy: message.userPrivacyPolicy ?? 0,
    userDisclosureDigest: optionalBytes(message.userDisclosureDigest),
    userDisclosureMode: message.userDisclosureMode ?? 0,
    userDisclosureTargetPubkey: optionalBytes(message.userDisclosureTargetPubkey),
    userDisclosurePayload: optionalBytes(message.userDisclosurePayload),
    auditDisclosureDigest: optionalBytes(message.auditDisclosureDigest),
    auditDisclosureTargetPubkey: optionalBytes(message.auditDisclosureTargetPubkey),
    auditDisclosurePayload: optionalBytes(message.auditDisclosurePayload)
  };
  return encodeFunctionData(
    options.signature || evmPrivacyTransferSignature,
    [evmPrivacyTransferTuple],
    [request]
  );
}

export function encodeEvmPrivacyWithdraw(message, options = {}) {
  const legacyOutput = legacyWithdrawOutput(message, options);
  const request = {
    proof: requiredBytes(message.proof, "withdraw proof"),
    root: requiredBytes(message.root, "withdraw root", 32),
    nullifier: requiredBytes(message.nullifier, "withdraw nullifier", 32),
    newNoteCommitment: legacyOutput.newNoteCommitment,
    encryptedNote: legacyOutput.encryptedNote,
    amount: String(message.amount || ""),
    recipient: withdrawRecipientToEvmAddress(message, options),
    chainId: String(message.chainId ?? message.chain_id ?? options.chainId ?? ""),
    expiresAtUnix: message.expiresAtUnix ?? message.expires_at_unix ?? 0
  };
  return encodeFunctionData(
    options.signature || evmPrivacyWithdrawSignature,
    [evmPrivacyWithdrawTuple],
    [request]
  );
}

export function defaultEncodeEvmDeposit(message, options = {}) {
  return encodeEvmPrivacyDeposit(message, options);
}

export function defaultEncodeEvmTransfer(message, options = {}) {
  return encodeEvmPrivacyTransfer(message, options);
}

export function defaultEncodeEvmWithdraw(message, options = {}) {
  return encodeEvmPrivacyWithdraw(message, options);
}

export function createEip1193WalletAdapter({ provider, account } = {}) {
  if (!provider?.request) {
    throw new Error("EIP-1193 provider with request({ method, params }) is required");
  }
  async function accounts() {
    const resolved = account
      ? [account]
      : await provider.request({ method: "eth_requestAccounts", params: [] });
    if (!Array.isArray(resolved) || !resolved[0]) {
      throw new Error("EVM wallet returned no accounts");
    }
    return resolved.map(item => normalizeEvmAddress(item));
  }
  return {
    async getAddress() {
      return (await accounts())[0];
    },
    async signPrivacyRoot(messageBytes) {
      const address = await this.getAddress();
      const messageHex = with0x(hexFromBytes(messageBytes));
      const signature = await provider.request({
        method: "personal_sign",
        params: [messageHex, address]
      });
      if (typeof signature !== "string" || !/^0x[0-9a-fA-F]+$/.test(signature)) {
        throw new Error("EVM wallet personal_sign must return a 0x-prefixed hex signature");
      }
      return signature;
    },
    async sendTransaction(transaction) {
      const from = transaction.from ? normalizeEvmAddress(transaction.from, "transaction from") : await this.getAddress();
      return provider.request({
        method: "eth_sendTransaction",
        params: [{ ...transaction, from }]
      });
    },
    async call(transaction, blockTag = "latest") {
      return provider.request({
        method: "eth_call",
        params: [transaction, blockTag]
      });
    },
    async getLogs(filter) {
      return provider.request({
        method: "eth_getLogs",
        params: [filter]
      });
    }
  };
}

export function createEvmContractAdapter({
  contractAddress = defaultEvmPrivacyPrecompileAddress,
  encodeDeposit = defaultEncodeEvmDeposit,
  encodeTransfer = defaultEncodeEvmTransfer,
  encodeWithdraw = defaultEncodeEvmWithdraw,
  accountPrefix,
  chainId,
  withdrawOutputMode
} = {}) {
  const to = normalizeEvmAddress(contractAddress, "contractAddress");
  return {
    contractAddress: to,
    abi: evmPrivacyPrecompileAbi,
    buildDepositTransaction(message, options = {}) {
      return {
        to,
        data: encodeDeposit(message, { accountPrefix, chainId, withdrawOutputMode, ...options }),
        value: options.value ?? "0x0"
      };
    },
    buildTransferTransaction(message, options = {}) {
      return {
        to,
        data: encodeTransfer(message, { accountPrefix, chainId, withdrawOutputMode, ...options }),
        value: options.value ?? "0x0"
      };
    },
    buildWithdrawTransaction(message, options = {}) {
      return {
        to,
        data: encodeWithdraw(message, { accountPrefix, chainId, withdrawOutputMode, ...options }),
        value: options.value ?? "0x0"
      };
    }
  };
}

export function createEvmPrivacyPrecompileAdapter(options = {}) {
  return createEvmContractAdapter({
    contractAddress: options.contractAddress ?? evmPrivacyPrecompileAddress,
    accountPrefix: options.accountPrefix,
    chainId: options.chainId,
    withdrawOutputMode: options.withdrawOutputMode ?? "legacy-zero",
    encodeDeposit: options.encodeDeposit ?? encodeEvmPrivacyDeposit,
    encodeTransfer: options.encodeTransfer ?? encodeEvmPrivacyTransfer,
    encodeWithdraw: options.encodeWithdraw ?? encodeEvmPrivacyWithdraw
  });
}

function publicPrivacyAccount(material) {
  return {
    address: material.address,
    pubKeyHex: material.pubKeyHex,
    signing_message: material.signingMessage,
    shielded_address: material.shieldedAddress,
    disclosure_pubkey_hex: material.disclosurePubKeyHex,
    root_signature_hash: material.rootSignatureHash
  };
}

export class ClairveilEvmClient {
  constructor({
    provider,
    contractAddress = defaultEvmPrivacyPrecompileAddress,
    chainId,
    accountPrefix,
    bech32Prefix,
    shieldedPrefix = defaultShieldedPrefix,
    defaultDenom = "uclair",
    withdrawOutputMode = "legacy-zero",
    contractAdapter
  } = {}) {
    this.provider = provider;
    this.chainId = chainId;
    this.accountPrefix = normalizeBech32Prefix(accountPrefix ?? bech32Prefix ?? "clair", "accountPrefix");
    this.bech32Prefix = this.accountPrefix;
    this.shieldedPrefix = normalizeBech32Prefix(shieldedPrefix, "shieldedPrefix");
    this.defaultDenom = String(defaultDenom || "uclair");
    this.withdrawOutputMode = withdrawOutputMode;
    this.contract = contractAdapter || createEvmPrivacyPrecompileAdapter({
      contractAddress,
      accountPrefix: this.accountPrefix,
      chainId,
      withdrawOutputMode
    });
  }

  buildDepositMaterial(input) {
    return buildDepositMaterial({
      assetDenom: input?.assetDenom ?? input?.denom ?? this.defaultDenom,
      shieldedPrefix: this.shieldedPrefix,
      ...input
    });
  }

  buildDepositTransaction(input = {}) {
    if (input.message) {
      return {
        status: "ready",
        message: input.message,
        transaction: this.contract.buildDepositTransaction(input.message, input.transactionOptions)
      };
    }
    const material = input.material || input.depositMaterial || input.deposit_material || this.buildDepositMaterial(input);
    const expectedCreator = String(input.creator || "").trim();
    if (expectedCreator && String(material.creator || "").trim() !== expectedCreator) {
      throw new Error(`deposit material creator mismatch: expected ${expectedCreator}, got ${material.creator || ""}`);
    }
    const expectedAmount = input.amount == null
      ? ""
      : parseCoin(input.amount, input.assetDenom ?? input.denom ?? this.defaultDenom).raw;
    if (expectedAmount && String(material.amount || "").trim() !== expectedAmount) {
      throw new Error(`deposit material amount mismatch: expected ${expectedAmount}, got ${material.amount || ""}`);
    }
    const message = input.message || {
      amount: material.amount,
      noteCommitment: material.note_commitment,
      encryptedNote: material.encrypted_note
    };
    return {
      status: "ready",
      material,
      message,
      transaction: this.contract.buildDepositTransaction(message, input.transactionOptions)
    };
  }

  async buildTransferTransaction(input = {}) {
    const built = input.message
      ? { message: input.message, payload: input.payload, proof: input.proof }
      : await buildTransferMessage({
        shieldedPrefix: this.shieldedPrefix,
        transferDenom: input.transferDenom ?? input.denom ?? this.defaultDenom,
        ...input,
        disableSelfViewDisclosure: input.disableSelfViewDisclosure ?? true
      });
    return {
      status: "ready",
      ...built,
      transaction: this.contract.buildTransferTransaction(built.message, input.transactionOptions)
    };
  }

  async buildPreparedTransferPayload(input = {}) {
    return buildPreparedTransferPayload({
      shieldedPrefix: this.shieldedPrefix,
      transferDenom: input.transferDenom ?? input.denom ?? this.defaultDenom,
      ...input,
      disableSelfViewDisclosure: input.disableSelfViewDisclosure ?? true
    });
  }

  async buildPreparedWithdrawProverPayload(input = {}) {
    const recipient = isEvmAddress(input.recipient)
      ? evmAddressToBech32(input.recipient, input.accountPrefix ?? this.accountPrefix)
      : input.recipient;
    return buildPreparedWithdrawProverPayload({
      assetDenom: input.assetDenom ?? input.denom ?? this.defaultDenom,
      ...input,
      recipient,
      accountPrefix: input.accountPrefix ?? this.accountPrefix,
      chainId: input.chainId ?? this.chainId
    });
  }

  async buildWithdrawTransaction(input = {}) {
    const accountPrefix = input.accountPrefix ?? this.accountPrefix;
    const evmRecipient = input.evmRecipient
      ?? input.evm_recipient
      ?? (isEvmAddress(input.recipient) ? normalizeEvmAddress(input.recipient, "withdraw recipient") : undefined);
    const recipient = evmRecipient
      ? evmAddressToBech32(evmRecipient, accountPrefix)
      : input.recipient;
    let built;
    if (input.message) {
      built = {
        message: input.message,
        payload: input.payload,
        proof: input.proof,
        proverPayload: input.proverPayload,
        selectedNote: input.selectedNote
      };
    } else if (input.payload) {
      const expectedRecipientInput = input.expectedRecipient
        ?? input.expected_recipient
        ?? (input.recipient == null ? undefined : recipient);
      const expectedRecipient = isEvmAddress(expectedRecipientInput)
        ? evmAddressToBech32(expectedRecipientInput, accountPrefix)
        : expectedRecipientInput;
      const expectedChainId = input.expectedChainId
        ?? input.expected_chain_id
        ?? input.chainId
        ?? input.chain_id
        ?? this.chainId;
      if (!String(expectedChainId ?? "").trim()) {
        throw new Error("expectedChainId is required for relay withdraw payload validation");
      }
      validateRelayWithdrawPayload(input.payload, {
        nowUnix: input.nowUnix ?? input.now_unix,
        expectedChainId,
        expectedRecipient,
        accountPrefix
      });
      built = {
        message: buildWithdrawMsgFromPayload(
          input.payload,
          input.relayer ?? input.creator ?? input.address ?? "",
          input.nowUnix ?? input.now_unix
        ),
        payload: input.payload,
        proof: input.proof,
        proverPayload: input.proverPayload,
        selectedNote: input.selectedNote
      };
    } else {
      built = await buildWithdrawMessage({
        assetDenom: input.assetDenom ?? input.denom ?? this.defaultDenom,
        ...input,
        recipient,
        accountPrefix,
        chainId: input.chainId ?? this.chainId
      });
    }
    const candidateMessage = evmRecipient
      ? { ...built.message, evmRecipient }
      : built.message;
    const messageEvmRecipient = explicitWithdrawEvmRecipient(candidateMessage);
    assertWithdrawEvmRecipientMatchesMessage(messageEvmRecipient, candidateMessage?.recipient, accountPrefix);
    const message = messageEvmRecipient
      ? { ...candidateMessage, evmRecipient: messageEvmRecipient }
      : candidateMessage;
    return {
      status: "ready",
      ...built,
      message,
      transaction: this.contract.buildWithdrawTransaction(message, input.transactionOptions)
    };
  }

  async sendTransaction(wallet, transaction) {
    if (wallet?.sendTransaction) {
      return wallet.sendTransaction(transaction);
    }
    const adapter = createEip1193WalletAdapter({ provider: this.provider });
    return adapter.sendTransaction(transaction);
  }

  privacyAccount(material) {
    return publicPrivacyAccount(material);
  }
}

export function createClairveilEvmClient(options) {
  return new ClairveilEvmClient(options);
}
