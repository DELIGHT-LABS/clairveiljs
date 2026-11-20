import { keccak_256 } from "@noble/hashes/sha3.js";
import { normalizeHex, hexFromBytes } from "./encoding.js";
const keccak256 = value => hexFromBytes(keccak_256(new TextEncoder().encode(value)));

export function strip0x(value) {
  return String(value || "").trim().replace(/^0x/i, "");
}

export function with0x(hex) {
  return `0x${strip0x(hex).toLowerCase()}`;
}

export function bytesLikeToHex(value, label = "bytes") {
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

export function bytes32Word(value, label = "bytes32") {
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
  if (name === "bool") {
    if (typeof value !== "boolean") {
      throw new Error("bool ABI value must be a boolean");
    }
    return uintWord(value ? 1 : 0, 8);
  }
  if (name === "address") return addressWord(value);
  if (name === "bytes32") return bytes32Word(value);
  throw new Error(`unsupported static ABI type ${name}`);
}

function encodeBytes(hex) {
  const clean = strip0x(hex);
  return `${uintWord(clean.length / 2)}${padRightWord(clean)}`;
}

function arrayElementAbiType(type) {
  const name = abiTypeName(type);
  if (!name.endsWith("[]")) throw new Error(`ABI type ${name} is not an array`);
  const elementName = name.slice(0, -2);
  return elementName === "tuple"
    ? { type: "tuple", components: abiComponents(type) }
    : elementName;
}

function encodeDynamicArray(type, value) {
  if (!Array.isArray(value)) {
    throw new Error(`${abiTypeName(type)} value must be an array`);
  }
  const elementType = arrayElementAbiType(type);
  const encodedItems = value.map(item => isDynamicAbiType(elementType)
    ? encodeDynamicAbi(elementType, item)
    : encodeStaticAbi(elementType, item));
  if (!isDynamicAbiType(elementType)) {
    return `${uintWord(value.length)}${encodedItems.join("")}`;
  }
  const heads = [];
  let offset = 32 * value.length;
  for (const encoded of encodedItems) {
    heads.push(uintWord(offset));
    offset += encoded.length / 2;
  }
  return `${uintWord(value.length)}${heads.join("")}${encodedItems.join("")}`;
}

function encodeDynamicAbi(type, value) {
  const name = abiTypeName(type);
  if (name === "tuple") return encodeTupleAbi(type, value);
  if (name === "bytes") return encodeBytes(bytesLikeToHex(value));
  if (name === "string") return encodeBytes(utf8Hex(value));
  if (name.endsWith("[]")) return encodeDynamicArray(type, value);
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
