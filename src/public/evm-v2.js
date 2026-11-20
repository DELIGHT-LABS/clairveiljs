import { encodeFunctionData, functionSelector, encodeAbiParameters } from "./evm-abi.js";
import { toHex, fromHex, toBech32 } from "@cosmjs/encoding";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { evmPrivacyV2Abi as definition } from "./evm-v2-abi.js";
import { unsignedInteger } from "./encoding.js";

function freeze(value) {
  if (value && typeof value === "object") {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}
export const evmPrivacyV2Abi = freeze(definition);
function signatureType(parameter) {
  return parameter.type.startsWith("tuple")
    ? `(${parameter.components.map(signatureType).join(",")})${parameter.type.slice(5)}`
    : parameter.type;
}
function wireValue(parameter, value, label) {
  const { type } = parameter;
  if (type.endsWith("[]")) {
    if (!Array.isArray(value) || value.length !== 2) throw new Error(`${label} requires two values`);
    return value.map((v, i) => wireValue({...parameter, type:type.slice(0,-2)}, v, `${label}[${i}]`));
  }
  if (type === "tuple") {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} object required`);
    const names = parameter.components.map(p => p.name);
    if (Object.keys(value).some(k => !names.includes(k))) throw new Error(`${label} contains unsupported fields`);
    return Object.fromEntries(parameter.components.map(p => [p.name, wireValue(p, value[p.name], `${label}.${p.name}`)]));
  }
  if (type === "bytes") {
    if (!(value instanceof Uint8Array) || value.length > 4096) throw new Error(`${label} requires bounded bytes`);
    return Uint8Array.from(value);
  }
  if (type.startsWith("uint")) {
    const max = label.endsWith(".expiresAtUnix") ? (1n<<63n)-1n : (1n<<BigInt(type.slice(4)))-1n;
    // Protobuf represents uint32 enums as numbers and uint64 fields as bigint.
    const integer = type === "uint32" && Number.isSafeInteger(value) ? BigInt(value) : value;
    return unsignedInteger(integer, `${label} integer`, max);
  }
  if (type === "address") {
    if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value)) throw new Error(`${label} requires an EVM address`);
    return value.toLowerCase();
  }
  if (type === "string" && typeof value === "string" && value.length <= 256) return value;
  throw new Error(`${label} has an unsupported value`);
}

/** Wire encoding only. The caller must verify the proof and bind actor, chain,
 * contract and exact payable deposit value before requesting a signature. */
export function encodeEvmPrivacyRequestV2(kind, request) {
  const method = evmPrivacyV2Abi.find(p => p.name === kind);
  if (!method) throw new Error("unsupported direct V2 operation");
  const input = method.inputs[0];
  return encodeFunctionData(`${kind}(${signatureType(input)})`, [input], [wireValue(input, request, kind)]);
}

/** Bounded canonical decoder. Re-encoding rejects aliases, overlap and padding. */
export function decodeEvmPrivacyRequestV2(kind, calldata) {
  const method = evmPrivacyV2Abi.find(p => p.name === kind);
  if (!method || typeof calldata !== "string" || calldata.length > 65536 || !/^0x(?:[0-9a-f]{2})+$/.test(calldata)) throw new Error("invalid V2 calldata");
  const input = method.inputs[0], signature = `${kind}(${signatureType(input)})`;
  if (calldata.slice(2,10) !== functionSelector(signature)) throw new Error("V2 selector mismatch");
  const bytes = calldata.slice(10), size = bytes.length / 2;
  function word(offset) {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset + 32 > size) throw new Error("V2 ABI bounds");
    return BigInt(`0x${bytes.slice(offset*2,offset*2+64)}`);
  }
  const dynamic = p => p.type === "tuple" || p.type === "bytes" || p.type === "string" || p.type.endsWith("[]");
  function tuple(parameters, base) {
    return parameters.map((p,i) => {
      const slot = base+i*32;
      if (!dynamic(p)) return value(p,slot);
      const offset = word(slot);
      if (offset % 32n || offset > BigInt(size)) throw new Error("V2 ABI offset");
      return value(p,base+Number(offset));
    });
  }
  function value(p,start) {
    if (p.type === "tuple") return Object.fromEntries(tuple(p.components,start).map((v,i)=>[p.components[i].name,v]));
    if (p.type.endsWith("[]")) {
      if (word(start) !== 2n) throw new Error("V2 ABI arity");
      return tuple(Array(2).fill({...p,type:p.type.slice(0,-2)}),start+32);
    }
    if (p.type === "bytes" || p.type === "string") {
      const length = word(start);
      if (length > 4096n || start+32+Number(length) > size) throw new Error("V2 ABI length");
      const result = Uint8Array.from(bytes.slice((start+32)*2,(start+32+Number(length))*2).match(/../g)??[],x=>parseInt(x,16));
      return p.type === "bytes" ? result : new TextDecoder("utf-8",{fatal:true}).decode(result);
    }
    const n = word(start);
    if (p.type === "address") { if (n >= 1n<<160n) throw new Error("V2 ABI address"); return `0x${n.toString(16).padStart(40,"0")}`; }
    if (p.type.startsWith("uint")) { if (n >= 1n<<BigInt(p.type.slice(4))) throw new Error("V2 ABI integer"); return p.type === "uint32" ? Number(n) : n; }
    throw new Error("V2 ABI type");
  }
  const request = tuple([input],0)[0];
  if (encodeEvmPrivacyRequestV2(kind,request) !== calldata) throw new Error("noncanonical V2 ABI");
  return request;
}

/** Exact direct-call identity and successful action event; finality is separate. */
export function verifyEvmEffectV2({ kind, request, creator, accountPrefix, amount, transaction, rpcTransaction, receipt, txHash }) {
  if (!/^0x[0-9a-f]{64}$/.test(txHash) || !transaction || !rpcTransaction) throw new Error("V2 transaction identity required");
  const tx=transaction,rpc=rpcTransaction;
  if (!/^0x[0-9a-f]{40}$/.test(tx.from) || !/^0x[0-9a-f]{40}$/.test(tx.to) || toBech32(accountPrefix,fromHex(tx.from.slice(2)))!==creator
    || rpc.hash!==txHash || rpc.from?.toLowerCase()!==tx.from || rpc.to?.toLowerCase()!==tx.to || rpc.chainId!==tx.chainId
    || rpc.input!==undefined && rpc.data!==undefined && rpc.input!==rpc.data
    || (rpc.input??rpc.data)!==tx.data || rpc.value!==tx.value || tx.data!==encodeEvmPrivacyRequestV2(kind,request)) throw new Error("V2 transaction mismatch");
  const coin=/^(0|[1-9][0-9]*)([A-Za-z][A-Za-z0-9/:._-]{2,127})$/.exec(amount??"");
  if(kind==='deposit' ? !coin || tx.value!==`0x${BigInt(coin[1]).toString(16)}` : tx.value!=='0x0')throw new Error("V2 transaction value mismatch");
  if(!receipt)return true;
  if(receipt.status!=='0x1' || receipt.transactionHash!==txHash || receipt.from?.toLowerCase()!==tx.from || receipt.to?.toLowerCase()!==tx.to || !Array.isArray(receipt.logs))throw new Error("V2 receipt failed");
  const topic = address => '0x'+address.slice(2).padStart(64,'0');
  const event = kind==='deposit'?'PrivacyDeposit(address,address,string,bytes)':kind==='transfer'?'PrivacyTransfer(address,address,bytes)':'PrivacyWithdraw(address,address,address,string)';
  const topic0='0x'+toHex(keccak_256(new TextEncoder().encode(event)));
  const topics=[topic0,topic(tx.from),topic(tx.from),...(kind==='withdraw'?[topic(request.recipient)]:[])];
  const data='0x'+(kind==='deposit'?encodeAbiParameters(['string','bytes'],[amount,request.output.commitment]):kind==='transfer'?encodeAbiParameters(['bytes'],[request.root]):encodeAbiParameters(['string'],[request.amount]));
  const logs=receipt.logs.filter(log=>log?.address?.toLowerCase()===tx.to && log.topics?.[0]===topic0);
  if(logs.length!==1 || JSON.stringify(logs[0].topics)!==JSON.stringify(topics) || logs[0].data!==data || logs[0].removed!==false
    || logs[0].transactionHash!==txHash || logs[0].blockHash!==receipt.blockHash || logs[0].blockNumber!==receipt.blockNumber || logs[0].transactionIndex!==receipt.transactionIndex)throw new Error("V2 receipt effect mismatch");
  return true;
}
