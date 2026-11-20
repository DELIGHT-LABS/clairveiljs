import { toBase64, toBech32, fromBech32, fromHex, toHex } from "@cosmjs/encoding";
import { encodePubkey, makeAuthInfoBytes } from "@cosmjs/proto-signing";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { MsgDeposit, MsgTransfer, MsgWithdraw } from "../generated/clairveil/privacy/v2/tx.js";
import { createClairveilV2Registry } from "./cosmos-v2.js";
import { buildAuditPublicInputsV2 } from "../privacy/audit-authorization-v2.js";
import { encodeEvmPrivacyRequestV2 } from "./evm-v2.js";
import { unsignedInteger } from "../core/encoding.js";

const codecs = { deposit: MsgDeposit, transfer: MsgTransfer, withdraw: MsgWithdraw };
const kinds = { deposit: 1, transfer: 3, withdraw: 2 };
const u64 = value => unsignedInteger(value,"uint64",(1n<<64n)-1n);

/** Public message validation only. Call after actual proof verification. */
export function validateDirectAuditMessageV2({ kind, message, snapshot }) {
  const codec = codecs[kind];
  if (!codec || !(message?.proof instanceof Uint8Array) || message.proof.length !== 164) throw new Error("direct V2 message/proof required");
  buildAuditPublicInputsV2({ kind: kinds[kind], message, snapshot });
  if (message.expiresAtUnix <= 0n) throw new Error("V2 expiry required");
  return codec.decode(codec.encode(message).finish());
}

/** No queries, signing or broadcast. All network/account facts are caller-pinned. */
export function buildCosmosTransactionV2(input) {
  const { kind, snapshot, actor, accountNumber, sequence, gasLimit, feeAmount = [], memo = "" } = input;
  const message = validateDirectAuditMessageV2(input);
  if (actor?.namespace !== "cosmos" || actor.chainId !== snapshot.chainId || actor.address !== message.creator || typeof actor.pubKeyHex !== "string" || !/^(02|03)[0-9a-f]{64}$/.test(actor.pubKeyHex)) throw new Error("V2 Cosmos actor mismatch");
  const key = fromHex(actor.pubKeyHex); secp256k1.Point.fromBytes(key).assertValidity();
  if (toBech32(snapshot.accountPrefix,ripemd160(sha256(key))) !== actor.address) throw new Error("V2 Cosmos signer mismatch");
  if (!Number.isSafeInteger(gasLimit) || gasLimit < 1 || typeof memo !== "string" || new TextEncoder().encode(memo).length > 256 || !Array.isArray(feeAmount) || feeAmount.length > 8) throw new Error("V2 Cosmos transaction options");
  const coins = feeAmount.map(c => {
    if (!c || Object.keys(c).sort().join() !== "amount,denom" || typeof c.amount !== "string" || !/^(0|[1-9][0-9]{0,77})$/.test(c.amount) || typeof c.denom !== "string" || !/^[A-Za-z][A-Za-z0-9/:._-]{2,127}$/.test(c.denom)) throw new Error("V2 fee coin");
    return { amount:c.amount, denom:c.denom };
  }).sort((a,b)=>a.denom.localeCompare(b.denom));
  if (new Set(coins.map(c=>c.denom)).size !== coins.length) throw new Error("V2 duplicate fee");
  const body = createClairveilV2Registry().encodeTxBody({ messages:[{ typeUrl:codecs[kind].typeUrl,value:message }],memo });
  const pubkey = encodePubkey({ type:"tendermint/PubKeySecp256k1",value:toBase64(key) });
  const auth = makeAuthInfoBytes([{pubkey,sequence:u64(sequence)}],coins,gasLimit);
  return { message, signDoc:{ bodyBytes:toBase64(body), authInfoBytes:toBase64(auth), chainId:snapshot.chainId, accountNumber:String(u64(accountNumber)) } };
}

export function evmRequestFromMessageV2(kind, message, accountPrefix) {
  if (!codecs[kind] || !message || typeof accountPrefix !== "string") throw new Error("V2 request input");
  const { creator: _creator, ...request } = message;
  if (kind === "deposit") delete request.amount;
  if (kind === "withdraw") {
    const decoded = fromBech32(request.recipient,255);
    if (decoded.prefix !== accountPrefix || decoded.data.length !== 20 || toBech32(accountPrefix,decoded.data) !== request.recipient) throw new Error("V2 EVM recipient mismatch");
    request.recipient = `0x${toHex(decoded.data)}`;
  }
  return request;
}

/** Native deposit value is bound to the exact amount/denom and selected actor. */
export function buildEvmTransactionV2(input) {
  const { kind, snapshot, actor, nativeDenom, contractAddress, transactionOptions } = input;
  const message = validateDirectAuditMessageV2(input), tx = structuredClone(transactionOptions);
  if (actor?.namespace !== "eip155" || !/^0x[0-9a-f]{40}$/.test(actor.address) || !/^0x[0-9a-f]{40}$/.test(contractAddress)
    || toBech32(snapshot.accountPrefix,fromHex(actor.address.slice(2))) !== message.creator) throw new Error("V2 EVM actor mismatch");
  const fields = ["from","to","chainId","gas","nonce","maxFeePerGas","maxPriorityFeePerGas"];
  if (!tx || Object.keys(tx).sort().join() !== fields.sort().join() || tx.from !== actor.address || tx.to !== contractAddress || tx.chainId !== actor.chainId) throw new Error("V2 EVM options mismatch");
  for (const f of fields.filter(f=>f!=="from"&&f!=="to")) if (typeof tx[f] !== "string" || !/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$/.test(tx[f])) throw new Error("V2 EVM quantity");
  if (BigInt(tx.gas) === 0n || BigInt(tx.chainId) === 0n || BigInt(tx.maxPriorityFeePerGas) > BigInt(tx.maxFeePerGas)) throw new Error("V2 EVM gas/fees");
  let value = "0x0";
  if (kind === "deposit") {
    const match = /^(0|[1-9][0-9]*)([A-Za-z][A-Za-z0-9/:._-]{2,127})$/.exec(message.amount);
    if (!match || match[2] !== nativeDenom) throw new Error("V2 native denom mismatch");
    value = `0x${BigInt(match[1]).toString(16)}`;
  }
  const request = evmRequestFromMessageV2(kind,message,snapshot.accountPrefix);
  return { message, transaction:{...tx,data:encodeEvmPrivacyRequestV2(kind,request),value} };
}
