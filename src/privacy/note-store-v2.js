import { normalizeFoundNote128 } from "../core/note128.js";
import { canonicalFieldHex } from "../core/crypto.js";
import { base64FromBytes,bytesFromBase64 } from "../core/browser-crypto.js";
import { marshalNotePlaintextV2,unmarshalNotePlaintextV2,computeNoteCommitmentV2,computeNoteNullifierV2 } from "./protocol-v2.js";
export const privacyNoteCacheStateVersionV2="privacy-audit-note-cache-v2";
const keys=["version","plaintext","commitment","nullifier","nullifierStatus","isSpent","txHash","height","sequence"].sort().join(",");
/** PRIVATE storage representation. The host must encrypt it before persistence. */
export function serializeFoundNoteV2(input) {
  const found=normalizeFoundNote128(input), plaintext=marshalNotePlaintextV2(found.note);
  try {
    const nullifier=canonicalFieldHex(computeNoteNullifierV2(found.note));
    if(found.nullifier!==nullifier)throw new Error("stored V2 nullifier mismatch");
    return {version:privacyNoteCacheStateVersionV2,plaintext:base64FromBytes(plaintext),commitment:canonicalFieldHex(computeNoteCommitmentV2(found.note)),
      nullifier,nullifierStatus:found.nullifierStatus,isSpent:found.isSpent,txHash:found.txHash,height:found.height,sequence:found.sequence};
  } finally {plaintext.fill(0);}
}
export function deserializeFoundNoteV2(input) {
  if(!input||typeof input!=="object"||Object.keys(input).sort().join(",")!==keys||input.version!==privacyNoteCacheStateVersionV2||typeof input.plaintext!=="string")throw new Error("V2 note cache identity required; rescan incompatible data");
  const plaintext=bytesFromBase64(input.plaintext);
  try {
    if(base64FromBytes(plaintext)!==input.plaintext)throw new Error("noncanonical V2 note cache");
    const note=unmarshalNotePlaintextV2(plaintext),found=normalizeFoundNote128({note,nullifier:input.nullifier,nullifierStatus:input.nullifierStatus,isSpent:input.isSpent,txHash:input.txHash,height:input.height,sequence:input.sequence});
    const canonical=serializeFoundNoteV2(found);
    if(Object.keys(canonical).some(k=>canonical[k]!==input[k]))throw new Error("V2 note cache binding mismatch");
    return found;
  } finally {plaintext.fill(0);}
}
export function isVerifiedUnspentFoundNoteV2(input) {
  const found=deserializeFoundNoteV2(serializeFoundNoteV2(input));
  return found.nullifierStatus==="unspent"&&!found.isSpent;
}
