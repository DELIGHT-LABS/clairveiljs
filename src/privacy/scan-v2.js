import { createPrivacyScanEngine } from "./scan-engine.js";
import { normalizeFoundNote128 } from "../core/note128.js";
import { canonicalFieldHex, deriveSpendKeys, deriveViewKeys } from "../core/crypto.js";
import { bytesFromHex } from "../core/browser-crypto.js";
import { computeNoteCommitmentV2,computeNoteNullifierV2,decryptDepositNoteV2,decryptTransferNoteV2,
  encryptedEnvelopeKindV2,privacyFixedV2,unwrapEncryptedEnvelopeV2,unmarshalNotePlaintextV2 } from "./protocol-v2.js";
import { auditCircuitSetIdV2 } from "./audit-circuit-v2.js";
import { counts } from "./audit-field-v2.js";
import { validateAuditPublicKeyV2 } from "./audit-key-v2.js";
import { createAuditOutputEffectV2 } from "./audit-authorization-v2.js";

const kinds={deposit:1,withdraw:2,shielded_transfer:3,batch_transfer:4};
const modes={USER_DISCLOSURE_MODE_NONE:0,USER_DISCLOSURE_MODE_PUBLIC:1,USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED:2};
function validateSummary(summary) {
  const kind=kinds[summary.event_type];
  if(!Object.hasOwn(kinds,summary.event_type)||BigInt(summary.audit_key_epoch)===0n||summary.effect_id.length!==32||!/^[0-9a-f]{64}$/.test(summary.audit_key_id))throw new Error("invalid audit scan summary identity");
  validateAuditPublicKeyV2(summary.audit_target_pubkey,bytesFromHex(summary.audit_key_id));
  counts(kind,summary.nullifiers.length,summary.output_count);
}
function validateOutput(o) {
  const kind=kinds[o.event_type],direct=kind===1||(kind===3&&o.output_index===1);
  if(o.audit_disclosure_payload.length)throw new Error("audit output carries retired audit ciphertext");
  if((kind===1&&o.ciphertext.length)||(kind!==1&&o.encrypted_note.length))throw new Error("audit recovery ciphertext sentinel mismatch");
  let mode=0;
  if(direct){if(o.user_disclosure_mode!=="")throw new Error("direct output disclosure sentinel mismatch");}
  else {if(!Object.hasOwn(modes,o.user_disclosure_mode))throw new Error("invalid audit scan disclosure mode");mode=modes[o.user_disclosure_mode];}
  createAuditOutputEffectV2(kind,o.output_index,{commitment:o.commitment,ciphertext:kind===1?o.encrypted_note:o.ciphertext,viewTag:o.view_tag,
    userPrivacyPolicy:o.user_privacy_policy,userDisclosureMode:mode,userDisclosureDigest:o.user_disclosure_digest,
    userDisclosureTargetPubkey:o.user_disclosure_target_pubkey,userDisclosurePayload:o.user_disclosure_payload,
    selfFullDisclosureDigest:o.full_disclosure_digest,selfViewDisclosurePayload:o.self_view_disclosure_payload});
}
function ownsNote(note,rootSeed) {
  const spend=deriveSpendKeys(rootSeed),view=deriveViewKeys(rootSeed);
  try{return note.receiverSpendPubKeyX===spend.pubKey.x&&note.receiverSpendPubKeyY===spend.pubKey.y&&note.receiverViewPubKeyX===view.pubKey.x&&note.receiverViewPubKeyY===view.pubKey.y;}
  finally{for(const key of [spend,view]){key.seed.fill(0);key.scalar=0n;key.scalarHex="";}}
}
const engine=createPrivacyScanEngine({normalizeFoundNote:normalizeFoundNote128,circuitSetId:auditCircuitSetIdV2,payloadVersion:privacyFixedV2,
  computeNoteCommitment:computeNoteCommitmentV2,computeNoteNullifier:computeNoteNullifierV2,decryptDepositNote:decryptDepositNoteV2,decryptTransferNote:decryptTransferNoteV2,
  encryptedEnvelopeKind:encryptedEnvelopeKindV2,fieldHex:canonicalFieldHex,unwrapEncryptedEnvelope:unwrapEncryptedEnvelopeV2,unmarshalNotePlaintext:unmarshalNotePlaintextV2,
  validateSummary,validateOutput,ownsNote,allowLegacyEvents:false,requireFreshNullifiers:true,validationStateVersion:"privacy-audit-scan-validation-v2"});
export const {privacyScanSchemaVersionV2,privacyScanEventTypeV2,privacyScanValidationStateVersionV2,parseNullifierUsage,parseNoteBytes,processPrivacyEvent,
  normalizeFoundNotes,isValidatedPrivacyScanOutputV2,createPrivacyScanValidationStateV2,serializePrivacyScanValidationStateV2,restorePrivacyScanValidationStateV2,
  validatePrivacyScanPageV2,processPrivacyScanOutputV2,processPrivacyScanPageV2,scanNotes}=engine;
