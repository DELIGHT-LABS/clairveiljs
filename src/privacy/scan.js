import { normalizeFoundNote } from "../core/note.js";
import { activeCircuitSetIdV1, privacyFixedV1, computeNoteCommitmentV1, computeNoteNullifierV1,
  decryptDepositNoteV1, decryptTransferNoteV1, encryptedEnvelopeKindV1, fieldHexV1,
  unwrapEncryptedEnvelopeV1, unmarshalNotePlaintextV1 } from "./protocol-v1.js";
import { createPrivacyScanEngine } from "./scan-engine.js";
const engine=createPrivacyScanEngine({ normalizeFoundNote, circuitSetId:activeCircuitSetIdV1, payloadVersion:privacyFixedV1,
  computeNoteCommitment:computeNoteCommitmentV1, computeNoteNullifier:computeNoteNullifierV1,
  decryptDepositNote:decryptDepositNoteV1, decryptTransferNote:decryptTransferNoteV1,
  encryptedEnvelopeKind:encryptedEnvelopeKindV1, fieldHex:fieldHexV1,
  unwrapEncryptedEnvelope:unwrapEncryptedEnvelopeV1, unmarshalNotePlaintext:unmarshalNotePlaintextV1 });
export const {privacyScanSchemaVersionV2, privacyScanEventTypeV2, privacyScanValidationStateVersionV2, parseNullifierUsage, parseNoteBytes, processPrivacyEvent, normalizeFoundNotes, isValidatedPrivacyScanOutputV2, createPrivacyScanValidationStateV2, serializePrivacyScanValidationStateV2, restorePrivacyScanValidationStateV2, validatePrivacyScanPageV2, processPrivacyScanOutputV2, processPrivacyScanPageV2, scanNotes}=engine;
