import { canonicalFieldHex, encodeShieldedAddress } from './crypto.js';
import { hexFromBytes } from './browser-crypto.js';
import { isValidatedPrivacyScanOutputV2 } from '../privacy/scan-v2.js';
import { computeAssetId } from '../privacy/protocol-domain.js';
import { canonicalAssetDenomV1 } from '../privacy/asset-registry.js';
import { unmarshalDisclosurePlaintextV2, decryptDisclosureV2, verifyDisclosureDigestV2,
  encryptedEnvelopeKindV2 } from '../privacy/protocol-v2.js';

const policyLabels = ['all-private', 'amount', 'to', 'amount-to', 'from', 'amount-from', 'from-to', 'amount-from-to'];
function decode(output, options, user) {
  if (!isValidatedPrivacyScanOutputV2(output)) throw new Error('validated audit-field V2 scan output required');
  if (output.event_type !== 'shielded_transfer' || output.output_index !== 0) throw new Error('direct-transfer recipient output required');
  const txHash = hexFromBytes(output.tx_hash);
  if (options.txHash !== undefined && (typeof options.txHash !== 'string'
    || !/^(?:0x)?[0-9a-fA-F]{64}$/.test(options.txHash) || options.txHash.replace(/^0x/, '').toLowerCase() !== txHash)) throw new Error('scan transaction hash mismatch');
  const publicMode = user && output.user_disclosure_mode === 'USER_DISCLOSURE_MODE_PUBLIC';
  const payloadBytes = user ? output.user_disclosure_payload : output.self_view_disclosure_payload;
  const digestBytes = user ? output.user_disclosure_digest : output.full_disclosure_digest;
  if (!payloadBytes.length || user && output.user_privacy_policy === 0) throw new Error('disclosure unavailable');
  if (user && !publicMode && (output.user_disclosure_mode !== 'USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED'
    || typeof options.disclosurePubKeyHex !== 'string'
    || hexFromBytes(output.user_disclosure_target_pubkey) !== options.disclosurePubKeyHex.toLowerCase())) throw new Error('disclosure recipient mismatch');
  const value = publicMode ? unmarshalDisclosurePlaintextV2(payloadBytes)
    : decryptDisclosureV2(payloadBytes, options.disclosureScalar, user ? encryptedEnvelopeKindV2.userDisclosure : encryptedEnvelopeKindV2.selfViewDisclosure);
  if (value.plane !== (user ? 1 : 2) || value.outputIndex !== output.output_index
    || canonicalFieldHex(value.commitment) !== hexFromBytes(output.commitment)
    || user && value.policy !== output.user_privacy_policy) throw new Error('disclosure plane, output or policy mismatch');
  verifyDisclosureDigestV2(value, digestBytes, 'transfer');
  const denom = options.assetDenom ? canonicalAssetDenomV1(options.assetDenom) : '';
  if (denom && computeAssetId(denom) !== value.assetID) throw new Error('disclosure asset mismatch');
  const full = !user, policy = full ? 7 : value.policy, plane = user ? 'user' : 'self-view';
  const address = prefix => encodeShieldedAddress({ x: value[`${prefix}SpendKeyX`], y: value[`${prefix}SpendKeyY`] },
    { x: value[`${prefix}ViewKeyX`], y: value[`${prefix}ViewKeyY`] }, { shieldedPrefix: options.shieldedPrefix });
  const amount = policy & 1 ? value.amount.toString() : '', from = policy & 4 ? address('sender') : '', to = policy & 2 ? address('recipient') : '';
  const delivery = publicMode ? 'public' : user ? 'recipient-encrypted' : 'self-view-encrypted';
  const payload = { version: 'privacy-fixed-v2', plane, policy, output_index: value.outputIndex,
    commitment_hex: canonicalFieldHex(value.commitment), disclosure_digest_hex: hexFromBytes(digestBytes),
    disclosure_blinding_hex: canonicalFieldHex(value.disclosureBlinding), asset_id_hex: canonicalFieldHex(value.assetID),
    ...(policy & 1 ? { amount, asset_denom: denom } : {}),
    ...(from ? { from_shielded_address: from } : {}), ...(to ? { to_shielded_address: to } : {}) };
  return { plane, policy: policyLabels[policy], output_index: value.outputIndex, commitment_hex: payload.commitment_hex,
    digest_hex: payload.disclosure_digest_hex, verified: true, amount, asset_denom: policy & 1 ? denom : '', from, to,
    source: publicMode ? 'public' : user ? 'recipient_encrypted' : 'self_view_encrypted', tx_hash: txHash.toUpperCase(),
    verification: { verified: true, fixed_encoding: true, typed_scan_output: true, output_index_match: true,
      output_commitment_match: true, output_policy_match: true, plaintext_blinding_bound: true,
      local_disclosure_digest_match: true, typed_scan_disclosure_digest_match: true,
      on_chain_disclosure_digest_used: true, on_chain_disclosure_digest_match: true, asset_denom_verified: Boolean(denom) },
    summary: { plane, delivery, policy: policyLabels[policy],
      disclosed_fields: [...(policy & 1 ? ['amount'] : []), ...(from ? ['from_shielded_address'] : []), ...(to ? ['to_shielded_address'] : [])],
      amount, asset_denom: policy & 1 ? denom : '', from_shielded_address: from, to_shielded_address: to }, payload };
}
/** Trusted wallet result; project an explicit field allowlist before page delivery. */
export function decodeUserDisclosureFromScanOutputV2(output, options = {}) { return decode(output, options, true); }
/** V2 mandatory auditor encryption is a separate protocol, never this self-view API. */
export function decodeSelfViewDisclosureFromScanOutputV2(output, options = {}) { return decode(output, options, false); }
