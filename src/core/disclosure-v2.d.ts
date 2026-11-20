import type { ValidatedPrivacyScanOutputV2 } from '../privacy/scan-v2.js';
export interface AuditDisclosureOptionsV2 {
  disclosureScalar?: bigint; disclosurePubKeyHex?: string; txHash?: string; shieldedPrefix?: string; assetDenom?: string;
}
export interface AuditDisclosureReportV2 {
  plane: 'user' | 'self-view'; policy: string; output_index: number; commitment_hex: string; digest_hex: string;
  verified: true; amount: string; asset_denom: string; from: string; to: string; source: string; tx_hash: string;
  verification: { verified: true; fixed_encoding: true; typed_scan_output: true; output_index_match: true;
    output_commitment_match: true; output_policy_match: true; plaintext_blinding_bound: true;
    local_disclosure_digest_match: true; typed_scan_disclosure_digest_match: true;
    on_chain_disclosure_digest_used: true; on_chain_disclosure_digest_match: true; asset_denom_verified: boolean };
  summary: { plane: string; delivery: string; policy: string; disclosed_fields: string[]; amount: string;
    asset_denom: string; from_shielded_address: string; to_shielded_address: string };
  payload: { version: 'privacy-fixed-v2'; plane: 'user' | 'self-view'; policy: number; output_index: number;
    commitment_hex: string; disclosure_digest_hex: string; disclosure_blinding_hex: string; asset_id_hex: string;
    amount?: string; asset_denom?: string; from_shielded_address?: string; to_shielded_address?: string };
}
/** Accepts only immutable, integrity-checked audit-field typed scan outputs. No legacy/event fallback. */
export function decodeUserDisclosureFromScanOutputV2(output: ValidatedPrivacyScanOutputV2, options?: AuditDisclosureOptionsV2): AuditDisclosureReportV2;
export function decodeSelfViewDisclosureFromScanOutputV2(output: ValidatedPrivacyScanOutputV2, options?: AuditDisclosureOptionsV2): AuditDisclosureReportV2;
