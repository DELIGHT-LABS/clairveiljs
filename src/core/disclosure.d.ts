import type { Hex } from "./crypto.js";
import type { ValidatedPrivacyScanOutputV2 } from "../privacy/scan.js";

export interface DisclosureDecodeOptions {
  shieldedPrefix?: string;
  /** Optional display denom; its derived asset ID is checked against the disclosure field. */
  assetDenom?: string;
}

export const planeUser: "user";
export const planeAudit: "audit";
export const planeSelfView: "self-view";
export const userDisclosureModeNone: "USER_DISCLOSURE_MODE_NONE";
export const userDisclosureModePublic: "USER_DISCLOSURE_MODE_PUBLIC";
export const userDisclosureModeRecipientEncrypted: "USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED";
export const transferPrivacyPolicyAllPrivate: 0;
export const transferPrivacyPolicyDiscloseAmount: 1;
export const transferPrivacyPolicyDiscloseTo: 2;
export const transferPrivacyPolicyDiscloseFrom: 4;

export interface DisclosurePayload {
  version: "privacy-fixed-v1";
  plane: "user" | "audit" | "self-view";
  policy: number;
  output_index: number;
  commitment_hex: Hex;
  disclosure_digest_hex: Hex;
  disclosure_blinding_hex: Hex;
  asset_id_hex: Hex;
  amount?: string;
  asset_denom?: string;
  from_shielded_address?: string;
  to_shielded_address?: string;
}

export interface DisclosureVerification {
  verified: boolean;
  fixed_encoding?: boolean;
  typed_scan_output?: boolean;
  batch_typed_scan_output?: boolean;
  output_index_match?: boolean;
  output_commitment_match?: boolean;
  output_policy_match?: boolean;
  plaintext_blinding_bound?: boolean;
  local_disclosure_digest_match?: boolean;
  typed_scan_disclosure_digest_match?: boolean;
  asset_denom_verified?: boolean;
  on_chain_disclosure_digest_used?: boolean;
  on_chain_disclosure_digest_match?: boolean;
}

export interface DisclosureReportSummary {
  plane: string;
  delivery: string;
  policy: string;
  disclosed_fields: string[];
  amount: string;
  asset_denom: string;
  from_shielded_address: string;
  to_shielded_address: string;
}

export interface DisclosureReport {
  plane: "user" | "audit" | "self-view";
  policy: string;
  output_index: number;
  commitment_hex: Hex | "";
  digest_hex: Hex | "";
  verified: boolean;
  amount: string;
  asset_denom: string;
  from: string;
  to: string;
  source: string;
  tx_hash: Hex | "";
  verification: DisclosureVerification;
  summary: DisclosureReportSummary;
  payload: DisclosurePayload;
}

/** An opaque output returned by `validatePrivacyScanPageV2`; raw protobuf records are rejected. */
export type PrivacyScanDisclosureOutputV2 = ValidatedPrivacyScanOutputV2;
export type BatchPrivacyScanDisclosureOutputV2 = PrivacyScanDisclosureOutputV2;

export interface BatchDisclosureDecodeOptions extends DisclosureDecodeOptions {
  /** Required for recipient-encrypted, audit, and self-view envelopes. */
  disclosureScalar?: bigint | string | number;
  /** Required with `disclosureScalar` for recipient-encrypted user disclosure. */
  disclosurePubKeyHex?: Hex;
  /** Asserts the typed scan's chain transaction hash; on Cosmos-EVM this is not the Ethereum receipt hash. */
  txHash?: Hex;
  /** Optional display-only denom; the field element remains independently bound. */
  assetDenom?: string;
}

export function privacyPolicyLabel(policy: number | string): string;
export function disclosedFields(payload: DisclosurePayload): string[];
export function disclosureAmountAndAsset(payload: {
  amount?: string;
  asset_id_hex?: Hex;
  asset_denom?: string;
}): {
  amount: bigint | null;
  assetId: bigint | null;
  assetDenom: string;
};
export function eventAttribute(event: object, key: string): string;
export function disclosureTargetPubKeyFromEvent(event: object, plane?: string): Hex;
export function decodeUserDisclosureFromEvent(event: object, disclosureScalar: bigint | string | number, disclosurePubKeyHex: Hex, txHash?: Hex, options?: DisclosureDecodeOptions): DisclosureReport;
export function decodeSelfViewDisclosureFromEvent(event: object, disclosureScalar: bigint | string | number, txHash?: Hex, options?: DisclosureDecodeOptions): DisclosureReport;
export function decodeAuditDisclosureFromEvent(event: object, disclosureScalar: bigint | string | number, txHash?: Hex, options?: DisclosureDecodeOptions): DisclosureReport;
export function decodeUserDisclosureFromScanOutput(output: PrivacyScanDisclosureOutputV2, options?: BatchDisclosureDecodeOptions): DisclosureReport;
export function decodeSelfViewDisclosureFromScanOutput(output: PrivacyScanDisclosureOutputV2, options?: BatchDisclosureDecodeOptions): DisclosureReport;
export function decodeAuditDisclosureFromScanOutput(output: PrivacyScanDisclosureOutputV2, options?: BatchDisclosureDecodeOptions): DisclosureReport;
export function decodeBatchUserDisclosureFromScanOutput(output: BatchPrivacyScanDisclosureOutputV2, options?: BatchDisclosureDecodeOptions): DisclosureReport;
export function decodeBatchSelfViewDisclosureFromScanOutput(output: BatchPrivacyScanDisclosureOutputV2, options?: BatchDisclosureDecodeOptions): DisclosureReport;
export function decodeBatchAuditDisclosureFromScanOutput(output: BatchPrivacyScanDisclosureOutputV2, options?: BatchDisclosureDecodeOptions): DisclosureReport;
export function disclosureScalarFromHex(value: Hex): bigint;
export function publicPayloadReport(payloadHex: Hex, onChainDigestHex?: Hex, txHash?: Hex, options?: DisclosureDecodeOptions): DisclosureReport;
