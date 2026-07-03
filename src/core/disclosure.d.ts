import type { Hex } from "./crypto.js";

export interface DisclosureDecodeOptions {
  shieldedPrefix?: string;
}

export const payloadVersion: "v4";
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
export const transferAuditDisclosureDomain: 255;
export const transferSelfViewDisclosureDomain: 254;
export const transferDisclosureRecipientOutputIndex: 0;

export interface DisclosurePayload {
  version?: string;
  plane?: string;
  policy?: string | number;
  output_index?: string | number;
  amount?: string;
  asset_id_hex?: Hex;
  asset_denom?: string;
  from_shielded_address?: string;
  to_shielded_address?: string;
  commitment_hex?: Hex;
  disclosure_digest_hex?: Hex;
  [key: string]: unknown;
}

export interface DisclosureVerification {
  verified: boolean;
  local_disclosure_digest_match?: boolean;
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
  plane: string;
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

export function privacyPolicyLabel(policy: number | string): string;
export function decodePublicPayloadHex(payloadHex: Hex): DisclosurePayload;
export function decryptPayloadHex(ciphertextHex: Hex, disclosureScalar: bigint | string | number): DisclosurePayload;
export function disclosedFields(payload: DisclosurePayload): string[];
export function disclosureAmountAndAsset(payload: DisclosurePayload): {
  amount: bigint | null;
  assetId: bigint | null;
  assetDenom: string;
};
export function computeTransferDisclosureDigestHex(input: object): Hex;
export function computeAuditTransferDisclosureDigestHex(input: object): Hex;
export function computeSelfViewTransferDisclosureDigestHex(input: object): Hex;
export function computeExpectedDisclosureDigestHex(payload: DisclosurePayload, options?: DisclosureDecodeOptions): Hex;
export function verifyPayload(payload: DisclosurePayload, onChainDigestHex?: Hex, options?: DisclosureDecodeOptions): DisclosureVerification;
export function buildDisclosureReport(input: object): DisclosureReport;
export function eventAttribute(event: object, key: string): string;
export function disclosureTargetPubKeyFromEvent(event: object, plane?: string): Hex;
export function decodeUserDisclosureFromEvent(event: object, disclosureScalar: bigint | string | number, disclosurePubKeyHex: Hex, txHash?: Hex, options?: DisclosureDecodeOptions): DisclosureReport;
export function decodeSelfViewDisclosureFromEvent(event: object, disclosureScalar: bigint | string | number, txHash?: Hex, options?: DisclosureDecodeOptions): DisclosureReport;
export function decodeAuditDisclosureFromEvent(event: object, disclosureScalar: bigint | string | number, txHash?: Hex, options?: DisclosureDecodeOptions): DisclosureReport;
export function disclosureScalarFromHex(value: Hex): bigint;
export function publicPayloadReport(payloadHex: Hex, onChainDigestHex?: Hex, txHash?: Hex, options?: DisclosureDecodeOptions): DisclosureReport;
export function payloadHex(payload: DisclosurePayload): Hex;
