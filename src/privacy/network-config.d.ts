export interface ValidatedAuditConfigV1 {
  audit_master_pubkey_hex: string;
  audit_key_id: string;
  audit_key_epoch: string;
}

export interface ValidatedDisclosureConfigV1 {
  payload_version: "privacy-fixed-v1";
  audit_disclosure_required: true;
  supported_user_policies: readonly string[];
  supported_user_modes: readonly string[];
}

export interface ValidatedReserveResponseV1 {
  denom: string;
  module_balance: string;
  total_deposited: string;
  total_withdrawn: string;
  expected_module_balance: string;
  invariant_holds: true;
}

export function normalizeAuditConfigV1(response: object): ValidatedAuditConfigV1;
export function normalizeDisclosureConfigV1(response: object): ValidatedDisclosureConfigV1;
export function normalizeReserveResponseV1(response: object, expectedDenom?: string): ValidatedReserveResponseV1;
