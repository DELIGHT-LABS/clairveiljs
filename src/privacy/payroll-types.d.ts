import type { Hex } from "../core/crypto.js";

export type PayrollAmount = bigint | number | string;
export type PayrollDisclosureScope = "employee" | "company" | "auditor" | "external";
export type PayrollDisclosureMode = 0 | 1 | 2 | "none" | "public" | "recipient-encrypted" | "USER_DISCLOSURE_MODE_NONE" | "USER_DISCLOSURE_MODE_PUBLIC" | "USER_DISCLOSURE_MODE_RECIPIENT_ENCRYPTED";

export interface PayrollDisclosurePolicy {
  user_privacy_policy?: number | string;
  user_disclosure_mode?: PayrollDisclosureMode | number;
  user_disclosure_target_pubkey_hex?: string;
  user_disclosure_target_key_id?: string;
  expected_user_disclosure_digest?: string;
  expected_audit_disclosure_digest?: string;
  expected_self_view_disclosure_digest?: string;
  userPrivacyPolicy?: number | string;
  userDisclosureMode?: PayrollDisclosureMode | number;
  userDisclosureTargetPubKeyHex?: string;
  userDisclosureTargetKeyID?: string;
  expectedUserDisclosureDigest?: string;
  expectedAuditDisclosureDigest?: string;
  expectedSelfViewDisclosureDigest?: string;
}

export interface NormalizedPayrollDisclosurePolicy {
  user_privacy_policy: number;
  user_disclosure_mode: 0 | 1 | 2;
  user_disclosure_target_pubkey_hex: string;
  user_disclosure_target_key_id: string;
  expected_user_disclosure_digest: string;
  expected_audit_disclosure_digest: string;
  expected_self_view_disclosure_digest: string;
}

export interface PayrollItemInput<Amount = PayrollAmount> {
  item_id?: string;
  employee_id?: string;
  recipient_address?: string;
  amount: Amount;
  denom?: string;
  disclosure_policy?: PayrollDisclosurePolicy;
  disclosure_policy_set?: boolean;
  expected_output_commitment?: string;
  expected_disclosure_digest?: string;
  itemID?: string;
  itemId?: string;
  employeeID?: string;
  employeeId?: string;
  recipientAddress?: string;
  disclosurePolicy?: PayrollDisclosurePolicy;
  disclosurePolicySet?: boolean;
  expectedOutputCommitment?: string;
  expectedDisclosureDigest?: string;
}

export interface PayrollInput<Amount = PayrollAmount> {
  company_id?: string;
  payroll_id?: string;
  batch_id: string;
  denom: string;
  attempt?: number;
  default_disclosure_policy?: PayrollDisclosurePolicy;
  created_at?: string | Date | null;
  items: PayrollItemInput<Amount>[];
  companyID?: string;
  companyId?: string;
  payrollID?: string;
  payrollId?: string;
  batchID?: string;
  batchId?: string;
  defaultDisclosurePolicy?: PayrollDisclosurePolicy;
  createdAt?: string | Date | null;
}

export interface NormalizedPayrollItemInput {
  item_id: string;
  employee_id: string;
  recipient_address: string;
  amount: bigint;
  denom: string;
  disclosure_policy: NormalizedPayrollDisclosurePolicy;
  expected_output_commitment: string;
  expected_disclosure_digest: string;
}

export interface NormalizedPayrollInput {
  company_id: string;
  payroll_id: string;
  batch_id: string;
  denom: string;
  attempt: number;
  default_disclosure_policy: NormalizedPayrollDisclosurePolicy;
  created_at: string | Date | null;
  items: readonly NormalizedPayrollItemInput[];
}

export interface TreasuryNote<Amount = PayrollAmount> {
  note_id?: string;
  owner_key_id?: string;
  nullifier_lookup_key?: string;
  nullifier_lookup_key_id?: string;
  denom: string;
  amount: Amount;
  is_spent?: boolean;
  reservation_id?: string;
  note?: object;
  merkle_path?: string[];
  merkle_path_helper?: number[];
  noteID?: string;
  noteId?: string;
  ownerKeyID?: string;
  ownerKeyId?: string;
  nullifierLookupKey?: string;
  nullifierLookupKeyID?: string;
  nullifierLookupKeyId?: string;
  isSpent?: boolean;
  reservationID?: string;
  reservationId?: string;
  [key: string]: unknown;
}

export interface DisclosureKeyEntry {
  key_id?: string;
  scope: PayrollDisclosureScope;
  subject_id?: string;
  public_key_hex?: string;
  version?: string;
  active: boolean;
  keyID?: string;
  keyId?: string;
  subjectID?: string;
  subjectId?: string;
  publicKeyHex?: string;
}

export interface NormalizedDisclosureKeyEntry {
  key_id: string;
  scope: PayrollDisclosureScope;
  subject_id: string;
  public_key_hex: string;
  version: string;
  active: boolean;
}

export interface PayrollPlanItem<Note = TreasuryNote> {
  company_id: string;
  payroll_id: string;
  batch_id: string;
  attempt: number;
  chunk_id: string;
  item_id: string;
  employee_id: string;
  operation_id: string;
  recipient_address: string;
  expected_recipient_hash: Hex;
  amount: bigint;
  expected_amount_hash: Hex;
  denom: string;
  disclosure_policy: NormalizedPayrollDisclosurePolicy;
  expected_output_commitment: string;
  expected_disclosure_digest: string;
  input_notes: Note[];
  status: string;
  failure_reason: string;
  retry_count: number;
  batch_item_index: number;
}

export interface PayrollOperationPlanFields<Note = TreasuryNote> {
  operation_id: string;
  items: PayrollPlanItem<Note>[];
  input_notes: Note[];
  input_total: bigint;
  payment_total: bigint;
  change: bigint;
  output_count: number;
  has_change: boolean;
  /** compact emits only payments/change; exact-32 fills remaining output slots with zero-value padding notes. */
  output_mode?: "compact" | "exact-32" | "exact32";
  padding_count?: number;
}

export interface PayrollPlanFields<Operation> {
  company_id: string;
  payroll_id: string;
  batch_id: string;
  denom: string;
  attempt: number;
  status: "Draft" | "Confirmed" | "Cancelled";
  operations: Operation[];
  created_at: string | Date | null;
  updated_at: string | Date | null;
}
