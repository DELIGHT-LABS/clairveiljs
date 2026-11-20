import type {
  AuditKindV2,
  AuditMessageV2,
  PreparedAuditAuthorizationV2,
} from "./audit-authorization-v2.js";
import type { AuditCircuitIdentityV2 } from "./audit-config-v2.js";
/** Trusted host-local verifier. Must verify canonical BN254 proof bytes using exactly these artifact/identity pins and PI23. */
export interface AuditProofVerifierV2 {
  verify(input: {
    kind: AuditKindV2;
    artifactHash: string;
    circuitIdentity: AuditCircuitIdentityV2;
    publicInputs: readonly bigint[];
    proof: Uint8Array;
    signal?: AbortSignal;
  }): Promise<true>;
}
export interface AuditProverV2 {
  /** Takes ownership of witness bytes: copied and cleared before any await. Prepared state is single-use and cleared after every attempt. */
  prove(input: {
    prepared: PreparedAuditAuthorizationV2;
    witness: Uint8Array;
    signal?: AbortSignal;
  }): Promise<AuditMessageV2>;
}
export class AuditProverErrorV2 extends Error {
  readonly code:
    | "request"
    | "snapshot"
    | "transport"
    | "response"
    | "verification"
    | "aborted"
    | "timeout";
  constructor(code: AuditProverErrorV2["code"]);
}
/** Explicitly selected, trusted prover origin. HTTPS or HTTP loopback only. No redirect, retry, endpoint discovery or V1 fallback. */
export function createAuditProverV2(options: {
  baseUrl: string;
  verifier: AuditProofVerifierV2;
  fetch?: typeof globalThis.fetch;
  /** Deadline covers fresh snapshots, HTTP body and local verification; 1..3600000 ms, default 120000. */
  timeoutMs?: number;
  bearerToken?: string;
}): AuditProverV2;
