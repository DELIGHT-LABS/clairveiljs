import type { AuditProofVerifierV2 } from "./audit-prover-v2.js";
import type { AuditCircuitIdentityInputV2 } from "./audit-config-v2.js";
/** Node-only. Immutable copies of independently pinned executable, manifest and four VKs; Core currently requires development-only artifacts. */
export function createAuditNativeVerifierV2(options: {
  executablePath: string;
  sha256: string;
  artifactDirectory: string;
  expectedArtifactHash: string;
  expectedCircuitIdentity: AuditCircuitIdentityInputV2;
  timeoutMs?: number;
  executionMode?: 'staged' | 'installed';
}): Promise<AuditProofVerifierV2>;
