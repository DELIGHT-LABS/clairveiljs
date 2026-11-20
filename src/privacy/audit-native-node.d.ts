import type { AuditEncryptionBackendV2 } from "./audit-authorization-v2.js";
/** Node-only adapter to an independently trusted/pinned Core native build. No download or remote fallback. */
export function createAuditNativeBackendV2(options: {
  executablePath: string;
  sha256: string;
  timeoutMs?: number;
}): Promise<AuditEncryptionBackendV2>;
