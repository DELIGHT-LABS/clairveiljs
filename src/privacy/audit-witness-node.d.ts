import type { AuditWitnessBackendV2 } from "./audit-witness-v2.js";
export function createAuditWitnessNativeBackendV2(input: {executablePath: string; sha256: string; timeoutMs?: number; executionMode?: 'staged' | 'installed'}): Promise<AuditWitnessBackendV2>;
