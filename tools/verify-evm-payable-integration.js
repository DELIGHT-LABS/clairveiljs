import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  evmEvidenceSchema,
  runEvmIntegrationVerification,
  validateEvmIntegrationEvidence,
  verifiedClairveilCommit,
  verifiedClairveilRelease,
  verifiedSdkVersion
} from "./verify-evm-integration.js";

// Deprecated compatibility entrypoint. The payable deposit gate now delegates
// to the complete EVM privacy-flow contract and therefore requires full evidence.
export const payableEvmEvidenceSchema = evmEvidenceSchema;
export const validatePayableEvmIntegrationEvidence = validateEvmIntegrationEvidence;
export {
  verifiedClairveilCommit,
  verifiedClairveilRelease,
  verifiedSdkVersion
};

export function runPayableEvmIntegrationVerification(options = {}) {
  return runEvmIntegrationVerification({
    driverPath: options.driverPath ?? (
      String(process.env.CLAIRVEIL_EVM_E2E_DRIVER ?? "").trim() ||
      process.env.CLAIRVEIL_EVM_PAYABLE_E2E_DRIVER
    ),
    required: options.required ?? (
      process.env.CLAIRVEIL_EVM_E2E_REQUIRED === "1" ||
      process.env.CLAIRVEIL_EVM_PAYABLE_E2E_REQUIRED === "1"
    )
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runPayableEvmIntegrationVerification()
    .then(result => {
      if (result.status === "skipped") {
        console.log(`SKIP EVM integration: ${result.reason}`);
      } else {
        console.log("PASS EVM full-flow integration evidence");
      }
    })
    .catch(error => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    });
}
