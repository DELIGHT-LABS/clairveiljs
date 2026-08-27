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

export const payableEvmEvidenceSchema = "clairveil-payable-evm-e2e-v1";
export const verifiedClairveilRelease = "v0.3.1";
export const verifiedClairveilCommit = "621c24a3ef1118b6ab2b8b780ab00da6fbc00e1b";
export const verifiedSdkVersion = "0.3.1";

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
