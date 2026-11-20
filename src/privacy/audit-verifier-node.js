import { open, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, isAbsolute } from "node:path";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  validateAuditArtifactManifestV2,
  validateAuditCircuitIdentityV2,
  sameIdentity,
} from "./audit-circuit-v2.js";
import { auditProofFrame, auditPublicInputBytes } from "./audit-prover-wire.js";
import { shape } from "./audit-field-v2.js";
import { verifyInstalledNative } from './native-installed.js';
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
async function boundedFile(path, maximum, label) {
  let file;
  try {
    file = await open(path, "r");
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > maximum)
      throw new Error();
    // Bounded allocation/read even if the file is replaced or grows after stat.
    const bytes = Buffer.alloc(stat.size + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await file.read(
        bytes,
        offset,
        bytes.length - offset,
        null,
      );
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset !== stat.size) throw new Error();
    return bytes.subarray(0, offset);
  } catch {
    throw new Error(`${label} file missing or outside bound`);
  } finally {
    await file?.close();
  }
}
function run(executable, request, timeoutMs, signal) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [], {
      stdio: ["pipe", "pipe", "pipe"],
      env: {},
    });
    let failure,
      total = 0,
      stderr = 0;
    const chunks = [];
    const stop = (message) => {
      failure ??= new Error(message);
      child.kill("SIGKILL");
    };
    const abort = () => stop("native verification aborted");
    const timer = setTimeout(
      () => stop("native verification timed out"),
      timeoutMs,
    );
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    child.on("error", () => {
      failure ??= new Error("native verification process failed");
    });
    child.stdin.on("error", () => {
      failure ??= new Error("native verification input failed");
    });
    child.stdout.on("data", (chunk) => {
      total += chunk.length;
      if (total > 4) stop("native verification output exceeds bound");
      else chunks.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.length;
      chunk.fill(0);
      if (stderr > 1024) stop("native verification diagnostics exceed bound");
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (failure) reject(failure);
      else if (
        code !== 0 ||
        stderr !== 0 ||
        Buffer.concat(chunks).toString("ascii") !== "CVV2"
      )
        reject(new Error("native proof verification failed"));
      else resolve(true);
    });
    child.stdin.end(request);
  });
}
/** Explicitly pinned native Core verifier. Reads only the four verification keys; never downloads artifacts. */
export async function createAuditNativeVerifierV2({
  executablePath,
  sha256,
  artifactDirectory,
  expectedArtifactHash,
  expectedCircuitIdentity,
  timeoutMs = 30000,
  executionMode = 'staged',
}) {
  if (!['staged','installed'].includes(executionMode)) throw new Error('unsupported native execution mode');
  if (
    typeof executablePath !== "string" ||
    !isAbsolute(executablePath) ||
    typeof sha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(sha256)
  )
    throw new Error("absolute verifier binary path and pinned SHA256 required");
  if (typeof artifactDirectory !== "string" || !isAbsolute(artifactDirectory))
    throw new Error("absolute artifact directory required");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000)
    throw new Error("native timeout must be 1..120000 ms");
  const identity = validateAuditCircuitIdentityV2(expectedCircuitIdentity);
  const binary = await boundedFile(
    executablePath,
    128 * 1024 * 1024,
    "native binary",
  );
  if (sha(binary) !== sha256) throw new Error("native binary hash mismatch");
  const manifest = await boundedFile(
    join(artifactDirectory, "privacy_zk_manifest.json"),
    65536,
    "artifact manifest",
  );
  const pin = validateAuditArtifactManifestV2(manifest, {
    expectedArtifactHash,
    expectedCircuitIdentity: identity,
  });
  if (!pin.developmentOnly)
    throw new Error(
      "Core audit-field verifier requires the explicit development bundle marker",
    );
  const descriptors = JSON.parse(manifest).artifacts.filter(
    (d) => d.artifact_type === "verifying_key",
  );
  const keys = [];
  for (const descriptor of descriptors) {
    const bytes = await boundedFile(
      join(artifactDirectory, descriptor.filename),
      65536,
      "verifying key",
    );
    if (sha(bytes) !== descriptor.sha256)
      throw new Error("verifying key hash mismatch");
    keys.push(bytes);
  }
  return Object.freeze({
    async verify({
      kind,
      artifactHash,
      circuitIdentity,
      publicInputs,
      proof,
      signal,
    }) {
      shape(kind);
      if (
        artifactHash !== pin.artifactHash ||
        !sameIdentity(
          validateAuditCircuitIdentityV2(circuitIdentity),
          pin.circuitIdentity,
        )
      )
        throw new Error("local verifier artifact or circuit identity mismatch");
      const pi = auditPublicInputBytes(publicInputs),
        frame = auditProofFrame(proof),
        vk = keys[kind - 1];
      const header = Buffer.alloc(13);
      header.write("CVV2");
      header[4] = kind;
      header.writeUInt32BE(manifest.length, 5);
      header.writeUInt32BE(vk.length, 9);
      const request = Buffer.concat([header, ...pi, frame, manifest, vk]);
      let stage;
      try {
        if (signal?.aborted) throw new Error("native verification aborted");
        let executable;
        if (executionMode === 'installed') { await verifyInstalledNative(executablePath, sha256); executable = executablePath; }
        else {
          stage = await mkdtemp(join(tmpdir(), "clairveil-audit-verify-"));
          executable = join(stage, "verify");
          await writeFile(executable, binary, { mode: 0o700, flag: "wx" });
        }
        if (signal?.aborted) throw new Error("native verification aborted");
        return await run(executable, request, timeoutMs, signal);
      } finally {
        if (stage) await rm(stage, { recursive: true, force: true });
      }
    },
  });
}
