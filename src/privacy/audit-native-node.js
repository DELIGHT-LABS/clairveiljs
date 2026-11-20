import { readFile, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, isAbsolute } from "node:path";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { shape, exactBytes } from "./audit-field-v2.js";
/** Explicit local native backend. The caller pins a trusted build's hash. */
export async function createAuditNativeBackendV2({
  executablePath,
  sha256,
  timeoutMs = 30000,
}) {
  if (
    typeof executablePath !== "string" ||
    !isAbsolute(executablePath) ||
    typeof sha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(sha256)
  )
    throw new Error("absolute native binary path and pinned SHA256 required");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000)
    throw new Error("native timeout must be 1..120000 ms");
  const binary = await readFile(executablePath);
  if (
    binary.length > 32 * 1024 * 1024 ||
    createHash("sha256").update(binary).digest("hex") !== sha256
  )
    throw new Error("native binary hash mismatch");
  return Object.freeze({
    async encrypt({ kind, publicInputs, plaintext, signal }) {
      const s = shape(kind);
      const pi = exactBytes(publicInputs, 672, "PI21"),
        plain = exactBytes(plaintext, s[2] * 32, "audit plaintext");
      let stage;
      let request;
      try {
        if (signal?.aborted) throw new Error("native encryption aborted");
        // Run exactly the bytes that were hashed, eliminating a source-path replacement race.
        stage = await mkdtemp(join(tmpdir(), "clairveil-audit-run-"));
        const executable = join(stage, "encrypt");
        await writeFile(executable, binary, { mode: 0o700, flag: "wx" });
        if (signal?.aborted) throw new Error("native encryption aborted");
        request = Buffer.concat([
          Buffer.from("CVA2"),
          Buffer.from([kind]),
          pi,
          plain,
        ]);
        plain.fill(0);
        return await new Promise((resolve, reject) => {
          const child = spawn(executable, [], {
            stdio: ["pipe", "pipe", "pipe"],
            env: { GODEBUG: process.env.GODEBUG ?? "" },
          });
          let failure;
          let total = 0;
          let stderrBytes = 0;
          const chunks = [];
          const stop = (reason) => {
            failure ??= new Error(reason);
            child.kill("SIGKILL");
          };
          const onAbort = () => stop("native encryption aborted");
          const timer = setTimeout(
            () => stop("native encryption timed out"),
            timeoutMs,
          );
          signal?.addEventListener("abort", onAbort, { once: true });
          if (signal?.aborted) onAbort();
          child.on("error", () => {
            failure ??= new Error("native encryption process failed");
          });
          child.stdin.on("error", () => {
            failure ??= new Error("native encryption input failed");
          });
          child.stdout.on("data", (chunk) => {
            total += chunk.length;
            if (total > s[3] + 36) {
              chunk.fill(0);
              stop("native encryption output exceeds bound");
            } else chunks.push(chunk);
          });
          child.stderr.on("data", (chunk) => {
            stderrBytes += chunk.length;
            chunk.fill(0);
            if (stderrBytes > 1024)
              stop("native encryption diagnostics exceed bound");
          });
          child.on("close", (code) => {
            clearTimeout(timer);
            signal?.removeEventListener("abort", onAbort);
            request.fill(0);
            const output = Buffer.concat(chunks);
            chunks.forEach((c) => c.fill(0));
            try {
              if (failure) throw failure;
              if (code !== 0 || stderrBytes !== 0)
                throw new Error(
                  "native encryption failed (including unsupported secret profile)",
                );
              if (
                output.length !== s[3] + 36 ||
                output.subarray(0, 4).toString("ascii") !== "CVA2"
              )
                throw new Error("invalid native encryption response");
              resolve({
                envelope: Uint8Array.from(output.subarray(4, -32)),
                witness: Uint8Array.from(output.subarray(-32)),
              });
            } catch (error) {
              reject(error);
            } finally {
              output.fill(0);
            }
          });
          child.stdin.end(request, () => request.fill(0));
        });
      } finally {
        plain.fill(0);
        request?.fill(0);
        if (stage) await rm(stage, { recursive: true, force: true });
      }
    },
  });
}
