import { readFile, mkdtemp, writeFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { verifyInstalledNative } from './native-installed.js';

/** Runs the exact hash-pinned Core adapter bytes, never a caller-supplied shell. */
export async function createAuditWitnessNativeBackendV2({executablePath,sha256,timeoutMs=30000,executionMode='staged'}) {
  if (!['staged','installed'].includes(executionMode)) throw new Error('unsupported native execution mode');
  if (typeof executablePath!=="string" || !isAbsolute(executablePath) || !/^[0-9a-f]{64}$/.test(sha256)
    || !Number.isSafeInteger(timeoutMs) || timeoutMs<1 || timeoutMs>120000) throw new Error("pinned native witness binary and bounded timeout required");
  const binary=await readFile(executablePath);
  if (binary.length>128*1024*1024 || createHash("sha256").update(binary).digest("hex")!==sha256) throw new Error("native witness binary hash mismatch");
  return Object.freeze({async prepare({request,signal}) {
    if (!(request instanceof Uint8Array) || request.length<1 || request.length>32768) throw new Error("native witness input bound");
    const owned=Buffer.from(request); let stage;
    try {
      signal?.throwIfAborted(); let executable;
      if (executionMode==='installed') { await verifyInstalledNative(executablePath,sha256); executable=executablePath; }
      else { stage=await mkdtemp(join(tmpdir(),"clairveil-witness-")); executable=join(stage,"prepare"); await writeFile(executable,binary,{mode:0o700,flag:"wx"}); }
      signal?.throwIfAborted();
      return await new Promise((resolve,reject)=>{
        const child=spawn(executable,[],{stdio:["pipe","pipe","pipe"],env:{GODEBUG:""}});
        let failure,total=0,diagnostics=0; const chunks=[];
        const stop=reason=>{failure??=new Error(reason);child.kill("SIGKILL");};
        const abort=()=>stop("native witness aborted");
        const timer=setTimeout(()=>stop("native witness timed out"),timeoutMs);
        signal?.addEventListener("abort",abort,{once:true}); if(signal?.aborted)abort();
        child.on("error",()=>{failure??=new Error("native witness process failed");});
        child.stdin.on("error",()=>{failure??=new Error("native witness input failed");});
        child.stdout.on("data",chunk=>{total+=chunk.length;if(total>65536){chunk.fill(0);stop("native witness output bound");}else chunks.push(chunk);});
        child.stderr.on("data",chunk=>{diagnostics+=chunk.length;chunk.fill(0);if(diagnostics>1024)stop("native witness diagnostics bound");});
        child.on("close",code=>{
          clearTimeout(timer);signal?.removeEventListener("abort",abort);owned.fill(0);
          const output=Buffer.concat(chunks);chunks.forEach(x=>x.fill(0));
          try { if(failure)throw failure;if(code!==0||diagnostics!==0)throw new Error("native witness preparation failed");resolve(Uint8Array.from(output)); }
          catch(error){reject(error);}finally{output.fill(0);}
        });
        child.stdin.end(owned,()=>owned.fill(0));
      });
    } finally { owned.fill(0);if(stage)await rm(stage,{recursive:true,force:true}); }
  }});
}
