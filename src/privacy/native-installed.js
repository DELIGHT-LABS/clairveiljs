import { open, lstat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';

/** Operator-installed binary only. The installer/configuration is trusted;
 * this does not protect against an administrator or the same OS account. */
export async function verifyInstalledNative(path, expectedHash) {
  const parent = await lstat(dirname(path)), owner = process.getuid?.();
  if (!parent.isDirectory() || parent.isSymbolicLink() || (parent.mode & 0o022)
    || owner !== undefined && parent.uid !== owner && parent.uid !== 0) throw new Error('unsafe native installation directory');
  const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > 128*1024*1024 || (stat.mode & 0o022) || !(stat.mode & 0o100)
      || owner !== undefined && stat.uid !== owner && stat.uid !== 0) throw new Error('unsafe native installation file');
    const bytes = Buffer.alloc(stat.size + 1); let offset = 0;
    try {
      while (offset < bytes.length) { const { bytesRead } = await file.read(bytes, offset, bytes.length - offset, null); if (!bytesRead) break; offset += bytesRead; }
      if (offset !== stat.size || createHash('sha256').update(bytes.subarray(0, offset)).digest('hex') !== expectedHash) throw new Error('installed native hash mismatch');
    } finally { bytes.fill(0); }
  } finally { await file.close(); }
}
