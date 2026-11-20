import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod, symlink, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyInstalledNative } from '../src/privacy/native-installed.js';

test('installed native execution refuses modified bytes, symlinks and writable installations', async () => {
  const directory=await mkdtemp(join(tmpdir(),'audit-installed-test-')),binary=join(directory,'binary'),link=join(directory,'link');
  const bytes=Buffer.from('synthetic executable bytes'),hash=createHash('sha256').update(bytes).digest('hex');
  try {
    await writeFile(binary,bytes,{mode:0o700});await verifyInstalledNative(binary,hash);
    await symlink(binary,link);await assert.rejects(verifyInstalledNative(link,hash));
    await writeFile(binary,Buffer.from('changed executable bytes'));await assert.rejects(verifyInstalledNative(binary,hash));
    await writeFile(binary,bytes);await chmod(binary,0o720);await assert.rejects(verifyInstalledNative(binary,hash));
    await chmod(binary,0o600);await assert.rejects(verifyInstalledNative(binary,hash));
    await chmod(binary,0o700);await chmod(directory,0o770);await assert.rejects(verifyInstalledNative(binary,hash));
    await chmod(directory,0o700);await verifyInstalledNative(binary,hash);
  } finally { await rm(directory,{recursive:true,force:true}); }
});
