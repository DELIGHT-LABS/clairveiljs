import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {resolve,dirname,relative} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
test('public DApp/provider import closure excludes private SDK implementations and dynamic code',()=>{
 const seen=new Set(),queue=['src/dapp/index.js','src/custody-provider/index.js','src/wallet-api/index.js'];
 const external=new Set(['@cosmjs/encoding','@noble/curves/secp256k1.js','@noble/hashes/sha2.js','@noble/hashes/legacy.js','@noble/hashes/sha3.js','cosmjs-types/cosmos/tx/v1beta1/tx','cosmjs-types/cosmos/crypto/secp256k1/keys','ajv/dist/runtime/ucs2length.js','ajv/dist/runtime/equal.js']);
 while(queue.length){
  const file=queue.pop();if(seen.has(file))continue;seen.add(file);
  assert.match(file,/^src\/(?:dapp|custody-provider|wallet-api|chain-wallet|generated)\//);
  const source=readFileSync(resolve(root,file),'utf8');
  assert.doesNotMatch(source,/\b(?:eval\s*\(|new\s+Function\s*\(|import\s*\(|require\s*\()/);
  for(const [,specifier] of source.matchAll(/(?:from\s+|import\s*)['"]([^'"]+)['"]/g)){
   if(specifier.startsWith('.'))queue.push(relative(root,resolve(root,dirname(file),specifier)));
   else assert.ok(external.has(specifier),`unreviewed public dependency: ${specifier}`);
  }
 }
 assert.ok(seen.has('src/dapp/submission.js'));assert.ok(seen.has('src/wallet-api/generated/validators.js'));
 const pkg=JSON.parse(readFileSync(resolve(root,'package.json')));
 assert.equal(pkg.exports['./legacy-browser'].import,'./src/browser/wallet-client.js');
 assert.notEqual(pkg.exports['./dapp'].import,pkg.exports['./browser-dapp'].import);
});
