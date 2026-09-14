import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const args=process.argv.slice(2),mode=args[0],target=args[1];
if(!['--check','--write'].includes(mode)||!target||args.length!==2)throw new Error('Usage: node tools/sync-wallet-api-mirror.js --check|--write CUSTODY_REPOSITORY');
const root=fileURLToPath(new URL('../src/wallet-api/schema/',import.meta.url));
const files=['wallet-api-draft.schema.json','wallet-api-draft.methods.json','wallet-api-draft.examples.json','walletconnect-cvpriv-draft.examples.json'];
for(const file of files){
 const source=readFileSync(resolve(root,file));
 const destination=resolve(target,'docs/schemas',file);
 if(mode==='--write')writeFileSync(destination,source);
 else if(!source.equals(readFileSync(destination)))throw new Error(`Generated custody mirror differs: ${file}`);
}
console.log(`${files.length} wallet-api mirrors ${mode==='--check'?'match':'updated'}; SDK is the authoring source.`);
