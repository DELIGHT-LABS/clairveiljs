import { keccak_256 } from '@noble/hashes/sha3.js';
const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
const shapes = {
  deposit: ['bytes','bytes','bytes'],
  transfer: ['bytes','bytes','bytes[]','bytes[]','bytes[]','bytes[]','uint32','bytes','uint8','bytes','bytes','bytes','bytes','bytes','bytes','bytes','uint64'],
  withdraw: ['bytes','bytes','bytes','string','address','string','uint64']
};
const hex = bytes => [...bytes].map(byte=>byte.toString(16).padStart(2,'0')).join('');
const word = value => BigInt(value).toString(16).padStart(64,'0');
function encode(types, values) {
  let head = '', tail = '';
  for (let i=0;i<types.length;i++) {
    const type=types[i], value=values[i];
    if (type.startsWith('uint')) head += word(value);
    else if (type==='address') head += value.slice(2).padStart(64,'0');
    else {
      head += word(types.length*32+tail.length/2);
      if (type==='bytes[]') tail += word(value.length)+encode(value.map(()=>'bytes'),value);
      else { const data=type==='string'?hex(encoder.encode(value)):value; tail+=word(data.length/2)+data.padEnd(Math.ceil(data.length/64)*64,'0'); }
    }
  }
  return head+tail;
}
/** Decode and reencode the complete canonical ABI, including every dynamic offset/padding byte. */
export function decodePrivacyCall(data, action) {
  const types=shapes[action];
  if (!types || typeof data!=='string' || !/^0x(?:[0-9a-f]{2})+$/.test(data)) throw new Error('invalid privacy calldata');
  const signature=`${action}((${types.join(',')}))`;
  if (data.slice(2,10)!==hex(keccak_256(encoder.encode(signature))).slice(0,8)) throw new Error('privacy action selector mismatch');
  const bytes=data.slice(10);
  function read(offset) {
    if (!Number.isSafeInteger(offset) || offset<0 || offset*2+64>bytes.length) throw new Error('ABI offset out of bounds');
    return BigInt('0x'+bytes.slice(offset*2,offset*2+64));
  }
  function tuple(types,base) {
    return types.map((type,i)=>{
      const slot=read(base+i*32);
      if(type.startsWith('uint')) {if(slot>=1n<<BigInt(type.slice(4)))throw new Error('ABI uint overflow');return slot;}
      if(type==='address') {if(slot>=1n<<160n)throw new Error('ABI address overflow');return '0x'+slot.toString(16).padStart(40,'0');}
      if(slot>BigInt(bytes.length/2)||slot%32n)throw new Error('invalid ABI offset');
      const start=base+Number(slot), length=read(start);
      if(length>BigInt(bytes.length/2))throw new Error('ABI length out of bounds');
      if(type==='bytes[]'){if(length>64n)throw new Error('ABI array limit');return tuple(Array(Number(length)).fill('bytes'),start+32);}
      const end=start+32+Number(length);
      if(end*2>bytes.length)throw new Error('truncated ABI data');
      const value=bytes.slice((start+32)*2,end*2);
      if(type==='bytes')return value;
      return decoder.decode(Uint8Array.from(value.match(/../g)??[],v=>parseInt(v,16)));
    });
  }
  if(read(0)!==32n)throw new Error('noncanonical ABI tuple offset');
  const values=tuple(types,32);
  if(word(32)+encode(types,values)!==bytes)throw new Error('noncanonical or trailing ABI data');
  if (!values[0].length) throw new Error('empty privacy proof');
  if(action==='deposit' && (values[0].length!==64 || !values[1].length || !values[2].length))throw new Error('empty deposit fields');
  if(action!=='deposit' && values[1].length!==64)throw new Error('invalid privacy root');
  if(action==='withdraw' && values[2].length!==64)throw new Error('invalid nullifier');
  return values;
}
