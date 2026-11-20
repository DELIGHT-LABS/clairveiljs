/** Public canonical integers and hex. No keys or privacy algorithms. */
export function unsignedInteger(value, label, maximum, minimum = 0n) {
  if (typeof value !== "bigint" && !(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value))) {
    throw new Error(`${label} must be a canonical decimal string or bigint`);
  }
  const number = BigInt(value);
  if (number < minimum || (maximum !== undefined && number > maximum)) throw new Error(`${label} is out of range`);
  return number;
}

export function normalizeHex(value,label='hex') {
  if(typeof value!=='string')throw new Error(`${label} must be a hex string`);
  const normalized=value.trim().replace(/^0x/i,'').toLowerCase();
  if(!normalized.length||normalized.length%2||!/^[0-9a-f]+$/.test(normalized))throw new Error(`${label} must be valid hex`);
  return normalized;
}
export const hexFromBytes = bytes => Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
