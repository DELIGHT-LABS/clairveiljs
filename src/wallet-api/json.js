const encoder = new TextEncoder();
const prohibited = new Set(['__proto__', 'prototype', 'constructor']);
const artifactStrings = new Set(['bodyBytesBase64', 'authInfoBytesBase64', 'data']);
export function freezeJson(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(freezeJson);
    Object.freeze(value);
  }
  return value;
}
function validUnicode(text) {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}
export function snapshotJson(value, { response = false } = {}) {
  const limit = response ? 524288 : 32768;
  const seen = new Set();
  let used = 0;
  const charge = bytes => { used += bytes; if (used > limit) throw new Error('JSON byte limit exceeded'); };
  function copy(item, depth, key = '') {
    if (typeof item === 'string') {
      if (item.length > limit || !validUnicode(item) || encoder.encode(item).length > (response && artifactStrings.has(key) ? limit : 4096)) throw new Error('Invalid JSON string');
      charge(encoder.encode(JSON.stringify(item)).length);
      return item;
    }
    if (item === null || typeof item === 'boolean') { charge(item === false ? 5 : 4); return item; }
    if (typeof item === 'number' && Number.isFinite(item)) { charge(JSON.stringify(item).length); return item; }
    if (!item || typeof item !== 'object' || depth >= 8 || seen.has(item)) throw new Error('Invalid JSON value');
    const array = Array.isArray(item);
    if (Object.getPrototypeOf(item) !== (array ? Array.prototype : Object.prototype) && !(Object.getPrototypeOf(item) === null && !array)) throw new Error('Invalid JSON object');
    const descriptors = Object.getOwnPropertyDescriptors(item);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some(name => typeof name !== 'string' || prohibited.has(name))) throw new Error('Invalid JSON key');
    seen.add(item);
    let result;
    if (array) {
      if (item.length > 64 || keys.length !== item.length + 1) throw new Error('Invalid JSON array');
      charge(2 + Math.max(0, item.length - 1));
      result = Array.from({ length: item.length }, (_, index) => {
        const d = descriptors[index];
        if (!d || !d.enumerable || !('value' in d)) throw new Error('Invalid JSON array entry');
        return copy(d.value, depth + 1);
      });
    } else {
      charge(2 + Math.max(0, keys.length - 1));
      result = {};
      for (const name of keys) {
        const d = descriptors[name];
        if (!d.enumerable || !('value' in d) || !validUnicode(name)) throw new Error('Invalid JSON property');
        if (name.length > 4096) throw new Error('Invalid JSON key');
        charge(encoder.encode(JSON.stringify(name)).length + 1);
        result[name] = copy(d.value, depth + 1, name);
      }
    }
    seen.delete(item);
    return result;
  }
  const result = copy(value, 0);
  if (encoder.encode(JSON.stringify(result)).length > limit) throw new Error('JSON byte limit exceeded');
  return freezeJson(result);
}

/** Duplicate members must be rejected before JSON.parse could discard them. */
export function parseWalletJson(text, options = {}) {
  if (text instanceof Uint8Array && text.byteLength > (options.response ? 524288 : 32768)) throw new Error('JSON byte limit exceeded');
  if (text instanceof Uint8Array) text = new TextDecoder('utf-8', { fatal: true }).decode(text);
  if (typeof text !== 'string' || encoder.encode(text).length > (options.response ? 524288 : 32768) || !validUnicode(text)) throw new Error('Invalid JSON text');
  let index = 0;
  const whitespace = () => { while (/[\x20\t\r\n]/.test(text[index] ?? '\0')) index++; };
  function string() {
    const start = index++;
    while (index < text.length) {
      if (text[index] === '\\') index += 2;
      else if (text[index++] === '"') return JSON.parse(text.slice(start, index));
    }
    throw new Error('Unterminated JSON string');
  }
  function value(depth) {
    whitespace();
    if (depth > 8) throw new Error('JSON depth exceeded');
    if (text[index] === '"') return string();
    if (text[index] === '{') {
      index++; whitespace(); const result = Object.create(null); const keys = new Set();
      if (text[index] === '}') { index++; return result; }
      while (true) {
        whitespace(); if (text[index] !== '"') throw new Error('Invalid JSON member');
        const key = string();
        if (keys.has(key) || prohibited.has(key)) throw new Error('Duplicate or prohibited JSON member');
        keys.add(key); whitespace(); if (text[index++] !== ':') throw new Error('Invalid JSON separator');
        result[key] = value(depth + 1); whitespace();
        const next = text[index++]; if (next === '}') return result;
        if (next !== ',') throw new Error('Invalid JSON object');
      }
    }
    if (text[index] === '[') {
      index++; whitespace(); const result = [];
      if (text[index] === ']') { index++; return result; }
      while (true) {
        if (result.length >= 64) throw new Error('JSON array limit');
        result.push(value(depth + 1)); whitespace(); const next = text[index++];
        if (next === ']') return result;
        if (next !== ',') throw new Error('Invalid JSON array');
      }
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(index));
    if (!match) throw new Error('Invalid JSON token');
    index += match[0].length; return JSON.parse(match[0]);
  }
  const result = value(0); whitespace();
  if (index !== text.length) throw new Error('Trailing JSON data');
  return snapshotJson(result, options);
}
