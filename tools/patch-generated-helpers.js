#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";

const args = process.argv.slice(2);
const checkOnly = args.includes("--check");
const files = args.filter(arg => arg !== "--check");
if (!files.length) {
  console.error("usage: node tools/patch-generated-helpers.js [--check] <helper-file> [...]");
  process.exit(1);
}

function patchHelper(source) {
  return source.replace(
    /Buffer\.from\(\s*pagination\.key\s*\)\.toString\(\s*['"]base64['"]\s*\)/g,
    "base64FromBytes(pagination.key)"
  );
}

function patchVarint(source) {
  if (!source.includes("export function int64FromString")) return source;
  const pattern = /export function int64FromString\(dec: string\): \{ lo: number; hi: number \} \{[\s\S]*?\n\}\n\s*(?=\/\*\*)/;
  if (!pattern.test(source)) {
    throw new Error("could not locate generated int64FromString implementation");
  }
  const withInt64Parser = source.replace(pattern, `export function int64FromString(dec: string): { lo: number; hi: number } {
  const value = BigInt(dec);
  const unsigned = BigInt.asUintN(64, value);
  const lo = Number(unsigned & 0xffffffffn);
  const hi = Number(unsigned >> 32n);
  return { lo, hi };
}
`);
  const lengthSignature = "export function int64Length(lo: number, hi: number) {\n";
  if (withInt64Parser.includes(`${lengthSignature}  lo >>>= 0;\n  hi >>>= 0;`)) {
    return withInt64Parser;
  }
  return withInt64Parser.replace(
    lengthSignature,
    `${lengthSignature}  lo >>>= 0;\n  hi >>>= 0;\n`
  );
}

for (const file of files) {
  const source = readFileSync(file, "utf8");
  const patched = file.endsWith("/varint.ts")
    ? patchVarint(source)
    : patchHelper(source);

  if (/Buffer\.from\(\s*pagination\.key\s*\)/.test(patched)) {
    throw new Error(`${file}: pagination.key still uses Buffer.from`);
  }
  if (patched.includes("pagination.key") && !patched.includes("base64FromBytes(pagination.key)")) {
    throw new Error(`${file}: pagination.key must use base64FromBytes`);
  }
  if (file.endsWith("/varint.ts") && (!patched.includes("BigInt.asUintN(64, value)") || !patched.includes("lo >>>= 0;"))) {
    throw new Error(`${file}: int64 helpers must preserve all 64 bits`);
  }
  if (checkOnly && patched !== source) {
    throw new Error(`${file}: generated helper patch has not been applied`);
  }
  if (!checkOnly) writeFileSync(file, patched);
}
