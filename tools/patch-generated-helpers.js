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

for (const file of files) {
  const source = readFileSync(file, "utf8");
  const patched = patchHelper(source);

  if (/Buffer\.from\(\s*pagination\.key\s*\)/.test(patched)) {
    throw new Error(`${file}: pagination.key still uses Buffer.from`);
  }
  if (patched.includes("pagination.key") && !patched.includes("base64FromBytes(pagination.key)")) {
    throw new Error(`${file}: pagination.key must use base64FromBytes`);
  }
  if (checkOnly && patched !== source) {
    throw new Error(`${file}: generated helper patch has not been applied`);
  }
  if (!checkOnly) writeFileSync(file, patched);
}
