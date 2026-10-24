// The promises a machine can check, run by CI and by `npm run check`:
//
// - no runtime dependencies in package.json;
// - nothing imported but Node's own modules and the project's own files, in any
//   form (import, export from, import(), require, createRequire), in any code file;
// - no invisible or direction-changing characters in any code file ("Trojan
//   Source", CVE-2021-42574: code that reads one way and runs another); write
//   them as escapes ("\u202e") instead.
//
// It also counts the library's lines. There's no limit: the rule is to write only
// what's needed, which a reviewer judges and a number can't.
//
//   node scripts/check-rules.ts

import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";

const root = join(import.meta.dirname, "..");
const CODE = new Set([".ts", ".mts", ".cts", ".js", ".mjs", ".cjs", ".tsx", ".jsx"]);
const problems: string[] = [];

const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
for (const kind of ["dependencies", "peerDependencies", "optionalDependencies", "bundleDependencies", "bundledDependencies"]) {
  for (const name of Object.keys(pkg[kind] ?? {})) problems.push(`package.json: ${kind} has ${name}: modest-auth has no runtime dependencies`);
}

async function files(dir: string): Promise<string[]> {
  const entries = await readdir(join(root, dir), { recursive: true, withFileTypes: true }).catch(() => []);
  return entries.filter((e) => e.isFile() && CODE.has(extname(e.name))).map((e) => relative(root, join(e.parentPath, e.name)));
}

const allowed = (spec: string) => spec.startsWith("node:") || spec.startsWith("./") || spec.startsWith("../");
let lines = 0;
// This file names the patterns it looks for, so it isn't searched itself.
const self = relative(root, import.meta.filename);
for (const file of [...(await files("src")), ...(await files("examples")), ...(await files("scripts")), ...(await files("test"))].filter((f) => f !== self)) {
  const code = await readFile(join(root, file), "utf8");
  if (file.startsWith("src") && !/\.test\.[a-z]+$/.test(file)) {
    lines += code.split("\n").length;
  }
  for (const [found] of code.matchAll(/[\p{Cf}\p{Default_Ignorable_Code_Point}\u2800]/gu)) {
    problems.push(`${file}: an invisible character (U+${(found.codePointAt(0) ?? 0).toString(16).toUpperCase()}): write it as an escape`);
  }
  // Every module named: `from "x"` (across lines), `import "x"`, `import("x")`, `import(`x`)`, `require("x")`.
  for (const [, , spec = ""] of code.matchAll(/(?:\bfrom|\bimport|\bimport\s*\(|\brequire\s*\()\s*(["'`])([^"'`\s]{1,200})\1/g)) {
    if (!allowed(spec) || spec.includes("${")) problems.push(`${file}: imports "${spec}": only node: modules and the project's own files`);
  }
  // Anything that loads code another way, or from a name worked out at run time.
  for (const [found] of code.matchAll(/\bcreateRequire\b|\brequire\s*\(|\bimport\s*\(\s*(?!["'`])|process\.binding|\bmodule\.constructor/g)) {
    problems.push(`${file}: "${found}": load modules with a plain import of a fixed name`);
  }
}

if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log(`Rules kept: no dependencies; only node: and own imports; source ${lines} lines.`);
