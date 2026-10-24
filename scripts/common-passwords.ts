// Makes src/common-passwords.txt: the common passwords long enough to pass the
// length rule, which are refused anyway. From two public lists in SecLists (MIT),
// at a fixed commit, so anyone can make the same file and check it.
//
//   node scripts/common-passwords.ts

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { SHORTEST_PASSWORD, LONGEST_PASSWORD } from "../src/passwords.ts";

const COMMIT = "a61e8f503c54bf3c399b8f9e4da97e7059a8437e";
const MIT = [
  "MIT License",
  "",
  "Copyright (c) 2018 Daniel Miessler",
  "",
  'Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:',
  "",
  "The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.",
  "",
  'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.',
];
const LISTS = ["Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt", "Passwords/Common-Credentials/Pwdb_top-1000000.txt"];

const all: string[] = [];
for (const list of LISTS) {
  const res = await fetch(`https://raw.githubusercontent.com/danielmiessler/SecLists/${COMMIT}/${list}`);
  if (!res.ok) throw new Error(`${list}: ${res.status}`);
  // One at a time: a million lines are too many to spread into one call.
  for (const raw of (await res.text()).split(/\r?\n/)) {
    // Some lists write awkward passwords in hashcat's "$HEX[...]" form: decode them.
    const hex = /^\$hex\[([0-9a-f]+)\]$/i.exec(raw);
    const line = hex ? new TextDecoder("utf-8", { fatal: false }).decode(Buffer.from(hex[1] ?? "", "hex")) : raw;
    all.push(line.normalize("NFKC").toLowerCase());
  }
}
const length = (text: string) => [...text].length;
const kept = [...new Set(all.filter((p) => length(p) >= SHORTEST_PASSWORD && length(p) <= LONGEST_PASSWORD && p.isWellFormed() && !p.startsWith("#")))].sort();

const head = [
  "# Common passwords of 15 characters or more, refused at sign-up and on changing a password.",
  '# Normalised (NFKC) and lowercase. Lines starting "#" are notes.',
  `# From SecLists, at commit ${COMMIT}:`,
  "#   Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt (the UK National Cyber Security Centre),",
  "#   Passwords/Common-Credentials/Pwdb_top-1000000.txt.",
  "# Made by scripts/common-passwords.ts. SecLists' licence:",
  ...MIT.map((line) => (line ? `#   ${line}` : "#")),
];
await writeFile(join(import.meta.dirname, "..", "src", "common-passwords.txt"), `${[...head, ...kept].join("\n")}\n`);
console.log(`${kept.length} passwords`);
