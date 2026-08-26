import { readFileSync } from "node:fs";
import { sectionFields } from "./coverage.mjs";
const seen = JSON.parse(readFileSync(process.env.COV, "utf8"));
const reached = sectionFields(seen);
const wanted = readFileSync("cli-fields.txt", "utf8").split("\n").map(l => l.trim()).filter(Boolean);
const bySection = new Map();
for (const pair of wanted) {
  const section = pair.split(" ")[0];
  const s = bySection.get(section) || { have: 0, want: 0, missing: [] };
  s.want++;
  if (reached.has(pair)) s.have++; else s.missing.push(pair.split(" ")[1]);
  bySection.set(section, s);
}
const have = [...bySection.values()].reduce((a, s) => a + s.have, 0);
console.log(`console covers ${have}/${wanted.length} CLI fields (${Math.round(have/wanted.length*100)}%)`);
for (const [sec, s] of [...bySection].sort((a,b) => a[1].have/a[1].want - b[1].have/b[1].want).slice(0, 8))
  console.log(`  ${sec.padEnd(14)} ${String(s.have).padStart(3)}/${s.want}${s.missing.length ? "  missing: " + s.missing.slice(0,5).join(", ") : ""}`);
