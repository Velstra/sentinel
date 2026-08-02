// What the console can actually write, as reported by the console itself.
//
// Regexing the source for field tables gets this wrong — several are wired up
// in ways a pattern does not see, and a miss reads as a gap that is not there.
// So the three builders that turn a field table into `set <path> <field>` are
// wrapped, every view and tab is opened, and what they were asked to build is
// written out.
//
//   tests/console/run.sh                       # start an appliance, then:
//   COVERAGE_OUT=cov.json node tests/console/coverage.mjs
//
// Compare the result with the `set` grammar in src/repl.rs. That comparison is
// how ten sections with no mask at all were found — see the coverage test in
// src/webui.rs, which pins what was closed.
import { browser, signIn } from "./harness.mjs";
import { writeFileSync } from "node:fs";

const page = await browser({ port: 0 });
await page.goto(process.env.CONSOLE_URL);
await signIn(page, process.env.CONSOLE_TOKEN);

await page.evaluate(`(() => {
  window.__seen = {};
  const note = (path, fields) => {
    if (!path) return;
    const key = String(path).replace(/\\s+/g, " ").trim();
    (window.__seen[key] ||= new Set());
    for (const f of fields || []) if (Array.isArray(f) && f[0] !== "#") window.__seen[key].add(f[0]);
  };
  const sp = settingsPanel;
  settingsPanel = (boxId, fields, current, path, label, form) => {
    note(path, fields); return sp(boxId, fields, current, path, label, form);
  };
  const ro = renderObjects;
  renderObjects = (o) => {
    try { note(o.path ? o.path("<n>") : null, o.fields); } catch (e) {}
    return ro(o);
  };
  const rap = typeof renderAddPanel === "function" ? renderAddPanel : null;
  if (rap) {
    renderAddPanel = (o) => {
      try { note(o.path ? o.path("<n>") : null, o.fields); } catch (e) {}
      return rap(o);
    };
  }
  return true;
})()`);

const labels = await page.evaluate(
  `[...document.querySelectorAll("aside button.navitem")].map((b) => b.textContent.trim())`);
console.error("rail entries:", labels.length);

for (let i = 0; i < labels.length; i++) {
  await page.evaluate(`(async () => {
    [...document.querySelectorAll("aside button.navitem")][${i}].click();
    await new Promise((r) => setTimeout(r, 450));
    return true;
  })()`).catch((e) => console.error("  !", labels[i], e.message));
}

// Then every tab of every strip, since a pane only builds when it is shown.
const strips = await page.evaluate(`Object.keys(TABS)`);
for (const v of strips) {
  const n = await page.evaluate(`(async () => {
    view = ${JSON.stringify("")} || view; await refresh();
    return (TABS[${JSON.stringify(v)}] || []).length;
  })()`).catch(() => 0);
  for (let i = 0; i < n; i++) {
    await page.evaluate(`(async () => {
      view = ${JSON.stringify(v)}; panel = null; await refresh();
      await new Promise((r) => setTimeout(r, 200));
      const strip = document.getElementById("tabs-" + ${JSON.stringify(v)});
      if (strip && strip.children[${i}]) strip.children[${i}].click();
      await new Promise((r) => setTimeout(r, 450));
      return true;
    })()`).catch((e) => console.error("  !", v, i, e.message));
  }
  console.error("tabs:", v, n);
}

const seen = await page.evaluate(
  `JSON.stringify(Object.fromEntries(Object.entries(window.__seen).map(([k, v]) => [k, [...v]])))`);
writeFileSync(process.env.COVERAGE_OUT || "ui-coverage.json", seen);
console.error("paths:", Object.keys(JSON.parse(seen)).length);
process.exit(0);
