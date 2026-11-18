// The settings catalogue behind "find a setting by name".
//
// `src/settings-index.json` is `[label, page, CLI path]` for every field a
// console mask offers. It is embedded into the page and read by the palette and
// the rail search. It is generated here, from the masks the console really
// builds — the three builders that turn a field table into a form are wrapped,
// every editable page is opened, and what they were asked to build is written
// down. A list typed beside the forms would drift from them the first time a
// field was added; this one is compared against a fresh walk by the browser
// suite (`workflow.mjs`), so a stale catalogue fails a test instead of sending
// an operator to the wrong page.
//
// Regenerate after adding, renaming or moving a field:
//
//   CONSOLE_TEST_FILE=settings-index.mjs tests/console/run.sh target/debug/sentinel
//
// then rebuild the binary so the new file is embedded.
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/// Walk every editable page and return the catalogue, sorted and de-duplicated.
/// Leaves the page on the dashboard with the builders restored.
export async function collectSettings(page) {
  const raw = await page.evaluate(`(async () => {
    const seen = [];
    // Where a mask is, read off the element it was built into — not the page
    // that happened to be open. A divided view builds every one of its panes
    // on each visit, so "the current tab" would credit all of them to it.
    const placeOf = (id) => {
      const node = id && document.getElementById(id);
      const box = node && node.closest('[id^="view-"]');
      if (!box) return viewKey();
      const pane = node.closest(".tabpane");
      return box.id.slice(5) + (pane && pane.dataset.tab ? ":" + pane.dataset.tab : "");
    };
    const note = (id, path, fields) => {
      const where = placeOf(id);
      const base = String(path || "").replace(/\\s+/g, " ").trim();
      for (const f of fields || []) {
        // A heading writes nothing; a field without a label cannot be searched for.
        if (!Array.isArray(f) || f[0] === "#" || typeof f[1] !== "string" || !f[1].trim()) continue;
        seen.push([f[1].trim(), where, (base + " " + f[0]).trim()]);
      }
    };
    const original = { settingsPanel, renderObjects, renderAddPanel, text };
    settingsPanel = (boxId, fields, current, path, label, form) => {
      note(boxId, path, fields); return original.settingsPanel(boxId, fields, current, path, label, form);
    };
    renderObjects = (o) => {
      try { note(o.listId || o.addId, o.path ? o.path("<name>") : "", o.fields); } catch (e) {}
      return original.renderObjects(o);
    };
    renderAddPanel = (o) => {
      try { note(o.addId || o.listId, o.path ? o.path("<name>") : "", o.fields); } catch (e) {}
      return original.renderAddPanel(o);
    };
    // The live panes are not what this measures, and each one is a child
    // process on the appliance. The configuration is the exception: the masks
    // that only exist once their object does are built from it.
    text = async (p) => (String(p).includes("/show/configuration") ? original.text(p) : "");
    const destinations = [];
    for (const group of SECTIONS) {
      for (const item of group.items) destinations.push(item.tab ? item.v + ":" + item.tab : item.v);
    }
    try {
      for (const key of destinations) {
        const [v, tab] = key.split(":");
        view = v; if (tab) tabs[v] = tab; panel = null;
        buildNav();
        await refresh();
        await new Promise((r) => setTimeout(r, 120));
      }
    } finally {
      settingsPanel = original.settingsPanel;
      renderObjects = original.renderObjects;
      renderAddPanel = original.renderAddPanel;
      text = original.text;
      view = "dashboard"; panel = null; buildNav(); await refresh();
    }
    return JSON.stringify(seen);
  })()`);
  const unique = new Map();
  for (const [label, where, path] of JSON.parse(raw)) {
    const key = label + "\u0000" + where;
    // One row per label and page: the first path a page builds for a label is
    // the one its own form writes.
    if (!unique.has(key)) unique.set(key, [label, where, path]);
  }
  return [...unique.values()].sort((a, b) =>
    a[0].localeCompare(b[0], "en") || a[1].localeCompare(b[1], "en") || a[2].localeCompare(b[2], "en"));
}

/// The catalogue as the file holds it: one entry per line, so a diff of the
/// file reads as the list of settings that moved.
export function formatSettings(entries) {
  return "[\n" + entries.map((e) => JSON.stringify(e)).join(",\n") + "\n]\n";
}

if (process.argv[1] && process.argv[1].endsWith("settings-index.mjs")) {
  const { browser, signIn } = await import("./harness.mjs");
  const page = await browser({ port: 0 });
  try {
    await page.goto(process.env.CONSOLE_URL);
    await signIn(page, process.env.CONSOLE_TOKEN);
    const entries = await collectSettings(page);
    const body = formatSettings(entries);
    // The page writes this into its script as a literal: it must stay
    // self-contained and must not read as code to the guards that scan it.
    for (const forbidden of ["</script", "<!--", "http://", "https://", "=>", '$("']) {
      if (body.toLowerCase().includes(forbidden)) throw new Error("the catalogue contains " + forbidden);
    }
    if (/[A-Za-z0-9_$]\(/.test(body)) throw new Error("a catalogue label reads as a function call");
    const here = dirname(fileURLToPath(import.meta.url));
    const out = process.env.SETTINGS_INDEX_OUT || join(here, "..", "..", "src", "settings-index.json");
    writeFileSync(out, body);
    console.log(`settings catalogue: ${entries.length} entries -> ${out}`);
    if (entries.length < 300) throw new Error("the catalogue unexpectedly shrank");
    const places = new Set(entries.map((e) => e[1]));
    if (places.size < 30) throw new Error("the catalogue names too few pages: " + places.size);
  } finally {
    page.close();
  }
}
