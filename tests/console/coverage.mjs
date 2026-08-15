// What the console can actually write, as reported by the console itself.
//
// Regexing the source for field tables gets this wrong — several are wired up
// in ways a pattern does not see, and a miss reads as a gap that is not there.
// So the three builders that turn a field table into `set <path> <field>` are
// wrapped, every view and tab is opened, and what they were asked to build is
// written out.
//
// Used two ways: as a module by the console's own test suite, which turns the
// result into a coverage assertion against `cli-fields.txt`, and standalone to
// look at the detail:
//
//   tests/console/run.sh                       # start an appliance, then:
//   COVERAGE_OUT=cov.json node tests/console/coverage.mjs
import { writeFileSync } from "node:fs";

/// Wrap the builders and `stage`, so everything the console offers to write is
/// recorded whether it comes from a field table or from a bespoke control.
///
/// `swallow` decides what happens to a staged change afterwards. The standalone
/// pass throws it away — it is taking an inventory, and a staged change would
/// follow it into the next section. A test suite that only wants the recording
/// must NOT: the other tests stage, apply and read back, and eating their
/// changes would break every one of them.
/// `live` decides whether the live-state panes really ask the appliance. They
/// are not what this measures — a pane is `show` output, not a way to configure
/// anything — and each one is a child process on the appliance, so a walk that
/// opens every page and moves every dropdown spends nearly all of its time
/// waiting for them: forty minutes against a debug build, versus three.
///
/// The configuration is NOT one of those, even though it arrives the same way.
/// Stubbing it too left the console blind: every list empty, every picker empty,
/// and every mask that only exists once its object does — a route map's
/// settings, a DHCP server's row — never built. The walk then reported those as
/// things the console cannot do.
export const instrument = (page, { swallow = true, live = false } = {}) =>
  page.evaluate(`(() => {
  const SWALLOW = ${JSON.stringify(swallow)};
  if (!${JSON.stringify(live)}) {
    const real = text;
    text = async (p) => (String(p).includes("/show/configuration") ? real(p) : "");
  }
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
  // The three builders above only see the generic masks. A great deal of the
  // console is bespoke: a default-policy dropdown, a posture checkbox, a
  // "generate" button. Those write through stage(), so wrapping it and then
  // actually operating every control is the only way to learn what they can do
  // -- and doubles as a check that a control does something at all.
  window.__staged = [];
  const st = stage;
  stage = (label, cmds) => {
    for (const c of cmds || []) window.__staged.push(String(c));
    if (!SWALLOW) return st(label, cmds);
    staged = []; dirty.clear(); renderStaged();
    return undefined;
  };
  return true;
})()`);

/// Operate every control the current view offers, and let the wrappers record
/// what each one wanted to write.
///
/// `panels` opens the "New"/"Edit" buttons as well. Off by default: the add
/// panel's own mask is built by `renderAddPanel` on every render, so it is
/// already recorded without clicking anything, and clicking every button on
/// every page is most of what this pass costs.
const exercise = (page, panels = false) =>
  page.evaluate(`(async () => {
    const PANELS = ${JSON.stringify(panels)};
    // A render is synchronous; what follows it is a config fetch the masks do
    // not wait for. So the pause after operating a control only has to let the
    // task queue turn over — at sixty milliseconds a control this walk spent
    // most of an hour asleep.
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 15));
    // Every section lives in the document at once and all but one is display:
    // none, so an unscoped query hands this walk the whole console on every
    // page — the same five hundred controls, sixty times over. Only what is on
    // screen belongs to the page being walked; the rest gets its turn when its
    // own page comes up.
    const onScreen = (n) => n.offsetParent !== null || n.getClientRects().length > 0;
    let touched = 0;
    for (const sel of [...document.querySelectorAll("select")].filter(onScreen)) {
      // A cap, because a few selects list every timezone or every country and
      // the mask behind them does not change from one to the next. What a value
      // can switch — a link's kind, a rule's protocol — it switches within the
      // first handful.
      for (const opt of [...sel.options].slice(0, 8)) {
        if (!opt.value) continue;
        sel.value = opt.value;
        sel.dispatchEvent(new Event("change", { bubbles: true }));
        touched++;
        await wait();
      }
    }
    // Some settings are verbs rather than fields: dhcp-server enable takes no
    // value, so no mask can hold it and only the button that says it writes it.
    // Pressed always, panels or not: a verb the console alone can express is
    // exactly the kind of thing this walk exists to find. Safe, because stage
    // is wrapped here and throws the change away.
    for (const b of [...document.querySelectorAll("button")].filter(onScreen)) {
      if (!/^(enable|turn off|advertise)\\b/i.test((b.textContent || "").trim())) continue;
      try { b.click(); } catch (e) {}
      touched++;
      await wait();
    }
    // Panels that only build when asked for. A mask nobody opened is a mask
    // this inventory never sees, which is how the global firewall posture read
    // as missing while it was sitting one click away.
    for (const b of (PANELS ? [...document.querySelectorAll("button")] : []).filter(onScreen)) {
      const t = (b.textContent || "").trim().toLowerCase();
      const id = b.id || "";
      if (/^(new|add|edit|configure|settings)\\b/.test(t) || /^(toggle|edit|add)/.test(id)) {
        try { b.click(); } catch (e) {}
        touched++;
        await wait(60);
      }
    }
    // One flip is enough to learn what a checkbox writes. Flipping it back was
    // tidiness — and this pass throws its staged changes away regardless.
    for (const box of [...document.querySelectorAll("input[type=checkbox]")].filter(onScreen)) {
      box.checked = !box.checked;
      box.dispatchEvent(new Event("change", { bubbles: true }));
      touched++;
      await wait();
    }
    return touched;
  })()`).catch((e) => (console.error("  ! exercise", e.message), 0));

/// Open every category, every page inside it, and every tab strip, exercising
/// each. One call per step: a build sandbox is slow enough that a single
/// evaluate over the whole console times out, and that reports as a page that
/// stopped answering.
export const walkAll = async (page, log = () => {}, panels = false) => {
  const cats = await page.evaluate(
    `[...document.querySelectorAll("aside button.navitem")].map((b) => b.textContent.trim())`);
  log(`rail entries: ${cats.length}`);
  for (let i = 0; i < cats.length; i++) {
    const pages = await page.evaluate(`(async () => {
      [...document.querySelectorAll("aside button.navitem")][${i}].click();
      await new Promise((r) => setTimeout(r, 350));
      return document.querySelectorAll("#sectionstrip .secitem").length || 1;
    })()`).catch((e) => (log(`  ! ${cats[i]} ${e.message}`), 1));
    for (let p = 0; p < pages; p++) {
      await page.evaluate(`(async () => {
        const strip = document.querySelectorAll("#sectionstrip .secitem");
        if (strip[${p}]) strip[${p}].click();
        await new Promise((r) => setTimeout(r, 300));
        return true;
      })()`).catch((e) => log(`  ! ${cats[i]}/${p} ${e.message}`));
      const spent = await exercise(page, panels);
      log(`  ${cats[i]} ${p + 1}/${pages}: ${spent} controls`);
    }
  }

  // Then every tab of every strip, since a pane only builds when it is shown.
  //
  // Set the state rather than clicking the control that sets it: the console
  // has had two navigations in its life — a per-view tab strip, then one strip
  // for the whole category — and a walk that clicks `#tabs-<view>` silently
  // stopped switching tabs the day that element went away. Every mask behind a
  // non-default tab then read as a mask the console does not have.
  const strips = await page.evaluate(`Object.keys(TABS)`);
  for (const v of strips) {
    const n = await page.evaluate(`(TABS[${JSON.stringify(v)}] || []).length`).catch(() => 0);
    for (let i = 0; i < n; i++) {
      await page.evaluate(`(async () => {
        view = ${JSON.stringify(v)}; panel = null;
        const tab = (TABS[${JSON.stringify(v)}] || [])[${i}];
        if (tab && typeof tabs === "object") tabs[${JSON.stringify(v)}] = tab.k;
        await refresh();
        await new Promise((r) => setTimeout(r, 400));
        return true;
      })()`).catch((e) => log(`  ! ${v} ${i} ${e.message}`));
      log(`  ${v} tab ${i + 1}/${n}: ${await exercise(page, panels)} controls`);
    }
  }
};

/// Fold what was recorded into `path -> [field]`. The bespoke controls staged
/// whole command lines, so those are reduced to the same shape: the last word
/// of a `set` line is its value, the one before it the field.
export const collect = async (page) => {
  const staged = JSON.parse(await page.evaluate(`JSON.stringify(window.__staged)`));
  const seen = JSON.parse(await page.evaluate(
    `JSON.stringify(Object.fromEntries(Object.entries(window.__seen).map(([k, v]) => [k, [...v]])))`));
  const note = (path, field) => {
    if (!path || !field) return;
    (seen[path] ||= []);
    if (!seen[path].includes(field)) seen[path].push(field);
  };
  for (const line of staged) {
    const w = line.trim().split(/\s+/);
    if (w[0] !== "set" || w.length < 3) continue;
    note(w.slice(1, w.length - 2).join(" "), w[w.length - 2]);
    // A line can also end in the setting itself: `dhcp-server enable` takes no
    // value, and reading it as a value would credit the console with the field
    // above it and never with the verb. A word that could be a value is not
    // read this way — and a keyword that turns out to name nothing the CLI has
    // simply never matches, so the reading costs nothing when it is wrong.
    const last = w[w.length - 1];
    if (/^[a-z][a-z0-9_-]*$/.test(last) && last !== "true" && last !== "false") {
      note(w.slice(1, w.length - 1).join(" "), last);
    }
  }
  return { seen, staged };
};

/// `section field` pairs, the shape `cli-fields.txt` records.
///
/// Object names are dropped rather than reconciled: the CLI inventory names
/// them one way (a seeded `eth0`) and the console another (a placeholder), and
/// a comparison that has to line those up mostly measures the lining up. What
/// a section can express survives both spellings.
/// A mask's key can carry the path to the setting rather than just its name —
/// `pppoe username`, `ip proxy-arp`, `bridge-port cost` — because one form
/// covers a whole link. The CLI names the same setting by its last word, which
/// is the position a value goes into, so that is what both sides compare on.
/// Reading the key whole instead reported eighty settings as missing that the
/// console had had a field for all along.
export const sectionFields = (seen) => {
  const out = new Set();
  for (const [path, fields] of Object.entries(seen)) {
    const section = path.split(/\s+/)[0];
    if (!section || section.startsWith("<")) continue;
    for (const key of fields) {
      const f = String(key || "").trim().split(/\s+/).pop();
      if (f && !f.startsWith("<")) out.add(`${section} ${f}`);
    }
  }
  return out;
};

// Standalone: run the whole pass — panels included, since a person reading the
// detail wants everything the console can build.
if (process.argv[1] && process.argv[1].endsWith("coverage.mjs")) {
  const { browser, signIn } = await import("./harness.mjs");
  const page = await browser({ port: 0 });
  await page.goto(process.env.CONSOLE_URL);
  await signIn(page, process.env.CONSOLE_TOKEN);
  await instrument(page);
  await walkAll(page, (m) => console.error(m), true);
  const { seen, staged } = await collect(page);
  writeFileSync(process.env.COVERAGE_OUT || "ui-coverage.json", JSON.stringify(seen));
  console.error("staged by bespoke controls:", staged.length);
  console.error("paths:", Object.keys(seen).length);
  process.exit(0);
}
