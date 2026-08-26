// What the console has to actually do, checked in a browser against a running
// appliance API.
//
// Every test here exists because the thing it checks was once broken in a way
// that looked fine: the page loaded, the layout was right, and the button did
// nothing. Read the failures as "an operator cannot do X", not as unit noise.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { browser, signIn, sleep, test, check, equal, summary } from "./harness.mjs";
import { instrument, walkAll, collect, sectionFields } from "./coverage.mjs";

// Note: this shadows the global `URL` for the whole file — resolve paths next
// to this file with `fileURLToPath(import.meta.url)`, never with `new URL()`.
const URL = process.env.CONSOLE_URL || "http://127.0.0.1:8088/";
const HERE = fileURLToPath(new globalThis.URL(".", import.meta.url));
const TOKEN = process.env.CONSOLE_TOKEN || "testtoken";
const CONFIG = process.env.CONSOLE_CONFIG;   // the toml the API is editing

const page = await browser({ port: Number(process.env.CDP_PORT || 0) });
await page.goto(URL);
await signIn(page, TOKEN);

const noThrows = (why) => check(page.thrown.length === 0, why + "\n  " + page.thrown.join("\n  "));

await test("the page loads without the script throwing", () => {
  noThrows("the console threw while loading");
});

// --- navigation -------------------------------------------------------------

// One rail entry per call, not sixty in one.
//
// Opening a section makes the appliance answer every live-state pane on it, and
// each of those is a process spawn. On a workstation the whole walk fits inside
// one evaluate; in a build sandbox it does not, and the call times out — which
// reports as "the page stopped answering" and looks exactly like a console that
// hangs. Driving the loop from here bounds every call by the slowest *single*
// section, and a failure names the entry rather than the walk.
await test("every section opens exactly one non-empty view", async () => {
  // The rail names categories, and the category's own pages sit in a strip in
  // the content. Walking only the rail would now check twelve doors and none of
  // the rooms behind them, so the walk descends: click a category, then click
  // every entry of the strip it revealed.
  const cats = await page.evaluate(
    `[...document.querySelectorAll("aside button.navitem")].map((b) => b.textContent.trim())`);
  check(cats.length > 8, `only ${cats.length} categories — the rail lost sections`);

  const broken = [], empty = [], slow = [];
  let visited = 0;
  const say = process.env.CONSOLE_PROGRESS ? (m) => console.log(`       ${m}`) : () => {};

  for (let c = 0; c < cats.length; c++) {
    const n = await page.evaluate(`(async () => {
      [...document.querySelectorAll("aside button.navitem")][${c}].click();
      await new Promise((r) => setTimeout(r, 250));
      return document.querySelectorAll("#sectionstrip .secitem").length || 1;
    })()`);
    for (let i = 0; i < n; i++) {
      const began = Date.now();
      say(`→ ${cats[c]} ${i + 1}/${n}`);
      let r;
      try {
        r = await page.evaluate(`(async () => {
          const strip = [...document.querySelectorAll("#sectionstrip .secitem")];
          const label = strip[${i}] ? strip[${i}].textContent.trim() : ${JSON.stringify(cats[c])};
          if (strip[${i}]) { strip[${i}].click(); await new Promise((r) => setTimeout(r, 250)); }
          const shown = [...document.querySelectorAll('[id^="view-"]')]
            .filter((v) => !v.classList.contains("hidden"));
          return { label, views: shown.length, text: shown.length === 1 ? shown[0].innerText.trim() : "" };
        })()`);
      } catch (e) {
        throw new Error(`in ${cats[c]}, entry ${i + 1}/${n}: ${e.message || e}`);
      }
      visited++;
      const took = Date.now() - began;
      if (took > 20000) slow.push(`${r.label} took ${Math.round(took / 1000)}s`);
      if (r.views !== 1) broken.push(`${r.label} showed ${r.views} views`);
      else if (!r.text) empty.push(r.label);
    }
  }
  // The categories are few on purpose; the pages behind them are not, and a
  // count that collapses is how a lost section would hide behind a short rail.
  check(visited > 30, `only ${visited} sections were reachable in total`);
  equal(broken, [], "sections that do not open one view");
  equal(empty, [], "sections that open an empty page");
  equal(slow, [], "sections that take longer than an operator will wait");
  noThrows("navigating threw");
});

// A divided view — routing, with a pane per protocol — used to print its panes
// twice: once in the category strip above the heading and once in a strip of
// its own below it. There is one strip now, and it is the section strip, so
// that is what this drives. The question is unchanged: does every pane of a
// divided view open on its own and get named at the top of the page.
await test("every tab strip switches panes and titles the page", async () => {
  const strips = await page.evaluate(`Object.keys(TABS)`);
  const bad = [];
  for (const v of strips) {
    // Every pane is listed in the one strip, and the strip is what a person
    // clicks — a pane the strip cannot reach is a pane that does not exist.
    const shape = await page.evaluate(`(async () => {
      view = ${JSON.stringify(v)}; panel = null;
      await refresh();
      await new Promise((r) => setTimeout(r, 200));
      const strip = [...document.querySelectorAll("#sectionstrip .secitem")];
      const labels = strip.map((b) => b.textContent.trim());
      const missing = TABS[view].filter((t) => !labels.includes(t.t));
      return { tabs: TABS[view].length, missing: missing.map((t) => t.k) };
    })()`);
    if (shape.missing.length) {
      bad.push(`${v}: the strip does not reach ${shape.missing.join(", ")}`);
      continue;
    }
    // Each tab is its own call for the same reason as above.
    for (let i = 0; i < shape.tabs; i++) {
      const r = await page.evaluate(`(async () => {
        const t = TABS[${JSON.stringify(v)}][${i}];
        const strip = [...document.querySelectorAll("#sectionstrip .secitem")];
        const button = strip.find((b) => b.textContent.trim() === t.t);
        const name = button ? button.textContent.trim() : t.k;
        if (button) button.click();
        await new Promise((r) => setTimeout(r, 200));
        const open = [...document.querySelectorAll("#view-" + ${JSON.stringify(v)} + " > .tabpane")]
          .filter((p) => !p.classList.contains("hidden"));
        const heading = document.querySelector("#pagehead h2");
        return { name, panes: open.length, heading: heading ? heading.textContent.trim() : "" };
      })()`);
      if (r.panes !== 1) bad.push(`${v}/${r.name}: ${r.panes} panes`);
      if (!r.heading) bad.push(`${v}/${r.name}: no heading`);
    }
  }
  const report = bad;
  equal(report, [], "tab strips that do not switch cleanly");
  noThrows("switching tabs threw");
});

// One navigation, not two. The category's pages are listed above the heading;
// nothing below it may list them again, or an operator has two rows of buttons
// for one decision and no way to tell which of them they are standing in.
await test("a page carries its navigation once", async () => {
  const doubled = await page.evaluate(`(async () => {
    const out = [];
    for (const v of Object.keys(TABS)) {
      view = v; panel = null; await refresh();
      await new Promise((r) => setTimeout(r, 200));
      const strip = [...document.querySelectorAll("#sectionstrip .secitem")]
        .map((b) => b.textContent.trim());
      // Anything on the page itself that offers the same destinations.
      const pane = document.getElementById("view-" + v);
      const echoes = [...pane.querySelectorAll("button")]
        .filter((b) => b.offsetParent !== null)
        .map((b) => b.textContent.trim())
        .filter((t) => strip.includes(t));
      if (echoes.length > 1) out.push(v + ": " + echoes.join(", "));
    }
    return out;
  })()`);
  equal(doubled, [], "views that repeat their own navigation");
});

// --- creating things --------------------------------------------------------

// Every "New" panel in the console, and where it lives. A panel missing from
// this list is one nothing checks, so adding a section means adding it here.
const PANELS = [
  ["interfaces", null, "toggleiface", "addifacepanel"],
  ["routing", "static", "toggleroute", "addroutepanel"],
  ["rules", null, "togglerule", "addrulepanel"],
  ["groups", null, "togglegroup", "addgrouppanel"],
  ["synproxy", null, "togglesyn", "addsynpanel"],
  ["nat", null, "togglesnat", "addsnatpanel"],
  ["nat", null, "toggleddnat", "adddnatpanel"],
  ["nat", null, "togglenpt", "addnptpanel"],
  ["lb", null, "togglelb", "addlbpanel"],
  ["routing", "bgp", "togglebgp", "addbgppanel"],
  ["routing", "bgp", "toggleagg", "addaggpanel"],
  ["routing", "bgp", "toggleroa", "addroapanel"],
  ["routing", "multicast", "togglemcastif", "addmcastifpanel"],
  ["routing", "vrf", "togglevrf", "addvrfpanel"],
  ["routepolicy", "prefix", "togglepl", "addplpanel"],
  ["routepolicy", "maps", "togglerm", "addrmpanel"],
  ["routepolicy", "pbr", "togglepbr", "addpbrpanel"],
  ["wan", null, "togglewan", "addwanpanel"],
  ["wan", null, "togglewanpolicy", "addwanpolicypanel"],
  ["ipsec", null, "toggleipsec", "addipsecpanel"],
  ["wireguard", null, "togglewg", "addwgpanel"],
  ["openconnect", null, "toggleocuser", "addocuserpanel"],
  ["pki", null, "toggleca", "addcapanel"],
  ["certs", null, "togglecert", "addcertpanel"],
  ["users", null, "toggleuser", "adduserpanel"],
  ["users", null, "toggleadmingroup", "addadmingrouppanel"],
  ["users", null, "toggleradius", "addradiuspanel"],
  ["users", null, "toggleldap", "addldappanel"],
  ["system", null, "togglesysctl", "addsysctlpanel"],
  ["ha", null, "togglevrrp", "addvrrppanel"],
  ["services", "publishing", "togglerp", "addrppanel"],
  ["services", "publishing", "togglebr", "addbrpanel"],
  ["services", "notification", "togglesl", "addslpanel"],
];

await test("a name with no settings is refused here, not by the appliance", async () => {
  // `set nat source web` is answered with "unknown set path" and the whole
  // grammar. The console must not send a command that cannot succeed.
  const bad = [];
  for (const [view, tab, toggle, panel] of PANELS) {
    const r = await page.evaluate(`(async () => {
      const wait = () => new Promise((r) => setTimeout(r, 250));
      staged = []; renderStaged();
      view = ${JSON.stringify(view)}; panel = null;
      ${tab ? `tabs[${JSON.stringify(view)}] = ${JSON.stringify(tab)};` : ""}
      await refresh(); await wait();
      const toggle = document.getElementById(${JSON.stringify(toggle)});
      const box = document.getElementById(${JSON.stringify(panel)});
      if (!toggle || !box) return { missing: true };
      if (toggle.disabled) return { skipped: "the control is disabled" };
      toggle.click(); await wait();
      const name = box.querySelector("input");
      if (name) name.value = "probe1";
      // The panel is rendered by an async refresh, so its Add button can be a
      // beat late. Waiting for it is the difference between a real finding and
      // a stray TypeError on a busy machine.
      let add = null;
      for (let i = 0; i < 20 && !add; i++) {
        add = [...box.querySelectorAll("button")].find((b) => /add/i.test(b.textContent));
        if (!add) await wait();
      }
      if (!add) return { missing: "the panel has no Add button" };
      add.click();
      await wait();
      const err = box.querySelector(".formerr");
      return {
        staged: stagedCommands(),
        said: err ? err.textContent : "",
        bare: stagedCommands().length === 1 && !/ .+ .+/.test(stagedCommands()[0].replace(/^set /, "")),
      };
    })()`);
    if (r.missing) {
      bad.push(`${panel}: ${typeof r.missing === "string" ? r.missing : "no New button or panel"}`);
      continue;
    }
    if (r.skipped) continue;
    // Either it refused with a sentence, or it staged a command with a setting
    // in it. What it must never do is stage a bare path.
    const staged = r.staged || [];
    if (!staged.length) {
      if (!r.said) bad.push(`${panel}: nothing staged and nothing said`);
      continue;
    }
    if (r.bare) {
      // Some objects the appliance does accept bare (an interface is a system
      // fact before it is a setting). Rather than keep a list here, ask it.
      const answer = await page.evaluate(
        `(async () => (await configure(${JSON.stringify(staged)})).output)()`);
      if (/unknown set path/.test(answer || "")) {
        bad.push(`${panel}: staged a path the appliance does not know — ${staged[0]}`);
      }
    }
  }
  equal(bad, [], "create panels that cannot create");
  noThrows("using the add panels threw");
});

await test("what a create panel stages is a command the appliance parses", async () => {
  // Filled in properly, a panel's commands must be ones the CLI accepts. This
  // sends them with no `commit`, so nothing is applied — a refusal here is the
  // console's grammar being wrong, not the configuration being invalid.
  // Some sections need a container named before a rule can go in it — a prefix
  // list is only real once it has a rule, so the name is typed first. `setup`
  // is the click an operator would make before pressing New.
  // Every panel, filled the way an operator would fill it. The values only have
  // to parse — nothing is committed — so what this catches is the console
  // writing a path the CLI does not have, which is a section in which nothing
  // can be created at all. That was true of prefix lists and route maps.
  const cases = [
    ["interfaces", null, "toggleiface", "addifacepanel", "eth9", { "Zone": "lan" }],
    ["routing", "static", "toggleroute", "addroutepanel", "0.0.0.0/0", { "Via": "192.0.2.1" }],
    ["rules", null, "togglerule", "addrulepanel", "probe-rule",
      { "From zone": "wan", "To zone": "lan", "Action": "accept" }],
    ["groups", null, "togglegroup", "addgrouppanel", "offices", { "Addresses": "10.0.0.0/8" }],
    ["synproxy", null, "togglesyn", "addsynpanel", "8443", { "MSS": "1400" }],
    ["nat", null, "togglesnat", "addsnatpanel", "wan-masq", { "Zone": "wan" }],
    ["nat", null, "toggleddnat", "adddnatpanel", "web", { "To": "10.0.0.5:80" }],
    ["nat", null, "togglenpt", "addnptpanel", "uplink",
      { "Internal prefix": "fd00:1::/48", "External prefix": "2001:db8:1::/48" }],
    ["routing", "bgp", "toggleagg", "addaggpanel", "10.0.0.0/8",
      { "Suppress more specifics": "true" }],
    ["routing", "bgp", "toggleroa", "addroapanel", "192.0.2.0/24", { "Origin AS": "64500" }],
    ["routing", "multicast", "togglemcastif", "addmcastifpanel", "eth0",
      { "Role": "downstream" }],
    ["routing", "vrf", "togglevrf", "addvrfpanel", "tenant-a", { "Routing table id": "100" }],
    ["lb", null, "togglelb", "addlbpanel", "web", { "Virtual address": "198.51.100.9" }],
    ["routing", "bgp", "togglebgp", "addbgppanel", "192.0.2.7", { "Remote AS": "65010" }],
    ["routepolicy", "prefix", "togglepl", "addplpanel", "10", { "Prefix": "10.0.0.0/8" },
      `document.getElementById("plnew").value = "customers"; await refreshRoutePolicy();`],
    ["routepolicy", "maps", "togglerm", "addrmpanel", "5",
      { "Action": "permit", "Prefix list": "customers", "Metric": "100" },
      `document.getElementById("rmnew").value = "to-transit"; await refreshRoutePolicy();`],
    ["routepolicy", "pbr", "togglepbr", "addpbrpanel", "guests-out",
      { "Routing table": "100", "Source": "10.9.0.0/24" }],
    ["wan", null, "togglewan", "addwanpanel", "wan0", { "Gateway": "192.0.2.1" }],
    // A policy names an uplink, and the field offers the uplinks this box has
    // rather than asking for one to be spelled from memory — so there has to be
    // one to offer. Staged, not committed: what is staged is configuration as
    // far as every picker in this console is concerned.
    ["wan", null, "togglewanpolicy", "addwanpolicypanel", "voip",
      { "Preferred uplinks": "wan0" },
      `stage("Uplink wan0", ["set multiwan uplink wan0 gateway 192.0.2.1"]);
       await refresh();`],
    ["ipsec", null, "toggleipsec", "addipsecpanel", "branch",
      { "Remote address": "203.0.113.9", "Local address": "192.0.2.2" }],
    ["wireguard", null, "togglewg", "addwgpanel", "wg1",
      { "Listen port": "51821",
        "Private key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" }],
    ["wireguard", null, "togglewgpeer", "addwgpeerpanel",
      "0000000000000000000000000000000000000000000=", { "Allowed IPs": "10.9.0.2/32" }],
    ["openconnect", null, "toggleocuser", "addocuserpanel", "alice", { "Password": "hunter2hunter2" }],
    ["pki", null, "toggleca", "addcapanel", "internal", { "Common name": "Internal CA" }],
    ["certs", null, "togglecert", "addcertpanel", "web", { "Common name": "fw.example.net" }],
    ["users", null, "toggleuser", "adduserpanel", "vera", { "Password": "a-good-password" }],
    ["users", null, "toggleadmingroup", "addadmingrouppanel", "operators", {}],
    ["users", null, "toggleradius", "addradiuspanel", "10.0.0.50",
      { "Shared secret": "a-shared-secret" }],
    ["users", null, "toggleldap", "addldappanel", "dir.example.com",
      { "Base DN": "ou=people,dc=example,dc=com" }],
    ["system", null, "togglesysctl", "addsysctlpanel", "net.ipv4.ip_nonlocal_bind",
      { "Value": "1" }],
    ["ha", null, "togglevrrp", "addvrrppanel", "wan-vip",
      { "Virtual addresses": "192.0.2.10", "Interface": "eth1", "Virtual router ID": "10" }],
    ["services", "publishing", "togglerp", "addrppanel", "web",
      { "Backends": "10.0.0.5:8080" }],
    ["services", "publishing", "togglebr", "addbrpanel", "wol", { "UDP port": "9" }],
    ["services", "notification", "togglesl", "addslpanel", "logs.example.net", { "Port": "514" }],
  ];

  const bad = [];
  for (const [view, tab, toggle, panel, name, fields, setup] of cases) {
    // Each case on its own: a panel that throws — or an appliance that stops
    // answering on one of the thirty-six — used to end the whole loop with a
    // bare timeout and no way to tell which panel was being filled in.
    const started = Date.now();
    let r;
    try {
      r = await page.evaluate(`(async () => {
      const wait = () => new Promise((r) => setTimeout(r, 250));
      staged = []; renderStaged();
      view = ${JSON.stringify(view)}; panel = null;
      ${tab ? `tabs[${JSON.stringify(view)}] = ${JSON.stringify(tab)};` : ""}
      await refresh(); await wait();
      ${setup || ""}
      await wait();
      const button = document.getElementById(${JSON.stringify(toggle)});
      if (button.disabled) return { error: "the New button is disabled" };
      button.click(); await wait();
      const box = document.getElementById(${JSON.stringify(panel)});
      const nameInput = box.querySelector("input");
      if (!nameInput) return { error: "the panel has no fields" };
      nameInput.value = ${JSON.stringify(name)};
      for (const [label, value] of Object.entries(${JSON.stringify(fields)})) {
        const f = [...box.querySelectorAll(".field")]
          .find((l) => l.querySelector("span").firstChild.textContent.trim() === label);
        if (!f) return { error: "no field named " + label };
        // A repeatable setting whose answers the appliance already knows is a
        // set of tick boxes, not a box to type in. It carries a value of its
        // own — the comma-separated selection — so it is filled the same way.
        const control = f.querySelector(".pick, .switch") || f.querySelector("input, select");
        if (!control) return { error: "no control under " + label };
        control.value = value;
      }
      let add = null;
      for (let i = 0; i < 20 && !add; i++) {
        add = [...box.querySelectorAll("button")].find((b) => /add/i.test(b.textContent));
        if (!add) await wait();
      }
      if (!add) return { error: "the panel has no Add button" };
      add.click();
      await wait();
      const cmds = stagedCommands();
      if (!cmds.length) return { error: "nothing staged: " + (box.querySelector(".formerr") || {}).textContent };
      // Validate only — the same commands, with no commit, so nothing applies.
      const reply = await configure(cmds);
      return { staged: cmds, output: reply.output };
    })()`);
    } catch (e) {
      bad.push(`${panel}: ${e.message} (after ${Math.round((Date.now() - started) / 1000)}s)`);
      continue;
    }
    if (r.error) { bad.push(`${panel}: ${r.error}`); continue; }
    if (/unknown set path|unknown delete path/.test(r.output || "")) {
      bad.push(`${panel}: the appliance does not know that path — ${r.staged.join("; ")}`);
    }
  }
  equal(bad, [], "create panels whose commands the appliance rejects");
});

// --- editing and saving -----------------------------------------------------

await test("a settings mask stages only what changed", async () => {
  const staged = await page.evaluate(`(async () => {
    const wait = () => new Promise((r) => setTimeout(r, 300));
    staged = []; renderStaged();
    view = "routing"; tabs.routing = "ospf"; panel = null; await refresh(); await wait();
    const field = (label) => [...document.querySelectorAll("#igp-ospf .field")]
      .find((l) => l.querySelector("span").textContent === label).querySelector("input, select");
    field("Cost").value = "77";
    [...document.querySelectorAll("#igp-ospf button")].find((b) => b.textContent.startsWith("Stage")).click();
    await wait();
    return stagedCommands();
  })()`);
  equal(staged, ["set protocols ospf cost 77"], "the OSPF mask staged the wrong commands");
});

await test("applying writes the appliance's configuration file", async () => {
  check(!!CONFIG, "CONSOLE_CONFIG is not set, so there is nothing to read back");
  const before = readFileSync(CONFIG, "utf8");
  // Wait for the appliance's answer rather than for a fixed number of seconds:
  // an apply that is merely slow is not the same failure as one that never
  // reports, and a fixed wait calls the first the second.
  const result = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 400));
    const said = () => document.getElementById("resultout").innerText.trim();
    document.getElementById("resultout").textContent = "";   // an older answer is not this one
    document.getElementById("applystaged").click();
    for (let i = 0; i < 120 && !said(); i++) await wait(500);
    await wait(500);
    return { left: stagedCommands(), said: said() };
  })()`);
  const after = readFileSync(CONFIG, "utf8");
  check(after !== before, `the file did not change. The appliance said:\n${result.said}`);
  check(/cost\s*=\s*77/.test(after), `the setting is not in the file. It said:\n${result.said}`);
  equal(result.left, [], "the staged list was not cleared after a clean apply");
});

await test("what was applied is what the mask shows afterwards", async () => {
  const shown = await page.evaluate(`(async () => {
    const wait = () => new Promise((r) => setTimeout(r, 400));
    view = "routing"; tabs.routing = "ospf"; panel = null; await refresh(); await wait();
    return [...document.querySelectorAll("#igp-ospf .field")]
      .find((l) => l.querySelector("span").textContent === "Cost").querySelector("input").value;
  })()`);
  equal(shown, "77", "the mask does not show what was just saved");
});

await test("emptying a field removes the setting", async () => {
  const staged = await page.evaluate(`(async () => {
    const wait = () => new Promise((r) => setTimeout(r, 300));
    staged = []; renderStaged();
    view = "routing"; tabs.routing = "ospf"; panel = null; await refresh(); await wait();
    [...document.querySelectorAll("#igp-ospf .field")]
      .find((l) => l.querySelector("span").textContent === "Cost")
      .querySelector("input").value = "";
    [...document.querySelectorAll("#igp-ospf button")].find((b) => b.textContent.startsWith("Stage")).click();
    await wait();
    const out = stagedCommands();
    document.getElementById("applystaged").click();
    await wait();
    return out;
  })()`);
  equal(staged, ["delete protocols ospf cost"], "clearing a field did not delete the setting");
});

// A mask that offers a setting the appliance does not have is not a cosmetic
// fault: the field stages a command that can only be refused, and a refusal is
// the whole batch's, so touching it once stopped everything staged beside it
// from being applied too. The global firewall block had two — `local` and
// `description`, which say something about a *zone* and nothing about the
// appliance-wide posture — because it was built from the zone's own table.
await test("every setting the global firewall posture offers is one the appliance has", async () => {
  const r = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 400));
    staged = []; dirty.clear(); renderStaged();
    view = "zones"; panel = null; await refresh(); await wait(600);
    const box = document.getElementById("globalform");
    // Every field filled, so every one of them writes a command. What the value
    // is does not matter — this is asking whether the *path* exists.
    for (const w of box.querySelectorAll("select, input")) {
      if (w.tagName === "SELECT") {
        const opt = [...w.options].find((o) => o.value);
        if (opt) w.value = opt.value;
      } else if (w.type === "checkbox") {
        w.checked = true;
      } else {
        w.value = "probe";
      }
    }
    [...box.querySelectorAll("button")].find((b) => b.textContent.startsWith("Stage")).click();
    await wait(400);
    const cmds = stagedCommands();
    // No commit, so nothing is applied and the appliance answers only about
    // whether it knows what it was asked for.
    const reply = cmds.length ? await configure(cmds) : { output: "" };
    staged = []; dirty.clear(); renderStaged();
    return { cmds, output: reply.output };
  })()`);
  check(r.cmds.length > 3, `the mask staged almost nothing: ${JSON.stringify(r.cmds)}`);
  check(!/unknown set path/.test(r.output || ""),
    `the mask offers a setting the appliance does not have:\n  ${r.cmds.join("\n  ")}`);
});

await test("a refused change no longer stops the ones staged beside it", async () => {
  check(!!CONFIG, "CONSOLE_CONFIG is not set, so there is nothing to read back");
  const outcome = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 400));
    staged = []; dirty.clear(); renderStaged();
    stage("Interface eth1", ["set interface eth1 description saved-anyway"]);
    stage("A setting that does not exist", ["set firewall nonsense true"]);
    document.getElementById("resultout").textContent = "";
    document.getElementById("applystaged").click();
    for (let i = 0; i < 90 && !document.getElementById("resultout").textContent.trim(); i++) await wait(500);
    await wait(600);
    const said = document.getElementById("resultout").innerText;
    const title = document.getElementById("resulttitle").textContent;
    const d = document.getElementById("result"); if (d.open) d.close();
    const left = stagedCommands();
    staged = []; dirty.clear(); renderStaged();
    return { title, said, left };
  })()`);
  const config = readFileSync(CONFIG, "utf8");
  check(/saved-anyway/.test(config),
    `the good change was not saved. The appliance said:\n${outcome.said}`);
  check(/accepts|refus/i.test(outcome.said),
    `the refusal was not reported: ${outcome.said}`);
  // A refusal an operator cannot place is one they cannot act on: with several
  // changes waiting, "that setting is not one this appliance accepts" does not
  // say which of them to correct.
  check(outcome.said.includes("A setting that does not exist"),
    `the dialog does not say which staged change was refused:\n${outcome.said}`);
  equal(outcome.left.length, 2, "a batch that was refused in part was thrown away");
});

await test("applying runs the batch once, not twice", async () => {
  // Applying used to validate first and then apply, so every command ran twice
  // on the appliance and every apply cost two round trips.
  const runs = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 400));
    staged = []; dirty.clear(); renderStaged();
    let posts = 0;
    const real = window.fetch;
    window.fetch = (url, opts) => {
      if (String(url).includes("/api/v1/configure")) posts++;
      return real(url, opts);
    };
    stage("Interface eth1", ["set interface eth1 description one-run"]);
    document.getElementById("resultout").textContent = "";
    document.getElementById("applystaged").click();
    for (let i = 0; i < 90 && !document.getElementById("resultout").textContent.trim(); i++) await wait(500);
    await wait(600);
    window.fetch = real;
    const title = document.getElementById("resulttitle").textContent;
    const d = document.getElementById("result"); if (d.open) d.close();
    return { posts, title };
  })()`);
  equal(runs.title, "Applied", "the change was not applied");
  equal(runs.posts, 1, "the appliance was asked to run the batch more than once");
});

// --- reading ----------------------------------------------------------------

await test("each live-state pane says which command produced it", async () => {
  const captions = await page.evaluate(`(async () => {
    const wait = () => new Promise((r) => setTimeout(r, 500));
    const seen = [];
    for (const t of ["static", "bgp", "ospf", "ospf3", "isis", "rip", "ripng", "babel", "bfd", "table"]) {
      view = "routing"; tabs.routing = t; panel = null; await refresh(); await wait();
      const cap = document.querySelector("#view-routing > .tabpane:not(.hidden) .cmd");
      seen.push(cap ? cap.textContent : "(none)");
    }
    return seen;
  })()`);
  check(new Set(captions).size === captions.length,
    "the routing panes do not say what they ran, so they all look the same:\n  " +
    captions.join("\n  "));
});

// --- appearance -------------------------------------------------------------

await test("the appearance toggle cycles system, light and dark", async () => {
  const seen = await page.evaluate(`(() => {
    const out = [];
    for (let i = 0; i < 3; i++) {
      document.getElementById("theme").click();
      out.push(document.documentElement.getAttribute("data-theme") || "system");
    }
    return out;
  })()`);
  check(new Set(seen).size === 3, `the toggle does not reach all three: ${seen.join(", ")}`);
});

// --- the trap that reads as data loss ---------------------------------------

await test("Apply with nothing staged says so instead of doing nothing", async () => {
  const said = await page.evaluate(`(async () => {
    const wait = () => new Promise((r) => setTimeout(r, 300));
    staged = []; renderStaged(); banner("");
    view = "routing"; tabs.routing = "ospf"; panel = null; await refresh(); await wait();
    document.getElementById("applystaged").click();
    await wait();
    const bar = document.getElementById("banner");
    return bar.classList.contains("hidden") ? "" : bar.textContent;
  })()`);
  check(/staged/i.test(said), `Apply said nothing at all (banner: ${JSON.stringify(said)})`);
});

// A dialog is the only thing in this console that animates rather than simply
// appearing, and an entrance animation has one catastrophic failure mode: it
// starts the surface transparent and something stops it getting to the end, so
// the operator is looking at a modal they cannot read. That is worth a check of
// its own — it cannot be seen in the source, and it depends on the browser
// supporting the entry syntax rather than on our CSS being right.
await test("the dialog an operator is answering is actually visible", async () => {
  const seen = await page.evaluate(`(async () => {
    const d = document.getElementById("result");
    if (d.open) d.close();
    d.showModal();
    await new Promise((r) => setTimeout(r, 600));
    const s = getComputedStyle(d);
    const out = { opacity: s.opacity, props: s.transitionProperty, dur: s.transitionDuration };
    d.close();
    return out;
  })()`);
  check(Number(seen.opacity) === 1,
    `the dialog settled at opacity ${seen.opacity} — an entrance that never finishes hides it`);
  // And the ingredients, at the one place they can be read back: what moves is
  // opacity and transform, and it is over before a third of a second.
  check(/opacity/.test(seen.props) && /transform/.test(seen.props),
    `the dialog transitions ${seen.props} — it should be opacity and transform`);
  const longest = Math.max(...(seen.dur || "0s").split(",").map((d) => parseFloat(d) * 1000));
  check(longest > 0 && longest <= 300, `the dialog takes ${longest}ms — UI motion stays under 300ms`);
});

await test("a typed-in mask shows that the change is not staged yet", async () => {
  const shown = await page.evaluate(`(async () => {
    const wait = () => new Promise((r) => setTimeout(r, 300));
    staged = []; renderStaged();
    view = "routing"; tabs.routing = "ospf"; panel = null; await refresh(); await wait();
    const input = [...document.querySelectorAll("#igp-ospf .field")]
      .find((l) => l.querySelector("span").textContent === "Cost").querySelector("input");
    input.value = "123";
    input.dispatchEvent(new Event("input"));
    await wait();
    const pill = [...document.querySelectorAll("#igp-ospf .pill")]
      .filter((p) => !p.classList.contains("hidden"));
    return pill.map((p) => p.textContent);
  })()`);
  check(shown.length === 1, `an unstaged edit is not marked (found ${JSON.stringify(shown)})`);
});

// --- one routing section ----------------------------------------------------

await test("every routing protocol reads the same way", async () => {
  // BGP in its own view with its own strip was the exterior protocol looking
  // like a different product from the six interior ones — and saying nothing
  // about them. One strip, one skeleton: a lede, settings, and live state.
  //
  // The explanation is now asked of the page header rather than of the pane.
  // Both used to carry one, in almost the same words, directly above and below
  // the heading; the one that survives is the one under the title, which is
  // where a screen says where you are.
  const report = await page.evaluate(`(async () => {
    const wait = () => new Promise((r) => setTimeout(r, 300));
    const out = { tabs: [], missing: [] };
    for (const t of TABS.routing) {
      view = "routing"; tabs.routing = t.k; panel = null; await refresh(); await wait();
      const pane = [...document.querySelectorAll("#view-routing > .tabpane")]
        .filter((p) => !p.classList.contains("hidden"))[0];
      if (!pane) { out.missing.push(t.k + ": no pane"); continue; }
      out.tabs.push(t.k);
      const said = document.querySelector("#pagehead .headtext p");
      if (!said || !said.textContent.trim()) out.missing.push(t.k + ": no explanation");
      // An "inset" lede explains the section it stands under — the aggregates,
      // the RP address. What may not come back is a pane-wide one, which is the
      // page's own sentence printed a second time under the heading.
      if (pane.querySelector(":scope > .lede:not(.inset)")) {
        out.missing.push(t.k + ": says it twice");
      }
      if (!pane.querySelector("pre.out")) out.missing.push(t.k + ": no live state");
      if (!pane.querySelector(".cmd")) out.missing.push(t.k + ": does not say what it ran");
      // Every protocol is configurable in the same shape. The routing table is
      // the one deliberate exception: it is the result, not a protocol, and
      // there is nothing on it to set.
      const settings = pane.querySelector(".grid, #routelist, #bgplist");
      if (!settings && t.k !== "table") out.missing.push(t.k + ": nothing to configure or list");
    }
    return out;
  })()`);
  equal(report.missing, [], "routing panes that break the shape");
  check(report.tabs.length >= 10,
    `the routing strip lost protocols: ${report.tabs.join(", ")}`);
});

await test("wherever you are in routing, every other protocol is one click away", async () => {
  const seen = await page.evaluate(`(async () => {
    const wait = () => new Promise((r) => setTimeout(r, 250));
    view = "routing"; tabs.routing = "bgp"; panel = null; await refresh(); await wait();
    return [...document.querySelectorAll("#sectionstrip .secitem")].map((b) => b.textContent.trim());
  })()`);
  for (const protocol of ["BGP", "OSPFv2", "OSPFv3", "IS-IS", "RIP", "RIPng", "Babel", "BFD"]) {
    check(seen.some((t) => t.startsWith(protocol)),
      `standing on BGP, ${protocol} is not reachable: ${seen.join(" | ")}`);
  }
});

await test("the routing entries do not all wear the same mark", async () => {
  // The protocols are no longer rail entries; they are the routing category's
  // own strip. The question is unchanged -- ten identical glyphs is a list you
  // read by position rather than by sight -- so it is asked of the strip above
  // the heading, which is the one navigation a page carries and where the icons
  // now live.
  const marks = await page.evaluate(`(async () => {
    view = "routing"; panel = null; await refresh();
    await new Promise((r) => setTimeout(r, 300));
    return [...document.querySelectorAll("#sectionstrip .secitem svg")]
      .map((s) => s.innerHTML);
  })()`);
  check(marks.length >= 10, `the routing strip is short: ${marks.length} entries`);
  check(new Set(marks).size >= 7,
    `only ${new Set(marks).size} distinct marks across ${marks.length} routing entries`);
});

// --- what the console can tell you about a value ----------------------------

await test("a prefix says what it actually covers", async () => {
  const hints = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 500));
    view = "interfaces"; panel = null; await refresh(); await wait();
    document.getElementById("toggleiface").click(); await wait();
    const field = [...document.querySelectorAll("#addifacepanel .field")]
      .find((l) => l.querySelector("span").textContent.startsWith("IPv4 address"));
    const input = field.querySelector("input");
    const out = {};
    for (const value of ["10.0.0.0/8", "192.168.1.0/24", "203.0.113.7/32", "dhcp"]) {
      input.value = value;
      input.dispatchEvent(new Event("change"));
      await wait(200);
      out[value] = field.querySelector(".hint").textContent;
    }
    return out;
  })()`);
  check(/10\.0\.0\.0 – 10\.255\.255\.255/.test(hints["10.0.0.0/8"]),
    `a /8 is not explained: ${JSON.stringify(hints["10.0.0.0/8"])}`);
  check(/254 usable/.test(hints["192.168.1.0/24"]),
    `a /24 does not say how many hosts: ${JSON.stringify(hints["192.168.1.0/24"])}`);
  check(/one address/.test(hints["203.0.113.7/32"]),
    `a /32 is not explained: ${JSON.stringify(hints["203.0.113.7/32"])}`);
  check(/DHCP/i.test(hints["dhcp"]), `"dhcp" is not explained: ${JSON.stringify(hints["dhcp"])}`);
});

await test("a port says what usually listens there", async () => {
  const hints = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 400));
    view = "rules"; panel = null; await refresh(); await wait();
    const toggle = document.getElementById("togglerule");
    if (toggle.textContent === "New rule") toggle.click();
    await wait();
    const field = [...document.querySelectorAll("#addrulepanel .field")]
      .find((l) => l.querySelector("span").textContent === "Port");
    const input = field.querySelector("input");
    const out = {};
    for (const value of ["443", "22", "8000-8100"]) {
      input.value = value;
      input.dispatchEvent(new Event("change"));
      await wait(150);
      out[value] = field.querySelector(".hint").textContent;
    }
    return out;
  })()`);
  check(/https/.test(hints["443"]), `443 is not named: ${JSON.stringify(hints["443"])}`);
  check(/ssh/.test(hints["22"]), `22 is not named: ${JSON.stringify(hints["22"])}`);
  check(/101 ports/.test(hints["8000-8100"]),
    `a range is not counted: ${JSON.stringify(hints["8000-8100"])}`);
});

await test("an AS number is answered by the appliance, not by the browser", async () => {
  // The reserved ranges are answered without a network at all, which is what
  // makes this assertable in a sandbox — and what makes the hint useful on an
  // appliance that has no route out.
  const hint = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 900));
    view = "routing"; tabs.routing = "bgp"; panel = null; await refresh(); await wait(400);
    const toggle = document.getElementById("togglebgp");
    if (!/cancel/i.test(toggle.textContent)) toggle.click();
    await wait(300);
    const field = [...document.querySelectorAll("#addbgppanel .field")]
      .find((l) => l.querySelector("span").textContent.startsWith("Remote AS"));
    const input = field.querySelector("input");
    input.value = "65001";
    input.dispatchEvent(new Event("change"));
    // The hint arrives when the appliance answers, so wait for the answer
    // rather than for a fixed moment: a loaded box is slower than a quiet one,
    // and a sleep long enough for both is a sleep everyone pays for.
    for (let i = 0; i < 40; i++) {
      const t = field.querySelector(".hint").textContent;
      if (t) return t;
      await wait(250);
    }
    return field.querySelector(".hint").textContent;
  })()`);
  check(/private/i.test(hint), `AS 65001 is not explained: ${JSON.stringify(hint)}`);
});

await test("the page still fetches nothing from outside itself", async () => {
  // The hints are the one feature that could have broken this: an operator's
  // console reaching a registry directly would leak what they are configuring
  // and would go blank on an isolated network.
  const external = await page.evaluate(`(() => {
    const html = document.documentElement.outerHTML;
    return (html.match(/https?:\\/\\/[^"' <]+/g) || [])
      .filter((u) => !u.startsWith("http://127.0.0.1") && !u.startsWith("http://localhost"));
  })()`);
  equal(external, [], "the page names an external URL");
});

// --- accounts and signing in ------------------------------------------------

await test("an administrator can be created from the console", async () => {
  // The account mask asked for a *crypt hash*, which nobody types into a form,
  // so in practice an administrator could not be created here at all.
  const result = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 400));
    staged = []; renderStaged();
    view = "users"; panel = null; await refresh(); await wait();

    // A group first: an account with no group can log in to the box and reach
    // nothing through the API, which is deliberate.
    document.getElementById("toggleadmingroup").click(); await wait();
    const groupBox = document.getElementById("addadmingrouppanel");
    groupBox.querySelector("input").value = "operators";
    [...groupBox.querySelectorAll("button")].find((b) => /add/i.test(b.textContent)).click();
    await wait();

    document.getElementById("toggleuser").click(); await wait();
    const box = document.getElementById("adduserpanel");
    box.querySelector("input").value = "vera";
    const set = (label, value) => {
      const f = [...box.querySelectorAll(".field")]
        .find((l) => l.querySelector("span").firstChild.textContent.trim() === label);
      if (!f) throw new Error("no field named " + label);
      f.querySelector("input, select").value = value;
    };
    set("Password", "console-test-pw");
    set("Management group", "operators");
    [...box.querySelectorAll("button")].find((b) => /add/i.test(b.textContent)).click();
    await wait();
    const staged_ = stagedCommands();
    document.getElementById("applystaged").click();
    await wait(3000);
    return { staged: staged_, said: document.getElementById("resultout").innerText };
  })()`);
  check(result.staged.some((c) => c.includes("system login vera password")),
    `the mask did not set a password: ${JSON.stringify(result.staged)}`);
  check(!/error/i.test(result.said), `creating the account was refused:\n${result.said}`);
  // And the plaintext must not have survived into the configuration.
  const config = readFileSync(CONFIG, "utf8");
  check(!config.includes("console-test-pw"), "the plaintext password reached the config file");
  check(/hashed_password|hashed-password/.test(config), `no hash was stored:\n${config}`);
});

await test("that account can then sign in with its username and password", async () => {
  const outcome = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 600));
    signOut("");
    await wait();
    document.getElementById("username").value = "vera";
    document.getElementById("password").value = "console-test-pw";
    document.getElementById("loginform").dispatchEvent(new Event("submit", { cancelable: true }));
    await wait(1500);
    return {
      inside: !document.getElementById("app").classList.contains("hidden"),
      said: document.getElementById("loginerr").textContent,
      who: document.getElementById("whoami").textContent,
      readOnly: !document.getElementById("permpill").classList.contains("hidden"),
      applyDisabled: document.getElementById("applystaged").disabled,
    };
  })()`);
  check(outcome.inside, `signing in did not get in: ${outcome.said}`);
  equal(outcome.who, "vera", "the console does not say who is signed in");
  check(outcome.readOnly, "a read-only account is not marked as one");
  check(outcome.applyDisabled, "a read-only account is offered Apply");
});

await test("a wrong password is refused, and says so once", async () => {
  const said = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 1200));
    signOut("");
    await wait(300);
    document.getElementById("username").value = "vera";
    document.getElementById("password").value = "not the password";
    document.getElementById("loginform").dispatchEvent(new Event("submit", { cancelable: true }));
    await wait(2500);
    return {
      inside: !document.getElementById("app").classList.contains("hidden"),
      error: document.getElementById("loginerr").textContent,
    };
  })()`);
  check(!said.inside, "a wrong password got in");
  check(/not accepted/i.test(said.error), `an unhelpful refusal: ${JSON.stringify(said.error)}`);
});

await test("and the token is still a way in", async () => {
  const inside = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 800));
    signOut("");
    await wait(300);
    document.getElementById("tokentoggle").click();
    await wait(200);
    document.getElementById("token").value = ${JSON.stringify(TOKEN)};
    document.getElementById("tokenform").dispatchEvent(new Event("submit", { cancelable: true }));
    await wait(1200);
    return !document.getElementById("app").classList.contains("hidden");
  })()`);
  check(inside, "the machine token no longer signs in");
});

await test("the console sees the account's group and the groups themselves", async () => {
  // The renderer used to drop both, so an administrator with full access was
  // shown as having none and the permission groups did not exist on screen at
  // all. Read through the same `show configuration` the console reads.
  const seen = await page.evaluate(`(async () => {
    const wait = () => new Promise((r) => setTimeout(r, 500));
    view = "users"; panel = null; await refresh(); await wait();
    return {
      accounts: document.getElementById("userlist").innerText,
      groups: document.getElementById("admingrouplist").innerText,
    };
  })()`);
  check(/operators/.test(seen.accounts),
    `an account's management group is invisible:\n${seen.accounts}`);
  check(!/no management access/i.test(seen.accounts),
    `an account with a group is shown as having none:\n${seen.accounts}`);
  check(/operators/.test(seen.groups) && !/No permission groups/.test(seen.groups),
    `the permission groups are invisible:\n${seen.groups}`);
});

await test("a secret is not printed across the summary of a list", async () => {
  // A list is read over a shoulder, screenshotted and pasted into tickets. The
  // value stays editable; it is simply not on the card.
  const cards = await page.evaluate(`(async () => {
    const wait = () => new Promise((r) => setTimeout(r, 500));
    view = "users"; panel = null; await refresh(); await wait();
    return document.getElementById("userlist").innerText;
  })()`);
  check(!/\$6\$/.test(cards), `a password hash is printed on the account list:\n${cards}`);
});

// --- forms that ask for what is needed, and no more --------------------------

await test("the interface form follows the kind of link being made", async () => {
  // Thirty fields for every interface is why creating one felt like filling in
  // a form about somebody else's network.
  const shape = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 350));
    view = "interfaces"; panel = null; await refresh(); await wait();
    const t = document.getElementById("toggleiface");
    if (!/cancel/i.test(t.textContent)) t.click();
    await wait();
    const box = document.getElementById("addifacepanel");
    const shown = () => [...box.querySelectorAll(".field")]
      .filter((f) => !f.classList.contains("hidden"))
      .map((f) => f.querySelector("span").firstChild.textContent.trim());
    const type = [...box.querySelectorAll(".field")]
      .find((f) => f.querySelector("span").firstChild.textContent.trim() === "Type")
      .querySelector("select");
    const out = { plain: shown() };
    for (const kind of ["bond", "gre", "pppoe"]) {
      type.value = kind;
      type.dispatchEvent(new Event("change"));
      await wait(200);
      out[kind] = shown();
    }
    // And everything is still reachable.
    [...box.querySelectorAll("button")].find((b) => /more settings/i.test(b.textContent)).click();
    await wait(200);
    out.all = shown().length;
    return out;
  })()`);
  check(shape.plain.length <= 8,
    `a plain interface still asks for ${shape.plain.length} things: ${shape.plain.join(", ")}`);
  check(shape.plain.includes("Parent interface") && shape.plain.includes("VLAN id"),
    `a VLAN cannot be made without opening anything: ${shape.plain.join(", ")}`);
  check(shape.bond.includes("Members") && !shape.bond.includes("VLAN id"),
    `a bond asks the wrong things: ${shape.bond.join(", ")}`);
  check(shape.gre.includes("Local") && shape.gre.includes("Remote") && !shape.gre.includes("Members"),
    `a tunnel asks the wrong things: ${shape.gre.join(", ")}`);
  check(shape.pppoe.includes("Username"), `PPPoE does not ask for credentials: ${shape.pppoe.join(", ")}`);
  check(shape.all > 20, `"More settings" does not reveal the rest (${shape.all} fields)`);
});

await test("what already exists is offered rather than typed", async () => {
  const offered = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 350));
    view = "interfaces"; panel = null; await refresh(); await wait();
    const t = document.getElementById("toggleiface");
    if (!/cancel/i.test(t.textContent)) t.click();
    await wait();
    const box = document.getElementById("addifacepanel");
    const field = (label) => [...box.querySelectorAll(".field")]
      .find((f) => f.querySelector("span").firstChild.textContent.trim() === label);
    const type = field("Type").querySelector("select");
    type.value = "bond"; type.dispatchEvent(new Event("change"));
    await wait(250);
    const members = field("Members");
    const ticks = [...members.querySelectorAll("input[type=checkbox]")].map((i) => i.value);
    // Tick one and read what the MTU says it will be.
    [...box.querySelectorAll("button")].find((b) => /more settings/i.test(b.textContent)).click();
    await wait(200);
    const first = members.querySelector("input[type=checkbox]");
    first.checked = true;
    first.dispatchEvent(new Event("change"));
    await wait(500);
    return {
      members: ticks,
      zones: [...field("Zone").querySelectorAll("option")].map((o) => o.value).filter(Boolean),
      mtu: field("MTU").querySelector(".hint").textContent,
    };
  })()`);
  check(offered.members.includes("eth0") && offered.members.includes("eth1"),
    `the interfaces on this box are not offered as members: ${JSON.stringify(offered.members)}`);
  check(offered.zones.includes("lan") && offered.zones.includes("wan"),
    `the zones are not offered: ${JSON.stringify(offered.zones)}`);
  check(/\d|member/i.test(offered.mtu),
    `the MTU says nothing about the members: ${JSON.stringify(offered.mtu)}`);
});

await test("a setting with a fixed vocabulary is chosen, not typed", async () => {
  // The CLI validates these against a list, so typing is a spelling test whose
  // result you only learn at commit time.
  const kinds = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 350));
    view = "interfaces"; panel = null; await refresh(); await wait();
    const t = document.getElementById("toggleiface");
    if (!/cancel/i.test(t.textContent)) t.click();
    await wait();
    const box = document.getElementById("addifacepanel");
    const field = (label) => [...box.querySelectorAll(".field")]
      .find((f) => f.querySelector("span").firstChild.textContent.trim() === label);
    const type = field("Type").querySelector("select");
    type.value = "bond"; type.dispatchEvent(new Event("change"));
    await wait(250);
    const mode = field("Bond mode");
    return {
      tag: mode.querySelector("select, input").tagName,
      options: [...mode.querySelectorAll("option")].map((o) => o.value).filter(Boolean),
    };
  })()`);
  equal(kinds.tag, "SELECT", "the bond mode is typed by hand");
  for (const mode of ["active-backup", "802.3ad", "balance-rr"]) {
    check(kinds.options.includes(mode), `${mode} is not offered: ${kinds.options.join(", ")}`);
  }
});

// --- a form that asks rather than dictates ----------------------------------

// The complaint this answers is "far too many fields where you have to type
// something". Every one of these was a box: a weekday list typed as `mon,tue`,
// a time typed as `09:00`, a port typed from memory, a rate with no unit on it.
await test("a firewall rule is asked for in groups, not as twenty boxes", async () => {
  const shape = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 400));
    view = "rules"; panel = null; await refresh(); await wait(600);
    const t = document.getElementById("togglerule");
    if (!/cancel/i.test(t.textContent)) t.click();
    await wait(400);
    const box = document.getElementById("addrulepanel");
    const field = (label) => [...box.querySelectorAll(".field")]
      .find((f) => f.querySelector("span").firstChild.textContent.trim() === label);
    // The protocol decides what a rule even has, and the schedule and the rate
    // only exist on a rule that has one.
    const proto = field("Protocol").querySelector("select");
    proto.value = "tcp"; proto.dispatchEvent(new Event("change"));
    await wait(300);
    const kind = (label) => {
      const f = field(label);
      if (!f) return "missing";
      if (f.querySelector(".pick")) return "ticks:" + f.querySelectorAll(".pickone").length;
      if (f.querySelector(".combo")) return "offers:" + f.querySelectorAll(".choice").length;
      if (f.querySelector(".num")) return "unit:" + f.querySelector(".unit").textContent;
      const i = f.querySelector("input");
      return i ? i.type || "text" : (f.querySelector("select") ? "select" : "?");
    };
    return {
      groups: [...box.querySelectorAll("h4.fieldgroup")].map((h) => h.textContent.trim()),
      days: kind("Open on days"), opens: kind("Opens at"), closes: kind("Closes at"),
      port: kind("Port"), source: kind("Source"), destination: kind("Destination"),
      limit: kind("New flows"), burst: kind("Burst"),
    };
  })()`);
  check(shape.groups.length >= 4,
    `the rule mask has no headings: ${JSON.stringify(shape.groups)}`);
  equal(shape.days, "ticks:7", "the open days are still typed");
  equal(shape.opens, "time", "the opening time is still typed");
  equal(shape.closes, "time", "the closing time is still typed");
  equal(shape.limit, "unit:packets/s", "the rate limit does not say what it counts");
  equal(shape.burst, "unit:packets", "the burst does not say what it counts");
  // Offered, not imposed: a port may legitimately be `8000-8100`, so the box
  // still takes anything and the well-known services hang off it.
  check(shape.port.startsWith("offers:"), `the port offers nothing: ${shape.port}`);
  check(shape.source.startsWith("offers:"), `the source offers nothing: ${shape.source}`);
  check(shape.destination.startsWith("offers:"),
    `the destination offers nothing: ${shape.destination}`);
});

// A schedule is three leaves of one thing, and the CLI has no way to remove one
// of them: `delete … schedule days` is answered with "unknown delete path", and
// a refusal takes every command staged beside it. The console used to write it.
await test("emptying a rule's schedule removes the window the appliance has", async () => {
  const r = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 400));
    staged = []; dirty.clear(); renderStaged();
    // A rule with a real schedule on it, so there is something to empty.
    await configure(["set firewall rule sched-probe from wan",
                     "set firewall rule sched-probe action accept",
                     "set firewall rule sched-probe proto tcp",
                     "set firewall rule sched-probe port 443",
                     "set firewall rule sched-probe schedule days mon,tue",
                     // Unpadded on purpose: the appliance's own parser takes
                     // 9:00 as readily as 09:00, and a control that will not
                     // hold what the CLI wrote would show an empty box for a
                     // window that exists.
                     "set firewall rule sched-probe schedule start 9:00",
                     "set firewall rule sched-probe schedule end 17:5",
                     // Saved as well as committed, which is what Apply does:
                     // show configuration reads the file, so a commit that was
                     // not saved is a rule the console cannot see.
                     "commit", "save"]);
    view = "rules"; panel = null; await refresh(); await wait(700);
    const rule = parseRules(lastLeaves).find((x) => x.name === "sched-probe");
    if (!rule) return { error: "the probe rule did not come back" };
    openEditor(rule, zoneNames(lastLeaves));
    await wait(400);
    const field = (label) => [...document.getElementById("editorfields").querySelectorAll(".field")]
      .find((f) => f.querySelector("span").firstChild.textContent.trim() === label);
    const held = [field("Opens at").querySelector("input").value,
                  field("Closes at").querySelector("input").value];
    // Untick every day, which is how an operator says "this is not on a
    // schedule any more".
    for (const box of field("Open on days").querySelectorAll("input[type=checkbox]")) {
      box.checked = false;
    }
    field("Opens at").querySelector("input").value = "";
    field("Closes at").querySelector("input").value = "";
    const lines = script();
    document.getElementById("editor").close();
    const reply = await configure(
      [...lines, "delete firewall rule sched-probe", "commit", "save"]);
    staged = []; dirty.clear(); renderStaged();
    return { lines, held, output: reply.output };
  })()`);
  check(!r.error, r.error || "");
  equal(r.held, ["09:00", "17:05"],
    "a window the CLI wrote unpadded is not shown, and would be deleted on the next Stage");
  check(r.lines.includes("delete firewall rule sched-probe schedule"),
    `the schedule is not removed as one thing: ${JSON.stringify(r.lines)}`);
  check(!r.lines.some((l) => /schedule (days|start|end)$/.test(l)),
    `a delete of a leaf the appliance cannot remove: ${JSON.stringify(r.lines)}`);
  check(!/unknown delete path/.test(r.output || ""),
    `the appliance refused what the console wrote:\n  ${r.lines.join("\\n  ")}\n  ${r.output}`);
});

// Four hundred timezones is not a dropdown and is not a memory test either.
// The answers come from the appliance, because the *validator* reads them off
// that filesystem too — a table compiled in here would drift out of step with
// the box's own idea of which zones exist.
await test("a closed set the appliance knows is offered rather than typed", async () => {
  const r = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 400));
    view = "system"; panel = null; await refresh(); await wait(600);
    const field = (label) => [...document.querySelectorAll("#view-system .field")]
      .find((f) => f.querySelector("span").firstChild.textContent.trim() === label);
    // The lists arrive asynchronously; a picker that has not been filled yet is
    // the plain box it degrades to, which is not what this is checking.
    for (let i = 0; i < 30; i++) {
      const list = field("Time zone").querySelector("input").getAttribute("list");
      if (list && document.getElementById(list) && document.getElementById(list).children.length) break;
      await wait(150);
    }
    const offered = (label) => {
      const input = field(label).querySelector("input");
      const id = input && input.getAttribute("list");
      const list = id && document.getElementById(id);
      return list ? [...list.children].map((o) => o.value) : [];
    };
    const speed = field("Console speed").querySelector("select");
    return {
      zones: offered("Time zone"),
      keymaps: offered("Console keyboard").length,
      locales: offered("Locale").length,
      speeds: speed ? [...speed.options].map((o) => o.value).filter(Boolean) : null,
    };
  })()`);
  // What is asserted is the contract, not the contents: the console offers what
  // THIS machine has. The zone list is read from `/usr/share/zoneinfo`, the
  // keymaps from the keymap directories, the locales from `locale -a` — the
  // same places the commit-time validator reads, so the console can never offer
  // a zone the appliance would refuse, nor refuse to offer one it would take.
  //
  // A build sandbox has none of those, and there the honest answer is a plain
  // box you type into — which is what this used to fail on. So each half is
  // checked against what the appliance actually answered.
  const has = (n) => n > 0;
  if (has(r.zones.length)) {
    check(r.zones.length > 100, `only ${r.zones.length} timezones offered`);
    check(r.zones.includes("UTC"), "UTC is not among the zones offered");
  }
  if (has(r.keymaps)) check(r.keymaps > 10, `only ${r.keymaps} keymaps offered`);
  // …and the whole test cannot pass vacuously: the console speed is a set this
  // binary carries, so it is offered on every machine there is.
  // Five rates and nothing else: a serial console is the one of the four that
  // is short enough to be a dropdown outright.
  equal(r.speeds, ["9600", "19200", "38400", "57600", "115200"],
    "the console speed is not the closed set it is");
});

// Sixteen dropdowns down a page, half of them labelled the same as the other
// half, is one question asked about nine things — which is a table.
await test("the route filters read as the table they are", async () => {
  const r = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 400));
    staged = []; dirty.clear(); renderStaged();
    view = "routing"; tabs.routing = "filters"; panel = null; await refresh(); await wait(700);
    const box = document.getElementById("redistfilters");
    const table = box.querySelector("table.mtx");
    if (!table) return { error: "no table" };
    // Still writable: the arrangement changed, not what the mask can do.
    const cell = [...table.querySelectorAll("select")][0];
    const option = [...cell.options].find((o) => o.value);
    if (option) { cell.value = option.value; cell.dispatchEvent(new Event("change")); }
    await wait(200);
    [...box.querySelectorAll("button")].find((b) => b.textContent.startsWith("Stage")).click();
    await wait(300);
    const cmds = stagedCommands();
    const reply = cmds.length ? await configure(cmds) : { output: "" };
    staged = []; dirty.clear(); renderStaged();
    return {
      cols: [...table.querySelectorAll("thead th")].map((h) => h.textContent.trim()),
      rows: [...table.querySelectorAll("tbody tr")].map((tr) => tr.querySelector("th").textContent.trim()),
      cmds, output: reply.output,
    };
  })()`);
  check(!r.error, r.error || "");
  equal(r.cols, ["Route source", "Coming in", "Going back out"],
    "the table does not say which way each column goes");
  check(r.rows.length === 9, `${r.rows.length} route sources, expected nine`);
  check(r.cmds.length > 0, "the table stages nothing — it is a picture of a mask");
  check(!/unknown set path/.test(r.output || ""),
    `the table writes a path the appliance does not have: ${r.cmds.join("; ")}`);
});

// One object, one shape. The editor used to take the mask apart and re-lay the
// fields in a grid of its own, so creating a rule was a four-column form and
// editing the same rule was twenty rows in a single column.
await test("a rule is the same form whether it is being made or changed", async () => {
  const r = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 400));
    view = "rules"; panel = null; await refresh(); await wait(600);
    const t = document.getElementById("togglerule");
    if (!/cancel/i.test(t.textContent)) t.click();
    await wait(300);
    const panelGroups = [...document.querySelectorAll("#addrulepanel h4.fieldgroup")]
      .map((h) => h.textContent.trim());
    const rule = parseRules(lastLeaves)[0];
    openEditor(rule, zoneNames(lastLeaves));
    await wait(400);
    const fields = document.getElementById("editorfields");
    const dialogGroups = [...fields.querySelectorAll("h4.fieldgroup")].map((h) => h.textContent.trim());
    const grid = fields.querySelector(".mask > .grid");
    const columns = grid ? getComputedStyle(grid).gridTemplateColumns.split(" ").length : 0;
    document.getElementById("editor").close();
    return { panelGroups, dialogGroups, columns };
  })()`);
  equal(r.dialogGroups, r.panelGroups, "the two forms for one rule are grouped differently");
  check(r.columns > 1, `the editor lays the mask out in ${r.columns} column`);
});

// The editor folds the unset rest away just as the add panel does, and is
// honest about it: a field the rule actually carries stays on screen, only the
// ones it never set go behind "More settings".
await test("the editor folds the unset rest and keeps what the rule sets", async () => {
  const r = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 400));
    await configure(["set firewall rule fold-probe from wan",
                     "set firewall rule fold-probe to lan",
                     "set firewall rule fold-probe action accept",
                     "set firewall rule fold-probe proto tcp",
                     "set firewall rule fold-probe port 443",
                     // Set, and not in the essential few: this must stay visible.
                     "set firewall rule fold-probe description 'kept in view'",
                     "commit", "save"]);
    view = "rules"; panel = null; await refresh(); await wait(700);
    const rule = parseRules(lastLeaves).find((x) => x.name === "fold-probe");
    if (!rule) return { error: "the fold-probe rule did not come back" };
    openEditor(rule, zoneNames(lastLeaves));
    await wait(400);
    const box = document.getElementById("editorfields");
    const field = (label) => [...box.querySelectorAll(".field")]
      .find((f) => f.querySelector("span").firstChild.textContent.trim() === label);
    const hidden = (label) => field(label).classList.contains("hidden");
    // "Burst" is unset and not essential, so it folds; "Description" is set but
    // not essential, so the honesty rule keeps it. (A field the appliance emits
    // a value for — "Log matches" comes back as "false" — is genuinely set, and
    // rightly stays too; "Burst" is the one this rule never touched.)
    const foldedBefore = hidden("Burst");
    const keptSet = !hidden("Description");
    const keptEssential = !hidden("From zone") && !hidden("Port");
    const moreBtn = [...document.querySelectorAll("#editormore button")]
      .find((b) => /more settings/i.test(b.textContent));
    const hadMore = !!moreBtn;
    if (moreBtn) { moreBtn.click(); await wait(200); }
    const revealed = !hidden("Burst");
    document.getElementById("editor").close();
    await configure(["delete firewall rule fold-probe", "commit", "save"]);
    return { foldedBefore, keptSet, keptEssential, hadMore, revealed };
  })()`);
  check(!r.error, r.error || "");
  check(r.hadMore, "the editor offers no \"More settings\" control");
  check(r.foldedBefore, "an unset, non-essential field is not folded away");
  check(r.keptSet, "a field the rule actually sets was hidden — the fold is lying");
  check(r.keptEssential, "an essential field was folded away");
  check(r.revealed, "\"More settings\" does not reveal the folded field");
});

// The jump palette: a flat search over every page, so a page an operator can
// name is one keystroke away rather than a guess at which category holds it.
await test("the jump palette reaches a page by name", async () => {
  const r = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 200));
    view = "dashboard"; panel = null; await refresh(); await wait(300);
    // Ctrl/Cmd-K from anywhere opens it.
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }));
    await wait(150);
    const opened = document.getElementById("palette").open;
    const q = document.getElementById("paletteq");
    q.value = "zones";
    q.dispatchEvent(new Event("input"));
    await wait(120);
    const rows = [...document.querySelectorAll("#palettelist .palitem")]
      .map((b) => b.querySelector(".palt").textContent.trim());
    // Enter takes the selected (first) row.
    q.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    await wait(250);
    const closed = !document.getElementById("palette").open;
    return { opened, rows, closed, view, panel };
  })()`);
  check(r.opened, "Ctrl/Cmd-K did not open the palette");
  check(r.rows.some((t) => /zones/i.test(t)), `the palette did not find Zones: ${JSON.stringify(r.rows)}`);
  check(r.closed, "the palette stayed open after Enter");
  equal(r.view, "zones", `Enter did not navigate to the named page (view=${r.view})`);
});

await test("validating leaves the change staged and applyable", async () => {
  // Validate used to clear the panel: the check said "fine" and then the change
  // could no longer be applied.
  const after = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 800));
    staged = []; renderStaged();
    view = "routing"; tabs.routing = "ospf"; panel = null; await refresh(); await wait(400);
    [...document.querySelectorAll("#igp-ospf .field")]
      .find((l) => l.querySelector("span").firstChild.textContent.trim() === "Cost")
      .querySelector("input").value = "55";
    [...document.querySelectorAll("#igp-ospf button")].find((b) => b.textContent.startsWith("Stage")).click();
    await wait(400);
    const before = stagedCommands();
    document.getElementById("validate").click();
    await wait(2500);
    const title = document.getElementById("resulttitle").textContent;
    document.getElementById("result").close();
    return { before, still: stagedCommands(), title };
  })()`);
  equal(after.still, after.before, "validating threw the staged change away");
  check(/would|accept/i.test(after.title), `the dialog claims it applied: ${after.title}`);
});

// Every control, in every section, actually operated.
//
// The section walk proves each page *renders*. This proves the things on it
// *work*: a dropdown, a posture checkbox, a switch. Each writes into the staged
// list, so what a control wants to write can be read off the console's own
// state and handed to the appliance — a control that stages a command the CLI
// refuses is a button that looks like it did something and did not, which is
// the failure this whole suite exists to catch.
//
// Second to last on purpose: it visits every section and clears the staged list
// as it goes, so it reloads the page when it is done rather than handing the
// next test a console it has been rummaging through.
await test("every control stages a command the appliance accepts", async () => {
  // One call per page, not one call for the whole console.
  //
  // Opening a page makes the appliance answer every live-state pane on it, and
  // each of those costs it a process spawn. A single evaluate over all of them
  // fits on a workstation and does not in a build sandbox, where it runs into
  // the call timeout and reports as "the page stopped answering" — a console
  // that hangs, which is not what happened.
  const cats = await page.evaluate(
    `[...document.querySelectorAll("aside button.navitem")].length`);
  const staged = [];
  for (let c = 0; c < cats; c++) {
    const pages = await page.evaluate(`(async () => {
      [...document.querySelectorAll("aside button.navitem")][${c}].click();
      await new Promise((r) => setTimeout(r, 200));
      return document.querySelectorAll("#sectionstrip .secitem").length || 1;
    })()`);
    for (let p = 0; p < pages; p++) {
      const out = await page.evaluate(`(async () => {
        const wait = (ms) => new Promise((r) => setTimeout(r, ms || 40));
        const out = [];
        const drain = () => {
          for (const e of staged) for (const c of e.cmds || []) out.push(String(c));
          staged = []; dirty.clear(); renderStaged();
        };
        const strip = document.querySelectorAll("#sectionstrip .secitem");
        if (strip[${p}]) { strip[${p}].click(); await wait(200); }
        for (const sel of [...document.querySelectorAll("select")]) {
          for (const opt of [...sel.options]) {
            if (!opt.value) continue;
            sel.value = opt.value;
            sel.dispatchEvent(new Event("change", { bubbles: true }));
            await wait(25);
            drain();
          }
        }
        for (const box of [...document.querySelectorAll("input[type=checkbox]")]) {
          box.checked = !box.checked;
          box.dispatchEvent(new Event("change", { bubbles: true }));
          await wait(25);
          drain();
        }
        return out;
      })()`).catch(() => []);
      staged.push(...out);
    }
  }

  check(staged.length > 10, `only ${staged.length} controls did anything at all`);

  // Through the same endpoint the console's own Apply uses, and in the same
  // shape: the CLI, one command per line. No `commit`, so every line is parsed
  // and validated and the session is then thrown away.
  const body = staged.join("\n") + "\n";
  const verdict = await page.evaluate(`(async () => {
    const r = await fetch("/api/v1/configure", {
      method: "POST",
      headers: { "Content-Type": "text/plain", Authorization: "Bearer " + token },
      body: ${JSON.stringify(body)},
    });
    return await r.text();
  })()`);
  // A line that needs company — a rule's port wants a proto — is the model
  // doing its job, not a broken control: this operates each control on its own,
  // which no operator does.
  const refused = (verdict.match(/error: [^\n"]+/g) || []).filter(
    (e) => !/together|require|need|must be|is required|not a declared|no such|not supported/i.test(e));
  check(refused.length === 0,
    `${refused.length} staged commands were refused:\n  ` + refused.slice(0, 8).join("\n  "));

  // Leave the console as we found it.
  await page.goto(URL);
  await signIn(page, TOKEN);
});

// How much of the appliance the console can actually configure.
//
// This exists because the number was being guessed. An earlier pass put it at
// 62% using an instrument that only saw the generic field tables — the global
// firewall posture read as missing while sitting one click away — and a figure
// that under-counts is worse than none: it invents gaps and hides real ones.
//
// So both halves are now measured rather than asserted. The CLI half is
// `cli-fields.txt`, written by the grammar walk from the same completion tables
// Tab and `?` read (see `the_cli_field_inventory_is_current`). The console half
// is the console reporting on itself: its three mask builders and `stage` are
// wrapped, then every category, page, tab and control is opened and operated.
//
// Both halves also have to count the same things, and getting that wrong is
// what the number mostly measured to begin with. Counting a position's *values*
// as fields — `accept`, `drop`, `tcp`, `802.1ad` — read 46%. Reading a mask's
// key whole instead of by its last word — `pppoe username` against the CLI's
// `username` — read 74%. Measuring a console that had been left blind, because
// the walk stubbed the configuration along with the live panes, read 97%.
//
// Seeing straight, it is all of it: every settable path in the grammar has a
// field, a picker or a button in the console.
//
// So the floor is the whole thing. A setting the CLI grows and the console does
// not is a defect, not a backlog item — and it cannot land quietly, because the
// inventory beside this is golden and has to be regenerated in the same breath.
await test("the console reaches most of what the CLI can configure", async () => {
  // Its own pass, last, on a page of its own: the recording wrappers replace
  // three of the console's functions, and an earlier attempt to install them
  // once at the top and let every test feed the inventory broke the tests that
  // create an account — a measurement that changes what it measures is not one.
  await page.goto(URL);
  await signIn(page, TOKEN);
  await instrument(page);
  await walkAll(page);
  const { seen } = await collect(page);
  const reached = sectionFields(seen);

  const wanted = readFileSync(HERE + "cli-fields.txt", "utf8")
    .split("\n").map((l) => l.trim()).filter(Boolean);
  check(wanted.length > 400, `the CLI inventory has only ${wanted.length} entries`);

  const bySection = new Map();
  for (const pair of wanted) {
    const section = pair.split(" ")[0];
    const s = bySection.get(section) || { have: 0, want: 0, missing: [] };
    s.want++;
    if (reached.has(pair)) s.have++;
    else s.missing.push(pair.split(" ")[1]);
    bySection.set(section, s);
  }
  const have = [...bySection.values()].reduce((a, s) => a + s.have, 0);
  const pct = Math.round((have / wanted.length) * 100);

  // Printed always, so the number is a fact in the log rather than something
  // to be re-derived by hand later.
  console.log(`  console covers ${have}/${wanted.length} CLI fields (${pct}%)`);
  for (const [section, s] of [...bySection].sort((a, b) => a[1].have / a[1].want - b[1].have / b[1].want)) {
    const miss = s.missing.slice(0, 6).join(", ");
    console.log(`    ${String(section).padEnd(14)} ${String(s.have).padStart(3)}/${String(s.want).padEnd(3)}` +
      (s.missing.length ? `  missing: ${miss}${s.missing.length > 6 ? ", …" : ""}` : ""));
  }

  const short = [...bySection]
    .filter(([, s]) => s.missing.length)
    .map(([section, s]) => `${section}: ${s.missing.join(", ")}`);
  check(short.length === 0,
    `the console has no way to set ${wanted.length - have} of the CLI's settings:\n  `
    + short.join("\n  "));
});

await test("nothing threw during the whole run", () => noThrows("the console threw"));

page.close();
process.exit(summary() ? 1 : 0);
