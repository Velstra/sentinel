// What the console has to actually do, checked in a browser against a running
// appliance API.
//
// Every test here exists because the thing it checks was once broken in a way
// that looked fine: the page loaded, the layout was right, and the button did
// nothing. Read the failures as "an operator cannot do X", not as unit noise.

import { readFileSync } from "node:fs";
import { browser, signIn, sleep, test, check, equal, summary } from "./harness.mjs";

const URL = process.env.CONSOLE_URL || "http://127.0.0.1:8088/";
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
await test("every rail entry opens exactly one non-empty view", async () => {
  // The labels first, so a call that never comes back can be named. "The page
  // stopped answering" is not a diagnosis; "Traffic shaping stopped answering"
  // is one.
  const labels = await page.evaluate(
    `[...document.querySelectorAll("aside button.navitem")].map((b) => b.textContent.trim())`);
  check(labels.length > 30, `only ${labels.length} rail entries — the rail lost sections`);

  const broken = [], empty = [], slow = [];
  for (let i = 0; i < labels.length; i++) {
    let r;
    const began = Date.now();
    const say = process.env.CONSOLE_PROGRESS
      ? (m) => console.log(`       ${m}`)
      : () => {};
    say(`→ ${i + 1}/${labels.length} ${labels[i]}`);
    try {
      r = await page.evaluate(`(async () => {
        const b = [...document.querySelectorAll("aside button.navitem")][${i}];
        b.click();
        await new Promise((r) => setTimeout(r, 200));
        const shown = [...document.querySelectorAll('[id^="view-"]')]
          .filter((v) => !v.classList.contains("hidden"));
        return { views: shown.length, text: shown.length === 1 ? shown[0].innerText.trim() : "" };
      })()`);
    } catch (e) {
      throw new Error(`at rail entry ${i + 1}/${labels.length} (${labels[i]}): ${e.message || e}`);
    }
    // A section that takes half a minute to open is a defect an operator meets
    // as "the console is broken", so it is worth saying out loud even when the
    // walk finishes.
    const took = Date.now() - began;
    say(`  ${(took / 1000).toFixed(1)}s`);
    if (took > 20000) slow.push(`${labels[i]} took ${Math.round(took / 1000)}s`);
    if (r.views !== 1) broken.push(`${labels[i]} showed ${r.views} views`);
    else if (!r.text) empty.push(labels[i]);
  }
  equal(broken, [], "rail entries that do not open one view");
  equal(empty, [], "rail entries that open an empty page");
  equal(slow, [], "rail entries that take longer than an operator will wait");
  noThrows("navigating threw");
});

await test("every tab strip switches panes and titles the page", async () => {
  const strips = await page.evaluate(`Object.keys(TABS)`);
  const bad = [];
  for (const v of strips) {
    const shape = await page.evaluate(`(async () => {
      view = ${JSON.stringify(v)}; panel = null;
      await refresh();
      await new Promise((r) => setTimeout(r, 200));
      const strip = document.getElementById("tabs-" + view);
      return { tabs: strip ? strip.children.length : -1, want: TABS[view].length };
    })()`);
    if (shape.tabs !== shape.want) { bad.push(`${v}: strip does not match the table`); continue; }
    // Each tab is its own call for the same reason as above.
    for (let i = 0; i < shape.tabs; i++) {
      const r = await page.evaluate(`(async () => {
        const button = document.getElementById("tabs-" + ${JSON.stringify(v)}).children[${i}];
        const name = button.textContent;
        button.click();
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
      [...box.querySelectorAll("button")].find((b) => /add/i.test(b.textContent)).click();
      await wait();
      const err = box.querySelector(".formerr");
      return {
        staged: stagedCommands(),
        said: err ? err.textContent : "",
        bare: stagedCommands().length === 1 && !/ .+ .+/.test(stagedCommands()[0].replace(/^set /, "")),
      };
    })()`);
    if (r.missing) { bad.push(`${panel}: no New button or panel`); continue; }
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
    ["wan", null, "togglewanpolicy", "addwanpolicypanel", "voip",
      { "Preferred uplinks": "wan0" }],
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
    const r = await page.evaluate(`(async () => {
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
        f.querySelector("input, select").value = value;
      }
      [...box.querySelectorAll("button")].find((b) => /add/i.test(b.textContent)).click();
      await wait();
      const cmds = stagedCommands();
      if (!cmds.length) return { error: "nothing staged: " + (box.querySelector(".formerr") || {}).textContent };
      // Validate only — the same commands, with no commit, so nothing applies.
      const reply = await configure(cmds);
      return { staged: cmds, output: reply.output };
    })()`);
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
    [...document.querySelectorAll("#igp-ospf button")].find((b) => b.textContent === "Stage").click();
    await wait();
    return stagedCommands();
  })()`);
  equal(staged, ["set protocols ospf cost 77"], "the OSPF mask staged the wrong commands");
});

await test("applying writes the appliance's configuration file", async () => {
  check(!!CONFIG, "CONSOLE_CONFIG is not set, so there is nothing to read back");
  const before = readFileSync(CONFIG, "utf8");
  const result = await page.evaluate(`(async () => {
    const wait = (ms) => new Promise((r) => setTimeout(r, ms || 400));
    document.getElementById("applystaged").click();
    await wait(2500);
    return {
      left: stagedCommands(),
      said: document.getElementById("resultout").innerText,
    };
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
    [...document.querySelectorAll("#igp-ospf button")].find((b) => b.textContent === "Stage").click();
    await wait();
    const out = stagedCommands();
    document.getElementById("applystaged").click();
    await wait();
    return out;
  })()`);
  equal(staged, ["delete protocols ospf cost"], "clearing a field did not delete the setting");
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
  const report = await page.evaluate(`(async () => {
    const wait = () => new Promise((r) => setTimeout(r, 300));
    const out = { tabs: [], missing: [] };
    for (const t of TABS.routing) {
      view = "routing"; tabs.routing = t.k; panel = null; await refresh(); await wait();
      const pane = [...document.querySelectorAll("#view-routing > .tabpane")]
        .filter((p) => !p.classList.contains("hidden"))[0];
      if (!pane) { out.missing.push(t.k + ": no pane"); continue; }
      out.tabs.push(t.k);
      if (!pane.querySelector(".lede")) out.missing.push(t.k + ": no explanation");
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
    return [...document.getElementById("tabs-routing").children].map((b) => b.textContent.trim());
  })()`);
  for (const protocol of ["BGP", "OSPFv2", "OSPFv3", "IS-IS", "RIP", "RIPng", "Babel", "BFD"]) {
    check(seen.some((t) => t.startsWith(protocol)),
      `standing on BGP, ${protocol} is not reachable: ${seen.join(" | ")}`);
  }
});

await test("the routing entries do not all wear the same mark", async () => {
  const marks = await page.evaluate(`(() => {
    const group = [...document.querySelectorAll("nav .group")]
      .find((g) => g.querySelector(".grouphead").textContent.startsWith("Routing"));
    return [...group.querySelectorAll(".navitem svg")].map((svg) => svg.innerHTML);
  })()`);
  check(marks.length >= 10, `the routing group is short: ${marks.length} entries`);
  // Ten identical glyphs is a list you read by position rather than by sight.
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
    await wait();
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
    [...document.querySelectorAll("#igp-ospf button")].find((b) => b.textContent === "Stage").click();
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

await test("nothing threw during the whole run", () => noThrows("the console threw"));

page.close();
process.exit(summary() ? 1 : 0);
