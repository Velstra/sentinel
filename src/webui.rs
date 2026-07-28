//! C12 — the **web console**.
//!
//! The third face of the same appliance, beside the CLI and the REST API. It
//! invents no endpoint and holds no state of its own: every panel is a `show`
//! the CLI also prints, and every change is the *same command* an operator would
//! type, sent to `POST /api/v1/configure`.
//!
//! ## Why it edits through the CLI grammar
//!
//! A management UI usually diverges from its config model the day someone adds a
//! form field. This one cannot: a form does not build a config document, it
//! builds `set …` lines. The appliance's own parser, validators, refusals and
//! commit warnings then apply unchanged, and the console shows the exact script
//! before it runs — so what was clicked is reviewable, pasteable into a
//! terminal, and identical to what a colleague would have typed.
//!
//! That also means the console can never do more than the CLI can, which is the
//! property that keeps the two honest about each other.
//!
//! ## One file, nothing fetched
//!
//! A single self-contained document: no CDN, no font, no framework, no chart
//! library. An appliance is expected to work on an isolated network, and a
//! console that half-renders because it cannot reach the internet is worse than
//! no console. The graphs are drawn on a canvas from the counters the box
//! already reports.
//!
//! ## The token never touches disk
//!
//! The page itself is public — markup with no data in it, and a sign-in form
//! that cannot be reached is not a sign-in form. Every byte of data behind it
//! needs the same bearer token the API requires, held in `sessionStorage` so it
//! is gone when the tab closes: an appliance token has no business outliving the
//! session on a shared machine.

/// A read-only view: a title and the `show` path behind it.
///
/// Grouped, because a flat list of thirty panels is a list nobody reads. The
/// groups are the operator's own vocabulary — what is being filtered, what is
/// being translated, what is being routed — not the source layout.
pub const PANELS: &[(&str, &[(&str, &str)])] = &[
    (
        "Firewall",
        &[
            ("Overview", "/api/v1/show/firewall"),
            ("Counters", "/api/v1/show/firewall/statistics"),
            ("Connections", "/api/v1/show/firewall/flows"),
            ("Top talkers", "/api/v1/show/firewall/top"),
            ("Recent log", "/api/v1/show/firewall/log"),
        ],
    ),
    (
        "NAT",
        &[
            ("Rules", "/api/v1/show/nat"),
            ("Load balancer", "/api/v1/show/load-balancer"),
        ],
    ),
    (
        "Network",
        &[
            ("Interfaces", "/api/v1/show/interfaces"),
            ("Routes", "/api/v1/show/ip/route"),
            ("Neighbours", "/api/v1/show/arp"),
        ],
    ),
    (
        "Routing",
        &[
            ("BGP", "/api/v1/show/ip/bgp"),
            ("OSPF", "/api/v1/show/ip/ospf/neighbors"),
            ("VRRP", "/api/v1/show/vrrp"),
            ("BFD", "/api/v1/show/bfd"),
        ],
    ),
    (
        "Security",
        &[
            ("Intrusion detection", "/api/v1/show/ids"),
            ("Alerts", "/api/v1/show/ids/alerts"),
            ("Run-time blocks", "/api/v1/show/ids/blocks"),
            ("Certificates", "/api/v1/show/pki"),
            ("VPN", "/api/v1/show/vpn"),
        ],
    ),
    (
        "Diagnostics",
        &[
            ("Data-plane log", "/api/v1/show/log/velstra"),
            ("Routing log", "/api/v1/show/log/wren"),
            ("Running config", "/api/v1/show/configuration"),
            ("Version", "/api/v1/show/version"),
        ],
    ),
];

/// The counters the dashboard graphs, and what each one means.
///
/// A chosen few rather than all forty: a wall of sparklines is decoration, and
/// these four answer the questions an operator actually opens a console with —
/// is traffic flowing, is anything being denied, is the box under attack, and is
/// the proxy holding.
pub const GRAPHS: &[(&str, &str)] = &[
    ("rx_packets", "Packets received"),
    ("dropped_rule", "Denied by a rule"),
    ("dropped_blocklist", "Denied by the blocklist"),
    ("synproxy_challenged", "SYNs challenged"),
];

/// The console, as one document.
pub fn page() -> String {
    let nav: String = PANELS
        .iter()
        .map(|(group, items)| {
            let entries: String = items
                .iter()
                .map(|(title, path)| format!("      {{ t: {title:?}, p: {path:?} }},\n"))
                .collect();
            format!("  {{ g: {group:?}, items: [\n{entries}  ] }},\n")
        })
        .collect();
    let graphs: String = GRAPHS
        .iter()
        .map(|(counter, label)| format!("  {{ c: {counter:?}, l: {label:?} }},\n"))
        .collect();
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel</title>
<style>
  :root {{
    color-scheme: light dark;
    --bg: #f4f6f8; --panel: #ffffff; --fg: #14181d; --muted: #5d6773;
    --line: #d5dbe2; --accent: #1f5fd0; --accent-fg: #ffffff;
    --ok: #157f3d; --warn: #9a6700; --bad: #b42318; --rail: #10151b; --rail-fg: #c9d3de;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #0f1216; --panel: #171c22; --fg: #e4e9ef; --muted: #97a3b0;
      --line: #262d36; --accent: #4c8dff; --accent-fg: #08111f;
      --ok: #3fb950; --warn: #d0a215; --bad: #f85149; --rail: #0a0d11; --rail-fg: #b6c2ce;
    }}
  }}
  :root[data-theme="dark"] {{
    --bg: #0f1216; --panel: #171c22; --fg: #e4e9ef; --muted: #97a3b0;
    --line: #262d36; --accent: #4c8dff; --accent-fg: #08111f;
    --ok: #3fb950; --warn: #d0a215; --bad: #f85149; --rail: #0a0d11; --rail-fg: #b6c2ce;
  }}
  :root[data-theme="light"] {{
    --bg: #f4f6f8; --panel: #ffffff; --fg: #14181d; --muted: #5d6773;
    --line: #d5dbe2; --accent: #1f5fd0; --accent-fg: #ffffff;
    --ok: #157f3d; --warn: #9a6700; --bad: #b42318; --rail: #10151b; --rail-fg: #c9d3de;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--fg);
    font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif;
  }}
  code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  .app {{ display: grid; grid-template-columns: 240px 1fr; min-height: 100vh; }}
  @media (max-width: 820px) {{ .app {{ grid-template-columns: 1fr; }} aside {{ position: static !important; height: auto !important; }} }}

  aside {{
    background: var(--rail); color: var(--rail-fg);
    position: sticky; top: 0; height: 100vh; overflow-y: auto;
    display: flex; flex-direction: column; gap: .25rem; padding: .9rem .6rem;
  }}
  aside h1 {{ font-size: .95rem; margin: .2rem .5rem 1rem; letter-spacing: .06em;
              text-transform: uppercase; color: #fff; }}
  aside .grp {{ font-size: .68rem; text-transform: uppercase; letter-spacing: .1em;
                color: #7d8b99; margin: .9rem .5rem .3rem; }}
  aside button {{
    display: block; width: 100%; text-align: left; background: none; border: 0;
    color: inherit; font: inherit; padding: .34rem .5rem; border-radius: 6px;
    cursor: pointer;
  }}
  aside button:hover {{ background: rgba(255,255,255,.07); }}
  aside button[aria-current="true"] {{ background: var(--accent); color: var(--accent-fg); }}

  main {{ padding: 1.1rem 1.3rem 3rem; max-width: 78rem; }}
  .bar {{ display: flex; align-items: center; gap: .75rem; flex-wrap: wrap; margin-bottom: 1rem; }}
  .bar h2 {{ font-size: 1.15rem; margin: 0; }}
  .spacer {{ margin-left: auto; }}
  .pill {{ font-size: .75rem; padding: .1rem .5rem; border-radius: 999px;
           border: 1px solid var(--line); color: var(--muted); }}
  .pill.up {{ color: var(--ok); border-color: currentColor; }}
  .pill.down {{ color: var(--bad); border-color: currentColor; }}

  .card {{ border: 1px solid var(--line); border-radius: 10px; background: var(--panel);
           padding: .85rem 1rem; margin: 0 0 1rem; }}
  .card > h3 {{ font-size: .72rem; text-transform: uppercase; letter-spacing: .09em;
                color: var(--muted); margin: 0 0 .6rem; }}
  .cards {{ display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); }}
  .metric {{ font-size: 1.6rem; font-variant-numeric: tabular-nums; }}
  .metric small {{ font-size: .8rem; color: var(--muted); }}
  canvas {{ width: 100%; height: 46px; display: block; }}

  pre.out {{ margin: 0; overflow-x: auto; white-space: pre; font-size: 12.5px; line-height: 1.45; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
  th, td {{ text-align: left; padding: .35rem .5rem; border-bottom: 1px solid var(--line);
            vertical-align: top; }}
  th {{ font-size: .7rem; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  tr.zero td {{ color: var(--muted); }}

  input, select, button.btn {{
    font: inherit; padding: .4rem .55rem; border-radius: 7px;
    border: 1px solid var(--line); background: var(--panel); color: var(--fg);
  }}
  button.btn {{ cursor: pointer; }}
  button.primary {{ background: var(--accent); border-color: var(--accent); color: var(--accent-fg); }}
  button.danger {{ color: var(--bad); }}
  .row {{ display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }}
  .field {{ display: flex; flex-direction: column; gap: .2rem; }}
  .field label {{ font-size: .7rem; text-transform: uppercase; letter-spacing: .07em; color: var(--muted); }}
  .grid2 {{ display: grid; gap: .7rem; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr)); }}
  .hidden {{ display: none; }}
  .err {{ color: var(--bad); white-space: pre-wrap; }}
  .ok {{ color: var(--ok); }}
  dialog {{ border: 1px solid var(--line); border-radius: 12px; background: var(--panel);
            color: var(--fg); padding: 1rem 1.1rem; max-width: 46rem; width: calc(100% - 2rem); }}
  dialog::backdrop {{ background: rgba(0,0,0,.45); }}
  .script {{ background: var(--bg); border: 1px solid var(--line); border-radius: 8px;
             padding: .6rem .7rem; font-size: 12.5px; white-space: pre-wrap; }}
</style>
</head>
<body>

<section id="login" class="card" style="max-width:26rem;margin:14vh auto">
  <h3>Sentinel — sign in</h3>
  <p style="margin:.2rem 0 .8rem;color:var(--muted)">
    The management token — the same bearer token the API takes. Kept for this tab
    only and never written to disk.
  </p>
  <form class="row" id="loginform">
    <input id="token" type="password" placeholder="management token" autocomplete="off"
           style="flex:1 1 14rem">
    <button class="btn primary" type="submit">Sign in</button>
  </form>
  <p id="loginerr" class="err"></p>
</section>

<div class="app hidden" id="app">
  <aside>
    <h1>Sentinel</h1>
    <button data-view="dashboard">Dashboard</button>
    <button data-view="rules">Firewall rules</button>
    <button data-view="stack">Stack</button>
    <div id="nav"></div>
    <div style="margin-top:auto;padding:.6rem .5rem 0">
      <button class="btn" id="theme" style="width:100%">Theme</button>
      <button class="btn" id="signout" style="width:100%;margin-top:.4rem">Sign out</button>
    </div>
  </aside>

  <main>
    <div class="bar">
      <h2 id="title">Dashboard</h2>
      <span class="pill" id="host"></span>
      <span class="spacer"></span>
      <span class="pill" id="target">this appliance</span>
      <button class="btn" id="refresh">Refresh</button>
    </div>

    <div id="view-dashboard">
      <div class="cards" id="services"></div>
      <div class="cards" id="graphs"></div>
      <div class="card">
        <h3>Counters</h3>
        <div class="row" style="margin-bottom:.5rem">
          <label class="row" style="gap:.35rem;color:var(--muted);font-size:.8rem">
            <input type="checkbox" id="allcounters"> show counters that are still zero
          </label>
        </div>
        <div style="overflow-x:auto"><table id="counters"></table></div>
      </div>
    </div>

    <div id="view-rules" class="hidden">
      <div class="card">
        <h3>Rules</h3>
        <div class="row" style="margin-bottom:.7rem">
          <button class="btn primary" id="addrule">Add rule</button>
          <span style="color:var(--muted);font-size:.8rem">
            Every change is a command; you see it before it runs.
          </span>
        </div>
        <div style="overflow-x:auto"><table id="ruletable"></table></div>
      </div>
      <div class="card">
        <h3>Firewall overview</h3>
        <pre class="out" id="fwshow">…</pre>
      </div>
    </div>

    <div id="view-stack" class="hidden">
      <div class="card">
        <h3>Members</h3>
        <div style="overflow-x:auto"><table id="stacktable"></table></div>
        <p style="color:var(--muted);font-size:.82rem;margin:.7rem 0 0">
          A member is a <code>system config-sync peer</code> — the boxes this one
          already pushes its running config to. Selecting one points the read-only
          views at it; configuration is always applied here and synced on commit.
        </p>
      </div>
    </div>

    <div id="view-panel" class="hidden">
      <div class="card"><pre class="out" id="panel">…</pre></div>
    </div>
  </main>
</div>

<dialog id="editor">
  <h3 style="margin:0 0 .8rem" id="editortitle">Rule</h3>
  <div class="grid2">
    <div class="field"><label for="r-name">Name</label><input id="r-name"></div>
    <div class="field"><label for="r-from">From zone</label><input id="r-from"></div>
    <div class="field"><label for="r-to">To zone</label><input id="r-to"></div>
    <div class="field"><label for="r-action">Action</label>
      <select id="r-action"><option>accept</option><option>drop</option><option>reject</option></select>
    </div>
    <div class="field"><label for="r-proto">Protocol</label>
      <select id="r-proto"><option value="">(any)</option><option>tcp</option><option>udp</option></select>
    </div>
    <div class="field"><label for="r-port">Port</label><input id="r-port" placeholder="443 or 8000-8100"></div>
    <div class="field"><label for="r-source">Source</label><input id="r-source" placeholder="CIDR"></div>
    <div class="field"><label for="r-dest">Destination</label><input id="r-dest" placeholder="CIDR"></div>
  </div>
  <p style="color:var(--muted);font-size:.8rem;margin:.7rem 0 .3rem">This will run:</p>
  <div class="script" id="preview"></div>
  <p id="editorerr" class="err"></p>
  <div class="row" style="margin-top:.9rem">
    <button class="btn primary" id="applysave">Apply and save</button>
    <button class="btn" id="applyonly">Apply without saving</button>
    <button class="btn" id="cancel">Cancel</button>
  </div>
</dialog>

<dialog id="result">
  <h3 style="margin:0 0 .6rem">Result</h3>
  <pre class="out" id="resultout"></pre>
  <div class="row" style="margin-top:.9rem"><button class="btn" id="resultclose">Close</button></div>
</dialog>

<script>
"use strict";
const NAV = [
{nav}];
const GRAPHS = [
{graphs}];

const $ = (id) => document.getElementById(id);
const KEY = "sentinel-token";
const THEME = "sentinel-theme";
let token = sessionStorage.getItem(KEY) || "";
let view = "dashboard";
let panel = null;
let target = "";           // "" = this appliance, otherwise a stack member
let timer = null;
const history = new Map(); // counter -> recent values, for the sparklines
let lastCounters = null;

// ---- plumbing ------------------------------------------------------------

async function api(path, opts) {{
  const r = await fetch(path, Object.assign({{
    headers: {{ Authorization: "Bearer " + token }},
  }}, opts || {{}}));
  if (r.status === 401) {{ signOut("That token was not accepted."); throw new Error("unauthorised"); }}
  if (!r.ok) throw new Error((await r.text()) || ("HTTP " + r.status));
  return r;
}}

// A `show` against whichever member is selected. The proxy exists so one pane
// can drive the pair; pointing the browser at the peer directly would need its
// management port reachable from wherever the operator happens to be.
function showPath(p) {{
  if (!target) return p;
  return "/api/v1/stack/" + encodeURIComponent(target) + "/show/" +
         p.replace(/^\/api\/v1\/show\//, "");
}}

async function text(path) {{ return (await (await api(showPath(path))).text()); }}

async function configure(lines) {{
  const r = await api("/api/v1/configure", {{
    method: "POST",
    headers: {{ Authorization: "Bearer " + token, "Content-Type": "text/plain" }},
    body: lines.join("\n") + "\n",
  }});
  return r.json();
}}

function el(tag, attrs, kids) {{
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {{}})) {{
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n[k] = v;
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }}
  for (const kid of kids || []) n.append(kid);
  return n;
}}

// ---- counters ------------------------------------------------------------

// `show firewall statistics` prints `name  value` lines. Parsing the CLI's own
// output rather than adding a JSON endpoint keeps one source of truth: if the
// console can show a counter, the terminal shows the same number.
function parseCounters(out) {{
  const m = new Map();
  for (const line of out.split("\n")) {{
    const t = line.trim().match(/^([a-z0-9_]+)\s+(\d+)$/);
    if (t) m.set(t[1], Number(t[2]));
  }}
  return m;
}}

function sparkline(canvas, values) {{
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w * dpr; canvas.height = h * dpr;
  const g = canvas.getContext("2d");
  g.scale(dpr, dpr);
  g.clearRect(0, 0, w, h);
  if (values.length < 2) return;
  const max = Math.max(1, ...values);
  const step = w / (values.length - 1);
  const y = (v) => h - 2 - (v / max) * (h - 6);
  const css = getComputedStyle(document.documentElement);
  const accent = css.getPropertyValue("--accent").trim() || "#4c8dff";
  g.beginPath();
  values.forEach((v, i) => (i ? g.lineTo(i * step, y(v)) : g.moveTo(0, y(v))));
  g.strokeStyle = accent; g.lineWidth = 1.6; g.stroke();
  g.lineTo(w, h); g.lineTo(0, h); g.closePath();
  g.globalAlpha = 0.13; g.fillStyle = accent; g.fill();
}}

async function refreshDashboard() {{
  // Services first: a red unit explains every strange number below it.
  try {{
    const s = await (await api("/api/v1/status")).json();
    $("host").textContent = s.hostname || "";
    const out = $("services");
    out.textContent = "";
    for (const [name, state] of Object.entries(s.services || {{}})) {{
      out.append(el("div", {{ class: "card" }}, [
        el("h3", {{ text: name }}),
        el("div", {{ class: "metric " + (state === "active" ? "ok" : "err"), text: state }}),
      ]));
    }}
  }} catch (e) {{ /* the counters below still work; the pill shows the failure */ }}

  let counters;
  try {{ counters = parseCounters(await text("/api/v1/show/firewall/statistics")); }}
  catch (e) {{ $("counters").textContent = ""; return; }}

  // The graphs plot the *rate*: a monotonic total tells you nothing about now.
  for (const g of GRAPHS) {{
    const now = counters.get(g.c) || 0;
    const prev = lastCounters ? (lastCounters.get(g.c) || 0) : null;
    if (prev !== null) {{
      const series = history.get(g.c) || [];
      series.push(Math.max(0, now - prev));
      while (series.length > 60) series.shift();
      history.set(g.c, series);
    }}
  }}
  lastCounters = counters;

  const box = $("graphs");
  box.textContent = "";
  for (const g of GRAPHS) {{
    const series = history.get(g.c) || [];
    const canvas = el("canvas", {{}});
    box.append(el("div", {{ class: "card" }}, [
      el("h3", {{ text: g.l }}),
      el("div", {{ class: "metric" }}, [
        document.createTextNode(String(counters.get(g.c) ?? 0)),
        el("small", {{ text: series.length ? "  +" + series[series.length - 1] + "/s" : "" }}),
      ]),
      canvas,
    ]));
    sparkline(canvas, series);
  }}

  const table = $("counters");
  const all = $("allcounters").checked;
  table.textContent = "";
  table.append(el("tr", {{}}, [el("th", {{ text: "counter" }}), el("th", {{ text: "value" }})]));
  for (const [name, value] of counters) {{
    if (!all && value === 0) continue;
    table.append(el("tr", {{ class: value === 0 ? "zero" : "" }}, [
      el("td", {{ text: name }}),
      el("td", {{ class: "num", text: String(value) }}),
    ]));
  }}
}}

// ---- rules ---------------------------------------------------------------

// The rule list is read out of the running configuration, which is the same text
// `show configuration` prints — so the table can never list a rule the appliance
// does not have.
function parseRules(config) {{
  const rules = new Map();
  const re = /^\s*set firewall rule (\S+)(?: (.*))?$/;
  let block = null;
  for (const raw of config.split("\n")) {{
    const line = raw.replace(/\s+$/, "");
    let m = line.match(/^\s*rule (\S+) \{{\s*$/);
    if (m) {{ block = m[1]; if (!rules.has(block)) rules.set(block, {{ name: block }}); continue; }}
    if (block && /^\s*\}}\s*$/.test(line)) {{ block = null; continue; }}
    if (block) {{
      const f = line.trim().split(/\s+/);
      if (f.length >= 2) rules.get(block)[f[0]] = f.slice(1).join(" ");
      continue;
    }}
    m = line.match(re);
    if (m && m[2]) {{
      const f = m[2].split(/\s+/);
      if (!rules.has(m[1])) rules.set(m[1], {{ name: m[1] }});
      rules.get(m[1])[f[0]] = f.slice(1).join(" ");
    }}
  }}
  return [...rules.values()];
}}

async function refreshRules() {{
  $("fwshow").textContent = "…";
  let config = "";
  try {{ config = await text("/api/v1/show/configuration"); }}
  catch (e) {{ $("fwshow").textContent = String(e.message || e); return; }}
  try {{ $("fwshow").textContent = (await text("/api/v1/show/firewall")).trimEnd(); }}
  catch (e) {{ $("fwshow").textContent = String(e.message || e); }}

  const rules = parseRules(config);
  const t = $("ruletable");
  t.textContent = "";
  t.append(el("tr", {{}}, ["name", "from", "to", "action", "proto", "port", "source", "destination", ""]
    .map((h) => el("th", {{ text: h }}))));
  if (!rules.length) {{
    t.append(el("tr", {{}}, [el("td", {{ colspan: "9", text: "no rules configured" }})]));
  }}
  for (const r of rules) {{
    const edit = el("button", {{ class: "btn", text: "Edit", onclick: () => openEditor(r) }});
    const del = el("button", {{
      class: "btn danger", text: "Delete",
      onclick: () => run(["delete firewall rule " + r.name], true),
    }});
    t.append(el("tr", {{}}, [
      el("td", {{ text: r.name }}),
      el("td", {{ text: r.from || "" }}),
      el("td", {{ text: r.to || "" }}),
      el("td", {{ text: r.action || "" }}),
      el("td", {{ text: r.proto || "" }}),
      el("td", {{ text: r.port || "" }}),
      el("td", {{ text: r.source || "" }}),
      el("td", {{ text: r.destination || "" }}),
      el("td", {{}}, [el("div", {{ class: "row" }}, [edit, del])]),
    ]));
  }}
}}

const FIELDS = [
  ["r-from", "from"], ["r-to", "to"], ["r-action", "action"], ["r-proto", "proto"],
  ["r-port", "port"], ["r-source", "source"], ["r-dest", "destination"],
];

function script() {{
  const name = $("r-name").value.trim();
  if (!name) return [];
  const lines = [];
  for (const [id, key] of FIELDS) {{
    const v = $(id).value.trim();
    if (v) lines.push(`set firewall rule ${{name}} ${{key}} ${{v}}`);
  }}
  return lines;
}}

function renderPreview() {{
  const lines = script();
  $("preview").textContent = lines.length ? lines.join("\n") : "(nothing to apply)";
}}

function openEditor(rule) {{
  $("editortitle").textContent = rule ? "Edit rule " + rule.name : "New rule";
  $("r-name").value = rule ? rule.name : "";
  $("r-name").readOnly = !!rule;
  for (const [id, key] of FIELDS) $(id).value = (rule && rule[key]) || "";
  $("editorerr").textContent = "";
  renderPreview();
  $("editor").showModal();
}}

async function run(lines, confirmFirst) {{
  if (!lines.length) return;
  if (confirmFirst && !window.confirm(lines.join("\n") + "\n\ncommit\nsave")) return;
  const r = await configure(lines.concat(["commit", "save"]));
  showResult(r);
  await refresh();
}}

function showResult(r) {{
  // The output is shown whether or not the exit status was a success: a commit
  // the appliance REFUSED reports that in its output, not in its status, and a
  // console that only looked at `ok` would tell the operator it worked.
  $("resultout").textContent = (r.output || "").trim() || (r.ok ? "applied" : "failed");
  $("result").showModal();
}}

// ---- stack ---------------------------------------------------------------

async function refreshStack() {{
  const t = $("stacktable");
  t.textContent = "";
  t.append(el("tr", {{}}, ["member", "hostname", "state", ""].map((h) => el("th", {{ text: h }}))));
  let data;
  try {{ data = await (await api("/api/v1/stack")).json(); }}
  catch (e) {{ t.append(el("tr", {{}}, [el("td", {{ colspan: "4", text: String(e.message || e) }})])); return; }}
  for (const m of data.members) {{
    const isSelf = m.name === "self";
    const name = isSelf ? "" : m.name;
    const select = el("button", {{
      class: "btn" + (target === name ? " primary" : ""),
      text: target === name ? "selected" : "view",
      onclick: () => {{ target = name; $("target").textContent = isSelf ? "this appliance" : m.name; refresh(); }},
    }});
    t.append(el("tr", {{}}, [
      el("td", {{ text: isSelf ? "this appliance" : m.name }}),
      el("td", {{ text: m.hostname || "" }}),
      el("td", {{}}, [el("span", {{
        class: "pill " + (m.reachable ? "up" : "down"),
        text: m.reachable ? "reachable" : "unreachable",
      }})]),
      el("td", {{}}, [select]),
    ]));
  }}
  if (data.members.length === 1) {{
    t.append(el("tr", {{}}, [el("td", {{
      colspan: "4",
      text: "No peers configured — set system config-sync peer <host> to add one.",
    }})]));
  }}
}}

// ---- views ---------------------------------------------------------------

function buildNav() {{
  const nav = $("nav");
  nav.textContent = "";
  for (const group of NAV) {{
    nav.append(el("div", {{ class: "grp", text: group.g }}));
    for (const item of group.items) {{
      nav.append(el("button", {{
        text: item.t,
        "data-view": "panel",
        "data-path": item.p,
        onclick: () => {{ view = "panel"; panel = item; refresh(); }},
      }}));
    }}
  }}
  for (const b of document.querySelectorAll("aside button[data-view]")) {{
    if (b.dataset.path) continue;
    b.onclick = () => {{ view = b.dataset.view; panel = null; refresh(); }};
  }}
}}

async function refresh() {{
  for (const b of document.querySelectorAll("aside button[data-view]")) {{
    const active = b.dataset.path ? (panel && b.dataset.path === panel.p)
                                  : (!panel && b.dataset.view === view);
    b.setAttribute("aria-current", String(!!active));
  }}
  for (const v of ["dashboard", "rules", "stack", "panel"]) {{
    $("view-" + v).classList.toggle("hidden", v !== view);
  }}
  $("title").textContent = panel ? panel.t
    : view === "rules" ? "Firewall rules" : view === "stack" ? "Stack" : "Dashboard";

  if (view === "dashboard") return refreshDashboard();
  if (view === "rules") return refreshRules();
  if (view === "stack") return refreshStack();
  if (view === "panel" && panel) {{
    $("panel").textContent = "…";
    try {{ $("panel").textContent = (await text(panel.p)).trimEnd() || "(nothing to show)"; }}
    catch (e) {{ $("panel").textContent = String(e.message || e); }}
  }}
}}

function signOut(message) {{
  token = "";
  sessionStorage.removeItem(KEY);
  if (timer) {{ clearInterval(timer); timer = null; }}
  $("app").classList.add("hidden");
  $("login").classList.remove("hidden");
  $("loginerr").textContent = message || "";
}}

function signedIn() {{
  $("login").classList.add("hidden");
  $("app").classList.remove("hidden");
  buildNav();
  refresh();
  // Only the dashboard polls: a panel refreshing under a reader who is trying to
  // read it is a worse experience than a stale one they chose to refresh.
  timer = setInterval(() => {{ if (view === "dashboard") refreshDashboard(); }}, 5000);
}}

$("loginform").onsubmit = (e) => {{
  e.preventDefault();
  token = $("token").value.trim();
  if (!token) return;
  sessionStorage.setItem(KEY, token);
  $("token").value = "";
  $("loginerr").textContent = "";
  signedIn();
}};
$("signout").onclick = () => signOut("");
$("refresh").onclick = () => refresh();
$("allcounters").onchange = () => refreshDashboard();
$("addrule").onclick = () => openEditor(null);
$("cancel").onclick = () => $("editor").close();
$("resultclose").onclick = () => $("result").close();
for (const [id] of FIELDS) $(id).oninput = renderPreview;
$("r-name").oninput = renderPreview;
$("applysave").onclick = async () => {{
  const lines = script();
  if (!lines.length) {{ $("editorerr").textContent = "A rule needs a name and at least one setting."; return; }}
  $("editor").close();
  showResult(await configure(lines.concat(["commit", "save"])));
  await refresh();
}};
$("applyonly").onclick = async () => {{
  const lines = script();
  if (!lines.length) {{ $("editorerr").textContent = "A rule needs a name and at least one setting."; return; }}
  $("editor").close();
  showResult(await configure(lines.concat(["commit"])));
  await refresh();
}};
$("theme").onclick = () => {{
  const now = document.documentElement.getAttribute("data-theme");
  const next = now === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem(THEME, next);
}};
const savedTheme = localStorage.getItem(THEME);
if (savedTheme) document.documentElement.setAttribute("data-theme", savedTheme);

if (token) signedIn();
</script>
</body>
</html>
"##
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_is_self_contained() {
        let html = page();
        // An appliance is expected to work on an isolated network: a console that
        // half-renders without the internet is worse than no console.
        for external in ["http://", "https://", "//cdn", "<link", "<script src"] {
            assert!(
                !html.contains(external),
                "the page reaches outside for {external:?}"
            );
        }
    }

    #[test]
    fn every_panel_is_an_api_path() {
        // The page may only call endpoints the API actually serves; anything
        // else is a link that 404s in front of an operator.
        for (group, items) in PANELS {
            for (title, path) in *items {
                assert!(
                    path.starts_with("/api/v1/"),
                    "{group}/{title} points outside the API: {path}"
                );
                assert!(
                    page().contains(path),
                    "{group}/{title} is declared but never rendered into the page"
                );
            }
        }
    }

    /// The management token is the appliance's keys. `localStorage` would leave
    /// it behind on a shared machine long after the tab was closed; the theme
    /// preference is the only thing that belongs there.
    #[test]
    fn the_token_is_kept_for_the_tab_and_nothing_else_is() {
        let html = page();
        assert!(html.contains("sessionStorage.getItem(KEY)"));
        assert!(!html.contains("localStorage.getItem(KEY)"));
        assert!(!html.contains("localStorage.setItem(KEY"));
    }

    /// Editing goes through the CLI grammar. If the console ever assembled a
    /// config document itself, this is the test that should have to change.
    #[test]
    fn changes_are_made_as_cli_commands_not_as_a_config_document() {
        let html = page();
        assert!(html.contains("/api/v1/configure"));
        assert!(html.contains("set firewall rule"));
        assert!(
            !html.contains("PUT"),
            "the console writes a whole config document instead of commands"
        );
    }

    /// A refused commit is reported in the output, not the exit status — so the
    /// console must never gate what it shows on `ok`.
    #[test]
    fn the_result_dialog_shows_output_regardless_of_status() {
        assert!(page().contains("r.output"));
    }

    /// Every graphed counter has to be one the data plane actually reports, or
    /// the dashboard shows a permanent zero and nobody can tell it apart from
    /// quiet traffic.
    #[test]
    fn graphed_counters_are_real_counter_names() {
        for (counter, label) in GRAPHS {
            assert!(
                counter
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{label}: {counter} is not a counter name"
            );
            assert!(page().contains(counter), "{counter} never reaches the page");
        }
    }
}
