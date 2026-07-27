//! C12 — the **web console**.
//!
//! Every comparable firewall has one, and until now Sentinel's management surface
//! was a CLI and a REST API. This is the missing third face of the *same* config
//! and the *same* `show` data — it invents no endpoint of its own and holds no
//! state, so there is nothing here that can disagree with what the CLI reports.
//!
//! ## Read-only, on purpose
//!
//! The console shows; it does not edit. Editing means `PUT /api/v1/config` with a
//! whole document, and a form that reassembles one from fields is precisely where
//! a UI starts to diverge from the config model it is supposed to be a view of.
//! The CLI (and the API, for automation) remains the editing surface until the
//! console can drive the *same* validated document rather than a rendering of it.
//!
//! ## One file, nothing fetched
//!
//! The page is a single self-contained document: no CDN, no font, no framework.
//! An appliance is expected to work on an isolated network, and a management
//! console that half-renders because it cannot reach the internet is worse than
//! no console. It is also why the page is served from the binary rather than from
//! a directory that could drift from it.
//!
//! ## The token never touches disk
//!
//! The page itself is public — it contains no data, only markup, and a login form
//! that cannot be reached is not a login form. Every byte of data behind it needs
//! the same bearer token the API requires, held in `sessionStorage` so it is gone
//! when the tab closes: an appliance token has no business outliving the session
//! on a shared machine.

/// The paths the page fetches. Kept beside the page so the check that asserts
/// every one of them answers has something to read, and so adding a panel means
/// adding a line here rather than discovering the omission in a browser.
///
/// `show` paths that need a subsystem to be configured still answer — they say so
/// in words — which is what makes them safe to render unconditionally.
pub const PANELS: &[(&str, &str)] = &[
    ("Firewall", "/api/v1/show/firewall"),
    ("Statistics", "/api/v1/show/firewall/statistics"),
    ("Connections", "/api/v1/show/firewall/flows"),
    ("Top talkers", "/api/v1/show/firewall/top"),
    ("NAT", "/api/v1/show/nat"),
    ("Interfaces", "/api/v1/show/interfaces"),
    ("Routes", "/api/v1/show/ip/route"),
    ("Intrusion detection", "/api/v1/show/ids"),
    ("Alerts", "/api/v1/show/ids/alerts"),
    ("Run-time blocks", "/api/v1/show/ids/blocks"),
    ("Certificates", "/api/v1/show/pki"),
    ("Load balancer", "/api/v1/show/load-balancer"),
    ("Broadcast relay", "/api/v1/show/broadcast-relay"),
    ("Version", "/api/v1/show/version"),
];

/// The console, as one document.
pub fn page() -> String {
    let panels: String = PANELS
        .iter()
        .map(|(title, path)| format!("        {{ title: {title:?}, path: {path:?} }},\n"))
        .collect();
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel</title>
<style>
  :root {{
    color-scheme: light dark;
    --bg: #ffffff; --fg: #16191d; --muted: #5b6470;
    --line: #d8dde3; --panel: #f6f8fa; --accent: #1f6feb;
    --ok: #1a7f37; --bad: #b42318;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #14171a; --fg: #e6e9ee; --muted: #99a2ad;
      --line: #2a2f36; --panel: #1b1f24; --accent: #58a6ff;
      --ok: #3fb950; --bad: #f85149;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--fg);
    font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif;
  }}
  header {{
    display: flex; align-items: baseline; gap: 1rem; flex-wrap: wrap;
    padding: 1rem 1.25rem; border-bottom: 1px solid var(--line);
  }}
  header h1 {{ font-size: 1.1rem; margin: 0; letter-spacing: .02em; }}
  header .host {{ color: var(--muted); font-variant-numeric: tabular-nums; }}
  main {{ padding: 1.25rem; max-width: 70rem; margin: 0 auto; }}
  .row {{ display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }}
  input, button, select {{
    font: inherit; padding: .4rem .6rem; border-radius: 6px;
    border: 1px solid var(--line); background: var(--bg); color: var(--fg);
  }}
  button {{ cursor: pointer; }}
  button.primary {{ background: var(--accent); border-color: var(--accent); color: #fff; }}
  .card {{
    border: 1px solid var(--line); border-radius: 8px;
    background: var(--panel); padding: .9rem 1rem; margin: 0 0 1rem;
  }}
  .card h2 {{ font-size: .8rem; text-transform: uppercase; letter-spacing: .08em;
              color: var(--muted); margin: 0 0 .6rem; }}
  pre {{ margin: 0; overflow-x: auto; font: 12.5px/1.45 ui-monospace, SFMono-Regular,
         Menlo, Consolas, monospace; white-space: pre; }}
  .grid {{ display: grid; gap: .35rem 1rem; grid-template-columns: max-content 1fr; }}
  .up {{ color: var(--ok); }} .down {{ color: var(--bad); }}
  .hidden {{ display: none; }}
  .err {{ color: var(--bad); }}
  nav {{ display: flex; gap: .35rem; flex-wrap: wrap; margin-bottom: 1rem; }}
  nav button[aria-current="true"] {{ border-color: var(--accent); color: var(--accent); }}
</style>
</head>
<body>
<header>
  <h1>Sentinel</h1>
  <span class="host" id="host"></span>
  <span class="row" style="margin-left:auto">
    <button id="signout" class="hidden">Sign out</button>
  </span>
</header>

<main>
  <section id="login" class="card">
    <h2>Sign in</h2>
    <p style="margin:.2rem 0 .8rem;color:var(--muted)">
      The management token — the same bearer token the API takes. It is kept for
      this tab only and never written to disk.
    </p>
    <form class="row" id="loginform">
      <input id="token" type="password" placeholder="management token"
             autocomplete="off" style="flex:1 1 18rem">
      <button class="primary" type="submit">Sign in</button>
    </form>
    <p id="loginerr" class="err"></p>
  </section>

  <section id="console" class="hidden">
    <div class="card">
      <h2>Status</h2>
      <div class="grid" id="status"></div>
    </div>
    <nav id="tabs"></nav>
    <div class="card">
      <h2 id="paneltitle"></h2>
      <pre id="panel">…</pre>
    </div>
    <p style="color:var(--muted)">
      This console is read-only. Configuration is changed from the CLI
      (<code>configure</code>) or through <code>PUT /api/v1/config</code>.
    </p>
  </section>
</main>

<script>
"use strict";
const PANELS = [
{panels}];

const $ = (id) => document.getElementById(id);
const KEY = "sentinel-token";
let token = sessionStorage.getItem(KEY) || "";
let current = 0;
let timer = null;

async function api(path) {{
  const r = await fetch(path, {{ headers: {{ Authorization: "Bearer " + token }} }});
  if (r.status === 401) {{ signOut("That token was not accepted."); throw new Error("unauthorised"); }}
  if (!r.ok) throw new Error((await r.text()) || ("HTTP " + r.status));
  return r;
}}

function signOut(message) {{
  token = "";
  sessionStorage.removeItem(KEY);
  if (timer) {{ clearInterval(timer); timer = null; }}
  $("console").classList.add("hidden");
  $("signout").classList.add("hidden");
  $("login").classList.remove("hidden");
  $("host").textContent = "";
  $("loginerr").textContent = message || "";
}}

function row(parent, label, value, cls) {{
  const k = document.createElement("div");
  k.style.color = "var(--muted)";
  k.textContent = label;
  const v = document.createElement("div");
  if (cls) v.className = cls;
  v.textContent = value;
  parent.append(k, v);
}}

async function refreshStatus() {{
  let s;
  try {{ s = await (await api("/api/v1/status")).json(); }} catch (e) {{ return; }}
  $("host").textContent = s.hostname || "";
  const out = $("status");
  out.textContent = "";
  for (const [name, state] of Object.entries(s.services || {{}})) {{
    row(out, name, state, state === "active" ? "up" : "down");
  }}
  for (const i of s.interfaces || []) {{
    // The API reports interfaces as objects; render whatever it named them
    // rather than assuming a shape this page would then have to keep in step.
    const label = i.name || "interface";
    const rest = Object.entries(i)
      .filter(([k]) => k !== "name")
      .map(([k, v]) => k + "=" + v)
      .join(" ");
    row(out, label, rest);
  }}
}}

async function showPanel(index) {{
  current = index;
  const p = PANELS[index];
  $("paneltitle").textContent = p.title;
  for (const b of $("tabs").children) {{
    b.setAttribute("aria-current", String(b.dataset.index === String(index)));
  }}
  $("panel").textContent = "…";
  try {{
    $("panel").textContent = (await (await api(p.path)).text()).trimEnd() || "(nothing to show)";
  }} catch (e) {{
    $("panel").textContent = String(e.message || e);
    $("panel").classList.add("err");
    return;
  }}
  $("panel").classList.remove("err");
}}

function signedIn() {{
  $("login").classList.add("hidden");
  $("console").classList.remove("hidden");
  $("signout").classList.remove("hidden");
  const tabs = $("tabs");
  tabs.textContent = "";
  PANELS.forEach((p, i) => {{
    const b = document.createElement("button");
    b.textContent = p.title;
    b.dataset.index = String(i);
    b.onclick = () => showPanel(i);
    tabs.append(b);
  }});
  refreshStatus();
  showPanel(0);
  // A firewall dashboard that shows a stale service state is worse than one
  // that shows none; the panels stay put so a reader is not interrupted.
  timer = setInterval(refreshStatus, 10000);
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

if (token) signedIn();
</script>
</body>
</html>
"#
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
        for external in ["http://", "https://", "//cdn", "<link"] {
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
        for (title, path) in PANELS {
            assert!(
                path.starts_with("/api/v1/"),
                "{title} points outside the API: {path}"
            );
            assert!(
                page().contains(path),
                "{title} is declared but never rendered into the page"
            );
        }
    }

    #[test]
    fn the_token_is_not_persisted_to_disk() {
        // localStorage would leave an appliance's management token behind on a
        // shared machine long after the tab was closed.
        let html = page();
        assert!(html.contains("sessionStorage"));
        assert!(!html.contains("localStorage"));
    }
}
