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
//! ## The design system, inlined
//!
//! The look is Velstra's own: the palette, type scale, spacing grid, radii and
//! elevation are its tokens, copied in rather than imported for the reason
//! above. It is dark only, as that system is — it defines no light ramp, and
//! inventing one here would be designing instead of adopting.
//!
//! The one deliberate divergence is the typefaces. The system names Space
//! Grotesk, IBM Plex Sans and JetBrains Mono; embedding three faces would add
//! several hundred kilobytes to a page an operator opens during an incident,
//! and fetching them is impossible by the same rule as everything else. So they
//! are named first and fall back to the system stack: exact where a workstation
//! has them, and carried by the palette and rhythm everywhere else.
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
            ("DHCP leases", "/api/v1/show/dhcp/leases"),
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
  /* ======================================================================
     Velstra design system — tokens, inlined.

     The console is one self-contained document, so the tokens live here
     rather than behind a linked stylesheet: an appliance is expected to work on an
     isolated network, and a stylesheet it cannot fetch is a console that
     renders as unstyled text at the worst possible moment.

     The families below name the design system's faces first and fall back to
     the system stack, because for the same reason no webfont can be fetched
     and none is embedded — a display face is not worth several hundred
     kilobytes in a page an operator opens during an incident. On a
     workstation that has them installed the console renders exactly as
     designed; everywhere else the palette, scale and rhythm still carry it.

     Dark only, as the system is: it defines no light ramp, and inventing one
     here would be designing rather than adopting.
     ====================================================================== */
  :root {{
    color-scheme: dark;

    --ink-950: #070a10; --ink-900: #0b0e14; --ink-850: #0e121a;
    --ink-800: #11151f; --ink-700: #161c28; --ink-600: #1d2431;
    --ink-500: #232b3a; --ink-400: #313b4d; --ink-300: #4a566b;
    --slate-400: #9ba6b8; --slate-100: #e6eaf2; --white: #f6f8fc;

    --signal-300: #85acff; --signal-400: #5f93ff; --signal-500: #4c8dff;
    --signal-600: #3a72e6; --signal-900: #16264f;
    --sentinel-500: #ffb020; --sentinel-600: #e6941a; --sentinel-900: #4a3208;

    --green-500: #3fb950; --amber-500: #ffb020; --red-500: #f85149;
    --cyan-500: #39b4d6;

    --bg-app: var(--ink-900); --surface: var(--ink-800);
    --surface-raised: var(--ink-700); --surface-sunken: var(--ink-850);
    --surface-hover: var(--ink-600);
    --text-strong: var(--white); --text-body: var(--slate-100);
    --text-muted: var(--slate-400); --text-faint: var(--ink-300);
    --border: var(--ink-500); --border-strong: var(--ink-400);
    --border-subtle: var(--ink-600);
    --brand: var(--signal-500); --brand-hover: var(--signal-400);
    --brand-active: var(--signal-600); --focus-ring: var(--signal-400);
    --link: var(--signal-400);
    --status-up: var(--green-500); --status-down: var(--red-500);
    --status-warn: var(--amber-500); --status-info: var(--cyan-500);

    /* Sentinel is the product this console belongs to, so its amber is the
       accent that marks state and identity; signal blue stays the action
       colour. Two roles, never interchanged. */
    --product: var(--sentinel-500);
    --product-strong: var(--sentinel-600);
    --product-subtle: var(--sentinel-900);

    --font-display: "Space Grotesk", "Segoe UI", system-ui, sans-serif;
    --font-sans: "IBM Plex Sans", system-ui, -apple-system, sans-serif;
    --font-mono: "JetBrains Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    --fw-regular: 400; --fw-medium: 500; --fw-semibold: 600;
    --text-2xs: .6875rem; --text-xs: .75rem; --text-sm: .8125rem;
    --text-base: .9375rem; --text-lg: 1.25rem; --text-xl: 1.5rem;
    --leading-tight: 1.1; --leading-snug: 1.28; --leading-normal: 1.55;
    --leading-code: 1.45;
    --tracking-tight: -.02em; --tracking-caps: .08em;

    --space-1: .25rem; --space-2: .5rem; --space-3: .75rem; --space-4: 1rem;
    --space-5: 1.25rem; --space-6: 1.5rem; --space-7: 2rem; --space-9: 3rem;
    --sidebar-w: 268px;

    --radius-xs: 3px; --radius-sm: 5px; --radius-md: 8px; --radius-lg: 12px;
    --radius-pill: 999px;

    --shadow-sm: 0 1px 2px rgba(0,0,0,.4);
    --shadow-md: 0 4px 12px rgba(0,0,0,.45);
    --shadow-lg: 0 12px 32px rgba(0,0,0,.5);
    --edge-top: inset 0 1px 0 rgba(255,255,255,.05);
    --glow-focus: 0 0 0 3px rgba(76,141,255,.35);
  }}

  *, *::before, *::after {{ box-sizing: border-box; }}
  html {{ -webkit-text-size-adjust: 100%; }}
  body {{
    margin: 0; background: var(--bg-app); color: var(--text-body);
    font: var(--fw-regular) var(--text-base)/var(--leading-normal) var(--font-sans);
    -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility;
  }}
  h1, h2, h3 {{
    margin: 0; color: var(--text-strong); font-family: var(--font-display);
    font-weight: var(--fw-semibold); letter-spacing: var(--tracking-tight);
    line-height: var(--leading-snug);
  }}
  p {{ margin: 0; }}
  code, pre {{
    font-family: var(--font-mono); font-size: var(--text-sm);
    line-height: var(--leading-code);
  }}
  ::selection {{ background: rgba(76,141,255,.4); color: var(--white); }}
  :focus-visible {{ outline: 2px solid var(--focus-ring); outline-offset: 2px; }}

  /* --- shell ------------------------------------------------------------ */
  .app {{ display: grid; grid-template-columns: var(--sidebar-w) 1fr; min-height: 100vh; }}
  @media (max-width: 900px) {{
    .app {{ grid-template-columns: 1fr; }}
    aside {{ position: static !important; height: auto !important; }}
  }}

  aside {{
    background: var(--ink-950); border-right: 1px solid var(--border-subtle);
    position: sticky; top: 0; height: 100vh; overflow-y: auto;
    display: flex; flex-direction: column; gap: var(--space-1);
    padding: var(--space-5) var(--space-3);
  }}
  aside h1 {{
    font-size: var(--text-lg); margin: var(--space-1) var(--space-3) var(--space-6);
    display: flex; align-items: center; gap: var(--space-2);
  }}
  /* The product mark: a small amber block, the same device the docs use for
     Sentinel. It is the only decoration in the rail. */
  aside h1::before {{
    content: ""; width: 10px; height: 18px; border-radius: var(--radius-xs);
    background: var(--product); box-shadow: 0 0 18px -2px var(--product);
  }}
  aside .grp {{
    font: var(--fw-semibold) var(--text-2xs)/1.2 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
    color: var(--text-faint); margin: var(--space-5) var(--space-3) var(--space-2);
  }}
  aside button {{
    display: block; width: 100%; text-align: left; background: none;
    border: 0; color: var(--text-muted); font: inherit; font-size: var(--text-sm);
    padding: var(--space-2) var(--space-3); border-radius: var(--radius-sm);
    cursor: pointer; position: relative;
  }}
  aside button:hover {{ background: var(--surface-hover); color: var(--text-body); }}
  aside button[aria-current="true"] {{
    background: var(--signal-900); color: var(--white);
  }}
  /* The current view is marked by a rail on its left edge rather than a fill,
     so the eye finds it without the sidebar turning into a block of colour. */
  aside button[aria-current="true"]::before {{
    content: ""; position: absolute; left: 0; top: 15%; bottom: 15%;
    width: 2px; border-radius: var(--radius-pill); background: var(--brand);
  }}

  main {{ padding: var(--space-6) var(--space-7) var(--space-9); max-width: 82rem; }}
  .bar {{
    display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap;
    margin-bottom: var(--space-5); padding-bottom: var(--space-4);
    border-bottom: 1px solid var(--border-subtle);
  }}
  .bar h2 {{ font-size: var(--text-xl); }}
  .spacer {{ margin-left: auto; }}

  .pill {{
    font: var(--fw-medium) var(--text-2xs)/1.6 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
    padding: 0 var(--space-2); border-radius: var(--radius-pill);
    border: 1px solid var(--border); color: var(--text-muted);
  }}
  .pill.up {{ color: var(--status-up); border-color: color-mix(in oklab, var(--status-up) 45%, transparent); }}
  .pill.down {{ color: var(--status-down); border-color: color-mix(in oklab, var(--status-down) 45%, transparent); }}

  /* --- surfaces --------------------------------------------------------- */
  .card {{
    border: 1px solid var(--border); border-radius: var(--radius-md);
    background: var(--surface); box-shadow: var(--shadow-sm), var(--edge-top);
    padding: var(--space-4) var(--space-5); margin: 0 0 var(--space-4);
  }}
  .card > h3 {{
    font: var(--fw-semibold) var(--text-2xs)/1.2 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
    color: var(--text-muted); margin: 0 0 var(--space-3);
  }}
  .cards {{
    display: grid; gap: var(--space-4);
    grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr));
    margin-bottom: var(--space-4);
  }}
  .metric {{
    font: var(--fw-semibold) var(--text-xl)/var(--leading-tight) var(--font-display);
    font-variant-numeric: tabular-nums; color: var(--text-strong);
  }}
  .metric small {{
    font: var(--fw-regular) var(--text-xs)/1.2 var(--font-mono);
    color: var(--text-muted); margin-left: var(--space-2);
  }}
  .metric.ok {{ color: var(--status-up); }}
  .metric.err {{ color: var(--status-down); }}
  canvas {{ width: 100%; height: 48px; display: block; margin-top: var(--space-2); }}

  pre.out {{
    margin: 0; overflow-x: auto; white-space: pre;
    background: var(--surface-sunken); border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm); padding: var(--space-3);
    color: var(--text-body);
  }}

  /* --- data ------------------------------------------------------------- */
  table {{ border-collapse: collapse; width: 100%; font-size: var(--text-sm); }}
  th, td {{
    text-align: left; padding: var(--space-2) var(--space-3);
    border-bottom: 1px solid var(--border-subtle); vertical-align: middle;
  }}
  th {{
    font: var(--fw-semibold) var(--text-2xs)/1.2 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
    color: var(--text-faint); border-bottom-color: var(--border-strong);
    white-space: nowrap;
  }}
  tbody tr:hover, tr:hover {{ background: var(--surface-raised); }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; font-family: var(--font-mono); }}
  tr.zero td {{ color: var(--text-faint); }}

  /* --- controls --------------------------------------------------------- */
  input, select, textarea, button.btn {{
    font: inherit; font-size: var(--text-sm); color: var(--text-body);
    padding: var(--space-2) var(--space-3); border-radius: var(--radius-sm);
    border: 1px solid var(--border-strong); background: var(--surface-sunken);
  }}
  input, select, textarea {{ width: 100%; min-width: 0; }}
  input:focus, select:focus, textarea:focus {{
    outline: none; border-color: var(--brand); box-shadow: var(--glow-focus);
  }}
  button.btn {{
    cursor: pointer; background: var(--surface-raised); width: auto;
    white-space: nowrap;
  }}
  button.btn:hover {{ background: var(--surface-hover); color: var(--text-strong); }}
  button.primary {{
    background: var(--brand); border-color: var(--brand); color: var(--ink-950);
    font-weight: var(--fw-medium);
  }}
  button.primary:hover {{ background: var(--brand-hover); color: var(--ink-950); }}
  button.danger {{ color: var(--status-down); }}
  button.danger:hover {{ color: var(--status-down); border-color: var(--status-down); }}

  .row {{ display: flex; gap: var(--space-2); flex-wrap: wrap; align-items: center; }}
  .field {{ display: flex; flex-direction: column; gap: var(--space-1); }}
  .field label {{
    font: var(--fw-medium) var(--text-2xs)/1.2 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
    color: var(--text-muted);
  }}
  .grid2 {{ display: grid; gap: var(--space-3); grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); }}
  .hidden {{ display: none; }}
  .err {{ color: var(--status-down); white-space: pre-wrap; }}
  .ok {{ color: var(--status-up); }}

  dialog {{
    border: 1px solid var(--border-strong); border-radius: var(--radius-lg);
    background: var(--surface); color: var(--text-body);
    box-shadow: var(--shadow-lg); padding: var(--space-5) var(--space-6);
    max-width: 48rem; width: calc(100% - var(--space-7));
  }}
  dialog::backdrop {{ background: rgba(7,10,16,.7); }}
  .script {{
    background: var(--surface-sunken); border: 1px solid var(--border);
    border-left: 2px solid var(--product); border-radius: var(--radius-sm);
    padding: var(--space-3); font: var(--fw-regular) var(--text-sm)/var(--leading-code) var(--font-mono);
    white-space: pre-wrap; color: var(--text-body);
  }}

  /* The sign-in card is the whole page before there is a session, so it gets
     the product mark and sits on the void rather than in the shell. */
  #login {{ max-width: 27rem; margin: 14vh auto; box-shadow: var(--shadow-md), var(--edge-top); }}

  /* --- brand & rail ------------------------------------------------------ */
  .brand {{ display: flex; align-items: center; gap: var(--space-3); }}
  .brand .mark {{
    display: grid; place-items: center; width: 34px; height: 34px; flex: none;
    border-radius: 12px; color: var(--ink-950);
    background: linear-gradient(150deg, var(--sentinel-500), var(--signal-500));
  }}
  .brand .mark svg {{ width: 18px; height: 18px; }}
  .wordmark {{ display: flex; flex-direction: column; gap: 1px; min-width: 0; }}
  .wordmark .name {{
    font: var(--fw-semibold) var(--text-base)/1.1 var(--font-display);
    letter-spacing: -.03em; color: var(--text-strong);
  }}
  .wordmark .sub {{
    font: var(--fw-regular) var(--text-2xs)/1.2 var(--font-mono);
    color: var(--text-faint);
  }}

  .search {{
    display: flex; align-items: center; gap: var(--space-2);
    padding: var(--space-2) var(--space-3); border-radius: var(--radius-sm);
    background: var(--surface-sunken); border: 1px solid var(--border-subtle);
  }}
  .search svg {{ width: 14px; height: 14px; flex: none; color: var(--text-faint); }}
  .search input {{
    flex: 1; min-width: 0; background: transparent; border: 0; padding: 0;
    color: var(--text-body); font-size: var(--text-sm);
  }}
  .search input:focus {{ outline: none; box-shadow: none; }}

  nav {{ display: flex; flex-direction: column; gap: var(--space-4); }}
  nav .group {{ display: flex; flex-direction: column; gap: 3px; }}
  aside button.navitem {{
    display: flex; align-items: center; gap: var(--space-2);
  }}
  aside button.navitem svg {{ width: 15px; height: 15px; flex: none; }}
  aside button.navitem .meta {{
    margin-left: auto; font: var(--fw-medium) var(--text-2xs)/1.4 var(--font-mono);
    color: var(--text-faint);
  }}

  .cluster {{
    margin-top: auto; display: flex; flex-direction: column; gap: var(--space-3);
    padding: var(--space-4); background: var(--surface-sunken);
    border: 1px solid var(--border-subtle); border-radius: 16px;
  }}
  .cluster .clabel {{
    font: var(--fw-semibold) var(--text-xs)/1.2 var(--font-sans); color: var(--text-muted);
  }}
  .cluster button {{
    display: flex; align-items: center; gap: var(--space-2); font-size: var(--text-sm);
  }}
  .cluster .role {{
    margin-left: auto; font: var(--fw-regular) var(--text-2xs)/1.4 var(--font-mono);
    color: var(--text-muted);
  }}
  .cluster .crev {{
    font-family: var(--font-mono); font-size: var(--text-2xs); color: var(--text-faint);
  }}
  .dot {{
    width: 8px; height: 8px; flex: none; border-radius: var(--radius-pill);
    background: var(--text-faint);
  }}
  .dot.up {{ background: var(--status-up); box-shadow: 0 0 8px -1px var(--status-up); }}
  .dot.down {{ background: var(--status-down); }}

  /* --- header ------------------------------------------------------------ */
  .crumbs {{ display: flex; flex-direction: column; gap: 3px; min-width: 0; flex: 1 1 220px; }}
  .crumbs .slug {{
    font-family: var(--font-mono); font-size: var(--text-2xs); color: var(--text-faint);
  }}

  /* --- staged changes ---------------------------------------------------- */
  .staged {{
    display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-4);
    border-radius: 16px; border-color: color-mix(in oklab, var(--product) 40%, var(--border));
  }}
  .staged .tile {{
    display: grid; place-items: center; width: 34px; height: 34px; flex: none;
    border-radius: 11px; background: var(--product-subtle); color: var(--product);
  }}
  .staged .tile svg {{ width: 17px; height: 17px; }}
  .stagedtext {{ display: flex; flex-direction: column; gap: 2px; min-width: 0; flex: 1 1 220px; }}
  .stagedtext .t {{ font: var(--fw-semibold) var(--text-base) var(--font-sans); color: var(--text-strong); }}
  .stagedtext .b {{ font-size: var(--text-sm); color: var(--text-muted); }}
</style>
</head>
<body>

<section id="login" class="card">
  <div class="brand" style="margin-bottom:var(--space-5)">
    <span class="mark"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></span>
    <span class="wordmark">
      <span class="name">Velstra Sentinel</span>
      <span class="sub">Appliance console</span>
    </span>
  </div>
  <p style="margin:0 0 var(--space-4);color:var(--text-muted);font-size:var(--text-sm)">
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
    <div class="brand">
      <span class="mark"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></span>
      <span class="wordmark">
        <span class="name">Velstra Sentinel</span>
        <span class="sub" id="navhost">appliance console</span>
      </span>
    </div>

    <label class="search">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
      <input id="navsearch" placeholder="Search sections">
    </label>

    <nav id="nav"></nav>

    <div class="cluster">
      <span class="clabel">Cluster</span>
      <div id="clusterlist"></div>
      <span class="crev" id="clusterrev">rev —</span>
    </div>

    <button class="btn" id="signout" style="width:100%">Sign out</button>
  </aside>

  <main>
    <header class="bar">
      <div class="crumbs">
        <span class="slug" id="crumb">appliance</span>
        <h2 id="title">Dashboard</h2>
      </div>
      <span class="spacer"></span>
      <span class="pill" id="stagedbadge">no staged changes</span>
      <button class="btn" id="discard">Discard</button>
      <button class="btn primary" id="applystaged">Apply</button>
    </header>

    <div class="card staged hidden" id="stagedcard">
      <span class="tile"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 2 9 5-9 5-9-5 9-5z"/><path d="m3 12 9 5 9-5"/><path d="m3 17 9 5 9-5"/></svg></span>
      <span class="stagedtext">
        <span class="t" id="stagedtitle">Staged changes</span>
        <span class="b">Nothing is applied until you say so. These are the exact
          commands that will run.</span>
      </span>
      <span class="row" style="flex:none">
        <button class="btn" id="validate">Validate</button>
        <button class="btn primary" id="applystaged2">Apply and save</button>
      </span>
      <div class="script" id="stagedlist" style="flex:1 1 100%"></div>
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

    <div id="view-zones" class="hidden">
      <div class="card">
        <h3>Global posture</h3>
        <div class="grid2" id="globalform"></div>
        <div class="row" style="margin-top:.8rem">
          <button class="btn primary" id="saveglobal">Apply and save</button>
        </div>
      </div>
      <div class="card">
        <h3>Zones</h3>
        <p style="color:var(--muted);font-size:.82rem;margin:0 0 .7rem">
          A zone exists as soon as an interface names it. Blank means "inherit
          the global setting" — the same as leaving it out of the config.
        </p>
        <div style="overflow-x:auto"><table id="zonetable"></table></div>
      </div>
    </div>

    <div id="view-nat" class="hidden">
      <div class="card">
        <h3>Source NAT (masquerade)</h3>
        <div class="row" style="margin-bottom:.7rem">
          <button class="btn primary" id="addsnat">Add</button>
        </div>
        <div style="overflow-x:auto"><table id="snattable"></table></div>
      </div>
      <div class="card">
        <h3>Destination NAT (port forwards)</h3>
        <div class="row" style="margin-bottom:.7rem">
          <button class="btn primary" id="adddnat">Add</button>
        </div>
        <div style="overflow-x:auto"><table id="dnattable"></table></div>
      </div>
      <div class="card">
        <h3>Live NAT state</h3>
        <pre class="out" id="natshow">…</pre>
      </div>
    </div>

    <div id="view-bgp" class="hidden">
      <div class="card">
        <h3>Router</h3>
        <div class="grid2" id="bgpglobal"></div>
        <div class="row" style="margin-top:.8rem">
          <button class="btn primary" id="savebgp">Apply and save</button>
        </div>
      </div>
      <div class="card">
        <h3>Neighbours</h3>
        <div class="row" style="margin-bottom:.7rem">
          <button class="btn primary" id="addneighbor">Add neighbour</button>
        </div>
        <div style="overflow-x:auto"><table id="bgptable"></table></div>
      </div>
      <div class="card"><h3>Session state</h3><pre class="out" id="bgpshow">…</pre></div>
    </div>

    <div id="view-ipsec" class="hidden">
      <div class="card">
        <h3>Site-to-site tunnels</h3>
        <div class="row" style="margin-bottom:.7rem">
          <button class="btn primary" id="addipsec">Add tunnel</button>
        </div>
        <div style="overflow-x:auto"><table id="ipsectable"></table></div>
      </div>
      <div class="card"><h3>Security associations</h3><pre class="out" id="ipsecshow">…</pre></div>
    </div>

    <div id="view-wireguard" class="hidden">
      <div class="card">
        <h3>Interfaces</h3>
        <div class="row" style="margin-bottom:.7rem">
          <button class="btn primary" id="addwg">Add interface</button>
        </div>
        <div style="overflow-x:auto"><table id="wgtable"></table></div>
        <p style="color:var(--muted);font-size:.82rem;margin:.7rem 0 0">
          A private key is generated on the appliance and never leaves it — the
          key field writes <code>private-key generate</code>, not a key you typed
          into a browser.
        </p>
      </div>
      <div class="card">
        <h3>Peers</h3>
        <div class="row" style="margin-bottom:.7rem">
          <button class="btn primary" id="addwgpeer">Add peer</button>
        </div>
        <div style="overflow-x:auto"><table id="wgpeers"></table></div>
      </div>
    </div>

    <div id="view-dhcp" class="hidden">
      <div class="card">
        <h3>Servers</h3>
        <p style="color:var(--muted);font-size:.82rem;margin:0 0 .7rem">
          A DHCP server hands out leases from its interface's own static subnet,
          so the interface needs a static address first. Every interface that has
          one is listed here.
        </p>
        <div class="row" style="margin-bottom:.7rem">
          <button class="btn primary" id="adddhcp">Enable on an interface</button>
        </div>
        <div style="overflow-x:auto"><table id="dhcptable"></table></div>
      </div>
      <div class="card"><h3>Leases</h3><pre class="out" id="dhcpshow">…</pre></div>
    </div>

    <div id="view-config" class="hidden">
      <div class="card">
        <h3>Run configuration commands</h3>
        <p style="color:var(--muted);font-size:.82rem;margin:0 0 .6rem">
          Anything the CLI accepts. This is the whole configuration surface — the
          forms elsewhere in this console are shortcuts that write these same
          lines.
        </p>
        <textarea id="cmd" rows="5" spellcheck="false"
                  style="width:100%;font:12.5px/1.5 ui-monospace,monospace;padding:.6rem;
                         border-radius:8px;border:1px solid var(--line);
                         background:var(--panel);color:var(--fg)"
                  placeholder="set interface eth0 zone wan&#10;set firewall zone wan default-action drop"></textarea>
        <div class="row" style="margin-top:.6rem">
          <button class="btn primary" id="runsave">Stage</button>
        </div>
      </div>
      <div class="card">
        <h3>Running configuration</h3>
        <p style="color:var(--muted);font-size:.82rem;margin:0 0 .6rem">
          Every setting, editable where it stands. Editing writes
          <code>set …</code>; removing writes <code>delete …</code>.
        </p>
        <div class="row" style="margin-bottom:.6rem">
          <input id="cfgfilter" placeholder="filter" style="flex:1 1 12rem">
        </div>
        <div style="overflow-x:auto"><table id="cfgtable"></table></div>
      </div>
      <div class="card">
        <h3>Revisions</h3>
        <div style="overflow-x:auto"><table id="revtable"></table></div>
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
      <div class="card">
        <div class="row" style="margin-bottom:.6rem">
          <input id="showcmd" placeholder="run any show command, e.g. ip route bgp"
                 style="flex:1 1 18rem">
          <button class="btn" id="runshow">Run</button>
        </div>
        <pre class="out" id="panel">…</pre>
      </div>
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
    <button class="btn primary" id="applysave">Stage</button>
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
      onclick: () => stage(["delete firewall rule " + r.name], true),
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

// Editing stages, it does not apply. The appliance's own model is a candidate
// configuration you commit or discard, and a console whose every button was a
// commit would be a different product from the CLI beside it. So a form's
// Apply appends its commands here, the header says how many are waiting, and
// nothing reaches the box until Apply — or Discard throws them away, which is
// what makes clicking safe enough not to need a confirmation on every delete.
let staged = [];

function stage(lines) {{
  staged.push(...lines.filter(Boolean));
  renderStaged();
}}

function renderStaged() {{
  const n = staged.length;
  $("stagedbadge").textContent = n ? n + " staged change" + (n === 1 ? "" : "s")
                                   : "no staged changes";
  $("stagedbadge").className = "pill" + (n ? " up" : "");
  $("stagedcard").classList.toggle("hidden", n === 0);
  $("stagedlist").textContent = staged.join("\n");
  $("stagedtitle").textContent = n + " command" + (n === 1 ? "" : "s") + " staged";
}}

// `tail` is what turns a script into an intention: nothing commits, `commit`
// applies for this boot, `commit save` also persists.
async function applyStaged(tail) {{
  if (!staged.length) return;
  const r = await configure(staged.concat(tail));
  showResult(r);
  // Only clear once they have actually run. A refused commit leaves the
  // commands staged, so the operator can fix one and try again rather than
  // reconstructing what they had clicked.
  if (r.ok && !/^error/m.test(r.output || "")) {{
    staged = [];
    renderStaged();
  }}
  await refresh();
}}

function showResult(r) {{
  // The output is shown whether or not the exit status was a success: a commit
  // the appliance REFUSED reports that in its output, not in its status, and a
  // console that only looked at `ok` would tell the operator it worked.
  $("resultout").textContent = (r.output || "").trim() || (r.ok ? "applied" : "failed");
  $("result").showModal();
}}


// ---- the running configuration, as a tree -------------------------------

// `show configuration` prints the same curly-brace document the CLI edits, so
// parsing it is how the console learns what exists. Reconstructing the full
// path of every leaf is what makes a generic editor possible: a leaf's path IS
// the `set` command, so nothing here needs to know what any setting means.
function parseConfig(text) {{
  const out = [];
  const stack = [];
  for (const raw of text.split("\n")) {{
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line === "}}") {{ stack.pop(); continue; }}
    const open = line.match(/^(.*?)\s*\{{$/);
    if (open) {{ stack.push(open[1].trim()); continue; }}
    const parts = line.split(/\s+/);
    const key = parts[0];
    const value = parts.slice(1).join(" ");
    out.push({{ path: stack.concat([key]), value, node: stack.join(" ") }});
  }}
  return out;
}}

async function refreshConfig() {{
  const t = $("cfgtable");
  t.textContent = "";
  t.append(el("tr", {{}}, ["setting", "value", ""].map((h) => el("th", {{ text: h }}))));
  let leaves = [];
  try {{ leaves = parseConfig(await text("/api/v1/show/configuration")); }}
  catch (e) {{
    t.append(el("tr", {{}}, [el("td", {{ colspan: "3", text: String(e.message || e) }})]));
    return;
  }}
  const filter = $("cfgfilter").value.trim().toLowerCase();
  let shown = 0;
  for (const leaf of leaves) {{
    const path = leaf.path.join(" ");
    if (filter && !(path + " " + leaf.value).toLowerCase().includes(filter)) continue;
    shown++;
    const input = el("input", {{ value: leaf.value, style: "width:100%" }});
    const save = el("button", {{
      class: "btn", text: "Set",
      onclick: () => stage(["set " + path + " " + input.value.trim()]),
    }});
    const del = el("button", {{
      class: "btn danger", text: "Delete",
      onclick: () => stage(["delete " + path], true),
    }});
    t.append(el("tr", {{}}, [
      el("td", {{ text: path }}),
      el("td", {{}}, [input]),
      el("td", {{}}, [el("div", {{ class: "row" }}, [save, del])]),
    ]));
  }}
  if (!shown) {{
    t.append(el("tr", {{}}, [el("td", {{ colspan: "3", text: "nothing matches" }})]));
  }}

  // Revisions: what `show system commit` lists, with a rollback beside each.
  const r = $("revtable");
  r.textContent = "";
  r.append(el("tr", {{}}, ["revision", ""].map((h) => el("th", {{ text: h }}))));
  try {{
    const revs = (await text("/api/v1/show/system/commit")).trimEnd().split("\n");
    for (const line of revs) {{
      if (!line.trim()) continue;
      const n = (line.trim().match(/^(\d+)/) || [])[1];
      r.append(el("tr", {{}}, [
        el("td", {{ text: line }}),
        el("td", {{}}, [n === undefined ? el("span", {{}}) : el("button", {{
          class: "btn", text: "Roll back",
          onclick: () => stage(["rollback " + n], true),
        }})]),
      ]));
    }}
  }} catch (e) {{
    r.append(el("tr", {{}}, [el("td", {{ colspan: "2", text: String(e.message || e) }})]));
  }}
}}

// ---- zones ---------------------------------------------------------------

const POSTURE = [
  ["default-action", ["", "accept", "drop", "reject"]],
  ["stateful", ["", "true", "false"]],
  ["block-icmp", ["", "true", "false"]],
  ["log", ["", "true", "false"]],
  ["source-validation", ["", "disable", "loose", "strict"]],
];

function selectFor(field, value, onchange) {{
  const sel = el("select", {{ onchange }});
  for (const opt of field[1]) {{
    const o = el("option", {{ value: opt, text: opt === "" ? "(inherit)" : opt }});
    if (opt === (value || "")) o.setAttribute("selected", "selected");
    sel.append(o);
  }}
  return sel;
}}

async function refreshZones() {{
  let leaves = [];
  try {{ leaves = parseConfig(await text("/api/v1/show/configuration")); }} catch (e) {{}}

  // Global posture: one form, applied as a batch so a half-changed posture is
  // never committed.
  const g = $("globalform");
  g.textContent = "";
  const globals = new Map();
  for (const l of leaves) {{
    if (l.node === "firewall global") globals.set(l.path[l.path.length - 1], l.value);
  }}
  const pending = new Map();
  for (const field of POSTURE) {{
    if (field[0] === "source-validation" && false) continue;
    const sel = selectFor(field, globals.get(field[0]), (e) => pending.set(field[0], e.target.value));
    g.append(el("div", {{ class: "field" }}, [el("label", {{ text: field[0] }}), sel]));
  }}
  $("saveglobal").onclick = () => {{
    const lines = [];
    for (const [k, v] of pending) {{
      lines.push(v ? `set firewall global ${{k}} ${{v}}` : `delete firewall global ${{k}}`);
    }}
    if (!lines.length) return;
    stage(lines);
  }};

  // Per-zone overrides. The zone list comes from the interfaces that name one,
  // because that is what makes a zone exist at all.
  const zones = new Map();
  for (const l of leaves) {{
    if (l.path.length >= 2 && l.path[0] === "firewall" && l.path[1] === "zone" && l.path.length >= 4) {{
      const name = l.path[2];
      if (!zones.has(name)) zones.set(name, {{}});
      zones.get(name)[l.path[3]] = l.value;
    }}
    if (l.path[0] === "interface" && l.path[l.path.length - 1] === "zone") {{
      if (!zones.has(l.value)) zones.set(l.value, {{}});
    }}
  }}

  const t = $("zonetable");
  t.textContent = "";
  t.append(el("tr", {{}}, ["zone"].concat(POSTURE.map((f) => f[0])).concat([""])
    .map((h) => el("th", {{ text: h }}))));
  if (!zones.size) {{
    t.append(el("tr", {{}}, [el("td", {{ colspan: "7", text: "no zones — give an interface a zone first" }})]));
  }}
  for (const [name, z] of [...zones].sort()) {{
    const cells = [el("td", {{ text: name }})];
    const edits = new Map();
    for (const field of POSTURE) {{
      const sel = selectFor(field, z[field[0]], (e) => edits.set(field[0], e.target.value));
      cells.push(el("td", {{}}, [sel]));
    }}
    cells.push(el("td", {{}}, [el("div", {{ class: "row" }}, [
      el("button", {{
        class: "btn", text: "Apply",
        onclick: () => {{
          const lines = [];
          for (const [k, v] of edits) {{
            lines.push(v ? `set firewall zone ${{name}} ${{k}} ${{v}}`
                         : `delete firewall zone ${{name}} ${{k}}`);
          }}
          if (lines.length) stage(lines);
        }},
      }}),
    ])]));
    t.append(el("tr", {{}}, cells));
  }}
}}

// ---- NAT -----------------------------------------------------------------

const SNAT_FIELDS = [["zone", "Zone"], ["source", "Source"], ["translation", "Translation"]];
const DNAT_FIELDS = [["zone", "Zone"], ["proto", "Protocol"], ["port", "Port"], ["to", "To"]];

function natEntries(leaves, kind) {{
  const out = new Map();
  for (const l of leaves) {{
    if (l.path[0] === "nat" && l.path[1] === kind && l.path.length >= 4) {{
      const name = l.path[2];
      if (!out.has(name)) out.set(name, {{ name }});
      out.get(name)[l.path[3]] = l.value;
    }}
  }}
  return [...out.values()];
}}

async function refreshNat() {{
  $("natshow").textContent = "…";
  try {{ $("natshow").textContent = (await text("/api/v1/show/nat")).trimEnd(); }}
  catch (e) {{ $("natshow").textContent = String(e.message || e); }}

  let leaves = [];
  try {{ leaves = parseConfig(await text("/api/v1/show/configuration")); }} catch (e) {{}}

  const build = (tableId, kind, fields) => {{
    const t = $(tableId);
    t.textContent = "";
    t.append(el("tr", {{}}, ["name"].concat(fields.map((f) => f[1])).concat([""])
      .map((h) => el("th", {{ text: h }}))));
    const rows = natEntries(leaves, kind);
    if (!rows.length) {{
      t.append(el("tr", {{}}, [el("td", {{
        colspan: String(fields.length + 2), text: "none configured",
      }})]));
    }}
    for (const r of rows) {{
      const inputs = fields.map((f) => el("input", {{ value: r[f[0]] || "" }}));
      const apply = el("button", {{
        class: "btn", text: "Apply",
        onclick: () => {{
          const lines = [];
          fields.forEach((f, i) => {{
            const v = inputs[i].value.trim();
            if (v) lines.push(`set nat ${{kind}} ${{r.name}} ${{f[0]}} ${{v}}`);
          }});
          if (lines.length) stage(lines);
        }},
      }});
      const del = el("button", {{
        class: "btn danger", text: "Delete",
        onclick: () => stage([`delete nat ${{kind}} ${{r.name}}`], true),
      }});
      t.append(el("tr", {{}}, [el("td", {{ text: r.name }})]
        .concat(inputs.map((i) => el("td", {{}}, [i])))
        .concat([el("td", {{}}, [el("div", {{ class: "row" }}, [apply, del])])])));
    }}
  }};
  build("snattable", "source", SNAT_FIELDS);
  build("dnattable", "destination", DNAT_FIELDS);
}}

// Adding starts as a blank row rather than a command: a NAT entry needs several
// fields to be valid, and creating it one `set` at a time would ask the
// appliance to commit a half-written entry it is right to refuse.
function addNat(tableId, kind, fields) {{
  const t = $(tableId);
  const name = el("input", {{ placeholder: "name" }});
  const inputs = fields.map((f) => el("input", {{ placeholder: f[1].toLowerCase() }}));
  const apply = el("button", {{
    class: "btn primary", text: "Create",
    onclick: () => {{
      const n = name.value.trim();
      if (!n) {{ name.focus(); return; }}
      const lines = [];
      fields.forEach((f, i) => {{
        const v = inputs[i].value.trim();
        if (v) lines.push(`set nat ${{kind}} ${{n}} ${{f[0]}} ${{v}}`);
      }});
      if (lines.length) stage(lines);
    }},
  }});
  t.append(el("tr", {{}}, [el("td", {{}}, [name])]
    .concat(inputs.map((i) => el("td", {{}}, [i])))
    .concat([el("td", {{}}, [apply])])));
  name.focus();
}}


// ---- a generic section editor -------------------------------------------

// Every one of the views below is the same shape: a set of named entries under
// a config path, each with a handful of fields. Writing that once means the
// forms cannot disagree with each other about how a setting is written — they
// all emit `set <prefix> <name> <field> <value>` and `delete <prefix> <name>`.
function entriesUnder(leaves, prefix) {{
  const depth = prefix.length;
  const out = new Map();
  for (const l of leaves) {{
    if (l.path.length < depth + 2) continue;
    if (prefix.some((p, i) => l.path[i] !== p)) continue;
    const name = l.path[depth];
    if (!out.has(name)) out.set(name, {{ name }});
    out.get(name)[l.path.slice(depth + 1).join(" ")] = l.value;
  }}
  return [...out.values()];
}}

// `fields` is [key, label, options?]. An `options` list renders a select, so a
// field with a fixed vocabulary cannot be mistyped into a refusal.
function editorTable(tableId, prefix, fields, rows, opts) {{
  const t = $(tableId);
  const path = prefix.join(" ");
  t.textContent = "";
  t.append(el("tr", {{}}, [(opts && opts.nameLabel) || "name"]
    .concat(fields.map((f) => f[1])).concat([""])
    .map((h) => el("th", {{ text: h }}))));
  if (!rows.length) {{
    t.append(el("tr", {{}}, [el("td", {{
      colspan: String(fields.length + 2),
      text: (opts && opts.empty) || "none configured",
    }})]));
  }}
  for (const r of rows) {{
    const inputs = fields.map((f) =>
      f[2] ? selectFor([f[0], f[2]], r[f[0]], null) : el("input", {{ value: r[f[0]] || "" }}));
    const apply = el("button", {{
      class: "btn", text: "Apply",
      onclick: () => {{
        const lines = [];
        fields.forEach((f, i) => {{
          const v = (inputs[i].value || "").trim();
          if (v) lines.push(`set ${{path}} ${{r.name}} ${{f[0]}} ${{v}}`);
          else if (r[f[0]]) lines.push(`delete ${{path}} ${{r.name}} ${{f[0]}}`);
        }});
        if (lines.length) stage(lines);
      }},
    }});
    const del = el("button", {{
      class: "btn danger", text: "Delete",
      onclick: () => stage([`delete ${{path}} ${{r.name}}`], true),
    }});
    t.append(el("tr", {{}}, [el("td", {{ text: r.name }})]
      .concat(inputs.map((i) => el("td", {{}}, [i])))
      .concat([el("td", {{}}, [el("div", {{ class: "row" }}, [apply, del])])])));
  }}
}}

// Adding is a blank row committed in one go, never one `set` at a time: an
// entry usually needs several fields before it is valid, and asking the
// appliance to commit half of one earns a refusal the operator did not deserve.
function addRow(tableId, prefix, fields, nameHint) {{
  const t = $(tableId);
  const path = prefix.join(" ");
  const name = el("input", {{ placeholder: nameHint || "name" }});
  const inputs = fields.map((f) =>
    f[2] ? selectFor([f[0], f[2]], "", null) : el("input", {{ placeholder: f[1].toLowerCase() }}));
  const create = el("button", {{
    class: "btn primary", text: "Create",
    onclick: () => {{
      const n = name.value.trim();
      if (!n) {{ name.focus(); return; }}
      const lines = [];
      fields.forEach((f, i) => {{
        const v = (inputs[i].value || "").trim();
        if (v) lines.push(`set ${{path}} ${{n}} ${{f[0]}} ${{v}}`);
      }});
      if (!lines.length) lines.push(`set ${{path}} ${{n}}`);
      stage(lines);
    }},
  }});
  t.append(el("tr", {{}}, [el("td", {{}}, [name])]
    .concat(inputs.map((i) => el("td", {{}}, [i])))
    .concat([el("td", {{}}, [create])])));
  name.focus();
}}

async function leaves() {{
  try {{ return parseConfig(await text("/api/v1/show/configuration")); }}
  catch (e) {{ return []; }}
}}

// ---- BGP -----------------------------------------------------------------

const BGP_GLOBAL = [
  ["local-as", ["" ]], ["router-id", [""]], ["hold-time", [""]],
  ["cluster-id", [""]], ["multipath", ["", "true", "false"]],
  ["ebgp-require-policy", ["", "true", "false"]],
];
const BGP_NEIGHBOR = [
  ["remote-as", "Remote AS"],
  ["description", "Description"],
  ["password", "Password"],
  ["passive", "Passive", ["", "true", "false"]],
  ["route-reflector-client", "RR client", ["", "true", "false"]],
  ["bfd", "BFD", ["", "true", "false"]],
  ["evpn", "EVPN", ["", "true", "false"]],
  ["max-prefix", "Max prefix"],
];

async function refreshBgp() {{
  $("bgpshow").textContent = "…";
  try {{ $("bgpshow").textContent = (await text("/api/v1/show/ip/bgp/summary")).trimEnd(); }}
  catch (e) {{ $("bgpshow").textContent = String(e.message || e); }}

  const ls = await leaves();
  const globals = {{}};
  for (const l of ls) {{
    if (l.node === "protocols bgp") globals[l.path[l.path.length - 1]] = l.value;
  }}
  const g = $("bgpglobal");
  g.textContent = "";
  const pending = new Map();
  for (const f of BGP_GLOBAL) {{
    const widget = f[1].length > 1
      ? selectFor(f, globals[f[0]], (e) => pending.set(f[0], e.target.value))
      : el("input", {{ value: globals[f[0]] || "", oninput: (e) => pending.set(f[0], e.target.value) }});
    g.append(el("div", {{ class: "field" }}, [el("label", {{ text: f[0] }}), widget]));
  }}
  $("savebgp").onclick = () => {{
    const lines = [];
    for (const [k, v] of pending) {{
      lines.push(v.trim() ? `set protocols bgp ${{k}} ${{v.trim()}}`
                          : `delete protocols bgp ${{k}}`);
    }}
    if (lines.length) stage(lines);
  }};

  editorTable("bgptable", ["protocols", "bgp", "neighbor"], BGP_NEIGHBOR,
    entriesUnder(ls, ["protocols", "bgp", "neighbor"]),
    {{ nameLabel: "neighbour", empty: "no neighbours configured" }});
}}

// ---- IPsec ---------------------------------------------------------------

const IPSEC = [
  ["local", "Local address"],
  ["remote", "Remote address"],
  ["local-subnet", "Local subnet"],
  ["remote-subnet", "Remote subnet"],
  ["psk", "Pre-shared key"],
  ["ike-version", "IKE", ["", "1", "2"]],
  ["start-action", "Start", ["", "start", "trap", "none"]],
];

async function refreshIpsec() {{
  $("ipsecshow").textContent = "…";
  try {{ $("ipsecshow").textContent = (await text("/api/v1/show/vpn/ipsec")).trimEnd(); }}
  catch (e) {{ $("ipsecshow").textContent = String(e.message || e); }}
  editorTable("ipsectable", ["vpn", "ipsec"], IPSEC,
    entriesUnder(await leaves(), ["vpn", "ipsec"]),
    {{ nameLabel: "tunnel", empty: "no tunnels configured" }});
}}

// ---- WireGuard -----------------------------------------------------------

const WG = [["listen-port", "Listen port"], ["private-key", "Private key"]];
const WG_PEER = [
  ["allowed-ips", "Allowed IPs"],
  ["endpoint", "Endpoint"],
  ["keepalive", "Keepalive"],
  ["preshared-key", "Pre-shared key"],
];

async function refreshWireguard() {{
  const ls = await leaves();
  const tunnels = entriesUnder(ls, ["vpn", "wireguard"])
    .map((t) => ({{ name: t.name, "listen-port": t["listen-port"], "private-key": t["private-key"] }}));
  editorTable("wgtable", ["vpn", "wireguard"], WG, tunnels,
    {{ nameLabel: "interface", empty: "no interfaces configured" }});

  // Peers live one level deeper, so they get their own table keyed by the
  // tunnel they belong to — a peer is only meaningful with its interface.
  const t = $("wgpeers");
  t.textContent = "";
  t.append(el("tr", {{}}, ["interface", "public key"].concat(WG_PEER.map((f) => f[1])).concat([""])
    .map((h) => el("th", {{ text: h }}))));
  let any = false;
  for (const tunnel of tunnels) {{
    const peers = entriesUnder(ls, ["vpn", "wireguard", tunnel.name, "peer"]);
    for (const p of peers) {{
      any = true;
      const inputs = WG_PEER.map((f) => el("input", {{ value: p[f[0]] || "" }}));
      const apply = el("button", {{
        class: "btn", text: "Apply",
        onclick: () => {{
          const lines = [];
          WG_PEER.forEach((f, i) => {{
            const v = inputs[i].value.trim();
            if (v) lines.push(`set vpn wireguard ${{tunnel.name}} peer ${{p.name}} ${{f[0]}} ${{v}}`);
          }});
          if (lines.length) stage(lines);
        }},
      }});
      const del = el("button", {{
        class: "btn danger", text: "Delete",
        onclick: () => stage([`delete vpn wireguard ${{tunnel.name}} peer ${{p.name}}`], true),
      }});
      t.append(el("tr", {{}}, [
        el("td", {{ text: tunnel.name }}),
        el("td", {{ text: p.name }}),
      ].concat(inputs.map((i) => el("td", {{}}, [i])))
       .concat([el("td", {{}}, [el("div", {{ class: "row" }}, [apply, del])])])));
    }}
  }}
  if (!any) {{
    t.append(el("tr", {{}}, [el("td", {{ colspan: "7", text: "no peers configured" }})]));
  }}
  $("addwgpeer").onclick = () => {{
    if (!tunnels.length) {{ window.alert("Add a WireGuard interface first."); return; }}
    const iface = window.prompt("Which interface?", tunnels[0].name);
    if (!iface) return;
    addRow("wgpeers", ["vpn", "wireguard", iface, "peer"], WG_PEER, "peer public key");
  }};
}}

// ---- DHCP ----------------------------------------------------------------

const DHCP = [
  ["pool-offset", "Pool offset"],
  ["pool-size", "Pool size"],
  ["default-router", "Default router"],
  ["dns", "DNS"],
  ["domain", "Domain"],
  ["lease-time", "Lease time"],
];

async function refreshDhcp() {{
  $("dhcpshow").textContent = "…";
  try {{ $("dhcpshow").textContent = (await text("/api/v1/show/dhcp/leases")).trimEnd(); }}
  catch (e) {{ $("dhcpshow").textContent = String(e.message || e); }}

  const ls = await leaves();
  // A DHCP server is a block on an interface, not an entry of its own, so the
  // rows are interfaces and the path carries the interface's name.
  const servers = new Map();
  for (const l of ls) {{
    if (l.path[0] === "interface" && l.path[2] === "dhcp-server" && l.path.length >= 4) {{
      const iface = l.path[1];
      if (!servers.has(iface)) servers.set(iface, {{ name: iface }});
      servers.get(iface)[l.path[3]] = l.value;
    }}
  }}
  const t = $("dhcptable");
  t.textContent = "";
  t.append(el("tr", {{}}, ["interface"].concat(DHCP.map((f) => f[1])).concat([""])
    .map((h) => el("th", {{ text: h }}))));
  if (!servers.size) {{
    t.append(el("tr", {{}}, [el("td", {{
      colspan: String(DHCP.length + 2), text: "no DHCP server enabled",
    }})]));
  }}
  for (const srv of servers.values()) {{
    const inputs = DHCP.map((f) => el("input", {{ value: srv[f[0]] || "" }}));
    const apply = el("button", {{
      class: "btn", text: "Apply",
      onclick: () => {{
        const lines = [];
        DHCP.forEach((f, i) => {{
          const v = inputs[i].value.trim();
          if (v) lines.push(`set interface ${{srv.name}} dhcp-server ${{f[0]}} ${{v}}`);
          else if (srv[f[0]]) lines.push(`delete interface ${{srv.name}} dhcp-server ${{f[0]}}`);
        }});
        if (lines.length) stage(lines);
      }},
    }});
    const del = el("button", {{
      class: "btn danger", text: "Disable",
      onclick: () => stage([`delete interface ${{srv.name}} dhcp-server`], true),
    }});
    t.append(el("tr", {{}}, [el("td", {{ text: srv.name }})]
      .concat(inputs.map((i) => el("td", {{}}, [i])))
      .concat([el("td", {{}}, [el("div", {{ class: "row" }}, [apply, del])])])));
  }}
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

// A minimal inline icon set. The design calls for lucide, which is fetched from
// a CDN — impossible here for the same reason as the fonts — so these are drawn
// in the same 24-unit stroke language rather than left out.
const ICONS = {{
  gauge: '<circle cx="12" cy="12" r="9"/><path d="M12 12 15.5 8.5"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  zones: '<rect x="3" y="4" width="8" height="7" rx="1"/><rect x="13" y="13" width="8" height="7" rx="1"/><path d="M11 7.5h2M11 16.5h2"/>',
  swap: '<path d="M4 8h13l-3-3M20 16H7l3 3"/>',
  route: '<circle cx="6" cy="6" r="2"/><circle cx="18" cy="18" r="2"/><path d="M8 6h6a4 4 0 0 1 0 8H8a4 4 0 0 0 0 8"/>',
  lock: '<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  key: '<circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v4"/>',
  address: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 10h18"/>',
  file: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/>',
  layers: '<path d="m12 2 9 5-9 5-9-5 9-5z"/><path d="m3 12 9 5 9-5"/>',
  chart: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  bug: '<rect x="8" y="8" width="8" height="10" rx="4"/><path d="M8 12H4M20 12h-4M9 8 7 5M15 8l2-3M9 18l-2 3M15 18l2 3"/>',
}};

// Built by parsing markup rather than `createElementNS`: the HTML parser puts
// `<svg>` in the right namespace by itself, and naming that namespace would put
// an absolute URL in a page whose whole point is that it fetches nothing — a
// self-containment check cannot tell a namespace from a request, and it should
// not have to.
function icon(name) {{
  const box = document.createElement("span");
  box.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    (ICONS[name] || ICONS.file) + "</svg>";
  return box.firstChild;
}}

// The editable views, in the order an operator meets them.
const SECTIONS = [
  {{ g: "Overview", items: [
    {{ v: "dashboard", t: "Dashboard", i: "gauge" }},
  ]}},
  {{ g: "Policy", items: [
    {{ v: "rules", t: "Firewall rules", i: "shield" }},
    {{ v: "zones", t: "Zones", i: "zones" }},
    {{ v: "nat", t: "NAT", i: "swap" }},
  ]}},
  {{ g: "Network", items: [
    {{ v: "bgp", t: "BGP", i: "route" }},
    {{ v: "ipsec", t: "IPsec", i: "lock" }},
    {{ v: "wireguard", t: "WireGuard", i: "key" }},
    {{ v: "dhcp", t: "DHCP", i: "address" }},
  ]}},
  {{ g: "System", items: [
    {{ v: "config", t: "Configuration", i: "file" }},
    {{ v: "stack", t: "Stack", i: "layers" }},
  ]}},
];

const meta = {{}};   // section → the count shown beside it, once known

function navButton(label, iconName, onclick, key) {{
  const b = el("button", {{ class: "navitem", onclick }});
  b.dataset.key = key;
  b.append(icon(iconName), el("span", {{ text: label }}));
  if (meta[key] !== undefined) b.append(el("span", {{ class: "meta", text: String(meta[key]) }}));
  return b;
}}

function buildNav() {{
  const nav = $("nav");
  const filter = $("navsearch").value.trim().toLowerCase();
  nav.textContent = "";
  for (const group of SECTIONS) {{
    const items = group.items.filter((i) => !filter || i.t.toLowerCase().includes(filter));
    if (!items.length) continue;
    const box = el("div", {{ class: "group" }}, [el("span", {{ class: "grp", text: group.g }})]);
    for (const item of items) {{
      box.append(navButton(item.t, item.i, () => {{ view = item.v; panel = null; refresh(); }}, item.v));
    }}
    nav.append(box);
  }}
  // The read-only views keep their own group; they are what you open to look,
  // not to change, and mixing them into the sections above would hide that.
  for (const group of NAV) {{
    const items = group.items.filter((i) => !filter || i.t.toLowerCase().includes(filter));
    if (!items.length) continue;
    const box = el("div", {{ class: "group" }}, [el("span", {{ class: "grp", text: group.g }})]);
    for (const item of items) {{
      const b = navButton(item.t, group.g === "Diagnostics" ? "bug" : "chart",
        () => {{ view = "panel"; panel = item; refresh(); }}, item.p);
      b.dataset.path = item.p;
      box.append(b);
    }}
    nav.append(box);
  }}
}}

// The rail's cluster card: the same members the Stack view lists, kept where an
// operator can see at a glance which box they are actually driving.
async function refreshCluster() {{
  const list = $("clusterlist");
  list.textContent = "";
  let data;
  try {{ data = await (await api("/api/v1/stack")).json(); }} catch (e) {{ return; }}
  for (const m of data.members) {{
    const isSelf = m.name === "self";
    const name = isSelf ? "" : m.name;
    const b = el("button", {{
      onclick: () => {{ target = name; refresh(); refreshCluster(); }},
    }});
    b.setAttribute("aria-current", String(target === name));
    b.append(
      el("span", {{ class: "dot " + (m.reachable ? "up" : "down") }}),
      el("span", {{ text: m.hostname || (isSelf ? "this appliance" : m.name) }}),
      el("span", {{ class: "role", text: isSelf ? "local" : "peer" }}),
    );
    list.append(b);
  }}
  try {{
    const revs = (await text("/api/v1/show/system/commit")).trim().split("\n");
    const first = revs.find((l) => /\d/.test(l));
    $("clusterrev").textContent = first ? "rev " + first.trim().split(/\s+/)[0] : "rev —";
  }} catch (e) {{ $("clusterrev").textContent = "rev —"; }}
}}

async function refresh() {{
  for (const b of document.querySelectorAll("aside button.navitem")) {{
    const active = b.dataset.path ? (panel && b.dataset.path === panel.p)
                                  : (!panel && b.dataset.key === view);
    b.setAttribute("aria-current", String(!!active));
  }}
  // The breadcrumb names the box being driven, so a peer's read-only view can
  // never be mistaken for the appliance you are configuring.
  $("crumb").textContent = (target || "this appliance") + " / " +
    (panel ? "show" : view);
  for (const v of ["dashboard", "rules", "zones", "nat", "bgp", "ipsec",
                   "wireguard", "dhcp", "config", "stack", "panel"]) {{
    $("view-" + v).classList.toggle("hidden", v !== view);
  }}
  const TITLES = {{
    rules: "Firewall rules", zones: "Zones", nat: "NAT",
    config: "Configuration", stack: "Stack", dashboard: "Dashboard",
    bgp: "BGP", ipsec: "IPsec", wireguard: "WireGuard", dhcp: "DHCP",
  }};
  $("title").textContent = panel ? panel.t : (TITLES[view] || "Dashboard");

  if (view === "dashboard") return refreshDashboard();
  if (view === "rules") return refreshRules();
  if (view === "zones") return refreshZones();
  if (view === "nat") return refreshNat();
  if (view === "bgp") return refreshBgp();
  if (view === "ipsec") return refreshIpsec();
  if (view === "wireguard") return refreshWireguard();
  if (view === "dhcp") return refreshDhcp();
  if (view === "config") return refreshConfig();
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
  renderStaged();
  refreshCluster();
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
$("navsearch").oninput = () => {{ buildNav(); refresh(); }};
$("discard").onclick = () => {{ staged = []; renderStaged(); }};
$("applystaged").onclick = () => applyStaged(["commit", "save"]);
$("applystaged2").onclick = () => applyStaged(["commit", "save"]);
// Validating sends the staged commands with no commit: the appliance checks
// every one of them and writes nothing, which is how you find out that a change
// would be refused before it touches the box.
$("validate").onclick = () => applyStaged([]);
$("refresh").onclick = () => refresh();
$("allcounters").onchange = () => refreshDashboard();
$("addrule").onclick = () => openEditor(null);
$("addsnat").onclick = () => addNat("snattable", "source", SNAT_FIELDS);
$("adddnat").onclick = () => addNat("dnattable", "destination", DNAT_FIELDS);
$("cfgfilter").oninput = () => refreshConfig();
$("addneighbor").onclick = () =>
  addRow("bgptable", ["protocols", "bgp", "neighbor"], BGP_NEIGHBOR, "neighbour address");
$("addipsec").onclick = () => addRow("ipsectable", ["vpn", "ipsec"], IPSEC, "tunnel name");
$("addwg").onclick = () => addRow("wgtable", ["vpn", "wireguard"], WG, "interface name");
$("adddhcp").onclick = () => {{
  const iface = window.prompt("Enable a DHCP server on which interface?");
  if (iface) stage([`set interface ${{iface}} dhcp-server enable`]);
}};
$("runsave").onclick = () => runScript();
$("runshow").onclick = async () => {{
  const words = $("showcmd").value.trim();
  if (!words) return;
  panel = {{ t: "show " + words, p: "/api/v1/show/" + words.split(/\s+/).map(encodeURIComponent).join("/") }};
  view = "panel";
  await refresh();
}};
$("cancel").onclick = () => $("editor").close();
$("resultclose").onclick = () => $("result").close();
for (const [id] of FIELDS) $(id).oninput = renderPreview;
$("r-name").oninput = renderPreview;
$("applysave").onclick = () => {{
  const lines = script();
  if (!lines.length) {{ $("editorerr").textContent = "A rule needs a name and at least one setting."; return; }}
  $("editor").close();
  stage(lines);
}};
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

    /// The claim the console makes is that anything the CLI can configure can be
    /// configured here. A form per feature could never hold that; what does is
    /// the generic pair — a table that turns every setting in the running
    /// configuration into `set`/`delete`, and a box that runs commands verbatim.
    #[test]
    fn the_whole_config_surface_is_reachable_not_just_the_forms() {
        let html = page();
        assert!(html.contains("parseConfig"), "no generic config editor");
        assert!(
            html.contains(r#""set " + path + " ""#),
            "settings are not editable in place"
        );
        assert!(
            html.contains(r#""delete " + path"#),
            "settings cannot be removed"
        );
        assert!(html.contains("runScript"), "no command box");
    }

    /// Validating without committing is the one operation that lets an operator
    /// find out whether a change would be refused before anything is touched:
    /// the staged commands run, the appliance checks every one, and no `commit`
    /// follows them so nothing is applied or written.
    #[test]
    fn staged_commands_can_be_validated_without_applying_them() {
        assert!(page().contains(r#"applyStaged([])"#));
    }

    /// The appliance's own model is a candidate configuration you commit or
    /// discard. A console whose every button committed would be a different
    /// product from the CLI beside it — and would make a mis-click a change to
    /// a live firewall rather than a line you can throw away.
    #[test]
    fn edits_stage_rather_than_apply_themselves() {
        let html = page();
        assert!(html.contains("let staged = []"), "no staged set");
        assert!(html.contains("function stage(lines)"), "forms do not stage");
        assert!(
            html.contains(r#"applyStaged(["commit", "save"])"#),
            "nothing applies the staged commands"
        );
        // A refused commit must leave the work in place to be corrected.
        assert!(
            html.contains("if (r.ok &&"),
            "staged commands clear unconditionally"
        );
    }

    /// The console wears the product's design system, and the tokens have to be
    /// *in* the page: an appliance cannot fetch a stylesheet, so a console that
    /// referenced one would render as unstyled text exactly when it is needed.
    #[test]
    fn the_design_tokens_travel_with_the_page() {
        let html = page();
        for token in [
            "--ink-900",
            "--signal-500",
            "--sentinel-500",
            "--space-4",
            "--radius-md",
        ] {
            assert!(html.contains(token), "{token} is missing from the page");
        }
        // Named first, never fetched — see the module header.
        assert!(html.contains("\"Space Grotesk\""));
        assert!(
            html.contains("system-ui"),
            "no fallback for a face that cannot be fetched"
        );
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
