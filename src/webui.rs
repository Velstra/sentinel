//! C12 — the **web console**.
//!
//! The third face of the same appliance, beside the CLI and the REST API. It
//! invents no endpoint and holds no state of its own: every panel is a `show`
//! the CLI also prints, and every change is the *same command* an operator would
//! type, sent to `POST /api/v1/configure`.
//!
//! ## Operated, not typed into
//!
//! Every control here is a native one — a select over the zones that exist, an
//! action badge, a labelled field — and there is no command box, no command
//! preview and no raw-path editor. An operator configures the appliance by
//! working the objects it has.
//!
//! Underneath, a change still reaches the box as the commands the CLI accepts.
//! That is not a shortcut: it is what puts a clicked edit through the same
//! parser, the same validators, the same refusals and the same commit warnings
//! as a typed one, and it is why the console can never do something the CLI
//! cannot. A form that assembled a configuration document instead would be a
//! second description of the config model, free to drift from the first.
//!
//! The pending panel therefore lists **what will change**, in words. The
//! commands are transport, and transport is not an interface.
//!
//! ## Staged, like the appliance itself
//!
//! Edits are a candidate, not a change: a form stages, the header counts, and
//! nothing reaches the box until Apply — or Discard drops it. That mirrors the
//! CLI's own candidate-and-commit model, and it is why deleting an object does
//! not ask for confirmation: a delete is a pending line you can still remove.
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

  /* --- object rows (the policy list) ------------------------------------- */
  .toolbar {{
    display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-3);
    margin-bottom: var(--space-4);
  }}
  .inline {{ display: flex; align-items: center; gap: var(--space-2); }}
  .inline > span {{ font-size: var(--text-sm); color: var(--text-muted); white-space: nowrap; }}
  .inline select {{ width: auto; }}

  .addpanel {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr));
    gap: var(--space-3); align-items: end; border-radius: 16px;
    /* The amber edge marks the one surface that is about to change something. */
    border-color: var(--sentinel-600);
  }}
  .addpanel .field span {{
    font: var(--fw-medium) var(--text-xs)/1.2 var(--font-sans); color: var(--text-muted);
    text-transform: none; letter-spacing: 0;
  }}

  .rule {{
    display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-4);
    padding: var(--space-4) var(--space-5); border-radius: 14px;
    background: var(--surface); border: 1px solid var(--border-subtle);
    margin-bottom: var(--space-2);
    transition: border-color var(--dur-fast, 130ms) ease;
  }}
  .rule:hover {{ border-color: var(--border-strong); }}
  .rule .col {{ display: flex; flex-direction: column; gap: 2px; min-width: 0; }}
  .rule .col.grow {{ flex: 1 1 200px; }}
  .eyebrow {{
    font: var(--fw-regular) var(--text-2xs)/1.2 var(--font-sans); color: var(--text-faint);
  }}
  .mono {{ font-family: var(--font-mono); font-size: var(--text-sm); color: var(--text-body); }}
  .mono.strong {{ color: var(--text-strong); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .sub {{ font-size: var(--text-2xs); color: var(--text-muted); }}

  /* The action is a badge because it changes what every other field means. */
  .act {{
    flex: none; padding: var(--space-1) var(--space-3); border-radius: var(--radius-pill);
    font: var(--fw-semibold) var(--text-2xs)/1.5 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
    border: 1px solid currentColor;
  }}
  .act.accept {{ color: var(--status-up); background: rgba(63,185,80,.1); }}
  .act.drop {{ color: var(--status-down); background: rgba(248,81,73,.1); }}
  .act.reject {{ color: var(--status-warn); background: rgba(255,176,32,.1); }}

  /* --- pending changes --------------------------------------------------- */
  .pill.warn {{ color: var(--status-warn); border-color: color-mix(in oklab, var(--status-warn) 45%, transparent); }}
  .dot.warn {{ background: var(--status-warn); box-shadow: 0 0 8px -1px var(--status-warn); }}
  .change {{
    display: flex; align-items: center; gap: var(--space-3);
    padding: var(--space-2) 0; border-bottom: 1px solid var(--border-subtle);
  }}
  .change:last-child {{ border-bottom: 0; }}
  .change .what {{ flex: 1 1 auto; font-size: var(--text-sm); color: var(--text-body); }}
  #stagedlist {{ background: none; border: 0; border-left: 0; padding: 0; white-space: normal; }}
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
    <div id="matches"></div>

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
      <div class="toolbar">
        <label class="inline">
          <span>Default policy</span>
          <select id="defaultpolicy">
            <option value="">(unchanged)</option>
            <option value="drop">drop</option>
            <option value="reject">reject</option>
            <option value="accept">accept</option>
          </select>
        </label>
        <span class="spacer"></span>
        <button class="btn" id="togglerule">New rule</button>
      </div>

      <div class="card addpanel hidden" id="addrulepanel">
        <label class="field"><span>Name</span><input id="n-name" placeholder="web-in"></label>
        <label class="field"><span>Action</span>
          <select id="n-action">
            <option value="accept">accept</option>
            <option value="drop">drop</option>
            <option value="reject">reject</option>
          </select>
        </label>
        <label class="field"><span>From zone</span><select id="n-from"></select></label>
        <label class="field"><span>To zone</span><select id="n-to"></select></label>
        <label class="field"><span>Protocol</span>
          <select id="n-proto">
            <option value="">(any)</option>
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
          </select>
        </label>
        <label class="field"><span>Port</span><input id="n-port" placeholder="443 or 8000-8100"></label>
        <label class="field"><span>Source</span><input id="n-source" placeholder="0.0.0.0/0"></label>
        <label class="field"><span>Destination</span><input id="n-dest" placeholder="10.20.0.0/24"></label>
        <button class="btn primary" id="createrule">Add rule</button>
      </div>

      <div id="rulelist"></div>
    </div>

    <div id="view-zones" class="hidden">
      <div class="card">
        <h3>Global posture</h3>
        <p style="color:var(--text-muted);font-size:var(--text-sm);margin:0 0 var(--space-3)">
          What every zone inherits. A zone leaving a field unset takes the value
          from here — the same thing as leaving it out of the config.
        </p>
        <div class="addpanel" id="globalform"></div>
      </div>
      <div id="zonelist"></div>
    </div>

    <div id="view-nat" class="hidden">
      <div class="toolbar">
        <span class="inline"><span>Source NAT</span></span>
        <span class="spacer"></span>
        <button class="btn" id="togglesnat">New source rule</button>
      </div>
      <div class="card addpanel hidden" id="addsnatpanel"></div>
      <div id="snatlist"></div>

      <div class="toolbar" style="margin-top:var(--space-6)">
        <span class="inline"><span>Destination NAT</span></span>
        <span class="spacer"></span>
        <button class="btn" id="toggleddnat">New port forward</button>
      </div>
      <div class="card addpanel hidden" id="adddnatpanel"></div>
      <div id="dnatlist"></div>

      <div class="card" style="margin-top:var(--space-6)">
        <h3>Live NAT state</h3><pre class="out" id="natshow">…</pre>
      </div>
    </div>

    <div id="view-bgp" class="hidden">
      <div class="card">
        <h3>Router</h3>
        <div class="addpanel" id="bgpglobal"></div>
      </div>
      <div class="toolbar">
        <span class="inline"><span>Neighbours</span></span>
        <span class="spacer"></span>
        <button class="btn" id="togglebgp">New neighbour</button>
      </div>
      <div class="card addpanel hidden" id="addbgppanel"></div>
      <div id="bgplist"></div>
      <div class="card" style="margin-top:var(--space-6)">
        <h3>Session state</h3><pre class="out" id="bgpshow">…</pre>
      </div>
    </div>

    <div id="view-ipsec" class="hidden">
      <div class="toolbar">
        <span class="inline"><span>Site-to-site tunnels</span></span>
        <span class="spacer"></span>
        <button class="btn" id="toggleipsec">New tunnel</button>
      </div>
      <div class="card addpanel hidden" id="addipsecpanel"></div>
      <div id="ipseclist"></div>
      <div class="card" style="margin-top:var(--space-6)">
        <h3>Security associations</h3><pre class="out" id="ipsecshow">…</pre>
      </div>
    </div>

    <div id="view-wireguard" class="hidden">
      <div class="toolbar">
        <span class="inline"><span>Interfaces</span></span>
        <span class="spacer"></span>
        <button class="btn" id="togglewg">New interface</button>
      </div>
      <div class="card addpanel hidden" id="addwgpanel"></div>
      <div id="wglist"></div>
      <p style="color:var(--text-muted);font-size:var(--text-sm);margin:var(--space-3) 0 var(--space-6)">
        A private key is generated on the appliance — set it to
        <code>generate</code> rather than pasting a key into a browser.
      </p>

      <div class="toolbar">
        <span class="inline"><span>Peers</span></span>
        <span class="spacer"></span>
        <label class="inline"><span>on</span><select id="wgtunnel"></select></label>
        <button class="btn" id="togglewgpeer">New peer</button>
      </div>
      <div class="card addpanel hidden" id="addwgpeerpanel"></div>
      <div id="wgpeerlist"></div>
    </div>

    <div id="view-dhcp" class="hidden">
      <div class="toolbar">
        <span class="inline"><span>Servers</span></span>
        <span class="spacer"></span>
        <label class="inline"><span>on</span><select id="dhcpiface"></select></label>
        <button class="btn" id="enabledhcp">Enable</button>
      </div>
      <div id="dhcplist"></div>
      <p style="color:var(--text-muted);font-size:var(--text-sm);margin:var(--space-3) 0 var(--space-6)">
        A server leases from its interface's own static subnet, so the interface
        needs a static address first.
      </p>
      <div class="card"><h3>Leases</h3><pre class="out" id="dhcpshow">…</pre></div>
    </div>

    <div id="view-interfaces" class="hidden">
      <div class="toolbar">
        <span class="inline"><span>Interfaces</span></span>
        <span class="spacer"></span>
        <button class="btn" id="toggleiface">New</button>
      </div>
      <div class="card addpanel hidden" id="addifacepanel"></div>
      <div id="ifacelist"></div>
      <div class="card" style="margin-top:var(--space-6)">
        <h3>Live state</h3><pre class="out" id="ifaceshow">…</pre>
      </div>
    </div>

    <div id="view-routes" class="hidden">
      <div class="toolbar">
        <span class="inline"><span>Static routes</span></span>
        <span class="spacer"></span>
        <button class="btn" id="toggleroute">New</button>
      </div>
      <div class="card addpanel hidden" id="addroutepanel"></div>
      <div id="routelist"></div>
      <div class="card" style="margin-top:var(--space-6)">
        <h3>Routing table</h3><pre class="out" id="routeshow">…</pre>
      </div>
    </div>

    <div id="view-groups" class="hidden">
      <div class="toolbar">
        <label class="inline"><span>Kind</span>
          <select id="groupkind">
            <option value="address-group">address</option>
            <option value="port-group">port</option>
            <option value="domain-group">domain</option>
          </select>
        </label>
        <span class="spacer"></span>
        <button class="btn" id="togglegroup">New</button>
      </div>
      <div class="card addpanel hidden" id="addgrouppanel"></div>
      <div id="grouplist"></div>
      <p style="color:var(--text-muted);font-size:var(--text-sm);margin:var(--space-3) 0 0">
        A group is referenced by a rule's source, destination or port field, so
        one edit here moves every rule that names it.
      </p>
    </div>

    <div id="view-lb" class="hidden">
      <div class="toolbar">
        <span class="inline"><span>Load-balanced services</span></span>
        <span class="spacer"></span>
        <button class="btn" id="togglelb">New</button>
      </div>
      <div class="card addpanel hidden" id="addlbpanel"></div>
      <div id="lblist"></div>
      <div class="card" style="margin-top:var(--space-6)">
        <h3>Live state</h3><pre class="out" id="lbshow">…</pre>
      </div>
    </div>

    <div id="view-pki" class="hidden">
      <div class="toolbar">
        <span class="inline"><span>Certificate authorities</span></span>
        <span class="spacer"></span>
        <button class="btn" id="toggleca">New</button>
      </div>
      <div class="card addpanel hidden" id="addcapanel"></div>
      <div id="calist"></div>
    </div>

    <div id="view-certs" class="hidden">
      <div class="toolbar">
        <span class="inline"><span>Certificates</span></span>
        <span class="spacer"></span>
        <button class="btn" id="togglecert">New</button>
      </div>
      <div class="card addpanel hidden" id="addcertpanel"></div>
      <div id="certlist"></div>
      <div class="card" style="margin-top:var(--space-6)">
        <h3>On disk</h3><pre class="out" id="pkishow">…</pre>
      </div>
    </div>

    <div id="view-users" class="hidden">
      <div class="toolbar">
        <span class="inline"><span>Administrators</span></span>
        <span class="spacer"></span>
        <button class="btn" id="toggleuser">New</button>
      </div>
      <div class="card addpanel hidden" id="adduserpanel"></div>
      <div id="userlist"></div>
    </div>

    <div id="view-synproxy" class="hidden">
      <div class="toolbar">
        <span class="inline"><span>SYN-protected ports</span></span>
        <span class="spacer"></span>
        <button class="btn" id="togglesyn">New</button>
      </div>
      <div class="card addpanel hidden" id="addsynpanel"></div>
      <div id="synlist"></div>
      <p style="color:var(--text-muted);font-size:var(--text-sm);margin:var(--space-3) 0 0">
        The firewall answers every SYN to these ports itself and only opens the
        real connection once a client returns its cookie. Protected connections
        lose window scaling, SACK and timestamps — protect where a flood is the
        greater risk.
      </p>
    </div>

    <div id="view-ids" class="hidden">
      <div class="toolbar">
        <span class="inline"><span>Run-time blocks</span></span>
        <span class="spacer"></span>
        <button class="btn" id="liftall">Lift every block</button>
      </div>
      <p style="color:var(--text-muted);font-size:var(--text-sm);margin:0 0 var(--space-4)">
        The detector adds these; they take effect at once and are nowhere in the
        saved configuration, so lifting one is an operation rather than a staged
        change. Blocking an address by hand is not something the CLI can do, so
        it is not offered here either.
      </p>
      <div id="blocklist"></div>
      <div class="card"><h3>Detector</h3><pre class="out" id="idsshow">…</pre></div>
      <div class="card"><h3>Recent alerts</h3><pre class="out" id="alertshow">…</pre></div>
    </div>

    <div id="view-ha" class="hidden">
      <div class="toolbar">
        <span class="inline"><span>Virtual router groups</span></span>
        <span class="spacer"></span>
        <button class="btn" id="togglevrrp">New</button>
      </div>
      <div class="card addpanel hidden" id="addvrrppanel"></div>
      <div id="vrrplist"></div>
      <p style="color:var(--text-muted);font-size:var(--text-sm);margin:var(--space-3) 0 var(--space-6)">
        A tracked interface is what makes failover mean something: when it goes
        down this box lowers its own priority by the decrement, and the peer —
        which did not lose that link — takes the address.
      </p>
      <div class="card"><h3>Live state</h3><pre class="out" id="vrrpshow">…</pre></div>

      <div class="toolbar" style="margin-top:var(--space-6)">
        <span class="inline"><span>The pair</span></span>
      </div>
      <div class="card">
        <h3>Configuration sync</h3>
        <p style="color:var(--text-muted);font-size:var(--text-sm);margin:0 0 var(--space-4)">
          Every commit on this box is pushed to its peers, so the standby is
          running the configuration that was just approved rather than the one
          somebody last remembered to copy. Both ends present the same secret.
          A peer is <code>host</code> or <code>host:port</code>; repeat the field
          to add more, separated by spaces.
        </p>
        <div class="grid" id="configsyncform"></div>
      </div>
      <div class="card">
        <h3>Connection sync</h3>
        <p style="color:var(--text-muted);font-size:var(--text-sm);margin:0 0 var(--space-4)">
          Without this a failover is a reconnect for every session in flight:
          the standby takes the address and then drops the traffic, because it
          has no state for connections it never saw start. With it, the flow
          table is pushed to the peer continuously.
        </p>
        <div class="grid" id="conntracksyncform"></div>
      </div>
    </div>

    <div id="view-capture" class="hidden">
      <div class="card addpanel">
        <label class="field"><span>Interface</span><select id="cap-iface"></select></label>
        <label class="field"><span>Filter</span><input id="cap-filter" placeholder="tcp port 443"></label>
        <label class="field"><span>Packets</span><input id="cap-count" value="50"></label>
        <label class="field"><span>Seconds</span><input id="cap-secs" value="10"></label>
        <button class="btn primary" id="runcapture">Capture</button>
      </div>
      <p style="color:var(--text-muted);font-size:var(--text-sm);margin:0 0 var(--space-4)">
        Bounded on purpose: never more than 500 packets or 60 seconds, headers
        only, and nothing is written to disk. A capture that finds nothing is an
        answer too.
      </p>
      <div class="card"><h3>Output</h3><pre class="out" id="capout">Not run yet.</pre></div>
    </div>

    <div id="view-config" class="hidden">
      <div class="card">
        <h3>Revisions</h3>
        <p style="color:var(--text-muted);font-size:var(--text-sm);margin:0 0 var(--space-3)">
          Every save archives a revision. Rolling back stages the change like any
          other, so it lands only when you apply it.
        </p>
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
    <div class="field"><label for="r-from">From zone</label><select id="r-from"></select></div>
    <div class="field"><label for="r-to">To zone</label><select id="r-to"></select></div>
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
  <p id="editorerr" class="err"></p>
  <div class="row" style="margin-top:.9rem">
    <button class="btn primary" id="applysave">Stage</button>
    <button class="btn" id="cancel">Cancel</button>
  </div>
</dialog>

<dialog id="result">
  <h3 style="margin:0 0 var(--space-4)" id="resulttitle">Applied</h3>
  <div id="resultout"></div>
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
// The zones an interface names — the vocabulary every zone field offers, so a
// zone can be chosen rather than spelled. A name typed by hand is the commonest
// way a rule ends up pointing at a zone that does not exist.
function zoneNames(ls) {{
  const zones = new Set();
  for (const l of ls) {{
    if (l.path[0] === "interface" && l.path[l.path.length - 1] === "zone") zones.add(l.value);
    if (l.path[0] === "firewall" && l.path[1] === "zone") zones.add(l.path[2]);
  }}
  return [...zones].filter(Boolean).sort();
}}

function fillZoneSelect(sel, zones, current) {{
  sel.textContent = "";
  sel.append(el("option", {{ value: "", text: "(any)" }}));
  for (const z of zones) {{
    const o = el("option", {{ value: z, text: z }});
    if (z === current) o.setAttribute("selected", "selected");
    sel.append(o);
  }}
}}

// Rules come out of the running configuration, so the list can never show a
// rule the appliance does not have.
function parseRules(leaves) {{
  const rules = new Map();
  for (const l of leaves) {{
    if (l.path[0] !== "firewall" || l.path[1] !== "rule" || l.path.length < 4) continue;
    const name = l.path[2];
    if (!rules.has(name)) rules.set(name, {{ name }});
    rules.get(name)[l.path.slice(3).join(" ")] = l.value;
  }}
  return [...rules.values()];
}}

async function refreshRules() {{
  const ls = await leaves();
  const zones = zoneNames(ls);
  fillZoneSelect($("n-from"), zones, "");
  fillZoneSelect($("n-to"), zones, "");

  const globals = {{}};
  for (const l of ls) {{
    if (l.node === "firewall global") globals[l.path[l.path.length - 1]] = l.value;
  }}
  $("defaultpolicy").value = "";
  $("defaultpolicy").dataset.current = globals["default-action"] || "";

  const rules = parseRules(ls);
  const list = $("rulelist");
  list.textContent = "";
  if (!rules.length) {{
    list.append(el("div", {{ class: "card", text: "No rules configured." }}));
  }}
  for (const r of rules) {{
    // A rule reads as what it does, then what it matches — the order an
    // operator scans in. The action is a badge because it is the one field
    // whose value changes the meaning of every other one.
    const action = r.action || "accept";
    const badge = el("span", {{ class: "act " + action, text: action }});

    const match = el("span", {{ class: "col grow" }}, [
      el("span", {{ class: "eyebrow", text: "match" }}),
      el("span", {{ class: "mono strong", text: (r.source || "any") + " → " + (r.destination || r.to || "any") }}),
      el("span", {{ class: "sub", text: "in " + (r.from || "any") +
        (r.proto ? " · " + r.proto + "/" + (r.port || "any") : "") }}),
    ]);

    const cols = [];
    if (r.schedule) cols.push(col("schedule", r.schedule));
    if (r.limit) cols.push(col("limit", r.limit + "/s"));
    if (r.description) cols.push(col("note", r.description));

    const edit = el("button", {{ class: "btn", text: "Edit", onclick: () => openEditor(r, zones) }});
    const del = el("button", {{
      class: "btn danger", text: "Delete",
      onclick: () => stage("Delete firewall rule " + r.name, ["delete firewall rule " + r.name]),
    }});

    list.append(el("div", {{ class: "rule" }}, [
      badge,
      el("span", {{ class: "col", style: "flex:0 0 auto" }}, [
        el("span", {{ class: "eyebrow", text: "rule" }}),
        el("span", {{ class: "mono strong", text: r.name }}),
      ]),
      match,
      ...cols,
      el("span", {{ class: "row", style: "flex:none" }}, [edit, del]),
    ]));
  }}
}}

function col(label, value) {{
  return el("span", {{ class: "col", style: "flex:0 0 auto" }}, [
    el("span", {{ class: "eyebrow", text: label }}),
    el("span", {{ class: "mono", text: value }}),
  ]);
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

function openEditor(rule, zones) {{
  $("editortitle").textContent = rule ? "Edit rule " + rule.name : "New rule";
  $("r-name").value = rule ? rule.name : "";
  $("r-name").readOnly = !!rule;
  fillZoneSelect($("r-from"), zones || [], rule && rule.from);
  fillZoneSelect($("r-to"), zones || [], rule && rule.to);
  for (const [id, key] of FIELDS) {{
    if (id === "r-from" || id === "r-to") continue;
    $(id).value = (rule && rule[key]) || "";
  }}
  $("editorerr").textContent = "";
  $("editor").showModal();
}}

// Editing stages, it does not apply. The appliance's own model is a candidate
// configuration you commit or discard, and a console whose every button was a
// commit would be a different product from the CLI beside it. So a form's
// Apply appends its commands here, the header says how many are waiting, and
// nothing reaches the box until Apply — or Discard throws them away, which is
// what makes clicking safe enough not to need a confirmation on every delete.
// Each entry is what the operator did, plus the commands that will carry it
// out. The commands are the transport — they are how the appliance's own
// parser, validators and refusals guard a clicked change exactly as they guard
// a typed one — but they are not the interface. What the panel shows is the
// change, in words.
let staged = [];

function stage(label, lines) {{
  const cmds = lines.filter(Boolean);
  if (!cmds.length) return;
  staged.push({{ label, cmds }});
  renderStaged();
}}

function stagedCommands() {{
  return staged.flatMap((s) => s.cmds);
}}

function renderStaged() {{
  const n = staged.length;
  $("stagedbadge").textContent = n ? n + " pending change" + (n === 1 ? "" : "s")
                                   : "no pending changes";
  $("stagedbadge").className = "pill" + (n ? " warn" : "");
  $("stagedcard").classList.toggle("hidden", n === 0);
  $("stagedtitle").textContent = n + " pending change" + (n === 1 ? "" : "s");

  const list = $("stagedlist");
  list.textContent = "";
  staged.forEach((entry, i) => {{
    list.append(el("div", {{ class: "change" }}, [
      el("span", {{ class: "dot warn" }}),
      el("span", {{ class: "what", text: entry.label }}),
      el("button", {{
        class: "btn", text: "Remove",
        onclick: () => {{ staged.splice(i, 1); renderStaged(); }},
      }}),
    ]));
  }});
}}

// `tail` is what turns a script into an intention: nothing commits, `commit`
// applies for this boot, `commit save` also persists.
async function applyStaged(tail) {{
  if (!staged.length) return;
  const r = await configure(stagedCommands().concat(tail));
  showResult(r);
  // Only clear once they have actually run. A refused commit leaves the
  // commands staged, so the operator can fix one and try again rather than
  // reconstructing what they had clicked.
  if (r.ok && !summarise(r.output).some((n) => n.kind === "bad")) {{
    staged = [];
    renderStaged();
  }}
  await buildSearchIndex();
  await refresh();
}}

// What came back, as an outcome — never as a transcript.
//
// The appliance answers in its own voice, and that voice is a terminal's: a
// refusal is followed by the whole `set` grammar, which is exactly right at a
// prompt and exactly wrong in a console. So the reply is read for the lines
// that say something about *this* change — the errors, the warnings, and the
// confirmation — and the grammar dump is dropped. A console that pasted it
// would be handing an operator a manual page instead of an answer.
function summarise(output) {{
  const notes = [];
  let grammar = false;
  for (const raw of (output || "").split("\n")) {{
    const line = raw.trim();
    if (!line) continue;
    // The help dump is a run of `set …` lines under an "unknown set path"
    // error; the error itself is kept, its enclosed grammar is not.
    if (grammar) {{
      if (line.startsWith("set ") || line.startsWith("(") || line.startsWith("|")) continue;
      grammar = false;
    }}
    if (line.startsWith("error:")) {{
      const short = line.replace(/^error:\s*/, "");
      if (short.startsWith("unknown set path")) {{
        grammar = true;
        notes.push({{ kind: "bad", text: "That setting is not one this appliance accepts." }});
        continue;
      }}
      notes.push({{ kind: "bad", text: short }});
      continue;
    }}
    if (line.startsWith("warning:")) {{
      notes.push({{ kind: "warn", text: line.replace(/^warning:\s*/, "") }});
      continue;
    }}
    if (line.startsWith("✔") || line.startsWith("commit:")) {{
      notes.push({{ kind: "ok", text: line.replace(/^✔\s*/, "") }});
    }}
  }}
  return notes;
}}

function showResult(r) {{
  const notes = summarise(r.output);
  const failed = notes.some((n) => n.kind === "bad");
  $("resulttitle").textContent = failed ? "Not applied" : "Applied";
  const box = $("resultout");
  box.textContent = "";
  if (!notes.length) {{
    notes.push({{ kind: r.ok ? "ok" : "bad", text: r.ok ? "Done." : "The appliance refused this." }});
  }}
  for (const n of notes) {{
    box.append(el("div", {{ class: "change" }}, [
      el("span", {{ class: "dot " + (n.kind === "bad" ? "down" : n.kind === "warn" ? "warn" : "up") }}),
      el("span", {{ class: "what", text: n.text }}),
    ]));
  }}
  $("result").showModal();
}}


// ---- objects, in one language --------------------------------------------

// Every configurable thing on this appliance is the same shape: a named object
// with a handful of fields. Rendering that once is what makes a zone, a tunnel
// and a DHCP server read alike — and it is why they cannot disagree about how a
// setting is written, since they all go through `path(name)`.
//
// `fields` is [key, label, options?]. An options list becomes a select, so a
// field with a fixed vocabulary is chosen rather than spelled.
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

function fieldWidget(field, value) {{
  if (!field[2]) return el("input", {{ value: value || "", placeholder: field[1].toLowerCase() }});
  const sel = el("select", {{}});
  for (const opt of field[2]) {{
    const o = el("option", {{ value: opt, text: opt === "" ? "(unset)" : opt }});
    if (opt === (value || "")) o.setAttribute("selected", "selected");
    sel.append(o);
  }}
  return sel;
}}

function fieldGrid(fields, row) {{
  const widgets = fields.map((f) => fieldWidget(f, row && row[f[0]]));
  const grid = el("div", {{ class: "addpanel inline-edit" }});
  fields.forEach((f, i) => {{
    grid.append(el("label", {{ class: "field" }}, [el("span", {{ text: f[1] }}), widgets[i]]));
  }});
  return {{ grid, widgets }};
}}

// The commands an edit becomes: a value writes, an emptied field removes. The
// difference matters — leaving a field blank has to mean "no longer set", not
// "leave whatever was there".
function fieldLines(fields, widgets, path, before) {{
  const lines = [];
  fields.forEach((f, i) => {{
    const v = (widgets[i].value || "").trim();
    if (v) lines.push(`set ${{path}} ${{f[0]}} ${{v}}`);
    else if (before && before[f[0]]) lines.push(`delete ${{path}} ${{f[0]}}`);
  }});
  return lines;
}}

// A section-wide settings block: the same field grid, staged as one change.
function settingsPanel(boxId, fields, current, path, label) {{
  const box = $(boxId);
  box.textContent = "";
  const {{ grid, widgets }} = fieldGrid(fields, current);
  for (const child of [...grid.children]) box.append(child);
  box.append(el("button", {{
    class: "btn primary", text: "Stage",
    onclick: () => stage(label, fieldLines(fields, widgets, path, current)),
  }}));
}}

// One object as a card: what it is, then what it is set to, then its controls.
// Editing opens the same field grid the add panel uses, in place — an operator
// should not have to learn two shapes for one job.
function objectCard(o, row) {{
  const path = o.path(row.name);
  const card = el("div", {{ class: "rule" }});

  const head = [];
  if (o.badge) {{
    const b = o.badge(row);
    if (b) head.push(el("span", {{ class: "act " + (b.cls || ""), text: b.text }}));
  }}
  head.push(el("span", {{ class: "col", style: "flex:0 0 auto" }}, [
    el("span", {{ class: "eyebrow", text: o.noun }}),
    el("span", {{ class: "mono strong", text: row.name }}),
  ]));

  const set = o.fields.filter((f) => row[f[0]]);
  for (const f of set.slice(0, 4)) {{
    head.push(el("span", {{ class: "col", style: "flex:0 1 auto" }}, [
      el("span", {{ class: "eyebrow", text: f[1] }}),
      el("span", {{ class: "mono", text: row[f[0]] }}),
    ]));
  }}
  head.push(set.length
    ? el("span", {{ class: "col grow" }})
    : el("span", {{ class: "col grow" }}, [el("span", {{ class: "sub", text: "nothing set yet" }})]));

  const editor = el("div", {{ class: "hidden", style: "flex:1 1 100%" }});
  const edit = el("button", {{
    class: "btn", text: "Edit",
    onclick: () => {{
      if (!editor.classList.contains("hidden")) {{ editor.classList.add("hidden"); return; }}
      editor.textContent = "";
      const {{ grid, widgets }} = fieldGrid(o.fields, row);
      grid.append(el("button", {{
        class: "btn primary", text: "Stage",
        onclick: () => stage(`${{o.noun}} ${{row.name}}`, fieldLines(o.fields, widgets, path, row)),
      }}));
      editor.append(grid);
      editor.classList.remove("hidden");
    }},
  }});
  const del = el("button", {{
    class: "btn danger", text: "Delete",
    onclick: () => stage(`Delete ${{o.noun.toLowerCase()}} ${{row.name}}`, [`delete ${{path}}`]),
  }});

  for (const part of head) card.append(part);
  card.append(el("span", {{ class: "row", style: "flex:none" }}, [edit, del]), editor);
  return card;
}}

// `o` carries: listId, addId?, noun, fields, path(name), rows, badge?, nameHint, empty.
function renderObjects(o) {{
  const list = $(o.listId);
  list.textContent = "";
  if (!o.rows.length) {{
    list.append(el("div", {{ class: "card", text: o.empty || ("No " + o.noun.toLowerCase() + " configured.") }}));
  }}
  for (const row of o.rows) list.append(objectCard(o, row));

  if (!o.addId) return;
  // The add panel is rebuilt each refresh so its selects carry the vocabulary
  // as it is now, not as it was when the page loaded.
  const box = $(o.addId);
  box.textContent = "";
  const name = el("input", {{ placeholder: o.nameHint || "name" }});
  box.append(el("label", {{ class: "field" }}, [el("span", {{ text: "Name" }}), name]));
  const {{ grid, widgets }} = fieldGrid(o.fields, null);
  for (const child of [...grid.children]) box.append(child);
  box.append(el("button", {{
    class: "btn primary", text: "Add",
    onclick: () => {{
      const n = name.value.trim();
      if (!n) {{ name.focus(); return; }}
      const lines = fieldLines(o.fields, widgets, o.path(n), null);
      // An object with no fields set is still an object; the appliance decides
      // whether that is valid, which is the whole reason to ask it.
      stage(`${{o.noun}} ${{n}}`, lines.length ? lines : [`set ${{o.path(n)}}`]);
      box.classList.add("hidden");
    }},
  }}));
}}

function wireToggle(buttonId, panelId, label) {{
  $(buttonId).onclick = () => {{
    const panel = $(panelId);
    panel.classList.toggle("hidden");
    $(buttonId).textContent = panel.classList.contains("hidden") ? label : "Cancel";
  }};
}}

async function leaves() {{
  try {{ return parseConfig(await text("/api/v1/show/configuration")); }}
  catch (e) {{ return []; }}
}}

// ---- zones ---------------------------------------------------------------

const POSTURE = [
  ["default-action", "Default action", ["", "accept", "drop", "reject"]],
  ["stateful", "Stateful", ["", "true", "false"]],
  ["block-icmp", "Block ICMP", ["", "true", "false"]],
  ["log", "Log", ["", "true", "false"]],
  ["source-validation", "Source validation", ["", "disable", "loose", "strict"]],
];

async function refreshZones() {{
  const ls = await leaves();
  const globals = {{}};
  for (const l of ls) {{
    if (l.node === "firewall global") globals[l.path[l.path.length - 1]] = l.value;
  }}
  settingsPanel("globalform", POSTURE, globals, "firewall global", "Global firewall posture");

  // A zone exists because an interface names it, so the list is the zones in
  // use — not only the ones that happen to carry an override.
  const overrides = new Map(entriesUnder(ls, ["firewall", "zone"]).map((z) => [z.name, z]));
  for (const name of zoneNames(ls)) {{
    if (!overrides.has(name)) overrides.set(name, {{ name }});
  }}
  renderObjects({{
    listId: "zonelist", noun: "Zone", fields: POSTURE,
    path: (n) => `firewall zone ${{n}}`,
    rows: [...overrides.values()].sort((a, b) => a.name.localeCompare(b.name)),
    badge: (r) => ({{ text: r["default-action"] || "inherits", cls: r["default-action"] || "" }}),
    empty: "No zones — give an interface a zone first.",
  }});
}}

// ---- NAT -----------------------------------------------------------------

const SNAT = [["zone", "Zone"], ["source", "Source"], ["translation", "Translation"]];
const DNAT = [
  ["zone", "Zone"], ["proto", "Protocol", ["", "tcp", "udp"]],
  ["port", "Port"], ["to", "To"],
];

async function refreshNat() {{
  $("natshow").textContent = "…";
  try {{ $("natshow").textContent = (await text("/api/v1/show/nat")).trimEnd(); }}
  catch (e) {{ $("natshow").textContent = String(e.message || e); }}

  const ls = await leaves();
  renderObjects({{
    listId: "snatlist", addId: "addsnatpanel", noun: "Source rule",
    fields: SNAT, nameHint: "wan-masq",
    path: (n) => `nat source ${{n}}`,
    rows: entriesUnder(ls, ["nat", "source"]),
    badge: (r) => ({{ text: r.translation ? "snat" : "masquerade", cls: "accept" }}),
    empty: "No source NAT configured.",
  }});
  renderObjects({{
    listId: "dnatlist", addId: "adddnatpanel", noun: "Port forward",
    fields: DNAT, nameHint: "web",
    path: (n) => `nat destination ${{n}}`,
    rows: entriesUnder(ls, ["nat", "destination"]),
    badge: (r) => r.port ? {{ text: (r.proto || "tcp") + "/" + r.port, cls: "accept" }}
                         : {{ text: "incomplete", cls: "reject" }},
    empty: "No port forwards configured.",
  }});
}}

// ---- BGP -----------------------------------------------------------------

const BGP_GLOBAL = [
  ["local-as", "Local AS"], ["router-id", "Router ID"], ["hold-time", "Hold time"],
  ["cluster-id", "Cluster ID"], ["multipath", "Multipath", ["", "true", "false"]],
  ["ebgp-require-policy", "Require policy", ["", "true", "false"]],
];
const BGP_NEIGHBOR = [
  ["remote-as", "Remote AS"], ["description", "Description"], ["password", "Password"],
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
  settingsPanel("bgpglobal", BGP_GLOBAL, globals, "protocols bgp", "BGP router settings");

  renderObjects({{
    listId: "bgplist", addId: "addbgppanel", noun: "Neighbour",
    fields: BGP_NEIGHBOR, nameHint: "neighbour address",
    path: (n) => `protocols bgp neighbor ${{n}}`,
    rows: entriesUnder(ls, ["protocols", "bgp", "neighbor"]),
    // A neighbour without a remote AS is not yet a session, and saying so is
    // more useful than showing an empty column.
    badge: (r) => r["remote-as"] ? {{ text: "AS " + r["remote-as"], cls: "accept" }}
                                 : {{ text: "incomplete", cls: "reject" }},
    empty: "No BGP neighbours configured.",
  }});
}}

// ---- IPsec ---------------------------------------------------------------

const IPSEC = [
  ["local", "Local address"], ["remote", "Remote address"],
  ["local-subnet", "Local subnet"], ["remote-subnet", "Remote subnet"],
  ["psk", "Pre-shared key"],
  ["ike-version", "IKE", ["", "1", "2"]],
  ["start-action", "Start", ["", "start", "trap", "none"]],
];

async function refreshIpsec() {{
  $("ipsecshow").textContent = "…";
  try {{ $("ipsecshow").textContent = (await text("/api/v1/show/vpn/ipsec")).trimEnd(); }}
  catch (e) {{ $("ipsecshow").textContent = String(e.message || e); }}
  renderObjects({{
    listId: "ipseclist", addId: "addipsecpanel", noun: "Tunnel",
    fields: IPSEC, nameHint: "tunnel name",
    path: (n) => `vpn ipsec ${{n}}`,
    rows: entriesUnder(await leaves(), ["vpn", "ipsec"]),
    badge: (r) => (r.local && r.remote) ? {{ text: "ike" + (r["ike-version"] || "2"), cls: "accept" }}
                                        : {{ text: "incomplete", cls: "reject" }},
    empty: "No IPsec tunnels configured.",
  }});
}}

// ---- WireGuard -----------------------------------------------------------

const WG = [["listen-port", "Listen port"], ["private-key", "Private key"]];
const WG_PEER = [
  ["allowed-ips", "Allowed IPs"], ["endpoint", "Endpoint"],
  ["keepalive", "Keepalive"], ["preshared-key", "Pre-shared key"],
];

async function refreshWireguard() {{
  const ls = await leaves();
  const tunnels = entriesUnder(ls, ["vpn", "wireguard"]);
  renderObjects({{
    listId: "wglist", addId: "addwgpanel", noun: "Interface",
    fields: WG, nameHint: "wg0",
    path: (n) => `vpn wireguard ${{n}}`,
    rows: tunnels,
    badge: (r) => r["listen-port"] ? {{ text: ":" + r["listen-port"], cls: "accept" }}
                                   : {{ text: "no port", cls: "reject" }},
    empty: "No WireGuard interfaces configured.",
  }});

  // Peers belong to an interface, so the interface is picked once in the
  // toolbar rather than repeated in every row.
  const sel = $("wgtunnel");
  const chosen = sel.value;
  sel.textContent = "";
  for (const t of tunnels) {{
    const o = el("option", {{ value: t.name, text: t.name }});
    if (t.name === chosen) o.setAttribute("selected", "selected");
    sel.append(o);
  }}
  const iface = sel.value || (tunnels[0] && tunnels[0].name);
  renderObjects({{
    listId: "wgpeerlist", addId: "addwgpeerpanel", noun: "Peer",
    fields: WG_PEER, nameHint: "peer public key",
    path: (n) => `vpn wireguard ${{iface}} peer ${{n}}`,
    rows: iface ? entriesUnder(ls, ["vpn", "wireguard", iface, "peer"]) : [],
    empty: iface ? "No peers on " + iface + "." : "Add an interface first.",
  }});
}}

// ---- DHCP ----------------------------------------------------------------

const DHCP = [
  ["pool-offset", "Pool offset"], ["pool-size", "Pool size"],
  ["default-router", "Default router"], ["dns", "DNS"],
  ["domain", "Domain"], ["lease-time", "Lease time"],
];

async function refreshDhcp() {{
  $("dhcpshow").textContent = "…";
  try {{ $("dhcpshow").textContent = (await text("/api/v1/show/dhcp/leases")).trimEnd(); }}
  catch (e) {{ $("dhcpshow").textContent = String(e.message || e); }}

  const ls = await leaves();
  // A DHCP server is a block on an interface, not an object of its own, so the
  // rows are interfaces and the path carries the interface's name.
  const servers = new Map();
  const interfaces = new Set();
  for (const l of ls) {{
    if (l.path[0] !== "interface") continue;
    interfaces.add(l.path[1]);
    if (l.path[2] === "dhcp-server" && l.path.length >= 4) {{
      if (!servers.has(l.path[1])) servers.set(l.path[1], {{ name: l.path[1] }});
      servers.get(l.path[1])[l.path[3]] = l.value;
    }}
  }}

  const sel = $("dhcpiface");
  const chosen = sel.value;
  sel.textContent = "";
  for (const i of [...interfaces].sort()) {{
    if (servers.has(i)) continue;
    const o = el("option", {{ value: i, text: i }});
    if (i === chosen) o.setAttribute("selected", "selected");
    sel.append(o);
  }}

  renderObjects({{
    listId: "dhcplist", noun: "Server", fields: DHCP,
    path: (n) => `interface ${{n}} dhcp-server`,
    rows: [...servers.values()],
    badge: (r) => r["pool-size"] ? {{ text: r["pool-size"] + " leases", cls: "accept" }}
                                 : {{ text: "default pool", cls: "" }},
    empty: "No DHCP server enabled.",
  }});
}}

// ---- interfaces, routes, groups, services, identity ----------------------

const IFACE = [
  ["zone", "Zone"], ["address", "IPv4 address"], ["address6", "IPv6 address"],
  ["mtu", "MTU"], ["description", "Description"],
  ["disabled", "Disabled", ["", "true", "false"]],
];

async function refreshInterfaces() {{
  $("ifaceshow").textContent = "…";
  try {{ $("ifaceshow").textContent = (await text("/api/v1/show/interfaces")).trimEnd(); }}
  catch (e) {{ $("ifaceshow").textContent = String(e.message || e); }}
  renderObjects({{
    listId: "ifacelist", addId: "addifacepanel", noun: "Interface",
    fields: IFACE, nameHint: "eth0",
    path: (n) => `interface ${{n}}`,
    rows: entriesUnder(await leaves(), ["interface"]),
    // The zone is the badge because it decides whether anything the firewall
    // says applies to this interface at all.
    badge: (r) => r.zone ? {{ text: r.zone, cls: "accept" }}
                         : {{ text: "unzoned", cls: "reject" }},
    empty: "No interfaces declared.",
  }});
}}

const ROUTE = [["via", "Via"], ["dev", "Device"], ["metric", "Metric"], ["vrf", "VRF"]];

async function refreshRoutes() {{
  $("routeshow").textContent = "…";
  try {{ $("routeshow").textContent = (await text("/api/v1/show/ip/route")).trimEnd(); }}
  catch (e) {{ $("routeshow").textContent = String(e.message || e); }}
  renderObjects({{
    listId: "routelist", addId: "addroutepanel", noun: "Route",
    fields: ROUTE, nameHint: "0.0.0.0/0",
    path: (n) => `protocols static ${{n}}`,
    rows: entriesUnder(await leaves(), ["protocols", "static"]),
    badge: (r) => (r.via || r.dev) ? {{ text: "static", cls: "accept" }}
                                   : {{ text: "no next hop", cls: "reject" }},
    empty: "No static routes configured.",
  }});
}}

// The three group kinds differ only in the word for a member, so one view with
// a kind picker beats three that would drift apart.
const GROUP_MEMBER = {{ "address-group": "address", "port-group": "port", "domain-group": "domain" }};

async function refreshGroups() {{
  const kind = $("groupkind").value;
  const member = GROUP_MEMBER[kind];
  renderObjects({{
    listId: "grouplist", addId: "addgrouppanel", noun: "Group",
    fields: [[member, member.charAt(0).toUpperCase() + member.slice(1)]],
    nameHint: "group name",
    path: (n) => `firewall group ${{kind}} ${{n}}`,
    rows: entriesUnder(await leaves(), ["firewall", "group", kind]),
    badge: () => ({{ text: member, cls: "" }}),
    empty: "No " + member + " groups configured.",
  }});
}}

const LB = [
  ["zone", "Zone"], ["vip", "Virtual address"],
  ["proto", "Protocol", ["", "tcp", "udp"]], ["port", "Port"],
  ["backend", "Backend"], ["disabled", "Disabled", ["", "true", "false"]],
];

async function refreshLb() {{
  $("lbshow").textContent = "…";
  try {{ $("lbshow").textContent = (await text("/api/v1/show/load-balancer")).trimEnd(); }}
  catch (e) {{ $("lbshow").textContent = String(e.message || e); }}
  renderObjects({{
    listId: "lblist", addId: "addlbpanel", noun: "Service",
    fields: LB, nameHint: "web",
    path: (n) => `load-balancer ${{n}}`,
    rows: entriesUnder(await leaves(), ["load-balancer"]),
    badge: (r) => r.vip ? {{ text: r.vip + ":" + (r.port || "?"), cls: "accept" }}
                        : {{ text: "incomplete", cls: "reject" }},
    empty: "No load-balanced services configured.",
  }});
}}

const CA = [
  ["common-name", "Common name"], ["organization", "Organization"],
  ["validity-days", "Validity (days)"], ["key-type", "Key type", ["", "ec", "rsa"]],
];
const CERT = [
  ["ca", "Signed by"], ["common-name", "Common name"],
  ["subject-alt-name", "Alt name"], ["validity-days", "Validity (days)"],
  ["key-type", "Key type", ["", "ec", "rsa"]],
  ["usage", "Usage", ["", "server", "client"]],
];

async function refreshPki() {{
  renderObjects({{
    listId: "calist", addId: "addcapanel", noun: "Authority",
    fields: CA, nameHint: "internal",
    path: (n) => `pki ca ${{n}}`,
    rows: entriesUnder(await leaves(), ["pki", "ca"]),
    badge: (r) => r["common-name"] ? {{ text: "ca", cls: "accept" }}
                                   : {{ text: "incomplete", cls: "reject" }},
    empty: "No certificate authorities configured.",
  }});
}}

async function refreshCerts() {{
  $("pkishow").textContent = "…";
  try {{ $("pkishow").textContent = (await text("/api/v1/show/pki")).trimEnd(); }}
  catch (e) {{ $("pkishow").textContent = String(e.message || e); }}
  renderObjects({{
    listId: "certlist", addId: "addcertpanel", noun: "Certificate",
    fields: CERT, nameHint: "web",
    path: (n) => `pki certificate ${{n}}`,
    rows: entriesUnder(await leaves(), ["pki", "certificate"]),
    badge: (r) => r.ca ? {{ text: r.ca, cls: "accept" }} : {{ text: "unsigned", cls: "reject" }},
    empty: "No certificates configured.",
  }});
}}

const USER = [["ssh-key", "SSH public key"], ["hashed-password", "Hashed password"]];

async function refreshUsers() {{
  renderObjects({{
    listId: "userlist", addId: "adduserpanel", noun: "Administrator",
    fields: USER, nameHint: "admin",
    path: (n) => `system login ${{n}}`,
    rows: entriesUnder(await leaves(), ["system", "login"]),
    // Key-only is the default and the better posture, so it is stated rather
    // than left as an empty column an operator has to interpret.
    badge: (r) => r["hashed-password"] ? {{ text: "password", cls: "reject" }}
                                       : {{ text: "key only", cls: "accept" }},
    empty: "No administrators configured.",
  }});
}}

async function refreshSynproxy() {{
  renderObjects({{
    listId: "synlist", addId: "addsynpanel", noun: "Port",
    fields: [["mss", "MSS"]], nameHint: "443",
    path: (n) => `firewall syn-protect ${{n}}`,
    rows: entriesUnder(await leaves(), ["firewall", "syn-protect"]),
    badge: (r) => ({{ text: "tcp/" + r.name, cls: "accept" }}),
    empty: "No ports are SYN-protected.",
  }});
}}

// An operational command: it has already happened by the time it returns, so
// there is nothing to stage and nothing to discard.
async function clearOp(path) {{
  try {{
    const r = await api("/api/v1/clear/" + path, {{ method: "POST" }});
    showResult({{ ok: true, output: await r.text() }});
  }} catch (e) {{
    showResult({{ ok: false, output: String(e.message || e) }});
  }}
  await refreshIds();
}}

async function refreshIds() {{
  const list = $("blocklist");
  list.textContent = "";
  try {{
    const blocks = (await text("/api/v1/show/ids/blocks")).trimEnd().split("\n");
    let any = false;
    for (const line of blocks) {{
      const addr = (line.match(/(\d+\.\d+\.\d+\.\d+(?:\/\d+)?)/) || [])[1];
      if (!addr) continue;
      any = true;
      list.append(el("div", {{ class: "rule" }}, [
        el("span", {{ class: "act drop", text: "blocked" }}),
        el("span", {{ class: "col grow" }}, [
          el("span", {{ class: "eyebrow", text: "source" }}),
          el("span", {{ class: "mono strong", text: line.trim() }}),
        ]),
        el("button", {{
          class: "btn", text: "Lift",
          onclick: () => clearOp("ids/block/" + encodeURIComponent(addr.split("/")[0])),
        }}),
      ]));
    }}
    if (!any) list.append(el("div", {{ class: "card", text: "Nothing is blocked." }}));
  }} catch (e) {{
    list.append(el("div", {{ class: "card", text: String(e.message || e) }}));
  }}

  for (const [id, path] of [["idsshow", "/api/v1/show/ids"],
                            ["alertshow", "/api/v1/show/ids/alerts"]]) {{
    $(id).textContent = "…";
    try {{ $(id).textContent = (await text(path)).trimEnd() || "(nothing)"; }}
    catch (e) {{ $(id).textContent = String(e.message || e); }}
  }}
}}

const VRRP = [
  ["interface", "Interface"],
  ["vrid", "Virtual router ID"],
  ["virtual-address", "Virtual address"],
  ["priority", "Priority"],
  ["preempt", "Preempt", ["", "true", "false"]],
  ["track-interface", "Tracked interface"],
  ["priority-decrement", "Priority decrement"],
  ["advert-interval", "Advert interval (ms)"],
];

// The two halves of a pair. Separate from VRRP on purpose: VRRP decides which
// box holds the address, and these decide what the other box knows when it
// does — a pair with VRRP alone fails over to a firewall that has neither the
// configuration nor the connections.
const CONFIG_SYNC = [
  ["peer", "Peers"], ["secret", "Shared secret"],
];
const CONNTRACK_SYNC = [
  ["peer", "Peers"], ["listen", "Listen on"], ["interval", "Interval (s)"],
];

async function refreshHa() {{
  $("vrrpshow").textContent = "…";
  try {{ $("vrrpshow").textContent = (await text("/api/v1/show/vrrp")).trimEnd(); }}
  catch (e) {{ $("vrrpshow").textContent = String(e.message || e); }}
  renderObjects({{
    listId: "vrrplist", addId: "addvrrppanel", noun: "Group",
    fields: VRRP, nameHint: "wan-vip",
    path: (n) => `protocols vrrp ${{n}}`,
    rows: entriesUnder(await leaves(), ["protocols", "vrrp"]),
    // The priority is what decides who holds the address, so it is the badge —
    // and a group without a virtual address holds nothing at all.
    badge: (r) => r["virtual-address"]
      ? {{ text: "prio " + (r.priority || "100"), cls: "accept" }}
      : {{ text: "no address", cls: "reject" }},
    empty: "No virtual router groups configured.",
  }});

  // The pair's own settings live under `system`, one level, so they are read
  // the same way BGP's router settings are rather than as objects with names.
  const ls = await leaves();
  const under = (node) => {{
    const out = {{}};
    for (const l of ls) {{
      if (l.node === node) out[l.path[l.path.length - 1]] = l.value;
    }}
    return out;
  }};
  settingsPanel(
    "configsyncform", CONFIG_SYNC, under("system config-sync"),
    "system config-sync", "Configuration sync",
  );
  settingsPanel(
    "conntracksyncform", CONNTRACK_SYNC, under("system conntrack-sync"),
    "system conntrack-sync", "Connection sync",
  );
}}

// The interface list comes from the config, so the picker offers the interfaces
// this appliance knows rather than whatever the kernel happens to have.
async function refreshCapture() {{
  const ls = await leaves();
  const names = [...new Set(ls.filter((l) => l.path[0] === "interface").map((l) => l.path[1]))];
  const sel = $("cap-iface");
  const chosen = sel.value;
  sel.textContent = "";
  for (const n of names.sort()) {{
    const o = el("option", {{ value: n, text: n }});
    if (n === chosen) o.setAttribute("selected", "selected");
    sel.append(o);
  }}
}}

// The Configuration view is the revision list and nothing else: rolling back is
// a real operation an operator needs, and it stages like every other change.
async function refreshConfig() {{
  const r = $("revtable");
  r.textContent = "";
  r.append(el("tr", {{}}, ["revision", ""].map((h) => el("th", {{ text: h }}))));
  try {{
    const revs = (await text("/api/v1/show/system/commit")).trimEnd().split("\n");
    for (const line of revs) {{
      if (!line.trim()) continue;
      const n = (line.trim().match(/^(\d+)/) || [])[1];
      r.append(el("tr", {{}}, [
        el("td", {{ class: "mono", text: line }}),
        el("td", {{}}, [n === undefined ? el("span", {{}}) : el("button", {{
          class: "btn", text: "Roll back",
          onclick: () => stage("Roll back to revision " + n, ["rollback " + n]),
        }})]),
      ]));
    }}
  }} catch (e) {{
    r.append(el("tr", {{}}, [el("td", {{ colspan: "2", text: String(e.message || e) }})]));
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
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
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
    {{ v: "groups", t: "Groups", i: "layers" }},
    {{ v: "nat", t: "NAT", i: "swap" }},
    {{ v: "synproxy", t: "SYN protection", i: "shield" }},
  ]}},
  {{ g: "Network", items: [
    {{ v: "interfaces", t: "Interfaces", i: "address" }},
    {{ v: "routes", t: "Static routes", i: "route" }},
    {{ v: "bgp", t: "BGP", i: "route" }},
    {{ v: "dhcp", t: "DHCP", i: "address" }},
    {{ v: "lb", t: "Load balancer", i: "swap" }},
  ]}},
  {{ g: "Security", items: [
    {{ v: "ipsec", t: "IPsec", i: "lock" }},
    {{ v: "wireguard", t: "WireGuard", i: "key" }},
    {{ v: "pki", t: "Authorities", i: "lock" }},
    {{ v: "certs", t: "Certificates", i: "file" }},
    {{ v: "ids", t: "Intrusion defence", i: "bug" }},
    {{ v: "capture", t: "Packet capture", i: "search" }},
  ]}},
  {{ g: "System", items: [
    {{ v: "ha", t: "High availability", i: "layers" }},
    {{ v: "users", t: "Administrators", i: "key" }},
    {{ v: "config", t: "Revisions", i: "file" }},
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

// Which section owns a setting. Search is only useful if a hit takes you where
// the thing can be changed, and the path already says which section that is —
// so the mapping lives here rather than being guessed from the words.
const OWNERS = [
  [["firewall", "rule"], "rules"],
  [["firewall", "zone"], "zones"],
  [["firewall", "global"], "zones"],
  [["firewall", "group"], "groups"],
  [["firewall", "syn-protect"], "synproxy"],
  [["nat"], "nat"],
  [["protocols", "static"], "routes"],
  [["protocols", "bgp"], "bgp"],
  [["protocols", "vrrp"], "ha"],
  [["vpn", "ipsec"], "ipsec"],
  [["vpn", "wireguard"], "wireguard"],
  [["load-balancer"], "lb"],
  [["pki", "ca"], "pki"],
  [["pki", "certificate"], "certs"],
  [["system", "login"], "users"],
];

function sectionFor(path) {{
  // An interface's DHCP block belongs to the DHCP view, not to Interfaces —
  // the more specific owner has to win, so this is checked first.
  if (path[0] === "interface") return path[2] === "dhcp-server" ? "dhcp" : "interfaces";
  for (const [prefix, view] of OWNERS) {{
    if (prefix.every((p, i) => path[i] === p)) return view;
  }}
  return null;
}}

// Searching the configuration, not the section names: an operator looking for
// an address or a port number is looking for the object that mentions it, and
// they will not know which section that turned out to be.
let searchIndex = [];

async function buildSearchIndex() {{
  const ls = await leaves();
  const seen = new Set();
  searchIndex = [];
  for (const l of ls) {{
    const view = sectionFor(l.path);
    if (!view) continue;
    // One entry per object, not per setting: twelve hits for one rule is a
    // list nobody reads.
    const label = l.path.slice(0, l.path[0] === "interface" ? 2 : 3).join(" ");
    const key = view + "|" + label;
    const haystack = (l.path.join(" ") + " " + l.value).toLowerCase();
    const existing = seen.has(key) ? searchIndex.find((e) => e.key === key) : null;
    if (existing) {{ existing.hay += " " + haystack; continue; }}
    seen.add(key);
    searchIndex.push({{ key, view, label, hay: haystack }});
  }}
}}

function renderMatches() {{
  const box = $("matches");
  box.textContent = "";
  const q = $("navsearch").value.trim().toLowerCase();
  if (q.length < 2) return;
  const hits = searchIndex.filter((e) => e.hay.includes(q)).slice(0, 12);
  if (!hits.length) return;
  box.append(el("span", {{ class: "grp", text: "Matches" }}));
  for (const h of hits) {{
    box.append(el("button", {{
      class: "navitem",
      text: h.label,
      onclick: () => {{ view = h.view; panel = null; refresh(); }},
    }}));
  }}
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
  for (const v of ["dashboard", "rules", "zones", "groups", "nat", "synproxy",
                   "interfaces", "routes", "bgp", "dhcp", "lb", "ipsec",
                   "wireguard", "pki", "certs", "ids", "capture", "ha", "users", "config",
                   "stack", "panel"]) {{
    $("view-" + v).classList.toggle("hidden", v !== view);
  }}
  const TITLES = {{
    rules: "Firewall rules", zones: "Zones", nat: "NAT",
    config: "Revisions", stack: "Stack", dashboard: "Dashboard",
    bgp: "BGP", ipsec: "IPsec", wireguard: "WireGuard", dhcp: "DHCP",
    groups: "Groups", synproxy: "SYN protection", interfaces: "Interfaces",
    routes: "Static routes", lb: "Load balancer", pki: "Authorities",
    certs: "Certificates", ids: "Intrusion defence", users: "Administrators",
    capture: "Packet capture", ha: "High availability",
  }};
  $("title").textContent = panel ? panel.t : (TITLES[view] || "Dashboard");

  if (view === "dashboard") return refreshDashboard();
  if (view === "rules") return refreshRules();
  if (view === "zones") return refreshZones();
  if (view === "nat") return refreshNat();
  if (view === "groups") return refreshGroups();
  if (view === "synproxy") return refreshSynproxy();
  if (view === "interfaces") return refreshInterfaces();
  if (view === "routes") return refreshRoutes();
  if (view === "lb") return refreshLb();
  if (view === "pki") return refreshPki();
  if (view === "certs") return refreshCerts();
  if (view === "ids") return refreshIds();
  if (view === "capture") return refreshCapture();
  if (view === "ha") return refreshHa();
  if (view === "users") return refreshUsers();
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
  buildSearchIndex();
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
$("navsearch").oninput = () => {{ buildNav(); renderMatches(); }};
$("togglerule").onclick = () => {{
  const panel = $("addrulepanel");
  panel.classList.toggle("hidden");
  $("togglerule").textContent = panel.classList.contains("hidden") ? "New rule" : "Cancel";
}};
$("defaultpolicy").onchange = (e) => {{
  const v = e.target.value;
  if (!v) return;
  stage("Default policy → " + v, ["set firewall global default-action " + v]);
  e.target.value = "";
}};
$("createrule").onclick = () => {{
  const name = $("n-name").value.trim();
  if (!name) {{ $("n-name").focus(); return; }}
  const lines = [];
  for (const [id, key] of [["n-from", "from"], ["n-to", "to"], ["n-action", "action"],
                           ["n-proto", "proto"], ["n-port", "port"],
                           ["n-source", "source"], ["n-dest", "destination"]]) {{
    const v = $(id).value.trim();
    if (v) lines.push(`set firewall rule ${{name}} ${{key}} ${{v}}`);
  }}
  stage("Firewall rule " + name, lines);
  $("addrulepanel").classList.add("hidden");
  $("togglerule").textContent = "New rule";
  for (const id of ["n-name", "n-port", "n-source", "n-dest"]) $(id).value = "";
}};
$("discard").onclick = () => {{ staged = []; renderStaged(); }};
$("applystaged").onclick = () => applyStaged(["commit", "save"]);
$("applystaged2").onclick = () => applyStaged(["commit", "save"]);
// Validating sends the staged commands with no commit: the appliance checks
// every one of them and writes nothing, which is how you find out that a change
// would be refused before it touches the box.
$("validate").onclick = () => applyStaged([]);
$("refresh").onclick = () => refresh();
$("allcounters").onchange = () => refreshDashboard();
wireToggle("toggleiface", "addifacepanel", "New");
wireToggle("toggleroute", "addroutepanel", "New");
wireToggle("togglegroup", "addgrouppanel", "New");
wireToggle("togglelb", "addlbpanel", "New");
wireToggle("toggleca", "addcapanel", "New");
wireToggle("togglecert", "addcertpanel", "New");
wireToggle("toggleuser", "adduserpanel", "New");
wireToggle("togglesyn", "addsynpanel", "New");
$("groupkind").onchange = () => refreshGroups();
$("liftall").onclick = () => clearOp("ids/blocks");
$("runcapture").onclick = async () => {{
  const btn = $("runcapture");
  // A capture takes as long as it takes; saying so beats a page that looks
  // frozen while an operator wonders whether it started.
  btn.disabled = true;
  btn.textContent = "Capturing…";
  $("capout").textContent = "Listening on " + $("cap-iface").value + "…";
  try {{
    const r = await api("/api/v1/capture", {{
      method: "POST",
      headers: {{ Authorization: "Bearer " + token, "Content-Type": "application/json" }},
      body: JSON.stringify({{
        interface: $("cap-iface").value,
        filter: $("cap-filter").value,
        packets: Number($("cap-count").value) || 50,
        seconds: Number($("cap-secs").value) || 10,
      }}),
    }});
    $("capout").textContent = (await r.text()).trimEnd();
  }} catch (e) {{
    $("capout").textContent = String(e.message || e);
  }}
  btn.disabled = false;
  btn.textContent = "Capture";
}};
wireToggle("togglesnat", "addsnatpanel", "New source rule");
wireToggle("toggleddnat", "adddnatpanel", "New port forward");
wireToggle("togglebgp", "addbgppanel", "New neighbour");
wireToggle("toggleipsec", "addipsecpanel", "New tunnel");
wireToggle("togglewg", "addwgpanel", "New interface");
wireToggle("togglewgpeer", "addwgpeerpanel", "New peer");
$("wgtunnel").onchange = () => refreshWireguard();
$("enabledhcp").onclick = () => {{
  const iface = $("dhcpiface").value;
  if (!iface) return;
  stage("Enable DHCP on " + iface, [`set interface ${{iface}} dhcp-server enable`]);
}};
$("runshow").onclick = async () => {{
  const words = $("showcmd").value.trim();
  if (!words) return;
  panel = {{ t: "show " + words, p: "/api/v1/show/" + words.split(/\s+/).map(encodeURIComponent).join("/") }};
  view = "panel";
  await refresh();
}};
$("cancel").onclick = () => $("editor").close();
$("resultclose").onclick = () => $("result").close();
$("applysave").onclick = () => {{
  const lines = script();
  if (!lines.length) {{ $("editorerr").textContent = "A rule needs a name and at least one setting."; return; }}
  $("editor").close();
  stage("Firewall rule " + $("r-name").value.trim(), lines);
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

    /// The console is operated, not typed into. Commands are how a change
    /// reaches the appliance — which is what puts every clicked edit through the
    /// same parser, validators and refusals as a typed one — but they are never
    /// the interface. If a command box or a raw-path editor comes back, this is
    /// the test that should have to be deleted on purpose.
    #[test]
    fn the_console_offers_no_command_surface() {
        let html = page();
        assert!(!html.contains("runScript"), "a command box is back");
        assert!(!html.contains("renderPreview"), "a command preview is back");
        assert!(!html.contains("cfgtable"), "the raw path editor is back");
        assert!(!html.contains("Run configuration commands"));
        // What the pending panel shows is the change, in words.
        assert!(
            html.contains("entry.label"),
            "staged changes are not described"
        );
    }

    /// The console is meant to be the whole management surface, so a section
    /// missing here is a thing an operator has to leave the browser for. This
    /// names them; adding a section means adding it here on purpose.
    #[test]
    fn every_configurable_area_has_a_section() {
        let html = page();
        for view in [
            "view-rules",
            "view-zones",
            "view-groups",
            "view-nat",
            "view-synproxy",
            "view-interfaces",
            "view-routes",
            "view-bgp",
            "view-dhcp",
            "view-lb",
            "view-ipsec",
            "view-wireguard",
            "view-pki",
            "view-certs",
            "view-ids",
            "view-users",
            "view-config",
            "view-stack",
        ] {
            assert!(html.contains(view), "{view} is missing");
        }
    }

    /// A search hit is only useful if it takes you where the thing can be
    /// changed, and every section that owns settings has to be reachable that
    /// way — otherwise searching finds objects it cannot open.
    #[test]
    fn search_maps_every_owned_setting_to_a_section() {
        let html = page();
        assert!(html.contains("function sectionFor"), "no owner mapping");
        assert!(
            html.contains("buildSearchIndex"),
            "search does not read the config"
        );
        // The specific owner must win over the general one: an interface's DHCP
        // block belongs to the DHCP view, not to Interfaces.
        assert!(
            html.contains(r#"path[2] === "dhcp-server" ? "dhcp" : "interfaces""#),
            "the more specific owner does not win"
        );
        for view in [
            "\"rules\"",
            "\"zones\"",
            "\"groups\"",
            "\"nat\"",
            "\"routes\"",
            "\"bgp\"",
            "\"ha\"",
            "\"ipsec\"",
            "\"wireguard\"",
            "\"lb\"",
            "\"pki\"",
            "\"certs\"",
            "\"users\"",
        ] {
            assert!(html.contains(view), "{view} is never a search destination");
        }
    }

    /// A capture holds a process open for as long as it runs, so it must be a
    /// POST — a GET that does that is one a browser or a proxy will repeat —
    /// and the page must say it is running rather than look frozen.
    #[test]
    fn a_capture_is_a_post_that_reports_it_is_running() {
        let html = page();
        assert!(html.contains(r#""/api/v1/capture""#));
        assert!(html.contains(r#"method: "POST""#));
        assert!(
            html.contains("Capturing…"),
            "the page looks frozen while it runs"
        );
    }

    /// The appliance answers in a terminal's voice: a refusal is followed by
    /// the whole `set` grammar. That is right at a prompt and wrong in a
    /// console — pasting it hands an operator a manual page instead of an
    /// answer — so the reply is read for what it says about *this* change.
    #[test]
    fn the_appliances_reply_is_summarised_not_pasted() {
        let html = page();
        assert!(
            html.contains("function summarise"),
            "the reply is shown raw"
        );
        assert!(
            html.contains("unknown set path"),
            "the grammar dump is not filtered"
        );
        assert!(
            !html.contains(r#"id="resultout"></pre>"#),
            "the result is a transcript"
        );
    }

    /// An operational action is not a staged change: it has already happened by
    /// the time it returns, and offering to discard it would be a lie. It also
    /// must not pretend to a capability the CLI lacks — there is no verb to
    /// *add* a run-time block, so the console does not offer one.
    #[test]
    fn operational_actions_are_separate_from_configuration() {
        let html = page();
        assert!(html.contains("function clearOp"), "no operational path");
        assert!(html.contains("/api/v1/clear/"), "clear is not reachable");
        assert!(
            !html.contains("Block now"),
            "the console invents a block verb"
        );
    }

    /// Every configurable thing renders through one path, so a zone, a tunnel
    /// and a DHCP server read alike and cannot disagree about how a setting is
    /// written. A section that grew its own renderer is the drift this guards.
    #[test]
    fn every_section_renders_through_the_same_object_language() {
        let html = page();
        assert!(
            html.contains("function objectCard"),
            "no shared object card"
        );
        assert!(
            html.contains("function renderObjects"),
            "no shared renderer"
        );
        for list in [
            "zonelist",
            "snatlist",
            "dnatlist",
            "bgplist",
            "ipseclist",
            "wglist",
            "wgpeerlist",
            "dhcplist",
        ] {
            assert!(html.contains(list), "{list} is not rendered as objects");
        }
        // The table era is over; a leftover would be a second language.
        assert!(!html.contains("editorTable"), "a table renderer is back");
    }

    /// An emptied field has to mean "no longer set", not "leave what was there"
    /// — otherwise a setting can be added from the console but never removed.
    #[test]
    fn clearing_a_field_removes_the_setting() {
        assert!(page().contains(r#"lines.push(`delete ${path} ${f[0]}`)"#));
    }

    /// Fields with a fixed vocabulary are chosen, not spelled. A zone typed by
    /// hand is the commonest way a rule ends up naming one that does not exist.
    #[test]
    fn bounded_fields_are_selects_over_the_real_vocabulary() {
        let html = page();
        assert!(
            html.contains("function zoneNames"),
            "zones are not enumerated"
        );
        assert!(html.contains("fillZoneSelect"), "zone fields are free text");
        assert!(
            html.contains(r#"<select id="n-action">"#),
            "action is free text"
        );
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
        assert!(
            html.contains("function stage(label, lines)"),
            "forms do not stage"
        );
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
