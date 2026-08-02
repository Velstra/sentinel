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
    // The light ramp, written once and applied twice — once for the system
    // preference, once for an explicit choice. A media query cannot join a
    // selector list, and a second hand-kept copy is exactly how the two
    // appearances drift apart, so the copy is made here instead.
    let light = r#"
      color-scheme: light;

      --bg-app: #f4f6fa; --surface: #ffffff;
      --surface-raised: #ffffff; --surface-sunken: #f2f5fa;
      --surface-hover: #e9eef7;
      /* The rail stays a shade off the page in both appearances: a console
         reads as navigation-plus-content, and two identical whites collapse
         that into one sheet. */
      --sidebar-bg: #edf1f8;
      --text-strong: #0b0e14; --text-body: #1d2431;
      --text-muted: #5b6779; --text-faint: #7a8699;
      --border: #dde3ec; --border-strong: #c6cfdc;
      --border-subtle: #e8edf4;
      --brand: var(--signal-600); --brand-hover: var(--signal-500);
      --brand-active: #2d5cc4; --focus-ring: var(--signal-600);
      --link: var(--signal-600);
      --green-500: #1a7f37; --amber-500: #9a6700; --red-500: #cf222e;
      --cyan-500: #1b7f9e;
      --product: #b06a00; --product-strong: #8a5200; --product-subtle: #fff4e0;
      --on-brand: #ffffff;

      --shadow-sm: 0 1px 2px rgba(16,24,40,.05);
      --shadow-md: 0 6px 16px rgba(16,24,40,.08);
      --shadow-lg: 0 18px 44px rgba(16,24,40,.14);
      --edge-top: inset 0 1px 0 rgba(255,255,255,.9);
      --glow-focus: 0 0 0 3px rgba(58,114,230,.22);
      --wash: radial-gradient(1100px 460px at 78% -12%, rgba(58,114,230,.10), transparent 62%);
"#;
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

     The dark ramp is the system's and is the default. A light one is derived
     below, because an enterprise console is used in daylight beside other
     documents and most operators' systems ask for one — it re-points the
     semantic tokens only, never the components.
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
    --surface-hover: var(--ink-600); --sidebar-bg: var(--ink-950);
    /* What text sits on a filled brand button, named rather than assumed: the
       dark ramp wants near-black on blue, the light one wants white. */
    --on-brand: var(--ink-950);
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
    --text-base: .875rem; --text-lg: 1.125rem; --text-xl: 1.5rem;
    --leading-tight: 1.1; --leading-snug: 1.28; --leading-normal: 1.55;
    --leading-code: 1.45;
    --tracking-tight: -.02em; --tracking-caps: .08em;

    --space-1: .25rem; --space-2: .5rem; --space-3: .75rem; --space-4: 1rem;
    --space-5: 1.25rem; --space-6: 1.5rem; --space-7: 2rem; --space-9: 3rem;
    --sidebar-w: 268px;

    /* The one gutter. Every label on the page — a group heading, the command a
       pane is showing — stands in a margin column of this width, so the page
       has exactly one left edge for labels and one for content. 180 + 28 is
       208, which is also the width the widest ordinary field takes: the
       measure is shared rather than invented twice. */
    --gutter: 180px; --gutter-gap: 28px;

    /* Square. Hairlines and space carry the structure here, not nested boxes
       with soft corners — a rounded rectangle inside a rounded rectangle is
       two frames around content that needed none. Only what is genuinely round
       (a status dot) keeps a radius. */
    --radius-xs: 0px; --radius-sm: 0px; --radius-md: 0px; --radius-lg: 0px;
    --radius-pill: 999px;

    --shadow-sm: 0 1px 2px rgba(0,0,0,.4);
    --shadow-md: 0 4px 12px rgba(0,0,0,.45);
    --shadow-lg: 0 12px 32px rgba(0,0,0,.5);
    --edge-top: inset 0 1px 0 rgba(255,255,255,.05);
    --glow-focus: 0 0 0 3px rgba(76,141,255,.35);
    /* A single cool wash behind the shell. Flat charcoal reads as a terminal;
       one light source is what makes a console read as a surface. */
    --wash: radial-gradient(1200px 520px at 82% -14%, rgba(76,141,255,.13), transparent 60%);

    --dur-fast: 130ms; --dur-base: 200ms;
    --ease: cubic-bezier(.2,.7,.3,1);
  }}

  /* ======================================================================
     A light ramp, because an enterprise console is used in daylight and
     alongside documents, and most operators' systems ask for one. The dark
     ramp above stays the default and the identity; this re-points the
     semantic tokens only, so every component below is written once and both
     appearances follow from it — a second set of component rules is how the
     two drift apart.

     Two applications of the same block: the system preference, and the
     operator's explicit choice from the header. An explicit dark choice has
     to beat a light system preference, which is what the :not() is for.
     ====================================================================== */
  @media (prefers-color-scheme: light) {{
    :root:not([data-theme="dark"]) {{ {light} }}
  }}
  :root[data-theme="light"] {{ {light} }}

  *, *::before, *::after {{ box-sizing: border-box; }}
  html {{ -webkit-text-size-adjust: 100%; }}
  body {{
    margin: 0; background: var(--bg-app); color: var(--text-body);
    background-image: var(--wash); background-repeat: no-repeat;
    background-attachment: fixed;
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
    /* Bounded, or forty section entries stand between the operator and the
       page — including the bar that carries the pending-change count. */
    aside {{ position: static !important; height: auto !important; max-height: 45vh; }}
  }}

  aside {{
    background: var(--sidebar-bg); border-right: 1px solid var(--border-subtle);
    position: sticky; top: 0; height: 100vh; overflow-y: auto;
    display: flex; flex-direction: column; gap: var(--space-1);
    padding: var(--space-5) var(--space-3);
  }}
  aside::-webkit-scrollbar {{ width: 10px; }}
  aside::-webkit-scrollbar-thumb {{
    background: color-mix(in srgb, var(--text-faint) 45%, transparent);
    border-radius: var(--radius-pill);
    border: 3px solid transparent; background-clip: content-box;
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
    background: var(--surface-hover); color: var(--text-strong);
  }}
  /* The current view is marked by a rail on its left edge rather than a fill,
     so the eye finds it without the sidebar turning into a block of colour. */
  aside button[aria-current="true"]::before {{
    content: ""; position: absolute; left: 0; top: 0; bottom: 0;
    width: 3px; background: var(--brand);
  }}

  main {{ padding: 0 var(--space-7) var(--space-9); max-width: 84rem; min-width: 0; }}

  /* The app bar. It stays put while the page scrolls, because the two things
     it carries — which appliance is being driven, and whether there are
     changes waiting to be applied — are the two things that must never scroll
     away from an operator mid-edit. */
  .bar {{
    position: sticky; top: 0; z-index: 20;
    display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap;
    margin: 0 calc(-1 * var(--space-7)) var(--space-5);
    padding: var(--space-4) var(--space-7);
    border-bottom: 1px solid var(--border-subtle);
    background: color-mix(in srgb, var(--bg-app) 82%, transparent);
    backdrop-filter: saturate(150%) blur(10px);
  }}
  .bar h2 {{ font-size: var(--text-lg); }}
  .iconbtn {{
    display: grid; place-items: center; width: 32px; height: 32px; flex: none;
    padding: 0; border-radius: var(--radius-sm); cursor: pointer;
    border: 1px solid var(--border-strong); background: var(--surface-raised);
    color: var(--text-muted);
  }}
  .iconbtn svg {{ width: 15px; height: 15px; }}
  .iconbtn:hover {{ color: var(--text-strong); background: var(--surface-hover); }}

  /* A page header per view: what this page is, one line saying what it is for,
     and the actions that belong to it. Toolbars alone left every screen looking
     like a fragment of a form — the difference between a console and a settings
     dialog is that a console tells you where you are. */
  .page {{
    display: flex; align-items: flex-start; gap: var(--space-4); flex-wrap: wrap;
    padding: var(--space-2) 0 var(--space-4);
    margin: 0 0 var(--space-2);
    border-bottom: 1px solid var(--border-strong);
  }}
  .page .headtext {{ flex: 1 1 26rem; min-width: 0; }}
  .page h2 {{
    font: var(--fw-semibold) 1.5rem/var(--leading-tight) var(--font-display);
    margin: 0 0 var(--space-2);
  }}
  /* Tables are read, not admired: a sticky header so the columns stay named
     while scrolling, tabular numerals so figures line up, and a hairline
     between rows instead of zebra stripes, which fight the status colours. */
  table {{ width: 100%; border-collapse: collapse; font-size: var(--text-sm); }}
  table th {{
    position: sticky; top: 0; z-index: 1;
    background: var(--surface); text-align: left;
    font: var(--fw-semibold) var(--text-2xs)/1.2 var(--font-mono);
    letter-spacing: var(--tracking-caps); text-transform: uppercase;
    color: var(--text-muted);
    padding: var(--space-2) var(--space-3);
    border-bottom: 1px solid var(--border);
  }}
  table td {{
    padding: var(--space-2) var(--space-3);
    border-bottom: 1px solid var(--border-subtle);
    font-variant-numeric: tabular-nums;
  }}
  table tr:last-child td {{ border-bottom: 0; }}
  table tbody tr:hover {{ background: var(--surface-sunken); }}

  /* A dot carries state faster than a word, and keeps the word for what the
     state is about. */
  .dot {{
    width: 7px; height: 7px; border-radius: 50%; display: inline-block;
    margin-right: var(--space-2); flex: none;
    background: var(--text-faint);
  }}
  .dot.up {{ background: var(--status-up); box-shadow: 0 0 0 3px color-mix(in srgb, var(--status-up) 20%, transparent); }}
  .dot.down {{ background: var(--status-down); box-shadow: 0 0 0 3px color-mix(in srgb, var(--status-down) 20%, transparent); }}
  .dot.warn {{ background: var(--status-warn); box-shadow: 0 0 0 3px color-mix(in srgb, var(--status-warn) 20%, transparent); }}

  .page p {{
    margin: 0; color: var(--text-muted); font-size: var(--text-sm);
    max-width: 66ch;
  }}
  /* The active item gets a rail rather than only a fill: at a glance down a
     long sidebar the eye finds an edge faster than a background. */
  /* A bar flush with the edge and a change of weight, not a rounded fill: at a
     glance down sixty entries the eye finds an edge faster than a background,
     and a pill floating inside the rail reads as a control rather than as
     "you are here". */
  aside button.on {{
    position: relative; background: var(--surface-hover); color: var(--text-strong);
    font-weight: var(--fw-semibold);
  }}
  aside button.on::before {{
    content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
    background: var(--brand);
  }}

  .spacer {{ margin-left: auto; }}

  .pill {{
    font: var(--fw-medium) var(--text-2xs)/1.6 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
    padding: 0 var(--space-2); border-radius: var(--radius-sm);
    border: 1px solid var(--border); color: var(--text-muted);
  }}
  .pill.up {{ color: var(--status-up); border-color: color-mix(in oklab, var(--status-up) 45%, transparent); }}
  .pill.down {{ color: var(--status-down); border-color: color-mix(in oklab, var(--status-down) 45%, transparent); }}

  /* --- surfaces --------------------------------------------------------- */
  .card {{
    border: 1px solid var(--border); border-radius: var(--radius-lg);
    background: var(--surface); box-shadow: var(--shadow-sm), var(--edge-top);
    padding: var(--space-5); margin: 0 0 var(--space-4);
  }}
  .card > h3 {{
    font: var(--fw-semibold) var(--text-2xs)/1.2 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
    color: var(--text-muted); margin: 0 0 var(--space-3);
  }}
  /* auto-fill, not auto-fit: two service tiles beside four counters stretched
     to half the page each and stopped reading as the same kind of thing. An
     empty column is better than a tile the width of a paragraph. */
  .cards {{
    display: grid; gap: var(--space-4);
    grid-template-columns: repeat(auto-fill, minmax(15rem, 1fr));
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
    margin: 0; overflow: auto; max-height: 32rem; white-space: pre;
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
  /* A tick box is not a text field: full width turns it into a stretched box
     with its label orphaned on the next line. */
  input[type="checkbox"], input[type="radio"] {{
    width: auto; min-width: 0; accent-color: var(--brand); margin: 0;
  }}
  .check {{
    display: inline-flex; align-items: center; gap: var(--space-2);
    font-size: var(--text-sm); color: var(--text-muted); cursor: pointer;
    margin-bottom: var(--space-3);
  }}
  input:focus, select:focus, textarea:focus {{
    outline: none; border-color: var(--brand); box-shadow: var(--glow-focus);
  }}
  button.btn {{
    cursor: pointer; background: var(--surface-raised); width: auto;
    white-space: nowrap;
  }}
  button.btn:hover {{ background: var(--surface-hover); color: var(--text-strong); }}
  button.primary {{
    background: var(--brand); border-color: var(--brand); color: var(--on-brand);
    font-weight: var(--fw-medium);
  }}
  button.primary:hover {{ background: var(--brand-hover); color: var(--on-brand); }}
  /* Destructive is quiet at rest. A list of forty rules with a red button on
     every row is forty alarms and no information; the label goes red only when
     the pointer or the keyboard is actually on it. */
  button.danger {{ color: var(--text-muted); }}
  button.danger:hover, button.danger:focus-visible {{
    color: var(--status-down); border-color: var(--status-down);
    background: color-mix(in srgb, var(--status-down) 10%, transparent);
  }}

  .row {{ display: flex; gap: var(--space-2); flex-wrap: wrap; align-items: center; }}
  .field {{ display: flex; flex-direction: column; gap: var(--space-1); }}
  .grid2 {{ display: grid; gap: var(--space-3); grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); }}
  /* The settings masks. Without this every panel was one column of full-width
     inputs — a form the length of the protocol rather than a page of it. */
  /* Fixed tracks, not stretched ones: with `1fr` two fields on a wide page sat
     half a screen apart with their inputs marooned at 208px inside a 528px
     cell. A column is the width of the thing in it, and the row ends where the
     fields end. */
  .grid {{
    display: grid; gap: var(--space-4) var(--space-5); align-items: end;
    grid-template-columns: repeat(auto-fill, 232px);
  }}
  @media (max-width: 620px) {{
    .grid {{ grid-template-columns: minmax(0, 1fr); }}
  }}
  /* A utility has to beat the component it is put on: `.staged` and `.addpanel`
     set `display` themselves, are defined further down, and so quietly won —
     which left the pending-changes card and every add panel on screen with
     nothing in them. */
  .hidden {{ display: none !important; }}
  /* The field that has to be filled, said where it is rather than only in the
     refusal you get after pressing the button. */
  /* A value the console can produce for you, offered beside the label. */
  /* A set of choices, ticked. */
  /* Each choice is its own control rather than a row of ticks inside a box:
     a bordered box holding bordered nothing is a frame around a frame, and the
     chips read as the pickable things they are. */
  .pick {{ display: flex; flex-wrap: wrap; gap: var(--space-2); }}
  .pickone {{
    display: inline-flex; align-items: center; gap: var(--space-2);
    padding: var(--space-1) var(--space-3);
    border: 1px solid var(--border-strong); border-radius: var(--radius-sm);
    background: var(--surface-sunken); color: var(--text-muted);
    font: var(--fw-regular) var(--text-sm)/1.7 var(--font-mono); cursor: pointer;
  }}
  .pickone:hover {{ border-color: var(--border-strong); color: var(--text-body); }}
  .pickone:has(input:checked) {{
    color: var(--text-strong); border-color: var(--brand);
    background: color-mix(in srgb, var(--brand) 10%, transparent);
  }}
  .suggest {{
    margin-left: var(--space-2); padding: 0 var(--space-2);
    border: 1px solid var(--border-strong); border-radius: var(--radius-pill);
    background: var(--surface-raised); color: var(--text-muted); cursor: pointer;
    font: var(--fw-medium) var(--text-2xs)/1.6 var(--font-mono);
    text-transform: none; letter-spacing: 0;
  }}
  .suggest:hover {{ color: var(--text-strong); border-color: var(--brand); }}
  .req {{
    margin-left: var(--space-2); color: var(--product-strong);
    font: var(--fw-medium) var(--text-2xs)/1.2 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
  }}
  .formerr {{ grid-column: 1 / -1; margin: var(--space-2) 0 0; font-size: var(--text-sm); }}
  /* What the value means, under the value. Small and quiet: it is an aid, and
     an aid that competes with the field is a distraction. */
  .hint {{ font: var(--fw-regular) var(--text-2xs)/1.4 var(--font-mono);
    color: var(--text-faint);
    /* Wrapping, not truncation: the answer is the whole point, and half a
       range ("10.0.0.0 – 10.255…") is worse than no answer at all. */
    overflow-wrap: anywhere;
  }}
  .hint:empty {{ min-height: 0; }}
  /* A group heading inside a settings mask. It stands in the margin column
     beside its fields rather than across them: a heading row every four fields
     is what turned a protocol's settings into a questionnaire. */
  .fieldgroup {{
    display: block; margin: 0;
    font: var(--fw-semibold) var(--text-2xs)/1.35 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
    color: var(--text-muted);
    padding-bottom: var(--space-2); border-bottom: 1px solid var(--border-strong);
  }}
  /* The command a pane is showing the output of. */
  .cmd {{
    display: block; margin: 0 0 var(--space-2);
    font: var(--fw-regular) var(--text-2xs)/1.4 var(--font-mono);
    color: var(--text-faint);
  }}
  .cmd::before {{ content: "$ "; opacity: .6; }}
  button:disabled {{ opacity: .5; cursor: not-allowed; }}
  .err {{ color: var(--status-down); white-space: pre-wrap; }}
  /* The banner carries two kinds of message and they must not look alike: a
     failure is red, a note about what to do next is not. */
  .note {{
    color: var(--text-body); white-space: pre-wrap;
    background: var(--surface-sunken);
    border-left: 3px solid var(--product);
  }}
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
    border-radius: var(--radius-sm); color: var(--ink-950);
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
  /* The input cancels the global ring, so the box it sits in shows the focus. */
  .search:focus-within {{ border-color: var(--brand); box-shadow: var(--glow-focus); }}

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
    border: 1px solid var(--border-subtle); border-radius: var(--radius-sm);
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
  .whoami {{
    display: flex; align-items: center; gap: var(--space-2);
    margin-top: var(--space-3); padding: 0 var(--space-1);
    font-size: var(--text-sm); color: var(--text-muted);
  }}
  .whoami span:nth-child(2) {{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
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
  .crumbs {{ display: flex; align-items: center; min-width: 0; flex: 1 1 220px; }}
  .crumbs .slug {{
    font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-muted);
    letter-spacing: .01em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }}

  /* --- staged changes ---------------------------------------------------- */
  .staged {{
    display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-4);
    border-radius: var(--radius-sm); border-color: color-mix(in oklab, var(--product) 40%, var(--border));
  }}
  .staged .tile {{
    display: grid; place-items: center; width: 34px; height: 34px; flex: none;
    border-radius: var(--radius-sm); background: var(--product-subtle); color: var(--product);
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

  /* The one surface that is about to change something, marked by an amber edge.
     It lays out nothing itself — the mask inside it brings its own groups and
     columns, and a grid wrapped in a grid is two layouts fighting over the same
     fields. */
  .addpanel {{
    display: block; border-radius: var(--radius-sm);
    border-color: var(--sentinel-600);
  }}
  .field > span:first-child {{
    font: var(--fw-medium) var(--text-xs)/1.2 var(--font-sans); color: var(--text-muted);
    text-transform: none; letter-spacing: 0;
  }}

  .mono {{
    font-family: var(--font-mono); font-size: var(--text-sm); color: var(--text-body);
    overflow-wrap: anywhere; min-width: 0;
  }}
  /* A remark under the thing it is about. */
  .sub {{ font-size: var(--text-2xs); color: var(--text-muted); }}

  /* The action is a badge because it changes what every other field means. */
  .act {{
    display: inline-flex; align-items: center; flex: none;
    padding: 1px var(--space-2); border-radius: var(--radius-sm);
    font: var(--fw-semibold) var(--text-2xs)/1.6 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
    border: 1px solid currentColor; white-space: nowrap;
  }}
  /* Within the denied family the difference is carried by SHAPE, not by hue:
     `drop` is filled, `reject` is a dashed outline. Allow against deny is
     therefore never a hue-matching exercise, and it still reads on a screen
     nobody calibrated, in a screenshot, and in greyscale. Amber is kept for
     caution alone — a rule that answers is not a warning. */
  /* No modifier: what a thing *is*. "Configured" is not a status and may not
     borrow a signal colour — that is how a console ends up green because a
     field is filled in. */
  .act {{ color: var(--text-muted); border-color: var(--border-strong); }}
  .act.warn {{
    color: var(--status-warn); background: color-mix(in srgb, var(--status-warn) 12%, transparent);
    border-color: currentColor;
  }}
  .act.accept {{ color: var(--status-up); background: color-mix(in srgb, var(--status-up) 12%, transparent); border-color: currentColor; }}
  .act.drop {{ color: var(--status-down); background: color-mix(in srgb, var(--status-down) 12%, transparent); }}
  .act.reject {{ color: var(--status-down); background: none; border-style: dashed; }}

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

  /* --- tabs --------------------------------------------------------------
     A section with seven protocols under it is a scroll, not a page. Tabs make
     the one being worked on the whole screen and keep its siblings one click
     away — and each tab is also a rail entry, so the nav and the strip are two
     ways into the same place rather than two different structures. */
  .tabs {{
    display: flex; gap: var(--space-1); flex-wrap: wrap;
    margin: 0 0 var(--space-5); padding: 0 0 1px;
    border-bottom: 1px solid var(--border-subtle);
    /* Horizontal scrolling drags a vertical scrollbar along with it in every
       engine that has one, and a 3px stub under a tab strip reads as a defect. */
    overflow-x: auto; overflow-y: hidden;
  }}
  .tabs button {{
    position: relative; cursor: pointer; background: none; border: 0;
    display: inline-flex; align-items: center; gap: var(--space-2);
    color: var(--text-muted); font: inherit; font-size: var(--text-sm);
    padding: var(--space-2) var(--space-3) var(--space-3);
    border-radius: var(--radius-sm) var(--radius-sm) 0 0;
  }}
  .tabs button svg {{ width: 14px; height: 14px; flex: none; opacity: .8; }}
  .tabs button:hover {{ color: var(--text-body); background: var(--surface-hover); }}
  .tabs button.on {{ color: var(--text-strong); font-weight: var(--fw-medium); }}
  .tabs button.on::after {{
    content: ""; position: absolute; left: var(--space-2); right: var(--space-2);
    bottom: -1px; height: 2px; border-radius: var(--radius-pill);
    background: var(--brand);
  }}
  /* A tab that already carries configuration says so, so an operator can see
     which of seven protocols is actually running without opening all seven. */
  /* A tab that already carries configuration says so — with a neutral mark.
     Configured is not a status, and a setting that borrows the colour of "up"
     tells an operator something the appliance never said. */
  .tabs button .live {{
    display: inline-block; width: 5px; height: 5px; margin-left: var(--space-2);
    border-radius: 50%; background: var(--text-faint); vertical-align: middle;
  }}

  /* --- rail groups --------------------------------------------------------
     Collapsible, because Routing alone is eleven entries once every protocol
     is listed, and a rail you have to scroll past is one you stop reading. */
  /* Group heads are the signs on a directory board: ruled off, so the eye can
     take the rail in as five short lists rather than as sixty lines. */
  nav .grouphead {{
    display: flex; align-items: center; gap: var(--space-2); width: 100%;
    background: none; cursor: pointer; color: var(--text-faint);
    font: var(--fw-semibold) var(--text-2xs)/1.2 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
    padding: var(--space-3) var(--space-3) var(--space-2);
    margin: var(--space-4) 0 var(--space-1);
    border: 0; border-bottom: 1px solid var(--border-subtle);
  }}
  nav .grouphead:hover {{ color: var(--text-muted); }}
  nav .grouphead svg {{
    width: 12px; height: 12px; margin-left: auto;
    transition: transform var(--dur-fast) var(--ease);
  }}
  nav .group.closed .grouphead svg {{ transform: rotate(-90deg); }}
  nav .group.closed .navitem {{ display: none; }}

  /* --- dashboard tiles ---------------------------------------------------- */
  .kpi {{
    display: flex; flex-direction: column; gap: var(--space-1);
    border: 1px solid var(--border); border-radius: var(--radius-lg);
    background: var(--surface); box-shadow: var(--shadow-sm), var(--edge-top);
    padding: var(--space-4) var(--space-5);
    transition: border-color var(--dur-fast) var(--ease),
                box-shadow var(--dur-fast) var(--ease);
  }}
  .kpi:hover {{ border-color: var(--border-strong); box-shadow: var(--shadow-md); }}
  .kpi .klabel {{
    font: var(--fw-semibold) var(--text-2xs)/1.2 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
    color: var(--text-muted);
  }}
  .kpi .kfoot {{ font-size: var(--text-xs); color: var(--text-faint); }}

  /* --- section headings inside a view ------------------------------------- */
  /* A heading and the control beside it belong on one line, centred — on a
     baseline the button hangs below the text it belongs to. */
  .section {{
    display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap;
    margin: var(--space-6) 0 var(--space-3);
    padding-bottom: var(--space-2);
    border-bottom: 1px solid var(--border-subtle);
  }}
  .section:first-child {{ margin-top: 0; }}
  .section h3 {{ font-size: var(--text-lg); }}
  .section p {{ color: var(--text-muted); font-size: var(--text-sm); }}
  .lede {{
    color: var(--text-muted); font-size: var(--text-sm);
    max-width: 66ch; margin: 0 0 var(--space-5);
  }}

  /* ======================================================================
     The gutter.

     Every label on a page — a group heading, the command a pane is showing the
     output of — leaves the flow of the thing it names and stands in a margin
     column of one fixed width. The page then has exactly one left edge for
     labels and one for content: a ruler laid against either side touches every
     item on it. The body keeps an uninterrupted measure instead of being
     broken every few centimetres by a heading row, which is what made a long
     section read as a stack of unrelated boxes.

     The sections themselves are separated by a hairline and space rather than
     by a border around each one. A box inside a box is two frames around
     content that needed none.
     ====================================================================== */
  .spread {{
    display: grid;
    grid-template-columns: var(--gutter) minmax(0, 1fr);
    column-gap: var(--gutter-gap);
    align-content: start;
    background: none; border: 0; box-shadow: none;
    border-top: 1px solid var(--border-subtle);
    padding: var(--space-7) 0 var(--space-5);
    margin: 0;
  }}
  .spread.first {{ border-top: 0; padding-top: var(--space-2); }}
  .spread > * {{ grid-column: 2; min-width: 0; }}
  .spread > .margin {{ grid-column: 1; }}
  .margin {{ min-width: 0; padding-top: 2px; }}
  .margin > h3 {{
    display: block; margin: 0;
    font: var(--fw-semibold) var(--text-2xs)/1.35 var(--font-mono);
    text-transform: uppercase; letter-spacing: var(--tracking-caps);
    color: var(--text-muted);
    padding-bottom: var(--space-2);
    border-bottom: 1px solid var(--border-strong);
  }}
  .margin > .cmd {{
    display: block; margin: var(--space-3) 0 0;
    font: var(--fw-regular) var(--text-2xs)/1.6 var(--font-mono);
    color: var(--text-muted); overflow-wrap: break-word;
  }}
  .sectionbar {{
    display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap;
    min-height: 2rem;
  }}
  .sectionbar button, .sectionbar select {{ width: auto; }}
  /* What belongs under a heading that stands in the margin keeps the content
     edge, so the page reads as two columns even where the markup is a stack. */
  .inset {{ margin-left: calc(var(--gutter) + var(--gutter-gap)); }}
  /* A rail, a gutter and a table of six columns do not fit on a laptop held
     sideways. Below the width where the margin column would start eating the
     content, the label simply goes back above what it names. */
  @media (max-width: 1180px) {{
    .spread {{ grid-template-columns: minmax(0, 1fr); }}
    .spread > *, .spread > .margin {{ grid-column: 1; }}
    .spread > .margin {{ margin-bottom: var(--space-3); }}
    .inset {{ margin-left: 0; }}
  }}

  /* --- object lists, set as a board --------------------------------------
     A list of named objects is a timetable: real column heads, one row per
     object, values in a face whose figures line up. The card list this
     replaces degraded as it grew — twelve cards are twelve little forms to be
     read across, and nothing above them says what the values mean. A board
     gets better with length rather than worse. */
  .tblwrap {{ overflow-x: auto; }}
  table.otbl {{ table-layout: auto; min-width: 100%; }}
  /* Not sticky here: the app bar is already pinned, and a second pinned strip
     sliding underneath it is a column head an operator cannot read. */
  table.otbl th {{ position: static; background: none; }}
  table.otbl td {{ vertical-align: middle; }}
  table.otbl td.mark {{
    box-shadow: inset 3px 0 0 var(--border-strong);
    padding-left: var(--space-4); width: 1%; white-space: nowrap;
  }}
  table.otbl tr.accept > td.mark {{ box-shadow: inset 3px 0 0 var(--status-up); }}
  table.otbl tr.warn > td.mark {{ box-shadow: inset 3px 0 0 var(--status-warn); }}
  table.otbl tr.drop > td.mark {{ box-shadow: inset 3px 0 0 var(--status-down); }}
  /* A rejection is a denial too, so it is red — but its bar is broken the way
     its chip is dashed, so the two denials are told apart without reading the
     hue at all. */
  table.otbl tr.reject > td.mark {{
    box-shadow: none;
    background-image: repeating-linear-gradient(180deg, var(--status-down) 0 4px, transparent 4px 9px);
    background-size: 3px 100%; background-repeat: no-repeat; background-position: left top;
  }}
  table.otbl td.end {{ text-align: right; white-space: nowrap; width: 1%; }}
  table.otbl td.end .btn {{ margin-left: var(--space-2); }}
  /* Administratively off: still listed, visibly not in force. */
  table.otbl tr.off > td {{ opacity: .55; }}
  table.otbl .val {{
    font-family: var(--font-mono); color: var(--text-strong);
    font-variant-numeric: tabular-nums; overflow-wrap: anywhere;
  }}
  table.otbl .val.dim {{ color: var(--text-muted); }}
  table.otbl .sub {{
    display: block; margin-top: 2px;
    font: var(--fw-regular) var(--text-2xs)/1.4 var(--font-mono); color: var(--text-faint);
  }}
  table.otbl td.ord {{
    font-family: var(--font-mono); color: var(--text-faint);
    font-variant-numeric: tabular-nums; width: 1%;
  }}
  /* The row that opens under an object being edited: the same field grid the
     add panel uses, in place — an operator should not have to learn two shapes
     for one job. */
  table.otbl tr.editrow > td {{
    padding: var(--space-4) var(--space-4) var(--space-5);
    background: var(--surface-sunken);
  }}
  table.otbl tr.editrow .addpanel {{ border: 0; background: none; padding: 0; margin: 0; }}
  .empty {{ color: var(--text-muted); font-size: var(--text-sm); padding: var(--space-4) 0; }}

  /* Fields are as wide as the data they hold. A port is five characters, and a
     box eighteen wide beside it says the console does not know what a port is;
     an address list needs the run. Uniform columns are how a mask stops being
     readable as a set of related facts. */
  .field.w-s input, .field.w-s select {{ max-width: 124px; }}
  .field.w-m input, .field.w-m select {{ max-width: 208px; }}
  .field.w-l {{ grid-column: span 2; }}

  /* --- the settings mask -------------------------------------------------
     A mask is a stack of groups; a group is a spread. The container it is put
     in lays out nothing, so the two never fight over the same fields. */
  .maskhost {{ display: block; }}
  .mask {{ display: block; }}
  /* A mask that starts with a heading has an empty leading row. */
  .mask > .grid:empty {{ display: none; }}
  .mask > .spread:first-child {{ border-top: 0; padding-top: 0; }}
  .mask > .spread:last-child {{ padding-bottom: 0; }}
  /* The controls that act on a mask, on a line of their own under it: sitting
     in the next field's cell, a button reads as another field. */
  .maskfoot {{
    display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap;
    margin-top: var(--space-5); padding-top: var(--space-4);
    border-top: 1px solid var(--border-subtle);
  }}
  .maskhost:has(.mask > .spread) > .maskfoot,
  .maskhost:has(.mask > .spread) > .formerr {{
    margin-left: calc(var(--gutter) + var(--gutter-gap));
  }}
  /* …but only where the mask opened the gutter itself. A mask inside a panel
     that is already indented has no margin column, so its foot has nothing to
     line up with. */
  .inset .maskfoot, .spread .maskfoot,
  .inset .formerr, .spread .formerr {{ margin-left: 0; }}
  @media (max-width: 1180px) {{
    .maskhost:has(.mask > .spread) > .maskfoot,
    .maskhost:has(.mask > .spread) > .formerr {{ margin-left: 0; }}
  }}
  /* A box that holds a mask is not a box: the mask's own groups carry the
     structure, and a frame around them is a frame around nothing. */
  .card.plain {{
    background: none; border: 0; box-shadow: none;
    padding: 0; margin: 0 0 var(--space-4);
  }}
  /* One gutter to a page. Where a spread ends up inside another one — a mask
     with groups inside a section that already has a margin — the inner label
     goes back above what it names rather than opening a second margin at
     416px. */
  .spread .spread, .inset .spread {{ grid-template-columns: minmax(0, 1fr); }}
  .spread .spread > *, .inset .spread > * {{ grid-column: 1; }}
  .spread .spread > .margin, .inset .spread > .margin {{ margin-bottom: var(--space-3); }}

  @media (prefers-reduced-motion: reduce) {{
    * {{ transition: none !important; animation: none !important; }}
  }}
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
  <!-- Signing in as somebody. The console used to ask only for the machine
       token, so in practice one secret was passed around and the accounts and
       permission groups on the box were configuration nobody could use. -->
  <form id="loginform">
    <div class="grid2" style="margin-bottom:var(--space-4)">
      <label class="field">
        <span>Username</span>
        <input id="username" autocomplete="username" placeholder="admin">
      </label>
      <label class="field">
        <span>Password</span>
        <input id="password" type="password" autocomplete="current-password">
      </label>
      <!-- Shown only once the appliance has said this account wants one, so an
           account without a second factor is not asked a question it has no
           answer to. -->
      <label class="field hidden" id="codefield">
        <span>One-time code</span>
        <input id="code" inputmode="numeric" autocomplete="one-time-code"
               maxlength="6" placeholder="000000">
      </label>
    </div>
    <button class="btn primary" type="submit" style="width:100%">Sign in</button>
  </form>

  <div id="tokenway" class="hidden" style="margin-top:var(--space-4)">
    <p style="margin:0 0 var(--space-3);color:var(--text-muted);font-size:var(--text-sm)">
      The management token — the same bearer token the API takes, and the way in
      before any account exists. Kept for this tab only and never written to disk.
    </p>
    <form class="row" id="tokenform">
      <input id="token" type="password" placeholder="management token" autocomplete="off"
             style="flex:1 1 14rem">
      <button class="btn" type="submit">Use token</button>
    </form>
  </div>
  <p id="loginerr" class="err" style="margin-top:var(--space-3)"></p>
  <button class="btn" id="tokentoggle"
          style="margin-top:var(--space-3);width:100%">Sign in with a token instead</button>
</section>

<div class="app hidden" id="app">
  <div id="banner" class="err hidden" style="grid-column:1/-1;padding:var(--space-3) var(--space-5);border-bottom:1px solid var(--border)"></div>
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

    <div class="whoami">
      <span class="dot up"></span>
      <span id="whoami">management token</span>
      <span class="pill warn hidden" id="permpill">read-only</span>
    </div>
    <button class="btn" id="signout" style="width:100%">Sign out</button>
  </aside>

  <main>
    <header class="bar">
      <!-- The bar says where you are and what is waiting to be applied; the
           page header below says what the page is. Two titles, one on top of
           the other, was the same word twice. -->
      <div class="crumbs">
        <span class="slug" id="crumb">appliance</span>
      </div>
      <span class="spacer"></span>
      <span class="pill" id="stagedbadge">no staged changes</span>
      <button class="iconbtn" id="refresh" title="Reload this page" aria-label="Reload this page">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v5h-5"/></svg>
      </button>
      <button class="iconbtn" id="theme" title="Appearance" aria-label="Appearance"></button>
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

    <div class="page" id="pagehead"></div>

    <div id="view-dashboard">
      <div class="cards" id="services"></div>
      <div class="cards" id="graphs"></div>
      <div class="card">
        <h3>Counters</h3>
        <label class="check">
          <input type="checkbox" id="allcounters">
          <span>Show counters that are still zero</span>
        </label>
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

      <!-- Built by `renderAddPanel` from the same field table as the editor. -->
      <div class="card addpanel hidden" id="addrulepanel"></div>

      <div id="rulelist"></div>
      <div class="card">
        <h3>What the rules have matched</h3>
        <pre class="out" id="rulesshow">…</pre>
      </div>
    </div>

    <div id="view-zones" class="hidden">
      <div class="card">
        <h3>Global posture</h3>
        <p class="lede" style="margin:0 0 var(--space-3)">
          What every zone inherits. A zone leaving a field unset takes the value
          from here — the same thing as leaving it out of the config.
        </p>
        <div class="addpanel" id="globalform"></div>
      </div>
      <div id="zonelist"></div>
    </div>

    <div id="view-nat" class="hidden">
      <div class="section">
        <h3>Source NAT</h3>
        <span class="spacer"></span>
        <button class="btn" id="togglesnat">New source rule</button>
      </div>
      <div class="card addpanel hidden" id="addsnatpanel"></div>
      <div id="snatlist"></div>

      <div class="section">
        <h3>Destination NAT</h3>
        <span class="spacer"></span>
        <button class="btn" id="toggleddnat">New port forward</button>
      </div>
      <div class="card addpanel hidden" id="adddnatpanel"></div>
      <div id="dnatlist"></div>

      <div class="card">
        <h3>NAT64</h3>
        <p class="lede" style="margin:0 0 var(--space-4)">
          Give an IPv6-only network its way to the IPv4 internet: hosts resolve a
          v4-only name to an address inside the prefix, and the appliance
          translates. DNS64 is what makes them ask for it — without it a
          v6-only client never learns an address in the prefix at all.
        </p>
        <div class="grid" id="nat64form"></div>
      </div>

      <div class="section">
        <h3>Prefix translation</h3>
        <span class="spacer"></span>
        <button class="btn" id="togglenpt">New translation</button>
      </div>
      <p class="lede inset" style="margin:0 0 var(--space-4)">
        NPTv6 swaps one IPv6 prefix for another as a packet leaves, and back on
        the way in. Addresses keep their host part and nothing is tracked, so
        this is not NAT: it is renumbering at the border, which is how a network
        with provider-assigned space keeps its own addressing inside.
      </p>
      <div class="card addpanel hidden" id="addnptpanel"></div>
      <div id="nptlist"></div>

      <div class="card">
        <h3>Live NAT state</h3><pre class="out" id="natshow">…</pre>
      </div>
    </div>


    <div id="view-ipsec" class="hidden">
      <div class="section">
        <h3>Site-to-site tunnels</h3>
        <span class="spacer"></span>
        <button class="btn" id="toggleipsec">New tunnel</button>
      </div>
      <div class="card addpanel hidden" id="addipsecpanel"></div>
      <div id="ipseclist"></div>
      <div class="card">
        <h3>Security associations</h3><pre class="out" id="ipsecshow">…</pre>
      </div>
    </div>

    <div id="view-wireguard" class="hidden">
      <div class="section">
        <h3>Interfaces</h3>
        <span class="spacer"></span>
        <button class="btn" id="togglewg">New interface</button>
      </div>
      <div class="card addpanel hidden" id="addwgpanel"></div>
      <div id="wglist"></div>
      <p class="lede" style="margin:var(--space-3) 0 var(--space-6)">
        A private key is generated on the appliance — set it to
        <code>generate</code> rather than pasting a key into a browser.
      </p>

      <div class="section">
        <h3>Peers</h3>
        <span class="spacer"></span>
        <label class="inline"><span>on</span><select id="wgtunnel"></select></label>
        <button class="btn" id="togglewgpeer">New peer</button>
      </div>
      <div class="card addpanel hidden" id="addwgpeerpanel"></div>
      <div id="wgpeerlist"></div>
      <div class="card">
        <h3>Live tunnels</h3><pre class="out" id="wgshow">…</pre>
      </div>
    </div>

    <div id="view-history" class="hidden">
      <p class="lede" style="margin:0 0 var(--space-5)">
        What the box looked like before now. Live counters answer what is
        happening; they cannot answer whether this was happening at three in the
        morning last Tuesday, which is the question people actually arrive with.
        A gap in a line is a gap in the record — the box was off, or the
        interface went away — and is drawn as one rather than joined up.
      </p>
      <div class="toolbar">
        <label class="inline"><span>Resolution</span>
          <select id="historyres">
            <option value="minute">Last day, by minute</option>
            <option value="quarter">Last month, by quarter hour</option>
            <option value="day">Two years, by day</option>
          </select>
        </label>
      </div>
      <div id="historycharts"></div>
    </div>

    <div id="view-dhcp" class="hidden">
      <div class="section">
        <h3>Servers</h3>
        <span class="spacer"></span>
        <label class="inline"><span>on</span><select id="dhcpiface"></select></label>
        <button class="btn" id="enabledhcp">Enable</button>
      </div>
      <div id="dhcplist"></div>
      <p class="lede" style="margin:var(--space-3) 0 var(--space-6)">
        A server leases from its interface's own static subnet, so the interface
        needs a static address first.
      </p>

      <div class="section">
        <h3>Reservations</h3>
        <span class="spacer"></span>
        <label class="inline"><span>on</span><select id="mapiface"></select></label>
        <button class="btn" id="togglemap">New</button>
      </div>
      <p class="lede inset" style="margin:0 0 var(--space-4)">
        The same address every time, for a machine that has to be findable. The
        address must be in the server's subnet but outside its pool, or the
        server will hand it to somebody else as well.
      </p>
      <div class="card addpanel hidden" id="addmappanel"></div>
      <div id="maplist"></div>

      <div class="section">
        <h3>Router advertisements</h3>
        <span class="spacer"></span>
        <label class="inline"><span>on</span><select id="raiface"></select></label>
        <button class="btn" id="enablera">Enable</button>
      </div>
      <p class="lede inset" style="margin:0 0 var(--space-4)">
        How IPv6 hosts learn there is a router and what prefix to use. Managed
        sends them to DHCPv6 for an address as well; other-config sends them
        there for everything but the address.
      </p>
      <div id="ralist"></div>

      <div class="card"><h3>Leases</h3><pre class="out" id="dhcpshow">…</pre></div>
    </div>

    <div id="view-interfaces" class="hidden">
      <div class="section">
        <h3>Interfaces</h3>
        <span class="spacer"></span>
        <button class="btn" id="toggleiface">New</button>
      </div>
      <div class="card addpanel hidden" id="addifacepanel"></div>
      <div id="ifacelist"></div>
      <div class="card">
        <h3>Live state</h3><pre class="out" id="ifaceshow">…</pre>
      </div>
    </div>


    <div id="view-groups" class="hidden">
      <div class="toolbar">
        <label class="inline"><span>Kind</span>
          <select id="groupkind">
            <option value="address-group">address</option>
            <option value="port-group">port</option>
            <option value="domain-group">domain</option>
            <option value="feed-group">published list</option>
          </select>
        </label>
        <span class="spacer"></span>
        <button class="btn" id="togglegroup">New</button>
      </div>
      <div class="card addpanel hidden" id="addgrouppanel"></div>
      <div id="grouplist"></div>
      <p class="lede" style="margin:var(--space-3) 0 0">
        A group is referenced by a rule's source, destination or port field, so
        one edit here moves every rule that names it.
      </p>
    </div>

    <div id="view-lb" class="hidden">
      <div class="section">
        <h3>Load-balanced services</h3>
        <span class="spacer"></span>
        <button class="btn" id="togglelb">New</button>
      </div>
      <div class="card addpanel hidden" id="addlbpanel"></div>
      <div id="lblist"></div>
      <div class="card">
        <h3>Live state</h3><pre class="out" id="lbshow">…</pre>
      </div>
    </div>

    <div id="view-pki" class="hidden">
      <div class="section">
        <h3>Certificate authorities</h3>
        <span class="spacer"></span>
        <button class="btn" id="toggleca">New</button>
      </div>
      <div class="card addpanel hidden" id="addcapanel"></div>
      <div id="calist"></div>
      <div class="card">
        <h3>Automatic issuance</h3>
        <p class="lede" style="margin:0 0 var(--space-4)">
          A certificate with <code>ca = "acme"</code> is obtained from this
          directory instead of signed here. The appliance has to be reachable
          for the challenge it agrees to answer.
        </p>
        <div class="grid" id="acmeform"></div>
      </div>
    </div>

    <div id="view-certs" class="hidden">
      <div class="section">
        <h3>Certificates</h3>
        <span class="spacer"></span>
        <button class="btn" id="togglecert">New</button>
      </div>
      <div class="card addpanel hidden" id="addcertpanel"></div>
      <div id="certlist"></div>
      <div class="card">
        <h3>On disk</h3><pre class="out" id="pkishow">…</pre>
      </div>
    </div>

    <div id="view-users" class="hidden">
      <div class="section">
        <h3>Administrators</h3>
        <span class="spacer"></span>
        <button class="btn" id="toggleuser">New</button>
      </div>
      <div class="card addpanel hidden" id="adduserpanel"></div>
      <div id="userlist"></div>
      <p class="lede" style="margin:var(--space-3) 0 var(--space-6)">
        An account without a group can log in to the box and reach nothing
        through this console or the API. Shell access and management access are
        separate grants on purpose — otherwise every operator who needed to read
        a rule would have a shell.
      </p>

      <div class="section">
        <h3>Permission groups</h3>
        <span class="spacer"></span>
        <button class="btn" id="toggleadmingroup">New group</button>
      </div>
      <div class="card addpanel hidden" id="addadmingrouppanel"></div>
      <div id="admingrouplist"></div>

      <div class="card">
        <h3>Where a password is checked</h3>
        <p class="lede" style="margin:0 0 var(--space-4)">
          A local account list is a shadow account list: it has to be kept
          alongside the real one, and it is the one nobody remembers to remove
          somebody from. A server here answers instead — but the local password
          is always tried first, because the moment a directory is unreachable
          is exactly the moment somebody needs to get in.
        </p>
        <div class="grid" id="aaa-form"></div>
      </div>
      <div class="section">
        <h3>Authentication servers</h3>
        <span class="spacer"></span>
        <button class="btn" id="toggleradius">New server</button>
      </div>
      <div class="card addpanel hidden" id="addradiuspanel"></div>
      <div id="radiuslist"></div>

      <div class="card">
        <h3>Accounts as the appliance sees them</h3>
        <pre class="out" id="usersshow">…</pre>
      </div>
      <p class="lede" style="margin:var(--space-3) 0 0">
        Two levels, deliberately: read-only may read everything and change
        nothing, read-write may do anything the CLI can. A finer split invites
        the question "may this person change <em>that</em> setting", which on a
        firewall is a question about the ruleset rather than about the person.
      </p>
    </div>

    <div id="view-synproxy" class="hidden">
      <div class="section">
        <h3>SYN-protected ports</h3>
        <span class="spacer"></span>
        <button class="btn" id="togglesyn">New</button>
      </div>
      <div class="card addpanel hidden" id="addsynpanel"></div>
      <div id="synlist"></div>
      <p class="lede" style="margin:var(--space-3) 0 0">
        The firewall answers every SYN to these ports itself and only opens the
        real connection once a client returns its cookie. Protected connections
        lose window scaling, SACK and timestamps — protect where a flood is the
        greater risk.
      </p>
    </div>

    <div id="view-ids" class="hidden">
      <div class="section">
        <h3>Run-time blocks</h3>
        <span class="spacer"></span>
        <button class="btn" id="liftall">Lift every block</button>
      </div>
      <p class="lede" style="margin:0 0 var(--space-4)">
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
      <div class="section">
        <h3>Virtual router groups</h3>
        <span class="spacer"></span>
        <button class="btn" id="togglevrrp">New</button>
      </div>
      <p class="lede">
        A tracked interface is what makes failover mean something: when it goes
        down this box lowers its own priority by the decrement, and the peer —
        which did not lose that link — takes the address.
      </p>
      <div class="card addpanel hidden" id="addvrrppanel"></div>
      <div id="vrrplist"></div>

      <div class="section"><h3>What the other box knows</h3></div>
      <div class="card">
        <h3>Configuration sync</h3>
        <p class="lede" style="margin:0 0 var(--space-4)">
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
        <p class="lede" style="margin:0 0 var(--space-4)">
          Without this a failover is a reconnect for every session in flight:
          the standby takes the address and then drops the traffic, because it
          has no state for connections it never saw start. With it, the flow
          table is pushed to the peer continuously.
        </p>
        <div class="grid" id="conntracksyncform"></div>
      </div>

      <div class="card"><h3>Live state</h3><pre class="out" id="vrrpshow">…</pre></div>
    </div>





    <div id="view-qos" class="hidden">
      <p class="lede" style="margin:0 0 var(--space-4)">
        Shaping belongs on the link that is actually congested — the uplink, on
        the way out. Set the bandwidth slightly <em>below</em> what the line
        really carries: the point is to hold the queue here, where it can be
        managed, instead of in the modem, where it cannot.
      </p>
      <label class="field" style="max-width:20rem">
        <span>Interface</span><select id="qosiface"></select>
      </label>
      <div class="card"><h3>Discipline</h3><div class="grid" id="qosform"></div></div>
      <div class="card"><h3>Live queues</h3><pre class="out" id="qosshow">…</pre></div>
    </div>

    <div id="view-wan" class="hidden">
      <div class="card">
        <h3>Mode</h3>
        <p class="lede" style="margin:0 0 var(--space-4)">
          Failover uses the highest-priority uplink that is up; load-balance
          spreads new connections across them by weight. An uplink with no health
          check is assumed up, which is what makes a check worth configuring.
        </p>
        <div class="grid" id="wan-mode"></div>
      </div>
      <div class="section">
        <h3>Uplinks</h3>
        <span class="spacer"></span>
        <button class="btn" id="togglewan">New uplink</button>
      </div>
      <div class="card addpanel hidden" id="addwanpanel"></div>
      <div id="wanlist"></div>

      <div class="section">
        <h3>Steering</h3>
        <span class="spacer"></span>
        <button class="btn" id="togglewanpolicy">New policy</button>
      </div>
      <p class="lede inset" style="margin:0 0 var(--space-4)">
        Failover answers "the uplink died, now what". Steering answers the
        question before it: this traffic belongs on that uplink, and moves only
        when the uplink stops being good enough for it. A video call and a backup
        want opposite things from the same two links, and priority alone cannot
        say so — which is why the uplinks above carry limits as well as targets.
      </p>
      <div class="card addpanel hidden" id="addwanpolicypanel"></div>
      <div id="wanpolicylist"></div>

      <div class="card"><h3>Live state</h3><pre class="out" id="wanshow">…</pre></div>
    </div>

    <div id="view-openconnect" class="hidden">
      <p class="lede" style="margin:0 0 var(--space-5)">
        The road-warrior server: a client connects with a username and password
        and lands in the zone named below. IPsec and WireGuard next door are
        site-to-site — this is the one people carry.
      </p>
      <div class="card"><h3>Server</h3><div class="grid" id="oc-server"></div></div>
      <div class="section">
        <h3>Accounts</h3>
        <span class="spacer"></span>
        <button class="btn" id="toggleocuser">New account</button>
      </div>
      <div class="card addpanel hidden" id="addocuserpanel"></div>
      <div id="oculist"></div>
      <div class="card">
        <h3>Live state</h3><pre class="out" id="ocshow">…</pre>
      </div>
    </div>

    <!-- Both of these are lists of numbered rules, not flat objects: the CLI
         path is `policy prefix-list <name> rule <seq> …`, and a mask that wrote
         `policy prefix-list <name> prefix …` was a section in which nothing
         could be created at all. The list is picked once, above, the way a
         WireGuard interface is. -->
    <div id="view-routepolicy" class="hidden">
      <div class="tabs" id="tabs-routepolicy"></div>

      <div class="tabpane hidden" data-tab="prefix">
        <p class="lede">
          A named set of prefixes a route map or a neighbour filter points at.
          Rules are read in sequence order, and <code>ge</code>/<code>le</code>
          widen one to a range of lengths. A list exists once it has a rule.
        </p>
        <div class="toolbar">
          <label class="inline"><span>List</span><select id="pllist-pick"></select></label>
          <input id="plnew" placeholder="or a new list name" style="max-width:14rem">
          <span class="spacer"></span>
          <button class="btn" id="togglepl">New rule</button>
        </div>
        <div class="card addpanel hidden" id="addplpanel"></div>
        <div id="pllist"></div>
      </div>

      <div class="tabpane hidden" data-tab="maps">
        <p class="lede">
          What is accepted, and what is changed on the way through. Each rule
          matches and then sets; the map's default decides what happens to a
          route no rule matched.
        </p>
        <div class="toolbar">
          <label class="inline"><span>Map</span><select id="rmlist-pick"></select></label>
          <input id="rmnew" placeholder="or a new map name" style="max-width:14rem">
          <span class="spacer"></span>
          <button class="btn" id="togglerm">New rule</button>
        </div>
        <div class="card"><h3>Map</h3><div class="grid" id="rmglobal"></div></div>
        <div class="card addpanel hidden" id="addrmpanel"></div>
        <div id="rmlist"></div>
      </div>

      <div class="tabpane hidden" data-tab="pbr">
        <p class="lede">
          Ordinary routing asks one question: where is this going? These rules
          ask the others — where it came from, over which link, to which port —
          and send the answer to a different routing table. That is how a guest
          network leaves by the cheap uplink while everything else takes the
          good one.
        </p>
        <div class="section">
          <h3>Rules</h3>
          <span class="spacer"></span>
          <button class="btn" id="togglepbr">New rule</button>
        </div>
        <div class="card addpanel hidden" id="addpbrpanel"></div>
        <div id="pbrlist"></div>
        <div class="card">
          <h3>In the kernel</h3><pre class="out" id="show-pbr">…</pre>
        </div>
      </div>
    </div>

    <div id="view-system" class="hidden">
      <div class="card"><h3>Identity</h3><div class="grid" id="sys-ident"></div></div>
      <div class="section">
        <h3>Kernel parameters</h3>
        <span class="spacer"></span>
        <button class="btn" id="togglesysctl">New</button>
      </div>
      <div class="card addpanel hidden" id="addsysctlpanel"></div>
      <div id="sysctllist"></div>
      <p class="lede" style="margin:var(--space-3) 0 var(--space-6)">
        The settings this schema has no opinion about. Only <code>net.*</code>
        and <code>vm.*</code> — everything else on a firewall is a way to make
        the box unbootable from a file it reads at start-up.
        <code>net.ipv4.ip_nonlocal_bind</code> is the usual one: it lets a
        service bind a virtual address this box does not hold right now, which
        is exactly where a VRRP backup stands.
      </p>
      <div class="card">
        <h3>Update channel</h3>
        <p class="lede" style="margin:0 0 var(--space-4)">
          Where signed images come from, and the key their manifest must be
          signed with. Without the key nothing is installed — the channel is a
          URL, the trust is the key.
        </p>
        <div class="grid" id="sys-update"></div>
      </div>
      <div class="card"><h3>Version</h3><pre class="out" id="sysshow">…</pre></div>
    </div>

    <!-- Interior routing. One view, one tab per protocol: an appliance that
         speaks seven of them must not stack seven forms on one scroll, and the
         rail lists the same seven so either way in lands on the same page. -->
    <div id="view-routing" class="hidden">
      <div class="tabs" id="tabs-routing"></div>

      <div class="tabpane hidden" data-tab="static">
        <p class="lede">
          Routes written by hand. They win over anything a protocol learns, which
          is what makes them useful and what makes a forgotten one hard to find.
        </p>
        <div class="section">
          <h3>Routes</h3>
          <span class="spacer"></span>
          <button class="btn" id="toggleroute">New</button>
        </div>
        <div class="card addpanel hidden" id="addroutepanel"></div>
        <div id="routelist"></div>
        <div class="card"><h3>Live state</h3><pre class="out" id="routeshow">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="bgp">
        <p class="lede">
          The exterior protocol: who this appliance is to another network, the
          neighbours it says it to, and what came of that. A neighbour without a
          remote AS is not a session.
        </p>
        <div class="card"><div class="grid" id="bgpglobal"></div></div>
        <div class="card"><div class="grid" id="bgpconfed"></div></div>
        <div class="card"><div class="grid" id="bgprpki"></div></div>
        <div class="section">
          <h3>Aggregates</h3>
          <span class="spacer"></span>
          <button class="btn" id="toggleagg">New aggregate</button>
        </div>
        <p class="lede inset" style="margin:0 0 var(--space-4)">
          One prefix announced in place of the more specific ones inside it.
          Summary-only suppresses those; without it both go out, which is a
          bigger table for the same reachability.
        </p>
        <div class="card addpanel hidden" id="addaggpanel"></div>
        <div id="agglist"></div>
        <div class="section">
          <h3>Route origin authorisations</h3>
          <span class="spacer"></span>
          <button class="btn" id="toggleroa">New authorisation</button>
        </div>
        <p class="lede inset" style="margin:0 0 var(--space-4)">
          Which AS may originate a prefix, stated locally rather than fetched
          from a validator. Useful where there is no RTR server to ask.
        </p>
        <div class="card addpanel hidden" id="addroapanel"></div>
        <div id="roalist"></div>
        <div class="section">
          <h3>Neighbours</h3>
          <span class="spacer"></span>
          <button class="btn" id="togglebgp">New neighbour</button>
        </div>
        <div class="card addpanel hidden" id="addbgppanel"></div>
        <div id="bgplist"></div>
        <div class="card"><h3>Sessions</h3><pre class="out" id="bgpshow">…</pre></div>
        <div class="card"><h3>Routes received</h3><pre class="out" id="bgproutes">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="ospf">
        <p class="lede">
          The interior protocol most networks are built on: a link-state view of
          one area, or several joined at this box. It is off until it is given an
          interface to speak on.
        </p>
        <div class="card"><div class="grid" id="igp-ospf"></div></div>
        <div class="card"><h3>Neighbours</h3><pre class="out" id="show-ospf">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="ospf3">
        <p class="lede">
          OSPF for IPv6. It is a separate protocol with its own adjacencies, not
          an address family of the one above — running both is normal.
        </p>
        <div class="card"><div class="grid" id="igp-ospf3"></div></div>
        <div class="card"><h3>Neighbours</h3><pre class="out" id="show-ospf3">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="isis">
        <p class="lede">
          Link-state routing that carries both address families over one set of
          adjacencies. The system ID and area are what an adjacency is formed on,
          so they are set before an interface is added.
        </p>
        <div class="card"><div class="grid" id="igp-isis"></div></div>
        <div class="card"><h3>Adjacencies</h3><pre class="out" id="show-isis">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="rip">
        <p class="lede">
          Distance-vector, and bounded to fifteen hops by design. It is here for
          the networks that still speak it, not as a first choice.
        </p>
        <div class="card"><div class="grid" id="igp-rip"></div></div>
        <div class="card"><h3>State</h3><pre class="out" id="show-rip">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="ripng">
        <p class="lede">RIP for IPv6, with the same reach and the same limits.</p>
        <div class="card"><div class="grid" id="igp-ripng"></div></div>
        <div class="card"><h3>State</h3><pre class="out" id="show-ripng">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="babel">
        <p class="lede">
          Distance-vector built for links that come and go — wireless, and meshes
          where the cost of a path is not the number of hops.
        </p>
        <div class="card"><div class="grid" id="igp-babel"></div></div>
        <div class="card"><h3>State</h3><pre class="out" id="show-babel">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="bfd">
        <p class="lede">
          Sub-second failure detection the protocols beside it subscribe to with
          their own <code>bfd</code> field. On its own it detects nothing.
        </p>
        <div class="card"><div class="grid" id="igp-bfd"></div></div>
        <div class="card"><h3>Sessions</h3><pre class="out" id="show-bfd">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="multicast">
        <p class="lede">
          Multicast is not forwarded by default: a router has to be told to
          listen for the reports that say who wants a group. IGMP is the IPv4
          half, MLD the IPv6 one, and an interface is either facing receivers or
          facing the source.
        </p>
        <div class="card"><div class="grid" id="mcastform"></div></div>
        <div class="section">
          <h3>Interfaces</h3>
          <span class="spacer"></span>
          <button class="btn" id="togglemcastif">New</button>
        </div>
        <div class="card addpanel hidden" id="addmcastifpanel"></div>
        <div id="mcastiflist"></div>
        <div class="card">
          <h3>Forwarding cache</h3><pre class="out" id="show-multicast">…</pre>
        </div>
      </div>

      <div class="tabpane hidden" data-tab="vrf">
        <p class="lede">
          A separate routing table with its own interfaces, so two tenants can
          use the same addresses without meeting. Route targets are what let
          something deliberately cross between them.
        </p>
        <div class="section">
          <h3>Instances</h3>
          <span class="spacer"></span>
          <button class="btn" id="togglevrf">New VRF</button>
        </div>
        <div class="card addpanel hidden" id="addvrfpanel"></div>
        <div id="vrflist"></div>
        <div class="card"><h3>Instances</h3><pre class="out" id="show-vrf">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="table">
        <p class="lede">
          What the protocols above actually agreed on. A route is here once, no
          matter how many of them offered it — this is the answer, not the
          argument.
        </p>
        <div class="card"><h3>Routing table</h3><pre class="out" id="igpshow">…</pre></div>
      </div>
    </div>

    <!-- Fourteen services on one scroll was a list, not a page. They group the
         way an operator thinks about them: what answers questions, what lets
         you in, what hands out addresses, what publishes, what tells you. -->
    <div id="view-services" class="hidden">
      <div class="tabs" id="tabs-services"></div>

      <div class="tabpane hidden" data-tab="resolution">
        <p class="lede">
          Each of these is off until it is given something to do — an upstream, an
          interface, a target. Staging a field and committing is what starts the
          service; clearing the fields is what stops it.
        </p>
        <div class="card"><h3>DNS resolver</h3><div class="grid" id="svc-dns"></div></div>
        <div class="card"><h3>NTP</h3><div class="grid" id="svc-ntp"></div></div>
      </div>

      <div class="tabpane hidden" data-tab="management">
        <p class="lede">
          How the box itself is reached and read. Every one of these is a way in
          or a way out — none of them should be listening on an untrusted zone.
        </p>
        <div class="card"><h3>SSH access</h3><div class="grid" id="svc-ssh"></div></div>
        <div class="card"><h3>SNMP (read-only)</h3><div class="grid" id="svc-snmp"></div></div>
        <div class="card"><h3>LLDP</h3><div class="grid" id="svc-lldp"></div></div>
      </div>

      <div class="tabpane hidden" data-tab="addressing">
        <p class="lede">
          Addresses and names for the segments behind this box — relayed to a
          server elsewhere, reflected across segments, or published upstream.
        </p>
        <div class="card"><h3>DHCP relay</h3><div class="grid" id="svc-dhcprelay"></div></div>
        <div class="card"><h3>Dynamic DNS</h3><div class="grid" id="svc-dyndns"></div></div>
        <div class="card"><h3>mDNS reflector</h3><div class="grid" id="svc-mdns"></div></div>
      </div>

      <div class="tabpane hidden" data-tab="publishing">
        <p class="lede">
          What this box puts in front of something else: a name terminated here,
          a broadcast carried across a segment boundary, a guest held at a login,
          a port an inside host asked for.
        </p>
        <div class="section">
          <h3>Reverse proxy</h3>
          <span class="spacer"></span>
          <button class="btn" id="togglerp">New frontend</button>
        </div>
        <div class="card addpanel hidden" id="addrppanel"></div>
        <div id="rplist"></div>

        <div class="section">
          <h3>Broadcast relays</h3>
          <span class="spacer"></span>
          <button class="btn" id="togglebr">New relay</button>
        </div>
        <div class="card addpanel hidden" id="addbrpanel"></div>
        <div id="brlist"></div>

        <div class="card"><h3>Captive portal</h3><div class="grid" id="svc-portal"></div></div>
        <div class="card"><h3>Who is admitted</h3><pre class="out" id="portalshow">…</pre></div>
        <div class="card"><h3>Port mapping (NAT-PMP)</h3><div class="grid" id="svc-portmap"></div></div>
        <div class="card"><h3>Mappings open now</h3><pre class="out" id="portmapshow">…</pre></div>
      </div>

      <div class="tabpane hidden" data-tab="notification">
        <p class="lede">
          Where this appliance speaks up. An alert is sent when a watched unit
          fails; the journal is forwarded continuously, whether or not anything
          is wrong.
        </p>
        <div class="card">
          <h3>Alerts</h3>
          <p class="lede" style="margin-bottom:var(--space-4)">
            Webhooks are a space-separated list; the mail relay below is optional.
          </p>
          <div class="grid" id="svc-alerts"></div>
        </div>
        <div class="card"><h3>Alert mail</h3><div class="grid" id="svc-alertmail"></div></div>

        <div class="section">
          <h3>Syslog collectors</h3>
          <span class="spacer"></span>
          <button class="btn" id="togglesl">New collector</button>
        </div>
        <div class="card addpanel hidden" id="addslpanel"></div>
        <div id="sllist"></div>
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
      <p class="lede" style="margin:0 0 var(--space-4)">
        Bounded on purpose: never more than 500 packets or 60 seconds, headers
        only, and nothing is written to disk. A capture that finds nothing is an
        answer too.
      </p>
      <div class="card"><h3>Output</h3><pre class="out" id="capout">Not run yet.</pre></div>
    </div>

    <div id="view-config" class="hidden">
      <div class="card">
        <h3>Revisions</h3>
        <p class="lede" style="margin:0 0 var(--space-3)">
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
        <p class="lede" style="margin:var(--space-3) 0 0">
          A member is a <code>system config-sync peer</code> — the boxes this one
          already pushes its running config to. Selecting one points the read-only
          views at it; configuration is always applied here and synced on commit.
        </p>
      </div>
    </div>

    <div id="view-panel" class="hidden">
      <div class="card">
        <pre class="out" id="panel">…</pre>
      </div>
    </div>
  </main>
</div>

<dialog id="editor">
  <h3 style="margin:0 0 .8rem" id="editortitle">Rule</h3>
  <!-- The fields are built from the same table the add panel uses, so a rule
       cannot be creatable with a setting that is not editable afterwards. -->
  <div class="field" style="margin-bottom:var(--space-4)">
    <label for="r-name">Name</label><input id="r-name">
  </div>
  <div class="grid" id="editorfields"></div>
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
// Who is signed in and what they may do. A read-only account must not be shown
// buttons that will be refused: the appliance would refuse them correctly, and
// the operator would learn their permission by being told no.
let who = "";
let permission = "read-write";
let view = "dashboard";
let panel = null;
let target = "";           // "" = this appliance, otherwise a stack member
let timer = null;
const history = new Map(); // counter -> recent values, for the sparklines
let lastCounters = null;

// ---- plumbing ------------------------------------------------------------

async function api(path, opts, patience) {{
  // Every request is bounded, so that an appliance which is restarting — or a
  // `show` waiting on a daemon that will never answer — fails instead of
  // leaving the page spinning with nothing said. The bound is deliberately
  // generous: the first call after a boot re-executes the appliance's own
  // binary, and a bound that fires on a legitimately slow answer is worse than
  // no bound at all. It exists to turn a hang into a failure, not to police
  // latency.
  // Reading is quick; applying re-executes the appliance's own configure over
  // the whole batch, so it gets its own, longer patience.
  const seconds = patience || 30;
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(), seconds * 1000);
  let r;
  try {{
    r = await fetch(path, Object.assign({{
      signal: deadline.signal,
      headers: {{ Authorization: "Bearer " + token }},
    }}, opts || {{}}));
  }} catch (e) {{
    clearTimeout(timer);
    throw new Error(e.name === "AbortError"
      ? "the appliance did not answer within " + seconds + " seconds"
      : "the appliance could not be reached: " + (e.message || e));
  }}
  clearTimeout(timer);
  if (r.status === 401) {{ signOut("That token was not accepted."); throw new Error("unauthorised"); }}
  if (!r.ok) {{
    const body = await r.text();
    throw new Error(unwrapError(body) || body.trim() || ("HTTP " + r.status));
  }}
  return r;
}}

// The API reports a failure as {{"error": "…"}}. An operator should read the
// sentence, not the envelope it arrived in — a pane that prints the JSON is
// asking them to parse it themselves.
function unwrapError(body) {{
  try {{
    const parsed = JSON.parse(body);
    if (parsed && typeof parsed.error === "string") return parsed.error.trim();
  }} catch (e) {{ /* plain text, which is the normal case */ }}
  return null;
}}

// A `show` against whichever member is selected. The proxy exists so one pane
// can drive the pair; pointing the browser at the peer directly would need its
// management port reachable from wherever the operator happens to be.
function showPath(p) {{
  if (!target) return p;
  return "/api/v1/stack/" + encodeURIComponent(target) + "/show/" +
         p.replace(/^\/api\/v1\/show\//, "");
}}

// A `show` answers in plain text, so a JSON object in the body is never output
// — it is the appliance saying the command failed, and it is raised as one.
async function text(path) {{
  const body = await (await api(showPath(path))).text();
  const failure = unwrapError(body);
  if (failure) throw new Error(failure);
  return body;
}}

async function configure(lines) {{
  const r = await api("/api/v1/configure", {{
    method: "POST",
    headers: {{ Authorization: "Bearer " + token, "Content-Type": "text/plain" }},
    body: lines.join("\n") + "\n",
  }}, 120);
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

// Nine digits of packets is a number nobody reads at a glance. Grouped below a
// million, shortened above it — on a tile the magnitude is the answer, and the
// table below still carries the exact figure.
function count(n) {{
  if (n < 1e6) return n.toLocaleString();
  if (n < 1e9) return (n / 1e6).toFixed(n < 1e7 ? 2 : 1) + "M";
  return (n / 1e9).toFixed(2) + "G";
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
  const accent = css.getPropertyValue("--brand").trim() || "#4c8dff";
  g.beginPath();
  values.forEach((v, i) => (i ? g.lineTo(i * step, y(v)) : g.moveTo(0, y(v))));
  g.strokeStyle = accent; g.lineWidth = 1.6; g.stroke();
  g.lineTo(w, h); g.lineTo(0, h); g.closePath();
  g.globalAlpha = 0.13; g.fillStyle = accent; g.fill();
}}

// A chart with a time axis and honest holes. The sparkline above cannot draw a
// gap — it takes bare numbers — and a history whose gaps are drawn as a line
// through them is a history that lies about the hours the box was off.
function chart(canvas, series, opts) {{
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w * dpr; canvas.height = h * dpr;
  const g = canvas.getContext("2d");
  g.scale(dpr, dpr);
  g.clearRect(0, 0, w, h);
  const all = series.flatMap((s) => s.points);
  const times = all.map((p) => p.at);
  if (times.length < 2) {{
    g.fillStyle = getComputedStyle(document.documentElement)
      .getPropertyValue("--text-muted").trim() || "#888";
    g.font = "12px system-ui, sans-serif";
    g.fillText("not enough history yet", 8, h / 2);
    return;
  }}
  const t0 = Math.min(...times), t1 = Math.max(...times);
  const max = Math.max(1, ...all.map((p) => (p.value == null ? 0 : p.value)));
  const pad = 22;
  const x = (t) => pad + ((t - t0) / Math.max(1, t1 - t0)) * (w - pad - 6);
  const y = (v) => h - 16 - (v / max) * (h - 26);

  // A baseline and a top line, so the scale is readable without a full grid.
  const css = getComputedStyle(document.documentElement);
  g.strokeStyle = css.getPropertyValue("--border-subtle").trim() || "#ddd";
  g.lineWidth = 1;
  g.beginPath(); g.moveTo(pad, h - 16); g.lineTo(w - 6, h - 16); g.stroke();

  series.forEach((s, i) => {{
    g.beginPath();
    let drawing = false;
    for (const p of s.points) {{
      if (p.value == null) {{ drawing = false; continue; }}   // a gap stays a gap
      const px = x(p.at), py = y(p.value);
      if (drawing) g.lineTo(px, py); else {{ g.moveTo(px, py); drawing = true; }}
    }}
    g.strokeStyle = s.colour || (i === 0 ? "#4c8dff" : "#e0a458");
    g.lineWidth = 1.6;
    g.stroke();
  }});

  g.fillStyle = css.getPropertyValue("--text-muted").trim() || "#888";
  g.font = "11px system-ui, sans-serif";
  g.fillText(opts.top || "", 2, 12);
  g.fillText(new Date(t0 * 1000).toLocaleString(), pad, h - 4);
  const end = new Date(t1 * 1000).toLocaleString();
  g.fillText(end, Math.max(pad, w - 6 - g.measureText(end).width), h - 4);
}}

// Bytes per second, said the way a person reads it.
function perSecond(v) {{
  const units = ["B/s", "kB/s", "MB/s", "GB/s"];
  let n = v, i = 0;
  while (n >= 1000 && i < units.length - 1) {{ n /= 1000; i++; }}
  return n.toFixed(n < 10 && i > 0 ? 1 : 0) + " " + units[i];
}}

async function refreshHistory() {{
  const res = $("historyres").value || "minute";
  const box = $("historycharts");
  let listing;
  try {{
    listing = await (await api("/api/v1/metrics")).json();
  }} catch (e) {{
    box.textContent = "";
    box.append(el("p", {{ class: "sub", text: "The appliance did not answer: " + e }}));
    return;
  }}
  const names = listing.series || [];
  if (!names.length) {{
    box.textContent = "";
    box.append(el("p", {{ class: "sub", text:
      "No history yet. Turn it on under System, then give it a few minutes — " +
      "a graph needs two samples before it is a line." }}));
    return;
  }}
  // Group an interface's two directions onto one chart: they are the same
  // question asked twice, and side by side they need two glances.
  const ifaces = new Set();
  for (const n of names) {{
    const m = /^iface\.(.+)\.(rx|tx)$/.exec(n);
    if (m) ifaces.add(m[1]);
  }}
  box.textContent = "";
  for (const iface of [...ifaces].sort()) {{
    const [rx, tx] = await Promise.all([
      api("/api/v1/metrics/" + res + "/iface." + iface + ".rx").then((r) => r.json()),
      api("/api/v1/metrics/" + res + "/iface." + iface + ".tx").then((r) => r.json()),
    ]);
    const peak = Math.max(0, ...[...rx.points, ...tx.points]
      .map((p) => p.value || 0));
    const card = el("div", {{ class: "card" }}, [
      el("h3", {{ text: iface }}),
      el("p", {{ class: "sub", text: "in and out, peak " + perSecond(peak) }}),
    ]);
    const cv = el("canvas", {{ style: "height:120px" }});
    card.append(cv);
    box.append(card);
    chart(cv, [
      {{ points: rx.points, colour: "#4c8dff" }},
      {{ points: tx.points, colour: "#e0a458" }},
    ], {{ top: "in / out" }});
  }}
  if (names.includes("gauge.sessions")) {{
    const s = await (await api("/api/v1/metrics/" + res + "/gauge.sessions")).json();
    const card = el("div", {{ class: "card" }}, [
      el("h3", {{ text: "Tracked connections" }}),
      el("p", {{ class: "sub", text: "how many flows the data plane held" }}),
    ]);
    const cv = el("canvas", {{ style: "height:120px" }});
    card.append(cv);
    box.append(card);
    chart(cv, [{{ points: s.points, colour: "#4c8dff" }}], {{ top: "connections" }});
  }}
}}

async function refreshDashboard() {{
  // Services first: a red unit explains every strange number below it.
  try {{
    const s = await (await api("/api/v1/status")).json();
    // The rail names the box being driven. It used to be written to an element
    // that does not exist, which threw before the services below were rendered
    // — the dashboard's top half was empty and nothing said why.
    $("navhost").textContent = s.hostname || "appliance console";
    // After a reload the console holds a token and nothing else, so who it is
    // signed in as comes back from the appliance rather than being remembered.
    if (s.you) {{
      who = s.you.user || "";
      permission = s.you.permission || "read-write";
      renderWho();
    }}
    const out = $("services");
    out.textContent = "";
    for (const [name, state] of Object.entries(s.services || {{}})) {{
      const up = state === "active";
      out.append(el("div", {{ class: "kpi" }}, [
        el("span", {{ class: "klabel", text: name }}),
        el("div", {{ class: "metric " + (up ? "ok" : "err") }}, [
          el("span", {{ class: "dot " + (up ? "up" : "down") }}),
          document.createTextNode(state),
        ]),
        el("span", {{ class: "kfoot", text: up ? "running" : "not running" }}),
      ]));
    }}
  }} catch (e) {{ /* the counters below still work; the pill shows the failure */ }}

  let counters;
  try {{ counters = parseCounters(await text("/api/v1/show/firewall/statistics")); }}
  catch (e) {{
    // Leaving the tiles up would be the console showing a minute-old number as
    // this second's, which is the one thing a throughput view must not do.
    $("counters").textContent = "";
    $("graphs").textContent = "";
    $("graphs").append(el("div", {{ class: "card", text:
      "The data plane's counters could not be read: " + (e.message || e) }}));
    lastCounters = null;
    return;
  }}

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
    const rate = series.length ? series[series.length - 1] : null;
    box.append(el("div", {{ class: "kpi" }}, [
      el("span", {{ class: "klabel", text: g.l }}),
      el("div", {{ class: "metric" }}, [
        document.createTextNode(count(counters.get(g.c) ?? 0)),
        el("small", {{ text: rate === null ? "" : "+" + count(rate) + "/s" }}),
      ]),
      canvas,
      el("span", {{ class: "kfoot", text: "since the data plane started" }}),
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
  // The same field table the editor uses, so a rule cannot be made with a
  // setting it cannot later be changed by.
  renderAddPanel({{
    addId: "addrulepanel", toggleId: "togglerule", toggleLabel: "New rule",
    noun: "Firewall rule", nameHint: "web-in", form: FORMS.rule,
    fields: ruleFields(zones),
    path: (n) => `firewall rule ${{n}}`,
  }});

  const globals = fieldsOf(ls, "firewall global");
  // The current value used to be parked in a dataset attribute nothing read,
  // so the one control that says what happens to unmatched traffic showed
  // "(unchanged)" and nothing else.
  $("defaultpolicy").value = "";
  $("defaultpolicy").options[0].textContent =
    "(now: " + (globals["default-action"] || "unset") + ")";

  const rules = parseRules(ls);
  // What each accept rule is currently carrying. Attribution, not a hardware
  // counter — and a rule that drops leaves no flow behind, so only accept rules
  // can be counted this way. The column says so rather than showing a zero that
  // reads as "never matched".
  let hits = {{}};
  let hitsAnswered = false;
  try {{
    const h = await (await api("/api/v1/rule-hits")).json();
    hitsAnswered = !!h.answered;
    for (const r of h.rules || []) hits[r.name] = r;
  }} catch (e) {{ /* the rules still render; the column just says nothing */ }}

  const list = $("rulelist");
  list.textContent = "";
  if (!rules.length) {{
    list.append(el("p", {{ class: "empty", text: "No rules configured." }}));
  }} else {{
    const body = el("tbody", {{}});
    rules.forEach((r, i) => body.append(ruleRow(r, i, zones, hitsAnswered ? hits : null)));
    list.append(el("div", {{ class: "tblwrap" }}, [
      el("table", {{ class: "otbl" }}, [
        el("thead", {{}}, [el("tr", {{}},
          ["order", "action", "rule", "match", "open", "carrying", "note", ""]
          .map((h) => el("th", {{ text: h }})))]),
        body,
      ]),
    ]));
  }}
  // The rules are a list until you can see which of them the box is using.
  await showInto("rulesshow", "/api/v1/show/firewall/statistics");
}}

// A rule reads as what it does, then what it matches — the order an operator
// scans in. The action is a badge because it is the one field whose value
// changes the meaning of every other one, and its denials are told apart by the
// shape of that badge rather than by its hue.
function ruleRow(r, i, zones, hits) {{
  const action = r.action || "accept";
  // A disabled rule that reads like an active one is how an operator spends an
  // afternoon on a rule the firewall is not consulting.
  const off = r.disabled === "true";

  // What the rule matches, in the words it was written in. A group is the whole
  // point of the rule that names one, and the *zone* must not be shown in the
  // address position — a rule reading "any → lan" that actually matches one
  // address group on two ports is a rule nobody can audit.
  const source = r["source-group"] ? "group " + r["source-group"] : (r.source || "any");
  const dest = r["destination-group"] ? "group " + r["destination-group"]
                                      : (r.destination || "any");
  const ports = r["port-group"] ? "group " + r["port-group"] : (r.port || "any");

  // The schedule is three settings; on a board it is one column — nobody reads
  // "days", "start" and "end" as three separate facts about a rule.
  const days = r["schedule days"], from = r["schedule start"], until = r["schedule end"];
  const open = (days || from || until)
    ? (days || "every day") + " " + (from || "00:00") + "–" + (until || "24:00")
    : "always";
  const note = [r.description, r.limit ? r.limit + "/s" : ""].filter(Boolean).join(" · ");

  const edit = el("button", {{ class: "btn", text: "Edit", onclick: () => openEditor(r, zones) }});
  const del = el("button", {{
    class: "btn danger", text: "Delete",
    onclick: () => stage("Delete firewall rule " + r.name, ["delete firewall rule " + r.name]),
  }});

  return el("tr", {{ class: action + (off ? " off" : "") }}, [
    el("td", {{ class: "mark ord", text: String(i + 1) }}),
    el("td", {{}}, [
      el("span", {{ class: "act " + action, text: action }}),
      ...(off ? [el("span", {{ class: "pill warn", text: "disabled" }})] : []),
    ]),
    el("td", {{}}, [el("span", {{ class: "val", text: r.name }})]),
    el("td", {{}}, [
      el("span", {{ class: "val", text: source + " → " + dest }}),
      el("span", {{ class: "sub", text: (r.from || "any") + " → " + (r.to || "any") +
        (r.proto ? " · " + r.proto + "/" + ports : "") }}),
    ]),
    el("td", {{}}, [el("span", {{ class: "val dim", text: open }})]),
    el("td", {{}}, carrying(r, action, hits)),
    el("td", {{}}, [el("span", {{ class: "val dim", text: note || "—" }})]),
    el("td", {{ class: "end" }}, [edit, del]),
  ]);
}}

// What a rule is carrying, or an honest reason why that cannot be said.
//
// A rule that drops leaves no flow behind — the packet is gone — so a zero
// against one would read as "never matched" when it means "nothing got through
// here", which is what the rule is *for*. Showing a dash and saying why beats
// showing a number that invites somebody to delete the rule doing its job.
function carrying(r, action, hits) {{
  if (!hits) return [el("span", {{ class: "val dim", text: "—" }})];
  if (action !== "accept") {{
    return [el("span", {{ class: "sub", title:
      "A rule that drops leaves no flow to count. Nothing getting through is what it is for.",
      text: "not counted" }})];
  }}
  const h = hits[r.name];
  if (!h) return [el("span", {{ class: "val dim", text: "—" }})];
  if (h.flows === 0) {{
    return [el("span", {{ class: "pill warn", text: "nothing" }})];
  }}
  return [
    el("span", {{ class: "val", text: h.flows + (h.flows === 1 ? " flow" : " flows") }}),
    el("span", {{ class: "sub", text: h.packets.toLocaleString() + " packets" }}),
  ];
}}

// Every field a firewall rule has, in the order the CLI's own list gives them:
// what it does, what it matches, when it is open, and what it is called. The
// console offering seven of seventeen was the difference between "configure the
// firewall here" and "configure the easy part of it here" — a schedule, a group
// or a rate limit could be set from the terminal and then not even be visible.
//
// The zone vocabulary is passed in rather than typed: a rule naming a zone that
// does not exist is the commonest way one silently matches nothing.
function ruleFields(zones) {{
  const zoneOpts = ["", ...zones];
  return [
    ["from", "From zone", zoneOpts],
    ["to", "To zone", zoneOpts],
    ["action", "Action", ["accept", "drop", "reject"]],
    ["proto", "Protocol",
     ["", "tcp", "udp", "tcp_udp", "icmp", "icmpv6", "vrrp", "esp", "ah", "gre"]],
    ["port", "Port"],
    ["port-group", "Port group"],
    ["source", "Source"],
    ["source-group", "Source group"],
    ["destination", "Destination"],
    ["destination-group", "Destination group"],
    ["limit", "New flows per second"],
    ["burst", "Burst"],
    // The schedule is three leaves under one word, and `set … schedule days …`
    // is exactly the command the CLI takes.
    ["schedule days", "Open on days"],
    ["schedule start", "Opens at"],
    ["schedule end", "Closes at"],
    ["log", "Log matches", ["", "true", "false"]],
    ["disabled", "Disabled", ["", "true", "false"]],
    ["description", "Description"],
  ];
}}

// What the editor is currently editing: the fields it was built from, their
// widgets, and the rule as it was — the last of these is what makes an emptied
// field mean "remove this setting" rather than "leave it alone".
let editing = null;

function script() {{
  const name = $("r-name").value.trim();
  if (!name || !editing) return [];
  return fieldLines(editing.fields, editing.widgets, "firewall rule " + name, editing.before);
}}

function openEditor(rule, zones) {{
  $("editortitle").textContent = rule ? "Edit rule " + rule.name : "New rule";
  $("r-name").value = rule ? rule.name : "";
  $("r-name").readOnly = !!rule;
  const fields = ruleFields(zones || []);
  const {{ grid, widgets }} = fieldGrid(fields, rule);
  const box = $("editorfields");
  box.textContent = "";
  for (const child of [...grid.children]) box.append(child);
  editing = {{ fields, widgets, before: rule }};
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
  // Only `show` is proxied to a peer; `configure` always runs here. Applying
  // while a peer's configuration is on screen would change the wrong firewall
  // — and on a config-synced pair the object names match by construction, so
  // it would succeed.
  if (target) {{
    banner("You are looking at " + target + ". Changes are only ever applied to " +
           "this appliance, so nothing was sent — select this appliance first.", "note");
    return;
  }}
  if (!staged.length) {{
    // Typing in a mask and pressing Apply is the commonest way to lose an edit:
    // nothing was staged, so nothing happened, and nothing said so.
    banner(dirty.size
      ? "Nothing is applied yet — you have changes that are not staged. Press " +
        "Stage in the section you edited, then Apply."
      : "Nothing is staged. Edits are staged per section first: change a " +
        "setting, press Stage there, then Apply here.", "note");
    return;
  }}
  banner("");
  // The appliance runs a batch line by line and commits whatever survived, so
  // one bad command used to leave the box half-changed while the dialog said
  // "Not applied". Applying now checks first and only commits a batch that
  // came back clean — the operator sees the refusal with nothing changed.
  if (tail.includes("commit")) {{
    const dry = await configure(stagedCommands());
    if (!dry.ok || summarise(dry.output).some((n) => n.kind === "bad")) {{
      showResult(dry, false);
      return;
    }}
  }}
  // Validating runs the same commands with no `commit`, so nothing is applied
  // — and the staged list must survive it. Clearing on a *validate* was the
  // worst possible bug in this panel: the check said "fine", the panel emptied
  // itself, and the change an operator had just been told was good could no
  // longer be applied.
  const committed = tail.includes("commit");
  const r = await configure(stagedCommands().concat(tail));
  showResult(r, committed);
  // Only clear once they have actually run. A refused commit leaves the
  // commands staged, so the operator can fix one and try again rather than
  // reconstructing what they had clicked.
  if (committed && r.ok && !summarise(r.output).some((n) => n.kind === "bad")) {{
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

function showResult(r, committed) {{
  const notes = summarise(r.output);
  const failed = notes.some((n) => n.kind === "bad");
  // The appliance runs the commands it can and reports what it could not: a
  // batch that is refused *and* committed leaves the box changed, and calling
  // that "Not applied" sends an operator to re-run commands that already ran.
  const partly = failed && /commit ok/i.test(r.output || "");
  // Validating and applying are different answers to different questions, and
  // a dialog that says "Applied" after a validate is a lie an operator acts on.
  $("resulttitle").textContent = failed
    ? (committed ? (partly ? "Partly applied" : "Not applied") : "This would be refused")
    : (committed ? "Applied" : "This would be accepted");
  const box = $("resultout");
  box.textContent = "";
  if (!notes.length) {{
    notes.push({{
      kind: r.ok ? "ok" : "bad",
      text: r.ok
        ? (committed ? "Done." : "Checked, and nothing was changed — the changes are still staged.")
        : "The appliance refused this.",
    }});
  }}
  if (!committed && !failed) {{
    notes.push({{ kind: "ok", text: "Press Apply when you are ready." }});
  }}
  if (partly) {{
    notes.unshift({{ kind: "warn", text:
      "Some of this was applied and saved before the refusal — the appliance " +
      "runs what it can. Check the section before applying again." }});
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
// A setting the appliance may state more than once — a blocked country, a
// blocked source — arrives as one leaf per value. Keeping the last would show
// one of three and let an operator remove the other two without seeing them, so
// repeats are joined into the list they are.
function addLeaf(row, key, value) {{
  row[key] = row[key] === undefined ? value : row[key] + "," + value;
}}

function entriesUnder(leaves, prefix) {{
  const depth = prefix.length;
  const out = new Map();
  for (const l of leaves) {{
    if (l.path.length < depth + 2) continue;
    if (prefix.some((p, i) => l.path[i] !== p)) continue;
    const name = l.path[depth];
    if (!out.has(name)) out.set(name, {{ name }});
    addLeaf(out.get(name), l.path.slice(depth + 1).join(" "), l.value);
  }}
  return [...out.values()];
}}

// Every leaf directly under one node, as a row the field grid can read.
function fieldsOf(leaves, node) {{
  const row = {{}};
  for (const l of leaves) {{
    if (l.node === node) addLeaf(row, l.path[l.path.length - 1], l.value);
  }}
  return row;
}}


// ---- what a value means --------------------------------------------------
//
// A field is a box you type into; a hint is the console reading it back to you.
// Most of these are arithmetic the browser can do on its own — a prefix's range
// and size, a port's usual service, how many countries a list names — and they
// cost nothing and work on an isolated appliance.
//
// Two are questions only the world can answer, and for those the page asks
// *this appliance*, which asks the registry. The console still fetches nothing
// from outside itself; that is the whole reason it works on a dark network.

const WELL_KNOWN_PORTS = {{
  20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
  67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 123: "ntp",
  143: "imap", 161: "snmp", 179: "bgp", 389: "ldap", 443: "https", 445: "smb",
  465: "smtps", 500: "isakmp", 514: "syslog", 587: "submission", 636: "ldaps",
  853: "dns-over-tls", 993: "imaps", 995: "pop3s", 1194: "openvpn",
  1701: "l2tp", 1723: "pptp", 1812: "radius", 3306: "mysql", 3389: "rdp",
  4500: "ipsec-nat-t", 5060: "sip", 5432: "postgres", 5900: "vnc",
  6379: "redis", 8080: "http-alt", 8443: "https-alt", 51820: "wireguard",
}};

function groupDigits(n) {{ return n.toLocaleString(); }}

// An IPv4 prefix, said as the range it actually covers. "10.0.0.0/8" is not a
// number of hosts anyone holds in their head.
function v4Range(text) {{
  const m = text.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/);
  if (!m) return null;
  const octets = [1, 2, 3, 4].map((i) => Number(m[i]));
  const bits = Number(m[5]);
  if (octets.some((o) => o > 255) || bits > 32) return null;
  const base = ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
  const size = Math.pow(2, 32 - bits);
  const mask = size - 1;
  const first = (base & ~mask) >>> 0;
  const last = (first + mask) >>> 0;
  const show = (n) => [24, 16, 8, 0].map((sh) => (n >>> sh) & 255).join(".");
  if (bits === 32) return show(first) + " · one address";
  const usable = bits <= 30 ? " · " + groupDigits(size - 2) + " usable" : "";
  return show(first) + " – " + show(last) + " · " + groupDigits(size) + " addresses" + usable;
}}

function cidrHint(value) {{
  const text = value.trim();
  if (!text) return "";
  if (text === "dhcp") return "address obtained from the upstream DHCP server";
  if (text === "auto") return "address formed from Router Advertisements (SLAAC)";
  const v4 = v4Range(text);
  if (v4) return v4;
  if (text.includes(":")) {{
    const bits = text.split("/")[1];
    return bits ? "IPv6, /" + bits + " — " + (Number(bits) === 64 ? "one subnet" : "a block of subnets")
                : "an IPv6 address";
  }}
  return "";
}}

function portHint(value) {{
  const text = value.trim();
  if (!text) return "";
  const range = text.match(/^(\d+)-(\d+)$/);
  if (range) {{
    const span = Number(range[2]) - Number(range[1]) + 1;
    return span > 0 ? groupDigits(span) + " ports" : "the range runs backwards";
  }}
  const n = Number(text);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return "";
  return WELL_KNOWN_PORTS[n] ? "usually " + WELL_KNOWN_PORTS[n] : "";
}}

function countryHint(value) {{
  const codes = value.split(/[,\s]+/).filter(Boolean);
  if (!codes.length) return "";
  const wrong = codes.filter((c) => !/^[A-Za-z]{{2}}$/.test(c));
  if (wrong.length) return "not a country code: " + wrong.join(", ");
  return codes.length + (codes.length === 1 ? " country" : " countries") + " blocked entirely";
}}

// The two that need the world. The appliance answers, and answers "not known"
// rather than failing when it has no route out.
async function ask(kind, value) {{
  try {{
    const r = await (await api("/api/v1/lookup/" + kind + "/" + encodeURIComponent(value))).json();
    return r.known ? r.answer : "";
  }} catch (e) {{ return ""; }}
}}

function asnHint(value) {{
  const text = value.trim();
  if (!/^\d+$/.test(text)) return "";
  const n = Number(text);
  if (n > 4294967295) return "beyond the largest AS number";
  // Typing the number is the one thing in this console an operator cannot check
  // against anything on the page: 65010 and 65001 look alike, and the wrong one
  // is a session that never comes up.
  return ask("asn", text);
}}

function addressHint(value) {{
  const text = value.trim();
  const v4 = v4Range(text);
  if (v4) return v4;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(text) || text.includes(":")) return ask("ptr", text);
  return "";
}}

// A lifetime in days is a date somebody will be woken up by. Saying which one
// turns "3650" into a decision rather than a number.
function validityHint(value) {{
  const days = Number((value || "").trim());
  if (!Number.isInteger(days) || days <= 0) return "";
  const when = new Date(Date.now() + days * 86400000);
  const years = days / 365;
  const rough = years >= 1.5 ? " (~" + Math.round(years) + " years)"
              : years >= 0.8 ? " (~a year)" : "";
  return "expires " + when.toISOString().slice(0, 10) + rough;
}}

function mtuHint(value, values) {{
  const text = (value || "").trim();
  // Nothing typed: say what it will be, and where that comes from. For a bond
  // or a bridge that is its members — which is the answer an operator was
  // about to go and look up.
  if (!text) {{
    const members = ((values && values.member) || "").split(/[,\s]+/).filter(Boolean);
    if (members.length) {{
      const sizes = members.map((m) => (fieldsOf(lastLeaves, "interface " + m) || {{}}).mtu);
      const named = sizes.filter(Boolean);
      if (named.length && named.every((v) => v === named[0])) {{
        return named[0] + " — the size " + members.join(", ") + " already use";
      }}
      if (!named.length) return "the members set no size, so the usual 1500 applies";
      return "the members disagree: " + members.map((m, i) => m + " " + (sizes[i] || "1500")).join(", ");
    }}
    if (values && values.type === "pppoe") return "1492 on a PPPoE link";
    return "";
  }}
  const mtu = Number(text);
  if (!Number.isInteger(mtu) || mtu <= 0) return "";
  if (mtu < 1280) return "below 1280 — IPv6 will not run on this link";
  if (mtu === 1492) return "the usual PPPoE size";
  if (mtu === 1500) return "the ordinary Ethernet size";
  if (mtu >= 9000) return "jumbo frames — every device on the segment must agree";
  if (mtu < 1500) return "smaller than Ethernet's 1500 — for a tunnel's overhead";
  return "";
}}

// Which fields say something about themselves. Keyed by the setting's own name,
// so a field means the same thing wherever it appears.
const HINTS = {{
  "remote-as": asnHint, "local-as": asnHint, "as": asnHint,
  address: cidrHint, address6: cidrHint, source: cidrHint, destination: cidrHint,
  prefix: cidrHint, "local-subnet": cidrHint, "remote-subnet": cidrHint,
  "allowed-ips": cidrHint, pool: cidrHint, block: cidrHint,
  via: addressHint, gateway: addressHint, vip: addressHint,
  "virtual-address": addressHint, remote: addressHint, local: addressHint,
  check: addressHint, relay: addressHint,
  port: portHint, "listen-port": portHint,
  "geoip-block": countryHint,
  "validity-days": validityHint, mtu: mtuHint, mru: mtuHint,
}};

// One hint per field, recomputed as it is typed into. Debounced because the
// asynchronous ones cross the network, and a keystroke is not a question.
function wireHint(field, widget, box, values) {{
  const compute = HINTS[field[0]];
  if (!compute) return;
  let timer = null;
  const run = () => {{
    const value = widget.value || "";
    let answer;
    try {{ answer = compute(value, values ? values() : {{}}); }} catch (e) {{ answer = ""; }}
    if (answer && typeof answer.then === "function") {{
      box.textContent = "";
      answer.then((text) => {{ if (widget.value === value) box.textContent = text || ""; }});
      return;
    }}
    box.textContent = answer || "";
  }};
  widget.addEventListener("input", () => {{
    clearTimeout(timer);
    timer = setTimeout(run, 300);
  }});
  widget.addEventListener("change", run);
  run();
}}

// What already exists, for the fields that point at it.
//
// An operator adding an interface to a bond should be choosing from the
// interfaces this appliance has, not typing a name and finding out at commit
// time that they misremembered it. The vocabulary is read from the same
// configuration every mask is built from.
function namesUnder(prefix) {{
  const names = entriesUnder(lastLeaves, prefix).map((r) => r.name);
  // What is staged counts too. In this console a change exists as soon as it is
  // staged, and refusing to offer a group somebody has just created — because
  // it is not committed yet — would mean creating a group and an account could
  // never be one piece of work.
  const head = "set " + prefix.join(" ") + " ";
  for (const entry of staged) {{
    for (const command of entry.cmds) {{
      if (!command.startsWith(head)) continue;
      const name = command.slice(head.length).split(/\s+/)[0];
      if (name && !names.includes(name)) names.push(name);
    }}
  }}
  return names;
}}

const VOCAB = {{
  zone: () => zoneNames(lastLeaves),
  parent: () => namesUnder(["interface"]),
  member: () => namesUnder(["interface"]),
  interface: () => namesUnder(["interface"]),
  "track-interface": () => namesUnder(["interface"]),
  "address-interface": () => namesUnder(["interface"]),
  // The link the translated traffic leaves by.
  "nat64 interface": () => namesUnder(["interface"]),
  // The session's source is one of this appliance's own addresses. Typing it is
  // how a neighbour ends up sourced from an address the peer does not expect.
  "update-source": () => localAddresses(),
  certificate: () => namesUnder(["pki", "certificate"]),
  ca: () => namesUnder(["pki", "ca"]),
  group: () => namesUnder(["system", "group"]),
  "match prefix-list": () => namesUnder(["policy", "prefix-list"]),
  import: () => namesUnder(["policy", "route-map"]),
  export: () => namesUnder(["policy", "route-map"]),
  "prefix-list": () => namesUnder(["policy", "prefix-list"]),
  "source-group": () => namesUnder(["firewall", "group", "address-group"]),
  "destination-group": () => namesUnder(["firewall", "group", "address-group"]),
  "port-group": () => namesUnder(["firewall", "group", "port-group"]),
}};

// Every address this appliance carries, from the configuration rather than from
// the live link: what a session may be sourced from is what the box is
// configured to hold, and an address that has not come up yet is still the
// right answer.
function localAddresses() {{
  const out = [];
  for (const l of lastLeaves) {{
    if (l.path[0] !== "interface") continue;
    const leaf = l.path[l.path.length - 1];
    if (leaf !== "address" && leaf !== "address6") continue;
    for (const one of String(l.value).split(/[,\s]+/)) {{
      const bare = one.split("/")[0].trim();
      if (bare && bare !== "dhcp" && !out.includes(bare)) out.push(bare);
    }}
  }}
  return out;
}}

/// A box of choices with a value, so the rest of the form can treat it as an
/// ordinary widget: `.value` is the comma-separated selection, which is exactly
/// what a repeatable setting is written from.
function multiPick(options, current) {{
  const box = el("div", {{ class: "pick" }});
  const chosen = new Set((current || "").split(/[,\s]+/).filter(Boolean));
  const boxes = [];
  for (const option of options) {{
    const tick = el("input", {{ type: "checkbox", value: option }});
    tick.checked = chosen.has(option);
    tick.onchange = () => box.dispatchEvent(new Event("change"));
    boxes.push(tick);
    box.append(el("label", {{ class: "pickone" }}, [tick, el("span", {{ text: option }})]));
  }}
  if (!options.length) {{
    box.append(el("span", {{ class: "sub", text: "nothing to choose from yet" }}));
  }}
  Object.defineProperty(box, "value", {{
    get: () => boxes.filter((b) => b.checked).map((b) => b.value).join(","),
    set: (v) => {{
      const want = new Set(String(v || "").split(/[,\s]+/).filter(Boolean));
      for (const b of boxes) b.checked = want.has(b.value);
    }},
  }});
  return box;
}}

// What the appliance uses when a field is left alone. Shown as the placeholder,
// so an empty box reads as "this is already right" rather than as one more
// thing to fill in — which is most of why a long form feels long.
const DEFAULTS = {{
  prefix: "64:ff9b::/96 — the well-known NAT64 prefix",
  mtu: "1500",
  "pppoe mru": "1492",
  ttl: "0 — inherit from the inner packet",
  "vlan-protocol": "802.1q",
  "validity-days": "3650 for an authority, 825 for a certificate",
  "key-type": "ec",
  "listen-port": "51820",
  "macvlan-mode": "bridge",
  priority: "100",
  "advert-interval": "1000",
  weight: "1",
  mode: "failover",
}};

// Values the console can offer rather than make an operator produce. A MAC is
// generated here; a WireGuard key is the word `generate`, because the appliance
// already knows that verb and minting a private key in a browser would be the
// one place this console invented its own crypto.
// How wide a field is, in the size of what goes in it. A port is five figures
// and a VLAN id four; a box eighteen characters wide beside them says the
// console does not know what a port is. Uniform columns are how a mask stops
// reading as a set of related facts and starts reading as a form.
const NARROW = [
  "port", "vlan-id", "cost", "mtu", "metric", "weight", "priority", "ttl",
  "distance", "limit", "burst", "hello-interval", "dead-interval",
  "advert-interval", "listen-port", "pool-size", "validity-days", "key-bits",
  "seq", "table", "vrf", "asn", "local-as", "remote-as", "area", "router-id",
  "system-id", "vrid", "block-size", "cgnat-block-size", "timeout",
];
const WIDTH = {{}};
for (const k of NARROW) WIDTH[k] = "w-s";

const SUGGEST = {{
  mac: () => {{
    // Locally administered, unicast: the range set aside for exactly this.
    const bytes = [0x02];
    for (let i = 0; i < 5; i++) bytes.push(Math.floor(Math.random() * 256));
    return bytes.map((b) => b.toString(16).padStart(2, "0")).join(":");
  }},
  "private-key": () => "generate",
  // A base32 secret the browser makes, so it is never carried anywhere it does
  // not have to be. The appliance validates it on commit either way.
  totp: () => {{
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const raw = new Uint8Array(20);
    crypto.getRandomValues(raw);
    return [...raw].map((b) => alphabet[b & 31]).join("");
  }},
}};

// The object a form is about, so its own name can be kept out of the choices
// it offers. Set around a render rather than threaded through every call.
let fieldSubject = "";

function fieldWidget(field, value) {{
  // A heading, not a setting: eighteen inputs in one flat grid is a form nobody
  // reads top to bottom, and the groups are how an operator already thinks
  // about the protocol — where it speaks, how fast, who it trusts.
  if (field[0] === "#") return null;
  // A field that points at something the appliance already has is a choice,
  // not a spelling test.
  let vocabulary = VOCAB[field[0]] ? VOCAB[field[0]]() : null;
  // Nothing may point at itself: a bond offered as its own member is a choice
  // whose only outcome is the appliance saying no.
  if (vocabulary && fieldSubject) {{
    vocabulary = vocabulary.filter((option) => option !== fieldSubject);
  }}
  if (vocabulary) {{
    // A repeatable setting is ticked, a single one is chosen. Which it is comes
    // from the field itself — OSPF speaks on several interfaces, a VRRP group
    // holds its address on exactly one.
    if (field[3]) return multiPick(vocabulary, value);
    const sel = el("select", {{}});
    for (const option of ["", ...vocabulary]) {{
      const o = el("option", {{ value: option, text: option === "" ? "(none)" : option }});
      if (option === (value || "")) o.setAttribute("selected", "selected");
      sel.append(o);
    }}
    return sel;
  }}
  if (field[2] && field[3]) return multiPick(field[2].filter(Boolean), value);
  if (!field[2]) {{
    const fallback = DEFAULTS[field[0]];
    return el("input", {{
      value: value || "",
      placeholder: fallback ? "default " + fallback : field[1].toLowerCase(),
    }});
  }}
  const sel = el("select", {{}});
  for (const opt of field[2]) {{
    const o = el("option", {{ value: opt, text: opt === "" ? "(unset)" : opt }});
    if (opt === (value || "")) o.setAttribute("selected", "selected");
    sel.append(o);
  }}
  return sel;
}}

// A form that asks for everything asks for nothing in particular.
//
// `form` describes what an operator actually has to decide: `essential` is what
// is on screen from the start, and `byValue` narrows the rest by what they have
// already chosen — a bond has no VLAN id and a VLAN has no members, and showing
// both to everybody is why creating an interface felt like filling in a form
// about somebody else's network. Everything hidden is still there, one click
// away, and can be set later or never.
function fieldGrid(fields, row, required, form) {{
  const widgets = fields.map((f) => fieldWidget(f, row && row[f[0]]));
  // The mask is a stack of groups, and a group is a spread: its heading stands
  // in the margin column and its fields keep the measure beside it. Eighteen
  // inputs in one flat grid under a rule of small caps is a questionnaire; the
  // groups are how an operator already thinks about the thing being set — where
  // it speaks, how fast, who it trusts — so they are given the page's own shape
  // rather than a heading row cutting the fields in half.
  const grid = el("div", {{ class: "mask" }});
  // Fields that come before the first heading belong to no group and lead the
  // mask. The body is empty for a mask that starts with a heading, and an empty
  // one takes no room.
  let body = el("div", {{ class: "grid" }});
  grid.append(body);
  // What the form holds right now, for the hints that depend on more than
  // their own field — a bond's MTU is a fact about its members.
  const values = () => {{
    const out = {{}};
    fields.forEach((f, i) => {{ if (widgets[i]) out[f[0]] = widgets[i].value || ""; }});
    return out;
  }};
  const boxes = [];   // the element per field or group, so it can be hidden
  fields.forEach((f, i) => {{
    if (!widgets[i]) {{
      body = el("div", {{ class: "grid" }});
      const section = el("section", {{ class: "spread" }}, [
        el("div", {{ class: "margin" }}, [el("h4", {{ class: "fieldgroup", text: f[1] }})]),
        body,
      ]);
      grid.append(section);
      // The group, not its heading: a heading hidden above fields still on
      // screen is a set of settings with nothing saying what they are.
      boxes.push(section);
      return;
    }}
    // The one field that has to be filled says so where it is, not only in the
    // message you get after pressing the button.
    const label = el("span", {{ text: f[1] }});
    if (required && f[0] === required) label.append(el("span", {{ class: "req", text: "required" }}));
    const hint = el("span", {{ class: "hint" }});
    // A `<label>` around a set of `<label>`s makes every click in the dead
    // space tick the first checkbox — nested labels are invalid, and the outer
    // one adopts the first control in tree order.
    const multi = widgets[i].classList && widgets[i].classList.contains("pick");
    // A set of tick boxes needs the run; a single figure does not.
    const size = multi ? " w-l" : (WIDTH[f[0]] ? " " + WIDTH[f[0]] : " w-m");
    const box = el(multi ? "div" : "label", {{ class: "field" + size }}, [label, widgets[i], hint]);
    // A value the console can produce, offered rather than demanded.
    if (SUGGEST[f[0]]) {{
      label.append(el("button", {{
        class: "suggest", type: "button", text: "generate",
        onclick: (e) => {{
          e.preventDefault();
          widgets[i].value = SUGGEST[f[0]]();
          widgets[i].dispatchEvent(new Event("change"));
        }},
      }}));
    }}
    body.append(box);
    boxes.push(box);
    wireHint(f, widgets[i], hint, values);
  }});

  // Which fields are on screen right now.
  let showAll = !form;
  const apply = () => {{
    if (!form) return;
    const chooser = form.byValue
      ? widgets[fields.findIndex((f) => f[0] === form.byValue.key)]
      : null;
    const extra = chooser ? (form.byValue.map[chooser.value] || []) : [];
    const visible = new Set([...(form.essential || []), ...extra]);
    let lastHead = null, headHasOne = false;
    fields.forEach((f, i) => {{
      if (!widgets[i]) {{
        if (lastHead) lastHead.classList.toggle("hidden", !headHasOne);
        lastHead = boxes[i];
        headHasOne = false;
        return;
      }}
      // Something already set stays visible however it was set: hiding a value
      // an operator can see in the config is how a console starts lying.
      const on = showAll || visible.has(f[0]) || !!(row && row[f[0]]) ||
                 !!(widgets[i].value && !DEFAULTS[f[0]]);
      boxes[i].classList.toggle("hidden", !on);
      if (on) headHasOne = true;
    }});
    if (lastHead) lastHead.classList.toggle("hidden", !headHasOne);
  }};
  if (form && form.byValue) {{
    const chooser = widgets[fields.findIndex((f) => f[0] === form.byValue.key)];
    if (chooser) chooser.addEventListener("change", apply);
  }}
  // A field whose hint depends on another one has to hear about it: ticking a
  // member is what tells the MTU what it will be.
  fields.forEach((f, i) => {{
    if (!widgets[i] || !["member", "type"].includes(f[0])) return;
    widgets[i].addEventListener("change", () => {{
      fields.forEach((g, j) => {{
        if (widgets[j] && HINTS[g[0]]) widgets[j].dispatchEvent(new Event("change"));
      }});
    }});
  }});
  apply();
  return {{
    grid, widgets,
    // The control that reveals the rest, for a caller that wants to place it.
    more: form
      ? el("button", {{
          class: "btn", type: "button", text: "More settings",
          onclick: (e) => {{
            e.preventDefault();
            showAll = !showAll;
            e.target.textContent = showAll ? "Fewer settings" : "More settings";
            apply();
          }},
        }})
      : null,
    refresh: apply,
  }};
}}

// The commands an edit becomes: a value writes, an emptied field removes. The
// difference matters — leaving a field blank has to mean "no longer set", not
// "leave whatever was there".
function fieldLines(fields, widgets, path, before) {{
  const lines = [];
  fields.forEach((f, i) => {{
    if (!widgets[i]) return;   // a heading writes nothing
    const v = (widgets[i].value || "").trim();
    const had = (before && before[f[0]]) || "";
    if (!v) {{
      if (had) lines.push(`delete ${{path}} ${{f[0]}}`);
      return;
    }}
    if (v === had) return;
    // A repeatable setting *adds*. Editing "CN,RU" down to "CN" by setting the
    // new value would leave RU blocked and nothing on screen would say so, so
    // the list is cleared first and then written.
    if (f[3] && had) lines.push(`delete ${{path}} ${{f[0]}}`);
    // Some of them take the list in one command; others take one value per
    // command, and writing a comma into those is a refusal.
    if (f[3] === "each") {{
      for (const one of v.split(",").map((one) => one.trim()).filter(Boolean)) {{
        lines.push(`set ${{path}} ${{f[0]}} ${{one}}`);
      }}
    }} else {{
      lines.push(`set ${{path}} ${{f[0]}} ${{v}}`);
    }}
  }});
  return lines;
}}

// A section-wide settings block: the same field grid, staged as one change.
// Which masks have been typed into and not staged. A change that only exists in
// the browser is the one state the console must never look calm about.
const dirty = new Set();

function settingsPanel(boxId, fields, current, path, label, form) {{
  if (!configReadable && !Object.keys(current || {{}}).length) return unreadable(boxId);
  const box = $(boxId);
  box.textContent = "";
  dirty.delete(boxId);
  // A mask with headings shows its first group and folds the rest away, unless
  // the caller says otherwise — the first group is what somebody came to set,
  // and the rest is why the page looked like a questionnaire.
  const shape = form || (fields.some((f) => f[0] === "#") ? {{ essential: firstGroup(fields) }} : null);
  const {{ grid, widgets, more }} = fieldGrid(fields, current, null, shape);
  maskHost(box);
  box.append(grid);
  const mark = el("span", {{ class: "pill warn hidden", text: "not staged yet" }});
  const button = el("button", {{
    class: "btn primary", text: "Stage",
    onclick: () => {{
      const lines = fieldLines(fields, widgets, path, current);
      if (!lines.length) {{
        // Pressing Stage with nothing changed should say so rather than look
        // like it worked — and the mask is no longer dirty either, or Apply
        // goes on claiming there is unstaged work in it.
        dirty.delete(boxId);
        mark.classList.add("hidden");
        banner("Nothing changed in " + label + ".", "note");
        return;
      }}
      banner("");
      dirty.delete(boxId);
      mark.classList.add("hidden");
      stage(label, lines);
    }},
  }});
  for (const w of widgets) {{
    if (!w) continue;
    w.oninput = w.onchange = () => {{
      dirty.add(boxId);
      mark.classList.remove("hidden");
    }};
  }}
  const foot = el("div", {{ class: "maskfoot" }}, [button, mark]);
  if (more) foot.append(more);
  box.append(foot);
}}

// A container that holds a mask lays out nothing itself: the mask brings its own
// groups and columns, and a grid wrapped in a grid is two layouts fighting over
// the same fields.
function maskHost(box) {{
  box.classList.remove("grid");
  box.classList.add("maskhost");
}}

// The keys of a mask's first group — everything before the second heading.
function firstGroup(fields) {{
  const out = [];
  let seen = 0;
  for (const f of fields) {{
    if (f[0] === "#") {{ if (++seen > 1) break; continue; }}
    if (seen) out.push(f[0]);
  }}
  return out;
}}

// Settings whose value is a secret. A list is read over somebody's shoulder, in
// a screenshot, in a support ticket — a pre-shared key or a private key printed
// across a row is a secret nobody meant to hand out. The value is still there
// to be edited; it is simply not on the board.
const SECRETS = [
  "psk", "password", "hashed-password", "private-key", "preshared-key",
  "auth-key", "secret", "passphrase", "macsec-key",
];

function shown(key, value) {{
  if (!SECRETS.includes(key)) return value;
  return value ? "set" : "";
}}

// The columns a list of these objects gets: the settings at least one of them
// actually carries, in the order the field table gives them. A column head is
// the promise a card list cannot make — that the value under it means the same
// thing in every row. Four, because a fifth pushes the controls off the measure
// and the rest is one click away in the editor anyway.
function objectColumns(o) {{
  const out = [];
  for (const f of o.fields) {{
    if (f[0] === "#") continue;
    if (!o.rows.some((r) => r[f[0]])) continue;
    out.push(f);
    if (out.length === 4) break;
  }}
  return out;
}}

// One object as a row: what it is, then what it is set to, then its controls.
// Editing opens the same field grid the add panel uses, in a row directly
// beneath it — an operator should not have to learn two shapes for one job.
//
// Settings whose value is a secret. A list is read over somebody's shoulder, in
// a screenshot, in a support ticket — a pre-shared key or a private key printed
// across a row is a secret nobody meant to hand out. The value is still there
// to be edited; it is simply not on the board.
function objectCard(o, row, cols, span) {{
  const path = o.path(row.name);
  fieldSubject = row.name;

  const b = o.badge ? o.badge(row) : null;
  const tr = el("tr", {{ class: (b && b.cls) || "" }});
  // The colour bar rides the first cell, and the first cell is whichever of the
  // two the list actually has.
  if (o.badge) {{
    tr.append(el("td", {{ class: "mark" }},
      b ? [el("span", {{ class: "act " + (b.cls || ""), text: b.text }})] : []));
  }}
  tr.append(el("td", {{ class: o.badge ? "" : "mark" }},
    [el("span", {{ class: "val", text: row.name }})]));
  for (const f of cols) {{
    const v = shown(f[0], row[f[0]]);
    tr.append(el("td", {{}}, [el("span", {{ class: "val dim", text: v || "—" }})]));
  }}

  // The editor is a row of its own, spanning the board, so opening one does not
  // deform the columns of the twelve objects around it.
  const editrow = el("tr", {{ class: "editrow hidden" }});
  const cell = el("td", {{ colspan: String(span) }});
  editrow.append(cell);

  const edit = el("button", {{
    class: "btn", text: "Edit",
    onclick: () => {{
      if (!editrow.classList.contains("hidden")) {{ editrow.classList.add("hidden"); return; }}
      cell.textContent = "";
      fieldSubject = row.name;
      const {{ grid, widgets, more }} = fieldGrid(o.fields, row, null, o.form);
      const stageit = el("button", {{
        class: "btn primary", text: "Stage",
        onclick: () => {{
          const lines = fieldLines(o.fields, widgets, path, row);
          // `stage` drops an empty list without a word, which reads as "it
          // worked" — the settings masks already say so, and this must too.
          if (!lines.length) {{
            banner("Nothing changed in " + o.noun.toLowerCase() + " " + row.name + ".", "note");
            return;
          }}
          banner("");
          stage(`${{o.noun}} ${{row.name}}`, lines);
        }},
      }});
      const foot = el("div", {{ class: "maskfoot" }}, [stageit]);
      if (more) foot.append(more);
      cell.append(grid, foot);
      editrow.classList.remove("hidden");
    }},
  }});
  const del = el("button", {{
    class: "btn danger", text: "Delete",
    onclick: () => stage(`Delete ${{o.noun.toLowerCase()}} ${{row.name}}`, [`delete ${{path}}`]),
  }});
  tr.append(el("td", {{ class: "end" }}, [edit, del]));
  return [tr, editrow];
}}

// Every section of every view stands in the same two columns: what it is called
// on the left, what it holds on the right. The markup is a stack — a heading,
// then the panel or the list that belongs to it — so this runs once over it and
// says which element is a label in the margin and which content keeps the
// content edge. Doing it here rather than in the markup means a section added
// later is in the same two columns without anyone having to remember.
function spreadify() {{
  const panes = [
    ...document.querySelectorAll('[id^="view-"]'),
    ...document.querySelectorAll(".tabpane"),
  ];
  for (const pane of panes) {{
    let inset = false, first = true;
    for (const node of [...pane.children]) {{
      if (node.classList.contains("tabpane") || node.classList.contains("tabs")) continue;
      const head = node.querySelector(":scope > h3");
      // A panel that is about to change something keeps its own frame: it is
      // the one surface on a page that is not a reading of the configuration.
      if (node.classList.contains("addpanel") || node.classList.contains("cards")) {{
        if (inset) node.classList.add("inset");
        continue;
      }}
      // A heading with its controls, and then the list it names: the list is a
      // sibling, so it is given the content edge rather than a wrapper.
      if (node.classList.contains("section")) {{
        markSpread(node, head, first, true);
        first = false; inset = true;
        continue;
      }}
      if (head) {{
        markSpread(node, head, first, false);
        first = false; inset = false;
        continue;
      }}
      // A box with no heading holds a mask, and a mask brings its own groups
      // and their margins. Framing it as well is a box inside a box.
      if (node.classList.contains("card")) node.classList.add("plain");
      if (inset) node.classList.add("inset");
    }}
  }}
}}

function markSpread(node, head, first, bar) {{
  node.classList.add("spread");
  if (first) node.classList.add("first");
  if (node.querySelector(":scope > .margin")) return;
  const m = el("div", {{ class: "margin" }});
  if (head) {{ node.insertBefore(m, head); m.append(head); }}
  else node.prepend(m);
  // What is left of a heading row — a picker, a New button — is one line of
  // controls, not one control per row. Without this the content column stacks
  // them and a button ends up as wide as the page. Only a heading row: a
  // section's body is a stack, and laying it out as a line puts a mask beside
  // its own explanation.
  if (!bar) return;
  const rest = [...node.children].filter((c) => c !== m);
  if (!rest.length) return;
  const line = el("div", {{ class: "sectionbar" }});
  for (const c of rest) line.append(c);
  node.append(line);
}}

// `o` carries: listId, addId?, noun, fields, path(name), rows, badge?, nameHint, empty.
function renderObjects(o) {{
  if (!configReadable && !o.rows.length) return unreadable(o.listId);
  const list = $(o.listId);
  list.textContent = "";
  if (!o.rows.length) {{
    list.append(el("p", {{ class: "empty",
      text: o.empty || ("No " + o.noun.toLowerCase() + " configured.") }}));
  }} else {{
    const cols = objectColumns(o);
    const span = (o.badge ? 1 : 0) + 1 + cols.length + 1;
    const head = el("tr", {{}});
    if (o.badge) head.append(el("th", {{}}));
    head.append(el("th", {{ text: o.noun }}));
    for (const f of cols) head.append(el("th", {{ text: f[1] }}));
    head.append(el("th", {{}}));
    const tbody = el("tbody", {{}});
    for (const row of o.rows) for (const tr of objectCard(o, row, cols, span)) tbody.append(tr);
    list.append(el("div", {{ class: "tblwrap" }}, [
      el("table", {{ class: "otbl" }}, [el("thead", {{}}, [head]), tbody]),
    ]));
  }}

  if (o.addId) renderAddPanel(o);
}}

// The panel that makes a new object. Split out because the firewall rules keep
// their own list — an ordered board with an action badge is not the same reading
// as a set of named objects — but must not keep their own *form*: a field the
// CLI has and this panel does not is a setting an operator cannot reach.
// A change an account may not make must not be offered to it. Called after
// every render, because the lists rebuild themselves constantly — and offering
// New, Edit, Delete and Stage to an account whose changes can never run is a
// console inviting work it will throw away.
function gateWrites() {{
  if (permission !== "read-only") return;
  for (const b of document.querySelectorAll("main button")) {{
    if (/^(edit|delete|new|add|stage|apply|validate|generate|lift|capture|roll)/i
        .test(b.textContent.trim())) {{
      b.disabled = true;
      b.title = "This account may read the configuration, not change it";
    }}
  }}
}}

function renderAddPanel(o) {{
  // Rebuilt each refresh so its selects carry the vocabulary as it is now, not
  // as it was when the page loaded.
  const box = $(o.addId);
  box.textContent = "";
  maskHost(box);
  const name = el("input", {{ placeholder: o.nameHint || "name" }});
  const {{ grid, widgets, more }} = fieldGrid(o.fields, null, o.required, o.form);
  // The name leads the mask rather than standing above it: it is the first
  // thing asked for, not a separate step before the form starts.
  grid.firstElementChild.prepend(
    el("label", {{ class: "field w-m" }}, [el("span", {{ text: "Name" }}), name]));
  box.append(grid);
  const err = el("p", {{ class: "err formerr" }});
  const add = el("button", {{
    class: "btn primary", text: "Add",
    onclick: () => {{
      const n = name.value.trim();
      if (!n) {{ err.textContent = "Give it a name."; name.focus(); return; }}
      const lines = fieldLines(o.fields, widgets, o.path(n), null);
      // A name on its own is not an object. The appliance stores settings, so a
      // path with no leaf under it is a path it does not know — `set nat source
      // web` is answered with "unknown set path" and the whole grammar. Asking
      // here, by name, beats sending a command that cannot succeed.
      if (!lines.length && !o.allowBare) {{
        err.textContent = o.required
          ? "Set " + fieldLabel(o.fields, o.required) + " — a " +
            o.noun.toLowerCase() + " with no settings is not one the appliance keeps."
          : "Fill in at least one setting: a name on its own is not a " +
            o.noun.toLowerCase() + " the appliance can keep.";
        return;
      }}
      // The one setting that makes this object mean anything. Without it the
      // command is accepted and the object is inert, which is worse than a
      // refusal because nothing says so.
      if (o.required && !lines.some((l) => l.includes(" " + o.required + " "))) {{
        err.textContent = "Set " + fieldLabel(o.fields, o.required) + ": without it the " +
          o.noun.toLowerCase() + " does nothing.";
        return;
      }}
      err.textContent = "";
      // Only the objects the appliance accepts bare get the bare command; for
      // everything else `lines` is non-empty by the check above.
      const body = lines.length ? lines : [`set ${{o.path(n)}}`];
      stage(`${{o.noun}} ${{n}}`, (o.prelude ? o.prelude(n) : []).concat(body));
      box.classList.add("hidden");
      // The toolbar button says "Cancel" while the panel is open; closing it
      // from in here has to put that back or the next click reopens nothing.
      if (o.toggleId && $(o.toggleId)) $(o.toggleId).textContent = o.toggleLabel || "New";
      // Rebuild the section so the thing just staged can be chosen by the next
      // one: creating a permission group and then an account in it is one piece
      // of work, and a form built before the group existed cannot offer it.
      refresh();
    }},
  }});
  const foot = el("div", {{ class: "maskfoot" }}, [add]);
  if (more) foot.append(more);
  box.append(foot, err);
}}

// The human name of a field, for a message about it. A message that names the
// key (`remote-as`) reads like a parser talking; the label is what is on screen.
function fieldLabel(fields, key) {{
  const hit = fields.find((f) => f[0] === key);
  return hit ? hit[1].toLowerCase() : key;
}}

// A section is a form until it also shows what the appliance is doing with it.
// One helper, so every live-state pane reports a failure the same way instead of
// leaving the previous answer on screen looking current.
async function showInto(boxId, path) {{
  const box = $(boxId);
  if (!box) return;
  // Which command produced this. Without it, seven protocol panes that all say
  // the same thing when the routing daemon is down are indistinguishable — and
  // an operator cannot tell "IS-IS has no adjacencies" from "nobody asked".
  //
  // It is set as the caption of the pane, in the margin beside its heading,
  // because that is where every other label on the page stands. Where there is
  // no margin — a pane on its own — it keeps its old place above the output.
  const section = box.closest(".spread");
  const margin = section && section.querySelector(":scope > .margin");
  let cap = (margin || box.parentNode).querySelector('[data-for="' + boxId + '"]');
  if (!cap) {{
    cap = el("code", {{ class: "cmd", "data-for": boxId }});
    if (margin) margin.append(cap);
    else box.parentNode.insertBefore(cap, box);
  }}
  cap.textContent = "show " + path.replace("/api/v1/show/", "").split("/").join(" ");
  box.textContent = "…";
  try {{ box.textContent = (await text(path)).trimEnd() || "(nothing to show)"; }}
  catch (e) {{ box.textContent = explain(String(e.message || e)); }}
}}

// A failure an operator can act on. The appliance's own words are kept, because
// they are what a bug report needs — but the common ones get the sentence that
// says what to do about them first.
function explain(message) {{
  if (/running wren|No such file or directory|Connection refused|connect/i.test(message)) {{
    return "The routing daemon is not running on this appliance, so no protocol " +
           "has any state to report. Configuring a protocol and committing is " +
           "what starts it.\n\n" + message;
  }}
  return message;
}}

function wireToggle(buttonId, panelId, label) {{
  $(buttonId).onclick = () => {{
    const panel = $(panelId);
    panel.classList.toggle("hidden");
    $(buttonId).textContent = panel.classList.contains("hidden") ? label : "Cancel";
  }};
}}

// The running configuration, read the way the appliance writes it.
//
// `show configuration` is a brace document, and its shape is the whole grammar:
// a line ending in an opening brace starts a block whose words are part of
// the path, a closing brace ends it, and any other line is a leaf whose **first token is the setting
// and whose rest is the value**. That is the same rule `flatten_config` applies
// on the appliance — this is its mirror, and it is why a description with
// spaces and a named block header (`zone wan`, brace and all) both fall out
// without either being a special case.
//
// Every mask on the page is built from what this returns, so when it was
// missing the console showed a fresh-looking appliance with nothing configured
// on it, whatever the box actually held.
function parseConfig(doc) {{
  const out = [];
  const stack = [];   // the words of every open block, outermost first
  const filled = [];  // whether each open block has anything inside it
  for (const raw of (doc || "").split("\n")) {{
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line === "}}") {{
      const closed = stack.pop();
      const had = filled.pop();
      // An object that takes every default is written as an empty block. With
      // no leaf to stand for it, every list built from `entriesUnder` reports
      // it as absent — so a collector just applied reads as "none configured",
      // inviting the operator to add it a second time.
      if (closed && !had && stack.length) {{
        const node = [].concat(...stack, closed);
        out.push({{ path: node.concat("_present"), node: node.join(" "), value: "" }});
      }}
      if (filled.length) filled[filled.length - 1] = true;
      continue;
    }}
    if (line.endsWith("{{")) {{
      stack.push(line.slice(0, -1).trim().split(/\s+/));
      filled.push(false);
      continue;
    }}
    // A leaf outside every block cannot be addressed by a `set` path, and the
    // appliance does not emit one either.
    if (!stack.length) continue;
    filled[filled.length - 1] = true;
    const node = [].concat(...stack);
    const words = line.split(/\s+/);
    out.push({{
      path: node.concat(words[0]),
      node: node.join(" "),
      value: words.slice(1).join(" "),
    }});
  }}
  return out;
}}

// Every configuration-driven view is built from this. When it fails, saying so
// is the whole job: returning an empty list silently renders every mask on the
// page as "nothing configured", which is indistinguishable from a fresh
// appliance and sends an operator looking for a problem that is not there.
// The last configuration read. A field that offers a choice — which zone, which
// interface to enslave — has to know what exists, and asking again per field
// would be a request per widget.
let lastLeaves = [];

let configReadable = true;

async function leaves() {{
  try {{
    const out = parseConfig(await text("/api/v1/show/configuration"));
    lastLeaves = out;
    configReadable = true;
    banner("");
    return out;
  }} catch (e) {{
    // A failed read must not throw away what we already knew. Rendering the
    // page as if the appliance were empty is the worst of both worlds: the
    // operator sees "nothing is configured" about a box that is fully
    // configured, and every mask, list and picker goes blank at once. The last
    // good reading stays on screen, and the banner says it is stale.
    configReadable = false;
    banner((lastLeaves.length ? "Showing the configuration as it was last read: "
                              : "Could not read the configuration: ") +
           (e.message || e) +
           (lastLeaves.length ? " — this may be out of date." : " — nothing could be read."));
    return lastLeaves;
  }}
}}

// Put that sentence where the settings would have been.
function unreadable(box) {{
  const host = $(box);
  if (!host) return true;
  host.textContent = "";
  host.append(el("p", {{ class: "err", text:
    "The configuration could not be read, so this cannot be shown. " +
    "Press the refresh control in the bar once the appliance answers again." }}));
  return true;
}}

// The one place the console admits something went wrong at the top of the page,
// rather than leaving a blank panel to be interpreted.
function banner(message, kind) {{
  const bar = $("banner");
  if (!bar) return;
  bar.textContent = message;
  bar.className = (kind === "note" ? "note" : "err") + (message ? "" : " hidden");
}}

// ---- zones ---------------------------------------------------------------

const POSTURE = [
  // Not posture, but the first thing to know about a zone: whether it is a set
  // of links or the appliance itself.
  ["local", "This is the appliance", ["", "true", "false"]],
  ["default-action", "Default action", ["", "accept", "drop", "reject"]],
  ["stateful", "Stateful", ["", "true", "false"]],
  ["block-icmp", "Block ICMP", ["", "true", "false"]],
  ["log", "Log", ["", "true", "false"]],
  ["source-validation", "Source validation", ["", "disable", "loose", "strict"]],
  // Country blocking and a manual block are posture, not rules: they are
  // decided before any rule is consulted, which is why they belong on the
  // zone rather than in a list of thousands of prefixes.
  // Both are repeatable. Countries take the whole list in one command;
  // a blocked source takes one command each, and a comma in it is a refusal.
  ["geoip-block", "Block countries", null, "list"],
  ["block", "Block sources", null, "each"],
  ["description", "Description"],
];

// The global block adds the one setting a zone cannot have: what happens to a
// packet the data plane cannot parse at all.
const GLOBAL_POSTURE = POSTURE.concat([
  ["fail-closed", "Drop unparseable packets", ["", "true", "false"]],
]);

async function refreshZones() {{
  const ls = await leaves();
  const globals = fieldsOf(ls, "firewall global");
  settingsPanel("globalform", GLOBAL_POSTURE, globals, "firewall global", "Global firewall posture");

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

// `source` and `translation` were never settings — the appliance answers them
// with "unknown set path", so filling either one failed the whole apply.
const SNAT = [
  ["zone", "Zone"], ["description", "Description"],
  ["cgnat-block-size", "CGNAT ports per host"],
  ["cgnat-base-port", "CGNAT first port"],
  ["disabled", "Disabled", ["", "true", "false"]],
];
const DNAT = [
  ["zone", "Zone"], ["proto", "Protocol", ["", "tcp", "udp"]],
  ["port", "Port"], ["to", "To"],
  ["description", "Description"],
  // Without it, a host inside reaching the public address of a service that is
  // also inside gets no answer — the reply crosses back by a different path
  // than it left. Turning it on is the whole fix, so it belongs on the rule.
  ["hairpin", "Hairpin", ["", "true", "false"]],
  ["disabled", "Disabled", ["", "true", "false"]],
];

async function refreshNat() {{
  await showInto("natshow", "/api/v1/show/nat");

  const ls = await leaves();
  settingsPanel("nat64form", NAT64, fieldsOf(ls, "nat nat64"), "nat nat64", "NAT64");
  renderObjects({{
    listId: "nptlist", required: "internal", toggleId: "togglenpt",
    toggleLabel: "New translation", addId: "addnptpanel", noun: "Translation",
    fields: NPT66, nameHint: "uplink",
    path: (n) => `nat npt66 ${{n}}`,
    rows: entriesUnder(ls, ["nat", "npt66"]),
    badge: (r) => (r.internal && r.external)
      ? {{ text: r.internal + " → " + r.external }}
      : {{ text: "incomplete", cls: "warn" }},
    empty: "No prefix translations configured.",
  }});
  renderObjects({{
    listId: "snatlist", form: FORMS.natSource, required: "zone", toggleId: "togglesnat", toggleLabel: "New source rule", addId: "addsnatpanel", noun: "Source rule",
    fields: SNAT, nameHint: "wan-masq",
    path: (n) => `nat source ${{n}}`,
    rows: entriesUnder(ls, ["nat", "source"]),
    badge: (r) => ({{ text: r["cgnat-block-size"] ? "cgnat" : "masquerade" }}),
    empty: "No source NAT configured.",
  }});
  renderObjects({{
    listId: "dnatlist", form: FORMS.natDest, required: "to", toggleId: "toggleddnat", toggleLabel: "New port forward", addId: "adddnatpanel", noun: "Port forward",
    fields: DNAT, nameHint: "web",
    path: (n) => `nat destination ${{n}}`,
    rows: entriesUnder(ls, ["nat", "destination"]),
    badge: (r) => r.port ? {{ text: (r.proto || "tcp") + "/" + r.port }}
                         : {{ text: "incomplete", cls: "warn" }},
    empty: "No port forwards configured.",
  }});
}}

// ---- Redistribution ------------------------------------------------------

// Every route source the routing daemon knows — `protocol_from_name` in wren,
// name for name. Offering three of the eight made `redistribute kernel`
// unreachable from the console although the CLI takes it, which is how a real
// configuration turned out to be writable in one place and not the other.
const REDIST_SOURCES = [
  "connected", "static", "kernel", "rip", "ospf", "isis", "babel", "bgp",
];
// A protocol does not redistribute itself.
const redist = (own) =>
  ["redistribute", "Redistribute", REDIST_SOURCES.filter((s) => s !== own), "list"];

// ---- BGP -----------------------------------------------------------------

const BGP_GLOBAL = [
  ["#", "This router"],
  ["local-as", "Local AS"], ["router-id", "Router ID"],
  ["#", "What it advertises"],
  ["network", "Networks", null, "list"],
  redist("bgp"),
  ["#", "What it tags its own routes with"],
  ["community", "Communities"], ["large-community", "Large communities"],
  ["ext-community", "Extended communities"],
  ["#", "How it behaves"],
  ["hold-time", "Hold time"], ["cluster-id", "Cluster ID"],
  // A count of equal-cost paths, not a yes/no — offering true/false made ECMP
  // unconfigurable and the refusal took the rest of the batch with it.
  ["multipath", "Multipath"],
  ["ebgp-require-policy", "Require policy", ["", "true", "false"]],
];
const BGP_NEIGHBOR = [
  ["#", "The session"],
  ["remote-as", "Remote AS"], ["description", "Description"],
  ["local-as", "Local AS"],
  ["update-source", "Source address"],
  ["ebgp-multihop", "Multihop TTL"],
  ["passive", "Passive", ["", "true", "false"]],
  ["shutdown", "Administratively down", ["", "true", "false"]],
  ["hold-time", "Hold time (s)"],
  ["#", "What it carries"],
  ["evpn", "EVPN", ["", "true", "false"]],
  ["link-state", "Link state", ["", "true", "false"]],
  ["flowspec", "FlowSpec", ["", "true", "false"]],
  ["srpolicy", "SR policy", ["", "true", "false"]],
  ["extended-nexthop", "Extended next hop", ["", "true", "false"]],
  ["add-path", "Add-path", ["", "off", "receive", "send", "both"]],
  ["default-originate", "Originate default", ["", "true", "false"]],
  ["route-reflector-client", "RR client", ["", "true", "false"]],
  ["max-prefix", "Max prefix"],
  ["#", "What policy it is under"],
  ["import", "Inbound route map"], ["export", "Outbound route map"],
  ["role", "Role", ["", "provider", "customer", "peer", "rs-server", "rs-client"]],
  ["#", "Trust and liveness"],
  ["password", "Password"],
  ["ao-key", "TCP-AO key"], ["ao-key-id", "TCP-AO key id"],
  ["ttl-security", "GTSM hops"],
  ["bfd", "BFD", ["", "true", "false"]],
  ["bfd-auth-type", "BFD authentication"],
  ["bfd-auth-key-id", "BFD key id"], ["bfd-auth-key", "BFD key"],
];
// A confederation is one AS to the outside and several inside it, which is how
// a large network runs iBGP without a full mesh or a reflector.
const BGP_CONFED = [
  ["confederation id", "Confederation AS"],
  ["confederation member", "Member ASes", null, "list"],
];
// Origin validation. Without an RTR server there is still the local table
// below, which is why the two live next to each other.
const BGP_RPKI = [
  ["rpki rtr", "RTR server"], ["rpki rtr-refresh", "Refresh (s)"],
  ["rpki reject-invalid", "Reject invalid", ["", "true", "false"]],
];
const BGP_AGGREGATE = [["summary-only", "Suppress more specifics", ["", "true", "false"]]];
const BGP_ROA = [["origin-as", "Origin AS"], ["max-length", "Maximum length"]];


// ---- IPsec ---------------------------------------------------------------

const IPSEC = [
  ["#", "The two ends"],
  ["local", "Local address"], ["remote", "Remote address"],
  ["#", "What goes through it"],
  ["local-subnet", "Local subnet"], ["remote-subnet", "Remote subnet"],
  ["#", "How it comes up"],
  ["psk", "Pre-shared key"], ["ike-version", "IKE", ["", "1", "2"]],
  ["start-action", "Start", ["", "start", "trap", "none"]],
  ["#", "What the two ends agree on"],
  // A peer that will not negotiate the appliance's defaults needs these, and
  // without them the tunnel is a support call rather than a setting.
  ["ike-proposal", "IKE proposal"], ["esp-proposal", "ESP proposal"],
  ["local-id", "Local identity"], ["remote-id", "Remote identity"],
];

async function refreshIpsec() {{
  await showInto("ipsecshow", "/api/v1/show/vpn/ipsec");
  renderObjects({{
    listId: "ipseclist", form: FORMS.ipsec, required: "remote", toggleId: "toggleipsec", toggleLabel: "New tunnel", addId: "addipsecpanel", noun: "Tunnel",
    fields: IPSEC, nameHint: "tunnel name",
    path: (n) => `vpn ipsec ${{n}}`,
    rows: entriesUnder(await leaves(), ["vpn", "ipsec"]),
    badge: (r) => (r.local && r.remote) ? {{ text: "ike" + (r["ike-version"] || "2") }}
                                        : {{ text: "incomplete", cls: "warn" }},
    empty: "No IPsec tunnels configured.",
  }});
}}

// ---- WireGuard -----------------------------------------------------------

const WG = [["listen-port", "Listen port"], ["private-key", "Private key"]];
const WG_PEER = [
  ["allowed-ips", "Allowed IPs", null, "list"], ["endpoint", "Endpoint"],
  ["keepalive", "Keepalive"], ["preshared-key", "Pre-shared key"],
];

async function refreshWireguard() {{
  const ls = await leaves();
  const tunnels = entriesUnder(ls, ["vpn", "wireguard"]);
  renderObjects({{
    listId: "wglist", form: FORMS.wireguard, required: "private-key",
    toggleId: "togglewg", toggleLabel: "New interface", addId: "addwgpanel", noun: "Interface",
    fields: WG, nameHint: "wg0",
    path: (n) => `vpn wireguard ${{n}}`,
    // `vpn wireguard wg0` is refused until `interface wg0 type wireguard`
    // exists. The console knows that, so it writes both rather than handing
    // the operator the appliance's refusal.
    prelude: (n) => [`set interface ${{n}} type wireguard`],
    rows: tunnels,
    badge: (r) => r["listen-port"] ? {{ text: ":" + r["listen-port"] }}
                                   : {{ text: "no port", cls: "warn" }},
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
  const iface = sel.value || (tunnels[0] && tunnels[0].name) || "";
  // With no interface there is nothing to add a peer *to*: the panel used to
  // build `vpn wireguard undefined peer …`, a command the appliance can only
  // refuse. The control is disabled instead, and says why.
  const canAddPeer = !!iface;
  $("togglewgpeer").disabled = !canAddPeer;
  $("togglewgpeer").title = canAddPeer ? "" : "Add a WireGuard interface first";
  if (!canAddPeer) $("addwgpeerpanel").classList.add("hidden");
  renderObjects({{
    listId: "wgpeerlist", form: FORMS.wgPeer, required: "allowed-ips", toggleId: "togglewgpeer", toggleLabel: "New peer",
    addId: canAddPeer ? "addwgpeerpanel" : null, noun: "Peer",
    fields: WG_PEER, nameHint: "peer public key",
    path: (n) => `vpn wireguard ${{iface}} peer ${{n}}`,
    rows: iface ? entriesUnder(ls, ["vpn", "wireguard", iface, "peer"]) : [],
    empty: iface ? "No peers on " + iface + "." : "Add an interface first.",
  }});
  await showInto("wgshow", "/api/v1/show/vpn");
}}

// ---- DHCP ----------------------------------------------------------------

const DHCP = [
  ["pool-offset", "Pool offset"], ["pool-size", "Pool size"],
  ["default-router", "Default router"], ["dns", "DNS", null, "list"],
  ["domain", "Domain"], ["lease-time", "Lease time"],
];
// A reservation is named, and the name is not the MAC — a machine can be
// replaced without the reservation losing what it was for.
const DHCP_MAPPING = [["mac", "MAC address"], ["ip", "Address"]];
// Router advertisements. The DHCPv6 pool is a block under them, and its three
// settings are ordinary two-word keys — `set … router-advert dhcp6-pool start`
// is the command, so nothing here has to know it is nested.
const RA = [
  ["#", "What it tells them"],
  ["prefix", "Prefix"], ["dns", "DNS", null, "list"],
  ["router-lifetime", "Router lifetime (s)"],
  ["#", "Where they get the rest"],
  ["managed", "Address from DHCPv6", ["", "true", "false"]],
  ["other-config", "Settings from DHCPv6", ["", "true", "false"]],
  ["dhcp6-pool start", "Pool start"], ["dhcp6-pool end", "Pool end"],
  ["dhcp6-pool lease-time", "Pool lease time"],
];

async function refreshDhcp() {{
  await showInto("dhcpshow", "/api/v1/show/dhcp/leases");

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
    badge: (r) => ({{ text: r["pool-size"] ? r["pool-size"] + " leases" : "default pool" }}),
    empty: "No DHCP servers configured.",
  }});

  // Reservations belong to one server, so the interface is chosen first and the
  // rows are that server's — the same shape as a prefix list's rules.
  const withServer = [...servers.keys()].sort().map((name) => ({{ name }}));
  const on = $("mapiface").value || (withServer[0] || {{}}).name || "";
  fillPicker("mapiface", withServer, on);
  // With no server chosen the path has a hole in it, and `set interface
  // dhcp-server static-mapping printer mac …` is a command that can only be
  // refused — so there is nothing to press rather than something that fails.
  $("togglemap").disabled = !on;
  renderObjects({{
    listId: "maplist", required: "mac", toggleId: "togglemap", toggleLabel: "New",
    addId: "addmappanel", noun: "Reservation",
    fields: DHCP_MAPPING, nameHint: "printer",
    path: (n) => `interface ${{on}} dhcp-server static-mapping ${{n}}`,
    rows: on ? entriesUnder(ls, ["interface", on, "dhcp-server", "static-mapping"]) : [],
    badge: (r) => r.ip ? {{ text: r.ip }} : {{ text: "no address", cls: "warn" }},
    empty: on ? "No reservations on " + on + "."
              : "No DHCP server to reserve an address on yet.",
  }});

  // Router advertisements are a block on an interface like the server is, so
  // the rows are the interfaces that have one.
  const ras = new Map();
  for (const l of ls) {{
    if (l.path[0] !== "interface" || l.path[2] !== "router-advert") continue;
    if (l.path.length < 4) continue;
    if (!ras.has(l.path[1])) ras.set(l.path[1], {{ name: l.path[1] }});
    ras.get(l.path[1])[l.path.slice(3).join(" ")] = l.value;
  }}
  fillPicker("raiface",
             [...interfaces].sort().filter((i) => !ras.has(i)).map((name) => ({{ name }})),
             $("raiface").value);
  renderObjects({{
    listId: "ralist", noun: "Advertisement", fields: RA,
    path: (n) => `interface ${{n}} router-advert`,
    rows: [...ras.values()],
    badge: (r) => r.prefix ? {{ text: r.prefix }}
                           : {{ text: "prefix from the interface" }},
    empty: "No interface advertises a router.",
  }});
}}

// ---- interfaces, routes, groups, services, identity ----------------------

// What each kind of link actually needs. Everything else about an interface can
// be decided later or never — and asking for all of it at once is why creating
// one felt like a questionnaire.

// What each kind of object needs before it is worth anything. Everything not
// listed is still there, one click away, under "More settings" — a form that
// asks for thirty things asks for nothing in particular, and the rest of these
// masks had the same problem the interface one did.
const FORMS = {{
  bgpNeighbour: {{ essential: ["remote-as", "description", "update-source"] }},
  ipsec: {{ essential: ["remote", "local", "psk"] }},
  wireguard: {{ essential: ["private-key", "listen-port"] }},
  wgPeer: {{ essential: ["allowed-ips", "endpoint"] }},
  loadBalancer: {{ essential: ["zone", "vip", "port", "backend"] }},
  natSource: {{ essential: ["zone", "description"] }},
  natDest: {{ essential: ["zone", "proto", "port", "to"] }},
  route: {{ essential: ["via", "dev"] }},
  uplink: {{ essential: ["priority", "gateway", "check target"] }},
  vrrp: {{ essential: ["interface", "vrid", "virtual-address"] }},
  cert: {{ essential: ["ca", "common-name", "usage"] }},
  ca: {{ essential: ["common-name", "organization"] }},
  user: {{ essential: ["password", "group"] }},
  reverseProxy: {{ essential: ["port", "backends", "certificate"] }},
  relay: {{ essential: ["port", "interface"] }},
  collector: {{ essential: ["port", "proto"] }},
  ocUser: {{ essential: ["password"] }},
  syn: {{ essential: ["mss"] }},
  group: {{ essential: ["permission"] }},
  rule: {{ essential: ["from", "to", "action", "proto", "port", "source", "destination"] }},
}};

const IFACE_FORM = {{
  essential: ["type", "zone", "address"],
  byValue: {{
    key: "type",
    map: {{
      // No type: an ordinary NIC, or a VLAN on one — which is a parent and an
      // id and nothing more, so both are here rather than behind "more".
      "": ["address6", "parent", "vlan", "description"],
      bridge: ["member", "vlan-aware"],
      bond: ["member", "bond-mode"],
      // A dummy link is a name and an address; there is nothing else to decide.
      dummy: ["address6", "description"],
      wireguard: [],
      pppoe: ["parent", "pppoe username", "pppoe password"],
      gre: ["local", "remote", "key"],
      ipip: ["local", "remote"],
      gretap: ["local", "remote", "key"],
      macvlan: ["parent", "macvlan-mode"],
      macsec: ["parent", "macsec-key", "macsec-peer"],
      l2tpv3: ["local", "remote", "key"],
    }},
  }},
}};

const IFACE = [
  ["#", "What it is"],
  ["description", "Description"],
  ["disabled", "Disabled", ["", "true", "false"]],
  // Everything below `type` is what makes an interface something other than a
  // NIC the box came with — a VLAN, a bridge, a tunnel. The console offering
  // six fields of thirty meant a VLAN or a bond could be made from the terminal
  // and then not be visible, let alone editable, here.
  // No `wireguard` here on purpose: a WireGuard link needs a private key,
  // which lives under `vpn wireguard`, and the WireGuard section writes both
  // halves. Offering it here was a dead end whose Apply could never succeed.
  ["type", "Type",
    ["", "bridge", "bond", "dummy", "pppoe", "gre", "ipip", "gretap",
     "macvlan", "macsec", "l2tpv3"]],
  ["mtu", "MTU"], ["mss", "Clamp TCP MSS"], ["mac", "MAC address"], ["hw-id", "Pin to MAC"],
  ["#", "Offload"],
  ["offload gro", "GRO", ["", "true", "false"]],
  ["offload gso", "GSO", ["", "true", "false"]],
  ["offload tso", "TSO", ["", "true", "false"]],
  ["offload lro", "LRO", ["", "true", "false"]],
  ["offload sg", "Scatter-gather", ["", "true", "false"]],
  ["offload rx", "RX checksum", ["", "true", "false"]],
  ["offload tx", "TX checksum", ["", "true", "false"]],
  ["offload rxvlan", "RX VLAN", ["", "true", "false"]],
  ["offload txvlan", "TX VLAN", ["", "true", "false"]],
  ["offload ntuple", "N-tuple filters", ["", "true", "false"]],
  ["offload rxhash", "RX hashing", ["", "true", "false"]],
  ["#", "Addressing"],
  ["zone", "Zone"], ["address", "IPv4 address"], ["address6", "IPv6 address"],
  ["pd-from", "Prefix from"], ["pd-subnet", "Prefix subnet"],
  ["#", "Where it hangs"],
  ["parent", "Parent interface"],
  ["member", "Members", null, "each"],
  // The modes the kernel has, and the CLI checks the value against exactly this
  // list — so it is chosen rather than typed and misspelt.
  ["bond-mode", "Bond mode",
    ["", "active-backup", "802.3ad", "balance-rr", "balance-xor", "broadcast",
     "balance-tlb", "balance-alb"]],
  // Two different things called VLAN, which is why they were confusing sitting
  // under one heading: *this* interface being a VLAN on a parent, and this
  // interface being a bridge (or a port on one) that filters VLANs.
  ["#", "This interface is a VLAN"],
  ["vlan", "VLAN id"],
  ["vlan-protocol", "Tag protocol", ["", "802.1q", "802.1ad"]],
  ["#", "VLAN filtering on a bridge"],
  ["vlan-aware", "Filter VLANs on this bridge", ["", "true", "false"]],
  ["vlan-tagged", "Tagged ids on this bridge port"],
  ["vlan-untagged", "Untagged id on this bridge port"],
  ["#", "Tunnel endpoints"],
  ["local", "Local"], ["remote", "Remote"], ["key", "Key"], ["ttl", "TTL"],
  ["#", "MACVLAN and MACsec"],
  ["macvlan-mode", "MACVLAN mode", ["", "bridge", "private", "vepa", "passthru"]],
  ["macsec-key", "MACsec key"], ["macsec-peer", "MACsec peer"],
  ["#", "PPPoE credentials"],
  ["pppoe username", "Username"], ["pppoe password", "Password"],
  ["pppoe service-name", "Service name"], ["pppoe ac-name", "Access concentrator"],
  ["pppoe mru", "MRU"],
];

async function refreshInterfaces() {{
  await showInto("ifaceshow", "/api/v1/show/interfaces");
  renderObjects({{
    listId: "ifacelist", allowBare: true, toggleId: "toggleiface", toggleLabel: "New",
    addId: "addifacepanel", noun: "Interface", form: IFACE_FORM,
    fields: IFACE, nameHint: "eth0",
    path: (n) => `interface ${{n}}`,
    rows: entriesUnder(await leaves(), ["interface"]),
    // The zone is the badge because it decides whether anything the firewall
    // says applies to this interface at all.
    badge: (r) => r.zone ? {{ text: r.zone }} : {{ text: "unzoned", cls: "warn" }},
    empty: "No interfaces configured.",
  }});
}}

const ROUTE = [
  ["via", "Via"], ["dev", "Device"], ["metric", "Metric"], ["vrf", "VRF"],
  // A route with nowhere to send. Two uses: null-routing a prefix, and holding
  // a BGP summary up whether or not anything inside it is reachable.
  ["blackhole", "Discard", ["", "true", "false"]],
  ["distance", "Distance"],
];


// The three group kinds differ only in the word for a member, so one view with
// a kind picker beats three that would drift apart.
const GROUP_MEMBER = {{
  "address-group": "address", "port-group": "port",
  "domain-group": "domain", "feed-group": "url",
}};

async function refreshGroups() {{
  const kind = $("groupkind").value;
  const member = GROUP_MEMBER[kind];
  renderObjects({{
    listId: "grouplist", toggleId: "togglegroup", toggleLabel: "New", addId: "addgrouppanel", noun: "Group",
    fields: [[member, member.charAt(0).toUpperCase() + member.slice(1) + "es", null, "list"]],
    nameHint: "group name",
    path: (n) => `firewall group ${{kind}} ${{n}}`,
    rows: entriesUnder(await leaves(), ["firewall", "group", kind]),
    badge: (r) => r[member] ? {{ text: member }} : {{ text: "empty", cls: "warn" }},
    empty: "No " + member + " groups configured.",
  }});
}}

const LB = [
  ["zone", "Zone"], ["vip", "Virtual address"],
  ["proto", "Protocol", ["", "tcp", "udp"]], ["port", "Port"],
  ["backend", "Backends", null, "each"], ["description", "Description"],
  ["disabled", "Disabled", ["", "true", "false"]],
];

async function refreshLb() {{
  await showInto("lbshow", "/api/v1/show/load-balancer");
  renderObjects({{
    listId: "lblist", form: FORMS.loadBalancer, required: "vip", toggleId: "togglelb", toggleLabel: "New", addId: "addlbpanel", noun: "Service",
    fields: LB, nameHint: "web",
    path: (n) => `load-balancer ${{n}}`,
    rows: entriesUnder(await leaves(), ["load-balancer"]),
    badge: (r) => r.vip ? {{ text: r.vip + ":" + (r.port || "?") }}
                        : {{ text: "incomplete", cls: "warn" }},
    empty: "No load-balanced services configured.",
  }});
}}

const CA = [
  ["common-name", "Common name"], ["organization", "Organization"],
  ["validity-days", "Validity (days)"], ["key-type", "Key type", ["", "ec", "rsa"]],
];
const CERT = [
  ["ca", "Signed by"], ["common-name", "Common name"],
  ["subject-alt-name", "Alt names (DNS:host, IP:addr)", null, "each"],
  ["validity-days", "Validity (days)"],
  ["key-type", "Key type", ["", "ec", "rsa"]],
  ["usage", "Usage", ["", "server", "client"]],
];

async function refreshPki() {{
  const ls = await leaves();
  renderObjects({{
    listId: "calist", form: FORMS.ca, required: "common-name", toggleId: "toggleca", toggleLabel: "New", addId: "addcapanel", noun: "Authority",
    fields: CA, nameHint: "internal",
    path: (n) => `pki ca ${{n}}`,
    rows: entriesUnder(ls, ["pki", "ca"]),
    badge: (r) => r["common-name"] ? {{ text: "ca" }} : {{ text: "incomplete", cls: "warn" }},
    empty: "No certificate authorities configured.",
  }});
  settingsPanel("acmeform", ACME, fieldsOf(ls, "pki acme"), "pki acme",
                "Automatic issuance");
}}

async function refreshCerts() {{
  await showInto("pkishow", "/api/v1/show/pki");
  renderObjects({{
    listId: "certlist", form: FORMS.cert, required: "common-name", toggleId: "togglecert", toggleLabel: "New", addId: "addcertpanel", noun: "Certificate",
    fields: CERT, nameHint: "web",
    path: (n) => `pki certificate ${{n}}`,
    rows: entriesUnder(await leaves(), ["pki", "certificate"]),
    badge: (r) => r.ca ? {{ text: r.ca }} : {{ text: "unsigned", cls: "warn" }},
    empty: "No certificates configured.",
  }});
}}

// A password an operator can type, not a crypt hash they have to produce. The
// appliance hashes it on the way in, and what is stored — and shown here after
// a commit — is only ever the hash.
const USER = [
  ["password", "Password"],
  ["group", "Management group"],
  // A second factor for the console and the API. Not for SSH — that is sshd's
  // own configuration — and not for the serial console, which is the port
  // somebody reaches for when everything else is broken.
  ["totp", "One-time code secret"],
  ["ssh-key", "SSH public keys", null, "each"],
  ["hashed-password", "Password hash"],
];
// Where a password is checked when it is not checked here. Local always goes
// first, which is why there is no order to configure.
const AAA = [["default-group", "Default group"]];
const AAA_RADIUS = [
  ["secret", "Shared secret"], ["port", "Port"], ["timeout", "Timeout (s)"],
];
const ADMIN_GROUP = [
  ["permission", "Permission", ["read-only", "read-write"]],
];

async function refreshUsers() {{
  const aaals = await leaves();
  settingsPanel("aaa-form", AAA, fieldsOf(aaals, "system aaa"), "system aaa",
                "Where a password is checked");
  renderObjects({{
    listId: "radiuslist", required: "secret", toggleId: "toggleradius",
    toggleLabel: "New server", addId: "addradiuspanel", noun: "Server",
    fields: AAA_RADIUS, nameHint: "10.0.0.50",
    path: (n) => `system aaa radius ${{n}}`,
    rows: entriesUnder(aaals, ["system", "aaa", "radius"]),
    // The secret is never a badge. Everything else about the server is.
    badge: (r) => r.secret ? {{ text: "port " + (r.port || 1812) }}
                           : {{ text: "no secret", cls: "warn" }},
    empty: "No authentication servers — accounts are local only.",
  }});
  renderObjects({{
    listId: "userlist", form: FORMS.user, toggleId: "toggleuser", toggleLabel: "New", addId: "adduserpanel", noun: "Administrator",
    fields: USER, nameHint: "admin",
    path: (n) => `system login ${{n}}`,
    rows: entriesUnder(await leaves(), ["system", "login"]),
    // Key-only is the default and the better posture, so it is stated rather
    // than left as an empty column an operator has to interpret.
    // Two things are worth reading at a glance, and management access is the
    // one that decides what this account can do to the firewall — so it is the
    // badge, and the login method is the second line.
    badge: (r) => r.group ? {{ text: r.group }}
                          : {{ text: "no management access", cls: "warn" }},
    empty: "No administrators configured.",
  }});
  renderObjects({{
    listId: "admingrouplist", form: FORMS.group, required: "permission", toggleId: "toggleadmingroup", toggleLabel: "New group", addId: "addadmingrouppanel", noun: "Group",
    fields: ADMIN_GROUP, nameHint: "operators",
    path: (n) => `system group ${{n}}`,
    rows: entriesUnder(await leaves(), ["system", "group"]),
    badge: (r) => r.permission === "read-write"
      ? {{ text: "read-write", cls: "warn" }}
      : {{ text: "read-only" }},
    empty: "No permission groups configured.",
  }});
  // Who may manage the box, as the appliance itself answers — a console that
  // only echoed its own form could not show an account the CLI added.
  await showInto("usersshow", "/api/v1/show/users");
}}

async function refreshSynproxy() {{
  renderObjects({{
    listId: "synlist", form: FORMS.syn, allowBare: true, toggleId: "togglesyn", toggleLabel: "New", addId: "addsynpanel", noun: "Port",
    fields: [["mss", "MSS"]], nameHint: "443",
    path: (n) => `firewall syn-protect ${{n}}`,
    // `syn-protect` is written as one flat line under `firewall`, not as a
    // named block, so `entriesUnder` cannot see it: the port IS the value.
    rows: (await leaves())
      .filter((l) => l.node === "firewall" && l.path[1] === "syn-protect")
      .map((l) => {{
        const words = String(l.value).split(/\s+/);
        return words[1] === "mss" ? {{ name: words[0], mss: words[2] }} : {{ name: words[0] }};
      }}),
    badge: (r) => ({{ text: "tcp/" + r.name }}),
    empty: "No SYN-protected ports configured.",
  }});
}}

// An operational command: it has already happened by the time it returns, so
// there is nothing to stage and nothing to discard.
async function clearOp(path) {{
  if (target) {{
    banner("You are looking at " + target + ". A block can only be lifted on this " +
           "appliance, so nothing was done.", "note");
    return;
  }}
  try {{
    const r = await api("/api/v1/clear/" + path, {{ method: "POST" }});
    showResult({{ ok: true, output: await r.text() }}, true);
  }} catch (e) {{
    showResult({{ ok: false, output: String(e.message || e) }}, true);
  }}
  await refreshIds();
}}

async function refreshIds() {{
  const list = $("blocklist");
  list.textContent = "";
  try {{
    const blocks = (await text("/api/v1/show/ids/blocks")).trimEnd().split("\n");
    // The same board every other list is read on, so a run-time block reads as
    // the same kind of thing as a rule rather than as a different console.
    const body = el("tbody", {{}});
    for (const line of blocks) {{
      const addr = (line.match(/(\d+\.\d+\.\d+\.\d+(?:\/\d+)?)/) || [])[1];
      if (!addr) continue;
      body.append(el("tr", {{ class: "drop" }}, [
        el("td", {{ class: "mark" }}, [el("span", {{ class: "act drop", text: "blocked" }})]),
        el("td", {{}}, [el("span", {{ class: "val", text: line.trim() }})]),
        el("td", {{ class: "end" }}, [el("button", {{
          class: "btn", text: "Lift",
          onclick: () => clearOp("ids/block/" + encodeURIComponent(addr.split("/")[0])),
        }})]),
      ]));
    }}
    if (!body.children.length) {{
      list.append(el("p", {{ class: "empty", text: "Nothing is blocked." }}));
    }} else {{
      list.append(el("div", {{ class: "tblwrap" }}, [
        el("table", {{ class: "otbl" }}, [
          el("thead", {{}}, [el("tr", {{}}, ["", "Source", ""].map((h) => el("th", {{ text: h }})))]),
          body,
        ]),
      ]));
    }}
  }} catch (e) {{
    list.append(el("p", {{ class: "empty err", text: String(e.message || e) }}));
  }}

  for (const [id, path] of [["idsshow", "/api/v1/show/ids"],
                            ["alertshow", "/api/v1/show/ids/alerts"]]) {{
    await showInto(id, path);
  }}
}}

// NAT64 (roadmap C10). The prefix is well-known on purpose: 64:ff9b::/96 is
// what a resolver synthesising DNS64 answers uses by default, so an appliance
// that picks its own has to teach every client about it.
// The kernel-parameter escape hatch. One field, because that is all it is: a
// name the kernel knows and a value. The refusal for anything outside net.*/vm.*
// lives in the appliance, so the console does not need its own opinion.
const SYSCTL = [["value", "Value"]];

const NAT64 = [
  ["enabled", "Enabled", ["", "true", "false"]],
  ["prefix", "Prefix"],
  ["pool", "IPv4 pool"],
  ["interface", "Interface"],
  ["dns64", "Synthesise DNS answers", ["", "true", "false"]],
];

// NPTv6 (roadmap C16). Both prefixes must be the same length: the translation
// is a checksum-neutral swap of the network part, so there is nothing to map
// unequal lengths onto.
const NPT66 = [
  ["interface", "Interface"],
  ["internal", "Internal prefix"], ["external", "External prefix"],
  ["description", "Description"],
];

const VRRP = [
  ["#", "The address being held"],
  ["interface", "Interface"], ["vrid", "Virtual router ID"],
  ["virtual-address", "Virtual addresses", null, "list"],
  ["prefix-length", "Prefix length"],
  ["address-interface", "Address interface"],
  ["#", "Who holds it"],
  ["priority", "Priority"], ["preempt", "Preempt", ["", "true", "false"]],
  ["advert-interval", "Advert interval (ms)"],
  ["#", "When to give it up"],
  ["track-interface", "Tracked interfaces", null, "list"],
  ["priority-decrement", "Priority decrement"],
];

// The two halves of a pair. Separate from VRRP on purpose: VRRP decides which
// box holds the address, and these decide what the other box knows when it
// does — a pair with VRRP alone fails over to a firewall that has neither the
// configuration nor the connections.
const CONFIG_SYNC = [
  ["peer", "Peers", null, "list"], ["secret", "Shared secret"],
];
const CONNTRACK_SYNC = [
  ["peer", "Peers", null, "list"], ["listen", "Listen on"], ["interval", "Interval (s)"],
];


// The box services. Every list here is the same field set the CLI's completion
// table offers under that node — derived from it rather than retyped, because a
// console that knows a different set of fields than the CLI is a console that
// will one day refuse something the appliance accepts.
const SVC_DNS = [
  ["upstream", "Upstream servers", null, "list"], ["serve-on", "Serve on", null, "list"],
  // Setting this takes the plaintext servers above out of the resolver: they
  // become the proxy's bootstrap, answering the one question its own hostname
  // poses rather than every question.
  ["secure-upstream", "Encrypted upstreams", null, "each"],
  ["allow-from", "Allow queries from", null, "each"],
  ["dont-query", "Never forward", null, "each"],
  ["host-override", "Host overrides", null, "each"], ["blocklist", "Blocklists", null, "each"],
  ["txt-record", "TXT records", null, "each"],
  ["dnssec", "DNSSEC", ["", "no", "yes", "allow-downgrade"]],
  ["cache-size", "Cache size"], ["negative-ttl", "Negative TTL (s)"],
  ["local-domain", "Local domain"],
];
const SVC_NTP = [
  ["upstream", "Upstream sources", null, "list"], ["serve-on", "Serve on", null, "list"],
  ["allow-from", "Allow from", null, "list"],
];
const SVC_SSH = [
  ["enable", "Enabled", ["", "true", "false"]], ["port", "Port"],
  ["listen-address", "Listen address"],
  ["password-authentication", "Passwords", ["", "true", "false"]],
  // VERBOSE is the one worth offering: it logs the fingerprint of the key that
  // was used, which turns "somebody logged in as admin" into "this key did".
  ["loglevel", "Log level",
   ["", "QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG1", "DEBUG2", "DEBUG3"]],
];
const SVC_SNMP = [
  ["community", "Community"], ["listen", "Listen"], ["location", "Location"],
  ["contact", "Contact"], ["allow", "Allow from", null, "list"],
];
const SVC_LLDP = [["enable", "Enabled", ["", "true", "false"]], ["interface", "Interfaces", null, "list"]];
const SVC_MDNS = [["interface", "Interfaces", null, "list"]];
const SVC_DYNDNS = [
  ["provider", "Provider", ["", "dyndns2", "cloudflare", "duckdns", "noip"]],
  ["server", "Server"], ["hostname", "Hostname"],
  ["login", "Login"], ["password", "Password"], ["interface", "Interface"],
];
const SVC_DHCPRELAY = [
  ["interface", "Interfaces", null, "list"],
  ["server", "Server (v4)", null, "list"], ["server6", "Server (v6)", null, "list"],
];
const SVC_PORTAL = [
  ["zone", "Gated zone"], ["port", "Port"], ["passphrase", "Passphrase"],
  ["session-timeout", "Session (s)"], ["message", "Message"],
];
const SVC_PORTMAP = [
  ["zone", "Asking zone"], ["wan-zone", "Opens on"],
  ["max-lifetime", "Max lifetime (s)"],
  ["allow-privileged", "Below 1024", ["", "true", "false"]],
];
const SVC_ALERTS = [["webhook", "Webhooks", null, "each"]];
const SVC_ALERTMAIL = [
  ["#", "The message"],
  ["to", "To"], ["from", "From"],
  ["#", "The relay it goes through"],
  ["relay", "Relay"], ["port", "Port"],
  ["starttls", "STARTTLS", ["", "true", "false"]],
  ["user", "User"], ["password", "Password"],
];
const RPROXY = [
  ["port", "Listen port"], ["certificate", "Certificate"],
  ["backends", "Backends", null, "list"], ["disabled", "Disabled", ["", "true", "false"]],
];
const BRELAY = [
  ["port", "UDP port"], ["interface", "Interfaces", null, "list"],
  ["description", "Description"], ["disabled", "Disabled", ["", "true", "false"]],
];
const SLTARGET = [
  ["port", "Port"], ["proto", "Protocol", ["", "udp", "tcp"]],
  ["level", "Level",
    ["", "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]],
  // Empty means every facility, which is why "all" is not on this list: it is
  // the absence of a selector, not one more thing to tick.
  ["facility", "Facilities",
    ["auth", "authpriv", "cron", "daemon", "ftp", "kern", "lpr", "mail", "news",
     "syslog", "user", "uucp", "local0", "local1", "local2", "local3", "local4",
     "local5", "local6", "local7"], "list"],
];


// The interior gateway protocols. Field lists mirror the CLI's completion
// tables node for node — see the services section for why they are derived
// rather than retyped.
const IGP_OSPF = [
  ["#", "Where it speaks"],
  ["interface", "Interfaces", null, "list"], ["area", "Area"],
  ["network-type", "Network type", ["", "broadcast", "point-to-point"]],
  ["passive-interface", "Passive", null, "list"], ["vrf", "VRF"],
  ["#", "How it is preferred"],
  ["cost", "Cost"], ["router-priority", "Priority"],
  ["stub-area", "Stub areas", null, "list"], ["nssa-area", "NSSA areas", null, "list"],
  ["totally-stubby-area", "Totally stubby areas", null, "list"],
  ["totally-nssa-area", "Totally NSSA areas", null, "list"],
  ["stub-default-cost", "Stub default cost"],
  ["nssa-default-area", "NSSA default area"],
  ["#", "What it carries in"],
  redist("ospf"),
  ["redistribute-metric", "Redistribute metric"],
  ["#", "Who it trusts"],
  ["auth-type", "Auth", ["", "none", "text", "md5"]],
  ["auth-key", "Auth key"], ["auth-key-id", "Key id"],
  ["auth-replay-protection", "Replay protection", ["", "true", "false"]],
  ["#", "How fast it notices"],
  ["hello-interval", "Hello (s)"], ["dead-interval", "Dead (s)"],
  ["bfd", "BFD", ["", "true", "false"]],
  ["graceful-restart", "Graceful restart", ["", "true", "false"]],
  ["graceful-restart-period", "Restart period (s)"],
];
const IGP_OSPF3 = [
  ["#", "Where it speaks"],
  ["interface", "Interfaces", null, "list"], ["area", "Area"],
  ["network-type", "Network type", ["", "broadcast", "point-to-point"]],
  ["instance-id", "Instance id"],
  ["#", "How it is preferred"],
  ["cost", "Cost"], ["router-priority", "Priority"],
  ["#", "What it carries in"],
  // Wren's OSPFv3 has `redistribute-static` and nothing else, so static is the
  // only source it can carry. Offering the others let an operator tick one and
  // get a refusal on Apply.
  ["redistribute", "Redistribute", ["static"], "list"],
  ["redistribute-metric", "Redistribute metric"],
  ["#", "How fast it notices"],
  ["bfd", "BFD", ["", "true", "false"]],
];
const IGP_ISIS = [
  ["#", "Identity"],
  ["system-id", "System id"], ["area", "Area"],
  ["level", "Level", ["", "1", "2", "1-2"]],
  ["#", "Where it speaks"],
  ["interface", "Interfaces", null, "list"],
  ["network-type", "Network type", ["", "broadcast", "point-to-point"]],
  ["vrf", "VRF"],
  ["#", "How it is preferred"],
  ["metric", "Metric"], ["priority", "Priority"],
  ["#", "What it carries in"],
  redist("isis"), ["redistribute-metric", "Redistribute metric"],
  // Level-2 routes into level-1, which is how a level-1 area reaches anything
  // that is not in it without a default route.
  ["l2-to-l1-leaking", "Leak L2 into L1", ["", "true", "false"]],
  ["#", "Who it trusts"],
  ["auth-type", "Auth", ["", "none", "text", "hmac-md5", "hmac-sha256"]],
  ["auth-key", "Auth key"], ["auth-key-id", "Key id"],
  ["#", "How fast it notices"],
  ["hello-interval", "Hello (s)"], ["bfd", "BFD", ["", "true", "false"]],
];
const IGP_RIP = [
  ["interface", "Interfaces", null, "list"], redist("rip"),
  ["redistribute-metric", "Redistribute metric"],
  ["bfd", "BFD", ["", "true", "false"]], ["vrf", "VRF"],
];
const IGP_RIPNG = [
  ["interface", "Interfaces", null, "list"], redist("rip"),
  ["redistribute-metric", "Redistribute metric"],
];
const IGP_BABEL = [
  ["interface", "Interfaces", null, "list"], ["network", "Networks", null, "list"], ["router-id", "Router id"],
  redist("babel"), ["redistribute-metric", "Redistribute metric"],
  ["bfd", "BFD", ["", "true", "false"]], ["vrf", "VRF"],
];
const MULTICAST = [
  ["#", "Which half is on"],
  ["enabled", "Enabled", ["", "true", "false"]],
  ["igmp", "IGMP (IPv4)", ["", "true", "false"]],
  ["mld", "MLD (IPv6)", ["", "true", "false"]],
  ["igmp-version", "IGMP version", ["", "2", "3"]],
  ["#", "How it asks who is listening"],
  ["query-interval", "Query interval (s)"],
  ["query-response-interval", "Response interval (s)"],
  ["robustness", "Robustness"],
];
// An interface either faces receivers or faces where the traffic comes from.
const MULTICAST_IFACE = [
  ["role", "Role", ["", "downstream", "upstream", "disabled"]],
  ["igmp-version", "IGMP version", ["", "2", "3"]],
];
// A VRF is a table plus the links that use it. Import and export are route
// targets: what may cross in, and what this one offers out.
const VRF = [
  ["table", "Routing table id"], ["rd", "Route distinguisher"],
  ["interface", "Interfaces", null, "list"],
  ["import", "Import targets", null, "list"],
  ["export", "Export targets", null, "list"],
];
const ACME = [
  ["email", "Contact address"],
  ["directory-url", "Directory URL"],
  ["challenge", "Challenge", ["", "http-01", "dns-01"]],
  ["agree-tos", "Terms accepted", ["", "true", "false"]],
];

const IGP_BFD = [
  ["#", "How fast it decides"],
  ["min-tx", "Min TX (ms)"], ["min-rx", "Min RX (ms)"],
  ["detect-mult", "Detect multiplier"],
  ["#", "Echo mode"],
  ["echo", "Echo", ["", "true", "false"]], ["echo-interval", "Echo interval (ms)"],
  ["#", "Who it trusts"],
  ["auth-type", "Auth",
    ["", "simple", "keyed-md5", "meticulous-md5", "keyed-sha1", "meticulous-sha1"]],
  ["auth-key", "Auth key"], ["auth-key-id", "Key id"],
];


// `failover` is the default and is not written to the configuration, so an
// applied failover reads back as unset — saying which one is the default is
// the difference between "my change was lost" and "nothing to write".
const WAN_MODE = [["mode", "Mode", ["", "failover", "load-balance"]]];
const WAN_UPLINK = [
  ["priority", "Priority"], ["weight", "Weight"], ["table", "Route table"],
  ["gateway", "Gateway"],
  // A nested block: `check target`, not `check`. The old key wrote a path the
  // appliance does not have, so failover checking was unconfigurable.
  ["check target", "Health check targets", null, "each"],
  ["check interval", "Probe interval (s)"], ["check timeout", "Probe timeout (s)"],
  ["check fail", "Losses to fail"], ["check rise", "Successes to recover"],
  // Out of SLA is not the same as down: a link that answers every probe in
  // 400 ms is up by any reachability test and useless for a call.
  ["#", "What counts as good enough"],
  ["check latency", "Latency limit (ms)"], ["check jitter", "Jitter limit (ms)"],
  ["check loss", "Loss limit (%)"], ["check probes", "Probes per round"],
];
// Steering. Failover answers "the uplink died, now what"; this answers the
// question before it — which traffic belongs on which uplink, and when it moves.
const WAN_POLICY = [
  ["uplink", "Preferred uplinks", null, "each"],
  ["#", "What it matches"],
  ["source", "Source"], ["destination", "Destination"],
  ["proto", "Protocol", ["", "tcp", "udp"]],
  ["source-port", "Source port"], ["destination-port", "Destination port"],
  ["#", "When nothing qualifies"],
  ["strict", "Hold rather than degrade", ["", "true", "false"]],
  ["disabled", "Disabled", ["", "true", "false"]],
];
const OC_SERVER = [
  ["#", "Where clients arrive"],
  ["port", "Port"], ["certificate", "Certificate"], ["zone", "Zone"],
  ["disabled", "Disabled", ["", "true", "false"]],
  ["#", "What they get"],
  ["pool", "Client pool"], ["dns", "DNS", null, "list"], ["routes", "Pushed routes", null, "list"],
  ["default-route", "Default route", ["", "true", "false"]],
];
const OC_USER = [["password", "Password"]];
const PLIST_RULE = [["prefix", "Prefix"], ["ge", "Length ≥"], ["le", "Length ≤"]];
// The map itself has one setting; everything else is a numbered rule under it.
const RMAP = [["default", "Default", ["", "permit", "deny"]]];
// A rule matches, then changes. The nested `match`/`set` blocks are ordinary
// two-word keys — `set policy route-map m rule 5 match prefix-list x` is exactly
// the command, so nothing here has to know they are nested.
const RMAP_RULE = [
  ["action", "Action", ["", "permit", "deny"]],
  ["#", "What it matches"],
  ["match prefix-list", "Prefix list"],
  ["match prefix", "Prefix pattern"],
  ["match protocol", "Protocol"],
  ["match metric-ge", "Metric ≥"],
  ["match metric-le", "Metric ≤"],
  ["#", "What it changes"],
  ["set next-hop", "Next hop"],
  ["set metric", "Metric"],
  ["set add-metric", "Metric delta"],
  ["set preference", "Preference"],
  ["set community", "Communities"],
  ["set add-community", "Add community"],
  ["set large-community", "Large communities"],
  ["set add-large-community", "Add large community"],
  ["set ext-community", "Extended communities"],
  ["set add-ext-community", "Add extended community"],
];
// Policy routing. Ordinary routing asks where a packet is going; these ask the
// other questions and send the answer to a different table.
const PBR = [
  ["table", "Routing table"],
  ["#", "What it matches"],
  ["source", "Source"], ["destination", "Destination"],
  ["interface", "Arrived on"],
  ["proto", "Protocol", ["", "tcp", "udp"]],
  ["source-port", "Source port"], ["destination-port", "Destination port"],
  ["#", "Where it sits"],
  ["priority", "Priority"], ["disabled", "Disabled", ["", "true", "false"]],
];

const SYS_IDENT = [
  ["hostname", "Hostname"],
  // The port somebody reaches for when the network this box manages is the
  // thing that is broken.
  ["console device", "Serial console"], ["console speed", "Console speed"],
  ["commit-revisions", "Revisions kept"],
];
const SYS_UPDATE = [["url", "Channel URL"], ["public-key", "Signing key"]];


// cake and fq_codel have different knobs, and the appliance refuses the other
// one's — so the form asks for the ones that belong to what was chosen.
const QOS_FORM = {{
  essential: ["discipline"],
  byValue: {{
    key: "discipline",
    map: {{
      cake: ["bandwidth", "rtt", "nat", "ack-filter", "diffserv"],
      fq_codel: ["target", "interval", "limit"],
    }},
  }},
}};

const QOS = [
  ["#", "The link"],
  ["discipline", "Discipline", ["", "cake", "fq_codel"]],
  ["bandwidth", "Bandwidth"],
  ["rtt", "RTT profile",
    ["", "datacentre", "lan", "metro", "regional", "internet", "oceanic",
     "satellite", "interplanetary"]],
  ["#", "What it knows about the traffic"],
  ["nat", "NAT-aware", ["", "true", "false"]],
  ["ack-filter", "ACK filter", ["", "true", "false"]],
  ["diffserv", "Diffserv",
    ["", "besteffort", "precedence", "diffserv3", "diffserv4", "diffserv8"]],
  ["#", "The queue itself"],
  ["target", "Target (ms)"], ["interval", "Interval (ms)"], ["limit", "Queue limit"],
];

async function refreshQos() {{
  const ls = await leaves();
  const ifaces = [...new Set(
    ls.filter((l) => l.path[0] === "interface" && l.path.length > 1)
      .map((l) => l.path[1])
  )].sort();
  const sel = $("qosiface");
  const chosen = sel.value || ifaces[0] || "";
  sel.textContent = "";
  for (const n of ifaces) sel.append(el("option", {{ value: n, text: n }}));
  if (chosen) sel.value = chosen;

  const current = {{}};
  for (const l of ls) {{
    if (l.node === `interface ${{chosen}} qos`) current[l.path[l.path.length - 1]] = l.value;
  }}
  settingsPanel(
    "qosform", QOS, current,
    `interface ${{chosen}} qos`, `Shaping on ${{chosen || "an interface"}}`,
    QOS_FORM,
  );
  await showInto("qosshow", "/api/v1/show/interfaces");
}}

async function refreshWan() {{
  const ls = await leaves();
  const under = (node) => fieldsOf(ls, node);
  settingsPanel("wan-mode", WAN_MODE, under("multiwan"), "multiwan", "Multi-WAN mode");
  renderObjects({{
    listId: "wanlist", form: FORMS.uplink, required: "gateway", toggleId: "togglewan", toggleLabel: "New uplink", addId: "addwanpanel", noun: "Uplink",
    fields: WAN_UPLINK, nameHint: "wan0",
    path: (n) => `multiwan uplink ${{n}}`,
    rows: entriesUnder(ls, ["multiwan", "uplink"]),
    // An uplink with no check is assumed up — which is exactly the case where a
    // failover does not happen when it should, so it is said on the card.
    badge: (r) => r.check ? {{ text: "checked" }} : {{ text: "assumed up", cls: "warn" }},
    empty: "No uplinks configured.",
  }});
  // There is no `show multiwan`; what an operator actually needs to see is
  // which uplink the routing table is using right now, which is the same
  // question `show ip route` answers — and the caption says so, so nobody
  // wonders why this pane looks like the routing table.
  renderObjects({{
    listId: "wanpolicylist", required: "uplink", toggleId: "togglewanpolicy",
    toggleLabel: "New policy", addId: "addwanpolicypanel", noun: "Steering policy",
    fields: WAN_POLICY, nameHint: "voip",
    path: (n) => `multiwan policy ${{n}}`,
    rows: entriesUnder(ls, ["multiwan", "policy"]),
    badge: (r) => r.uplink ? {{ text: String(r.uplink).split(",")[0] + " first" }}
                           : {{ text: "no uplink", cls: "warn" }},
    empty: "No steering policies — every uplink carries whatever failover gives it.",
  }});
  // What each uplink is measuring, and where steering is sending traffic. The
  // route table alone cannot show either.
  await showInto("wanshow", "/api/v1/show/multiwan");
}}

async function refreshOpenconnect() {{
  const ls = await leaves();
  const server = {{}};
  for (const l of ls) {{
    if (l.node === "vpn openconnect") server[l.path[l.path.length - 1]] = l.value;
  }}
  settingsPanel("oc-server", OC_SERVER, server, "vpn openconnect", "OpenConnect server");
  renderObjects({{
    listId: "oculist", form: FORMS.ocUser, required: "password", toggleId: "toggleocuser", toggleLabel: "New account", addId: "addocuserpanel", noun: "Account",
    fields: OC_USER, nameHint: "alice",
    path: (n) => `vpn openconnect user ${{n}}`,
    rows: entriesUnder(ls, ["vpn", "openconnect", "user"]),
    empty: "No accounts configured — nobody can connect.",
  }});
  await showInto("ocshow", "/api/v1/show/vpn");
}}

// Which named list a picker is on: the one chosen, or a name typed beside it for
// one that does not exist yet — a list is only real once it has a rule, so the
// name has to exist somewhere before that rule can be written.
function chosenName(pickId, newId, names) {{
  const typed = ($(newId).value || "").trim();
  if (typed) return typed;
  const pick = $(pickId);
  return pick.value || (names[0] && names[0].name) || "";
}}

function fillPicker(pickId, names, current) {{
  const pick = $(pickId);
  pick.textContent = "";
  for (const n of names) {{
    const o = el("option", {{ value: n.name, text: n.name }});
    if (n.name === current) o.setAttribute("selected", "selected");
    pick.append(o);
  }}
  if (!names.length) pick.append(el("option", {{ value: "", text: "(none yet)" }}));
}}

async function refreshRoutePolicy() {{
  const ls = await leaves();
  markTabs("routepolicy", ls);

  renderObjects({{
    listId: "pbrlist", required: "table", toggleId: "togglepbr",
    toggleLabel: "New rule", addId: "addpbrpanel", noun: "Policy route",
    fields: PBR, nameHint: "guests-out",
    path: (n) => `policy route ${{n}}`,
    rows: entriesUnder(ls, ["policy", "route"]),
    badge: (r) => r.table ? {{ text: "table " + r.table }}
                          : {{ text: "no table", cls: "warn" }},
    empty: "No policy routes configured.",
  }});
  if (currentTab("routepolicy") === "pbr") await showInto("show-pbr", "/api/v1/show/policy/route");

  const lists = entriesUnder(ls, ["policy", "prefix-list"]);
  const list = chosenName("pllist-pick", "plnew", lists);
  fillPicker("pllist-pick", lists, list);
  renderObjects({{
    listId: "pllist", required: "prefix",
    toggleId: "togglepl", toggleLabel: "New rule",
    addId: list ? "addplpanel" : null, noun: "Rule",
    fields: PLIST_RULE, nameHint: "10",
    // The rule's *name* is its sequence number, which is what orders them.
    path: (seq) => `policy prefix-list ${{list}} rule ${{seq}}`,
    rows: list ? entriesUnder(ls, ["policy", "prefix-list", list, "rule"]) : [],
    badge: (r) => ({{ text: "seq " + r.name }}),
    empty: list ? "No rules in " + list + " yet."
                : "Type a name beside the picker to start a list.",
  }});
  $("togglepl").disabled = !list;

  const maps = entriesUnder(ls, ["policy", "route-map"]);
  const map = chosenName("rmlist-pick", "rmnew", maps);
  fillPicker("rmlist-pick", maps, map);
  // With no map chosen the path has a hole in it, and `set policy route-map
  // default permit` is a command the appliance can only refuse.
  if (map) {{
    settingsPanel("rmglobal", RMAP, fieldsOf(ls, "policy route-map " + map),
                  "policy route-map " + map, "Route map " + map);
  }} else {{
    $("rmglobal").textContent = "";
    $("rmglobal").append(el("p", {{ class: "sub", text:
      "Name a map beside the picker first — a map has to exist before it has settings." }}));
  }}
  renderObjects({{
    listId: "rmlist", required: "action",
    toggleId: "togglerm", toggleLabel: "New rule",
    addId: map ? "addrmpanel" : null, noun: "Rule",
    fields: RMAP_RULE, nameHint: "10",
    path: (seq) => `policy route-map ${{map}} rule ${{seq}}`,
    rows: map ? entriesUnder(ls, ["policy", "route-map", map, "rule"]) : [],
    badge: (r) => r.action ? {{ text: r.action, cls: r.action === "deny" ? "drop" : "accept" }}
                           : {{ text: "no action", cls: "warn" }},
    empty: map ? "No rules in " + map + " yet."
               : "Type a name beside the picker to start a map.",
  }});
  $("togglerm").disabled = !map;
}}

async function refreshSystem() {{
  const ls = await leaves();
  const under = (node) => fieldsOf(ls, node);
  settingsPanel("sys-ident", SYS_IDENT, under("system"), "system", "Identity");
  renderObjects({{
    listId: "sysctllist", addId: "addsysctlpanel",
    toggleId: "togglesysctl", toggleLabel: "New",
    noun: "Parameter", required: "value",
    fields: SYSCTL, nameHint: "net.ipv4.ip_nonlocal_bind",
    path: (n) => `system sysctl ${{n}}`,
    rows: entriesUnder(ls, ["system", "sysctl"]),
    empty: "No kernel parameters set.",
  }});
  settingsPanel("sys-update", SYS_UPDATE, under("update"), "update", "Update channel");
  await showInto("sysshow", "/api/v1/show/version");
}}

// The routing section, all of it. One reader for ten protocols, because the
// alternative — a view per protocol — is how BGP ended up looking like a
// different product from the six interior protocols beside it.
async function refreshRouting() {{
  const ls = await leaves();
  const tab = currentTab("routing");
  markTabs("routing", ls);

  // Every protocol's settings mask, filled whether or not it is the open tab:
  // the marks on the strip are what tell an operator which protocols are
  // running, and they come from the same read.
  for (const [box, fields, path, label] of [
    ["igp-ospf", IGP_OSPF, "protocols ospf", "OSPFv2"],
    ["igp-ospf3", IGP_OSPF3, "protocols ospf3", "OSPFv3"],
    ["igp-isis", IGP_ISIS, "protocols isis", "IS-IS"],
    ["igp-rip", IGP_RIP, "protocols rip", "RIP"],
    ["igp-ripng", IGP_RIPNG, "protocols ripng", "RIPng"],
    ["igp-babel", IGP_BABEL, "protocols babel", "Babel"],
    ["igp-bfd", IGP_BFD, "protocols bfd", "BFD"],
    ["bgpglobal", BGP_GLOBAL, "protocols bgp", "BGP router settings"],
    // Both write under `protocols bgp` as well: their keys carry the sub-node,
    // so `confederation id` and `rpki rtr` are the commands they already are.
    ["bgpconfed", BGP_CONFED, "protocols bgp", "Confederation"],
    ["bgprpki", BGP_RPKI, "protocols bgp", "Origin validation"],
    ["mcastform", MULTICAST, "protocols multicast", "Multicast routing"],
  ]) {{
    settingsPanel(box, fields, fieldsOf(ls, path), path, label);
  }}

  // The two protocols that have objects as well as settings.
  renderObjects({{
    listId: "routelist", form: FORMS.route, required: "via",
    toggleId: "toggleroute", toggleLabel: "New", addId: "addroutepanel", noun: "Route",
    fields: ROUTE, nameHint: "0.0.0.0/0",
    path: (n) => `protocols static ${{n}}`,
    rows: entriesUnder(ls, ["protocols", "static"]),
    badge: (r) => r.via ? {{ text: "via " + r.via }} : {{ text: "no next hop", cls: "warn" }},
    empty: "No static routes configured.",
  }});
  renderObjects({{
    listId: "bgplist", form: FORMS.bgpNeighbour, required: "remote-as",
    toggleId: "togglebgp", toggleLabel: "New neighbour", addId: "addbgppanel", noun: "Neighbour",
    fields: BGP_NEIGHBOR, nameHint: "neighbour address",
    path: (n) => `protocols bgp neighbor ${{n}}`,
    rows: entriesUnder(ls, ["protocols", "bgp", "neighbor"]),
    // A neighbour without a remote AS is not yet a session, and saying so is
    // more useful than showing an empty column.
    badge: (r) => r["remote-as"] ? {{ text: "AS " + r["remote-as"] }}
                                 : {{ text: "incomplete", cls: "warn" }},
    empty: "No BGP neighbours configured.",
  }});
  renderObjects({{
    listId: "agglist", toggleId: "toggleagg", toggleLabel: "New aggregate",
    addId: "addaggpanel", noun: "Aggregate",
    fields: BGP_AGGREGATE, nameHint: "10.0.0.0/8",
    path: (n) => `protocols bgp aggregate ${{n}}`,
    rows: entriesUnder(ls, ["protocols", "bgp", "aggregate"]),
    badge: (r) => r["summary-only"] === "true"
      ? {{ text: "specifics suppressed" }} : {{ text: "specifics kept" }},
    empty: "No aggregates configured.",
  }});
  renderObjects({{
    listId: "roalist", required: "origin-as", toggleId: "toggleroa",
    toggleLabel: "New authorisation", addId: "addroapanel", noun: "Authorisation",
    fields: BGP_ROA, nameHint: "192.0.2.0/24",
    path: (n) => `protocols bgp roa ${{n}}`,
    rows: entriesUnder(ls, ["protocols", "bgp", "roa"]),
    badge: (r) => r["origin-as"] ? {{ text: "AS " + r["origin-as"] }}
                                 : {{ text: "no origin", cls: "warn" }},
    empty: "No local authorisations.",
  }});
  renderObjects({{
    listId: "mcastiflist", required: "role", toggleId: "togglemcastif",
    toggleLabel: "New", addId: "addmcastifpanel", noun: "Interface",
    fields: MULTICAST_IFACE, nameHint: "eth0",
    path: (n) => `protocols multicast interface ${{n}}`,
    rows: entriesUnder(ls, ["protocols", "multicast", "interface"]),
    badge: (r) => r.role ? {{ text: r.role }} : {{ text: "no role", cls: "warn" }},
    empty: "No multicast interfaces configured.",
  }});
  renderObjects({{
    listId: "vrflist", required: "table", toggleId: "togglevrf",
    toggleLabel: "New VRF", addId: "addvrfpanel", noun: "VRF",
    fields: VRF, nameHint: "tenant-a",
    path: (n) => `protocols vrf ${{n}}`,
    rows: entriesUnder(ls, ["protocols", "vrf"]),
    badge: (r) => r.table ? {{ text: "table " + r.table }}
                          : {{ text: "no table", cls: "warn" }},
    empty: "No VRFs configured.",
  }});

  // Only the open protocol is asked what it is doing. Ten `show` calls to fill
  // panes nobody is looking at is a page that takes a second to open for
  // nothing, and each of these crosses to the routing daemon.
  const LIVE = {{
    static: [["routeshow", "/api/v1/show/ip/route/static"]],
    bgp: [["bgpshow", "/api/v1/show/ip/bgp/summary"],
          ["bgproutes", "/api/v1/show/ip/bgp/routes"]],
    ospf: [["show-ospf", "/api/v1/show/ip/ospf/neighbors"]],
    ospf3: [["show-ospf3", "/api/v1/show/ip/ospf3/neighbors"]],
    isis: [["show-isis", "/api/v1/show/isis/neighbors"]],
    rip: [["show-rip", "/api/v1/show/ip/rip"]],
    ripng: [["show-ripng", "/api/v1/show/ipv6/ripng"]],
    babel: [["show-babel", "/api/v1/show/babel/neighbors"]],
    bfd: [["show-bfd", "/api/v1/show/bfd"]],
    multicast: [["show-multicast", "/api/v1/show/multicast"]],
    vrf: [["show-vrf", "/api/v1/show/vrf"]],
    table: [["igpshow", "/api/v1/show/ip/route"]],
  }};
  await Promise.all((LIVE[tab] || []).map(([boxId, path]) => showInto(boxId, path)));
}}

async function refreshServices() {{
  const ls = await leaves();
  const under = (node) => fieldsOf(ls, node);
  const flat = [
    ["svc-dns", SVC_DNS, "services dns", "DNS resolver"],
    ["svc-ntp", SVC_NTP, "services ntp", "NTP"],
    ["svc-ssh", SVC_SSH, "services ssh", "SSH access"],
    ["svc-snmp", SVC_SNMP, "services snmp", "SNMP"],
    ["svc-lldp", SVC_LLDP, "services lldp", "LLDP"],
    ["svc-mdns", SVC_MDNS, "services mdns", "mDNS reflector"],
    ["svc-dyndns", SVC_DYNDNS, "services dyndns", "Dynamic DNS"],
    ["svc-dhcprelay", SVC_DHCPRELAY, "services dhcp-relay", "DHCP relay"],
    ["svc-portal", SVC_PORTAL, "services portal", "Captive portal"],
    ["svc-portmap", SVC_PORTMAP, "services port-mapping", "Port mapping"],
    ["svc-alerts", SVC_ALERTS, "services alerts", "Alerts"],
    ["svc-alertmail", SVC_ALERTMAIL, "services alerts mail", "Alert mail"],
  ];
  for (const [box, fields, path, label] of flat) {{
    settingsPanel(box, fields, under(path), path, label);
  }}

  renderObjects({{
    listId: "rplist", form: FORMS.reverseProxy, required: "backends", toggleId: "togglerp", toggleLabel: "New frontend", addId: "addrppanel", noun: "Frontend",
    fields: RPROXY, nameHint: "web",
    path: (n) => `services reverse-proxy ${{n}}`,
    rows: entriesUnder(ls, ["services", "reverse-proxy"]),
    badge: (r) => r.certificate ? {{ text: "TLS" }} : {{ text: "plain", cls: "warn" }},
    empty: "No reverse-proxy frontends configured.",
  }});
  renderObjects({{
    listId: "brlist", form: FORMS.relay, required: "port", toggleId: "togglebr", toggleLabel: "New relay", addId: "addbrpanel", noun: "Relay",
    fields: BRELAY, nameHint: "wol",
    path: (n) => `services broadcast-relay ${{n}}`,
    rows: entriesUnder(ls, ["services", "broadcast-relay"]),
    // A relay never emits onto the segment a packet came from, so one interface
    // carries nothing — worth saying on the card rather than at commit.
    badge: (r) => (r.interface || "").trim().split(/\s+/).filter(Boolean).length >= 2
      ? {{ text: "carrying" }}
      : {{ text: "needs two", cls: "warn" }},
    empty: "No broadcast relays configured.",
  }});
  renderObjects({{
    listId: "sllist", form: FORMS.collector, allowBare: true, toggleId: "togglesl", toggleLabel: "New collector", addId: "addslpanel", noun: "Collector",
    fields: SLTARGET, nameHint: "logs.example.net",
    path: (n) => `services syslog target ${{n}}`,
    rows: entriesUnder(ls, ["services", "syslog", "target"]),
    empty: "No syslog collectors configured.",
  }});
  // Only the open tab's daemons are asked, for the same reason the protocols
  // are: three `show` calls to fill panes nobody is looking at.
  if (currentTab("services") === "publishing") {{
    await Promise.all([
      showInto("portalshow", "/api/v1/show/portal"),
      showInto("portmapshow", "/api/v1/show/port-mapping"),
    ]);
  }}
}}

async function refreshHa() {{
  await showInto("vrrpshow", "/api/v1/show/vrrp");
  renderObjects({{
    listId: "vrrplist", form: FORMS.vrrp, required: "virtual-address", toggleId: "togglevrrp", toggleLabel: "New", addId: "addvrrppanel", noun: "Group",
    fields: VRRP, nameHint: "wan-vip",
    path: (n) => `protocols vrrp ${{n}}`,
    rows: entriesUnder(await leaves(), ["protocols", "vrrp"]),
    // The priority is what decides who holds the address, so it is the badge —
    // and a group without a virtual address holds nothing at all.
    badge: (r) => r["virtual-address"]
      ? {{ text: "prio " + (r.priority || "100") }}
      : {{ text: "no address", cls: "warn" }},
    empty: "No virtual router groups configured.",
  }});

  // The pair's own settings live under `system`, one level, so they are read
  // the same way BGP's router settings are rather than as objects with names.
  const ls = await leaves();
  const under = (node) => fieldsOf(ls, node);
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
      // Which box is being read is said by the breadcrumb and by the rail's
      // cluster card, so both are re-rendered and neither is written to here.
      // The rate series belongs to the box it was read from: a delta across two
      // appliances is not a rate.
      onclick: () => {{
        target = name; history.clear(); lastCounters = null;
        refresh(); refreshCluster(); refreshStack();
      }},
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
  chevron: '<path d="m6 9 6 6 6-6"/>',
  pin: '<path d="M12 21s6-5.7 6-10a6 6 0 1 0-12 0c0 4.3 6 10 6 10z"/><circle cx="12" cy="11" r="2"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.7 2.5 15 0 18M12 3c-2.5 2.7-2.5 15 0 18"/>',
  star: '<circle cx="12" cy="12" r="2.5"/><path d="M12 3v6M12 15v6M3 12h6M15 12h6M6.3 6.3l3.5 3.5M14.2 14.2l3.5 3.5M17.7 6.3l-3.5 3.5M9.8 14.2l-3.5 3.5"/>',
  hex: '<path d="m12 2 8 5v10l-8 5-8-5V7z"/><path d="M12 7v10"/>',
  loop: '<path d="M4 12a8 8 0 0 1 8-8 8 8 0 0 1 7 4"/><path d="M20 12a8 8 0 0 1-8 8 8 8 0 0 1-7-4"/><path d="M19 4v4h-4M5 20v-4h4"/>',
  mesh: '<circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="6" cy="18" r="2"/><circle cx="18" cy="18" r="2"/><path d="M8 6h8M6 8v8M18 8v8M8 18h8M7.5 7.5l9 9M16.5 7.5l-9 9"/>',
  pulse: '<path d="M2 12h4l2.5-7 4 14L15 12h7"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/>',
  filter: '<path d="M3 5h18l-7 8v6l-4 2v-8z"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
  contrast: '<circle cx="12" cy="12" r="9"/><path d="M12 3v18a9 9 0 0 0 0-18z" fill="currentColor" stroke="none"/>',
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
    {{ v: "history", t: "History", i: "gauge" }},
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
    {{ v: "dhcp", t: "DHCP", i: "address" }},
    {{ v: "qos", t: "Traffic shaping", i: "gauge" }},
    {{ v: "lb", t: "Load balancer", i: "swap" }},
  ]}},
  // Everything that decides where a packet goes next, in one place. Static
  // routes, one exterior protocol, six interior ones, the detector they share,
  // the policy that filters between them and the uplink selection on top — an
  // operator chasing a route should not have to know which of those answered.
  // Every protocol is named in the rail: a box that speaks seven of them and
  // shows one is a box an operator will assume cannot do the other six.
  {{ g: "Routing", items: [
    {{ v: "routing", tab: "static", t: "Static routes", i: "pin" }},
    {{ v: "routing", tab: "bgp",    t: "BGP", i: "globe" }},
    {{ v: "routing", tab: "ospf",   t: "OSPFv2", i: "star" }},
    {{ v: "routing", tab: "ospf3",  t: "OSPFv3", i: "star" }},
    {{ v: "routing", tab: "isis",   t: "IS-IS", i: "hex" }},
    {{ v: "routing", tab: "rip",    t: "RIP", i: "loop" }},
    {{ v: "routing", tab: "ripng",  t: "RIPng", i: "loop" }},
    {{ v: "routing", tab: "babel",  t: "Babel", i: "mesh" }},
    {{ v: "routing", tab: "bfd",    t: "BFD", i: "pulse" }},
    {{ v: "routing", tab: "multicast", t: "Multicast", i: "mesh" }},
    {{ v: "routing", tab: "vrf",    t: "VRFs", i: "list" }},
    {{ v: "routing", tab: "table",  t: "Routing table", i: "list" }},
    {{ v: "routepolicy", tab: "prefix", t: "Prefix lists", i: "filter" }},
    {{ v: "routepolicy", tab: "maps", t: "Route maps", i: "filter" }},
    {{ v: "routepolicy", tab: "pbr", t: "Policy routing", i: "pin" }},
    {{ v: "wan", t: "Multi-WAN", i: "swap" }},
  ]}},
  {{ g: "Security", items: [
    {{ v: "ipsec", t: "IPsec", i: "lock" }},
    {{ v: "wireguard", t: "WireGuard", i: "key" }},
    {{ v: "openconnect", t: "Remote access", i: "lock" }},
    {{ v: "pki", t: "Authorities", i: "lock" }},
    {{ v: "certs", t: "Certificates", i: "file" }},
    {{ v: "ids", t: "Intrusion detection", i: "bug" }},
    {{ v: "capture", t: "Packet capture", i: "search" }},
  ]}},
  {{ g: "Services", items: [
    {{ v: "services", tab: "resolution", t: "DNS and time", i: "layers" }},
    {{ v: "services", tab: "management", t: "Management access", i: "key" }},
    {{ v: "services", tab: "addressing", t: "Addressing", i: "address" }},
    {{ v: "services", tab: "publishing", t: "Publishing", i: "swap" }},
    {{ v: "services", tab: "notification", t: "Logging and alerts", i: "bug" }},
  ]}},
  {{ g: "System", items: [
    {{ v: "system", t: "System", i: "gauge" }},
    {{ v: "ha", t: "High availability", i: "layers" }},
    {{ v: "users", t: "Administrators", i: "key" }},
    {{ v: "config", t: "Revisions", i: "file" }},
    {{ v: "stack", t: "Stack", i: "layers" }},
  ]}},
];

// The tabs a divided view is made of, and the config node each one owns.
//
// The rail lists the same tabs as ordinary entries, so this table is what keeps
// the two agreeing: one place says what the parts are, the strip and the rail
// both read it, and a part added to one appears in the other.
const TABS = {{
  routing: [
    {{ k: "static", t: "Static",  i: "pin",   n: "protocols static" }},
    {{ k: "bgp",    t: "BGP",     i: "globe", n: "protocols bgp" }},
    {{ k: "ospf",   t: "OSPFv2",  i: "star",  n: "protocols ospf" }},
    {{ k: "ospf3",  t: "OSPFv3",  i: "star",  n: "protocols ospf3" }},
    {{ k: "isis",   t: "IS-IS",   i: "hex",   n: "protocols isis" }},
    {{ k: "rip",    t: "RIP",     i: "loop",  n: "protocols rip" }},
    {{ k: "ripng",  t: "RIPng",   i: "loop",  n: "protocols ripng" }},
    {{ k: "babel",  t: "Babel",   i: "mesh",  n: "protocols babel" }},
    {{ k: "bfd",    t: "BFD",     i: "pulse", n: "protocols bfd" }},
    {{ k: "multicast", t: "Multicast", i: "mesh", n: "protocols multicast" }},
    {{ k: "vrf",    t: "VRFs",    i: "list",  n: "protocols vrf" }},
    {{ k: "table",  t: "Routing table", i: "list" }},
  ],
  routepolicy: [
    {{ k: "prefix", t: "Prefix lists", n: "policy" }},
    {{ k: "maps",   t: "Route maps" }},
    {{ k: "pbr",    t: "Policy routing" }},
  ],
  services: [
    {{ k: "resolution",   t: "DNS and time" }},
    {{ k: "management",   t: "Management access" }},
    {{ k: "addressing",   t: "Addressing" }},
    {{ k: "publishing",   t: "Publishing" }},
    {{ k: "notification", t: "Logging and alerts" }},
  ],
}};

let tabs = {{}};        // view → the tab open in it
const tabMarks = {{}};  // view → the tabs that already carry configuration

function tabsOf(v) {{ return TABS[v] || null; }}
function currentTab(v) {{
  const t = tabsOf(v);
  return t ? (tabs[v] || t[0].k) : null;
}}
// What the rail, the header and the strip all agree the operator is looking at.
function viewKey() {{
  const t = currentTab(view);
  return t ? view + ":" + t : view;
}}

function renderTabs(v) {{
  const host = $("tabs-" + v);
  const items = tabsOf(v);
  if (!host || !items) return;
  const cur = currentTab(v);
  const marks = tabMarks[v] || new Set();
  host.textContent = "";
  for (const it of items) {{
    const b = el("button", {{
      class: it.k === cur ? "on" : "",
      onclick: () => {{ tabs[v] = it.k; refresh(); }},
    }});
    // The same mark the rail uses, so the strip and the rail read as one thing.
    if (it.i) b.append(icon(it.i));
    b.append(el("span", {{ text: it.t }}));
    // A dot on the tabs that are actually running: seven protocols, and the
    // one question worth answering before opening any of them is which.
    if (marks.has(it.k)) b.append(el("span", {{ class: "live", title: "configured" }}));
    host.append(b);
  }}
  for (const pane of document.querySelectorAll("#view-" + v + " > .tabpane")) {{
    pane.classList.toggle("hidden", pane.dataset.tab !== cur);
  }}
}}

// Which tabs of a view carry configuration, worked out from the leaves the
// view already fetched — asking the appliance a second time for something it
// just answered is how a console gets slow.
function markTabs(v, ls) {{
  const items = tabsOf(v);
  if (!items) return;
  const marks = new Set();
  for (const it of items) {{
    if (it.n && ls.some((l) => l.node === it.n)) marks.add(it.k);
  }}
  tabMarks[v] = marks;
  renderTabs(v);
}}

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
// A destination may name a tab (`view:tab`), because a hit on an OSPF setting
// that opened the routing section on whatever tab was last used would have made
// the operator find it a second time.
const OWNERS = [
  [["firewall", "rule"], "rules"],
  [["firewall", "zone"], "zones"],
  [["firewall", "global"], "zones"],
  [["firewall", "group"], "groups"],
  [["firewall", "syn-protect"], "synproxy"],
  [["nat"], "nat"],
  [["protocols", "static"], "routing:static"],
  [["protocols", "bgp"], "routing:bgp"],
  [["protocols", "vrrp"], "ha"],
  [["protocols", "ospf"], "routing:ospf"],
  [["protocols", "ospf3"], "routing:ospf3"],
  [["protocols", "isis"], "routing:isis"],
  [["protocols", "rip"], "routing:rip"],
  [["protocols", "ripng"], "routing:ripng"],
  [["protocols", "babel"], "routing:babel"],
  [["protocols", "bfd"], "routing:bfd"],
  [["policy"], "routepolicy"],
  [["multiwan"], "wan"],
  [["vpn", "ipsec"], "ipsec"],
  [["vpn", "wireguard"], "wireguard"],
  [["vpn", "openconnect"], "openconnect"],
  [["load-balancer"], "lb"],
  [["pki", "ca"], "pki"],
  [["pki", "certificate"], "certs"],
  [["services", "dns"], "services:resolution"],
  [["services", "ntp"], "services:resolution"],
  [["services", "ssh"], "services:management"],
  [["services", "snmp"], "services:management"],
  [["services", "lldp"], "services:management"],
  [["services", "mdns"], "services:addressing"],
  [["services", "dyndns"], "services:addressing"],
  [["services", "dhcp-relay"], "services:addressing"],
  [["services", "reverse-proxy"], "services:publishing"],
  [["services", "broadcast-relay"], "services:publishing"],
  [["services", "portal"], "services:publishing"],
  [["services", "port-mapping"], "services:publishing"],
  [["services", "alerts"], "services:notification"],
  [["services", "syslog"], "services:notification"],
  [["system", "login"], "users"],
  [["system", "group"], "users"],
  [["system", "config-sync"], "ha"],
  [["system", "conntrack-sync"], "ha"],
  [["system"], "system"],
  [["update"], "system"],
];

// Open a destination, whether it names a tab or not. One door, so the rail, the
// search results and anything added later cannot open a section differently.
function goto(key) {{
  const [v, tab] = String(key).split(":");
  view = v;
  if (tab) tabs[v] = tab;
  panel = null;
  buildNav();
  refresh();
}}

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
      onclick: () => goto(h.view),
    }}));
  }}
}}


// What each view is, in one line. Kept beside the nav table rather than in the
// markup so a section and its heading cannot drift apart, and so a view added
// without a description is visibly missing one.
const ABOUT = {{
  dashboard: "Throughput, verdicts and what the data plane is doing right now.",
  rules: "What is allowed between zones, in the order the firewall reads them.",
  zones: "The posture each zone starts from before any rule is consulted.",
  groups: "Named sets of addresses, ports and domains that rules point at.",
  nat: "Source translation on the way out, destination translation on the way in.",
  synproxy: "Which listeners have their handshake completed by the appliance.",
  interfaces: "Links, addresses and the zone each one belongs to.",
  dhcp: "Addresses handed out on each segment, and the reservations that are not.",
  qos: "Shaping on the link that is congested — set it below the real line rate.",
  lb: "Virtual addresses in front of backend pools.",
  routing: "Everything that decides where a packet goes next.",
  "routing:ospf": "Link-state routing inside your own network, area by area.",
  "routing:ospf3": "OSPF for IPv6 — its own adjacencies, alongside the v2 process.",
  "routing:isis": "Link-state routing that carries both address families at once.",
  "routing:rip": "Distance-vector, fifteen hops, and here for the networks that still speak it.",
  "routing:ripng": "RIP for IPv6, with the same reach and the same limits.",
  "routing:babel": "Distance-vector for links that come and go — wireless and meshes.",
  "routing:bfd": "Sub-second liveness the other protocols subscribe to.",
  "routing:table": "What the protocols agreed on, as the kernel will use it.",
  "routing:static": "Routes written by hand, which win over anything learned.",
  "routing:bgp": "The exterior protocol: neighbours, what is advertised, and what came back.",
  "services:resolution": "Answering names, and agreeing what time it is.",
  "services:management": "How this box is reached and read from outside itself.",
  "services:addressing": "Addresses and names for the segments behind this box.",
  "services:publishing": "What this box puts in front of something else.",
  "services:notification": "Where the appliance speaks up, and who hears it.",
  history: "What the box looked like before now — throughput and connections over time.",
  routepolicy: "Prefix lists and route maps — what is accepted, and what is changed.",
  "routepolicy:prefix": "Named sets of prefixes a route map or a neighbour filter points at.",
  "routepolicy:maps": "What is accepted, and what is changed on the way through.",
  "routepolicy:pbr": "Traffic sent by where it came from rather than where it is going.",
  wan: "Which uplink carries new connections, and what happens when one fails.",
  ipsec: "Site-to-site IKEv2 tunnels.",
  wireguard: "Site-to-site WireGuard interfaces and their peers.",
  openconnect: "The road-warrior server people carry on a laptop.",
  pki: "Local certificate authorities.",
  certs: "Issued certificates and what they are used for.",
  ids: "Detection, and what an alert is allowed to do about it.",
  capture: "See the wire itself — bounded, and never written to disk.",
  services: "The box services: resolution, time, management access, notification.",
  system: "Identity, and where signed images come from.",
  ha: "The pair: who holds the address, and what the other box knows when it does.",
  users: "Who may manage this appliance, and with what permission.",
  config: "Every saved revision, and the way back to one.",
  stack: "The peers this appliance is managed alongside.",
  panel: "Command output.",
}};

// The rail entry an operator is standing on, whatever they clicked to get here,
// and the group it belongs to — the breadcrumb is built from the same table the
// rail is, so the path it prints is the path they walked.
function sectionPlace() {{
  const tab = currentTab(view);
  for (const g of SECTIONS) {{
    const hit = g.items.find((i) => i.v === view && (!i.tab || i.tab === tab));
    if (hit) return {{ group: g.g, item: hit }};
  }}
  return null;
}}
function sectionItem() {{
  const place = sectionPlace();
  return place ? place.item : null;
}}

function renderPageHeader() {{
  const host = $("pagehead");
  if (!host) return;
  const item = sectionItem();
  const title = item ? item.t : "";
  host.textContent = "";
  if (!title && view !== "panel") return;
  const text = el("div", {{ class: "headtext" }}, [
    el("h2", {{ text: title || (panel ? panel.t : "Output") }}),
  ]);
  const about = ABOUT[viewKey()] || ABOUT[view];
  if (about) text.append(el("p", {{ text: about }}));
  // A read-only view is the output of one command, and saying which is what
  // lets an operator run it themselves or quote it in a ticket.
  if (panel && panel.p) {{
    text.append(el("code", {{
      class: "cmd",
      text: "show " + panel.p.replace("/api/v1/show/", "").split("/").join(" "),
    }}));
  }}
  host.append(text);
}}

// Groups the operator has folded away. A rail with every protocol named is
// long on purpose; which parts of it stay open is their business, and it is
// the only preference this console keeps between sessions.
const FOLDED = "sentinel-folded";
let folded = new Set();
try {{ folded = new Set(JSON.parse(localStorage.getItem(FOLDED) || "[]")); }} catch (e) {{}}
function toggleGroup(name) {{
  folded.has(name) ? folded.delete(name) : folded.add(name);
  try {{ localStorage.setItem(FOLDED, JSON.stringify([...folded])); }} catch (e) {{}}
  buildNav();
}}

function groupBox(name, hasCurrent) {{
  // A folded group that holds the current page would hide where you are, so it
  // opens itself rather than being right about a stale preference.
  const shut = folded.has(name) && !hasCurrent;
  const head = el("button", {{ class: "grouphead", onclick: () => toggleGroup(name) }});
  head.append(el("span", {{ text: name }}), icon("chevron"));
  head.setAttribute("aria-expanded", String(!shut));
  return el("div", {{ class: "group" + (shut ? " closed" : "") }}, [head]);
}}

function buildNav() {{
  const nav = $("nav");
  const filter = $("navsearch").value.trim().toLowerCase();
  nav.textContent = "";
  const key = viewKey();
  for (const group of SECTIONS) {{
    const items = group.items.filter((i) => !filter || i.t.toLowerCase().includes(filter));
    if (!items.length) continue;
    const itemKey = (i) => i.tab ? i.v + ":" + i.tab : i.v;
    // A search filters the rail down to what matched, so folding it away then
    // would hide the answer.
    const box = groupBox(group.g, !!filter || items.some((i) => itemKey(i) === key));
    for (const item of items) {{
      const b = navButton(item.t, item.i, () => goto(itemKey(item)), itemKey(item));
      if (itemKey(item) === key && !panel) b.classList.add("on");
      box.append(b);
    }}
    nav.append(box);
  }}
  // The read-only views keep their own group; they are what you open to look,
  // not to change, and mixing them into the sections above would hide that.
  for (const group of NAV) {{
    const items = group.items.filter((i) => !filter || i.t.toLowerCase().includes(filter));
    if (!items.length) continue;
    const box = groupBox(group.g, !!filter || (!!panel && items.some((i) => i.p === panel.p)));
    for (const item of items) {{
      const b = navButton(item.t, group.g === "Diagnostics" ? "bug" : "chart",
        () => {{ view = "panel"; panel = item; refresh(); }}, item.p);
      b.dataset.path = item.p;
      box.append(b);
    }}
    nav.append(box);
  }}
  // A filter that matches nothing used to leave the rail empty and say nothing,
  // which reads as a console that has lost its own sections.
  if (filter && !nav.children.length) {{
    nav.append(el("div", {{ class: "group" }}, [
      el("span", {{ class: "grp", text: "No section matches" }}),
      el("button", {{
        class: "navitem", text: "Clear the search",
        onclick: () => {{ $("navsearch").value = ""; buildNav(); renderMatches(); }},
      }}),
    ]));
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
      onclick: () => {{
        target = name; history.clear(); lastCounters = null;
        refresh(); refreshCluster();
      }},
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
  renderPageHeader();
  renderTabs(view);
  const key = viewKey();
  for (const b of document.querySelectorAll("aside button.navitem")) {{
    const active = b.dataset.path ? (panel && b.dataset.path === panel.p)
                                  : (!panel && b.dataset.key === key);
    b.classList.toggle("on", !!active);
    b.setAttribute("aria-current", String(!!active));
  }}
  // The breadcrumb names the box being driven first, so a peer's read-only view
  // can never be mistaken for the appliance you are configuring.
  const place = sectionPlace();
  // When the rail entry does not name the tab — BGP has one entry and three
  // tabs — the crumb carries it, so the trail always ends where you are.
  const tab = currentTab(view);
  const tabName = (tabsOf(view) || []).find((t) => t.k === tab);
  const named = place && place.item.tab;
  $("crumb").textContent = [
    target || "this appliance",
    panel ? "show" : (place ? place.group : ""),
    panel ? panel.t : (place ? place.item.t : ""),
    panel || named || !tabName ? "" : tabName.t,
  ].filter(Boolean).join("  /  ");
  // Read off the document rather than a list kept beside it: a view added to
  // the markup and forgotten here was a section that could be reached from the
  // rail and never appeared, which is exactly what happened once.
  for (const box of document.querySelectorAll('[id^="view-"]')) {{
    box.classList.toggle("hidden", box.id !== "view-" + view);
  }}
  document.title = (panel ? panel.t : (place ? place.item.t : "Dashboard")) + " — Sentinel";
  gateWrites();

  if (view === "dashboard") return refreshDashboard();
  if (view === "rules") return refreshRules();
  if (view === "zones") return refreshZones();
  if (view === "nat") return refreshNat();
  if (view === "groups") return refreshGroups();
  if (view === "synproxy") return refreshSynproxy();
  if (view === "interfaces") return refreshInterfaces();
  if (view === "lb") return refreshLb();
  if (view === "pki") return refreshPki();
  if (view === "certs") return refreshCerts();
  if (view === "ids") return refreshIds();
  if (view === "capture") return refreshCapture();
  if (view === "ha") return refreshHa();
  if (view === "users") return refreshUsers();
  if (view === "ipsec") return refreshIpsec();
  if (view === "routing") return refreshRouting();
  if (view === "wan") return refreshWan();
  if (view === "qos") return refreshQos();
  if (view === "openconnect") return refreshOpenconnect();
  if (view === "history") return refreshHistory();
  if (view === "routepolicy") return refreshRoutePolicy();
  if (view === "system") return refreshSystem();
  if (view === "services") return refreshServices();
  if (view === "wireguard") return refreshWireguard();
  if (view === "dhcp") return refreshDhcp();
  if (view === "config") return refreshConfig();
  if (view === "stack") return refreshStack();
  if (view === "panel" && panel) {{
    $("panel").textContent = "…";
    try {{ $("panel").textContent = (await text(panel.p)).trimEnd() || "(nothing to show)"; }}
    catch (e) {{ $("panel").textContent = explain(String(e.message || e)); }}
  }}
}}

// Who is signed in, and — when it is less than everything — what they may do.
// A read-only operator who is offered Apply learns their permission by being
// refused, which is the worst possible time to find out.
function renderWho() {{
  const label = $("whoami");
  if (label) {{
    label.textContent = who || "management token";
    label.title = who ? "signed in as " + who : "signed in with the machine token";
  }}
  const readOnly = permission === "read-only";
  const pill = $("permpill");
  if (pill) {{
    pill.textContent = "read-only";
    pill.classList.toggle("hidden", !readOnly);
  }}
  // Everything that changes the appliance is a POST, and a read-only token is
  // refused every one of them. Saying so here beats saying it afterwards.
  for (const id of ["applystaged", "applystaged2", "validate", "discard"]) {{
    const b = $(id);
    if (!b) continue;
    b.disabled = readOnly;
    b.title = readOnly ? "This account may read the configuration, not change it" : "";
  }}
}}

function signOut(message) {{
  token = "";
  who = "";
  permission = "read-write";
  // Nothing of the last session may outlive it: staged commands the next
  // operator would apply as their own, a peer they did not select, and a
  // configuration they were never shown.
  staged = [];
  dirty.clear();
  target = "";
  view = "dashboard";
  panel = null;
  lastLeaves = [];
  searchIndex = [];
  history.clear();
  lastCounters = null;
  renderStaged();
  banner("");
  sessionStorage.removeItem(KEY);
  if (timer) {{ clearInterval(timer); timer = null; }}
  $("app").classList.add("hidden");
  $("login").classList.remove("hidden");
  $("loginerr").textContent = message || "";
}}

function signedIn() {{
  renderWho();
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

// Signing in as an account: the appliance checks the password and hands back
// that account's token, which is the same token everything else here uses. The
// password is never kept — not in a variable that outlives this function, not
// in storage, not anywhere.
$("loginform").onsubmit = async (e) => {{
  e.preventDefault();
  const username = $("username").value.trim();
  const password = $("password").value;
  if (!username || !password) {{
    $("loginerr").textContent = "A username and a password, please.";
    return;
  }}
  $("loginerr").textContent = "Signing in…";
  try {{
    const r = await fetch("/api/v1/login", {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{ username, password, code: $("code").value.trim() }}),
    }});
    const body = await r.json().catch(() => ({{}}));
    if (!r.ok) {{
      // The password was right and a code is what is missing: reveal the field
      // and say so, rather than repeating "sign-in failed" at somebody who did
      // nothing wrong.
      if (/one-time code/i.test(body.error || "")) {{
        $("codefield").classList.remove("hidden");
        $("code").focus();
      }}
      $("loginerr").textContent = body.error || ("Sign-in failed (HTTP " + r.status + ")");
      return;
    }}
    token = body.token;
    permission = body.permission || "read-write";
    who = body.user || username;
    sessionStorage.setItem(KEY, token);
    $("password").value = "";
    $("code").value = "";
    $("codefield").classList.add("hidden");
    $("loginerr").textContent = "";
    signedIn();
  }} catch (err) {{
    $("loginerr").textContent = String(err.message || err);
  }}
}};

// The way in before any account exists, and the way a peer or a script gets in.
$("tokentoggle").onclick = () => {{
  const box = $("tokenway");
  box.classList.toggle("hidden");
  $("tokentoggle").textContent = box.classList.contains("hidden")
    ? "Sign in with a token instead" : "Sign in with a username instead";
}};
$("tokenform").onsubmit = (e) => {{
  e.preventDefault();
  token = $("token").value.trim();
  if (!token) return;
  permission = "read-write";
  who = "";
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
wireToggle("togglevrrp", "addvrrppanel", "New");
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
wireToggle("togglerp", "addrppanel", "New frontend");
wireToggle("togglebr", "addbrpanel", "New relay");
wireToggle("togglesl", "addslpanel", "New collector");
wireToggle("toggleadmingroup", "addadmingrouppanel", "New group");
wireToggle("togglewan", "addwanpanel", "New uplink");
wireToggle("toggleocuser", "addocuserpanel", "New account");
wireToggle("togglepl", "addplpanel", "New rule");
wireToggle("togglerm", "addrmpanel", "New rule");
$("wgtunnel").onchange = () => refreshWireguard();
$("pllist-pick").onchange = () => {{ $("plnew").value = ""; refreshRoutePolicy(); }};
$("rmlist-pick").onchange = () => {{ $("rmnew").value = ""; refreshRoutePolicy(); }};
$("plnew").onchange = () => refreshRoutePolicy();
$("rmnew").onchange = () => refreshRoutePolicy();
$("qosiface").onchange = () => refreshQos();
$("historyres").onchange = () => refreshHistory();
$("enabledhcp").onclick = () => {{
  const iface = $("dhcpiface").value;
  if (!iface) return;
  stage("Enable DHCP on " + iface, [`set interface ${{iface}} dhcp-server enable`]);
}};
// `enable` takes no value, so it cannot come from a field the way every other
// setting does — it is a verb, and this is the button that says it.
$("enablera").onclick = () => {{
  const iface = $("raiface").value;
  if (!iface) return;
  stage("Advertise a router on " + iface,
        [`set interface ${{iface}} router-advert enable`]);
}};
$("mapiface").onchange = () => refreshDhcp();

$("cancel").onclick = () => $("editor").close();
$("resultclose").onclick = () => $("result").close();
$("applysave").onclick = () => {{
  const lines = script();
  if (!lines.length) {{ $("editorerr").textContent = "A rule needs a name and at least one setting."; return; }}
  $("editor").close();
  stage("Firewall rule " + $("r-name").value.trim(), lines);
}};
// Appearance: follow the system, or say otherwise. Three states rather than a
// switch, because "follow the system" is the honest default and a two-way
// toggle cannot express it — and the choice is a preference, not a credential,
// so it is the one thing that outlives the tab.
const THEME = "sentinel-theme";
let theme = "system";
try {{ theme = localStorage.getItem(THEME) || "system"; }} catch (e) {{}}

function applyTheme() {{
  const root = document.documentElement;
  if (theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
  const b = $("theme");
  if (!b) return;
  b.textContent = "";
  b.append(icon(theme === "light" ? "sun" : theme === "dark" ? "moon" : "contrast"));
  b.title = "Appearance: " + (theme === "system" ? "follow the system" : theme);
}}

$("theme").onclick = () => {{
  theme = theme === "system" ? "light" : theme === "light" ? "dark" : "system";
  try {{ localStorage.setItem(THEME, theme); }} catch (e) {{}}
  applyTheme();
}};
applyTheme();

// A reload throws away everything staged — the token survives in session
// storage, the commands do not. Asking is the difference between a mis-click
// and an afternoon.
window.addEventListener("beforeunload", (e) => {{
  if (!staged.length && !dirty.size) return;
  e.preventDefault();
  e.returnValue = "";
}});

spreadify();
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

    /// The console's route sources are the routing daemon's, not a subset of
    /// them. It offered three of the eight, so a configuration that
    /// redistributes kernel routes — an ordinary thing to do on a box with a
    /// default route from DHCP or from a provider — could be written in the CLI
    /// and not clicked together in the console.
    #[test]
    fn every_route_source_the_daemon_knows_can_be_ticked() {
        let html = page();
        // The list itself, not the words in it — every one of these names also
        // occurs elsewhere on the page, so a per-word search would pass on a
        // console that offers none of them.
        assert!(
            html.contains(
                r#""connected", "static", "kernel", "rip", "ospf", "isis", "babel", "bgp","#
            ),
            "the console's route sources are not the routing daemon's"
        );
        // And every protocol's own mask draws from that list rather than from a
        // hand-written subset, which is what had drifted.
        for protocol in ["bgp", "ospf", "isis", "rip", "babel"] {
            assert!(
                html.contains(&format!("redist(\"{protocol}\")")),
                "{protocol} still has its own redistribute list"
            );
        }
    }

    /// Everything the CLI can configure, the console can too. This list was
    /// found by instrumenting the page — recording what path each mask writes
    /// to — and comparing it with the grammar in `repl.rs` node by node. Ten
    /// sections had no mask at all: an operator could type them and not click
    /// them, which makes the console a partial view of the appliance rather
    /// than a way to run it.
    ///
    /// A new `set` path belongs on this list. If it has no mask, this test is
    /// where that gets noticed rather than by somebody looking for the setting.
    #[test]
    fn every_configurable_section_has_somewhere_to_click() {
        let html = page();
        for path in [
            // Sub-nodes reached through a two-word field key.
            "confederation id",
            "rpki rtr",
            "dhcp6-pool start",
            "offload ntuple",
            "set add-ext-community",
            // Sections with a mask of their own.
            "nat npt66 ",
            "pki acme",
            "protocols bgp aggregate ",
            "protocols bgp roa ",
            "protocols multicast",
            "protocols multicast interface ",
            "protocols vrf ",
            "router-advert",
            "static-mapping ",
        ] {
            assert!(
                html.contains(path),
                "nothing in the console writes {path:?}"
            );
        }
    }

    /// Editing goes through the CLI grammar. If the console ever assembled a
    /// config document itself, this is the test that should have to change.
    #[test]
    fn changes_are_made_as_cli_commands_not_as_a_config_document() {
        let html = page();
        assert!(html.contains("/api/v1/configure"));
        // Every edit becomes `set <path> <field> <value>` — the CLI's own verb.
        assert!(html.contains("lines.push(`set ${path} ${f[0]} ${v}`)"));
        assert!(html.contains("firewall rule "));
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
        // Nor a `show` box. It reads as harmless — it only reads — but it is
        // still a command line on a page whose whole claim is that you click.
        assert!(!html.contains("showcmd"), "the free-text show box is back");
        assert!(
            !html.contains("run any show command"),
            "the console invites typing a command"
        );
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
            // Static routes and BGP are panes of the routing section now: an
            // appliance that speaks ten protocols showing each in its own
            // shape was the section reading as ten different products.
            "view-routing",
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
        // Every top-level word of the CLI's grammar has an owner. A section
        // with none is one whose settings are found by search and then cannot
        // be opened — the console admitting it has a hole.
        for top in [
            "system",
            "firewall",
            "nat",
            "load-balancer",
            "protocols",
            "services",
            "multiwan",
            "vpn",
            "pki",
            "policy",
            "update",
        ] {
            assert!(
                html.contains(&format!("[[\"{top}\"")),
                "nothing owns `{top}`, so a hit under it opens nothing"
            );
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
        // The rule's own vocabularies live in one table, and a field with a
        // fixed set of values carries it there rather than in the markup.
        assert!(
            html.contains(r#"["action", "Action", ["accept", "drop", "reject"]]"#),
            "action is free text"
        );
        assert!(
            html.contains(r#"const zoneOpts = ["", ...zones]"#),
            "a zone is typed rather than chosen"
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
        // A refused commit must leave the work in place to be corrected — and
        // so must a *validate*, which applies nothing at all. Clearing on a
        // validate meant the check said "fine" and then emptied the panel.
        assert!(
            html.contains("if (committed && r.ok &&"),
            "staged commands clear even when nothing was applied"
        );
        assert!(
            html.contains(r#"const committed = tail.includes("commit")"#),
            "applying and validating are not told apart"
        );
    }

    /// Every element the script reaches for by name has to be in the markup.
    ///
    /// This is the bug that has cost the console most: one `$("refresh")` for a
    /// button a redesign had removed threw at load, and everything wired *after*
    /// that line — every "New" button, the capture, the appearance toggle —
    /// silently never happened. A page whose script parses can still be dead,
    /// and `node --check` cannot see it, so the ids are checked here instead.
    #[test]
    fn every_element_the_script_reaches_for_exists() {
        let html = page();
        let ids: std::collections::HashSet<&str> = html
            .match_indices("id=\"")
            .filter_map(|(i, _)| {
                let rest = &html[i + 4..];
                rest.find('"').map(|end| &rest[..end])
            })
            .collect();
        // Only the literal lookups: `$("view-" + v)` is built at run time and is
        // covered by the view test above.
        for (i, _) in html.match_indices("$(\"") {
            let rest = &html[i + 3..];
            let Some(end) = rest.find("\")") else {
                continue;
            };
            let id = &rest[..end];
            if id.contains('"') || id.contains(' ') {
                continue;
            }
            assert!(
                ids.contains(id),
                "the script reaches for #{id}, which no element has"
            );
        }
    }

    /// Every function the script calls has to be one the script defines.
    ///
    /// `parseConfig` was called by the one function every configuration-driven
    /// view is built on, and was never written. The page parsed, the console
    /// loaded, and every mask on it showed an appliance with nothing configured
    /// — for months, on a box that was fully configured. A parser cannot see
    /// this and neither can a reviewer; a name check can.
    #[test]
    fn every_function_the_script_calls_is_defined() {
        let html = page();
        let script = html
            .split_once("<script>")
            .and_then(|(_, rest)| rest.split_once("</script>"))
            .map(|(s, _)| s)
            .expect("the page has a script");

        fn ident(s: &str) -> Option<&str> {
            let end = s
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
                .unwrap_or(s.len());
            (end > 0).then(|| &s[..end])
        }
        let mut defined: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for keyword in ["function ", "const ", "let ", "var "] {
            for (i, _) in script.match_indices(keyword) {
                if let Some(name) = ident(&script[i + keyword.len()..]) {
                    defined.insert(name);
                }
            }
        }
        // The names the browser brings. Anything else has to come from the page.
        const BUILTIN: &[&str] = &[
            "if",
            "for",
            "while",
            "switch",
            "catch",
            "return",
            "typeof",
            "new",
            "await",
            "function",
            "else",
            "do",
            "in",
            "of",
            "delete",
            "void",
            "yield",
            "throw",
            "String",
            "Number",
            "Boolean",
            "Object",
            "Array",
            "JSON",
            "Math",
            "Date",
            "Set",
            "Map",
            "Promise",
            "Error",
            "RegExp",
            "Intl",
            "fetch",
            "encodeURIComponent",
            "decodeURIComponent",
            "setInterval",
            "setTimeout",
            "clearInterval",
            "clearTimeout",
            "isNaN",
            "parseInt",
            "parseFloat",
            "getComputedStyle",
            "requestAnimationFrame",
            "structuredClone",
            "Event",
            "URL",
            "AbortController",
            // Typed arrays and the crypto interface: a page that generates a
            // secret in the browser needs both, and both are as much a builtin
            // as `Array` is.
            "Uint8Array",
        ];
        for (i, _) in script.match_indices('(') {
            let before = &script[..i];
            let start = before
                .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
                .map(|p| p + 1)
                .unwrap_or(0);
            let name = &before[start..];
            if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
                continue;
            }
            // `a.b(…)` is a method on a value, not a name this page has to own.
            if start > 0 && before.as_bytes()[start - 1] == b'.' {
                continue;
            }
            if BUILTIN.contains(&name) || defined.contains(name) {
                continue;
            }
            panic!("the script calls {name}(), which nothing defines");
        }
    }

    /// The rail, the tab strips and the page headers are three views of one
    /// table, so they cannot be allowed to disagree: every destination the rail
    /// offers must have a pane to show, a mark to draw and a line explaining
    /// what it is. Each of these was a real omission at some point — a rail
    /// entry with no pane opens a blank page, and one with no description opens
    /// a page that does not say what it is for.
    #[test]
    fn every_destination_has_a_pane_a_mark_and_a_description() {
        let html = page();

        // The marks the rail and the strips draw, taken from the icon table.
        let icons: std::collections::HashSet<&str> = html
            .split_once("const ICONS = {")
            .map(|(_, rest)| rest.split_once("\n}").map(|(t, _)| t).unwrap_or(""))
            .unwrap_or("")
            .lines()
            .filter_map(|line| line.trim().split_once(':').map(|(name, _)| name.trim()))
            .collect();
        assert!(icons.contains("globe"), "the icon table did not parse");

        // Every `{ v: "…", tab: "…", t: "…", i: "…" }` the rail offers.
        for (i, _) in html.match_indices("{ v: \"") {
            let end = html[i..].find("}}").map(|e| i + e).unwrap_or(html.len());
            let entry = &html[i..end];
            let field = |key: &str| -> Option<String> {
                let at = entry.find(&format!("{key}: \""))? + key.len() + 3;
                let rest = &entry[at..];
                Some(rest[..rest.find('"')?].to_string())
            };
            let Some(view) = field("v") else { continue };
            let tab = field("tab");
            let mark = field("i").expect("a rail entry with no mark");
            assert!(
                icons.contains(mark.as_str()),
                "{view}: no such mark {mark:?}"
            );
            assert!(
                html.contains(&format!("id=\"view-{view}\"")),
                "the rail offers {view}, which has no pane"
            );
            if let Some(tab) = &tab {
                assert!(
                    html.contains(&format!("data-tab=\"{tab}\"")),
                    "the rail offers {view}/{tab}, which has no pane"
                );
            }
            let key = match &tab {
                Some(tab) => format!("{view}:{tab}"),
                None => view.clone(),
            };
            // A description is keyed either by the destination or by the view.
            assert!(
                html.contains(&format!("\"{key}\": \""))
                    || html.contains(&format!("\n  {view}: \"")),
                "{key} has no line saying what it is for"
            );
        }
    }

    /// The page has one left edge for labels and one for content. Both come
    /// from the same pair of numbers, so a section that opens the margin and a
    /// list that is pushed past it cannot drift apart.
    #[test]
    fn labels_and_content_share_one_gutter() {
        let html = page();
        for token in ["--gutter: 180px", "--gutter-gap: 28px"] {
            assert!(html.contains(token), "{token} is missing");
        }
        assert!(
            html.contains(".inset {{ margin-left: calc(var(--gutter) + var(--gutter-gap)); }}")
                || html
                    .contains(".inset { margin-left: calc(var(--gutter) + var(--gutter-gap)); }"),
            "content that follows a margin heading no longer uses the gutter"
        );
        assert!(
            html.contains("function spreadify"),
            "nothing puts the sections into the two columns"
        );
    }

    /// A list of named objects is a board with column heads, not a stack of
    /// cards. Cards degrade as they grow: twelve of them are twelve little
    /// forms to read across, and nothing above them says what the values mean.
    #[test]
    fn a_list_of_objects_is_a_board() {
        let html = page();
        assert!(
            html.contains(r#"el("table", { class: "otbl" }"#),
            "the object lists no longer render a table"
        );
        assert!(
            !html.contains(r#"el("div", { class: "rule" }"#),
            "something still renders an object as a card"
        );
        assert!(
            html.contains("function objectColumns"),
            "nothing decides what the columns of a list are"
        );
    }

    /// Allow against deny must never be a hue-matching exercise: within the
    /// denied family the difference is carried by shape, so it survives a
    /// screen nobody calibrated, a screenshot and colour blindness.
    #[test]
    fn a_denial_is_told_apart_by_shape_not_by_hue() {
        let html = page();
        assert!(
            html.contains(
                ".act.reject { color: var(--status-down); background: none; border-style: dashed; }"
            ),
            "reject is no longer a dashed outline in the deny colour"
        );
        assert!(
            html.contains("repeating-linear-gradient(180deg, var(--status-down)"),
            "the row bar for a rejection is no longer broken"
        );
    }

    /// Colour is a code with four meanings. "Configured" is not one of them —
    /// a mark that borrows the colour of "up" tells an operator something the
    /// appliance never said.
    #[test]
    fn configured_is_not_a_status() {
        let html = page();
        assert!(
            html.contains(
                "border-radius: 50%; background: var(--text-faint); vertical-align: middle;"
            ),
            "the mark on a configured tab took a signal colour again"
        );
        assert!(
            html.contains(r#"badge: (r) => ({ text: "tcp/" + r.name }),"#),
            "a badge that only says what a thing is took a signal colour again"
        );
    }

    /// A list of forty rules must not read as forty alarms.
    #[test]
    fn delete_is_quiet_until_it_is_aimed_at() {
        let html = page();
        assert!(
            html.contains("button.danger { color: var(--text-muted); }"),
            "delete is loud at rest again"
        );
        assert!(
            html.contains("button.danger:hover, button.danger:focus-visible {"),
            "delete no longer turns red when it is aimed at"
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
